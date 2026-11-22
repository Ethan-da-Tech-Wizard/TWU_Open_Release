#!/usr/bin/env python3
"""write_guard: single-writer locks and task-root path validation. stdlib only.

  write_guard.py write  --path P --task-root R --agent A [--session S] [--root DATA_ROOT] [--data-file F|-] [--ttl SECONDS]
  write_guard.py append --path P --task-root R --agent A ...     (same options; appends one line)
  write_guard.py lock-status --root DATA_ROOT                    JSON list of lock files and their holders
  write_guard.py reclaim-stale --root DATA_ROOT                  remove locks whose holder is dead or whose TTL expired

Exit codes: 0 ok, 2 REFUSED (outside root, or an unsafe path), 75 BLOCKED-BY-LOCK. No retry loops.

What it is: a lock file per target path (under DATA_ROOT/data/locks, mode 0600 in a 0700 folder) so that two cooperating
writers do not write the same file at once, plus a check that a write stays inside a declared task root.

What it is NOT, stated plainly: the root check is a guard against accidents and path mistakes (.. segments, symlinks that
point out, sibling folders with a shared name prefix), not a security boundary against someone who can change the
directory tree while it runs. Hardening that IS done: the target's folder is opened once with O_DIRECTORY | O_NOFOLLOW,
its real location is re-checked from the descriptor against the root (macOS F_GETPATH or Linux /proc/self/fd), and the
temp file, rename and append all happen relative to that descriptor; the final file is opened with O_NOFOLLOW. Remaining
TOCTOU: the path is validated with realpath() before the folder is opened, missing parent folders are created with
os.makedirs (which follows symlinks in parts created by someone else in that instant), and on a system where the
descriptor's path cannot be read the re-check is skipped. A hostile writer who shares the task root can still race these
windows; locks are advisory and a program that writes the file directly ignores them.
"""
# Standard library only. fcntl/stat/os are for descriptor-based file work, secrets for random temp names,
# socket only to record the host name inside a lock record.
import argparse, errno, fcntl, hashlib, json, os, secrets, socket, stat, sys, time
from datetime import datetime, timezone

# Wall clock and sleep are module-level names so tests can replace them and age a lock without waiting.
# Production code always calls them through these names, never time.time() directly.
# Fields recorded in a lock file: pid, session, agent_id, path, acquired_at, ttl_s, host. The pid is what liveness
# is judged on; the TTL bounds how long a live-but-stuck holder can block others.
_clock = time.time      # wall clock; tests replace it to age locks without sleeping
_sleep = time.sleep     # used only by the test hold hooks below


# Raised by acquire() when another live writer holds the lock. The CLI turns it into exit status 75.
class BlockedByLock(Exception):
    """Another live writer holds the lock for this path; carries the path and the holder's record."""

    def __init__(self, path, holder):
        """Remember the blocked path and the holder's lock record; the message is the CLI's BLOCKED-BY-LOCK line."""
        self.path, self.holder = path, holder
        super().__init__("BLOCKED-BY-LOCK " + _blocked_line(path, holder))


# Raised when a target resolves outside the declared task root. The CLI turns it into exit status 2.
class PathOutsideRoot(Exception):
    """The resolved target path is not inside the declared task root."""

    def __init__(self, resolved, declared_root):
        """Remember the resolved path and the declared root; the message is the CLI's REFUSED line."""
        self.resolved, self.declared_root = resolved, declared_root
        super().__init__("REFUSED write: resolved=%s declared_root=%s" % (resolved, declared_root))


# One format for the blocked message, used by the exception text and by the CLI so they cannot drift apart.
def _blocked_line(path, h):
    """One-line description of a blocked write: path plus the holder's pid, agent, session, acquisition time and TTL."""
    return "path=%s holder_pid=%s holder_agent=%s holder_session=%s acquired_at=%s ttl_s=%s" % (
        path, h.get("pid"), h.get("agent_id"), h.get("session"), h.get("acquired_at"), h.get("ttl_s"))


# Timestamps in logs and lock records are UTC with a trailing Z, so they sort and compare as plain strings.
def _iso(ts=None):
    """UTC ISO-8601 timestamp with microseconds for `ts` (default: now)."""
    return datetime.fromtimestamp(_clock() if ts is None else ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# Signal 0 is the standard "does this process exist" probe: it checks permissions and existence and sends nothing.
# Limit worth knowing: liveness is a pid check on THIS host, so a lock record written on another machine (shared
# folder)
# is judged against the wrong process table. Use one data root per host.
def pid_alive(pid):
    """True if a process with this pid exists (EPERM counts as alive); False for dead, non-positive or invalid pids."""
    try:
        pid = int(pid)
        # pid 0 and negatives would address process groups; they are never a valid lock holder, so treat them as dead.
        if pid <= 0:
            return False
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    # EPERM means the process exists but belongs to another user: alive.
    except PermissionError:
        return True
    # Anything else (bad pid text, odd errno) is dead unless the errno says EPERM.
    # Limit: a recycled pid looks alive, so a dead holder whose pid was reused is only reclaimed by its TTL.
    except (OSError, ValueError, TypeError) as e:
        return getattr(e, "errno", None) == errno.EPERM
    return True


# All comparisons use real paths so symlinks and .. segments cannot make two spellings of one file look different.
def _rp(p):
    """realpath shorthand."""
    return os.path.realpath(p)


# Locks live under <data root>/data/locks, separate from the files they protect.
def _locks_dir(root):
    """The folder that holds lock files for data root `root`."""
    return os.path.join(_rp(root), "data", "locks")


# Locks are keyed by the target's path RELATIVE to the data root, so the same file has one lock whichever
# spelling a caller uses.
# Hashing keeps lock file names short and free of path characters; SHA-1 is acceptable here because the digest
# is only a file name, never a security check.
def lock_path_for(path, root):
    """Lock file path for a target: a hash of its path relative to the data root (SHA-1 is only a file name here)."""
    rroot = _rp(root)
    # A path outside the root gets a ../ prefix here; the root check is done separately in check_in_root.
    rel = os.path.relpath(_rp(path), rroot)
    return os.path.join(rroot, "data", "locks", hashlib.sha1(rel.encode()).hexdigest() + ".lock")


# A lock file that cannot be parsed is reported as corrupt with pid -1, which counts as a dead holder.
# Lock records are plain JSON so an operator can read them with any tool.
def _read_lock(lp):
    """Parse a lock file: its dict, None if it does not exist, or {"corrupt": True, "pid": -1} if unreadable."""
    try:
        with open(lp) as f:
            rec = json.load(f)
        # RED-TEAM 5 (Rule 16): valid JSON that is not an object ([], "x", 3) used to crash every caller with AttributeError.
        return rec if isinstance(rec, dict) else {"corrupt": True, "pid": -1}
    # No lock file: the path is free.
    except FileNotFoundError:
        return None
    except (ValueError, OSError):
        return {"corrupt": True, "pid": -1}


# The lock file's modification time is its heartbeat: creation sets it, touch() renews it.
def _mtime(lp):
    """Modification time of a lock file (its heartbeat), or None if it is gone."""
    try:
        return os.stat(lp).st_mtime
    except OSError:
        return None


# Two independent reasons a lock may be taken over: the holder process is gone, or it stopped refreshing
# (touch) for longer than its own TTL.
def _stale_reason(holder, lp):
    """Why a lock may be reclaimed: "pid-dead", "ttl" (not refreshed within its TTL), or None if it is still valid."""
    if not pid_alive(holder.get("pid")):
        return "pid-dead"
    mt = _mtime(lp)
    # A record without a TTL falls back to five minutes.
    ttl = holder.get("ttl_s", 300)
    # RED-TEAM 5: a TTL that is not a finite number (a string, NaN, null) used to raise or never expire; it counts as the default.
    try:
        ttl = float(ttl)
        if ttl != ttl or ttl in (float("inf"), float("-inf")):
            ttl = 300.0
    except (TypeError, ValueError):
        ttl = 300.0
    if mt is not None and _clock() - mt > ttl:
        return "ttl"
    return None


# Atomic creation is the heart of the lock: exactly one of several simultaneous callers can link the file into place.
def _create(lp, rec):
    """Create the lock file with its full content or not at all: write a private temp file, then hard-link it into place.
    os.link fails with FileExistsError if someone else holds the lock, and a reader can never see a half-written record
    (an empty lock file would otherwise look like a dead holder and be reclaimed)."""
    # Build the complete record in a private temp file first (never visible as a lock because of its .new suffix).
    tmp = "%s.%s.new" % (lp, secrets.token_hex(6))
    # Mode 0600: only the owning user can read the record, which names agents and paths.
    fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        try:
            # One JSON object per lock, written in a single call and fsynced before it is linked into place.
            os.write(fd, json.dumps(rec).encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        # Hard-link into the final name: atomic, and it fails with FileExistsError if the lock already exists.
        os.link(tmp, lp)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


# Every takeover of a stale lock is written to an append-only log, so a lock that was taken from a live-but-slow
# holder can be investigated afterwards.
# The log is never rotated or deleted by this tool.
def _log_reclaim(root, reclaimer, holder, reason, heartbeat, lp):
    """Append one JSON line to reclaim.log.jsonl recording who took over which stale lock and why."""
    d = _locks_dir(root)
    os.makedirs(d, mode=0o700, exist_ok=True)
    # The log line names who took over, why, the old holder's record and when the old holder last refreshed the lock.
    line = {"at": _iso(), "reclaimer": reclaimer, "reason": reason, "holder": holder,
            "holder_last_heartbeat": _iso(heartbeat) if heartbeat else None, "lock": lp}
    fd = os.open(os.path.join(d, "reclaim.log.jsonl"), os.O_CREAT | os.O_APPEND | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, (json.dumps(line) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)


# Lock protocol, in order: (1) try to create the lock; (2) if it exists and is still valid, refuse;
# (3) if it is stale, take over, serialised by a guard file so two reclaimers cannot both win.
def acquire(path, agent_id, session, root, ttl_s=300):
    """Returns lock file path. Raises BlockedByLock. No retries."""
    # Record the real path in the lock so a human reading it knows exactly which file it protects.
    rpath = _rp(path)
    lp = lock_path_for(path, root)
    # The lock folder is private (0700) because lock records name paths and agents.
    os.makedirs(os.path.dirname(lp), mode=0o700, exist_ok=True)
    # The record this caller stores if it wins: its pid, session and agent, the real target path, the start time,
    # the TTL and this host's name.
    rec = {"pid": os.getpid(), "session": session, "agent_id": agent_id, "path": rpath,
           "acquired_at": _iso(), "ttl_s": ttl_s, "host": socket.gethostname()}
    try:
        _create(lp, rec)
        return lp
    # Someone holds the lock (or just took it). Fall through and inspect the holder.
    except FileExistsError:
        pass
    # Step 2: the lock exists. Look at who holds it.
    holder = _read_lock(lp)
    # The holder released between our failed create and this read; one more attempt, no loop.
    if holder is None:  # vanished between calls: single attempt to create
        try:
            _create(lp, rec)
            return lp
        except FileExistsError:
            holder = _read_lock(lp) or {}
            # Lost the one allowed retry: report the holder that beat us.
            raise BlockedByLock(rpath, holder)
    # Valid lock held by a live writer: refuse, never wait or retry (callers decide what to do).
    if _stale_reason(holder, lp) is None:
        raise BlockedByLock(rpath, holder)
    # stale: serialize reclaimers with a guard file
    # Step 3: stale. Only one process may reclaim at a time; the guard file is the mutex for that.
    guard = lp + ".reclaim"
    try:
        # O_EXCL: if another reclaimer holds the guard we back off and report BlockedByLock.
        gfd = os.open(guard, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        try:
            # A guard older than 30 seconds was abandoned by a crashed reclaimer: remove it so the next caller can
            # proceed.
            if _clock() - os.stat(guard).st_mtime > 30:
                os.unlink(guard)  # abandoned guard
        except OSError:
            pass
        raise BlockedByLock(rpath, holder)
    # We hold the guard; the descriptor itself is not needed, only the file's existence.
    os.close(gfd)
    try:
        # Re-read under the guard: the lock may have been released or re-acquired by someone else since we looked.
        holder2 = _read_lock(lp)
        # The lock changed under us; it is no longer the stale one we decided to take over.
        if holder2 is None or holder2 != holder:
            raise BlockedByLock(rpath, holder2 or holder)
        # Check staleness again with the fresh record (a heartbeat may have arrived).
        reason = _stale_reason(holder2, lp)
        if reason is None:
            raise BlockedByLock(rpath, holder2)
        # Log first, then delete: if we crash in between, the log still shows the takeover.
        _log_reclaim(root, {"pid": os.getpid(), "agent_id": agent_id, "session": session},
                     holder2, reason, _mtime(lp), lp)
        # Remove the stale lock and immediately create ours; FileExistsError here means a third writer won the race.
        os.unlink(lp)
        try:
            _create(lp, rec)
        except FileExistsError:
            raise BlockedByLock(rpath, _read_lock(lp) or {})
        return lp
    finally:
        try:
            os.unlink(guard)
        except OSError:
            pass


# Release is by path and agent; _release_lp does the work and is also used with a remembered lock path.
# Releasing a lock that is not ours returns False and changes nothing.
def release(path, agent_id, root):
    """Remove lock only if ours (pid + agent). Returns True if removed."""
    return _release_lp(lock_path_for(path, root), agent_id)


# Only the holder (same pid AND same agent id) may release, so one agent cannot drop another agent's lock.
def _release_lp(lp, agent_id):
    """Remove the lock file `lp` only if this process and agent hold it. Releasing by the lock path that acquire returned
    (not by re-resolving the target) keeps the lock from leaking if the target path changed meanwhile."""
    # Nothing to release, or the lock now belongs to someone else (it went stale and was reclaimed).
    h = _read_lock(lp)
    if not h or h.get("pid") != os.getpid() or h.get("agent_id") != agent_id:
        return False
    try:
        os.unlink(lp)
        return True
    except FileNotFoundError:
        return False


# A long-running writer calls this periodically so its lock does not expire while it is still working.
def touch(path, root):
    """Heartbeat: refresh the lock file's mtime so its TTL restarts; True if the lock exists. (Public API, used by long writers.)"""
    lp = lock_path_for(path, root)
    try:
        os.utime(lp, None)
        return True
    except OSError:
        return False


# Path validation: resolve both sides (symlinks, .., relative parts), then require the target to be inside the root.
# commonpath compares whole path components, so /data/root-evil is not mistaken for being inside /data/root.
def check_in_root(path, task_root):
    """Return the resolved path if it lies inside the resolved task root, else raise PathOutsideRoot."""
    resolved, rroot = _rp(path), _rp(task_root)
    try:
        # Different drives or mixing absolute and relative paths raise ValueError: treat as outside.
        inside = os.path.commonpath([resolved, rroot]) == rroot
    except ValueError:
        inside = False
    if not inside:
        raise PathOutsideRoot(resolved, rroot)
    return resolved


# After a rename the directory entry itself must be flushed for the rename to survive a crash.
def _fsync_dir(d):
    """Best-effort fsync of a directory (path or descriptor) so a rename survives a crash; errors are ignored."""
    try:
        # Already a descriptor: flush it directly.
        if isinstance(d, int):
            os.fsync(d)
            return
        # A path was given: open it read-only just to fsync it.
        fd = os.open(d, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


# Ask the kernel where an open descriptor really points. This is what makes the root check hold even if the
# path was swapped after validation: the answer comes from the descriptor, not from a path lookup.
def _fd_path(fd):
    """Real path of an open directory descriptor (macOS F_GETPATH, else Linux /proc/self/fd), or None if unavailable."""
    # macOS has F_GETPATH (command 50); Linux has no such fcntl but exposes /proc/self/fd/N.
    getpath = getattr(fcntl, "F_GETPATH", 50 if sys.platform == "darwin" else None)
    if getpath is not None:
        try:
            # The kernel fills a 1024-byte buffer with the NUL-terminated path.
            raw = fcntl.fcntl(fd, getpath, b"\0" * 1024)
            return os.path.realpath(os.fsdecode(raw.split(b"\0", 1)[0]))
        except (OSError, ValueError, TypeError):
            pass
    try:
        # Linux fallback. If neither works the caller skips the re-check (documented limit).
        return os.path.realpath(os.readlink("/proc/self/fd/%d" % fd))
    except OSError:
        return None


# Wrapper used for every create-relative-to-a-directory-descriptor in this module.
def _open_create_at(name, flags, mode, dfd):
    """os.open(name, flags | O_CREAT, mode, dir_fd=dfd) retried on ENOENT: on macOS simultaneous creation of the same name
    relative to a directory descriptor can fail with a spurious ENOENT. A directory that really vanished keeps failing and the
    last error is raised after 50 attempts."""
    # Bounded retry; a real ENOENT keeps failing and is raised on the last attempt.
    for attempt in range(50):
        try:
            return os.open(name, flags | os.O_CREAT, mode, dir_fd=dfd)
        except FileNotFoundError:
            if attempt == 49:
                raise
    raise AssertionError("unreachable")


# Open the target's folder safely and prove, from the descriptor, that it is inside the root.
def _open_dir_in_root(d, task_root):
    """Open directory `d` without following a final symlink and confirm, from the descriptor itself, that it is inside the
    task root. Returns the fd; raises PathOutsideRoot (closing the fd) if it moved outside after validation."""
    # O_NOFOLLOW makes a symlink at the last component an error instead of silently following it.
    fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    # None means this platform cannot tell; then only the earlier realpath check applies.
    where = _fd_path(fd)
    if where is not None:
        rroot = _rp(task_root)
        try:
            inside = os.path.commonpath([where, rroot]) == rroot
        except ValueError:
            inside = False
        # The folder is not where validation thought it was: close the descriptor and refuse the write.
        if not inside:
            os.close(fd)
            raise PathOutsideRoot(where, rroot)
    return fd


# Whole-file write, in order: validate the path, take the lock, pin the folder, write a temp file,
# rename it over the target, flush the folder entry, release the lock.
# The caller passes `root` when the lock folder should live somewhere other than under the task root.
def safe_write(path, data, task_root, agent_id, session, root=None, ttl_s=300, _hook=None):
    """Atomically write `data` to `path` (inside `task_root`) under a lock. Returns the resolved path.
    Raises PathOutsideRoot, BlockedByLock, or OSError (for example when the target became a symlink)."""
    # Step 1: validate against the root before anything is created.
    resolved = check_in_root(path, task_root)
    root = root or task_root
    # Text is encoded as UTF-8 (the Python default); bytes pass through unchanged.
    if isinstance(data, str):
        data = data.encode()
    # Step 2: take the lock. Remember its path so the release does not depend on re-resolving the target
    # (which an attacker may have changed meanwhile).
    lp = acquire(resolved, agent_id, session, root, ttl_s)
    try:
        # Test hook: lets a test hold the lock, or change the filesystem, at exactly this point.
        if _hook:
            _hook()
        # The target is split into its folder and its file name; from here the file name is used only relative to a
        # descriptor.
        d, name = os.path.dirname(resolved), os.path.basename(resolved)
        # Create missing parent folders. The path was validated above; makedirs itself follows symlinks in parts
        # that already exist (a documented TOCTOU limit).
        os.makedirs(d, exist_ok=True)  # inside root: validated above
        # Step 3: pin the folder; every step below is relative to this descriptor.
        dfd = _open_dir_in_root(d, task_root)       # pin the folder; every step below is relative to this descriptor
        try:
            # Step 4: write to a temp file beside the target (same filesystem) so the final rename is atomic.
            tmp = ".wg-" + secrets.token_hex(8) + ".tmp"
            # Exclusive and no-follow: a planted file or symlink under the temp name makes this fail.
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
            try:
                # Flush and fsync before the rename so a crash leaves either the old content or the complete new
                # content.
                with os.fdopen(fd, "wb") as f:
                    f.write(data)
                    f.flush()
                    os.fsync(f.fileno())
                # Step 5: atomic rename relative to the pinned folder.
                os.replace(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
            # On any failure remove the temp file, then re-raise.
            except BaseException:
                try:
                    os.unlink(tmp, dir_fd=dfd)
                except OSError:
                    pass
                raise
            # Make the rename itself durable.
            _fsync_dir(dfd)
        finally:
            os.close(dfd)
        return resolved
    finally:
        # Always release, whether the write succeeded or raised.
        _release_lp(lp, agent_id)


# Append one line under the same lock and root rules as safe_write. O_APPEND makes each write land at the end
# even if another program appends too, and O_NOFOLLOW refuses a symlink as the final component.
# Appends are not atomic across crashes beyond what O_APPEND gives: a power loss can leave a partial last line.
def safe_append(path, line, task_root, agent_id, session, root=None, ttl_s=300, _hook=None):
    """Append one newline-terminated line to `path` (inside `task_root`) under a lock; the file is opened with O_NOFOLLOW.
    Returns the resolved path. Raises PathOutsideRoot, BlockedByLock, or OSError."""
    resolved = check_in_root(path, task_root)
    root = root or task_root
    if isinstance(line, str):
        line = line.encode()
    # Every record ends with a newline so lines never run together.
    if not line.endswith(b"\n"):
        line += b"\n"
    lp = acquire(resolved, agent_id, session, root, ttl_s)
    try:
        if _hook:
            _hook()
        d, name = os.path.dirname(resolved), os.path.basename(resolved)
        os.makedirs(d, exist_ok=True)
        dfd = _open_dir_in_root(d, task_root)
        try:
            # 0644: log files are meant to be readable by the user's other tools.
            fd = _open_create_at(name, os.O_APPEND | os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK, 0o644, dfd)
            try:
                # RED-TEAM 5 (Rule 16): only a regular file with ONE name. A hard link inside the root to a file outside it
                # passes every path check (it is a different name for the same data) and the append would write through it;
                # a FIFO would block or feed another program.
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink > 1:
                    raise OSError(errno.EPERM, "not a regular file with a single name (hard link or special file)")
                os.write(fd, line)
                # Flush the appended data before releasing the lock.
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            os.close(dfd)
        return resolved
    finally:
        _release_lp(lp, agent_id)


# Read-only view for operators: every lock, who holds it, whether the holder is alive and whether it is stale.
# The "alive" flag and the stale reason are computed fresh on every call; nothing is cached.
def lock_status(root):
    """List the lock files under the data root as dicts: lock path, holder record, alive flag, stale reason, last heartbeat."""
    d = _locks_dir(root)
    out = []
    if os.path.isdir(d):
        for n in sorted(os.listdir(d)):
            # Only real lock files; .reclaim guards, .new temp files and the log are skipped.
            if n.endswith(".lock"):
                lp = os.path.join(d, n)
                h = _read_lock(lp)
                # Released between listing and reading.
                if h is None:
                    continue
                # One row per lock: lock file path, the holder's record, liveness, stale reason (or None) and last
                # heartbeat.
                out.append({"lock": lp, "holder": h, "alive": pid_alive(h.get("pid")),
                            "stale_reason": _stale_reason(h, lp), "last_heartbeat": _iso(_mtime(lp))})
    return out


# Operator command: remove every lock whose holder is dead or expired, with the same guard-file protocol as acquire.
# Safe to run from a scheduler: locks held by live, unexpired writers are never removed.
def reclaim_stale(root, agent_id="reclaim-cli", session=None):
    """Remove every stale lock under the data root (logging each); returns [{"lock": path, "reason": why}]."""
    done = []
    for st in lock_status(root):
        # Valid locks are never touched.
        if not st["stale_reason"]:
            continue
        lp = st["lock"]
        # Serialise with any other reclaimer working on the same lock.
        guard = lp + ".reclaim"
        try:
            gfd = os.open(guard, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            continue
        os.close(gfd)
        try:
            # Re-read under the guard and re-check staleness before deleting.
            h = _read_lock(lp)
            reason = _stale_reason(h, lp) if h else None
            if reason:
                _log_reclaim(root, {"pid": os.getpid(), "agent_id": agent_id, "session": session},
                             h, reason, _mtime(lp), lp)
                os.unlink(lp)
                # Report what was removed and why, for the operator's records.
                done.append({"lock": lp, "reason": reason})
        finally:
            try:
                os.unlink(guard)
            except OSError:
                pass
    return done


# Hold hooks exist so tests can make a lock holder wait for an event instead of sleeping a guessed time.
# Never set these in production: they make every write wait.
def _hold_hook():
    """Test hooks that keep a lock held: WRITE_GUARD_HOLD_S (seconds) and/or WRITE_GUARD_HOLD_FILE (hold while that file
    exists, up to 60 s). Empty or invalid values mean no hold. Returns a callable or None."""
    try:
        hold = float(os.environ.get("WRITE_GUARD_HOLD_S") or 0)
    except ValueError:
        hold = 0.0
    # An empty value is the same as unset.
    hold_file = os.environ.get("WRITE_GUARD_HOLD_FILE") or ""
    if not hold and not hold_file:
        return None

    # Runs inside the lock: first the optional fixed delay, then (if configured) wait until the hold file disappears.
    def hook():
        """Hold the lock for the configured time, then until the hold file is removed."""
        if hold:
            _sleep(hold)
        if hold_file:
            # Safety cap: a forgotten hold file must not wedge a process forever.
            deadline = _clock() + 60
            while os.path.exists(hold_file) and _clock() < deadline:
                _sleep(0.01)
    return hook


# Sub-commands: write and append take a task root and an agent id; lock-status and reclaim-stale take the data root.
# Exit statuses are stable and documented in the module docstring so wrappers can rely on them.
def main(argv=None):
    """Command line entry; returns the exit status (0 ok, 2 refused or unsafe path, 75 blocked by a lock)."""
    # Standard argparse CLI; every option is documented in the module docstring.
    ap = argparse.ArgumentParser(prog="write_guard.py")
    # One sub-command per action; argparse rejects anything else with exit status 2.
    sub = ap.add_subparsers(dest="cmd", required=True)
    # write and append share all their options.
    for name in ("write", "append"):
        p = sub.add_parser(name)
        # The target file to write.
        p.add_argument("--path", required=True)
        # The folder the target must stay inside.
        p.add_argument("--task-root", required=True)
        # Who is writing: recorded in the lock so a blocked caller can see the holder.
        p.add_argument("--agent", required=True)
        p.add_argument("--session", default=None)
        # Where data/locks lives; defaults to the task root.
        p.add_argument("--root", default=None)
        p.add_argument("--data-file", default="-")
        # Seconds after which an un-refreshed lock may be reclaimed.
        p.add_argument("--ttl", type=float, default=300)
    # The two operator commands only need the data root.
    for name in ("lock-status", "reclaim-stale"):
        p = sub.add_parser(name)
        p.add_argument("--root", required=True)
        p.add_argument("--agent", default="reclaim-cli")
    a = ap.parse_args(argv)
    try:
        if a.cmd in ("write", "append"):
            # Content comes from standard input unless a file is named.
            if a.data_file == "-":
                data = sys.stdin.buffer.read()
            else:
                with open(a.data_file, "rb") as f:
                    data = f.read()
            # Only set by the test environment variables; None in normal use.
            hook = _hold_hook()
            fn = safe_write if a.cmd == "write" else safe_append
            res = fn(a.path, data, a.task_root, a.agent, a.session, a.root, a.ttl, _hook=hook)
            # Success line: the action and the resolved path that was written.
            print("OK %s %s" % (a.cmd, res))
        elif a.cmd == "lock-status":
            # Machine-readable output for scripts and for humans.
            print(json.dumps(lock_status(a.root), indent=1))
        else:
            print(json.dumps(reclaim_stale(a.root, a.agent), indent=1))
        return 0
    # Exit 2: the request itself was wrong (outside the declared root).
    except PathOutsideRoot as e:
        print("REFUSED write: resolved=%s declared_root=%s" % (e.resolved, e.declared_root), file=sys.stderr)
        return 2
    # Exit 75 (EX_TEMPFAIL): another writer is active; try again later. No retry loop here by design.
    except BlockedByLock as e:
        print("BLOCKED-BY-LOCK " + _blocked_line(e.path, e.holder), file=sys.stderr)
        return 75
    # Anything the descriptor-based checks refuse (a symlinked target, a vanished folder) is also exit 2,
    # with a one-line message instead of a traceback.
    except OSError as e:
        print("write_guard: REFUSED, unsafe or unwritable path (%s)" % (e.strerror or type(e).__name__), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
