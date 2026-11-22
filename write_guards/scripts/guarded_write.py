#!/usr/bin/env python3
"""guarded_write: optimistic locking for shared files (compare-and-swap on the file's SHA-256). Stdlib only, local only.

Advisory locks and claims do not stop another writer. This is the enforcement a writer can opt into:

  guarded_write.py hash PATH                      print the SHA-256 of PATH (record it when you READ the file)
  guarded_write.py write PATH --expect SHA        replace PATH with stdin, but ONLY if PATH still hashes to SHA
  guarded_write.py write PATH --expect-missing    create PATH, but ONLY if it does not exist

Exit 0 written | 3 CONCURRENT MODIFICATION (file changed since you read it; nothing written; re-read, re-apply, retry) | 2 bad use.
The compare and the replace happen under one per-file exclusive lock, and the replace is atomic (temp file + rename), so of two
writers holding the same expected hash exactly one succeeds. Limit, stated plainly: it only protects writers that call it. An
editor or script that writes the file directly is not stopped; that needs an OS permission or an editor hook.

WHERE THE LOCK FILES LIVE: not beside the target. They are in one per-user folder,
$TWU_WRITE_LOCK_DIR if set (non-empty), else $XDG_STATE_HOME/twu-write-locks (absolute value only), else ~/.local/state/twu-write-locks.
The folder is created with mode 0700 and, on every use, must be a real directory (not a symlink) owned by you, else the write
is refused. Lock files in it are mode 0600, named by a hash of the target's resolved path, and opened without following symlinks.
The only other files written are a temp file beside the target (".gw-<random>", renamed over the target or removed).

Path handling is fd-based where it can be: the target's parent directory is opened once (O_DIRECTORY | O_NOFOLLOW, after
realpath) and the existence check, hash, temp file creation and rename are all done relative to that directory descriptor, and
the target itself is opened with O_NOFOLLOW. Remaining TOCTOU, stated honestly: realpath() of the parent happens before the
directory is opened, so a process that can swap a directory in the path in that instant can redirect the write; and a hostile
writer who can already write in the target's folder can still replace the file between our checks. This guards against
accidents between cooperating writers, not against an attacker who shares the folder.
"""
# Annotations are not evaluated at import, so `str | None` in signatures also works on Python 3.9.
from __future__ import annotations

# Standard library only. fcntl gives flock (the per-file lock); hashlib the SHA-256 compare;
# secrets a random temp-file name; stat the file-type and mode checks.
import fcntl
import hashlib
import os
import secrets
import stat
import sys
from pathlib import Path


# Raised (and mapped to exit status 3) when the compare step fails: someone else changed the file.
# Design note: this is optimistic locking. Readers take no lock; only the short compare-and-replace is
# serialised, so a slow editor never blocks other readers.
class ConcurrentModification(Exception):
    """The file's content is no longer the content the writer read."""


def sha256_of(path) -> str | None:
    """SHA-256 hex of the file at `path` (a symlink is followed, this is a read), or None if it does not exist."""
    # Missing file: there is nothing to hash. Callers treat None as "does not exist".
    p = Path(path)
    if not p.exists():
        return None
    return hashlib.sha256(p.read_bytes()).hexdigest()


# Public so tests and operators can see exactly which folder is used (the README lists the same rules).
def lock_dir_path() -> str:
    """Where lock files live: env TWU_WRITE_LOCK_DIR, else $XDG_STATE_HOME/twu-write-locks, else ~/.local/state/twu-write-locks.
    Empty values count as unset, and a relative XDG_STATE_HOME is ignored (as the XDG specification says)."""
    # Order of precedence: explicit override, then the XDG state directory, then ~/.local/state.
    # An exported-but-empty variable is treated as unset (the example env file exports empty strings).
    explicit = os.environ.get("TWU_WRITE_LOCK_DIR") or ""
    if explicit:
        # RED-TEAM 5 (Rule 16): a RELATIVE value meant a different folder for every caller's current directory, so two writers
        # of one file could take two different locks and both pass the compare. Refused, like a relative XDG_STATE_HOME.
        if not os.path.isabs(explicit):
            raise ValueError("refusing TWU_WRITE_LOCK_DIR %r: it must be an absolute path (a relative one splits the lock "
                             "between callers in different folders)" % explicit)
        return explicit
    # The XDG specification says a relative XDG_STATE_HOME must be ignored.
    base = os.environ.get("XDG_STATE_HOME") or ""
    if not base or not os.path.isabs(base):
        base = os.path.join(os.path.expanduser("~"), ".local", "state")
    return os.path.join(base, "twu-write-locks")


def _open_lock_dir() -> int:
    """Create (mode 0700) if needed and open the per-user lock directory; return its fd. Refuses a symlink, a non-directory,
    or a directory owned by someone else. Our own directory with looser permissions is tightened to 0700."""
    # Step 1: make sure the parent exists. Its permissions are not ours to decide, only the leaf folder is private.
    d = lock_dir_path()
    # Races between two first-time callers are harmless: exist_ok makes the second makedirs a no-op.
    os.makedirs(os.path.dirname(d) or ".", exist_ok=True)           # parents get default modes; only the leaf is ours to protect
    try:
        # Create the leaf with mode 0700. mkdir does not follow a symlink at the leaf and fails if it exists,
        # so a planted symlink is detected by the open below, not silently reused.
        os.mkdir(d, 0o700)
    except FileExistsError:
        pass
    try:
        # Step 2: open the leaf as a directory without following a symlink. From here on we work with the descriptor,
        # not the path, so the checks below apply to the thing we actually hold.
        fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)   # ELOOP if the last component is a symlink
    except OSError as exc:
        raise ValueError("refusing lock directory %s: cannot open it as a real directory (%s)" % (d, exc.strerror)) from exc
    # Step 3: verify what we opened. It must be a directory and it must belong to us: in a shared temp folder
    # another user could have created the path first, and we must not put our locks in their directory.
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        os.close(fd)
        # A refusal is an error, not a fallback: silently using another folder would split the lock between two
        # places.
        raise ValueError("refusing lock directory %s: not a directory owned by this user" % d)
    # Our own directory but group/other accessible (for example an old umask): tighten it rather than refuse.
    if info.st_mode & 0o077:
        os.fchmod(fd, 0o700)
    return fd


def _lock_name(parent_real: str, name: str) -> str:
    """File name of the lock for one target: a hash of its resolved path, so two spellings of one file share a lock."""
    # Hash of the resolved path, shortened to 32 hex characters: unique enough for a lock name, and it
    # keeps the real path (which may be private) out of the folder listing.
    return hashlib.sha256(os.path.join(parent_real, name).encode()).hexdigest()[:32] + ".lock"


def _open_create_at(name: str, flags: int, mode: int, dfd: int) -> int:
    """os.open(name, flags | O_CREAT, mode, dir_fd=dfd), retried on ENOENT. On macOS two processes or threads creating the same
    name relative to a directory descriptor at the same moment can see a spurious ENOENT (observed: about half of simultaneous
    first-time creations); the directory still exists, so a retry succeeds. A directory that really vanished keeps failing and
    the last error is raised after 50 attempts."""
    # Bounded retry: the spurious ENOENT disappears on the next try, a real one persists and is raised.
    for attempt in range(50):
        try:
            return os.open(name, flags | os.O_CREAT, mode, dir_fd=dfd)
        except FileNotFoundError:
            if attempt == 49:
                raise
    # Unreachable: the loop either returns or raises on the last attempt. Present so the function has no implicit
    # None.
    raise AssertionError("unreachable")


def _open_lock(parent_real: str, name: str) -> int:
    """Open (creating, mode 0600) the lock file for the target and return its fd; refuse symlinks and foreign owners."""
    # The lock folder is opened (and verified) every time: its identity is never cached between calls.
    dfd = _open_lock_dir()
    try:
        # O_NOFOLLOW: if a symlink was planted under the lock name, the open fails instead of following it.
        fd = _open_create_at(_lock_name(parent_real, name), os.O_RDWR | os.O_NOFOLLOW, 0o600, dfd)
    except OSError as exc:
        raise ValueError("refusing lock file in %s: %s" % (lock_dir_path(), exc.strerror)) from exc
    finally:
        os.close(dfd)
    # Re-verify the lock file itself: regular file, owned by us (it could have been created by another user
    # if the folder permissions were ever too open).
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
        os.close(fd)
        raise ValueError("refusing lock file in %s: not a regular file owned by this user" % lock_dir_path())
    return fd


# Used by write_if_unchanged for the compare step; kept separate so tests can interpose between hash and write.
def _hash_at(dfd: int, name: str) -> str | None:
    """SHA-256 of `name` inside directory fd `dfd`, opened without following a symlink; None if it does not exist."""
    try:
        # Open relative to the pinned directory and refuse a symlink at the final component (ELOOP).
        # RED-TEAM 5: O_NONBLOCK, because opening a FIFO read-only blocks until a writer appears, and this runs while the
        # per-file lock is held (a FIFO planted at the target name wedged every writer). The type check below then refuses it.
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ValueError("refusing to write through a symlink or unreadable file: %s (%s)" % (name, exc.strerror)) from exc
    try:
        # A FIFO, device or directory at the target is refused: hashing it could block or be meaningless.
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("refusing to write over something that is not a regular file: %s" % name)
        # Hash in 1 MiB chunks from a duplicate descriptor so big files do not have to fit in memory and the
        # descriptor we checked is the one that is read.
        digest = hashlib.sha256()
        with os.fdopen(os.dup(fd), "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                digest.update(chunk)
        return digest.hexdigest()
    finally:
        os.close(fd)


def write_if_unchanged(path, data: bytes, expected_sha256: str | None) -> str:
    """Write `data` to `path` iff it still hashes to `expected_sha256` (None = must not exist). Returns the new SHA-256.
    Raises ConcurrentModification on a mismatch, ValueError for a symlink or unsafe lock folder, OSError otherwise."""
    p = Path(path)
    # A path such as "/", ".." or "" has no file name to write.
    if not p.name or p.name in (".", ".."):
        raise ValueError("not a file path: %s" % p)
    # The only path-based step: resolve the folder once. Everything after this uses descriptors.
    # A process able to swap a folder in the path at exactly this instant can still redirect the write (documented
    # limit).
    parent_real = os.path.realpath(p.parent)          # step 1: resolve the folder once (see the TOCTOU note in the docstring)
    # The lock is per target file and exclusive; it lives in the private per-user folder, not beside the target.
    lock_fd = _open_lock(parent_real, p.name)         # step 2: per-file exclusive lock held until the end
    try:
        # Blocks until any other holder is done. The lock is released when lock_fd is closed in the outer finally.
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        # Pin the target's folder by descriptor (no symlink at the last component). All remaining file operations
        # are relative to dfd, so renaming or swapping the folder path afterwards cannot move them.
        dfd = os.open(parent_real, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)   # step 3: pin the folder by descriptor
        try:
            try:
                # lstat (not stat): look at the directory entry itself, so a symlink is seen as a symlink.
                before = os.lstat(p.name, dir_fd=dfd)
            except FileNotFoundError:
                before = None
            # Writing through a symlink would modify a different file than the one the caller hashed.
            if before is not None and stat.S_ISLNK(before.st_mode):
                raise ValueError("refusing to write through a symlink: %s" % p)
            # The compare half of compare-and-swap: hash what is on disk right now, under the lock.
            current = _hash_at(dfd, p.name)           # step 4: compare under the lock
            if current != expected_sha256:
                raise ConcurrentModification("%s changed since it was read (expected %s, found %s); nothing written"
                                             % (p, (expected_sha256 or "missing")[:12], (current or "missing")[:12]))
            # Keep the existing permission bits (including exec); a new file gets 0644.
            mode = stat.S_IMODE(before.st_mode) if before is not None else 0o644
            # The swap half: write the new content to a temp file in the same folder (same filesystem, so the rename
            # is atomic).
            tmp = ".gw-" + secrets.token_hex(8)       # step 5: write a temp file in the same folder, then rename over the target
            # O_EXCL | O_NOFOLLOW: the temp name must be new; a pre-planted file or symlink makes this fail instead of
            # being used.
            tfd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
            try:
                # Write, flush and fsync before the rename so a crash leaves either the old file or the complete new
                # one.
                with os.fdopen(tfd, "wb") as fh:
                    fh.write(data)
                    fh.flush()
                    os.fsync(fh.fileno())
                    # Set the final permissions on the descriptor before the rename, so the file is never visible with
                    # the wrong mode.
                    os.fchmod(fh.fileno(), mode)
                # Atomic: readers see the old file or the new one, never a mixture. Source and destination are both
                # relative to dfd, so the rename cannot leave the folder we pinned.
                os.replace(tmp, p.name, src_dir_fd=dfd, dst_dir_fd=dfd)
            # Any failure, including KeyboardInterrupt: do not leave the temp file behind, then re-raise.
            except BaseException:
                try:
                    os.unlink(tmp, dir_fd=dfd)
                except OSError:
                    pass
                raise
            # Return the hash of what was written so the caller can chain the next compare-and-swap without re-
            # reading.
            return hashlib.sha256(data).hexdigest()
        finally:
            os.close(dfd)
    finally:
        os.close(lock_fd)     # closing releases the flock


def main(argv=None) -> int:
    """Command line entry: hash | write; returns the exit status (0 written, 3 conflict, 2 bad use or refusal)."""
    # Arguments are parsed by hand: three fixed shapes only, anything else prints the usage text and exits 2.
    a = list(sys.argv[1:] if argv is None else argv)
    try:
        if len(a) == 2 and a[0] == "hash":
            # `hash` prints the digest to record when reading the file, or the word "missing".
            print(sha256_of(a[1]) or "missing")
            return 0
        if len(a) == 4 and a[0] == "write" and a[2] == "--expect":
            expected = a[3]
        elif len(a) == 3 and a[0] == "write" and a[2] == "--expect-missing":
            expected = None
        else:
            print(__doc__, file=sys.stderr)
            return 2
        # The new content comes from standard input as raw bytes; the new digest is printed on success.
        print(write_if_unchanged(a[1], sys.stdin.buffer.read(), expected))
        return 0
    # Exit 3 is the "someone else wrote first" signal; the caller should re-read, re-apply and retry.
    except ConcurrentModification as exc:
        print("CONCURRENT MODIFICATION: %s" % exc, file=sys.stderr)
        return 3
    # Symlink targets, unsafe lock folders and I/O problems are refusals (exit 2), not conflicts.
    except (OSError, ValueError) as exc:
        print("guarded_write: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
