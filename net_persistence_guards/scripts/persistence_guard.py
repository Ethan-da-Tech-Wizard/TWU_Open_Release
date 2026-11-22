#!/usr/bin/env python3
"""persistence_guard: alarm when something new sets itself up to survive a reboot or steal a login. No root, no model, no network.

  persistence_guard.py learn    accept the current state as the baseline
  persistence_guard.py show     print "digest  path" for every watched item (to fill the opt-in exemption file)
  persistence_guard.py check    compare to baseline; write data/netguard/PERSIST.<host>.json; exit 1 on findings

Watches the places malware and bad installers use: shell startup files, ssh authorized_keys/config, autostart entries,
user systemd units, ~/.local/bin, environment.d, cron files, /etc/ld.so.preload, /etc/systemd/system, and /etc/profile.d. Stores content hashes when readable;
for permission-denied regular files, stores a metadata fingerprint (device, inode, mode, size, mtime and ctime), never contents.

No item is exempt by name. The only way to silence a finding is the opt-in exemption file (env TWU_PERSIST_EXEMPT_FILE), where
each entry binds one exact path to one exact content digest; a changed file under an exempt name alarms again.
"""
# Overview of the flow, so the file can be read top to bottom:
#   1. constants and the list of watched places (PATTERNS)
#   2. helpers that run system tools and hash files without trusting PATH
#   3. snapshot(): expand the patterns on disk into {path: digest}
#   4. compare(): turn the difference between baseline and snapshot into findings
#   5. learn / learn_only / check: the commands that read or write the baseline and the receipt
#   6. main(): the command line
#
# Design decisions worth knowing before changing anything:
#   * Metadata and hashes only. File contents are never stored, so a baseline or receipt cannot leak a key
#     that happens to sit in a watched file (an authorized_keys line, an rc file with a token).
#   * Fail loudly. Anything that stops the scan from seeing every watched item (a directory that cannot be
#     listed, a file that cannot be read) raises GuardUnavailable and is reported as a finding. The guard
#     never turns "I could not look" into "nothing changed".
#   * No name-based trust. An earlier design treated units with certain prefixes as harmless. Any program can
#     choose its own file name, so a name proves nothing; trust now has to name a path AND a content digest.
#   * Same-user limits. This runs as the user it watches, so malware running as that user can also edit the
#     baseline, the receipt or this script. It catches mistakes, installers and unsophisticated persistence,
#     not a determined attacker with the same privileges (see SECURITY.md).
#   * Exit status: 0 clean, 1 findings (or an incomplete scan), 2 usage error. Schedulers must treat 1 as
#     "look at the output", not as "the job crashed".
from __future__ import annotations
import fnmatch, glob, hashlib, json, os, socket, stat, sys, time
from pathlib import Path

# ROOT is where data/ is read and written: the folder above scripts/ unless env TWU_ROOT is set. The
# `or` (not a get() default) matters: an exported but empty TWU_ROOT must fall back to the default.
ROOT = Path(os.environ.get("TWU_ROOT") or Path(__file__).resolve().parent.parent)
# Baseline and receipt files live here, one pair per host name.
DIR = ROOT / "data" / "netguard"
# Only the short host name is used, so "box.local" and "box" share files.  leakguard:allow
HOST = socket.gethostname().split(".")[0]
# TWU_PERSIST_HOME lets tests and cautious users point the scan at another home folder. Empty means "unset".
HOME = Path(os.environ.get("TWU_PERSIST_HOME") or Path.home())

# Raised whenever the scan cannot be trusted to be complete. check() converts it into a persisted
# "persist:sensor-unavailable" finding; learn() lets it abort so a half-seen state is never saved as a baseline.
class GuardUnavailable(RuntimeError):
    """The persistence scan could not inspect every item it found."""


# Places that can run code at login, boot or ssh time. A relative pattern is taken from HOME; an absolute one is used as is.
# A "*" matches one path component. Adding a place here is enough to start watching it.
PATTERNS = [
    # shell and X session startup files in the home folder
    ".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc", ".zprofile", ".zshenv", ".xprofile", ".xinitrc", ".pam_environment",
    # RED-TEAM 5: login/logout scripts, git config (core.fsmonitor/hooksPath run programs), ssh login environment, fish conf.d,
    # systemd drop-in folders (ExecStart overrides), and system-wide files the first list missed.
    ".zlogin", ".zlogout", ".bash_logout", ".gitconfig", ".config/git/config", ".ssh/environment", ".config/fish/conf.d/*",
    ".config/systemd/user/*.d/*.conf", "/etc/zshrc", "/etc/zprofile", "/etc/zshenv", "/etc/sudoers", "/etc/sudoers.d/*",
    "/etc/rc.loca[l]", "/etc/ssh/sshd_config.d/*", "/etc/systemd/system/*.d/*.conf",
    # ssh: who may log in (authorized_keys) and what runs on login (rc, config ProxyCommand)
    ".ssh/authorized_keys", ".ssh/authorized_keys2", ".ssh/config", ".ssh/rc",
    # desktop autostart and user-level systemd units
    ".config/autostart/*", ".config/systemd/user/*.service", ".config/systemd/user/*.timer", ".config/systemd/user/*.path",
    ".config/systemd/user/*.socket", ".config/systemd/user/*.target.wants/*", ".config/environment.d/*", ".config/fish/config.fish",
    # user binaries that are usually first on PATH, and KDE session hooks
    ".local/bin/*", ".config/plasma-workspace/env/*", ".config/plasma-workspace/shutdown/*", ".config/autostart-scripts/*",
    # system-wide hooks (read-only for a normal user, but still worth noticing when they change)
    "/etc/ld.so.preload", "/etc/profile", "/etc/profile.d/*", "/etc/bash.bashrc", "/etc/cron*/*", "/etc/cron.deny", "/etc/crontab",
    "/etc/systemd/system/*.service", "/etc/systemd/system/*.timer", "/etc/systemd/system/*.wants/*", "/etc/pam.d/*", "/etc/ssh/sshd_config",
    # macOS launchd job folders: per-user, all users, and daemons
    "Library/LaunchAgents/*", "/Library/LaunchAgents/*", "/Library/LaunchDaemons/*",
]


# The only folders external tools are taken from. PATH is deliberately not consulted: a user-writable PATH entry
# (such as ~/.local/bin, which this very guard watches) could otherwise replace a tool and feed the guard a clean answer.
TRUSTED_DIRS = ("/bin", "/usr/bin", "/sbin", "/usr/sbin")


# RED-TEAM 5 (Rule 16): a tool file owned by uid 65534 ("nobody") was accepted as "root-owned" everywhere. That uid is what root
# looks like INSIDE an unprivileged user namespace, so it is trusted only when this process really is in one (the uid map is not
# the identity map). On an ordinary host a file owned by nobody is refused again.
UID_MAP = "/proc/self/uid_map"


def _trusted_owner(uid):
    """True for uid 0, or for uid 65534 only inside an unprivileged user namespace (uid map other than '0 0 4294967295')."""
    if uid == 0:
        return True
    if uid != 65534:
        return False
    try:
        with open(UID_MAP) as fh:
            rows = [ln.split() for ln in fh.read().splitlines() if ln.strip()]
    except OSError:
        return False
    return bool(rows) and rows != [["0", "0", "4294967295"]]


def trusted_command(name):
    """Absolute path of a system tool found only in TRUSTED_DIRS (never via PATH); raises GuardUnavailable if absent or unsafe."""
    # Folder order matters only when a tool exists in more than one place; the first acceptable one wins.
    for d in TRUSTED_DIRS:
        cand = os.path.join(d, name)
        # A missing candidate is normal (the tool lives in one of several folders); try the next folder.
        try:
            st = os.stat(cand)
        except OSError:
            continue
        # Accept only a regular, executable file owned by root (or unprivileged user namespace mapping 65534) that nobody else can write.
        if stat.S_ISREG(st.st_mode) and os.access(cand, os.X_OK) and _trusted_owner(st.st_uid) and not st.st_mode & 0o022:
            return cand
    raise GuardUnavailable(f"required command {name} not found as a root-owned file in {', '.join(TRUSTED_DIRS)}")


# RED-TEAM 5 (Rule 16): the baseline, the learn temp file and the receipt used to be written with write_text(), which follows a
# symlink planted at that name (for example one that arrived through a synced folder) and overwrites its target. This writer
# removes whatever is at the temp name, creates it exclusively without following links, then renames it into place.
def _write_nofollow(path, text, mode=0o600):
    """Atomically write `text` to `path` through a freshly created temp file (O_EXCL | O_NOFOLLOW); never writes through a symlink."""
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    if tmp.is_symlink() or tmp.exists():
        tmp.unlink()
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.write(fd, text.encode())
    finally:
        os.close(fd)
    os.replace(tmp, path)


# digest() reduces one path to a comparable string. Three outcomes, in order of strength:
#   16 hex characters   the file was readable and this is a prefix of its sha256
#   "link:<target>"     a symbolic link, compared by where it points
#   "metadata:<hash>"   unreadable file; only size, times and inode are fingerprinted (weaker, always alarmed)
def digest(p):
    """Return a short fingerprint of one watched path: sha256 prefix, "link:<target>", "metadata:<hash>", or None for a directory."""
    try:
        # A symlink is fingerprinted by its target text, so swapping the target changes the value without following it.
        if os.path.islink(p):
            target = os.readlink(p)
            # RED-TEAM 5 (Rule 16): a link used to be fingerprinted by its target TEXT only, so editing the file the link points to
            # (a dotfiles repo behind ~/.zshrc is common) was invisible. The target's content hash is part of the value now.
            try:
                th = hashlib.sha256()
                with open(p, "rb") as f:
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        th.update(chunk)
                return "link:%s|%s" % (target, th.hexdigest()[:16])
            except OSError:
                return "link:" + target      # dangling, a folder, or unreadable: the target text is all there is
        # Directories are only containers; their entries are matched by the patterns instead.
        if os.path.isdir(p):
            return None
        # Hash in 1 MiB chunks so a large file never has to fit in memory. 16 hex characters (64 bits) are enough
        # to notice an edit; this is change detection, not a signature.
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()[:16]
    except PermissionError:
        # Some security-sensitive root-owned files (Fedora's sshd_config is
        # mode 0600) are intentionally unreadable to this unprivileged sensor.
        # Preserve change detection without reading contents or running the
        # repository scanner as root. This weaker coverage is always alarmed.
        try:
            st = os.stat(p, follow_symlinks=False)
        except OSError as exc:
            raise GuardUnavailable(f"could not inspect unreadable watched item {Path(p).name} ({type(exc).__name__})") from exc
        return _metadata_digest(st)
    except OSError as exc:
        # Any other read failure means the scan would be incomplete, so stop instead of recording a partial baseline.
        raise GuardUnavailable(f"could not read watched item {Path(p).name} ({type(exc).__name__})") from exc


def _metadata_digest(st):
    """Stable file metadata hash; omit uid/gid because systemd can id-map them in the unit namespace."""
    # These six fields change when the file is replaced or edited, even if its contents could not be read.
    fields = (st.st_dev, st.st_ino, st.st_mode, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
    # JSON with fixed separators gives one canonical byte string for the tuple, so the hash is reproducible.
    h = hashlib.sha256(json.dumps(fields, separators=(",", ":")).encode()).hexdigest()[:16]
    return "metadata:" + h


def _glob_checked(pattern):
    """Expand a glob pattern component by component; a directory that exists but cannot be listed raises GuardUnavailable."""
    # Plain glob.glob() would treat an unreadable directory as "no match" and so as a clean result. Walking the
    # components ourselves lets us tell "nothing there" (fine) from "could not look" (an incomplete scan).
    # Split the pattern into components. For an absolute pattern the root ("/") is the starting point and is
    # not matched against anything; for a relative one the walk starts at the current directory (snapshot()
    # always joins relative patterns to the home folder first, so that case is only used by tests).
    path = Path(pattern)
    parts = path.parts[1:] if path.is_absolute() else path.parts
    candidates = [Path(path.anchor)] if path.is_absolute() else [Path()]
    # Each loop turn narrows the set of candidate paths by one more component of the pattern.
    for part in parts:
        next_candidates = []
        for parent in candidates:
            if glob.has_magic(part):
                # Wildcard component: list the parent directory and keep the names that match.
                # The error handling below is deliberate: a missing directory is simply "no match", but a directory that
                # exists and cannot be listed is reported, because it could be hiding a new startup item.
                try:
                    with os.scandir(parent) as entries:
                        names = [entry.name for entry in entries]
                except FileNotFoundError:
                    continue
                except NotADirectoryError:
                    # Broad patterns such as /etc/cron*/* also match files (for
                    # example /etc/cron.deny) before their final path component.
                    continue
                except OSError as exc:
                    raise GuardUnavailable(f"could not enumerate watched directory {parent.name or parent} ({type(exc).__name__})") from exc
                for name in names:
                    # Like a shell, a "*" does not match dot-files unless the pattern itself starts with a dot.
                    if name.startswith(".") and not part.startswith("."):
                        continue
                    if fnmatch.fnmatchcase(name, part):
                        next_candidates.append(parent / name)
            else:
                # Literal component: it either exists or the branch ends here.
                candidate = parent / part
                try:
                    candidate.lstat()
                except FileNotFoundError:
                    continue
                except OSError as exc:
                    raise GuardUnavailable(f"could not inspect watched path {candidate.name} ({type(exc).__name__})") from exc
                next_candidates.append(candidate)
        candidates = next_candidates
        # Nothing left to extend: stop early instead of walking the remaining components.
        if not candidates:
            break
    return candidates


# snapshot() is the only place that touches the watched files. It is a pure read: no file is created,
# modified or opened for writing, which is why `check` can run unattended every few minutes.
def snapshot(home=None, patterns=None):
    """Return {display path: digest} for everything the patterns match; paths under home are shown as "~/..."."""
    # A home passed in (tests) wins over the module default, which in turn comes from TWU_PERSIST_HOME.
    home = Path(home or HOME)
    patterns = PATTERNS if patterns is None else patterns
    out = {}
    # Sorting the matches of each pattern keeps the snapshot (and so the baseline file) stable between runs.
    for pat in patterns:
        # Absolute patterns stand alone; relative ones hang off the home folder.
        full = pat if pat.startswith("/") else str(home / pat)
        for match in sorted(_glob_checked(full)):
            p = str(match)
            d = digest(p)
            # digest() is None for directories, which are skipped.
            if d:
                # Store "~" instead of the real home so a baseline is readable and does not embed the user name.
                out[p.replace(str(home), "~", 1) if p.startswith(str(home)) else p] = d
    return out


def load_exemptions(path=None):
    """Return {watched path: content digest} from the opt-in exemption file; {} when no file is configured."""
    # `or` semantics: an empty TWU_PERSIST_EXEMPT_FILE means "no exemption file", never "the current directory".
    path = path if path is not None else os.environ.get("TWU_PERSIST_EXEMPT_FILE")
    if not path:
        return {}
    # A file that was asked for but cannot be trusted must raise, not silently exempt nothing or everything:
    # the caller turns that into a visible "sensor-unavailable" alarm.
    try:
        # Expected file shape: {"exempt": [{"path": "~/.config/systemd/user/x.service", "digest": "<from `show`>"}]}
        data = json.loads(Path(path).read_text())
        out = {}
        for e in data["exempt"]:
            # Reject entries with a missing or empty digest: an empty digest could otherwise match nothing or everything by accident.
            if not isinstance(e["path"], str) or not isinstance(e["digest"], str) or not e["digest"]:
                raise ValueError("entry needs string path and digest")
            out[e["path"]] = e["digest"]
        return out
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise GuardUnavailable(f"exemption file is unreadable or malformed ({type(exc).__name__})") from exc


def compare(base, now, exempt=None):
    """-> (problems, info). Every new, changed or removed item is a problem unless exempt binds its path and digest. Pure."""
    # exempt maps a display path to the one digest that is allowed for it; None and {} both mean "no exemptions".
    exempt = exempt or {}
    problems, info = {}, []
    # Pass 1: items present now. Anything that is not byte-for-byte what the baseline recorded is a finding.
    for p, d in now.items():
        # Identical to the baseline: nothing to report. The comparison is on the digest string, so an
        # unreadable file that turns readable (or the reverse) also differs and is reported as CHANGED.
        if p in base and base[p] == d:
            continue
        # NEW: the path was not in the baseline at all. CHANGED: it was, but its digest differs.
        kind = "NEW" if p not in base else "CHANGED"
        # The exemption must match both the exact path and the exact digest of what is on disk now, so editing an
        # exempt file (or planting a different one under the same name) alarms again.
        if exempt.get(p) == d:
            info.append(f"{kind} {p} (exempt: path and content digest match the exemption file)")
        elif kind == "NEW":
            problems[f"persist:new:{p}"] = (f"persistence: NEW startup item {p} | fix: inspect it; if yours run "
                                            f"persistence_guard.py learn, if not remove it and rotate any credential it could reach")
        else:
            problems[f"persist:changed:{p}"] = (f"persistence: startup item CHANGED {p} | fix: diff against git/backup; "
                                                f"if not yours treat as compromise and rotate any credential it could reach")
    # Pass 2: items that were in the baseline but are gone. An item that vanished is always reported: deleting a guard or a key is also a change worth knowing about.
    for p in base:
        if p not in now:
            problems[f"persist:removed:{p}"] = f"persistence: startup item REMOVED {p} | fix: confirm you removed it, then learn"
    return problems, info


# Files that share the state folder (all names carry the host so one folder can serve several machines):
#   persistence.<host>.json    the accepted baseline {display path: digest}
#   PERSIST.<host>.json        the receipt of the latest `check`, read by alarm_problems()
#   learn_receipts.<host>.jsonl one line per accepted baseline change, appended only
def paths(host=HOST, d=None):
    """Return (baseline file, latest receipt file) for a host inside the state folder d (default DIR)."""
    d = Path(d) if d else DIR
    return d / f"persistence.{host}.json", d / f"PERSIST.{host}.json"


# The two helpers below (_redact, _sha) and _write_learn_receipt exist only for the audit trail of `learn`.
# They are intentionally small and self-contained so a receipt failure can never block the security-relevant work.
def _redact(text):
    """Mask the value after password/token/secret/key words (name=value, name: value or name value)."""
    import re as _re
    # Learn receipts record the parent command line; this keeps an accidentally typed secret out of them.
    return _re.sub(r"(?i)([\w-]*(?:password|passwd|token|secret|key)[\w-]*(?:\s*[=:]\s*|\s+))(\S+)", r"\1[REDACTED]", text)


def _sha(path):
    """Full sha256 hex of a file, or None if it cannot be read (for example the baseline does not exist yet)."""
    import hashlib
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return None


def _write_learn_receipt(base_p, before, tool, accepted=None):
    """One JSON line per successful learn, appended with a single os.write (safe on a synced folder, per-host file).
    A failure here only warns on stderr; it never blocks learn. No secrets, no file contents."""
    try:
        # Imported here, not at the top, because these are needed only on the (rare) learn path.
        import datetime, getpass, subprocess
        host = socket.gethostname().split(".")[0]
        # Who ran learn: the terminal, and the parent process command line (redacted). This answers "who accepted this?" later.
        try:
            tty = os.ttyname(0)
        except OSError:
            tty = os.environ.get("SSH_TTY") or os.environ.get("TTY") or "none"
        try:
            parent = subprocess.run([trusted_command("ps"), "-o", "command=", "-p", str(os.getppid())], capture_output=True,
                                    text=True, timeout=5).stdout.strip() or "unknown"
        except Exception:
            parent = "unknown"
        # Both local time (with its UTC offset) and UTC are stored so receipts from machines in different time zones sort cleanly.
        now = datetime.datetime.now().astimezone()
        try:
            user = getpass.getuser()
        except Exception:
            user = "unknown"
        # Before/after hashes of the baseline file let a reader see whether learn actually changed anything.
        rec = {"time": now.isoformat(timespec="seconds"),
               "time_utc": now.astimezone(datetime.timezone.utc).isoformat(timespec="seconds"),
               "user": user, "terminal": tty,
               "parent_cmd": _redact(parent)[:200],
               "argv": _redact(" ".join(sys.argv[1:]))[:200],
               "host": host, "tool": "persistence_guard", "baseline_file": str(base_p),
               "baseline_before": before, "baseline_after": _sha(base_p)}
        if accepted is not None:
            rec["accepted_keys"] = sorted(accepted)
        data = (json.dumps(rec, sort_keys=True) + "\n").encode()
        # O_APPEND plus one os.write keeps concurrent writers from interleaving partial lines.
        fd = os.open(Path(base_p).parent / f"learn_receipts.{host}.jsonl", os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            if os.write(fd, data) != len(data):
                raise OSError("short write")
        finally:
            os.close(fd)
    except Exception as exc:
        print(f"WARNING: learn receipt NOT written: {type(exc).__name__}: {exc}", file=sys.stderr)



# learn() trusts whatever is on disk right now. Run it only after you have looked at `show` output or the
# findings, because a compromised machine will happily learn a compromised baseline.
def learn(d=None, home=None):
    """Accept the current state of every watched place as the new baseline and return it."""
    b, _ = paths(d=d)
    b.parent.mkdir(parents=True, exist_ok=True)
    # Scan first: if the scan raises GuardUnavailable the old baseline is left untouched.
    s = snapshot(home)
    before = _sha(b)
    # The baseline is made private (0600) because it lists which startup items and keys exist on this machine.
    _write_nofollow(b, json.dumps(s, indent=1))
    _write_learn_receipt(b, before, "persistence_guard")
    return s


# Raised by learn_only() for any request that cannot be honoured exactly. The CLI maps it to exit status 1 and an
# unchanged baseline, so a mistyped finding key never accepts something unintended.
class LearnRefused(Exception):
    """learn --only was asked for a key that is not a current, baseline-acceptable finding."""


def learn_only(keys, d=None, home=None):
    """Accept ONLY the named findings (exact persist:new|changed|removed:PATH keys from `check`); the rest stay open.
    Raises LearnRefused (baseline untouched) for an unknown key."""
    b, _ = paths(d=d)
    keys = list(dict.fromkeys(keys))
    if not keys:
        raise LearnRefused("no key given")
    try:
        base = json.loads(b.read_text())
    except (OSError, ValueError) as exc:
        raise LearnRefused(f"no readable baseline ({type(exc).__name__}); run a full learn once first") from exc
    # Both the baseline and the current state are read fresh here, not taken from the last receipt, so what is
    # accepted is what is on disk at this moment. Only keys that `check` would print right now may be accepted, so a typo cannot rewrite the baseline.
    now = snapshot(home)
    problems, _info = compare(base, now, load_exemptions())
    unknown = [k for k in keys if k not in problems]
    if unknown:
        raise LearnRefused("not a current finding: " + ", ".join(unknown))
    # Work on a copy so that a refused key halfway through leaves the on-disk baseline exactly as it was.
    new = dict(base)
    for k in keys:
        # Key shape is persist:<kind>:<path>; the path itself may contain colons, hence partition.
        kind, _, path = k[len("persist:"):].partition(":")
        if kind in ("new", "changed") and path in now:
            new[path] = now[path]
        elif kind == "removed":
            new.pop(path, None)
        else:
            raise LearnRefused(f"{k} cannot be accepted into the baseline")
    # Write to a temporary name and rename: rename is atomic, so readers see the old or the new file, never half of one.
    before = _sha(b)
    _write_nofollow(b, json.dumps(new, indent=1))
    _write_learn_receipt(b, before, "persistence_guard", accepted=keys)
    return new


# check() is what the scheduler runs. The receipt it writes is what a monitoring wrapper reads later, so it
# records completeness explicitly: complete=False means the scan itself failed and the problems dict says why.
def check(d=None, home=None, exempt=None):
    """Scan, compare with the baseline, write the receipt and return it. A scan that could not finish is itself a finding."""
    b, latest = paths(d=d)
    # now stays None if the scan fails, which is how the receipt below knows not to report an item count.
    now = None
    complete = False
    try:
        now = snapshot(home)
        if not b.exists():
            # No baseline is reported, never treated as "all clear". The fix text tells a new user what to do first.
            problems, info = {"persist:no-baseline": "persistence: no baseline yet | fix: python3 scripts/persistence_guard.py learn"}, []
        else:
            try:
                problems, info = compare(json.loads(b.read_text()), now, load_exemptions() if exempt is None else exempt)
            except (OSError, ValueError) as exc:
                # A corrupt or unreadable baseline must not read as "no differences"; escalate to an incomplete scan.
                raise GuardUnavailable(f"persistence baseline is unreadable ({type(exc).__name__})") from exc
        complete = True
    except GuardUnavailable as exc:
        problems, info = {"persist:sensor-unavailable": f"persistence: required scan failed ({exc}); no clean result was recorded"}, []
    # complete=True is required below because after a failed scan `now` may be partial or None.
    # Files whose content could not be read are tracked by metadata only; that weaker coverage is reported on every check.
    metadata_only = sorted(p for p, value in (now or {}).items() if value.startswith("metadata:"))
    if complete:
        for path in metadata_only:
            problems[f"persist:metadata-only:{path}"] = (
                f"persistence: content is unreadable; metadata-only change detection for {path} | "
                "fix: review this root-owned file's access or provide an approved read-only hash sensor")
    # The receipt keeps at most 50 info lines so a mass-exempt tree cannot grow it without bound.
    r = {"checked": time.time(), "host": HOST, "complete": complete,
         "problems": problems, "info": info[:50], "items": len(now) if complete else None}
    r["metadata_only"] = metadata_only
    latest.parent.mkdir(parents=True, exist_ok=True)
    _write_nofollow(latest, json.dumps(r, indent=1))  # atomic: a reader never sees a half-written receipt
    return r


def alarm_problems(now=None, d=None):
    """For an alarm aggregator (not part of this release). Quiet sensor is a problem. Never raises."""
    try:
        now = time.time() if now is None else now
        _, latest = paths(d=d)
        # No receipt at all means the guard never ran, which must not look like a clean machine.
        if not latest.exists():
            return {"persist:quiet": "persistence: guard never ran | fix: systemctl --user enable --now persist-guard.timer"}
        r = json.loads(latest.read_text())
        # A receipt from another host, or one with the wrong shape, is not evidence about this machine.
        if not isinstance(r, dict) or r.get("host") != HOST or not isinstance(r.get("problems"), dict):
            raise ValueError("wrong host or invalid receipt shape")
        # Start from the findings the last check recorded, then add staleness and completeness findings on top.
        out = dict(r["problems"])
        if r.get("complete") is not True:
            out.setdefault("persist:sensor-unavailable", "persistence: latest scan receipt is incomplete; no clean state is trusted")
        checked = float(r["checked"])
        # A timestamp in the future (beyond one minute of clock skew) would hide staleness, so it is an error too.
        if checked > now + 60:
            raise ValueError("receipt timestamp is in the future")
        if now - checked > 3 * 3600:
            out["persist:quiet"] = "persistence: guard silent for 3h | fix: systemctl --user status persist-guard.service"
        return out
    except Exception as exc:
        return {"persist:receipt-unavailable": f"persistence: guard receipt is unreadable or malformed ({type(exc).__name__})"}


def main(a=None):
    """Command-line entry point; returns the process exit status (0 clean, 1 findings or failure, 2 usage)."""
    # With no arguments the safe, read-only command runs; nothing ever defaults to `learn`.
    a = (a if a is not None else sys.argv[1:]) or ["check"]
    if set(a) & {"-h", "--help", "help"}:        # a help request must NEVER run a command: `learn` rewrites the security baseline
        print(__doc__ or "usage: check | learn [--only KEY ...] | status")
        return 0
    # `learn --only KEY [--only KEY2]`: accept individual findings instead of the whole current state.
    if a[0] == "learn" and "--only" in a[1:]:
        keys, rest, i = [], a[1:], 0
        while i < len(rest):
            if rest[i] == "--only" and i + 1 < len(rest):
                keys.append(rest[i + 1]); i += 2
            else:
                print("ERROR usage: learn --only KEY [--only KEY2]", file=sys.stderr); return 2
        try:
            learn_only(keys)
        except (LearnRefused, GuardUnavailable) as exc:
            print(f"ERROR persistence baseline NOT changed: {exc}", file=sys.stderr)
            return 1
        print(f"accepted {len(keys)} finding(s): {', '.join(keys)}")
        return 0
    # Plain `learn`: accept everything currently present.
    if a[0] == "learn":
        try:
            baseline = learn()
            limited = sorted(p for p, value in baseline.items() if value.startswith("metadata:"))
            print(f"baseline saved: {len(baseline)} startup items")
            for path in limited:
                print(f"WARN metadata-only coverage: {path}")
            return 0
        except GuardUnavailable as exc:
            print(f"ERROR persistence baseline was not saved: scan failed ({exc})", file=sys.stderr); return 1
    # `check` is the scheduled command: one PROBLEM line per finding, exit 1 when there is any.
    if a[0] == "check":
        r = check()
        for k, v in r["problems"].items():
            print(f"PROBLEM {k}: {v}")
        for i in r["info"]:
            print("info:", i)
        print(f"persistence_guard {r['host']}: {len(r['problems'])} finding(s), {r['items']} items watched, {len(r['metadata_only'])} metadata-only")
        return 1 if r["problems"] else 0
    # (Anything not matched above is an unknown command: fall through to the usage text and exit status 2.)
    # `show` prints the digest of each item so an exemption entry can be written without computing hashes by hand.
    if a[0] == "show":
        try:
            for path, value in sorted(snapshot().items()):
                print(f"{value}  {path}")
            return 0
        except GuardUnavailable as exc:
            print(f"ERROR scan failed ({exc})", file=sys.stderr); return 1
    print(__doc__); return 2


if __name__ == "__main__":
    sys.exit(main())
