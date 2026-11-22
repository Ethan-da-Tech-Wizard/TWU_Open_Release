#!/usr/bin/env python3
"""home_secret_scan: find credentials in the home folder OUTSIDE any git repo (where git-based scanning never looks).

READS YOUR HOME FOLDER AND SHELL HISTORY. `check` opens dotfiles, shell history and rc files, ~/.config, ~/Downloads,
~/Desktop and ~/Documents on this machine. It prints and stores only fingerprints, but the receipt lists the home-relative
path of every file that holds a credential-shaped string. So `check` refuses to run until you confirm: pass
`--yes-read-home`, or answer `y` when asked on an interactive terminal. `report`, `status` and `accept` read only the receipt.

  home_secret_scan.py check --yes-read-home scan; write data/netguard/HOMESECRETS.<host>.json; exit 1 if any unaccepted finding
  home_secret_scan.py accept FP --reason T  accept one fingerprint (reason required) in data/netguard/homesecrets_known.json
  home_secret_scan.py report                list findings from the last receipt (file:line type fp)
  home_secret_scan.py status                one-line summary of the last receipt

Covers: shell history and rc files, dotfile configs (~/.config and top-level dotfiles: .env, .netrc, .npmrc, .pypirc,
.git-credentials, .aws, .gcloud, .docker/config.json auth, gh hosts.yml plaintext oauth_token), ~/Downloads, ~/Desktop,
~/Documents (text, <1 MB), and world/group-readable key files (id_*, *.pem, *.key, *.p12, *.kdbx, credentials*).
Never reads ~/Library or the Keychain, never follows symlinks, bounded by file count, size and a time budget.

PRIVACY: a finding is only {file (home-relative), line, type, fp = first 10 hex of a salted HMAC-SHA256 of the match}. The
match, the line and any surrounding text are never stored or printed. The salt is per install (see secret_scan.py); receipts
made before salting existed do not match any more, so re-run `check` and `accept` the findings you have reviewed.
"""
from __future__ import annotations
# Standard library only. secret_scan is imported for the shared rules, placeholder filter, fingerprint and salt.
import argparse, json, os, re, stat, sys, time
from pathlib import Path

# Make the sibling module importable when this file is run as a script from any directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import secret_scan
from secret_scan import RULES, PLACEHOLDER, scan_text

# Receipts go to the same place as secret_scan.py's: <root>/data/netguard/ (do not commit data/).
ROOT = secret_scan.ROOT
DIR = ROOT / "data" / "netguard"
HOST = secret_scan.HOST
# Bounds that keep a run cheap and predictable: at most 1 MB per file (history files: their newest 2 MB), 2500 files
# per
# folder tree, 6 levels deep and a 20 second budget. A run that hits a bound says so (truncated).
MAX_BYTES = 1_000_000
HIST_BYTES = 2_000_000          # history files: only the newest 2 MB
MAX_FILES_PER_TREE = 2500
MAX_DEPTH = 6
BUDGET_S = 20.0
# Shell history is scanned (tail only) because passwords typed on a command line end up there.
HISTORY = (".zsh_history", ".bash_history")
# Shell start-up files, where tokens are often exported.
RCFILES = (".zshrc", ".zprofile", ".bashrc", ".profile")
# Folders that are large, regenerated or not user-authored: dependency trees, caches, the macOS Library folder,
# media folders. Skipping them is a speed and noise trade-off; secrets stored there are not seen.
SKIP_DIRS = {"node_modules", ".git", "Library", "venv", ".venv", "__pycache__", "site-packages", ".cache", "cache",
             "caches", ".Trash", "Cache", "Caches", "CachedData", "GPUCache", "Code Cache", "Service Worker", ".npm", ".cargo",
             ".rustup", ".pyenv", ".nvm", "Pictures", "Music", "Movies"}
# Binary and media extensions are not scanned as text.
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".heic", ".pdf", ".zip", ".gz", ".tgz", ".dmg", ".pkg", ".iso", ".mp4", ".mov",
            ".mp3", ".m4a", ".wav", ".sqlite", ".db", ".docx", ".xlsx", ".pptx", ".app", ".so", ".dylib", ".pyc", ".woff", ".woff2"}
# File names that look like private keys or credential stores: id_*, *.pem, *.key, *.p12, *.pfx, *.kdbx, credentials*.
KEYNAME = re.compile(r"(?i)^(id_[a-z0-9_]+(?<!\.pub)|.+\.(pem|key|p12|pfx|kdbx)|credentials.*)$")
# Well-known per-tool config folders directly under the home folder, scanned to a small depth.
CONFIG_DIRS = (".aws", ".gcloud", ".docker", ".kube", ".ssh")

# assignment-style patterns for shell/config text: (type, regex, value group)
# A variable or key name that suggests a secret: contains password, passwd, secret, token, api key.
NAME = r"[A-Za-z0-9_.\-]*(?:password|passwd|secret|token|api[_-]?key|apikey)[A-Za-z0-9_]*"
# Assignment-style shapes found in shell commands and config text. Each entry is (type, pattern, group number of the
# value).
# Only values of 12 or more characters that do not look like placeholders are reported.
ASSIGN = [
    # NAME = value or NAME: value with an unquoted or quoted literal.
    ("literal-assignment", re.compile(r"(?i)\b" + NAME + r"\s*[=:]\s*(['\"]?)([^\s'\"`;&|<>]{12,})"), 2),
    # --password VALUE, --token=VALUE and similar command-line flags.
    ("cli-password-flag", re.compile(r"(?i)--(?:password|passwd|token|secret|api-key|apikey|auth-token)(?:\s+|=)(['\"]?)([^\s'\"`;&|<>-][^\s'\"`;&|<>]{11,})"), 2),
    # curl called with the -u (or --user) option and a user-and-password pair.
    ("curl-basic-auth", re.compile(r"\bcurl\b[^|;\n]*?\s(?:-u|--user)\s+(['\"]?)[^\s:'\"$]+:([^\s'\"`;&|<>]{12,})"), 2),
    # An Authorization: Bearer header with a literal token.
    ("bearer-token", re.compile(r"(?i)\bAuthorization:\s*Bearer\s+(['\"]?)([A-Za-z0-9._~+/=\-]{12,})"), 2),
    # mysql -pPASSWORD (no space after -p).
    ("mysql-password", re.compile(r"\bmysql(?:dump|admin)?\b[^|;\n]*?\s-p()([^\s'\"`;&|<>-][^\s'\"`;&|<>]{11,})"), 2),
]
# Per-file patterns for formats where the password has its own syntax; the key is the file name.
FILE_RULES = {  # file-specific plaintext credential patterns: name -> (type, regex, value group)
    ".netrc": ("netrc-password", re.compile(r"\bpassword\s+(\S+)"), 1),
    ".npmrc": ("npmrc-auth", re.compile(r"(?i)(?:_authToken|_auth|_password)\s*=\s*(\S+)"), 1),
    ".pypirc": ("pypirc-password", re.compile(r"(?i)^\s*password\s*[:=]\s*(\S+)"), 1),
    ".git-credentials": ("git-credentials", re.compile(r"://[^/\s:@]+:([^@\s]+)@"), 1),
    "hosts.yml": ("gh-plaintext-token", re.compile(r"\boauth_token:\s*(\S+)"), 1),
    "config.json": ("docker-auth", re.compile(r'"auth"\s*:\s*"([^"]+)"'), 1),
}


# Only fingerprints leave the matching code; this wraps the salted fingerprint from secret_scan.
# The salt means a receipt alone cannot be used to confirm a guessed password offline.
def _fp(s):
    """Salted fingerprint (10 hex characters) of a matched string; the string itself is never kept."""
    return secret_scan.fingerprint(s)


# Decide whether a captured value is a real literal. Variable references, template markers and obvious
# placeholders are not findings.
def _literal(v):
    """True when v looks like a real literal rather than a placeholder or variable reference."""
    # Strip one layer of quotes before judging the value.
    v = v.strip("'\"")
    # Shell variable references ($VAR), template markers ({{ }}, %, @) and command substitution are not literals.
    if len(v) < 1 or "$" in v or v.startswith(("{{", "%", "@", "`")) or PLACEHOLDER.search(v):
        return False
    # Obvious placeholder words.
    if re.search(r"(?i)(your[_-]|_here|changeme|replace|insert|todo|redacted|password123|\bnone\b|\bnull\b)", v):
        return False
    # A value made of three or fewer distinct characters (xxxxxxxx, 11111111) is filler.
    return len(set(v)) > 3


# Per-text scanner: the shared secret_scan rules plus the assignment patterns plus an optional file-specific rule.
# Returned tuples are (line number, type, fingerprint); the matched text is dropped immediately.
def scan_lines(text, assign=True, filerule=None):
    """[(line, type, fp)] - fingerprints only; the text never leaves this function."""
    # Start with the generic credential shapes (AWS, GitHub, ...).
    hits = list(scan_text(text))
    # Then the assignment-style patterns, line by line (lines over 4000 characters are skipped, as in secret_scan).
    for n, line in enumerate(text.splitlines(), 1):
        if len(line) > 4000:
            continue
        # A file-specific rule is tried first, then the general assignment patterns.
        rules = ([filerule] if filerule else []) + (list(ASSIGN) if assign else [])
        got = False
        for kind, rx, g in rules:
            # When the file-specific rule already matched this line, do not also report it under a general pattern.
            if got and filerule and kind != filerule[0]:
                continue  # the file-specific rule already covers this line
            # A line can contain several matches.
            for m in rx.finditer(line):
                v = m.group(g)
                # File-specific rules accept any literal; general rules also require 12+ characters to keep false
                # positives low.
                if _literal(v) and (kind in ("netrc-password", "npmrc-auth", "pypirc-password", "git-credentials",
                                             "gh-plaintext-token", "docker-auth") or len(v.strip("'\"")) >= 12):
                    hits.append((n, kind, _fp(m.group(0)))); got = True
    # Collapse duplicates: the same fingerprint on the same line is one finding.
    seen, out = set(), []
    for h in hits:  # one finding per (line, fp)
        if (h[0], h[2]) not in seen:
            seen.add((h[0], h[2])); out.append(h)
    return out


# Holds everything one scan needs so the helper functions can stay small.
class Ctx:
    """Mutable state of one home scan: the home folder, the time budget, the findings so far, a file counter and
    a truncated flag.
    """
    def __init__(self, home, deadline):
        """Hold the scan state: home folder, monotonic deadline, findings list, file counter and the truncated flag."""
        self.home, self.deadline, self.findings, self.files, self.truncated = Path(home), deadline, [], 0, False

    def add(self, p, line, kind, cls, fp):
        """Record one finding with a home-relative path (never the matched text)."""
        self.findings.append({"file": str(Path(p).relative_to(self.home)), "line": line, "type": kind, "class": cls, "fp": fp})

    def out_of_time(self):
        """True once the time budget is spent (and remember that the scan was truncated)."""
        if time.monotonic() > self.deadline:
            self.truncated = True
        return self.truncated


# Safe read: O_NOFOLLOW (a symlink is refused), regular files only, size-bounded, non-blocking so a FIFO cannot hang
# the scan.
# Returns None for anything it will not read, so callers can treat "skipped" and "empty" the same way.
def _read(p, limit, tail=False):
    """Read a regular, non-symlink file with O_NOFOLLOW; None if unreadable/binary/too big."""
    try:
        # O_NONBLOCK matters for named pipes; O_NOFOLLOW for symlinks.
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return None
    try:
        # Check the object we actually opened, not the path.
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return None
        # Too big to read whole: skip (history files are exempt because only their end is read).
        if info.st_size > limit and not tail:
            return None
        # History files: seek to the newest part, which is the most likely to hold live credentials.
        if tail and info.st_size > limit:
            os.lseek(fd, info.st_size - limit, os.SEEK_SET)
        data = os.read(fd, limit)
    except OSError:
        return None
    finally:
        os.close(fd)
    # Binary content: not text, not scanned.
    if b"\0" in data[:2048]:
        return None
    return data.decode("utf-8", "replace")


# File-specific rules apply only in the right folder: docker config.json under .docker, gh hosts.yml under gh.
def _scan_file(ctx, p, cls, assign, tail=False):
    """Read one file (never following a symlink) and add a finding for every credential-shaped line; counts the
    file.
    """
    # Counted even if the file turns out unreadable, so the summary shows how much was attempted.
    ctx.files += 1
    name = Path(p).name
    text = _read(p, HIST_BYTES if tail else MAX_BYTES, tail)
    if text is None:
        return
    # A file called config.json elsewhere is not a Docker config.
    frule = FILE_RULES.get(name)
    if name == "config.json" and Path(p).parent.name != ".docker":
        frule = None
    if name == "hosts.yml" and Path(p).parent.name != "gh":
        frule = None
    # Record each hit as home-relative file, line, type, class and fingerprint.
    for n, kind, fp in scan_lines(text, assign, frule):
        ctx.add(p, n, kind, cls, fp)


# Bounded iterative walk that never follows a symlink (neither files nor folders) and stops when the time budget
# or the per-tree file limit is reached.
# Depth is counted from the folder passed in; the caller chooses a smaller depth for config folders.
def _walk(ctx, top, cls, assign, name_ok=None, depth=MAX_DEPTH):
    """Bounded walk without following symlinks (neither files nor directories)."""
    top = Path(top)
    try:
        if top.is_symlink() or not top.is_dir():
            return
    except OSError:
        return
    # Explicit stack instead of recursion; each entry is (folder, depth).
    stack, count = [(str(top), 0)], 0
    while stack:
        cur, d = stack.pop()
        # Stop cleanly when the time budget is spent; the result is marked truncated.
        if ctx.out_of_time():
            return
        try:
            with os.scandir(cur) as it:
                # Sorted so repeated runs visit files in the same order (stable truncation).
                entries = sorted(it, key=lambda e: e.name)
        except OSError:
            continue
        for e in entries:
            try:
                # Symlinks are skipped entirely: a link could point anywhere on the machine.
                if e.is_symlink():
                    continue
                # Descend into real folders only, within the depth limit, and not into the skip list.
                if e.is_dir(follow_symlinks=False):
                    if d < depth and e.name not in SKIP_DIRS:
                        stack.append((e.path, d + 1))
                    continue
                if not e.is_file(follow_symlinks=False):
                    continue
            except OSError:
                continue
            # Per-tree file limit reached: record that the scan was cut short.
            if count >= MAX_FILES_PER_TREE:
                ctx.truncated = True
                return
            # Skip media and binary extensions, and apply the optional file-name filter.
            ext = os.path.splitext(e.name)[1].lower()
            if ext in SKIP_EXT or (name_ok and not name_ok(e.name)):
                continue
            count += 1
            # Check permissions of key-looking files, then scan their text.
            _key_perms(ctx, e.path, e)
            _scan_file(ctx, e.path, cls, assign)


# Private keys readable by group or others (mode bits 044) are a finding even if the content is not read.
def _key_perms(ctx, path, entry=None):
    """Flag private-key-looking files that other users can read (group or other read bit set); the content is not
    read here.
    """
    name = os.path.basename(path)
    # Only key-looking names; public keys (.pub) are fine.
    if not KEYNAME.match(name) or name.endswith(".pub"):
        return
    try:
        # lstat: judge the entry itself, never a link target.
        mode = os.lstat(path).st_mode
    except OSError:
        return
    # The fingerprint covers the relative path and the mode, so a changed mode is a new finding.
    if stat.S_ISREG(mode) and mode & 0o044:
        ctx.add(path, 0, "key-file-permissions", "key-permissions", _fp(f"{os.path.relpath(path, ctx.home)}:{mode & 0o777:o}"))


# Scan order: shell history, shell rc files, top-level dotfiles, config folders, ~/.config, then the three user
# folders.
# Nothing outside the home folder is read, and ~/Library and the Keychain are never opened.
# The `now` argument is accepted for symmetry with check() and is not used by the scan itself.
def scan(home=None, now=None):
    """Scan the home folder and return (sorted unique findings, {files_scanned, truncated}). Reads only; writes
    nothing.
    """
    # Default: the current user's home folder.
    home = Path(home or Path.home())
    # The deadline is monotonic time, immune to clock changes.
    ctx = Ctx(home, time.monotonic() + BUDGET_S)
    # History files: tail only.
    for n in HISTORY:
        _scan_file(ctx, home / n, "shell-history", True, tail=True)
    # Start-up files: whole file.
    for n in RCFILES:
        _scan_file(ctx, home / n, "shell-rc", True)
    # top-level dotfiles (files only)
    try:
        with os.scandir(home) as it:
            tops = sorted(it, key=lambda e: e.name)
    except OSError:
        tops = []
    # Top-level dotfiles (.env, .netrc, .npmrc, ...) and any *.env file directly in the home folder.
    for e in tops:
        try:
            if e.is_symlink():
                continue
            if e.is_file(follow_symlinks=False) and e.name.startswith(".") and e.name not in HISTORY + RCFILES \
                    and os.path.splitext(e.name)[1].lower() not in SKIP_EXT:
                _key_perms(ctx, e.path, e)
                _scan_file(ctx, e.path, "dotfile-config", True)
            elif e.is_file(follow_symlinks=False) and e.name.endswith(".env"):
                _scan_file(ctx, e.path, "dotfile-config", True)
        except OSError:
            continue
    # Per-tool config folders; .ssh is scanned for key blocks and permissions only (no assignment patterns).
    for d in CONFIG_DIRS:
        _walk(ctx, home / d, "dotfile-config", d != ".ssh", depth=3)
    # ~/.config to depth 4.
    _walk(ctx, home / ".config", "dotfile-config", True, depth=4)
    # The user folders are scanned for text files only (no assignment patterns), to catch pasted keys and exported
    # files.
    for d in ("Downloads", "Desktop", "Documents"):
        _walk(ctx, home / d, d.lower(), False)
    # Deterministic order and no duplicates.
    f = sorted(ctx.findings, key=lambda x: (x["file"], x["line"], x["type"], x["fp"]))
    uniq = [x for i, x in enumerate(f) if x not in f[:i]]
    return uniq, {"files_scanned": ctx.files, "truncated": ctx.truncated}


# The accepted list maps fingerprint to the reason and time it was accepted. A damaged file means nothing is accepted.
# The reason text is the accepting person's own words and is stored verbatim.
def known(d=None):
    """Load the accepted fingerprints {fp: {reason, accepted}}; a missing or unreadable file means none are accepted."""
    f = Path(d or DIR) / "homesecrets_known.json"
    try:
        v = json.loads(f.read_text())
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        return {}
    return v if isinstance(v, dict) else {}


# Counts only, for the receipt summary and the report command.
def _counts(findings):
    """Tally findings by type and by class for the receipt summary."""
    by_t, by_c = {}, {}
    for x in findings:
        by_t[x["type"]] = by_t.get(x["type"], 0) + 1
        by_c[x["class"]] = by_c.get(x["class"], 0) + 1
    return {"by_type": by_t, "by_class": by_c}


# One problem per unaccepted fingerprint; the message has no secret in it.
# The problem key is the fingerprint, so accepting a fingerprint silences exactly that finding.
def _problems(findings, k):
    """Turn unaccepted findings into a {key: message} problem table (messages carry type, path, line and fingerprint only)."""
    return {f"homesecrets:{x['fp']}": (f"home secret: {x['type']} at ~/{x['file']}:{x['line']} (fp {x['fp']}) | fix: rotate/remove it, "
                                       f"or home_secret_scan.py accept {x['fp']} --reason TEXT")
            for x in findings if x["fp"] not in k}


# check = scan + compare with the accepted list + write the receipt. The caller must already have confirmed the read.
# The receipt lists home-relative paths of files that hold credential-shaped strings: treat data/ as private.
def check(home=None, d=None, now=None):
    """Scan the home folder, write the receipt atomically, return (receipt, unaccepted findings). Callers must have confirmed."""
    d = Path(d or DIR)
    # Fingerprints from a one-run salt could not be compared with the accepted list: stop instead of reporting
    # nonsense.
    if secret_scan.salt_is_ephemeral():     # fingerprints from a one-run salt could never be compared with an accepted list
        raise secret_scan.ScanUnavailable("fingerprint salt could not be read or created (set TWU_FP_SALT_FILE)")
    # Step 1: the read-only scan.
    findings, meta = scan(home, now)
    # Step 2: mark each finding accepted or not.
    k = known(d)
    for x in findings:
        x["accepted"] = x["fp"] in k
    new = [x for x in findings if not x["accepted"]]
    # Step 3: the receipt (findings, counts, problems).
    r = {"checked": time.time() if now is None else now, "host": HOST, "complete": True, **meta,
         "findings": findings, "counts": _counts(findings), "new": len(new), "problems": _problems(findings, k)}
    d.mkdir(parents=True, exist_ok=True)
    # Atomic write: temp file then rename.
    t = d / f"HOMESECRETS.{HOST}.json.tmp"
    t.write_text(json.dumps(r, indent=1)); os.replace(t, d / f"HOMESECRETS.{HOST}.json")
    return r, new


# Acceptance needs a reason, so the list explains itself later.
# Accepting a fingerprint does not delete the secret from the file: rotate real credentials.
def accept(fp, reason, d=None, now=None):
    """Accept one fingerprint with a mandatory reason; returns the updated accepted table."""
    if not reason or not reason.strip():
        raise ValueError("a reason is required")
    d = Path(d or DIR); d.mkdir(parents=True, exist_ok=True)
    k = known(d)
    # Stored with the reason and the time.
    k[fp] = {"reason": reason.strip(), "accepted": time.time() if now is None else now}
    t = d / "homesecrets_known.json.tmp"
    t.write_text(json.dumps(k, indent=1, sort_keys=True)); os.replace(t, d / "homesecrets_known.json")
    return k


# Used by report and status.
def _load(d=None):
    """Read the last receipt for this host (raises OSError or ValueError if it is missing or malformed)."""
    return json.loads((Path(d or DIR) / f"HOMESECRETS.{HOST}.json").read_text())


# Monitor hook: unaccepted findings are problems; a missing, silent (26 hours) or malformed receipt is a problem.
# Messages name the file and line but never the value.
def alarm_problems(now=None, d=None):
    """Problem table from the last receipt: unaccepted findings, plus a quiet-scanner or malformed-receipt entry."""
    try:
        now = time.time() if now is None else now
        f = Path(d or DIR) / f"HOMESECRETS.{HOST}.json"
        # Never ran on this host.
        if not f.exists():
            return {"homesecrets:quiet": "home secrets: scanner never ran | fix: python3 scripts/home_secret_scan.py check --yes-read-home"}
        r = json.loads(f.read_text())
        if not isinstance(r, dict) or r.get("host") != HOST or not isinstance(r.get("findings"), list):
            raise ValueError("wrong host or invalid receipt shape")
        checked = float(r["checked"])
        # A receipt dated in the future is not trusted.
        if checked > now + 60:
            raise ValueError("receipt timestamp is in the future")
        out = _problems(r["findings"], known(d))
        if now - checked > 26 * 3600:
            out["homesecrets:quiet"] = "home secrets: scanner silent for 26h | fix: python3 scripts/home_secret_scan.py check --yes-read-home"
        return out
    except Exception as exc:
        return {"homesecrets:quiet": f"home secrets: receipt is unreadable or malformed ({type(exc).__name__})"}


# The confirmation gate: a flag for scripts, an interactive yes for people, and a refusal otherwise.
# No environment variable or config file can switch this off: the confirmation is always per run.
def confirmed(args, stdin=None, stdout=None):
    """True if the user agreed to read the home folder: the flag, or a `y` answer on an interactive terminal."""
    # Explicit flag given.
    if getattr(args, "yes_read_home", False):
        return True
    stdin, stdout = stdin or sys.stdin, stdout or sys.stderr
    # Not a terminal and no flag: refuse (cron jobs and pipes must pass the flag deliberately).
    if not stdin.isatty():
        return False
    # Say exactly what will be read before asking.
    stdout.write("home_secret_scan will read your home folder and shell history (output: fingerprints only). Continue? [y/N] ")
    stdout.flush()
    return stdin.readline().strip().lower() in ("y", "yes")


# Commands: check (needs confirmation), accept FP --reason TEXT, report, status.
# Exit status: 0 clean (or all accepted), 1 unaccepted findings, 2 refused or bad use, 3 untrusted scan.
def main(argv=None):
    """Command line entry: check | accept | report | status; returns the process exit status."""
    # Standard argparse CLI.
    ap = argparse.ArgumentParser(prog="home_secret_scan.py", description="Scan the home folder for credentials (fingerprints only, never values).")
    sub = ap.add_subparsers(dest="cmd")
    c = sub.add_parser("check", help="scan the home folder and shell history, write receipt, exit 1 on unaccepted findings")
    c.add_argument("--yes-read-home", action="store_true", help="confirm that this run may read the home folder and shell history")
    a = sub.add_parser("accept", help="accept a fingerprint")
    a.add_argument("fp"); a.add_argument("--reason", required=True)
    sub.add_parser("report", help="list findings from the last receipt")
    sub.add_parser("status", help="one-line receipt summary")
    args = ap.parse_args(sys.argv[1:] if argv is None else argv)
    # No subcommand means check, and check needs confirmation like any other read of the home folder.
    if args.cmd in (None, "check"):
        # Exit status 2 = refused (bad use), nothing was read.
        if not confirmed(args):
            print("home_secret_scan: this reads your home folder and shell history. Re-run with --yes-read-home to confirm.",
                  file=sys.stderr)
            return 2
        try:
            r, new = check()
        # Exit status 3 = the scan could not be trusted (for example no usable salt).
        except secret_scan.ScanUnavailable as exc:
            print(f"home_secret_scan: {exc}", file=sys.stderr)
            return 3
        # Print only unaccepted findings: ~/path:line type fp=fingerprint.
        for x in new:
            print(f"~/{x['file']}:{x['line']} {x['type']} fp={x['fp']}")
        print(f"home_secret_scan: {len(r['findings'])} finding(s), {r['new']} unaccepted, {r['files_scanned']} files"
              + (" (truncated)" if r["truncated"] else ""))
        return 1 if new else 0
    # Accept one fingerprint with its reason.
    if args.cmd == "accept":
        try:
            accept(args.fp, args.reason)
        except ValueError as exc:
            print(f"error: {exc}"); return 2
        print(f"accepted {args.fp}"); return 0
    try:
        # report and status only read the last receipt; they do not scan.
        r = _load()
    except (OSError, ValueError):
        print("home_secret_scan: no readable receipt; run check"); return 1
    if args.cmd == "report":
        for x in r["findings"]:
            print(f"~/{x['file']}:{x['line']} {x['type']} fp={x['fp']}{' (accepted)' if x.get('accepted') else ''}")
        print(json.dumps(r["counts"], sort_keys=True))
        return 0
    print(f"home_secret_scan: {len(r['findings'])} finding(s), {r['new']} unaccepted, checked {time.strftime('%F %T', time.localtime(r['checked']))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
