#!/usr/bin/env python3
"""secret_scan: find credential-shaped strings in a git working tree. Never prints a secret.

  secret_scan.py check    scan; print file:line TYPE fingerprint; exit 1 if any NEW finding
  secret_scan.py accept   record ALL current findings as known (revoked keys, reviewed fixtures), by fingerprint

Files scanned: git-tracked plus untracked-not-ignored, regular, text, at most 1 MB. A finding is identified by a short
salted fingerprint of the match, so the baseline file (data/netguard/secrets_known.json) holds no secret either.
Receipt: data/netguard/SECRETS.<host>.json.

What is NOT scanned (stated plainly, these are evasion routes as well as speed-ups):
  - files larger than 1 MB and non-regular files (a NUL byte or a very long line no longer exempts anything: lines over 4000
    characters are scanned in overlapping pieces, NUL-stripped and zero-width-stripped / NFKC-folded copies are scanned too);
  - what a pattern cannot see: a secret split across lines or string pieces, base64 / hex / otherwise encoded secrets, and a real
    key with a placeholder word (example, fake, dummy, xxxx, ...) attached to it, which the placeholder filter treats as a sample;
  - paths under the prefixes in env TWU_SECRET_SCAN_SKIP_PREFIXES (empty by default);
  - dangling symlinks and files deleted between listing and reading.
(git_secret_hook.py additionally skips a line that contains the text `leakguard:allow`.)

How it works: main() runs check() or accept(); both call scan(), which asks files() for the git file list, reads each file
and tests every line against RULES; a match that looks like a placeholder is ignored. check() drops fingerprints that are
already in secrets_known.json; whatever is left is NEW and the exit status is 1. If git or a file read fails, ScanUnavailable
is raised and the receipt says complete=false, so a failed scan never records a clean result.

Fingerprint salt: each install has a random salt (file 0600 in a 0700 per-user folder, env TWU_FP_SALT_FILE overrides the
location). Fingerprints created before salting existed no longer match: re-run `accept` after reviewing the findings.
"""
# Lets `str | None`-style annotations parse on Python 3.9.
from __future__ import annotations
# Standard library only. hmac/hashlib make the salted fingerprint, subprocess runs git, stat checks file types.
import hashlib, hmac, json, os, re, socket, stat, subprocess, sys, time
from pathlib import Path

# ROOT is where data/ is read and written: env TWU_ROOT (when non-empty), else the folder above scripts/.
ROOT = Path(os.environ.get("TWU_ROOT") or Path(__file__).resolve().parent.parent)
# Receipts and the accepted-fingerprint list live under <root>/data/netguard/ (keep data/ out of version control).
DIR = ROOT / "data" / "netguard"
# Short host name: receipts are per host so two machines sharing a folder do not overwrite each other.
HOST = socket.gethostname().split(".")[0]
# One regular expression per credential shape. Adding a rule needs no other change: the cache signature below includes
# the pattern text, so every cached result is dropped automatically when a rule changes.
RULES = {
    "aws-access-key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    # Classic prefixes (ghp_, gho_, ghu_, ghs_, ghr_) with 36+ characters, or a fine-grained github_pat_ token.
    "github-token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b"),
    "anthropic-key": re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{30,}"),
    # The negative lookahead keeps this rule from also matching the Anthropic prefix above.
    "openai-key": re.compile(r"\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_\-]{40,}"),
    "google-api-key": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "slack-token": re.compile(r"\bxox[abprs]-[0-9A-Za-z\-]{20,}"),
    "stripe-live-key": re.compile(r"\b[sr]k_live_[0-9A-Za-z]{20,}"),
    # Only the BEGIN line is matched: one finding per key block, and the key body is never touched.
    "private-key-block": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
    # Group 1 is the base64 key itself (43 characters plus padding); a template value starting with @ is skipped
    # later.
    "wireguard-private-key": re.compile(r"(?i)\bPrivateKey\s*=\s*([A-Za-z0-9+/]{43}=)"),
}
# Words that make a match a documented example rather than a credential (EXAMPLE, your_key, xxxx, <...>, ...).
# This is a heuristic: a real key that happens to contain one of these words is not reported.
PLACEHOLDER = re.compile(r"(?i)(example|placeholder|your[_-]?key|xxxx|<[^>]*>|\.\.\.|dummy|fake|redacted|0{8,})")
# Folders (path prefixes relative to the scan root, separated by os.pathsep) that are never scanned, for example saved
# third-party pages whose public client keys are not yours. Empty by default; the scanner skips nothing by path.
SKIP_ENV = "TWU_SECRET_SCAN_SKIP_PREFIXES"
GIT_CANDIDATES = ("/usr/bin/git", "/opt/homebrew/bin/git", "/usr/local/bin/git")   # absolute paths only: no PATH lookup


# Fail-closed signal: when raised, check() records complete=false instead of a clean result.
class ScanUnavailable(RuntimeError):
    """The credential scan could not inspect its complete input set."""


# Skipping is opt-in and by path prefix only; nothing is skipped by default (see the module docstring).
def skip_prefixes():
    """Path prefixes to skip, from env TWU_SECRET_SCAN_SKIP_PREFIXES; an empty or unset value means none."""
    return tuple(x for x in (os.environ.get(SKIP_ENV) or "").split(os.pathsep) if x)


# No PATH lookup: a writable directory earlier on PATH could otherwise substitute its own `git`.
def git_executable():
    """Absolute path of git: env TWU_GIT if it is an absolute path, else the first known system location; None if absent."""
    # An empty value counts as unset. A relative value is refused for the same no-PATH-lookup reason.
    given = os.environ.get("TWU_GIT") or ""
    if given:
        return given if os.path.isabs(given) else None   # a relative value would reintroduce a PATH-style lookup
    # System git first, then the two usual Homebrew locations.
    for cand in GIT_CANDIDATES:
        if os.access(cand, os.X_OK):
            return cand
    return None


# Same convention as the other tools in this folder: XDG state directory, never the repository itself,
# so `git add -A` cannot publish the salt.
def _state_dir():
    """Per-user state folder: $XDG_STATE_HOME when it is set, non-empty and absolute, else ~/.local/state, plus twu-leakguard."""
    # The XDG specification says a relative XDG_STATE_HOME must be ignored.
    base = os.environ.get("XDG_STATE_HOME") or ""
    if not base or not os.path.isabs(base):
        base = os.path.join(os.path.expanduser("~"), ".local", "state")
    return Path(base) / "twu-leakguard"


# TWU_FP_SALT_FILE lets a test or a multi-user setup point at a different salt file.
def salt_file():
    """Where the per-install fingerprint salt lives: env TWU_FP_SALT_FILE (non-empty) else <state dir>/fingerprint_salt."""
    return Path(os.environ.get("TWU_FP_SALT_FILE") or (_state_dir() / "fingerprint_salt"))


# Salt lifecycle: read it if present; otherwise create it exclusively. Two processes starting together
# both end up reading the same value because the loser of the create race simply reads the winner's file.
def _read_or_create_salt(path):
    """Return the salt bytes in `path`, creating it (random, mode 0600, never following a symlink) if it does not exist."""
    # The folder is private (0700); parents above it keep their existing modes.
    os.makedirs(path.parent, mode=0o700, exist_ok=True)
    # At most two passes: one to create, one to read back.
    for _ in range(2):
        try:
            # O_NOFOLLOW: a symlink planted at the salt path is refused, not followed to some other file.
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            try:
                # O_EXCL: create only if absent; mode 0600 so only this user can read the salt.
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            except FileExistsError:
                continue                       # another process created it first: read theirs
            try:
                # 256 bits of OS randomness, hex encoded, one line.
                os.write(fd, os.urandom(32).hex().encode() + b"\n")
            finally:
                os.close(fd)
            continue
        try:
            # Verify the file we actually opened (not a path): regular file, owned by the current user.
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
                raise OSError("fingerprint salt file is not a regular file owned by this user")
            # Ours but readable by others: tighten instead of refusing (the value was never published by this tool).
            if info.st_mode & 0o077:
                os.fchmod(fd, 0o600)           # ours but too open: tighten rather than refuse
            data = os.read(fd, 4096).strip()
        finally:
            os.close(fd)
        # An empty or truncated file would give a predictable salt, so it is an error.
        if len(data) < 32:
            raise OSError("fingerprint salt file is empty or truncated")
        return data
    raise OSError("fingerprint salt file could not be created")


# Cache of salts read in this process, keyed by file path. Tests clear it to simulate a restart.
_SALTS = {}   # salt file path -> (salt bytes, ephemeral flag); read once per process


# Failure to read or create the salt must not crash a hook, but must not silently pass either:
# use a random one-run salt, say so on stderr, and mark it ephemeral so baselines refuse to use it.
def fp_salt():
    """The salt for fingerprints. If the salt file cannot be read or created, use a random in-memory salt and warn once."""
    key = str(salt_file())
    if key not in _SALTS:
        try:
            _SALTS[key] = (_read_or_create_salt(Path(key)), False)
        except OSError as exc:
            print("secret_scan: WARNING fingerprint salt unavailable (%s); using a one-run salt, so fingerprints "
                  "will not match earlier runs" % type(exc).__name__, file=sys.stderr)
            _SALTS[key] = (os.urandom(32).hex().encode(), True)
    return _SALTS[key][0]


# Baseline comparisons call this: a one-run salt would make every accepted fingerprint look new (or worse, wrong).
def salt_is_ephemeral():
    """True when this run had to fall back to a one-run salt (baselines cannot be compared or written safely then)."""
    fp_salt()
    return _SALTS[str(salt_file())][1]


# HMAC-SHA256 keyed with the install salt: the same secret gives the same fingerprint on this machine,
# but someone holding only a receipt cannot confirm a guessed secret offline without also having the salt.
def fingerprint(value):
    """Short salted fingerprint (10 hex characters of HMAC-SHA256 under the install salt) of a matched string."""
    return hmac.new(fp_salt(), value.encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:10]


# The file list comes from git itself (tracked plus untracked-not-ignored), so .gitignore is respected.
def files(root=ROOT):
    """List the files to scan (git-tracked plus untracked-not-ignored) as Paths; raise ScanUnavailable if git cannot run."""
    # No git means no file inventory: fail closed rather than report "0 findings" for a scan that did not happen.
    exe = git_executable()
    if exe is None:
        raise ScanUnavailable("git was not found at an absolute system path (set TWU_GIT to its full path)")
    try:
        result = subprocess.run([exe, "-C", str(root), "ls-files", "-co", "--exclude-standard", "-z"],
                                capture_output=True, timeout=60, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ScanUnavailable(f"git file inventory could not run ({type(exc).__name__})") from exc
    # A non-zero exit (not a repository, corrupt index) is also a failed inventory.
    if result.returncode != 0:
        raise ScanUnavailable(f"git file inventory exited with status {result.returncode}")
    return [root / p for p in result.stdout.decode("utf-8", "replace").split("\0") if p]


# The line-level scanner shared with git_secret_hook.py and home_secret_scan.py.
# RED-TEAM 5 (Rule 16): five evasions of this function were closed. (1) Every match of a rule is judged, not only the first:
# a placeholder key placed first on a line used to hide a real key after it. (2) Lines over 4000 characters are scanned in
# overlapping 4000-character pieces instead of being skipped. (3) A line holding NUL bytes (UTF-16 text) is also scanned with
# the NULs removed. (4) A line with non-ASCII characters is also scanned with zero-width characters removed and after Unicode
# NFKC folding (full-width look-alike letters become ASCII). (5) Each variant keeps the same line number.
LINE_LIMIT = 4000        # longest piece handed to the regular expressions (keeps each regex run cheap)
LINE_OVERLAP = 512       # overlap between pieces, longer than any credential shape, so a token cannot straddle a cut
_ZERO_WIDTH = {ord(c): None for c in "\u200b\u200c\u200d\u2060\ufeff\u00ad\u180e"}


def _variants(line):
    """The texts to scan for one line: the line itself plus de-NULled / de-zero-widthed / NFKC-folded copies when they differ."""
    out = [line]
    if "\0" in line:
        out.append(line.replace("\0", ""))
    if not line.isascii():
        import unicodedata
        flat = line.replace("\0", "").translate(_ZERO_WIDTH)
        out.append(flat)
        out.append(unicodedata.normalize("NFKC", flat))
    return list(dict.fromkeys(out))


def _pieces(text):
    """Split text into pieces of at most LINE_LIMIT characters that overlap by LINE_OVERLAP (one piece for a normal line)."""
    if len(text) <= LINE_LIMIT:
        return [text]
    step = LINE_LIMIT - LINE_OVERLAP
    return [text[i:i + LINE_LIMIT] for i in range(0, len(text), step)]


def scan_text(text):
    """Return [(line number, rule name, fingerprint)] for every credential-shaped match in `text` (all matches, long lines in pieces)."""
    hits, seen = [], set()
    # Line numbers are 1-based so they match what an editor shows.
    for n, line in enumerate(text.splitlines(), 1):
        for variant in _variants(line):
            for piece in _pieces(variant):
                for kind, rx in RULES.items():
                    # Every match is judged on its own: one placeholder must not hide a real key later on the same line.
                    for m in rx.finditer(piece):
                        if PLACEHOLDER.search(m.group(0)) and kind != "private-key-block":
                            continue
                        # Template placeholders such as `PrivateKey = @KEY@` are not keys.
                        if kind == "wireguard-private-key" and m.group(1).startswith("@"):
                            continue
                        fp = fingerprint(m.group(0))
                        if (n, kind, fp) not in seen:
                            seen.add((n, kind, fp))
                            hits.append((n, kind, fp))
    return hits


# RED-TEAM 5 (Rule 16): receipts, the cache and the baseline used to be written with write_text(), which follows a symlink planted
# at the file name or at its .tmp name (for example one that arrived through a synced folder) and overwrites its target.
# This writer removes whatever is at the temp name, creates it exclusively without following links, then renames it into place.
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


# The cache speeds up repeated full scans. It holds fingerprints and file sizes/times, never secrets.
def _cache_file():
    """Path of the scan cache: env TWU_SECRET_SCAN_CACHE (non-empty) else ~/.cache/twu/secret_scan_cache.json."""
    return Path(os.environ.get("TWU_SECRET_SCAN_CACHE") or Path.home() / ".cache" / "twu" / "secret_scan_cache.json")


# Signature of everything that decides what a hit is: rules, placeholder filter, line limit and the salt tag.
# If any of them changes, every cached result is stale and is dropped.
def _rules_sig():
    """Changes whenever a rule or the placeholder filter changes, which throws the whole cache away."""
    # A tag derived from the salt (not the salt) so a new salt invalidates cached fingerprints.
    salt_tag = hashlib.sha256(b"cache" + fp_salt()).hexdigest()[:8]      # a new salt means old cached fingerprints are void
    return hashlib.sha256(repr((sorted((k, rx.pattern) for k, rx in RULES.items()), PLACEHOLDER.pattern, LINE_LIMIT, LINE_OVERLAP, "rt5", salt_tag)).encode()).hexdigest()[:16]


# Any problem with the cache (missing, corrupt, wrong signature) means "no cache": it can only cost time.
def _load_cache(path):
    """Read the cache file; return its per-file hit table, or {} if it is missing, corrupt or from other rules."""
    try:
        d = json.loads(Path(path).read_text())
        if d.get("sig") == _rules_sig() and isinstance(d.get("files"), dict):
            return d["files"]
    except (OSError, ValueError, AttributeError):
        pass
    return {}


# Atomic write via a temp file and rename, so a crash cannot leave a half-written cache.
def _save_cache(path, files):
    """Write the cache atomically (temp file then replace); a failure is ignored because the cache is only a speed-up."""
    try:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        _write_nofollow(path, json.dumps({"sig": _rules_sig(), "files": files}))
    except OSError:
        pass          # the cache is only a speed-up: failing to write it must never change what is reported


# Scan flow: (1) refuse to run without a usable salt; (2) get the file list; (3) per file: skip rules, size/type
# checks,
# cache lookup, read and scan; (4) save the cache.
def scan(root=ROOT, flist=None, cache=None):
    """Scan the workspace. For the full workspace scan (flist is None) unchanged files are NOT re-read: a file whose size and mtime match the
    last scan, under the same rules, reuses its previous hits. The cache never hides a finding: any change to a file or a rule rescans it, and
    read errors still fail closed. (Re-reading tens of thousands of unchanged files on every scheduled run is slow, hence the cache.)"""
    # Step 1: fingerprints made with a one-run salt could never match the baseline.
    if salt_is_ephemeral():
        raise ScanUnavailable("fingerprint salt could not be read or created (set TWU_FP_SALT_FILE); no baseline can be trusted")
    found = []
    # The cache is used for full scans by default and never for an explicit file list (unless asked).
    use_cache = (flist is None) if cache is None else bool(cache)
    cpath = _cache_file()
    # Read once per scan so the loop below does not re-parse the environment for every file.
    skips = skip_prefixes()
    old = _load_cache(cpath) if use_cache else {}
    new = {}
    # Step 2: explicit list (tests, the git hook) or the git inventory.
    for p in (flist if flist is not None else files(root)):
        try:
            # Report paths relative to the root when possible so receipts do not carry the absolute location.
            rel = str(p.relative_to(root)) if root in p.parents else str(p)
            # Opt-in prefix skip (TWU_SECRET_SCAN_SKIP_PREFIXES).
            if skips and rel.startswith(skips):
                continue
            # Dangling symlink: there is no content to scan and nothing to fail on.
            if p.is_symlink() and not p.exists():
                continue  # dangling symlink: no content exists to hold a secret (other read errors still fail closed)
            # Any other stat error (permissions) raises OSError and fails the scan closed.
            info = p.stat()
            # Skip directories, sockets and devices, and files over 1 MB (stated limit: a secret padded past 1 MB is
            # not seen).
            if not stat.S_ISREG(info.st_mode) or info.st_size > 1_000_000:
                continue
            # Cache key: size plus modification time in nanoseconds.
            sig = [info.st_size, info.st_mtime_ns]
            # Unchanged since the last scan under the same rules: reuse the stored hits instead of re-reading the
            # file.
            hit = old.get(rel)
            if hit is not None and hit.get("sig") == sig:
                hits = [tuple(h) for h in hit["hits"]]
            else:
                # Changed or new file: read it whole (it is at most 1 MB).
                data = p.read_bytes()
                # RED-TEAM 5: a NUL byte no longer exempts a file (a NUL at the top of a text file hid everything below it);
                # scan_text also reads NUL-stripped lines, which covers UTF-16 text.
                hits = scan_text(data.decode("utf-8", "replace"))
            if use_cache:
                new[rel] = {"sig": sig, "hits": [list(h) for h in hits]}
            # Step 3 result: one record per hit, with file, line, rule name and fingerprint only.
            for n, kind, fp in hits:
                found.append({"file": str(p.relative_to(root)) if root in p.parents else str(p), "line": n, "type": kind, "fp": fp})
        # The file vanished between listing and reading (sync tools create and delete conflict copies): not a failure.
        except FileNotFoundError:
            continue  # deleted between the file listing and the read (sync tools create and remove conflict copies): nothing left to scan
        # Any other read problem means the input set was not fully inspected: fail closed.
        except OSError as exc:
            raise ScanUnavailable(f"could not read scan input {p.name} ({type(exc).__name__})") from exc
    if use_cache:
        # Step 4: the new table contains only files seen this time, so deleted files drop out of the cache.
        _save_cache(cpath, new)
    return found


# The baseline is a JSON list of accepted fingerprints. It is data from disk, so it is validated before use.
def known(d=None):
    """Load the accepted-fingerprint baseline as a set; a missing file is empty, an unreadable or malformed one is ScanUnavailable."""
    f = Path(d or DIR) / "secrets_known.json"
    try:
        value = json.loads(f.read_text())
    except FileNotFoundError:
        return set()
    except (OSError, ValueError) as exc:
        raise ScanUnavailable(f"known-fingerprint baseline is unreadable ({type(exc).__name__})") from exc
    # A baseline that is not a list of strings is treated as corrupt, never as "nothing accepted".
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ScanUnavailable("known-fingerprint baseline has an invalid format")
    return set(value)


# check = scan + compare with the baseline + write the receipt. The receipt is written even when the scan failed,
# with complete=false, so the alarm can tell "clean" from "could not look".
def check(root=ROOT, d=None, flist=None):
    """Scan, compare with the baseline, write the receipt atomically; returns (receipt dict, list of new findings)."""
    d = Path(d or DIR)
    try:
        found = scan(root, flist)
        k = known(d)
        # New = not in the accepted list. Only these make the exit status 1.
        new = [x for x in found if x["fp"] not in k]
        # Problem table keyed by fingerprint (at most 20 entries) for alarm consumers; messages carry type, file, line
        # and fingerprint only.
        problems = {f"secret:{x['fp']}": (f"secret: {x['type']} at {x['file']}:{x['line']} (fp {x['fp']}) | fix: rotate it at the provider, remove it from the file "
                                          f"(a sync tool or a push may have copied it), then secret_scan.py accept") for x in new[:20]}
        complete = True
    # Fail closed: no findings are recorded as clean.
    except ScanUnavailable as exc:
        found, new = [], []
        problems = {"secret:scan-unavailable": f"secret_scan: required scan failed ({exc}); no clean result was recorded"}
        complete = False
    # The receipt: when, which host, whether the scan was complete, the problems and the counts.
    r = {"checked": time.time(), "host": HOST, "complete": complete, "problems": problems,
         "findings": len(found) if complete else None, "new": len(new) if complete else None}
    # The receipt folder is created on demand.
    d.mkdir(parents=True, exist_ok=True)
    # Write-then-rename so a reader never sees a half-written receipt.
    _write_nofollow(d / f"SECRETS.{HOST}.json", json.dumps(r, indent=1))  # atomic, never through a symlink
    return r, new


# Accepting records EVERY current finding without a per-finding reason: rotate or remove real credentials first.
# Fingerprints created before salting existed no longer match, so re-run this after reviewing the findings.
def accept(root=ROOT, d=None, flist=None):
    """Record every current finding as known (no per-finding reason). Review and rotate first; returns the sorted fingerprints."""
    d = Path(d or DIR); d.mkdir(parents=True, exist_ok=True)
    # Union with the existing list so earlier acceptances are kept.
    fps = sorted({x["fp"] for x in scan(root, flist)} | known(d))
    _write_nofollow(d / "secrets_known.json", json.dumps(fps))
    return fps


# Read-back used by monitors: anything other than a fresh, complete, valid receipt for this host is a problem.
def alarm_problems(now=None, d=None):
    """Read the last receipt back as a {key: message} problem table; a missing, stale, malformed or incomplete receipt is a problem."""
    try:
        now = time.time() if now is None else now
        f = Path(d or DIR) / f"SECRETS.{HOST}.json"
        # Never ran on this host.
        if not f.exists():
            return {"secret:quiet": "secrets: scanner never ran | fix: run python3 scripts/secret_scan.py check (and schedule it)"}
        r = json.loads(f.read_text())
        # Wrong host or a receipt of the wrong shape (for example copied from another machine) is not trusted.
        if not isinstance(r, dict) or r.get("host") != HOST or not isinstance(r.get("problems"), dict):
            raise ValueError("wrong host or invalid receipt shape")
        out = dict(r["problems"])
        # An incomplete scan is never reported as clean.
        if r.get("complete") is not True:
            out.setdefault("secret:scan-unavailable", "secret_scan: latest scan receipt is incomplete; no clean credential result is trusted")
        # A timestamp in the future (clock skew or tampering) is rejected below.
        checked = float(r["checked"])
        if checked > now + 60:
            raise ValueError("receipt timestamp is in the future")
        # More than 26 hours old: the scheduled run has stopped working.
        if now - checked > 26 * 3600:
            out["secret:quiet"] = "secrets: scanner silent for 26h | fix: check that the scheduled secret_scan.py run still works"
        return out
    # Any parse problem is reported as a problem, never as success.
    except Exception as exc:
        return {"secret:receipt-unavailable": f"secret_scan: receipt is unreadable or malformed ({type(exc).__name__})"}


# Command line: `check` (default) or `accept`; anything else prints the usage text and exits 2.
def main(a=None):
    """Command line entry: check (default) or accept; returns the process exit status (0 clean, 1 findings, 2 bad use)."""
    a = (a if a is not None else sys.argv[1:]) or ["check"]
    # Exit status 1 when there are NEW findings or the scan could not complete, 0 otherwise.
    if a[0] == "check":
        r, new = check()
        # A failed scan prints PROBLEM lines and fails; it never prints "0 findings".
        if not r["complete"]:
            for key, message in r["problems"].items():
                print(f"PROBLEM {key}: {message}")
            return 1
        # Output is file:line TYPE fingerprint, never the secret.
        for x in new:
            print(f"{x['file']}:{x['line']} {x['type']} fp={x['fp']}")
        print(f"secret_scan: {r['findings']} finding(s), {r['new']} new")
        return 1 if new else 0
    if a[0] == "accept":
        print(f"accepted {len(accept())} fingerprint(s)"); return 0
    print(__doc__); return 2


if __name__ == "__main__":
    sys.exit(main())
