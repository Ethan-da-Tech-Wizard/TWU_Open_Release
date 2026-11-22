#!/usr/bin/env python3
"""twu_leakwatch: offline sweeper for secrets and personal data in the wrong place.

  python3 scripts/twu_leakwatch.py scan                 write data/health/leakwatch.<host>.json; exit 2 on any non-allowlisted hit
  python3 scripts/twu_leakwatch.py show                 print the last report (masked)
  python3 scripts/twu_leakwatch.py allow PATH PATTERN --reason TEXT --days N
  python3 scripts/twu_leakwatch.py scan --changed --since-minutes N   rescan only recently modified + unseen files (cache merge)
  python3 scripts/twu_leakwatch.py gate PATH...         outbound pre-flight: exit 2 on secrets, personal literals, TODO/lorem/example@
  python3 scripts/twu_leakwatch.py propose-policy       write data/health/leakwatch_policy.proposed.json (paths and counts only)
Exit codes: 0 clean, 2 findings, 3 tool error.
Buckets: hits (act on these) | fixtures (documented placeholders / test data, counted) | saved_third_party (other
organizations' saved pages: EIN/phone/address-shaped values counted) | policy_allowed (data/health/leakwatch_policy.json).

Secrets are looked for everywhere. Personal data (EIN, SSN, and the phone/address literals read at run time from a profile
folder you name) is looked for only in zones that sync or leave the building. Zones are DATA, not code: nothing is built in.
You list them with env vars or data/health/leakwatch_zones.json (see README): private prefixes (personal data allowed by design,
only secrets are reported), sync prefixes (personal data reported), outbound globs (strictest, used by `gate`) and
business prefixes (used only to word the policy proposal). With no zones configured every file is zone "other" and only
secrets are reported. Every preview is masked to the first 2 and last 2 characters; a full value is never printed, logged or
written. Python 3.9 stdlib only, no network, no model, no daemon, never follows symlinks.
"""
from __future__ import annotations

# Standard library only; subprocess is used only to ask git whether a hit's file is tracked, ignored or untracked.
import argparse
import fnmatch
import hashlib
import json
import math
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ROOT is where data/ is read and written: env TWU_ROOT (when non-empty), else the folder above scripts/.
# Everything this tool reads or writes lives under one root; --root overrides it per run.
ROOT = Path(os.environ.get("TWU_ROOT") or Path(__file__).resolve().parent.parent)
# Data files, all under data/health/ in the root: the allowlist (dated exceptions), the personal-data policy, the
# proposal written by propose-policy, and the incremental cache. None is shipped; each is created or read on demand.
ALLOW_REL = "data/health/leakwatch_allow.json"
# Exactly the files this tool writes or reads under data/health/ (report per host, allowlist, policy, proposal, cache, zones).
OWN_FILES = re.compile(r"^data/health/leakwatch(?:\.[A-Za-z0-9_-]+\.json|_(?:allow|policy|policy\.proposed|cache|zones)\.json)$")
POLICY_REL = "data/health/leakwatch_policy.json"
PROPOSED_REL = "data/health/leakwatch_policy.proposed.json"
CACHE_REL = "data/health/leakwatch_cache.json"
# Report size limits: at most 1000 fixture items are listed (the rest are counted) and files over 2 MB are not read.
FIXTURE_LIST_CAP = 1000
MAX_BYTES = 2_000_000
# Zone configuration is data, not code: nothing is built in, see zone_config().
ZONES_REL = "data/health/leakwatch_zones.json"   # optional zone lists (see zone_config); env vars win over it
# Folders never entered. Add more with TWU_LEAKWATCH_SKIP_DIRS.
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv"}   # extra names: env TWU_LEAKWATCH_SKIP_DIRS (os.pathsep-separated)
# git is run only by absolute path (or TWU_GIT).
GIT_CANDIDATES = ("/usr/bin/git", "/opt/homebrew/bin/git", "/usr/local/bin/git")   # absolute paths only: no PATH lookup
# Extensions that are never read as text.
BINARY_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tgz", ".xz", ".bz2", ".7z", ".docx",
              ".xlsx", ".pptx", ".db", ".sqlite", ".sqlite3", ".gguf", ".safetensors", ".bin", ".pt", ".pth", ".woff", ".woff2",
              ".ttf", ".otf", ".mp3", ".mp4", ".mov", ".wav", ".pyc", ".so", ".dylib", ".class", ".jar", ".heic"}

# ----------------------------------------------------------------------------- patterns
# (name, regex, group holding the secret value, kind)
# Secret shapes, looked for in every zone: private key headers, AWS and GitHub and Slack tokens, JWTs,
# URLs with a password, and key/secret/token/password assignments with a long value.
SECRET_PATTERNS = [
    # Only the BEGIN line; fixture_reason() decides later whether a body follows.
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), 0),
    # AKIA (long-term) and ASIA (temporary) access key ids.
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 0),
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"), 0),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), 0),
    # Three base64url parts, the first two starting like JSON ({"...) after decoding.
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), 0),
    # scheme://user:password@host; group 1 is the password.
    ("url_password", re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]*://[^\s/:@'\"]+:([^\s/@'\"]{3,})@"), 1),
    # name = value where the name suggests a secret and the value is 16+ characters; group 1 is the value.
    ("generic_secret", re.compile(r"(?i)\b(?:api[_-]?key|secret|token|passwd|password)\b[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9._~+/=-]{16,})"), 1),
]
# Personal-data shapes, looked for only in the sync, outbound and saved-page zones.
PII_PATTERNS = [
    # US employer id format NN-NNNNNNN.
    ("ein", re.compile(r"(?<![\d-])\d{2}-\d{7}(?![\d-])"), 0),
    # US social security number format NNN-NN-NNNN.
    ("ssn", re.compile(r"(?<![\d-])\d{3}-\d{2}-\d{4}(?![\d-])"), 0),
]
# Words that mark a value as an example or template.
PLACEHOLDER = re.compile(r"(?i)example|your[_-]|xxxx|\*\*\*|changeme|placeholder|redacted|\$\{|<|dummy|sample|fake")
# Words that mark a value as test data when found in the value itself.
FIX_MARK = re.compile(r"(?i)example|fake|dummy|test|xxxx|hunter2|changeme|your_")
# Key ids used in vendor documentation (AKIA1234..., AKIA0000...).
DOC_AWS = re.compile(r"^(?:AKIA|ASIA)(?:1234|0000|1111|5678)")
# Which policy literal covers which pattern name.
PERSONAL_LIT = {"ein": "ein", "profile_phone": "phone", "profile_address": "address"}
# Extra checks only for `gate`: unfinished-document markers (TODO, FIXME, lorem ipsum, example@, [INSERT ...]).
GATE_TEXT = [("todo", re.compile(r"\bTODO\b")), ("fixme", re.compile(r"\bFIXME\b")),
             ("lorem_ipsum", re.compile(r"(?i)lorem ipsum")), ("example_email", re.compile(r"(?i)\bexample@")),
             ("bracket_placeholder", re.compile(r"\[(?:INSERT|YOUR|FILL)[^\]\n]{0,40}\]"))]
# Name lists used to validate the `allow` command's pattern argument.
SECRET_NAMES = [p[0] for p in SECRET_PATTERNS]
PII_NAMES = [p[0] for p in PII_PATTERNS] + ["profile_phone", "profile_address"]
ALL_NAMES = SECRET_NAMES + PII_NAMES


# Same rule as secret_scan.py: absolute path or nothing, never a PATH lookup.
def git_executable():
    """Absolute path of git: env TWU_GIT if it is an absolute path, else the first known system location; None if absent."""
    # Empty counts as unset; a relative value is refused.
    given = os.environ.get("TWU_GIT") or ""
    if given:
        return given if os.path.isabs(given) else None
    for cand in GIT_CANDIDATES:
        if os.access(cand, os.X_OK):
            return cand
    return None


# Lists in environment variables are separated by os.pathsep (':' on macOS and Linux).
def _env_list(name: str) -> list:
    """Split env var `name` on os.pathsep into non-empty items; unset or empty gives []."""
    return [x for x in (os.environ.get(name) or "").split(os.pathsep) if x]


# Built-in names plus the user's additions.
def skip_dirs() -> set:
    """Directory names never entered: the built-in set plus env TWU_LEAKWATCH_SKIP_DIRS."""
    return SKIP_DIRS | set(_env_list("TWU_LEAKWATCH_SKIP_DIRS"))


# Zones decide which files may hold personal data. They come from env vars (first) or the zones file (second);
# the default is empty, which means every file is zone "other" and only secrets are reported.
def zone_config(root: Path) -> dict:
    """Zone lists: {private_prefixes, sync_prefixes, outbound_globs, business_prefixes}, each a list of strings.
    Each list comes from its env var when that is non-empty (TWU_LEAKWATCH_PRIVATE_PREFIXES, _SYNC_PREFIXES, _OUTBOUND_GLOBS,
    _BUSINESS_PREFIXES; os.pathsep-separated), else from the same-named key of the zones file (env TWU_LEAKWATCH_ZONES_FILE,
    default data/health/leakwatch_zones.json under the root), else empty. Prefixes end with "/" to mean a folder."""
    # Config key -> environment variable.
    env = {"private_prefixes": "TWU_LEAKWATCH_PRIVATE_PREFIXES", "sync_prefixes": "TWU_LEAKWATCH_SYNC_PREFIXES",
           "outbound_globs": "TWU_LEAKWATCH_OUTBOUND_GLOBS", "business_prefixes": "TWU_LEAKWATCH_BUSINESS_PREFIXES"}
    # The zones file path may be overridden; otherwise data/health/leakwatch_zones.json under the root.
    zf = os.environ.get("TWU_LEAKWATCH_ZONES_FILE") or ""
    try:
        # A missing or malformed zones file is ignored (env vars still apply).
        data = json.loads((Path(zf) if zf else root / ZONES_REL).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    out = {}
    # Per list: the environment variable wins if non-empty, otherwise the file's list, otherwise nothing.
    for key, var in env.items():
        vals = _env_list(var)
        if not vals and isinstance(data, dict) and isinstance(data.get(key), list):
            vals = [str(x) for x in data[key] if isinstance(x, str) and x]
        out[key] = vals
    return out


# Every preview in every output goes through this: first two and last two characters, or four stars for short values.
# Masking is lossy on purpose: two characters at each end are enough to recognise a value you know, and not enough to
# use it.
def mask(value: str) -> str:
    """First 2 and last 2 characters only; short values are fully hidden."""
    v = value.strip()
    if len(v) <= 8:
        return "****"
    return v[:2] + "..." + v[-2:]


# generic_secret needs variety (5+ distinct characters) and both a digit and a letter; url_password must not be a
# stock word.
def _plausible_secret(name: str, value: str) -> bool:
    """Final plausibility filter for a secret-shaped match: placeholders and low-variety values are not secrets."""
    if name == "generic_secret":
        if PLACEHOLDER.search(value) or len(set(value)) < 5:
            return False
        return bool(re.search(r"\d", value) and re.search(r"[A-Za-z]", value))
    if name == "url_password":
        return not (PLACEHOLDER.search(value) or value.lower() in {"password", "pass", "secret", "token"})
    return True


# Test files are where example credentials live, so they get more lenient treatment (see fixture_reason).
# A path is a test path if its file name is test_*.py or *_test.py, or any folder in it is called tests or fixtures.
def is_test_path(rel: str) -> bool:
    """True for test files and test folders (test_*.py, *_test.py, tests/, fixtures/), where example credentials
    are expected.
    """
    parts = rel.split("/")
    base = parts[-1]
    return (fnmatch.fnmatchcase(base, "test_*.py") or fnmatch.fnmatchcase(base, "*_test.py")
            or any(d in ("tests", "fixtures") for d in parts[:-1]))


# Used by _realistic to tell random-looking strings from patterned ones.
def _entropy(v: str) -> float:
    """Shannon entropy of a string in bits per character (0.0 for an empty string)."""
    n = len(v)
    return -sum(c / n * math.log2(c / n) for c in (v.count(ch) for ch in set(v))) if n else 0.0


# Thresholds chosen so that real keys (random) pass and typed examples (ABCABC..., 1234...) do not.
def _realistic(v: str) -> bool:
    """True if a value looks random enough to be a real credential: at least 10 distinct characters and entropy
    of 3.3 or more.
    """
    return len(set(v)) >= 10 and _entropy(v) >= 3.3


# Strip punctuation, ignore the 4-character prefix of long keys (AKIA, ghp_), then look for repetition and sequences.
def _filler(v: str) -> bool:
    """True if the value is filler rather than a key: one repeated character, a short repeated pattern, or a run
    like 0123456789.
    """
    body = re.sub(r"[^A-Za-z0-9]", "", v)
    tail = body[4:] if len(body) > 12 else body
    if len(set(tail)) <= 1:
        return True
    for p in (2,):
        if len(tail) >= 8 and tail == (tail[:p] * len(tail))[:len(tail)]:
            return True
    low = body.lower()
    return any(seq in low and len(seq) >= 0.6 * len(body[4:] or body) for seq in ("0123456789", "abcdefghij", "9876543210"))


# Fixture logic: a secret-shaped value is counted as a documented placeholder (not a hit) when it is clearly an
# example.
# Reasons: header_only, marker, placeholder_word, doc_example, filler, test_file. Anything else stays a hit.
# Order matters: cheaper and more specific reasons are tried first, and the first one that applies is the reason
# reported.
def fixture_reason(name: str, val: str, rel: str, lines: list, idx: int):
    """Why a secret-shaped value is a documented placeholder, or None when it must stay a hit."""
    # A key header counts as a fixture only if no base64 body follows within three lines and the file is a test,
    # document or docs/ file. A real key (header plus body) is always a hit.
    if name == "private_key":
        # A base64-looking line right after the header means there is an actual key body.
        body = any(re.fullmatch(r"[A-Za-z0-9+/=]{40,}", ln.strip()) for ln in lines[idx + 1:idx + 4])
        if not body and (is_test_path(rel) or rel.lower().endswith((".md", ".rst")) or rel.startswith("docs/")):
            return "header_only"
        return None
    # A marker word inside the value itself (example, fake, test, hunter2, ...).
    if FIX_MARK.search(val):
        return "marker"
    if name in ("generic_secret", "url_password") and (PLACEHOLDER.search(val) or val.lower() in {"password", "pass", "secret", "token"}):
        return "placeholder_word"
    # Well-known documentation key ids.
    if DOC_AWS.match(val):
        return "doc_example"
    # Repetition or sequence rather than randomness.
    if _filler(val) or (name == "generic_secret" and len(set(val)) < 5):
        return "filler"
    # In a test file a value that does not look random is test data; a random-looking one still counts as a hit.
    if rel and is_test_path(rel) and not _realistic(val):
        return "test_file"
    return None


# ----------------------------------------------------------------------------- profile literals
# Profile notes are often Markdown tables; the cell text is what matters.
def _clean_cell(s: str) -> str:
    """Strip Markdown emphasis characters (*, _, `) and surrounding space from a table cell."""
    return re.sub(r"[*_`]+", "", s).strip()


# Opt-in: no profile folder is read unless TWU_LEAKWATCH_PROFILE_DIR names one.
def _profile_dir(root: Path):
    """The configured profile folder as a Path, or None when TWU_LEAKWATCH_PROFILE_DIR is unset or empty."""
    given = os.environ.get("TWU_LEAKWATCH_PROFILE_DIR") or ""
    return (root / given) if given else None


# Reads the person's own phone number and home address from their notes at run time so the sweep can find those exact
# values in the wrong place. The values are kept only in memory (a compiled pattern and normalised strings), never
# written.
# Never printed or stored: the report only says whether each literal was known.
def load_profile_literals(root: Path) -> dict:
    """Read the phone and home address from profile files at run time. Never stored. None means unknown."""
    # phone_digits: ten digits or None. addresses: candidate address strings.
    phone_digits, addresses = None, []
    # The folder of profile notes (source of the phone and address literals) is env TWU_LEAKWATCH_PROFILE_DIR, relative to
    # the scan root or absolute. Unset or empty means no profile is read and both literals stay unknown.
    pdir = _profile_dir(root)
    # No profile folder configured (or not readable) leaves this empty and both literals unknown.
    files = []
    try:
        files = sorted(p for p in pdir.iterdir() if p.is_file() and not p.is_symlink() and p.suffix.lower() in {".md", ".txt"}) if pdir else []
    except OSError:
        pass
    # A line like `| Phone | 555-0100 |` or `Address: ...` (Markdown table row or label: value).
    row = re.compile(r"^\W*(?:home\s+|mailing\s+|current\s+)?(address|phone|mobile|cell)\b[^|:\n]*?(?:\||:)\s*(.+)$", re.I)
    # Files are read as UTF-8 text; unreadable ones are skipped.
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        # Markdown bold markers are removed first so `**Phone**` rows match.
        for line in text.splitlines():
            m = row.match(line.replace("**", ""))
            if not m:
                continue
            # label is address/phone/mobile/cell; val is the first cell after it.
            label, val = m.group(1).lower(), _clean_cell(m.group(2).split("|")[0])
            # An address needs a digit and 8+ characters; the street part alone (before the first comma) is also
            # matched.
            if label == "address":
                # Short strings (a city name) are not addresses.
                if len(val) >= 8 and re.search(r"\d", val):
                    addresses.append(val)
                    street = val.split(",")[0].strip()
                    if len(street) >= 8 and re.search(r"\d", street):
                        addresses.append(street)
            # Only the first phone number found is used. 11 digits starting with 1 are reduced to 10.
            elif phone_digits is None:
                d = re.sub(r"\D", "", val)
                if len(d) == 11 and d.startswith("1"):
                    d = d[1:]
                if len(d) == 10:
                    phone_digits = d
    # The phone becomes a pattern tolerant of punctuation and a +1 prefix.
    out = {"phone": None, "address": []}
    if phone_digits:
        a, b, c = phone_digits[:3], phone_digits[3:6], phone_digits[6:]
        out["phone"] = re.compile(r"(?<!\d)(?:\+?1[\s.-]*)?\(?%s\)?[\s.-]*%s[\s.-]*%s(?!\d)" % (a, b, c))
    # Addresses are normalised (whitespace and case) and de-duplicated, longest first so the most specific match wins.
    seen = []
    for a in addresses:
        norm = re.sub(r"\s+", " ", a).casefold()
        if norm not in seen:
            seen.append(norm)
    out["address"] = sorted(seen, key=len, reverse=True)
    return out


# ----------------------------------------------------------------------------- zones
# Why not fnmatch: fnmatch lets * cross folder boundaries, which would make every outbound glob too broad.
def _glob_re(pattern: str):
    """Compile a glob into a regular expression: * and ? stay inside one path segment, ** crosses folders."""
    i, out = 0, ""
    while i < len(pattern):
        c = pattern[i]
        if pattern[i:i + 3] == "**/":
            out += "(?:.*/)?"; i += 3; continue
        if pattern[i:i + 2] == "**":
            out += ".*"; i += 2; continue
        out += "[^/]*" if c == "*" else "[^/]" if c == "?" else re.escape(c)
        i += 1
    return re.compile("^" + out + "$")


# Kept as a small wrapper so callers have one name for "what leaves the building".
def outbound_globs(root: Path) -> list:
    """The configured outbound globs (see zone_config); empty when none are configured."""
    return zone_config(root)["outbound_globs"]


# Folder names that conventionally hold saved copies of other people's web pages.
SAVED_DIRS = {"saved_pages", "web_pages", "page_snapshots", "saved_web"}


# Zone precedence, strongest first: outbound (matches an outbound glob), saved_third_party, private, sync, other.
# Outbound wins even inside a private folder, because a file you publish is judged as published.
# The same file always gets the same zone for a given configuration, which is what makes cached results valid.
def zone_of(rel: str, out_res: list, head: str = "", private: tuple = (), sync: tuple = ()) -> str:
    """Classify a root-relative path: outbound | saved_third_party | private | sync | other, using the configured lists."""
    # An outbound glob matched.
    if any(r.match(rel) for r in out_res):
        return "outbound"
    # Saved pages are recognised by folder name, by .mhtml/.webarchive extension, or by a "saved from url=" header.
    parts0 = rel.split("/")
    if (SAVED_DIRS & set(parts0[:-1])
            or rel.lower().endswith((".mhtml", ".webarchive")) or "saved from url=" in head.lower()):
        return "saved_third_party"
    # Personal data is allowed by design in private folders: only secrets are reported there.
    if private and rel.startswith(tuple(private)):
        return "private"
    # Sync folders leave the machine (cloud sync, shared drives), so personal data is reported there.
    if sync and rel.startswith(tuple(sync)):
        return "sync"
    return "other"


# ----------------------------------------------------------------------------- allowlist
# Allowlist and policy expiry use this clock; tests pass `now` explicitly instead.
def _now() -> datetime:
    """Current UTC time as a timezone-aware datetime (one place to replace in tests)."""
    return datetime.now(timezone.utc)


# Entries look like {path, pattern, reason, expires, added}.
def load_allow(root: Path) -> list:
    """Read the allowlist entries from data/health/leakwatch_allow.json; a missing or malformed file means no
    entries.
    """
    try:
        data = json.loads((root / ALLOW_REL).read_text(encoding="utf-8"))
        return [e for e in data.get("entries", []) if isinstance(e, dict)]
    except (OSError, ValueError):
        return []


# Expiry is a date; the entry stays valid through the whole of that day (UTC). A bad or missing date means inactive.
def _entry_active(e: dict, now: datetime) -> bool:
    """True if an allowlist or policy entry has not expired (its date is valid through the end of that day, UTC)."""
    try:
        exp = datetime.strptime(str(e.get("expires")), "%Y-%m-%d").replace(tzinfo=timezone.utc) + timedelta(days=1)
    except ValueError:
        return False
    return now < exp


# An entry matches when its pattern equals the finding's pattern (or is *) and its path glob matches the path.
# Allowlist entries are per file and per pattern on purpose: one exception never silences the whole tree.
def allow_reason(allow: list, rel: str, pattern: str, now: datetime):
    """The reason text of the first active allowlist entry that matches this path and pattern, or None."""
    for e in allow:
        if not _entry_active(e, now):
            continue
        if e.get("pattern") in (pattern, "*") and fnmatch.fnmatchcase(rel, str(e.get("path", ""))):
            return str(e.get("reason", ""))
    return None


# Entries look like {path_glob, literals, reason, expires}.
def load_policy(root: Path) -> list:
    """Read the allow_personal policy entries from data/health/leakwatch_policy.json; none if missing or
    malformed.
    """
    try:
        data = json.loads((root / POLICY_REL).read_text(encoding="utf-8"))
        return [e for e in data.get("allow_personal", []) if isinstance(e, dict)]
    except (OSError, ValueError, AttributeError):
        return []


# Policy applies only to personal-data literals, never to secrets.
def policy_covers(policy: list, rel: str, pattern: str, now: datetime) -> bool:
    """True if an active policy entry allows this personal-data literal (ein, phone, address) in this path."""
    lit = PERSONAL_LIT.get(pattern)
    if not lit:
        return False
    for e in policy:
        if lit in (e.get("literals") or []) and _entry_active(e, now) and _glob_re(str(e.get("path_glob", "\0"))).match(rel):
            return True
    return False


# Temp file in the same folder, then os.replace: atomic on one filesystem.
def atomic_write(path: Path, data: dict) -> None:
    """Write JSON to `path` through a temp file in the same folder and rename it, so a reader never sees a
    partial file.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=1, sort_keys=True)
            fh.write("\n")
        os.replace(tmp, path)
    # Clean up the temp file on any failure, then re-raise.
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# Guard rails: the pattern must be a known name, a reason is required, and the entry expires within a year.
# The confirmation line names only the path, the pattern and the expiry date.
def cmd_allow(root: Path, path: str, pattern: str, reason: str, days: int) -> int:
    """The `allow` command: add or replace an expiring allowlist entry (needs a reason and 1-365 days); returns
    the exit status.
    """
    if pattern not in ALL_NAMES:
        print("unknown pattern; choose one of: " + ", ".join(ALL_NAMES), file=sys.stderr)
        return 1
    if not reason.strip() or not (1 <= days <= 365):
        print("need a non-empty --reason and --days between 1 and 365", file=sys.stderr)
        return 1
    # Entries are stored relative to the root with forward slashes.
    rel = os.path.relpath(path, root) if os.path.isabs(path) else path.lstrip("./")
    # Replace any existing entry for the same path and pattern.
    entries = [e for e in load_allow(root) if not (e.get("path") == rel and e.get("pattern") == pattern)]
    # Expiry date: today plus N days.
    exp = (_now() + timedelta(days=days)).strftime("%Y-%m-%d")
    entries.append({"path": rel, "pattern": pattern, "reason": reason.strip(), "expires": exp,
                    "added": _now().strftime("%Y-%m-%dT%H:%M:%SZ")})
    atomic_write(root / ALLOW_REL, {"entries": entries})
    print("allowed %s [%s] until %s" % (rel, pattern, exp))
    return 0


# ----------------------------------------------------------------------------- scanning
# Only files that have hits are looked up, to keep this cheap. tracked = committed, untracked = new, ignored = covered
# by .gitignore.
# If git is unavailable every hit is reported with git=unknown; the sweep itself does not depend on git.
def _git_status(root: Path, files: list) -> dict:
    """Label each file tracked / ignored / untracked by asking git (absolute path); every file is "unknown" if git cannot run."""
    status = {f: "unknown" for f in files}
    exe = git_executable()
    if not files or exe is None:
        return status
    try:
        # One call for the tracked set.
        tr = subprocess.run([exe, "-C", str(root), "ls-files", "-z"], capture_output=True, timeout=60)
        if tr.returncode != 0:
            return status
        tracked = set(x for x in tr.stdout.decode("utf-8", "ignore").split("\0") if x)
        # One call for the ignored set, with the file list on stdin (NUL-separated, so odd names are safe).
        ig = subprocess.run([exe, "-C", str(root), "check-ignore", "-z", "--stdin"], input="\0".join(files).encode(),
                            capture_output=True, timeout=60)
        ignored = set(x for x in ig.stdout.decode("utf-8", "ignore").split("\0") if x)
    except (OSError, subprocess.SubprocessError):
        return status
    for f in files:
        status[f] = "tracked" if f in tracked else "ignored" if f in ignored else "untracked"
    return status


# Scan one file's text. Secrets everywhere; personal data only where the zone allows it. Values are masked on the
# spot,
# so nothing downstream ever holds the full value.
# Return value: a list of (line number, pattern, masked preview, class, reason).
def scan_text(text: str, zone: str, lits: dict, rel: str = "") -> list:
    """Return [(line_no, pattern, masked, cls, reason)] for one file's text. Values are masked immediately.
    cls: hit | fixture | pii (personal literal, policy decides) | third_party."""
    out = []
    # Personal data is looked for in sync, outbound and saved-page zones only.
    pii_on = zone in ("sync", "outbound", "saved_third_party")
    saved = zone == "saved_third_party"
    lines = text.splitlines()
    # Per line, per pattern, per match.
    for no, line in enumerate(lines, 1):
        # Patterns are tried independently; one line can produce several findings.
        for name, rx, grp in SECRET_PATTERNS:
            for m in rx.finditer(line):
                # The captured value (a password, a token), not the surrounding text.
                val = m.group(grp)
                # A match that is clearly an example is recorded as a fixture (counted), not as a hit.
                why = fixture_reason(name, val, rel, lines, no - 1)
                if why:
                    out.append((no, name, mask(val), "fixture", why))
                # Otherwise it is a hit unless it fails the plausibility filter.
                elif _plausible_secret(name, val):
                    out.append((no, name, mask(val), "hit", ""))
        # Private and other zones: secrets only.
        if not pii_on:
            continue
        # EIN and SSN shapes, only where personal data is in scope.
        for name, rx, grp in PII_PATTERNS:
            for m in rx.finditer(line):
                # In saved third-party pages an EIN is somebody else's: counted, not reported.
                cls = "third_party" if saved and name == "ein" else "pii" if name == "ein" else "hit"
                out.append((no, name, mask(m.group(grp)), cls, ""))
        # Phone and address literals in a saved page are counted too; elsewhere they are personal-data findings.
        pcls = "third_party" if saved else "pii"
        # The person's own phone number, in any common punctuation.
        if lits.get("phone"):
            for m in lits["phone"].finditer(line):
                out.append((no, "profile_phone", mask(m.group(0)), pcls, ""))
        # The person's own address (full, and the street part alone).
        if lits.get("address"):
            # Address matching ignores case and runs of whitespace.
            flat = re.sub(r"\s+", " ", line).casefold()
            for lit in lits["address"]:
                i = flat.find(lit)
                if i >= 0:
                    out.append((no, "profile_address", mask(flat[i:i + len(lit)]), pcls, ""))
                    break
    return out


# A fingerprint of the profile folder (names, sizes, mtimes) so the cache notices when the profile changes.
def _profile_stats(root: Path) -> list:
    """Name, size and mtime of the profile files (no content), so the cache is dropped when they change."""
    st = []
    pdir = _profile_dir(root)
    try:
        for p in (sorted(pdir.iterdir()) if pdir else []):
            if p.is_file() and not p.is_symlink() and p.suffix.lower() in {".md", ".txt"}:
                s = p.stat()
                st.append([p.name, s.st_size, s.st_mtime_ns])
    except OSError:
        pass
    return st


# The cache key. It covers this script's own text, the zone configuration, the skip list, the profile files' stats
# and the size limit, so changing any of them forces a full rescan.
# Hashing the script text means upgrading the tool automatically discards results made by older rules.
def rules_hash(root: Path, out_globs: list) -> str:
    """Invalidates the cache when the tool, the zone lists or the profile source files change (no literal is hashed)."""
    h = hashlib.sha256()
    try:
        h.update(Path(__file__).read_bytes())
    except OSError:
        h.update(b"?")
    h.update(json.dumps([out_globs, zone_config(root), sorted(skip_dirs()), _profile_stats(root), MAX_BYTES], sort_keys=True).encode())
    return h.hexdigest()


# A cache from another rules hash is ignored.
def load_cache(root: Path, rh: str) -> dict:
    """Load the per-file result cache if it was made under the same rules hash, else an empty cache."""
    try:
        data = json.loads((root / CACHE_REL).read_text(encoding="utf-8"))
        if data.get("rules") == rh and isinstance(data.get("files"), dict):
            return data["files"]
    except (OSError, ValueError, AttributeError):
        pass
    return {}


# Scan flow: (1) read configuration (zones, profile literals, allowlist, policy); (2) walk the tree; (3) per file use
# the
# cache or read and scan it; (4) sort findings into buckets; (5) look up git status of hit files; (6) build and write
# the report.
# Return value: the report dict (counts, hits, allowed hits, fixtures, third-party counts, policy-allowed counts, not-
# checked list).
def scan(root: Path, host: str = None, write: bool = True, now: datetime = None, use_cache: bool = None,
         since_minutes: float = None) -> dict:
    """Sweep the root and return the report dict. Writes the cache and report files when write=True; never prints
    values.
    """
    # `now` is injectable so expiry can be tested without waiting.
    now = now or _now()
    host = host or socket.gethostname().split(".")[0]
    use_cache = write if use_cache is None else use_cache
    # Step 1: configuration, all read fresh on every run.
    zc = zone_config(root)
    private, sync, skips = tuple(zc["private_prefixes"]), tuple(zc["sync_prefixes"]), skip_dirs()
    # Outbound globs are compiled once into regular expressions.
    globs = zc["outbound_globs"]
    out_res = [_glob_re(g) for g in globs]
    # The profile literals exist only in memory for the duration of this run.
    lits = load_profile_literals(root)
    # Dated exceptions (see the `allow` command).
    allow = load_allow(root)
    # Personal-data exceptions by path glob (see propose-policy).
    policy = load_policy(root)
    # The cache key for this run.
    rh = rules_hash(root, globs)
    # Previous per-file results, only if the key still matches and caching is on.
    old = load_cache(root, rh) if use_cache else {}
    # Results for this run; written back at the end.
    new_cache = {}
    # --changed mode: files not modified since this moment are trusted from the cache.
    cutoff = (time.time() - since_minutes * 60) * 1e9 if since_minutes is not None else None
    # Everything the sweep did not read, with a reason, so the report shows its own blind spots.
    not_checked, nc_counts = [], {}
    # Cache statistics.
    stats = {"cached": 0, "scanned": 0}

    # Bookkeeping for the "not checked" section of the report: nothing is silently ignored.
    def skip(rel, reason):
        """Record a file or folder that was not checked, with the reason (counted, and the first 300 are listed)."""
        nc_counts[reason] = nc_counts.get(reason, 0) + 1
        if len(not_checked) < 300:
            not_checked.append({"path": rel, "reason": reason})

    # Step 2: raw collects every finding; scanned counts the files actually inspected.
    raw, scanned = [], 0
    # followlinks=False: symlinked folders are listed as skipped, never entered.
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # Paths are stored relative to the root with forward slashes, so reports are the same on every machine.
        reld = os.path.relpath(dirpath, root)
        reld = "" if reld == "." else reld.replace(os.sep, "/")
        # Decide which sub-folders to descend into.
        keep = []
        # Sorted so two runs visit folders in the same order.
        for d in sorted(dirnames):
            rel = (reld + "/" + d).lstrip("/")
            # Skipped folders are counted in the report, not hidden.
            if d in skips:
                skip(rel + "/", "skipped dir")
            # A symlinked folder is never entered.
            elif os.path.islink(os.path.join(dirpath, d)):
                skip(rel, "symlink")
            else:
                keep.append(d)
        # Editing dirnames in place is how os.walk is told which folders to visit.
        dirnames[:] = keep
        # Files in a stable order.
        for fn in sorted(filenames):
            rel = (reld + "/" + fn).lstrip("/")
            full = os.path.join(dirpath, fn)
            # Symlinked files are never read.
            if os.path.islink(full):
                skip(rel, "symlink"); continue
            # The tool's own reports, cache and config files are not scanned. RED-TEAM 5 (Rule 16): this used to be a prefix
            # test (rel.startswith("data/health/leakwatch")), so ANY file whose name began with those characters, such as
            # data/health/leakwatch_notes.txt, was never scanned. Now only the tool's exact file names are exempt.
            if OWN_FILES.match(rel):
                continue
            # Known binary extensions are skipped only when the file really looks binary (a NUL byte in its first 8 KB).
            # RED-TEAM 5: the extension alone used to decide, so a text file with a secret saved as notes.png was never read.
            if os.path.splitext(fn)[1].lower() in BINARY_EXT:
                try:
                    with open(full, "rb") as fh:
                        head = fh.read(8192)
                except OSError:
                    skip(rel, "unreadable"); continue
                if b"\0" in head:
                    skip(rel, "binary"); continue
            try:
                stt = os.stat(full)
            except OSError:
                skip(rel, "unreadable"); continue
            # Large files are not read (stated limit: a secret in a file over 2 MB is not seen).
            if stt.st_size > MAX_BYTES:
                skip(rel, "huge"); continue
            # Cache hit rule: same size and same mtime. In --changed mode an older file is also trusted from the
            # cache.
            ent = old.get(rel)
            # fresh = the cache entry still describes this file.
            fresh = ent is not None and ent.get("s") == stt.st_size and ent.get("m") == stt.st_mtime_ns
            # --changed mode: a file that has not been touched inside the time window is trusted from the cache even
            # if it differs.
            if ent is not None and not fresh and cutoff is not None and stt.st_mtime_ns < cutoff:
                fresh = True  # --changed: untouched inside the window, trust the cache
            # Step 3: not cached. Read the file whole.
            if not fresh:
                try:
                    # Read as bytes, decode leniently (invalid UTF-8 is ignored, not fatal).
                    with open(full, "rb") as fh:
                        blob = fh.read()
                except OSError:
                    skip(rel, "unreadable"); continue
                # RED-TEAM 5: a NUL byte no longer exempts a file (one NUL at the top of a text file hid everything below it, and
                # UTF-16 text has NULs between every letter). The text is read with the NULs removed.
                text = blob.replace(b"\0", b"").decode("utf-8", "ignore")
                # Zone is decided per file, from its path and the first 2000 characters (for the saved-page
                # header).
                zone = zone_of(rel, out_res, text[:2000], private, sync)
                # Cache entry: size, mtime, zone, findings (already masked).
                ent = {"s": stt.st_size, "m": stt.st_mtime_ns, "z": zone, "f": scan_text(text, zone, lits, rel)}
                # Counters for the report: how many files were read versus reused from the cache.
                stats["scanned"] += 1
            else:
                stats["cached"] += 1
            # The new cache holds only files seen in this run, so deleted files drop out.
            new_cache[rel] = ent
            # Entries marked binary are reported as not checked.
            if ent.get("k"):
                skip(rel, ent["k"]); continue
            # Count of files actually inspected.
            scanned += 1
            for no, pat, mk, cls, why in ent["f"]:
                # One raw finding per match; the report keeps the masked preview only.
                raw.append({"path": rel, "line": no, "pattern": pat, "zone": ent["z"], "masked": mk, "cls": cls, "why": why})
    # Persist the cache (never contains a full value, only masked previews).
    if write and use_cache:
        atomic_write(root / CACHE_REL, {"rules": rh, "files": new_cache})

    # Step 4: buckets. hits = act on these; fixtures = documented examples; third = other organisations' saved pages;
    # policy_ok = personal data the policy file allows.
    hits_raw, fixtures, third, policy_ok = [], [], [], []
    # Sort each finding into exactly one bucket.
    for h in raw:
        # Remove the internal class and reason fields from the finding as it is moved into its bucket.
        cls = h.pop("cls"); why = h.pop("why")
        if cls == "fixture":
            h["reason"] = why; fixtures.append(h)
        elif cls == "third_party":
            third.append(h)
        elif cls == "pii" and policy_covers(policy, h["path"], h["pattern"], now):
            policy_ok.append(h)
        else:
            hits_raw.append(h)
    # Step 5: only files that have hits are asked about in git.
    hit_files = sorted({h["path"] for h in hits_raw})
    # Tracked / ignored / untracked for each file that has a hit.
    git = _git_status(root, hit_files)
    hits, allowed = [], []
    # Apply the dated allowlist: allowed hits are kept in the report but do not fail the run.
    for h in hits_raw:
        # Whether the file is tracked helps decide the urgency: a tracked file with a secret may already be in
        # history.
        h["git"] = git.get(h["path"], "unknown")
        # A matching, unexpired allowlist entry moves the hit to the allowed list.
        why = allow_reason(allow, h["path"], h["pattern"], now)
        if why is None:
            hits.append(h)
        else:
            h["allow_reason"] = why
            allowed.append(h)

    # Counts by zone, pattern and zone/pattern for the summary.
    def tally(items):
        """Count findings by zone, by pattern and by zone/pattern."""
        z, p, zp = {}, {}, {}
        for h in items:
            z[h["zone"]] = z.get(h["zone"], 0) + 1
            p[h["pattern"]] = p.get(h["pattern"], 0) + 1
            k = h["zone"] + "/" + h["pattern"]
            zp[k] = zp.get(k, 0) + 1
        return {"by_zone": z, "by_pattern": p, "by_zone_pattern": zp}

    # Counts by one key.
    def simple(items, key="pattern"):
        """Count findings by one key (the pattern name by default)."""
        d = {}
        for h in items:
            d[h[key]] = d.get(h[key], 0) + 1
        return d

    # Expired allowlist entries are listed so they get cleaned up or renewed.
    expired = [{"path": e.get("path"), "pattern": e.get("pattern"), "expires": e.get("expires")}
               for e in allow if not _entry_active(e, now)]
    # Say whether the profile literals were known: "unknown" means the profile phone or address could not be read, so
    # those checks did not run.
    nc_note = {"profile_phone": "known" if lits.get("phone") else "unknown (profile phone not readable)",
               "profile_address": "known" if lits.get("address") else "unknown (profile address not readable)"}
    # Step 6: the report. It holds paths, line numbers, pattern names, zones and masked previews only.
    report = {"ts": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "host": host, "files_scanned": scanned,
              "counts": tally(hits), "allowed_counts": tally(allowed)["by_pattern"],
              "hits": hits, "allowed_hits": allowed, "expired_allow_entries": expired,
              "private_zone": [h for h in hits if h["zone"] == "private"],
              "fixtures": {"total": len(fixtures), "by_pattern": simple(fixtures), "by_reason": simple(fixtures, "reason"),
                           "items": fixtures[:FIXTURE_LIST_CAP]},
              "saved_third_party": {"total": len(third), "by_pattern": simple(third)},
              "policy_allowed": {"total": len(policy_ok), "by_pattern": simple(policy_ok)},
              "buckets": {"hits": len(hits), "fixtures": len(fixtures), "saved_third_party": len(third),
                          "policy_allowed": len(policy_ok), "allowed": len(allowed)},
              "cache": dict(stats, enabled=bool(use_cache), changed_only=since_minutes is not None),
              "not_checked": not_checked, "not_checked_counts": nc_counts, "profile_literals": nc_note}
    # leakwatch.<host>.json under data/health/.
    if write:
        atomic_write(root / "data/health" / ("leakwatch.%s.json" % host), report)
    return report


# ----------------------------------------------------------------------------- gate
# The outbound pre-flight: treat the named files as outbound regardless of where they live, so personal data,
# secrets and unfinished-document markers all block. Nothing is written. Unreadable or missing input is an error, not
# a pass.
# Return value: sorted list of (path, line, pattern, masked preview).
def gate(root: Path, paths: list, now: datetime = None) -> list:
    """Outbound pre-flight. Returns [(rel, line, pattern, masked)]; raises OSError for unreadable input."""
    now = now or _now()
    # Same literals as the sweep (empty unless a profile folder is configured).
    lits = load_profile_literals(root)
    policy = load_policy(root)
    # The expanded list of files to check.
    files = []
    # Expand each argument: files as given, folders recursively.
    for p in paths:
        pp = Path(p) if os.path.isabs(p) else Path(os.getcwd()) / p
        # A folder argument is walked recursively.
        if pp.is_dir():
            files += [Path(d) / f for d, _, fs in os.walk(pp) for f in sorted(fs)]
        elif pp.is_file():
            files.append(pp)
        else:
            # A missing path must fail the gate, never be skipped.
            raise OSError("no such file: " + str(p))
    out = []
    for f in files:
        try:
            # Policy globs are matched against the path relative to the root.
            rel = os.path.relpath(f.resolve(), root).replace(os.sep, "/")
        except ValueError:
            rel = str(f)
        # Lenient decoding, as in the sweep.
        text = f.read_bytes().decode("utf-8", "ignore")
        # Fixtures are reported too (marked placeholder): in a document that is about to go out, even an example key
        # is suspect.
        for no, pat, mk, cls, why in scan_text(text, "outbound", lits, ""):
            if cls == "pii" and policy_covers(policy, rel, pat, now):
                continue
            out.append((rel, no, pat + ("(placeholder)" if cls == "fixture" else ""), mk))
        # Then the unfinished-document markers.
        for no, line in enumerate(text.splitlines(), 1):
            for name, rx in GATE_TEXT:
                for m in rx.finditer(line):
                    out.append((rel, no, name, mask(m.group(0))))
    # De-duplicated and sorted for stable output.
    return sorted(set(out))


# ----------------------------------------------------------------------------- policy proposal
# Helps write the policy file: it groups the current personal-data hits by folder and suggests a class for each group.
# It only proposes; nothing is applied. The output has paths and counts, never values.
# Returns 0; prints one line with the group count and the number of files per suggested class.
def cmd_propose(root: Path) -> int:
    """The `propose-policy` command: group personal-data hits by folder and write a proposal file (paths and
    counts only).
    """
    # A scan that writes no report but may use the cache.
    rep = scan(root, write=False, use_cache=True)
    # path -> {literal kind: count}.
    per = {}
    # Count phone/address/EIN hits per file.
    for h in rep["hits"]:
        lit = PERSONAL_LIT.get(h["pattern"])
        if lit:
            per.setdefault(h["path"], {}).setdefault(lit, 0)
            per[h["path"]][lit] += 1
    # Folders configured as business prefixes (TWU_LEAKWATCH_BUSINESS_PREFIXES) where a phone number is expected to
    # appear.
    biz = tuple(zone_config(root)["business_prefixes"])   # empty by default: then every group is "review"
    # Folder (first three levels) -> files and totals.
    groups = {}
    # Group files by their first three folder levels.
    for path, c in per.items():
        d = "/".join(path.split("/")[:-1][:3]) or "."
        g = groups.setdefault(d, {"directory": d, "files": [], "totals": {}})
        g["files"].append(dict(path=path, **c))
        for k, v in c.items():
            g["totals"][k] = g["totals"].get(k, 0) + v
    for g in groups.values():
        # Stable order for the proposal file.
        g["files"].sort(key=lambda f: f["path"])
        # Only phone-only groups under a business prefix are suggested as intended; anything with an address is always
        # "review".
        intended = bool(biz) and all(set(f) <= {"path", "phone"} and f["path"].startswith(biz) for f in g["files"])
        g["suggested_class"] = "probably intended business contact" if intended else "review"
        g["file_count"] = len(g["files"])
    # The proposal file: a note, a timestamp and the groups.
    doc = {"note": "PROPOSAL ONLY. Review each group yourself; copy the ones you accept into leakwatch_policy.json as "
                   "allow_personal entries {path_glob, literals, reason, expires}. Paths and counts only, no values. Any "
                   "address literal is always 'review'.",
           "generated": _now().strftime("%Y-%m-%dT%H:%M:%SZ"),
           "groups": sorted(groups.values(), key=lambda g: g["directory"])}
    atomic_write(root / PROPOSED_REL, doc)
    # Totals per suggested class for the console summary.
    n = {}
    for g in groups.values():
        n[g["suggested_class"]] = n.get(g["suggested_class"], 0) + g["file_count"]
    print("proposed policy written to %s: %d groups; files by class %s" % (PROPOSED_REL, len(groups), n))
    return 0


# Plain text, masked, grouped by file and pattern; at most 25 rows, the rest are in the JSON report.
# The text report starts with a one-line headline, then buckets, then a zone/pattern table, then the first hits.
def render(report: dict) -> str:
    """Format a report as the short masked text shown by `scan` and `show`."""
    L = ["LEAK WATCH %s host=%s files_scanned=%d non-allowlisted hits=%d allowed=%d" % (
        report["ts"], report["host"], report["files_scanned"], len(report["hits"]), len(report["allowed_hits"]))]
    b = report.get("buckets")
    if b:
        L.append("buckets: hits=%d fixtures=%d saved_third_party=%d policy_allowed=%d" % (
            b["hits"], b["fixtures"], b["saved_third_party"], b["policy_allowed"]))
        if report["fixtures"]["total"]:
            L.append("fixtures by reason: " + ", ".join("%s=%d" % kv for kv in sorted(report["fixtures"]["by_reason"].items())))
        if report["saved_third_party"]["total"]:
            L.append("saved_third_party by pattern: " + ", ".join("%s=%d" % kv for kv in sorted(report["saved_third_party"]["by_pattern"].items())))
    # zone/pattern -> count.
    zp = report["counts"]["by_zone_pattern"]
    L.append("%-10s %-18s %6s" % ("zone", "pattern", "count"))
    # Table rows, sorted by name.
    for k in sorted(zp):
        z, p = k.split("/", 1)
        L.append("%-10s %-18s %6d" % ("private zone" if z == "private" else z, p, zp[k]))
    if not zp:
        L.append("(no hits)")
    # Shows whether the phone/address checks were active (known) or not (unknown).
    L.append("profile literals: phone=%s; address=%s" % (report["profile_literals"]["profile_phone"],
                                                         report["profile_literals"]["profile_address"]))
    L.append("not checked: " + (", ".join("%s=%d" % kv for kv in sorted(report["not_checked_counts"].items())) or "none"))
    if report["expired_allow_entries"]:
        L.append("expired allowlist entries: %d" % len(report["expired_allow_entries"]))
    # Most exposed zones first.
    order = {"outbound": 0, "sync": 1, "other": 2, "private": 3}
    # Sort key: zone exposure, then path, then line.
    top = sorted(report["hits"], key=lambda h: (order.get(h["zone"], 9), h["path"], h["line"]))
    # One row per (file, pattern) with a count of further hits in the same file.
    grouped = {}
    for h in top:
        k = (h["path"], h["pattern"])
        if k in grouped:
            grouped[k][1] += 1
        else:
            grouped[k] = [h, 1]
    # At most 25 rows are printed.
    rows = list(grouped.values())
    for h, n in rows[:25]:
        more = "  (+%d more in file)" % (n - 1) if n > 1 else ""
        L.append("  %s:%d  %s  %s  zone=%s git=%s%s" % (h["path"], h["line"], h["pattern"], h["masked"], h["zone"], h["git"], more))
    if len(rows) > 25:
        L.append("  ... %d more file/pattern groups in the JSON report" % (len(rows) - 25))
    return "\n".join(L)


# Exit statuses: 0 clean, 2 findings, 3 tool error (unreadable input, git failure).
# show is the default action when the first argument is not a known sub-command handled above.
def main(argv=None) -> int:
    """Command line entry: scan, show, allow, gate and propose-policy; returns 0 clean, 2 findings, 3 tool error."""
    # Sub-commands: scan, show, propose-policy, gate, allow.
    ap = argparse.ArgumentParser(description="LEAK WATCH: offline secret and PII sweeper")
    ap.add_argument("--root", default=str(ROOT))
    sub = ap.add_subparsers(dest="cmd", required=True)
    # scan options: --changed with --since-minutes N rescans only recently modified or unseen files; --no-cache
    # ignores the cache.
    sc = sub.add_parser("scan")
    sc.add_argument("--changed", action="store_true")
    sc.add_argument("--since-minutes", type=float, default=15.0)
    sc.add_argument("--no-cache", action="store_true")
    sub.add_parser("show")
    sub.add_parser("propose-policy")
    # gate takes one or more files or folders.
    g = sub.add_parser("gate")
    g.add_argument("paths", nargs="+")
    # allow takes PATH PATTERN --reason TEXT --days N.
    a = sub.add_parser("allow")
    a.add_argument("path"); a.add_argument("pattern"); a.add_argument("--reason", required=True)
    a.add_argument("--days", type=int, required=True)
    args = ap.parse_args(argv)
    # --root defaults to the folder above scripts/ (or TWU_ROOT).
    root = Path(args.root).resolve()
    try:
        # Management commands first.
        if args.cmd == "allow":
            return cmd_allow(root, args.path, args.pattern, args.reason, args.days)
        if args.cmd == "propose-policy":
            return cmd_propose(root)
        # gate prints one masked line per finding and a summary; any finding makes the exit status 2.
        if args.cmd == "gate":
            found = gate(root, args.paths)
            for rel, no, pat, mk in found:
                print("%s:%d  %s  %s" % (rel, no, pat, mk))
            print("GATE %s: %d finding(s)" % ("BLOCKED" if found else "clean", len(found)))
            return 2 if found else 0
        # scan prints the masked summary; exit status 2 if there are non-allowlisted hits.
        if args.cmd == "scan":
            rep = scan(root, use_cache=not args.no_cache, since_minutes=args.since_minutes if args.changed else None)
            print(render(rep))
            return 2 if rep["hits"] else 0
    # Only the exception type is printed, never a path or message that could carry a value.
    except (OSError, ValueError, subprocess.SubprocessError) as e:
        print("leakwatch error: %s" % type(e).__name__, file=sys.stderr)
        # Tool error.
        return 3
    # `show`: print the last report for this host.
    f = root / "data/health" / ("leakwatch.%s.json" % socket.gethostname().split(".")[0])
    try:
        # show: render the stored report (it is already masked).
        print(render(json.loads(f.read_text(encoding="utf-8"))))
    except (OSError, ValueError):
        # No report for this host yet.
        print("no report yet; run scan", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
