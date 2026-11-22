#!/usr/bin/env python3
"""git_secret_hook: PREVENT a credential from being committed or pushed (secret_scan.py only detects leaks after the fact).

  git_secret_hook.py pre-commit              scan ADDED lines of the staged diff + staged sensitive file names
  git_secret_hook.py pre-push REMOTE [URL]   (git's pre-push stdin) scan commits about to leave the machine
  git_secret_hook.py install REPO...         write chained .git/hooks/pre-commit + pre-push (existing hook kept as <name>.pre-leakguard)
  git_secret_hook.py uninstall REPO...       remove our hooks, restore the saved ones
  git_secret_hook.py lock REPO... | unlock   private repo: pre-push ALWAYS fails, and no remote may exist (exit 1 if one does)
  git_secret_hook.py status REPO... | --under DIR   which repos have it (default DIR: ~)

Output is file:line TYPE fingerprint, never the secret. A line containing `leakguard:allow` is skipped (reviewed fixtures).
Failure policy: FAIL CLOSED. A finding -> exit 1; git erroring -> exit 1; git, python3 or this script missing -> BLOCKED, exit 1
with a message saying what is missing. Override for one command: LEAKGUARD_ALLOW_MISSING=1 (the scan is then skipped with a
loud warning). Bypass in an emergency: git commit/push --no-verify. Only touches repos explicitly passed to install; no
global config. Every external program is run by absolute path (git: /usr/bin, Homebrew or env TWU_GIT).
"""
from __future__ import annotations
# Standard library only; git is the only external program, and it is run by absolute path.
import json, os, re, subprocess, sys
from pathlib import Path

# Make the sibling module importable when this file is run as a script (git runs hooks from the repository).
sys.path.insert(0, str(Path(__file__).resolve().parent))
import secret_scan  # shared RULES / PLACEHOLDER / scan_text

# Absolute path of this script: it is baked into the installed hook text.
SELF = Path(__file__).resolve()
# Marker line that identifies a hook file as ours (so install can replace it and uninstall can remove it).
MARKER = "# leakguard-hook v1"
# A line containing this text is skipped by the scan. Anyone who can edit the file can add it: it marks a reviewed
# fixture, it is not a security control.
ALLOW = "leakguard:allow"
HOOKS = ("pre-commit", "pre-push")
# All-zero object id: git's way of saying "no such commit" (a new branch or a deletion).
ZERO = "0" * 40
# Template files are expected to look like credential files without holding real ones.
SAFE_SUFFIX = (".example", ".sample", ".template", ".dist", ".tpl")
# File names that normally hold credentials; staging one is blocked by name even if its content looks harmless.
SENSITIVE_NAMES = {".env", ".envrc", ".netrc", "_netrc", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".npmrc_auth", "credentials.json",
                   ".pgpass", ".git-credentials", ".pypirc", ".htpasswd"}
SENSITIVE_SUFFIX = (".pem", ".key", ".p12", ".pfx", ".ppk", ".keystore", ".kdbx", ".jks")
# Optional list of private host names to keep out of commits; nothing is built in.
HOSTS_FILE = "private_hosts.json"      # optional {"hosts": ["name", {"host": "name", "aliases": ["other"]}]} next to the script or in ../data
# The only way to let a commit through when the scanner cannot run (see unavailable()).
OVERRIDE = "LEAKGUARD_ALLOW_MISSING"   # set to 1 to let a commit/push through when the scanner cannot run
# The fix hint printed with every block. It names the reviewed-fixture escape hatch so people do not reach for --no-
# verify first.
HINT = "remove it, rotate the credential if it was real, load it from the environment; reviewed fixture: add 'leakguard:allow' to that line"


# Marker line of the lock hook (a pre-push hook that always refuses).
LOCK = "# leakguard-lock v1"
# A MAC address: six hex pairs separated consistently by ':' or '-', not part of a longer hex run.
MAC_RX = re.compile(r"(?<![0-9A-Fa-f:-])(?:[0-9A-Fa-f]{2}([:-]))(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:-])")
# Placeholder MACs that are not findings: all zeros, all ff, or one pair repeated six times.
# Case-insensitive; the same rule accepts either separator.
MAC_OK = re.compile(r"(?i)^(?:00[:-]00[:-]00[:-]00[:-]00[:-]00|ff[:-]ff[:-]ff[:-]ff[:-]ff[:-]ff|(?:([0-9a-f]{2})[:-])\1(?:[:-]\1){4})$")
# Names ending in .local are mDNS host names of machines on a private network.
HOST_RX = re.compile(r"(?i)\b[a-z0-9][a-z0-9-]{1,40}\.local\b")
HOST_OK = {"localhost.local"}


# Normalising lets "My-Box", "my_box" and "my box" all match one entry in the private-hosts file.
def _norm(v: str) -> str:
    """Normalise a name for comparison: lower case, with '-', '_' and spaces treated as the same character."""
    return re.sub(r"[-_ ]", "-", v.strip().lower())


# Search order: the explicit env file first, then next to the script, then ../data.
# Relative candidates are resolved against the script, never the current directory, so a hostile repository cannot
# supply the list.
def _candidates(fname):
    """Places to look for an optional data file: next to the script, in ../data, and env TWU_PRIVATE_HOSTS_FILE (or the older
    TWU_REDACTIONS_FILE) for the private-hosts file. Empty env values are ignored."""
    out = [SELF.parent / fname, SELF.parent.parent / "data" / fname]
    given = os.environ.get("TWU_PRIVATE_HOSTS_FILE") or os.environ.get("TWU_REDACTIONS_FILE")
    if fname == HOSTS_FILE and given:
        out.insert(0, Path(given).expanduser())
    return out


# Missing or malformed files are skipped silently: an absent list means no private names, not an error.
def _load(fname):
    """Return the parsed JSON of the first readable candidate file, or None."""
    for c in _candidates(fname):
        try:
            return json.loads(c.read_text())
        except (OSError, ValueError):
            continue
    return None


# Accepted shapes: a plain name, or {"host": name, "aliases": [names]}.
# Sorted and de-duplicated so the order of the file does not change the output.
def _private_hosts():
    """Private host names (normalised: lowercase, '-', '_', ' ' interchangeable) from the private-hosts file. Missing file: none."""
    names = set()

    def add(v):
        """Remember one candidate host name if it is a string of at least four characters (shorter names match
        too much).
        """
        if isinstance(v, str) and len(v.strip()) >= 4:
            names.add(_norm(v))
    # The file is read on every call (hooks are short-lived processes), so edits take effect immediately.
    d = _load(HOSTS_FILE)
    items = d.get("hosts") if isinstance(d, dict) else None
    for x in items if isinstance(items, list) else []:
        if isinstance(x, dict):
            add(x.get("host"))
            for al in x.get("aliases", []) if isinstance(x.get("aliases"), list) else []:
                add(al)
        else:
            add(x)
    return sorted(names)


# Identity scan of one added line: MAC addresses, .local names and listed private names. Fingerprints only.
# Returns [(type, fingerprint)]; the matched MAC address or host name itself is never returned.
# Cost note: the private-hosts file is parsed once per added line; lists are expected to be short.
def scan_identity(line: str):
    """MAC addresses and private hostnames in one added line -> [(type, fingerprint)]; never the value."""
    out = []
    # Same salted fingerprint as the credential rules, so a finding can be recognised without revealing the value.
    fp = lambda v: secret_scan.fingerprint(v.lower())
    # Every MAC that is not a placeholder.
    for m in MAC_RX.finditer(line):
        if not MAC_OK.match(m.group(0)):
            out.append(("mac-address", fp(m.group(0))))
    # Every .local name except localhost.local.
    for m in HOST_RX.finditer(line):
        if m.group(0).lower() not in HOST_OK:
            out.append(("local-hostname", fp(m.group(0))))
    # Compare normalised text so the listed names match however the line spells them.
    low = _norm(line)
    # Distro-like names (fedora, arch, ...) need context, other names match as plain substrings.
    for h in _private_hosts():
        if h in DISTRO_WORDS:
            if _distro_host_hit(line, h):
                out.append(("private-hostname", fp(h)))
        elif h in low:
            out.append(("private-hostname", fp(h)))
    return out


# A Linux distro name that is ALSO a machine name (e.g. a laptop called like its OS). In prose ("Fedora 40", "Ubuntu LTS")
# it is not a host; as a lowercase token, or next to host words (ssh, host, machine, @ ...), it still is.
# Words that are both a Linux distribution and a plausible machine name. In prose ("Fedora 40") they are not findings.
DISTRO_WORDS = {"fedora", "ubuntu", "debian", "arch", "centos", "rhel", "alpine", "mint", "kali", "nixos",
                "suse", "opensuse", "gentoo", "manjaro", "popos", "rocky", "almalinux"}
# Words near the name that show it is being used as a machine (ssh fedora, user@fedora, host: fedora ...).
_HOST_CONTEXT = re.compile(r"(?i)(ssh|scp|sftp|rsync|ping|host|hostname|machine|\bbox\b|node|server|\bvm\b|laptop|"
                           r"@|\.local|\bnamed\b|\bcalled\b|fleet|peer|\bon the\b)")


# Rules: the word must stand alone (not inside a longer word); all lower case counts as a host token;
# otherwise it needs a host-like word within 24 characters.
# Mixed-case prose such as "Fedora Linux" without host words nearby is therefore not a finding.
def _distro_host_hit(line: str, host: str) -> bool:
    """True if `host` (a distro-like word) appears in `line` as a machine name rather than in ordinary prose."""
    for m in re.finditer(r"(?<![A-Za-z])" + re.escape(host) + r"(?![A-Za-z])", line, re.I):
        if m.group(0) == m.group(0).lower():
            return True
        ctx = line[max(0, m.start() - 24):m.start()] + " " + line[m.end():m.end() + 24]
        if _HOST_CONTEXT.search(ctx):
            return True
    return False


# git cannot be started at all. The hook fails closed on this unless the override is set.
class GitUnavailable(RuntimeError):
    """git itself cannot be started (not installed at an absolute system path, or not executable)."""


# git ran but failed or timed out; the hook always blocks (there is no override for a git error).
class GitFailed(RuntimeError):
    """git started but exited non-zero or did not finish."""


# Every git call goes through here: absolute path, argv list (no shell), 120 second timeout.
# The caller decides what a failure means: GitUnavailable and GitFailed are different policies.
def git(args, cwd=None):
    """Run git by absolute path with an argv list (never a shell); return stdout text. Raises GitUnavailable or GitFailed."""
    exe = secret_scan.git_executable()
    if exe is None:
        raise GitUnavailable("git not found at an absolute system path; set TWU_GIT to its full path")
    try:
        r = subprocess.run([exe, *args], cwd=cwd, capture_output=True, timeout=120)
    except (FileNotFoundError, PermissionError) as exc:
        raise GitUnavailable(str(type(exc).__name__)) from exc
    except subprocess.SubprocessError as exc:
        raise GitFailed(f"git {args[0]} did not finish ({type(exc).__name__})") from exc
    # A non-zero exit is an error, not an empty result: an empty diff must never be confused with a failed one.
    if r.returncode != 0:
        raise GitFailed(f"git {args[0]} exited {r.returncode}")
    return r.stdout.decode("utf-8", "replace")


# Judged on the file name only (the last path component), case-insensitively.
# Examples that match: .env, .env.production, id_ed25519, server.pem. Examples that do not: .env.example, notes.txt.
def sensitive_name(path: str) -> bool:
    """True for file names that normally hold credentials (.env, id_rsa, *.pem, ...) unless they are
    .example/.sample templates.
    """
    name = path.rsplit("/", 1)[-1]
    # Template suffixes win over everything else.
    low = name.lower()
    if low.endswith(SAFE_SUFFIX):
        return False
    # RED-TEAM 5: .env-prod, .env_local and id_ed25519_work (any separator after the base name) count too; public keys do not.
    if re.match(r"id_(rsa|dsa|ecdsa|ed25519)", low) and not low.endswith(".pub"):
        return True
    return low in SENSITIVE_NAMES or re.match(r"\.env[._-]", low) is not None or low.endswith(SENSITIVE_SUFFIX)


# Input is a zero-context unified diff. Only ADDED lines are scanned, so an old secret that is merely unchanged
# context is not re-reported.
# Result entries: commit, file, line, type, fingerprint.
# RED-TEAM 5 (Rule 16): the first parser decided "header or content" from the text of a line ("+++ " starts a header) and split
# the patch with str.splitlines(). An added content line starting with "++ " (diff line "+++ ...") was taken for a file header
# and skipped; "++ /dev/null" switched the rest of the hunk off; a CR, VT, FF, U+0085 or U+2028 inside a line cut it in two and
# the second half was dropped. Now the patch is split on "\n" only, and the hunk header's line counts say how many lines of
# the hunk body follow, so a "+++ " line is a file header only OUTSIDE a hunk body. Anything that starts with "+" and is not
# a header is scanned (fail safe), even when the file name is unknown.
HUNK = re.compile(r"^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def unquote_path(p: str) -> str:
    """Undo git's C-style quoting of a path ("a\\tb" -> a<TAB>b); an unquoted path is returned as it is."""
    p = p.strip()
    if len(p) < 2 or p[0] != '"' or p[-1] != '"':
        return p
    body, out, i = p[1:-1], bytearray(), 0
    esc = {"a": 7, "b": 8, "f": 12, "n": 10, "r": 13, "t": 9, "v": 11, "\\": 92, '"': 34}
    while i < len(body):
        c = body[i]
        if c == "\\" and i + 1 < len(body):
            n = body[i + 1]
            if n in esc:
                out.append(esc[n]); i += 2; continue
            m = re.match(r"[0-7]{1,3}", body[i + 1:])
            if m:
                out.append(int(m.group(0), 8) & 255); i += 1 + len(m.group(0)); continue
        out += c.encode("utf-8", "replace"); i += 1
    return out.decode("utf-8", "replace")


def scan_patch(patch: str, commit: str = ""):
    """Scan a unified diff (-U0): only added lines. Yields dicts {where, file, line, type, fp}."""
    # path/lineno track which file and new-file line number the current added line belongs to.
    out, path, lineno = [], None, 0
    # Lines of the current hunk body still to come (removed, added). Both zero means "outside a hunk".
    old_left = new_left = 0
    for raw in patch.split("\n"):
        in_hunk = old_left > 0 or new_left > 0
        if in_hunk:
            if raw.startswith("-") and old_left > 0:
                old_left -= 1
                continue
            if raw.startswith("\\"):          # "\ No newline at end of file"
                continue
            if raw.startswith("+"):
                new_left = max(0, new_left - 1)
            else:                             # the hunk ended earlier than its header said: treat the line as outside
                old_left = new_left = 0
                in_hunk = False
        if not in_hunk and not raw.startswith("+"):
            # Outside a hunk: a hunk header starts a body; everything else (diff, index, ---) carries no added content.
            m = HUNK.match(raw)
            if m:
                lineno = int(m.group(2))
                old_left = int(m.group(1)) if m.group(1) is not None else 1
                new_left = int(m.group(3)) if m.group(3) is not None else 1
            elif raw.startswith("@@"):         # a header we cannot read: scan what follows rather than skip it
                lineno, old_left, new_left = 0, 0, 1 << 30
            continue
        if not in_hunk and raw.startswith("+++ "):
            # New-file header (outside any hunk): strip the b/ or w/ prefix; /dev/null means a deletion.
            p = unquote_path(raw[4:])
            path = None if p == "/dev/null" else (p[2:] if p[:2] in ("b/", "w/") else p)
            continue
        # An added line. A reviewed fixture can opt out with the allow marker on that line.
        if raw.startswith("+"):
            line = raw[1:]
            where = path or "(unknown file)"
            # The allow marker is honoured per line. It is visible in the file and in review, which is the point.
            if ALLOW not in line:
                # Credential shapes first (the same rules as secret_scan.py).
                for _, kind, fp in secret_scan.scan_text(line):
                    out.append({"commit": commit, "file": where, "line": lineno, "type": kind, "fp": fp})
                # Then identity data: MAC addresses and private host names.
                for kind, fp in scan_identity(line):
                    out.append({"commit": commit, "file": where, "line": lineno, "type": kind, "fp": fp})
            # Each added line advances the new-file line counter.
            lineno += 1
    return out


# Findings for file names have line 0 and no fingerprint (there is no value to fingerprint).
# Used by both the commit and push paths.
def name_findings(paths, commit=""):
    """Turn staged or pushed file paths into findings for the ones with sensitive names (line 0, no fingerprint)."""
    return [{"commit": commit, "file": p, "line": 0, "type": "sensitive-file", "fp": "-"} for p in paths if p and sensitive_name(p)]


# Output format: leakguard: [commit] file:line TYPE fingerprint. Duplicates are printed once.
# Everything goes to stderr so it shows in git's output and never mixes with data on stdout.
def report(findings, what):
    """Print each distinct finding as 'file:line TYPE fingerprint' (never the secret), then the BLOCKED line with
    the fix hint.
    """
    seen = set()
    for f in findings:
        # Identity of a finding for de-duplication.
        key = (f["commit"], f["file"], f["line"], f["type"], f["fp"])
        if key in seen:
            continue
        seen.add(key)
        c = f"[{f['commit'][:8]}] " if f["commit"] else ""
        print(f"leakguard: {c}{f['file']}:{f['line']} {f['type']} {f['fp']}", file=sys.stderr)
    # Final line: what was blocked, how to fix it, and the emergency bypass.
    print(f"leakguard: BLOCKED {what}. Fix: {HINT}. (emergency only: --no-verify)", file=sys.stderr)


# Policy: fail closed. Only an explicit LEAKGUARD_ALLOW_MISSING=1 (exactly "1") lets the command through, loudly.
def unavailable(exc):
    """git is missing: fail closed (exit 1) with a clear message, unless LEAKGUARD_ALLOW_MISSING=1 asks to skip the scan."""
    if os.environ.get(OVERRIDE) == "1":
        print(f"leakguard: WARNING git is unavailable ({exc}); secret scan SKIPPED because {OVERRIDE}=1, nothing was checked.",
              file=sys.stderr)
        return 0
    print(f"leakguard: BLOCKED, git is unavailable ({exc}), so nothing could be checked. Fix git, or run this one command with "
          f"{OVERRIDE}=1, or use --no-verify if you are sure.", file=sys.stderr)
    return 1


# RED-TEAM 5 (Rule 16): options every diff/log call carries so a repository's own settings cannot change what the scan sees.
# --text: a file with a NUL byte, `-diff`/`binary` in .gitattributes, or a binary-looking type is shown as text, not as
#   "Binary files differ" (which has no lines to scan). --no-textconv/--no-ext-diff: never run a converter or diff program.
# --src-prefix/--dst-prefix and the -c settings: diff.noprefix, diff.mnemonicPrefix, diff.interHunkContext and
#   diff.suppressBlankEmpty are repository config that could otherwise change prefixes or merge/drop hunks.
SCAN_DIFF_OPTS = ["--text", "--no-color", "--no-ext-diff", "--no-textconv", "--src-prefix=a/", "--dst-prefix=b/", "-U0"]
SCAN_CONFIG = ["-c", "core.quotepath=off", "-c", "diff.noprefix=false", "-c", "diff.mnemonicPrefix=false",
               "-c", "diff.interHunkContext=0", "-c", "diff.suppressBlankEmpty=false", "-c", "diff.context=0"]
# ACMRT: Added, Copied, Modified, Renamed and Type-changed (a symlink replaced by a regular file is a "T").
FILTER = "--diff-filter=ACMRT"


def _all_zero(sha: str) -> bool:
    """True for git's 'no such object' id of any hash length (40 zeros for SHA-1, 64 for SHA-256)."""
    return bool(sha) and set(sha) == {"0"}


# Staged changes are scanned, not the working tree, because that is what the commit will contain.
# Exit status: 0 clean, 1 blocked.
def pre_commit() -> int:
    """The pre-commit check: scan the added lines of the staged diff and the staged file names; 1 blocks the
    commit.
    """
    try:
        # --no-textconv and --no-ext-diff: never run a converter or diff program named in the repository's own git
        # config.
        patch = git([*SCAN_CONFIG, "diff", "--cached", *SCAN_DIFF_OPTS, FILTER])
        # Names come from a separate NUL-separated listing so unusual file names are handled safely.
        names = git([*SCAN_CONFIG, "diff", "--cached", "--name-only", "-z", FILTER]).split("\0")
    # git missing: block, or skip with a warning only if the override is set.
    except GitUnavailable as exc:
        return unavailable(exc)
    # A git error blocks the commit: an unchecked commit is not allowed to pass silently.
    except GitFailed as exc:
        print(f"leakguard: BLOCKED, scan could not run ({exc}). Fix git, or use --no-verify if you are sure.", file=sys.stderr)
        return 1
    # Credential and identity findings from added lines, plus sensitive file names.
    found = scan_patch(patch) + name_findings(names)
    if found:
        report(found, "commit")
        return 1
    return 0


# git feeds one line per ref on stdin: <local ref> <local sha> <remote ref> <remote sha>.
# A branch that already exists remotely is scanned from the remote tip; a new one from everything unpublished.
def push_ranges(stdin_text: str, remote: str):
    """Parse git's pre-push stdin into (range, tip, remote) specs; deletions send nothing and are skipped."""
    specs = []
    for ln in stdin_text.splitlines():
        parts = ln.split()
        if len(parts) < 4:
            continue
        # Only the two object ids matter for deciding what to scan.
        _, lsha, _, rsha = parts[:4]
        # Deleting a remote ref sends no commits.
        if _all_zero(lsha):
            continue  # deletion: nothing is sent
        # Updating an existing remote ref: scan exactly the new commits (remote..local).
        if not _all_zero(rsha):
            specs.append([f"{rsha}..{lsha}", lsha, remote])
        else:
            specs.append([lsha, lsha, remote])  # new branch: everything not already on a remote
    return specs


# Two git log runs over the same range: the patch text (added lines) and the file names, both tagged with commit ids.
# Limit: very large histories make `git log -p` slow; the 120 second git timeout then turns into a BLOCKED result.
def scan_range(rng: str, tip: str, remote: str):
    """Scan every commit in a push range: added lines (via git log -p) and file names; returns findings with the
    commit id.
    """
    # Common arguments (see SCAN_DIFF_OPTS). --root: the root commit's own diff is shown even when log.showRoot is false.
    base = [*SCAN_CONFIG, "log", "--root", "--format=@@leakguard-commit %H"]
    # RED-TEAM 5: a new branch is scanned from "commits not reachable from the remote you push to". That cut is only
    # trusted when `remote` is the NAME of a configured remote. A URL or path (git push file://..., git@host:x/y) used to
    # cut at EVERY remote, so a commit that sat on some other remote was never scanned; now a URL scans the whole history.
    cut = []
    try:
        names = git(["remote"]).split()
    except GitFailed:
        names = []
    if remote and remote in names:
        cut = ["--not", f"--remotes={remote}"]
    try:
        # An update has an explicit range; a new branch is "commits not reachable from the remote".
        spec = [rng] if ".." in rng else [rng, *cut]
        patch = git([*base, "-p", *SCAN_DIFF_OPTS, FILTER, *spec])
        names = git([*base, "--name-only", FILTER, *spec])
    # If the old remote commit is not known locally (force push, shallow history) fall back to the unpublished
    # commits.
    except GitFailed:
        if ".." not in rng:
            raise
        spec = [tip, *cut]  # remote sha unknown locally (force push etc.): fall back to unpublished commits
        patch = git([*base, "-p", *SCAN_DIFF_OPTS, FILTER, *spec])
        names = git([*base, "--name-only", FILTER, *spec])
    # The log output interleaves commit markers and diffs; collect the diff lines per commit and scan each chunk.
    found, commit, chunk = [], "", []

    # Scan what was collected for the commit seen so far.
    def flush():
        """Scan the diff lines collected for the current commit and clear the buffer."""
        if chunk:
            found.extend(scan_patch("\n".join(chunk), commit))
            chunk.clear()
    # Split the log output at the commit marker lines ("\n" only: str.splitlines() also cuts at CR, VT, FF, U+2028).
    for ln in patch.split("\n"):
        if ln.startswith("@@leakguard-commit ") and len(ln.split()) == 2:
            flush()
            commit = ln.split()[1]
        else:
            chunk.append(ln)
    flush()
    commit = ""
    # Second pass over the names listing, attributing sensitive file names to their commits. git quotes unusual paths
    # (tab, double quote, backslash) in C style; they are unquoted first, otherwise `d<TAB>x/.env` hid the .env name.
    for ln in names.split("\n"):
        if ln.startswith("@@leakguard-commit "):
            commit = ln.split()[1]
        elif ln:
            found.extend(name_findings([unquote_path(ln)], commit))
    return found


# git calls the hook with the remote name and URL as arguments and the ref list on stdin.
# The remote name is used to decide what "already published" means for a new branch.
def pre_push(remote: str, stdin_text: str) -> int:
    """The pre-push check: scan all commits that are about to leave the machine; 1 blocks the push."""
    found = []
    try:
        for rng, tip, rem in push_ranges(stdin_text, remote):
            found += scan_range(rng, tip, rem)
    except GitUnavailable as exc:
        return unavailable(exc)
    except GitFailed as exc:
        print(f"leakguard: BLOCKED push, scan could not run ({exc}). Fix git, or use --no-verify if you are sure.", file=sys.stderr)
        return 1
    if found:
        report(found, "push")
        return 1
    return 0


# ---- install / uninstall / status -------------------------------------------------------------------------------------

# The interpreter baked into the hook is the one that ran install; this is the fallback if that path disappears.
SYS_PYTHON = "/usr/bin/python3"   # last-resort interpreter if the one baked in at install time has moved


# Quoting matters: the script and interpreter paths are written into a shell script.
def _q(text: str) -> str:
    """Quote a string for a POSIX shell: single quotes, with embedded single quotes escaped."""
    return "'" + text.replace("'", "'\\''") + "'"


# Shape of the generated hook: find its own folder, pick the interpreter, FAIL CLOSED if interpreter or script is
# missing, run any chained hook that was already there, then run the scan. Built by string joining (not an f-string)
# because the shell's ${VAR:-} syntax needs literal braces.
# Install-time facts (interpreter and script path) are baked in; everything else is looked up when the hook runs.
# Exit codes from the chained hook are honoured: if it fails, the commit or push stops there.
def hook_text(name: str) -> str:
    """The shell text of the pre-commit or pre-push hook. It FAILS CLOSED: if the interpreter or this script is missing it
    prints what is missing and exits 1, unless LEAKGUARD_ALLOW_MISSING=1 is set for that command. Every external program is
    called by absolute path (no PATH lookup); the interpreter path is the one that ran `install`."""
    # Header: marker line, the hook's own folder (for the chained hook), and the interpreter choice.
    # RED-TEAM 5: the skip flag is a shell variable that is RESET here. The first version read an inherited SKIP variable
    # (the pre-commit framework's own convention, SKIP=pytest), so any ambient SKIP silently switched the scan off.
    head = ("#!/bin/sh\n" + MARKER + "\nlg_skip=\nd=$(/usr/bin/dirname \"$0\")\nPY=" + _q(sys.executable or SYS_PYTHON) + "\n"
            "[ -x \"$PY\" ] || PY=" + SYS_PYTHON + "\n")
    # The fail-closed guard: python or the script missing means BLOCKED (exit 1), unless the override variable is 1.
    guard = ("if [ ! -x \"$PY\" ] || [ ! -f " + _q(str(SELF)) + " ]; then\n"
             "  echo 'leakguard: BLOCKED, python3 or git_secret_hook.py is missing (expected '\"$PY\"' and " + str(SELF).replace("'", "") + "); "
             "reinstall with git_secret_hook.py install, or set " + OVERRIDE + "=1 for this one command to skip the scan' >&2\n"
             "  if [ \"${" + OVERRIDE + ":-}\" = 1 ]; then lg_skip=1; else exit 1; fi\n"
             "fi\n")
    # The script path, shell-quoted.
    py = _q(str(SELF))
    # pre-commit: run the chained hook first (its failure stops the commit), then replace this process with the scan.
    if name == "pre-commit":
        return (head + guard + "if [ -x \"$d/pre-commit.pre-leakguard\" ]; then \"$d/pre-commit.pre-leakguard\" \"$@\" || exit $?; fi\n"
                + "[ -n \"$lg_skip\" ] && exit 0\nexec \"$PY\" " + py + " pre-commit \"$@\"\n")
    # pre-push: git sends the ref list on stdin; keep it in a temp file so the chained hook and our scan both see it.
    # The temp file name is spelled with ${TMPDIR:-/tmp} because plain mktemp ignores $TMPDIR on macOS.
    # pre-push also saves git's stdin to a temp file so the chained hook and our scan both receive it, and removes it
    # afterwards.
    return (head + guard + "in=$(/usr/bin/mktemp \"${TMPDIR:-/tmp}/leakguard.XXXXXXXX\") || exit 1\n/bin/cat > \"$in\"\n"
            + "if [ -x \"$d/pre-push.pre-leakguard\" ]; then \"$d/pre-push.pre-leakguard\" \"$@\" < \"$in\" || { rc=$?; /bin/rm -f \"$in\"; exit $rc; }; fi\n"
            + "[ -n \"$lg_skip\" ] && { /bin/rm -f \"$in\"; exit 0; }\n\"$PY\" " + py + " pre-push \"$@\" < \"$in\"; rc=$?\n/bin/rm -f \"$in\"; exit $rc\n")


# Atomic and symlink-safe: write a temp file next to the target (exclusive, no-follow) then rename it into place.
# mode 0755 is set on the descriptor before the rename, so the hook is never visible without its execute bit.
def write_hook(path: Path, text: str, mode: int = 0o755) -> None:
    """Write a hook file atomically without following a symlink: temp file (O_EXCL|O_NOFOLLOW) then rename over `path`."""
    # Same folder, so the rename cannot cross filesystems.
    tmp = path.with_name(path.name + ".leakguard-tmp")
    # Remove a leftover (or planted) temp name before creating ours.
    if tmp.is_symlink() or tmp.exists():
        tmp.unlink()
    # O_EXCL | O_NOFOLLOW: refuse to write through anything already at that name.
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.write(fd, text.encode())
        os.fchmod(fd, mode)
    finally:
        os.close(fd)
    # Rename replaces the target entry itself, so a symlink at `path` is replaced, not followed.
    os.replace(tmp, path)


# Locate the repository's hooks folder, refusing the cases where writing there would be wrong.
# Returns (hooks folder, None) or (None, refusal message).
def repo_info(repo):
    """-> (hooks_dir, error). error is a refusal message or None."""
    repo = Path(repo).expanduser()
    if not repo.is_dir():
        return None, f"{repo}: not a directory"
    try:
        # --git-common-dir works for normal repositories, worktrees and submodules.
        gd = git(["rev-parse", "--git-common-dir"], cwd=repo).strip()
    except GitFailed:
        return None, f"{repo}: not a git repository"
    except GitUnavailable:
        return None, "git is unavailable"
    try:
        # A configured core.hooksPath means another system manages hooks; we do not touch it.
        hp = git(["config", "--get", "core.hooksPath"], cwd=repo).strip()
    except GitFailed:
        hp = ""  # exit 1 = unset
    if hp:
        return None, f"{repo}: REFUSED, core.hooksPath is set to '{hp}' (hooks there are managed elsewhere); not touching it"
    g = Path(gd)
    g = g if g.is_absolute() else (repo / g)
    # Resolve the git directory, then add "hooks". If that folder is itself a symlink, refuse: writes would land
    # elsewhere.
    hooks = g.resolve() / "hooks"
    if hooks.is_symlink():
        return None, f"{repo}: REFUSED, {hooks} is a symlink (writes would land elsewhere); not touching it"
    return hooks, None


def is_ours(p: Path) -> bool:
    """True if the file contains this tool's marker line, i.e. it is a hook we installed."""
    try:
        return MARKER in p.read_text(errors="replace")
    except OSError:
        return False


# For each repository: refuse unusual setups, keep any existing hook as <name>.pre-leakguard, write ours.
# Output: '<repo>: installed' per repository; any refusal makes the exit status 1.
def install(repos) -> int:
    """Install chained pre-commit and pre-push hooks into each repository; an existing hook is kept as
    <name>.pre-leakguard.
    """
    rc = 0
    for repo in repos:
        hooks, err = repo_info(repo)
        if err:
            print(err, file=sys.stderr); rc = 1; continue
        # The hooks folder may not exist yet (git does not always create it).
        hooks.mkdir(parents=True, exist_ok=True)
        for name in HOOKS:
            h, bak = hooks / name, hooks / f"{name}.pre-leakguard"
            # Someone else's hook is present: save it so ours can chain to it.
            if (h.exists() or h.is_symlink()) and not is_ours(h):
                # Both the hook and its backup exist: ambiguous, so stop and let a person resolve it.
                if bak.exists() or bak.is_symlink():
                    print(f"{repo}: REFUSED {name}: existing hook AND {bak.name} both present; resolve by hand", file=sys.stderr); rc = 1; continue
                # Move the existing hook aside (a rename never follows a symlink).
                h.rename(bak)
            # Idempotent: reinstalling rewrites our own hook with identical text.
            write_hook(h, hook_text(name))
        print(f"{repo}: installed")
    return rc


# Reverse of install: delete our hook files and put any saved hook back.
# Safe to run twice: a second run finds nothing of ours and changes nothing.
def uninstall(repos) -> int:
    """Remove our hooks from each repository and restore any hook that was saved when we installed."""
    rc = 0
    for repo in repos:
        hooks, err = repo_info(repo)
        if err:
            print(err, file=sys.stderr); rc = 1; continue
        for name in HOOKS:
            h, bak = hooks / name, hooks / f"{name}.pre-leakguard"
            # Only files carrying our marker are removed.
            if h.exists() and is_ours(h):
                h.unlink()
            # Restore the saved hook, but never overwrite something that appeared in the meantime.
            if (bak.exists() or bak.is_symlink()) and not (h.exists() or h.is_symlink()):
                bak.rename(h)
        print(f"{repo}: uninstalled")
    return rc


# The lock hook refuses every push. It is a convenience for private repositories, not an enforcement: removing the
# hook or using --no-verify bypasses it.
# The message tells the person how to undo the lock instead of naming any particular workflow.
def lock_text() -> str:
    """Shell text of the lock hook: every push from this repository fails. Undo with `git_secret_hook.py unlock REPO`."""
    return (f"#!/bin/sh\n{LOCK}\necho 'leakguard: PUSH FORBIDDEN, this repository is locked (git_secret_hook.py unlock REPO undoes it; "
            f"git push --no-verify bypasses it)' >&2\nexit 1\n")


# lock: install the refusing pre-push hook (saving any existing one) and require that the repository has no remote.
# The lock is advisory: it stops an accidental push, not a deliberate one.
def lock(repo, undo=False) -> int:
    """Make every push from REPO fail (pre-push always exits 1) and require that it has no remote. Refuses if a remote exists."""
    hooks, err = repo_info(repo)
    if err:
        print(err, file=sys.stderr); return 1
    h, bak = hooks / "pre-push", hooks / "pre-push.pre-lock"
    # unlock: remove our lock hook and restore the saved one.
    if undo:
        if h.exists() and LOCK in h.read_text(errors="replace"):
            h.unlink()
        if bak.exists() and not h.exists():
            bak.rename(h)
        print(f"{repo}: unlocked"); return 0
    hooks.mkdir(parents=True, exist_ok=True)
    if (h.exists() or h.is_symlink()) and LOCK not in h.read_text(errors="replace"):
        if bak.exists():
            print(f"{repo}: REFUSED, pre-push and {bak.name} both exist", file=sys.stderr); return 1
        h.rename(bak)
    write_hook(h, lock_text())
    try:
        # A configured remote means a push is still possible by name, so report it as a problem.
        remotes = git(["remote"], cwd=repo).split()
    except (GitFailed, GitUnavailable) as exc:
        print(f"{repo}: cannot list remotes ({exc})", file=sys.stderr); return 1
    if remotes:
        print(f"{repo}: LOCKED but {len(remotes)} remote(s) are configured; remove them: git remote remove <name>", file=sys.stderr); return 1
    print(f"{repo}: locked, no remotes"); return 0


# A repository counts as locked only if the lock hook is present AND no remote exists.
def locked(repo) -> bool:
    """True if the repository has our lock hook and no remote configured."""
    hooks, err = repo_info(repo)
    try:
        return not err and LOCK in (hooks / "pre-push").read_text(errors="replace") and not git(["remote"], cwd=repo).split()
    except (OSError, GitFailed, GitUnavailable):
        return False


# Both hooks must be ours.
def installed(repo: Path) -> bool:
    """True if both of our hooks are present in the repository."""
    hooks, err = repo_info(repo)
    return not err and all(is_ours(hooks / n) for n in HOOKS)


# Folders not worth walking when looking for repositories.
PRUNE = {"node_modules", "Library", ".Trash", ".cache", ".venv", "venv", "__pycache__", ".npm", ".cargo", ".rustup", "Applications", "Pictures", "Music", "Movies"}


# os.walk with pruning; a folder containing .git (or a .git file, for worktrees and submodules) is a repository.
# Depth limit 6 keeps a scan of the home folder from wandering through huge trees.
def find_repos(under: Path, max_depth=6):
    """Yield every git repository under `under`, to a depth limit, skipping large non-source folders."""
    base = len(under.parts)
    for cur, dirs, files in os.walk(under):
        if ".git" in dirs or ".git" in files:
            yield Path(cur)
        dirs[:] = [d for d in dirs if d != ".git" and d not in PRUNE and len(Path(cur, d).parts) - base < max_depth]


# status REPO... or status --under DIR (default: the home folder).
# Purely informational: it never changes anything.
def status(args) -> int:
    """Print whether the hooks are installed for the given repositories (or every repository under a folder)."""
    if args and args[0] == "--under":
        repos = list(find_repos(Path(args[1] if len(args) > 1 else "~").expanduser()))
    elif args:
        repos = [Path(a).expanduser() for a in args]
    else:
        repos = list(find_repos(Path("~").expanduser()))
    for r in sorted(repos):
        print(f"{'installed    ' if installed(r) else 'NOT installed'}  {r}")
    return 0


# Exit status: 0 ok, 1 findings/refusal, 2 bad use. -h prints the module docstring.
# Anything not recognised prints the usage text to stderr and exits 2.
def main(argv=None) -> int:
    """Command line entry: dispatch pre-commit, pre-push, install, uninstall, lock, unlock and status; returns
    the exit status.
    """
    a = list(sys.argv[1:] if argv is None else argv)
    if not a or a[0] in ("-h", "--help"):
        print(__doc__); return 0
    cmd, rest = a[0], a[1:]
    # Hook entry points: git invokes these with its own arguments.
    if cmd == "pre-commit":
        return pre_commit()
    if cmd == "pre-push":
        return pre_push(rest[0] if rest else "", sys.stdin.read())
    # Management commands take one or more repository paths.
    if cmd in ("install", "uninstall") and rest:
        return (install if cmd == "install" else uninstall)(rest)
    if cmd in ("lock", "unlock") and rest:
        return max(lock(r, undo=cmd == "unlock") for r in rest)
    if cmd == "status":
        return status(rest)
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
