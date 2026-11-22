# Secret and leak tools

> Status: working; own tests pass on macOS (arm64) with Python 3.9.6 and 3.13. **Linux has not been run.** Not an independent audit.

## What it is
Four cooperating command-line tools, Python standard library only:

| Tool | What it does |
|---|---|
| `scripts/secret_scan.py` | Finds credential-shaped strings (AWS, GitHub, Slack, Anthropic/OpenAI/Google/Stripe keys, private-key headers, WireGuard keys) in the files of a **git working tree**. Records only a short salted fingerprint of each match. |
| `scripts/home_secret_scan.py` | The same idea for your **home folder and shell history**, outside any repository. Needs an explicit confirmation (see below). |
| `scripts/twu_leakwatch.py` | Zone-aware sweep for secrets and personal data (EIN, SSN, your own phone and address) in files that sync or leave your machine, plus an outbound pre-flight `gate`. Zones are configuration you supply; none are built in. |
| `scripts/git_secret_hook.py` | Installs `pre-commit` and `pre-push` hooks that block a commit or push containing a credential, a MAC address, a `.local` host name or a private host name you list. **Fails closed.** |

## Why it is needed
Credentials end up in synced or pushed files by accident. Finding them afterwards is too late, so the hook blocks before the commit leaves your machine, and the scanners find what is already there.

## Requirements
- Python 3.9 or newer, standard library only. No install step, no network, no root.
- `git` at `/usr/bin/git`, `/opt/homebrew/bin/git` or `/usr/local/bin/git` (or set `TWU_GIT` to its absolute path). git is never looked up on `PATH`.
- For the installed hooks: a POSIX `/bin/sh` and `/usr/bin/dirname`, `/usr/bin/mktemp`, `/bin/cat`, `/bin/rm` (present on macOS and standard Linux; Linux not run).

## Quick start
Run from this folder (`secret_leak_tools/`). It works in a fresh clone and uses a throwaway repository so nothing of yours is scanned or changed:

```bash
demo=$(mktemp -d) && git -C "$demo" init -q
printf 'aws_key = %s\n' "AKIA""ABCDEFGHIJKLMNOP" > "$demo/leak.txt"      # a fake key, built from two pieces

TWU_ROOT="$demo" python3 -B scripts/secret_scan.py check                  # exit 1: one new finding
TWU_ROOT="$demo" python3 -B scripts/secret_scan.py accept                 # record it as known (rotate real keys first!)
TWU_ROOT="$demo" python3 -B scripts/secret_scan.py check                  # exit 0

python3 -B scripts/git_secret_hook.py install "$demo"                     # chain hooks into that repo
( cd "$demo" && git add leak.txt && git commit -m x )                     # BLOCKED by the hook
```
Real output from the first `check` (the fingerprint differs on every install, because it is salted):
```
leak.txt:1 aws-access-key fp=967f1ecf57
secret_scan: 1 finding(s), 1 new
```
To use it on your own repository, set `TWU_ROOT=/path/to/repo` (or run from a clone that contains the repo) and `python3 scripts/git_secret_hook.py install /path/to/repo`.

**Home folder scan.** `home_secret_scan.py check` **reads your home folder and shell history**: dotfiles, `~/.zsh_history` and `~/.bash_history`, rc files, `~/.config`, `~/Downloads`, `~/Desktop`, `~/Documents`. It prints and stores only fingerprints, but the receipt lists the home-relative path of every file that holds a credential-shaped string. It therefore refuses to run until you confirm:
```bash
python3 -B scripts/home_secret_scan.py check --yes-read-home      # or answer "y" at the prompt on a terminal
python3 -B scripts/home_secret_scan.py report                     # list the last findings (reads only the receipt)
```
Without the flag (and not on a terminal) it exits 2 and reads nothing. It never opens `~/Library` or the Keychain and never follows symlinks.

## Configuration
All settings are environment variables. An **empty value is the same as unset** (the example env file exports empty strings). `config.example.env` lists every variable; load it with `set -a; . ./my.env; set +a`. Lists use the path separator `:`.

| Variable | Default | Read by | Effect |
|---|---|---|---|
| `TWU_ROOT` | folder above `scripts/` | `secret_scan.py`, `home_secret_scan.py`, `twu_leakwatch.py` | Where `data/netguard/` and `data/health/` receipts are written, and which repo `secret_scan.py` scans. |
| `XDG_STATE_HOME` | `~/.local/state` (ignored if relative) | `secret_scan.py` and the tools that import it | Parent of `twu-leakguard/fingerprint_salt`. |
| `TWU_FP_SALT_FILE` | `$XDG_STATE_HOME/twu-leakguard/fingerprint_salt` | same | Exact path of the per-install fingerprint salt. |
| `TWU_SECRET_SCAN_CACHE` | `~/.cache/twu/secret_scan_cache.json` | `secret_scan.py` | Speed-up cache (fingerprints and file sizes/times, no secrets). |
| `TWU_SECRET_SCAN_SKIP_PREFIXES` | none | `secret_scan.py` | List of path prefixes never scanned. |
| `TWU_GIT` | `/usr/bin/git`, Homebrew paths | `secret_scan.py`, `git_secret_hook.py`, `twu_leakwatch.py` | Absolute path of git. A relative value is refused. |
| `TWU_PRIVATE_HOSTS_FILE` | `private_hosts.json` beside the script or in `../data` | `git_secret_hook.py` | JSON `{"hosts": ["name", {"host": "name", "aliases": ["x"]}]}` of private host names to block. |
| `TWU_REDACTIONS_FILE` | none | `git_secret_hook.py` | Older name for the same file; used when `TWU_PRIVATE_HOSTS_FILE` is empty. |
| `LEAKGUARD_ALLOW_MISSING` | unset | installed hooks, `git_secret_hook.py` | Exactly `1` lets one command through when python3, git or the hook script is missing (see below). Empty or any other value: fail closed. |
| `TMPDIR` | `/tmp` | installed `pre-push` hook | Where the hook keeps git's stdin for the duration of the push. |
| `HOME` | system | all | Home folder for `home_secret_scan.py` and default cache/salt paths. |
| `TWU_LEAKWATCH_PROFILE_DIR` | none (nothing read) | `twu_leakwatch.py` | Folder (relative to the scan root, or absolute) of `.md`/`.txt` notes containing your own `Phone` and `Address` rows; they are loaded into memory at run time, never stored. |
| `TWU_LEAKWATCH_PRIVATE_PREFIXES` | none | `twu_leakwatch.py` | List: folders where personal data is allowed by design (only secrets are reported there). |
| `TWU_LEAKWATCH_SYNC_PREFIXES` | none | `twu_leakwatch.py` | List: folders that sync or leave the machine (personal data is reported). |
| `TWU_LEAKWATCH_OUTBOUND_GLOBS` | none | `twu_leakwatch.py` | List of globs (`*` one level, `**` any depth) for files that are published; strictest zone. |
| `TWU_LEAKWATCH_BUSINESS_PREFIXES` | none | `twu_leakwatch.py` | List: folders where a phone number is expected; only used to word `propose-policy`. |
| `TWU_LEAKWATCH_ZONES_FILE` | `data/health/leakwatch_zones.json` | `twu_leakwatch.py` | JSON with keys `private_prefixes`, `sync_prefixes`, `outbound_globs`, `business_prefixes` (used for any list whose variable is empty). |
| `TWU_LEAKWATCH_SKIP_DIRS` | none | `twu_leakwatch.py` | List of extra folder names never entered (built in: `.git node_modules __pycache__ .venv`). |

Neutral example for leakwatch zones: `TWU_LEAKWATCH_SYNC_PREFIXES="docs/:shared/"`, `TWU_LEAKWATCH_PRIVATE_PREFIXES="notes/personal/"`, `TWU_LEAKWATCH_OUTBOUND_GLOBS="site/*.html:press/**/*.md"`.

## Files written
- `<TWU_ROOT>/data/netguard/` (`SECRETS.<host>.json`, `HOMESECRETS.<host>.json`, accepted lists) and `<TWU_ROOT>/data/health/` (leakwatch report, cache, allowlist, policy). With the default root this is **inside your clone, and receipts list file paths**: never commit `data/`, add it to `.gitignore`.
- `~/.local/state/twu-leakguard/fingerprint_salt` (random, mode 0600, folder 0700) and `~/.cache/twu/secret_scan_cache.json`.
- `.git/hooks/pre-commit`, `pre-push` (and `<name>.pre-leakguard` copies of hooks that were already there) in repositories you explicitly pass to `install`. Nothing global is touched; `core.hooksPath` repositories and symlinked hook folders are refused.

## Fingerprints and the salt (migration note)
A fingerprint is the first 10 hex characters of an HMAC-SHA256 of the matched text, keyed with a random per-install salt. Earlier versions used a plain, unsalted SHA-256 prefix, which would let someone holding only a receipt confirm a guessed low-entropy password offline. **Upgrade effect:** fingerprints from older receipts and accepted lists (`secrets_known.json`, `homesecrets_known.json`) no longer match, so every existing finding shows as new once. Review them, then run `secret_scan.py accept` and `home_secret_scan.py accept FP --reason TEXT` again. Losing or replacing the salt file has the same effect. If the salt cannot be read or created, scans that compare against a baseline stop with an error (exit 3 for the home scan, `complete=false` for `secret_scan.py`); the git hook only prints fingerprints and carries on with a one-run salt and a warning.

## The git hook fails closed
If git, python3 or the hook script is missing (for example the clone was moved or deleted), the installed hook **blocks** the commit or push with a message saying what is missing, instead of silently skipping the scan. To let one command through anyway: `LEAKGUARD_ALLOW_MISSING=1 git commit ...` (the skip is announced on stderr). `git commit --no-verify` still bypasses the hook entirely, as for any git hook. A git error during the scan also blocks; there is no override for that. The hook runs git with `--text --no-ext-diff --no-textconv` and fixed `-c diff.*` settings, so a program or setting named in a repository's own git config can neither run during the scan nor change what it sees, and runs every external tool by absolute path. `LEAKGUARD_ALLOW_MISSING` is the only environment variable the hook reads; a generic `SKIP` variable (the pre-commit framework's convention) is NOT honoured (the first release did honour any inherited `SKIP`: fixed, see `docs/RED_TEAM_SEAT5.md`). The interpreter path baked into the hook is the one that ran `install` (fallback `/usr/bin/python3`).

## What is not scanned (stated plainly)
These are evasion routes as well as speed-ups, and are not bugs:
- `secret_scan.py` skips files over 1 MB (a secret padded past 1 MB is not seen by `check`; the git hook has no size limit), non-regular files, and paths under `TWU_SECRET_SCAN_SKIP_PREFIXES` (empty by default). A NUL byte no longer exempts a file, and lines over 4000 characters are now scanned in overlapping pieces (both were skips in the first release; closed by red-team 5). Earlier versions also skipped every file named `secret_scan.py`; that exception is gone.
- `git_secret_hook.py` additionally skips any added line containing the text `leakguard:allow` (a reviewed-fixture marker; anyone who can edit the file can add it) and scans only added lines of the staged diff or pushed commits, not unchanged context.
- `home_secret_scan.py` reads files up to 1 MB (history: the newest 2 MB), at most 2500 files per folder tree, 6 levels deep, within a 20 second budget (it reports `truncated`), and skips dependency/cache/media folders, `~/Library`, symlinks and binary files.
- `twu_leakwatch.py` skips files over 2 MB, files with a binary extension that really contain a NUL byte in their first 8 KB (text saved as `notes.png` is now read), symlinks, `.git node_modules __pycache__ .venv` and `TWU_LEAKWATCH_SKIP_DIRS`; everything skipped is listed under `not_checked` in its report.
- `secret_scan.py accept` accepts **every** current finding at once, with no per-finding reason. `home_secret_scan.py accept` needs a reason per fingerprint.
- Secrets with no recognisable shape, encoded or split secrets, and history already pushed are out of scope.

## What the hook does NOT stop (a hook is advisory)
A git hook runs only if git runs it, so it is a safety net against accidents, not a barrier. Each item below was tried in the red-team round (`docs/RED_TEAM_SEAT5.md`) and is **not** stopped:
- `git commit --no-verify` / `git push --no-verify` skip the hook. `git -c core.hooksPath=/dev/null commit`, or setting `core.hooksPath` after `install`, makes git ignore `.git/hooks` (`status` then reports NOT installed).
- A repository where `install` was never run has no hook: `git clone` does not copy hooks, so every fresh clone, and each repository you forgot, is unprotected. Linked worktrees DO share the main repository's hooks. Submodules need their own `install`.
- Merge commits: the hook scans a merge's staged diff at `git commit`, but `git merge` that auto-commits runs no pre-commit hook, and `git log -p` shows no diff for a merge at push time. Content that exists on neither parent (an "evil merge") is only caught if the commit itself went through the hook.
- Commit messages, tag messages, branch names and file names other than the credential-file name list are not scanned.
- Encoded or split secrets: base64/hex, a token cut into string pieces, line continuations and similar. Zero-width characters, NUL padding (UTF-16) and full-width look-alike letters ARE folded away before matching; other Unicode confusables are not.
- The placeholder filter: a real key with a placeholder word attached to it (for example a key followed directly by `-example` or `fake`) is treated as a sample and not reported (probed: an `sk-` key with a `-example` suffix passes). The marker `leakguard:allow` on a line also skips that line; anyone who can edit the file can add it.
- A new branch pushed to a configured remote is scanned from the remote-tracking refs (`refs/remotes/<name>/*`), which are trusted: `git update-ref refs/remotes/origin/x HEAD` before pushing makes those commits look published. A push to a URL or path now scans the whole history (slower).
- Anything that can set `TWU_GIT` or replace `/usr/bin/python3` / the script the hook points at defeats the hook; so does anything that runs as you and edits `.git/hooks`.
- Submodule contents, Git LFS pointers' targets and files changed only by `--no-ext-diff` converters are not read; only what `git diff --text` prints is scanned.

## Limits and known issues
- Pattern based: it finds credential shapes, it cannot know what is secret to you. Expect false positives and misses.
- macOS tested; **Linux not run**.
- Everything runs as you: another process of the same user can change the files these tools rely on. See `SECURITY.md`.
- No example policy file for `twu_leakwatch.py` ships; `propose-policy` writes a proposal you can copy from.
- The tests build every key-shaped fixture from pieces at run time; no source file contains a scannable credential (a test checks this component's own files).

## How to run the tests
```bash
./run_tests.sh                       # python3
PYTHON=/path/to/python3.13 ./run_tests.sh
```
The suite uses its own temporary folders and its own fingerprint salt; it does not touch your real `~/.local/state` or `~/.cache`.

Re-measured after the bypass-hunt fixes (`docs/RED_TEAM_SEAT5.md`) [observed 2026-11-21, the numbers below replace the earlier ones; the older paragraph's code digest no longer applies to this folder; own tests, macOS 27.2.1 arm64, code digest `8216b138b505…`]: `env -i` with a separate realpath-resolved `HOME` and `TMPDIR` per run, three runs per interpreter, run from a copy of the tree. All 6 runs passed; no `ResourceWarning` lines; no files left in `HOME` or `TMPDIR`.

| Python | Tests ran | Raw summary lines (3 runs) |
|---|---|---|
| 3.9.6 (`/usr/bin/python3`) | 177 | `Ran 177 tests in 28.215s / OK`, `Ran 177 tests in 32.747s / OK`, `Ran 177 tests in 37.938s / OK` |
| 3.13.17 (`~/.local/bin/python3.13`) | 177 | `Ran 177 tests in 24.979s / OK`, `Ran 177 tests in 24.254s / OK`, `Ran 177 tests in 22.160s / OK` |

Skipped or failed: none. Not run from a fresh git clone (run in a working copy).

## Architecture
```
secret_scan.py (RULES, scan_text, fingerprint, salt)  <--imported by--  home_secret_scan.py, git_secret_hook.py
twu_leakwatch.py                                       (independent: zones, fixtures, allowlist/policy files, gate)
git_secret_hook.py install REPO -> .git/hooks/pre-commit + pre-push (existing hooks chained)
receipts: data/netguard/*.json (fingerprints only)   data/health/leakwatch.<host>.json (masked previews only)
```

## Security posture
- Threat model: accidents. Defends against committing, pushing or syncing common credential shapes plus private host names and MAC addresses you list. Not a defence against a determined person who uses `--no-verify`, edits the hook, or splits or encodes a secret.
- Output is `file:line TYPE fingerprint` (leakwatch: a 2+2 character masked preview), never the secret. Local only, no network, no global git config.
- Tests are the project's own; the code has had no penetration test. See `SECURITY.md`.

## License
MIT, see `LICENSE`.
