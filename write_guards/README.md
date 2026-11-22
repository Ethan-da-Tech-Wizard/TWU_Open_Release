# Guarded write, write guard and signal guard

> Status: working; own tests pass on macOS (arm64) with Python 3.9.6 and 3.13. **Linux has not been run.** Not an independent audit.

## What it is
Three small standard-library Python modules that make the safe way of writing shared files the easy way:

| Module | What it does |
|---|---|
| `scripts/guarded_write.py` | Compare-and-swap writes: the file is replaced only if it still has the SHA-256 you read, under a per-file exclusive lock, via a temp file and an atomic rename. |
| `scripts/write_guard.py` | Single-writer lock files with a TTL and stale-lock reclaim, plus task-root path validation (`..`, symlinks that point out, sibling folders with a shared name prefix are refused). |
| `scripts/signal_guard.py` | While a unittest run is in progress, refuses signals that could reach the whole session (pid 0, 1, negative, mocks, the test's own process group or parent). |

## Why it is needed
Several writers (people or programs) overwrite each other's shared files without noticing, and a mocked `os.killpg` can end a whole desktop session. These make the safe path the easy one.

## Requirements
Python 3.9 or newer, standard library only, POSIX (`fcntl`, `O_NOFOLLOW`, `dir_fd`). No install step, no network, no root.

## Quick start
Run from this folder (`write_guards/`). It works in a fresh clone:
```bash
work=$(mktemp -d) && printf 'v1\n' > "$work/notes.txt"
H=$(python3 -B scripts/guarded_write.py hash "$work/notes.txt")
echo v2 | python3 -B scripts/guarded_write.py write "$work/notes.txt" --expect "$H"    # exit 0, prints the new hash
echo v3 | python3 -B scripts/guarded_write.py write "$work/notes.txt" --expect "$H"    # exit 3: the file changed since $H

echo hello | python3 -B scripts/write_guard.py write --path "$work/sub/a.txt" --task-root "$work" --agent me   # exit 0
echo hi    | python3 -B scripts/write_guard.py write --path /tmp/outside.txt   --task-root "$work" --agent me   # exit 2, REFUSED
```
Real output of the third command (the paths and hashes differ on every run):
```
CONCURRENT MODIFICATION: <work>/notes.txt changed since it was read (expected 2d27fbdf4e8c, found 81db67b6a570); nothing written
exit 3
```
Exit codes: `guarded_write.py` 0 written, 3 conflict, 2 bad use or refusal. `write_guard.py` 0 ok, 2 refused (outside the root or an unsafe path), 75 blocked by another writer's lock. There are no retry loops: the caller decides.

`signal_guard.py` is **not applied automatically**: nothing here installs itself (no `.pth`, no `sitecustomize`). A test suite calls `signal_guard.install()`. Once installed, any process that has `unittest` loaded gets the blocks, including a program that imports `unittest` for some other reason and legitimately signals pid 1 or a negative pid.

## Where the files go
- **`guarded_write.py` lock files are NOT beside the target.** They are in one per-user folder: `$TWU_WRITE_LOCK_DIR` if set, else `$XDG_STATE_HOME/twu-write-locks` (absolute value only), else `~/.local/state/twu-write-locks`. The folder is created with mode 0700 and checked on every use: it must be a real directory (not a symlink) owned by you, or the write is refused. Lock files are mode 0600, named by a hash of the target's resolved path, opened without following symlinks. (Earlier versions used a predictable path in the shared temp folder.)
- `guarded_write.py` also creates a temp file `.gw-<random>` beside the target, renamed over it or removed.
- `write_guard.py` keeps locks under `<data root>/data/locks/` (data root = `--root`, default the task root): lock records (mode 0600, folder 0700) and `reclaim.log.jsonl`. They name agents and paths: do not commit `data/`.
- `write_guard.py` writes a temp file `.wg-<random>.tmp` beside the target, renamed over it or removed.

## Configuration
All settings are environment variables. An **empty value is the same as unset**. `config.example.env` lists every variable.

| Variable | Default | Read by | Effect |
|---|---|---|---|
| `TWU_WRITE_LOCK_DIR` | see below | `guarded_write.py` | Exact lock folder (created 0700, must be yours). |
| `XDG_STATE_HOME` | `~/.local/state` (ignored if relative) | `guarded_write.py` | Parent of `twu-write-locks/` when `TWU_WRITE_LOCK_DIR` is empty. |
| `HOME` | system | `guarded_write.py` | Used for the `~/.local/state` fallback. |
| `WRITE_GUARD_HOLD_S` | none | `write_guard.py` | Test hook: seconds to hold the lock before writing. Invalid values are ignored. Never set in normal use. |
| `WRITE_GUARD_HOLD_FILE` | none | `write_guard.py` | Test hook: hold the lock while this file exists (60 second cap). Never set in normal use. |

The modules read no other environment variables.

## What the path checks do and do not guarantee
Both writers resolve the target, open its parent folder once with `O_DIRECTORY | O_NOFOLLOW`, and do the existence check, hash, temp-file creation and rename relative to that folder descriptor; the final file is opened with `O_NOFOLLOW`. `write_guard.py` additionally re-checks, from the descriptor itself (macOS `F_GETPATH`, Linux `/proc/self/fd`), that the folder is still inside the task root. Remaining TOCTOU, stated honestly:
- `realpath()` of the parent runs before the folder is opened; a process that can swap a folder in the path at exactly that instant can redirect the write.
- Missing parent folders are created with `os.makedirs`, which follows symlinks in parts that already exist.
- Where the platform cannot report a descriptor's path, the descriptor re-check is skipped.
- A hostile writer who shares the folder can still race these windows. These are guardrails for cooperating writers, not a security boundary; see `SECURITY.md`.

## Limits and known issues
- Found by the seat-5 bypass hunt and fixed: a relative `TWU_WRITE_LOCK_DIR` (now refused), a FIFO at the target name wedging `guarded_write` (now refused at once), `write_guard append` through a hard link to a file outside the root (now refused; a file with several names is not appended to), lock records that are not JSON objects or carry a non-numeric TTL (now handled), and `signal_guard` allowing a signal to the parent's own process group (now refused). Not fixed, by design: a lock holder chooses its own `--ttl`, so a holder can make its lock stale immediately; locks and the root check remain advisory (see above). Details: `../docs/RED_TEAM_SEAT5.md`.
- Locks are advisory: a program that writes the file directly ignores them.
- Lock liveness is a pid check on this host; a recycled pid looks alive until its TTL expires, and a lock folder shared between machines is judged against the wrong process table.
- Not tested on network filesystems. macOS tested; **Linux not run**.
- On macOS, two processes creating the same new file relative to a directory descriptor at the same instant can see a spurious `ENOENT` (observed here, about half of simultaneous first-time creations); the code retries up to 50 times. This workaround is only exercised on macOS.
- `write_guard.touch()` (lock heartbeat) has no CLI command; it is public API for long-running writers.

## How to run the tests
```bash
./run_tests.sh                       # python3
PYTHON=/path/to/python3.13 ./run_tests.sh
```
The race tests are deterministic: the lock holder waits for an event or a hold file instead of sleeping a guessed time, and lock ageing uses an injected clock. The suite keeps lock files in its own temporary folders.

Re-measured after the bypass-hunt fixes (`docs/RED_TEAM_SEAT5.md`) [observed 2026-11-21, the numbers below replace the earlier ones; the older paragraph's code digest no longer applies to this folder; own tests, macOS 27.2.1 arm64, code digest `8216b138b505…`]: `env -i` with a separate realpath-resolved `HOME` and `TMPDIR` per run, three runs per interpreter, run from a copy of the tree. All 6 runs passed; no `ResourceWarning` lines; no files left in `HOME` or `TMPDIR`.

| Python | Tests ran | Raw summary lines (3 runs) |
|---|---|---|
| 3.9.6 (`/usr/bin/python3`) | 62 | `Ran 62 tests in 2.766s / OK`, `Ran 62 tests in 2.611s / OK`, `Ran 62 tests in 2.561s / OK` |
| 3.13.17 (`~/.local/bin/python3.13`) | 62 | `Ran 62 tests in 1.475s / OK`, `Ran 62 tests in 1.072s / OK`, `Ran 62 tests in 1.338s / OK` |

Skipped or failed: none. Not run from a fresh git clone (run in a working copy).

## Architecture
```
guarded_write.py: hash PATH | write PATH --expect SHA     flock (per-user lock folder) + temp file + rename
write_guard.py:   write | append | lock-status | reclaim-stale   lock files + task-root validation
signal_guard.py:  install() wraps os.kill / os.killpg; refuses dangerous targets only while unittest is loaded
```

## Security posture
- Threat model: lost updates between cooperating writers and one class of test accident. Out of scope: hostile writers, writers that bypass the tool, network filesystems with unreliable locks.
- `guarded_write.py` writes nothing unless the expected hash still matches. `signal_guard` does nothing outside a unittest run.
- Tests are the project's own; the code has had no penetration test.

## License
MIT, see `LICENSE`.
