# Enki Waypoint

> Status: working, tests pass (own tests only, macOS tested, Linux not run) | Python 3.9+, standard library only (SQLite) | POSIX

## What it is
Typed, bounded stage contracts over a local SQLite job queue. An authorised task becomes one immutable job, the worker is not the verifier, repairs are limited to two, and every receipt is hash-bound to its evidence. `enki_runtime.py` and `enki_adaptive_learning.py` can record a verified outcome into a small BKT mastery tracker and a LinUCB task recommender. Nothing here starts a process, a model or a network request. `malakopia_job_queue.py` is a copy of the queue from the `malakopia_core` component, included so this folder runs on its own.

## Why it exists
Stage work done by cheap workers needs a record and a hard limit on retries. Otherwise a failed stage is retried forever, or reported as done by the same worker that did it. Enki stores each stage as a job and writes hash-bound receipts. The record is tamper-evident only: it is protected by SQLite triggers in a file the current user can write, so it can be trusted against honest workers, not against anything running as that user.

## Requirements
- Python 3.9 or newer (tested on 3.9.6 and 3.13), standard library only. No install step, no network, no root.
- macOS or another POSIX system. macOS is the only system tested.

## Quick start
```bash
REPO_URL=https://github.com/Ethan-da-Tech-Wizard/TWU_Open_Release
git clone "$REPO_URL"
cd TWU_Open_Release/enki_waypoint
STATE=$(mktemp -d)                      # private (mode 0700) folder, not a shared /tmp name
python3 scripts/enki_waypoint.py --state-dir "$STATE/queue" status
ENKI_ADAPTIVE_STATE_ROOT="$STATE/adaptive" python3 scripts/enki_runtime.py status | head -8
```
Real output from a run of the same commands:
```
{"jobs": 0, "schema": "enki.waypoint.v1", "state": "not_initialized"}
{
  "bandit_arms": 0,
  "engine": "BKT_LinUCB",
  "mastery": {},
  "mode": "private_adaptive_learning",
  "parameters": {
    "guess": 0.2,
    "learn": 0.12,
```
Other commands: `create`, `claim`, `finish`, `record-adaptive`, `reconcile` (see `--help`).

## Configuration
Every variable is optional. An empty value counts as unset. `config.example.env` lists them all.

| Variable | Default | Meaning |
|---|---|---|
| `MALAKOPIA_JOBS_STATE_DIR` | macOS: `~/Library/Application Support/malakopia/jobs/<hash>`; else `$XDG_STATE_HOME` or `~/.local/state`, then `malakopia/jobs/<hash>` | Base folder for the job queue. Created with mode 0700; an existing folder must already be private. `--state-dir` overrides it per command. |
| `XDG_STATE_HOME` | `~/.local/state` | Base folder of the default queue state on non-macOS systems. |
| `ENKI_ADAPTIVE_STATE_ROOT` | `./state` inside this component folder | Absolute folder where the learner state file may live. It must be private (mode 0700) and free of symlinks. |

## Tests
```bash
./run_tests.sh                          # uses python3
PYTHON=/path/to/python3.13 ./run_tests.sh
```
Final measured run [observed 2026-11-21, own tests, macOS 27.2.1 arm64, code digest `8216b138b505…`]: `env -i` with a separate realpath-resolved `HOME` and `TMPDIR` per run, three runs per interpreter, run from a copy of the tree. All 6 runs passed; no `ResourceWarning` lines; no files left in `HOME` or `TMPDIR`.

| Python | Tests ran | Raw summary lines (3 runs) |
|---|---|---|
| 3.9.6 (`/usr/bin/python3`) | 107 | `Ran 107 tests in 2.968s / OK`, `Ran 107 tests in 3.880s / OK`, `Ran 107 tests in 2.921s / OK` |
| 3.13.17 (`~/.local/bin/python3.13`) | 107 | `Ran 107 tests in 1.700s / OK`, `Ran 107 tests in 1.564s / OK`, `Ran 107 tests in 1.389s / OK` |

No tests are skipped. The tests use real short sleeps, so on a very loaded machine a timing-sensitive test could flake.

## Architecture
```
enki_waypoint.py  create -> claim -> finish (receipt, hashes) -> status / reconcile   (max 2 repairs)
   |-- malakopia_job_queue.py (SQLite leases)
   `-- enki_runtime.py -> enki_adaptive_learning.py (BKT + LinUCB; state file mode 0700, no symlinks)
```
Key files: `scripts/enki_waypoint.py`, `scripts/enki_runtime.py`, `scripts/enki_adaptive_learning.py`, `scripts/malakopia_job_queue.py`.

## Security posture
- Records and limits staged work done by cooperating workers. Actor names in receipts document accountability but are not authentication.
- Tamper-evident only: nothing stops a process running as the same user from dropping the triggers or editing the database.
- Out of scope: proving a worker did what it claims beyond the recorded hashes, and access control.
- Local only; no process, model or network. The learner refuses state paths outside its configured root.
- The queue module is shipped twice (here and in `malakopia_core`); see SECURITY.md for how the copies are kept identical.
- These are guardrails, not a security boundary and not an independent audit. See SECURITY.md.

## Limits and known issues
- Cooperative: nothing stops a worker from writing to the queue database directly.
- The queue database is machine-local and POSIX only. macOS tested; Linux has not been run.
- The learner module creates and sets mode 0700 on its state root, so point `ENKI_ADAPTIVE_STATE_ROOT` at a dedicated folder only.
- The recommender is a small statistical helper, not a trained model; its quality was not evaluated.
- Most of the code was written with AI coding agents and reviewed by the maintainer; the tests are the project's own.

## License
MIT, see `LICENSE`.
