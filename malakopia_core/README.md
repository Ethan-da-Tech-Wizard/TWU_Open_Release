# Malakopia core

> Status: working, tests pass (own tests only, macOS tested, Linux not run) | Python 3.9+, standard library only | POSIX (uses `fcntl` and `sqlite3`)

## What it is
A small local workflow engine. A goal is split into small checked steps, scripts do the exact work, and a separate validator (never the model) marks a step passed. The component contains:

- `malakopia_engine`: a resumable serial runner with a journal, artifact hashes and bounded attempts.
- `malakopia_completion`: a bounded generate / validate / repair controller (at most 4 attempts).
- `malakopia_decompose` and `malakopia_local_tasks`: a splitter for one fixed fixture.
- `malakopia_job_queue`: a SQLite job queue with leases. A lost lease becomes `needs_review`, never a silent retry.
- `malakopia_export`: a reproducible, allowlist-only zip exporter with a SHA-256 manifest.
- `examples/one_command.py`: a 12-step runnable example.

## Why it exists
Cheap models and long runs claim success falsely, lose state on a crash and retry forever. Malakopia keeps state in a journal, limits attempts, and lets only an independent check accept work.

## Requirements
- Python 3.9 or newer (tested on 3.9.6 and 3.13), standard library only. No install step, no network, no root.
- macOS or another POSIX system. macOS is the only system tested.

## Quick start
```bash
REPO_URL=https://github.com/Ethan-da-Tech-Wizard/TWU_Open_Release
git clone "$REPO_URL"
cd TWU_Open_Release/malakopia_core
STATE=$(mktemp -d)                      # private (mode 0700) folder, not a shared /tmp name
python3 examples/one_command.py --state-dir "$STATE/run" | head -8
```
Real output from a run of the same command (ids and times differ on every run):
```
{
  "run_id": "20261121T173551-19861d8571fa4554",
  "workflow": "portable-example",
  "version": 1,
  "status": "succeeded",
  "resumed": false,
  "steps": {
```
The command exits 0 when the status is `succeeded`. Writes only to the state folder you pass, plus the job queue state (see the config table).

## Configuration
Every variable is optional. An empty value counts as unset. `config.example.env` lists them all.

| Variable | Default | Meaning |
|---|---|---|
| `MALAKOPIA_JOBS_STATE_DIR` | macOS: `~/Library/Application Support/malakopia/jobs/<hash>`; else `$XDG_STATE_HOME` or `~/.local/state`, then `malakopia/jobs/<hash>` | Folder for the job queue database. Created with mode 0700; an existing folder must already be private. |
| `XDG_STATE_HOME` | `~/.local/state` | Base folder of the default queue state on non-macOS systems. |
| `MALAKOPIA_EXPORT_ROOT` | the component folder | Root that export paths are relative to. |
| `MALAKOPIA_EXPORT_DESTINATION` | `dist/malakopia-source.zip` | Output zip, relative to the export root. |
| `MALAKOPIA_LICENSES_DIR` | `licenses` | Licence folder (relative to the export root) that must contain `manifest.json`. |
| `MALAKOPIA_EXPORT_ALLOWLIST` | `<root>/export_allowlist.json` | JSON `{source path: archive path}`. Missing file means an empty list, and the export refuses to run. |

To export, copy `export_allowlist.example.json` to `export_allowlist.json` and run `python3 scripts/malakopia_export.py`.

## Tests
```bash
./run_tests.sh                          # uses python3
PYTHON=/path/to/python3.13 ./run_tests.sh
```
Final measured run [observed 2026-11-21, own tests, macOS 27.2.1 arm64, code digest `8216b138b505…`]: `env -i` with a separate realpath-resolved `HOME` and `TMPDIR` per run, three runs per interpreter, run from a copy of the tree. All 6 runs passed; no `ResourceWarning` lines; no files left in `HOME` or `TMPDIR`.

| Python | Tests ran | Raw summary lines (3 runs) |
|---|---|---|
| 3.9.6 (`/usr/bin/python3`) | 103 | `Ran 103 tests in 2.454s / OK`, `Ran 103 tests in 3.244s / OK`, `Ran 103 tests in 2.533s / OK` |
| 3.13.17 (`~/.local/bin/python3.13`) | 103 | `Ran 103 tests in 1.674s / OK`, `Ran 103 tests in 1.608s / OK`, `Ran 103 tests in 1.400s / OK` |

No tests are skipped. The tests use real short sleeps, so on a very loaded machine a timing-sensitive test could flake.

## Architecture
```
examples/one_command.py --> scripts/malakopia_engine.py (journal, hashes, attempts, resume)
scripts/malakopia_completion.py  (goal contract -> candidate JSON -> independent validator -> 4 attempts by default, configurable from 1 to 20)
scripts/malakopia_decompose.py + malakopia_local_tasks.py (one fixture split into single-case calls)
scripts/malakopia_job_queue.py   (SQLite leases; a lost lease becomes "needs_review", never silently retried)
scripts/malakopia_export.py      (allowlist JSON -> reproducible zip + manifest with SHA-256)
```
`docs/WORKER_CARD.md` is a short instruction card for a worker that runs under these rules.

## Security posture
- Defends against a worker or model that claims success without evidence, runs forever, or loses state on a crash.
- Out of scope: running untrusted code safely (handlers you register are ordinary Python), multi-machine coordination, authentication.
- No network, no model and no process launching by the engine itself. The exporter refuses to run until you supply an allowlist.
- The queue folder is private to the current user and the queue never changes the permissions of a folder it did not create.
- The queue module is shipped twice (here and in `enki_waypoint`); see SECURITY.md for how the copies are kept identical.
- These are guardrails, not a security boundary and not an independent audit. See SECURITY.md.

## Limits and known issues
- macOS tested. Linux has not been run.
- The queue database is machine-local; never copy it between machines.
- Most of the code was written with AI coding agents and reviewed by the maintainer; the tests are the project's own.
- There is no real model adapter in this component, only the controller that would drive one.
- No CI configuration yet.

## License
MIT, see `LICENSE`. The licence text is also kept under `licenses/` for the exporter.
