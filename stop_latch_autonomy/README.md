# STOP latch and autonomy policy

> Status: working, tests pass (own tests only, macOS tested, Linux not run) | Python 3.9+, standard library only

## What it is
Two small tools for unattended automation.

- `stop_latch.py`: one shared STOP file. A cooperating worker calls `enforce(name)` at startup. While the file exists the worker refuses to start. If the file appears while the worker runs, the worker receives SIGTERM, and if it is still running after a grace period (default 30 s) the process exits at once with status 0 (`os._exit`), without running cleanup handlers.
- `twu_autonomy.py`: a rule table that classifies an action name as AUTO (may run by itself), PROPOSE (must ask first) or NEVER (must not happen). NEVER beats PROPOSE beats AUTO. Unknown actions are PROPOSE. A broken policy file fails closed (everything PROPOSE).

## The STOP latch concept
A latch is a switch that stays set until a person clears it. Here the switch is the existence of a file named `STOP`:

1. You create the file (`touch STOP`) when something is going wrong and you want all automation to pause.
2. Every worker that called `enforce()` notices within a few seconds (it polls with one `stat()` call, near-zero CPU) and shuts down cleanly with SIGTERM first, so its own shutdown handlers run.
3. New workers that call `enforce()` see the file and exit immediately without doing any work.
4. Nothing resumes by itself. You delete the file when it is safe, and workers started afterwards run normally.

It is cooperative: a process that never calls `enforce()` is not affected, and anyone who can create the file can stop every cooperating worker. It is a polling hint with a hard-exit fallback, not an access-control mechanism.

## Why it exists
Unattended workers need one thing everybody checks to stop work, and a written rule for what may run by itself. Both are checked by code instead of being remembered.

## Requirements
- Python 3.9 or newer (tested on 3.9.6 and 3.13), standard library only. No install step, no network, no root.
- macOS or another POSIX system (SIGTERM based). macOS is the only system tested.

## Quick start
```bash
REPO_URL=https://github.com/Ethan-da-Tech-Wizard/TWU_Open_Release
git clone "$REPO_URL"
cd TWU_Open_Release/stop_latch_autonomy
DEMO=$(mktemp -d)                                    # private folder, not a shared /tmp name
STOP_LATCH_ROOT="$DEMO" python3 scripts/stop_latch.py    # STOP absent
touch "$DEMO/STOP"
STOP_LATCH_ROOT="$DEMO" python3 scripts/stop_latch.py    # STOP present
TWU_ROOT="$DEMO" python3 scripts/twu_autonomy.py check send_telemetry    # exit code 4
```
Real output from a run of the same commands:
```
STOP absent
STOP present
NEVER send_telemetry
never-telemetry [NEVER] match=send_telemetry*
  reason: telemetry to third parties
  source: Project policy: nothing sends telemetry to anyone outside the project's own systems
```
The last command exits 4 (NEVER); AUTO exits 0 and PROPOSE exits 3, so shell scripts can branch on the result. In a worker, use `import stop_latch; stop_latch.enforce("my-worker")`.

## The policy file
`data/health/autonomy_policy.json` is a neutral example policy that lists exactly the built-in seed rules (a test checks that they match). Copy it, edit it, and check it with `python3 scripts/twu_autonomy.py validate`. Each rule is `{id, class, match, reason, source, expires?}`, where `match` is a glob on the action name. A seeded NEVER rule cannot be loosened or removed unless the edited rule has `"explicit_widen": true` and a future `expires` date. Commands: `check`, `explain`, `list`, `log`, `validate`. Decisions made by `check` are appended to `<root>/data/health/autonomy_log.<host>.jsonl`.

## Configuration
Every variable is optional. An empty value counts as unset. `config.example.env` lists them all.

| Variable | Default | Meaning |
|---|---|---|
| `STOP_LATCH_FILE` | none | Exact path of the STOP file. Wins over `STOP_LATCH_ROOT`. A relative path is resolved against each process's current directory, so use an absolute one. |
| `STOP_LATCH_ROOT` | the component folder (parent of `scripts/`) | Folder; the STOP file is `<folder>/STOP`. |
| `TWU_ROOT` | the component folder | Root for `data/health/autonomy_policy.json` and the decision log. |

Both STOP variables are read once, when `stop_latch` is imported.

## Tests
```bash
./run_tests.sh                          # uses python3
PYTHON=/path/to/python3.13 ./run_tests.sh
```
Re-measured after the bypass-hunt fixes (`docs/RED_TEAM_SEAT5.md`) [observed 2026-11-21, the numbers below replace the earlier ones; the older paragraph's code digest no longer applies to this folder; own tests, macOS 27.2.1 arm64, code digest `8216b138b505…`]: `env -i` with a separate realpath-resolved `HOME` and `TMPDIR` per run, three runs per interpreter, run from a copy of the tree. All 6 runs passed; no `ResourceWarning` lines; no files left in `HOME` or `TMPDIR`.

| Python | Tests ran | Raw summary lines (3 runs) |
|---|---|---|
| 3.9.6 (`/usr/bin/python3`) | 39 | `Ran 39 tests in 1.686s / OK`, `Ran 39 tests in 1.615s / OK`, `Ran 39 tests in 1.507s / OK` |
| 3.13.17 (`~/.local/bin/python3.13`) | 39 | `Ran 39 tests in 1.218s / OK`, `Ran 39 tests in 1.289s / OK`, `Ran 39 tests in 1.259s / OK` |

No tests are skipped. The tests use real short sleeps, so on a very loaded machine a timing-sensitive test could flake.

## Architecture
```
worker --enforce("name")--> stop_latch: STOP present? -> exit 0 | else daemon thread polls stat() -> SIGTERM -> os._exit after grace
action name --> twu_autonomy: match rules (glob) -> strongest class wins -> exit 0 AUTO | 3 PROPOSE | 4 NEVER
```

## Security posture
- A cooperative kill switch and a policy lookup. Neither enforces anything: callers must ask and obey.
- Unknown actions are PROPOSE; a malformed policy file makes everything PROPOSE; seeded NEVER rules cannot be loosened silently.
- These are guardrails, not a security boundary and not an independent audit. See SECURITY.md.

## Limits and known issues
- Found by the seat-5 bypass hunt and fixed: a dangling symlink at the STOP path counted as "no STOP"; an unreadable STOP folder crashed the watcher thread (Python 3.9) or read as "no STOP" (3.12+): now only "no such file or folder" means absent; a relative `STOP_LATCH_FILE` followed `os.chdir()` to another file (now made absolute at import); a custom `on_stop` callback that raised left STOP unhandled (the default shutdown now runs); in `twu_autonomy` a seeded NEVER rule kept word for word but given a past `expires` date was silently switched off (now restored like any other loosening) and an action name ending in a newline was accepted. Not fixed, by design: the latch is cooperative and level-triggered (a STOP file created and removed between two polls is missed), and `twu_autonomy` classifies by action NAME only (`regenerate_delete_model_weights` matches only the AUTO `regenerate_*` rule), and its policy file and decision log are not pinned or signed. Details: `../docs/RED_TEAM_SEAT5.md`.
- Cooperative only: a worker that does not call `enforce` is not affected.
- It polls `stat()` every few seconds; it is not a file-event watch.
- macOS tested; Linux has not been run.
- Most of the code was written with AI coding agents and reviewed by the maintainer; the tests are the project's own.

## License
MIT, see `LICENSE`.
