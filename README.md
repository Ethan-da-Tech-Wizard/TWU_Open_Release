# TWU open release: guardrails for AI agents that break things

I run several AI coding agents against one workspace, and I build small, standard-library-only Python tools so they are less likely to overwrite each other, run away, or leak secrets. They reduce those accidents; they do not eliminate them (recovery stories 24 and 34 record overwrites that still happened). Agents write most of the code. I set the rules, decide what counts as a pass, and review what comes back.

What makes this repo different is the record of failures. When something broke I wrote down what happened, how I found it, the fix and the test that now guards it. Five of those stories are the best place to start: a claim of mine that turned out wrong, a `--help` flag that ran a command, a scan that timed out, a fix that broke its own tests, and a filter that would have missed real leaks.

Six components are released. Each lists its tests with raw output, what is not done, and what the evidence does not prove. All tests are my own, run on one Mac. No outside party has reviewed this code.

Published by [Ethan-da-Tech-Wizard](https://github.com/Ethan-da-Tech-Wizard).

## Start here

1. This README (2 minutes): what is here and why.
2. [docs/RECOVERY_STORIES.md](docs/RECOVERY_STORIES.md), the "Read these five first" box (about 6 minutes). This is the strongest part of the repo.
3. The last two sections of the same file, "Cases I rejected as unverifiable" and "What is not proven" (2 minutes). They show where I stopped short of a claim.
4. One small component, [net_persistence_guards/](net_persistence_guards/) or [write_guards/](write_guards/): run `./run_tests.sh` and compare with its README (3 minutes). This lets you check recovery story 2 or 24 yourself.
5. [docs/VERIFICATION.md](docs/VERIFICATION.md): how this was checked, what the AI-run reviews found, what is still open.
6. [docs/KNOWN_LIMITS.md](docs/KNOWN_LIMITS.md): everything I know does not hold, on one page.
7. [docs/VOLUME_FACTS.md](docs/VOLUME_FACTS.md): only if you ask "how big is this really". It measures my private workspace, not this repo.

## What is here

Each folder is standalone: Python 3.9 or newer, standard library only, no network, no install step. Each has a README, `config.example.env`, `SECURITY.md` and a `run_tests.sh`.

| Component | What it does, in one line | Tests run on this Mac [observed] | Status |
|---|---|---|---|
| [malakopia_core](malakopia_core/) | A small local workflow engine: a goal is split into checked steps, scripts do the work, and a separate validator, never the model, marks a step passed. | 103 ran, 1 skipped, OK | working, tests pass (own tests only, macOS only) |
| [enki_waypoint](enki_waypoint/) | Typed stage contracts over a local job queue: the worker is not the verifier, repairs are capped at two, each receipt is hash-bound to its evidence. | 107 tests, OK | working, tests pass (own tests only, macOS only) |
| [net_persistence_guards](net_persistence_guards/) | Compare listening ports, gateway, DNS and startup items to a baseline you accepted, and say what changed. | 95 tests, OK | working, tests pass (own tests only, macOS only) |
| [secret_leak_tools](secret_leak_tools/) | Four scanners that find credential-shaped strings and personal data in the wrong place, plus git hooks that block a commit or push. | 177 tests, OK | working, tests pass (own tests only, macOS only) |
| [stop_latch_autonomy](stop_latch_autonomy/) | One shared STOP file that cooperating workers obey, and a small rule table that classes an action as AUTO, PROPOSE or NEVER. | 39 tests, OK | working, tests pass (own tests only, macOS only) |
| [write_guards](write_guards/) | Compare-and-swap writes, single-writer locks and signal guards, so two writers cannot silently overwrite one file. | 62 tests, OK | working, tests pass (own tests only, macOS only) |

How to read the test column: counts and the `OK` verdict come from one final measured run on 2026-11-21 (macOS arm64, Python 3.9.6 and 3.13.17, three runs each, `env -i`, separate scratch `HOME` and `TMPDIR`, code digest `8216b138b505…`, see docs/VERIFICATION.md), recorded with raw output in [docs/VERIFICATION.md](docs/VERIFICATION.md). Every run gave the same counts. They are tests that ran, not a pass rate over the code, and they will move as tests are added. Run `./run_all_tests.sh` for the numbers on your machine. One unexplained intermittent failure of the `malakopia_core` suite is described in [docs/KNOWN_LIMITS.md](docs/KNOWN_LIMITS.md).

Two components share one module: `malakopia_job_queue.py` is copied byte for byte into `enki_waypoint/scripts/` so that folder runs alone. `tools/check_queue_sync.sh` fails if the copies drift.

## Try it

```bash
cd TWU_Open_Release        # the folder you cloned
./run_all_tests.sh         # every component, one summary table
PYTHON=/path/to/python3.13 ./run_all_tests.sh
```

CI (`.github/workflows/ci.yml`) is a matrix of ubuntu-24.04 and macOS, Python 3.9 and 3.13. For the release commit all 26 jobs were green: [run 44962057871](https://github.com/Ethan-da-Tech-Wizard/TWU_Open_Release/actions/runs/44962057871). I ran the tests myself only on macOS. The Linux code paths (systemd units, cron, `/proc`) are exercised by tests with fixtures, not on a real Linux machine I operate.

## Related repositories

These overlap on purpose; they come from the same AI-assisted workflow, so they are not independent confirmations of each other.

- [agent-guardrails](https://github.com/Ethan-da-Tech-Wizard/agent-guardrails): an older standalone copy of the stop latch, write guards and secret scanner.
- [release-kit](https://github.com/Ethan-da-Tech-Wizard/release-kit): the scrub-and-gate tool used to prepare releases like this one.


## What I did, and what AI agents did

Agents write most of the code in this repo, run most of the tests, and wrote the reviews listed in [docs/VERIFICATION.md](docs/VERIFICATION.md). I choose what gets built and what gets published, and I push it by hand.

What the record can actually show about my part is narrower than I would like, so here is only what I can point to:

- In recovery story 2, an agent re-saved a network baseline by accident. The fix was limited to the one entry the alarm had named, and accepting the listener was left to me.
- In story 6, an agent did not re-pin a trust record, because that is a trust decision. I was given the exact steps.
- In story 26, an agent could not prove who recreated 23 repositories, so it left the incidents open instead of closing them.

Those are agents deferring a decision to me [relayed: read from my own CHANGELOG, not re-run]. I do not have a comparable record of decisions I made that an agent did not, so I make no larger claim here. The stories do show the rule I set (no green claim without evidence, and say what you could not prove) being followed, which is the kind of thing I review for.

## How it was verified

- Every component's own unit tests, run on macOS with Python 3.9 and 3.13, with a scratch `HOME` and `TMPDIR` [observed].
- A fresh-clone run of every quick start by an agent, with a separate review of engineering quality, security, privacy leaks and first impressions [observed, agent-run; findings and their status are in [docs/VERIFICATION.md](docs/VERIFICATION.md)].
- `tools/check_placeholders.sh` fails the build on leftover placeholders, private paths, key blocks, token-like strings and a short list of hype words.
- CI (`.github/workflows/ci.yml`) runs the same on GitHub's Ubuntu and macOS runners. A green check means those checks passed, nothing more.

## Known limits

The full list is in [docs/KNOWN_LIMITS.md](docs/KNOWN_LIMITS.md). The short version:

- **Tested on macOS only.** Linux has not been run by me. CI will show whether it passes there; until I have read that run, treat Linux as unsupported.
- **Counts are static definitions, not pass rates.** "14,930 test definitions" in [docs/VOLUME_FACTS.md](docs/VOLUME_FACTS.md) is an AST count of test functions in my private workspace, not a count of passes, and not a claim about this repo.
- **Tests are mine, and the reviews were agent-assisted.** No independent human or third party has reviewed this code. Several fixes were reviewed by the same agent system that wrote them.
- **Not a security boundary.** These tools notice and prevent accidents by a cooperating, same-user process. They do not stop a hostile one. See [SECURITY.md](SECURITY.md).
- **Most recovery stories are [relayed],** meaning read from my own notes, not re-run. The ones whose guard tests ship here have a "Reproduce" line you can run.
- **Open review findings** are listed, not hidden, in [docs/VERIFICATION.md](docs/VERIFICATION.md).
- **One unexplained intermittent failure** of the `malakopia_core` suite on Python 3.13 was seen once in about 100 runs; see [docs/KNOWN_LIMITS.md](docs/KNOWN_LIMITS.md).

## Glossary

- **TWU**: the short name of my company. It appears as a prefix in some file and variable names (`TWU_ROOT`, `twu_leakwatch.py`). It carries no meaning for how the code works.
- **Malakopia**: my name for a small local workflow engine. Its rule: a script or a model does a bounded step, and a separate validator, never the thing that did the work, decides whether the step passed. Component: `malakopia_core`.
- **Enki**: my name for stage contracts built on the Malakopia job queue. A worker does a stage; a separate check verifies it; receipts are hash-bound. Component: `enki_waypoint`.
- **Magi / seat**: one of my numbered AI agent sessions ("Magi 6" is session number 6). A "seat" is one such session. When a story says "an agent", it means one of these sessions, not me.
- **STOP latch**: a single file called `STOP`. While it exists, cooperating workers refuse to start; when it appears, running workers are told to exit and exit with status 0 after a grace period if they ignore the signal. It is a polite shared signal, not an enforced kill switch.

## Contributing, security, licence

[CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) (private vulnerability reporting through GitHub), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). MIT licence, see [LICENSE](LICENSE). Found a wrong claim? Open an issue with the "Correction or overclaim" template; corrections are welcome.
