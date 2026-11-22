# How this was verified, and what is still open

This page says what was checked, by whom, what it found, and what I have and have not fixed. Tags: **[observed]** means a command was run and its output read in the pass that produced the statement. **[static]** means read from code without running it. **[relayed]** means read from someone else's notes. **Every review below was run by an AI agent, not by an independent human.** That is a limit, not a footnote. The full list of what does not hold is in [KNOWN_LIMITS.md](KNOWN_LIMITS.md).

## 1. The component test suites

Each component has a `run_tests.sh` (unittest discovery, standard library only). `./run_all_tests.sh` at the repo root runs all of them and prints one table, plus the queue-copy check and the leak check.

### The final measured run [observed 2026-11-21]

This is the one run every test table in this repository quotes: the root README table and each component README.

- Date: 2026-11-21. Machine: one Mac, macOS 27.2.1 (Darwin 27.2.0), arm64.
- Interpreters: `/usr/bin/python3` is Python 3.9.6; `~/.local/bin/python3.13` is Python 3.13.17.
- Method: the tree was copied to a scratch folder (without `.git`). For each interpreter, three times: a fresh scratch `HOME` and `TMPDIR` (each resolved with `pwd -P`), then every component's `run_tests.sh`, then `./run_all_tests.sh`, all started with `env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin HOME=... TMPDIR=... PYTHON=<interpreter>`. That is 36 component runs and 6 whole-repo runs.
- Tree state: the published commit (the tested copy and the published tree have identical code). The code files in the tested copy have the SHA-256 digest `8216b138b5056b1f302418d1081995e53f748ee45f58d1d386ff80c0b3996912` (digest of the sorted per-file SHA-256 list of every `.py`, `.sh`, `.env`, `.json`, `.txt` and `LICENSE` file). Documentation edits made after the run, for example pasting these numbers, are not tests and are not in that digest.
- Result: 36 of 36 component runs green and 6 of 6 whole-repo runs green; counts identical across all runs; 480 tests per interpreter. No `ResourceWarning` lines in any output, and `HOME` and `TMPDIR` were empty after every run.

| Component | Tests ran | Result | Time on 3.9.6 (3 runs) | Time on 3.13.17 (3 runs) |
|---|---|---|---|---|
| enki_waypoint | 107 | OK | 2.9 to 3.9 s | 1.4 to 1.7 s |
| malakopia_core | 103 | OK | 2.5 to 3.2 s | 1.4 to 1.7 s |
| net_persistence_guards | 95 | OK | 0.6 to 0.9 s | 0.3 to 0.5 s |
| secret_leak_tools | 177 | OK | 15.6 to 19.9 s | 10.2 to 12.0 s |
| stop_latch_autonomy | 39 | OK | 1.3 to 1.4 s | 1.1 to 1.2 s |
| write_guards | 62 | OK | 2.0 to 2.2 s | 0.8 to 1.4 s |

Whole-repo runs (`./run_all_tests.sh`; the last two columns are the two repo-level checks):

| Python | Run | Tests across components | Queue copies identical | Leak check | Result |
|---|---|---|---|---|---|
| 3.9.6 | 1 | 480 | PASS | PASS | all passed |
| 3.9.6 | 2 | 480 | PASS | PASS | all passed |
| 3.9.6 | 3 | 480 | PASS | PASS | all passed |
| 3.13.17 | 1 | 480 | PASS | PASS | all passed |
| 3.13.17 | 2 | 480 | PASS | PASS | all passed |
| 3.13.17 | 3 | 480 | PASS | PASS | all passed |

Those are tests that ran, not a pass rate over the code and not coverage. The tests use real `time.sleep` waits (0.05 to 0.2 s). One unexplained intermittent failure of the `malakopia_core` suite on Python 3.13 was seen once in about 100 earlier runs and did not recur in these runs; I have not found a cause (see [KNOWN_LIMITS.md](KNOWN_LIMITS.md)).

The raw `Ran N tests in X.XXXs / OK` lines for every run are in each component README. The leak check passes only with `tools/leak_ignore.txt`, which lists the fake key-shaped fixtures and the scanners' own detector patterns that the check would otherwise flag (7 fixed strings).

### Other static checks run on the final tree [observed 2026-11-21]

| Check | Result |
|---|---|
| `python -I` compile of every `.py` (45 files under `scripts/` and `examples/`; 45 files in the tree) on 3.9.6 and 3.13.17 | 0 failures on both |
| `sh -n` on every `.sh` (11 files) | 0 failures |
| YAML parse (Ruby) of `.github/workflows/ci.yml` and the three issue templates | all parse |
| `plutil -lint` on the two launchd templates | both OK |
| `tools/check_placeholders.sh` with `tools/leak_ignore.txt` | `leak check: clean` |
| `tools/check_queue_sync.sh` | both queue files identical |
| Markdown link check (relative links and heading anchors, 22 `.md` files) | 0 broken |
| Scan of the tree for double-curly-brace placeholders (the leak check's first rule) | none found; the only match for the pattern is the leak check script's own copy of it, which it excludes from scanning, and GitHub's expression syntax in the CI file, which it also excludes |
| Rule 16: every `def` and `class` has a docstring (1077 definitions in 45 files) | 0 missing |

Rule 16 comment density, production files only (tests excluded). "`#` comment lines" counts lines whose first non-blank character is `#`; the last column adds docstring lines. Lowest `#` density is 25.5%; lowest with docstrings is 34.3%.

| File | Non-blank lines | `#` comment lines | Comments plus docstrings |
|---|---|---|---|
| `enki_waypoint/scripts/enki_adaptive_learning.py` | 492 | 29.7% | 36.8% |
| `enki_waypoint/scripts/enki_runtime.py` | 388 | 30.2% | 34.8% |
| `enki_waypoint/scripts/enki_waypoint.py` | 540 | 30.6% | 36.7% |
| `enki_waypoint/scripts/malakopia_job_queue.py` | 940 | 29.4% | 42.1% |
| `malakopia_core/examples/one_command.py` | 49 | 36.7% | 42.9% |
| `malakopia_core/scripts/malakopia_completion.py` | 219 | 30.6% | 37.9% |
| `malakopia_core/scripts/malakopia_decompose.py` | 143 | 29.4% | 40.6% |
| `malakopia_core/scripts/malakopia_engine.py` | 479 | 30.3% | 37.8% |
| `malakopia_core/scripts/malakopia_export.py` | 199 | 29.1% | 36.2% |
| `malakopia_core/scripts/malakopia_job_queue.py` | 940 | 29.4% | 42.1% |
| `malakopia_core/scripts/malakopia_local_tasks.py` | 210 | 29.0% | 34.3% |
| `net_persistence_guards/scripts/net_guard.py` | 669 | 28.1% | 34.5% |
| `net_persistence_guards/scripts/persistence_guard.py` | 477 | 27.9% | 34.8% |
| `secret_leak_tools/scripts/git_secret_hook.py` | 586 | 25.8% | 37.0% |
| `secret_leak_tools/scripts/home_secret_scan.py` | 474 | 25.5% | 36.1% |
| `secret_leak_tools/scripts/secret_scan.py` | 383 | 27.2% | 39.4% |
| `secret_leak_tools/scripts/twu_leakwatch.py` | 955 | 27.1% | 35.5% |
| `stop_latch_autonomy/scripts/stop_latch.py` | 95 | 34.7% | 55.8% |
| `stop_latch_autonomy/scripts/twu_autonomy.py` | 333 | 27.9% | 36.0% |
| `write_guards/scripts/guarded_write.py` | 248 | 27.0% | 44.0% |
| `write_guards/scripts/signal_guard.py` | 79 | 30.4% | 55.7% |
| `write_guards/scripts/write_guard.py` | 574 | 26.0% | 36.8% |

The test files carry a one-line docstring on every test and helper (generated from the test name, so they say what is checked, not why); they have almost no `#` comments and are not counted above.

### Earlier runs (superseded, kept for the record)

- Initial snapshot, review run [observed 2026-11-21, agent-run]: clone of the first snapshot, three runs per interpreter, own scratch `HOME` and `TMPDIR`; 36 of 36 runs green; 390 tests per interpreter (101, 96, 52, 98, 18 with 1 skipped, 25). The components were edited many times after that, which is why the counts above differ.
- A mid-assembly run showed `secret_leak_tools` and `write_guards` failing while other passes were still editing those folders. Those failures were not investigated at the time; both are green in the final run above.

### Re-run of the wider workspace test files (not this repo) [observed 2026-11-21, agent-run]

Separately, an agent re-ran 87 of my private workspace's unit-test files for the areas these components came from (guards, secret scanners, stop latch, the Malakopia and Enki families, the sandbox runners, a dashboard). It ran each file once per interpreter in a scratch copy with a scratch `HOME` and `TMPDIR`, on macOS: Python 3.9.6 and 3.13.17. These are not the same files as this repo's `run_tests.sh` suites, and most of that code is not published.

- Result on 3.13: 78 of 87 files passed completely; 1,541 of 1,628 tests passed. On 3.9: 1,535 of 1,624. Nine files were not clean on either interpreter.
- The guard-style areas this repo is built from (network and persistence guards, secret scans, git hook, stop latch, autonomy rules, guarded writes, signal guard, command gate, the dashboard suites) had no failing test in the final run.
- The red was real defects and environment, honestly classified: one `RLIMIT_AS` call that macOS refuses (31 or 32 failures from one line), a `/tmp` prefix check that fails on macOS because `/tmp` resolves to `/private/tmp`, two tests that are wrong as written, a Linux-only `/proc` suite, and Python 3.9 syntax gaps. Two suites were red on the first snapshot and fixed in the live tree during the session, so "always green" would be a false claim for them.
- Limits: 16 of the 87 files ran without the filesystem write fence because the macOS sandbox cannot run `ps` or nest, so for those, isolation rests on the scratch home and path derivation. Skips are not passes. It is one Mac and one snapshot, not a claim about Linux or about the live system.

## 2. The five reviews

Five written reviews were run on the first snapshot (git commit `5f00f5d`), all read-only, all by AI agents under my direction, none by an outside person. Letters A to E are the labels I use in the status table in section 3.

- **A. Privacy.** An adversarial scan, independent of my own tooling, for about 90 private values (names, hosts, IPs, MACs, device IDs, home paths) in the tree and its git metadata. Found zero literal private values; found context-level identity leaks (dated policy quotes, references to a private operating-instructions file, agent session names, private job names, pipeline wording). Verdict: safe as to literal values, not safe until the context items were neutralised.
- **B. Security.** A static review with reproductions in a scratch copy: no `shell=True`, `eval`, `exec`, `pickle`, `os.system`, listeners, network calls or `sudo`. Found three high findings (name-prefix exemptions in the persistence guard, a journal database that could silence changes, a spoofable program-name exemption in the network guard), five medium and six low. Verdict: not ready until the high findings, the private context, the receipt-publishing risk and the licence note were dealt with.
- **C. Claims.** Checked every claim in the READMEs, the recovery stories and my career drafts against a re-run, with the three incompatible volume number sets. Found no invented results; found drift, internal contradictions, placeholders and four wording overclaims. Verdict: not ready until counts were regenerated from one run, the index README existed, the volume tool citation was fixed and placeholders were gone.
- **D. Engineering.** A stranger-clone review: ran every quick start, compile, imports, comment density, links. Found 15 items (E-1 to E-15): density under 20% in 19 of 20 production files, no root files, empty environment variables overriding defaults, an undocumented `lsof` requirement, placeholder clone URL, state written into the clone, a duplicated queue module. Verdict: functionally solid, polish not release-ready.
- **E. First impression.** A sceptical reader. Found no index README, contradictory volume numbers, template text and pipeline notes in public READMEs, mixed voice, undefined jargon, mostly relayed evidence, uniform hedging. Recommended an index that leads with the recovery stories, one volume file, a section on what I did versus what agents did, and a firm statement of the independence limit.

## 3. Findings status after a real re-check [observed 2026-11-21]

For each finding I re-read the code or document that the finding named in the final tree, ran the relevant test or command where one exists, and recorded what I saw. A grep alone was not accepted as evidence of a fix when a behaviour was claimed: for the behaviour findings the test that exercises it is named. Status values: **fixed** (the problem is gone and I checked it), **accepted** (still true, stated openly where it applies, and I am keeping it), **open** (not fixed).

Counts: 48 fixed, 14 accepted, 3 open.

### A. Privacy

| ID | Finding | Status | What I checked |
|---|---|---|---|
| A-0 | Literal private values | fixed | I counted whole-token occurrences of every string in my private rules file (88 values) in the working tree, printing counts only: 0 for 85 values; 3 values are ordinary words (the word "email" and two common English words) that occur in normal prose and code. Git history has one commit. |
| A-1 | Dated verbatim quotes in the autonomy rule sources | fixed | `twu_autonomy.py` rule sources are neutral constants; the quoted sentences and dates are gone; its tests pass. |
| A-2 | References to a private operating-instructions file | fixed | No match for the file name or rule number anywhere in the tree. |
| A-3 | Agent session names with dates in code and comments | accepted | None in code or comments. "Magi" and "seat" remain as explained concepts in the README glossary and the recovery stories. |
| A-4 | Company shorthand and private job names | accepted | The three private job names are gone. The `TWU` prefix remains in some file and variable names; it is explained in the glossary and I am keeping it. |
| A-5 | Personal software names (games, sync tool) | accepted | Game titles are gone. A sync tool is named in generic examples and in recovery stories. |
| A-6 | Hardware and OS fingerprint, exact dates | accepted | READMEs say "macOS arm64". This page names the macOS version of the test machine; dates remain. |
| A-7 | Release-pipeline wording (notes about a trial run, a pending licence decision, per-change adaptation tags) | fixed | None of those phrases or tags remain in the tree. The `--dry-run` flag of the two installers is a real feature, not pipeline wording. |
| A-8 | Private state-path leftover in the Enki runtime | fixed | No match; the learner state root is an environment variable with a documented default. |
| A-9 | Model name in the worker card | fixed | No match. |
| A-10 | Dated personal-incident anecdote in `signal_guard.py` | fixed | Header describes the mechanism only. |
| A-11 | Unusual private subnet in test fixtures | fixed | Zero occurrences; fixtures use documentation ranges. |

### B. Security

| ID | Finding | Status | What I checked |
|---|---|---|---|
| S-1 | Name-prefix exemptions let a new or changed startup item stay silent | fixed | Code read: no prefix list in `persistence_guard.py`; tests `test_no_name_is_exempt_by_default` and `test_changed_and_removed_items_with_formerly_exempt_names_alarm` pass. |
| S-2 | Journal database could silence "changed" findings | fixed | The feature is removed; `test_no_journal_feature_remains` passes. |
| S-3 | Program-name exemption in `net_guard` a process can spoof | fixed | No built-in exemptions; exact entries come only from opt-in allow files, which can be pinned with a sha256 variable; tests pass. |
| S-4 | Private context in shipped defaults | fixed | See A-1, A-2, A-3, A-8. Leakwatch zone lists are empty by default. The seed rule table in `twu_autonomy.py` still marks some actions `AUTO`; it is a lookup that executes nothing, and the README and [KNOWN_LIMITS.md](KNOWN_LIMITS.md) say to review it. |
| S-5 | Predictable lock folder in shared temp | fixed | `guarded_write.py` creates a 0700 per-user folder, checks owner and type by descriptor, opens locks with `O_NOFOLLOW`; tests pass. |
| S-6 | Check-then-use races in the write guards | accepted | Folder opened with `O_DIRECTORY|O_NOFOLLOW` and work done relative to the descriptor; the remaining race is stated in the code and README. Not a boundary against a hostile writer. |
| S-7 | Receipts written into the clone with no `.gitignore` | accepted | Root `.gitignore` excludes `data/`, `state/`, receipts and `STOP`. The default state folder is still inside the component folder; documented. |
| S-8 | Broad default read scope, unsalted fingerprints, wholesale `accept`, skip-by-file-name | accepted | Fingerprints are salted per install; the home scan needs `--yes-read-home` or a prompt; the scan-skip-by-name is gone; line-length, size and `accept` limits are stated in the README. |
| S-9 | Git hook fails open and bakes an absolute path | fixed | Hook text fails closed unless `LEAKGUARD_ALLOW_MISSING=1`; `--no-textconv`; refuses a symlinked hooks folder; tests pass. |
| S-10 | Commands resolved through `PATH` | fixed | Both guards use `trusted_command()` (system folders, root-owned, not group or world writable); tests pass. |
| S-11 | Installers: no confirmation, user-writable Python preferred | fixed | Installers ask (or `--yes`), default to `/usr/bin/python3`, warn on `--python`. Not run as live services in a real home. |
| S-12 | STOP latch can end the host process | accepted | By design and documented as cooperative; I corrected the wording about the grace period (the process exits with status 0 via `os._exit`). |
| S-13 | Predictable `/tmp` quick starts, chmod of an existing folder | fixed | Quick starts use `mktemp -d`; the queue refuses an existing non-private folder; the learner state root must be absolute. |
| S-14 | Key-shaped fixtures flagged by other scanners | fixed | Every key-shaped fixture is built from pieces at run time; the README shows a salted fingerprint, not a plain hash. |
| B-docs | Docs overclaimed ("cannot be edited after the fact"; persistence promise false for exempt names) | fixed | No such phrase remains; README states names are not trusted. |

### C. Claims

| ID | Finding | Status | What I checked |
|---|---|---|---|
| C-1 | Stale test counts in READMEs | fixed | All tables replaced from the one final run above. |
| C-2 | No index README, licence or security policy | fixed | Root README, LICENSE, SECURITY, CONTRIBUTING, CODE_OF_CONDUCT present; link check 0 broken. |
| C-3 | Volume tool cited at a path that does not exist | fixed | [VOLUME_FACTS.md](VOLUME_FACTS.md) shows the command with a placeholder path and says the tool is not shipped. |
| C-4 | Three incompatible volume sets | fixed | One dated figure set in this repo; the old numbers appear only in the "superseded" table. My résumé and cover-letter drafts are not in this repo and I did not re-check them here. |
| C-5 | "No overwrites" claim contradicted by my own incident log | fixed | The root README now says the tools reduce overwrites and cites stories 24 and 34. The résumé wording is outside this repo. |
| C-6 | "Tests re-run green in 32" repositories | open | A claim in a document outside this repo; corrected to 30 genuine passes and 2 repos where every test was skipped. Not re-checked here. |
| C-7 | Placeholder text and template notes in READMEs | fixed | No clone-URL placeholder, no "Expected output: see --help", no licence-decision note. |
| C-8 | "Metadata only" and "within minutes" in the network and persistence README | fixed | Reworded: file contents are hashed but not stored; the check runs when you schedule it. |
| C-9 | `max 4 attempts` | fixed | Now "4 by default, configurable from 1 to 20", matching `complete_task`. |
| C-10 | STOP latch "killed after grace" | fixed | Now describes `os._exit(0)` after the grace period. |
| C-11 | Lock files "beside the file" | fixed | README states they live in a per-user folder. |
| C-12 | "Independent" used for AI review sessions | fixed | README and stories say separate AI sessions, not outside people. |
| C-13 | Story 32 stated chaos-tool guards as safe | fixed | Story 32 rewritten with the macOS path-guard bug, its fix, the re-run and the one still-open test. |
| C-14 | Résumé and profile drafts (counts, `<link>` placeholders, interpreter) | open | Outside this repository; not re-checked. |

### D. Engineering

| ID | Finding | Status | What I checked |
|---|---|---|---|
| E-1 | Comment and docstring density; undocumented functions | fixed | Table in section 1: every production file at or above 25.5% `#` comments; 0 of 1077 definitions lack a docstring. Test docstrings are generated from test names. |
| E-2 | No root files, no `.gitignore` | fixed | Present. A per-component CONTRIBUTING is not provided; the root file covers all six (accepted). |
| E-3 | Empty environment variable overrides a default | fixed | `or` fallbacks in `persistence_guard.py`, `twu_leakwatch.py`, `malakopia_job_queue.py`, `twu_autonomy.py`; I read each. |
| E-4 | Undocumented `lsof` requirement | fixed | README lists the required system tools; absolute paths are used. |
| E-5 | Persistence quick start ends in a non-zero exit on a stock Mac | accepted | Unchanged behaviour; the README explains the `metadata-only` finding and what exit 1 means. |
| E-6 | Placeholder clone URL and references to unshipped files | fixed | No placeholder; no reference to an unshipped file in the tree. |
| E-7 | State written inside the clone | accepted | `.gitignore` covers it; default location unchanged; documented in [KNOWN_LIMITS.md](KNOWN_LIMITS.md). |
| E-8 | Duplicated queue module with nothing keeping copies in sync | accepted | Now a `cmp` check script, a test in each component and a CI step. Still duplicated by design. |
| E-9 | Undocumented environment reads, internal name `MAGI_SEAT` | fixed | `MAGI_SEAT` is gone; the other reads are in `config.example.env`. |
| E-10 | Unresolved decision notes and private provenance in public text | fixed | See A-1, A-7; licence settled (section 4 of this pass). |
| E-11 | `ResourceWarning` lines and leftover lock folders in tests | fixed | Zero `ResourceWarning` lines and empty `HOME` and `TMPDIR` in all 36 component runs. |
| E-12 | One test skipped because a policy file is not shipped | fixed | No skipped tests in any run. |
| E-13 | Real `sleep` waits may flake | accepted | Still present; see the intermittent failure in [KNOWN_LIMITS.md](KNOWN_LIMITS.md). |
| E-14 | Functions with no production caller | open | Not removed; low value. |
| E-15 | Scan from a non-git directory silently reports zero | fixed | I ran `secret_scan.py check` in a non-git scratch root: it prints a `scan-unavailable` problem instead of a clean result. |

### E. First impression

| ID | Finding | Status | What I checked |
|---|---|---|---|
| F-1 | No index README | fixed | Root README leads with the recovery stories. |
| F-2 | Contradictory volume numbers | fixed | See C-4. |
| F-3 | Template text and pipeline notes in READMEs | fixed | See C-7, A-7. |
| F-4 | Mixed voice | fixed | READMEs use first person; no third-person references to me remain in the tree. |
| F-5 | Undefined jargon | fixed | README glossary defines TWU, Malakopia, Enki, Magi/seat, STOP latch. |
| F-6 | Evidence mostly relayed | accepted | Stated plainly in the README and the stories; cannot be changed without re-running my private workspace. |
| F-7 | Uniform hedging hides what is solid | accepted | I kept the hedges and moved the five flagship stories to the top. |
| F-8 | No statement of what I did versus what agents did | fixed | README section "What I did, and what AI agents did". |
| F-9 | No firm statement of the independence limit | fixed | README, SECURITY and [KNOWN_LIMITS.md](KNOWN_LIMITS.md) say no outside human reviewed this. |

## 4. Using CI as the external check

`.github/workflows/ci.yml` runs on GitHub's runners: the leak check, the queue-copy check, and every component on Python 3.9 and 3.13 on Ubuntu and macOS. This is the first run of anything on Linux. Until I have read a green run, treat Linux as unsupported, and treat a red Linux row as a real finding, not noise. Pushing the workflow file needs a token with the `workflow` scope.

## 5. How to re-run it yourself

```bash
./run_all_tests.sh                                   # all components, one table
PYTHON=/path/to/python3.13 ./run_all_tests.sh        # another interpreter

# fully isolated: scratch HOME and TMPDIR, resolved to real paths
scratch=$(mktemp -d) && mkdir "$scratch/h" "$scratch/t"
env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin HOME="$(cd "$scratch/h" && pwd -P)" \
  TMPDIR="$(cd "$scratch/t" && pwd -P)" ./run_all_tests.sh

CHECK_PLACEHOLDERS_IGNORE_FILE=tools/leak_ignore.txt bash tools/check_placeholders.sh .   # leak check
sh tools/check_queue_sync.sh                         # the two queue copies match
```


Note (2026-11-21, after the bypass hunt): the test counts for secret_leak_tools, stop_latch_autonomy, write_guards and net_persistence_guards in the table above were re-measured after the fixes in [RED_TEAM_SEAT5.md](RED_TEAM_SEAT5.md); the timings, coverage table and code digest above describe the earlier run and were not redone.
