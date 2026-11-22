# When Things Broke and How I Recovered

Real failures from my own multi-agent workspace. For each one: what broke, how it was found, the fix, the lesson, and the test or check that guards it. Some failures came from my own agents, and some are corrections of earlier claims. I include them because owning those is part of recovering.

In these stories "I" is me. "An agent" is one AI coding session (what I call a seat; see the glossary in the [README](../README.md#glossary)). AI coding agents wrote most of the code in this workspace under my direction and verification. Several agent sessions run in the same workspace at once, and I do not control them one by one, which is the reason many of these failures exist. Overwrites between them did happen (stories 24 and 34). The claims ledger and write guards I added reduce them; they do not prevent them.

## Evidence tags

- [observed] I ran the command or read the file in the pass that wrote this document.
- [relayed] Stated in my workspace's `CHANGELOG.md` by whoever did the work. I read the entry. I did not re-run the test. Most of the stories below are [relayed], so read them as my own notes about my own work, not as independent proof.

Where a guard test ships in this repository, the story has a "Reproduce" line you can run yourself. The Reproduce line only tells you what to run; the story text keeps its original tags, and the current results of those test suites are in [VERIFICATION.md](VERIFICATION.md).

## What the paths mean

Paths in the stories are relative to my private workspace, which is not published. Only the six component folders in this repository are public, so most file names below will not exist here. Where a file does ship, I name its component. Dates are CHANGELOG section dates; the workspace has no git history, so they are not commit dates. Test counts of the form "N tests" are counts of `def test` in the file [observed, `grep -c`, earlier pass] unless marked as reported pass results [relayed].

For code volume see [VOLUME_FACTS.md](VOLUME_FACTS.md). Volume measures how much code exists, not whether it is good, so it is not repeated here.

## Read these five first

| # | Why start here |
|---|---|
| [1](#1-comment-only-edits-broke-integrity-checks-2026-11-20) | My own claim was wrong: "comment-only edits change nothing" held for behaviour but not for code that hashes its own bytes. |
| [2](#2---help-re-saved-the-network-baseline-2026-11-20) | A `--help` flag ran a command and re-saved a security baseline. The fix was kept to the one thing the alarm named. |
| [3](#3-alarm-job-timing-out-2026-11-20) | Measure first: a 310 s scan became 21 s with identical findings (10 both ways). |
| [20](#20-my-guard-fix-broke-the-guards-own-tests-2026-11-09) | A fix of mine broke the guard's own tests; I replaced a path heuristic with an explicit marker. |
| [21](#21-leak-watch-could-miss-a-name-followed-by-a-digit-2026-11-09) | I re-ran old and new logic over 61 findings before accepting a "tightening" that would have missed real leaks. |

Then read [Cases I rejected as unverifiable](#cases-i-rejected-as-unverifiable) and [What is not proven](#what-is-not-proven). They show where I stopped short of a claim.

## Index of all 34 stories

Every story has a number that does not change. The first five are the flagship set, then the rest in descending story number, then the weaker cases in the appendix.

| # | Date | What broke | Guard | Evidence |
|---|---|---|---|---|
| 1 | 2026-11-20 | Comment-only edits broke byte-fingerprint checks (my claim was wrong) | the typo-normalizer's test file, `canonical_pins.json` | relayed |
| 2 | 2026-11-20 | `net_guard.py --help` re-saved the network baseline | `scripts/test_net_guard.py`, `scripts/test_persistence_guard.py` | relayed |
| 3 | 2026-11-20 | Alarm job timing out: secret scan read 55,148 files each run | `scripts/test_secret_scan.py` | relayed |
| 20 | 2026-11-09 | My guard fix broke the guard's own tests | installer tests, `.leakguard-fixture` marker | relayed |
| 21 | 2026-11-09 | Leak watch could miss a name followed by a digit | `scripts/test_github_leak_watch.py` | relayed |
| 34 | 2026-11-21 | A bulk edit broke compilation and overwrote six newer files | restored tests (net_guard 27, persistence_guard 25, secret_scan 20) | relayed + observed (one hash comparison) |
| 33 | 2026-11-21 | Security review: guards trusted names, not executables | `scripts/test_guard_exemption_binding.py` (17 tests) | relayed + observed (17 tests re-run) |
| 32 | 2026-10-20 to 2026-11-21 | Chaos and healer tools to rehearse failures (macOS path guards were wrong; fixed; one test open) | `scripts/test_twu_chaos.py` and others | observed (file headers, re-run) + relayed |
| 31 | 2026-11-11 | Wrong licence claim for a dataset | licence gate Rule E19 | relayed |
| 30 | 2026-11-07 | `pgrep` failure reported as "Syncthing not running" | `scripts/test_sync_health_monitor.py` | relayed |
| 29 | 2026-11-08 | An agent asked about a host already recorded as retired | `scripts/test_twu_facts.py` | relayed |
| 28 | 2026-11-08 | Stale-doc check's first run: half false alarms | `scripts/test_reality_check.py` | relayed |
| 27 | 2026-11-08 | Incidents could be marked fixed with nothing preventing repeat | `scripts/test_incident_ledger.py` | relayed + observed (data dir) |
| 25 | 2026-11-09 | Test wrote the real launcher file | launcher regression in `scripts/test_dashboard_fivetab.py` | relayed |
| 24 | 2026-11-09 | Two writers overwrote one file (overwrites happened; guard added) | `scripts/test_guarded_write.py` | relayed |
| 23 | 2026-11-09 | Relay scrubber gaps found by red-team | `scripts/test_relay_redteam.py`, `scripts/test_relay_redteam2.py` | relayed |
| 22 | 2026-11-09 | `verified_by` blacklist bypassed; ReDoS; FIFO hang | the incident tool's test file | relayed |
| 19 | 2026-11-09 | Global git guard let a private host name through | hook tests, `scripts/git_secret_hook.py` | relayed + observed (hook file exists) |
| 18 | 2026-11-10 | Model start failed with a misleading "file missing" message (GPU full) | the autostart test file, `scripts/test_dashboard_panel_engine.py` | relayed |
| 17 | 2026-11-12 | Literal "no tools" reply misrouted by the word "files" | `scripts/test_gemini_broker_bridge.py` | relayed |
| 16 | 2026-11-12 | Registry misread a panel ID as a button | `scripts/test_dashboard_registry.py` | relayed |
| 15 | 2026-11-12 | Dashboard status reported healthy on bad data | `scripts/test_dashboard_panel_right_now.py` | relayed |
| 14 | 2026-11-12 | `check_all.py --help` started real work | `scripts/test_check_all.py` | relayed |
| 9 | 2026-11-17 | RPM query timed out in a throttled shared CPU slice | `scripts/test_box_watch.py` | relayed |
| 8 | 2026-11-19 | Fleet dashboard buttons all failed with a ValueError | popup-vs-door regression test | relayed |
| 7 | 2026-11-19 | Six security-review findings (path quoting, hostname capture, control characters, symlink temp file) | regression tests in `scripts/test_fleet_registry.py`, `scripts/test_dev_patch_flow.py` | relayed |
| 6 | 2026-11-19 | Fleet tests changed real trust state | `scripts/test_fleet_registry.py`, `Fleet.locked()` guard | relayed |
| 4 | 2026-11-20 | My guide refresh starved the alarm job | `scripts/test_codebase_guide_build.py` | relayed |
| 5 | 2026-11-20 | Wrong claim from `systemctl cat` hiding root-only drop-ins | none found (correction only) | relayed |
| 10 | 2026-11-16 | Laptop battery down to about 1 h from unconstrained background job | systemd drop-ins (no test found) | relayed |
| 11 | 2026-11-16 | Syncthing broadcast temp files before they were renamed | `.stignore` rules (no test found) | relayed |
| 12 | 2026-11-16 | Watchdog notifications from a 570,963-entry file walk | self-test reported (no file located) | relayed |
| 13 | 2026-11-13 | Global check cut off at 420 s; wrong inference corrected | receipt in `archive/` | relayed |
| 26 | 2026-11-09 | Repo recreation: executor not provable | evidence file, incidents left open | relayed |

The Evidence column says which tag the story's key claims carry. "relayed" means read from my CHANGELOG, not re-run.

## The five flagship stories

### 1. Comment-only edits broke integrity checks (2026-11-20)
- Broke: Five modules got explanatory comment blocks. An agent had said they "change no behaviour", because an AST check ignores comments. That holds for Python behaviour, not for code that hashes raw bytes. the decoder's `engine_signature()` hashes the typo-normalizer module, so the decoder refused to load 43 reviewed corrections. `canonical_pins.json` pinned four more edited files, and each failed its pin. [relayed]
- Found: Running each module's own tests (the typo-normalizer's tests: 3 failures, 14 errors). [relayed]
- Fix: Removed the block from all five files. Each matches its pin byte for byte again, and the decoder loads its 43 corrections. Explanations moved to a separate notes file. A detector was added, and the files are listed in an exemption list. [relayed]
- Lesson: "Does not change behaviour" must be checked against what fingerprints the file, not only what runs it.
- Guard: the typo-normalizer's test file (19 tests; reported 19 of 19), `canonical_pins.json`.

### 2. `--help` re-saved the network baseline (2026-11-20)
- Broke: While investigating an alarm about a new listener, an agent ran `net_guard.py learn --help`. The tool had no help handling, ran `learn`, and wrote "baseline saved: 18 exposed listeners". That accepted the current state as trusted, which is my decision. No earlier copy existed. [relayed]
- Found: The agent saw the output and stopped. [relayed]
- Fix: The alarm just before had named exactly one new listener, so only that entry was removed from the Linux host's network baseline file. A re-run of `check` showed exactly that one finding again. The listener itself was checked read-only and acceptance left to me. `net_guard.py` and `persistence_guard.py` now treat `-h`, `--help` and `help` as inert. [relayed]
- Lesson: Help flags must never run actions. The slip was recorded in my operating manual's security chapter. [relayed]
- Guard: `scripts/test_net_guard.py` (27 tests), `scripts/test_persistence_guard.py` (25 tests).
- Reproduce: the guard tests for story 2 ship in `net_persistence_guards/` (`test_net_guard.py`, `test_persistence_guard.py`). Run `cd net_persistence_guards && ./run_tests.sh`.

### 3. Alarm job timing out (2026-11-20)
- Broke: The "ALARM CHECK STALE" alarm. [relayed]
- Found: Measurement. The alarm job's `watch_proof` step ran `secret_scan.check`, which read all 55,148 workspace files (about 53,000 are downloaded manual libraries). A cold scan took 310 s against a 5-minute service limit. [relayed]
- Fix: `scripts/secret_scan.py` keeps an incremental cache. A file is skipped only if size, mtime and the rules are unchanged. Findings were identical (10 both ways). Read errors still fail closed. The cache stores fingerprints, not secrets. Warm scan 21 s, whole alarm run 49 s. [relayed]
- Lesson: Fix the measured cause, and prove the faster path finds the same things.
- Guard: `scripts/test_secret_scan.py` (20 tests; 7 added).
- Reproduce: the secret-scan tests ship in `secret_leak_tools/`. Run `cd secret_leak_tools && ./run_tests.sh`.

### 20. My guard fix broke the guard's own tests (2026-11-09)
- Broke: The new global guard blocked planted fake secrets in throwaway test repos: `test_github_leak_watch` 6 errors, `test_watch_proof` 6 failures. [relayed]
- Fix: The pre-commit hook first skipped repos under OS temp dirs. It was later changed to a `.leakguard-fixture` marker (a regular file at the repo top level only, so a symlink or subdirectory copy does not count). Pre-push has no exception. Real-repo MAC and host-name commits still exit 1. [relayed]
- Lesson: A path heuristic is weaker than an explicit marker. One leftover test failure was reported as a different cause, with its own open incident, rather than hidden. [relayed]
- Guard: Installer tests 12 of 12 [relayed].

### 21. Leak watch could miss a name followed by a digit (2026-11-09)
- Broke: A tightening meant to cut false positives would have missed `name2` and `name_x`. [relayed]
- Found: The agent re-ran old and new logic over 61 old findings: 37 of 39 literal findings still reported, 2 dropped (true false positives), all 22 MAC findings unchanged. [relayed]
- Fix: Boundary changed to letters-only in `github_leak_watch.bad_hits()`. The old logic was recoverable only from a Syncthing version copy, because the file is not in git. [relayed]
- Guard: `scripts/test_github_leak_watch.py` (23 tests).

## More stories

### 34. A bulk edit broke compilation and overwrote six newer files (2026-11-21)
- Status: fixed for the eight guard and scanner files; two other problems found the same day are still open (below).
- Broke: a 09:37 sweep by another of my agent sessions rewrote scripts with a new header. For six files it replaced newer content with an older, shorter version: `net_guard.py` (496 to 407 lines, losing the reviewed-listener allow list), `persistence_guard.py` (382 to 296), `secret_scan.py` (230 to 167) and their three test files (304 to 252, 263 to 222, 190 to 121). Two install scripts only gained the header. [relayed from CHANGELOG 2026-11-21]
- Found: a different session, while auditing code, reported that the same bulk pass had put stub docstrings before `from __future__` lines, so files in `scripts/` no longer compiled. That entry counts 628 files. I have also seen 637 quoted for the same event but could not find it written anywhere, so I use the CHANGELOG's 628 [relayed]. That session repaired the files it owned. One file it could not claim was still broken when it wrote the entry, and one module had lost a function that another module calls. [relayed]
- Fix: the eight swept files were restored from a pre-sweep copy taken by one of my agent sessions (older modification times kept). Each swept version was first saved beside the file as `<name>.bak-20261121-sweep`. Nothing was deleted. Then compile checks and the unit tests ran with separate temp HOME/TMPDIR: net_guard 27, persistence_guard 25, secret_scan 20 tests OK on the system Python and on Python 3.13. [relayed]
- Not restorable: the lost function exists in no copy that was searched (live, archive, exports, conflict copies). It needs a rewrite by whoever wrote it, not a guess. Still open. [relayed]
- A caveat about my own evidence: my release tooling keeps a SHA-256 list of source files. Its file time is after the sweep, so on timing alone it could contain hashes of swept content. I compared one entry: the hash for `net_guard.py` equals the restored version, not the swept one [observed 2026-11-21]. That file has been edited again since (the story 33 fix), so the list no longer matches the live file either. I did not check the other entries. Treat that list as a record of the time it was made, not as proof of current content.
- Lesson (from the CHANGELOG): a sweep must never rewrite a file whose content is newer than its template, and it must claim-check each file first. The guard that would catch this is the per-file claims ledger; I have no automated test for it yet.
- Guard: the restored tests above (`test_net_guard`, `test_persistence_guard`, `test_secret_scan`; the first two ship in `net_persistence_guards/`, the last in `secret_leak_tools/`).

### 33. Security-review finding: guards trusted names, not identity (2026-11-21)
- Status: fixed and tested in my workspace; reviewed by an AI session, not by an outside person.
- Broke: a review of my own release candidate (an AI review session; its first three security findings, which the CHANGELOG says were reproduced) showed that my network and persistence guards trusted names. `persistence_guard.compare` treated any NEW or CHANGED startup item whose name carried one of a few of my own prefixes as informational, so `~/.local/bin/<prefix>-backdoor` would raise no alarm. `journal_accepts` matched by substring and accepted a future-dated row forever. `net_guard.compare` skipped any high UDP listener whose process was called by one of three application names, and any process can use that name. [relayed from CHANGELOG 2026-11-21]
- Fix: quietness in `persistence_guard.py` is now bound to the baseline content digest: an unchanged known item is quiet, a NEW or CHANGED one is always a problem whatever its name. `journal_accepts` needs exact whole-token path equality, ignores future-dated rows and refuses a database that is not a regular, user-owned, non-symlink, non-group/world-writable file. `net_guard.py` now resolves each candidate pid to its executable (realpath and sha256) and exempts only a root-owned, non-writable system install under a system directory whose name matches, or an exact (program, path, sha256) entry in an optional allow file. An unresolved identity alarms. [relayed] The version published in this repository took a simpler route: it has no name exemptions at all, and exemptions come only from opt-in allow files with exact entries (optionally pinned to a sha256) [static, read from the shipped code on 2026-11-21].
- Guard: `scripts/test_guard_exemption_binding.py`, 17 tests (a prefixed backdoor name, a changed prefixed unit, `toolbox-long` against `tool`, a future timestamp, a group/world-writable database, a wrong owner, a symlinked database, a fake application from a temp path, an unresolved executable, a wrong-name system binary, a replaced hash). The CHANGELOG records that against the pre-fix code 15 of the 17 fail or error and the two positive controls pass; against the fix all pass [relayed]. Re-run on 2026-11-21 against the current code: 17 tests OK [observed 2026-11-21]. I did not re-run them against the old code, so the "15 of 17" is the CHANGELOG's number.
- Consequence I accepted: an edited unit of my own now alarms until I accept it with `persistence_guard.py learn --only <key>`, and an exempted application binary under my home directory needs an allow-file entry or its ephemeral UDP port alarms. Two older tests that encoded the weakness were rewritten.
- Lesson: a name is a label, not an identity. An exemption has to be bound to content or to the executable, and each weakness needs a test that fails on the old code.
- Reproduce: `cd net_persistence_guards && ./run_tests.sh`. The 17 tests above are in my workspace and are not shipped; the shipped suites test the simpler published design instead (for example `test_no_name_is_exempt_by_default` in `test_persistence_guard.py`).

### 32. Chaos and healer tools (2026-10-20 to 2026-11-21)
- What exists: `scripts/twu_chaos.py` (four experiments: kill a worker, truncate a temp state file, overfill a temp log, plant a dead-owner lock) acts only on targets it creates and kills only PIDs it started [observed, file header]. Also `scripts/chaos_vs_healer_arena.py`, `scripts/chaos_adversarial_security_suite.py` and `scripts/twin_box_chaos_dojo_healer.py`.
- Broke (found 2026-11-21 from a test re-run of my workspace suites): the path guards in `twin_box_chaos_dojo_healer.py` and `chaos_monkey_resting_healer.py` compared a string prefix, which is wrong on macOS (`/tmp` resolves to `/private/tmp`), so every sandbox was rejected and the twin_box tests errored; and the chaos_monkey guard had a `"scratch" in path` escape hatch that accepted any path containing that word. [relayed from CHANGELOG 2026-11-21]
- Fix: both guards now compare resolved paths against resolved allowed roots (`/tmp`, `/var/tmp`, the system temp dir; a root of `/` or the home folder is ignored) and require a strict child. The `scratch` escape hatch is removed. Tests added: a path merely named scratch is refused, a real temp path is accepted. [relayed]
- Re-run, 2026-11-21, throwaway HOME, Python 3.13.17: `test_twin_box_chaos_dojo_healer` 5 tests OK, `test_chaos_monkey_resting_healer` 5 tests OK, `test_chaos_vs_healer_arena` 3 tests OK [observed 2026-11-21]. So the guards now work on macOS; that is a result for this Mac only.
- Still open: `scripts/test_twu_chaos.py` has 8 tests; on the same re-run 7 passed and 1 failed (`test_every_experiment_recovers_and_cleans_up`: one experiment raised an `ImportError` for a `StateReadError` name from a self-heal module) [observed 2026-11-21]. The CHANGELOG says that name was added deliberately; the file in my workspace does not have it right now, so another session's edit or a sync is the likely cause. I have not diagnosed it further.
- Guard: `scripts/test_twu_chaos.py` (8 tests), `scripts/test_chaos_vs_healer_arena.py` (3 tests), plus tests for the other two.
- Honest note: a 2026-10-23 entry recorded `test_twin_box_chaos_dojo_healer` with 3 errors on the Mac, reported to the Linux side; the fix above is the follow-up I had not found earlier. [relayed]

### 31. Wrong licence claim for a dataset (2026-11-11)
- Broke: Earlier text called `allenai/sciq` Apache-2.0. It is CC-BY-NC-3.0, which the licence gate (Rule E19) rejects. [relayed]
- Fix: Removed from the dataset-builder script. The agent checked none of its rows were in the training files, so counts were unchanged. [relayed]
- Lesson: Re-check a claim against the project's own gate.

### 30. `pgrep` failure reported as "Syncthing not running" (2026-11-07)
- Broke: A false "SYNC BROKEN" alarm. [relayed]
- Fix: `scripts/sync_health_monitor.py` treats a `pgrep` failure as UNKNOWN. [relayed]
- Guard: `scripts/test_sync_health_monitor.py` (42 tests).

### 29. An agent asked about a host already recorded as retired (2026-11-08)
- Broke: An agent asked me whether I knew a Syncthing peer that a retired-hosts record and the hardware inventory already listed as retired. [relayed]
- Fix: A single command to check those records, and a rule to look before asking. A fact-check test now guards a related assumed-Linux-version incident. [relayed]
- Guard: `scripts/test_twu_facts.py` (32 tests).

### 28. Stale-doc check's first run (2026-11-08)
- Broke: Nothing in production. `scripts/reality_check.py` first ran and reported 53 doc-versus-reality mismatches, about half false alarms, including the agent's own correction note. [relayed]
- Fix: Tuned and put on an hourly job with a stale-docs alarm. [relayed]
- Guard: `scripts/test_reality_check.py` (9 tests).

### 27. Incidents could be "fixed" with nothing to prevent a repeat (2026-11-08)
- Broke: Two trackers existed, and fixed status needed no proof. [relayed]
- Fix: `scripts/incident_ledger.py` is append-only per host. `fixed` requires a real in-repo preventer file, re-verified on every read. Forged lines, `..`, absolute paths, symlinks and directories are rejected. When 7 registry incidents were imported, 3 became fixed and 4 stayed open because their preventers could not be verified. Closing by absence is recorded as `resolved`, never `fixed`. [relayed]
- Guard: `scripts/test_incident_ledger.py` (33 tests). Data in the incident data folder [observed].

### 25. A test wrote the real launcher file (2026-11-09)
- Broke: `LaunchMac` in `scripts/test_dashboard_fivetab.py` wrote the real launcher command into a shared temp dir on every run. [relayed]
- Fix: It writes into a private folder, and a new test checks the real launcher is never touched. [relayed]
- Lesson: Same family as story 6. Tests must not touch real state.

### 24. Two writers overwrote one file (2026-11-09)
- Broke: Incident `57ee46915a`. [relayed]
- Fix: `scripts/guarded_write.py` records a SHA-256 at read time. `write --expect SHA` succeeds only if it still matches, under a per-file lock with an atomic replace, else exits 3 and writes nothing. It refuses symlinks. [relayed]
- Status: overwrites did happen and still can across machines. The write guard reduces them between cooperating local writers; it is not a guarantee.
- Honest limit: the same day, a separate overwrite was traced through Syncthing version copies to another machine's incoming copy (three erasures of one line in `scripts/dashboard_actions.py`). A local lock cannot stop a cross-machine write. The agent said so, named the writer as unidentified, and did not re-apply the line. [relayed]
- Guard: `scripts/test_guarded_write.py` (7 tests), including two real processes racing, so that one wins.
- Reproduce: `cd write_guards && ./run_tests.sh`.

### 23. Relay scrubber red-team rounds (2026-11-09)
- Broke: Two attack rounds found 112 and 39 gaps. [relayed]
- Fix: All fixed except 2 accepted by policy (a capitalised distro word with no host context). The combined run was 1,273 tests with 2 failures and 3 skipped. 48 incidents were closed with the tests as preventers. When tests failed on one machine because they planted that machine's own name, only that name was ignored in file names and the ledger host field. The secret checks were not weakened. [relayed]
- Guard: `scripts/test_relay_redteam.py` (82 test functions) and `scripts/test_relay_redteam2.py` (98). The CHANGELOG says 357 and 397 attacks, probably parameterised cases, which I did not verify.

### 22. Allow-list instead of blacklist for `verified_by` (2026-11-09)
- Broke: A regex blacklist was bypassed by `/bin/rm`, `sh -c`, backticks, `find -delete`, `python3 -c` and others. Signatures could also trigger ReDoS, and a FIFO could hang a scan. [relayed]
- Found: Ten findings from a skeptic review, each fixed test-first. [relayed]
- Fix: the incident tool runs commands split with `shlex`, with no shell. Metacharacters are refused. The first token must be in `python3 grep test ls cat wc stat`. Python may run only a repo `scripts/*.py`. A scrubbed env, a 20 s timeout and a process-group kill apply. Nested-quantifier or over-200-character signatures are refused, and matching has a 1 s alarm. Special files are skipped via `lstat`, `O_NOFOLLOW` and `O_NONBLOCK`. [relayed]
- Lesson: Allow-lists beat blacklists. Each old bypass is now a test case.
- Guard: the incident tool's test file (26 tests).

### 19. Global git guard let a private host name through (2026-11-08 to 2026-11-09)
- Broke: The installed guard could not find the redaction list (path relative to the repo), so it allowed a commit with a private host name. This is how such names reached a public repo. [relayed]
- Found: After the leak, by the leak watch and a review. [relayed]
- Fix: `scripts/git_secret_hook.py` finds the list beside itself and matches `-`, `_` and space variants. `scripts/install_global_hooks.sh` copies the data files (mode 600). Uninstall removes the template dir. The agent also corrected a stale leak-watch finding: by the time it checked, the public history had already been replaced by a clean one pushed by someone else, and its own proposed edit was moot. [relayed]
- Lesson: A guard must work from any directory. Check live state before acting on a stale alert.
- Guard: Observed in the entry: host-name commit exits 1, MAC commit exits 1, clean commit exits 0. `scripts/twu-githooks/pre-commit` exists [observed]. Hook tests 27 and 11 [relayed].

### 18. Misleading "model file missing" when the GPU was full (2026-11-10)
- Broke: My local-model launcher printed "model (.gguf) file is missing" and then "Connection refused". [relayed]
- Found: I reported it from the terminal. The log and `nvidia-smi` showed the file was fine. Another local process held 5,682 of 8,192 MiB of VRAM, and the start asked for 99 GPU layers (4,168 MiB). [relayed]
- Fix: the local-model autostart script steps down automatically on CUDA out-of-memory, and the failure message now says the real cause. The engine panel diagnoses VRAM state, and a stale OOM line no longer shows once enough VRAM is free (>= 4,600 MiB, no conflicts). [relayed]
- Lesson: An error message that names the wrong cause is itself a bug.
- Guard: the autostart test file (103 tests), `scripts/test_dashboard_panel_engine.py` (8 tests).

### 17. Literal "no tools" reply misrouted (2026-11-12)
- Broke: A reply that literally asked for no tools was treated as a tool request because of the word "files". [relayed]
- Found: A live native check. [relayed]
- Fix: A full-match literal-reply exception omits tool schemas. Undeclared structured calls are blocked even if the backend ignores omitted schemas. [relayed]
- Guard: `scripts/test_gemini_broker_bridge.py` (213 tests, with a real disposable HTTP/SSE case).

### 16. Registry misread a panel ID as a button (2026-11-12)
- Broke: `scripts/dashboard_registry.py` classified a panel's own underscore-containing ID as a button. [relayed]
- Fix: Fixed it, and kept independent action discovery. Nothing in my registry entries was removed. [relayed]
- Guard: `scripts/test_dashboard_registry.py` (14 tests).

### 15. Dashboard said "healthy" on bad data (2026-11-12)
- Broke: Non-finite check-in and sync timestamps, and impossible peer counts, showed as healthy. [relayed]
- Found: The new regression test exposed it first. [relayed]
- Fix: Such values report as unknown. 15 panel tests pass. [relayed]
- Guard: `scripts/test_dashboard_panel_right_now.py` (15 tests).

### 14. `check_all.py --help` started real work (2026-11-12)
- Broke: Help ran the checker. [relayed]
- Found: Review item M10. [relayed]
- Fix: Argument parsing runs before locks, build and checks. Unknown and abbreviated arguments are rejected. A regression failed before and 27 capped tests pass after. [relayed]
- Lesson: Same trap as story 2, caught earlier.
- Guard: `scripts/test_check_all.py` (27 tests).

### 9. RPM query timed out in a throttled CPU slice (2026-11-17)
- Broke: The box-watch service timed out at 120 s. [relayed]
- Found: A controlled experiment with the same 25% CPU quota: it timed out in the shared 30% housekeeping slice, and completed in 11.0 s in `app.slice`. [relayed]
- Fix: box-watch and watch-proof were moved out of the shared slice. Limits, memory and sandbox settings stay the same. The real service then returned a 2,175-package query in 7.7 s. [relayed]
- Lesson: Reproduce under the same limits before changing code.
- Guard: `scripts/test_box_watch.py` (37 tests) includes a resource-policy regression.

### 8. Every fleet dashboard button failed (2026-11-19)
- Broke: Popup buttons used panel `fleet-rollout`, but the action door accepts module names (`fleet_rollout`). Every button answered "could not start (ValueError)". Also, "connection refused" was explained as the machine being asleep, and a not-ready readiness (exit 42) was shown as a connection error. [relayed]
- Found: Checking the real live dashboard after the tile was built. [relayed]
- Fix: Buttons use module names. The messages now say the machine is awake but the remote-control service is not running, with the setup command, and show component states. [relayed]
- Lesson: Test against the live page, not only the unit.
- Guard: A regression test renders the popup and checks every button against the door's rules, and fails on the old bug. [relayed] I could not match it to a file by name.

### 7. Six security-review findings, each fixed with a test (2026-11-19)
- Broke: `dev_patch_flow.path_problem` accepted git C-quoted names that decode to protected folders. `fleet_registry.load()` let one computer capture another's hostname. Labels could inject a line into generated firewall text. `recovery._record_readiness` followed a planted symlink at a fixed temp name. A test-only override applied outside tests. [relayed]
- Found: A second independent security review. [relayed]
- Fix: Refuse backslash, quote and control characters in paths. A computer's own name wins its own hostname, and colliding entries are dropped. Labels are stripped of control characters and capped at 40. Temp files use `mkstemp` plus `os.replace`. The override is honoured only when `unittest` is loaded. [relayed]
- Lesson: Each finding gets its own failing test first.
- Guard: `scripts/test_dev_patch_flow.py` (19 tests), `scripts/test_fleet_registry.py` (26 tests).

### 6. Fleet tests changed real trust state (2026-11-19)
- Broke: Tests used a temp `--workspace`, but `Fleet(workspace)` used the default private runtime under `$HOME`. They revoked a real trust pin and wrote the real audit log. One host then showed "not paired". [relayed]
- Found: The audit log showed a revoke and onboard/offboard of a made-up computer. [relayed]
- Fix: The test helper sets HOME to a temp dir. `Fleet.locked()`, the lock around every change to keys, pins, window and policy, refuses while a unit test runs against the real runtime (`TWU_FLEET_REAL_STATE_OK` is the only override). Two tests were added, and real pins and receipts were shown identical before and after a 185-test run. The re-pin was not done by the agent, because it is a trust decision and the permission system denied the attempt. I was given exact steps. [relayed]
- Lesson: A temp workspace is not isolation. Check what the code touches outside it.
- Guard: `scripts/test_fleet_registry.py` (26 tests).

### 4. My guide refresh starved the alarm job (2026-11-20)
- Broke: `codebase_guide_build.py refresh`, which that agent had added to `check_all`, took minutes under load and starved the alarm job. [relayed]
- Found: Profiling: about 4 million `fnmatch` calls, 17 million lines counted in `archive/`, and `private/` opened. [relayed]
- Fix: Patterns compiled once (54 s to 4 s). Only live code folders are counted. History and private folders are listed but not read. Card validation is skipped when nothing changed. Whole refresh about 6 s. [relayed]
- Lesson: A new check added to a shared job needs its own cost measured.
- Guard: `scripts/test_codebase_guide_build.py` (19 tests).

## Cases I rejected as unverifiable

- `adversarial_fault_injector.py` (301 lines, a 5-vector gauntlet). I found no test for it and no `research_export/` output directory, so I could not confirm it ran or what it found.
- Linux watch timers (2026-11-08): the CHANGELOG itself says they were not run on a real Linux host.
- Mistake logger (2026-11-08): the entry says recall is unmeasured and the tool stays off, so there is no fix to show.
- Wi-Fi passphrase correction (2026-11-09): a one-line note that tutorial text was misread. I did not see the original file, so I kept it out.
- Battery and Syncthing fixes (stories 10 to 12) are kept, but with no test found. They are system settings rather than code, and I could not check them.
- Counts such as "48 incidents closed" and "112 + 39 gaps" are relayed only. I did not re-count them.

## What is not proven

- Most tests were not re-run for the story text (the exceptions are tagged [observed 2026-11-21], stories 32 and 33). The Reproduce lines are pointers, and current results are in [VERIFICATION.md](VERIFICATION.md). Other pass results are from CHANGELOG entries written by the agent sessions that made the fixes.
- The chaos tools use temp-directory targets, and their path guards were wrong on macOS until 2026-11-21 (story 32). They show the experiments work, not that the live system survives those faults.
- Several fixes were reviewed by the same agent system that wrote them. The CHANGELOG mentions "independent" reviews; these were separate AI review sessions run under my direction, not people outside the project, and I could not confirm how separate they were.
- Leak-watch coverage is only as good as its pattern list. Story 21 shows one boundary bug found by manual cross-check.
- Story 26 has an unconfirmed executor, and its scan covered MAC addresses and private literals only.
- Dates are CHANGELOG section dates, not commit dates.
- The volume numbers measure how much code exists. They do not measure quality or usage.

## Appendix: weaker cases, kept for honesty

These five stories (plus the unprovable story 26) are real but thin: there is no test I could find, or the cause could not be proven. They are here so the list is not curated to flatter me. Treat them as notes, not evidence.

### 5. A wrong claim from `systemctl cat` (2026-11-20)
- Broke: An earlier entry said a systemd drop-in "is still not present". [relayed]
- Found: `systemctl show -p DropInPaths` listed it. `systemctl cat` silently skips drop-ins a non-root user cannot read. [relayed]
- Fix: A correction entry. What the unplug test showed was the intended order: the old writer sets one power mode, then the policy runs last and sets the final one. Whether the drop-in existed before the reinstall is stated as unknown. [relayed]
- Lesson: Use a command that shows its own failures. State what is not known.
- Guard: none found. This is a correction only.

### 10. Laptop battery down to about 1 hour (2026-11-16)
- Broke: Battery life on a Linux laptop. Temperatures reached 100°C and fans 7,198 RPM. [relayed]
- Found: Traced to a boot-time `twu-check-all.service` running with `CPUQuota=200%`. [relayed]
- Fix: A background slice at 30% CPU, per-unit drop-ins that run only on AC power, and a battery profile (turbo off, power clamp). Fans fell to about 1,450 RPM. [relayed] A later root-cause entry (2026-11-18) found a stale power script that always enabled turbo, and was corrected the same way. [relayed]
- Lesson: Background jobs need a cap and a battery rule.
- Guard: none found by name. Power tests exist (`scripts/test_power_policy.py`, `scripts/test_power_stability.py`) but I did not confirm they cover this fix.

### 11. Syncthing sent temp files before rename (2026-11-16)
- Broke: Remote `pull: no such file` errors on Fedora JSON paths. [relayed]
- Found: Atomic writes created `.tmp` files that inotify broadcast before `os.replace` removed them. [relayed]
- Fix: Added `.tmp`, `.lock` and `__pycache__` ignore rules to the Fedora `.stignore`. [relayed]
- Guard: none found.

### 12. Watchdog notifications and a 300 s file walk (2026-11-16)
- Broke: Recurring desktop notifications from a watchdog service. [relayed]
- Found: The walk visited 570,963 entries and timed out at over 300 s. [relayed]
- Fix: Skip non-code trees (22,138 entries, 689 ms). Scheduling changed from idle to nice and IO priority. Removed the `OnFailure` self-alert recursion. [relayed]
- Guard: a 112-check self-test is reported. I did not locate the file.

### 13. Global check cut off, and my inference corrected (2026-11-13)
- Broke: The final capped global check was cut off at 420 s. The CLI contract passed 835 tests, memory suites were NOT_RUN, and no complete PASS was claimed. [relayed]
- Found: The agent first thought it was only waiting for a slot. Actual process lineage showed otherwise, and it corrected the claim. It did not retry unchanged or kill another worker's process. [relayed]
- Lesson: Report NOT_RUN as NOT_RUN. No green claim without a full summary.
- Guard: receipt an archived verification receipt in my private workspace [relayed].

### 26. Repo recreation: cause not provable (2026-11-09)
- Broke: 23 repos were deleted and recreated in about 7 minutes, with history kept. [relayed]
- Found: Leak watch counts and the events feed. The executor could not be confirmed, so the claim was labelled [RELAYED]. The earlier counts were reconciled (the "8 events" were 9 branch-creation events covering only 6 repos). [relayed]
- Fix: The agent scanned all 23 full histories itself: 0 real MAC addresses, 0 whole-word private literals. It listed what was not scanned (IPs, e-mails, tokens). Evidence is in a file under my private `data/health/`. The incidents stayed open. [relayed]
- Lesson: Say what you could not prove, and leave the incident open.
