# Bypass hunt of the guard code (red-team round 5)

Date: 2026-11-21. Scope: the guard code in this repository: the git hook and scanners in `secret_leak_tools`, `write_guards`, `net_persistence_guards`, `stop_latch_autonomy`, and the job queue. Method: reading the code against the bypass classes found in earlier red-team reports of sibling repositories (release-kit, agent-guardrails), then trying each class in throwaway git repositories and temporary folders (fake credentials assembled from pieces at run time, no network, no real home folder, no live service). Every bypass below was reproduced first, got a failing test, was fixed with the smallest change, and then the test passed. Reviewer: an AI session; no outside human has reviewed this. "Fixed" means the listed test passes, not that no other bypass exists.

Tags: [observed] = I ran it and read the output; [by reading] = from the code only.

## The git hook: classes from the earlier reports, checked one by one [observed]

| # | Class (earlier report) | Reproduction (minimal) | Result on the first release | Sev | Now | Test |
|---|---|---|---|---|---|---|
| H1 | Added line starting `++ ` read as a diff file header (redteam_03 B1a) | stage a file whose line 2 is `++ <fake token>`, `git commit` | commit passed | HIGH | fixed | `test_plus_plus_space_line_is_scanned` |
| H2 | `++ /dev/null` line switches the rest of the hunk off (B1b) | file line 1 `++ /dev/null`, line 2 a token | commit passed | HIGH | fixed | `test_plus_plus_dev_null_line_does_not_hide_the_hunk` |
| H3 | `splitlines()` cuts an added line at CR, VT, FF, U+0085, U+2028, 0x1c (B1c) | `foo<CR>k=<token>` | commit passed | HIGH | fixed | `test_exotic_line_separators_do_not_split_added_lines` |
| H4 | Type change `T` left out of `--diff-filter=ACMR` (redteam_07 N1), content | tracked symlink replaced by a regular file holding a token | commit passed | MED | fixed | `test_type_change_symlink_to_file_is_scanned` |
| H5 | Same, sensitive file name | symlink replaced by a regular `.env` | commit passed | MED | fixed | same test |
| H6 | NUL byte: git prints "Binary files differ", no lines (redteam_05 H1) | `a<NUL>b` then a token line | commit and push passed | HIGH | fixed (`--text`) | `test_nul_byte_file_is_scanned`, `test_push_scans_nul_file_and_ignores_hunk_config` |
| H7 | `* -diff` in `.gitattributes` (H1) | commit `.gitattributes`, then a token file | commit passed | HIGH | fixed (`--text`) | `test_gitattributes_minus_diff_does_not_hide_content` |
| H8 | UTF-16 file (H1) | token in a UTF-16 file | commit passed | MED | fixed (NUL-stripped copy of each line is scanned) | `test_utf16_file_is_scanned` |
| H9 | Line over 4000 characters skipped | 5000 filler characters, a token, 5000 more | commit passed | HIGH | fixed (scanned in overlapping pieces) | `test_very_long_line_is_scanned` |
| H10 | Only the first match per rule judged (redteam_03 L3) | a placeholder token (all `x`), then a real token, same line | commit passed | HIGH | fixed (every match judged) | `test_real_token_after_a_placeholder_on_one_line` |
| H11 | Ambient `SKIP` variable honoured by the generated hook (the lead from the reconcile review) | `SKIP=1 git commit` (also `SKIP=pytest`) | commit passed, no warning, undocumented | HIGH | fixed (hook resets its own `lg_skip` variable; `LEAKGUARD_ALLOW_MISSING` is the only variable read) | `test_ambient_skip_variable_does_not_disable_the_hook` |
| H12 | Push to a URL cut history at every remote (redteam_05 M2) | commit pushed to remote `priv` with `--no-verify`, then `git push file://...`, a plain path, `git@host:x/y` | the push to a `file://` URL passed (a plain path was already blocked) | MED | fixed (the cut applies only to a configured remote name; a URL scans all history) | `test_push_to_url_scans_commits_present_on_another_remote` |
| H13 | `log.showRoot=false` hides the root commit's diff (redteam_07 N2) | orphan root commit with a token, push | push passed | MED | fixed (`--root`) | `test_push_scans_root_commit_even_with_showroot_false` |
| H14 | git quotes a path containing a tab or `"`; `.env` name not recognised at push (redteam_03 B2) | `d<TAB>x/.env`, `d"x/.env` committed with `--no-verify`, then push | push passed | MED | fixed (C-style unquote) | `test_push_sensitive_name_in_quoted_path` |
| H15 | Credential file names beyond the short list | `.env-prod`, `.env_local`, `.envrc`, `id_ed25519_work`, `.pgpass`, `.git-credentials`, `.pypirc`, `*.kdbx` | commit passed (probed `.env-prod`, `.envrc`) | LOW | fixed (list and rule extended; `id_rsa.pub`, `.env.example` stay allowed) | `test_more_credential_file_names` |
| H16 | Zero-width characters inside a token, full-width look-alike letters | a token with U+200B inside; a full-width copy | not scanned | LOW | fixed (variants scanned) | `test_invisible_and_fullwidth_disguises_are_scanned` |
| H17 | SHA-256 repositories: 64-zero object id compared with 40 zeros | `push_ranges` with a 64-zero new-branch id | wrong range (push blocked or mis-scanned; robustness, not a bypass) | LOW | fixed | `test_sha256_zero_object_ids_mean_new_branch_and_delete` |

Classes from the earlier reports that were already fine or do not apply, probed anyway [observed]:

| Class | Result |
|---|---|
| `diff.interHunkContext` / `diff.suppressBlankEmpty` repository config (redteam_05 M1) | blocked on the first release too; the options are now set explicitly in every call (regression test `test_push_scans_nul_file_and_ignores_hunk_config` sets them) |
| converter and external diff settings in the repository's own configuration | already disabled by options on the first release |
| `diff.noprefix`, `diff.mnemonicPrefix` mangling file names (redteam_03 L6) | cosmetic; now `--src-prefix/--dst-prefix` and `-c` settings are fixed |
| scanner skips a file named `secret_scan.py` (redteam_03 M4) | not present in this code; `test_a_file_named_like_the_scanner_is_still_scanned` exists |
| `SECRET_HOOK_SKIP` variable | not in this code |
| `LEAKGUARD_ALLOW_MISSING=1` while python, git and the script are all present | commit blocked (probed, test `test_allow_missing_does_not_skip_when_everything_is_present`); it only applies when the interpreter or script is missing or git cannot start |
| `git commit -a`, `--amend`, commit in a linked worktree | blocked; worktrees share the main repository's hooks |
| auto-merge or cherry-pick of a branch whose commit holds a token | pre-commit does not run for them (git design); the push is blocked because the commit is new and scanned |
| token in a pushed annotated tag | blocked |

## What the hook still does NOT stop [observed unless marked]

- `--no-verify`; `git -c core.hooksPath=...`; `core.hooksPath` set after `install`; a repository where `install` was not run, including every fresh `git clone` and every submodule (`status` reports NOT installed). By design: a hook is advisory.
- A merge commit created with `--no-verify`: `git log -p` shows no diff for merges, so content that exists on neither parent is not seen at push.
- Token in a commit message or tag message; the `leakguard:allow` marker on a line with a real secret (by design, documented); encoded or split secrets (base64, concatenated string pieces, line continuations, other Unicode confusables).
- A real key with a placeholder word attached: an `sk-` key followed by `-example` passes (probed). The placeholder filter judges the whole match, and the match includes the suffix. Not fixed: any rule that accepts documented samples (`AKIA...EXAMPLE`) has this shape; it is listed as a limit.
- Remote-tracking refs are trusted as "already published" for a new branch pushed to a configured remote (`git update-ref refs/remotes/<name>/x HEAD` first) [by reading].
- Environment control: `TWU_GIT` pointing at another program, a replaced interpreter, an edited hook file [by reading].
- Submodule contents and LFS targets are not read.

## Other components

| # | Component | Class | Reproduction | Result on the first release | Sev | Now | Test |
|---|---|---|---|---|---|---|---|
| S1 | `secret_scan.py` | NUL byte exempts a whole file | a token under a leading NUL | not found by `check` | MED | fixed | `test_configured_skip_prefix_skipped_but_nul_files_are_not` |
| S2 | `secret_scan.py` | lines over 4000 characters skipped | padded line | not found | MED | fixed | `test_big_file_is_skipped_as_documented_but_long_line_is_not` |
| S3 | `secret_scan.py`, `net_guard`, `persistence_guard` | receipt, cache, baseline written with `write_text`; a symlink at the name or `.tmp` name overwrote its target | planted symlink to a victim file | victim overwritten [by reading, then reproduced by the new tests failing] | MED | fixed (exclusive no-follow temp file then rename) | `test_receipt_cache_and_baseline_are_not_written_through_a_symlink`, `test_baseline_and_receipt_are_not_written_through_a_symlink` (net, persistence) |
| L1 | `twu_leakwatch.py` | prefix skip `data/health/leakwatch*` | `data/health/leakwatch_notes.txt` with a secret | never scanned | MED | fixed (exact file names only) | `test_only_the_tools_own_files_are_exempt_from_the_sweep` |
| L2 | `twu_leakwatch.py` | NUL in the first 8 KB or UTF-16 hides a file | token behind a NUL | counted as binary, exit 0 | MED | fixed | `test_nul_at_the_top_or_utf16_does_not_hide_a_secret` |
| L3 | `twu_leakwatch.py` | extension decides "binary" | secret in `pic.png` that is plain text | never read | MED | fixed (skipped only if it really has a NUL) | `test_binary_huge_and_skipped_dirs` |
| T1 | `stop_latch.py` | dangling symlink at STOP | `ln -s missing STOP` | "STOP absent" | MED | fixed (`lstat`) | `test_dangling_symlink_counts_as_stop_present` |
| T2 | `stop_latch.py` | unreadable folder | `chmod 0` on the folder | Python 3.9: watcher thread dies silently; 3.12+: "absent" | MED | fixed (fail closed) | `test_unreadable_folder_fails_closed` |
| T3 | `stop_latch.py` | relative `STOP_LATCH_FILE` + `chdir` | worker `chdir('/')` | watches another file | LOW | fixed | `test_relative_stop_file_survives_chdir` |
| T4 | `stop_latch.py` | `on_stop` callback raises | callback raises | STOP unhandled | LOW | fixed | `test_failing_callback_still_stops_the_process` |
| A1 | `twu_autonomy.py` | seeded NEVER rule kept verbatim with a past `expires` | `never-bypass-stop` + `expires: 2000-01-01` | NEVER silently off, `validate` clean | HIGH | fixed | `test_expired_seed_never_rule_is_restored` |
| A2 | `twu_autonomy.py` | action name with a trailing newline accepted (`$`) | `run_x\n` | accepted as a valid name | LOW | fixed (`\Z`) | `test_trailing_newline_is_not_a_valid_action_name` |
| W1 | `guarded_write.py` | relative `TWU_WRITE_LOCK_DIR` | two cwds | different lock per folder, both pass the compare | MED | fixed (refused) | `test_relative_lock_dir_is_refused` |
| W2 | `guarded_write.py` | FIFO at the target name | `mkfifo` | writer hangs under its lock | LOW | fixed (`O_NONBLOCK`, refused) | `test_fifo_at_the_target_does_not_hang_the_writer` |
| W3 | `write_guard.py` | append through a hard link to a file outside the root | `ln outside/x root/alias` | outside file appended | MED | fixed (refuse `st_nlink > 1`) | `test_append_through_a_hard_link_to_a_file_outside_is_refused` |
| W4 | `write_guard.py` | lock file that is JSON but not an object, or has a non-numeric TTL | `[]`, `"ttl_s":"abc"` | crash with a traceback in every caller | LOW | fixed | `test_lock_record_that_is_not_an_object_is_corrupt_not_a_crash`, `test_non_numeric_ttl_in_a_lock_does_not_crash` |
| G1 | `signal_guard.py` | signal to the parent's process group | `killpg(getpgid(getppid()))` | allowed | LOW | fixed | `test_parent_process_group_is_refused` |
| P1 | `persistence_guard.py` | symlink fingerprinted by target text only | edit the file behind `~/.bashrc` | no finding | MED | fixed (target content hash added) | `test_edit_behind_a_symlink_is_detected` |
| P2 | `persistence_guard.py` | watch list gaps | `.zlogin`, `.gitconfig`, `*.service.d/*.conf`, `/etc/zshrc`, sudoers.d ... | not watched | MED | fixed (patterns added) | `test_default_patterns_cover_login_scripts_git_config_and_dropins` |
| P3 | `net_guard.py`, `persistence_guard.py` | change by another contributor after this release was published: tool files owned by uid 65534 accepted as "root-owned" | by reading the diff | trusted on every host | LOW | fixed (only inside a real user namespace) | `test_nobody_owned_tool_is_trusted_only_inside_a_user_namespace` (both) |

## What I could not break [observed unless marked]

- `malakopia_job_queue.py` (the same file in `malakopia_core` and `enki_waypoint`): job and owner names are matched with `fullmatch`, the state folder and database are opened without following symlinks, claims are SQLite transactions, only the token holder can finish a job [by reading; no bypass found, no dynamic fuzzing done]. Not red-teamed beyond reading: this is a gap.
- `write_guard.py` lock creation (hard link into place), the `dir_fd` pinning, and `guarded_write.py` compare-and-swap with the per-user lock folder: two-writer races, a symlink at the target, a symlink at the lock folder: refused as documented. The remaining check-then-use window described in the code is real and unchanged.
- `home_secret_scan.py`: reads with `O_NOFOLLOW | O_NONBLOCK`, stays within its bounds. Its extension skip list (`.png`, `.db`, ...) is the same class as L3 and was NOT changed; it is a documented speed trade-off of a home-folder sweep. Not fixed.
- `net_guard.py` parsers and compare logic: no bypass found beyond the items above. Limits stay: listeners are keyed by protocol and port, outbound is judged only against a short suspect-port list, program names in allow entries are chosen by the process, the allow files are pinned only if you set `*_SHA256`, up to `MAX_NEIGHBOURS_NEW` new LAN devices are never reported.
- `persistence_guard.py`: hidden files and sub-folders inside watched folders are still not watched (not fixed: `.DS_Store` would raise a false alarm on every Mac).
- `twu_autonomy.py`: classification is by action name only; the policy file and decision log can be edited by the user; a trailing-name trick such as `regenerate_delete_model_weights` matches only the AUTO rule. Documented, not changed.

## Foreign change reviewed

Another contributor's commits added `st_uid in (0, 65534)` to the tool-owner check in `net_guard.py` and `persistence_guard.py` (so the tools run inside an unprivileged user namespace, where root appears as uid 65534). That weakens the "root-owned tool" rule on every ordinary host. Fixed by P3 above; the user-namespace case still works.

## Test runs after the fixes [observed]

Command per run: `env -i PATH=/usr/bin:/bin HOME=<fresh dir> TMPDIR=<fresh dir> PYTHON=<interpreter> ./run_tests.sh` in a copy of the tree, three runs per component per interpreter (`/usr/bin/python3` is 3.9.6, `python3.13` is 3.13.17). Raw lines are in the section "Raw runs" below. The failing-first check (new tests against the unmodified code) failed 45 test results across the four components, including the new tests listed above; the same tests pass with the fixes.

Note on `HOME`: with the system Python 3.9.6 on macOS one entry (`Library/Caches/com.apple.python`, Apple's bytecode cache) appears in the scratch `HOME`; it is created by the interpreter, also with the unmodified code, not by these tests.

| Component | Python | Tests | Raw summary lines (3 runs) |
|---|---|---|---|
| secret_leak_tools | 3.9.6 (`/usr/bin/python3`) | 177 | `Ran 177 tests in 28.215s / OK`, `Ran 177 tests in 32.747s / OK`, `Ran 177 tests in 37.938s / OK` |
| stop_latch_autonomy | 3.9.6 (`/usr/bin/python3`) | 39 | `Ran 39 tests in 1.686s / OK`, `Ran 39 tests in 1.615s / OK`, `Ran 39 tests in 1.507s / OK` |
| write_guards | 3.9.6 (`/usr/bin/python3`) | 62 | `Ran 62 tests in 2.766s / OK`, `Ran 62 tests in 2.611s / OK`, `Ran 62 tests in 2.561s / OK` |
| net_persistence_guards | 3.9.6 (`/usr/bin/python3`) | 93 | `Ran 93 tests in 0.904s / OK`, `Ran 93 tests in 0.929s / OK`, `Ran 93 tests in 1.086s / OK` |
| secret_leak_tools | 3.13.17 (`~/.local/bin/python3.13`) | 177 | `Ran 177 tests in 24.979s / OK`, `Ran 177 tests in 24.254s / OK`, `Ran 177 tests in 22.160s / OK` |
| stop_latch_autonomy | 3.13.17 (`~/.local/bin/python3.13`) | 39 | `Ran 39 tests in 1.218s / OK`, `Ran 39 tests in 1.289s / OK`, `Ran 39 tests in 1.259s / OK` |
| write_guards | 3.13.17 (`~/.local/bin/python3.13`) | 62 | `Ran 62 tests in 1.475s / OK`, `Ran 62 tests in 1.072s / OK`, `Ran 62 tests in 1.338s / OK` |
| net_persistence_guards | 3.13.17 (`~/.local/bin/python3.13`) | 93 | `Ran 93 tests in 0.970s / OK`, `Ran 93 tests in 0.784s / OK`, `Ran 93 tests in 0.722s / OK` |


Final tree (the committed state, exported with `git archive`, run once per interpreter after the last edits): secret_leak_tools 177, stop_latch_autonomy 39, write_guards 62, net_persistence_guards 93, malakopia_core 103, enki_waypoint 107 tests, all OK on 3.9.6 and on 3.13.17.

## How this was published

The publish gate has four steps. On the real repository the three tree and identity steps pass. The fourth step scans the whole history and reports findings only in two earlier commits (f9bfe61, ad9e8d8) that were already public before this round; those commits were not touched and no history was rewritten. To show that the new commits add nothing, the gate was also run on a one-commit repository holding exactly the tree of the new HEAD: all four steps PASS. The push is a normal fast-forward push, no force.
