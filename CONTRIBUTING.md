# Contributing

Thanks for looking. This is a small, one-maintainer project, so the process is light.

## What is most useful

1. **Corrections.** A claim in a README or doc that the code or tests do not support. Open an issue with the "Correction or overclaim" template.
2. **Bug reports** with a reproduction (component, command, Python version, OS, raw output).
3. **A run on Linux.** Linux is not tested by me. A CI or local result, pass or fail, is valuable. Paste raw output.
4. **Small pull requests** that fix one thing and add or change a test.

Vulnerabilities do not go in public issues; see [SECURITY.md](SECURITY.md).

## Ground rules

- **Standard library only.** No third-party dependencies, no network access at runtime, no installs.
- **Python 3.9 and newer.** CI runs 3.9 and 3.13. Avoid syntax newer than 3.9.
- **Tests for every change.** Each component has its own `run_tests.sh`. Run everything with `./run_all_tests.sh` before you open a PR.
- **Tests must be hermetic.** They must not read or write your real home folder or the real network. Run them with a scratch `HOME` and `TMPDIR` to check (see [docs/VERIFICATION.md](docs/VERIFICATION.md)).
- **Keep the two queue copies identical.** `malakopia_core/scripts/malakopia_job_queue.py` and its test are copied into `enki_waypoint/scripts/`. Change both, then run `tools/check_queue_sync.sh`.
- **No private data.** No real hostnames, usernames, IPs, MACs, keys, tokens or personal paths, even in tests. Use documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`) and obviously fake values. Build key-shaped test strings from pieces at run time. Run `tools/check_placeholders.sh .` before you push.
- **Claims need evidence.** Numbers in docs come from a real run: paste the command, the date and the raw summary line, and tag it `[observed]` (you ran it) or `[relayed]` (you read it somewhere). Do not use hype words about quality or verification (the leak check fails on a short list of them).
- **Say if an AI agent wrote it.** AI-assisted contributions are welcome. Say so in the PR and read the code yourself before you submit it.

## Licence

By contributing you agree that your contribution is licensed under the MIT licence in [LICENSE](LICENSE).

Please follow the [Code of Conduct](CODE_OF_CONDUCT.md).
