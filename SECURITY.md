# Security policy

## What these tools are, and are not

The components here are small, standard-library Python tools that help an operator notice or prevent accidents: an unexpected listening port, a new startup item, a secret in a commit, two writers overwriting one file, a runaway worker.

They are **not**:

- a sandbox or a security boundary. Nothing here isolates untrusted code.
- an intrusion-detection or antivirus product. They compare the machine to a baseline you accepted, as the same user, and a process running as that user can edit the baseline.
- audited. All tests are my own, written with AI coding agents, and run on one Mac. No third party has reviewed this code. Linux has not been run (CI will show whether it passes there).
- guaranteed to find every secret. Scanners match patterns; encoded or split secrets are out of scope, and some skip rules exist (each component README lists its limits).

Each component folder has its own `SECURITY.md` with the specifics. A written review of the code is summarised, with its open items, in [docs/VERIFICATION.md](docs/VERIFICATION.md). Read it before you rely on any of this.

## Do not commit what the tools write

Several tools write receipts and baselines under `data/` (listeners, startup items, paths of files that contain credential-shaped strings, user and terminal names). That output describes your machine. `.gitignore` excludes `data/`, `state/`, receipts and logs; keep it that way and never publish those files.

## Reporting a vulnerability

Please use GitHub's **private vulnerability reporting**: open the repository's **Security** tab and choose **Report a vulnerability**. That creates a private advisory visible only to me and to you. I have no email address for security reports on purpose; please do not open a public issue for a vulnerability.

Useful in a report: the component and file, what you did, what you expected, what happened, and the Python and OS version. If it is about `malakopia_job_queue.py`, say so: that module ships in two identical copies (`malakopia_core/scripts/` and `enki_waypoint/scripts/`), and a fix must land in both. `tools/check_queue_sync.sh` checks they match.

I will acknowledge a report as soon as I can. This is a one-person project with no service-level promise.

Wrong claims count too. If a README or doc says something the code or tests do not support, report it as an issue (use the "Correction or overclaim" template); that is a bug in the documentation and I will fix it and log it.

## The git hook is advisory
The pre-commit and pre-push hooks in `secret_leak_tools` stop accidents. They do not stop `git commit --no-verify`, a repository or clone where the hook was never installed, `core.hooksPath`, encoded or split secrets, or a real key with a placeholder word attached. A bypass hunt (see [docs/RED_TEAM_SEAT5.md](docs/RED_TEAM_SEAT5.md)) fixed 16 bypasses in the first release and lists what is still open.

## Supported versions

Only the latest commit on the default branch. There are no releases.
