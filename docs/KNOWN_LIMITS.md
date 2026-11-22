# Known limits

This page lists what I know does not hold, in one place. Nothing here is hidden elsewhere and softened here; each item is also said where it applies. Numbers and dates are in [VERIFICATION.md](VERIFICATION.md).

## Where it was tested

- **macOS only.** Every result I report was produced on one Mac (arm64) with Python 3.9.6 and 3.13.17. I have not run any of it on Linux.
- **Linux is untested until CI runs.** `.github/workflows/ci.yml` runs every component on Ubuntu and macOS, Python 3.9 and 3.13. I have not read a CI result yet. Until I have, treat Linux as unsupported, and treat a red Linux row as a real finding. The systemd unit templates and the Linux code paths in the network guard were written but never run as services.
- **No Windows support.** Not attempted.

## What the test counts mean

- **Counts are static.** "N tests" is what `unittest` printed on the run recorded in [VERIFICATION.md](VERIFICATION.md). It is a count of tests that ran, not a pass rate over the code, not coverage, and it changes whenever a test is added.
- **One intermittent failure I cannot explain.** In roughly 100 runs of the `malakopia_core` suite on Python 3.13, one run failed once. I have not found the cause and do not know whether it is a timing assumption in the queue tests (some use short real `sleep` calls) or something else. It did not recur in the final measured run. Treat the suites as "passed on every recorded run", not as proven free of flakes. If you see it, please open an issue with the output.
- **Tests use short real sleeps** (0.05 to 0.2 s) in the queue and stop-latch tests. A very loaded machine could make one fail.
- **Volume numbers** in [VOLUME_FACTS.md](VOLUME_FACTS.md) measure my private workspace, not this repository.

## Who checked it

- **All five reviews were AI-assisted. No outside human has reviewed this code.** The reviews were run by other AI sessions under my direction. "Independent" in this repository means "a separate session", not "a person outside the project". The tests are my own, written with AI coding agents, so passing them shows the code does what its authors expected, not that the expectations are right.
- Several fixes were reviewed by the same agent system that wrote them.
- Most recovery stories are [relayed]: read from my own CHANGELOG, not re-run.

## Design limits you will run into

- **The job-queue module is duplicated.** `malakopia_job_queue.py` and its test exist as byte-identical copies in `malakopia_core/scripts/` and `enki_waypoint/scripts/` so that each folder runs alone. `tools/check_queue_sync.sh` and a test in each component fail if the copies differ, but a fix still has to be made twice.
- **Not a security boundary.** These tools notice and prevent accidents by cooperating, same-user processes. A process running as you can edit a baseline, an allow file or a guard. See [SECURITY.md](../SECURITY.md).
- **The STOP latch is cooperative.** A worker that does not import it ignores it. A worker that does import it exits when the file appears.
- **Path checks in `write_guards` are not a boundary against a hostile writer.** The remaining check-then-use race is stated in the code and in that component's README.
- **Scanners miss things.** Encoded or split secrets, a real key with a placeholder word attached, and files over 1 MB (`secret_scan.py check`) or 2 MB (`twu_leakwatch.py`) are not scanned. (Lines over 4,000 characters and files containing a NUL byte were skipped in the first release; both are scanned now.) See the component README for the full list.
- **The git hook is advisory.** `--no-verify`, `core.hooksPath`, a clone or repository without the hook installed, merge commits made without `--no-verify` but without a pre-commit run, and anything else listed under "What the hook does NOT stop" in [secret_leak_tools/README.md](../secret_leak_tools/README.md) bypass it. A bypass hunt after publication found and fixed 16 hook bypasses that were present in the first release (see [RED_TEAM_SEAT5.md](RED_TEAM_SEAT5.md)); it does not prove the hook has no others.
- **Guards that watch files are same-user tools.** `persistence_guard` does not watch hidden files inside the watched folders (for example `~/.local/bin/.x`) or sub-folders of them, and `net_guard` only knows listeners and a short list of suspect outbound ports; both can be edited, along with their baselines, by anything that runs as you.

## Behaviour that needs configuration

- **`net_guard` and `persistence_guard` first runs.**
  - `net_guard` needs `lsof`, `arp`, `route` and `scutil` on macOS, or `ss` and `ip` on Linux. They are called by absolute path from system folders, so a Mac without the Command Line Tools, or an unusual Linux layout, makes a check report the sensor as unavailable.
  - On a stock Mac `persistence_guard check` exits 1 after `learn`, with one `metadata-only` finding for `/etc/ssh/sshd_config`, which only root can read. That is expected, not a compromise.
  - Without root, both tools see only this user's sockets and files.
  - Nothing is exempt by name. A program that opens ephemeral UDP ports (a sync tool, a game) will alarm until you add an exact entry to the opt-in allow file, ideally pinned with the `*_SHA256` variable.
- **State is written where you point it.** The default state folder is the component folder, under `data/`. The repository `.gitignore` excludes it, but do not copy it elsewhere: baselines and receipts describe your machine.
- **Scheduling is yours to set up.** The macOS installers write a user LaunchAgent only after you confirm, and were exercised with a scratch `HOME` without loading the job. The systemd templates were not run.
- **`twu_leakwatch` zones are empty by default.** Set the zone environment variables or a zones file, otherwise it reports secrets only and no personal-data zone findings.
- **`malakopia_export` refuses to run** until you supply an allowlist.
- **`stop_latch_autonomy`** ships a seed policy table for illustration. Review every `AUTO` rule before you rely on it; it is a lookup, nothing is executed by it.

## Naming

"TWU" is the short name of my company and "Magi" is my name for a numbered agent session; both are explained in the [README glossary](../README.md#glossary). They appear in some environment variable and file names and carry no meaning for how the code works.
