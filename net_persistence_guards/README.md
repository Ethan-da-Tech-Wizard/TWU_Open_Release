# Network and persistence guards

Two small standard-library Python tools that tell you when your machine's network exposure or its startup items change.
Status: working on macOS; unit tests pass; Linux and systemd paths are written but not run. See [Limits](#limits).

## What it is
- `scripts/net_guard.py` compares the current listening ports, default-gateway MAC address, DNS resolvers, LAN neighbours
  and outbound connections with a baseline you accepted earlier, and reports the differences.
- `scripts/persistence_guard.py` does the same for places that run code at login or boot: shell rc files, ssh keys and
  config, autostart entries, launchd and user systemd units, `~/.local/bin`, cron files and `/etc/ld.so.preload`.
- Both run as a normal user, read metadata or hashes only, and write a small JSON receipt. `scripts/mac_*_install.sh`
  schedules them with launchd; `templates/` holds the launchd and systemd files.

## Why it exists
A new listener, a changed gateway MAC address or a new login hook is how many compromises start, and nobody looks.
These tools make the change visible the next time they run (every 10 or 15 minutes if you install the macOS jobs; nothing runs until you schedule it), using only what an unprivileged user can see. They are
change detectors, not protection: see [Security notes](#security-notes).

## Requirements
- Python 3.9 or newer, standard library only. No network access, no root, nothing to install.
- macOS: the stock `lsof` (`/usr/sbin`), `arp` (`/usr/sbin`), `route` (`/sbin`), `scutil` (`/usr/sbin`) and `ps` (`/bin`).
- Linux (untested): `ss`, `ip`, `systemctl` and `ps` from a root-owned system folder.
- External commands are called by absolute path from `/bin`, `/usr/bin`, `/sbin` and `/usr/sbin` only, never through
  `PATH`, so a minimal `PATH` (launchd, cron) works. A tool that is missing, not owned by root, or writable by others is
  reported as `sensor-unavailable`.
- Linux, non-root: root-only system folders on the watch list (for example `/etc/sudoers.d`, `/etc/cron.d` when mode 0750 root) cannot be listed. Instead of aborting the whole scan, `learn` records the folder as `<folder>/` = `unreadable:<hash of the folder's own metadata>` and every `check` reports `persist:unreadable:<folder>/` ("unreadable: sudoers.d ..."), so it never reads as clean. Only a root-owned folder matched by an absolute pattern and a permission error qualify; an unreadable folder in your home, or owned by anyone else, is still `sensor-unavailable`.

## Quick start
```bash
# from the root of a clone or unpacked copy of the repository
cd net_persistence_guards
python3 scripts/net_guard.py learn          # on a network you trust: saves the baseline
python3 scripts/net_guard.py check          # prints one PROBLEM line per finding
python3 scripts/persistence_guard.py show   # review what will be accepted
python3 scripts/persistence_guard.py learn
python3 scripts/persistence_guard.py check
```
What the exit status means: `0` nothing differs from the baseline; `1` there are findings (or the check could not
finish, which is reported as a finding such as `sensor-unavailable`); `2` wrong usage. Exit 1 means "read the output",
not "the program crashed".

On a stock Mac the last command normally exits 1 with one finding, `persist:metadata-only:/etc/ssh/sshd_config`. That
file is readable only by root, so the guard can fingerprint its size and timestamps but not its content, and it says so
on every check instead of pretending to have full coverage. Review it once; it is expected and not a compromise. A
baseline from `learn` is only as trustworthy as the machine at that moment, so run it after looking at `show` output.

Baselines and receipts are written to `data/netguard/` under the state folder (`TWU_ROOT`, default: this folder). That
folder holds details of your machine; do not commit or publish it.

## Scheduling on macOS
```bash
bash scripts/mac_net_guard_install.sh            # writes the plist, asks, then loads it with launchctl
bash scripts/mac_persistence_guard_install.sh
bash scripts/mac_net_guard_install.sh --check    # state of script, plist and job, plus one run
bash scripts/mac_net_guard_install.sh --uninstall
```
Options: `--yes` skips the question (required when stdin is not a terminal), `--dry-run` writes the plist but does not
load it, `--python PATH` overrides the interpreter. The installer refuses to run without a baseline, asks for
confirmation before loading anything, and uses `/usr/bin/python3` by default. It does not search for Homebrew, pyenv or
`~/.local` Pythons, because a user-writable interpreter would let anyone who can edit it run code every time the job
fires. On a Mac without the Command Line Tools, `/usr/bin/python3` triggers Apple's installer prompt; install them first
(`xcode-select --install`) or pass `--python`. The jobs are labelled `local.net-persistence-guards.*` and log to
`~/Library/Logs`. The launchd installer has been exercised only with a scratch `HOME` and without loading the job.

## Linux (systemd), untested
The service files in `templates/` contain `@@ROOT@@`, the absolute path of this folder. Render and install, for example:
```bash
mkdir -p ~/.config/systemd/user
for u in net-guard persist-guard; do
  sed "s|@@ROOT@@|$PWD|g" templates/$u.service > ~/.config/systemd/user/$u.service
  cp templates/$u.timer ~/.config/systemd/user/
done
systemctl --user daemon-reload && systemctl --user enable --now net-guard.timer persist-guard.timer
```

## Configuration
Every setting is an environment variable; an empty value means "use the default". `config.example.env` lists them all.

| Variable | Default | Meaning |
|---|---|---|
| `TWU_ROOT` | folder above `scripts/` | Where `data/netguard/` (baselines, receipts) is written. `TWU_` is just this project's variable prefix. |
| `TWU_PERSIST_HOME` | your home folder | Folder `persistence_guard` scans instead of your home (testing, or another user's copy). |
| `TWU_PERSIST_EXEMPT_FILE` | none | Opt-in exemption file for `persistence_guard` (format below). |
| `TWU_NET_ALLOW_LISTEN_FILE` | `<state>/allow_listen.json` if present | Exact `(proto, port, program)` listeners to skip. |
| `TWU_NET_ALLOW_LISTEN_SHA256` | none | sha256 (hex) that file must have; if set and different, the check reports `net:sensor-unavailable`. |
| `TWU_NET_ALLOW_OUTBOUND_FILE` | `<state>/allow_outbound.json` if present | Exact `(program, port)` outbound pairs to skip. |
| `TWU_NET_ALLOW_OUTBOUND_SHA256` | none | sha256 (hex) that file must have. |
| `SSH_TTY`, `TTY` | unset | Read only to label the terminal in `learn` receipts when there is no controlling terminal. |
| `PYTHON` | `python3` | Interpreter used by `run_tests.sh` only. |

Nothing is exempt by default and no program or unit name is trusted.

- Startup items: `persistence_guard.py show` prints `digest  path` for every watched item. An exemption file is
  `{"exempt": [{"path": "~/.config/systemd/user/example.service", "digest": "<digest from show>"}]}`. An item is
  reported as `info` only while both its path and its digest match; change the file and it alarms again. Removed
  items always alarm.
- Network: `{"allow": [{"proto": "udp", "port": 40000, "prog": "name"}]}` for listeners and
  `{"allow": [{"prog": "name", "port": 9001}]}` for outbound pairs. Entries match exactly, with no ranges. Set the
  matching `*_SHA256` variable to the file's sha256 (`shasum -a 256 FILE`) so that editing the file is noticed.

## Tests
```bash
./run_tests.sh                                   # python3
PYTHON=/path/to/python3.13 ./run_tests.sh
```
The tests use fake command output and temporary folders only: no network, no root, no real home folder.
Re-measured after the bypass-hunt fixes (`docs/RED_TEAM_SEAT5.md`) [observed 2026-11-21, the numbers below replace the earlier ones; the older paragraph's code digest no longer applies to this folder; own tests, macOS 27.2.1 arm64, code digest `8216b138b505…`]: `env -i` with a separate realpath-resolved `HOME` and `TMPDIR` per run, three runs per interpreter, run from a copy of the tree. All 6 runs passed; no `ResourceWarning` lines; no files left in `HOME` or `TMPDIR`.

| Python | Tests ran | Raw summary lines (3 runs) |
|---|---|---|
| 3.9.6 (`/usr/bin/python3`) | 95 | `Ran 95 tests in 1.051s / OK`, `Ran 95 tests in 1.054s / OK`, `Ran 95 tests in 0.982s / OK` |
| 3.13.17 (`~/.local/bin/python3.13`) | 95 | `Ran 95 tests in 0.715s / OK`, `Ran 95 tests in 0.732s / OK`, `Ran 95 tests in 0.811s / OK` |

Two tests were added after the first Linux CI run (ubuntu-24.04, non-root runner) failed on `/etc/sudoers.d` (mode 0750 root, unreadable): the default-pattern test now reads a fake root folder, never the real `/etc`, and two new tests cover the `unreadable:` behaviour below. The 6 runs above were repeated after that change; the code digest above predates it.

Platform: macOS, arm64. These are the project's own tests; they are not an independent audit.

## Design
```
net_guard.py          injected runner (ss/ip or lsof/route/arp/scutil) -> snapshot -> compare to baseline -> receipt
persistence_guard.py  glob list of startup places -> hashes (or metadata when unreadable) -> compare -> receipt
templates/            launchd plists and systemd units; scripts/mac_*_install.sh renders and loads the plists
```
Nothing is stored beyond addresses, ports, program names, file paths and hashes. File contents are never recorded.

## Security notes
- Threat model: unnoticed changes in network exposure and startup persistence on a machine you administer. Out of
  scope: kernel or firmware tampering, an attacker running as the same user (who can edit the baseline, the allow files
  or the guard itself), remote monitoring, anything that needs root.
- No built-in trust by name. Names and prefixes prove nothing because any program can choose its own; exemptions are
  opt-in and exact. See [SECURITY.md](SECURITY.md) and the repository-wide [../SECURITY.md](../SECURITY.md).
- Allow and exemption files are ordinary same-user files. Keep them read-only and pin the network ones with `*_SHA256`.
- Without root, `lsof` and `ss` show only this user's sockets, so listeners owned by other users or root are not seen.
- The code has not been penetration-tested. These tools are guardrails, not a security boundary.

## Limits
- Found by the seat-5 bypass hunt and fixed: baseline, receipt and `.tmp` files were written through a planted symlink (now created exclusively without following links); `persistence_guard` fingerprinted a symlink by its target text only, so editing the file behind `~/.zshrc` was invisible (the target's content hash is now part of the value, so existing symlink entries show once as CHANGED after upgrading); the watch list lacked `.zlogin`, `.zlogout`, `.bash_logout`, `.gitconfig`, systemd drop-in `.conf` files and a few `/etc` files (added; expect NEW findings once); and a tool file owned by uid 65534 (added by another contributor for user namespaces) was trusted on every host, now only inside a real user namespace. Not fixed: hidden files and sub-folders inside watched folders are not watched, the exemption and allow files are only pinned if you set the `*_SHA256` variable, and new LAN devices up to `MAX_NEIGHBOURS_NEW` are never reported. Details: `../docs/RED_TEAM_SEAT5.md`.
- Tested on macOS only. Linux (`ss`, `ip`, `systemctl`, `/etc/resolv.conf`) and the systemd templates have not been run.
- The unit tests use fake command output; they do not prove the real `lsof`, `ss` or `arp` formats on every system.
- A probe that fails (for example a missing tool) is reported as `sensor-unavailable` instead of a clean result.
- A baseline is only as good as the moment you ran `learn`; a compromised machine will learn a compromised baseline.
- Receipts and baselines are unsigned plain JSON.
- Most of this code was written with AI coding agents and reviewed by a person; the tests are the authors' own.

## License
MIT, see [LICENSE](LICENSE) (this folder) and [../LICENSE](../LICENSE) (repository root).
