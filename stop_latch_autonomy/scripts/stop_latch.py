#!/usr/bin/env python3
"""The shared STOP latch: one file that tells every cooperating worker to stop.

Program:    scripts/stop_latch.py
Programmer: written with AI coding agents and reviewed by the maintainer
Purpose:    a worker calls ``stop_latch.enforce("<name>")`` once at its entrypoint:

* if the STOP file is present it refuses to start (exit 0, one stderr line), and
* otherwise a daemon thread checks the file every few seconds (a single ``stat``; near-zero
  CPU) and, when STOP appears, sends the process SIGTERM so its normal shutdown handlers run,
  then hard-exits after a grace period if the process is still alive.

``refuse_if_stopped`` is the entry check alone, for one-shot commands. Nothing here starts a
process, model, service or network request. This is cooperative: a process that never calls it is not stopped.
"""
# >>> HOW THIS WORKS
# FLOW:    1 A worker calls enforce("name") at startup. 2 enforce() calls refuse_if_stopped(): if the STOP file exists it
#          prints one line to stderr and raises SystemExit(0). 3 Otherwise watch() starts one daemon thread per name.
#          4 The thread's loop() checks stop_present() every `interval` seconds (default 5, never below 0.05).
#          5 When STOP appears it runs _default_on_stop(): print a line, send SIGTERM to its own process, sleep the
#          grace time (default 30 s), then os._exit(0) if the process is still alive.
# DATA:    Reads only: whether the STOP file exists. Where that file is (first match wins):
#            1. env STOP_LATCH_FILE  = exact path of the STOP file;
#            2. env STOP_LATCH_ROOT  = folder, the file is <folder>/STOP;
#            3. default              = <parent of the scripts/ folder>/STOP.
#          Writes nothing. It calls nothing outside the standard library.
# FAILS:   STOP present at start: clean exit 0, no work. STOP appears later: SIGTERM first, so normal shutdown
#          handlers run; a process that ignores SIGTERM is killed after the grace time. Calling watch() twice with the
#          same name returns the existing live thread (no duplicates). A custom on_stop callback replaces the default.
# EXTEND:  Add new helpers near enforce(). Test: scripts/test_stop_latch.py. Run (from the component folder):
#          python3 -B -m unittest -q scripts.test_stop_latch
# GOTCHAS: Running the file directly only prints "STOP present" or "STOP absent". Watching is a stat poll, not a file
#          event. A relative STOP_LATCH_FILE is resolved against the current directory of each process (use an absolute path).
# GLOSSARY: STOP latch = the file whose mere existence tells every cooperating worker to stop work.
# <<< HOW THIS WORKS
from __future__ import annotations

import os
import signal
import sys
import threading
import time
from pathlib import Path

# Folder that holds scripts/ (this file's grandparent); only used when neither env variable below is set.
REPO_ROOT = Path(__file__).resolve().parent.parent
# Step 1: an explicit file wins; step 2: an explicit folder; step 3: the default folder. Evaluated once at import time.
# RED-TEAM 5 (Rule 16): the path is made ABSOLUTE here. A relative STOP_LATCH_FILE / STOP_LATCH_ROOT used to be looked up
# against the current directory on every poll, so a worker that called os.chdir() after import watched a different
# (usually missing) file and never saw STOP.
def _abs(p) -> Path:
    """Absolute form of a path (user folder expanded, current directory applied now); no symlink is resolved."""
    return Path(os.path.abspath(os.path.expanduser(str(p))))


if os.environ.get("STOP_LATCH_FILE"):
    STOP_FILE = _abs(os.environ["STOP_LATCH_FILE"])
else:
    STOP_FILE = _abs(os.environ.get("STOP_LATCH_ROOT") or REPO_ROOT) / "STOP"
# Seconds between stat() polls of the STOP file, and seconds to wait after SIGTERM before a hard exit.
DEFAULT_INTERVAL = 5.0
DEFAULT_GRACE = 30.0
ENTRY_FUNCTIONS = frozenset({"enforce", "refuse_if_stopped"})  # the two entry calls a coverage checker can look for

# One live watcher thread per worker name, so calling watch() twice never starts a duplicate poller.
_watchers: dict[str, threading.Thread] = {}


def stop_present(path: Path | None = None) -> bool:
    """True when the STOP latch file exists. Fail closed: only "no such file / folder" means absent.

    RED-TEAM 5 (Rule 16): Path.exists() follows symlinks, so a DANGLING symlink at the STOP path read as "absent"; and an
    unreadable folder either raised (Python 3.9: the watcher thread died silently) or returned False (3.12+). os.lstat() sees
    the directory entry itself, and any error other than ENOENT/ENOTDIR counts as STOP present."""
    target = STOP_FILE if path is None else _abs(path)
    try:
        os.lstat(target)
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError:
        return True
    return True


def refuse_if_stopped(name: str, path: Path | None = None) -> None:
    """Exit cleanly before doing any work when STOP is present."""
    if stop_present(path):
        print(f"{name}: STOP latch present ({STOP_FILE if path is None else path}); not starting.", file=sys.stderr)
        raise SystemExit(0)


def _default_on_stop(name: str, grace: float) -> None:
    """Default reaction to STOP: log one line, send SIGTERM to this process, then hard-exit after the grace period."""
    # Ask for a normal shutdown first so the worker's own SIGTERM handlers can flush state and clean up.
    print(f"{name}: STOP latch appeared; shutting down.", file=sys.stderr, flush=True)
    os.kill(os.getpid(), signal.SIGTERM)
    # Give those handlers the grace period; if we are still running afterwards the process ignored SIGTERM.
    time.sleep(grace)
    os._exit(0)  # the process ignored SIGTERM; STOP still wins


def watch(name: str, interval: float = DEFAULT_INTERVAL, path: Path | None = None,
          on_stop=None, grace: float | None = None) -> threading.Thread:
    """Start (once per name) a daemon thread that reacts when STOP appears."""
    # Reuse a watcher that is still alive for this name instead of starting a second one.
    if name in _watchers and _watchers[name].is_alive():
        return _watchers[name]
    # Clamp the poll interval so a tiny or zero value cannot turn the watcher into a busy loop.
    interval = max(0.05, float(interval))

    def loop() -> None:
        """Thread body: wait for the STOP file to appear, then run the stop action once."""
        # Poll until the file appears; a single stat() per interval costs almost nothing.
        while not stop_present(path):
            time.sleep(interval)
        # Run the caller's callback if given, otherwise the default SIGTERM-then-exit behaviour.
        # RED-TEAM 5: a custom callback that raises used to end this thread with STOP unhandled; STOP always wins, so the
        # default shutdown runs if the callback fails.
        default = lambda: _default_on_stop(name, DEFAULT_GRACE if grace is None else grace)  # noqa: E731
        if on_stop is None:
            default()
            return
        try:
            on_stop()
        except BaseException:
            default()

    # A daemon thread never keeps the process alive on its own; it only watches for STOP.
    thread = threading.Thread(target=loop, name=f"stop-latch-{name}", daemon=True)
    thread.start()
    _watchers[name] = thread
    return thread


def enforce(name: str, interval: float = DEFAULT_INTERVAL, path: Path | None = None) -> threading.Thread:
    """Entry check plus a running watch: the standard call for any daemon or server."""
    # Entry check first: if STOP already exists the worker exits cleanly before doing any work.
    refuse_if_stopped(name, path)
    return watch(name, interval, path)


if __name__ == "__main__":
    print("STOP present" if stop_present() else "STOP absent")
