"""Process-wide safety net: while a unittest is running, refuse signals that can reach the whole session.

Why: a mocked Popen's pid (a MagicMock, which converts to 1) can reach os.killpg(1, SIGKILL), which is kill(-1, SIGKILL),
and that ends the whole desktop session. A sandboxed runner contains that, but anyone can run a test by hand.
This guard works for every launcher: install() wraps os.kill/os.killpg, and the wrapper checks AT CALL TIME whether
unittest is loaded, so production daemons (which never import unittest) are unaffected.

Not applied automatically: nothing here installs itself (no .pth or sitecustomize). A program that calls install() and also
imports unittest for some other reason would see the same blocks on legitimate pid <= 1 or negative-pid signals.

Blocked while testing: pid 0 / 1 / negative targets for kill, group <= 1 or our own group for killpg, non-integers
(mocks), and our own parent. Everything else (a test killing its own child) passes through unchanged.
"""
# Standard library only. os provides the process and signal calls that are wrapped below;
# sys.modules is how the guard notices that a test run is active.
import os
import sys

# Module-level flag that makes install() idempotent: wrapping twice would stack wrappers.
_installed = False


def blocked_reason(pid, group=False):
    """Why this signal target is unsafe during a test, or None."""
    # Check the type first: a Mock or MagicMock converts to the integer 1 when passed to the C-level signal
    # calls, which is how a mocked pid ends up signalling init or every process the user owns.
    # `type(...) is not int` (not isinstance) also rejects bool and int subclasses on purpose.
    if type(pid) is not int:
        return f"non-integer target {type(pid).__name__} (a mock converts to 1)"
    # killpg rules. Group ids 0 and 1 are never a test's own child group, and a negative id is not a valid
    # group id for killpg at all, so all of them are refused.
    # RED-TEAM 5 (Rule 16): the PARENT's process group is as dangerous as our own (a terminal or launcher in its own job
    # group); only our own group was refused before, so os.killpg(os.getpgid(os.getppid()), ...) and kill(-that) went through.
    try:
        parent_group = os.getpgid(os.getppid())
    except OSError:
        parent_group = None
    if group:
        if parent_group is not None and pid == parent_group:
            return "killpg of our parent's process group (the launcher/terminal)"
        # killpg(1, ...) is kill(-1, ...): every process the user may signal. 0 and negative values are refused too.
        if pid <= 1:
            return f"killpg({pid}) is kill(-{pid}): signals every process you own"
        # Our own process group contains the test runner and whatever launched it (a shell, a terminal),
        # so a test must never signal it.
        if pid == os.getpgrp():
            return "killpg of our own process group (the test runner and its launcher)"
        # Not dangerous by these rules: the caller may go ahead.
        return None
    # kill rules. pid 0 means our own process group, -1 means every process we may signal, 1 is init/launchd.
    if pid <= 1 or pid == -1:
        return f"kill({pid}) targets init, our whole group, or every process you own"
    # A negative pid addresses a whole process group: refuse init's group and our own.
    if pid < 0 and -pid in (1, os.getpgrp(), parent_group):
        return "kill of init's or our own process group"
    # Signalling the parent would end the launcher or terminal that started the tests.
    if pid == os.getppid():
        return "signalling our own parent (the launcher/terminal)"
    return None


def _testing():
    """True while the unittest module is loaded, i.e. while some test run is in progress in this process."""
    # The check runs at call time, not at import time: production daemons never import unittest, so for them
    # the wrappers are pass-throughs. (A program that imports unittest for other reasons is treated as testing.)
    return "unittest" in sys.modules


def install():
    """Idempotent. Safe to call from sitecustomize/.pth at interpreter start."""
    # Second and later calls do nothing.
    global _installed
    if _installed:
        return
    # Keep the genuine functions in closures so the wrappers can still reach them.
    real_kill, real_killpg = os.kill, os.killpg

    def kill(pid, sig, *a, **k):
        """Replacement for os.kill: refuses unsafe targets during a test run, otherwise calls the real os.kill."""
        # False when not testing, a message string when the target is unsafe, None when it is fine.
        reason = _testing() and blocked_reason(pid)
        if reason:
            # PermissionError is what a real refused signal raises, so callers already know how to handle it.
            raise PermissionError(f"signal_guard blocked os.kill({pid!r}, {sig}): {reason}")
        return real_kill(pid, sig, *a, **k)

    def killpg(pgid, sig, *a, **k):
        """Replacement for os.killpg: refuses unsafe process groups during a test run, otherwise calls the real
        one.
        """
        # Same pattern for process groups.
        reason = _testing() and blocked_reason(pgid, group=True)
        if reason:
            raise PermissionError(f"signal_guard blocked os.killpg({pgid!r}, {sig}): {reason}")
        return real_killpg(pgid, sig, *a, **k)

    # Patch the os module itself so every importer of os.kill/os.killpg, including subprocess helpers,
    # goes through the guard from now on.
    os.kill, os.killpg = kill, killpg
    _installed = True
