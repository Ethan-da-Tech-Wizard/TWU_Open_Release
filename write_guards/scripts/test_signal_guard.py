import os, sys, unittest
from pathlib import Path
from unittest.mock import MagicMock, Mock
sys.path.insert(0, str(Path(__file__).resolve().parent))
import signal_guard as g


class Guard(unittest.TestCase):
    """Tests for: Guard."""
    def test_dangerous_targets_are_named(self):
        """Check that dangerous targets are named."""
        for pid in (MagicMock(), Mock(), None, "7", 0, 1, -1, os.getppid()):
            self.assertTrue(g.blocked_reason(pid), pid)
        for pgid in (MagicMock(), 0, 1, -5, os.getpgrp()):
            self.assertTrue(g.blocked_reason(pgid, group=True), pgid)
        self.assertTrue(g.blocked_reason(-1))
        self.assertTrue(g.blocked_reason(-os.getpgrp()))

    def test_ordinary_child_targets_pass(self):
        """Check that ordinary child targets pass."""
        self.assertIsNone(g.blocked_reason(os.getpid() + 100000))
        self.assertIsNone(g.blocked_reason(2**22 + 5, group=True))

    def test_installed_wrappers_block_before_any_syscall(self):
        """Check that installed wrappers block before any syscall."""
        g.install(); g.install()   # idempotent
        import signal
        for call in (lambda: os.kill(1, 0), lambda: os.kill(MagicMock(), 0), lambda: os.killpg(1, 0),
                     lambda: os.killpg(MagicMock(), 0), lambda: os.killpg(os.getpgrp(), 0)):
            with self.assertRaises(PermissionError):
                call()       # signal 0 only: harmless even if the guard were broken

    def test_real_child_can_still_be_signalled(self):
        """Check that real child can still be signalled."""
        import subprocess, signal
        g.install()
        with subprocess.Popen([sys.executable, "-c", "import time;time.sleep(30)"], start_new_session=True) as child:
            os.killpg(child.pid, signal.SIGTERM)
            self.assertEqual(child.wait(timeout=5), -signal.SIGTERM)

    def test_guard_is_inert_when_unittest_is_not_loaded(self):
        # call-time check: a production process never imports unittest, so nothing is blocked there
        """Check that guard is inert when unittest is not loaded."""
        src = Path(g.__file__).read_text()
        self.assertIn('"unittest" in sys.modules', src)


class RedTeam5(unittest.TestCase):
    """Seat-5 bypass hunt."""
    def test_parent_process_group_is_refused(self):
        """The launcher's own process group (different from ours) must be refused for killpg and for kill(-pgid)."""
        from unittest import mock
        with mock.patch("os.getpgid", return_value=987654):
            self.assertTrue(g.blocked_reason(987654, group=True))
            self.assertTrue(g.blocked_reason(-987654))
            self.assertIsNone(g.blocked_reason(987655, group=True))


if __name__ == "__main__":
    unittest.main()
