#!/usr/bin/env python3
"""Real-process checks for the shared STOP latch (no models, services or network)."""
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import stop_latch  # noqa: E402


def child(stop_path, body):
    """Helper: child."""
    code = textwrap.dedent(f"""
        import sys, time
        sys.path.insert(0, {str(HERE)!r})
        import stop_latch
        {body}
    """)
    return subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)


class StopLatchTests(unittest.TestCase):
    """Tests for: Stop Latch Tests."""
    def setUp(self):
        """Create the scratch state this test needs."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.stop = Path(tmp.name) / "STOP"

    def spawn(self, body):
        """Helper: spawn."""
        proc = child(self.stop, body)

        def cleanup():
            """Helper: cleanup."""
            if proc.poll() is None:
                proc.kill()
            proc.communicate()
        self.addCleanup(cleanup)
        return proc

    # These tests check the location rule: STOP_LATCH_FILE > STOP_LATCH_ROOT > <repo>/STOP.
    def _child(self, env_extra, code):
        """Run CODE in a fresh interpreter with exactly the STOP_LATCH_* variables given (Args: env_extra dict; Returns: stdout)."""
        env = {k: v for k, v in os.environ.items() if not k.startswith("STOP_LATCH_")}
        env.update(env_extra)
        env["PYTHONPATH"] = str(HERE)
        result = subprocess.run([sys.executable, "-B", "-c", code], env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def test_default_path_is_repo_root_stop(self):
        """Check that default path is repo root stop."""
        out = self._child({}, "import stop_latch; print(stop_latch.STOP_FILE)")
        self.assertEqual(out, str(HERE.parent / "STOP"))

    def test_root_env_and_file_env_precedence(self):
        """Check that root env and file env precedence."""
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            self.assertEqual(self._child({"STOP_LATCH_ROOT": str(base)}, "import stop_latch; print(stop_latch.STOP_FILE)"),
                             str(base / "STOP"))
            explicit = base / "custom-name"
            both = {"STOP_LATCH_ROOT": str(base / "ignored"), "STOP_LATCH_FILE": str(explicit)}
            self.assertEqual(self._child(both, "import stop_latch; print(stop_latch.STOP_FILE)"), str(explicit))

    def test_empty_env_variables_fall_back_to_the_default(self):
        """Check that empty env variables fall back to the default."""
        out = self._child({"STOP_LATCH_FILE": "", "STOP_LATCH_ROOT": ""}, "import stop_latch; print(stop_latch.STOP_FILE)")
        self.assertEqual(out, str(HERE.parent / "STOP"))

    def test_stop_present_follows_the_configured_file(self):
        """Check that stop present follows the configured file."""
        with tempfile.TemporaryDirectory() as temporary:
            flag = Path(temporary).resolve() / "STOP"
            code = "import stop_latch; print(stop_latch.stop_present())"
            self.assertEqual(self._child({"STOP_LATCH_FILE": str(flag)}, code), "False")   # file absent
            flag.write_text("fixture incident")
            self.assertEqual(self._child({"STOP_LATCH_FILE": str(flag)}, code), "True")    # file present

    def test_refuses_to_start_when_stop_present(self):
        """Check that refuses to start when stop present."""
        self.stop.write_text("incident")
        proc = self.spawn(f"stop_latch.enforce('fixture', path={str(self.stop)!r}); print('WORKED')")
        out, err = proc.communicate(timeout=20)
        self.assertEqual(proc.returncode, 0)
        self.assertNotIn("WORKED", out)
        self.assertIn("not starting", err)

    def test_running_worker_stops_when_stop_appears(self):
        """Check that running worker stops when stop appears."""
        proc = self.spawn(f"stop_latch.enforce('fixture', interval=0.1, path={str(self.stop)!r})\n"
                                "        print('started', flush=True)\n"
                                "        time.sleep(60)")
        self.assertEqual(proc.stdout.readline().strip(), "started")
        started = time.monotonic()
        self.stop.write_text("incident")
        proc.wait(timeout=20)
        self.assertLess(time.monotonic() - started, 15)
        self.assertNotEqual(proc.returncode, None)

    def test_worker_that_ignores_sigterm_is_still_stopped(self):
        """Check that worker that ignores sigterm is still stopped."""
        body = ("import signal\n"
                "        signal.signal(signal.SIGTERM, lambda *a: None)\n"
                "        stop_latch.DEFAULT_GRACE = 0.3\n"
                f"        stop_latch.enforce('fixture', interval=0.1, path={str(self.stop)!r})\n"
                "        print('started', flush=True)\n"
                "        time.sleep(60)")
        proc = self.spawn(body)
        self.assertEqual(proc.stdout.readline().strip(), "started")
        self.stop.write_text("incident")
        proc.wait(timeout=20)
        self.assertEqual(proc.returncode, 0)

    def test_absent_stop_lets_work_run_and_custom_handler_fires(self):
        """Check that absent stop lets work run and custom handler fires."""
        fired = []
        stop_latch.refuse_if_stopped("fixture", self.stop)  # no exit
        stop_latch.watch("fixture-custom", interval=0.05, path=self.stop, on_stop=lambda: fired.append(1))
        time.sleep(0.2)
        self.assertEqual(fired, [])
        self.stop.write_text("incident")
        deadline = time.monotonic() + 5
        while not fired and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertEqual(fired, [1])


class RedTeam5Tests(unittest.TestCase):
    """Seat-5 bypass hunt: each test below failed against the first release."""
    def setUp(self):
        """Create the scratch state this test needs."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name).resolve()

    def test_dangling_symlink_counts_as_stop_present(self):
        """A symlink at the STOP path whose target is missing is still a STOP file (Path.exists() said absent)."""
        os.symlink(self.dir / "nowhere", self.dir / "STOP")
        self.assertTrue(stop_latch.stop_present(self.dir / "STOP"))
        with self.assertRaises(SystemExit):
            stop_latch.refuse_if_stopped("t", self.dir / "STOP")

    def test_unreadable_folder_fails_closed(self):
        """When the STOP path cannot be examined (permission denied) the latch reads as present, never as absent or a crash."""
        sub = self.dir / "locked"; sub.mkdir(); (sub / "STOP").write_text("")
        sub.chmod(0)
        self.addCleanup(sub.chmod, 0o700)
        if os.geteuid() == 0:
            self.skipTest("root ignores directory permissions")
        self.assertTrue(stop_latch.stop_present(sub / "STOP"))

    def test_missing_file_and_missing_folder_are_absent(self):
        """The only 'absent' answers are no such file and no such folder (or a parent that is a plain file)."""
        (self.dir / "plain").write_text("")
        self.assertFalse(stop_latch.stop_present(self.dir / "STOP"))
        self.assertFalse(stop_latch.stop_present(self.dir / "nodir" / "STOP"))
        self.assertFalse(stop_latch.stop_present(self.dir / "plain" / "STOP"))

    def test_relative_stop_file_survives_chdir(self):
        """A relative STOP_LATCH_FILE is fixed to an absolute path at import; os.chdir() later must not move the latch."""
        (self.dir / "STOP2").write_text("")
        code = ("import os, sys; sys.path.insert(0, %r); import stop_latch; os.chdir('/'); print(stop_latch.stop_present())" % str(HERE))
        r = subprocess.run([sys.executable, "-c", code], cwd=self.dir, capture_output=True, text=True,
                           env={**os.environ, "STOP_LATCH_FILE": "STOP2"})
        self.assertEqual(r.stdout.strip(), "True", r.stderr)

    def test_failing_callback_still_stops_the_process(self):
        """If a custom on_stop callback raises, the default shutdown (SIGTERM then hard exit) still runs."""
        calls = []

        def boom():
            """Callback that fails."""
            raise RuntimeError("callback broke")
        orig = stop_latch._default_on_stop
        stop_latch._default_on_stop = lambda name, grace: calls.append(name)
        self.addCleanup(setattr, stop_latch, "_default_on_stop", orig)
        stop = self.dir / "STOP"; stop.write_text("")
        stop_latch.watch("rt5-callback", interval=0.05, path=stop, on_stop=boom)
        deadline = time.monotonic() + 5
        while not calls and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertEqual(calls, ["rt5-callback"])


if __name__ == "__main__":
    unittest.main()
