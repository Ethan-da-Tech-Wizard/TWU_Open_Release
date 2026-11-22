"""guarded_write: two real writers race on one file; exactly one wins, the other gets ConcurrentModification and writes nothing."""
import os, stat, subprocess, sys, tempfile, threading, unittest
from pathlib import Path
from unittest import mock
sys.path.insert(0, str(Path(__file__).resolve().parent))
import guarded_write as gw

SCRIPT = str(Path(__file__).resolve().parent / "guarded_write.py")


class T(unittest.TestCase):
    """Tests for: T."""
    def setUp(self):
        """Create the scratch state this test needs."""
        self.td = tempfile.TemporaryDirectory(); self.addCleanup(self.td.cleanup)
        self.f = Path(self.td.name) / "shared.py"
        self.f.write_text("base\n")
        # keep lock files inside this test's own folder so nothing is left in the real state directory
        self.locks = Path(self.td.name + "-locks")
        patcher = mock.patch.dict(os.environ, {"TWU_WRITE_LOCK_DIR": str(self.locks)})
        patcher.start(); self.addCleanup(patcher.stop)
        self.addCleanup(self._remove_locks)

    def _remove_locks(self):
        """Delete this test's lock folder (or the symlink standing in for it)."""
        if self.locks.is_symlink():
            self.locks.unlink()
        else:
            __import__("shutil").rmtree(self.locks, ignore_errors=True)

    def test_write_succeeds_when_unchanged_and_returns_new_hash(self):
        """Check that write succeeds when unchanged and returns new hash."""
        h = gw.sha256_of(self.f)
        new = gw.write_if_unchanged(self.f, b"mine\n", h)
        self.assertEqual(self.f.read_text(), "mine\n")
        self.assertEqual(new, gw.sha256_of(self.f))
        self.assertEqual([p.name for p in Path(self.td.name).iterdir()], ["shared.py"])   # no temp litter

    def test_stale_hash_is_refused_and_nothing_is_written(self):
        """Check that stale hash is refused and nothing is written."""
        h = gw.sha256_of(self.f)
        self.f.write_text("someone else\n")
        with self.assertRaises(gw.ConcurrentModification):
            gw.write_if_unchanged(self.f, b"mine\n", h)
        self.assertEqual(self.f.read_text(), "someone else\n")

    def test_two_threads_same_expected_hash_exactly_one_wins(self):
        """Check that two threads same expected hash exactly one wins."""
        h = gw.sha256_of(self.f)
        results, barrier = [], threading.Barrier(2)

        def writer(tag):
            """Helper: writer."""
            barrier.wait()
            try:
                gw.write_if_unchanged(self.f, ("from %s\n" % tag).encode(), h); results.append((tag, "ok"))
            except gw.ConcurrentModification:
                results.append((tag, "conflict"))
        ts = [threading.Thread(target=writer, args=(t,)) for t in "AB"]
        [t.start() for t in ts]; [t.join() for t in ts]
        self.assertEqual(sorted(r[1] for r in results), ["conflict", "ok"])
        winner = next(t for t, r in results if r == "ok")
        self.assertEqual(self.f.read_text(), "from %s\n" % winner)

    def test_two_real_processes_race_through_the_cli(self):
        """Check that two real processes race through the cli."""
        h = subprocess.run([sys.executable, SCRIPT, "hash", str(self.f)], capture_output=True, text=True).stdout.strip()   # env (lock dir) is inherited
        procs = [subprocess.Popen([sys.executable, SCRIPT, "write", str(self.f), "--expect", h], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(2)]
        for i, p in enumerate(procs):
            p.stdin.write(("writer %d\n" % i).encode()); p.stdin.close()
        codes = sorted(p.wait() for p in procs)
        for p in procs:
            p.stdout.close(); p.stderr.close()
        self.assertEqual(codes, [0, 3])                    # one wrote, one got CONCURRENT MODIFICATION
        self.assertIn(self.f.read_text(), ("writer 0\n", "writer 1\n"))

    def test_expect_missing_creates_once_and_refuses_an_existing_file(self):
        """Check that expect missing creates once and refuses an existing file."""
        new = Path(self.td.name) / "new.txt"
        gw.write_if_unchanged(new, b"x", None)
        with self.assertRaises(gw.ConcurrentModification):
            gw.write_if_unchanged(new, b"y", None)
        self.assertEqual(new.read_text(), "x")

    def test_symlink_target_is_refused(self):
        """Check that symlink target is refused."""
        link = Path(self.td.name) / "link.py"; link.symlink_to(self.f)
        with self.assertRaises(ValueError):
            gw.write_if_unchanged(link, b"z", gw.sha256_of(self.f))

    def test_file_mode_is_preserved(self):
        """Check that file mode is preserved."""
        self.f.chmod(0o750)
        gw.write_if_unchanged(self.f, b"m", gw.sha256_of(self.f))
        self.assertEqual(self.f.stat().st_mode & 0o777, 0o750)


class LockDirectory(T):
    """The lock folder is per user, private, and refused if it is a symlink or owned by someone else."""

    def write(self):
        """Helper: write."""
        return gw.write_if_unchanged(self.f, b"x\n", gw.sha256_of(self.f))

    def test_lock_dir_is_created_0700_and_lock_file_0600(self):
        """Check that lock dir is created 0700 and lock file 0600."""
        self.write()
        self.assertEqual(stat.S_IMODE(self.locks.stat().st_mode), 0o700)
        names = [p for p in self.locks.iterdir()]
        self.assertEqual(len(names), 1)
        self.assertEqual(stat.S_IMODE(names[0].stat().st_mode), 0o600)

    def test_loose_lock_dir_that_we_own_is_tightened(self):
        """Check that loose lock dir that we own is tightened."""
        self.locks.mkdir(mode=0o755)
        self.locks.chmod(0o755)
        self.write()
        self.assertEqual(stat.S_IMODE(self.locks.stat().st_mode), 0o700)

    def test_symlinked_lock_dir_is_refused(self):
        """Check that symlinked lock dir is refused."""
        elsewhere = Path(self.td.name) / "elsewhere"; elsewhere.mkdir()
        self.locks.symlink_to(elsewhere)
        with self.assertRaises(ValueError):
            self.write()
        self.assertEqual(list(elsewhere.iterdir()), [])
        self.assertEqual(self.f.read_text(), "base\n")

    def test_lock_dir_owned_by_someone_else_is_refused(self):
        """Check that lock dir owned by someone else is refused."""
        self.locks.mkdir(mode=0o700)
        with mock.patch.object(gw.os, "geteuid", return_value=os.geteuid() + 1):
            with self.assertRaises(ValueError):
                self.write()
        self.assertEqual(self.f.read_text(), "base\n")

    def test_symlinked_lock_file_is_refused(self):
        """Check that symlinked lock file is refused."""
        self.write()
        lock = next(self.locks.iterdir())
        victim = Path(self.td.name) / "victim.txt"; victim.write_text("keep\n")
        lock.unlink(); lock.symlink_to(victim)
        with self.assertRaises(ValueError):
            gw.write_if_unchanged(self.f, b"y\n", gw.sha256_of(self.f))
        self.assertEqual(victim.read_text(), "keep\n")

    def test_symlink_swapped_in_after_the_hash_check_is_not_followed(self):
        # the target becomes a symlink while we hold the lock: the O_NOFOLLOW open must refuse, not write through
        """Check that symlink swapped in after the hash check is not followed."""
        victim = Path(self.td.name) / "victim.txt"; victim.write_text("keep\n")
        h = gw.sha256_of(self.f)
        real = gw._hash_at
        def swap(dfd, name):
            """Helper: swap."""
            self.f.unlink(); self.f.symlink_to(victim)
            return real(dfd, name)
        with mock.patch.object(gw, "_hash_at", side_effect=swap):
            with self.assertRaises(ValueError):
                gw.write_if_unchanged(self.f, b"y\n", h)
        self.assertEqual(victim.read_text(), "keep\n")


class LockDirectoryEnv(unittest.TestCase):
    """Empty environment values count as unset (the example env file exports empty strings)."""

    def test_empty_values_fall_back_to_the_default(self):
        """Check that empty values fall back to the default."""
        with tempfile.TemporaryDirectory() as home:
            env = {"TWU_WRITE_LOCK_DIR": "", "XDG_STATE_HOME": "", "HOME": home}
            with mock.patch.dict(os.environ, env):
                self.assertEqual(gw.lock_dir_path(), os.path.join(home, ".local", "state", "twu-write-locks"))

    def test_relative_xdg_is_ignored_and_absolute_xdg_is_used(self):
        """Check that relative xdg is ignored and absolute xdg is used."""
        with tempfile.TemporaryDirectory() as home:
            with mock.patch.dict(os.environ, {"TWU_WRITE_LOCK_DIR": "", "XDG_STATE_HOME": "rel/state", "HOME": home}):
                self.assertTrue(gw.lock_dir_path().startswith(home))
            with mock.patch.dict(os.environ, {"TWU_WRITE_LOCK_DIR": "", "XDG_STATE_HOME": home + "/xdg", "HOME": home}):
                self.assertEqual(gw.lock_dir_path(), home + "/xdg/twu-write-locks")

    def test_explicit_lock_dir_wins(self):
        """Check that explicit lock dir wins."""
        with mock.patch.dict(os.environ, {"TWU_WRITE_LOCK_DIR": "/some/where", "XDG_STATE_HOME": "/other"}):
            self.assertEqual(gw.lock_dir_path(), "/some/where")


class RedTeam5(T):
    """Seat-5 bypass hunt: failed against the first release."""
    def test_relative_lock_dir_is_refused(self):
        """A relative TWU_WRITE_LOCK_DIR would give writers in different folders different locks."""
        with mock.patch.dict(os.environ, {"TWU_WRITE_LOCK_DIR": "locks-rel"}):
            with self.assertRaises(ValueError):
                gw.write_if_unchanged(self.f, b"x\n", gw.sha256_of(self.f))
        self.assertEqual(self.f.read_text(), "base\n")

    def test_fifo_at_the_target_does_not_hang_the_writer(self):
        """A FIFO planted at the target name must be refused at once (opening it for reading used to block under the lock)."""
        fifo = Path(self.td.name) / "pipe"; os.mkfifo(fifo)
        code = ("import sys; sys.path.insert(0, %r); import guarded_write as g; "
                "g.write_if_unchanged(%r, b'x', None)" % (str(Path(__file__).resolve().parent), str(fifo)))
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=20,
                           env={**os.environ, "TWU_WRITE_LOCK_DIR": str(self.locks)})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not a regular file", r.stderr)


if __name__ == "__main__":
    unittest.main()
