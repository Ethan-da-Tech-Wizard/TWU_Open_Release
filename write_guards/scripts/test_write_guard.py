"""Tests for write_guard.py: locks, task-root validation, stale-lock reclaim. Races are made deterministic with events
and a hold file (the lock holder waits to be released) instead of sleeping and hoping the other writer arrives in time."""
import json, multiprocessing as mp, os, shutil, subprocess, sys, tempfile, time, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import write_guard as wg

HERE = os.path.dirname(os.path.abspath(__file__))
CLI = os.path.join(HERE, "write_guard.py")


def read_bytes(p):
    """Whole file as bytes, with the file closed."""
    with open(p, "rb") as f:
        return f.read()


def read_text(p):
    """Whole file as text, with the file closed."""
    with open(p) as f:
        return f.read()


def write_text(p, text):
    """Write text to a file, with the file closed."""
    with open(p, "w") as f:
        f.write(text)


def wait_until(cond, timeout=20.0):
    """Poll `cond` until it is true or `timeout` real seconds pass (a wait for an event, not a guess at timing)."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.01)
    return cond()


def _worker(barrier, q, release, path, task_root, agent, content):
    """Process body: write `path`; the winner holds its lock until the parent sets `release`."""
    try:
        barrier.wait(10)
        wg.safe_write(path, content, task_root, agent, "s-" + agent, _hook=lambda: release.wait(20))
        q.put((agent, "OK"))
    except wg.BlockedByLock:
        q.put((agent, "BLOCKED"))
    except Exception as e:
        q.put((agent, "ERR " + repr(e)))


def _app_worker(barrier, q, release, path, task_root, agent):
    """Process body: append to `path`; the winner holds its lock until the parent sets `release`."""
    try:
        barrier.wait(10)
        wg.safe_append(path, "line-from-" + agent, task_root, agent, "s", _hook=lambda: release.wait(20))
        q.put((agent, "OK"))
    except wg.BlockedByLock:
        q.put((agent, "BLOCKED"))
    except Exception as e:
        q.put((agent, "ERR " + repr(e)))


def cli(*args, env=None, inp=b""):
    """Run write_guard.py as a subprocess; returns the CompletedProcess."""
    e = dict(os.environ)
    e.update(env or {})
    return subprocess.run([sys.executable, "-B", CLI] + list(args), input=inp, capture_output=True, env=e)


class Base(unittest.TestCase):
    """Tests for: Base."""
    def setUp(self):
        """Create the scratch state this test needs."""
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="wgtest-"))
        self.root = os.path.join(self.tmp, "root")
        os.makedirs(self.root)
        self.addCleanup(shutil.rmtree, self.tmp, True)


class Race(Base):
    """Tests for: Race."""
    def test_race_in_process_api(self):
        """Check that race in process api."""
        ctx = mp.get_context("fork")
        for i in range(5):
            target = os.path.join(self.root, "f%d.txt" % i)
            b, release, q = ctx.Barrier(2), ctx.Event(), ctx.Queue()
            ps = [ctx.Process(target=_worker, args=(b, q, release, target, self.root, ag, ("content-" + ag).encode()))
                  for ag in ("A", "B")]
            [p.start() for p in ps]
            first = q.get(timeout=20)             # the winner is held inside its lock, so the first answer is the loser's
            self.assertEqual(first[1], "BLOCKED", first)
            release.set()
            second = q.get(timeout=20)
            [p.join() for p in ps]
            res = dict([first, second])
            self.assertEqual(sorted(res.values()), ["BLOCKED", "OK"], res)
            winner = [k for k, v in res.items() if v == "OK"][0]
            self.assertEqual(read_bytes(target), ("content-" + winner).encode())
            self.assertEqual(os.listdir(os.path.join(self.root, "data", "locks")), [])

    def test_race_cli(self):
        """Check that race cli."""
        target = os.path.join(self.root, "c.txt")
        locks = os.path.join(self.root, "data", "locks")
        for i in range(5):
            hold = os.path.join(self.tmp, "hold%d" % i)
            write_text(hold, "")
            a_env = dict(os.environ, WRITE_GUARD_HOLD_FILE=hold)
            a_proc = subprocess.Popen([sys.executable, "-B", CLI, "write", "--path", target, "--task-root", self.root,
                                       "--agent", "A", "--session", "s"], stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=a_env)
            a_proc.stdin.write(("cli-A" + str(i)).encode())
            a_proc.stdin.close()
            # A now holds the lock until the hold file is removed; wait for the lock file, then let B collide with it
            self.assertTrue(wait_until(lambda: os.path.isdir(locks) and any(n.endswith(".lock") for n in os.listdir(locks))))
            r = cli("write", "--path", target, "--task-root", self.root, "--agent", "B", "--session", "s", inp=("cli-B" + str(i)).encode())
            os.unlink(hold)
            a_proc.wait(timeout=20)
            a_err = a_proc.stderr.read().decode()
            a_proc.stderr.close(); a_proc.stdout.close()
            self.assertEqual(a_proc.returncode, 0, a_err)
            self.assertEqual(r.returncode, 75, r.stderr)
            loser_err = r.stderr.decode()
            self.assertTrue(loser_err.startswith("BLOCKED-BY-LOCK path="), loser_err)
            self.assertIn("holder_pid=", loser_err)
            self.assertIn("holder_agent=A", loser_err)
            self.assertEqual(read_bytes(target), ("cli-A" + str(i)).encode())

    def test_locks_folder_is_private(self):
        """Check that locks folder is private."""
        lp = wg.acquire(os.path.join(self.root, "k.txt"), "A", "s", self.root)
        self.assertEqual(oct(os.stat(os.path.dirname(lp)).st_mode & 0o777), "0o700")
        self.assertEqual(oct(os.stat(lp).st_mode & 0o777), "0o600")
        wg.release(os.path.join(self.root, "k.txt"), "A", self.root)

    def test_lock_file_is_never_visible_half_written(self):
        # _create links a finished temp file into place, so the lock either does not exist or has its whole record
        """Check that lock file is never visible half written."""
        p = os.path.join(self.root, "h.txt")
        lp = wg.lock_path_for(p, self.root)
        os.makedirs(os.path.dirname(lp))
        wg._create(lp, {"pid": os.getpid(), "agent_id": "A"})
        self.assertEqual(json.loads(read_text(lp))["agent_id"], "A")
        self.assertEqual(oct(os.stat(lp).st_mode & 0o777), "0o600")
        with self.assertRaises(FileExistsError):
            wg._create(lp, {"pid": 1})
        self.assertEqual([n for n in os.listdir(os.path.dirname(lp)) if n.endswith(".new")], [])


class PathValidation(Base):
    """Tests for: Path Validation."""
    def test_sibling_refused_cli(self):
        """Check that sibling refused cli."""
        sib = os.path.join(self.tmp, "sibling")
        target = os.path.join(sib, "x.txt")
        r = cli("write", "--path", target, "--task-root", self.root, "--agent", "A", inp=b"hi")
        self.assertEqual(r.returncode, 2)
        msg = r.stderr.decode().strip()
        self.assertIn("resolved=" + target, msg)
        self.assertIn("declared_root=" + self.root, msg)
        self.assertTrue(msg.startswith("REFUSED write: resolved="))
        self.assertFalse(os.path.exists(target))
        self.assertFalse(os.path.exists(sib))
        self.assertFalse(os.path.exists(os.path.join(self.root, "data")))

    def test_dotdot(self):
        """Check that dotdot."""
        t = os.path.join(self.root, "..", "esc", "x.txt")
        with self.assertRaises(wg.PathOutsideRoot):
            wg.safe_write(t, b"x", self.root, "A", "s")
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "esc")))

    def test_symlink_out(self):
        """Check that symlink out."""
        out = os.path.join(self.tmp, "outside")
        os.makedirs(out)
        os.symlink(out, os.path.join(self.root, "link"))
        with self.assertRaises(wg.PathOutsideRoot):
            wg.safe_write(os.path.join(self.root, "link", "x.txt"), b"x", self.root, "A", "s")
        self.assertEqual(os.listdir(out), [])
        # symlinked file too
        victim = os.path.join(out, "v.txt")
        write_text(victim, "orig")
        os.symlink(victim, os.path.join(self.root, "fl"))
        with self.assertRaises(wg.PathOutsideRoot):
            wg.safe_write(os.path.join(self.root, "fl"), b"x", self.root, "A", "s")
        self.assertEqual(read_text(victim), "orig")

    def test_append_does_not_follow_a_symlink_swapped_in_after_validation(self):
        # simulate the check-then-use race: validation passes, then the target becomes a symlink before the open
        """Check that append does not follow a symlink swapped in after validation."""
        out = os.path.join(self.tmp, "outside")
        os.makedirs(out)
        victim = os.path.join(out, "v.txt")
        write_text(victim, "orig\n")
        target = os.path.join(self.root, "log.txt")

        def swap():
            """Helper: swap."""
            os.symlink(victim, target)
        with self.assertRaises(OSError):
            wg.safe_append(target, "pwned", self.root, "A", "s", _hook=swap)
        self.assertEqual(read_text(victim), "orig\n")
        self.assertEqual(os.listdir(os.path.join(self.root, "data", "locks")), [])

    def test_write_into_a_directory_swapped_for_an_outside_symlink_is_refused(self):
        """Check that write into a directory swapped for an outside symlink is refused."""
        out = os.path.join(self.tmp, "outside2")
        os.makedirs(out)
        sub = os.path.join(self.root, "sub")
        os.makedirs(sub)

        def swap():
            """Helper: swap."""
            shutil.rmtree(sub)
            os.symlink(out, sub)
        with self.assertRaises((wg.PathOutsideRoot, OSError)):
            wg.safe_write(os.path.join(sub, "x.txt"), b"x", self.root, "A", "s", _hook=swap)
        self.assertEqual(os.listdir(out), [])

    def test_cli_reports_unsafe_target_without_traceback(self):
        """Check that cli reports unsafe target without traceback."""
        out = os.path.join(self.tmp, "outside3")
        os.makedirs(out)
        victim = os.path.join(out, "v.txt")
        write_text(victim, "orig\n")
        os.symlink(victim, os.path.join(self.root, "l.txt"))
        r = cli("append", "--path", os.path.join(self.root, "l.txt"), "--task-root", self.root, "--agent", "A", inp=b"x")
        self.assertEqual(r.returncode, 2)
        self.assertNotIn(b"Traceback", r.stderr)

    def test_prefix_trap(self):
        """Check that prefix trap."""
        evil = self.root + "-evil"
        with self.assertRaises(wg.PathOutsideRoot):
            wg.safe_write(os.path.join(evil, "x.txt"), b"x", self.root, "A", "s")
        self.assertFalse(os.path.exists(evil))

    def test_normal_and_nested(self):
        """Check that normal and nested."""
        p = os.path.join(self.root, "a", "b", "c.txt")
        wg.safe_write(p, b"data", self.root, "A", "s")
        self.assertEqual(read_bytes(p), b"data")
        wg.safe_write(p, b"data2", self.root, "A", "s")
        self.assertEqual(read_bytes(p), b"data2")


def dead_pid():
    """Helper: dead pid."""
    p = subprocess.Popen([sys.executable, "-c", "pass"])
    p.wait()
    return p.pid


class Stale(Base):
    """Tests for: Stale."""
    def _plant(self, path, pid, ttl=300, age=0):
        """Helper: plant."""
        lp = wg.lock_path_for(path, self.root)
        os.makedirs(os.path.dirname(lp), exist_ok=True)
        rec = {"pid": pid, "session": "old", "agent_id": "OLD", "path": path,
               "acquired_at": "2020-01-01T00:00:00.000000Z", "ttl_s": ttl, "host": "h"}
        write_text(lp, json.dumps(rec))
        if age:
            t = time.time() - age
            os.utime(lp, (t, t))
        return lp, rec

    def _log(self):
        """Helper: log."""
        with open(os.path.join(self.root, "data", "locks", "reclaim.log.jsonl")) as f:
            return [json.loads(l) for l in f]

    def test_dead_pid(self):
        """Check that dead pid."""
        p = os.path.join(self.root, "d.txt")
        dp = dead_pid()
        lp, rec = self._plant(p, dp, age=5)
        wg.safe_write(p, b"new", self.root, "NEW", "s")
        self.assertEqual(read_bytes(p), b"new")
        lines = self._log()
        self.assertEqual(len(lines), 1)
        L = lines[0]
        self.assertEqual(L["reason"], "pid-dead")
        self.assertEqual(L["holder"], rec)
        self.assertEqual(L["reclaimer"]["agent_id"], "NEW")
        self.assertIsNotNone(L["holder_last_heartbeat"])

    def test_ttl_live_pid(self):
        """Check that ttl live pid."""
        p = os.path.join(self.root, "t.txt")
        self._plant(p, os.getpid(), ttl=10, age=100)
        wg.safe_write(p, b"new", self.root, "NEW", "s")
        L = self._log()[0]
        self.assertEqual(L["reason"], "ttl")
        self.assertEqual(L["holder"]["pid"], os.getpid())

    def test_ttl_uses_the_injected_clock_not_real_time(self):
        """Check that ttl uses the injected clock not real time."""
        p = os.path.join(self.root, "c.txt")
        lp, _ = self._plant(p, os.getpid(), ttl=10)      # a fresh lock held by a live pid
        with self.assertRaises(wg.BlockedByLock):
            wg.acquire(p, "NEW", "s", self.root)
        real = wg._clock
        wg._clock = lambda: real() + 1000                # 1000 "seconds" later, without sleeping
        self.addCleanup(setattr, wg, "_clock", real)
        wg.safe_write(p, b"new", self.root, "NEW", "s")
        self.assertEqual(self._log()[0]["reason"], "ttl")

    def test_live_blocks_and_touch_heartbeat(self):
        """Check that live blocks and touch heartbeat."""
        p = os.path.join(self.root, "l.txt")
        lp, _ = self._plant(p, os.getpid(), ttl=10, age=100)
        self.assertTrue(wg.touch(p, self.root))  # heartbeat revives it
        with self.assertRaises(wg.BlockedByLock) as cm:
            wg.acquire(p, "NEW", "s", self.root)
        self.assertEqual(cm.exception.holder["agent_id"], "OLD")
        self.assertFalse(os.path.exists(os.path.join(self.root, "data", "locks", "reclaim.log.jsonl")))
        r = cli("write", "--path", p, "--task-root", self.root, "--agent", "N", inp=b"x")
        self.assertEqual(r.returncode, 75)
        self.assertIn("BLOCKED-BY-LOCK path=", r.stderr.decode())

    def test_release_only_own_and_cli_reclaim(self):
        """Check that release only own and cli reclaim."""
        p = os.path.join(self.root, "o.txt")
        lp, _ = self._plant(p, os.getpid())
        self.assertFalse(wg.release(p, "OTHER", self.root))
        self.assertTrue(os.path.exists(lp))
        lp2, _ = self._plant(os.path.join(self.root, "z.txt"), dead_pid())
        r = cli("reclaim-stale", "--root", self.root)
        self.assertEqual(r.returncode, 0)
        self.assertFalse(os.path.exists(lp2))
        self.assertTrue(os.path.exists(lp))
        r = cli("lock-status", "--root", self.root)
        self.assertEqual(len(json.loads(r.stdout)), 1)


class Release(Base):
    """Tests for: Release."""
    def test_released_after_exception(self):
        """Check that released after exception."""
        p = os.path.join(self.root, "e.txt")
        def boom():
            """Helper: boom."""
            raise RuntimeError("x")
        with self.assertRaises(RuntimeError):
            wg.safe_write(p, b"x", self.root, "A", "s", _hook=boom)
        self.assertEqual(os.listdir(os.path.join(self.root, "data", "locks")), [])
        self.assertFalse(os.path.exists(p))
        wg.safe_write(p, b"ok", self.root, "A", "s")


class Append(Base):
    """Tests for: Append."""
    def test_concurrent_appenders(self):
        """Check that concurrent appenders."""
        ctx = mp.get_context("fork")
        p = os.path.join(self.root, "log.txt")
        b, release, q = ctx.Barrier(8), ctx.Event(), ctx.Queue()
        ps = [ctx.Process(target=_app_worker, args=(b, q, release, p, self.root, "w%d" % i)) for i in range(8)]
        [x.start() for x in ps]
        got = [q.get(timeout=20) for _ in range(7)]    # one writer holds the lock until released, so seven are blocked
        self.assertEqual({v for _, v in got}, {"BLOCKED"}, got)
        release.set()
        got.append(q.get(timeout=20))
        [x.join() for x in ps]
        res = dict(got)
        ok = sorted(k for k, v in res.items() if v == "OK")
        self.assertEqual(len(ok), 1, res)
        self.assertEqual(read_text(p).splitlines(), ["line-from-" + ok[0]])


class Env(Base):
    """Tests for: Env."""
    def test_hold_hook_ignores_empty_and_invalid_values(self):
        """Check that hold hook ignores empty and invalid values."""
        for k in ("WRITE_GUARD_HOLD_S", "WRITE_GUARD_HOLD_FILE"):
            self.addCleanup(os.environ.pop, k, None)
        os.environ["WRITE_GUARD_HOLD_S"] = ""
        os.environ["WRITE_GUARD_HOLD_FILE"] = ""
        self.assertIsNone(wg._hold_hook())
        os.environ["WRITE_GUARD_HOLD_S"] = "not-a-number"
        self.assertIsNone(wg._hold_hook())
        os.environ["WRITE_GUARD_HOLD_S"] = "0.5"
        self.assertIsNotNone(wg._hold_hook())

    def test_hold_hook_waits_with_injected_sleep(self):
        """Check that hold hook waits with injected sleep."""
        slept = []
        self.addCleanup(setattr, wg, "_sleep", wg._sleep)
        wg._sleep = slept.append
        os.environ["WRITE_GUARD_HOLD_S"] = "7"
        self.addCleanup(os.environ.pop, "WRITE_GUARD_HOLD_S", None)
        wg._hold_hook()()
        self.assertEqual(slept, [7.0])


class RedTeam5(unittest.TestCase):
    """Seat-5 bypass hunt: each test failed against the first release."""
    def setUp(self):
        """Create the scratch state this test needs."""
        self.td = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, self.td, True)
        self.td = os.path.realpath(self.td)
        self.root = os.path.join(self.td, "root"); os.mkdir(self.root)
        self.out = os.path.join(self.td, "outside"); os.mkdir(self.out)

    def test_append_through_a_hard_link_to_a_file_outside_is_refused(self):
        """A hard link inside the root to an outside file passes the path checks; the append must not write through it."""
        victim = os.path.join(self.out, "victim.txt"); write_text(victim, "keep\n")
        os.link(victim, os.path.join(self.root, "alias.txt"))
        with self.assertRaises(OSError):
            wg.safe_append(os.path.join(self.root, "alias.txt"), "evil", self.root, "a", None)
        self.assertEqual(read_text(victim), "keep\n")

    def test_lock_record_that_is_not_an_object_is_corrupt_not_a_crash(self):
        """A lock file holding valid JSON that is not an object ([] or "x") is a corrupt lock (reclaimable), not an AttributeError."""
        target = os.path.join(self.root, "f.txt")
        lp = wg.lock_path_for(target, self.root); os.makedirs(os.path.dirname(lp), exist_ok=True)
        for junk in ("[]", '"x"', "3", "null"):
            write_text(lp, junk)
            wg.safe_write(target, "ok", self.root, "a", None)
            self.assertEqual(read_text(target), "ok")
            if os.path.exists(lp):
                os.unlink(lp)

    def test_non_numeric_ttl_in_a_lock_does_not_crash(self):
        """A live holder whose record has ttl_s 'abc' or NaN still blocks (default TTL), and acquire raises BlockedByLock only."""
        target = os.path.join(self.root, "f.txt")
        lp = wg.lock_path_for(target, self.root); os.makedirs(os.path.dirname(lp), exist_ok=True)
        for ttl in ("abc", None, float("nan")):
            write_text(lp, json.dumps({"pid": os.getpid(), "agent_id": "other", "ttl_s": ttl}).replace("NaN", "\"nan\""))
            with self.assertRaises(wg.BlockedByLock):
                wg.acquire(target, "me", None, self.root)
            os.unlink(lp)


if __name__ == "__main__":
    unittest.main()
