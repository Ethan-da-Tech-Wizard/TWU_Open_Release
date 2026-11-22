#!/usr/bin/env python3
"""Tests for scripts/secret_scan.py. Fake credentials are assembled at runtime so this file holds no scannable secret."""
import atexit, json, os, shutil, stat, sys, tempfile, unittest
from pathlib import Path
from unittest import mock
sys.path.insert(0, str(Path(__file__).resolve().parent))
import secret_scan as ss

# The fingerprint salt lives in a throwaway folder for the whole test run, never in the real state directory.
_SALT_DIR = tempfile.mkdtemp(prefix="fpsalt-")
atexit.register(shutil.rmtree, _SALT_DIR, True)
os.environ["TWU_FP_SALT_FILE"] = os.path.join(_SALT_DIR, "salt")

AWS = "AKIA" + "ABCDEFGHIJKLMNOP"
AWS_DOC = "AKIA" + "EXAMPLEEXAMPLE12"          # placeholder-looking key, also built at runtime
GH = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
ANT = "sk-ant-" + "api03-" + "Zx9Qw8Er7Ty6Ui5Op4As3Df2Gh1Jk0Lm"


class T(unittest.TestCase):
    """Tests for: T."""
    def setUp(self):
        """Create the scratch state this test needs."""
        self.t = tempfile.TemporaryDirectory(); self.r = Path(self.t.name).resolve(); self.d = self.r / "state"

    def tearDown(self):
        """Remove the scratch state this test created."""
        self.t.cleanup()

    def w(self, name, txt):
        """Helper: w."""
        p = self.r / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(txt); return p

    def test_detects_and_never_prints_secret(self):
        """Check that detects and never prints secret."""
        f = self.w("a.env", f"x=1\nTOKEN={GH}\nK={AWS}\n{ANT}\n")
        r, new = ss.check(self.r, self.d, [f])
        self.assertEqual({x["type"] for x in new}, {"github-token", "aws-access-key", "anthropic-key"})
        blob = json.dumps(r) + (self.d / f"SECRETS.{ss.HOST}.json").read_text()
        for secret in (AWS, GH, ANT):
            self.assertNotIn(secret, blob)

    def test_placeholders_and_clean_ignored(self):
        """Check that placeholders and clean ignored."""
        f = self.w("b.md", "key = " + AWS_DOC + "\nuse sk-ant-<your key here> and ghp_xxxx\n")
        self.assertEqual(ss.scan(self.r, [f]), [])

    def test_private_key_block_and_wg_key(self):
        """Check that private key block and wg key."""
        f = self.w("c.txt", "-----BEGIN OPENSSH " + "PRIVATE KEY-----\nPrivateKey = @PRIVATE_KEY@\n" + "PrivateKey = " + "A" * 43 + "=\n")
        self.assertEqual({x["type"] for x in ss.scan(self.r, [f])}, {"private-key-block", "wireguard-private-key"})

    def test_accept_then_quiet_and_new_one_alarms(self):
        """Check that accept then quiet and new one alarms."""
        f = self.w("d.env", f"{GH}\n")
        ss.accept(self.r, self.d, [f]); self.assertEqual(ss.check(self.r, self.d, [f])[1], [])
        g = self.w("e.env", f"{AWS}\n"); self.assertEqual(len(ss.check(self.r, self.d, [f, g])[1]), 1)
        self.assertTrue(any(k.startswith("secret:") for k in ss.alarm_problems(d=self.d)))

    def test_configured_skip_prefix_skipped_but_nul_files_are_not(self):
        """The configured skip prefix skips; a NUL byte no longer exempts a file (red-team 5: a NUL at the top hid everything)."""
        b = self.r / "x.bin"; b.write_bytes(b"\0\0" + GH.encode())
        s = self.w("saved_pages/z.txt", GH)
        self.assertEqual(len(ss.scan(self.r, [b])), 1)
        with mock.patch.dict(os.environ, {"TWU_SECRET_SCAN_SKIP_PREFIXES": "saved_pages/"}):
            self.assertEqual(ss.scan(self.r, [s]), [])
        with mock.patch.dict(os.environ, {"TWU_SECRET_SCAN_SKIP_PREFIXES": ""}):      # empty value = skip nothing
            self.assertEqual(len(ss.scan(self.r, [s])), 1)
        self.assertEqual(len(ss.scan(self.r, [s])), 1)                                # nothing is skipped by default

    def test_big_file_is_skipped_as_documented_but_long_line_is_not(self):
        """A file over 1 MB is skipped (documented limit); a line over 4000 characters is scanned in pieces (red-team 5)."""
        big = self.w("big.txt", GH + "\n" + "a" * 1_000_001)
        longline = self.w("long.txt", "a" * 4001 + " " + GH + "\n")
        self.assertEqual(ss.scan(self.r, [big]), [])
        self.assertEqual([x["type"] for x in ss.scan(self.r, [longline])], ["github-token"])

    def test_receipt_cache_and_baseline_are_not_written_through_a_symlink(self):
        """A symlink planted at a .tmp name or at the baseline name must not redirect the write onto another file."""
        victim = self.r / "victim.txt"; victim.write_text("keep")
        d = self.r / "state"; d.mkdir()
        for name in (f"SECRETS.{ss.HOST}.json.tmp", "secrets_known.json.tmp"):
            os.symlink(victim, d / name)
        ss.check(self.r, d, [self.w("a.txt", "x\n")]); ss.accept(self.r, d, [self.w("a.txt", "x\n")])
        self.assertEqual(victim.read_text(), "keep")

    def test_a_file_named_like_the_scanner_is_still_scanned(self):
        # earlier versions skipped any file called secret_scan.py: a secret there was invisible
        """Check that a file named like the scanner is still scanned."""
        f = self.w("vendor/secret_scan.py", "TOKEN = '" + GH + "'\n")
        self.assertEqual([x["type"] for x in ss.scan(self.r, [f])], ["github-token"])

    def test_this_components_own_files_hold_no_scannable_secret(self):
        """Check that this components own files hold no scannable secret."""
        here = Path(__file__).resolve().parent
        found = ss.scan(here.parent, sorted(here.glob("*.py")) + sorted(here.parent.glob("*.md")))
        self.assertEqual(found, [], "a source file contains a credential-shaped literal: build it at runtime")

    def test_alarm_quiet(self):
        """Check that alarm quiet."""
        self.assertIn("secret:quiet", ss.alarm_problems(d=self.d))

    def test_incomplete_scan_is_persisted_as_alarm(self):
        """Check that incomplete scan is persisted as alarm."""
        with mock.patch.object(ss, "scan", side_effect=ss.ScanUnavailable("permission denied")):
            r, new = ss.check(self.r, self.d, [])
        self.assertFalse(r["complete"])
        self.assertIsNone(r["findings"])
        self.assertEqual(new, [])
        self.assertIn("secret:scan-unavailable", r["problems"])
        self.assertIn("secret:scan-unavailable", ss.alarm_problems(d=self.d))

    def test_git_inventory_failure_is_not_empty_success(self):
        """Check that git inventory failure is not empty success."""
        failed = mock.Mock(returncode=128, stdout=b"", stderr=b"repository unavailable")
        with mock.patch.object(ss.subprocess, "run", return_value=failed):
            with self.assertRaises(ss.ScanUnavailable):
                ss.files(self.r)

    def test_unreadable_scan_input_is_not_skipped_as_nonfile(self):
        """Check that unreadable scan input is not skipped as nonfile."""
        p = self.w("restricted.txt", "ordinary text\n")
        original = Path.stat
        def denied(path, *args, **kwargs):
            """Helper: denied."""
            if path == p:
                raise PermissionError("denied")
            return original(path, *args, **kwargs)
        with mock.patch.object(Path, "stat", new=denied):
            with self.assertRaises(ss.ScanUnavailable):
                ss.scan(self.r, [p])

    def test_file_deleted_between_listing_and_read_is_skipped_but_permission_errors_still_fail(self):
        """Check that file deleted between listing and read is skipped but permission errors still fail."""
        gone = self.r / "sync-conflict-copy.html"  # listed, then a sync tool removed it before the read
        self.assertEqual(ss.scan(self.r, [gone]), [])
        p = self.w("kept.txt", "ordinary text\n")
        original = Path.read_bytes
        def denied(path, *a, **k):
            """Helper: denied."""
            if path == p:
                raise PermissionError("denied")
            return original(path, *a, **k)
        with mock.patch.object(Path, "read_bytes", new=denied):
            with self.assertRaises(ss.ScanUnavailable):
                ss.scan(self.r, [p])

    def test_dangling_symlink_is_skipped_not_scan_failure(self):
        """Check that dangling symlink is skipped not scan failure."""
        link = self.r / "dangling.md"
        link.symlink_to(self.r / "missing target.md")
        good = self.w("leak.txt", "key " + AWS + "\n")
        found = ss.scan(self.r, [link, good])
        self.assertEqual([f["file"] for f in found], ["leak.txt"])

    def test_corrupt_baseline_and_malformed_receipt_are_alarms(self):
        """Check that corrupt baseline and malformed receipt are alarms."""
        self.d.mkdir(parents=True, exist_ok=True)
        (self.d / "secrets_known.json").write_text("not json")
        with mock.patch.object(ss, "scan", return_value=[]):
            r, _ = ss.check(self.r, self.d, [])
        self.assertFalse(r["complete"])
        self.assertIn("secret:scan-unavailable", r["problems"])
        latest = self.d / f"SECRETS.{ss.HOST}.json"
        latest.write_text("not json")
        self.assertIn("secret:receipt-unavailable", ss.alarm_problems(d=self.d))

    def test_legacy_or_wrong_host_receipt_is_not_clean(self):
        """Check that legacy or wrong host receipt is not clean."""
        self.d.mkdir(parents=True, exist_ok=True)
        latest = self.d / f"SECRETS.{ss.HOST}.json"
        latest.write_text('{"checked": 1, "host": "' + ss.HOST + '", "problems": {}}')
        self.assertIn("secret:scan-unavailable", ss.alarm_problems(d=self.d))
        latest.write_text('{"checked": 1, "host": "other-host", "complete": true, "problems": {}}')
        self.assertIn("secret:receipt-unavailable", ss.alarm_problems(d=self.d))


class Salt(unittest.TestCase):
    """Fingerprints are salted per install; the salt file is private; empty environment values mean "unset"."""

    def setUp(self):
        """Create the scratch state this test needs."""
        self.t = tempfile.TemporaryDirectory(); self.addCleanup(self.t.cleanup)
        self.base = Path(self.t.name).resolve()
        self.salt = self.base / "state" / "salt"
        p = mock.patch.dict(os.environ, {"TWU_FP_SALT_FILE": str(self.salt)})
        p.start(); self.addCleanup(p.stop)
        self.addCleanup(ss._SALTS.pop, str(self.salt), None)

    def test_salt_file_is_created_private_and_reused(self):
        """Check that salt file is created private and reused."""
        a = ss.fingerprint("value")
        self.assertEqual(stat.S_IMODE(self.salt.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.salt.parent.stat().st_mode), 0o700)
        ss._SALTS.clear()
        self.assertEqual(ss.fingerprint("value"), a)           # read back from the file, same salt

    def test_fingerprint_is_not_a_plain_hash_and_changes_with_the_salt(self):
        """Check that fingerprint is not a plain hash and changes with the salt."""
        import hashlib
        a = ss.fingerprint("value")
        self.assertNotEqual(a, hashlib.sha256(b"value").hexdigest()[:10])
        self.salt.write_text("f" * 64 + "\n"); ss._SALTS.clear()
        self.assertNotEqual(ss.fingerprint("value"), a)
        self.assertEqual(len(a), 10)

    def test_loose_salt_permissions_are_tightened(self):
        """Check that loose salt permissions are tightened."""
        ss.fingerprint("x")
        self.salt.chmod(0o644); ss._SALTS.clear()
        ss.fingerprint("x")
        self.assertEqual(stat.S_IMODE(self.salt.stat().st_mode), 0o600)

    def test_symlinked_salt_file_is_not_followed_and_scan_fails_closed(self):
        """Check that symlinked salt file is not followed and scan fails closed."""
        victim = self.base / "victim"; victim.write_text("keep")
        self.salt.parent.mkdir(parents=True); self.salt.symlink_to(victim)
        err = __import__("io").StringIO()
        with mock.patch.object(sys, "stderr", err):
            self.assertTrue(ss.salt_is_ephemeral())
        self.assertIn("WARNING", err.getvalue())
        self.assertEqual(victim.read_text(), "keep")
        with self.assertRaises(ss.ScanUnavailable):
            ss.scan(self.base, [])
        r, new = ss.check(self.base, self.base / "d", [])
        self.assertFalse(r["complete"])

    def test_salt_owned_by_someone_else_is_refused(self):
        """Check that salt owned by someone else is refused."""
        ss.fingerprint("x"); ss._SALTS.clear()
        with mock.patch.object(ss.os, "geteuid", return_value=os.geteuid() + 1):
            with mock.patch.object(sys, "stderr", __import__("io").StringIO()):
                self.assertTrue(ss.salt_is_ephemeral())

    def test_default_location_follows_xdg_state_home_and_ignores_empty(self):
        """Check that default location follows xdg state home and ignores empty."""
        with mock.patch.dict(os.environ, {"TWU_FP_SALT_FILE": "", "XDG_STATE_HOME": "", "HOME": str(self.base)}):
            self.assertEqual(ss.salt_file(), self.base / ".local" / "state" / "twu-leakguard" / "fingerprint_salt")
        with mock.patch.dict(os.environ, {"TWU_FP_SALT_FILE": "", "XDG_STATE_HOME": str(self.base / "xdg")}):
            self.assertEqual(ss.salt_file(), self.base / "xdg" / "twu-leakguard" / "fingerprint_salt")
        with mock.patch.dict(os.environ, {"TWU_FP_SALT_FILE": "", "XDG_STATE_HOME": "relative", "HOME": str(self.base)}):
            self.assertEqual(ss.salt_file().parts[-3:], ("state", "twu-leakguard", "fingerprint_salt"))


class EmptyEnvironment(unittest.TestCase):
    """The example env file exports empty strings; an empty value must behave exactly like an unset one."""

    def test_empty_cache_and_git_values_use_defaults(self):
        """Check that empty cache and git values use defaults."""
        with mock.patch.dict(os.environ, {"TWU_SECRET_SCAN_CACHE": "", "TWU_GIT": "", "TWU_SECRET_SCAN_SKIP_PREFIXES": ""}):
            self.assertEqual(ss._cache_file(), Path.home() / ".cache" / "twu" / "secret_scan_cache.json")
            self.assertTrue(os.path.isabs(ss.git_executable() or "/"))
            self.assertEqual(ss.skip_prefixes(), ())

    def test_git_path_must_be_absolute_and_missing_git_fails_closed(self):
        """Check that git path must be absolute and missing git fails closed."""
        with mock.patch.dict(os.environ, {"TWU_GIT": "git"}):
            self.assertIsNone(ss.git_executable())
            with self.assertRaises(ss.ScanUnavailable):
                ss.files(Path("."))
        with mock.patch.dict(os.environ, {"TWU_GIT": "/nonexistent/git"}):
            with self.assertRaises(ss.ScanUnavailable):
                ss.files(Path("."))


class IncrementalCache(unittest.TestCase):
    """The workspace scan skips files unchanged since the last scan, but must never hide a finding."""

    def setUp(self):
        """Create the scratch state this test needs."""
        import tempfile
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.root = Path(self.td.name)
        self.cache = self.root / "cache.json"
        self._old = os.environ.get("TWU_SECRET_SCAN_CACHE")
        os.environ["TWU_SECRET_SCAN_CACHE"] = str(self.cache)
        self.addCleanup(lambda: os.environ.pop("TWU_SECRET_SCAN_CACHE", None) if self._old is None else os.environ.__setitem__("TWU_SECRET_SCAN_CACHE", self._old))
        self.f = self.root / "a.txt"
        self.f.write_text("nothing here\n")

    def run_scan(self):
        """Helper: run scan."""
        return ss.scan(self.root, [self.f], cache=True)

    def test_unchanged_file_is_not_reread_and_results_match(self):
        """Check that unchanged file is not reread and results match."""
        first = self.run_scan()
        calls = []
        real = ss.scan_text
        ss.scan_text = lambda t: calls.append(1) or real(t)
        try:
            second = self.run_scan()
        finally:
            ss.scan_text = real
        self.assertEqual((first, calls), (second, []))

    def test_a_changed_file_is_rescanned_and_a_new_secret_is_found(self):
        """Check that a changed file is rescanned and a new secret is found."""
        self.assertEqual(self.run_scan(), [])
        self.f.write_text(AWS + "\n")
        os.utime(self.f, (self.f.stat().st_atime, self.f.stat().st_mtime + 5))
        hits = self.run_scan()
        self.assertEqual([h["type"] for h in hits], ["aws-access-key"])

    def test_an_old_finding_stays_reported_while_the_file_is_unchanged(self):
        """Check that an old finding stays reported while the file is unchanged."""
        self.f.write_text(AWS + "\n")
        a = self.run_scan()
        b = self.run_scan()
        self.assertEqual((len(a), a), (1, b))

    def test_a_changed_rule_invalidates_the_whole_cache(self):
        """Check that a changed rule invalidates the whole cache."""
        self.f.write_text(AWS + "\n")
        self.run_scan()
        saved = dict(ss.RULES)
        ss.RULES.clear()
        ss.RULES["other"] = ss.re.compile(r"zzzzzz")
        try:
            self.assertEqual(self.run_scan(), [])                       # the old hit must NOT be replayed under different rules
        finally:
            ss.RULES.clear()
            ss.RULES.update(saved)

    def test_a_corrupt_cache_is_ignored_and_never_changes_results(self):
        """Check that a corrupt cache is ignored and never changes results."""
        self.f.write_text(AWS + "\n")
        self.cache.write_text("{not json")
        self.assertEqual(len(self.run_scan()), 1)

    def test_the_cache_stores_fingerprints_never_the_secret(self):
        """Check that the cache stores fingerprints never the secret."""
        self.f.write_text(AWS + "\n")
        self.run_scan()
        self.assertNotIn(AWS, self.cache.read_text())

    def test_a_file_list_scan_without_cache_flag_does_not_touch_the_cache(self):
        """Check that a file list scan without cache flag does not touch the cache."""
        ss.scan(self.root, [self.f])
        self.assertFalse(self.cache.exists())


if __name__ == "__main__":
    unittest.main()
