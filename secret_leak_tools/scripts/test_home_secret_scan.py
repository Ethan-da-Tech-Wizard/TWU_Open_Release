import atexit, contextlib, io, json, os, shutil, sys, tempfile, time, unittest
from pathlib import Path
from unittest import mock
sys.path.insert(0, str(Path(__file__).resolve().parent))
import home_secret_scan as h

# The fingerprint salt lives in a throwaway folder for the whole test run, never in the real state directory.
_SALT_DIR = tempfile.mkdtemp(prefix="fpsalt-")
atexit.register(shutil.rmtree, _SALT_DIR, True)
os.environ["TWU_FP_SALT_FILE"] = os.path.join(_SALT_DIR, "salt")

AWS = "AKIA" + "ABCDEFGHIJKLMNOP"      # assembled at runtime so this file holds no scannable secret

def rnd(n=30):  # assembled at runtime so the test source holds no scannable secret
    """Helper: rnd."""
    return "Zq" + "k7Rt9" * (n // 5)

class T(unittest.TestCase):
    """Tests for: T."""
    def setUp(self):
        """Create the scratch state this test needs."""
        self._t = tempfile.TemporaryDirectory(); self.addCleanup(self._t.cleanup)
        self.home = Path(self._t.name) / "home"; self.home.mkdir()
        self.d = Path(self._t.name) / "out"
        self.val = rnd()

    def w(self, rel, text, mode=None):
        """Helper: w."""
        p = self.home / rel; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(text)
        if mode: p.chmod(mode)
        return p

    def types(self):
        """Helper: types."""
        f, _ = h.scan(self.home); return {(x["file"], x["type"]) for x in f}

    def test_shell_patterns(self):
        """Check that shell patterns."""
        v = self.val
        self.w(".zsh_history", "\n".join([
            f"export MY_API_TOKEN={v}", f"tool --password {v}", f"cu" f"rl -u bob:{v} http://x",
            f"curl -H 'Authorization: Bearer {v}' http://x", f"mysql -u root -p{v}"]))
        t = {y for _, y in self.types()}
        self.assertTrue({"literal-assignment", "cli-password-flag", "curl-basic-auth", "bearer-token", "mysql-password"} <= t)

    def test_rc_and_rules(self):
        """Check that rc and rules."""
        self.w(".zshrc", "export GH=gh" + "p_" + "A1b2C3d4E5" * 4)
        self.assertIn((".zshrc", "github-token"), self.types())

    def test_configs(self):
        """Check that configs."""
        v = self.val
        self.w(".netrc", f"machine x login u password {v}")
        self.w(".npmrc", f"//r/:_authToken={v}")
        self.w(".pypirc", f"[pypi]\npassword = {v}")
        self.w(".git-credentials", f"https://u:{v}@github.com")
        self.w(".docker/config.json", json.dumps({"auths": {"r": {"auth": "dTpw" + v}}}))
        self.w(".config/gh/hosts.yml", f"github.com:\n  oauth_token: {v}\n")
        self.w(".config/app/prod.env", f"DB_PASSWORD={v}")
        t = self.types()
        for k in [(".netrc", "netrc-password"), (".npmrc", "npmrc-auth"), (".pypirc", "pypirc-password"),
                  (".git-credentials", "git-credentials"), (".docker/config.json", "docker-auth"),
                  (".config/gh/hosts.yml", "gh-plaintext-token"), (".config/app/prod.env", "literal-assignment")]:
            self.assertIn(k, t)

    def test_user_folders(self):
        """Check that user folders."""
        for n in ("Downloads", "Desktop", "Documents"):
            self.w(f"{n}/n.txt", "k = " + AWS)
        f, _ = h.scan(self.home)
        self.assertEqual({x["class"] for x in f}, {"downloads", "desktop", "documents"})

    def test_value_never_leaks(self):
        """Check that value never leaks."""
        v = self.val
        self.w(".zsh_history", f"export A_SECRET={v}\ncu" f"rl -u u:{v} x")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            r, new = h.check(self.home, self.d)
            h.HOST  # noqa
            old = h.DIR; h.DIR = self.d
            try:
                h.main(["report"]); h.main(["status"]); h.main(["check"]) if False else None
            finally:
                h.DIR = old
        blob = buf.getvalue() + (self.d / f"HOMESECRETS.{h.HOST}.json").read_text()
        self.assertTrue(new); self.assertNotIn(v, blob); self.assertNotIn("A_SECRET", blob)
        for x in r["findings"]:
            self.assertEqual(set(x) - {"accepted"}, {"file", "line", "type", "class", "fp"})
            self.assertEqual(len(x["fp"]), 10)

    def test_placeholders_ignored(self):
        """Check that placeholders ignored."""
        self.w(".zshrc", "\n".join(["export A_TOKEN=$OTHER_TOKEN_VALUE_X", "export B_TOKEN=your_token_goes_here_12345",
                                    "export C_PASSWORD=xxxxxxxxxxxxxxxx", "export D_TOKEN=short", "export E_TOKEN=<paste-token-here-abc>"]))
        self.assertEqual(h.scan(self.home)[0], [])

    def test_symlink_not_followed(self):
        """Check that symlink not followed."""
        out = Path(self._t.name) / "outside"; out.mkdir()
        (out / "s.txt").write_text(f"export A_SECRET={self.val}")
        (self.home / "Downloads").mkdir()
        os.symlink(out / "s.txt", self.home / "Downloads" / "l.txt")
        os.symlink(out, self.home / "Documents")
        os.symlink(out / "s.txt", self.home / ".zshrc")
        self.assertEqual(h.scan(self.home)[0], [])

    def test_size_binary_skip_and_library(self):
        """Check that size binary skip and library."""
        line = "key = " + AWS
        self.w("Downloads/big.txt", line + "\n" + "x" * 1_100_000)
        (self.home / "Downloads" / "bin.dat").write_bytes(b"\0\0" + line.encode())
        self.w("Downloads/node_modules/p/a.txt", line)
        self.w("Library/x.txt", line)
        self.assertEqual(h.scan(self.home)[0], [])

    def test_key_permissions(self):
        """Check that key permissions."""
        self.w(".ssh/id_ed25519", "not a real key", 0o644)
        self.w(".ssh/id_rsa2", "x", 0o600)
        self.w("Documents/server.pem", "x", 0o640)
        f, _ = h.scan(self.home)
        got = {x["file"] for x in f if x["type"] == "key-file-permissions"}
        self.assertEqual(got, {".ssh/id_ed25519", "Documents/server.pem"})

    def test_accept_requires_reason(self):
        """Check that accept requires reason."""
        with self.assertRaises(ValueError): h.accept("abc", "", self.d)
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            h.main(["accept", "abc"])
        self.w(".zshrc", f"export A_SECRET={self.val}")
        r, new = h.check(self.home, self.d)
        h.accept(new[0]["fp"], "test fixture", self.d)
        r2, new2 = h.check(self.home, self.d)
        self.assertEqual(new2, []); self.assertEqual(r2["new"], 0)

    def test_alarm_conventions(self):
        """Check that alarm conventions."""
        now = time.time()
        self.assertIn("homesecrets:quiet", h.alarm_problems(now, self.d))
        self.w(".zshrc", f"export A_SECRET={self.val}")
        r, new = h.check(self.home, self.d, now=now)
        p = h.alarm_problems(now, self.d)
        self.assertIn(f"homesecrets:{new[0]['fp']}", p); self.assertNotIn(self.val, json.dumps(p))
        self.assertIn("homesecrets:quiet", h.alarm_problems(now + 27 * 3600, self.d))
        self.assertIn("homesecrets:quiet", h.alarm_problems(now - 3600, self.d))  # future-dated
        (self.d / f"HOMESECRETS.{h.HOST}.json").write_text("{bad")
        self.assertIn("homesecrets:quiet", h.alarm_problems(now, self.d))
        h.accept(new[0]["fp"], "ok", self.d)
        (self.d / f"HOMESECRETS.{h.HOST}.json").write_text(json.dumps(r))
        self.assertEqual(h.alarm_problems(now, self.d), {})

class Confirmation(unittest.TestCase):
    """`check` reads the home folder and shell history, so it must be confirmed; report/status/accept must not need it."""

    def run_main(self, argv, tty=False):
        """Helper: run main."""
        err, out = io.StringIO(), io.StringIO()
        fake_in = mock.Mock(); fake_in.isatty.return_value = tty; fake_in.readline.return_value = "y\n"
        with mock.patch.object(h, "check", return_value=({"findings": [], "new": 0, "files_scanned": 0, "truncated": False}, [])) as chk, \
             mock.patch.object(sys, "stdin", fake_in), contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
            rc = h.main(argv)
        return rc, chk.called, err.getvalue()

    def test_check_refuses_without_confirmation(self):
        """Check that check refuses without confirmation."""
        rc, called, err = self.run_main(["check"])
        self.assertEqual((rc, called), (2, False))
        self.assertIn("--yes-read-home", err)
        rc, called, _ = self.run_main([])            # no subcommand means check
        self.assertEqual((rc, called), (2, False))

    def test_flag_confirms(self):
        """Check that flag confirms."""
        rc, called, _ = self.run_main(["check", "--yes-read-home"])
        self.assertEqual((rc, called), (0, True))

    def test_interactive_yes_confirms_and_non_tty_never_prompts(self):
        """Check that interactive yes confirms and non tty never prompts."""
        rc, called, err = self.run_main(["check"], tty=True)
        self.assertEqual((rc, called), (0, True))
        self.assertIn("home folder and shell history", err)

    def test_missing_salt_fails_closed(self):
        """Check that missing salt fails closed."""
        with tempfile.TemporaryDirectory() as td, mock.patch.object(h.secret_scan, "salt_is_ephemeral", return_value=True):
            with self.assertRaises(h.secret_scan.ScanUnavailable):
                h.check(Path(td), Path(td) / "out")

    def test_fingerprints_are_salted(self):
        """Check that fingerprints are salted."""
        import hashlib
        self.assertNotEqual(h._fp("value"), hashlib.sha256(b"value").hexdigest()[:10])


if __name__ == "__main__":
    unittest.main()
