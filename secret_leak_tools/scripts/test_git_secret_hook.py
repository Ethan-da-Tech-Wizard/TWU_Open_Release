#!/usr/bin/env python3
"""Tests for scripts/git_secret_hook.py in real throwaway git repos. Fake credentials are assembled at runtime."""
import atexit, contextlib, io, os, shutil, subprocess, sys, tempfile, unittest
from pathlib import Path
from unittest import mock
sys.path.insert(0, str(Path(__file__).resolve().parent))
import git_secret_hook as h

# isolate from the machine's real global git config (a global core.hooksPath would make install refuse)
os.environ["GIT_CONFIG_GLOBAL"] = os.devnull
os.environ["GIT_CONFIG_SYSTEM"] = os.devnull
# The fingerprint salt lives in a throwaway folder for the whole test run, never in the real state directory.
_SALT_DIR = tempfile.mkdtemp(prefix="fpsalt-")
atexit.register(shutil.rmtree, _SALT_DIR, True)
os.environ["TWU_FP_SALT_FILE"] = os.path.join(_SALT_DIR, "salt")

GH = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
AWS = "AKIA" + "ABCDEFGHIJKLMNOP"
AWS_DOC = "AKIA" + "EXAMPLEEXAMPLE12"      # placeholder-looking key, also built at runtime
HOOK = str(h.SELF)


def sh(repo, *a, check=True):
    """Helper: sh."""
    env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull}
    return subprocess.run(["git", "-C", str(repo), *a], capture_output=True, text=True, check=check, env=env)


class T(unittest.TestCase):
    """Tests for: T."""
    def setUp(self):
        """Create the scratch state this test needs."""
        self.t = tempfile.TemporaryDirectory(); self.r = Path(self.t.name).resolve()
        self.repo = self.r / "repo"; self.repo.mkdir()
        sh(self.repo, "init", "-q", "-b", "main")
        sh(self.repo, "config", "user.email", "t@t"); sh(self.repo, "config", "user.name", "t")
        sh(self.repo, "config", "commit.gpgsign", "false")
        self.w("README.md", "hello\n"); sh(self.repo, "add", "-A"); sh(self.repo, "commit", "-qm", "init", "--no-verify")

    def tearDown(self):
        """Remove the scratch state this test created."""
        self.t.cleanup()

    def w(self, name, txt):
        """Helper: w."""
        p = self.repo / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(txt); return p

    def run_hook(self, *args, stdin="", cwd=None):
        """Helper: run hook."""
        return subprocess.run([sys.executable, "-B", HOOK, *args], cwd=cwd or self.repo, input=stdin, capture_output=True, text=True)

    def stage(self, name, txt):
        """Helper: stage."""
        self.w(name, txt); sh(self.repo, "add", name)

    def test_clean_commit_passes(self):
        """Check that clean commit passes."""
        self.stage("a.py", "x = 1\n")
        self.assertEqual(self.run_hook("pre-commit").returncode, 0)

    def test_secret_blocked_never_echoed(self):
        """Check that secret blocked never echoed."""
        self.stage("a.py", f"x = 1\nT = '{GH}'\n")
        r = self.run_hook("pre-commit")
        self.assertEqual(r.returncode, 1)
        self.assertIn("a.py:2 github-token", r.stderr)
        self.assertNotIn(GH, r.stdout + r.stderr)
        self.assertNotIn(GH[4:], r.stdout + r.stderr)

    def test_only_added_lines_scanned(self):
        """Check that only added lines scanned."""
        self.w("old.txt", f"{AWS}\n"); sh(self.repo, "add", "-A"); sh(self.repo, "commit", "-qm", "o", "--no-verify")
        self.w("old.txt", f"{AWS}\nmore\n"); sh(self.repo, "add", "-A")  # secret line unchanged context
        self.assertEqual(self.run_hook("pre-commit").returncode, 0)

    def test_placeholder_and_allow_marker(self):
        """Check that placeholder and allow marker."""
        self.stage("a.md", "key = " + AWS_DOC + "\nuse ghp_xxxx\n")
        self.assertEqual(self.run_hook("pre-commit").returncode, 0)
        self.stage("b.py", f"T = '{GH}'  # leakguard:allow test fixture\n")
        self.assertEqual(self.run_hook("pre-commit").returncode, 0)

    def test_env_blocked_example_allowed(self):
        """Check that env blocked example allowed."""
        self.stage(".env.example", "A=1\n"); self.stage("x.env.sample", "A=1\n")
        self.assertEqual(self.run_hook("pre-commit").returncode, 0)
        self.stage(".env", "A=1\n")
        r = self.run_hook("pre-commit")
        self.assertEqual(r.returncode, 1); self.assertIn(".env:0 sensitive-file", r.stderr)
        sh(self.repo, "reset", "-q"); self.stage("keys/id_rsa", "x\n")
        self.assertEqual(self.run_hook("pre-commit").returncode, 1)

    def push(self, lref, lsha, rref, rsha, remote="origin"):
        """Helper: push."""
        return self.run_hook("pre-push", remote, "u", stdin=f"{lref} {lsha} {rref} {rsha}\n")

    def test_pre_push_ranges(self):
        """Check that pre push ranges."""
        base = sh(self.repo, "rev-parse", "HEAD").stdout.strip()
        self.stage("c.py", f"T = '{GH}'\n"); sh(self.repo, "commit", "-qm", "leak", "--no-verify")
        tip = sh(self.repo, "rev-parse", "HEAD").stdout.strip()
        r = self.push("refs/heads/main", tip, "refs/heads/main", base)
        self.assertEqual(r.returncode, 1); self.assertIn("c.py:1 github-token", r.stderr); self.assertNotIn(GH, r.stderr)
        r = self.push("refs/heads/feat", tip, "refs/heads/feat", "0" * 40)  # new branch
        self.assertEqual(r.returncode, 1)
        self.assertEqual(self.push("refs/heads/main", tip, "refs/heads/main", tip).returncode, 0)
        self.assertEqual(self.push("(delete)", "0" * 40, "refs/heads/old", tip).returncode, 0)
        self.assertEqual(self.push("refs/heads/main", base, "refs/heads/main", "0" * 40).returncode, 0)  # clean history

    def hooks(self):
        """Helper: hooks."""
        return self.repo / ".git" / "hooks"

    def test_install_chain_idempotent_uninstall(self):
        """Check that install chain idempotent uninstall."""
        old = self.hooks() / "pre-commit"
        old.write_text("#!/bin/sh\necho OLDHOOK >> \"$(dirname \"$0\")/ran\"\nexit 0\n"); old.chmod(0o755)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(h.install([self.repo]), 0)
            first = (self.hooks() / "pre-commit").read_text()
            self.assertEqual(h.install([self.repo]), 0)
        self.assertEqual(first, (self.hooks() / "pre-commit").read_text())
        self.assertTrue((self.hooks() / "pre-commit.pre-leakguard").exists())
        self.assertTrue(h.installed(self.repo))
        # clean commit runs old hook then passes; secret commit blocked
        self.w("ok.txt", "fine\n"); sh(self.repo, "add", "-A")
        self.assertEqual(sh(self.repo, "commit", "-qm", "ok", check=False).returncode, 0)
        self.assertIn("OLDHOOK", (self.hooks() / "ran").read_text())
        self.w("bad.txt", f"{GH}\n"); sh(self.repo, "add", "-A")
        r = sh(self.repo, "commit", "-qm", "bad", check=False)
        self.assertNotEqual(r.returncode, 0); self.assertNotIn(GH, r.stdout + r.stderr)
        sh(self.repo, "reset", "-q")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(h.uninstall([self.repo]), 0)
        self.assertIn("OLDHOOK", old.read_text())
        self.assertFalse((self.hooks() / "pre-commit.pre-leakguard").exists())
        self.assertFalse((self.hooks() / "pre-push").exists())
        self.assertFalse(h.installed(self.repo))

    def test_installed_pre_push_blocks(self):
        """Check that installed pre push blocks."""
        with contextlib.redirect_stdout(io.StringIO()):
            h.install([self.repo])
        bare = self.r / "bare.git"; sh(self.r, "init", "-q", "--bare", str(bare))
        sh(self.repo, "remote", "add", "origin", str(bare))
        self.w("s.txt", f"{AWS}\n"); sh(self.repo, "add", "-A"); sh(self.repo, "commit", "-qm", "s", "--no-verify")
        r = sh(self.repo, "push", "origin", "main", check=False)
        self.assertNotEqual(r.returncode, 0); self.assertIn("BLOCKED", r.stderr); self.assertNotIn(AWS, r.stderr)

    def test_install_refuses_foreign_hookspath(self):
        """Check that install refuses foreign hookspath."""
        sh(self.repo, "config", "core.hooksPath", ".githooks")
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(h.install([self.repo]), 1)
        self.assertIn("core.hooksPath", err.getvalue())
        self.assertFalse((self.hooks() / "pre-commit").exists())

    def test_status_under(self):
        """Check that status under."""
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            h.install([self.repo])
            other = self.r / "other"; other.mkdir(); sh(other, "init", "-q")
            h.status(["--under", str(self.r)])
        txt = out.getvalue()
        self.assertRegex(txt, r"installed\s+" + str(self.repo)); self.assertRegex(txt, r"NOT installed\s+" + str(other))

    def test_git_missing_fails_closed_with_a_clear_message(self):
        """Check that git missing fails closed with a clear message."""
        self.stage("a.py", "x = 1\n")
        env = {**os.environ, "TWU_GIT": "/nonexistent/git"}
        for argv, stdin in ((["pre-commit"], ""), (["pre-push", "origin", "u"], "refs/heads/main %s refs/heads/main %s\n" % ("a" * 40, "0" * 40))):
            r = subprocess.run([sys.executable, "-B", HOOK, *argv], cwd=self.repo, env=env, input=stdin, capture_output=True, text=True)
            self.assertEqual(r.returncode, 1, r.stderr)
            self.assertIn("BLOCKED", r.stderr); self.assertIn("LEAKGUARD_ALLOW_MISSING=1", r.stderr)

    def test_git_missing_override_skips_loudly(self):
        """Check that git missing override skips loudly."""
        env = {**os.environ, "TWU_GIT": "/nonexistent/git", "LEAKGUARD_ALLOW_MISSING": "1"}
        r = subprocess.run([sys.executable, "-B", HOOK, "pre-commit"], cwd=self.repo, env=env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0); self.assertIn("WARNING", r.stderr); self.assertIn("SKIPPED", r.stderr)
        env["LEAKGUARD_ALLOW_MISSING"] = ""            # an empty value is NOT an override
        r = subprocess.run([sys.executable, "-B", HOOK, "pre-commit"], cwd=self.repo, env=env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)

    def test_installed_hook_fails_closed_when_script_or_python_is_missing(self):
        """Check that installed hook fails closed when script or python is missing."""
        inst = self.r / "inst"; inst.mkdir()
        for f in ("git_secret_hook.py", "secret_scan.py"):
            (inst / f).write_text((Path(HOOK).parent / f).read_text())
        run = lambda *a, **k: subprocess.run([sys.executable, "-B", str(inst / "git_secret_hook.py"), *a], capture_output=True, text=True, **k)
        self.assertEqual(run("install", str(self.repo)).returncode, 0)
        shutil.rmtree(inst)                                  # the clone was moved or deleted
        self.w("ok.txt", "fine\n"); sh(self.repo, "add", "-A")
        r = sh(self.repo, "commit", "-qm", "ok", check=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("BLOCKED", r.stderr); self.assertIn("missing", r.stderr); self.assertIn("LEAKGUARD_ALLOW_MISSING=1", r.stderr)
        env = {**os.environ, "LEAKGUARD_ALLOW_MISSING": "1"}
        r = subprocess.run(["git", "-C", str(self.repo), "commit", "-qm", "ok"], capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("SKIP", r.stderr.upper())

    def test_installed_hook_fails_closed_when_python_is_missing(self):
        """Check that installed hook fails closed when python is missing."""
        with contextlib.redirect_stdout(io.StringIO()):
            h.install([self.repo])
        hook = self.hooks() / "pre-commit"
        text = hook.read_text().replace(sys.executable, "/nonexistent/python").replace(h.SYS_PYTHON, "/nonexistent/python2")
        hook.write_text(text)
        self.w("ok.txt", "fine\n"); sh(self.repo, "add", "-A")
        r = sh(self.repo, "commit", "-qm", "ok", check=False)
        self.assertNotEqual(r.returncode, 0); self.assertIn("python3 or git_secret_hook.py is missing", r.stderr)

    def test_hook_text_uses_absolute_paths_for_every_tool(self):
        """Check that hook text uses absolute paths for every tool."""
        for name in h.HOOKS:
            text = h.hook_text(name)
            self.assertNotIn("command -v", text)
            for tool in ("dirname", "mktemp", "cat", "rm"):
                self.assertNotRegex(text, r"(?<![/\w.-])" + tool + r"(?=[ )\"])" if tool != "cat" else r"(?m)^cat ")
            self.assertIn("/usr/bin/dirname", text)
            self.assertIn('"$PY"', text)

    def test_no_textconv_so_repo_config_cannot_run_a_program_during_the_scan(self):
        """Check that no textconv so repo config cannot run a program during the scan."""
        marker = self.r / "ran-textconv"
        conv = self.r / "conv.sh"
        conv.write_text("#!/bin/sh\ntouch '%s'\ncat \"$1\"\n" % marker); conv.chmod(0o755)
        sh(self.repo, "config", "diff.evil.textconv", str(conv))
        (self.repo / ".gitattributes").write_text("*.txt diff=evil\n")
        self.stage("note.txt", "hello\n")
        sh(self.repo, "diff", "--cached")                      # sanity: plain git diff DOES run the converter
        self.assertTrue(marker.exists()); marker.unlink()
        self.assertEqual(self.run_hook("pre-commit").returncode, 0)
        self.assertFalse(marker.exists(), "pre-commit ran a repo-configured textconv program")
        base = sh(self.repo, "rev-parse", "HEAD").stdout.strip()
        sh(self.repo, "commit", "-qm", "n", "--no-verify")
        tip = sh(self.repo, "rev-parse", "HEAD").stdout.strip()
        self.assertEqual(self.push("refs/heads/main", tip, "refs/heads/main", base).returncode, 0)
        self.assertFalse(marker.exists(), "pre-push ran a repo-configured textconv program")

    def test_install_refuses_a_symlinked_hooks_directory(self):
        """Check that install refuses a symlinked hooks directory."""
        elsewhere = self.r / "elsewhere"; elsewhere.mkdir()
        shutil.rmtree(self.hooks()); self.hooks().symlink_to(elsewhere)
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(h.install([self.repo]), 1)
        self.assertIn("symlink", err.getvalue())
        self.assertEqual(list(elsewhere.iterdir()), [])

    def test_install_does_not_write_through_a_symlinked_hook_file(self):
        """Check that install does not write through a symlinked hook file."""
        victim = self.r / "victim"; victim.write_text("keep\n")
        (self.hooks() / "pre-commit").symlink_to(victim)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(h.install([self.repo]), 0)
        self.assertEqual(victim.read_text(), "keep\n")
        self.assertTrue(h.is_ours(self.hooks() / "pre-commit"))


class LockAndIdentity(T):
    """Tests for: Lock And Identity."""
    def test_mac_and_hostname_blocked_values_not_echoed(self):
        """Check that mac and hostname blocked values not echoed."""
        mac = ":".join(["a4", "83", "e7", "12", "34", "56"])
        self.stage("m.txt", f"nic {mac}\n")
        r = self.run_hook("pre-commit"); self.assertEqual(r.returncode, 1)
        self.assertIn("mac-address", r.stderr); self.assertNotIn(mac, r.stderr)
        sh(self.repo, "reset", "-q")
        self.stage("h.txt", "ssh box-7.local\n")  # leakguard:allow
        r = self.run_hook("pre-commit"); self.assertEqual(r.returncode, 1); self.assertIn("local-hostname", r.stderr)

    def test_placeholder_mac_ok(self):
        """Check that placeholder mac ok."""
        self.stage("m.txt", "00:00:00:00:00:00 ff:ff:ff:ff:ff:ff xx:yy\n")
        self.assertEqual(self.run_hook("pre-commit").returncode, 0)

    def test_lock_blocks_every_push_and_flags_remote(self):
        """Check that lock blocks every push and flags remote."""
        bare = self.r / "bare.git"; sh(self.r, "init", "-q", "--bare", str(bare))
        self.assertEqual(self.run_hook("lock", str(self.repo)).returncode, 0)
        sh(self.repo, "remote", "add", "fake", str(bare))
        self.assertEqual(self.run_hook("lock", str(self.repo)).returncode, 1)  # remote present is reported
        p = sh(self.repo, "push", "fake", "main", check=False)
        self.assertNotEqual(p.returncode, 0); self.assertIn("FORBIDDEN", p.stderr)
        self.assertEqual(sh(bare, "branch", "--list").stdout.strip(), "")
        sh(self.repo, "remote", "remove", "fake")
        self.assertTrue(h.locked(self.repo))
        self.run_hook("unlock", str(self.repo)); self.assertFalse(h.locked(self.repo))


    def test_hostnames_from_private_hosts_file_next_to_script(self):
        """Check that hostnames from private hosts file next to script."""
        import json as _j
        d = self.r / "inst"; d.mkdir()
        for f in ("git_secret_hook.py", "secret_scan.py"):
            (d / f).write_text((Path(HOOK).parent / f).read_text())
        (d / "private_hosts.json").write_text(_j.dumps({"hosts": [{"host": "testbox-alpha", "aliases": ["test beta"]}]}))
        self.stage("a.txt", '"10.0.0.1": "TestBox_Alpha",\n')
        run = lambda: subprocess.run([sys.executable, "-B", str(d / "git_secret_hook.py"), "pre-commit"], cwd=self.repo, capture_output=True, text=True)
        r = run(); self.assertEqual(r.returncode, 1); self.assertNotIn("testbox", (r.stdout + r.stderr).lower())
        self.stage("a.txt", "fine\n"); self.assertEqual(run().returncode, 0)

    def test_env_private_hosts_file_and_legacy_name(self):
        """Check that env private hosts file and legacy name."""
        import json as _j
        f = self.r / "red.json"; f.write_text(_j.dumps({"hosts": ["secretbox-one"]}))
        self.stage("b.txt", "secretbox_one\n")
        for var in ("TWU_PRIVATE_HOSTS_FILE", "TWU_REDACTIONS_FILE"):
            env = dict(os.environ, **{var: str(f)})
            r = subprocess.run([sys.executable, "-B", HOOK, "pre-commit"], cwd=self.repo, capture_output=True, text=True, env=env)
            self.assertEqual(r.returncode, 1, var)

    def test_empty_env_values_are_ignored(self):
        """Check that empty env values are ignored."""
        with mock.patch.dict(os.environ, {"TWU_PRIVATE_HOSTS_FILE": "", "TWU_REDACTIONS_FILE": ""}):
            self.assertEqual(len(h._candidates(h.HOSTS_FILE)), 2)      # no empty-string path was added
            self.assertEqual(h._private_hosts(), [])
        self.stage("c.txt", "nothing private\n")
        env = dict(os.environ, TWU_PRIVATE_HOSTS_FILE="", TWU_REDACTIONS_FILE="", TWU_GIT="")
        r = subprocess.run([sys.executable, "-B", HOOK, "pre-commit"], cwd=self.repo, capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)


class DistroWordTests(unittest.TestCase):
    """A distro name that is also a machine name: prose is fine, a real host token still blocks."""
    def setUp(self):
        """Create the scratch state this test needs."""
        self._old = h._private_hosts
        h._private_hosts = lambda: ["fedora", "somehostx"]

    def tearDown(self):
        """Remove the scratch state this test created."""
        h._private_hosts = self._old

    def hits(self, line):
        """Helper: hits."""
        return [t for t, _ in h.scan_identity(line) if t == "private-hostname"]

    def test_distro_word_in_prose_is_not_a_host(self):
        """Check that distro word in prose is not a host."""
        for line in ("Targets Fedora 40 and Ubuntu 24.04 LTS", "| Fedora | Linux workstation distro |",
                     "Debian-based; Fedora Linux package names differ", "the Fedora Project mirrors"):
            self.assertEqual(self.hits(line), [], line)

    def test_real_host_token_still_blocks(self):
        """Check that real host token still blocks."""
        for line in ("ssh fedora", "ping fedora now", "user@fedora", "host: fedora", "the Fedora laptop", "Fedora machine",
                     "fedora", "name=fedora"):
            self.assertTrue(self.hits(line), line)

    def test_other_private_host_always_blocks(self):
        """Check that other private host always blocks."""
        self.assertTrue(self.hits("deploy to SomeHostX tonight"))

    def test_longer_word_containing_distro_is_not_a_host(self):
        """Check that longer word containing distro is not a host."""
        self.assertEqual(self.hits("registry.fedoraproject.org"), [])


class RedTeam5(T):
    """Seat-5 red-team regressions: every test here failed against the first release of the hook (bypass hunt)."""
    # Fake token assembled at runtime, so no token-shaped literal sits in this file.
    TOK = "gh" + "p_" + "Q7mZk2XvR9tLw4NcB8yHd3JfS6gPa5UeT1oV"

    def blocked(self, name, txt, raw=False):
        """Stage `txt` as `name` and return True when the pre-commit scan blocks it."""
        p = self.repo / name; p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(txt if raw else txt.encode()); sh(self.repo, "add", "-A")
        return self.run_hook("pre-commit").returncode == 1

    def test_plus_plus_space_line_is_scanned(self):
        """A content line starting with '++ ' makes the diff line '+++ ...': it must not be read as a file header."""
        self.assertTrue(self.blocked("f.txt", "a\n++ " + self.TOK + "\n"))

    def test_plus_plus_dev_null_line_does_not_hide_the_hunk(self):
        """A content line '++ /dev/null' must not switch the scan off for the lines after it."""
        self.assertTrue(self.blocked("f.txt", "++ /dev/null\nk=" + self.TOK + "\n"))

    def test_exotic_line_separators_do_not_split_added_lines(self):
        """CR, VT, FF, U+0085 and U+2028 inside an added line must not hide a token that follows them."""
        for i, sep in enumerate(["\r", "\x0b", "\x0c", "\x85", "\u2028", "\x1c"]):
            self.assertTrue(self.blocked("f%d.txt" % i, "foo" + sep + "k=" + self.TOK + "\n"), repr(sep))

    def test_type_change_symlink_to_file_is_scanned(self):
        """Replacing a tracked symlink by a regular file is a type change (T): content and name must still be checked."""
        os.symlink("README.md", self.repo / "l"); sh(self.repo, "add", "l"); sh(self.repo, "commit", "-qm", "l", "--no-verify")
        (self.repo / "l").unlink(); (self.repo / "l").write_text("k=" + self.TOK + "\n"); sh(self.repo, "add", "l")
        self.assertEqual(self.run_hook("pre-commit").returncode, 1)
        sh(self.repo, "reset", "-q", "--hard")
        os.symlink("README.md", self.repo / ".env"); sh(self.repo, "add", ".env"); sh(self.repo, "commit", "-qm", "e", "--no-verify")
        (self.repo / ".env").unlink(); (self.repo / ".env").write_text("hi\n"); sh(self.repo, "add", ".env")
        self.assertEqual(self.run_hook("pre-commit").returncode, 1)

    def test_nul_byte_file_is_scanned(self):
        """A NUL byte makes git call the file binary and print no lines; the hook must still read it (--text)."""
        self.assertTrue(self.blocked("f.bin", b"a\0b\nk=" + self.TOK.encode() + b"\n", raw=True))

    def test_gitattributes_minus_diff_does_not_hide_content(self):
        """`* -diff` in .gitattributes must not turn the staged content into 'Binary files differ'."""
        self.w(".gitattributes", "* -diff\n"); sh(self.repo, "add", "-A"); sh(self.repo, "commit", "-qm", "a", "--no-verify")
        self.assertTrue(self.blocked("f.txt", "k=" + self.TOK + "\n"))

    def test_utf16_file_is_scanned(self):
        """A UTF-16 file has NULs between the letters; the scan also reads the line with the NULs removed."""
        self.assertTrue(self.blocked("f.txt", ("k=" + self.TOK + "\n").encode("utf-16"), raw=True))

    def test_very_long_line_is_scanned(self):
        """Padding a line past 4000 characters must not hide a token (long lines are scanned in overlapping pieces)."""
        self.assertTrue(self.blocked("f.txt", "a" * 5000 + " k=" + self.TOK + " " + "b" * 5000 + "\n"))

    def test_real_token_after_a_placeholder_on_one_line(self):
        """Only the FIRST match per rule used to be judged: a placeholder first must not hide a real token after it."""
        self.assertTrue(self.blocked("f.txt", "a=gh" + "p_" + "x" * 36 + " b=" + self.TOK + "\n"))

    def test_invisible_and_fullwidth_disguises_are_scanned(self):
        """A zero-width character inside the token, or full-width look-alike letters, are folded before matching."""
        t = self.TOK
        self.assertTrue(self.blocked("z.txt", "k=" + t[:10] + "\u200b" + t[10:] + "\n"))
        fw = "".join(chr(ord(c) + 0xFEE0) if c.isascii() and c.isalnum() else c for c in t)
        self.assertTrue(self.blocked("w.txt", "k=" + fw + "\n"))

    def test_more_credential_file_names(self):
        """Common credential file names beyond .env/id_rsa: .env-prod, .envrc, id_ed25519_x, .pgpass, .git-credentials."""
        for n in (".env-prod", ".env_local", ".envrc", "id_ed25519_work", ".pgpass", ".git-credentials", ".pypirc", "keys.kdbx"):
            self.assertTrue(h.sensitive_name(n), n)
        for n in ("id_rsa.pub", ".env.example", "environment.md", ".environment"):
            self.assertFalse(h.sensitive_name(n), n)

    def install_hooks(self):
        """Install the real hooks into the scratch repo."""
        self.assertEqual(h.install([self.repo]), 0)

    def commit_env(self, **extra):
        """Run `git commit` (hooks active) with extra environment variables; returns the CompletedProcess."""
        env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull, **extra}
        return subprocess.run(["git", "-C", str(self.repo), "commit", "-qm", "x"], capture_output=True, text=True, env=env)

    def test_ambient_skip_variable_does_not_disable_the_hook(self):
        """SKIP=1 (the pre-commit framework's convention) in the environment used to skip the scan silently."""
        self.install_hooks(); self.stage("f.txt", "k=" + self.TOK + "\n")
        for v in ("1", "pytest", "leakguard"):
            self.assertEqual(self.commit_env(SKIP=v).returncode, 1, v)
        self.assertNotIn("SKIP", h.hook_text("pre-commit").replace("LEAKGUARD_ALLOW_MISSING", ""))

    def test_allow_missing_does_not_skip_when_everything_is_present(self):
        """LEAKGUARD_ALLOW_MISSING=1 is only for a missing interpreter/script, never a general off switch."""
        self.install_hooks(); self.stage("f.txt", "k=" + self.TOK + "\n")
        self.assertEqual(self.commit_env(LEAKGUARD_ALLOW_MISSING="1").returncode, 1)

    def test_push_to_url_scans_commits_present_on_another_remote(self):
        """Pushing to a URL must not treat commits that exist on some OTHER remote as already published."""
        priv, pub = self.r / "priv.git", self.r / "pub.git"
        for d in (priv, pub):
            subprocess.run(["git", "init", "-q", "--bare", str(d)], check=True)
        sh(self.repo, "remote", "add", "priv", str(priv))
        self.stage("f.txt", "k=" + self.TOK + "\n"); sh(self.repo, "commit", "-qm", "leak", "--no-verify")
        sh(self.repo, "push", "-q", "--no-verify", "priv", "main")
        tip = sh(self.repo, "rev-parse", "HEAD").stdout.strip()
        for dest in ("file://" + str(pub), str(pub), "git@example.invalid:x/y.git"):
            r = self.run_hook("pre-push", dest, dest, stdin="refs/heads/main %s refs/heads/main %s\n" % (tip, "0" * 40))
            self.assertEqual(r.returncode, 1, dest)

    def test_push_scans_root_commit_even_with_showroot_false(self):
        """`log.showRoot=false` hides the root commit's diff from git log -p; the scan must pass --root."""
        sh(self.repo, "config", "log.showRoot", "false")
        sh(self.repo, "checkout", "-q", "--orphan", "o"); sh(self.repo, "rm", "-rqf", ".")
        self.stage("f.txt", "k=" + self.TOK + "\n"); sh(self.repo, "commit", "-qm", "root", "--no-verify")
        tip = sh(self.repo, "rev-parse", "HEAD").stdout.strip()
        self.assertEqual(self.push("refs/heads/o", tip, "refs/heads/o", "0" * 40, remote="nowhere").returncode, 1)

    def test_push_sensitive_name_in_quoted_path(self):
        """git quotes paths with a tab or double quote; the name check must unquote before judging the file name."""
        for d in ("d\tx", 'd"x'):
            sh(self.repo, "reset", "-q", "--hard"); self.stage(d + "/.env", "hi\n")
            sh(self.repo, "commit", "-qm", "e", "--no-verify")
            tip = sh(self.repo, "rev-parse", "HEAD").stdout.strip(); base = sh(self.repo, "rev-parse", "HEAD~1").stdout.strip()
            self.assertEqual(self.push("refs/heads/main", tip, "refs/heads/main", base).returncode, 1, repr(d))

    def test_push_scans_nul_file_and_ignores_hunk_config(self):
        """The push scan also uses --text, and repository diff config (interHunkContext, noprefix) cannot hide lines."""
        base = sh(self.repo, "rev-parse", "HEAD").stdout.strip()
        sh(self.repo, "config", "diff.interHunkContext", "100"); sh(self.repo, "config", "diff.noprefix", "true")
        self.w("f.bin", "a\0b\nk=" + self.TOK + "\n"); sh(self.repo, "add", "-A"); sh(self.repo, "commit", "-qm", "n", "--no-verify")
        tip = sh(self.repo, "rev-parse", "HEAD").stdout.strip()
        r = self.push("refs/heads/main", tip, "refs/heads/main", base)
        self.assertEqual(r.returncode, 1); self.assertIn("f.bin:", r.stderr)

    def test_sha256_zero_object_ids_mean_new_branch_and_delete(self):
        """A SHA-256 repository uses 64 zeros; they must be read as 'none', not as a commit to scan."""
        z = "0" * 64
        self.assertEqual(h.push_ranges("(delete) %s refs/heads/x abc\n" % z, "o"), [])
        self.assertEqual(h.push_ranges("refs/heads/m abc refs/heads/m %s\n" % z, "o"), [["abc", "abc", "o"]])


if __name__ == "__main__":
    unittest.main()
