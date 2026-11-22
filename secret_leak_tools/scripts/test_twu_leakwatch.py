"""Tests for scripts/twu_leakwatch.py. Every fake secret/PII value is assembled at runtime from fragments."""
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import twu_leakwatch as lw  # noqa: E402

A = "".join
FAKE = {
    "private_key": A(["-----BEGIN ", "RSA PRIV", "ATE KEY-----"]),
    "aws_access_key": A(["AK", "IA", "ABCDEFGH", "12345678"]),
    "github_token": A(["gh", "p_", "Qw3rTy" * 6]),
    "github_pat": A(["github", "_pat_", "Ab1Cd2Ef3Gh4Ij5Kl6Mn7O"]),
    "slack_token": A(["xo", "xb-", "1234567890-AbCdEfGhIj"]),
    "generic_secret": A(["api", "_key = ", "'Zq8", "Lm2Xv9Tn4Bc7Wd1'"]),
    "url_password": A(["https", "://bob:", "Hunt3rTwo9Zz", "@db.example.org/x"]),
    "jwt": A(["ey", "Jhbgcioij9", ".ey", "Jzdwiolm9x", ".sIgNaTuRe9Zq"]),
}
EIN = A(["12", "-", "3456789"])
SSN = A(["123", "-", "45", "-", "6789"])
PHONE = A(["555", "-", "014", "-", "2297"])
ADDR = A(["9921 N Fake", " Ln, Unit 7, Nowhere, ZZ 00000"])


# Neutral example zone layout used by the tests: nothing is built in, so every test configures its own zones.
ZONE_ENV = {
    "TWU_LEAKWATCH_PROFILE_DIR": "profile",
    "TWU_LEAKWATCH_PRIVATE_PREFIXES": os.pathsep.join(["profile/", "vault/"]),
    "TWU_LEAKWATCH_SYNC_PREFIXES": os.pathsep.join(["docs/", "exports/", "shared/", "inbox/", "partners/", "work/"]),
    "TWU_LEAKWATCH_OUTBOUND_GLOBS": "",
    "TWU_LEAKWATCH_BUSINESS_PREFIXES": "",
    "TWU_LEAKWATCH_ZONES_FILE": "",
    "TWU_LEAKWATCH_SKIP_DIRS": "",
}


class Tree(unittest.TestCase):
    """Tests for: Tree."""
    def setUp(self):
        """Create the scratch state this test needs."""
        self._td = tempfile.TemporaryDirectory()
        self.root = Path(self._td.name)
        self.addCleanup(self._td.cleanup)
        patcher = mock.patch.dict(os.environ, ZONE_ENV)
        patcher.start()
        self.addCleanup(patcher.stop)

    def allow(self, *args):
        """lw.cmd_allow with its console output captured (it prints a confirmation or a usage error)."""
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return lw.cmd_allow(self.root, *args)

    def zones_file(self, **lists):
        """Write the optional zones file (used when the matching env var is empty)."""
        self.put("data/health/leakwatch_zones.json", json.dumps(lists))

    def put(self, rel, text, mode="w"):
        """Helper: put."""
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if mode == "wb":
            p.write_bytes(text)
        else:
            p.write_text(text, encoding="utf-8")
        return p

    def scan(self, **kw):
        """Helper: scan."""
        return lw.scan(self.root, host="testhost", **kw)

    def pats(self, rep):
        """Helper: pats."""
        return {(h["path"], h["pattern"]) for h in rep["hits"]}


class SecretPatterns(Tree):
    """Tests for: Secret Patterns."""
    def test_each_secret_pattern(self):
        """Check that each secret pattern."""
        for key, name in [("private_key", "private_key"), ("aws_access_key", "aws_access_key"), ("github_token", "github_token"),
                          ("github_pat", "github_token"), ("slack_token", "slack_token"), ("generic_secret", "generic_secret"),
                          ("url_password", "url_password"), ("jwt", "jwt")]:
            with self.subTest(key):
                self.put("scripts/%s.txt" % key, "x\nvalue: %s\n" % FAKE[key])
                rep = self.scan(write=False)
                self.assertIn(("scripts/%s.txt" % key, name), self.pats(rep))
                h = [h for h in rep["hits"] if h["path"] == "scripts/%s.txt" % key and h["pattern"] == name][0]
                self.assertEqual(h["line"], 2)

    def test_placeholders_not_flagged(self):
        """Check that placeholders not flagged."""
        self.put("scripts/a.txt", "password = 'your-password-goes-here-123'\napi_key = ${API_KEY_FROM_ENV_1}\n")
        self.assertEqual(self.scan(write=False)["hits"], [])


class Masking(Tree):
    """Tests for: Masking."""
    def test_mask_shape(self):
        """Check that mask shape."""
        self.assertEqual(lw.mask("abcdefghijkl"), "ab...kl")
        self.assertEqual(lw.mask("short"), "****")

    def test_no_full_value_in_any_output(self):
        """Check that no full value in any output."""
        for k in ("aws_access_key", "github_token", "generic_secret", "url_password", "jwt"):
            self.put("docs/%s.md" % k, FAKE[k] + "\n")
        self.put("docs/pii.md", "ein %s ssn %s\n" % (EIN, SSN))
        self.put("profile/me.md", "| Phone | %s |\n| Address | %s |\n" % (PHONE, ADDR))
        self.put("docs/lit.md", "call %s at %s\n" % (PHONE, ADDR))
        buf = io.StringIO()
        with redirect_stdout(buf):
            rep = self.scan()
            print(lw.render(rep))
            lw.main(["--root", str(self.root), "show"]) if False else None
        blob = buf.getvalue() + (self.root / "data/health/leakwatch.testhost.json").read_text() + json.dumps(rep)
        for secret in (FAKE["aws_access_key"], FAKE["github_token"], FAKE["jwt"], "Hunt3rTwo9Zz", "Zq8Lm2Xv9Tn4Bc7Wd1",
                       EIN, SSN, PHONE, ADDR, "9921 N Fake"):
            self.assertNotIn(secret, blob)
        self.assertGreaterEqual(len(rep["hits"]), 8)


class Zones(Tree):
    """Tests for: Zones."""
    def test_private_zone_secrets_only(self):
        """Check that private zone secrets only."""
        self.put("profile/p.md", "ein %s ssn %s\nkey %s\n" % (EIN, SSN, FAKE["aws_access_key"]))
        rep = self.scan(write=False)
        self.assertEqual({(h["pattern"], h["zone"]) for h in rep["hits"]}, {("aws_access_key", "private")})
        self.assertEqual(len(rep["private_zone"]), 1)

    def test_pii_in_sync_zones_and_not_in_other(self):
        """Check that pii in sync zones and not in other."""
        for d in ("docs", "exports", "shared", "inbox", "partners", "work"):
            self.put("%s/n.md" % d, "ein %s ssn %s\n" % (EIN, SSN))
        self.put("scripts/n.md", "ein %s\n" % EIN)
        rep = self.scan(write=False)
        paths = {h["path"] for h in rep["hits"] if h["pattern"] in ("ein", "ssn")}
        self.assertEqual(paths, {d + "/n.md" for d in ("docs", "exports", "shared", "inbox", "partners", "work")})

    def test_nothing_is_built_in_without_configuration(self):
        # no zones configured: every file is zone "other", so personal data is not reported anywhere, only secrets
        """Check that nothing is built in without configuration."""
        with mock.patch.dict(os.environ, {k: "" for k in ZONE_ENV}):
            self.put("docs/n.md", "ein %s\n" % EIN)
            self.put("profile/p.md", "key %s\n" % FAKE["aws_access_key"])
            rep = self.scan(write=False)
            self.assertEqual({(h["pattern"], h["zone"]) for h in rep["hits"]}, {("aws_access_key", "other")})

    def test_zones_come_from_the_zones_file_when_env_is_empty(self):
        """Check that zones come from the zones file when env is empty."""
        with mock.patch.dict(os.environ, {k: "" for k in ZONE_ENV}):
            self.zones_file(sync_prefixes=["notes/"], private_prefixes=["secret_notes/"])
            self.put("notes/a.md", "ein %s\n" % EIN)
            self.put("secret_notes/a.md", "ein %s\n" % EIN)
            rep = self.scan(write=False)
            self.assertEqual({(h["path"], h["zone"]) for h in rep["hits"]}, {("notes/a.md", "sync")})

    def test_env_beats_the_zones_file_and_a_corrupt_file_is_ignored(self):
        """Check that env beats the zones file and a corrupt file is ignored."""
        self.zones_file(sync_prefixes=["notes/"])
        self.put("notes/a.md", "ein %s\n" % EIN)
        self.put("docs/a.md", "ein %s\n" % EIN)
        self.assertEqual({h["path"] for h in self.scan(write=False)["hits"]}, {"docs/a.md"})   # env sync list wins
        (self.root / "data/health/leakwatch_zones.json").write_text("{not json")
        self.assertEqual({h["path"] for h in self.scan(write=False)["hits"]}, {"docs/a.md"})

    def test_changing_the_zone_config_drops_the_cache(self):
        """Check that changing the zone config drops the cache."""
        self.put("docs/a.md", "ein %s\n" % EIN)
        self.scan()
        with mock.patch.dict(os.environ, {"TWU_LEAKWATCH_SYNC_PREFIXES": ""}):
            rep = self.scan()
            self.assertEqual(rep["cache"]["scanned"], 1)
            self.assertEqual(rep["hits"], [])

    def test_outbound_glob_beats_private_and_other(self):
        """Check that outbound glob beats private and other."""
        self.zones_file(outbound_globs=["profile/out.md", "site/*.html"])
        self.put("profile/out.md", "ein %s\n" % EIN)
        self.put("site/index.html", "ein %s\n" % EIN)
        rep = self.scan(write=False)
        self.assertEqual({(h["path"], h["zone"]) for h in rep["hits"]},
                         {("profile/out.md", "outbound"), ("site/index.html", "outbound")})

    def test_outbound_globs_from_env(self):
        """Check that outbound globs from env."""
        with mock.patch.dict(os.environ, {"TWU_LEAKWATCH_OUTBOUND_GLOBS": os.pathsep.join(["out/*.md", "site/**/*.html"])}):
            self.put("out/a.md", "ein %s\n" % EIN)
            self.put("site/x/y.html", "ein %s\n" % EIN)
            rep = self.scan(write=False)
            self.assertEqual({(h["path"], h["zone"]) for h in rep["hits"]}, {("out/a.md", "outbound"), ("site/x/y.html", "outbound")})

    def test_git_status_reported(self):
        """Check that git status reported."""
        self.put("docs/a.md", "ein %s\n" % EIN)
        rep = self.scan(write=False)
        self.assertIn(rep["hits"][0]["git"], ("tracked", "ignored", "untracked", "unknown"))


class Allowlist(Tree):
    """Tests for: Allowlist."""
    def test_allow_and_expiry(self):
        """Check that allow and expiry."""
        self.put("docs/a.md", "ein %s\n" % EIN)
        self.assertEqual(self.allow("docs/a.md", "ein", "public sample id", 5), 0)
        rep = self.scan(write=False)
        self.assertEqual(rep["hits"], [])
        self.assertEqual(rep["allowed_hits"][0]["allow_reason"], "public sample id")
        later = datetime.now(timezone.utc) + timedelta(days=7)
        rep = self.scan(write=False, now=later)
        self.assertEqual(len(rep["hits"]), 1)
        self.assertEqual(len(rep["expired_allow_entries"]), 1)

    def test_allow_is_specific_and_validated(self):
        """Check that allow is specific and validated."""
        self.put("docs/a.md", "ein %s ssn %s\n" % (EIN, SSN))
        self.allow("docs/a.md", "ein", "r", 3)
        self.assertEqual({h["pattern"] for h in self.scan(write=False)["hits"]}, {"ssn"})
        self.assertEqual(self.allow("docs/a.md", "bogus", "r", 3), 1)
        self.assertEqual(self.allow("docs/a.md", "ein", "", 3), 1)
        self.assertEqual(self.allow("docs/a.md", "ein", "r", 0), 1)


class Skips(Tree):
    """Tests for: Skips."""
    def test_symlink_skipped(self):
        """Check that symlink skipped."""
        outside = tempfile.TemporaryDirectory()
        self.addCleanup(outside.cleanup)
        (Path(outside.name) / "s.txt").write_text(FAKE["aws_access_key"])
        os.symlink(Path(outside.name) / "s.txt", self.root / "link.txt")
        os.symlink(outside.name, self.root / "linkdir")
        rep = self.scan(write=False)
        self.assertEqual(rep["hits"], [])
        self.assertTrue({"link.txt", "linkdir"} <= {n["path"] for n in rep["not_checked"] if n["reason"] == "symlink"})

    def test_binary_huge_and_skipped_dirs(self):
        """Binary files with a binary extension, huge files and skipped folders are not read; text hiding behind a name is."""
        self.put("a.dat", b"\0\0" + FAKE["aws_access_key"].encode(), "wb")       # NUL but no binary extension: scanned (red-team 5)
        self.put("pic.png", FAKE["aws_access_key"])                                # text saved as .png: scanned (red-team 5)
        self.put("real.png", b"\x89PNG\0\0" + FAKE["aws_access_key"].encode(), "wb")   # really binary: skipped
        self.put("node_modules/x/k.txt", FAKE["aws_access_key"])
        self.put("vendored/k.txt", FAKE["aws_access_key"])
        self.put(".git/k.txt", FAKE["aws_access_key"])
        self.put("big.txt", FAKE["aws_access_key"] + "\n" + "a" * (lw.MAX_BYTES + 10))
        rep = self.scan(write=False)
        reasons = rep["not_checked_counts"]
        self.assertEqual(reasons.get("skipped dir"), 2)       # the built-in names only; "vendored" is not one of them
        self.assertEqual(sorted(h["path"] for h in rep["hits"]), ["a.dat", "pic.png", "vendored/k.txt"])
        with mock.patch.dict(os.environ, {"TWU_LEAKWATCH_SKIP_DIRS": "vendored"}):
            rep = self.scan(write=False)
        self.assertEqual(sorted(h["path"] for h in rep["hits"]), ["a.dat", "pic.png"])
        reasons = rep["not_checked_counts"]
        self.assertEqual(reasons.get("binary"), 1)
        self.assertEqual(reasons.get("huge"), 1)
        self.assertEqual(reasons.get("skipped dir"), 3)

    def test_only_the_tools_own_files_are_exempt_from_the_sweep(self):
        """A file whose name merely starts with data/health/leakwatch must still be scanned (red-team 5: prefix skip)."""
        self.put("data/health/leakwatch_notes.txt", FAKE["aws_access_key"])
        self.put("data/health/leakwatch.testhost.json", FAKE["aws_access_key"])      # the tool's own report: exempt
        self.assertEqual([h["path"] for h in self.scan(write=False)["hits"]], ["data/health/leakwatch_notes.txt"])

    def test_nul_at_the_top_or_utf16_does_not_hide_a_secret(self):
        """One NUL byte at the top of a text file, or UTF-16 text, must not exempt the file (red-team 5)."""
        self.put("n.txt", b"\0" + FAKE["aws_access_key"].encode(), "wb")
        self.put("u16.txt", FAKE["aws_access_key"].encode("utf-16"), "wb")
        self.assertEqual(sorted(h["path"] for h in self.scan(write=False)["hits"]), ["n.txt", "u16.txt"])


class ProfileLiterals(Tree):
    """Tests for: Profile Literals."""
    def test_detects_profile_derived_literals(self):
        """Check that detects profile derived literals."""
        self.put("profile/me.md", "| Phone | %s |\n| Address | %s |\n" % (PHONE, ADDR))
        self.put("docs/x.md", "line one\nreach (555) 014 2297 now\nlives at %s\n" % ADDR.upper())
        rep = self.scan(write=False)
        got = {(h["line"], h["pattern"]) for h in rep["hits"] if h["path"] == "docs/x.md"}
        self.assertEqual(got, {(2, "profile_phone"), (3, "profile_address")})
        self.assertEqual(rep["profile_literals"]["profile_phone"], "known")

    def test_unknown_without_profile(self):
        """Check that unknown without profile."""
        self.put("docs/x.md", "reach %s\n" % PHONE)
        rep = self.scan(write=False)
        self.assertEqual(rep["hits"], [])
        self.assertIn("unknown", rep["profile_literals"]["profile_phone"])
        self.assertIn("unknown", rep["profile_literals"]["profile_address"])

    def test_empty_profile_dir_env_reads_nothing_not_the_scan_root(self):
        # an empty TWU_LEAKWATCH_PROFILE_DIR once meant "the scan root itself"; it must mean "no profile"
        """Check that empty profile dir env reads nothing not the scan root."""
        self.put("notes.md", "| Phone | %s |\n| Address | %s |\n" % (PHONE, ADDR))
        self.put("docs/x.md", "reach %s\n" % PHONE)
        with mock.patch.dict(os.environ, {"TWU_LEAKWATCH_PROFILE_DIR": ""}):
            rep = self.scan(write=False)
        self.assertEqual(rep["hits"], [])
        self.assertIn("unknown", rep["profile_literals"]["profile_phone"])
        with mock.patch.dict(os.environ):
            os.environ.pop("TWU_LEAKWATCH_PROFILE_DIR")            # unset behaves the same as empty
            self.assertIn("unknown", self.scan(write=False)["profile_literals"]["profile_phone"])

    def test_profile_dir_can_be_absolute(self):
        """Check that profile dir can be absolute."""
        elsewhere = tempfile.TemporaryDirectory(); self.addCleanup(elsewhere.cleanup)
        (Path(elsewhere.name) / "me.md").write_text("| Phone | %s |\n" % PHONE)
        self.put("docs/x.md", "reach %s\n" % PHONE)
        with mock.patch.dict(os.environ, {"TWU_LEAKWATCH_PROFILE_DIR": elsewhere.name}):
            rep = self.scan(write=False)
        self.assertEqual([(h["path"], h["pattern"]) for h in rep["hits"]], [("docs/x.md", "profile_phone")])

    def test_profile_literals_not_in_private_zone_hits(self):
        """Check that profile literals not in private zone hits."""
        self.put("profile/me.md", "| Phone | %s |\n" % PHONE)
        self.assertEqual(self.scan(write=False)["hits"], [])


class Cli(Tree):
    """Tests for: Cli."""
    def test_scan_exit_codes_and_show(self):
        """Check that scan exit codes and show."""
        self.put("scripts/ok.txt", "nothing\n")
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.assertEqual(lw.main(["--root", str(self.root), "scan"]), 0)
            self.put("scripts/bad.txt", FAKE["slack_token"])
            self.assertEqual(lw.main(["--root", str(self.root), "scan"]), 2)
            self.assertEqual(lw.main(["--root", str(self.root), "show"]), 0)
        self.assertNotIn(FAKE["slack_token"], buf.getvalue())
        self.assertFalse([p for p in (self.root / "data/health").iterdir() if p.name.endswith(".tmp")])


REAL_AWS = A(["AK", "IA", "Q7ZP4MXT", "2KJD9WRB"])
DOC_AWS = A(["AK", "IAIOSFODNN7", "EXAMPLE"])
REAL_BODY = "".join(["MIIEvQIBADANBgkqhkiG9w0BAQEFAASC", "BKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj"])


class Fixtures(Tree):
    """Tests for: Fixtures."""
    def test_doc_example_and_filler_are_fixtures_not_hits(self):
        """Check that doc example and filler are fixtures not hits."""
        self.put("docs/a.md", "key %s\ntok %s\nurl %s\n" % (
            DOC_AWS, A(["gh", "p_", "a" * 36]), A(["https", "://u:", "hunter2", "@h.org/x"])))
        rep = self.scan(write=False)
        self.assertEqual(rep["hits"], [])
        self.assertEqual(rep["fixtures"]["total"], 3)
        self.assertEqual(rep["buckets"]["fixtures"], 3)
        self.assertNotIn(DOC_AWS, json.dumps(rep))

    def test_marker_words_and_header_only_in_docs_and_tests(self):
        """Check that marker words and header only in docs and tests."""
        self.put("scripts/test_x.py", "k = '%s'\nh = '%s'\n" % (A(["Zq8", "TEST", "Lm2Xv9Tn4Bc7"]), FAKE["private_key"]))
        self.put("docs/k.md", FAKE["private_key"] + "\n")
        rep = self.scan(write=False)
        self.assertEqual(rep["hits"], [])
        self.assertGreaterEqual(rep["fixtures"]["by_reason"].get("header_only", 0), 2)

    def test_low_entropy_value_in_test_file_is_fixture(self):
        """Check that low entropy value in test file is fixture."""
        self.put("tests/test_a.py", "a = '%s'\n" % A(["AK", "IA", "ABABABAB", "ABABABAB"]))
        self.put("pkg/fixtures/data.txt", "a = '%s'\n" % A(["AK", "IA", "ABCDEFAB", "ABCDEFAB"]))
        rep = self.scan(write=False)
        self.assertEqual(rep["hits"], [])
        self.assertEqual(rep["fixtures"]["total"], 2)

    def test_real_looking_key_in_test_file_still_hit(self):
        """Check that real looking key in test file still hit."""
        for rel in ("scripts/test_real.py", "scripts/real_test.py", "tests/a.py", "fixtures/a.txt"):
            self.put(rel, "k = '%s'\n" % REAL_AWS)
        rep = self.scan(write=False)
        self.assertEqual(len(rep["hits"]), 4)
        self.assertEqual(rep["fixtures"]["total"], 0)

    def test_private_key_with_body_in_test_file_still_hit(self):
        """Check that private key with body in test file still hit."""
        self.put("scripts/test_k.py", FAKE["private_key"] + "\n" + REAL_BODY + "\n")
        self.assertEqual([h["pattern"] for h in self.scan(write=False)["hits"]], ["private_key"])


class SavedThirdParty(Tree):
    """Tests for: Saved Third Party."""
    def test_pii_counted_not_hit_but_secrets_hit(self):
        """Check that pii counted not hit but secrets hit."""
        self.put("profile/me.md", "| Phone | %s |\n" % PHONE)
        self.put("saved_pages/P1/a.html.txt", "ein %s call %s key %s ssn %s\n" % (EIN, PHONE, REAL_AWS, SSN))
        self.put("inbox/page.mhtml", "ein %s\n" % EIN)
        self.put("docs/saved.md", "<!-- saved from url=(0022)http://x.org/ -->\nein %s\n" % EIN)
        rep = self.scan(write=False)
        self.assertEqual({(h["path"], h["pattern"]) for h in rep["hits"]},
                         {("saved_pages/P1/a.html.txt", "aws_access_key"),
                          ("saved_pages/P1/a.html.txt", "ssn")})
        self.assertEqual(rep["saved_third_party"]["by_pattern"], {"ein": 3, "profile_phone": 1})
        self.assertEqual(rep["buckets"]["saved_third_party"], 4)

    def test_outbound_beats_saved_zone(self):
        """Check that outbound beats saved zone."""
        self.zones_file(outbound_globs=["saved_pages/out.md"])
        self.put("saved_pages/out.md", "ein %s\n" % EIN)
        self.assertEqual(len(self.scan(write=False)["hits"]), 1)


class Policy(Tree):
    """Tests for: Policy."""
    def setUp(self):
        """Create the scratch state this test needs."""
        super().setUp()
        self.put("profile/me.md", "| Phone | %s |\n| Address | %s |\n" % (PHONE, ADDR))
        self.put("shared/a.md", "call %s\n" % PHONE)
        self.put("shared/b.md", "call %s at %s\n" % (PHONE, ADDR))

    def pol(self, exp, lits=("phone",)):
        """Helper: pol."""
        self.put("data/health/leakwatch_policy.json", json.dumps({"allow_personal": [
            {"path_glob": "shared/*.md", "literals": list(lits), "reason": "business line", "expires": exp}]}))

    def test_uncovered_literals_are_hits(self):
        """Check that uncovered literals are hits."""
        rep = self.scan(write=False)
        self.assertEqual(len(rep["hits"]), 3)

    def test_policy_covers_only_listed_literal_and_glob(self):
        """Check that policy covers only listed literal and glob."""
        self.pol((datetime.now(timezone.utc) + timedelta(days=5)).strftime("%Y-%m-%d"))
        rep = self.scan(write=False)
        self.assertEqual({(h["path"], h["pattern"]) for h in rep["hits"]}, {("shared/b.md", "profile_address")})
        self.assertEqual(rep["policy_allowed"]["by_pattern"], {"profile_phone": 2})

    def test_expired_policy_does_not_cover(self):
        """Check that expired policy does not cover."""
        self.pol("2020-01-01")
        self.assertEqual(len(self.scan(write=False)["hits"]), 3)

    def test_propose_policy_has_paths_and_counts_only(self):
        """Check that propose policy has paths and counts only."""
        self.put("docs/z.md", "call %s\n" % PHONE)
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.assertEqual(lw.main(["--root", str(self.root), "propose-policy"]), 0)
        txt = (self.root / lw.PROPOSED_REL).read_text()
        self.assertNotIn(PHONE, txt); self.assertNotIn("9921", txt)
        groups = {g["directory"]: g for g in json.loads(txt)["groups"]}
        self.assertEqual(groups["shared"]["suggested_class"], "review")  # b.md has an address
        self.assertEqual(groups["docs"]["suggested_class"], "review")
        self.assertNotIn("owner", json.loads(txt)["note"].lower())
        self.assertFalse((self.root / lw.POLICY_REL).exists())


    def test_business_prefixes_make_phone_only_groups_intended(self):
        """Check that business prefixes make phone only groups intended."""
        (self.root / "shared/b.md").unlink()
        with mock.patch.dict(os.environ, {"TWU_LEAKWATCH_BUSINESS_PREFIXES": "shared/"}):
            with redirect_stdout(io.StringIO()):
                self.assertEqual(lw.main(["--root", str(self.root), "propose-policy"]), 0)
        groups = {g["directory"]: g for g in json.loads((self.root / lw.PROPOSED_REL).read_text())["groups"]}
        self.assertEqual(groups["shared"]["suggested_class"], "probably intended business contact")


class GitPath(Tree):
    """Tests for: Git Path."""
    def test_git_is_absolute_or_absent_and_empty_env_uses_default(self):
        """Check that git is absolute or absent and empty env uses default."""
        with mock.patch.dict(os.environ, {"TWU_GIT": ""}):
            self.assertTrue(lw.git_executable() is None or os.path.isabs(lw.git_executable()))
        with mock.patch.dict(os.environ, {"TWU_GIT": "git"}):
            self.assertIsNone(lw.git_executable())
        self.put("docs/a.md", "ein %s\n" % EIN)
        with mock.patch.dict(os.environ, {"TWU_GIT": "/nonexistent/git"}):
            rep = self.scan(write=False)
        self.assertEqual(rep["hits"][0]["git"], "unknown")      # git unavailable: reported as unknown, never a crash


class Incremental(Tree):
    """Tests for: Incremental."""
    def test_cache_reuse_invalidate_and_delete(self):
        """Check that cache reuse invalidate and delete."""
        self.put("scripts/a.txt", "value: %s\n" % FAKE["slack_token"])
        self.put("scripts/b.txt", "clean\n")
        r1 = self.scan()
        self.assertEqual(r1["cache"]["scanned"], 2)
        r2 = self.scan()
        self.assertEqual((r2["cache"]["scanned"], r2["cache"]["cached"]), (0, 2))
        self.assertEqual(r2["hits"], r1["hits"])
        self.assertEqual(len(r2["hits"]), 1)
        cache_txt = (self.root / lw.CACHE_REL).read_text()
        self.assertNotIn(FAKE["slack_token"], cache_txt)
        p = self.put("scripts/b.txt", "clean but longer now\n" + FAKE["aws_access_key"] + "\n")
        r3 = self.scan()
        self.assertEqual((r3["cache"]["scanned"], len(r3["hits"])), (1, 2))
        p.unlink()
        self.scan()
        self.assertNotIn("scripts/b.txt", json.loads((self.root / lw.CACHE_REL).read_text())["files"])

    def test_rule_hash_change_drops_cache(self):
        """Check that rule hash change drops cache."""
        self.put("scripts/a.txt", "x\n")
        self.scan()
        cp = self.root / lw.CACHE_REL
        d = json.loads(cp.read_text()); d["rules"] = "stale"; cp.write_text(json.dumps(d))
        self.assertEqual(self.scan()["cache"]["scanned"], 1)

    def test_changed_mode_scans_recent_and_unseen_only(self):
        """Check that changed mode scans recent and unseen only."""
        a = self.put("scripts/a.txt", "x\n")
        os.utime(a, (1_000_000_000, 1_000_000_000))
        self.scan()
        a.write_text("value: %s\n" % FAKE["slack_token"])
        os.utime(a, (1_000_000_001, 1_000_000_001))   # changed, but outside the window
        self.put("scripts/new.txt", "y\n")             # unseen
        rep = lw.scan(self.root, host="testhost", since_minutes=10)
        self.assertEqual(rep["cache"]["scanned"], 1)
        self.assertEqual(rep["hits"], [])               # stale-by-design: old file trusted from cache
        os.utime(a, None)                               # now recent
        rep = lw.scan(self.root, host="testhost", since_minutes=10)
        self.assertEqual(len(rep["hits"]), 1)
        self.assertTrue((self.root / "data/health/leakwatch.testhost.json").exists())

    def test_cli_changed_exit_codes(self):
        """Check that cli changed exit codes."""
        self.put("scripts/a.txt", "ok\n")
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.assertEqual(lw.main(["--root", str(self.root), "scan", "--changed", "--since-minutes", "5"]), 0)
            self.put("scripts/b.txt", FAKE["slack_token"])
            self.assertEqual(lw.main(["--root", str(self.root), "scan", "--changed", "--since-minutes", "5"]), 2)
        self.assertNotIn(FAKE["slack_token"], buf.getvalue())

    def test_tool_error_exit_3(self):
        """Check that tool error exit 3."""
        self.put("x.txt", "x")
        orig = lw.scan
        lw.scan = lambda *a, **k: (_ for _ in ()).throw(OSError("boom"))
        self.addCleanup(setattr, lw, "scan", orig)
        err = io.StringIO()
        with redirect_stderr(err):
            self.assertEqual(lw.main(["--root", str(self.root), "scan"]), 3)


class Gate(Tree):
    """Tests for: Gate."""
    def run_gate(self, *paths):
        """Helper: run gate."""
        buf = io.StringIO()
        with redirect_stdout(buf), redirect_stderr(io.StringIO()):
            rc = lw.main(["--root", str(self.root), "gate"] + [str(self.root / p) for p in paths])
        return rc, buf.getvalue()

    def test_clean_document_passes(self):
        """Check that clean document passes."""
        self.put("out/a.md", "Plain text.\n")
        self.assertEqual(self.run_gate("out/a.md")[0], 0)

    def test_blocks_secrets_literals_and_placeholders_masked(self):
        """Check that blocks secrets literals and placeholders masked."""
        self.put("profile/me.md", "| Phone | %s |\n" % PHONE)
        self.put("out/a.md", "TODO fix\nLorem Ipsum dolor\nmail example@" "x.org\ncall %s\nk %s\nd %s\n" % (
            PHONE, REAL_AWS, DOC_AWS))
        rc, out = self.run_gate("out/a.md")
        self.assertEqual(rc, 2)
        for pat in ("todo", "lorem_ipsum", "example_email", "profile_phone", "aws_access_key", "aws_access_key(placeholder)"):
            self.assertIn(pat, out)
        for v in (PHONE, REAL_AWS, DOC_AWS):
            self.assertNotIn(v, out)
        self.assertIn("out/a.md:4", out)

    def test_policy_exempts_personal_literal_in_gate(self):
        """Check that policy exempts personal literal in gate."""
        self.put("profile/me.md", "| Phone | %s |\n" % PHONE)
        self.put("out/a.md", "call %s\n" % PHONE)
        self.put("data/health/leakwatch_policy.json", json.dumps({"allow_personal": [
            {"path_glob": "out/*.md", "literals": ["phone"], "reason": "r", "expires": "2999-01-01"}]}))
        self.assertEqual(self.run_gate("out/a.md")[0], 0)

    def test_missing_path_exit_3_and_directory_ok(self):
        """Check that missing path exit 3 and directory ok."""
        self.put("out/a.md", "TODO\n")
        self.assertEqual(self.run_gate("nope.md")[0], 3)
        self.assertEqual(self.run_gate("out")[0], 2)


if __name__ == "__main__":
    unittest.main()
