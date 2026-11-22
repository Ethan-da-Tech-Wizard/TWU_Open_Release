import io, json, sys, tempfile, time, unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import twu_autonomy as a


def rule(rid, cls, match, **kw):
    """Helper: rule."""
    d = {"id": rid, "class": cls, "match": match, "reason": "r", "source": "s"}
    d.update(kw)
    return d


class T(unittest.TestCase):
    """Tests for: T."""
    def setUp(self):
        """Create the scratch state this test needs."""
        self.td = tempfile.TemporaryDirectory()
        self.root = Path(self.td.name)
        (self.root / "data/health").mkdir(parents=True)

    def tearDown(self):
        """Remove the scratch state this test created."""
        self.td.cleanup()

    def write(self, rules, raw=None):
        """Helper: write."""
        a.policy_path(self.root).write_text(raw if raw is not None else json.dumps({"rules": rules}))

    def d(self, action, **kw):
        """Helper: d."""
        return a.decide(action, self.root, "h", **kw)

    def test_seed_classification(self):
        """Check that seed classification."""
        for act, want in (("refresh_knowledge_index", "AUTO"), ("run_integrity", "AUTO"), ("run_leakwatch_changed_scan", "AUTO"),
                          ("rotate_own_logs", "AUTO"), ("regenerate_skeleton_catalog", "AUTO"),
                          ("install_software", "PROPOSE"), ("git_commit", "PROPOSE"), ("upload_data", "PROPOSE"),
                          ("delete_model_weights", "NEVER"), ("send_telemetry", "NEVER"), ("bypass_stop_latch", "NEVER"),
                          ("pay_money", "NEVER")):
            self.assertEqual(self.d(act), want, act)

    # The shipped example policy (data/health/autonomy_policy.json) must list exactly the built-in seed rules, so the
    # file and the code cannot drift apart. The test is skipped only if someone deletes the example file.
    @unittest.skipUnless((Path(__file__).resolve().parent.parent / "data/health/autonomy_policy.json").is_file(),
                         "no data/health/autonomy_policy.json next to scripts/")
    def test_seed_file_matches_builtin_seed(self):
        """Check that seed file matches builtin seed."""
        doc = json.loads((Path(__file__).resolve().parent.parent / "data/health/autonomy_policy.json").read_text())
        self.assertEqual([r["id"] for r in doc["rules"]], [r["id"] for r in a.SEED_RULES])
        for r in doc["rules"]:
            self.assertTrue(r["source"] and r["reason"])

    def test_unknown_is_propose(self):
        """Check that unknown is propose."""
        self.assertEqual(self.d("brand_new_thing"), "PROPOSE")
        self.assertEqual(self.d("bad action with spaces; rm -rf"), "PROPOSE")

    def test_glob_precedence_never_beats_propose_beats_auto(self):
        """Check that glob precedence never beats propose beats auto."""
        self.write([rule("a", "AUTO", "do_*"), rule("p", "PROPOSE", "do_x*"), rule("n", "NEVER", "do_xy"),
                    ] + [dict(r) for r in a.SEED_NEVER.values()])
        self.assertEqual(self.d("do_a"), "AUTO")
        self.assertEqual(self.d("do_xa"), "PROPOSE")
        self.assertEqual(self.d("do_xy"), "NEVER")

    def test_expiry(self):
        """Check that expiry."""
        rules = [dict(r) for r in a.SEED_NEVER.values()]
        self.write(rules + [rule("old", "AUTO", "tmp_job", expires="2000-01-01"),
                            rule("new", "AUTO", "tmp_job2", expires="2999-01-01")])
        self.assertEqual(self.d("tmp_job"), "PROPOSE")  # expired AUTO ignored
        self.assertEqual(self.d("tmp_job2"), "AUTO")

    def test_expired_propose_rule_does_not_unblock_never(self):
        """Check that expired propose rule does not unblock never."""
        rules = [dict(r) for r in a.SEED_NEVER.values()] + [rule("x", "PROPOSE", "pay_money", expires="2000-01-01")]
        self.write(rules)
        self.assertEqual(self.d("pay_money"), "NEVER")

    def test_malformed_policy_fails_closed(self):
        """Check that malformed policy fails closed."""
        for raw in ("{not json", "[]", json.dumps({"rules": "x"}), json.dumps({"rules": [{"id": "a"}]}),
                    json.dumps({"rules": [rule("a", "MAYBE", "x")]}),
                    json.dumps({"rules": [rule("a", "AUTO", "x", expires="soon")]})):
            self.write(None, raw)
            self.assertEqual(self.d("refresh_knowledge_index"), "PROPOSE", raw)
            self.assertEqual(self.d("run_integrity"), "PROPOSE", raw)

    def test_never_cannot_be_widened_silently(self):
        """Check that never cannot be widened silently."""
        rules = [r for r in map(dict, a.SEED_RULES) if r["id"] != "never-weights-delete"]
        rules.append(rule("never-weights-delete", "AUTO", "delete_model_weights*"))
        self.write(rules)
        self.assertEqual(self.d("delete_model_weights"), "NEVER")
        _, problems, _ = a.load_policy(self.root)
        self.assertTrue(problems)
        # removal is also restored
        self.write([r for r in a.SEED_RULES if r["id"] != "never-pay"])
        self.assertEqual(self.d("pay_money"), "NEVER")

    def test_never_widening_needs_flag_and_future_expiry(self):
        """Check that never widening needs flag and future expiry."""
        base = [r for r in map(dict, a.SEED_RULES) if r["id"] != "never-pay"]
        self.write(base + [rule("never-pay", "PROPOSE", "pay_money*", explicit_widen=True, expires="2999-01-01")])
        self.assertEqual(self.d("pay_money"), "PROPOSE")
        self.write(base + [rule("never-pay", "PROPOSE", "pay_money*", explicit_widen=True)])  # no expiry
        self.assertEqual(self.d("pay_money"), "NEVER")
        self.write(base + [rule("never-pay", "PROPOSE", "pay_money*", explicit_widen=True, expires="2000-01-01")])  # lapsed
        self.assertEqual(self.d("pay_money"), "NEVER")

    def test_log_append_only_no_secrets_and_rotates(self):
        """Check that log append only no secrets and rotates."""
        self.d("refresh_knowledge_index")
        self.d("secret_token_sk-ABCDEF123456 and password=hunter2")
        text = a.log_path(self.root, "h").read_text()
        rows = [json.loads(x) for x in text.splitlines()]
        self.assertEqual(len(rows), 2)
        self.assertEqual(sorted(rows[0]), ["action", "class", "rule", "time"])
        self.assertNotIn("hunter2", text)
        self.assertNotIn("sk-ABCDEF", text)
        self.assertEqual(rows[1]["action"], "invalid")
        a.LOG_CAP, old = 300, a.LOG_CAP
        try:
            for _ in range(20):
                self.d("run_integrity")
        finally:
            a.LOG_CAP = old
        lp = a.log_path(self.root, "h")
        self.assertTrue(Path(str(lp) + ".1").exists())
        self.assertLess(lp.stat().st_size, 400)

    def test_cli_exit_codes(self):
        """Check that cli exit codes."""
        def run(*args):
            """Helper: run."""
            out = io.StringIO()
            with redirect_stdout(out), redirect_stderr(io.StringIO()):
                rc = a.main(list(args), root=self.root)
            return rc, out.getvalue()
        rc, out = run("check", "refresh_knowledge_index")
        self.assertEqual(rc, 0)
        self.assertIn("source:", out)
        self.assertEqual(run("check", "install_software")[0], 3)
        self.assertEqual(run("check", "delete_model_weights")[0], 4)
        self.assertEqual(run("check", "no way; ls")[0], 2)
        self.assertEqual(run("check")[0], 2)
        self.assertEqual(run("list")[0], 0)
        self.assertIn("never-pay", run("explain", "pay_money")[1])
        self.assertIn("refresh_knowledge_index", run("log")[1])

    def test_empty_twu_root_falls_back_to_the_component_folder(self):
        """Check that empty twu root falls back to the component folder."""
        import os, subprocess
        env = dict(os.environ, TWU_ROOT="", PYTHONPATH=str(Path(__file__).resolve().parent))
        out = subprocess.run([sys.executable, "-B", "-c", "import twu_autonomy as a; print(a.REPO)"],
                             env=env, capture_output=True, text=True, timeout=20)
        self.assertEqual(out.stdout.strip(), str(Path(__file__).resolve().parent.parent))


class RedTeam5(T):
    """Seat-5 bypass hunt regressions."""
    def test_expired_seed_never_rule_is_restored(self):
        """A seeded NEVER rule kept verbatim but with a past 'expires' used to be ignored by classify (NEVER switched off)."""
        seed = dict(a.SEED_NEVER["never-bypass-stop"], expires="2000-01-01")
        self.write([seed])
        rules, problems, state = a.load_policy(self.root)
        self.assertEqual(self.d("bypass_stop_now"), "NEVER")
        self.assertTrue(any("never-bypass-stop" in p for p in problems), problems)
        # even with a broader AUTO rule that matches the same action, NEVER must win
        self.write([seed, rule("auto-all", "AUTO", "*")])
        self.assertEqual(self.d("bypass_stop_now"), "NEVER")

    def test_trailing_newline_is_not_a_valid_action_name(self):
        """'$' matches before a final newline; an action name with a trailing newline is invalid (needs approval)."""
        self.write([rule("auto-x", "AUTO", "run_x*")])
        self.assertEqual(self.d("run_x"), "AUTO")
        self.assertEqual(self.d("run_x\n"), "PROPOSE")


if __name__ == "__main__":
    unittest.main()
