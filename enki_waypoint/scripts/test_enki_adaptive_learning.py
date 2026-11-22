import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import enki_adaptive_learning as al


class BKTTests(unittest.TestCase):
    """Tests for: BKTTests."""
    def test_probability_and_correct_update_match_bkt_equations(self):
        """Check that probability and correct update match bkt equations."""
        p = al.BKTParameters(prior=0.2, learn=0.12, guess=0.2, slip=0.1)
        self.assertAlmostEqual(al.bkt_probability_correct(0.2, p.guess, p.slip), 0.34)
        expected = (0.2 * 0.9 / 0.34) + (1 - (0.2 * 0.9 / 0.34)) * 0.12
        self.assertAlmostEqual(al.bkt_update(0.2, True, p), expected)

    def test_incorrect_update_uses_bayes_and_learning_transition(self):
        """Check that incorrect update uses bayes and learning transition."""
        p = al.BKTParameters(prior=0.2, learn=0.12, guess=0.2, slip=0.1)
        posterior = (0.2 * 0.1) / 0.66
        self.assertAlmostEqual(al.bkt_update(0.2, False, p), posterior + (1 - posterior) * 0.12)

    def test_parameters_and_probabilities_are_bounded(self):
        """Check that parameters and probabilities are bounded."""
        with self.assertRaises(ValueError):
            al.BKTParameters(guess=1.0).validate()
        with self.assertRaises(ValueError):
            al.bkt_probability_correct(float("nan"), 0.2, 0.1)


class LinUCBTests(unittest.TestCase):
    """Tests for: Lin UCBTests."""
    def test_safe_task_selection_uses_need_and_excludes_unsafe_tasks(self):
        """Check that safe task selection uses need and excludes unsafe tasks."""
        learner = al.AdaptiveLearner(alpha=0.0)
        need = al.PracticeTask("needed", "math", need=1, expected_gain=1)
        distractor = al.PracticeTask("low-need", "math", need=0, expected_gain=0)
        unsafe = al.PracticeTask("unsafe", "math", need=1, expected_gain=1, safe=False)
        arm = learner.bandit._arm("needed")
        arm["b"] = [0, 4, 0, 0, 0]
        self.assertEqual(learner.choose([distractor, unsafe, need]).task_id, "needed")

    def test_mastery_and_configuration_inputs_are_validated(self):
        """Check that mastery and configuration inputs are validated."""
        task = al.PracticeTask("task", "math", need=0.5, expected_gain=0.5)
        for mastery in (-0.1, 1.1, float("nan"), True):
            with self.subTest(mastery=mastery), self.assertRaises(ValueError):
                task.features(mastery)
        for kwargs in ({"dimension": True}, {"dimension": 1.5}, {"alpha": "high"}, {"risk_penalty": True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                al.LinUCB(**kwargs)
        with self.assertRaises(ValueError):
            al.PracticeTask("task", "math", 0.5, 0.5, safe=1)
        with self.assertRaises(ValueError):
            al.bkt_update(0.5, 1, al.BKTParameters())
        with self.assertRaises(ValueError):
            al.LinUCB().score("task", [1, True, 0, 0, 1])

    def test_no_safe_tasks_fails_closed(self):
        """Check that no safe tasks fails closed."""
        learner = al.AdaptiveLearner()
        with self.assertRaisesRegex(ValueError, "no safe"):
            learner.choose([al.PracticeTask("bad", "math", 0.5, 0.5, safe=False)])

    def test_task_and_skill_identifiers_cannot_be_free_text(self):
        """Check that task and skill identifiers cannot be free text."""
        learner = al.AdaptiveLearner()
        with self.assertRaisesRegex(ValueError, "non-content"):
            learner.choose([al.PracticeTask("my full prompt", "math", 0.5, 0.5)])
        with self.assertRaisesRegex(ValueError, "non-content"):
            learner.mastery_for("my private skill description")

    def test_unverified_outcome_does_not_update_either_learner(self):
        """Check that unverified outcome does not update either learner."""
        learner = al.AdaptiveLearner()
        task = al.PracticeTask("task-1", "math", 0.8, 0.7)
        with self.assertRaisesRegex(ValueError, "verified"):
            learner.observe(task, True, 1.0, verified=False)
        self.assertEqual(learner.mastery, {})
        self.assertEqual(learner.bandit.arms, {})

    def test_verified_outcome_updates_mastery_and_bandit(self):
        """Check that verified outcome updates mastery and bandit."""
        learner = al.AdaptiveLearner()
        task = al.PracticeTask("task-1", "math", 0.8, 0.7)
        mastery = learner.observe(task, True, 1.0, verified=True)
        self.assertGreater(mastery, learner.parameters.prior)
        self.assertIn("task-1", learner.bandit.arms)
        self.assertGreater(learner.bandit.score("task-1", task.features(mastery)), 0)

    def test_cost_and_risk_reduce_selection_score(self):
        """Check that cost and risk reduce selection score."""
        learner = al.AdaptiveLearner(alpha=0.0)
        expensive = al.PracticeTask("expensive", "skill", 0.5, 0.7, time_cost=0.4, compute_cost=0.3, risk=0.2)
        cheap = al.PracticeTask("cheap", "skill", 0.5, 0.7)
        self.assertEqual(learner.choose([expensive, cheap]).task_id, "cheap")


class PrivateStateTests(unittest.TestCase):
    """Tests for: Private State Tests."""
    def setUp(self):
        """Create the scratch state this test needs."""
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve() / "private" / "malakopia" / "training" / "adaptive_state"
        self.root.mkdir(parents=True)
        self.patcher = mock.patch.object(al, "PRIVATE_STATE_ROOT", self.root)
        self.patcher.start()

    def tearDown(self):
        """Remove the scratch state this test created."""
        self.patcher.stop()
        self.tmp.cleanup()

    def test_private_state_round_trip_contains_metadata_only_and_mode_0600(self):
        """Check that private state round trip contains metadata only and mode 0600."""
        learner = al.AdaptiveLearner()
        task = al.PracticeTask("task-42", "fractions", 0.9, 0.8)
        learner.observe(task, True, 1.0, verified=True)
        saved = learner.save_private()
        self.assertEqual(saved.stat().st_mode & 0o777, 0o600)
        payload = json.loads(saved.read_text())
        self.assertEqual(payload["schema"], al.STATE_SCHEMA)
        self.assertNotIn("prompt", json.dumps(payload).lower())
        loaded = al.AdaptiveLearner.load_private()
        self.assertEqual(loaded.mastery, learner.mastery)
        self.assertEqual(loaded.bandit.arms, learner.bandit.arms)

    def test_external_state_path_is_rejected(self):
        """Check that external state path is rejected."""
        with self.assertRaisesRegex(ValueError, "only be stored"):
            al.AdaptiveLearner().save_private(Path(self.tmp.name) / "public.json")

    def test_symlinked_state_target_is_rejected(self):
        """Check that symlinked state target is rejected."""
        target = Path(self.tmp.name) / "target.json"
        target.write_text("{}\n")
        link = self.root / "learner.json"
        link.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "symlinks"):
            al.AdaptiveLearner().save_private(link)

    def test_malformed_or_nonfinite_state_is_rejected(self):
        """Check that malformed or nonfinite state is rejected."""
        path = self.root / "learner.json"
        os.chmod(self.root, 0o700)
        path.write_text(json.dumps({"schema": al.STATE_SCHEMA, "parameters": {}, "mastery": {"x": float("nan")},
                                    "bandit": {"alpha": 0.5, "dimension": 7, "arms": {}}}))
        with self.assertRaises(ValueError):
            al.AdaptiveLearner.load_private(path)

    def test_malformed_outer_shapes_always_raise_value_error(self):
        """Check that malformed outer shapes always raise value error."""
        os.chmod(self.root, 0o700)
        path = self.root / "learner.json"
        for payload in ("null", "[]", "{}", json.dumps({"schema": al.STATE_SCHEMA, "parameters": {},
                                                             "mastery": {}, "bandit": []})):
            path.write_text(payload)
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                al.AdaptiveLearner.load_private(path)

    def test_save_repairs_existing_permissive_state_directory(self):
        """Check that save repairs existing permissive state directory."""
        os.chmod(self.root, 0o777)
        saved = al.AdaptiveLearner().save_private()
        self.assertEqual(self.root.stat().st_mode & 0o777, 0o700)
        self.assertEqual(saved.stat().st_mode & 0o777, 0o600)

    def test_load_rejects_permissive_state_directory(self):
        """Check that load rejects permissive state directory."""
        path = self.root / "learner.json"
        path.write_text("{}")
        with self.assertRaisesRegex(ValueError, "mode 0700"):
            al.AdaptiveLearner.load_private(path)


class EmptyEnvTests(unittest.TestCase):
    """Tests for: Empty Env Tests."""
    def test_empty_state_root_variable_falls_back_to_the_default(self):
        """Check that empty state root variable falls back to the default."""
        import subprocess
        env = dict(os.environ, ENKI_ADAPTIVE_STATE_ROOT="", PYTHONPATH=str(HERE))
        out = subprocess.run([sys.executable, "-B", "-c", "import enki_adaptive_learning as m; print(m.PRIVATE_STATE_ROOT)"],
                             env=env, capture_output=True, text=True, timeout=20)
        self.assertEqual(out.stdout.strip(), str(HERE.parent / "state"))


if __name__ == "__main__":
    unittest.main()
