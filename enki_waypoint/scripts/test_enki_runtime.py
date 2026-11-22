#!/usr/bin/env python3
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
import enki_runtime as runtime


class EnkiRuntimeRecommendationTests(unittest.TestCase):
    """Tests for: Enki Runtime Recommendation Tests."""
    def setUp(self):
        """Create the scratch state this test needs."""
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve() / "private" / "malakopia" / "training" / "adaptive_state"
        self.root.mkdir(parents=True)
        os.chmod(self.root, 0o700)
        self.patcher = mock.patch.object(al, "PRIVATE_STATE_ROOT", self.root)
        self.patcher.start()

    def tearDown(self):
        """Remove the scratch state this test created."""
        self.patcher.stop()
        self.tmp.cleanup()

    def test_recommend_task_selects_highest_need_candidate(self):
        """Check that recommend task selects highest need candidate."""
        candidates = [
            {"task_id": "low-need", "skill": "testing", "need": 0.1, "expected_gain": 0.1},
            {"task_id": "high-need", "skill": "testing", "need": 0.9, "expected_gain": 0.8},
        ]
        rec = runtime.recommend_task(candidates)
        self.assertEqual(rec["schema"], runtime.SCHEMA_RECOMMENDATION)
        self.assertEqual(rec["task_id"], "high-need")
        self.assertEqual(rec["skill"], "testing")
        self.assertAlmostEqual(rec["mastery"], 0.2)
        self.assertGreater(rec["score"], 0)

    def test_recommend_task_excludes_unsafe_candidates(self):
        """Check that recommend task excludes unsafe candidates."""
        candidates = [
            {"task_id": "unsafe-task", "skill": "deploy", "need": 0.9, "expected_gain": 0.9, "safe": False},
            {"task_id": "safe-task", "skill": "deploy", "need": 0.5, "expected_gain": 0.5, "safe": True},
        ]
        rec = runtime.recommend_task(candidates)
        self.assertEqual(rec["task_id"], "safe-task")

    def test_recommend_task_refuses_empty_candidates(self):
        """Check that recommend task refuses empty candidates."""
        with self.assertRaisesRegex(ValueError, "no candidate tasks"):
            runtime.recommend_task([])

    def test_recommend_task_validates_candidate_fields(self):
        """Check that recommend task validates candidate fields."""
        with self.assertRaisesRegex(ValueError, "task_id"):
            runtime.recommend_task([{"task_id": "bad task id!", "skill": "testing", "need": 0.5, "expected_gain": 0.5}])
        with self.assertRaisesRegex(ValueError, "need"):
            runtime.recommend_task([{"task_id": "valid-id", "skill": "testing"}])


class EnkiRuntimeRecordOutcomeTests(unittest.TestCase):
    """Tests for: Enki Runtime Record Outcome Tests."""
    def setUp(self):
        """Create the scratch state this test needs."""
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve() / "private" / "malakopia" / "training" / "adaptive_state"
        self.root.mkdir(parents=True)
        os.chmod(self.root, 0o700)
        self.patcher = mock.patch.object(al, "PRIVATE_STATE_ROOT", self.root)
        self.patcher.start()

    def tearDown(self):
        """Remove the scratch state this test created."""
        self.patcher.stop()
        self.tmp.cleanup()

    def test_record_outcome_updates_bkt_mastery_and_persists_privately(self):
        """Check that record outcome updates bkt mastery and persists privately."""
        res = runtime.record_outcome("task-101", correct=True, reward=1.0, verified=True, skill="regex")
        self.assertEqual(res["schema"], runtime.SCHEMA_OUTCOME)
        self.assertEqual(res["task_id"], "task-101")
        self.assertEqual(res["skill"], "regex")
        self.assertTrue(res["verified"])
        self.assertAlmostEqual(res["mastery_before"], 0.2)
        self.assertGreater(res["mastery_after"], 0.2)

        # Confirm persisted state on disk
        saved = Path(res["saved_path"])
        self.assertTrue(saved.is_file())
        self.assertEqual(saved.stat().st_mode & 0o777, 0o600)
        state = json.loads(saved.read_text())
        self.assertIn("regex", state["mastery"])
        self.assertEqual(state["mastery"]["regex"], res["mastery_after"])

    def test_record_outcome_incorrect_decreases_mastery(self):
        # Set a higher prior or multiple correct updates first
        """Check that record outcome incorrect decreases mastery."""
        res1 = runtime.record_outcome("task-101", correct=True, reward=1.0, verified=True, skill="math")
        self.assertGreater(res1["mastery_after"], 0.2)
        res2 = runtime.record_outcome("task-101", correct=False, reward=0.0, verified=True, skill="math")
        self.assertLess(res2["mastery_after"], res1["mastery_after"])

    def test_record_outcome_refuses_free_text_identifiers(self):
        """Check that record outcome refuses free text identifiers."""
        with self.assertRaisesRegex(ValueError, "non-content"):
            runtime.record_outcome("my free text prompt task id", correct=True, reward=1.0, verified=True, skill="math")
        with self.assertRaisesRegex(ValueError, "non-content"):
            runtime.record_outcome("task-1", correct=True, reward=1.0, verified=True, skill="private prompt skill text")

    def test_record_outcome_refuses_unverified_results(self):
        """Check that record outcome refuses unverified results."""
        with self.assertRaisesRegex(ValueError, "verified=True"):
            runtime.record_outcome("task-101", correct=True, reward=1.0, verified=False, skill="regex")

    def test_record_outcome_refuses_non_boolean_correctness(self):
        """Check that record outcome refuses non boolean correctness."""
        with self.assertRaisesRegex(ValueError, "verified boolean"):
            runtime.record_outcome("task-101", correct="yes", reward=1.0, verified=True, skill="regex")

    def test_record_outcome_refuses_invalid_reward(self):
        """Check that record outcome refuses invalid reward."""
        with self.assertRaisesRegex(ValueError, "reward"):
            runtime.record_outcome("task-101", correct=True, reward=1.5, verified=True, skill="regex")
        with self.assertRaisesRegex(ValueError, "reward"):
            runtime.record_outcome("task-101", correct=True, reward=-0.1, verified=True, skill="regex")


class EnkiRuntimeWaypointReceiptTests(unittest.TestCase):
    """Tests for: Enki Runtime Waypoint Receipt Tests."""
    def setUp(self):
        """Create the scratch state this test needs."""
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve() / "private" / "malakopia" / "training" / "adaptive_state"
        self.root.mkdir(parents=True)
        os.chmod(self.root, 0o700)
        self.patcher = mock.patch.object(al, "PRIVATE_STATE_ROOT", self.root)
        self.patcher.start()

    def tearDown(self):
        """Remove the scratch state this test created."""
        self.patcher.stop()
        self.tmp.cleanup()

    def test_record_waypoint_receipt_accepted(self):
        """Check that record waypoint receipt accepted."""
        receipt = {
            "schema": "enki.waypoint-receipt.v1",
            "job_id": "job-alpha-001",
            "contract_hash": "a" * 64,
            "attempt": 1,
            "status": "passed",
            "action_label": "accepted",
            "next_action": "stage accepted",
            "reflection": {"cause": "c", "evidence": "e", "proposed_change": "p", "next_check": "n"},
            "evidence": {"artifacts": [], "checks": []},
            "boundary": "candidate_only_no_training_or_policy_change",
        }
        res = runtime.record_waypoint_receipt(receipt, skill="waypoint_flow")
        self.assertEqual(res["task_id"], "job-alpha-001")
        self.assertEqual(res["skill"], "waypoint_flow")
        self.assertTrue(res["correct"])
        self.assertGreater(res["mastery_after"], 0.2)

    def test_record_waypoint_receipt_failed(self):
        """Check that record waypoint receipt failed."""
        receipt = {
            "schema": "enki.waypoint-receipt.v1",
            "job_id": "job-alpha-002",
            "contract_hash": "b" * 64,
            "attempt": 1,
            "status": "failed",
            "action_label": "repair_stage",
            "next_action": "repair stage",
            "reflection": {"cause": "c", "evidence": "e", "proposed_change": "p", "next_check": "n"},
            "evidence": {"artifacts": [], "checks": []},
            "boundary": "candidate_only_no_training_or_policy_change",
        }
        res = runtime.record_waypoint_receipt(receipt, skill="waypoint_flow")
        self.assertEqual(res["task_id"], "job-alpha-002")
        self.assertFalse(res["correct"])
        self.assertEqual(res["reward"], 0.0)

    def test_record_waypoint_receipt_refuses_pending_status(self):
        """Check that record waypoint receipt refuses pending status."""
        receipt = {
            "schema": "enki.waypoint-receipt.v1",
            "job_id": "job-alpha-003",
            "status": "pending_queue_commit",
            "action_label": "repair_stage",
        }
        with self.assertRaisesRegex(ValueError, "pending receipt"):
            runtime.record_waypoint_receipt(receipt)


class EnkiRuntimeStatusAndCLITests(unittest.TestCase):
    """Tests for: Enki Runtime Status And CLITests."""
    def setUp(self):
        """Create the scratch state this test needs."""
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve() / "private" / "malakopia" / "training" / "adaptive_state"
        self.root.mkdir(parents=True)
        os.chmod(self.root, 0o700)
        self.patcher = mock.patch.object(al, "PRIVATE_STATE_ROOT", self.root)
        self.patcher.start()

    def tearDown(self):
        """Remove the scratch state this test created."""
        self.patcher.stop()
        self.tmp.cleanup()

    def test_runtime_status_reports_uninitialized_and_initialized_state(self):
        """Check that runtime status reports uninitialized and initialized state."""
        st1 = runtime.runtime_status()
        self.assertFalse(st1["state_initialized"])
        self.assertEqual(st1["tracked_skills"], 0)

        runtime.record_outcome("t1", correct=True, reward=1.0, verified=True, skill="s1")

        st2 = runtime.runtime_status()
        self.assertTrue(st2["state_initialized"])
        self.assertEqual(st2["tracked_skills"], 1)
        self.assertIn("s1", st2["mastery"])

    def test_cli_round_trip(self):
        # Recommend via CLI
        """Check that cli round trip."""
        candidates_json = json.dumps([
            {"task_id": "cli-1", "skill": "cli_skill", "need": 0.8, "expected_gain": 0.7}
        ])
        exit_code = runtime.main(["recommend", "--candidates", candidates_json])
        self.assertEqual(exit_code, 0)

        # Record via CLI
        exit_code = runtime.main(["record", "--task", "cli-1", "--skill", "cli_skill", "--correct"])
        self.assertEqual(exit_code, 0)

        # Status via CLI
        exit_code = runtime.main(["status"])
        self.assertEqual(exit_code, 0)

        # Record receipt via CLI
        receipt_path = self.root / "test-receipt.json"
        receipt_data = {
            "schema": "enki.waypoint-receipt.v1",
            "job_id": "cli-job-1",
            "status": "passed",
            "action_label": "accepted",
            "attempt": 1,
            "contract_hash": "c" * 64,
            "evidence": {"artifacts": [], "checks": []},
            "reflection": {"cause": "c", "evidence": "e", "proposed_change": "p", "next_check": "n"},
            "boundary": "candidate_only_no_training_or_policy_change",
        }
        receipt_path.write_text(json.dumps(receipt_data))
        exit_code = runtime.main(["record-receipt", str(receipt_path), "--skill", "cli_flow"])
        self.assertEqual(exit_code, 0)

        # Verify CLI recommend reading candidate file
        cand_file = self.root / "candidates.json"
        cand_file.write_text(candidates_json)
        exit_code = runtime.main(["recommend", "--candidates", str(cand_file)])
        self.assertEqual(exit_code, 0)


if __name__ == "__main__":
    unittest.main()
