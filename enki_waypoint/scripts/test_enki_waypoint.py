"""Focused, disposable tests for Enki Waypoint; no model, process, or network use."""
from __future__ import annotations
import contextlib, hashlib, io, json, os, tempfile, unittest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from unittest import mock
from enki_waypoint import Waypoint, WaypointError, main, summary

class WaypointTests(unittest.TestCase):
    """Tests for: Waypoint Tests."""
    def test_reconcile_changed_artifact_requires_review(self):
        """Check that reconcile changed artifact requires review."""
        self.w.prepare(self.contract()); claim = self.w.claim("Forge"); artifacts, checks, review = self.complete_inputs(claim)
        with mock.patch.object(self.w, "_receipt", side_effect=RuntimeError("crash")):
            with self.assertRaises(RuntimeError): self.w.finish(claim, artifacts=artifacts, checks=checks, review=review, reflection=self.reflection())
        self.assertEqual(summary(self.state)["pending_receipts"], 1)
        (self.root / artifacts[0]["path"]).write_text("unreviewed change")
        self.assertEqual(self.w.reconcile()[0]["state"], "needs_review")
        self.assertEqual(summary(self.state)["needs_review_receipts"], 1)

    def test_corrupt_pending_identity_never_writes_outside_receipts(self):
        """Check that corrupt pending identity never writes outside receipts."""
        self.w.receipts.mkdir()
        for name, content in [("broken.json", "{bad"), ("hostile.json", json.dumps({"schema": "enki.waypoint-receipt.v1", "status": "pending_queue_commit", "job_id": "../escaped", "attempt": 1}))]:
            (self.w.receipts / name).write_text(content)
        result = self.w.reconcile()
        self.assertEqual([row["state"] for row in result], ["invalid", "invalid"])
        self.assertFalse((self.state / "escaped-001.json").exists())

    def setUp(self):
        """Create the scratch state this test needs."""
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.root = self.base / "workspace"; self.root.mkdir(); self.state = self.base / "state"
        self.w = Waypoint(self.state, root=self.root)

    def test_receipts_follow_the_queue_verified_state_path(self):
        """Check that receipts follow the queue verified state path."""
        self.assertEqual(self.w.state_dir, self.w.queue.state_dir)
        self.assertEqual(self.w.receipts, self.w.queue.state_dir / "waypoint-receipts")
    def contract(self, **extra):
        """Helper: contract."""
        data = {"intent_id":"intent.demo", "stage_id":"stage-1", "objective":"verify adapter", "scope":["test only"], "acceptance_checks":["receipt_passes"], "worker":"Forge", "verifier":"Lens", "max_repairs":2, "authority_ref":"existing admitted task", "action_labels":["repair_stage", "accepted"]}; data.update(extra); return data
    def ref(self, rel, content):
        """Helper: ref."""
        path = self.root / rel; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(content)
        return {"path":rel, "sha256":hashlib.sha256(path.read_bytes()).hexdigest()}
    def reflection(self):
        """Return a well-formed reflection record for the stage under test."""
        return {"cause":"measured outcome", "evidence":"receipt refs", "proposed_change":"candidate only", "next_check":"review next stage"}
    def complete_inputs(self, claim):
        """Helper: complete inputs."""
        artifact = self.ref("out/artifact.txt", "built")
        check = self.ref("out/check.json", json.dumps({"check_id":"receipt_passes","passed":True,"contract_hash":claim["contract_hash"],"attempt":claim["attempt"],"artifact_hashes":[artifact["sha256"]]}))
        review = {"verifier":"Lens","decision":"accept","contract_hash":claim["contract_hash"],"attempt":claim["attempt"],"artifact_hashes":[artifact["sha256"]],"check_hashes":[check["sha256"]]}
        return [artifact],[check],review
    def test_pass_records_receipt_and_uses_queue(self):
        """Check that pass records receipt and uses queue."""
        job = self.w.prepare(self.contract()); claim = self.w.claim("Forge")
        artifacts, checks, review = self.complete_inputs(claim)
        receipt = self.w.finish(claim, artifacts=artifacts, checks=checks, review=review, reflection=self.reflection())
        self.assertEqual(self.w.queue.get(job)["status"], "passed"); self.assertEqual(receipt["action_label"], "accepted")
        self.assertEqual(receipt["boundary"], "candidate_only_no_training_or_policy_change")

    def test_record_adaptive_outcome_updates_learner(self):
        """Check that record adaptive outcome updates learner."""
        job = self.w.prepare(self.contract()); claim = self.w.claim("Forge")
        artifacts, checks, review = self.complete_inputs(claim)
        receipt = self.w.finish(claim, artifacts=artifacts, checks=checks, review=review, reflection=self.reflection())
        import enki_adaptive_learning as al
        adaptive_root = self.base / "private" / "malakopia" / "training" / "adaptive_state"
        adaptive_root.mkdir(parents=True)
        os.chmod(adaptive_root, 0o700)
        state_file = adaptive_root / "learner.json"
        with mock.patch.object(al, "PRIVATE_STATE_ROOT", adaptive_root):
            res = self.w.record_adaptive_outcome(receipt, skill="pipeline_test", state_path=state_file)
            self.assertEqual(res["task_id"], job)
            self.assertEqual(res["skill"], "pipeline_test")
            self.assertTrue(res["correct"])
            self.assertGreater(res["mastery_after"], 0.2)
            self.assertTrue(state_file.exists())
    def test_contract_limits_repairs_to_two(self):
        """Check that contract limits repairs to two."""
        job = self.w.prepare(self.contract());
        for number in range(3):
            claim = self.w.claim("Forge"); artifacts, checks, review = self.complete_inputs(claim); review["decision"]="reject"
            receipt = self.w.finish(claim, artifacts=artifacts, checks=checks, review=review, reflection=self.reflection())
            self.assertEqual(receipt["action_label"], "repair_stage" if number < 2 else "owner_approval_required")
        self.assertEqual(self.w.queue.get(job)["status"], "needs_review"); self.assertIsNone(self.w.claim("Forge"))
    def test_rejects_same_worker_reviewer_and_stale_artifact(self):
        """Check that rejects same worker reviewer and stale artifact."""
        with self.assertRaises(WaypointError): self.w.prepare(self.contract(verifier="Forge"))
        self.w.prepare(self.contract()); claim = self.w.claim("Forge"); artifacts, checks, review = self.complete_inputs(claim)
        review["verifier"]="Forge"
        receipt = self.w.finish(claim, artifacts=artifacts, checks=checks, review=review, reflection=self.reflection())
        self.assertEqual(receipt["action_label"], "repair_stage")
    def test_rejects_hash_mismatch_and_invalid_labels(self):
        """Check that rejects hash mismatch and invalid labels."""
        with self.assertRaises(WaypointError): self.w.prepare(self.contract(action_labels=["invented"]))
        self.w.prepare(self.contract()); claim = self.w.claim("Forge"); artifact = self.ref("out/a", "a"); artifact["sha256"]="0"*64
        check = self.ref("out/c", json.dumps({"check_id":"receipt_passes","passed":True,"contract_hash":claim["contract_hash"],"attempt":claim["attempt"],"artifact_hashes":[artifact["sha256"]]}))
        review={"verifier":"Lens","decision":"accept","contract_hash":claim["contract_hash"],"attempt":claim["attempt"],"artifact_hashes":[],"check_hashes":[check["sha256"]]}
        with self.assertRaises(WaypointError): self.w.finish(claim, artifacts=[artifact], checks=[check], review=review, reflection=self.reflection())
        self.assertEqual(self.w.queue.get(claim["job_id"])["status"], "running")
    def test_wrong_worker_cannot_lease_and_failed_check_retries(self):
        """Check that wrong worker cannot lease and failed check retries."""
        self.w.prepare(self.contract())
        with self.assertRaises(WaypointError): self.w.claim("Other")
        claim = self.w.claim("Forge"); artifacts, checks, review = self.complete_inputs(claim)
        check_path = self.root / checks[0]["path"]
        check_path.write_text(json.dumps({"check_id":"receipt_passes","passed":False,"contract_hash":claim["contract_hash"],"attempt":claim["attempt"],"artifact_hashes":[artifacts[0]["sha256"]]}))
        checks[0]["sha256"] = hashlib.sha256(check_path.read_bytes()).hexdigest()
        review["check_hashes"] = [checks[0]["sha256"]]
        result = self.w.finish(claim, artifacts=artifacts, checks=checks, review=review, reflection=self.reflection())
        self.assertEqual(result["action_label"], "repair_stage")
        self.assertEqual(self.w.queue.get(claim["job_id"])["status"], "queued")
    def test_check_cannot_certify_a_different_artifact(self):
        """Check that check cannot certify a different artifact."""
        self.w.prepare(self.contract()); claim = self.w.claim("Forge"); artifacts, checks, review = self.complete_inputs(claim)
        check_path = self.root / checks[0]["path"]
        data = json.loads(check_path.read_text()); data["artifact_hashes"] = ["0" * 64]; check_path.write_text(json.dumps(data))
        checks[0]["sha256"] = hashlib.sha256(check_path.read_bytes()).hexdigest(); review["check_hashes"] = [checks[0]["sha256"]]
        with self.assertRaises(WaypointError): self.w.finish(claim, artifacts=artifacts, checks=checks, review=review, reflection=self.reflection())
        self.assertEqual(self.w.queue.get(claim["job_id"])["status"], "running")
    def test_bad_token_or_reflection_does_not_reserve_receipt(self):
        """Check that bad token or reflection does not reserve receipt."""
        self.w.prepare(self.contract()); claim = self.w.claim("Forge"); artifacts, checks, review = self.complete_inputs(claim)
        with self.assertRaises(WaypointError): self.w.finish(claim, artifacts=artifacts, checks=checks, review=review, reflection={})
        self.assertFalse(self.w.receipts.exists())
        bad = dict(claim); bad["token"] = "not-the-token"
        with self.assertRaises(Exception): self.w.finish(bad, artifacts=artifacts, checks=checks, review=review, reflection=self.reflection())
        self.assertFalse(self.w.receipts.exists())
        self.assertEqual(self.w.queue.get(claim["job_id"])["status"], "running")
    def test_exact_claim_race_cannot_fall_through_to_second_job(self):
        """Check that exact claim race cannot fall through to second job."""
        first = self.w.prepare(self.contract(stage_id="stage-1")); second = self.w.prepare(self.contract(stage_id="stage-2"))
        with mock.patch.object(self.w.queue, "claim", return_value=None) as claimed:
            self.assertIsNone(self.w.claim("Forge"))
        self.assertEqual(claimed.call_args.kwargs["job_id"], first)
        self.assertEqual(self.w.queue.get(second)["status"], "queued")
    def test_explicit_stage_preserves_unrelated_queue_and_default_fifo(self):
        """Check that explicit stage preserves unrelated queue and default fifo."""
        first = self.w.prepare(self.contract(stage_id="earlier", worker="Other"))
        target = self.w.prepare(self.contract(stage_id="authorized"))
        with self.assertRaises(WaypointError): self.w.claim("Other", job_id=target)
        self.assertIsNone(self.w.claim("Forge", job_id="missing-stage"))
        claim = self.w.claim("Forge", job_id=target)
        self.assertEqual(claim["job_id"], target)
        self.assertIsNone(self.w.claim("Forge", job_id=target))
        self.assertEqual(self.w.queue.get(first)["status"], "queued")
        self.assertEqual(self.w.queue.get(first)["attempt"], 0)
        self.assertEqual(self.w.claim("Other")["job_id"], first)
    def test_explicit_stage_race_never_claims_another_job(self):
        """Check that explicit stage race never claims another job."""
        first = self.w.prepare(self.contract(stage_id="earlier"))
        target = self.w.prepare(self.contract(stage_id="authorized"))
        with mock.patch.object(self.w.queue, "claim", return_value=None) as claimed:
            self.assertIsNone(self.w.claim("Forge", job_id=target))
        self.assertEqual(claimed.call_args.kwargs["job_id"], target)
        self.assertEqual(self.w.queue.get(first)["attempt"], 0)
    def test_cli_claim_exact_stage_and_lease(self):
        """Check that cli claim exact stage and lease."""
        first = self.w.prepare(self.contract(stage_id="earlier"))
        target = self.w.prepare(self.contract(stage_id="authorized"))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(["--state-dir", str(self.state), "claim", "Forge", "--job-id", target, "--lease-seconds", "30"]), 0)
        claim = json.loads(output.getvalue())
        self.assertEqual(claim["job_id"], target)
        self.assertEqual(self.w.queue.get(first)["attempt"], 0)
        attempt = self.w.queue.attempts(target)[0]
        from datetime import datetime
        started = datetime.fromisoformat(attempt["started_at"].replace("Z", "+00:00")).timestamp()
        self.assertAlmostEqual(attempt["lease_until"] - started, 30, delta=1)
    def test_expired_worker_before_receipt_is_held_and_recorded_once(self):
        """Check that expired worker before receipt is held and recorded once."""
        self.w.queue.clock = lambda: 1000
        job = self.w.prepare(self.contract()); self.w.claim("Forge", lease_seconds=2)
        self.assertEqual(self.w.reconcile(), [])
        self.assertFalse(self.w.receipts.exists())
        self.w.queue.clock = lambda: 1003
        result = self.w.reconcile()
        self.assertEqual(result, [{"receipt": f"{job}-001.json", "state": "needs_review"}])
        self.assertEqual(self.w.queue.get(job)["status"], "needs_review")
        path = self.w.receipts / result[0]["receipt"]; before = path.read_bytes()
        receipt = json.loads(before)
        self.assertEqual(receipt["action_label"], "owner_approval_required")
        self.assertEqual(receipt["evidence"]["artifacts"], [])
        self.assertEqual(receipt["evidence"]["lease_expiry"]["event"], "lease_expired")
        self.assertEqual(self.w.reconcile(), [])
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(self.w.queue.get(job)["attempt"], 1)
    def test_expiry_receipt_recovers_after_recovery_crash_and_explicit_retry(self):
        """Check that expiry receipt recovers after recovery crash and explicit retry."""
        self.w.queue.clock = lambda: 1000
        job = self.w.prepare(self.contract()); self.w.claim("Forge", lease_seconds=2)
        self.w.queue.clock = lambda: 1003
        self.assertEqual(self.w.queue.recover_expired(), [job])
        self.assertFalse(self.w.receipts.exists())
        self.w.queue.retry(job)
        second = self.w.claim("Forge", job_id=job)
        self.assertEqual(second["attempt"], 2)
        self.assertEqual(self.w.reconcile(), [{"receipt": f"{job}-001.json", "state": "needs_review"}])
        receipt = json.loads((self.w.receipts / f"{job}-001.json").read_text())
        self.assertEqual(receipt["attempt"], 1)
        self.assertEqual(receipt["contract_hash"], second["contract_hash"])
        self.assertEqual(self.w.queue.get(job)["status"], "running")
    def test_summary_rejects_symlink_without_initializing(self):
        """Check that summary rejects symlink without initializing."""
        target = Path(self.tmp.name) / "uninitialized-target"
        linked = Path(self.tmp.name) / "link"; linked.symlink_to(target)
        report = summary(linked, root=self.root)
        self.assertEqual(report["state"], "unavailable")
        self.assertFalse((linked / "jobs.sqlite3").exists())
    def test_summary_distinguishes_absence_from_an_unsafe_database_entry(self):
        """Check that summary distinguishes absence from an unsafe database entry."""
        for kind in ("absent", "directory", "dangling_link"):
            with self.subTest(kind=kind):
                state = Path(self.tmp.name) / kind; state.mkdir()
                database = state / "jobs.sqlite3"
                if kind == "directory": database.mkdir()
                if kind == "dangling_link": database.symlink_to(state / "missing-target")
                report = summary(state, root=self.root)
                self.assertEqual(report["state"], "not_initialized" if kind == "absent" else "unavailable")
                self.assertFalse((state / "missing-target").exists())
    def test_reconcile_finalizes_post_commit_pending_idempotently(self):
        """Check that reconcile finalizes post commit pending idempotently."""
        self.w.prepare(self.contract()); claim = self.w.claim("Forge"); artifacts, checks, review = self.complete_inputs(claim)
        with mock.patch.object(self.w, "_receipt", side_effect=RuntimeError("simulated crash")):
            with self.assertRaises(RuntimeError): self.w.finish(claim, artifacts=artifacts, checks=checks, review=review, reflection=self.reflection())
        self.assertEqual(self.w.queue.get(claim["job_id"])["status"], "passed")
        self.assertEqual(self.w.inspect()["pending_receipts"], 1)
        self.assertEqual(self.w.reconcile()[0]["state"], "finalized")
        self.assertEqual(self.w.inspect()["pending_receipts"], 0)
        self.assertEqual(self.w.reconcile(), [])
    def test_reconcile_mismatch_holds_for_review_without_restart(self):
        """Check that reconcile mismatch holds for review without restart."""
        self.w.prepare(self.contract()); claim = self.w.claim("Forge"); artifacts, checks, review = self.complete_inputs(claim)
        pending = self.w._receipt_payload(claim, action_label="accepted", next_action="x", reflection=self.reflection(), evidence={"artifacts":artifacts,"checks":checks,"review":review}, queue_status="pending_queue_commit")
        self.w._write_receipt(pending)
        self.assertEqual(self.w.reconcile()[0]["state"], "needs_review")
        self.assertEqual(self.w.queue.get(claim["job_id"])["status"], "running")
if __name__ == "__main__": unittest.main()
