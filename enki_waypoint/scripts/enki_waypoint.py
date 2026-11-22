#!/usr/bin/env python3
"""Enki Waypoint: typed, bounded stage contracts over the local JobQueue.

This module never starts a process, model, service, or network request.  It
turns an already-authorized bounded task into one immutable queue job, records
hash-bound local evidence, and limits repairs to two.  Actor strings document
accountability but are not authentication credentials.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
from urllib.parse import quote
from typing import Any

from malakopia_job_queue import JobQueue, QueueError, default_state_dir, local_state_path, _no_symlink_chain

# Component root used as the default evidence workspace.
ROOT = Path(__file__).resolve().parents[1]
# Schema tags stamped on queue specs and receipts so readers can reject other formats.
SCHEMA = "enki.waypoint.v1"
RECEIPT_SCHEMA = "enki.waypoint-receipt.v1"
# Evidence is read fully into memory to hash it, so each file is capped at 1 MiB.
MAX_FILE_BYTES = 1024 * 1024
# Declared age budget for evidence (24 hours); the freshness test itself compares
# file mtime against the start of the current attempt.
MAX_REF_AGE_SECONDS = 24 * 60 * 60
# Identifier whitelist shared by actors, stages and check ids. No path separators or
# whitespace, so an id cannot alter a file name or a log line.
IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}")
# Closed vocabulary of next-action labels. A receipt with a label outside this set is
# refused, so downstream readers can branch on it exhaustively.
LABELS = frozenset({"owner_approval_required", "repair_stage", "independent_review_required",
                    "blocked_by_evidence", "resume_from_receipt", "closeout_reflection_required", "accepted"})


class WaypointError(ValueError):
    """Raised for any contract, evidence, receipt or queue-state violation in this module."""
    pass


def _now() -> str:
    """Return the current UTC time as ISO-8601 with a trailing Z and no microseconds."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _canonical(value: Any) -> str:
    """Serialise value to canonical JSON (sorted keys, no whitespace, non-ASCII kept) so equal data always yields identical bytes."""
    # Canonical form: sorted keys and compact separators make the byte string, and so
    # the hash, independent of dict ordering and formatting.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: Any) -> str:
    """Return the SHA-256 hex digest of the canonical JSON form of value."""
    # Hash the canonical bytes. The digest is the contract identity used for the
    # idempotency key and for binding evidence to one contract.
    return hashlib.sha256(_canonical(value).encode()).hexdigest()


def _text(value: Any, name: str, limit=240) -> str:
    """Return value stripped, after checking it is a non-empty printable string of at most limit characters; raises WaypointError naming the field."""
    # isprintable rejects control characters and newlines, which could forge log lines or
    # break the one-record-per-line receipts; the length cap bounds stored size.
    if not isinstance(value, str) or not value.strip() or len(value) > limit or not value.isprintable():
        raise WaypointError(f"invalid {name}")
    return value.strip()


def _ident(value: Any, name: str) -> str:
    """Return value if it is a valid identifier of at most 96 characters; raises WaypointError otherwise."""
    # Length check first, then the character-set check.
    value = _text(value, name, 96)
    if not IDENT.fullmatch(value):
        raise WaypointError(f"invalid {name}")
    return value


def _labels(value: Any) -> list[str]:
    """Return the action labels sorted, after checking they are a non-empty duplicate-free list of at most 8 known labels."""
    # Non-empty, at most 8, no unknown labels and no duplicates. Sorting makes the stored
    # contract (and so its hash) independent of the order the caller supplied.
    if not isinstance(value, list) or not value or len(value) > 8 or set(value) - LABELS or len(set(value)) != len(value):
        raise WaypointError("invalid action_labels")
    return sorted(value)


def validate_contract(value: Any) -> dict[str, Any]:
    """Validate a stage contract (exact field set, bounded lists, max_repairs 0-2, distinct worker and verifier) and return a normalised copy; raises WaypointError."""
    # Exact key set: unknown fields are refused rather than ignored, so a typo cannot
    # silently drop a requirement and the contract hash covers every field.
    if not isinstance(value, dict) or set(value) != {"intent_id", "stage_id", "objective", "scope", "acceptance_checks", "worker", "verifier", "max_repairs", "authority_ref", "action_labels"}:
        raise WaypointError("invalid Waypoint contract fields")
    # Scope entries are bounded free text; check ids must be identifiers because they are
    # matched against check receipts later.
    scope, checks = value["scope"], value["acceptance_checks"]
    if not isinstance(scope, list) or not scope or len(scope) > 30 or not all(isinstance(x, str) and 0 < len(x) <= 300 for x in scope):
        raise WaypointError("invalid scope")
    if not isinstance(checks, list) or not checks or len(checks) > 30 or not all(isinstance(x, str) and IDENT.fullmatch(x) for x in checks) or len(set(checks)) != len(checks):
        raise WaypointError("invalid acceptance_checks")
    # Repair budget is 0 to 2 and must be a true int (bool excluded). The queue allows
    # 1 + max_repairs attempts, so this number is the hard cap on retries.
    repairs = value["max_repairs"]
    if type(repairs) is not int or not 0 <= repairs <= 2:
        raise WaypointError("max_repairs must be 0, 1, or 2")
    # Separation of duties: the stage worker may not review its own output.
    worker, verifier = _ident(value["worker"], "worker"), _ident(value["verifier"], "verifier")
    if worker == verifier:
        raise WaypointError("worker and verifier must be distinct")
    # Return a freshly built normalised dict (lists copied, text stripped) so later
    # hashing sees only validated, canonical values.
    return {"intent_id": _ident(value["intent_id"], "intent_id"), "stage_id": _ident(value["stage_id"], "stage_id"),
            "objective": _text(value["objective"], "objective", 1200), "scope": list(scope),
            "acceptance_checks": list(checks), "worker": worker, "verifier": verifier,
            "max_repairs": repairs, "authority_ref": _text(value["authority_ref"], "authority_ref", 240),
            "action_labels": _labels(value["action_labels"])}


def _safe_ref(root: Path, ref: Any, *, after: float) -> dict[str, str]:
    """Validate an evidence reference {path, sha256} under root and return it with the recomputed hash; refuses absolute paths, parent segments, symlinks, escapes, oversize or stale files and hash mismatches."""
    if not isinstance(ref, dict) or set(ref) != {"path", "sha256"}:
        raise WaypointError("invalid evidence reference")
    path_text, expected = ref["path"], ref["sha256"]
    # Reject absolute paths and any parent-directory segment before touching the
    # filesystem; the hash must be 64 lowercase hex digits.
    if (not isinstance(path_text, str) or not isinstance(expected, str) or Path(path_text).is_absolute()
            or ".." in Path(path_text).parts or not re.fullmatch(r"[0-9a-f]{64}", expected)):
        raise WaypointError("invalid evidence reference")
    # Symlink and containment checks follow, in that order: a link must be caught before
    # resolve() follows it and makes the final path look legitimate.
    raw = root / path_text
    # `resolve()` would hide a symlink in the supplied route; reject every
    # existing component before resolving containment.
    cursor = root
    for part in Path(path_text).parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise WaypointError("evidence path contains a symbolic link")
    # Second line of defence: even with no symlinks, the resolved path must still sit
    # inside the workspace root.
    candidate = raw.resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as exc:
        raise WaypointError("evidence path escapes workspace") from exc
    # Regular files only (no devices, pipes or directories), capped in size.
    if not candidate.is_file() or candidate.stat().st_size > MAX_FILE_BYTES:
        raise WaypointError("evidence file is unsafe or too large")
    # A result must be produced during this claimed attempt, not reused silently.
    if candidate.stat().st_mtime + 1 < after:
        raise WaypointError("evidence is older than this attempt")
    # Hash what is actually on disk now and compare with the caller's claim. This binds
    # the reference to exact content, so a file changed after the claim is detected.
    content = candidate.read_bytes()
    actual = hashlib.sha256(content).hexdigest()
    if actual != expected:
        raise WaypointError("evidence hash mismatch")
    return {"path": path_text, "sha256": actual}


def _check_ref(root: Path, ref: Any, *, contract_hash: str, attempt: int, artifact_hashes: list[str], after: float) -> dict[str, Any]:
    """Validate a check receipt file and confirm it is bound to this contract hash, attempt and artifact hashes; returns its path, hash, check_id and passed flag."""
    # The check file goes through the same safety and freshness validation as artifacts,
    # then its content is parsed below.
    checked = _safe_ref(root, ref, after=after)
    try:
        record = json.loads((root / checked["path"]).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise WaypointError("check receipt is not valid JSON") from exc
    # Hash binding: a check result counts only if it names this contract hash, this
    # attempt number and exactly the artifact hashes under review. A receipt copied from
    # another stage, attempt or artifact set therefore cannot be replayed here.
    if (not isinstance(record, dict) or type(record.get("passed")) is not bool
            or not isinstance(record.get("check_id"), str) or not IDENT.fullmatch(record["check_id"])
            or record.get("contract_hash") != contract_hash or record.get("attempt") != attempt
            or record.get("artifact_hashes") != artifact_hashes):
        raise WaypointError("check receipt is not bound to this attempt")
    # Only the validated fields are propagated, never the raw record.
    return {**checked, "check_id": record["check_id"], "passed": record["passed"]}


def _reflection(value: Any) -> dict[str, str]:
    """Return the reflection with each of its four required fields validated as bounded printable text; raises WaypointError otherwise."""
    if not isinstance(value, dict) or set(value) != {"cause", "evidence", "proposed_change", "next_check"}:
        raise WaypointError("reflection must contain cause, evidence, proposed_change, next_check")
    # Reflection is mandatory structured text so every attempt records cause, evidence,
    # proposed change and next check, even on success.
    return {key: _text(item, "reflection." + key, 400) for key, item in value.items()}


# The queue stays the single source of truth for scheduling and history; this class
# only adds typed contracts, evidence checks and receipts.
class Waypoint:
    """Thin typed adapter; JobQueue remains the only scheduler and history store."""
    def __init__(self, state_dir: Path, *, root: Path = ROOT):
        """Open the dedicated JobQueue under state_dir; receipts are kept in a waypoint-receipts folder beside it."""
        # Evidence paths are interpreted relative to this resolved workspace root.
        self.root = Path(root).resolve()
        self.queue = JobQueue(state_dir, root=self.root)
        self.state_dir = self.queue.state_dir
        self.receipts = self.state_dir / "waypoint-receipts"

    def _only_waypoint_jobs(self) -> None:
        """A Waypoint state directory is dedicated.  Generic queue jobs must use
        their own state directory; the generic claim API has no recipe filter."""
        # Refuse to operate on a mixed directory, because the generic claim cannot filter by
        # recipe and might hand a foreign job to a Waypoint worker.
        for row in self.queue.list_jobs():
            if row["spec"].get("recipe") != "enki.waypoint" or row["spec"].get("schema") != SCHEMA:
                raise WaypointError("Waypoint state directory contains a non-Waypoint job; refusing to claim it")

    def prepare(self, contract: dict[str, Any], *, job_id: str | None = None) -> str:
        """Validate a contract and enqueue it as one job whose attempt budget is 1 plus max_repairs; returns the job id. Idempotent on the contract digest."""
        contract = validate_contract(contract)
        # The validated contract is embedded in the queue spec; max_attempts and the
        # idempotency key below derive from it.
        spec = {"recipe": "enki.waypoint", "schema": SCHEMA, "contract": contract}
        return self.queue.enqueue(spec, job_id=job_id, max_attempts=1 + contract["max_repairs"],
                                  idempotency_key="waypoint:" + _digest(contract))

    def claim(self, actor: str, lease_seconds=300, *, job_id: str | None = None) -> dict[str, Any] | None:
        """Claim the next queued stage for the assigned worker (optionally a specific job); returns the claim with repair counters, or None if nothing was claimed."""
        # Actor names record accountability only; they are not credentials, so anyone able to
        # run this code can claim to be any worker. They are still validated as identifiers.
        actor = _ident(actor, "actor")
        if job_id is not None:
            job_id = _ident(job_id, "job_id")
        self._only_waypoint_jobs()
        # Candidates are queued jobs, optionally narrowed to one job id.
        queued = [row for row in self.queue.list_jobs("queued") if job_id is None or row["job_id"] == job_id]
        # Check the assignment before claiming so a wrong actor does not take a lease on
        # someone else's stage.
        if queued:
            expected = validate_contract(queued[0]["spec"].get("contract"))["worker"]
            if actor != expected:
                raise WaypointError("next Waypoint is assigned to a different worker")
        # Queue v1's exact-job selector makes a concurrent claim resolve to
        # None rather than falling through to another queued job.
        # Claiming a specific job id means a lost race returns None instead of silently
        # taking a different job whose worker assignment was never checked.
        claim = self.queue.claim(actor, lease_seconds, job_id=queued[0]["job_id"]) if queued else None
        if claim is None:
            return None
        # Re-validate the claimed job itself, since the earlier check read the queued view.
        spec = claim["spec"]
        if spec.get("recipe") != "enki.waypoint" or spec.get("schema") != SCHEMA:
            raise WaypointError("queue contains a non-Waypoint job")
        contract = validate_contract(spec.get("contract"))
        if actor != contract["worker"]:
            raise WaypointError("claimed actor does not match the stage worker")
        # Attempt 1 is the original try; each later attempt is a repair. The remaining count
        # tells the worker how many repair rounds are left before escalation.
        claim["repair_round"] = claim["attempt"] - 1
        claim["repair_rounds_remaining"] = contract["max_repairs"] - claim["repair_round"]
        return claim

    def _receipt_payload(self, job: dict[str, Any], *, action_label: str, next_action: str, reflection: dict[str, str], evidence: dict[str, Any], queue_status: str) -> dict[str, Any]:
        """Build (without writing) a receipt record bound to the job, contract hash and attempt; raises WaypointError for an unknown action label."""
        # Same closed vocabulary as the contract labels.
        if action_label not in LABELS:
            raise WaypointError("invalid action_label")
        # The receipt carries contract hash and attempt number, so it cannot be attached to a
        # different contract or attempt. The boundary string states what the record does not
        # authorise.
        record = {"schema": RECEIPT_SCHEMA, "created_at": _now(), "job_id": job["job_id"],
                  "contract_hash": job["contract_hash"], "attempt": job["attempt"], "status": queue_status,
                  "action_label": action_label, "next_action": _text(next_action, "next_action", 500),
                  "reflection": reflection, "evidence": evidence,
                  "boundary": "candidate_only_no_training_or_policy_change"}
        return record

    def _write_receipt(self, record: dict[str, Any], *, overwrite=False) -> dict[str, Any]:
        """Atomically write a receipt file named by job and attempt; refuses to replace an existing one unless overwrite is set. Returns the record."""
        # Receipt directory is owner-only and must not be, or sit behind, a symlink.
        self.receipts.mkdir(parents=True, exist_ok=True, mode=0o700)
        _no_symlink_chain(self.receipts)
        # One file per job and attempt number (zero padded), which keeps lookups predictable
        # and lets reconciliation derive the expected name from receipt contents.
        target = self.receipts / f"{record['job_id']}-{record['attempt']:03d}.json"
        # First write must not clobber an existing receipt; only the finalising step is
        # allowed to replace its own pending record.
        if target.exists() and not overwrite:
            raise WaypointError("receipt already exists")
        # Write-then-rename in the same directory: a crash leaves either the old file or the
        # complete new one, never a partial receipt. fsync before the rename for durability.
        fd, temporary = tempfile.mkstemp(prefix=".waypoint-", dir=self.receipts)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(record, handle, sort_keys=True); handle.write("\n"); handle.flush(); os.fsync(handle.fileno())
            os.replace(temporary, target)
        finally:
            # Remove the temporary file if the rename did not happen; after a successful
            # replace it no longer exists.
            if os.path.exists(temporary): os.unlink(temporary)
        return record

    def _receipt(self, job: dict[str, Any], *, action_label: str, next_action: str, reflection: dict[str, str], evidence: dict[str, Any]) -> dict[str, Any]:
        """Build and write the final receipt for a job's current queue status, replacing any pending receipt for the same attempt."""
        # queue_status comes from the committed job, so a final receipt mirrors durable
        # queue state.
        record = self._receipt_payload(job, action_label=action_label, next_action=next_action, reflection=reflection, evidence=evidence, queue_status=job["status"])
        return self._write_receipt(record, overwrite=True)

    def finish(self, claim: dict[str, Any], *, artifacts: list[dict[str, str]], checks: list[dict[str, str]], review: dict[str, Any], reflection: dict[str, str]) -> dict[str, Any]:
        """Verify fresh artifacts, bound check receipts and an independent review for a live claim, reserve a pending receipt, then commit the queue result and return the final receipt."""
        # The claim token proves the caller holds the live lease; it is verified by the queue
        # heartbeat further down.
        if not isinstance(claim, dict) or not isinstance(claim.get("token"), str):
            raise WaypointError("a live Waypoint claim is required")
        # Re-read the job from the queue rather than trusting the caller's copy of the claim.
        job = self.queue.get(claim["job_id"])
        contract = validate_contract(job["spec"].get("contract"))
        # Reject a claim that no longer matches the stored contract or attempt number, for
        # example after the lease expired and the job was recovered or retried.
        if claim.get("contract_hash") != job["contract_hash"] or claim.get("attempt") != job["attempt"]:
            raise WaypointError("claim no longer matches queue state")
        attempts = self.queue.attempts(job["job_id"])
        # Start time of the current attempt: evidence must have been written after this
        # moment, so output from an earlier attempt cannot be resubmitted.
        started = datetime.fromisoformat(attempts[-1]["started_at"].replace("Z", "+00:00")).timestamp()
        reflection = _reflection(reflection)
        if not isinstance(artifacts, list) or not artifacts or not isinstance(checks, list) or not checks:
            raise WaypointError("fresh artifacts and check receipts are required")
        # Each artifact is path-checked, size-limited, fresh and hash-verified.
        artifact_refs = [_safe_ref(self.root, item, after=started) for item in artifacts]
        # Ordered list of artifact hashes; check receipts and the review must repeat it
        # exactly, which ties all three to the same output.
        artifact_hashes = [row["sha256"] for row in artifact_refs]
        if len({(row["path"], row["sha256"]) for row in artifact_refs}) != len(artifact_refs):
            raise WaypointError("duplicate artifact references are not allowed")
        # Every check receipt must be bound to this contract hash, attempt and artifact set.
        check_refs = [_check_ref(self.root, item, contract_hash=job["contract_hash"], attempt=job["attempt"], artifact_hashes=artifact_hashes, after=started) for item in checks]
        # Coverage rule: the set of checks submitted must equal the contract's acceptance
        # checks, each exactly once. Skipping a check or adding duplicates is refused.
        if {row["check_id"] for row in check_refs} != set(contract["acceptance_checks"]) or len({row["check_id"] for row in check_refs}) != len(check_refs):
            raise WaypointError("check receipts must cover each acceptance check exactly once")
        # Review is an exact-shape record naming the verifier, its decision and the same
        # hashes as above.
        if not isinstance(review, dict) or set(review) != {"verifier", "decision", "contract_hash", "attempt", "artifact_hashes", "check_hashes"}:
            raise WaypointError("invalid independent review")
        reviewer = _ident(review["verifier"], "reviewer")
        # Acceptance needs every check to have passed.
        checks_passed = all(row["passed"] for row in check_refs)
        # Acceptance conjunction: all checks passed; the reviewer is the contract's named
        # verifier and not the worker; the decision is accept; and the review's contract
        # hash, attempt, artifact hashes and check hashes all match this attempt. Any
        # mismatch means no acceptance, never a partial pass.
        accepted = (checks_passed and reviewer == contract["verifier"] and reviewer != contract["worker"] and review["decision"] == "accept"
                    and review["contract_hash"] == job["contract_hash"] and review["attempt"] == job["attempt"]
                    and review["artifact_hashes"] == artifact_hashes
                    and review["check_hashes"] == [x["sha256"] for x in check_refs])
        # Evidence bundles the validated artifacts, checks and review with the review's
        # digest, so the queue result and the receipt can later be compared byte for byte.
        review_hash, evidence = _digest(review), {"artifacts": artifact_refs, "checks": check_refs, "review": review, "review_hash": _digest(review)}
        # Repair budget: attempt 1 is the original try, so a repair remains only while the
        # attempt number is at most max_repairs. A rejected stage with budget left goes back
        # to the queue; with none left it stops for an owner decision.
        repair_left = job["attempt"] <= contract["max_repairs"]
        # Three outcomes: accepted (passed), rejected with budget left (retry and
        # repair_stage), rejected with budget exhausted (needs_review and owner approval).
        disposition, label = ("passed", "accepted") if accepted else (("retry", "repair_stage") if repair_left else ("needs_review", "owner_approval_required"))
        next_action = ("stage accepted; request close-out reflection when the parent outcome is complete" if accepted else ("repair the failed check or stated review failure and rerun bounded checks" if repair_left else "owner decision required; repair budget is exhausted"))
        # Validate and durably reserve a receipt *before* moving the queue. A crash
        # can leave only a pending receipt, never a finished queue attempt with none.
        # Validate ownership only after all caller data has passed validation;
        # an invalid/stale token must never reserve a receipt path.
        # Ownership check, performed only after every input passed validation, so an invalid
        # or stale token can never reserve a receipt path.
        self.queue.heartbeat(job["job_id"], claim["token"])
        # Write-ahead receipt: record the intended outcome durably before changing the
        # queue. If the process dies between the two steps, reconcile can see the pending
        # receipt and finalise or hold it.
        pending = self._receipt_payload(job, action_label=label, next_action=next_action, reflection=reflection, evidence=evidence, queue_status="pending_queue_commit")
        self._write_receipt(pending)
        # Commit to the queue. The pending receipt is then replaced by a final one carrying
        # the queue status.
        if accepted:
            completed = self.queue.finish(job["job_id"], claim["token"], {"passed": True, "failures": [], "evidence": evidence})
            return self._receipt(completed, action_label="accepted", next_action="stage accepted; request close-out reflection when the parent outcome is complete", reflection=reflection, evidence=evidence)
        # Failure reason only names the category; details live in the evidence bundle.
        failures = ["one or more acceptance checks failed"] if not checks_passed else ["independent review did not accept this stage"]
        # disposition selects retry or needs_review in the queue, enforcing the repair budget.
        completed = self.queue.finish(job["job_id"], claim["token"], {"passed": False, "failures": failures, "evidence": evidence}, disposition)
        return self._receipt(completed, action_label=label, next_action=next_action, reflection=reflection, evidence=evidence)

    def inspect(self) -> dict[str, Any]:
        """Return job counts by status plus the number of receipts still pending a queue commit."""
        # Counts only Waypoint jobs. The status map lists every state so absent states show
        # as zero.
        jobs = [row for row in self.queue.list_jobs() if row["spec"].get("recipe") == "enki.waypoint"]
        pending = 0
        # Read-only scan; a symlinked receipt directory is ignored. Unreadable files are
        # skipped rather than counted.
        if self.receipts.is_dir() and not self.receipts.is_symlink():
            for path in self.receipts.glob("*.json"):
                try: pending += json.loads(path.read_text()).get("status") == "pending_queue_commit"
                except (OSError, ValueError): pass
        return {"schema": SCHEMA, "jobs": len(jobs), "by_status": {s: sum(j["status"] == s for j in jobs) for s in ("queued", "running", "passed", "failed", "needs_review", "blocked", "canceled")}, "pending_receipts": pending, "queue_state": str(self.state_dir), "rule": "queue pass is not finalized acceptance while a pending receipt exists"}

    def reconcile(self) -> list[dict[str, Any]]:
        """Retain expired leases and finalize exactly bound pending receipts; never restart work."""
        self._only_waypoint_jobs()
        _no_symlink_chain(self.receipts)
        # Expired leases are moved to needs_review by the queue itself; they are never
        # restarted automatically because the outcome of the lost run is unknown.
        self.queue.recover_expired()
        # Reconciliation has two passes: (1) create missing receipts for expired leases,
        # (2) finalise pending receipts that exactly match durable queue evidence.
        outcomes = []
        # Read durable expiry events so a crash after queue recovery but before
        # receipt creation is itself recoverable on the next reconciliation.
        # Using the durable event log makes the first pass restartable at any point.
        for event in self.queue.events():
            if event["event"] != "lease_expired":
                continue
            job = self.queue.get(event["job_id"])
            number = event["details"]["attempt"]
            path = self.receipts / f"{job['job_id']}-{number:03d}.json"
            # An existing receipt (or symlink in its place) is never overwritten here.
            if path.exists() or path.is_symlink():
                continue
            # Create a receipt only if the queue recorded this attempt as needs_review with
            # evidence identical to the expiry event; anything else is left untouched.
            attempt = next((row for row in self.queue.attempts(job["job_id"]) if row["attempt"] == number), None)
            if (attempt is None or attempt["disposition"] != "needs_review"
                    or attempt.get("result", {}).get("evidence") != event["details"]):
                continue
            # Expired-lease receipts are always owner_approval_required: nobody knows what the
            # lost worker changed, so a human must inspect before a retry.
            record = self._receipt_payload(dict(job, attempt=number), action_label="owner_approval_required",
                next_action="execution outcome unknown after lease expiry; inspect side effects and evidence before any explicit retry",
                reflection={"cause": "Worker lease expired without a terminal result; cause of lost worker is unknown.",
                    "evidence": f"queue lease_expired event {event['id']}, job {job['job_id']}, attempt {number}",
                    "proposed_change": "Review external effects and preserve the original repair budget before resuming.",
                    "next_check": "Confirm the expired attempt has a durable review receipt and was not restarted."},
                evidence={"artifacts": [], "checks": [], "lease_expiry": event}, queue_status="needs_review")
            self._write_receipt(record)
            outcomes.append({"receipt": path.name, "state": "needs_review"})
        # Nothing to finalise when the receipt directory was never created.
        if not self.receipts.exists(): return []
        _no_symlink_chain(self.receipts)
        # Second pass, in sorted order for deterministic output. Symlinks and unparsable
        # files are skipped or reported as invalid, never followed.
        for path in sorted(self.receipts.glob("*.json")):
            if path.is_symlink(): continue
            try: record = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError): outcomes.append({"receipt": path.name, "state": "invalid"}); continue
            if not isinstance(record, dict) or record.get("status") != "pending_queue_commit": continue
            # The file name must equal the name derived from its own job and attempt, which stops
            # a receipt being filed under another job's name.
            if (record.get("schema") != RECEIPT_SCHEMA or not isinstance(record.get("job_id"), str)
                    or not IDENT.fullmatch(record["job_id"]) or type(record.get("attempt")) is not int or record["attempt"] < 1
                    or path.name != f"{record['job_id']}-{record['attempt']:03d}.json"):
                outcomes.append({"receipt": path.name, "state": "invalid"}); continue
            try:
                job = self.queue.get(record["job_id"]); evidence = record["evidence"]
                artifacts = [_safe_ref(self.root, {"path": item["path"], "sha256": item["sha256"]}, after=0) for item in evidence["artifacts"]]
                checks = [_safe_ref(self.root, {"path": item["path"], "sha256": item["sha256"]}, after=0) for item in evidence["checks"]]
                # Finalise only on an exact match: same contract hash and attempt, and the queue's
                # stored result evidence equals the receipt's evidence. Referenced files are
                # re-hashed again as well (after=0 skips the freshness test, keeping the hash test).
                exact = (job["status"] in {"passed", "queued", "needs_review", "failed"} and job["contract_hash"] == record["contract_hash"]
                         and job["attempt"] == record["attempt"] and job.get("result", {}).get("evidence") == evidence)
                if not exact: raise WaypointError("queue result does not exactly match pending evidence")
                # The label follows the durable queue status, not the pending receipt's claim.
                label = "accepted" if job["status"] == "passed" else ("repair_stage" if job["status"] == "queued" else "owner_approval_required")
                final = dict(record); final.update({"status": job["status"], "action_label": label,
                    "next_action": "stage acceptance finalized from exact queue evidence" if label == "accepted" else record["next_action"]})
                self._write_receipt(final, overwrite=True); outcomes.append({"receipt": path.name, "state": "finalized"})
            # Any mismatch or error holds the receipt as needs_review for owner inspection
            # instead of guessing; work is never restarted automatically.
            except (OSError, QueueError, KeyError, TypeError, AttributeError, WaypointError):
                held = dict(record); held.update({"status": "needs_review", "action_label": "owner_approval_required", "next_action": "pending receipt does not exactly match durable queue evidence; inspect before any restart"})
                self._write_receipt(held, overwrite=True); outcomes.append({"receipt": path.name, "state": "needs_review"})
        return outcomes

    def record_adaptive_outcome(self, receipt: dict[str, Any], *, skill: str | None = None, state_path: Path | None = None) -> dict[str, Any]:
        """Record verified outcome of a Waypoint receipt into private adaptive learner."""
        # Imported lazily so the queue path has no dependency on the learning code.
        import enki_runtime
        return enki_runtime.record_waypoint_receipt(receipt, skill=skill, state_path=state_path)


def summary(state_dir: Path, *, root: Path = ROOT) -> dict[str, Any]:
    """Read only: never creates a directory, changes permissions, or initializes SQLite."""
    # Read-only observer: it must not create directories, change permissions or
    # initialise SQLite, so every unsafe or missing situation maps to a state string.
    state_dir = local_state_path(state_dir)
    path = state_dir / "jobs.sqlite3"
    try:
        _no_symlink_chain(path.parent)
    except (OSError, QueueError):
        return {"schema": SCHEMA, "state": "unavailable", "jobs": 0}
    if path.is_symlink() or (path.exists() and not path.is_file()):
        return {"schema": SCHEMA, "state": "unavailable", "jobs": 0}
    if not path.exists():
        return {"schema": SCHEMA, "state": "not_initialized", "jobs": 0}
    try:
        try:
            # First try a true read-only URI connection; the quote() call keeps odd characters in
            # the path from being parsed as URI syntax.
            connection = sqlite3.connect("file:" + quote(str(path)) + "?mode=ro", uri=True)
            try:
                rows = connection.execute("SELECT status,contract_json FROM jobs").fetchall()
            finally: connection.close()
        except sqlite3.OperationalError:
            # Fallback for builds that cannot open read-only URIs; query_only still prevents any
            # write.
            connection = sqlite3.connect(str(path))
            try:
                connection.execute("PRAGMA query_only = ON")
                rows = connection.execute("SELECT status,contract_json FROM jobs").fetchall()
            finally: connection.close()
        waypoint = 0; statuses: dict[str, int] = {}
        # Stored contracts are decoded defensively; non-Waypoint jobs are ignored here.
        for status, raw in rows:
            decoded = json.loads(raw)
            contract = decoded.get("spec", {}) if isinstance(decoded, dict) else {}
            if contract.get("recipe") == "enki.waypoint" and contract.get("schema") == SCHEMA:
                waypoint += 1; statuses[status] = statuses.get(status, 0) + 1
        # Tally receipt states without reading more than each file once; unreadable files are
        # counted as invalid.
        receipts = state_dir / "waypoint-receipts"; pending = invalid = review = 0
        if receipts.exists() and not receipts.is_symlink():
            for item in receipts.glob("*.json"):
                try:
                    record = json.loads(item.read_text(encoding="utf-8")); state = record.get("status")
                    pending += state == "pending_queue_commit"; review += state == "needs_review"
                except (OSError, ValueError, AttributeError): invalid += 1
        return {"schema": SCHEMA, "state": "observed", "jobs": waypoint, "by_status": statuses,
                "pending_receipts": pending, "needs_review_receipts": review, "invalid_receipts": invalid,
                "rule": "queue pass is not finalized acceptance while a pending receipt exists"}
    # Summary never raises: any failure is reported as an unavailable state.
    except (OSError, sqlite3.Error, ValueError, TypeError, AttributeError):
        return {"schema": SCHEMA, "state": "unavailable", "jobs": 0}


def main(argv=None) -> int:
    """Command-line entry point for create, claim, finish, record-adaptive, status and reconcile; prints JSON and returns 0."""
    # Subcommands correspond to Waypoint methods. State defaults to a waypoint folder
    # inside the queue's default private state directory.
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, default=default_state_dir(ROOT) / "waypoint", help="private local JobQueue state directory")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create"); create.add_argument("contract_json", type=Path); create.add_argument("--job-id")
    claim = sub.add_parser("claim"); claim.add_argument("actor")
    claim.add_argument("--job-id", help="claim only this stage; never fall back to another queued job")
    claim.add_argument("--lease-seconds", type=int, default=300)
    finish = sub.add_parser("finish"); finish.add_argument("claim_json", type=Path); finish.add_argument("artifacts_json", type=Path); finish.add_argument("checks_json", type=Path); finish.add_argument("review_json", type=Path); finish.add_argument("reflection_json", type=Path)
    record_adaptive = sub.add_parser("record-adaptive"); record_adaptive.add_argument("receipt_json", type=Path); record_adaptive.add_argument("--skill")
    sub.add_parser("status"); sub.add_parser("reconcile")
    args = parser.parse_args(argv)
    # Status and reconcile are handled first; status never opens the queue for writing.
    if args.command == "status":
        print(json.dumps(summary(args.state_dir), sort_keys=True)); return 0
    waypoint = Waypoint(args.state_dir)
    if args.command == "reconcile":
        print(json.dumps(waypoint.reconcile(), sort_keys=True)); return 0
    if args.command == "create":
        print(json.dumps({"job_id": waypoint.prepare(json.loads(args.contract_json.read_text()), job_id=args.job_id)}, sort_keys=True))
    elif args.command == "claim":
        print(json.dumps(waypoint.claim(args.actor, args.lease_seconds, job_id=args.job_id), sort_keys=True))
    elif args.command == "finish":
        # Each input JSON file is read and parsed independently; all validation happens in
        # finish().
        loads = lambda path: json.loads(path.read_text())
        print(json.dumps(waypoint.finish(loads(args.claim_json), artifacts=loads(args.artifacts_json), checks=loads(args.checks_json), review=loads(args.review_json), reflection=loads(args.reflection_json)), sort_keys=True))
    elif args.command == "record-adaptive":
        receipt_data = json.loads(args.receipt_json.read_text(encoding="utf-8"))
        print(json.dumps(waypoint.record_adaptive_outcome(receipt_data, skill=args.skill), sort_keys=True))
    else:
        print(json.dumps(waypoint.inspect(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
