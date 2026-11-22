#!/usr/bin/env python3
"""Enki Runtime: task dispatch, LinUCB task recommendation, and BKT outcome tracking.

This module integrates the private adaptive learning engine (BKT / LinUCB) into the
Enki runtime. It queries the adaptive learner for practice task recommendation
(via LinUCB) and records verified outcome updates (via BKT), respecting private state
persistence under the adaptive state root (env ENKI_ADAPTIVE_STATE_ROOT, default ./state under the component folder).

Deterministic stdlib only; no network access, no background daemons, no model training.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import re
import sys
from typing import Any, Iterable

# Component root (the folder above scripts/). It is only used to anchor defaults;
# all learner state still goes through the private state root in the learning module.
ROOT = Path(__file__).resolve().parents[1]
# Directory of this file, resolved through symlinks so the path inserted below is the
# real location of the sibling modules.
SCRIPTS_DIR = Path(__file__).resolve().parent
# Make the sibling learning module importable when this file is run directly as a
# script, where the scripts folder is not automatically first on sys.path.
# Guarded so repeated imports do not stack duplicate entries.
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

# Imported after the path fix above on purpose; moving it to the top would break
# direct execution of this file.
import enki_adaptive_learning as al
from enki_adaptive_learning import AdaptiveLearner, PracticeTask, BKTParameters

# Schema tags stamped on every JSON payload this module emits, so consumers can
# reject output from an incompatible version instead of guessing at its shape.
SCHEMA_RECOMMENDATION = "enki.runtime-recommendation.v1"
SCHEMA_OUTCOME = "enki.runtime-outcome.v1"
SCHEMA_STATUS = "enki.runtime-status.v1"


def _now() -> str:
    """Return the current UTC time as an ISO-8601 string with a trailing Z and no microseconds."""
    # Drop microseconds for stable, compact timestamps and swap the +00:00 suffix for
    # the conventional Z so the value is identical across platforms.
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _clean_ident(value: Any, name: str) -> str:
    """Return value unchanged if it is a string matching the learner's identifier pattern; raise ValueError naming the offending field otherwise."""
    # Identifiers are the only user-supplied text allowed into learner state. Forcing
    # them through the shared KEY_ID pattern keeps prompt or answer content out of the
    # persisted file and stops path-like or oversized keys.
    if not isinstance(value, str) or not al.KEY_ID.fullmatch(value):
        raise ValueError(f"{name} must be a non-content identifier (letters, numbers, . _ : -)")
    return value


def _as_practice_task(item: PracticeTask | dict[str, Any]) -> PracticeTask:
    """Coerce a PracticeTask or a plain dict into a validated PracticeTask; raise ValueError on missing, malformed or non-identifier fields."""
    # Already-validated objects pass straight through; PracticeTask validates itself in
    # its constructor, so re-checking here would be redundant.
    if isinstance(item, PracticeTask):
        return item
    # Anything else (lists, strings, None) is rejected up front so the failure message
    # points at the candidate rather than at a later attribute error.
    if not isinstance(item, dict):
        raise ValueError("candidate task must be a PracticeTask or dictionary")
    # Identifiers are cleaned before any numeric conversion so a bad identifier is
    # reported first and never reaches the float() calls below.
    task_id = _clean_ident(item.get("task_id"), "task_id")
    skill = _clean_ident(item.get("skill"), "skill")
    need = item.get("need")
    expected_gain = item.get("expected_gain")
    # need and expected_gain have no safe default: guessing them would silently bias
    # the bandit toward or away from a task. The cost fields below default to zero.
    if need is None or expected_gain is None:
        raise ValueError("candidate task requires 'need' and 'expected_gain'")
    return PracticeTask(
        task_id=task_id,
        skill=skill,
        need=float(need),
        expected_gain=float(expected_gain),
        time_cost=float(item.get("time_cost", 0.0)),
        compute_cost=float(item.get("compute_cost", 0.0)),
        risk=float(item.get("risk", 0.0)),
        # Candidates default to safe because the caller is documented to filter through the
        # command, privacy, compute and thermal gates before calling; an explicit False
        # still excludes the task from selection.
        safe=bool(item.get("safe", True)),
    )


# Thin wrapper kept as a single seam so callers and tests can replace how state is
# loaded without touching the recommend and record paths.
def get_learner(state_path: Path | None = None) -> AdaptiveLearner:
    """Load the private adaptive learner from the given path or default private state root."""
    return AdaptiveLearner.load_private(state_path)


def recommend_task(
    candidates: Iterable[PracticeTask | dict[str, Any]],
    *,
    state_path: Path | None = None,
    learner: AdaptiveLearner | None = None,
) -> dict[str, Any]:
    """Query the adaptive learner for practice task recommendation via LinUCB."""
    # Materialize once: the iterable may be a generator, and it is read both for the
    # emptiness check and for conversion.
    raw_list = list(candidates)
    # Refuse an empty candidate set; the bandit has nothing to rank and returning a
    # made-up task would look like a real recommendation.
    if not raw_list:
        raise ValueError("no candidate tasks provided for recommendation")
    # Convert every candidate before selecting, so one malformed entry fails the whole
    # call instead of being silently dropped from the ranking.
    tasks = [_as_practice_task(item) for item in raw_list]
    # An injected learner lets tests and callers reuse in-memory state; otherwise state
    # is loaded from the private store, which re-checks directory permissions.
    if learner is None:
        learner = get_learner(state_path)
    # LinUCB picks the task with the highest upper-confidence score after cost and
    # risk penalties, skipping tasks flagged unsafe or with an unknown skill state.
    chosen = learner.choose(tasks)
    # Recompute the feature vector and score for the chosen task only so the report can
    # show what the bandit saw; selection itself already happened above.
    mastery = learner.mastery_for(chosen.skill)
    # Feature order is (bias, need, 1 - mastery, uncertainty, expected_gain); it must
    # match the order used when the arm was trained or the score is meaningless.
    features = chosen.features(mastery)
    score = learner.bandit.score(chosen.task_id, features)
    # Bernoulli standard deviation of the mastery estimate: largest at 0.5, zero at 0 or
    # 1. The max() guards against tiny negative rounding error under the square root.
    uncertainty = math.sqrt(max(0.0, mastery * (1.0 - mastery)))
    return {
        # Plain data only: no candidate descriptions or other free text leave this function.
        "schema": SCHEMA_RECOMMENDATION,
        "task_id": chosen.task_id,
        "skill": chosen.skill,
        "score": score,
        "mastery": mastery,
        "uncertainty": uncertainty,
        "features": list(features),
        "task": asdict(chosen),
        "recommended_at": _now(),
    }


def record_outcome(
    task: PracticeTask | dict[str, Any] | str,
    correct: bool,
    reward: float = 1.0,
    *,
    verified: bool = True,
    skill: str | None = None,
    need: float = 0.5,
    expected_gain: float = 0.5,
    state_path: Path | None = None,
    learner: AdaptiveLearner | None = None,
) -> dict[str, Any]:
    """Record a verified task outcome into BKT and LinUCB, saving private state."""
    # Outcome gate, three checks in order. Only an explicit verified=True is accepted
    # (identity test, so truthy values like 1 or "yes" fail): an unverified result must
    # never move mastery or bandit statistics.
    if verified is not True:
        raise ValueError("outcome updates require verified=True; unverified outcomes are refused")
    # Exact type test rather than isinstance: bool subclasses int, and ints such as 0/1
    # or numpy values must not slip in as a verdict.
    if type(correct) is not bool:
        raise ValueError("correct must be a verified boolean")
    # Reward feeds the LinUCB b vector directly, so it must be a real finite number in
    # [0, 1]; NaN, infinity and booleans would corrupt the arm permanently.
    if isinstance(reward, bool) or not isinstance(reward, (int, float)) or not math.isfinite(reward) or not 0 <= reward <= 1:
        raise ValueError("reward must be a finite probability in [0, 1]")

    # A bare string is shorthand for a task id. The skill defaults to the id itself, and
    # need/expected_gain take the neutral 0.5 defaults supplied by the caller.
    if isinstance(task, str):
        task_id = _clean_ident(task, "task_id")
        skill_id = _clean_ident(skill or task, "skill")
        practice_task = PracticeTask(
            task_id=task_id,
            skill=skill_id,
            need=need,
            expected_gain=expected_gain,
            safe=True,
        )
    else:
        practice_task = _as_practice_task(task)

    # Same lazy load as in recommend_task. Loading happens after validation so a rejected
    # outcome never touches the state directory at all.
    if learner is None:
        learner = get_learner(state_path)

    # Snapshot mastery before the update so the result can show the BKT movement.
    # observe() then applies the Bayesian posterior and the learning transition for the
    # skill and updates the bandit arm with the same feature vector used for selection.
    before = learner.mastery_for(practice_task.skill)
    after = learner.observe(practice_task, correct=correct, reward=float(reward), verified=True)
    # Persist only after both models updated in memory. save_private validates the path,
    # writes a temporary file and renames it, so a crash never leaves a half-written
    # state file.
    saved_target = learner.save_private(state_path)

    return {
        "schema": SCHEMA_OUTCOME,
        "task_id": practice_task.task_id,
        "skill": practice_task.skill,
        "verified": True,
        "correct": correct,
        "reward": float(reward),
        "mastery_before": before,
        "mastery_after": after,
        "saved_path": str(saved_target),
        "recorded_at": _now(),
    }


def record_waypoint_receipt(
    receipt: dict[str, Any] | Path | str,
    *,
    skill: str | None = None,
    need: float = 0.5,
    expected_gain: float = 0.5,
    reward: float | None = None,
    state_path: Path | None = None,
    learner: AdaptiveLearner | None = None,
) -> dict[str, Any]:
    """Record a verified outcome from a finalized Enki Waypoint stage receipt."""
    # Accept either an in-memory receipt or a path to one on disk; any other type is
    # rejected below rather than coerced.
    if isinstance(receipt, (str, Path)):
        receipt_path = Path(receipt)
        if not receipt_path.is_file():
            raise ValueError(f"receipt file does not exist: {receipt_path}")
        data = json.loads(receipt_path.read_text(encoding="utf-8"))
    # In-memory receipts skip the file checks but still go through the schema and status
    # validation that follows.
    elif isinstance(receipt, dict):
        data = receipt
    else:
        raise ValueError("receipt must be a dictionary or a path to a receipt JSON file")

    # Refuse receipts from any other producer or version; the field meanings below are
    # only guaranteed for this exact schema.
    if data.get("schema") != "enki.waypoint-receipt.v1":
        raise ValueError("invalid receipt schema; expected enki.waypoint-receipt.v1")

    status = data.get("status")
    # A pending receipt is written before the queue commit and may describe work that
    # never finished. Learning from it could reward an outcome that was later refused,
    # so only finalized receipts count.
    if status == "pending_queue_commit":
        raise ValueError("cannot record outcome from pending receipt; receipt must be finalized")
    if status not in {"passed", "failed", "needs_review"}:
        raise ValueError(f"unsupported receipt status: {status}")

    # Success requires both signals: the queue status says passed AND the label says the
    # independent review accepted. A queue pass without acceptance earns no credit.
    # Unless the caller overrides it, reward is 1.0 for acceptance and 0.0 otherwise.
    action_label = data.get("action_label")
    # The acceptance flag doubles as the correctness verdict recorded into BKT.
    is_accepted = (status == "passed" and action_label == "accepted")
    # An explicit reward from the caller wins; otherwise the reward is derived from the
    # acceptance verdict computed above.
    reward_val = float(reward) if reward is not None else (1.0 if is_accepted else 0.0)

    # The job id becomes the bandit arm key, so it gets the same identifier check as any
    # other task id. The skill falls back to a generic stage label when none is given.
    job_id = _clean_ident(data.get("job_id"), "job_id")
    skill_name = _clean_ident(skill or "waypoint_stage", "skill")

    return record_outcome(
        task=job_id,
        correct=is_accepted,
        reward=reward_val,
        verified=True,
        skill=skill_name,
        need=need,
        expected_gain=expected_gain,
        state_path=state_path,
        learner=learner,
    )


def runtime_status(*, state_path: Path | None = None) -> dict[str, Any]:
    """Read the current status of the adaptive learning runtime without leaking secrets."""
    # Status is a read-only view: it never creates the state directory or file. A missing
    # file is reported as not initialized and shown with a fresh default learner.
    target = Path(state_path) if state_path is not None else al.PRIVATE_STATE_ROOT / "learner.json"
    # Existence check only; it does not open or parse the file, so a status call on an
    # uninitialized install has no side effects.
    initialized = target.exists()
    try:
        # load_private performs the full validation (permissions, symlinks, size, schema,
        # matrix symmetry and positive definiteness), so a tampered file lands in the except
        # branch below instead of producing misleading numbers.
        learner = AdaptiveLearner.load_private(target) if initialized else AdaptiveLearner()
        tracked = len(learner.mastery)
        mastery = dict(sorted(learner.mastery.items()))
        arms = len(learner.bandit.arms)
        params = asdict(learner.parameters)
        status_state = "ready"
    # Broad on purpose: a status command must always answer. The error text goes into the
    # state field and the counters fall back to zero or defaults.
    except Exception as exc:
        status_state = f"error: {exc}"
        tracked = 0
        mastery = {}
        arms = 0
        # On error the report still shows the default BKT parameters so the output keeps the
        # same shape and consumers do not need a special case for failures.
        params = asdict(BKTParameters())

    return {
        "schema": SCHEMA_STATUS,
        # Only counts, mastery numbers and parameters are reported; arm matrices and anything
        # else that could reveal task history stay out of the output.
        "mode": "private_adaptive_learning",
        "engine": "BKT_LinUCB",
        "state": status_state,
        "state_initialized": initialized,
        "state_path": str(target),
        "tracked_skills": tracked,
        "mastery": mastery,
        "bandit_arms": arms,
        "parameters": params,
    }


def main(argv=None) -> int:
    """Command-line entry point: parse argv, dispatch to the status, recommend, record or record-receipt command, print JSON and return the exit code."""
    # Top-level options come first, then one subcommand. The module docstring doubles as
    # the help text so the two cannot drift apart.
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-path", type=Path, default=None, help="path to private learner state")
    # A subcommand is mandatory; running with none prints usage instead of doing nothing.
    sub = parser.add_subparsers(dest="command", required=True)

    # Subcommands mirror the public functions: recommend maps to recommend_task, record
    # to record_outcome, record-receipt to record_waypoint_receipt.
    recommend_cmd = sub.add_parser("recommend", help="recommend the best practice task via LinUCB")
    recommend_cmd.add_argument("--candidates", required=True, help="JSON file or JSON string containing candidate tasks")

    record_cmd = sub.add_parser("record", help="record verified outcome via BKT and LinUCB")
    record_cmd.add_argument("--task", required=True, help="task identifier")
    record_cmd.add_argument("--skill", required=True, help="skill identifier")
    # Exactly one of --correct / --incorrect is required, so the verdict is always
    # explicit and never defaulted.
    record_group = record_cmd.add_mutually_exclusive_group(required=True)
    record_group.add_argument("--correct", action="store_true", help="outcome was correct / passed")
    record_group.add_argument("--incorrect", action="store_true", help="outcome was incorrect / failed")
    record_cmd.add_argument("--reward", type=float, default=1.0, help="reward value in [0, 1]")
    record_cmd.add_argument("--need", type=float, default=0.5, help="task need value in [0, 1]")
    record_cmd.add_argument("--gain", type=float, default=0.5, help="expected gain value in [0, 1]")

    # record-receipt takes the receipt path positionally; the verified outcome is read
    # from the file, so there is no correct/incorrect flag here.
    receipt_cmd = sub.add_parser("record-receipt", help="record outcome from a Waypoint receipt JSON")
    receipt_cmd.add_argument("receipt_json", type=Path, help="path to enki.waypoint-receipt.v1 JSON")
    receipt_cmd.add_argument("--skill", default="waypoint_stage", help="skill identifier")
    receipt_cmd.add_argument("--reward", type=float, default=None, help="custom reward value in [0, 1]")

    sub.add_parser("status", help="show runtime status and mastery tracking overview")

    # Dispatch below: each branch prints sorted-key JSON so output is deterministic and
    # diffable, and returns 0 only after the operation succeeded (errors raise).
    args = parser.parse_args(argv)

    if args.command == "status":
        # The status path never loads a learner for writing and exits before any state could
        # be saved.
        print(json.dumps(runtime_status(state_path=args.state_path), indent=2, sort_keys=True))
        return 0

    # --candidates takes either a file path or an inline JSON string; an existing file
    # wins. A wrapper object with a tasks key is unwrapped for convenience.
    if args.command == "recommend":
        candidates_raw = args.candidates.strip()
        # Treat the argument as a path first; if it is not an existing file it must be an
        # inline JSON document, and a parse error is raised to the operator as-is.
        if Path(candidates_raw).is_file():
            data = json.loads(Path(candidates_raw).read_text(encoding="utf-8"))
        else:
            data = json.loads(candidates_raw)
        # Accept either a bare list of candidates or an object wrapping them under tasks.
        if isinstance(data, dict) and "tasks" in data:
            data = data["tasks"]
        result = recommend_task(data, state_path=args.state_path)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    if args.command == "record":
        # The mutually exclusive group guarantees one flag is set, so the absence of --correct
        # means --incorrect.
        correct = True if args.correct else False
        result = record_outcome(
            task=args.task,
            correct=correct,
            reward=args.reward,
            verified=True,
            skill=args.skill,
            need=args.need,
            expected_gain=args.gain,
            state_path=args.state_path,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    # Verified-ness here comes from the receipt itself (schema, finalized status), not
    # from a command-line flag the operator could simply assert.
    if args.command == "record-receipt":
        result = record_waypoint_receipt(
            args.receipt_json,
            skill=args.skill,
            reward=args.reward,
            state_path=args.state_path,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    return 0


# Convert the integer return code into the process exit status.
if __name__ == "__main__":
    raise SystemExit(main())
