"""Split a known onboarding fixture into checked, single-case model calls.

The caller still submits the returned JSON to the original parent validator.
Each invocation requires a fresh machine-local output directory. No inference
is supplied here: model_generate must return actual model text for each child.
"""
from __future__ import annotations

import json
from pathlib import Path

# Reuse the controller, JSON helpers and fixed fixture so child checks cannot drift from the parent's.
from malakopia_completion import complete_task
from malakopia_engine import atomic_json, clone, digest
from malakopia_local_tasks import EXPECTED, specs


def _checked_spec(spec):
    """Return a copy of the spec's id/goal/acceptance after confirming it matches the known fixture; raise ValueError otherwise."""
    # Only fixtures with a known expected-answer map are allowed; anything else cannot be scored here.
    if not isinstance(spec, dict) or spec.get('id') not in EXPECTED:
        raise ValueError('Decomposition requires a known onboarding task')
    # Copy just the three needed fields so extra caller keys cannot leak into the child tasks.
    original = clone({key: spec[key] for key in ('id', 'goal', 'acceptance')})
    # Look up the canonical contract by ID; the caller's copy is compared against it and never trusted.
    canonical = next(task for task in specs() if task['id'] == original['id'])['acceptance']
    supplied = original['acceptance']
    # The acceptance contract must be a mapping so its keys can be compared.
    if not isinstance(supplied, dict):
        raise ValueError('The original acceptance contract must be an object')
    # Rules, allowed decisions and input cases determine the expected answers. If any of them differ,
    # the stored answers may be stale, so refuse instead of scoring a changed case against an old answer.
    for key in ('rules', 'allowed_decisions', 'input_cases'):
        if supplied.get(key) != canonical[key]:
            raise ValueError('Original onboarding ' + key + ' changed; requalify its answer checks first')
    return original


def _single_validator(identifier, expected, allowed):
    """Build the validator for one case: it accepts only {id, decision} whose decision equals the expected answer."""
    # The closure holds the expected answer; the model never sees it.
    def validate(candidate):
        """Return {passed, failures, evidence} for one candidate, in the shape the completion controller requires."""
        # Collect every problem instead of stopping at the first, so the repair prompt can list them all.
        failures = []
        # schema_valid flips to True only after the shape check below passes.
        # The expected answer is stored in evidence for reviewers only; it is never placed into any prompt.
        evidence = {'case_id': identifier, 'expected': expected, 'schema_valid': False}
        # Exactly two keys: extra keys such as reasons or completion claims are not allowed.
        if not isinstance(candidate, dict) or set(candidate) != {'id', 'decision'}:
            failures.append('Output must contain exactly id and decision')
        else:
            evidence['schema_valid'] = True
            # The ID must echo the single supplied case, so a model cannot answer a different one.
            if candidate['id'] != identifier:
                failures.append('id must match the supplied input case: ' + identifier)
            # The allowed-set check precedes the answer check, so an out-of-vocabulary value gets the clearer message.
            decision = candidate['decision']
            if not isinstance(decision, str) or decision not in allowed:
                failures.append(identifier + ': decision is not allowed')
            elif decision != expected:
                failures.append(f'{identifier}: expected {expected}, received {decision}')
            # Keep a copy of what the model produced as evidence.
            evidence['observed'] = clone(candidate)
        return {'passed': not failures, 'failures': failures, 'evidence': evidence}
    return validate


def _record_child_metrics(journal, folder, parent):
    """Attach per-case decomposition metrics to the child's journal and rewrite its run.json."""
    # The first attempt is the fair measure of the model, because later attempts received validator feedback.
    first = journal['attempts'][0] if journal['attempts'] else {}
    # A first attempt that errored inside a callback was never scored, so it is reported as None, not as failed.
    scored = first.get('status') in ('accepted', 'rejected')
    # The scope string states plainly that this covers one fixed case and is not a general qualification.
    journal['decomposition'] = {
        # Hash the parent spec so the evidence is tied to the exact contract that was used.
        'parent_task_id': parent['id'], 'parent_spec_sha256': digest(parent),
        'scope': 'one fixed onboarding case; no general worker qualification',
        'first_attempt_scored': scored,
        'first_attempt_passed': first.get('status') == 'accepted' if scored else None,
        'accepted_after_feedback': journal['status'] == 'completed' and len(journal['attempts']) > 1,
        'attempt_count': len(journal['attempts']),
    }
    # Rewrite the journal so the metrics sit beside the attempt evidence.
    atomic_json(folder / 'run.json', journal)


def generate_decomposed(spec, model_generate, output_dir):
    """Return rows from accepted child responses; halt if any child cannot pass.

Use as a parent's generator callback with a fresh output_dir for each invocation.
Original input cases and rules must match the known fixed fixture. This prevents
an altered case from being accepted using a stale, fixed expected-answer map.
"""
    # Validate the spec before creating any directory or calling any model.
    parent = _checked_spec(spec)
    # There is no built-in model: the caller must supply real generation.
    if not callable(model_generate):
        raise ValueError('An explicit model generator is required')
    # Resolve first so '..' tricks or symlinks cannot slip past the workspace check below.
    output = Path(output_dir).expanduser().resolve()
    # Live evidence must stay outside the source tree.
    if output.is_relative_to(Path(__file__).resolve().parents[1]):
        raise ValueError('Live decomposition evidence must stay outside the workspace')
    # exist_ok=False makes the directory an exclusive reservation; reusing a folder would mix evidence from two runs.
    output.mkdir(parents=True, exist_ok=False)
    original = parent['acceptance']
    # Accepted child answers are collected in input order, matching the parent's case order.
    decisions = []
    # One child task per input case, so each model call has a single, small decision.
    for case in original['input_cases']:
        identifier = case['id']
        # Folder names come from validated fixture IDs, never from model output.
        folder = output / identifier
        # The child contract copies the original rules and allowed decisions unchanged but includes only one case.
        acceptance = {
            'rules': clone(original['rules']),
            'input_cases': [clone(case)],
            'allowed_decisions': clone(original['allowed_decisions']),
            # Narrower output contract than the parent's: just id and decision, nothing extra.
            'output_contract': {'top_level_keys': ['id', 'decision'], 'extra_keys_allowed': False},
        }
        # The goal restates rule ordering and forbids extra content; the validator enforces the same constraints.
        goal = (f'Decide only the supplied case "{identifier}" for the {parent["id"]} task. '
                'Apply every original rule in its listed order. Return one JSON object with '
                'exactly id and decision. Copy the input case id and select one allowed decision. '
                'Do not include other cases, reasons, or a claim that the task is finished.')
        # The expected answer comes from the fixed map and is used only inside the validator.
        validate = _single_validator(identifier, EXPECTED[parent['id']][identifier],
                                     tuple(original['allowed_decisions']))
        # Two attempts per case: one try plus a single repair with validator feedback.
        try:
            # Each child gets its own folder and journal, so a failure is traceable to one case.
            journal = complete_task(identifier, goal, acceptance, model_generate, validate,
                                    folder, max_attempts=2)
        # BaseException includes interruption. The controller already saved the partial attempt, so attach
        # the metrics to it before re-raising.
        except BaseException:
            # The controller persists interrupted attempts before rethrowing.
            # If the child died before its first save there is no journal yet, so there is nothing to annotate.
            saved = folder / 'run.json'
            if saved.is_file():
                _record_child_metrics(json.loads(saved.read_text()), folder, parent)
            raise
        # Record metrics for the normal outcome, whether the child passed or not.
        _record_child_metrics(journal, folder, parent)
        # Any non-completed status halts the whole decomposition; a partial answer set is never returned.
        if journal['status'] != 'completed':
            raise RuntimeError(f'needs_manager: child {identifier} did not pass: '
                               f'{journal.get("reason", journal["status"])}; evidence: {folder / "run.json"}')
        # Never synthesize the expected answer: take the checked model artifact.
        decisions.append(clone(journal['accepted_candidate']))
    # The output shape matches the parent task's expected format: {"decisions": [...]}.
    return json.dumps({'decisions': decisions}, ensure_ascii=False)
