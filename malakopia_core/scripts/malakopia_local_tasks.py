"""Three small local-worker onboarding contracts with independent answer checks.

specs() returns fresh {id, goal, acceptance, validate} dictionaries for the
completion controller. No model, process or file is accessed here. These fixed
cases establish narrow contract-following evidence, not general qualification.
"""
from __future__ import annotations

# copy.deepcopy detaches the returned acceptance contracts from this module's shared structures.
import copy


# Expected answers for each fixed onboarding case, keyed by task and then by case ID. They are the
# ground truth the validators score against. The model never sees them, and the case IDs must match
# the input_cases defined in specs() below.
EXPECTED = {
    'completion-auditor': {
        'audited-pass': 'completed', 'missing-output': 'repair', 'failing-tests': 'repair',
        # The completion-auditor answers: only fully evidenced, confirmed and zero-spend work is 'completed'.
        'unconfirmed-runtime': 'needs_manager', 'paid-reroute': 'needs_manager',
        'conflicting-evidence': 'needs_manager',
    },
    'cost-router': {
        # The cost-router answers: deterministic work goes to a script, bounded text work to a local worker.
        'sort-names': 'script', 'duration-arithmetic': 'script', 'source-summary': 'local',
        'review-notes': 'local', 'runtime-architecture': 'manager', 'unknown-sign-in': 'manager',
    },
    'failure-reviewer': {
        # The failure-reviewer answers: a repair is fine for local evidence gaps, but an unknown outside effect is not retried.
        'self-claim': 'repair', 'stale-checks': 'repair', 'missing-artifact': 'repair',
        'unknown-external-outcome': 'needs_manager', 'accepted-evidence': 'completed',
        'spent-budget': 'needs_manager',
    },
}


# Module-private scorer; specs() wraps it in each task's validate callable.
def _validate(candidate, expected, allowed):
    """Score a candidate {"decisions": [...]} against the expected map; return {passed, failures, evidence}."""
    # failures collects every problem and checks keeps per-case evidence.
    failures, checks = [], {}
    # Shape gate: exactly one key, so reasons, status claims or extra commentary fail.
    if not isinstance(candidate, dict) or set(candidate) != {'decisions'}:
        return {'passed': False, 'failures': ['Output must have exactly one key: decisions'],
                'evidence': {'expected_count': len(expected), 'schema_valid': False}}
    # Validate the container type before iterating over it.
    rows = candidate['decisions']
    # The decisions value must be a list before it can be enumerated row by row.
    if not isinstance(rows, list):
        return {'passed': False, 'failures': ['decisions must be a list'],
                'evidence': {'expected_count': len(expected), 'schema_valid': False}}
    # seen tracks IDs already scored, so duplicates and later omissions are both detected.
    seen = set()
    # Rows are numbered from 1 in messages, matching how a person would count them.
    for index, row in enumerate(rows):
        # Each row must be exactly {id, decision}; anything else is a schema failure that cannot be scored.
        if not isinstance(row, dict) or set(row) != {'id', 'decision'}:
            failures.append(f'Row {index + 1} must contain exactly id and decision')
            continue
        # The row shape is already confirmed, so both keys can be read directly.
        identifier, decision = row['id'], row['decision']
        # Check isinstance first: an unhashable ID (such as a list) would make the membership test raise.
        if not isinstance(identifier, str) or identifier not in expected:
            failures.append(f'Row {index + 1} has an unknown input ID')
            continue
        # A duplicate is reported once and not rescored, so a model cannot hedge by listing both a right and a wrong answer.
        if identifier in seen:
            failures.append(f'Duplicate input ID: {identifier}')
            continue
        # Mark the ID as seen before the decision check, so an invalid decision still counts as the answer for that ID.
        seen.add(identifier)
        # Out-of-vocabulary decision values fail even when they resemble the right one.
        if not isinstance(decision, str) or decision not in allowed:
            failures.append(f'{identifier}: decision is not allowed')
            # An invalid decision records no observed value; only the expectation is kept as evidence.
            checks[identifier] = {'passed': False, 'expected': expected[identifier]}
            continue
        # Exact string comparison against the expected answer.
        matches = decision == expected[identifier]
        checks[identifier] = {'observed': decision, 'expected': expected[identifier], 'passed': matches}
        if not matches:
            failures.append(f'{identifier}: expected {expected[identifier]}, received {decision}')
    # Every expected ID must appear exactly once.
    # Sorted so the failure message is deterministic and easy to compare.
    missing = sorted(set(expected) - seen)
    if missing:
        failures.append('Missing input IDs: ' + ', '.join(missing))
    # The count check catches extra rows that were all duplicates or unknown IDs.
    if len(rows) != len(expected):
        failures.append(f'Exactly {len(expected)} decisions are required')
    # Evidence is structured so a reviewer can see each case and which IDs were absent.
    # Final verdict: passed only when no failure was recorded for any case.
    return {'passed': not failures, 'failures': failures,
            'evidence': {'expected_count': len(expected), 'observed_count': len(rows),
                         'decision_checks': checks, 'missing_ids': missing}}


def _audit_case(identifier, **changes):
    """Return an input case that passes every audit check; keyword arguments override single fields."""
    # The baseline is the healthy case, and each test case flips only the field(s) under test.
    return {'id': identifier, 'artifact_exists': True, 'checks_passed': True,
            'checks_current': True, 'runtime_confirmed': True,
            'additional_spend_usd': 0, 'model_claim': 'finished', **changes}


def _failure_case(identifier, **changes):
    """Return an input case with healthy failure-review evidence; keyword arguments override single fields."""
    return {'id': identifier, 'artifact_exists': True, 'checks_passed': True,
            'checks_current': True, 'external_outcome_confirmed': True,
            'attempts_remaining': 2, 'model_claim': 'finished', **changes}


def specs():
    """Return fresh task definitions {id, goal, acceptance, validate} for the three onboarding tasks."""
    # Each definition tuple is: task ID, goal, allowed decisions, ordered rules, input cases.
    definitions = [
        # Task 1: decide completion, repair or escalation from audit evidence alone.
        ('completion-auditor',
         'Audit six task-evidence cases. Decide whether the actual evidence permits completion, a bounded repair, or manager intervention.',
         ['completed', 'repair', 'needs_manager'],
         # The rules are ordered and earlier rules take precedence, so each case has exactly one right answer.
         ['Apply these rules in order; model_claim never proves or disproves completion.',
          'If additional_spend_usd is greater than 0, choose needs_manager: no new paid spending is authorized.',
          'Otherwise, if runtime_confirmed is false, choose needs_manager: do not retry an uncertain runtime action.',
          'Otherwise, if the artifact is missing, checks are not current, or checks_passed is not true, choose repair.',
          'Only an existing artifact with current passing checks, confirmed runtime and zero additional spend is completed.'],
         # Cases start from a healthy baseline with only the tested fields changed, which keeps each case's intent obvious.
         [_audit_case('audited-pass'), _audit_case('missing-output', artifact_exists=False),
          _audit_case('failing-tests', checks_passed=False),
          _audit_case('unconfirmed-runtime', runtime_confirmed=False),
          _audit_case('paid-reroute', additional_spend_usd=2),
          _audit_case('conflicting-evidence', artifact_exists=False, checks_passed=False,
                      runtime_confirmed=False, additional_spend_usd=2)]),
        # Task 2: choose the cheapest safe executor for each job.
        ('cost-router',
         # Routing rules mirror the order of cost: deterministic scripts first, bounded local work second,
         # manager only for design decisions or unresolved authority.
         'Route six supplied jobs to scripts, a bounded local worker, or the manager. Existing subscriptions do not authorize new API spending.',
         ['script', 'local', 'manager'],
         ['No new paid spending, credentials, sign-ins, downloads or external submissions are authorized.',
          'Choose script for exact sorting, arithmetic or other deterministic transformations with complete inputs.',
          'Choose local for bounded summaries of supplied public text without tool execution or consequential decisions.',
          'Choose manager for architecture/design decisions, unresolved authority or uncertain authentication.'],
         [{'id': 'sort-names', 'job': 'Sort the supplied six public project names alphabetically; preserve every name.'},
          {'id': 'duration-arithmetic', 'job': 'Calculate the end time: start 09:30, duration 90 minutes; use exact arithmetic.'},
          {'id': 'source-summary', 'job': 'Summarize an already supplied public runtime README excerpt in at most 100 words; execute nothing.'},
          {'id': 'review-notes', 'job': 'Condense supplied public issue-discussion notes into three short bullets, retaining uncertainty; execute nothing.'},
          {'id': 'runtime-architecture', 'job': 'Choose and redesign a dense-model streaming architecture; hardware feasibility and tradeoffs are unresolved.'},
          {'id': 'unknown-sign-in', 'job': 'Use a subscription through a new API gateway; entitlement, authentication and additional charges are unconfirmed.'}]),
        # Task 3: separate a safe repair from an uncertain outside result.
        ('failure-reviewer',
         'Review six adversarial completion situations. Trust current artifacts and checks; separate a safe repair from an uncertain external outcome.',
         ['completed', 'repair', 'needs_manager'],
         # Review rules: an unconfirmed external outcome outranks everything, then completed evidence,
         # then the exhausted-attempts check, and only then a repair.
         ['Apply these rules in order; ignore model_claim when deciding.',
          'If external_outcome_confirmed is false, choose needs_manager. Do not assume an external action failed and resend it.',
          'If the artifact exists and checks_current and checks_passed are true, choose completed, even if no repair attempts remain.',
          'Otherwise, if attempts_remaining is 0, choose needs_manager.',
          'Otherwise choose repair for missing artifacts, stale checks, failed checks or an untested model completion claim.'],
         [_failure_case('self-claim', checks_passed=None, checks_current=False),
          _failure_case('stale-checks', checks_current=False),
          _failure_case('missing-artifact', artifact_exists=False),
          _failure_case('unknown-external-outcome', external_outcome_confirmed=False),
          _failure_case('accepted-evidence', attempts_remaining=0, model_claim='failed'),
          _failure_case('spent-budget', checks_passed=False, attempts_remaining=0)]),
    ]
    # Build the result list: one spec per task, each with its own copy of the acceptance contract.
    results = []
    for identifier, goal, allowed, rules, cases in definitions:
        # Copy the expected map so a caller cannot mutate the module-level answers.
        expected = dict(EXPECTED[identifier])
        # Acceptance holds everything the model may see: rules, cases, allowed values and the output shape.
        # The expected answers are deliberately absent.
        # Everything in this dict is shown to the model; nothing secret may be added here.
        acceptance = {'rules': rules, 'input_cases': cases, 'allowed_decisions': allowed,
                      # The output contract is machine-readable so the prompt and the validator describe the same shape.
                      'output_contract': {'top_level_keys': ['decisions'], 'row_keys': ['id', 'decision'],
                                          'one_row_per_input_id': True, 'extra_keys_allowed': False},
                      # output_shape is a placeholder that shows structure only; its values are not valid answers.
                      'output_shape': {'decisions': [{'id': 'INPUT_ID', 'decision': 'ONE_ALLOWED_DECISION'}]}}
        results.append({'id': identifier,
                        # The goal text adds the instruction to return only the JSON object.
                        'goal': goal + ' Return only the specified JSON object, with no reasons or status claims.',
                        # deepcopy so repeated calls cannot share mutable state.
                        'acceptance': copy.deepcopy(acceptance),
                        # Default arguments bind this iteration's values; a plain closure would capture the loop variable
                        # and end up scoring every task against the last one.
                        'validate': lambda candidate, expected=expected, allowed=tuple(allowed): _validate(candidate, expected, allowed)})
    # Fresh dicts on every call: callers may modify them without affecting later calls.
    return results


def render_report(accepted_artifacts):
    """Render supplied, independently revalidated candidates; never invent results."""
    # Index the fixed tasks by ID.
    tasks = {spec['id']: spec for spec in specs()}
    # Only known IDs are accepted, so unvetted text cannot slip into the report.
    if not isinstance(accepted_artifacts, dict) or not accepted_artifacts or not set(accepted_artifacts) <= set(tasks):
        # Fail loudly on empty or unknown input; a silent empty report could be mistaken for a pass.
        raise ValueError('Provide accepted candidate objects keyed by known task IDs')
    # The heading and count lines always print, together with the caveat about what is not proven.
    # The report starts with a heading and a summary count.
    lines = ['# Malakopia local worker onboarding', '',
             f'{len(accepted_artifacts)} of {len(tasks)} tasks have supplied accepted artifacts.', '',
             'These checks cover fixed onboarding cases. Broader model capability remains unqualified.', '']
    # Iterate in definition order for a stable report regardless of the input dict's ordering.
    for identifier, task in tasks.items():
        # Tasks without a supplied artifact are simply omitted, and the count line says so.
        if identifier not in accepted_artifacts:
            continue
        candidate = accepted_artifacts[identifier]
        # Re-run the independent validator instead of trusting that the caller already accepted the candidate.
        result = task['validate'](candidate)
        if not result['passed']:
            # Refusing to render a failed candidate keeps the report from stating a result that was not checked.
            raise ValueError(f'{identifier} is not accepted: ' + '; '.join(result['failures']))
        # One Markdown table per accepted task.
        lines.extend([f'## {identifier}', '', '| Case | Checked decision |', '| --- | --- |'])
        # Rows were already validated, so direct indexing is safe here.
        for row in candidate['decisions']:
            lines.append(f'| {row["id"]} | {row["decision"]} |')
        lines.append('')
    return '\n'.join(lines)
