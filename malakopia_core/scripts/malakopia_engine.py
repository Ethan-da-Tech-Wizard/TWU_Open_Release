"""Small, local workflow runner with explicit handlers and resumable evidence.

run_workflow(workflow, inputs, handlers, state_dir, run_id=None,
             replay_safe_actions=(), max_attempts=2) returns a JSON summary.

Handlers receive (context, params) and return a JSON object. Context contains
inputs, outputs keyed by completed step ID, and run_id. A condition such as
when={"inputs.run_inference": True} must match exactly; a missing key skips it.
The engine never launches processes, connects to services or evaluates code.
"""
from __future__ import annotations

# Standard library only: the engine stays dependency-free so it can be audited and run offline.
from contextlib import contextmanager
from datetime import datetime, timezone
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import re
import tempfile
import uuid

# fcntl provides advisory file locks (flock). It is missing on some platforms, and the run functions
# then refuse to execute rather than run unlocked, since two writers would corrupt a run record.
try:
    import fcntl
except ImportError:  # No unlocked fallback on unsupported platforms.
    fcntl = None


class WorkflowError(ValueError):
    """Invalid workflow, inputs, saved state, or changed resume evidence."""


# Separate from WorkflowError so callers can tell "someone else is running this" from "the data is invalid".
class RunLockedError(RuntimeError):
    """Another writer owns this run."""


# Allowed per-step states. COMPLETE holds those that satisfy a dependent step's prerequisite.
# Module constants shared by restore() and run_workflow().
STATES = {'waiting', 'running', 'succeeded', 'skipped', 'failed', 'blocked'}
COMPLETE = {'succeeded', 'skipped'}
# IDs become folder and file name parts, so restrict them to a short, safe alphanumeric charset
# (no separators, dots or leading punctuation).
IDENTIFIER = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,95}')


def require(condition, message):
    """Raise WorkflowError(message) unless condition is truthy; one error type covers every validation failure."""
    if not condition:
        raise WorkflowError(message)


def json_bytes(value):
    """Reject objects that only loosely resemble JSON, including NaN and bad keys."""
    # Walk the structure explicitly: json.dumps alone would accept some inputs (for example int keys
    # or NaN) that are not canonical JSON.
    def inspect(item):
        """Recursively check that item contains only JSON-safe types; raises WorkflowError otherwise."""
        if isinstance(item, dict):
            # Non-string keys would be silently converted by json.dumps, making different inputs hash alike.
            require(all(isinstance(key, str) for key in item), 'JSON object keys must be strings')
            for child in item.values():
                inspect(child)
        elif isinstance(item, list):
            for child in item:
                inspect(child)
        else:
            # An exact type match (not isinstance) excludes subclasses such as custom numbers or string types.
            require(item is None or type(item) in (str, bool, int, float), 'Value is not JSON data')
            # NaN and infinity have no JSON representation.
            require(type(item) is not float or math.isfinite(item), 'Nonfinite numbers are not JSON data')
    # Canonical form: sorted keys, minimal separators, UTF-8, trailing newline, no NaN.
    # Equal data always produces equal bytes, which is what makes the hashes meaningful.
    try:
        inspect(value)
        return (json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False) + '\n').encode('utf-8')
    # Convert every encoding or recursion failure into the engine's own error type.
    except (RecursionError, UnicodeError, TypeError, ValueError) as exc:
        raise WorkflowError(f'Invalid JSON data: {exc}') from exc


def clone(value):
    """Return a deep copy of a JSON value via a strict round trip (this also validates it)."""
    # The round trip guarantees the copy shares no mutable state with the original.
    # Parsing the bytes back (instead of copy.deepcopy) is what enforces strict JSON types.
    return json.loads(json_bytes(value))


def digest(value):
    """Return the SHA-256 hex digest of the canonical JSON form of value."""
    # Hashing the canonical bytes makes the digest independent of key order and whitespace.
    return sha256(json_bytes(value)).hexdigest()


def now():
    """Return the current UTC time as an ISO-8601 string with microsecond precision."""
    return datetime.now(timezone.utc).isoformat(timespec='microseconds')


def atomic_json(path, value):
    """Write value as canonical JSON to path atomically and return the SHA-256 of the written bytes."""
    # Write-then-rename: readers see either the old file or the complete new one, never a partial file.
    content = json_bytes(value)
    # The temporary file lives in the same directory so os.replace is an atomic rename on one filesystem;
    # its name is hidden and unique.
    # mkstemp creates the file with owner-only permissions, so evidence is not world-readable.
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        # Flush and fsync before the rename so a power loss cannot leave a renamed but empty file.
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        # Atomic replace of the destination.
        os.replace(temporary, path)
    # On any failure, remove the temporary file so no stray partial files accumulate.
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    # The returned hash covers the bytes actually written; callers store it as a fingerprint.
    return sha256(content).hexdigest()


def prepare(workflow, inputs, handlers, replay_safe_actions, max_attempts):
    """Validate a workflow and its inputs, handlers and policy."""
    # Returns (normalized workflow, input copy, policy, steps in dependency order); raises WorkflowError.
    # Structural checks on the workflow envelope come first.
    # The three top-level keys are mandatory; extra keys are tolerated but become part of the fingerprint.
    require(isinstance(workflow, dict) and {'name', 'version', 'steps'} <= set(workflow),
            'Workflow needs name, version and steps')
    require(isinstance(workflow['name'], str) and bool(workflow['name'].strip()), 'Workflow name must be text')
    # The version is a positive int or a nonblank string; bool is excluded by the exact type test.
    version = workflow['version']
    require((type(version) is int and version > 0) or (isinstance(version, str) and bool(version.strip())),
            'Workflow version must be a positive integer or nonempty string')
    # Inputs, handlers and limits are validated up front so nothing runs against a malformed setup.
    require(isinstance(inputs, dict), 'Inputs must be a JSON object')
    require(isinstance(handlers, dict) and all(isinstance(k, str) and callable(v) for k, v in handlers.items()),
            'Handlers must map action names to callables')
    require(type(max_attempts) is int and max_attempts > 0, 'max_attempts must be a positive integer')
    # A bare string would be treated as a set of single characters; require a real collection.
    require(not isinstance(replay_safe_actions, str), 'replay_safe_actions must be a collection of action names')
    # Sorted so the policy is deterministic, since it is hashed into the run fingerprint.
    try:
        replay_safe = sorted(set(replay_safe_actions))
    except (TypeError, ValueError) as exc:
        raise WorkflowError('Invalid replay_safe_actions') from exc
    # Replay-safe means a handler may be re-run after a failure, so that claim must name an action that exists.
    require(all(isinstance(action, str) and action in handlers for action in replay_safe),
            'Every replay-safe action must have an explicit handler')
    # Work on a validated deep copy so the caller's dicts are never mutated (defaults are added below).
    # Cloning also validates that the whole workflow is plain JSON data.
    normalized = clone(workflow)
    require(isinstance(normalized['steps'], list) and bool(normalized['steps']), 'Workflow steps must be a nonempty list')
    # Index steps by ID while checking field names. Only these keys are allowed, so typos fail loudly.
    steps = {}
    # Per-step validation. Any problem raises immediately, before a single handler can run.
    for step in normalized['steps']:
        require(isinstance(step, dict) and {'id', 'action'} <= set(step)
                and set(step) <= {'id', 'action', 'needs', 'when', 'params'}, 'Invalid step fields')
        # Identifiers are checked against the safe charset because they become part of artifact file names.
        identifier, action = step['id'], step['action']
        require(isinstance(identifier, str) and IDENTIFIER.fullmatch(identifier), f'Invalid step ID: {identifier!r}')
        require(identifier not in steps, f'Duplicate step ID: {identifier}')
        require(isinstance(action, str) and action in handlers, f'Unknown action: {action!r}')
        # Fill in defaults on the normalized copy.
        step.setdefault('needs', [])
        step.setdefault('when', {})
        step.setdefault('params', {})
        # Prerequisites must be unique step IDs; a duplicate would hide a mistake.
        # Dependencies are listed by step ID only; no expressions or wildcards are supported.
        require(isinstance(step['needs'], list) and all(isinstance(x, str) for x in step['needs']),
                f'{identifier}: needs must be a list of step IDs')
        require(len(step['needs']) == len(set(step['needs'])), f'{identifier}: duplicate prerequisite')
        require(isinstance(step['when'], dict) and isinstance(step['params'], dict),
                f'{identifier}: when and params must be JSON objects')
        # Condition keys are dotted paths; restricting the characters prevents odd lookups.
        for key in step['when']:
            require(bool(re.fullmatch(r'[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*', key)),
                    f'{identifier}: invalid condition key {key!r}')
        steps[identifier] = step
    # Topological sort by depth-first visit: 'order' lists each step after all of its prerequisites.
    # order is the result, seen marks finished steps, visiting marks the current recursion path.
    order, seen, visiting = [], set(), set()

    def visit(identifier):
        """Depth-first visit that appends a step after its dependencies; raises on unknown IDs and cycles."""
        # 'visiting' holds the current path, so meeting a step already on it means a dependency cycle.
        require(identifier in steps, f'Unknown prerequisite: {identifier}')
        require(identifier not in visiting, f'Dependency cycle at {identifier}')
        # Already placed in the order; nothing more to do.
        if identifier in seen:
            return
        visiting.add(identifier)
        for dependency in steps[identifier]['needs']:
            visit(dependency)
        visiting.remove(identifier)
        seen.add(identifier)
        order.append(identifier)

    # Visit in declared order so independent steps keep their written sequence.
    for identifier in steps:
        visit(identifier)
    # ancestors maps each step to the full set of steps it transitively depends on.
    ancestors = {}
    for identifier in order:
        # 'order' guarantees every parent already has an entry in ancestors here.
        parents = set(steps[identifier]['needs'])
        ancestors[identifier] = parents | {ancestor for parent in parents for ancestor in ancestors[parent]}
        # Conditions may reference outputs only of declared prerequisites (direct or indirect); otherwise
        # a step could depend on a result that might not exist yet when it is evaluated.
        # Each condition key is checked against the declared prerequisites of this step.
        for key in steps[identifier]['when']:
            parts = key.split('.')
            if parts[0] == 'outputs':
                require(len(parts) >= 2 and parts[1] in steps, f'{identifier}: unknown output reference in condition {key!r}')
                require(parts[1] in ancestors[identifier],
                        f'{identifier}: condition output must be a declared prerequisite: {parts[1]}')
    # The policy is stored with the run so a resume under different settings is detected.
    policy = {'replay_safe_actions': replay_safe, 'max_attempts': max_attempts}
    return normalized, clone(inputs), policy, [steps[identifier] for identifier in order]


# Public dry-run check: lets callers validate a workflow definition without any side effects.
def validate_workflow(workflow, handlers):
    """Return a validated normalized copy without executing handlers or touching disk."""
    return prepare(workflow, {}, handlers, (), 1)[0]


@contextmanager
def writer_lock(folder):
    """Hold an exclusive non-blocking lock on the run folder for the duration of the with block."""
    # Raises RunLockedError if another process already holds it.
    # Refuse to run unlocked: two concurrent writers would corrupt the run record.
    require(fcntl is not None, 'Workflow execution requires fcntl.flock on Linux/macOS; no unlocked fallback is supported')
    # O_NOFOLLOW stops a planted symlink from redirecting the lock file; mode 0600 keeps it owner-only.
    descriptor = os.open(folder / '.writer.lock', os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        try:
            # LOCK_NB fails immediately instead of waiting, so a second invocation reports the conflict at once.
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            # Only the "lock busy" case maps to RunLockedError; other OS errors propagate unchanged.
            raise RunLockedError(f'Run {folder.name} is already being written by another process') from exc
        yield
    finally:
        # Closing the descriptor in finally releases the lock even when the body raised.
        os.close(descriptor)  # Keep the lock inode; closing releases flock safely.


def save(folder, state, event, step_id=None, details=None):
    """Append an event to state and persist both run.json and events.json."""
    # Timestamp and sequence number give each event a total order.
    state['updated_at'] = now()
    state['events'].append({'sequence': len(state['events']) + 1, 'time': state['updated_at'],
                            'event': event, 'step_id': step_id, 'details': details or {}})
    # run.json is authoritative; events.json is a recoverable projection.
    atomic_json(folder / 'run.json', state)
    # Written second: after a crash between the two writes, events.json can simply be rebuilt from run.json.
    atomic_json(folder / 'events.json', state['events'])


def artifact(folder, identifier, attempt, kind, value):
    """Store value as a uniquely named artifact file and return its {path, sha256} reference."""
    # A random suffix keeps attempts from ever overwriting earlier evidence; the path is relative to the
    # run folder so the run stays portable.
    # Attempt 0 is used for skipped steps, which never ran.
    relative = f'artifacts/{identifier}.attempt-{attempt:03d}.{kind}-{uuid.uuid4().hex[:12]}.json'
    # The hash goes into the reference, letting later reads detect tampering.
    checksum = atomic_json(folder / relative, value)
    return {'path': relative, 'sha256': checksum}


def read_artifact(folder, reference):
    """Load an artifact from a {path, sha256} reference; raise WorkflowError if it is malformed, escaped, missing or changed."""
    # Saved state is untrusted on resume, so validate the reference shape first.
    require(isinstance(reference, dict) and set(reference) == {'path', 'sha256'}, 'Invalid artifact reference')
    relative = reference['path']
    # Strict pattern: a single level under artifacts/, with no separators and no '..'.
    require(isinstance(relative, str) and re.fullmatch(r'artifacts/[A-Za-z0-9_.-]+\.json', relative),
            'Artifact path must stay inside this run')
    # The reference was already shape-checked, so this join cannot contain separators or parent hops.
    path = folder / relative
    # Defence against symlinks and path escapes: the resolved path must stay inside the run folder.
    require(path.resolve().is_relative_to(folder.resolve()) and not path.is_symlink(), 'Artifact escapes the run directory')
    require(path.is_file(), f'Missing saved artifact: {relative}')
    content = path.read_bytes()
    # Compare the hash of the bytes just read; any edit since they were written is detected.
    require(sha256(content).hexdigest() == reference['sha256'], f'Changed saved artifact: {relative}')
    # Parse the same bytes that were hashed (no second read, so no gap between check and use).
    result = json.loads(content)
    require(isinstance(result, dict), f'Artifact is not a JSON object: {relative}')
    # Re-validate as strict JSON data.
    json_bytes(result)
    return result


def restore(folder, workflow, inputs, policy):
    """Load saved run state, check it against the current workflow, inputs and policy, and return (state, outputs of completed steps)."""
    # Everything read from disk is untrusted; each field is checked before it is used.
    try:
        state = json.loads((folder / 'run.json').read_bytes())
    except (OSError, ValueError) as exc:
        # Unreadable or non-JSON state is a hard error: guessing at a half-written record would be worse than stopping.
        raise WorkflowError(f'Cannot read saved run {folder.name}: {exc}') from exc
    # Identity check: the folder name must equal the recorded run ID, so folders cannot be swapped.
    require(isinstance(state, dict) and state.get('schema_version') == 1 and state.get('run_id') == folder.name,
            'Invalid saved run identity/schema')
    # The artifacts directory must be a real directory, not a symlink pointing elsewhere.
    artifacts = folder / 'artifacts'
    require(artifacts.is_dir() and not artifacts.is_symlink(), 'Saved artifact directory is missing or is a symlink')
    # Resume only with exactly the same workflow, inputs and policy: the stored copy, its stored hash and the
    # current value must all agree. Changing any of them would make the old evidence meaningless.
    for key, expected in (('workflow', workflow), ('inputs', inputs), ('policy', policy)):
        require(key in state and state.get(key + '_sha256') == digest(state[key]) == digest(expected),
                f'Cannot resume: {key} fingerprint changed')
    # Saved step records must match the workflow's step IDs exactly.
    records = state.get('steps')
    require(isinstance(records, dict) and set(records) == {step['id'] for step in workflow['steps']},
            'Saved step IDs do not match workflow')
    # The event log is only a projection, but a missing list still signals a damaged record.
    require(isinstance(state.get('events'), list), 'Saved event history is missing')
    # Rebuild outputs only from artifacts whose hashes verify.
    outputs = {}
    for step in workflow['steps']:
        row = records[step['id']]
        # Per-step record checks: the action must be unchanged and the state a known one.
        require(isinstance(row, dict) and row.get('action') == step['action'] and row.get('state') in STATES,
                f'Invalid saved state for {step["id"]}')
        # Attempt counters can never exceed the policy limit, and the history must agree with the counter.
        require(type(row.get('attempts')) is int and 0 <= row['attempts'] <= policy['max_attempts'],
                f'Invalid saved attempt count for {step["id"]}')
        history = row.get('history')
        require(isinstance(history, list) and len(history) == row['attempts'], 'Saved attempt history is inconsistent')
        # Check each attempt in order; finished attempts must carry evidence, which is re-read and hash-verified.
        for number, attempt in enumerate(history, 1):
            require(isinstance(attempt, dict) and attempt.get('attempt') == number
                    and attempt.get('state') in ('running', 'succeeded', 'failed', 'interrupted'),
                    'Invalid saved attempt history')
            require(attempt['state'] == 'running' or attempt.get('artifact'), 'Completed attempt is missing its evidence')
            if attempt.get('artifact'):
                read_artifact(folder, attempt['artifact'])
        # A step that ran must have history, otherwise the record claims work with no trace.
        if row['state'] in ('running', 'succeeded', 'failed'):
            require(bool(history), 'Attempted step is missing its history')
        # A successful step's recorded output must be exactly its last attempt's artifact.
        if row['state'] == 'succeeded':
            require(history[-1]['state'] == 'succeeded' and history[-1]['artifact'] == row.get('output'),
                    'Successful output does not match its recorded attempt')
        # Skipped steps were never attempted.
        if row['state'] == 'skipped':
            require(row['attempts'] == 0, 'Skipped step has an inconsistent attempt count')
        # Only completed steps feed the context for later steps.
        if row['state'] in COMPLETE:
            outputs[step['id']] = read_artifact(folder, row.get('output'))
    # Both values are returned so the caller continues from verified data only.
    return state, outputs


def matches(condition, context):
    """Return True when every condition key's value equals the expected value (exact JSON comparison)."""
    for key, expected in condition.items():
        parts = key.split('.')
        # Keys starting with inputs, outputs or run_id are absolute paths into the context; any other key is shorthand for an input.
        value = context if parts[0] in ('inputs', 'outputs', 'run_id') else context['inputs']
        for part in parts:
            # A missing path means the condition is not met; it is not an error.
            if not isinstance(value, dict) or part not in value:
                return False
            value = value[part]
        # Compare canonical JSON so near-equal values (for example 1 and True) do not match.
        if json_bytes(value) != json_bytes(expected):
            return False
    return True


def failure(folder, state, identifier, error, *, interrupted=False):
    """Record a failed or interrupted attempt for a step, with an evidence artifact; the step always ends in 'failed'."""
    row = state['steps'][identifier]
    # Used in the artifact name and the event name, so the two outcomes are distinguishable on disk.
    kind = 'interrupted' if interrupted else 'failed'
    # The evidence artifact is written before the state change that references it.
    evidence = artifact(folder, identifier, row['attempts'], kind, {'error': error, 'interrupted': interrupted})
    # Interrupted and failed both end in the step state 'failed'; the attempt history keeps the distinction.
    # A failed step has no output; clearing it prevents dependents from reading stale data.
    row['state'], row['error'], row['output'] = 'failed', error, None
    # The last history entry is the attempt that just ended; it receives its final state and evidence.
    row['history'][-1].update(state=kind, finished_at=now(), error=error, artifact=evidence)
    save(folder, state, 'step_' + kind, identifier, error)


def run_workflow(workflow, inputs, handlers, state_dir, *, run_id=None, replay_safe_actions=(), max_attempts=2):
    """Execute a new run or resume an existing ID; all side effects belong to handlers.

    Successful/skipped results are reused only after fingerprint/hash checks.
    Failed and interrupted handlers retry only when explicitly replay-safe, up
    to max_attempts across all invocations. There are no immediate retry loops.
    BaseException (including KeyboardInterrupt) leaves an honest running record.
    """
    # Validate everything before creating files or calling any handler.
    workflow, inputs, policy, ordered = prepare(workflow, inputs, handlers, replay_safe_actions, max_attempts)
    # Fail early if locking is unavailable, before any folder is created.
    require(fcntl is not None, 'Workflow execution requires fcntl.flock on Linux/macOS; no unlocked fallback is supported')
    # Resolve for an absolute, normalised state directory.
    root = Path(state_dir).expanduser().resolve()
    resumed = run_id is not None
    # Resume an existing run only by its ID, validated against the safe charset to prevent path traversal.
    if resumed:
        require(isinstance(run_id, str) and IDENTIFIER.fullmatch(run_id), 'Invalid run ID')
        folder = root / run_id
        # A symlinked run folder could redirect evidence elsewhere, so refuse it.
        require(folder.is_dir() and not folder.is_symlink(), f'Unknown run ID: {run_id}')
    else:
        # New run: a timestamp plus a random suffix gives unique, sortable IDs, and the folders are owner-only.
        run_id = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S') + '-' + uuid.uuid4().hex[:16]
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        folder = root / run_id
        folder.mkdir(mode=0o700)
        (folder / 'artifacts').mkdir(mode=0o700)
    # Hold the lock for the whole run so concurrent processes cannot interleave writes.
    with writer_lock(folder):
        if resumed:
            # Resume path: restore verifies all saved evidence before anything is reused.
            state, outputs = restore(folder, workflow, inputs, policy)
        else:
            # New run: the state records the workflow, inputs and policy with their hashes, so a later
            # resume can prove nothing changed.
            state = {'schema_version': 1, 'run_id': run_id, 'workflow': workflow, 'inputs': inputs, 'policy': policy,
                     'workflow_sha256': digest(workflow), 'inputs_sha256': digest(inputs), 'policy_sha256': digest(policy),
                     'created_at': now(), 'status': 'running', 'events': [],
                     'steps': {step['id']: {'action': step['action'], 'state': 'waiting', 'attempts': 0,
                                           'history': [], 'output': None, 'error': None, 'blocked_by': []}
                               for step in ordered}}
            outputs = {}
            # The first save gives the run an on-disk record before any step executes.
            save(folder, state, 'run_created')
        # Reconcile saved statuses before executing; this pass only repairs bookkeeping.
        for step in ordered:
            identifier, row = step['id'], state['steps'][step['id']]
            # A 'running' step at start means the previous process died mid-step. Its outcome is unknown,
            # so it is marked interrupted instead of being assumed to have succeeded or failed.
            if row['state'] == 'running':
                failure(folder, state, identifier, {'type': 'Interrupted', 'message':
                        'Previous execution stopped while this step was running; completion was not recorded.'}, interrupted=True)
            # Blocked steps from a previous invocation are re-evaluated from scratch.
            if row['state'] == 'blocked':
                # Back to waiting: the dependency check in the main pass decides again.
                row.update(state='waiting', blocked_by=[])
            # Retry only if the action was declared replay-safe and attempts remain; other failures stay failed
            # so a side effect is never repeated without explicit permission.
            if row['state'] == 'failed' and step['action'] in policy['replay_safe_actions'] and row['attempts'] < max_attempts:
                # Clear the old error; the failed attempt stays in the history as evidence.
                row.update(state='waiting', error=None)
                save(folder, state, 'step_retry_scheduled', identifier, {'next_attempt': row['attempts'] + 1})
        # The status stays 'running' until the final pass decides.
        state['status'] = 'running'
        if resumed:
            save(folder, state, 'run_resumed')
        # Main pass: run steps in dependency order.
        for step in ordered:
            identifier, row = step['id'], state['steps'][step['id']]
            # Finished and failed steps stay as they are; failed steps were already rescheduled above when allowed.
            if row['state'] in COMPLETE or row['state'] == 'failed':
                continue
            # A step runs only if every prerequisite succeeded or was skipped; otherwise it is recorded as blocked.
            # A failed or blocked prerequisite blocks this step; nothing is run on partial inputs.
            blocked = [dependency for dependency in step['needs'] if state['steps'][dependency]['state'] not in COMPLETE]
            if blocked:
                row.update(state='blocked', blocked_by=blocked)
                save(folder, state, 'step_blocked', identifier, {'blocked_by': blocked})
                continue
            # Handlers get copies, so they cannot modify the engine's state or inputs.
            # The context is rebuilt per step from the latest outputs, so each handler sees every earlier result.
            context = {'inputs': clone(inputs), 'outputs': clone(outputs), 'run_id': run_id}
            # A condition that does not match skips the step. The skip is saved as its own artifact so
            # dependents can still proceed.
            # Conditions run after the dependency check, so they only see outputs that actually exist.
            if not matches(step['when'], context):
                # Skipped steps still produce an output, so steps that depend on them are not blocked.
                result = {'skipped': True, 'reason': 'condition_not_met', 'when': clone(step['when'])}
                row.update(state='skipped', output=artifact(folder, identifier, 0, 'skipped', result))
                outputs[identifier] = result
                save(folder, state, 'step_skipped', identifier, {'when': step['when']})
                continue
            # Hard cap on attempts, counted across all invocations of this run.
            # Reaching this line with no attempts left means the state is inconsistent, so stop loudly.
            require(row['attempts'] < max_attempts, f'Attempt limit reached for {identifier}')
            # Save the 'running' record before calling the handler: if the process dies, the record honestly
            # says the outcome is unknown.
            row['attempts'] += 1
            row.update(state='running', error=None, blocked_by=[])
            row['history'].append({'attempt': row['attempts'], 'state': 'running', 'started_at': now()})
            save(folder, state, 'step_running', identifier, {'attempt': row['attempts']})
            # Only Exception is caught below; BaseException (such as KeyboardInterrupt) propagates and leaves
            # the running record in place for the next resume to mark as interrupted.
            try:
                # The handler receives a copy of its params; its return value must be a JSON object, which is checked and copied.
                result = handlers[step['action']](context, clone(step['params']))
                require(isinstance(result, dict), f'Handler {step["action"]} must return a JSON object')
                # Clone again so the stored output cannot be changed through the handler's own reference.
                result = clone(result)
            except Exception as exc:
                # Failure is recorded and the loop continues; later steps then become blocked.
                failure(folder, state, identifier, {'type': type(exc).__name__, 'message': str(exc)})
                continue
            # Persist the output artifact before updating the step state that points to it.
            # Evidence for a successful attempt; its hash is what a later resume verifies before reuse.
            reference = artifact(folder, identifier, row['attempts'], 'succeeded', result)
            row.update(state='succeeded', output=reference)
            row['history'][-1].update(state='succeeded', finished_at=now(), artifact=reference)
            outputs[identifier] = result
            save(folder, state, 'step_succeeded', identifier, {'attempt': row['attempts'], 'artifact': reference})
        # Overall success requires every step to be complete (succeeded or skipped).
        state['status'] = 'succeeded' if all(row['state'] in COMPLETE for row in state['steps'].values()) else 'failed'
        save(folder, state, 'run_finished', details={'status': state['status']})
        # Return a summary built from copies so callers cannot mutate the engine's records.
        # The summary points at the state directory so a failed run can be inspected or resumed by ID.
        return {'run_id': run_id, 'workflow': workflow['name'], 'version': workflow['version'], 'status': state['status'],
                'resumed': resumed, 'steps': clone(state['steps']), 'outputs': clone(outputs),
                'state_directory': str(folder), 'events_file': str(folder / 'events.json')}
