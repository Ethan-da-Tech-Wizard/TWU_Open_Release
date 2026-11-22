"""Queue correctness tests use disposable files and no model or live books."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import malakopia_job_queue as queue_module
from malakopia_job_queue import ContractError, JobQueue, LeaseError, QueueError, default_state_dir, local_state_path


PASSED = {'passed': True, 'failures': [], 'evidence': {'checks': 4, 'artifact_sha256': 'fixture'}}
FAILED = {'passed': False, 'failures': ['case 2 expected 3, received 4'], 'evidence': {'check': 'case-2'}}


class Clock:
    """Tests for: Clock."""
    def __init__(self):
        """Helper: init."""
        self.value = 1_800_000_000.0

    def __call__(self):
        """Helper: call."""
        return self.value


class QueueTests(unittest.TestCase):
    """Tests for: Queue Tests."""
    def test_exact_claim_never_falls_through_under_concurrent_workers(self):
        """Check that exact claim never falls through under concurrent workers."""
        selected = self.add('selected')
        untouched = self.add('untouched')
        with ThreadPoolExecutor(max_workers=2) as workers:
            claims = list(workers.map(lambda owner: self.queue.claim(owner, job_id=selected), ['a', 'b']))
        self.assertEqual(sum(claim is not None for claim in claims), 1)
        self.assertEqual(self.queue.get(untouched)['status'], 'queued')
        self.assertIsNone(self.queue.claim('third', job_id=selected))
        self.assertEqual(self.queue.get(untouched)['attempt'], 0)

    def setUp(self):
        """Create the scratch state this test needs."""
        self.temporary = tempfile.TemporaryDirectory(prefix='malakopia-queue-test-')
        self.addCleanup(self.temporary.cleanup)
        self.folder = Path(self.temporary.name)
        self.root = self.folder / 'workspace'
        self.root.mkdir()
        self.state = self.folder / 'private-state'
        self.clock = Clock()
        self.queue = JobQueue(self.state, root=self.root, clock=self.clock)

    def add(self, name='build', **kwargs):
        """Helper: add."""
        return self.queue.enqueue({'recipe': 'fixture', 'task': name}, **kwargs)

    def test_contract_is_a_deep_copy_with_stable_fingerprint(self):
        """Check that contract is a deep copy with stable fingerprint."""
        spec = {'task': 'fixture', 'input': [1, {'value': 2}]}
        job = self.queue.enqueue(spec)
        before = self.queue.get(job)
        spec['input'][1]['value'] = 99
        self.assertEqual(self.queue.get(job)['spec']['input'][1]['value'], 2)
        self.assertEqual(len(before['contract_hash']), 64)
        before['spec']['input'][1]['value'] = 100
        self.assertEqual(self.queue.get(job)['spec']['input'][1]['value'], 2)

    def test_idempotency_survives_reopen_and_key_order(self):
        """Check that idempotency survives reopen and key order."""
        first = self.queue.enqueue({'a': 1, 'b': 2}, idempotency_key='request-1')
        second = JobQueue(self.state, root=self.root).enqueue({'b': 2, 'a': 1}, idempotency_key='request-1')
        self.assertEqual(first, second)
        self.assertEqual(len(self.queue.list_jobs()), 1)
        self.assertEqual(len(self.queue.events()), 1)

    def test_idempotency_rejects_changed_spec_or_budget(self):
        """Check that idempotency rejects changed spec or budget."""
        self.queue.enqueue({'a': 1}, idempotency_key='request-1')
        with self.assertRaises(ContractError):
            self.queue.enqueue({'a': 2}, idempotency_key='request-1')
        with self.assertRaises(ContractError):
            self.queue.enqueue({'a': 1}, idempotency_key='request-1', max_attempts=4)
        self.assertEqual(len(self.queue.list_jobs()), 1)

    def test_explicit_id_is_idempotent_but_cannot_change(self):
        """Check that explicit id is idempotent but cannot change."""
        self.add(job_id='fixed')
        self.assertEqual(self.add(job_id='fixed'), 'fixed')
        with self.assertRaises(ContractError):
            self.add('different', job_id='fixed')
        with self.assertRaises(ContractError):
            self.add(job_id='fixed', idempotency_key='new-key')

    def test_key_and_explicit_id_cannot_disagree(self):
        """Check that key and explicit id cannot disagree."""
        self.add(job_id='first', idempotency_key='key')
        with self.assertRaises(ContractError):
            self.add(job_id='second', idempotency_key='key')

    def test_missing_self_duplicate_and_changed_dependencies_rejected(self):
        """Check that missing self duplicate and changed dependencies rejected."""
        for dependencies in [('missing',), ('self',), ('missing', 'missing')]:
            with self.subTest(dependencies=dependencies), self.assertRaises(ContractError):
                self.add(job_id='self', depends_on=dependencies)
        parent = self.add(job_id='parent')
        self.add(job_id='child', depends_on=(parent,), idempotency_key='child-key')
        with self.assertRaises(ContractError):
            self.add(job_id='parent', depends_on=('child',))
        with self.assertRaises(ContractError):
            self.add(job_id='child', idempotency_key='child-key')
        self.assertEqual(len(self.queue.list_jobs()), 2)

    def test_dependencies_must_pass_before_child_can_claim(self):
        """Check that dependencies must pass before child can claim."""
        parent = self.add(job_id='parent')
        child = self.add(job_id='child', depends_on=(parent,))
        claimed = self.queue.claim('worker')
        self.assertEqual(claimed['job_id'], parent)
        self.assertIsNone(self.queue.claim('other'))
        self.queue.finish(parent, claimed['token'], PASSED)
        self.assertEqual(self.queue.claim('other')['job_id'], child)

    def test_success_requires_actual_checked_result_shape(self):
        """Check that success requires actual checked result shape."""
        job = self.add()
        claim = self.queue.claim('worker')
        invalid = [
            {}, {'passed': 'true', 'failures': [], 'evidence': {'a': 1}},
            {'passed': True, 'failures': [], 'evidence': {}},
            {'passed': True, 'failures': ['wrong'], 'evidence': {'a': 1}},
            {'passed': False, 'failures': [], 'evidence': {'a': 1}},
            {'passed': True, 'failures': [], 'evidence': ['not an object']},
        ]
        for result in invalid:
            with self.subTest(result=result), self.assertRaises(QueueError):
                self.queue.finish(job, claim['token'], result)
        self.assertEqual(self.queue.get(job)['status'], 'running')
        self.assertEqual(self.queue.finish(job, claim['token'], PASSED)['status'], 'passed')

    def test_failed_disposition_cannot_contradict_success_or_omit_failure(self):
        """Check that failed disposition cannot contradict success or omit failure."""
        job = self.add()
        claim = self.queue.claim('worker')
        for result in (PASSED, {'passed': False, 'failures': [], 'evidence': {}}):
            with self.assertRaises(QueueError):
                self.queue.finish(job, claim['token'], result, disposition='retry')
        self.assertEqual(self.queue.get(job)['status'], 'running')

    def test_bounded_automatic_repairs_retain_every_failure(self):
        """Check that bounded automatic repairs retain every failure."""
        job = self.add(max_attempts=2)
        first = self.queue.claim('worker')
        self.assertIsNone(first['previous_validation'])
        self.assertEqual(self.queue.finish(job, first['token'], FAILED, 'retry')['status'], 'queued')
        second = self.queue.claim('worker')
        self.assertEqual(second['attempt'], 2)
        self.assertEqual(second['previous_validation'], FAILED)
        final = self.queue.finish(job, second['token'], FAILED, 'retry')
        self.assertEqual(final['status'], 'failed')
        self.assertIsNone(self.queue.claim('worker'))
        with self.assertRaises(QueueError):
            self.queue.retry(job)
        self.assertEqual([a['result'] for a in self.queue.attempts(job)], [FAILED, FAILED])
        self.assertIn('attempts_exhausted', [event['event'] for event in self.queue.events()])

    def test_failed_attempt_followed_by_pass_records_both(self):
        """Check that failed attempt followed by pass records both."""
        job = self.add(max_attempts=2)
        first = self.queue.claim('worker')
        self.queue.finish(job, first['token'], FAILED, 'retry')
        second = self.queue.claim('worker')
        done = self.queue.finish(job, second['token'], PASSED)
        self.assertEqual(done['status'], 'passed')
        self.assertEqual([a['disposition'] for a in self.queue.attempts(job)], ['retry', 'passed'])
        self.assertEqual(done['attempt_count'], 2)

    def test_stale_token_cannot_complete_or_heartbeat_later_attempt(self):
        """Check that stale token cannot complete or heartbeat later attempt."""
        job = self.add()
        first = self.queue.claim('first')
        self.queue.finish(job, first['token'], FAILED, 'retry')
        second = self.queue.claim('second')
        self.assertNotEqual(first['token'], second['token'])
        for action in (lambda: self.queue.finish(job, first['token'], PASSED),
                       lambda: self.queue.heartbeat(job, first['token']),
                       lambda: self.queue.finish(job, '\N{SNOWMAN}', PASSED)):
            with self.assertRaises(LeaseError):
                action()
        self.assertEqual(self.queue.get(job)['owner'], 'second')
        self.queue.finish(job, second['token'], PASSED)

    def test_claim_is_atomic_across_threads(self):
        """Check that claim is atomic across threads."""
        job = self.add()
        with ThreadPoolExecutor(max_workers=8) as pool:
            claims = list(pool.map(lambda i: self.queue.claim(f'worker-{i}'), range(16)))
        actual = [claim for claim in claims if claim]
        self.assertEqual(len(actual), 1)
        self.assertEqual(actual[0]['job_id'], job)
        self.assertEqual(len(self.queue.attempts(job)), 1)

    def test_claim_and_finish_are_atomic_across_processes(self):
        """Check that claim and finish are atomic across processes."""
        jobs = {self.add(job_id=f'job-{n:02d}') for n in range(24)}
        scripts = str(Path(__file__).resolve().parent)
        program = '''import json, pathlib, sys, time
sys.path.insert(0, sys.argv[1])
from malakopia_job_queue import JobQueue
q = JobQueue(sys.argv[2], root=sys.argv[3])
pathlib.Path(sys.argv[4]).write_text('ready')
while not pathlib.Path(sys.argv[5]).exists(): time.sleep(.005)
claimed=[]
while True:
    item=q.claim(sys.argv[6])
    if item is None: break
    time.sleep(.003)
    q.finish(item['job_id'], item['token'], {'passed':True,'failures':[],'evidence':{'test':'process'}})
    claimed.append(item['job_id'])
print(json.dumps(claimed))
'''
        barrier = self.folder / 'start'
        processes = []
        try:
            for number in range(4):
                ready = self.folder / f'ready-{number}'
                processes.append(subprocess.Popen([sys.executable, '-c', program, scripts, str(self.state), str(self.root),
                                                   str(ready), str(barrier), f'process-{number}'],
                                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
            deadline = time.monotonic() + 15
            while not all((self.folder / f'ready-{number}').exists() for number in range(4)):
                if time.monotonic() > deadline or any(p.poll() is not None for p in processes):
                    self.fail('Queue process initialization failed')
                time.sleep(.005)
            barrier.write_text('start')
            claimed = []
            for process in processes:
                output, error = process.communicate(timeout=20)
                self.assertEqual(process.returncode, 0, error)
                claimed.extend(json.loads(output))
            self.assertEqual(set(claimed), jobs)
            self.assertEqual(len(claimed), len(jobs))
            self.assertTrue(all(job['status'] == 'passed' and job['attempt_count'] == 1 for job in self.queue.list_jobs()))
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=10)

    def test_concurrent_idempotent_enqueue_makes_one_job(self):
        """Check that concurrent idempotent enqueue makes one job."""
        with ThreadPoolExecutor(max_workers=8) as pool:
            ids = list(pool.map(lambda _: self.add(idempotency_key='one-request'), range(24)))
        self.assertEqual(len(set(ids)), 1)
        self.assertEqual(len(self.queue.events()), 1)

    def test_crashed_worker_is_not_silently_replayed(self):
        """Check that crashed worker is not silently replayed."""
        job = self.add()
        claim = self.queue.claim('crashed', lease_seconds=5)
        self.clock.value += 6
        reopened = JobQueue(self.state, root=self.root, clock=self.clock)
        self.assertIsNone(reopened.claim('replacement'))
        self.assertEqual(reopened.get(job)['status'], 'needs_review')
        self.assertEqual(reopened.get(job)['attempt_count'], 1)
        with self.assertRaises(LeaseError):
            reopened.finish(job, claim['token'], PASSED)
        self.assertEqual(len(reopened.attempts(job)), 1)
        self.assertIn('uncertain', reopened.attempts(job)[0]['result']['failures'][0])

    def test_abrupt_process_exit_retains_claim_until_review(self):
        """Check that abrupt process exit retains claim until review."""
        job = self.add()
        program = '''import json, os, sys
sys.path.insert(0, sys.argv[1])
from malakopia_job_queue import JobQueue
q=JobQueue(sys.argv[2], root=sys.argv[3], clock=lambda:float(sys.argv[4]))
print(json.dumps(q.claim('abrupt-process', lease_seconds=1)), flush=True)
os._exit(23)
'''
        process = subprocess.run([sys.executable, '-c', program, str(Path(__file__).resolve().parent),
                                  str(self.state), str(self.root), str(self.clock.value)],
                                 capture_output=True, text=True, timeout=10)
        self.assertEqual(process.returncode, 23, process.stderr)
        claim = json.loads(process.stdout)
        self.assertEqual(claim['job_id'], job)
        self.assertEqual(self.queue.get(job)['status'], 'running')
        self.clock.value += 2
        self.assertIsNone(self.queue.claim('replacement'))
        self.assertEqual(self.queue.get(job)['status'], 'needs_review')
        self.assertEqual(self.queue.get(job)['attempt_count'], 1)

    def test_expired_heartbeat_commits_recovery_before_raising(self):
        """Check that expired heartbeat commits recovery before raising."""
        job = self.add()
        claim = self.queue.claim('worker', lease_seconds=5)
        self.clock.value += 5
        with self.assertRaises(LeaseError):
            self.queue.heartbeat(job, claim['token'])
        self.assertEqual(self.queue.get(job)['status'], 'needs_review')
        self.assertEqual(self.queue.recover_expired(), [])

    def test_expired_finish_cannot_count_as_success(self):
        """Check that expired finish cannot count as success."""
        job = self.add()
        claim = self.queue.claim('worker', lease_seconds=5)
        self.clock.value += 5
        with self.assertRaises(LeaseError):
            self.queue.finish(job, claim['token'], PASSED)
        self.assertEqual(self.queue.get(job)['status'], 'needs_review')
        self.assertFalse(self.queue.get(job)['result']['passed'])

    def test_heartbeat_extends_only_active_claim(self):
        """Check that heartbeat extends only active claim."""
        job = self.add()
        claim = self.queue.claim('worker', lease_seconds=5)
        self.clock.value += 4
        self.queue.heartbeat(job, claim['token'], lease_seconds=10)
        self.clock.value += 2
        self.assertEqual(self.queue.recover_expired(), [])
        self.queue.finish(job, claim['token'], PASSED)
        with self.assertRaises(LeaseError):
            self.queue.heartbeat(job, claim['token'])

    def test_explicit_retry_after_review_preserves_total_budget(self):
        """Check that explicit retry after review preserves total budget."""
        job = self.add(max_attempts=2)
        claim = self.queue.claim('worker', lease_seconds=1)
        self.clock.value += 2
        self.assertEqual(self.queue.recover_expired(), [job])
        self.assertEqual(self.queue.retry(job)['attempt_count'], 1)
        second = self.queue.claim('reviewed-worker')
        self.assertEqual(second['attempt'], 2)
        self.assertIn('uncertain', second['previous_validation']['failures'][0])
        self.queue.finish(job, second['token'], FAILED, 'retry')
        with self.assertRaises(QueueError):
            self.queue.retry(job)
        with self.assertRaises(LeaseError):
            self.queue.finish(job, claim['token'], PASSED)

    def test_failure_propagates_transitively_without_attempts(self):
        """Check that failure propagates transitively without attempts."""
        first = self.add(job_id='first')
        second = self.add(job_id='second', depends_on=(first,))
        third = self.add(job_id='third', depends_on=(second,))
        claim = self.queue.claim('worker')
        self.queue.finish(first, claim['token'], FAILED, 'failed')
        for job in (second, third):
            self.assertEqual(self.queue.get(job)['status'], 'blocked')
            self.assertEqual(self.queue.get(job)['attempt_count'], 0)
        self.assertIsNone(self.queue.claim('worker'))
        with self.assertRaises(QueueError):
            self.queue.retry(third)
        self.queue.retry(first)
        self.assertEqual(self.queue.get(second)['status'], 'queued')
        self.assertEqual(self.queue.get(third)['status'], 'queued')
        claim = self.queue.claim('worker')
        self.assertEqual(claim['job_id'], first)
        self.queue.finish(first, claim['token'], PASSED)
        self.assertEqual(self.queue.claim('worker')['job_id'], second)

    def test_multiple_parents_one_failure_blocks_child(self):
        """Check that multiple parents one failure blocks child."""
        first = self.add(job_id='first')
        second = self.add(job_id='second')
        child = self.add(job_id='child', depends_on=(second, first))
        first_claim = self.queue.claim('one')
        second_claim = self.queue.claim('two')
        self.queue.finish(first, first_claim['token'], PASSED)
        self.queue.finish(second, second_claim['token'], FAILED, 'needs_review')
        self.assertEqual(self.queue.get(child)['status'], 'blocked')
        self.assertEqual(self.queue.get(child)['depends_on'], [first, second])

    def test_enqueue_after_failed_dependency_starts_blocked(self):
        """Check that enqueue after failed dependency starts blocked."""
        parent = self.add()
        self.queue.cancel(parent)
        child = self.add(depends_on=(parent,))
        self.assertEqual(self.queue.get(child)['status'], 'blocked')
        self.assertEqual(self.queue.get(child)['attempt_count'], 0)

    def test_cancel_running_invalidates_token_and_preserves_attempt(self):
        """Check that cancel running invalidates token and preserves attempt."""
        job = self.add()
        claim = self.queue.claim('worker')
        self.assertEqual(self.queue.cancel(job)['status'], 'canceled')
        with self.assertRaises(LeaseError):
            self.queue.finish(job, claim['token'], PASSED)
        self.assertEqual(self.queue.attempts(job)[0]['disposition'], 'canceled')
        before = len(self.queue.events())
        self.queue.cancel(job)
        self.assertEqual(len(self.queue.events()), before)

    def test_idempotency_does_not_reset_canceled_or_exhausted_work(self):
        """Check that idempotency does not reset canceled or exhausted work."""
        canceled = self.add(job_id='canceled', idempotency_key='canceled-key')
        self.queue.cancel(canceled)
        self.assertEqual(self.add(job_id='canceled', idempotency_key='canceled-key'), canceled)
        self.assertEqual(self.queue.get(canceled)['status'], 'canceled')
        exhausted = self.add(max_attempts=1, idempotency_key='failed-key')
        claim = self.queue.claim('worker')
        self.queue.finish(exhausted, claim['token'], FAILED, 'retry')
        self.assertEqual(self.add(max_attempts=1, idempotency_key='failed-key'), exhausted)
        self.assertEqual(self.queue.get(exhausted)['status'], 'failed')
        self.assertIsNone(self.queue.claim('worker'))

    def test_passed_jobs_cannot_be_retried_or_canceled(self):
        """Check that passed jobs cannot be retried or canceled."""
        job = self.add()
        claim = self.queue.claim('worker')
        self.queue.finish(job, claim['token'], PASSED)
        with self.assertRaises(QueueError):
            self.queue.retry(job)
        with self.assertRaises(QueueError):
            self.queue.cancel(job)

    def test_events_are_ordered_cursorable_and_do_not_expose_token(self):
        """Check that events are ordered cursorable and do not expose token."""
        job = self.add()
        claim = self.queue.claim('worker')
        self.queue.finish(job, claim['token'], PASSED)
        events = self.queue.events()
        self.assertEqual([event['event'] for event in events], ['enqueued', 'claimed', 'finished'])
        self.assertEqual(self.queue.events(events[0]['id']), events[1:])
        for output in (events, self.queue.get(job), self.queue.list_jobs(), self.queue.attempts(job)):
            self.assertNotIn(claim['token'], json.dumps(output))
        self.assertEqual(len(self.queue.list_jobs('passed')), 1)
        self.assertEqual(self.queue.list_jobs('failed'), [])

    def test_invalid_json_and_job_inputs_do_not_create_jobs(self):
        """Check that invalid json and job inputs do not create jobs."""
        invalid = [{1: 'non-string-key'}, {'a': float('nan')}, {'a': float('inf')}, {'a': (1, 2)}, {'a': {1, 2}}]
        for spec in invalid:
            with self.subTest(spec=str(spec)), self.assertRaises(QueueError):
                self.queue.enqueue(spec)
        for number in (0, -1, True, 1.5, 101):
            with self.assertRaises(QueueError):
                self.add(max_attempts=number)
        for name in ('', '..', '../escape', '/absolute', 0, 'a' * 97):
            with self.assertRaises(QueueError):
                self.add(job_id=name)
        self.assertEqual(self.queue.list_jobs(), [])

    def test_invalid_leases_are_rejected_without_claim(self):
        """Check that invalid leases are rejected without claim."""
        job = self.add()
        for lease in (0, -1, float('inf'), float('nan'), True, 86401):
            with self.assertRaises(QueueError):
                self.queue.claim('worker', lease_seconds=lease)
        self.assertEqual(self.queue.get(job)['attempt_count'], 0)

    def test_queue_state_cannot_live_in_workspace_or_its_parent(self):
        """Check that queue state cannot live in workspace or its parent."""
        for folder in (self.root, self.root / 'state', self.root / '..'):
            with self.assertRaises(QueueError):
                JobQueue(folder, root=self.root)
        self.assertFalse((self.root / 'state').exists())

    def test_verified_macos_system_aliases_are_normalized_without_resolving_arbitrary_links(self):
        """Check that verified macos system aliases are normalized without resolving arbitrary links."""
        def readlink(path):
            """Helper: readlink."""
            return {'/var': 'private/var', '/tmp': '/private/tmp'}[path]

        with patch.object(queue_module.sys, 'platform', 'darwin'), patch.object(queue_module.os, 'readlink', side_effect=readlink):
            self.assertEqual(local_state_path('/var/folders/fixture/state'), Path('/private/var/folders/fixture/state'))
            self.assertEqual(local_state_path('/tmp/fixture/state'), Path('/private/tmp/fixture/state'))
        # An arbitrary linked parent still reaches the existing lstat rejection path.
        linked = self.folder / 'linked-parent'
        linked.symlink_to(self.state, target_is_directory=True)
        with self.assertRaises(QueueError):
            JobQueue(linked / 'child', root=self.root)

    def test_tampered_macos_alias_and_linux_paths_are_not_silently_normalized(self):
        """Check that tampered macos alias and linux paths are not silently normalized."""
        with patch.object(queue_module.sys, 'platform', 'darwin'), patch.object(queue_module.os, 'readlink', return_value='/attacker/var'):
            self.assertEqual(local_state_path('/var/folders/fixture/state'), Path('/var/folders/fixture/state'))
        with patch.object(queue_module.sys, 'platform', 'linux'), patch.object(queue_module.os, 'readlink') as readlink:
            self.assertEqual(local_state_path('/var/folders/fixture/state'), Path('/var/folders/fixture/state'))
            readlink.assert_not_called()

    def test_state_directory_or_its_parent_cannot_be_symlink(self):
        """Check that state directory or its parent cannot be symlink."""
        linked = self.folder / 'link'
        linked.symlink_to(self.state, target_is_directory=True)
        with self.assertRaises(QueueError):
            JobQueue(linked, root=self.root)
        with self.assertRaises(QueueError):
            JobQueue(linked / 'nested', root=self.root)
        self.assertFalse((self.state / 'nested').exists())

    def test_database_symlinks_and_hardlinks_rejected(self):
        """Check that database symlinks and hardlinks rejected."""
        for suffix, kind in (('', 'symlink'), ('-wal', 'symlink'), ('-shm', 'symlink'), ('-journal', 'symlink'), ('', 'hardlink')):
            with self.subTest(suffix=suffix, kind=kind):
                state = self.folder / ('state-' + suffix.replace('-', '') + kind)
                state.mkdir(mode=0o700)
                original = self.folder / ('original-' + suffix.replace('-', '') + kind)
                original.write_bytes(b'untouched')
                original.chmod(0o600)
                linked = state / ('jobs.sqlite3' + suffix)
                if kind == 'symlink':
                    linked.symlink_to(original)
                else:
                    os.link(original, linked)
                with self.assertRaises(QueueError):
                    JobQueue(state, root=self.root)
                self.assertEqual(original.read_bytes(), b'untouched')

    def test_new_symlink_after_initialization_is_detected(self):
        """Check that new symlink after initialization is detected."""
        target = self.folder / 'unrelated'
        target.write_text('untouched')
        linked = self.state / 'jobs.sqlite3-wal'
        linked.symlink_to(target)
        with self.assertRaises(QueueError):
            self.queue.list_jobs()
        self.assertEqual(target.read_text(), 'untouched')

    def test_reject_unrelated_sqlite_database_without_changing_it(self):
        """Check that reject unrelated sqlite database without changing it."""
        other = self.folder / 'other'
        other.mkdir(mode=0o700)
        path = other / 'jobs.sqlite3'
        connection = sqlite3.connect(path)
        connection.execute('CREATE TABLE unrelated (fact TEXT)')
        connection.execute("INSERT INTO unrelated VALUES ('leave me alone')")
        connection.commit()
        connection.close()
        path.chmod(0o600)
        before = path.read_bytes()
        with self.assertRaises(QueueError):
            JobQueue(other, root=self.root)
        self.assertEqual(path.read_bytes(), before)

    def test_existing_empty_database_is_not_initialized_as_new_history(self):
        """Check that existing empty database is not initialized as new history."""
        self.add(job_id='history-that-must-not-disappear-silently')
        self.queue.path.write_bytes(b'')
        with self.assertRaisesRegex(QueueError, 'empty'):
            JobQueue(self.state, root=self.root)
        self.assertEqual(self.queue.path.read_bytes(), b'')

    def test_existing_foreign_empty_schema_is_not_adopted(self):
        """Check that existing foreign empty schema is not adopted."""
        state = self.folder / 'foreign-empty'
        state.mkdir(mode=0o700)
        path = state / 'jobs.sqlite3'
        with closing(sqlite3.connect(path)) as connection:
            connection.execute('VACUUM')
        path.chmod(0o600)
        before = path.read_bytes()
        self.assertGreater(len(before), 0)
        with self.assertRaisesRegex(QueueError, 'unrelated'):
            JobQueue(state, root=self.root)
        self.assertEqual(path.read_bytes(), before)

    def test_two_processes_can_initialize_a_new_queue_concurrently(self):
        """Check that two processes can initialize a new queue concurrently."""
        state = self.folder / 'fresh-shared-state'
        program = '''import sys,time
sys.path.insert(0,sys.argv[1])
from malakopia_job_queue import JobQueue
from contextlib import contextmanager
original=JobQueue._connect
@contextmanager
def slow(self, **kwargs):
    if kwargs.get('initializing'): time.sleep(.2)
    with original(self, **kwargs) as connection: yield connection
JobQueue._connect=slow
print('ready',flush=True)
sys.stdin.readline()
q=JobQueue(sys.argv[2],root=sys.argv[3])
q.enqueue({'fixture':sys.argv[4]},job_id=sys.argv[4])
'''
        children = [subprocess.Popen([sys.executable, '-B', '-c', program,
                     str(Path(__file__).resolve().parent), str(state), str(self.root), name],
                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    for name in ('first', 'second')]
        try:
            for child in children:
                self.assertEqual(child.stdout.readline().strip(), 'ready')
            for child in children:
                child.stdin.write('start\n')
                child.stdin.flush()
            for child in children:
                out, error = child.communicate(timeout=10)
                self.assertEqual(child.returncode, 0, error)
        finally:
            for child in children:
                if child.poll() is None:
                    child.kill()
                child.communicate(timeout=5)
        reopened = JobQueue(state, root=self.root)
        self.assertEqual({r['id'] for r in reopened.list_jobs()}, {'first', 'second'})
        self.assertEqual(len(reopened.events()), 2)

    def test_unsafe_initialization_lock_is_rejected_without_touching_its_target(self):
        """Check that unsafe initialization lock is rejected without touching its target."""
        state = self.folder / 'unsafe-lock'
        state.mkdir(mode=0o700)
        outside = self.folder / 'outside-lock'
        outside.write_bytes(b'preserve this')
        outside.chmod(0o600)
        os.link(outside, state / '.initialization.lock')
        with self.assertRaisesRegex(QueueError, 'initialization lock'):
            JobQueue(state, root=self.root)
        self.assertEqual(outside.read_bytes(), b'preserve this')
        self.assertFalse((state / 'jobs.sqlite3').exists())

    def test_contract_sql_trigger_rejects_in_place_change(self):
        """Check that contract sql trigger rejects in place change."""
        job = self.add()
        connection = sqlite3.connect(self.queue.path)
        try:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute('UPDATE jobs SET max_attempts=99 WHERE job_id=?', (job,))
            connection.rollback()
        finally:
            connection.close()
        self.assertEqual(self.queue.get(job)['max_attempts'], 3)

    def test_changed_dependency_edges_fail_fingerprint_validation(self):
        """Check that changed dependency edges fail fingerprint validation."""
        parent = self.add(job_id='parent')
        child = self.add(job_id='child')
        connection = sqlite3.connect(self.queue.path)
        connection.execute('INSERT INTO dependencies(job_id,dependency_id) VALUES (?,?)', (child, parent))
        connection.commit()
        connection.close()
        with self.assertRaises(ContractError):
            self.queue.get(child)
        with self.assertRaises(ContractError):
            self.add()

    def test_event_history_cannot_be_updated_or_deleted(self):
        """Check that event history cannot be updated or deleted."""
        self.add()
        connection = sqlite3.connect(self.queue.path)
        try:
            for statement in ('DELETE FROM events', "UPDATE events SET event='passed'"):
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(statement)
                connection.rollback()
        finally:
            connection.close()

    def test_state_permissions_are_private(self):
        """Check that state permissions are private."""
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.queue.path.stat().st_mode & 0o777, 0o600)

    def test_missing_database_is_not_silently_recreated(self):
        """Check that missing database is not silently recreated."""
        self.queue.path.unlink()
        with self.assertRaises(QueueError):
            self.queue.list_jobs()
        self.assertFalse(self.queue.path.exists())

    def test_default_state_path_does_not_create_files_or_enter_workspace(self):
        """Check that default state path does not create files or enter workspace."""
        with patch.dict(os.environ, {'MALAKOPIA_JOBS_STATE_DIR': '', 'XDG_STATE_HOME': str(self.folder / 'xdg')}):
            folder = default_state_dir(self.root)
        self.assertFalse(folder.is_relative_to(self.root))
        self.assertFalse(folder.exists())

    def test_empty_xdg_state_home_falls_back_to_the_default(self):
        """Check that empty xdg state home falls back to the default."""
        with patch.dict(os.environ, {'MALAKOPIA_JOBS_STATE_DIR': '', 'XDG_STATE_HOME': ''}), \
                patch.object(queue_module.sys, 'platform', 'linux'):
            folder = default_state_dir(self.root)
        self.assertTrue(folder.is_absolute())
        self.assertEqual(folder.parts[-3:-1], ('malakopia', 'jobs'))

    def test_existing_open_directory_is_refused_and_left_untouched(self):
        """Check that existing open directory is refused and left untouched."""
        shared = self.folder / 'shared'
        shared.mkdir(mode=0o755)
        os.chmod(shared, 0o755)
        with self.assertRaises(QueueError):
            JobQueue(shared, root=self.root, clock=self.clock)
        self.assertEqual(os.stat(shared).st_mode & 0o777, 0o755)

    def test_new_directory_is_created_private_and_private_existing_one_is_accepted(self):
        """Check that new directory is created private and private existing one is accepted."""
        fresh = self.folder / 'fresh-state'
        JobQueue(fresh, root=self.root, clock=self.clock)
        self.assertEqual(os.stat(fresh).st_mode & 0o777, 0o700)
        JobQueue(fresh, root=self.root, clock=self.clock)


if __name__ == '__main__':
    unittest.main()
