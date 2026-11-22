"""Failure, restart, integrity and locking checks for the local workflow engine."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import malakopia_engine as engine


def workflow(*steps):
    """Helper: workflow."""
    return {'name': 'test-workflow', 'version': 1, 'steps': list(steps)}


def step(identifier, action='ok', needs=(), **extra):
    """Helper: step."""
    return {'id': identifier, 'action': action, 'needs': list(needs), **extra}


class EngineTests(unittest.TestCase):
    """Tests for: Engine Tests."""
    def setUp(self):
        """Create the scratch state this test needs."""
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / 'state'

    def run_engine(self, specification, handlers, inputs=None, **options):
        """Helper: run engine."""
        return engine.run_workflow(specification, inputs or {}, handlers, self.root, **options)

    def test_dependency_order_and_context_isolation(self):
        """Check that dependency order and context isolation."""
        calls = []
        def first(context, params):
            """Helper: first."""
            calls.append('first')
            context['inputs']['changed'] = True
            params['mutated'] = True
            return {'value': 7}
        def second(context, params):
            """Helper: second."""
            calls.append('second')
            self.assertNotIn('changed', context['inputs'])
            return {'received': context['outputs']['first']['value']}
        specification = workflow(step('second', 'second', ['first']), step('first', 'first'))
        result = self.run_engine(specification, {'first': first, 'second': second})
        self.assertEqual(calls, ['first', 'second'])
        self.assertEqual(result['outputs']['second'], {'received': 7})
        self.assertEqual(result['status'], 'succeeded')
        events = json.loads(Path(result['events_file']).read_text())
        self.assertEqual([event['sequence'] for event in events], list(range(1, len(events) + 1)))

    def test_conditional_skip_satisfies_dependency_and_is_explicit(self):
        """Check that conditional skip satisfies dependency and is explicit."""
        calls = []
        def final(context, params):
            """Helper: final."""
            calls.append('final')
            self.assertTrue(context['outputs']['optional']['skipped'])
            return {'mode': 'readiness only'}
        result = self.run_engine(workflow(
            step('optional', when={'inputs.run_inference': True}), step('final', 'final', ['optional'])),
            {'ok': lambda *_: self.fail('skipped handler ran'), 'final': final}, {'run_inference': False})
        self.assertEqual(result['steps']['optional']['state'], 'skipped')
        self.assertEqual(result['steps']['optional']['attempts'], 0)
        self.assertEqual(result['status'], 'succeeded')
        self.assertEqual(calls, ['final'])

    def test_condition_is_typed_and_missing_keys_skip(self):
        """Check that condition is typed and missing keys skip."""
        result = self.run_engine(workflow(step('typed', when={'enabled': True}), step('missing', when={'inputs.absent': True})),
                                 {'ok': lambda *_: self.fail('condition should skip')}, {'enabled': 1})
        self.assertEqual([row['state'] for row in result['steps'].values()], ['skipped', 'skipped'])

    def test_condition_output_references_require_real_prerequisites(self):
        """Check that condition output references require real prerequisites."""
        handlers = {'ok': lambda *_: {'eligible': True}}
        for specification in (
            workflow(step('one', when={'outputs.missing.eligible': True})),
            workflow(step('one'), step('two', when={'outputs.one.eligible': True})),
        ):
            with self.subTest(workflow=specification):
                with self.assertRaisesRegex(engine.WorkflowError, '(output reference|declared prerequisite)'):
                    self.run_engine(specification, handlers)
                self.assertFalse(self.root.exists())
        result = self.run_engine(workflow(step('one'), step('two', needs=['one'], when={'outputs.one.eligible': True})), handlers)
        self.assertEqual(result['steps']['two']['state'], 'succeeded')

    def test_failure_blocks_descendants_but_independent_branch_finishes(self):
        """Check that failure blocks descendants but independent branch finishes."""
        def fail(*_):
            """Helper: fail."""
            raise RuntimeError('original failure evidence')
        result = self.run_engine(workflow(step('bad', 'fail'), step('blocked', needs=['bad']),
                                         step('grandchild', needs=['blocked']), step('independent')),
                                 {'ok': lambda *_: {'done': True}, 'fail': fail})
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['steps']['bad']['error']['message'], 'original failure evidence')
        self.assertEqual(result['steps']['blocked']['state'], 'blocked')
        self.assertEqual(result['steps']['grandchild']['state'], 'blocked')
        self.assertEqual(result['steps']['independent']['state'], 'succeeded')
        self.assertNotIn('bad', result['outputs'])

    def test_resume_does_not_repeat_successes_or_skips(self):
        """Check that resume does not repeat successes or skips."""
        calls = []
        def action(context, params):
            """Helper: action."""
            calls.append(params['name'])
            return {'done': True}
        specification = workflow(step('one', params={'name': 'one'}), step('optional', when={'never': True}))
        handlers = {'ok': action}
        result = self.run_engine(specification, handlers)
        resumed = self.run_engine(specification, handlers, run_id=result['run_id'])
        self.assertEqual(calls, ['one'])
        self.assertEqual(result['outputs'], resumed['outputs'])
        self.assertTrue(resumed['resumed'])
        self.assertEqual(resumed['steps']['one']['attempts'], 1)

    def test_retry_resumes_blocked_work_and_retains_failure_evidence(self):
        """Check that retry resumes blocked work and retains failure evidence."""
        calls = []
        def flaky(*_):
            """Helper: flaky."""
            calls.append('flaky')
            if len(calls) == 1:
                raise ValueError('first attempt failed')
            return {'recovered': True}
        specification = workflow(step('first', 'flaky'), step('child', needs=['first']))
        handlers = {'flaky': flaky, 'ok': lambda *_: {'finished': True}}
        result = self.run_engine(specification, handlers, replay_safe_actions=['flaky'])
        first_failure = result['steps']['first']['history'][0]['artifact']
        resumed = self.run_engine(specification, handlers, run_id=result['run_id'], replay_safe_actions=['flaky'])
        self.assertEqual(resumed['status'], 'succeeded')
        history = resumed['steps']['first']['history']
        self.assertEqual([attempt['state'] for attempt in history], ['failed', 'succeeded'])
        self.assertEqual(history[0]['artifact'], first_failure)
        self.assertEqual(history[0]['error']['message'], 'first attempt failed')
        self.assertTrue((Path(result['state_directory']) / first_failure['path']).is_file())

    def test_attempt_limit_is_across_resume_invocations(self):
        """Check that attempt limit is across resume invocations."""
        calls = []
        def fail(*_):
            """Helper: fail."""
            calls.append(1)
            raise RuntimeError(f'failure {len(calls)}')
        specification = workflow(step('bad', 'fail'))
        handlers = {'fail': fail}
        result = self.run_engine(specification, handlers, replay_safe_actions=['fail'], max_attempts=2)
        for _ in range(3):
            result = self.run_engine(specification, handlers, run_id=result['run_id'], replay_safe_actions=['fail'], max_attempts=2)
        self.assertEqual(len(calls), 2)
        self.assertEqual(result['steps']['bad']['attempts'], 2)
        self.assertEqual([x['error']['message'] for x in result['steps']['bad']['history']], ['failure 1', 'failure 2'])

    def test_interrupted_step_retries_only_if_replay_safe(self):
        """Check that interrupted step retries only if replay safe."""
        for safe in (False, True):
            with self.subTest(replay_safe=safe):
                calls, run_ids = [], []
                def interrupt(context, params):
                    """Helper: interrupt."""
                    calls.append(1)
                    run_ids.append(context['run_id'])
                    if len(calls) == 1:
                        raise KeyboardInterrupt('simulated process interruption')
                    return {'recovered': True}
                specification = workflow(step('interrupt'))
                policy = {'replay_safe_actions': ['ok'] if safe else []}
                with self.assertRaises(KeyboardInterrupt):
                    self.run_engine(specification, {'ok': interrupt}, **policy)
                saved = json.loads((self.root / run_ids[0] / 'run.json').read_text())
                self.assertEqual(saved['steps']['interrupt']['state'], 'running')
                resumed = self.run_engine(specification, {'ok': interrupt}, run_id=run_ids[0], **policy)
                self.assertEqual(len(calls), 2 if safe else 1)
                self.assertEqual(resumed['status'], 'succeeded' if safe else 'failed')
                self.assertEqual(resumed['steps']['interrupt']['history'][0]['state'], 'interrupted')

    def test_invalid_graph_and_unknown_action_rejected_before_handlers_or_state(self):
        """Check that invalid graph and unknown action rejected before handlers or state."""
        invalid = (
            workflow(step('one'), step('one')),
            workflow(step('one', needs=['missing'])),
            workflow(step('one', needs=['two']), step('two', needs=['one'])),
            workflow(step('one'), step('two', 'unknown')),
            workflow(step('../escape')),
        )
        for specification in invalid:
            with self.subTest(workflow=specification):
                with self.assertRaises(engine.WorkflowError):
                    self.run_engine(specification, {'ok': lambda *_: self.fail('preflight must reject')})
                self.assertFalse(self.root.exists())

    def test_pure_validator_returns_a_copy_without_executing_or_writing(self):
        """Check that pure validator returns a copy without executing or writing."""
        specification = workflow({'id': 'one', 'action': 'ok'})
        normalized = engine.validate_workflow(specification, {'ok': lambda *_: self.fail('must not execute')})
        self.assertEqual(normalized['steps'][0]['needs'], [])
        self.assertNotIn('needs', specification['steps'][0])
        self.assertFalse(self.root.exists())

    def test_changed_workflow_inputs_or_retry_policy_rejected_before_calls(self):
        """Check that changed workflow inputs or retry policy rejected before calls."""
        specification = workflow(step('one'))
        handlers = {'ok': lambda *_: {'value': 1}}
        result = self.run_engine(specification, handlers, {'input': 'original'})
        original_state = (Path(result['state_directory']) / 'run.json').read_bytes()
        changed = copy.deepcopy(specification)
        changed['version'] = 2
        variants = ((changed, {'input': 'original'}, {}), (specification, {'input': 'changed'}, {}),
                    (specification, {'input': 'original'}, {'replay_safe_actions': ['ok']}))
        for candidate, inputs, options in variants:
            with self.subTest(inputs=inputs, options=options):
                with self.assertRaisesRegex(engine.WorkflowError, 'fingerprint changed'):
                    self.run_engine(candidate, {'ok': lambda *_: self.fail('resume must reject')}, inputs,
                                    run_id=result['run_id'], **options)
                self.assertEqual((Path(result['state_directory']) / 'run.json').read_bytes(), original_state)

    def test_changed_or_missing_success_artifact_rejected(self):
        """Check that changed or missing success artifact rejected."""
        specification = workflow(step('one'))
        handlers = {'ok': lambda *_: {'value': 1}}
        for remove in (False, True):
            with self.subTest(remove=remove):
                result = self.run_engine(specification, handlers)
                artifact = Path(result['state_directory']) / result['steps']['one']['output']['path']
                if remove:
                    artifact.unlink()
                else:
                    artifact.write_text('{"value":999}')
                with self.assertRaisesRegex(engine.WorkflowError, '(Changed|Missing) saved artifact'):
                    self.run_engine(specification, handlers, run_id=result['run_id'])

    def test_failed_artifact_tamper_cannot_erase_original_evidence(self):
        """Check that failed artifact tamper cannot erase original evidence."""
        def fail(*_):
            """Helper: fail."""
            raise RuntimeError('preserve this')
        specification = workflow(step('one'))
        result = self.run_engine(specification, {'ok': fail}, replay_safe_actions=['ok'])
        artifact = Path(result['state_directory']) / result['steps']['one']['history'][0]['artifact']['path']
        artifact.write_text('{}')
        with self.assertRaisesRegex(engine.WorkflowError, 'Changed saved artifact'):
            self.run_engine(specification, {'ok': lambda *_: self.fail('must not retry')},
                            run_id=result['run_id'], replay_safe_actions=['ok'])

    def test_handler_non_json_result_is_an_honest_failed_step(self):
        """Check that handler non json result is an honest failed step."""
        for value in (None, {'bad': float('nan')}, {'bad': object()}, {1: 'bad key'}):
            with self.subTest(value=type(value).__name__):
                result = self.run_engine(workflow(step('one')), {'ok': lambda *_: value})
                self.assertEqual(result['steps']['one']['state'], 'failed')
                self.assertEqual(result['steps']['one']['error']['type'], 'WorkflowError')

    @unittest.skipIf(engine.fcntl is None, 'flock is unavailable')
    def test_writer_lock_contention_and_recovery(self):
        """Check that writer lock contention and recovery."""
        specification = workflow(step('one'))
        handlers = {'ok': lambda *_: {'value': 1}}
        result = self.run_engine(specification, handlers)
        with (Path(result['state_directory']) / '.writer.lock').open('rb') as lock:
            engine.fcntl.flock(lock.fileno(), engine.fcntl.LOCK_EX | engine.fcntl.LOCK_NB)
            with self.assertRaisesRegex(engine.RunLockedError, 'already being written'):
                self.run_engine(specification, handlers, run_id=result['run_id'])
        resumed = self.run_engine(specification, handlers, run_id=result['run_id'])
        self.assertEqual(resumed['status'], 'succeeded')

    def test_no_silent_unlocked_platform_fallback(self):
        """Check that no silent unlocked platform fallback."""
        with mock.patch.object(engine, 'fcntl', None):
            with self.assertRaisesRegex(engine.WorkflowError, 'no unlocked fallback'):
                self.run_engine(workflow(step('one')), {'ok': lambda *_: {}})
        self.assertFalse(self.root.exists())


if __name__ == '__main__':
    unittest.main()
