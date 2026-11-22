"""Real validator and persistence tests, with no model/network/process launch."""
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest

from malakopia_completion import CompletionError, complete_task, parse_candidate


class CompletionTests(unittest.TestCase):
    """Tests for: Completion Tests."""
    def setUp(self):
        """Create the scratch state this test needs."""
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name) / 'run'

    def run_task(self, generate, validate=None, **kwargs):
        """Helper: run task."""
        return complete_task('fixture', 'Compute the sum of 2 and 3', ['answer must equal 5'],
                             generate, validate or self.validate, self.output, **kwargs)

    @staticmethod
    def validate(candidate):
        """Helper: validate."""
        passed = candidate.get('answer') == 5
        return {'passed': passed, 'failures': [] if passed else ['answer must equal 5'],
                'evidence': {'observed_answer': candidate.get('answer'), 'expected': 5}}

    def test_model_claim_is_rejected_then_failed_checks_drive_repair(self):
        """Check that model claim is rejected then failed checks drive repair."""
        prompts = []
        def generate(prompt):
            """Helper: generate."""
            prompts.append(prompt)
            return '{"finished":true,"answer":4}' if len(prompts) == 1 else '{"answer":5}'
        report = self.run_task(generate)
        self.assertEqual(report['status'], 'completed')
        self.assertEqual([a['status'] for a in report['attempts']], ['rejected', 'accepted'])
        for prompt in prompts:
            goal = prompt.split('\n\nGOAL\n', 1)[1].split('\n\nACCEPTANCE RULES\n', 1)[0]
            acceptance = prompt.split('\n\nACCEPTANCE RULES\n', 1)[1].split('\n\nPREVIOUS CANDIDATE\n', 1)[0]
            self.assertEqual(goal, report['contract']['goal'])
            self.assertEqual(json.loads(acceptance), report['contract']['acceptance'])
            self.assertNotIn('contract_sha256', prompt)
            self.assertNotIn(report['contract_sha256'], prompt)
            self.assertNotIn('max_attempts', prompt)
        previous = prompts[1].split('\n\nPREVIOUS CANDIDATE\n', 1)[1].split('\n\nFINAL FEEDBACK\n', 1)[0]
        self.assertEqual(json.loads(previous), {'finished': True, 'answer': 4})
        feedback = prompts[1].split('\n\nFINAL FEEDBACK\n', 1)[1]
        self.assertIn('- answer must equal 5', feedback)
        self.assertIn('actual values', feedback)
        self.assertEqual(report['accepted_candidate'], {'answer': 5})

    def test_finite_attempt_budget_needs_manager(self):
        """Check that finite attempt budget needs manager."""
        calls = []
        report = self.run_task(lambda _: calls.append(1) or '{"finished":true}', max_attempts=3)
        self.assertEqual(len(calls), 3)
        self.assertEqual(report['status'], 'needs_manager')
        self.assertEqual(report['reason'], 'attempt_budget_exhausted')
        self.assertIsNone(report['accepted_candidate'])

    def test_transport_failure_halts_without_retry(self):
        """Check that transport failure halts without retry."""
        calls = []
        def generate(_):
            """Helper: generate."""
            calls.append(1)
            raise TimeoutError('The underlying action may still be running')
        report = self.run_task(generate)
        self.assertEqual(len(calls), 1)
        self.assertEqual(report['status'], 'needs_manager')
        self.assertFalse(report['external_completion_confirmed'])
        self.assertEqual(report['attempts'][0]['error']['type'], 'TimeoutError')

    def test_artifacts_match_hashes_and_contract_survives_callback_mutation(self):
        """Check that artifacts match hashes and contract survives callback mutation."""
        acceptance = {'answer': 5}
        def validate(candidate):
            """Helper: validate."""
            acceptance['answer'] = 4
            candidate['answer'] = 999
            return {'passed': True, 'failures': [], 'evidence': {'checked_before_mutation': 5}}
        report = complete_task('fixture', 'Compute sum', acceptance, lambda _: '{"answer":5}', validate, self.output)
        self.assertEqual(report['contract']['acceptance'], {'answer': 5})
        self.assertEqual(report['accepted_candidate'], {'answer': 5})
        self.assertEqual(sha256((self.output / 'contract.json').read_bytes()).hexdigest(), report['contract_sha256'])
        for attempt in report['attempts']:
            artifact = self.output / attempt['artifact']['path']
            self.assertEqual(sha256(artifact.read_bytes()).hexdigest(), attempt['artifact']['sha256'])
            saved = json.loads(artifact.read_text())
            self.assertEqual(saved['raw_response'], '{"answer":5}')
            self.assertEqual(saved['candidate'], {'answer': 5})
            self.assertEqual(saved['validator_result']['evidence'], {'checked_before_mutation': 5})

    def test_interruption_saves_partial_evidence_and_rethrows(self):
        """Check that interruption saves partial evidence and rethrows."""
        def validate(_):
            """Helper: validate."""
            raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.run_task(lambda _: '{"answer":5}', validate)
        journal = json.loads((self.output / 'run.json').read_text())
        self.assertEqual(journal['status'], 'interrupted')
        self.assertEqual(journal['attempts'][0]['candidate'], {'answer': 5})
        self.assertIsNone(journal['attempts'][0]['validator_result'])
        self.assertEqual(journal['attempts'][0]['error']['stage'], 'validating')

    def test_parser_accepts_single_object_and_fence_rejects_ambiguity(self):
        """Check that parser accepts single object and fence rejects ambiguity."""
        self.assertEqual(parse_candidate('```json\n{"answer":5}\n```'), {'answer': 5})
        self.assertEqual(parse_candidate(' {"answer":5} '), {'answer': 5})
        for raw in ('{"answer":5} {"answer":4}', 'text {"answer":5}', '[5]',
                    '{"answer":5,"answer":4}', '{"answer":NaN}',
                    '```json\n{"answer":5}\n```\n```json\n{"answer":4}\n```'):
            with self.subTest(raw=raw), self.assertRaises(CompletionError):
                parse_candidate(raw)

    def test_invalid_json_can_be_repaired_without_faking_validator_evidence(self):
        """Check that invalid json can be repaired without faking validator evidence."""
        outputs = iter(['not JSON', '{"answer":5}'])
        report = self.run_task(lambda _: next(outputs))
        self.assertEqual(report['status'], 'completed')
        self.assertIsNone(report['attempts'][0]['validator_result'])
        self.assertIn('parse_error', report['attempts'][0])

    def test_invalid_validator_result_cannot_accept(self):
        """Check that invalid validator result cannot accept."""
        report = self.run_task(lambda _: '{"answer":5}', lambda _: {
            'passed': True, 'failures': ['A real failed check'], 'evidence': {}})
        self.assertEqual(report['status'], 'needs_manager')
        self.assertIsNone(report['accepted_candidate'])
        self.assertEqual(report['attempts'][0]['validator_result']['failures'], ['A real failed check'])

    def test_existing_output_is_not_overwritten(self):
        """Check that existing output is not overwritten."""
        self.output.mkdir()
        (self.output / 'existing').write_text('keep')
        with self.assertRaises(FileExistsError):
            self.run_task(lambda _: self.fail('must reject before generation'))
        self.assertEqual((self.output / 'existing').read_text(), 'keep')


if __name__ == '__main__':
    unittest.main()
