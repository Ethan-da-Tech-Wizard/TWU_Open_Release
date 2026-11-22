"""Offline decomposition checks; no model, network or subprocess is invoked."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from malakopia_completion import complete_task
from malakopia_decompose import generate_decomposed
from malakopia_local_tasks import EXPECTED, specs


class DecompositionTests(unittest.TestCase):
    """Tests for: Decomposition Tests."""
    def setUp(self):
        """Create the scratch state this test needs."""
        self.temporary = tempfile.TemporaryDirectory(prefix='malakopia-decomposition-test-')
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name) / 'children'
        self.spec = specs()[0]

    def responses(self, spec=None):
        """Helper: responses."""
        selected = spec or self.spec
        return [{'id': row['id'], 'decision': EXPECTED[selected['id']][row['id']]}
                for row in selected['acceptance']['input_cases']]

    def test_combines_actual_accepted_children_and_preserves_original_contract(self):
        """Check that combines actual accepted children and preserves original contract."""
        for spec in specs():
            before = copy.deepcopy(spec['acceptance'])
            rows = self.responses(spec)
            remaining = iter(rows)
            prompts = []
            def generate(prompt):
                """Helper: generate."""
                prompts.append(prompt)
                return json.dumps(next(remaining))
            output = self.output / spec['id']
            candidate = json.loads(generate_decomposed(spec, generate, output))
            self.assertEqual(candidate, {'decisions': rows})
            self.assertTrue(spec['validate'](candidate)['passed'])
            self.assertEqual(len(prompts), len(rows))
            self.assertEqual(spec['acceptance'], before)
            for row, prompt, case in zip(rows, prompts, before['input_cases']):
                folder = output / row['id']
                journal = json.loads((folder / 'run.json').read_text())
                contract = journal['contract']['acceptance']
                self.assertEqual(contract['rules'], before['rules'])
                self.assertEqual(contract['allowed_decisions'], before['allowed_decisions'])
                self.assertEqual(contract['input_cases'], [case])
                self.assertNotIn('output_shape', contract)
                self.assertNotIn('INPUT_ID', prompt)
                self.assertNotIn('ONE_ALLOWED_DECISION', prompt)
                self.assertEqual(journal['contract']['max_attempts'], 2)
                self.assertEqual(journal['accepted_candidate'], row)
                self.assertTrue(journal['decomposition']['first_attempt_passed'])
                self.assertFalse(journal['decomposition']['accepted_after_feedback'])

    def test_failed_child_stops_aggregate_and_parent_cannot_claim_completion(self):
        """Check that failed child stops aggregate and parent cannot claim completion."""
        calls = []
        def generate(prompt):
            """Helper: generate."""
            calls.append(prompt)
            return json.dumps({'id': 'audited-pass', 'decision': 'repair'})
        result = complete_task(self.spec['id'], self.spec['goal'], self.spec['acceptance'],
            lambda _: generate_decomposed(self.spec, generate, self.output), self.spec['validate'],
            Path(self.temporary.name) / 'parent')
        self.assertEqual(result['status'], 'needs_manager')
        self.assertIsNone(result['accepted_candidate'])
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(result['attempts']), 1)
        self.assertIn('needs_manager: child audited-pass', result['attempts'][0]['error']['message'])
        child = json.loads((self.output / 'audited-pass/run.json').read_text())
        self.assertEqual(child['status'], 'needs_manager')
        self.assertFalse(child['decomposition']['first_attempt_passed'])
        self.assertFalse((self.output / 'missing-output').exists())

    def test_repair_records_first_failure_and_uses_returned_accepted_row(self):
        """Check that repair records first failure and uses returned accepted row."""
        rows = self.responses()
        answers = iter([{'id': 'audited-pass', 'decision': 'repair'}, *rows])
        prompts = []
        def generate(prompt):
            """Helper: generate."""
            prompts.append(prompt)
            return json.dumps(next(answers))
        candidate = json.loads(generate_decomposed(self.spec, generate, self.output))
        self.assertEqual(candidate['decisions'], rows)
        child = json.loads((self.output / 'audited-pass/run.json').read_text())
        self.assertEqual([a['status'] for a in child['attempts']], ['rejected', 'accepted'])
        self.assertFalse(child['decomposition']['first_attempt_passed'])
        self.assertTrue(child['decomposition']['accepted_after_feedback'])
        self.assertIn('expected completed, received repair', prompts[1])
        self.assertEqual(child['accepted_candidate'], rows[0])

    def test_wrong_case_id_or_extra_status_cannot_be_aggregated(self):
        """Check that wrong case id or extra status cannot be aggregated."""
        for index, candidate in enumerate(({'id': 'different', 'decision': 'completed'},
                                          {'id': 'audited-pass', 'decision': 'completed', 'status': 'completed'})):
            with self.subTest(candidate=candidate), self.assertRaisesRegex(RuntimeError, 'needs_manager'):
                generate_decomposed(self.spec, lambda _: json.dumps(candidate), self.output / str(index))

    def test_changed_case_or_rules_are_rejected_before_generation(self):
        """Check that changed case or rules are rejected before generation."""
        for key in ('input_cases', 'rules', 'allowed_decisions'):
            spec = dict(self.spec, acceptance=copy.deepcopy(self.spec['acceptance']))
            spec['acceptance'][key] = []
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'changed'):
                generate_decomposed(spec, lambda _: self.fail('must not generate'), self.output)
        self.assertFalse(self.output.exists())

    def test_interruption_keeps_child_journal_and_rethrows(self):
        """Check that interruption keeps child journal and rethrows."""
        def interrupt(_):
            """Helper: interrupt."""
            raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            generate_decomposed(self.spec, interrupt, self.output)
        child = json.loads((self.output / 'audited-pass/run.json').read_text())
        self.assertEqual(child['status'], 'interrupted')
        self.assertFalse(child['decomposition']['first_attempt_scored'])
        self.assertIsNone(child['decomposition']['first_attempt_passed'])
        self.assertIsNone(child['accepted_candidate'])

    def test_existing_output_is_not_reused(self):
        """Check that existing output is not reused."""
        self.output.mkdir()
        with self.assertRaises(FileExistsError):
            generate_decomposed(self.spec, lambda _: self.fail('must not generate'), self.output)


if __name__ == '__main__':
    unittest.main()
