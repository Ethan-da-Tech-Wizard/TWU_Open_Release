"""Offline checks for the three explicit local-worker task contracts."""
import copy
import json
import unittest

from malakopia_local_tasks import render_report, specs


ANSWERS = {
    'completion-auditor': [('audited-pass', 'completed'), ('missing-output', 'repair'),
        ('failing-tests', 'repair'), ('unconfirmed-runtime', 'needs_manager'),
        ('paid-reroute', 'needs_manager'), ('conflicting-evidence', 'needs_manager')],
    'cost-router': [('sort-names', 'script'), ('duration-arithmetic', 'script'),
        ('source-summary', 'local'), ('review-notes', 'local'),
        ('runtime-architecture', 'manager'), ('unknown-sign-in', 'manager')],
    'failure-reviewer': [('self-claim', 'repair'), ('stale-checks', 'repair'),
        ('missing-artifact', 'repair'), ('unknown-external-outcome', 'needs_manager'),
        ('accepted-evidence', 'completed'), ('spent-budget', 'needs_manager')],
}


def answer(identifier):
    """Helper: answer."""
    return {'decisions': [{'id': key, 'decision': value} for key, value in ANSWERS[identifier]]}


class LocalTaskTests(unittest.TestCase):
    """Tests for: Local Task Tests."""
    def test_contracts_are_bounded_and_have_six_cases(self):
        """Check that contracts are bounded and have six cases."""
        self.assertEqual({task['id'] for task in specs()}, set(ANSWERS))
        for task in specs():
            self.assertEqual(set(task), {'id', 'goal', 'acceptance', 'validate'})
            self.assertEqual(len(task['acceptance']['input_cases']), 6)
            prompt = json.dumps({key: value for key, value in task.items() if key != 'validate'})
            self.assertLess(len(prompt) + 500, 6000)

    def test_independent_expected_decisions_are_accepted(self):
        """Check that independent expected decisions are accepted."""
        for task in specs():
            with self.subTest(task=task['id']):
                result = task['validate'](answer(task['id']))
                self.assertTrue(result['passed'], result)
                self.assertEqual(result['failures'], [])
                self.assertEqual(len(result['evidence']['decision_checks']), 6)

    def test_bad_duplicate_missing_and_nonstring_ids_reject(self):
        """Check that bad duplicate missing and nonstring ids reject."""
        for task in specs():
            valid = answer(task['id'])
            unknown = copy.deepcopy(valid); unknown['decisions'][0]['id'] = 'invented'
            duplicate = copy.deepcopy(valid); duplicate['decisions'][1]['id'] = duplicate['decisions'][0]['id']
            missing = copy.deepcopy(valid); missing['decisions'].pop()
            nonstring = copy.deepcopy(valid); nonstring['decisions'][0]['id'] = ['bad']
            for value in (unknown, duplicate, missing, nonstring):
                with self.subTest(task=task['id'], candidate=value):
                    self.assertFalse(task['validate'](value)['passed'])

    def test_wrong_decisions_and_invented_lanes_reject(self):
        """Check that wrong decisions and invented lanes reject."""
        for task in specs():
            wrong = answer(task['id'])
            allowed = task['acceptance']['allowed_decisions']
            wrong['decisions'][0]['decision'] = next(value for value in allowed if value != wrong['decisions'][0]['decision'])
            result = task['validate'](wrong)
            self.assertFalse(result['passed'])
            self.assertTrue(any('expected' in failure for failure in result['failures']))
            wrong['decisions'][0]['decision'] = 'paid-cloud'
            self.assertFalse(task['validate'](wrong)['passed'])

    def test_contradictory_status_and_extra_keys_cannot_bypass_validator(self):
        """Check that contradictory status and extra keys cannot bypass validator."""
        for task in specs():
            extra_status = answer(task['id']); extra_status['status'] = 'completed'
            extra_row = answer(task['id']); extra_row['decisions'][0]['status'] = 'failed'
            reason = answer(task['id']); reason['decisions'][0]['reason'] = 'Trust me'
            for value in (extra_status, extra_row, reason, {'finished': True}, {'decisions': 'all done'}):
                self.assertFalse(task['validate'](value)['passed'])

    def test_precedence_rejects_retrying_unknown_outcome_and_ignores_model_claim(self):
        """Check that precedence rejects retrying unknown outcome and ignores model claim."""
        tasks = {task['id']: task for task in specs()}
        candidate = answer('completion-auditor')
        candidate['decisions'][-1]['decision'] = 'repair'
        self.assertFalse(tasks['completion-auditor']['validate'](candidate)['passed'])
        candidate = answer('failure-reviewer')
        candidate['decisions'][4]['decision'] = 'needs_manager'
        self.assertFalse(tasks['failure-reviewer']['validate'](candidate)['passed'])

    def test_contracts_are_fresh_and_do_not_expose_answer_map(self):
        """Check that contracts are fresh and do not expose answer map."""
        task = specs()[0]
        task['acceptance']['input_cases'][0]['artifact_exists'] = False
        self.assertTrue(specs()[0]['acceptance']['input_cases'][0]['artifact_exists'])
        self.assertNotIn('expected', task['acceptance'])
        self.assertTrue(task['validate'](answer(task['id']))['passed'])

    def test_report_requires_revalidated_artifacts_and_marks_partial_coverage(self):
        """Check that report requires revalidated artifacts and marks partial coverage."""
        report = render_report({'cost-router': answer('cost-router')})
        self.assertIn('1 of 3 tasks', report)
        self.assertIn('| source-summary | local |', report)
        self.assertNotIn('## completion-auditor', report)
        with self.assertRaises(ValueError):
            render_report({'cost-router': {'decisions': []}})
        with self.assertRaises(ValueError):
            render_report({'invented': answer('cost-router')})


if __name__ == '__main__':
    unittest.main()
