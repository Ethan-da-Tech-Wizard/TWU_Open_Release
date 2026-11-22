"""Guard for the duplicated queue module: malakopia_core and enki_waypoint each ship a copy that must stay identical.

The expected SHA-256 of the module and of its test file is recorded in queue_copy_sha256.txt, which is also identical in
both components. Changing either file in only one place makes this test fail until both copies and the record are updated.
"""
from hashlib import sha256
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
TRACKED = ('malakopia_job_queue.py', 'test_malakopia_job_queue.py')
SIBLINGS = ('malakopia_core', 'enki_waypoint')


def recorded(folder):
    """Return {file name: sha256} parsed from queue_copy_sha256.txt in the given scripts folder (comments skipped)."""
    result = {}
    for line in (folder / 'queue_copy_sha256.txt').read_text(encoding='utf-8').splitlines():
        if line.strip() and not line.startswith('#'):
            name, digest = line.split()
            result[name] = digest
    return result


class QueueCopySyncTests(unittest.TestCase):
    """Tests for: Queue Copy Sync Tests."""
    def test_this_copy_matches_the_recorded_hashes(self):
        """Check that this copy matches the recorded hashes."""
        record = recorded(HERE)
        self.assertEqual(sorted(record), sorted(TRACKED))
        for name in TRACKED:
            self.assertEqual(sha256((HERE / name).read_bytes()).hexdigest(), record[name], name)

    def test_sibling_copy_is_identical_when_present(self):
        """Check that sibling copy is identical when present."""
        component = HERE.parent.name
        others = [name for name in SIBLINGS if name != component]
        sibling = HERE.parent.parent / others[0] / 'scripts' if others else None
        if sibling is None or not (sibling / 'queue_copy_sha256.txt').is_file():
            self.skipTest('sibling component is not next to this one (standalone copy)')
        self.assertEqual(recorded(sibling), recorded(HERE))
        for name in TRACKED:
            self.assertEqual((sibling / name).read_bytes(), (HERE / name).read_bytes(), name)


if __name__ == '__main__':
    unittest.main()
