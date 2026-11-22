"""Source release boundaries and third-party license integrity."""
from hashlib import sha256
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import malakopia_export as export


class ExportTests(unittest.TestCase):
    """Tests for: Export Tests."""
    def setUp(self):
        """Create the scratch state this test needs."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        folder = self.root / export.LICENSES
        folder.mkdir(parents=True)
        license_bytes = b'Fixture license only\n'
        (folder / 'LICENSE').write_bytes(license_bytes)
        (folder / 'manifest.json').write_text(json.dumps({'schema_version': 1, 'entries': [
            {'status': 'obtained', 'local_filename': 'LICENSE', 'bytes': len(license_bytes),
             'sha256': sha256(license_bytes).hexdigest()}]}))
        (self.root / 'public.py').write_text('print("public")\n')
        (self.root / 'private-record.txt').write_text('PRIVATE-FIXTURE-MUST-NOT-EXPORT')

    def test_allowlist_excludes_private_files_and_zip_is_reproducible(self):
        """Check that allowlist excludes private files and zip is reproducible."""
        with patch.dict(export.FILES, {'public.py': 'scripts/public.py', str(export.LICENSES / 'LICENSE'): 'LICENSE'}, clear=True):
            first, manifest = export.archive_bytes(self.root)
            second, _ = export.archive_bytes(self.root)
        self.assertEqual(first, second)
        with zipfile.ZipFile(io.BytesIO(first)) as package:
            self.assertIn('LICENSE', package.namelist())
            self.assertIn('licenses/LICENSE', package.namelist())
            self.assertNotIn('private-record.txt', package.namelist())
            self.assertFalse(any(b'PRIVATE-FIXTURE' in package.read(name) for name in package.namelist()))
            for row in manifest['files']:
                self.assertEqual(sha256(package.read(row['path'])).hexdigest(), row['sha256'])

    # An empty allowlist refuses to export, and allowlist files are validated.
    def test_empty_allowlist_refuses_to_export(self):
        """Check that empty allowlist refuses to export."""
        with patch.dict(export.FILES, {}, clear=True):           # nothing allowed -> must refuse, never export everything
            with self.assertRaisesRegex(ValueError, 'no export allowlist'):
                export.source_files(self.root)

    def test_allowlist_file_is_loaded_and_missing_file_is_empty(self):
        """Check that allowlist file is loaded and missing file is empty."""
        good = self.root / 'allow.json'
        good.write_text(json.dumps({'public.py': 'scripts/public.py'}))
        self.assertEqual(export.load_allowlist(good), {'public.py': 'scripts/public.py'})
        self.assertEqual(export.load_allowlist(self.root / 'does-not-exist.json'), {})

    def test_allowlist_rejects_paths_that_escape_the_root(self):
        """Check that allowlist rejects paths that escape the root."""
        for bad in ({'../secret': 'x'}, {'/etc/passwd': 'x'}, {'a.py': '../x'}, {'a.py': 5}, ['not', 'an', 'object']):
            path = self.root / 'bad.json'
            path.write_text(json.dumps(bad))
            with self.assertRaises(ValueError, msg=repr(bad)):
                export.load_allowlist(path)

    def test_changed_license_is_rejected(self):
        """Check that changed license is rejected."""
        (self.root / export.LICENSES / 'LICENSE').write_text('altered text')
        with self.assertRaisesRegex(ValueError, 'fingerprint'):
            export.check_licenses(self.root)

    def test_unregistered_license_file_is_rejected(self):
        """Check that unregistered license file is rejected."""
        (self.root / export.LICENSES / 'unregistered.txt').write_text('unknown')
        with self.assertRaisesRegex(ValueError, 'manifest disagree'):
            export.check_licenses(self.root)

    def test_docs_links_to_licenses_are_rewritten_for_the_archive(self):
        """Check that docs links to licenses are rewritten for the archive."""
        guide = self.root / 'guide.md'
        guide.write_text('[License](licenses/LICENSE)\n')
        original = guide.read_bytes()
        with patch.dict(export.FILES, {'guide.md': 'docs/guide.md'}, clear=True):
            files = export.source_files(self.root)
        self.assertEqual(files['docs/guide.md'], b'[License](../licenses/LICENSE)\n')
        self.assertEqual(guide.read_bytes(), original)

    def test_example_allowlist_matches_the_release_layout(self):
        """Check that example allowlist matches the release layout."""
        component = Path(export.__file__).resolve().parents[1]
        allowed = export.load_allowlist(component / 'export_allowlist.example.json')
        self.assertTrue(allowed)
        for source in allowed:
            self.assertTrue((component / source).is_file(), source)
        with patch.dict(export.FILES, allowed, clear=True):
            payload, manifest = export.archive_bytes(component)
        names = {row['path'] for row in manifest['files']}
        self.assertIn('scripts/malakopia_engine.py', names)
        self.assertIn('licenses/MIT.txt', names)
        self.assertTrue(payload)

    def test_empty_env_variables_fall_back_to_the_defaults(self):
        """Check that empty env variables fall back to the defaults."""
        import os, subprocess, sys
        names = ('MALAKOPIA_EXPORT_ROOT', 'MALAKOPIA_EXPORT_DESTINATION', 'MALAKOPIA_LICENSES_DIR', 'MALAKOPIA_EXPORT_ALLOWLIST')
        env = dict(os.environ, PYTHONPATH=str(Path(export.__file__).resolve().parent), **{n: '' for n in names})
        code = 'import malakopia_export as m; print(m.ROOT, m.DESTINATION, m.LICENSES, len(m.FILES))'
        out = subprocess.run([sys.executable, '-B', '-c', code], env=env, capture_output=True, text=True, timeout=20)
        root = str(Path(export.__file__).resolve().parents[1])
        self.assertEqual(out.stdout.split(), [root, 'dist/malakopia-source.zip', 'licenses', '0'])


if __name__ == '__main__':
    unittest.main()
