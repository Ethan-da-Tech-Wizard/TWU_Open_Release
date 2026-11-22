"""Build a reproducible, explicitly allowlisted open-source Malakopia archive."""
from __future__ import annotations

import argparse
# hashlib supplies the content fingerprints; zipfile and io build the archive in memory so nothing is half-written.
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import sys
import zipfile

# Configuration. Every variable may be left empty, which counts as unset.
#   ROOT         = env MALAKOPIA_EXPORT_ROOT, else the component folder (the parent of scripts/).
#   DESTINATION  = env MALAKOPIA_EXPORT_DESTINATION (path relative to ROOT), else dist/malakopia-source.zip.
#   LICENSES     = env MALAKOPIA_LICENSES_DIR (relative to ROOT), else licenses/ (must hold manifest.json).
#   FILES        = JSON object {"source path relative to ROOT": "path inside the archive"} read from the file named by
#                  env MALAKOPIA_EXPORT_ALLOWLIST, else ROOT/export_allowlist.json. A missing file gives an EMPTY
#                  allowlist and the export then refuses to run (fail closed: nothing is exported by default).
# load_allowlist() rejects absolute paths, '..' segments and non-string entries, so the allowlist cannot reach outside ROOT.
# See export_allowlist.example.json for the format.
# Each setting is read once at import; an empty environment value counts as unset (the "or" fallback).
ROOT = Path(os.environ.get('MALAKOPIA_EXPORT_ROOT') or Path(__file__).resolve().parents[1])
# The destination is relative to ROOT; it is joined with ROOT only inside main().
DESTINATION = Path(os.environ.get('MALAKOPIA_EXPORT_DESTINATION') or 'dist/malakopia-source.zip')
LICENSES = Path(os.environ.get('MALAKOPIA_LICENSES_DIR') or 'licenses')


def load_allowlist(path):
    """Read the export allowlist JSON.

    Args:
        path: file path (str or Path). A missing file is NOT an error: it yields {} (the export then refuses to run).
    Returns:
        dict mapping source path (relative to ROOT) -> archive path; both are plain relative POSIX-style strings.
    Raises:
        ValueError: the file is not a JSON object, an entry is not a string pair, or a path is absolute / contains '..'.
    """
    path = Path(path)
    if not path.is_file():                       # no file = nothing allowed (fail closed)
        return {}
    # Malformed JSON raises json.JSONDecodeError, a ValueError subclass, which main() reports as a normal error.
    data = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(data, dict):
        raise ValueError('allowlist must be a JSON object {source: archive path}')
    for source, target in data.items():
        for value in (source, target):
            # every path must be a non-empty relative string without parent-directory hops
            if not isinstance(value, str) or not value or value.startswith('/') or '..' in Path(value).parts:
                raise ValueError('unsafe or invalid allowlist path')
    # Return a plain copy so the caller cannot alias the parsed object.
    return dict(data)


# FILES is a module global on purpose: the tests replace it with unittest.mock.patch.dict(export.FILES, ..., clear=True).
FILES = load_allowlist(os.environ.get('MALAKOPIA_EXPORT_ALLOWLIST') or ROOT / 'export_allowlist.json')


def check_licenses(root=ROOT):
    """Verify the central license inventory against the files on disk and return how many are obtained."""
    # Raises ValueError when the manifest is malformed, an entry makes a false claim, or a file is missing, unsafe or altered.
    folder = root / LICENSES
    # The manifest is the single source of truth for which license files must exist and what they hash to.
    data = json.loads((folder / 'manifest.json').read_text())
    # Reject unknown manifest versions and non-list entries rather than guessing at their meaning.
    if data.get('schema_version') != 1 or not isinstance(data.get('entries'), list):
        raise ValueError('Invalid central license manifest')
    # obtained collects filenames already vouched for, to detect duplicates and to compare with the folder contents afterwards.
    obtained = set()
    # Entries are checked one at a time; 'obtained' ones must have a matching local file.
    for entry in data['entries']:
        name = entry.get('local_filename')
        if entry.get('status') != 'obtained':
            # An entry that is not obtained must not claim a file, hash or size, otherwise the inventory would overstate what was collected.
            if name is not None or entry.get('sha256') is not None or entry.get('bytes') is not None:
                raise ValueError('Unobtained license entry cannot claim a local artifact')
            continue
        # A filename must be text and unique, so two entries cannot vouch for the same file.
        if not isinstance(name, str) or name in obtained:
            raise ValueError('Missing or duplicate license filename')
        path = folder / name
        # Refuse symlinks and anything resolving outside the license folder, so the manifest cannot pull in files from elsewhere.
        if path.is_symlink() or not path.resolve().is_relative_to(folder.resolve()) or not path.is_file():
            raise ValueError('Missing or unsafe license file: ' + name)
        # Compare both hash and size against the manifest; either mismatch means the file changed after it was recorded.
        content = path.read_bytes()
        if sha256(content).hexdigest() != entry.get('sha256') or len(content) != entry.get('bytes'):
            raise ValueError('License fingerprint differs: ' + name)
        obtained.add(name)
    # Final consistency check in the other direction: no extra, unlisted file may sit in the license folder.
    actual = {str(path.relative_to(folder)) for path in folder.rglob('*') if path.is_file()}
    if actual != obtained | {'manifest.json'}:
        raise ValueError('Central license files and manifest disagree')
    # The count is only informational; any inconsistency has already raised above.
    return len(obtained)


def source_files(root=ROOT):
    """Return {archive path: bytes} for every allowlisted source plus the license files and a small test runner."""
    # Raises ValueError if the allowlist is empty, a source is missing or unsafe, or two sources share a target.
    # Fail closed: with no allowlist configured there is nothing to export, so say so plainly.
    if not FILES:
        raise ValueError('no export allowlist configured; see export_allowlist.example.json')
    # Licenses are verified before anything is collected, so an unverified license set can never be exported.
    check_licenses(root)
    # Start from the allowlist and append every license file, mapped into licenses/ inside the archive.
    mapping = list(FILES.items())
    for path in sorted((root / LICENSES).rglob('*')):
        if path.is_file():
            mapping.append((str(path.relative_to(root)), 'licenses/' + str(path.relative_to(root / LICENSES))))
    # result maps archive path to file content; building it in memory keeps the export free of side effects.
    result = {}
    # Validate and read each source in turn.
    for source, target in mapping:
        path = root / source
        # Only regular files that resolve inside ROOT are allowed: no symlinks, no escapes, no missing files.
        if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
            raise ValueError('Missing or unsafe export source: ' + source)
        # Two sources mapping to one archive path would silently overwrite each other, so fail instead.
        if target in result:
            raise ValueError('Duplicate export target: ' + target)
        content = path.read_bytes()
        # Documentation is moved to docs/ in the archive, so its relative license links need one more level up.
        if target.startswith('docs/'):
            content = content.replace(b'](licenses/', b'](../licenses/')
        if target == 'licenses/manifest.json':
            # The exported archive keeps the licence files under licenses/, so record that as the filename base.
            inventory = json.loads(content)
            inventory['source_local_filename_base'] = inventory.get('local_filename_base')
            inventory['local_filename_base'] = 'licenses'
            content = (json.dumps(inventory, indent=2) + '\n').encode()
        result[target] = content
    # The archive carries a small runner so the exported modules can be tested without the rest of the repository.
    # The archive carries a small runner so the exported modules can be tested without the rest of the repository.
    # The tests package marker is empty on purpose, so the archive's test runner is importable.
    result['tests/__init__.py'] = b''
    result['tests/run_core_tests.py'] = (
        b'import pathlib,sys,unittest\n'
        b'sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/"scripts"))\n'
        b'suite=unittest.defaultTestLoader.discover(str(pathlib.Path(__file__).parent),pattern="test_malakopia_engine.py")\n'
        b'raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())\n')
    return result


def archive_bytes(root=ROOT):
    """Build the zip as bytes in memory and return (zip bytes, manifest dict)."""
    # The same inputs always produce identical bytes, so the --check mode can compare byte for byte.
    files = source_files(root)
    # The manifest lists every file with size and hash; the manifest file itself is added afterwards.
    manifest = {'version': 1, 'license': 'MIT for original Malakopia work; third-party terms retained',
                'private_files_included': False,
                'files': [{'path': name, 'bytes': len(value), 'sha256': sha256(value).hexdigest()}
                          for name, value in sorted(files.items())]}
    # Add the manifest after hashing the other files, since it cannot contain its own hash.
    files['MANIFEST.json'] = (json.dumps(manifest, indent=2) + '\n').encode()
    buffer = io.BytesIO()
    # Sorted order and a fixed timestamp (1980-01-01), fixed permissions and fixed compression keep the archive reproducible.
    with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for name, value in sorted(files.items()):
            entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            entry.external_attr = 0o100644 << 16
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, value)
    return buffer.getvalue(), manifest


def main(argv=None):
    """Command-line entry: build the export, or with --check verify the existing one; return 0 on success, 1 on error."""
    # Parse the two flags: --check compares without writing, --licenses verifies the license inventory only.
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--licenses', action='store_true', help='Verify the central license inventory only')
    args = parser.parse_args(argv)
    # Expected failures (bad allowlist, missing files, I/O errors) are reported below as one line, not a traceback.
    try:
        # License-only mode: no archive is built or written.
        if args.licenses:
            print(f'Malakopia licenses: {check_licenses()} obtained license/notice/declaration files match their fingerprints.')
            return 0
        # Build the archive in memory first, so a failure cannot leave a half-written file on disk.
        # Build first, then compare or write, so --check and write mode share exactly the same bytes.
        payload, manifest = archive_bytes()
        destination = ROOT / DESTINATION
        # The checksum line uses the same format as sha256sum so users can verify the download directly.
        checksum_line = sha256(payload).hexdigest() + '  ' + destination.name + '\n'
        # Check mode never writes: it fails when the committed archive, manifest or checksum is missing or differs.
        if args.check:
            # A stale or missing archive fails the check; this guards against shipping a build that no longer matches the sources.
            if not destination.is_file() or destination.read_bytes() != payload:
                raise ValueError('Source export is missing or stale; run python3 scripts/malakopia_export.py')
            if (json.loads((destination.parent / 'MANIFEST.json').read_text()) != manifest
                    or (destination.parent / 'SHA256SUMS').read_text() != checksum_line):
                raise ValueError('Source export manifest or checksum is stale')
        # Write mode: create the folder, then write the archive via a temporary file and rename it into place,
        # so readers never see a partial archive.
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            temporary = destination.with_suffix('.tmp')
            temporary.write_bytes(payload)
            # Rename is atomic, so an interrupted write never replaces a good archive with a partial one.
            temporary.replace(destination)
            # The manifest and checksum files sit beside the archive for verification without unzipping.
            (destination.parent / 'MANIFEST.json').write_text(json.dumps(manifest, indent=2) + '\n')
            (destination.parent / 'SHA256SUMS').write_text(checksum_line)
        print(f'Malakopia source export: {len(manifest["files"])} files, {len(payload)} bytes; private records excluded by allowlist.')
        return 0
    # Report errors on stderr with a non-zero status, so scripts and CI can detect them.
    except (OSError, ValueError) as exc:
        print('Malakopia source export: ' + str(exc), file=sys.stderr)
        return 1


# Run only when executed as a script, not when imported by the tests.
if __name__ == '__main__':
    raise SystemExit(main())
