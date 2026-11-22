# >>> HOW THIS WORKS
# FLOW:    1 JobQueue(state_dir) opens a SQLite database (jobs.sqlite3) after _check_paths() rejects symlinks; first-time setup is guarded by a file lock (.initialization.lock).
#          2 enqueue(spec, depends_on=...) stores a job; _check_graph() refuses dependency cycles.
#          3 claim(owner) picks the oldest queued job whose dependencies all passed, marks it running, makes a secret token and a lease (default 300 s, max 86400).
#          4 The worker calls heartbeat() to extend the lease and finish(job_id, token, result) to end it; only the token holder may do so.
#          5 retry(), cancel(), attempts(), events() manage or audit jobs; every change writes a row in the events table.
# DATA:    default state dir is $MALAKOPIA_JOBS_STATE_DIR, else ~/.local/state/malakopia/jobs/<workspace hash> (macOS: ~/Library/Application Support/...), OUTSIDE the synced repo. Tables: jobs, dependencies, attempts, events.
#          Callers: your own job runner calls this module; in this repository only enki_waypoint does.
# FAILS:   A lease that runs out is NOT retried automatically: _expire() sets status needs_review (outcome uncertain) and a human/review must call retry(). A late heartbeat or finish raises LeaseError. Bad specs raise ContractError. Attempts are capped by max_attempts (default 3, hard max 100).
# EXTEND:  New status = STATUSES (and BLOCKING if it should block dependents); schema changes = SCHEMA plus SCHEMA_VERSION. Test file: scripts/test_malakopia_job_queue.py
#          Test: PYTHONPATH=scripts python3 -B -m unittest -q scripts.test_malakopia_job_queue  (run from the component folder)
# GOTCHAS: Never copy the database between machines; each machine has its own queue. The queue never runs jobs and never trusts generated text to mark "passed".
# <<< HOW THIS WORKS
"""Durable, machine-local jobs for checked Malakopia workers.

This module does not execute a job or inspect its business inputs. The trusted
worker adapter supplies validation results; generated text cannot mark a job as
passed. SQLite transactions make claims exclusive across local processes. A
lost lease is *uncertain*, so recovery requires explicit review before retry.

All live state belongs outside the synced workspace. Do not copy this database
between running machines: each machine has an independent execution queue.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from hashlib import sha256
import fcntl
import json
import math
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import sys
import time
import uuid


# Component root (parent of scripts/). Used to derive the default per-workspace state path
# and to refuse a queue directory that lives inside the synced workspace.
# Two levels up from scripts/: the component directory that the workspace check compares against.
ROOT = Path(__file__).resolve().parents[1]
# Stamped into the SQLite header (PRAGMA application_id) so a foreign database that merely
# has the right file name is never opened as a job queue. Value is the ASCII bytes 'MKJQ'.
APPLICATION_ID = 0x4D4B4A51
# Bump together with SCHEMA; stored in PRAGMA user_version and checked on every connection.
SCHEMA_VERSION = 1
# Upper bound for any single stored JSON record (contract, result, event details), so a
# runaway worker cannot grow the database without limit.
MAX_JSON_BYTES = 4 * 1024 * 1024
# Hard ceiling on retries per job; mirrored by the CHECK constraint in SCHEMA.
MAX_ATTEMPTS = 100
# Every legal job status. Mirrored by the CHECK constraint on jobs.status in SCHEMA;
# keep the two lists identical when adding a status.
STATUSES = frozenset({'queued', 'running', 'passed', 'failed', 'needs_review', 'blocked', 'canceled'})
# Statuses that stop dependents: a child of a job in one of these is marked blocked rather
# than run. needs_review is included because the parent's outcome is uncertain.
BLOCKING = frozenset({'failed', 'needs_review', 'blocked', 'canceled'})
# Job and dependency identifiers: must start alphanumeric, then letters, digits, '_' or '-',
# at most 96 chars. Used with fullmatch so no newline or path-like text slips through.
IDENTIFIER = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,95}')


# Error hierarchy: callers can catch QueueError for any queue problem, or the narrower
# ContractError (immutable contract violated) and LeaseError (token/lease no longer valid)
# to react differently. All derive from ValueError so they read as bad input, not I/O faults.
class QueueError(ValueError):
    """Invalid job request, queue path or saved queue state."""


class ContractError(QueueError):
    """An immutable job contract or idempotency key was changed."""


class LeaseError(QueueError):
    """A worker no longer owns an active, unexpired claim."""


# Serializes first-time database creation between processes. Without it two starters could
# both see no file, both create and migrate, or one could read a half-initialized schema.
@contextmanager
def _initialization_lock(state):
    """Hold an exclusive advisory lock on the state directory for the with-block.

    Raises QueueError if the lock file is unsafe or not acquired within 30 s.
    """
    # Keep this inode: unlinking a lock can let two initializers own different locks.
    # O_NOFOLLOW makes the open fail if the lock name was swapped for a symlink; mode 0600 keeps
    # other users from holding or inspecting the lock.
    descriptor = os.open(state / '.initialization.lock',
                         os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        # Validate the already-open descriptor (fstat), not the path, to avoid a check/use race:
        # it must be a regular file, unshared (nlink 1, no hard-link alias), ours, and not group/other
        # accessible.
        info = os.fstat(descriptor)
        _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
                 and not info.st_mode & 0o077, 'Unsafe queue initialization lock')
        # Non-blocking attempts in a loop give a bounded wait instead of hanging forever behind a
        # crashed or stuck initializer.
        # monotonic clock: immune to wall-clock jumps while waiting.
        deadline = time.monotonic() + 30
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            # Another process holds the lock; poll until the deadline passes.
            except BlockingIOError:
                _require(time.monotonic() < deadline, 'Queue initialization is busy; retry after its owner finishes')
                time.sleep(.05)
        # The protected block (schema creation) runs here while the lock is held.
        yield
    # Closing the descriptor releases the flock. The file itself is intentionally left in place.
    finally:
        os.close(descriptor)


# Small guard helper used instead of assert, which is stripped under python -O and would
# silently disable these security checks.
def _require(condition, message, kind=QueueError):
    """Raise kind(message) unless condition is truthy."""
    if not condition:
        raise kind(message)


def _json(value):
    """Validate value as strict JSON data and return its canonical text.

    Raises QueueError for non-JSON types, non-string keys, non-finite floats or
    records over MAX_JSON_BYTES.
    """
    # Exact type checks (not isinstance) reject subclasses, which could smuggle in custom
    # serialization behavior or non-JSON payloads.
    def inspect(item):
        """Recursively check that item contains only plain JSON values."""
        if type(item) is dict:
            _require(all(type(k) is str for k in item), 'JSON object keys must be strings')
            for child in item.values():
                inspect(child)
        elif type(item) is list:
            for child in item:
                inspect(child)
        else:
            _require(item is None or type(item) in (str, bool, int, float), 'Value is not JSON data')
            _require(type(item) is not float or math.isfinite(item), 'JSON numbers must be finite')
    # Canonical form (sorted keys, no spaces, no NaN) so equal data always hashes identically;
    # the contract fingerprint depends on this being deterministic.
    try:
        inspect(value)
        content = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)
        _require(len(content.encode('utf-8')) <= MAX_JSON_BYTES, 'JSON record is too large')
        return content
    # Normalize low-level encoding and nesting failures into the module's own error type.
    except (TypeError, UnicodeError, RecursionError) as exc:
        raise QueueError('Invalid JSON data') from exc


# Storage uses REAL epoch seconds (cheap to compare); text is only for display.
def _timestamp(value):
    """Format epoch seconds as a UTC ISO-8601 string with microseconds."""
    return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec='microseconds')


def _name(value, label):
    """Return value if it is a valid identifier (see IDENTIFIER); otherwise raise QueueError naming label."""
    _require(type(value) is str and IDENTIFIER.fullmatch(value), f'Invalid {label}')
    return value


def _text(value, label, limit=200):
    """Return value if it is a non-blank string of at most limit printable characters.

    Control characters are refused so values are safe to log and display.
    """
    _require(type(value) is str and value.strip() and len(value) <= limit
             and all(ord(c) >= 32 for c in value), f'Invalid {label}')
    return value


# Path policy: the location is chosen here but not created or validated; JobQueue does that.
def default_state_dir(root=ROOT):
    # An explicit override wins, which lets tests and operators pin the location.
    """Return a per-workspace local path without creating it."""
    if os.environ.get('MALAKOPIA_JOBS_STATE_DIR'):
        return Path(os.environ['MALAKOPIA_JOBS_STATE_DIR']).expanduser()
    # Hash the resolved workspace path so each checkout gets its own queue without leaking
    # the path into the directory name.
    identity = sha256(str(Path(root).resolve()).encode()).hexdigest()[:16]
    # State lives under the per-user application-data area, never inside the repository.
    if sys.platform == 'darwin':
        base = Path.home() / 'Library' / 'Application Support'
    else:
        base = Path(os.environ.get('XDG_STATE_HOME') or Path.home() / '.local' / 'state')
    return base / 'malakopia' / 'jobs' / identity


def local_state_path(value):
    """Expand a local queue path without broadly resolving symbolic links.

    macOS exposes the system-owned ``/var`` and ``/tmp`` aliases as links into
    ``/private``.  Accept only those exact, verified aliases; every other link
    remains visible to the lstat checks below.
    """
    # abspath (not resolve) on purpose: resolve() would silently follow symlinks and hide them
    # from the lstat-based checks in _no_symlink_chain.
    # Normalizes '..' and relative segments lexically while keeping every link visible.
    path = Path(os.path.abspath(os.fspath(Path(value).expanduser())))
    if sys.platform != 'darwin':
        return path
    # Only the well-known system aliases are rewritten, and only if the link really points at
    # the expected /private target (absolute or relative form). A tampered alias falls through
    # and is rejected later as a symlink.
    for alias, target in (('/var', '/private/var'), ('/tmp', '/private/tmp')):
        try:
            literal_target = os.readlink(alias)
        # Alias is not a link at all (or unreadable): leave the path untouched.
        except OSError:
            continue
        # Some systems store the alias as a relative link ('private/var'); accept both spellings.
        relative_target = str(Path(target).relative_to(Path(alias).parent))
        if literal_target not in (target, relative_target):
            continue
        # Exact alias or anything beneath it is rewritten to the real /private location.
        if str(path) == alias:
            return Path(target)
        prefix = alias + os.sep
        if str(path).startswith(prefix):
            return Path(target + str(path)[len(alias):])
    return path


def _no_symlink_chain(path):
    """Reject existing symlinks, including broken links and linked parents."""
    # Walk from the filesystem root downward so the first offending ancestor is reported.
    # lstat does not follow links, which is the point of this check.
    for component in reversed((path, *path.parents)):
        try:
            mode = component.lstat().st_mode
        except FileNotFoundError:
            # Parts of the path that do not exist yet are fine; mkdir will create them later.
            continue
        # Also catches dangling links, which exist as links even though their target does not.
        _require(not stat.S_ISLNK(mode), 'Queue paths must not contain symbolic links')
        if component != path:
            # A file where a directory is expected would make mkdir fail confusingly later.
            _require(stat.S_ISDIR(mode), 'A queue parent is not a directory')


# Full database schema. Executed statement by statement at first initialization, so do not
# put '--' comments in here. Integrity is enforced by the database itself, not only by this
# module, so a buggy or hostile writer cannot rewrite history:
#   jobs: attempt_count is capped by max_attempts, status is restricted to the known set.
#   idempotency_key is UNIQUE so a repeated enqueue maps to one job.
#   token/lease_until/owner are only meaningful while status is 'running'.
#   triggers: contract columns are immutable; jobs, dependencies, attempts and events can
#   never be deleted, and dependencies/events can never be updated (an append-only audit trail).
SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    job_id TEXT PRIMARY KEY,
    contract_json TEXT NOT NULL,
    contract_hash TEXT NOT NULL,
    idempotency_key TEXT UNIQUE,
    max_attempts INTEGER NOT NULL CHECK(max_attempts BETWEEN 1 AND 100),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count >= 0 AND attempt_count <= max_attempts),
    status TEXT NOT NULL CHECK(status IN ('queued','running','passed','failed','needs_review','blocked','canceled')),
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    owner TEXT,
    token TEXT,
    lease_until REAL,
    result_json TEXT
);
CREATE TABLE IF NOT EXISTS dependencies (
    job_id TEXT NOT NULL REFERENCES jobs(job_id),
    dependency_id TEXT NOT NULL REFERENCES jobs(job_id),
    PRIMARY KEY(job_id, dependency_id),
    CHECK(job_id != dependency_id)
);
CREATE TABLE IF NOT EXISTS attempts (
    job_id TEXT NOT NULL REFERENCES jobs(job_id),
    attempt INTEGER NOT NULL,
    owner TEXT NOT NULL,
    started_at REAL NOT NULL,
    lease_until REAL NOT NULL,
    finished_at REAL,
    disposition TEXT NOT NULL,
    result_json TEXT,
    PRIMARY KEY(job_id, attempt)
);
CREATE TABLE IF NOT EXISTS events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL REFERENCES jobs(job_id),
    time REAL NOT NULL,
    event TEXT NOT NULL,
    details_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS jobs_ready ON jobs(status, created_at, job_id);
CREATE INDEX IF NOT EXISTS dependencies_parent ON dependencies(dependency_id);
CREATE INDEX IF NOT EXISTS events_job ON events(job_id, event_id);
CREATE TRIGGER IF NOT EXISTS immutable_job_contract
BEFORE UPDATE OF job_id, contract_json, contract_hash, max_attempts, idempotency_key, created_at ON jobs
BEGIN SELECT RAISE(ABORT, 'Job contracts are immutable'); END;
CREATE TRIGGER IF NOT EXISTS retain_jobs BEFORE DELETE ON jobs
BEGIN SELECT RAISE(ABORT, 'Job history cannot be deleted'); END;
CREATE TRIGGER IF NOT EXISTS immutable_dependency BEFORE UPDATE ON dependencies
BEGIN SELECT RAISE(ABORT, 'Job dependencies are immutable'); END;
CREATE TRIGGER IF NOT EXISTS retain_dependencies BEFORE DELETE ON dependencies
BEGIN SELECT RAISE(ABORT, 'Job dependencies are immutable'); END;
CREATE TRIGGER IF NOT EXISTS retain_attempts BEFORE DELETE ON attempts
BEGIN SELECT RAISE(ABORT, 'Job attempts cannot be deleted'); END;
CREATE TRIGGER IF NOT EXISTS immutable_events BEFORE UPDATE ON events
BEGIN SELECT RAISE(ABORT, 'Job events are immutable'); END;
CREATE TRIGGER IF NOT EXISTS retain_events BEFORE DELETE ON events
BEGIN SELECT RAISE(ABORT, 'Job events cannot be deleted'); END;
"""


class JobQueue:
    """A process-safe local queue; each operation opens its own SQLite handle.

    get/list/claim expose contract_hash, spec, depends_on, status and attempts.
    claim alone additionally exposes its opaque token. lease_until is epoch
    seconds; human-facing timestamps are UTC ISO strings. Tokens are deliberately
    absent from get/list/events/attempt history.
    """

    def __init__(self, state_dir, root=ROOT, *, clock=None):
        """Open or create the queue under state_dir.

        raises QueueError if the directory is a symlink chain, inside the workspace, not
        private and user-owned, or if an existing database is empty or not a queue.
        clock is an optional callable returning Unix seconds (used by tests).
        """
        # The workspace root is resolved (symlinks followed) so the containment checks below
        # compare real locations; the state path is not resolved, so its links stay detectable.
        self.root = Path(root).expanduser().resolve()
        self.state_dir = local_state_path(state_dir)
        self.path = self.state_dir / 'jobs.sqlite3'
        # Injectable clock: tests can control lease expiry without sleeping.
        self.clock = time.time if clock is None else clock
        # Reject links before touching anything, so mkdir/chmod below cannot be redirected elsewhere.
        _no_symlink_chain(self.state_dir)
        # Live state must stay outside the synced workspace, otherwise syncing would copy the
        # database (and its tokens) to other machines; the reverse nesting is refused too.
        _require(not self.state_dir.is_relative_to(self.root), 'Queue state must stay outside the synced workspace')
        _require(not self.root.is_relative_to(self.state_dir), 'Queue state cannot be a parent of the workspace')
        # Remember whether we created the directory: it decides below if we may adjust its mode.
        existed = self.state_dir.exists()
        self.state_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
        # Re-check after mkdir in case a component was replaced by a symlink in between.
        _no_symlink_chain(self.state_dir)
        # stat() of the final directory; ownership and mode are verified on the real inode.
        info = self.state_dir.stat()
        # Owner check stops a directory pre-created by another user from receiving our job data.
        _require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid(), 'Queue directory must be owned by this user')
        # Two cases with different trust: a directory we made is ours to chmod; a pre-existing one
        # is the operator's, so we only verify it and never loosen or tighten it behind their back.
        if existed:
            # Never change the permissions of a directory this queue did not create: refuse if it is open to others.
            _require(stat.S_IMODE(info.st_mode) & 0o077 == 0,
                     'Existing queue directory must already be private (mode 0700); choose a new directory or chmod it yourself')
        else:
            # Created just now by this call, so it is dedicated to private machine-local execution state.
            os.chmod(self.state_dir, 0o700)
        # Second full validation, including any pre-existing database/WAL/SHM files.
        self._check_paths()
        # Everything from here to the end of schema setup runs under the cross-process lock.
        # Initialization is idempotent and safe to run from many processes at once.
        with _initialization_lock(self.state_dir):
            # 'created' distinguishes a database born in this call (may be blank) from a pre-existing
            # one (must already carry our application_id and schema version).
            created = False
            try:
                # O_EXCL means exactly one initializer creates the file; the others fall into the except.
                # O_NOFOLLOW and 0600 guard against a pre-planted symlink or world-readable database.
                descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, 'O_NOFOLLOW', 0), 0o600)
            except FileExistsError:
                # A zero-byte file that we did not create could be a wiped database. Refuse rather than
                # quietly start an empty history over it.
                _require(self.path.stat().st_size > 0,
                         'Existing queue database is empty; restore its history instead of initializing it')
            else:
                os.close(descriptor)
                created = True
            # initializing=True skips the application_id/user_version checks that a brand-new file
            # cannot yet satisfy.
            # From here the file exists with mode 0600 and is ours, so SQLite can safely open it.
            with self._connect(initializing=True) as connection:
                # IMMEDIATE takes the write lock up front so identity checks and schema creation are atomic.
                connection.execute('BEGIN IMMEDIATE')
                try:
                    application = connection.execute('PRAGMA application_id').fetchone()[0]
                    # A blank database has application_id 0 and no tables; anything else must carry our stamp.
                    tables = connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
                    # Accept either our stamp, or a file this very call just created and that is still blank.
                    # Any other SQLite file (even an empty one we did not create) is refused as unrelated.
                    _require(application == APPLICATION_ID or (created and application == 0 and not tables),
                             'Refusing to use an unrelated SQLite database')
                    # user_version is the schema generation; there is no migration code, so mismatch means refuse.
                    version = connection.execute('PRAGMA user_version').fetchone()[0]
                    # Same rule for the version: a newer or older layout must not be silently reused.
                    _require(version == SCHEMA_VERSION or (created and version == 0),
                             'Unsupported job queue schema version')
                    # executescript would COMMIT first and break atomicity. Split SCHEMA at statement
                    # boundaries instead; sqlite3.complete_statement understands triggers' inner semicolons.
                    # executescript commits implicitly, so execute complete statements
                    # individually to retain the initialization transaction.
                    statement = ''
                    for line in SCHEMA.splitlines(keepends=True):
                        statement += line
                        if sqlite3.complete_statement(statement):
                            connection.execute(statement)
                            statement = ''
                    # Stamp identity and version inside the same transaction as the tables, so a crash
                    # cannot leave tables without the stamp (or the reverse).
                    # CREATE ... IF NOT EXISTS statements above make a re-run against an existing queue harmless.
                    connection.execute(f'PRAGMA application_id={APPLICATION_ID}')
                    connection.execute(f'PRAGMA user_version={SCHEMA_VERSION}')
                    connection.commit()
                # BaseException so even KeyboardInterrupt leaves no half-built schema.
                except BaseException:
                    connection.rollback()
                    raise
                # WAL is a persistent database property that cannot change inside a transaction, so set it
                # after the commit. Sidecar -wal/-shm files are covered by _check_paths.
                connection.execute('PRAGMA journal_mode=WAL')
        # Final audit now that WAL/SHM files may exist.
        self._check_paths()

    def _now(self):
        """Return the current time from the injected clock, validated as finite Unix seconds."""
        value = self.clock()
        # A misbehaving clock (NaN, negative, absurd) would corrupt lease arithmetic, so fail loudly.
        # The upper bound is the last second datetime can format (year 9999).
        _require(type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 253402300799,
                 'Clock must return finite Unix seconds')
        return float(value)

    def _check_paths(self):
        """Verify the state directory and every database file are private and unlinked.

        Raises QueueError on symlinks, wrong owner, group/other access, or hard links.
        """
        _no_symlink_chain(self.state_dir)
        info = self.state_dir.stat()
        # Mode mask 0o077 means any group/other permission bit fails the check.
        _require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                 and not info.st_mode & 0o077, 'Queue directory must remain private and user-owned')
        # SQLite sidecars: write-ahead log, shared memory index, rollback journal. Any of them can
        # hold job data, so each gets the same scrutiny as the main file.
        # Files that do not exist yet are fine (SQLite creates them lazily); existing ones must be private.
        for suffix in ('', '-wal', '-shm', '-journal'):
            target = Path(str(self.path) + suffix)
            # lstat (no link following) so a symlink planted at this name is seen, not followed.
            try:
                info = target.lstat()
            except FileNotFoundError:
                continue
            # nlink == 1 rules out a hard link to a file elsewhere (e.g. one readable by another user).
            _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
                     and not info.st_mode & 0o077, 'Queue database files must be private regular files without links')

    @contextmanager
    def _connect(self, *, initializing=False):
        """Yield a configured SQLite connection in autocommit mode, closing it afterwards.

        Every open re-verifies paths and database identity. Raises QueueError if the
        database is missing, unrecognized or has an unsupported schema version.
        """
        # Re-validate on every connection: the filesystem can change between operations.
        self._check_paths()
        # Never create the file here; a vanished database means lost history, not a fresh start.
        _require(self.path.is_file(), 'Job queue database is missing; do not silently replace execution history')
        # isolation_level=None disables the driver's implicit transactions so BEGIN/COMMIT are
        # issued explicitly and exactly where the code says.
        # 30 s timeout plus busy_timeout below: writers wait for each other instead of failing
        # immediately with 'database is locked' under normal contention.
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        # Name-based column access keeps the code independent of column order.
        connection.row_factory = sqlite3.Row
        try:
            # Enforce REFERENCES clauses (SQLite leaves foreign keys off by default).
            connection.execute('PRAGMA foreign_keys=ON')
            connection.execute('PRAGMA busy_timeout=30000')
            # FULL fsyncs at each commit so an acknowledged claim or finish survives power loss.
            connection.execute('PRAGMA synchronous=FULL')
            if not initializing:
                # Confirms the file really is a queue before trusting any of its rows.
                _require(connection.execute('PRAGMA application_id').fetchone()[0] == APPLICATION_ID,
                         'Unrecognized job queue database')
                _require(connection.execute('PRAGMA user_version').fetchone()[0] == SCHEMA_VERSION,
                         'Unsupported job queue schema version')
            # Check again now that SQLite may have created WAL/SHM files while we opened it.
            self._check_paths()
            # The caller uses the connection here; closing happens in the finally clause below.
            yield connection
        finally:
            connection.close()

    @contextmanager
    def _transaction(self):
        """Run one write transaction: commit on success, roll back on any exception.

        BEGIN IMMEDIATE takes the write lock immediately, so concurrent claimers are
        serialized and cannot both observe the same job as available.
        """
        with self._connect() as connection:
            # IMMEDIATE (not DEFERRED) avoids lock-upgrade deadlocks and read-then-write races.
            connection.execute('BEGIN IMMEDIATE')
            try:
                yield connection
                # Commit is the last step inside the try, so any failure before it triggers the rollback.
                connection.commit()
            # Roll back on BaseException, not just Exception, so an interrupt cannot leave a partial write.
            except BaseException:
                connection.rollback()
                raise

    def _row(self, connection, job_id):
        """Return the jobs row for job_id; raise QueueError if the ID is malformed or unknown."""
        # Validate the ID shape first so only well-formed identifiers reach the query.
        _name(job_id, 'job ID')
        row = connection.execute('SELECT * FROM jobs WHERE job_id=?', (job_id,)).fetchone()
        _require(row is not None, f'Unknown job: {job_id}')
        return row

    def _contract(self, connection, row):
        """Load and verify the saved contract of row, returning the decoded dict.

        Raises ContractError if the stored JSON, dependency rows, attempt limit or hash
        no longer agree, which indicates tampering or corruption.
        """
        try:
            # Re-canonicalize before hashing, so the hash is compared against the canonical form
            # regardless of how the text was stored.
            # Defensive parse: a hand-edited or damaged row must fail as ContractError, not crash later.
            contract = json.loads(row['contract_json'])
            encoded = _json(contract)
            # Dependencies live in two places (contract JSON and the dependencies table); compare both.
            dependencies = [item[0] for item in connection.execute(
                'SELECT dependency_id FROM dependencies WHERE job_id=? ORDER BY dependency_id', (row['job_id'],))]
            # Strict shape check: exact key set, known version, and the redundant columns must match.
            # The fingerprint test comes last and catches any edit of the stored contract text.
            _require(set(contract) == {'version', 'spec', 'depends_on', 'max_attempts'}
                     and contract['version'] == 1 and type(contract['spec']) is dict
                     and contract['depends_on'] == dependencies and contract['max_attempts'] == row['max_attempts']
                     and sha256(encoded.encode()).hexdigest() == row['contract_hash'],
                     'Saved job contract fingerprint does not match', ContractError)
            return contract
        # Corrupt rows surface as one well-defined error instead of random decode failures.
        except (TypeError, KeyError, json.JSONDecodeError) as exc:
            # 'from exc' keeps the original decode problem visible in the traceback.
            raise ContractError('Invalid saved job contract') from exc

    def _public(self, connection, row):
        """Build the caller-visible dict for row. The claim token is never included here."""
        # Verifying the contract on every read means tampered rows are never handed to workers.
        contract = self._contract(connection, row)
        # Most recent attempt that recorded a result, so a retrying worker sees why the last
        # try failed. The token is deliberately omitted from this dict.
        # result_json is NULL while an attempt is still running, hence the IS NOT NULL filter.
        previous = connection.execute(
            'SELECT result_json FROM attempts WHERE job_id=? AND result_json IS NOT NULL ORDER BY attempt DESC LIMIT 1',
            (row['job_id'],)).fetchone()
        # 'id'/'job_id' and 'attempt'/'attempt_count' are duplicated aliases kept for callers.
        # Explicit allow-list of fields: raw columns such as token are never exposed by accident.
        return {
            'id': row['job_id'], 'job_id': row['job_id'], 'spec': contract['spec'],
            'contract_hash': row['contract_hash'], 'depends_on': contract['depends_on'],
            'idempotency_key': row['idempotency_key'], 'status': row['status'],
            'attempt': row['attempt_count'], 'attempt_count': row['attempt_count'], 'max_attempts': row['max_attempts'],
            'owner': row['owner'], 'lease_until': row['lease_until'],
            # Timestamps are converted to UTC text for people; lease_until stays epoch seconds for arithmetic.
            'created_at': _timestamp(row['created_at']), 'updated_at': _timestamp(row['updated_at']),
            'result': json.loads(row['result_json']) if row['result_json'] else None,
            'previous_validation': json.loads(previous[0]) if previous else None,
        }

    def _event(self, connection, job_id, event, now, details=None):
        """Append an audit row to the events table within the caller's transaction."""
        connection.execute('INSERT INTO events(job_id,time,event,details_json) VALUES (?,?,?,?)',
                           (job_id, now, event, _json(details or {})))

    def _check_graph(self, connection, new_id=None, dependencies=()):
        """Reject dependency cycles and missing dependencies across all jobs plus a prospective one.

        Raises ContractError. new_id/dependencies describe a job about to be inserted.
        """
        # Rebuild the whole graph from verified contracts, including the candidate job, so a cycle
        # is detected before anything is written.
        # Every stored contract is verified while loading, so a corrupt row stops enqueue instead
        # of silently producing a graph that does not match the database.
        rows = connection.execute('SELECT * FROM jobs').fetchall()
        # Existing edges come from the verified contracts, not the dependencies table alone.
        graph = {row['job_id']: self._contract(connection, row)['depends_on'] for row in rows}
        if new_id is not None:
            graph[new_id] = list(dependencies)
        # visiting = current DFS path (a hit means a cycle); visited = fully explored, skip repeats.
        visiting, visited = set(), set()

        def visit(identifier):
            """Depth-first walk from identifier; raises ContractError on a cycle or unknown job."""
            _require(identifier in graph, f'Missing dependency: {identifier}', ContractError)
            _require(identifier not in visiting, 'Job dependency cycle', ContractError)
            if identifier in visited:
                return
            visiting.add(identifier)
            for dependency in graph[identifier]:
                visit(dependency)
            visiting.remove(identifier)
            visited.add(identifier)
        # Very deep chains would exhaust the recursion limit; report that as a contract problem.
        try:
            for identifier in graph:
                visit(identifier)
        except RecursionError as exc:
            raise ContractError('Job dependency graph is too deep') from exc

    def enqueue(self, spec, *, job_id=None, depends_on=(), max_attempts=3, idempotency_key=None):
        """Store a new job and return its ID, or return the existing ID for an identical request.

        The spec, dependencies and max_attempts form an immutable contract. Re-enqueueing
        with the same job_id or idempotency_key and the same contract is a no-op; any
        difference raises ContractError. Other invalid input raises QueueError.
        """
        # Validate everything before opening a transaction so bad input never takes the write lock.
        # The spec is opaque to the queue; it only has to be a JSON object that round-trips.
        _require(type(spec) is dict, 'Job spec must be a JSON object')
        # type() is int excludes bool, which would otherwise pass as 1 or 0.
        _require(type(max_attempts) is int and 1 <= max_attempts <= MAX_ATTEMPTS,
                 f'max_attempts must be between 1 and {MAX_ATTEMPTS}')
        # A bare string would be iterated per character; require a real collection of IDs.
        _require(not isinstance(depends_on, (str, bytes)), 'depends_on must contain job IDs')
        try:
            dependencies = list(depends_on)
        except TypeError as exc:
            raise QueueError('depends_on must contain job IDs') from exc
        for identifier in dependencies:
            # Each parent ID must be well formed here; existence is verified later inside the transaction.
            _name(identifier, 'dependency ID')
        # Sorted, de-duplicated dependencies make the contract (and its hash) independent of order.
        _require(len(dependencies) == len(set(dependencies)), 'Duplicate dependency', ContractError)
        dependencies.sort()
        # Remember whether the caller chose the ID: an auto-generated one must not conflict with
        # an existing job found through the idempotency key.
        supplied_id = job_id
        job_id = _name(('job-' + uuid.uuid4().hex) if job_id is None else job_id, 'job ID')
        # Self-dependency is rejected early; the CHECK constraint in SCHEMA is the backstop.
        _require(job_id not in dependencies, 'A job cannot depend on itself', ContractError)
        if idempotency_key is not None:
            _text(idempotency_key, 'idempotency key', 512)
        # The fingerprint covers the full contract; it is what makes a repeated request provably
        # the same request.
        encoded = _json({'version': 1, 'spec': spec, 'depends_on': dependencies, 'max_attempts': max_attempts})
        fingerprint = sha256(encoded.encode()).hexdigest()
        now = self._now()
        # Existence checks and insert happen in one IMMEDIATE transaction, so two racing enqueues
        # of the same key cannot both insert.
        with self._transaction() as connection:
            # Both lookups (by ID and by key) must agree on one job, otherwise the request is ambiguous
            # and is refused rather than guessed at.
            existing = connection.execute('SELECT * FROM jobs WHERE job_id=?', (job_id,)).fetchone()
            keyed = connection.execute('SELECT * FROM jobs WHERE idempotency_key=?', (idempotency_key,)).fetchone() if idempotency_key else None
            # Idempotency lookup: the key may already map to a job, which must be the one the caller meant.
            if keyed is not None:
                _require(supplied_id is None or keyed['job_id'] == supplied_id,
                         'Idempotency key belongs to another job ID', ContractError)
                _require(existing is None or existing['job_id'] == keyed['job_id'],
                         'Job ID and idempotency key disagree', ContractError)
                existing = keyed
            # Replay: verify the stored job is intact and byte-for-byte the same contract, then return it.
            if existing is not None:
                self._contract(connection, existing)
                _require(existing['contract_hash'] == fingerprint and existing['idempotency_key'] == idempotency_key,
                         'Existing job has a different immutable contract or idempotency key', ContractError)
                # Returning the existing ID makes enqueue safe to retry after a crash or timeout.
                return existing['job_id']
            # Cycle and missing-parent check inside the transaction, against current data.
            self._check_graph(connection, job_id, dependencies)
            # The contract text and hash are written once; the immutable_job_contract trigger forbids edits.
            connection.execute('''INSERT INTO jobs(job_id,contract_json,contract_hash,idempotency_key,max_attempts,
                status,created_at,updated_at) VALUES (?,?,?,?,?,'queued',?,?)''',
                               (job_id, encoded, fingerprint, idempotency_key, max_attempts, now, now))
            # Dependency rows are written after the job row to satisfy the foreign keys.
            connection.executemany('INSERT INTO dependencies(job_id,dependency_id) VALUES (?,?)',
                                   [(job_id, dependency) for dependency in dependencies])
            self._event(connection, job_id, 'enqueued', now, {'contract_hash': fingerprint})
            # A new child may already be blocked by a failed parent; settle statuses now.
            self._refresh_dependencies(connection, now)
        # Returned only after the transaction has committed.
        return job_id

    def get(self, job_id):
        """Return the public view of job_id (no token). Raises QueueError if unknown or corrupt."""
        with self._connect() as connection:
            # Explicit BEGIN gives the contract, attempt and job reads one consistent snapshot.
            connection.execute('BEGIN')
            return self._public(connection, self._row(connection, job_id))

    def list_jobs(self, status=None):
        """Return public views of jobs, oldest first, optionally filtered by status."""
        # Reject unknown filters instead of returning an empty list that hides a typo.
        _require(status is None or status in STATUSES, 'Unknown job status')
        with self._connect() as connection:
            connection.execute('BEGIN')
            # Only constant SQL text is concatenated here; the status value itself is bound as a parameter.
            query = 'SELECT * FROM jobs' + (' WHERE status=?' if status else '') + ' ORDER BY created_at, job_id'
            return [self._public(connection, row) for row in connection.execute(query, (status,) if status else ())]

    def _refresh_dependencies(self, connection, now):
        """Propagate prerequisite outcomes: block queued children of stopped parents, unblock recovered ones."""
        # Changes propagate both failure and explicit recovery. A blocked child
        # never consumes an attempt and can run only after all parents pass.
        while True:
            # Loop to a fixed point: blocking or unblocking one job can change its own children.
            changed = False
            # Only queued/blocked jobs can change here; running and finished jobs are never touched.
            # Re-read after each pass: status changes below may alter the candidates' parents.
            for row in connection.execute("SELECT * FROM jobs WHERE status IN ('queued','blocked') ORDER BY created_at,job_id").fetchall():
                # Parent statuses are read live rather than cached, since earlier iterations may have changed them.
                parents = connection.execute('''SELECT p.job_id,p.status FROM dependencies d JOIN jobs p
                    ON d.dependency_id=p.job_id WHERE d.job_id=? ORDER BY p.job_id''', (row['job_id'],)).fetchall()
                # Any parent in a BLOCKING status stops the child. needs_review blocks because the parent's
                # side effects may or may not have happened.
                # Snapshot of which parents block, recorded so a reviewer can see exactly why a job stopped.
                blockers = [{'job_id': p['job_id'], 'status': p['status']} for p in parents if p['status'] in BLOCKING]
                # Block without spending an attempt; the reason and the culprits are recorded as evidence.
                if blockers and row['status'] == 'queued':
                    # Blocked jobs get a synthetic failed result; nothing ran, so no attempt row is written.
                    result = {'passed': False, 'failures': ['A prerequisite requires review or did not pass'],
                              'evidence': {'dependencies': blockers}}
                    connection.execute("UPDATE jobs SET status='blocked',result_json=?,updated_at=? WHERE job_id=?",
                                       (_json(result), now, row['job_id']))
                    self._event(connection, row['job_id'], 'blocked', now, result['evidence'])
                    changed = True
                # Parents are fixed (e.g. via retry), so the child returns to the queue with its attempts intact.
                elif not blockers and row['status'] == 'blocked':
                    connection.execute("UPDATE jobs SET status='queued',result_json=NULL,updated_at=? WHERE job_id=?", (now, row['job_id']))
                    self._event(connection, row['job_id'], 'unblocked', now)
                    changed = True
            if not changed:
                return

    def _expire(self, connection, row, now):
        """Mark an overdue running job needs_review and clear its lease and token."""
        # The outcome is deliberately 'uncertain', not failed: the worker may have finished the
        # side effects before dying, so an automatic retry could repeat them. A human must decide.
        result = {'passed': False, 'failures': ['Worker lease expired; execution outcome is uncertain and requires review'],
                  'evidence': {'owner': row['owner'], 'attempt': row['attempt_count'], 'lease_until': row['lease_until']}}
        # The same result is stored on the attempt and on the job so both views explain the stop.
        encoded = _json(result)
        # The disposition='running' guard means a finished attempt row is never overwritten.
        connection.execute("""UPDATE attempts SET finished_at=?,disposition='needs_review',result_json=?
            WHERE job_id=? AND attempt=? AND disposition='running'""", (now, encoded, row['job_id'], row['attempt_count']))
        # Clearing token and owner invalidates the old holder: its next heartbeat/finish raises LeaseError.
        connection.execute("""UPDATE jobs SET status='needs_review',owner=NULL,token=NULL,lease_until=NULL,
            result_json=?,updated_at=? WHERE job_id=?""", (encoded, now, row['job_id']))
        # The old owner and expiry time are kept in the event as evidence for the reviewer.
        self._event(connection, row['job_id'], 'lease_expired', now, result['evidence'])

    def _recover(self, connection, now):
        """Expire every running job whose lease has ended and refresh dependents; return the expired IDs."""
        # lease_until <= now: a lease that ends exactly now counts as expired.
        rows = connection.execute("SELECT * FROM jobs WHERE status='running' AND lease_until<=? ORDER BY job_id", (now,)).fetchall()
        for row in rows:
            self._expire(connection, row, now)
        self._refresh_dependencies(connection, now)
        # Children of expired jobs are blocked in the same transaction, so no one sees a half-updated graph.
        return [row['job_id'] for row in rows]

    def recover_expired(self):
        """Expire all overdue leases in one transaction and return their job IDs."""
        with self._transaction() as connection:
            return self._recover(connection, self._now())

    def _lease_seconds(self, value):
        """Return lease_seconds as a float, requiring 0 < value <= 86400 (one day)."""
        # The cap bounds how long a dead worker can hold a job before it surfaces for review.
        _require(type(value) in (int, float) and math.isfinite(value) and 0 < value <= 86400,
                 'lease_seconds must be greater than zero and at most 86400')
        return float(value)

    def claim(self, owner, lease_seconds=300, *, job_id=None):
        """Claim the oldest runnable job for owner, or return None.

        Returns the public job dict plus a secret 'token' that is needed for heartbeat and
        finish. job_id restricts the claim to one specific job. Raises QueueError for
        invalid owner, job_id or lease_seconds.
        """
        # Owner is a free-form label for audit only; it grants no authority (the token does).
        _text(owner, 'worker owner')
        if job_id is not None:
            _text(job_id, 'job id')
        duration = self._lease_seconds(lease_seconds)
        # Selecting and updating inside one IMMEDIATE transaction is what makes a claim exclusive:
        # a second process waits for the lock and then no longer sees this job as queued.
        with self._transaction() as connection:
            now = self._now()
            # Expire stale leases first, so their state is settled before choosing what to run.
            self._recover(connection, now)
            # Eligible: queued, attempts left, matches the optional job_id, and no parent is anything
            # other than passed. Oldest first with job_id as tie-breaker gives deterministic FIFO order.
            row = connection.execute("""SELECT j.* FROM jobs j WHERE j.status='queued' AND j.attempt_count<j.max_attempts
                AND (? IS NULL OR j.job_id=?)
                AND NOT EXISTS (SELECT 1 FROM dependencies d JOIN jobs p ON d.dependency_id=p.job_id
                                WHERE d.job_id=j.job_id AND p.status!='passed')
                ORDER BY j.created_at,j.job_id LIMIT 1""", (job_id, job_id)).fetchone()
            # Nothing runnable right now (empty queue, unmet dependencies, or budget used up).
            if row is None:
                return None
            # Do not hand out a job whose stored contract fails verification.
            self._contract(connection, row)
            # 32 random bytes from the OS CSPRNG; the token is the sole proof of lease ownership.
            # It is stored, but never returned by get/list/events.
            # Number the attempt from the stored counter, so attempts rows and the budget stay in step.
            token, number, until = secrets.token_urlsafe(32), row['attempt_count'] + 1, now + duration
            # Attempt count is incremented at claim time, so a crash still counts against the budget.
            connection.execute("""UPDATE jobs SET status='running',attempt_count=?,owner=?,token=?,lease_until=?,
                updated_at=? WHERE job_id=?""", (number, owner, token, until, now, row['job_id']))
            connection.execute("""INSERT INTO attempts(job_id,attempt,owner,started_at,lease_until,disposition)
                VALUES (?,?,?,?,?,'running')""", (row['job_id'], number, owner, now, until))
            # Only the attempt number, owner and expiry are logged; the token stays out of the audit trail.
            self._event(connection, row['job_id'], 'claimed', now, {'attempt': number, 'owner': owner, 'lease_until': until})
            # Re-read the row after the updates so the returned view reflects what was committed.
            public = self._public(connection, self._row(connection, row['job_id']))
            # Token is attached only to this return value, never persisted in any public structure.
            public['token'] = token
            return public

    def _owned(self, connection, job_id, token):
        """Return the running row for job_id if token is its current lease token, else raise LeaseError."""
        row = self._row(connection, job_id)
        # compare_digest gives a constant-time comparison; isascii avoids TypeError from
        # compare_digest on non-ASCII text. Status must still be 'running': a finished, expired or
        # canceled job has its token cleared, so stale tokens fail here.
        # Contract verification here protects finish/heartbeat from acting on a tampered row.
        _require(type(token) is str and token.isascii() and row['status'] == 'running' and row['token'] is not None
                 and secrets.compare_digest(token, row['token']), 'Worker does not own the active job lease', LeaseError)
        self._contract(connection, row)
        return row

    def heartbeat(self, job_id, token, lease_seconds=300):
        """Extend the lease of a running job and return its public view.

        Raises LeaseError if the token is wrong or the lease had already expired.
        """
        duration = self._lease_seconds(lease_seconds)
        # The error is raised after the transaction closes: the expiry bookkeeping above must be
        # committed, not rolled back by the exception.
        expired = False
        with self._transaction() as connection:
            row = self._owned(connection, job_id, token)
            now = self._now()
            # A heartbeat cannot resurrect an expired lease: the job may already be treated as lost,
            # so it is sent to needs_review instead of being extended.
            # Expiry is checked against the server-side clock at the moment of the call, inside the
            # transaction, so a slow worker cannot race the recovery logic.
            if row['lease_until'] <= now:
                self._expire(connection, row, now)
                self._refresh_dependencies(connection, now)
                expired = True
            else:
                # Extend from now (not from the old end), so the lease length is always lease_seconds.
                until = now + duration
                connection.execute('UPDATE jobs SET lease_until=?,updated_at=? WHERE job_id=?', (until, now, job_id))
                # Keep the attempt history in step with the job row so audits show the final lease end.
                connection.execute('UPDATE attempts SET lease_until=? WHERE job_id=? AND attempt=?', (until, job_id, row['attempt_count']))
                self._event(connection, job_id, 'heartbeat', now, {'attempt': row['attempt_count'], 'lease_until': until})
                public = self._public(connection, self._row(connection, job_id))
        _require(not expired, 'Worker lease expired; review before retrying', LeaseError)
        return public

    @staticmethod
    def _result(result, disposition):
        """Validate a completion result against its disposition and return it as canonical JSON.

        Raises QueueError unless the result has passed, failures and evidence in the right combination.
        """
        # 'retry' re-queues the job; the other values are final states.
        _require(disposition in {'passed', 'retry', 'needs_review', 'failed'}, 'Unknown completion disposition')
        # The result's shape is checked by the queue, never trusted from generated text.
        _require(type(result) is dict and type(result.get('passed')) is bool
                 and type(result.get('failures')) is list and type(result.get('evidence')) is dict,
                 'Validation result requires passed (bool), failures (list), evidence (object)')
        # Passing is the only way to unblock children, so it demands success, no failures and
        # non-empty evidence that a validator actually ran.
        if disposition == 'passed':
            _require(result['passed'] is True and not result['failures'] and bool(result['evidence']),
                     'Passed jobs require successful validation, no failures and recorded evidence')
        # Every non-pass outcome must say why, so failures are never silent.
        else:
            _require(result['passed'] is False and bool(result['failures']),
                     'Unsuccessful jobs require failed validation and recorded failures')
        return _json(result)

    def finish(self, job_id, token, result, disposition='passed'):
        """Record the outcome of a running job and return its public view.

        disposition is one of passed, retry, needs_review or failed. Raises LeaseError
        if the token is wrong or the lease expired (the job then becomes needs_review).
        """
        # Validate the result before taking the write lock.
        # Disposition 'passed' is only reachable through a validated, evidence-carrying result.
        encoded = self._result(result, disposition)
        expired = False
        with self._transaction() as connection:
            row = self._owned(connection, job_id, token)
            now = self._now()
            # Late finish: even a correct token cannot report success after the lease ran out, because
            # another worker may already have been allowed to take over.
            if row['lease_until'] <= now:
                self._expire(connection, row, now)
                self._refresh_dependencies(connection, now)
                expired = True
            else:
                # 'retry' means back to the queue while attempts remain, otherwise the job fails for good.
                # For final dispositions the job status equals the disposition name.
                status = disposition
                if disposition == 'retry':
                    status = 'queued' if row['attempt_count'] < row['max_attempts'] else 'failed'
                # Close the attempt row and the job in the same transaction as the event.
                connection.execute('''UPDATE attempts SET finished_at=?,disposition=?,result_json=?
                    WHERE job_id=? AND attempt=?''', (now, disposition, encoded, job_id, row['attempt_count']))
                connection.execute('''UPDATE jobs SET status=?,result_json=?,updated_at=?,owner=NULL,token=NULL,lease_until=NULL
                    WHERE job_id=?''', (status, encoded, now, job_id))
                # The full result is recorded in the event; no token appears anywhere in it.
                self._event(connection, job_id, 'finished', now,
                            {'attempt': row['attempt_count'], 'disposition': disposition, 'status': status, 'result': result})
                # Make budget exhaustion visible as its own event for auditors.
                if disposition == 'retry' and status == 'failed':
                    self._event(connection, job_id, 'attempts_exhausted', now, {'max_attempts': row['max_attempts']})
                # Passing unblocks children and failing blocks them; propagate now.
                self._refresh_dependencies(connection, now)
                public = self._public(connection, self._row(connection, job_id))
        # Raised outside the transaction so the needs_review change above commits first.
        _require(not expired, 'Worker lease expired; completion was not accepted', LeaseError)
        return public

    def retry(self, job_id):
        """Explicitly re-queue a stopped job and return its public view.

        Raises QueueError if the job is not stopped, has no attempts left, or has a
        stopped prerequisite.
        """
        with self._transaction() as connection:
            row = self._row(connection, job_id)
            self._contract(connection, row)
            # Only a human/review decision may restart a job; running, queued or passed jobs cannot.
            _require(row['status'] in {'failed', 'needs_review', 'canceled', 'blocked'}, 'Only stopped jobs can be explicitly retried')
            # The attempt budget is global per job, so retry cannot be used to run forever.
            _require(row['attempt_count'] < row['max_attempts'], 'Total attempt budget is exhausted; create a new reviewed job')
            now = self._now()
            # Refuse while any parent is still stopped, otherwise the job would just be blocked again.
            blocked = connection.execute("""SELECT p.job_id FROM dependencies d JOIN jobs p ON d.dependency_id=p.job_id
                WHERE d.job_id=? AND p.status IN ('failed','needs_review','blocked','canceled')""", (job_id,)).fetchall()
            _require(not blocked, 'Retry or resolve the failed prerequisites first')
            # Existing attempts and events are kept; only the live status and lease fields are reset.
            # result_json is kept on purpose: the next worker can read why the previous attempt stopped
            # through previous_validation.
            connection.execute("UPDATE jobs SET status='queued',owner=NULL,token=NULL,lease_until=NULL,updated_at=? WHERE job_id=?", (now, job_id))
            # Recording the budget used makes repeated manual retries easy to audit.
            self._event(connection, job_id, 'retry_requested', now, {'attempts_used': row['attempt_count'], 'max_attempts': row['max_attempts']})
            self._refresh_dependencies(connection, now)
            return self._public(connection, self._row(connection, job_id))

    def cancel(self, job_id):
        """Cancel a job that has not passed and return its public view; repeating the call is harmless."""
        with self._transaction() as connection:
            row = self._row(connection, job_id)
            self._contract(connection, row)
            # A passed job has already produced accepted output and cannot be undone.
            _require(row['status'] != 'passed', 'Passed jobs cannot be canceled')
            # Idempotent: canceling twice returns the existing state.
            if row['status'] == 'canceled':
                return self._public(connection, row)
            now = self._now()
            # A synthetic failure result documents the cancellation for dependents and reviewers.
            result = {'passed': False, 'failures': ['Job canceled by an explicit request'],
                      'evidence': {'previous_status': row['status'], 'attempt': row['attempt_count']}}
            encoded = _json(result)
            # If a worker holds a lease, end its attempt record; clearing the token below makes the
            # worker's next heartbeat or finish fail with LeaseError.
            if row['status'] == 'running':
                connection.execute("""UPDATE attempts SET finished_at=?,disposition='canceled',result_json=?
                    WHERE job_id=? AND attempt=?""", (now, encoded, job_id, row['attempt_count']))
            connection.execute("""UPDATE jobs SET status='canceled',owner=NULL,token=NULL,lease_until=NULL,
                result_json=?,updated_at=? WHERE job_id=?""", (encoded, now, job_id))
            self._event(connection, job_id, 'canceled', now, result['evidence'])
            # Canceled is a blocking status, so dependents are blocked in the same transaction.
            self._refresh_dependencies(connection, now)
            return self._public(connection, self._row(connection, job_id))

    def attempts(self, job_id):
        """Return the attempt history of job_id in order; tokens are not included."""
        # Read-only: a plain connection, no write transaction.
        with self._connect() as connection:
            self._row(connection, job_id)
            return [{
                # The tokens column does not exist on attempts, so history can never expose a lease secret.
                'job_id': row['job_id'], 'attempt': row['attempt'], 'owner': row['owner'],
                'started_at': _timestamp(row['started_at']), 'finished_at': _timestamp(row['finished_at']) if row['finished_at'] is not None else None,
                'lease_until': row['lease_until'], 'disposition': row['disposition'],
                'result': json.loads(row['result_json']) if row['result_json'] else None,
            } for row in connection.execute('SELECT * FROM attempts WHERE job_id=? ORDER BY attempt', (job_id,))]

    def events(self, after=0):
        """Return audit events with an id greater than after, in order (use the last id as a cursor)."""
        # bool is excluded by the exact type check; negative cursors would be meaningless.
        _require(type(after) is int and after >= 0, 'Event cursor must be a nonnegative integer')
        with self._connect() as connection:
            # Events are append-only (see triggers), so a caller can poll with the last seen id safely.
            return [{'id': row['event_id'], 'event_id': row['event_id'], 'job_id': row['job_id'],
                     'time': _timestamp(row['time']), 'event': row['event'], 'details': json.loads(row['details_json'])}
                    for row in connection.execute('SELECT * FROM events WHERE event_id>? ORDER BY event_id', (after,))]
