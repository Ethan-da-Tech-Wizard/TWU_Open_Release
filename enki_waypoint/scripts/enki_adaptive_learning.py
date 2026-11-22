"""Private, interpretable BKT mastery tracking and LinUCB practice selection.

This module changes task selection only. It does not train model weights, retain
prompt/answer text, or accept unverified outcomes. Persisted learner state is
restricted to PRIVATE_STATE_ROOT (default ./state under the component folder, or env ENKI_ADAPTIVE_STATE_ROOT).

The caller must first approve candidate tasks through the existing command,
privacy, compute and thermal gates. The `safe` flag here excludes candidates
that those gates rejected; it is not a substitute for those gates.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import math
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Iterable

# Component root, used only to build the default state location below.
ROOT = Path(__file__).resolve().parents[1]
# Where the learner's state file may live: env ENKI_ADAPTIVE_STATE_ROOT (an absolute path; the folder must be mode 0700
# and free of symlinks), else <component>/state. An empty variable counts as unset. Tests patch this attribute directly.
# Read once at import. Tests replace the attribute directly; everything below
# consults the module-level name at call time so that patching works.
PRIVATE_STATE_ROOT = Path(os.environ.get("ENKI_ADAPTIVE_STATE_ROOT") or ROOT / "state")
# Version tag written into and required from the state file; a file from any other
# producer or version is refused rather than interpreted.
STATE_SCHEMA = "twu.private-adaptive-learning.v1"
# Identifier whitelist (letters, digits, . _ : -, at most 100 characters, starting
# alphanumeric). Skill and task ids are the only text stored, so free-form content
# cannot end up in the learner state and keys cannot look like paths.
KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}$")


@dataclass(frozen=True)
class BKTParameters:
    """The four numbers of a Bayesian knowledge tracing model: prior, learn, slip and guess."""
    # Standard four-parameter BKT. prior is P(already known) before any evidence; learn
    # is P(transition unknown -> known) after each opportunity; guess is P(correct while
    # unknown); slip is P(wrong while known).
    prior: float = 0.2
    learn: float = 0.12
    guess: float = 0.2
    slip: float = 0.1

    def validate(self) -> None:
        """Raise ValueError unless every BKT parameter is a finite real number in [0, 1)."""
        # Strictly below 1 so the Bayes denominators in bkt_update cannot collapse to zero
        # in the usual parameter ranges. NaN, infinity and booleans are refused.
        if any(isinstance(x, bool) or not isinstance(x, (int, float)) or not math.isfinite(x) or not 0 <= x < 1
               for x in asdict(self).values()):
            raise ValueError("BKT parameters must be finite probabilities in [0, 1)")


def bkt_probability_correct(mastery: float, guess: float, slip: float) -> float:
    """Return P(correct) = mastery*(1-slip) + (1-mastery)*guess; raises ValueError if any input is not a probability."""
    # Validate all three inputs so a corrupted state value cannot leak a number outside
    # [0, 1] into the posterior.
    _probability(mastery, "mastery")
    _probability(guess, "guess")
    _probability(slip, "slip")
    # Law of total probability over the hidden state: known and no slip, plus unknown
    # and a lucky guess.
    return mastery * (1.0 - slip) + (1.0 - mastery) * guess


# Order matters: evidence update first, then the learning transition. Applying the
# transition first would credit learning before the answer was observed.
def bkt_update(mastery: float, correct: bool, params: BKTParameters) -> float:
    """Bayesian posterior after an answer, followed by learning transition T."""
    # Only a real boolean verdict is accepted; an int or None is not evidence.
    if not isinstance(correct, bool):
        raise ValueError("correct must be a verified boolean outcome")
    params.validate()
    # Step 1 of BKT: Bayes rule. The posterior P(known | observation) is the likelihood
    # of the observation under 'known' divided by its total probability.
    p_correct = bkt_probability_correct(mastery, params.guess, params.slip)
    # Correct answer: P(known|correct) = P(known)(1-slip) / P(correct).
    # Wrong answer: P(known|wrong) = P(known)*slip / P(wrong).
    # The conditional on the denominator avoids dividing by zero and leaves mastery
    # unchanged in that degenerate case.
    if correct:
        denominator = p_correct
        posterior = mastery * (1.0 - params.slip) / denominator if denominator else mastery
    else:
        denominator = 1.0 - p_correct
        posterior = mastery * params.slip / denominator if denominator else mastery
    # Step 2: learning transition. Whatever the posterior, an unknown skill may become
    # known with probability learn: new = p + (1-p)*learn. min() only absorbs rounding.
    return min(1.0, posterior + (1.0 - posterior) * params.learn)


def _probability(value: float, label: str) -> None:
    """Raise ValueError unless value is a finite int or float in [0, 1]; bools are rejected. label names the field in the message."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 <= value <= 1:
        raise ValueError(f"{label} must be a finite probability in [0, 1]")


@dataclass(frozen=True)
class PracticeTask:
    """One candidate practice task: its skill, need, expected gain and costs."""
    task_id: str
    skill: str
    need: float
    expected_gain: float
    time_cost: float = 0.0
    compute_cost: float = 0.0
    risk: float = 0.0
    safe: bool = True

    # Dataclass hook: runs on every construction, so an invalid task can never exist.
    def __post_init__(self) -> None:
        """Validate identifiers, the safe flag and all numeric fields at construction; raises ValueError on any violation."""
        # Ids first: they become dictionary keys in persisted state.
        for name, value in (("task_id", self.task_id), ("skill", self.skill)):
            if not isinstance(value, str) or not KEY_ID.fullmatch(value):
                raise ValueError(f"{name} must be a non-content identifier (letters, numbers, . _ : -)")
        # Strict bool: safe is the hand-off from the caller's command, privacy, compute and
        # thermal gates, so a truthy non-bool value must not count as approval.
        if type(self.safe) is not bool:
            raise ValueError("safe must be a boolean from the caller's existing safety gates")
        # Every numeric field is a normalised score in [0, 1], which keeps the penalty terms
        # in LinUCB.select on one comparable scale.
        for name, value in (("need", self.need), ("expected_gain", self.expected_gain),
                            ("time_cost", self.time_cost), ("compute_cost", self.compute_cost),
                            ("risk", self.risk)):
            _probability(value, name)

    def features(self, mastery: float) -> tuple[float, ...]:
        """Return the 5-dimensional LinUCB context (bias, need, 1-mastery, uncertainty, expected_gain) for the given mastery."""
        _probability(mastery, "mastery")
        # Bernoulli standard deviation sqrt(m(1-m)): peaks at m = 0.5, vanishes at certainty.
        uncertainty = math.sqrt(max(0.0, mastery * (1.0 - mastery)))
        # Context x = [bias, need, 1-mastery (room to learn), uncertainty, expected_gain].
        # Order is part of the persisted format; changing it invalidates stored arms.
        return (1.0, self.need, 1.0 - mastery, uncertainty, self.expected_gain)


# Shared by score and observe, so the same shape and finiteness rules apply to both
# reads and writes of arm statistics.
def _feature_vector(features: Iterable[float], dimension: int) -> list[float]:
    """Return features as a list of floats; raise ValueError if the length differs from dimension or any value is non-finite or a bool."""
    # Materialize once, then check length and element types; a wrong-sized vector would
    # otherwise broadcast silently through zip().
    values = list(features)
    if (len(values) != dimension or any(isinstance(value, bool) or not isinstance(value, (int, float))
                                        or not math.isfinite(value) for value in values)):
        raise ValueError("feature vector has invalid dimension or values")
    return [float(value) for value in values]


def _solve(matrix: list[list[float]], vector: list[float]) -> list[float]:
    """Solve a small positive-definite system with pivoted Gauss-Jordan elimination."""
    # Gauss-Jordan on the augmented matrix [A | b]. Partial pivoting (largest absolute
    # entry in the column) keeps the elimination numerically stable.
    n = len(vector)
    augmented = [list(map(float, matrix[i])) + [float(vector[i])] for i in range(n)]
    for col in range(n):
        # Choose the row with the largest magnitude entry at or below the diagonal.
        pivot = max(range(col, n), key=lambda row: abs(augmented[row][col]))
        # A near-zero pivot means A is singular. A valid LinUCB matrix is positive definite
        # (identity plus outer products), so this only happens for corrupted state.
        if abs(augmented[pivot][col]) < 1e-12:
            raise ValueError("singular LinUCB matrix")
        augmented[col], augmented[pivot] = augmented[pivot], augmented[col]
        # Normalise the pivot row so the pivot entry becomes 1.
        scale = augmented[col][col]
        augmented[col] = [x / scale for x in augmented[col]]
        for row in range(n):
            # Eliminate this column from every other row; afterwards the left block is the
            # identity and the last column holds the solution.
            if row == col:
                continue
            scale = augmented[row][col]
            augmented[row] = [a - scale * b for a, b in zip(augmented[row], augmented[col])]
    return [augmented[i][-1] for i in range(n)]


class LinUCB:
    """Per-task contextual bandit: score = x'θ + α√(x'A⁻¹x)."""

    # Disjoint LinUCB (Li et al. 2010) with one arm per task id: each arm keeps A (d x d,
    # starts as identity = ridge regularisation) and b (d, starts at zero).
    def __init__(self, dimension: int = 5, alpha: float = 0.5,
                 cost_penalty: float = 0.25, risk_penalty: float = 0.5):
        """Create an empty bandit; raises ValueError for a bad dimension or a negative or non-finite alpha, cost_penalty or risk_penalty."""
        # alpha scales exploration; the penalties scale cost and risk deductions. All must be
        # finite and non-negative, since a negative alpha would reward being uncertain less
        # than being known and a negative penalty would reward cost.
        if type(dimension) is not int or dimension < 1 or any(
                isinstance(value, bool) or not isinstance(value, (int, float))
                or not math.isfinite(value) or value < 0
                for value in (alpha, cost_penalty, risk_penalty)):
            raise ValueError("invalid LinUCB configuration")
        self.dimension = dimension
        self.alpha = alpha
        self.cost_penalty = cost_penalty
        self.risk_penalty = risk_penalty
        # Arm state maps task id to {a, b}. It is plain lists so it serialises to JSON.
        self.arms: dict[str, dict[str, list]] = {}

    def _arm(self, task_id: str) -> dict[str, list]:
        """Return the statistics for task_id (creating an identity-initialised arm on first use); raises ValueError on a bad id or stored dimension mismatch."""
        if not isinstance(task_id, str) or not KEY_ID.fullmatch(task_id):
            raise ValueError("task_id must be a non-content identifier (letters, numbers, . _ : -)")
        # Lazily create an arm: A = I so the first solve is well defined, b = 0 so the first
        # estimated weights are zero and only the uncertainty term drives exploration.
        if task_id not in self.arms:
            self.arms[task_id] = {
                "a": [[float(i == j) for j in range(self.dimension)] for i in range(self.dimension)],
                "b": [0.0] * self.dimension,
            }
        # Re-check stored shapes on every access: arms may have been loaded from disk.
        arm = self.arms[task_id]
        if len(arm["a"]) != self.dimension or len(arm["b"]) != self.dimension:
            raise ValueError("stored LinUCB dimensions do not match")
        return arm

    def score(self, task_id: str, features: Iterable[float]) -> float:
        """Return the upper-confidence score for task_id under the given feature vector."""
        x = _feature_vector(features, self.dimension)
        arm = self._arm(task_id)
        # LinUCB score = x . theta + alpha * sqrt(x' A^-1 x) with theta = A^-1 b.
        # Rather than invert A, solve two linear systems: A theta = b for the mean
        # estimate, and A z = x so that x' A^-1 x = x . z for the variance term.
        theta = _solve(arm["a"], arm["b"])
        mean = sum(a * b for a, b in zip(theta, x))
        solved = _solve(arm["a"], x)
        # Clamp tiny negative values from floating-point error before the square root.
        variance = max(0.0, sum(a * b for a, b in zip(x, solved)))
        return mean + self.alpha * math.sqrt(variance)

    # Selection is read-only: scoring creates a missing arm in memory, but nothing is
    # persisted until save_private is called.
    def select(self, candidates: Iterable[PracticeTask], mastery: dict[str, float]) -> PracticeTask:
        """Return the safe candidate with the best penalised score; ties break on task_id; raises ValueError if none is eligible."""
        # Only tasks the caller marked safe and whose skill has a known state compete; the
        # penalised score is the UCB score minus cost_penalty*(time+compute) minus
        # risk_penalty*risk, so cheap, low-risk practice is preferred among equals.
        safe = []
        for task in candidates:
            if task.safe and task.skill in mastery:
                adjusted = (self.score(task.task_id, task.features(mastery[task.skill]))
                            - self.cost_penalty * (task.time_cost + task.compute_cost)
                            - self.risk_penalty * task.risk)
                safe.append((adjusted, task))
        if not safe:
            raise ValueError("no safe practice task has a known skill state")
        # Highest score first; task_id as secondary key makes the choice deterministic
        # when scores tie, which keeps runs reproducible and testable.
        return sorted(safe, key=lambda row: (-row[0], row[1].task_id))[0][1]

    def observe(self, task_id: str, features: Iterable[float], reward: float, *, verified: bool) -> None:
        """Add one verified (features, reward) sample to the arm for task_id; raises ValueError if unverified or invalid."""
        # Learning only from outcomes the caller has verified; an unconfirmed reward would
        # teach the policy something that may be false.
        if verified is not True:
            raise ValueError("LinUCB updates require a verified task outcome")
        _probability(reward, "reward")
        x = _feature_vector(features, self.dimension)
        arm = self._arm(task_id)
        # Rank-one update: b += r*x and A += x x'. Updates are additive, so A stays
        # symmetric positive definite, a property the loader re-checks.
        for i in range(self.dimension):
            arm["b"][i] += reward * x[i]
            for j in range(self.dimension):
                arm["a"][i][j] += x[i] * x[j]


class AdaptiveLearner:
    """BKT state and LinUCB policy using metadata only, never exercise content."""

    def __init__(self, parameters: BKTParameters | None = None, *, alpha: float = 0.5):
        """Create a learner with validated BKT parameters, no mastery estimates and a fresh LinUCB bandit."""
        # Parameters are validated here so a learner can never hold unusable BKT settings.
        self.parameters = parameters or BKTParameters()
        self.parameters.validate()
        self.mastery: dict[str, float] = {}
        self.bandit = LinUCB(alpha=alpha)

    def mastery_for(self, skill: str) -> float:
        """Return the stored mastery of skill, or the BKT prior if the skill has not been seen; raises ValueError on a bad skill id."""
        if not isinstance(skill, str) or not KEY_ID.fullmatch(skill):
            raise ValueError("skill must be a non-content identifier (letters, numbers, . _ : -)")
        # Unseen skills start at the BKT prior rather than failing or defaulting to zero.
        return self.mastery.get(skill, self.parameters.prior)

    def choose(self, tasks: Iterable[PracticeTask]) -> PracticeTask:
        """Pick the best practice task from tasks using current mastery and the bandit."""
        # Materialise so the iterable can be read twice: once for the mastery map, once by
        # the bandit.
        tasks = list(tasks)
        return self.bandit.select(tasks, {task.skill: self.mastery_for(task.skill) for task in tasks})

    def observe(self, task: PracticeTask, correct: bool, reward: float, *, verified: bool) -> float:
        """Apply one verified outcome to BKT and the bandit and return the new mastery; raises ValueError if unverified."""
        # Both models are updated together or not at all; the check happens before either.
        if not verified or not isinstance(correct, bool):
            raise ValueError("a verified boolean outcome is required")
        before = self.mastery_for(task.skill)
        # Use the pre-update mastery for the bandit context: the reward is credited to the
        # state the policy actually saw when it made the choice.
        features = task.features(before)
        after = bkt_update(before, correct, self.parameters)
        # The same verified observation updates BKT (above) and the bandit; mastery is stored
        # last so a rejected bandit update leaves state unchanged.
        self.bandit.observe(task.task_id, features, reward, verified=True)
        self.mastery[task.skill] = after
        return after

    def to_dict(self) -> dict:
        """Return the serialisable learner state (parameters, mastery, bandit) with a schema tag; no content text is included."""
        # Mastery keys are sorted for stable output; the schema tag is what load_private
        # checks first on the way back in.
        return {"schema": STATE_SCHEMA, "parameters": asdict(self.parameters), "mastery": dict(sorted(self.mastery.items())),
                "bandit": {"dimension": self.bandit.dimension, "alpha": self.bandit.alpha,
                           "cost_penalty": self.bandit.cost_penalty, "risk_penalty": self.bandit.risk_penalty,
                           "arms": self.bandit.arms}}

    def save_private(self, path: Path | None = None) -> Path:
        """Atomically write learner state under the private state root with owner-only permissions and return the target path; raises ValueError for unsafe paths."""
        # Default target is learner.json inside the private root. Validation runs before
        # anything is created so an unsafe path produces no filesystem side effects.
        target = Path(path) if path is not None else PRIVATE_STATE_ROOT / "learner.json"
        _assert_private_path(target)
        # Directory creation uses mode 0700, but the mode argument does not affect existing
        # directories, which the explicit chmod walk below handles.
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Existing directories may predate this store; make each private-state
        # directory owner-only before placing learner state inside it.
        # Walk from the root down to the target's parent, creating and tightening each
        # directory, and refusing any that is a symlink or not a directory.
        cursor = PRIVATE_STATE_ROOT
        cursor.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(cursor, 0o700)
        for part in target.parent.relative_to(PRIVATE_STATE_ROOT).parts:
            cursor = cursor / part
            cursor.mkdir(exist_ok=True, mode=0o700)
            if cursor.is_symlink() or not cursor.is_dir():
                raise ValueError("private learner state directories must be real directories")
            os.chmod(cursor, 0o700)
        # Write to a temporary file in the same directory (so the rename stays on one
        # filesystem), then swap it in. Readers see the old or the new file, never a mix.
        fd, temp = tempfile.mkstemp(prefix=".learner-", dir=target.parent)
        try:
            # Owner-only permissions are applied to the descriptor before any data is written.
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                # allow_nan=False makes serialisation fail on NaN or infinity instead of writing a
                # file the loader would later reject.
                json.dump(self.to_dict(), stream, sort_keys=True, allow_nan=False)
                stream.write("\n")
                stream.flush()
                # Flush file contents to disk before the rename so a crash cannot expose a renamed
                # but empty file.
                os.fsync(stream.fileno())
            # Atomic replace on POSIX; the final directory fsync below makes the rename durable.
            os.replace(temp, target)
            # fsync the directory so the rename itself survives power loss, not just the data.
            dir_fd = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        # Clean up the temporary file on any failure, including interrupts, then re-raise so
        # the caller still sees the original error.
        except BaseException:
            try:
                os.unlink(temp)
            except FileNotFoundError:
                pass
            raise
        return target

    @classmethod
    def load_private(cls, path: Path | None = None) -> "AdaptiveLearner":
        """Load and fully validate learner state from the private store; returns a fresh learner if the file is absent; raises ValueError for any unsafe or malformed state."""
        target = Path(path) if path is not None else PRIVATE_STATE_ROOT / "learner.json"
        # Load-time check is stricter than save-time: existing directories must already be
        # mode 0700, so a state folder that someone else can read or alter is refused.
        _assert_private_path(target, check_permissions=True)
        if not target.exists():
            return cls()
        # Open with O_NOFOLLOW and then inspect the descriptor itself (fstat), so the checks
        # apply to the file actually opened and cannot be raced by swapping in a symlink.
        fd = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(fd)
            # Reject non-regular files, hard-linked files (another name could be modified from
            # elsewhere) and anything over 4 MiB, bounding memory use on hostile input.
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 4 * 1024 * 1024:
                raise ValueError("private learner state must be a bounded, single-link regular file")
            # Collect the file contents in a bounded buffer.
            raw = bytearray()
            # Bounded read: stop one byte past the limit so an oversized file is detected even if
            # its size changed after fstat.
            while len(raw) <= 4 * 1024 * 1024:
                chunk = os.read(fd, min(65536, 4 * 1024 * 1024 + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
            if len(raw) > 4 * 1024 * 1024:
                raise ValueError("private learner state exceeded its read limit")
        finally:
            os.close(fd)
        try:
            # Parse and validate structure step by step; any decoding or shape problem is turned
            # into one generic ValueError at the except below, without echoing file content.
            payload = json.loads(raw.decode("utf-8"))
            if not isinstance(payload, dict) or payload.get("schema") != STATE_SCHEMA:
                raise ValueError("unsupported private learner state schema")
            if not isinstance(payload.get("parameters"), dict) or not isinstance(payload.get("mastery"), dict):
                raise ValueError("malformed private learner state")
            bandit_state = payload.get("bandit")
            if not isinstance(bandit_state, dict) or not isinstance(bandit_state.get("arms"), dict):
                raise ValueError("malformed private LinUCB state")
            # Constructing the learner re-runs parameter validation, so out-of-range BKT values
            # in the file are refused here.
            params = BKTParameters(**payload["parameters"])
            dimension = bandit_state.get("dimension")
            if type(dimension) is not int or dimension < 1:
                raise ValueError("invalid private LinUCB dimension")
            # alpha comes from the file; LinUCB.__init__ rejects non-numeric or negative values.
            learner = cls(params, alpha=bandit_state.get("alpha"))
            if learner.bandit.dimension != dimension:
                raise ValueError("stored LinUCB dimensions do not match")
            # Penalty values bypass the constructor, so they are checked explicitly: finite, real
            # and non-negative.
            penalties = (bandit_state["cost_penalty"], bandit_state["risk_penalty"])
            if any(isinstance(value, bool) or not isinstance(value, (int, float))
                   or not math.isfinite(value) or value < 0 for value in penalties):
                raise ValueError("invalid private LinUCB cost or risk penalty")
            learner.bandit.cost_penalty, learner.bandit.risk_penalty = penalties
        except (UnicodeError, json.JSONDecodeError, KeyError, TypeError, AttributeError, OverflowError) as exc:
            raise ValueError("malformed private learner state") from exc
        # Second guard on the final values, after they were copied onto the bandit.
        if (not math.isfinite(learner.bandit.cost_penalty) or learner.bandit.cost_penalty < 0
                or not math.isfinite(learner.bandit.risk_penalty) or learner.bandit.risk_penalty < 0):
            raise ValueError("invalid private LinUCB cost or risk penalty")
        # Every stored key and value is validated: skill ids must match the identifier
        # pattern and mastery must be a probability.
        learner.mastery = payload["mastery"]
        for key, value in learner.mastery.items():
            if not KEY_ID.fullmatch(key):
                raise ValueError("stored skill key is not a non-content identifier")
            _probability(value, "stored mastery")
        # Each arm is checked for shape, element types and finiteness, then cast to floats.
        # Symmetry and positive definiteness below guarantee that _solve works later.
        learner.bandit.arms = bandit_state["arms"]
        for task_id, arm in learner.bandit.arms.items():
            if not isinstance(task_id, str) or not KEY_ID.fullmatch(task_id):
                raise ValueError("stored task key is not a non-content identifier")
            if (not isinstance(arm, dict) or not isinstance(arm.get("a"), list) or not isinstance(arm.get("b"), list)
                    or len(arm["a"]) != learner.bandit.dimension or len(arm["b"]) != learner.bandit.dimension):
                raise ValueError("malformed private LinUCB state")
            if any(not isinstance(row, list) or len(row) != learner.bandit.dimension for row in arm["a"]):
                raise ValueError("malformed private LinUCB matrix")
            # Flatten once so a single pass can check every number for type and finiteness.
            matrix_values = [x for row in arm["a"] for x in row]
            vector_values = list(arm["b"])
            if any(isinstance(x, bool) or not isinstance(x, (int, float)) or not math.isfinite(x)
                   for x in matrix_values + vector_values):
                raise ValueError("non-finite private LinUCB state")
            arm["a"] = [[float(x) for x in row] for row in arm["a"]]
            arm["b"] = [float(x) for x in arm["b"]]
            # A is a sum of outer products plus identity, hence symmetric; asymmetry beyond
            # rounding noise means the file was edited.
            if any(abs(float(arm["a"][i][j]) - float(arm["a"][j][i])) > 1e-9
                   for i in range(learner.bandit.dimension) for j in range(learner.bandit.dimension)):
                raise ValueError("private LinUCB matrix is not symmetric")
            # Cholesky factorisation as a positive-definiteness test: it succeeds only if every
            # pivot (the diagonal value before the square root) is positive.
            lower = [[0.0] * learner.bandit.dimension for _ in range(learner.bandit.dimension)]
            for i in range(learner.bandit.dimension):
                for j in range(i + 1):
                    value = float(arm["a"][i][j]) - sum(lower[i][k] * lower[j][k] for k in range(j))
                    if i == j:
                        if value <= 1e-12:
                            raise ValueError("private LinUCB matrix is not positive definite")
                        lower[i][j] = math.sqrt(value)
                    else:
                        lower[i][j] = value / lower[j][j]
        return learner


def _assert_private_path(path: Path, *, check_permissions: bool = False) -> None:
    """Raise ValueError unless path lies inside the private state root, uses no symlinks, and (optionally) its directories are owner-only."""
    # Containment check works on absolute paths without resolve(), because resolve()
    # would follow symlinks and hide them from the checks below.
    root = PRIVATE_STATE_ROOT.absolute()
    target = path.absolute()
    try:
        relative = target.relative_to(root)
    except ValueError as exc:
        raise ValueError("learner state may only be stored under the configured adaptive state root") from exc
    # The path must name something below the root and contain no empty, current or parent
    # components that could escape it.
    if not relative.parts or any(part in ("", ".", "..") for part in relative.parts):
        raise ValueError("learner state path is invalid")
    # Build every component from the filesystem root down to the target so a symlink
    # anywhere along the route, including above the state root, is detected.
    chain = list(reversed(root.parents)) + [root]
    cursor = root
    # Add each intermediate directory below the root; the last part is the file itself
    # and is appended after the loop.
    for part in relative.parts[:-1]:
        cursor = cursor / part
        chain.append(cursor)
    chain.append(target)
    # is_symlink is true even for a dangling link, so broken links cannot slip through
    # the existence checks used elsewhere.
    for candidate in chain:
        if candidate.is_symlink():
            raise ValueError("private learner state path may not use symlinks")
    # Only directories under the state root are required to be owner-only; ancestors
    # such as the home folder are outside this store's control.
    if check_permissions:
        for directory in chain:
            # Skip the target itself and anything missing; groups and others must hold no
            # permission bits on the directories that guard the state file.
            if directory == target or not directory.exists() or not directory.is_dir():
                continue
            if directory.is_relative_to(root) and directory.stat().st_mode & 0o077:
                raise ValueError("private learner state directories must have mode 0700")
    # Destination must be a plain single-link regular file or not exist yet.
    if target.is_symlink() or (target.exists() and (not target.is_file() or target.stat().st_nlink != 1)):
        raise ValueError("private learner state destination must be a regular file")
