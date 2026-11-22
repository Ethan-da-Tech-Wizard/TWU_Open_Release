"""Portable twelve-step Malakopia workflow; no model or network needed."""
# Only standard-library modules are used so the example runs on a bare interpreter.
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

# This file lives in examples/, a sibling of scripts/, so parents[1] is the component folder.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
# Imported after the path tweak above; that tweak is what makes the sibling scripts/ folder importable.
from malakopia_engine import run_workflow


# Entry point: builds a fixed linear workflow, runs it and prints the JSON summary.
def main():
    """Parse --state-dir/--resume, run the example workflow and return an exit status (0 on success, 1 otherwise)."""
    # Reuse the module docstring as the --help text so the two never drift apart.
    parser = argparse.ArgumentParser(description=__doc__)
    # The state directory is chosen by the caller; the engine creates one new run folder beneath it.
    parser.add_argument('--state-dir', required=True)
    # Passing an existing run ID resumes that run instead of starting a new one; saved hashes gate any reuse.
    parser.add_argument('--resume')
    args = parser.parse_args()
    # Twelve stage names in order; each stage depends on the one before it, forming a strict chain.
    names = ('intake', 'scope', 'sources', 'capabilities', 'budget', 'route',
             'packet', 'work', 'review', 'artifact', 'memory', 'handoff')
    # One step per stage. The first step has no prerequisite (empty needs); every other step needs its
    # predecessor, so a failure blocks everything downstream instead of being skipped silently.
    steps = [{'id': name, 'action': 'observe', 'needs': [names[i - 1]] if i else [],
              'params': {'stage': name}} for i, name in enumerate(names)]

    # Handler contract: receives the run context and the step params, returns a JSON-serialisable dict.
    def observe(ctx, params):
        """Handler for the 'observe' action: return a checksummed record of the stage, the goal and earlier steps."""
        # Record which stage ran, the shared goal, and which earlier steps had completed at this point.
        value = {'stage': params['stage'], 'goal': ctx['inputs']['goal'],
                 'source_steps': list(ctx['outputs'])}
        # A hash of the canonical (sorted-key) JSON gives a tamper-evident fingerprint of this step's output.
        value['evidence_sha256'] = sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()
        return value

    # Run the workflow. Action names map to handlers explicitly; nothing is looked up dynamically.
    result = run_workflow({'name': 'portable-example', 'version': 1, 'steps': steps},
        {'goal': 'Demonstrate a checked twelve-step cascade with no network or model'},
        # 'observe' is declared replay-safe because it is pure, so a failed or interrupted attempt may be retried on resume.
        {'observe': observe}, args.state_dir, run_id=args.resume, replay_safe_actions={'observe'})
    # Print the full run summary so the evidence file locations are visible to the caller.
    print(json.dumps(result, indent=2))
    # A non-zero exit lets shell scripts and CI detect an incomplete cascade.
    return 0 if result['status'] == 'succeeded' else 1


# Raise SystemExit with main()'s return value so the exit status reaches the shell.
if __name__ == '__main__':
    raise SystemExit(main())
