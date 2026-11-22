#!/bin/sh
# run_tests.sh - run every test of this component with one Python interpreter.
# Program: run_tests.sh | Purpose: one command for the component's whole test suite | Last modified: 2026-11-21
#   ./run_tests.sh                 uses `python3`
#   PYTHON=/path/to/python3.13 ./run_tests.sh
# Extra arguments are passed to unittest (for example `-v` or a test module name).
# Needs: Python 3.9 or newer, standard library only, no network, no installs.  Writes only to temporary folders
# (the tests create their own); set HOME/TMPDIR to a scratch folder if you want the run fully isolated.
set -eu
# Step 1: work from this script's own folder so the relative path `scripts` is right wherever it is called from.
here=$(cd "$(dirname "$0")" && pwd)
cd "$here"
# Step 2: pick the interpreter (default python3) and run unittest discovery over scripts/ (tests sit next to the code).
PYTHON=${PYTHON:-python3}
exec "$PYTHON" -B -m unittest discover -s scripts -p 'test_*.py' "$@"
