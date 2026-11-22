#!/bin/sh
# run_all_tests.sh - run every component's run_tests.sh and print one summary table.
# Program: run_all_tests.sh | Purpose: one command for the whole repo's own test suites
#   ./run_all_tests.sh                       uses `python3`
#   PYTHON=/path/to/python3.13 ./run_all_tests.sh
#   ./run_all_tests.sh --no-checks           skip the queue-sync and leak checks (tests only)
# Needs: Python 3.9 or newer, standard library only, no network, no installs.
# For a fully isolated run, point HOME and TMPDIR at a scratch folder first (see docs/VERIFICATION.md).
# Exit: 0 only if every component passed and (unless --no-checks) both checks passed.
# The counts in the table are what unittest printed on this run; they are the repo's own tests, not an audit.
set -u
# Step 1: work from this script's own folder so component paths are right wherever it is called from.
here=$(cd "$(dirname "$0")" && pwd)
cd "$here" || exit 2
PYTHON=${PYTHON:-python3}
run_checks=1
[ "${1:-}" = "--no-checks" ] && run_checks=0
out=$(mktemp -d "${TMPDIR:-/tmp}/twu-run-all.XXXXXX") || exit 2
trap 'rm -rf "$out"' EXIT INT TERM
rows="$out/rows"; : > "$rows"
fail=0
echo "python: $("$PYTHON" -c 'import sys; print(sys.version.split()[0])' 2>&1)  ($PYTHON)"
# Step 2: run each component (any folder with a run_tests.sh), keep its raw output, and pull out the unittest summary.
for dir in */; do
  c=${dir%/}
  [ -f "$c/run_tests.sh" ] || continue
  start=$(date +%s)
  PYTHON="$PYTHON" sh "$c/run_tests.sh" > "$out/$c.log" 2>&1
  rc=$?
  secs=$(( $(date +%s) - start ))
  ran=$(sed -n 's/^Ran \([0-9]*\) tests\{0,1\} in .*/\1/p' "$out/$c.log" | tail -1)
  verdict=$(grep -E '^(OK|FAILED)' "$out/$c.log" | tail -1)
  [ -n "$ran" ] || ran="?"
  [ -n "$verdict" ] || verdict="no unittest summary"
  [ "$rc" -eq 0 ] && st=PASS || { st=FAIL; fail=1; cp "$out/$c.log" "$out/FAILED_$c.log"; }
  printf '%s|%s|%s|%ss|%s\n' "$c" "$st" "$ran" "$secs" "$verdict" >> "$rows"
done
# Step 3: the two repo-level checks (cheap, no network).
if [ "$run_checks" -eq 1 ]; then
  if sh tools/check_queue_sync.sh "$here" > "$out/queue.log" 2>&1; then st=PASS; else st=FAIL; fail=1; fi
  printf '%s|%s|-|-|%s\n' "queue-copies-sync" "$st" "$(tail -1 "$out/queue.log")" >> "$rows"
  # tools/leak_ignore.txt lists the fake fixture strings and detector regexes that the leak check must not trip on.
  if CHECK_PLACEHOLDERS_IGNORE_FILE="$here/tools/leak_ignore.txt" sh tools/check_placeholders.sh "$here" > "$out/leak.log" 2>&1; then st=PASS; else st=FAIL; fail=1; fi
  printf '%s|%s|-|-|%s\n' "placeholder-leak-check" "$st" "$(tail -1 "$out/leak.log")" >> "$rows"
fi
# Step 4: one summary table, then the head of any failing log so the cause is visible.
echo
printf '%-26s %-5s %5s %6s  %s\n' "component / check" "state" "ran" "time" "unittest summary"
printf '%-26s %-5s %5s %6s  %s\n' "--------------------------" "-----" "-----" "------" "----------------"
while IFS='|' read -r c st ran secs verdict; do
  printf '%-26s %-5s %5s %6s  %s\n' "$c" "$st" "$ran" "$secs" "$verdict"
done < "$rows"
total=$(awk -F'|' '$3 ~ /^[0-9]+$/ {n += $3} END {print n+0}' "$rows")
echo
echo "tests run across components: $total"
if [ "$fail" -ne 0 ]; then
  echo "RESULT: FAILED"
  for f in "$out"/FAILED_*.log "$out/queue.log" "$out/leak.log"; do
    [ -f "$f" ] || continue
    case "$f" in */FAILED_*) ;; */queue.log) grep -q FAILED "$f" || continue ;; */leak.log) grep -q FAILED "$f" || continue ;; esac
    echo "---- $(basename "$f") (last 25 lines) ----"; tail -25 "$f"
  done
  exit 1
fi
echo "RESULT: all passed"
