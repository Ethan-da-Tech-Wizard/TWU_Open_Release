#!/usr/bin/env bash
# check_placeholders.sh - fail if unfilled template placeholders, likely secrets or private paths remain.
#
# Usage:  check_placeholders.sh [PATH]
#   PATH               directory to scan (default: current directory).  Nothing outside PATH is read.
# Environment:
#   CHECK_PLACEHOLDERS_IGNORE_FILE  optional file of FIXED strings, one per line (the allowlisted fake fixture
#                      strings).  A scan hit whose line contains one of them is ignored.  Whole-line granularity:
#                      keep fixture strings specific.
# Exit: 0 clean, 1 findings, 2 usage error.  Output is file:line plus the matching line (as the original script did);
# run it on an already-scrubbed tree, never on a tree that still holds private values.
set -u

ROOT="."
for arg in "$@"; do
  case "$arg" in
    -*) echo "usage: $0 [PATH]" >&2; exit 2 ;;
    *) ROOT="$arg" ;;
  esac
done
[ -d "$ROOT" ] || { echo "check_placeholders: not a directory: $ROOT" >&2; exit 2; }
cd "$ROOT" || exit 2          # every grep below is relative to PATH, so the script can be run from anywhere

fail=0
# Never descend into VCS metadata, vendored deps, the template sources, or this script / the CI file themselves.
EXCL=(--exclude-dir=.git --exclude-dir=node_modules --exclude-dir=templates --exclude=check_placeholders.sh --exclude=ci.yml)

# filter_ignored: drop lines containing any fixed string from the ignore file (if one was given).
filter_ignored() {
  if [ -n "${CHECK_PLACEHOLDERS_IGNORE_FILE:-}" ] && [ -s "$CHECK_PLACEHOLDERS_IGNORE_FILE" ]; then
    grep -v -F -f "$CHECK_PLACEHOLDERS_IGNORE_FILE"
  else
    cat
  fi
}

# scan LABEL REGEX: grep -E over the tree; report up to 20 hits per rule.
scan() {
  local out
  out=$(grep -RInE "${EXCL[@]}" -e "$2" . 2>/dev/null | filter_ignored | head -20)
  if [ -n "$out" ]; then echo "FAIL: $1"; echo "$out"; fail=1; fi
}

scan "unfilled placeholder tokens" '[{][{][A-Za-z_][^}]*[}][}]'
scan "private home paths" '/Users/[a-z]+/|/home/[a-z]+/|TWU_LL[C]'
scan "private key blocks" 'BEGIN [A-Z ]*PRIVATE KEY'
scan "token-like strings" '(ghp_|gho_|github_pat_|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-)'
scan "overclaim words" '(100% verified|production-grade|battle-tested)'
[ $fail -eq 0 ] && echo "leak check: clean" || echo "leak check: FAILED"
exit $fail
