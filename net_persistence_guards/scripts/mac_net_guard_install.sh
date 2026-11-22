#!/bin/bash
# Installs the network guard as a user LaunchAgent (no sudo, no network).
#   bash scripts/mac_net_guard_install.sh [--check | --uninstall | --dry-run] [--yes] [--python PATH]
#
# What it does, in order: picks a Python, checks that a reviewed baseline exists, renders the plist template from
# templates/ into ~/Library/LaunchAgents, and then (only after you confirm) loads it with launchctl.
#   --check      show the state of the script, plist and launchd job, then run the guard once
#   --uninstall  unload the job and delete the plist (baselines, receipts and logs are kept)
#   --dry-run    write the plist but do not load it and do not ask anything
#   --yes        do not ask for confirmation (needed when stdin is not a terminal)
#   --python P   use this interpreter instead of /usr/bin/python3 (you take responsibility for who can write to it)
set -u
LABEL="local.net-persistence-guards.net-guard"
# Step 1: locate this component from the script's own path so the installer works from any current directory.
SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SELF_DIR/.." && pwd)"
SCRIPT="$ROOT/scripts/net_guard.py"
TEMPLATE="$ROOT/templates/$LABEL.plist"
AGENT_DIR="$HOME/Library/LaunchAgents"
PLIST="$AGENT_DIR/$LABEL.plist"
MODE=install; DRY=0; YES=0; PY=""; PY_ARG=""
say() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
# Step 2: parse options. Unknown options stop the run so a typo cannot silently install something.
while [ $# -gt 0 ]; do
  case "$1" in
    --check) MODE=check ;;
    --uninstall) MODE=uninstall ;;
    --dry-run) DRY=1 ;;
    --yes) YES=1 ;;
    --python) shift; [ $# -gt 0 ] || die "--python needs a path"; PY_ARG="$1" ;;
    -h|--help) say "User LaunchAgent; every 10 minutes; no sudo. Options: --check --uninstall --dry-run --yes --python PATH"; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
  shift
done
# Step 3: choose the interpreter. The default is the system Python, which only an administrator can change. A
# user-writable Python (Homebrew, pyenv, ~/.local) is NOT searched for: whoever can edit it could run code as this
# agent every time it fires. An explicit --python is accepted with a warning.
py_ok() { [ -x "$1" ] && "$1" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' >/dev/null 2>&1; }
if [ -n "$PY_ARG" ]; then
  PY="$PY_ARG"; say "WARNING: using $PY chosen with --python; make sure only you can write to it and its folders."
else
  PY="/usr/bin/python3"
fi
py_ok "$PY" || die "$PY is missing or older than Python 3.9 (on a stock Mac, install the Command Line Tools: xcode-select --install)"
target="gui/$(id -u)"
loaded() { launchctl print "$target/$LABEL" >/dev/null 2>&1; }
# Step 4: ask before changing launchd. Without a terminal and without --yes the answer is "no".
confirm() {
  [ "$YES" = 1 ] && return 0
  [ -t 0 ] || die "not a terminal: re-run with --yes if you really want to load $LABEL"
  printf 'Load %s now? It will run %s with %s every 10 minutes. [y/N] ' "$LABEL" "$SCRIPT" "$PY"
  read -r answer
  case "$answer" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}
case "$MODE" in
  check)
    say "script:  $([ -f "$SCRIPT" ] && echo present || echo MISSING)"
    say "plist:   $([ -f "$PLIST" ] && echo present || echo MISSING) ($PLIST)"
    if [ -f "$PLIST" ]; then plutil -lint "$PLIST" || say "plist:   INVALID"; fi
    if loaded; then say "launchd: loaded"; else say "launchd: NOT loaded"; fi
    "$PY" -I "$SCRIPT" status
    ;;
  uninstall)
    if [ "$DRY" = 0 ]; then launchctl bootout "$target/$LABEL" >/dev/null 2>&1 || true; rm -f "$PLIST"; fi
    say "removed LaunchAgent (data receipts and logs retained)"
    ;;
  install)
    [ -f "$SCRIPT" ] && [ -f "$TEMPLATE" ] || die "guard script or plist template missing"
    # Step 5: refuse to schedule a guard that has nothing to compare against. The same expression the guard uses
    # for its host name picks the baseline file, so the two cannot disagree.
    "$PY" -I -c 'import pathlib, socket, sys; sys.exit(0 if (pathlib.Path(sys.argv[1]) / "baseline.HOST.json".replace("HOST", socket.gethostname().split(chr(46))[0])).is_file() else 1)' "$ROOT/data/netguard" \
      || die "no baseline found; run: $PY $SCRIPT learn   (after reviewing the current state)"
    mkdir -p "$AGENT_DIR" "$HOME/Library/Logs" || die "cannot create user LaunchAgent/log directories"
    # Step 6: render the template. Values are XML-escaped; the file is written 0600 and swapped in atomically.
    "$PY" -I - "$TEMPLATE" "$PLIST" "$PY" "$SCRIPT" "$HOME" "$ROOT" <<'PYEOF'
import os, sys
from xml.sax.saxutils import escape
template, out, py, script, home, root = sys.argv[1:7]
s = open(template, encoding="utf-8").read()
for k, v in (("PYTHON", py), ("SCRIPT", script), ("HOME", home), ("ROOT", root)):
    s = s.replace("@@%s@@" % k, escape(v))
if "@@" in s:
    raise SystemExit("unrendered plist placeholder")
tmp = out + ".tmp"
with open(tmp, "w", encoding="utf-8") as f: f.write(s)
os.chmod(tmp, 0o600)
os.replace(tmp, out)
PYEOF
    [ "$DRY" = 1 ] && { say "dry-run: wrote $PLIST; launchd not changed"; exit 0; }
    plutil -lint "$PLIST" || die "plutil rejected plist"
    # Step 7: the only step that changes what runs on this Mac, so it is the one that asks.
    confirm || { say "not loaded (the plist stays at $PLIST; load it later with launchctl bootstrap)"; exit 0; }
    launchctl bootout "$target/$LABEL" >/dev/null 2>&1 || true
    launchctl bootstrap "$target" "$PLIST" || die "launchctl bootstrap failed; run from logged-in Terminal"
    launchctl enable "$target/$LABEL" >/dev/null 2>&1 || true
    say "loaded $LABEL; checks run at login and every 10 minutes"
    ;;
esac
