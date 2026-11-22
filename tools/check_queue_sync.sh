#!/bin/sh
# check_queue_sync.sh - fail if the two copies of the job-queue module (and its test) have drifted apart.
# Program: check_queue_sync.sh | Purpose: enki_waypoint ships a copy of malakopia_core's malakopia_job_queue.py so it
# runs alone; nothing else keeps the copies identical, so this check does.
# Usage: tools/check_queue_sync.sh [REPO_ROOT]     (default: the folder above this script)
# Exit: 0 identical, 1 drifted or missing.
set -eu
root=${1:-$(cd "$(dirname "$0")/.." && pwd)}
status=0
for f in malakopia_job_queue.py test_malakopia_job_queue.py; do
  a="$root/malakopia_core/scripts/$f"
  b="$root/enki_waypoint/scripts/$f"
  if [ ! -f "$a" ] || [ ! -f "$b" ]; then
    echo "queue-sync: missing copy of $f"; status=1
  elif cmp -s "$a" "$b"; then
    echo "queue-sync: $f identical in malakopia_core and enki_waypoint"
  else
    echo "queue-sync: FAILED, $f differs between malakopia_core/scripts and enki_waypoint/scripts"; status=1
  fi
done
exit $status
