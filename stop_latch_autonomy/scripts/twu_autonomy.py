#!/usr/bin/env python3
"""twu_autonomy: what may run by itself (AUTO), what must ask (PROPOSE), what never happens (NEVER).

  twu_autonomy.py check ACTION     exit 0 AUTO, 3 PROPOSE, 4 NEVER, 2 error; prints the matching rule + source
  twu_autonomy.py list             every rule, expired ones marked
  twu_autonomy.py explain ACTION   why ACTION is classed as it is (all matching rules)
  twu_autonomy.py log [N]          last N decisions (default 20)
  twu_autonomy.py validate         check data/health/autonomy_policy.json

Policy file: <root>/data/health/autonomy_policy.json (you edit it; <root> = env TWU_ROOT, else the folder above scripts/).  Rules: {id, class, match, reason, source, expires?}.
Several rules may match one action; NEVER beats PROPOSE beats AUTO.  No match = PROPOSE.
A missing policy uses the built-in seed; a malformed one FAILS CLOSED (everything PROPOSE).
A seeded NEVER rule cannot be removed or loosened unless the edited rule carries "explicit_widen": true AND an
"expires" date; without both, the built-in NEVER rule stays in force and validate reports it.
Expiry: an expired AUTO or PROPOSE rule is ignored (falls back to PROPOSE). An expired NEVER widening stops
applying, so the seeded NEVER returns. No network, no model calls; stdlib only.
"""
# Postponed evaluation of annotations keeps the module importable on older Python 3 versions.
from __future__ import annotations

# Standard library only: no network access and no model calls are needed to classify an action.
import fnmatch
import json
import os
import platform
import re
# sys is used for argv and for the exit code; file locations use pathlib so they behave the same on macOS and Linux.
import sys
import time
from pathlib import Path

# The policy and the decision log live under <root>/data/health/. <root> is the folder above scripts/ unless env
# TWU_ROOT names another folder (an empty value counts as unset), so the policy can live outside the code folder.
# Evaluated once at import; a relative TWU_ROOT is resolved against the current directory.
# REPO is the root folder for the policy and the log; tests and callers can pass a different root explicitly.
REPO = Path(os.environ.get("TWU_ROOT") or Path(__file__).resolve().parent.parent)
# Short host name, used only to keep one decision log per machine; 'host' if the name is unavailable.
HOST = platform.node().split(".")[0] or "host"
# The three decision classes, ordered by strictness: RANK lets the strictest matching rule win, EXIT maps each class to a process exit code.
CLASSES = ("AUTO", "PROPOSE", "NEVER")
# Numeric strictness of each class; max() over the matching rules picks the winner.
RANK = {"AUTO": 0, "PROPOSE": 1, "NEVER": 2}
# Process exit codes: 0 AUTO, 3 PROPOSE, 4 NEVER. 2 is reserved for usage and policy errors.
EXIT = {"AUTO": 0, "PROPOSE": 3, "NEVER": 4}
# Decision log size cap in bytes; one rotation (.1 file) keeps the log bounded.
LOG_CAP = 256 * 1024
# Action names are restricted to a small safe alphabet, so they can be logged and matched without escaping.
# RED-TEAM 5: \Z (not $) so a trailing newline is not accepted as part of a "safe" name.
ACTION_RE = re.compile(r"^[A-Za-z0-9_.:\-]{1,80}\Z")
# Neutral rationale strings used as each seed rule's 'source' field.
P_AUTO = "Project policy: routine maintenance tasks run unattended when they are local, read-only or self-contained"
P_SEC = "Project policy: security tooling must be real and protective, event-driven, with no telemetry and no spend"
P_DAEMON = "Project policy: background daemons are deterministic, event-driven and use near-zero idle CPU"
P_CHANGE = "Project policy: changes to code, files, services and settings need a reviewed, scoped approval"
P_SPEND = "Project policy: nothing should cost money"
P_TELEMETRY = "Project policy: nothing sends telemetry to anyone outside the project's own systems"
P_NEVER = "Project policy: these actions are never taken automatically"


def _r(rid, cls, match, reason, source):
    """Build one rule dictionary."""
    return {"id": rid, "class": cls, "match": match, "reason": reason, "source": source}


# Built-in seed policy, used when no policy file exists and as the floor that NEVER rules cannot be widened beneath.
# Each rule is (id, class, glob pattern matched against the action name, human reason, source).
SEED_RULES = [
    # AUTO rules: local, read-only or self-contained maintenance that may run without asking.
    # Patterns ending in * cover a family of action names (for example every run_leakwatch_<mode>).
    _r("auto-knowledge-index", "AUTO", "refresh_knowledge_index", "rebuild the local knowledge index; workspace-only, free", P_AUTO),
    _r("auto-integrity", "AUTO", "run_integrity", "read-only integrity run", P_AUTO),
    _r("auto-leakwatch", "AUTO", "run_leakwatch_*", "offline leak scan, sends nothing out", P_AUTO),
    _r("auto-linkmap", "AUTO", "run_linkmap", "read-only link map", P_AUTO),
    _r("auto-offline-proof", "AUTO", "run_offline_proof", "read-only offline proof", P_AUTO),
    _r("auto-forever", "AUTO", "run_forever_checks", "read-only forever checks", P_AUTO),
    _r("auto-regenerate", "AUTO", "regenerate_*", "regenerate generated files and caches", P_AUTO),
    _r("auto-enki-resmoke", "AUTO", "resmoke_enki_tools", "re-run the smoke tests after the agent's own script edits", P_AUTO),
    _r("auto-rotate-logs", "AUTO", "rotate_own_logs", "rotate the agent's own capped logs", P_DAEMON),
    # Security tooling: scanning is automatic, but fetching new signatures or rules downloads data, so it must be approved.
    _r("auto-malware-scan", "AUTO", "run_malware_scan", "malware scan only reads files and runs local scanners; sends nothing out", P_SEC),
    _r("propose-update-clamav-signatures", "PROPOSE", "update_clamav_signatures", "fetches antivirus signatures from the official mirror (free, no telemetry); shown as 'update available, approve'", P_SEC),
    _r("propose-update-yara-rules", "PROPOSE", "update_yara_rules", "refreshing vetted YARA rules means downloading a pinned commit and re-running the vet; never silent", P_SEC),
    # PROPOSE rules: the action may be valid, but a person has to approve it each time.
    _r("propose-edit-source", "PROPOSE", "edit_source*", "changes source code", P_CHANGE),
    _r("propose-delete", "PROPOSE", "delete_*", "deletes files", P_CHANGE),
    _r("propose-move", "PROPOSE", "move_*", "moves files", P_CHANGE),
    _r("propose-install", "PROPOSE", "install_*", "installs software or services", P_CHANGE),
    _r("propose-system-settings", "PROPOSE", "change_system_settings*", "changes system settings", P_CHANGE),
    _r("propose-upload", "PROPOSE", "upload_*", "sends data somewhere", P_CHANGE),
    _r("propose-commit", "PROPOSE", "git_commit*", "commits", P_CHANGE),
    _r("propose-spend", "PROPOSE", "spend_*", "spends money", P_SPEND),
    # NEVER rules: refused regardless of any AUTO or PROPOSE rule that also matches.
    _r("never-offensive", "NEVER", "run_offensive_tool*", "offensive tools", P_NEVER),
    _r("never-collect-ids", "NEVER", "collect_identifiers*", "other people's identifiers", P_NEVER),
    _r("never-telemetry", "NEVER", "send_telemetry*", "telemetry to third parties", P_TELEMETRY),
    _r("never-weights-delete", "NEVER", "delete_model_weights*", "model weights are never deleted", P_NEVER),
    _r("never-weights-move", "NEVER", "move_model_weights*", "model weights are never moved", P_NEVER),
    _r("never-expose", "NEVER", "expose_private_data*", "private data stays private", P_NEVER),
    _r("never-bypass-stop", "NEVER", "bypass_stop*", "STOP always wins", P_NEVER),
    _r("never-bypass-guards", "NEVER", "bypass_guard*", "guards are boundaries", P_NEVER),
    _r("never-pay", "NEVER", "pay_money*", "no paid services or spending", P_SPEND),
]
# Index of the seeded NEVER rules by id; load_policy() restores any of them that a policy file loosens or drops.
SEED_NEVER = {r["id"]: r for r in SEED_RULES if r["class"] == "NEVER"}


# Default layout: <root>/data/health/autonomy_policy.json and one log per host next to it.
def policy_path(root=REPO):
    """Path of the policy file under the given root."""
    return Path(root) / "data" / "health" / "autonomy_policy.json"


def log_path(root=REPO, host=HOST):
    """Path of the per-host decision log under the given root."""
    return Path(root) / "data" / "health" / ("autonomy_log.%s.jsonl" % host)


# Expiry dates are UTC; a plain date means 'valid through the end of that day'.
def _parse_expiry(v):
    """-> epoch seconds or raises ValueError. Accepts YYYY-MM-DD (end of that day UTC) or ISO date-time."""
    if not isinstance(v, str):
        raise ValueError("expires must be a string")
    # Imported lazily because only expiry parsing needs them.
    import calendar
    import datetime
    # A trailing Z is rewritten to +00:00 because older Python versions cannot parse it.
    d = datetime.datetime.fromisoformat(v.replace("Z", "+00:00"))
    # A bare YYYY-MM-DD is 10 characters: move to the start of the next day so the whole day counts.
    if len(v) <= 10:
        d = d + datetime.timedelta(days=1)
    # Naive date-times are interpreted as UTC so the result never depends on the machine's time zone.
    if d.tzinfo is None:
        d = d.replace(tzinfo=datetime.timezone.utc)
    return d.timestamp()


# Contract: never raises. Returns the rules, a list of human-readable problems, and the state (seed, file or failed_closed).
def load_policy(root=REPO):
    """-> (rules, problems, state). state: seed | file | failed_closed. Never raises."""
    # Step 1: no policy file means the built-in seed applies (the caller is told through the problems list).
    p = policy_path(root)
    # The seed is returned as copies, so callers can modify the list without changing SEED_RULES.
    if not p.exists():
        return [dict(r) for r in SEED_RULES], ["policy file missing; using built-in seed"], "seed"
    try:
        # Step 2: parse and validate the file strictly; any structural error fails CLOSED (every action becomes PROPOSE).
        doc = json.loads(p.read_text(encoding="utf-8"))
        # A policy file is a JSON object with a 'rules' list; other keys (such as a note) are ignored.
        raw = doc["rules"]
        # A policy whose 'rules' is not a list is structurally broken.
        if not isinstance(raw, list):
            raise ValueError("rules is not a list")
        rules, seen = [], set()
        for r in raw:
            # Each rule must be a JSON object.
            if not isinstance(r, dict):
                raise ValueError("rule is not an object")
            # Every rule needs non-empty string fields; a missing reason or source is treated as a broken policy.
            for k in ("id", "class", "match", "reason", "source"):
                if not isinstance(r.get(k), str) or not r[k].strip():
                    raise ValueError("rule %r: missing or empty %s" % (r.get("id"), k))
            # Only AUTO, PROPOSE and NEVER are valid classes.
            if r["class"] not in CLASSES:
                raise ValueError("rule %s: class must be one of %s" % (r["id"], CLASSES))
            # Rule ids must be unique so 'explain' and the log can name a rule unambiguously.
            if r["id"] in seen:
                raise ValueError("duplicate rule id %s" % r["id"])
            seen.add(r["id"])
            # Validate the date now so a typo is reported by 'validate' instead of silently never expiring.
            if "expires" in r and r["expires"] is not None:
                _parse_expiry(r["expires"])
            rules.append(r)
    # Unreadable, non-JSON, wrongly shaped or invalid-expiry files all land here and fail closed.
    except (OSError, ValueError, KeyError, TypeError) as e:
        return [], ["malformed policy, failing closed (everything PROPOSE): %s" % e], "failed_closed"
    # Step 3: a valid file must not weaken a seeded NEVER rule. Loosening needs explicit_widen plus a future expiry.
    problems = []
    # Single timestamp so every rule in the listing is judged against the same instant.
    now = time.time()
    # Only the seeded NEVER rules are protected; the user's own rules may be changed freely.
    for sid, seed in SEED_NEVER.items():
        # Find the file's version of this seeded rule, if it kept one.
        cur = next((r for r in rules if r["id"] == sid), None)
        # A seeded NEVER rule counts as widened when it is missing, no longer NEVER, or matches a different pattern.
        # RED-TEAM 5 (Rule 16): a seeded NEVER rule that is kept word for word but given an "expires" date counts as widened too.
        # classify() ignores an expired rule, so `"expires": "2000-01-01"` on never-bypass-stop silently switched it off while
        # validate printed no problem. Now the rule needs explicit_widen plus a future date, like any other loosening.
        widened = ((cur is not None and cur["class"] != "NEVER") or cur is None or cur["match"] != seed["match"]
                   or bool(cur.get("expires")))
        # Untouched seed rule: nothing to do.
        if not widened:
            continue
        # An override is honoured only while both opt-in markers are present and the expiry date is still in the future.
        ok = cur is not None and cur.get("explicit_widen") is True and cur.get("expires")
        active = ok and _parse_expiry(cur["expires"]) > now
        # Deliberate, time-boxed widening is allowed; once the expiry passes the seed rule returns by itself.
        if active:
            continue
        # Report the restoration so 'validate' and 'explain' show it instead of hiding it.
        problems.append("NEVER rule %s was loosened or removed without explicit_widen plus a future expires; seed restored" % sid)
        # Drop the weakened version and put the seed rule back, so NEVER stays in force.
        rules = [r for r in rules if r["id"] != sid] + [dict(seed)]
    # Valid file: the (possibly repaired) rules plus any problems found.
    return rules, problems, "file"


# Used both when classifying and when 'list' marks expired rules.
def _active(rule, now):
    """True when the rule has no expiry or its expiry is still in the future (an unreadable date counts as active)."""
    # A rule without an expiry never expires.
    ex = rule.get("expires")
    if not ex:
        return True
    try:
        # Expired means the end of the expiry day has passed.
        return _parse_expiry(ex) > now
    # An unparseable date is treated as still active; load_policy() already rejects such files, so this is only a safety net.
    except ValueError:
        return True


# Pure function of the rules, the action and the clock, which makes it easy to test.
def classify(action, rules, state="file", now=None):
    """-> (class, rule|None, matches). NEVER > PROPOSE > AUTO; unknown or failed-closed = PROPOSE."""
    # Injectable clock keeps expiry testable.
    now = time.time() if now is None else now
    # A broken policy file never grants anything: every action needs approval.
    if state == "failed_closed":
        return "PROPOSE", None, []
    # Collect every active rule whose pattern matches, so 'explain' can show all of them.
    hits = []
    for r in rules:
        # Expired AUTO and PROPOSE rules are ignored, so an action falls back to the next matching rule or to PROPOSE.
        if not _active(r, now):
            continue
        # Case-sensitive glob match of the rule pattern against the action name.
        if fnmatch.fnmatchcase(action, r["match"]):
            hits.append(r)
    # No rule at all means the action is unknown, and unknown actions need approval.
    if not hits:
        return "PROPOSE", None, []
    # Several rules may match; the strictest class wins (NEVER beats PROPOSE beats AUTO).
    best = max(hits, key=lambda r: RANK[r["class"]])
    # Return the winning class, the winning rule and every match, so callers can explain the decision.
    return best["class"], best, hits


# Best effort: callers wrap this in try/except because a full disk must never block a decision.
def _append_log(path, line, cap=None):
    """Append one line to the log, rotating it to a single .1 backup when it would pass the size cap."""
    cap = LOG_CAP if cap is None else cap
    path = Path(path)
    # Create the log folder on first use.
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        # Rotate when the next line would exceed the cap: keep exactly one previous file.
        if path.exists() and path.stat().st_size + len(line) + 1 > cap:
            # Replace any older backup so at most two files (current and .1) ever exist.
            os.replace(str(path), str(path) + ".1")
    except OSError:
        pass
    # Append-only: one JSON object per decision.
    with open(path, "a", encoding="utf-8") as f:
        f.write(line + "\n")


# The programmatic entry point: other tools call decide('action_name') and obey the returned class.
def decide(action, root=REPO, host=HOST, now=None, log=True):
    """Classify ACTION, append the decision to the log, return 'AUTO' | 'PROPOSE' | 'NEVER'. Never raises."""
    # One timestamp for both the expiry check and the log entry.
    t = time.time() if now is None else now
    # Anything that is not a plain safe action name is logged as 'invalid' and needs approval; the raw text is never logged.
    if not isinstance(action, str) or not ACTION_RE.match(action):
        cls, rid, shown = "PROPOSE", "invalid-action", "invalid"
    else:
        # Reload the policy on every call so edits take effect immediately; nothing is cached or watched.
        rules, _, state = load_policy(root)
        cls, rule, _ = classify(action, rules, state, t)
        # The log records which rule decided, or why none did (unknown action or failed-closed policy).
        rid = rule["id"] if rule else ("failed-closed" if state == "failed_closed" else "unknown-action")
        shown = action
    # Logging must never change the decision, so file errors are swallowed.
    if log:
        try:
            # sort_keys keeps each log line stable and easy to diff or grep.
            _append_log(log_path(root, host), json.dumps(
                {"time": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(t)), "action": shown, "class": cls, "rule": rid},
                sort_keys=True))
        except OSError:
            pass
    return cls


# The same layout is used by check, explain and list.
def _show(rule):
    """Format one rule for printing."""
    ex = " expires=%s" % rule["expires"] if rule.get("expires") else ""
    return "%s [%s] match=%s%s\n  reason: %s\n  source: %s" % (
        rule["id"], rule["class"], rule["match"], ex, rule["reason"], rule["source"])


def main(argv=None, root=REPO):
    """Command-line entry point; returns the process exit code."""
    a = list(sys.argv[1:] if argv is None else argv)
    # Dispatch on the first word: check, explain, list, log, validate.
    cmd = a[0] if a else ""
    # Both subcommands take exactly one ACTION argument.
    if cmd in ("check", "explain"):
        # Reject malformed action names before any lookup (exit 2 = usage error).
        if len(a) != 2 or not ACTION_RE.match(a[1]):
            print("usage: %s ACTION (letters, digits, _ . : - only)" % cmd, file=sys.stderr)
            return 2
        rules, problems, state = load_policy(root)
        cls, rule, hits = classify(a[1], rules, state)
        # check records the decision in the log and exits with the class's code so shell scripts can branch on it.
        if cmd == "check":
            decide(a[1], root)
            # First line is always CLASS ACTION so scripts can read the verdict from stdout as well as from the exit code.
            print("%s %s" % (cls, a[1]))
            print(_show(rule) if rule else "  no matching rule: unknown actions need approval%s" % (
                " (policy failed closed)" if state == "failed_closed" else ""))
            return EXIT[cls]
        print("%s %s" % (cls, a[1]))
        # Show policy problems as notes so the user sees why a rule was restored or the file failed.
        for p in problems:
            print("  note: " + p)
        # explain lists every matching rule, strictest first, without logging.
        for h in sorted(hits, key=lambda r: -RANK[r["class"]]):
            print(_show(h))
        if not hits:
            print("  no rule matches; default is PROPOSE")
        return 0
    # list prints all rules, strictest class first, flagging expired ones.
    if cmd == "list":
        rules, problems, state = load_policy(root)
        now = time.time()
        for p in problems:
            print("note: " + p)
        # Strictest classes first, then alphabetical by id, for a stable listing.
        for r in sorted(rules, key=lambda r: (-RANK[r["class"]], r["id"])):
            print(_show(r) + ("" if _active(r, now) else "\n  EXPIRED (ignored)"))
        return 0
    if cmd == "log":
        # Optional line count for 'log'; anything that is not a number falls back to 20.
        n = int(a[1]) if len(a) > 1 and a[1].isdigit() else 20
        try:
            # A missing log is not an error: it just means nothing has been decided yet.
            lines = log_path(root).read_text(encoding="utf-8").splitlines()
        except OSError:
            lines = []
        print("\n".join(lines[-n:]) if lines else "no decisions logged yet")
        return 0
    # validate exits 0 only when a policy file loaded with no problems.
    if cmd == "validate":
        # Only the state and the problems matter here; the rules themselves are not printed.
        _, problems, state = load_policy(root)
        print("state: " + state)
        for p in problems:
            print("problem: " + p)
        # Exit 2 for a missing file, a malformed file or a restored NEVER rule; 0 only for a clean file.
        return 0 if state == "file" and not problems else 2
    # Unknown or missing command: show the usage text.
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
