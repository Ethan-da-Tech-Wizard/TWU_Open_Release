#!/usr/bin/env python3
"""net_guard: user-level network monitor (no root, no model, no network calls of its own).

  net_guard.py learn     accept the current network state as the baseline
  net_guard.py learn --only KEY [--only KEY2]  accept just those findings (keys exactly as `check` prints them)
  net_guard.py check     compare now to baseline; write data/netguard/LATEST.<host>.json; exit 1 on findings
  net_guard.py status    print the last receipt
  net_guard.py snapshot  print the current snapshot as JSON

Detects: new non-loopback listeners, a listener whose program changed, gateway MAC change (ARP spoofing / rogue
router), DNS resolver change, new LAN neighbours, outbound connections to classic backdoor/C2/Tor ports.
Metadata only: addresses, ports, program names. Linux (ss, ip) and macOS (lsof, route, arp, scutil) via an injected runner.
"""
# Flow of this file, top to bottom:
#   1. constants and the trusted-command helper (nothing is run through PATH)
#   2. parsers: pure functions that turn tool output text into Python data (easy to test with fixed text)
#   3. snapshot(): run the probes through an injected `runner` and assemble the current state
#   4. compare(): baseline versus now -> findings keyed "net:<kind>:<detail>"
#   5. posture(): is a host firewall on
#   6. learn / learn_only / check / alarm_problems: baseline, receipt and monitoring-side helpers
#   7. main(): the command line
#
# Design decisions:
#   * The runner is injected. Production uses run() (real commands); tests pass a function returning canned
#     text, so no test needs a network, root, or any particular OS tool.
#   * Nothing is exempt by program name. Any process can pick its own name, so a name-based allow list lets an
#     attacker hide behind a well-known one. Exemptions are exact, opt-in files (see allowed_listeners) and can
#     be pinned to a sha256 so that editing them is noticed.
#   * Without root, lsof and ss show only this user's sockets. Listeners owned by other users or root are
#     invisible to this tool; see the README limits.
#   * Fail loudly: a probe that fails raises ProbeUnavailable and is reported, never read as "no listeners".
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import platform
import re
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path

# ROOT is where data/ is read and written: the folder above scripts/ unless env TWU_ROOT is set. The `or`
# (not a get() default) matters: an exported but empty TWU_ROOT must fall back to the default.
ROOT = Path(os.environ.get("TWU_ROOT") or Path(__file__).resolve().parent.parent)
# Baseline, receipt and allow files live here, one set per host name.
DIR = ROOT / "data" / "netguard"
# Only the short host name is used, so "box.local" and "box" share files.  leakguard:allow
HOST = socket.gethostname().split(".")[0]
# Remote ports that classic backdoors, Tor and remote-desktop tools use. An outbound connection to one of
# these is reported unless an exact (program, port) pair is allowed.
SUSPECT_PORTS = {4444, 5555, 1337, 31337, 6667, 6697, 9001, 9050, 9051, 12345, 54321, 3389, 5900}
MAX_NEIGHBOURS_NEW = 3  # a few new devices are normal (phones); more is a scan or a rogue network
# Addresses that never leave the machine; listeners and peers on them are ignored.
LOOPBACK = {"127.0.0.1", "::1", "localhost"}


# Raised whenever a required probe fails or cannot be trusted. check() turns it into a persisted
# "net:sensor-unavailable" finding; learn() aborts on it so a half-seen network is never saved as a baseline.
class ProbeUnavailable(RuntimeError):
    """A required network or firewall sensor failed, so its result is not trustworthy."""


# The only folders external tools are taken from. PATH is deliberately not consulted: a user-writable PATH
# entry (for example ~/.local/bin, which persistence_guard watches) could otherwise replace lsof or arp and feed the
# guard a clean answer. Requirements: lsof, arp, route and scutil live in /usr/sbin or /sbin on macOS (lsof is in
# /usr/sbin); ss, ip, systemctl on Linux; ps in /bin. Each must be a root-owned file that others cannot write.
TRUSTED_DIRS = ("/bin", "/usr/bin", "/sbin", "/usr/sbin")


# RED-TEAM 5 (Rule 16): a tool file owned by uid 65534 ("nobody") was accepted as "root-owned" everywhere. That uid is what root
# looks like INSIDE an unprivileged user namespace, so it is trusted only when this process really is in one (the uid map is not
# the identity map). On an ordinary host a file owned by nobody is refused again.
UID_MAP = "/proc/self/uid_map"


def _trusted_owner(uid):
    """True for uid 0, or for uid 65534 only inside an unprivileged user namespace (uid map other than '0 0 4294967295')."""
    if uid == 0:
        return True
    if uid != 65534:
        return False
    try:
        with open(UID_MAP) as fh:
            rows = [ln.split() for ln in fh.read().splitlines() if ln.strip()]
    except OSError:
        return False
    return bool(rows) and rows != [["0", "0", "4294967295"]]


def trusted_command(name):
    """Absolute path of a system tool found only in TRUSTED_DIRS (never via PATH); raises ProbeUnavailable if absent or unsafe."""
    # Folder order matters only when a tool exists in more than one place; the first acceptable one wins.
    # A missing candidate is normal, so it only moves on to the next folder. A candidate is accepted only if it is a
    # regular executable file owned by root with no group or world write bit; anything else is refused, not used.
    for d in TRUSTED_DIRS:
        cand = os.path.join(d, name)
        try:
            st = os.stat(cand)
        except OSError:
            continue
        if stat.S_ISREG(st.st_mode) and os.access(cand, os.X_OK) and _trusted_owner(st.st_uid) and not st.st_mode & 0o022:
            return cand
    raise ProbeUnavailable(f"required command {name} not found as a root-owned file in {', '.join(TRUSTED_DIRS)}")


# All external commands go through run(). Tests replace it with a fake runner, so this is the only function
# that ever starts a process (apart from the parent-process lookup in the learn receipt).
def run(cmd, timeout=10):
    """Run one command and return its stdout; a missing tool, a timeout or a non-zero exit raises ProbeUnavailable."""
    # Bare tool names are resolved through trusted_command(); an absolute path (such as the macOS firewall
    # helper) is used as given. Output is text; stderr is captured and discarded so a probe cannot spill into logs.
    # Keep the caller's name for error messages: they stay short and identical on every machine.
    name = cmd[0]
    # Absolute names (the macOS firewall helper) are used as given; bare names go through the trusted list.
    if not os.path.isabs(name):
        cmd = [trusted_command(name)] + list(cmd[1:])
    try:
        # Arguments are always a list (never a shell string), so nothing in them can be interpreted by a shell.
        # The timeout stops a hung tool from blocking the scheduled run forever.
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ProbeUnavailable(f"{name} could not run ({type(exc).__name__})") from exc
    # A non-zero exit means the probe did not run properly. Raising is the safe choice: an empty or partial
    # reply must never be mistaken for a clean network.
    if result.returncode != 0:
        raise ProbeUnavailable(f"{name} exited with status {result.returncode}")
    return result.stdout


# RED-TEAM 5 (Rule 16): the baseline, the learn temp file and the receipt used to be written with write_text(), which follows a
# symlink planted at that name (for example one that arrived through a synced folder) and overwrites its target. This writer
# removes whatever is at the temp name, creates it exclusively without following links, then renames it into place.
def _write_nofollow(path, text, mode=0o600):
    """Atomically write `text` to `path` through a freshly created temp file (O_EXCL | O_NOFOLLOW); never writes through a symlink."""
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    if tmp.is_symlink() or tmp.exists():
        tmp.unlink()
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.write(fd, text.encode())
    finally:
        os.close(fd)
    os.replace(tmp, path)


def split_hostport(s):
    """Split "host:port" or "[v6]:port" into (host, port) text; a zone suffix like %en0 is dropped."""
    # Bracketed IPv6 ("[::1]:80") needs the "]:" split; everything else splits at the last colon, which also
    # keeps an IPv6 address without brackets in one piece.
    s = s.strip()
    if s.startswith("["):
        host, _, port = s[1:].rpartition("]:")
    else:
        host, _, port = s.rpartition(":")
    host = host.split("%")[0]
    return host, port


def is_loopback(host):
    """True for 127.x, ::1 and localhost, which are never reported as exposed."""
    # String checks come first because they are cheap and cover "localhost"; ipaddress handles the rest of the
    # 127.0.0.0/8 and IPv6 forms. A value that is not an address (a host name) is not loopback.
    if host in LOOPBACK or host.startswith("127."):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def parse_ss_listeners(text):
    """Parse `ss -H -tulnp` output into [{proto, addr, port, prog}]; prog is "?" when ss could not show the owner."""
    # Column 5 of `ss -tulnp` is the local address:port. The owning program, when ss can show it, sits in a
    # users:(("name",pid=..)) suffix; without privileges that suffix is missing for other users' sockets, hence "?".
    out = []
    for line in text.splitlines():
        f = line.split()
        # Skip headers and blank lines: a listener row has a protocol word first and at least five columns.
        if len(f) < 5 or f[0] not in ("tcp", "udp"):
            continue
        host, port = split_hostport(f[4])
        if not port.isdigit():
            continue
        m = re.search(r'users:\(\("([^"]+)"', line)
        # Take the first process name in the users:(( )) list; "?" keeps the entry but marks the owner as unknown.
        out.append({"proto": f[0], "addr": host, "port": int(port), "prog": m.group(1) if m else "?"})
    return out


def parse_lsof_listeners(text):
    """Parse `lsof -nP -iTCP -sTCP:LISTEN` output into the same listener dicts as the ss parser."""
    # lsof columns: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME. The first line is a header and is skipped.
    # TCP rows end in "(LISTEN)", so the address is the field before it; UDP rows have no state, so it is the last field.
    out = []
    for line in text.splitlines()[1:]:
        f = line.split()
        # A valid lsof data row has at least nine columns; shorter lines are noise and are skipped.
        if len(f) < 9:
            continue
        # Choose the NAME column: for LISTEN rows the field before the state, otherwise the last field.
        name = f[8] if f[-1] == "(LISTEN)" else f[-1]
        if f[-1] == "(LISTEN)":
            name = f[-2]
        # lsof prints "*:7000" for "all interfaces"; rewrite it to 0.0.0.0 so it parses as an address and is not loopback.
        host, port = split_hostport(name.replace("*:", "0.0.0.0:", 1) if name.startswith("*:") else name)
        if port.isdigit():
            out.append({"proto": f[7].lower() if f[7] in ("TCP", "UDP") else "tcp", "addr": host, "port": int(port), "prog": f[0]})
    return out


def parse_ss_established(text):
    """Parse `ss -tnp state established` into [{remote, port, prog}], skipping loopback peers."""
    out = []
    for line in text.splitlines():
        f = line.split()
        # Fewer than four columns cannot hold a local and a peer address.
        if len(f) < 4:
            continue
        host, port = split_hostport(f[3])  # `ss state established` omits the State column: Recv-Q Send-Q Local Peer
        if port.isdigit() and not is_loopback(host):
            m = re.search(r'users:\(\("([^"]+)"', line)
            out.append({"remote": host, "port": int(port), "prog": m.group(1) if m else "?"})
    return out


def parse_ip_neigh(text):
    """Parse `ip neigh show` into {ip: mac}; FAILED and INCOMPLETE entries have no usable MAC and are skipped."""
    # Typical line: "192.0.2.1 dev wlan0 lladdr <mac> REACHABLE". Lines without lladdr have no MAC.
    # Neighbours in a failed state were never reachable, so they are not counted as devices on the LAN.
    out = {}
    for line in text.splitlines():
        f = line.split()
        # Only rows that carry a hardware address are neighbours; "FAILED" rows have none.
        if len(f) >= 5 and "lladdr" in f:
            state = f[-1]
            if state in ("FAILED", "INCOMPLETE"):
                continue
            # Key is the neighbour IP; MACs are lower-cased so compare() never sees a case-only difference.
            out[f[0]] = f[f.index("lladdr") + 1].lower()
    return out


def parse_arp_a(text):
    """Parse `arp -an` (macOS) into {ip: mac}, zero-padding the short octets macOS prints."""
    # Typical line: "? (192.0.2.1) at 2:aa:bb:cc:0:a on en0 ifscope [ethernet]". macOS drops leading zeros
    # in each octet, so the MAC is padded back to two digits to compare equal to the Linux form.
    out = {}
    for m in re.finditer(r"\(([\d.]+)\) at ([0-9a-f:]+)", text.lower()):
        # Pad each octet to two digits (macOS prints "2" for "02").
        mac = ":".join(p.zfill(2) for p in m.group(2).split(":"))
        # Broadcast and incomplete entries are not real devices.
        if mac not in ("ff:ff:ff:ff:ff:ff", "(incomplete)"):
            out[m.group(1)] = mac
    return out


def parse_default_gateway(text):
    """Extract the default gateway address from `ip route` (Linux) or `route -n get default` (macOS) output, or None."""
    # Linux prints "default via 192.0.2.1 dev ..."; macOS prints "gateway: 192.0.2.1". Either may be missing
    # (no network), in which case None is returned and compare() reports it against a baseline that had one.
    # Try the Linux form first, then the macOS form.
    m = re.search(r"default via ([\d.]+)", text) or re.search(r"gateway:\s*([\d.]+)", text)
    return m.group(1) if m else None


def parse_resolvers(text):
    """Return the sorted unique nameserver addresses found in resolv.conf text."""
    # A set removes duplicates (the same server is often listed twice) and sorting makes the list comparable.
    # re.M anchors each match at a line start, so comments mentioning "nameserver" are ignored.
    return sorted(set(re.findall(r"^\s*nameserver\s+(\S+)", text, re.M)))


def snapshot(runner=run, resolv_text=None, os_name=None):
    """Probe the machine with `runner` and return the current state: exposed listeners, gateway and its MAC, neighbours, resolvers, outbound connections."""
    # Two branches because the platforms expose the same facts through different tools. macOS: lsof for
    # listeners and connections, route and arp for the gateway and neighbours, scutil for DNS. Linux: ss, ip and
    # /etc/resolv.conf. os_name and resolv_text can be injected so tests run on any host.
    # os_name overrides the real platform so tests can exercise both branches on any machine.
    mac_os = (os_name or platform.system()) == "Darwin"
    if mac_os:
        # TCP listeners first; UDP sockets are added below because lsof lists them with a different filter.
        listeners = parse_lsof_listeners(runner(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"]))
        # UDP has no "listen" state: any unconnected UDP socket is treated as a listener (rows with "->" are connected flows).
        for u in runner(["lsof", "-nP", "-iUDP"]).splitlines()[1:]:
            f = u.split()
            if len(f) >= 9 and "->" not in f[-1]:
                host, port = split_hostport(f[8].replace("*:", "0.0.0.0:", 1) if f[8].startswith("*:") else f[8])
                if port.isdigit():
                    listeners.append({"proto": "udp", "addr": host, "port": int(port), "prog": f[0]})
        # Gateway, then its MAC from the ARP table: a changed MAC for the same gateway address is the ARP-spoofing signal.
        gw = parse_default_gateway(runner(["route", "-n", "get", "default"]))
        neigh = parse_arp_a(runner(["arp", "-an"]))
        # Established TCP connections feed the suspect-port check; they are not part of the baseline (see learn()).
        est = []
        for line in runner(["lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED"]).splitlines()[1:]:
            # An established TCP row reads "local->remote"; take the remote part after the arrow.
            m = re.search(r"->([^\s]+)", line)
            if m:
                host, port = split_hostport(m.group(1))
                if port.isdigit() and not is_loopback(host):
                    est.append({"remote": host, "port": int(port), "prog": line.split()[0]})
        # scutil --dns lists "nameserver[0] : addr" lines; the regex tolerates the index and spacing.
        resolv = resolv_text if resolv_text is not None else runner(["scutil", "--dns"])
        resolvers = sorted(set(re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", resolv)))
    else:
        # Linux branch.
        listeners = parse_ss_listeners(runner(["ss", "-H", "-tulnp"]))
        gw = parse_default_gateway(runner(["ip", "route", "show", "default"]))
        neigh = parse_ip_neigh(runner(["ip", "neigh", "show"]))
        est = parse_ss_established(runner(["ss", "-H", "-tnp", "state", "established"]))
        # Linux resolvers come from /etc/resolv.conf unless a test supplied the text.
        if resolv_text is None:
            try:
                resolv_text = Path("/etc/resolv.conf").read_text()
            except OSError as exc:
                raise ProbeUnavailable(f"could not read resolver configuration ({type(exc).__name__})") from exc
        resolvers = parse_resolvers(resolv_text)
    # No resolver at all means the probe saw nothing useful (offline, or a parse failure). Treat that as a failed
    # sensor instead of recording an empty, always-matching baseline.
    if not resolvers:
        raise ProbeUnavailable("resolver configuration contained no nameserver")
    # A set of tuples removes duplicates (the same socket can appear for IPv4 and IPv6 rows) and sorting makes
    # the baseline file stable between runs. Loopback listeners are not exposure and are left out.
    exposed = sorted({(l["proto"], l["addr"], l["port"], l["prog"]) for l in listeners if not is_loopback(l["addr"])})
    return {
        # The snapshot is plain JSON-able data so the same structure is the baseline, the comparison input and the output of `snapshot`.
        "host": HOST,
        "at": time.time(),
        # Rebuild dicts from the sorted tuples so every listener has the same four keys in the same order.
        "exposed": [dict(proto=p, addr=a, port=n, prog=g) for p, a, n, g in exposed],
        "gateway": gw,
        "gateway_mac": neigh.get(gw) if gw else None,
        "neighbours": sorted(neigh),
        "resolvers": resolvers,
        "outbound": est,
    }


# Findings are keyed by proto/port rather than by process: a port is the thing that is exposed, and the
# program name can legitimately vary (helpers, renames), so it is compared as a secondary signal.
def _key(l):
    """Identity of a listener for comparison: protocol and port (the program is compared separately)."""
    return f"{l['proto']}/{l['port']}"


# Opt-in allow files. Two files can be supplied, each optionally pinned to a sha256 set in an environment
# variable. Nothing is allowed by default, and there are no built-in names.
def _allow_entries(env_file, default_name, env_pin):
    """Return the list under "allow" of an opt-in allow file; [] when absent. A set pin that does not match the bytes raises."""
    # `or` (not a get() default): an exported but empty variable means "use the default location".
    # An unreadable or missing file allows nothing, which is the safe direction. A pin that does not match
    # raises, because a silently ignored mismatch would hide that someone edited the file.
    path = Path(os.environ.get(env_file) or (DIR / default_name))
    try:
        # Read bytes once and hash those same bytes, so the pin check and the parsed content cannot differ (no re-read race).
        raw = path.read_bytes()
    except OSError:
        return []
    # An empty or unset pin variable means "no pin"; a set one must equal the sha256 of the exact bytes read.
    pin = os.environ.get(env_pin) or ""
    if pin and hashlib.sha256(raw).hexdigest() != pin.strip().lower():
        raise ProbeUnavailable(f"{path.name} does not match the sha256 pinned in {env_pin}; its entries are NOT trusted")
    try:
        # Malformed JSON or a wrong top-level type allows nothing.
        return list(json.loads(raw.decode("utf-8")).get("allow", []))
    except (ValueError, AttributeError, TypeError):
        return []


def allowed_listeners(path=None):
    """Exact (proto, port, prog) listeners from the opt-in allow_listen.json (env TWU_NET_ALLOW_LISTEN_FILE); nothing by default."""
    # Entry shape: {"allow": [{"proto": "udp", "port": 40000, "prog": "name"}]}. All three fields must match
    # exactly, so allowing one port of one program does not open a range or a name.
    try:
        if path is not None:
            entries = json.loads(Path(path).read_text()).get("allow", [])
        else:
            entries = _allow_entries("TWU_NET_ALLOW_LISTEN_FILE", "allow_listen.json", "TWU_NET_ALLOW_LISTEN_SHA256")
        # Normalise to hashable tuples; int() makes "40000" and 40000 equal and rejects non-numeric ports.
        return {(a["proto"], int(a["port"]), a["prog"]) for a in entries}
    except (OSError, ValueError, KeyError, TypeError):
        return set()


def allowed_outbound():
    """Exact (prog, port) outbound pairs from the opt-in allow_outbound.json (env TWU_NET_ALLOW_OUTBOUND_FILE); nothing by default."""
    # Entry shape: {"allow": [{"prog": "name", "port": 9001}]}. Only the named program on the named port is
    # excused; the same port from another program still alarms.
    try:
        # Same normalisation for outbound pairs.
        return {(a["prog"], int(a["port"])) for a in
                _allow_entries("TWU_NET_ALLOW_OUTBOUND_FILE", "allow_outbound.json", "TWU_NET_ALLOW_OUTBOUND_SHA256")}
    except (KeyError, ValueError, TypeError):
        return set()


# compare() is pure (no I/O apart from reading the opt-in allow files), which is why most tests call it directly.
def compare(base, now, allow=None):
    """Return {key: text}. Pure; tests call it directly (allow=set() disables the on-disk allow list)."""
    # Rules: a listener is NEW when its proto/port is not in the baseline, and "program changed" when the port
    # is known but a different named program owns it (a "?" on either side is ignored because unprivileged tools
    # often cannot name the owner). Gateway, DNS and neighbour rules follow, then outbound connections.
    p = {}
    # `allow=None` reads the opt-in file; tests pass allow=set() to prove behaviour with nothing exempt.
    allow = allowed_listeners() if allow is None else allow
    # Index the baseline by proto/port for constant-time lookups below.
    bl = {_key(l): l for l in base.get("exposed", [])}
    for l in now.get("exposed", []):
        k = _key(l)
        # An exact opt-in entry skips the listener entirely; there is no name- or port-range-based skip.
        if (l.get("proto"), l.get("port"), l.get("prog")) in allow:
            continue
        # Not in the baseline: a new exposed port. Fix text tells the reader to stop it or to learn on purpose.
        if k not in bl:
            p[f"net:listener:{k}"] = (f"net: NEW non-loopback listener {k} on {l['addr']} by {l['prog']} | fix: if unwanted stop it, "
                                      f"if wanted run: python3 scripts/net_guard.py learn")
        # Port already baselined: alarm only if a different, named program now owns it.
        elif bl[k]["prog"] != l["prog"] and "?" not in (bl[k]["prog"], l["prog"]):
            p[f"net:listener-prog:{k}"] = f"net: listener {k} program changed {bl[k]['prog']} -> {l['prog']} | fix: investigate before running learn"
    # Same gateway address, different hardware address: ARP spoofing or a rogue router. Comparing only when the
    # address is unchanged avoids false alarms when the machine simply joined another network.
    if base.get("gateway_mac") and now.get("gateway_mac") and base.get("gateway") == now.get("gateway") \
            and base["gateway_mac"] != now["gateway_mac"]:
        p["net:gateway-mac"] = (f"net: GATEWAY {now['gateway']} MAC changed {base['gateway_mac']} -> {now['gateway_mac']} "
                                f"(ARP spoofing or rogue router) | fix: leave this network; verify router; use the VPN")
    # Losing the gateway or its MAC is reported too, so a failed probe cannot hide a change.
    if base.get("gateway") and not now.get("gateway"):
        p["net:gateway-missing"] = "net: default gateway disappeared | fix: verify host connectivity and routing"
    # Same gateway but no MAC any more: ARP could not resolve it, which is worth a look.
    if base.get("gateway_mac") and base.get("gateway") == now.get("gateway") and not now.get("gateway_mac"):
        p["net:gateway-mac-unavailable"] = "net: gateway MAC could not be resolved | fix: verify the gateway and local network"
    # Resolvers are compared as sets; order changes are not findings.
    if base.get("resolvers") and now.get("resolvers") and set(base["resolvers"]) != set(now["resolvers"]):
        p["net:resolvers"] = (f"net: DNS resolvers changed {','.join(base['resolvers'])} -> {','.join(now['resolvers'])} "
                              f"| fix: confirm you changed networks; else suspect DNS hijack")
    # Resolvers that vanished entirely are a separate finding from a changed list.
    if base.get("resolvers") and not now.get("resolvers"):
        p["net:resolvers-missing"] = "net: DNS resolver list disappeared | fix: verify resolver configuration"
    # More than MAX_NEIGHBOURS_NEW new devices on the same network is treated as a scan or a rogue network; a
    # few new devices (phones, guests) are normal. Skipped on a different gateway, which means a different LAN.
    new_n = sorted(set(now.get("neighbours", [])) - set(base.get("neighbours", [])))
    if len(new_n) > MAX_NEIGHBOURS_NEW and base.get("gateway") == now.get("gateway"):
        p["net:neighbours"] = f"net: {len(new_n)} new LAN devices since baseline (first: {', '.join(new_n[:3])}) | fix: check router client list; then learn"
    # Outbound connections are judged only against the suspect-port list, minus exact opt-in (program, port) pairs.
    allowed = allowed_outbound()
    for o in now.get("outbound", []):
        # Exact (program, port) pair opted in: skip. The same port from any other program is still reported.
        if (o.get("prog"), o["port"]) in allowed:
            continue
        # Key includes remote and port so two different suspicious destinations are two findings.
        if o["port"] in SUSPECT_PORTS:
            p[f"net:out:{o['remote']}:{o['port']}"] = (f"net: outbound to {o['remote']}:{o['port']} by {o['prog']} "
                                                       f"(backdoor/Tor/remote-desktop port) | fix: identify the program, kill if unknown")
    return p


# Firewall posture is a separate probe from the network snapshot because it asks a different question
# (is protection on) rather than what changed; its answers are never stored in a baseline.
def posture(runner=run, os_name=None):
    """Is a supported host firewall actually on? Readable without root. Returns {key: text}."""
    # macOS: socketfilterfw is called by absolute path and its text is parsed; an empty reply is a failed probe,
    # not "firewall off". Linux: ask systemd whether firewalld or ufw is active; the first active one is enough.
    p = {}
    if (os_name or platform.system()) == "Darwin":
        # Apple ships this helper at a fixed absolute path; it can report state without root.
        fw = "/usr/libexec/ApplicationFirewall/socketfilterfw"
        out = runner([fw, "--getglobalstate"]).lower()
        # An empty answer is a failed probe, not "firewall off".
        if not out.strip():
            raise ProbeUnavailable("macOS firewall state returned no data")
        # Accept both wordings macOS uses: "enabled" text and the numeric State = 1 or 2 forms.
        if "enabled" not in out and "state = 1" not in out and "state = 2" not in out:
            p["net:firewall-off"] = "net: macOS application firewall is OFF | fix: System Settings > Network > Firewall (needs an administrator), or sudo socketfilterfw --setglobalstate on"
        # Stealth mode makes the Mac ignore probes such as ping and closed-port replies; reported separately.
        stealth = runner([fw, "--getstealthmode"]).lower()
        if not stealth.strip():
            raise ProbeUnavailable("macOS firewall stealth state returned no data")
        if "stealth mode is on" not in stealth:
            p["net:stealth-off"] = "net: macOS firewall stealth mode is OFF | fix: System Settings > Network > Firewall > Options > Enable stealth mode"
    else:
        # Collected so the "no firewall" finding is only raised after every known service was actually checked.
        states = []
        for unit in ("firewalld.service", "ufw.service"):
            state = runner(["systemctl", "show", "--property=ActiveState", "--value", unit]).strip().lower()
            # Any state outside this set means systemctl gave an unexpected answer; do not guess.
            if state not in {"active", "inactive", "failed", "not-found"}:
                raise ProbeUnavailable(f"{unit} state could not be verified")
            states.append(state)
            # The first active firewall service is enough; no findings.
            if state == "active":
                return p
        # Cannot happen with a non-empty unit list; kept so removing every unit name fails loudly instead of reporting "no firewall".
        if not states:
            raise ProbeUnavailable("no firewall service state was checked")
        if "active" not in states:
            p["net:firewall-off"] = "net: no host firewall is active (firewalld, ufw) | fix: enable the distro firewall after reviewing its policy; do not use an installer for another distro"
    return p


# File naming: baseline.<host>.json (accepted state), LATEST.<host>.json (newest check receipt) and
# learn_receipts.<host>.jsonl (append-only audit trail of accepted changes), all in the state folder.
def paths(host=HOST, d=None):
    """Return (baseline file, latest receipt file) for a host inside the state folder d (default DIR)."""
    d = Path(d) if d else DIR
    return d / f"baseline.{host}.json", d / f"LATEST.{host}.json"


# Helpers for the audit trail of `learn`; small and self-contained so a receipt failure can never block the
# security-relevant work.
def _redact(text):
    """Mask the value after password/token/secret/key words (name=value, name: value or name value)."""
    # Learn receipts record the parent command line; this keeps an accidentally typed secret out of them.
    import re as _re
    return _re.sub(r"(?i)([\w-]*(?:password|passwd|token|secret|key)[\w-]*(?:\s*[=:]\s*|\s+))(\S+)", r"\1[REDACTED]", text)


def _sha(path):
    """Full sha256 hex of a file, or None if it cannot be read (for example the baseline does not exist yet)."""
    import hashlib
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return None


def _write_learn_receipt(base_p, before, tool, accepted=None):
    """One JSON line per successful learn, appended with a single os.write (safe on a synced folder, per-host file).
    A failure here only warns on stderr; it never blocks learn. No secrets, no file contents."""
    # The receipt answers "who accepted this baseline, from where, and did it change anything": it stores
    # the terminal, the parent command line (redacted), and the baseline hash before and after.
    try:
        import datetime, getpass, subprocess
        host = socket.gethostname().split(".")[0]
        try:
            tty = os.ttyname(0)
        except OSError:
            # No controlling terminal (cron, launchd): fall back to the SSH or TTY variables, empty values counting as unset.
            tty = os.environ.get("SSH_TTY") or os.environ.get("TTY") or "none"
        try:
            parent = subprocess.run([trusted_command("ps"), "-o", "command=", "-p", str(os.getppid())], capture_output=True,
                                    text=True, timeout=5).stdout.strip() or "unknown"
        except Exception:
            parent = "unknown"
        now = datetime.datetime.now().astimezone()
        try:
            user = getpass.getuser()
        except Exception:
            user = "unknown"
        rec = {"time": now.isoformat(timespec="seconds"),
               "time_utc": now.astimezone(datetime.timezone.utc).isoformat(timespec="seconds"),
               "user": user, "terminal": tty,
               # Redact before truncating so a secret cannot straddle the 200-character cut.
               "parent_cmd": _redact(parent)[:200],
               "argv": _redact(" ".join(sys.argv[1:]))[:200],
               "host": host, "tool": "net_guard", "baseline_file": str(base_p),
               "baseline_before": before, "baseline_after": _sha(base_p)}
        if accepted is not None:
            rec["accepted_keys"] = sorted(accepted)
        data = (json.dumps(rec, sort_keys=True) + "\n").encode()
        # O_APPEND plus a single os.write keeps concurrent writers from interleaving partial lines.
        fd = os.open(Path(base_p).parent / f"learn_receipts.{host}.jsonl", os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            if os.write(fd, data) != len(data):
                raise OSError("short write")
        finally:
            os.close(fd)
    except Exception as exc:
        print(f"WARNING: learn receipt NOT written: {type(exc).__name__}: {exc}", file=sys.stderr)



def learn(d=None, runner=run, os_name=None):
    """Accept the current network state as the baseline (outbound connections are not baselined) and return it."""
    base_p, _ = paths(d=d)
    base_p.parent.mkdir(parents=True, exist_ok=True)
    snap = snapshot(runner, os_name=os_name)
    # Current outbound connections are transient, so they are not part of the baseline; they are judged fresh each check.
    snap["outbound"] = []
    before = _sha(base_p)
    # The baseline is made private (0600) afterwards because it lists exposed ports and LAN devices.
    _write_nofollow(base_p, json.dumps(snap, indent=1))
    _write_learn_receipt(base_p, before, "net_guard")
    return snap


# Raised by learn_only() for any request that cannot be honoured exactly. The CLI maps it to exit status 1 and
# an unchanged baseline, so a mistyped finding key never accepts something unintended.
class LearnRefused(Exception):
    """learn --only was asked for a key that is not a current, baseline-acceptable finding."""


# learn_only is the narrow alternative to learn(): it accepts specific findings and leaves every other one open.
def learn_only(keys, d=None, runner=run, os_name=None, allow=None):
    """Accept ONLY the named findings (exact keys printed by `check`); every other finding stays open.
    Raises LearnRefused (baseline untouched) for an unknown key or a finding no baseline can accept."""
    # Only keys that `check` would print right now may be accepted, so a typo cannot rewrite the baseline.
    # Gateway-missing, firewall and outbound findings cannot be accepted this way: they must be investigated.
    base_p, _ = paths(d=d)
    # Remove duplicate keys but keep their order.
    keys = list(dict.fromkeys(keys))
    if not keys:
        raise LearnRefused("no key given")
    try:
        base = json.loads(base_p.read_text())
    except (OSError, ValueError) as exc:
        raise LearnRefused(f"no readable baseline ({type(exc).__name__}); run a full learn once first") from exc
    now = snapshot(runner, os_name=os_name)
    now["outbound"] = []
    # Compare against the current probe exactly as check() would, to find out which keys are real findings.
    problems = compare(base, now, allow=allow)
    unknown = [k for k in keys if k not in problems]
    if unknown:
        raise LearnRefused("not a current finding: " + ", ".join(unknown))
    # Deep copy through JSON so a refused key halfway through leaves the on-disk baseline untouched.
    new = json.loads(json.dumps(base))
    for k in keys:
        # Listener findings: replace just that proto/port in the baseline.
        if k.startswith(("net:listener:", "net:listener-prog:")):
            # Key shape is net:listener:<proto>/<port>; keep the other listeners and replace only the accepted one.
            lk = k.split(":", 2)[2]
            kept = [l for l in new.get("exposed", []) if _key(l) != lk]
            new["exposed"] = sorted(kept + [l for l in now["exposed"] if _key(l) == lk],
                                    key=lambda l: (l["proto"], l["addr"], l["port"], l["prog"]))
        # Single-value findings: copy the newly observed value into the baseline.
        elif k == "net:gateway-mac":
            new["gateway_mac"] = now.get("gateway_mac")
        elif k == "net:resolvers":
            new["resolvers"] = now.get("resolvers")
        elif k == "net:neighbours":
            new["neighbours"] = now.get("neighbours")
        else:
            # Anything else (missing gateway, outbound connections, firewall) must be investigated, never baselined.
            raise LearnRefused(f"{k} cannot be accepted into the baseline (investigate it instead)")
    before = _sha(base_p)
    # Write to a temporary name and rename: rename is atomic, so readers see the old or the new file, never half of one.
    _write_nofollow(base_p, json.dumps(new, indent=1))      # atomic: a crash mid-write must not leave a truncated baseline
    _write_learn_receipt(base_p, before, "net_guard", accepted=keys)
    return new


def check(d=None, runner=run, os_name=None):
    """Probe, compare with the baseline, add the firewall posture, write the receipt and return it; a failed probe yields an incomplete receipt."""
    # Probe, compare with the baseline, add the firewall posture, write the receipt and return it. If any probe
    # fails the whole receipt is marked incomplete (complete=False) with a "net:sensor-unavailable" finding, because
    # a partial result must never be read as a clean one.
    base_p, latest_p = paths(d=d)
    now = None
    complete = False
    try:
        now = snapshot(runner, os_name=os_name)
        if not base_p.exists():
            # No baseline is reported as a finding, never treated as "all clear".
            problems = {"net:no-baseline": "net: no baseline yet | fix: python3 scripts/net_guard.py learn (after you trust this network)"}
        else:
            try:
                problems = compare(json.loads(base_p.read_text()), now)
            except (OSError, ValueError) as exc:
                # A corrupt baseline must not read as "no differences"; escalate to an incomplete result.
                raise ProbeUnavailable(f"network baseline is unreadable ({type(exc).__name__})") from exc
        # Firewall state is judged fresh every time and is never part of the baseline.
        problems.update(posture(runner, os_name))
        complete = True
    except ProbeUnavailable as exc:
        # Persist the failure as a finding so a monitoring reader sees it, instead of leaving an old clean receipt in place.
        problems = {"net:sensor-unavailable": f"net: required network or firewall probe failed ({exc}); no clean result was recorded"}
    # Counts are None when the probe failed so a reader cannot mistake "0 listeners" for "could not look".
    receipt = {"checked": time.time(), "host": HOST, "complete": complete, "problems": problems,
               "exposed": len(now["exposed"]) if complete else None,
               "neighbours": len(now["neighbours"]) if complete else None,
               "outbound": len(now["outbound"]) if complete else None}
    latest_p.parent.mkdir(parents=True, exist_ok=True)
    # Atomic replace again: a monitoring reader must never see a half-written receipt.
    _write_nofollow(latest_p, json.dumps(receipt, indent=1))  # atomic: a reader never sees a half-written receipt
    return receipt


# Monitoring-side helper: reads the receipt written by check() and returns its findings, plus findings
# for a missing, stale, foreign or malformed receipt. It never raises, so a broken receipt cannot crash the caller.
def alarm_problems(now=None, d=None):
    """Used by an alarm aggregator (not part of this release): findings from the saved receipt; a quiet sensor is itself a problem. Never raises."""
    # A missing receipt, a receipt for another host, a malformed one, a future timestamp or one older than three
    # hours are all findings: a guard that has stopped running looks the same as a quiet network unless checked.
    try:
        now = time.time() if now is None else now
        _, latest_p = paths(d=d)
        if not latest_p.exists():
            # No receipt at all means the guard never ran, which must not look like a quiet network.
            return {"net:quiet": "net: net_guard has never run | fix: systemctl --user enable --now net-guard.timer"}
        r = json.loads(latest_p.read_text())
        # A receipt for another host, or one without the expected shape, is not evidence about this machine.
        if not isinstance(r, dict) or r.get("host") != HOST or not isinstance(r.get("problems"), dict):
            raise ValueError("wrong host or invalid receipt shape")
        # Start from the findings the last check recorded, then add completeness and staleness on top.
        out = dict(r["problems"])
        if r.get("complete") is not True:
            out.setdefault("net:sensor-unavailable", "net: latest probe receipt is incomplete; no clean network state is trusted")
        checked = float(r["checked"])
        # A timestamp more than a minute in the future would hide staleness, so it counts as an error.
        if checked > now + 60:
            raise ValueError("receipt timestamp is in the future")
        # Three hours is a generous bound for a job scheduled every ten minutes; it tolerates a machine that was asleep for a while.
        if now - checked > 3 * 3600:
            out["net:quiet"] = "net: net_guard has not reported for 3h | fix: systemctl --user status net-guard.service"
        return out
    except Exception as exc:
        return {"net:receipt-unavailable": f"net: guard receipt is unreadable or malformed ({type(exc).__name__})"}


def main(argv=None):
    """Command-line entry point; returns the process exit status (0 clean, 1 findings or failure, 2 usage)."""
    a = (argv if argv is not None else sys.argv[1:]) or ["check"]
    # Help must be inert: an earlier version re-saved the baseline on `learn --help`.
    if set(a) & {"-h", "--help", "help"}:        # a help request must NEVER run a command: `learn` rewrites the security baseline
        print(__doc__ or "usage: check | status | snapshot | learn [--only KEY ...]")
        return 0
    cmd = a[0]
    # `learn --only KEY [--only KEY2]` accepts individual findings instead of the whole current state.
    if cmd == "learn" and "--only" in a[1:]:
        # Hand-rolled parsing keeps the tool dependency-free; each --only must be followed by exactly one key.
        keys, rest, i = [], a[1:], 0
        while i < len(rest):
            if rest[i] == "--only" and i + 1 < len(rest):
                keys.append(rest[i + 1]); i += 2
            else:
                print("ERROR usage: learn --only KEY [--only KEY2]", file=sys.stderr); return 2
        try:
            learn_only(keys)
        except (LearnRefused, ProbeUnavailable) as exc:
            print(f"ERROR net_guard baseline NOT changed: {exc}", file=sys.stderr)
            return 1
        print(f"accepted {len(keys)} finding(s): {', '.join(keys)}")
        return 0
    if cmd == "learn":
        try:
            s = learn()
        except ProbeUnavailable as exc:
            print(f"ERROR net_guard did not save a baseline: required probe failed ({exc})", file=sys.stderr)
            return 1
        print(f"baseline saved: {len(s['exposed'])} exposed listeners, gateway {s['gateway']} {s['gateway_mac']}, {len(s['neighbours'])} neighbours")
        return 0
    # `check` is the scheduled command: one PROBLEM line per finding and exit 1 when there is any.
    if cmd == "check":
        r = check()
        for k, v in r["problems"].items():
            print(f"PROBLEM {k}: {v}")
        print(f"net_guard {r['host']}: {len(r['problems'])} finding(s); exposed={r['exposed']} neighbours={r['neighbours']} outbound={r['outbound']}")
        # Exit 1 means "findings were reported" (or the probe was incomplete); schedulers should treat it as "read the output", not "crashed".
        return 1 if r["problems"] else 0
    # `status` prints the last receipt without probing anything.
    if cmd == "status":
        print((paths()[1]).read_text() if paths()[1].exists() else "no receipt")
        return 0
    # `snapshot` prints the raw current state as JSON, useful for writing opt-in allow entries.
    if cmd == "snapshot":
        print(json.dumps(snapshot(), indent=1))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
