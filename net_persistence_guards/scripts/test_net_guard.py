#!/usr/bin/env python3
"""Tests for scripts/net_guard.py: fake runner and temp dirs only; no network, no root."""
from __future__ import annotations
import io, json, os, subprocess, sys, tempfile, unittest
from pathlib import Path
from unittest import mock
sys.path.insert(0, str(Path(__file__).resolve().parent))
import net_guard as ng

SS_L = ('tcp LISTEN 0 4096 127.0.0.1:8384 0.0.0.0:* users:(("syncapp",pid=1,fd=3))\n'
        'tcp LISTEN 0 4096 *:22000 *:* users:(("syncapp",pid=1,fd=4))\n'
        'udp UNCONN 0 0 0.0.0.0:5353 0.0.0.0:*\n'
        'udp UNCONN 0 0 [::]:21027 [::]:* users:(("syncapp",pid=1,fd=5))\n')
SS_E = ('0 0 192.0.2.252:50000 93.184.216.34:443 users:(("curl",pid=2,fd=3))\n'
        '0 0 192.0.2.252:50001 203.0.113.9:4444 users:(("evil",pid=3,fd=3))\n'
        '0 0 127.0.0.1:1 127.0.0.1:2\n')
NEIGH = "192.0.2.1 dev wlan0 lladdr AA:BB:CC:" "00:00:01 REACHABLE\n192.0.2.7 dev wlan0 lladdr aa:bb:cc:" "00:00:07 STALE\n192.0.2.9 dev wlan0  FAILED\n"


def runner(gw_mac_neigh=NEIGH, listeners=SS_L):
    """Helper: runner."""
    def r(cmd, timeout=10):
        """Helper: r."""
        if cmd[0] == "ss" and "established" in cmd: return SS_E
        if cmd[0] == "ss": return listeners
        if cmd[0] == "systemctl": return "inactive\n"
        if cmd[:3] == ["ip", "route", "show"]: return "default via 192.0.2.1 dev wlan0 proto dhcp\n"
        if cmd[:2] == ["ip", "neigh"]: return gw_mac_neigh
        return ""
    return r


class T(unittest.TestCase):
    """Tests for: T."""
    def snap(self, **k):
        """Helper: snap."""
        return ng.snapshot(runner(**k), resolv_text="nameserver 192.0.2.1\n", os_name="Linux")

    def test_parse(self):
        """Check that parse."""
        s = self.snap()
        ports = {(l["proto"], l["port"]) for l in s["exposed"]}
        self.assertEqual(ports, {("tcp", 22000), ("udp", 5353), ("udp", 21027)})  # loopback 8384 excluded
        self.assertEqual(s["gateway_mac"], "aa:bb:cc:" "00:00:01")
        self.assertEqual(s["neighbours"], ["192.0.2.1", "192.0.2.7"])  # FAILED skipped
        self.assertEqual(len(s["outbound"]), 2)  # loopback pair excluded

    def test_clean_compare(self):
        """Check that clean compare."""
        s = self.snap(); b = dict(s, outbound=[])
        s["outbound"] = [o for o in s["outbound"] if o["port"] == 443]
        self.assertEqual(ng.compare(b, s), {})

    def test_allow_outbound_list(self):
        """A reviewed (program, port) pair in allow_outbound.json no longer alarms; an unlisted one still does."""
        import json, tempfile
        from pathlib import Path
        s = self.snap(); b = dict(s, outbound=[])
        s["outbound"] = [{"prog": "tor", "port": 9001, "remote": "1.2.3.4"}, {"prog": "nc", "port": 4444, "remote": "5.6.7.8"}]
        old = ng.DIR
        with tempfile.TemporaryDirectory() as d:
            ng.DIR = Path(d)
            try:
                self.assertEqual(len(ng.compare(b, s)), 2)  # no list: both alarm
                (Path(d) / "allow_outbound.json").write_text(json.dumps({"allow": [{"prog": "tor", "port": 9001}]}))
                got = ng.compare(b, s)
                self.assertEqual(list(got), ["net:out:5.6.7.8:4444"])  # only the unlisted one
            finally:
                ng.DIR = old

    def test_new_listener_and_prog_change(self):
        """Check that new listener and prog change."""
        b = self.snap()
        n = self.snap(listeners=SS_L + 'tcp LISTEN 0 1 0.0.0.0:8080 0.0.0.0:* users:(("python3",pid=9,fd=3))\n')
        self.assertIn("net:listener:tcp/8080", ng.compare(b, n))
        # No program name is exempt: a UDP listener in the dynamic range under a well-known name still alarms.
        for prog in ("syncapp", "launcher", "gameclient"):
            n_st = self.snap(listeners=SS_L + f'udp UNCONN 0 0 0.0.0.0:35352 0.0.0.0:* users:(("{prog}",pid=9,fd=3))\n')
            self.assertIn("net:listener:udp/35352", ng.compare(b, n_st, allow=set()), prog)
        n2 = self.snap(listeners=SS_L.replace("syncapp", "hacked", 2))
        self.assertTrue(any(k.startswith("net:listener-prog") for k in ng.compare(b, n2)))

    def test_gateway_mac_change(self):
        """Check that gateway mac change."""
        b = self.snap()
        n = self.snap(gw_mac_neigh=NEIGH.replace("AA:BB:CC:" "00:00:01", "de:ad:be:" "ef:00:01"))
        self.assertIn("net:gateway-mac", ng.compare(b, n))

    def test_gateway_change_by_moving_networks_is_not_spoof(self):
        """Check that gateway change by moving networks is not spoof."""
        b = self.snap(); n = self.snap(gw_mac_neigh=NEIGH.replace("AA:BB:CC:" "00:00:01", "de:ad:be:" "ef:00:01"))
        n["gateway"] = "10.0.0.1"
        self.assertNotIn("net:gateway-mac", ng.compare(b, n))

    def test_resolver_and_suspect_port_and_neighbours(self):
        """Check that resolver and suspect port and neighbours."""
        b = self.snap(); n = self.snap(); n["resolvers"] = ["6.6.6.6"]
        n["neighbours"] = b["neighbours"] + [f"192.0.2.{i}" for i in range(20, 25)]
        p = ng.compare(b, n)
        self.assertIn("net:resolvers", p); self.assertIn("net:neighbours", p)
        self.assertIn("net:out:203.0.113.9:4444", p)

    def test_check_flow_and_alarm(self):
        """Check that check flow and alarm."""
        with tempfile.TemporaryDirectory() as t:
            self.assertIn("net:quiet", ng.alarm_problems(d=t))
            r = ng.check(d=t, runner=runner(), os_name='Linux'); self.assertIn("net:no-baseline", r["problems"])
            ng.learn(d=t, runner=runner(), os_name='Linux')
            r = ng.check(d=t, runner=runner(), os_name='Linux')
            self.assertEqual([k for k in r["problems"] if k != "net:firewall-off"], ["net:out:203.0.113.9:4444"])
            self.assertIn("net:out:203.0.113.9:4444", ng.alarm_problems(d=t))
            self.assertIn("net:quiet", ng.alarm_problems(now=r["checked"] + 4 * 3600, d=t))

    def test_macos_adapter(self):
        """Check that macos adapter."""
        LSOF_L = ("COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
                  "com.docker 1 e 10u IPv4 0x1 0t0 TCP 127.0.0.1:1433 (LISTEN)\n"
                  "ControlCe 2 e 8u IPv4 0x2 0t0 TCP *:7000 (LISTEN)\n")
        LSOF_E = ("COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
                  "curl 3 e 5u IPv4 0x3 0t0 TCP 192.0.2.5:5000->93.184.216.34:443 (ESTABLISHED)\n")
        def r(cmd, timeout=10):
            """Helper: r."""
            if cmd[0] == "lsof" and "-iUDP" in cmd:
                return "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\nmDNSRespo 4 e 9u IPv4 0x4 0t0 UDP *:5353\n"
            if cmd[0] == "lsof": return LSOF_E if "ESTABLISHED" in " ".join(cmd) else LSOF_L
            if cmd[0] == "route": return "   gateway: 192.0.2.1\n"
            if cmd[0] == "arp": return "? (192.0.2.1) at 2:aa:bb:cc:0:a on en0 ifscope [ethernet]\n"
            return ""
        s = ng.snapshot(r, resolv_text="nameserver[0] : 192.0.2.1\n", os_name="Darwin")
        self.assertEqual([(l["port"], l["prog"]) for l in s["exposed"]], [(7000, "ControlCe"), (5353, "mDNSRespo")])  # 1433 on loopback excluded
        self.assertEqual(s["gateway"], "192.0.2.1"); self.assertEqual(s["gateway_mac"], "02:aa:bb:" "cc:00:0a")
        self.assertEqual(s["resolvers"], ["192.0.2.1"]); self.assertEqual(s["outbound"][0]["port"], 443)

    def test_posture(self):
        """Check that posture."""
        on = lambda cmd, timeout=10: "active\n" if cmd[0] == "systemctl" and cmd[-1] == "private-fw.service" else "inactive\n"
        self.assertIn("net:firewall-off", ng.posture(on, "Linux"))   # a private-looking unit name is no longer special
        fw = lambda cmd, timeout=10: "active\n" if cmd[0] == "systemctl" and cmd[-1] == "firewalld.service" else "inactive\n"
        self.assertEqual(ng.posture(fw, "Linux"), {})
        ufw = lambda cmd, timeout=10: "active\n" if cmd[0] == "systemctl" and cmd[-1] == "ufw.service" else "inactive\n"
        self.assertEqual(ng.posture(ufw, "Linux"), {})
        none = lambda cmd, timeout=10: "inactive\n"
        self.assertIn("net:firewall-off", ng.posture(none, "Linux"))
        mac_off = lambda cmd, timeout=10: "Firewall is disabled. (State = 0)\n"
        mac_on = lambda cmd, timeout=10: "Firewall is enabled. (State = 1)\nStealth mode is on\n"
        self.assertIn("net:firewall-off", ng.posture(mac_off, "Darwin")); self.assertEqual(ng.posture(mac_on, "Darwin"), {})

    def test_sensor_failure_is_persisted_as_alarm_not_empty_snapshot(self):
        """Check that sensor failure is persisted as alarm not empty snapshot."""
        with tempfile.TemporaryDirectory() as t:
            def denied(cmd, timeout=10):
                """Helper: denied."""
                raise ng.ProbeUnavailable("ss exited with status 2")
            r = ng.check(d=t, runner=denied, os_name="Linux")
            self.assertFalse(r["complete"])
            self.assertIsNone(r["exposed"])
            self.assertIn("net:sensor-unavailable", r["problems"])
            self.assertNotIn("net:no-baseline", r["problems"])
            self.assertIn("net:sensor-unavailable", ng.alarm_problems(d=t))

    def test_command_failure_is_not_converted_to_empty_output(self):
        """Check that command failure is not converted to empty output."""
        failed = mock.Mock(returncode=2, stdout="", stderr="Operation not permitted")
        with mock.patch.object(ng.subprocess, "run", return_value=failed):
            with self.assertRaises(ng.ProbeUnavailable):
                ng.run(["ss", "-H", "-tulnp"])

    def test_firewall_probe_failure_is_not_reported_as_off(self):
        """Check that firewall probe failure is not reported as off."""
        def denied(cmd, timeout=10):
            """Helper: denied."""
            raise ng.ProbeUnavailable("systemctl exited with status 1")
        with self.assertRaises(ng.ProbeUnavailable):
            ng.posture(denied, "Linux")

    def test_firewall_probe_failure_makes_whole_receipt_incomplete(self):
        """Check that firewall probe failure makes whole receipt incomplete."""
        with tempfile.TemporaryDirectory() as t:
            normal = runner()
            def firewall_denied(cmd, timeout=10):
                """Helper: firewall denied."""
                if cmd[0] == "systemctl":
                    raise ng.ProbeUnavailable("systemctl exited with status 1")
                return normal(cmd, timeout)
            r = ng.check(d=t, runner=firewall_denied, os_name="Linux")
            self.assertFalse(r["complete"])
            self.assertIsNone(r["exposed"])
            self.assertIn("net:sensor-unavailable", r["problems"])

    def test_unreadable_alarm_receipt_is_an_alarm(self):
        """Check that unreadable alarm receipt is an alarm."""
        with tempfile.TemporaryDirectory() as t:
            _, latest = ng.paths(d=t)
            latest.write_text("not json")
            self.assertIn("net:receipt-unavailable", ng.alarm_problems(d=t))

    def test_legacy_or_wrong_host_receipt_is_not_clean(self):
        """Check that legacy or wrong host receipt is not clean."""
        with tempfile.TemporaryDirectory() as t:
            _, latest = ng.paths(d=t)
            latest.write_text(json.dumps({"checked": 1, "host": ng.HOST, "problems": {}}))
            self.assertIn("net:sensor-unavailable", ng.alarm_problems(d=t))
            latest.write_text(json.dumps({"checked": 1, "host": "other-host", "complete": True, "problems": {}}))
            self.assertIn("net:receipt-unavailable", ng.alarm_problems(d=t))

    def test_gateway_and_resolver_disappearance_are_reported(self):
        """Check that gateway and resolver disappearance are reported."""
        base = self.snap()
        now = dict(base, gateway_mac=None, resolvers=[])
        p = ng.compare(base, now)
        self.assertIn("net:gateway-mac-unavailable", p)
        self.assertIn("net:resolvers-missing", p)
        self.assertIn("net:gateway-missing", ng.compare(base, dict(now, gateway=None)))

    def test_ipv6_hostport_and_arp(self):
        """Check that ipv6 hostport and arp."""
        self.assertEqual(ng.split_hostport("[fe80::1%wlan0]:546"), ("fe80::1", "546"))
        self.assertEqual(ng.parse_arp_a("? (192.0.2.1) at a:b:c:" "0:0:1 on en0 ifscope [ethernet]"), {"192.0.2.1": "0a:0b:0c:" "00:00:01"})

class LearnReceiptTests:
    """learn writes one receipt line per success; temp dirs only, never the real data/."""
    FIELDS = {"time", "time_utc", "user", "terminal", "parent_cmd", "argv", "host", "tool",
              "baseline_file", "baseline_before", "baseline_after"}

    def setUp(self):
        """Create the scratch state this test needs."""
        self.t = tempfile.TemporaryDirectory(); self.d = Path(self.t.name)
        self.addCleanup(self.t.cleanup)

    def lines(self, host=None):
        """Helper: lines."""
        f = self.d / f"learn_receipts.{host or MOD.socket.gethostname().split('.')[0]}.jsonl"
        return [json.loads(x) for x in f.read_text().splitlines()]

    def test_one_line_all_fields(self):
        """Check that one line all fields."""
        self.learn()
        (r,) = self.lines()
        self.assertEqual(set(r), self.FIELDS)
        self.assertEqual(r["tool"], TOOL)
        self.assertIsNone(r["baseline_before"])
        self.assertEqual(len(r["baseline_after"]), 64)
        self.assertRegex(r["time"], r"[+-]\d\d:\d\d$")
        self.assertTrue(r["time_utc"].endswith("+00:00"))

    def test_hashes_differ_when_changed_equal_when_not(self):
        """Check that hashes differ when changed equal when not."""
        self.learn(); self.learn()
        a, b = self.lines()
        self.assertEqual(b["baseline_before"], a["baseline_after"])
        self.assertEqual(b["baseline_before"], b["baseline_after"])  # unchanged
        self.change(); self.learn()
        c = self.lines()[2]
        self.assertNotEqual(c["baseline_before"], c["baseline_after"])

    def test_two_learns_two_lines(self):
        """Check that two learns two lines."""
        self.learn(); self.learn()
        self.assertEqual(len(self.lines()), 2)

    def test_unwritable_receipt_warns_and_learn_succeeds(self):
        """Check that unwritable receipt warns and learn succeeds."""
        host = MOD.socket.gethostname().split(".")[0]
        (self.d / f"learn_receipts.{host}.jsonl").mkdir()  # cannot be opened for append, even as root
        err = io.StringIO()
        with mock.patch("sys.stderr", err):
            self.learn()
        self.assertIn("learn receipt NOT written:", err.getvalue())
        self.assertTrue(self.baseline().exists())

    def test_redaction_of_planted_token(self):
        """Check that redaction of planted token."""
        self.assertNotIn("abc123", MOD._redact("run.sh token=abc123 --x"))
        self.assertNotIn("abc123", MOD._redact("run.sh --password abc123"))
        self.assertIn("run.sh", MOD._redact("run.sh token=abc123"))
        with mock.patch.object(sys, "argv", ["x", "learn", "secret=abc123"]):
            self.learn()
        self.assertNotIn("abc123", json.dumps(self.lines()))

    def test_receipt_file_is_per_host(self):
        """Check that receipt file is per host."""
        with mock.patch.object(MOD.socket, "gethostname", return_value="boxA.local"):  # leakguard:allow
            self.learn()
        self.assertTrue((self.d / "learn_receipts.boxA.jsonl").exists())
        self.assertEqual(self.lines("boxA")[0]["host"], "boxA")
        with mock.patch.object(MOD.socket, "gethostname", return_value="boxB"):
            self.learn()
        self.assertEqual(len(self.lines("boxA")), 1); self.assertEqual(len(self.lines("boxB")), 1)

MOD, TOOL = ng, "net_guard"


class NetLearnReceipts(LearnReceiptTests, unittest.TestCase):
    """Tests for: Net Learn Receipts."""
    listeners = SS_L
    def learn(self):  # snapshot embeds time.time() ("at"); freeze it so an unchanged network gives identical bytes
        """Helper: learn."""
        with mock.patch.object(ng.time, "time", return_value=1000.0):
            ng.learn(d=self.d, runner=runner(listeners=self.listeners), os_name="Linux")
    def baseline(self):
        """Return the path of the baseline file under test."""
        return ng.paths(d=self.d)[0]
    def change(self):
        """Add one new listener that the guard should report."""
        self.listeners = SS_L + "tcp LISTEN 0 1 *:9999 *:*\n"


class AllowListenTests(unittest.TestCase):
    """Reviewed listeners in the opt-in allow file are skipped; anything else still alarms."""
    def test_allowed_listener_is_skipped_others_alarm(self):
        """Check that allowed listener is skipped others alarm."""
        base = {"exposed": []}
        now = {"exposed": [{"proto": "tcp", "addr": "0.0.0.0", "port": 27500, "prog": "passimd"},
                           {"proto": "tcp", "addr": "0.0.0.0", "port": 9999, "prog": "evil"}]}
        self.assertEqual(sorted(ng.compare(base, now, allow={("tcp", 27500, "passimd")})), ["net:listener:tcp/9999"])
        self.assertEqual(len(ng.compare(base, now, allow=set())), 2)

    def test_missing_allow_file_allows_nothing(self):
        """Check that missing allow file allows nothing."""
        self.assertEqual(ng.allowed_listeners("/nonexistent/allow.json"), set())

    def test_empty_env_values_use_the_default_file(self):
        """Check that empty env values use the default file."""
        with mock.patch.dict(os.environ, {"TWU_NET_ALLOW_LISTEN_FILE": "", "TWU_NET_ALLOW_LISTEN_SHA256": "",
                                          "TWU_NET_ALLOW_OUTBOUND_FILE": "", "TWU_NET_ALLOW_OUTBOUND_SHA256": ""}):
            with tempfile.TemporaryDirectory() as d, mock.patch.object(ng, "DIR", Path(d)):
                (Path(d) / "allow_listen.json").write_text(json.dumps({"allow": [{"proto": "udp", "port": 40000, "prog": "x"}]}))
                self.assertEqual(ng.allowed_listeners(), {("udp", 40000, "x")})
                self.assertEqual(ng.allowed_outbound(), set())

    def test_udp_exemption_is_exact_and_hash_pinned(self):
        """Check that udp exemption is exact and hash pinned."""
        import hashlib
        base = {"exposed": []}
        now = {"exposed": [{"proto": "udp", "addr": "0.0.0.0", "port": 40000, "prog": "syncapp"},
                           {"proto": "udp", "addr": "0.0.0.0", "port": 40001, "prog": "syncapp"}]}
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "allow.json"
            f.write_bytes(json.dumps({"allow": [{"proto": "udp", "port": 40000, "prog": "syncapp"}]}).encode())
            env = {"TWU_NET_ALLOW_LISTEN_FILE": str(f), "TWU_NET_ALLOW_LISTEN_SHA256": hashlib.sha256(f.read_bytes()).hexdigest()}
            with mock.patch.dict(os.environ, env):
                self.assertEqual(sorted(ng.compare(base, now)), ["net:listener:udp/40001"])   # only the exact port is exempt
                f.write_bytes(f.read_bytes() + b" ")                                          # tamper: pin no longer matches
                with self.assertRaises(ng.ProbeUnavailable):
                    ng.compare(base, now)
                ng.learn(d=Path(d) / "state", runner=runner(), os_name="Linux")
                r = ng.check(d=Path(d) / "state", runner=runner(), os_name="Linux")
                self.assertIn("net:sensor-unavailable", r["problems"])


class TrustedCommandTests(unittest.TestCase):
    """External tools are found only in a fixed list of system directories, never through PATH."""
    def test_path_entry_cannot_replace_a_tool(self):
        """Check that path entry cannot replace a tool."""
        with tempfile.TemporaryDirectory() as d:
            fake = Path(d) / "lsof"; fake.write_text("#!/bin/sh\necho pwned\n"); fake.chmod(0o755)
            with mock.patch.dict(os.environ, {"PATH": d}):
                got = ng.trusted_command("ps")
            self.assertNotEqual(os.path.dirname(got), d)
            self.assertIn(os.path.dirname(got), ng.TRUSTED_DIRS)

    def test_unknown_or_user_owned_tool_is_unavailable(self):
        """Check that unknown or user owned tool is unavailable."""
        with self.assertRaises(ng.ProbeUnavailable):
            ng.trusted_command("definitely-not-a-system-tool")
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "tool").write_text("x"); (Path(d) / "tool").chmod(0o755)   # owned by this user, not root
            with mock.patch.object(ng, "TRUSTED_DIRS", (d,)):
                with self.assertRaises(ng.ProbeUnavailable):
                    ng.trusted_command("tool")

    def test_run_uses_the_absolute_path(self):
        """Check that run uses the absolute path."""
        seen = {}
        def fake_run(cmd, **kw):
            """Helper: fake run."""
            seen["cmd"] = cmd
            return mock.Mock(returncode=0, stdout="ok")
        with mock.patch.object(ng.subprocess, "run", fake_run):
            self.assertEqual(ng.run(["ps", "-x"]), "ok")
        self.assertTrue(os.path.isabs(seen["cmd"][0]))
        self.assertEqual(seen["cmd"][1:], ["-x"])


class EmptyEnvTests(unittest.TestCase):
    """An exported but empty variable (a copied config.example.env) must behave like an unset one."""
    def test_empty_root_falls_back_to_the_folder_above_scripts(self):
        """Check that empty root falls back to the folder above scripts."""
        code = "import net_guard as n; print(n.ROOT)"
        env = dict(os.environ, TWU_ROOT="", PYTHONPATH=str(Path(__file__).resolve().parent))
        out = subprocess.run([sys.executable, "-B", "-c", code], env=env, capture_output=True, text=True, cwd=tempfile.gettempdir())
        self.assertEqual(out.stdout.strip(), str(Path(__file__).resolve().parent.parent), out.stderr)


class RedTeam5(unittest.TestCase):
    """Seat-5 bypass hunt: each test failed against the first release."""
    def test_baseline_and_receipt_are_not_written_through_a_symlink(self):
        """A symlink planted at a .tmp name or at the baseline name must not redirect the write onto another file."""
        with tempfile.TemporaryDirectory() as t:
            d = Path(t) / "state"; d.mkdir(); victim = Path(t) / "victim.txt"; victim.write_text("keep")
            base, latest = ng.paths(d=d)
            os.symlink(victim, d / (latest.name + ".tmp")); os.symlink(victim, d / (base.name + ".tmp"))
            ng.learn(d, runner(), "Linux")  # baseline saved
            ng.check(d, runner(), "Linux")
            self.assertEqual(victim.read_text(), "keep")
            os.unlink(base); os.symlink(victim, base)            # a symlink AT the baseline name is replaced, not followed
            ng.learn(d, runner(), "Linux")
            self.assertEqual(victim.read_text(), "keep")

    def test_nobody_owned_tool_is_trusted_only_inside_a_user_namespace(self):
        """uid 65534 is root inside an unprivileged user namespace; on an ordinary host it is just 'nobody' and is refused."""
        with tempfile.TemporaryDirectory() as d:
            ident, ns = Path(d) / "ident", Path(d) / "ns"
            ident.write_text("0 0 4294967295\n"); ns.write_text("0 1000 1\n")
            with mock.patch.object(ng, "UID_MAP", str(ident)):
                self.assertTrue(ng._trusted_owner(0)); self.assertFalse(ng._trusted_owner(65534))
            with mock.patch.object(ng, "UID_MAP", str(ns)):
                self.assertTrue(ng._trusted_owner(65534)); self.assertFalse(ng._trusted_owner(1000))


if __name__ == "__main__":
    unittest.main()


class HelpNeverRunsACommand(unittest.TestCase):
    """`net_guard.py learn --help`-style calls silently re-saved the security baseline. A help request must be inert."""

    def test_help_flags_print_usage_and_change_nothing(self):
        """Check that help flags print usage and change nothing."""
        import io
        import contextlib
        import net_guard
        for flags in (["--help"], ["-h"], ["help"], ["learn", "--help"], ["learn", "-h"]):
            saved = []
            real_learn, real_learn_only = net_guard.learn, net_guard.learn_only
            net_guard.learn = lambda *a, **k: saved.append("learn")
            net_guard.learn_only = lambda *a, **k: saved.append("learn_only")
            buf = io.StringIO()
            try:
                with contextlib.redirect_stdout(buf):
                    rc = net_guard.main(flags)
            finally:
                net_guard.learn, net_guard.learn_only = real_learn, real_learn_only
            self.assertEqual((rc, saved), (0, []), flags)
            self.assertIn("net_guard", buf.getvalue())
