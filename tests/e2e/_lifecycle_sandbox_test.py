#!/usr/bin/env python3
"""Unit tests for the lifecycle/upgrade sandbox helpers (no root needed).

Run: ``python3 tests/e2e/_lifecycle_sandbox_test.py`` (CI: lint job). The
name starts with ``_`` so the black-box loop does not run it as a suite.
"""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import unittest.mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _lifecycle_fixtures as fx  # noqa: E402
import _lifecycle_host as host  # noqa: E402
import _lifecycle_sandbox as sb  # noqa: E402


class TreeDigestTest(unittest.TestCase):
    def test_records_kind_mode_content_and_honors_exclusions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "d").mkdir(mode=0o700)
            (root / "d/f").write_text("x")
            (root / "d/f").chmod(0o600)
            (root / "skip").mkdir()
            (root / "skip/g").write_text("y")
            (root / "link").symlink_to("d/f")
            tree = sb.tree_digest(root, exclude=["skip"])
            self.assertEqual(set(tree), {"d", "d/f", "link"})
            self.assertEqual(tree["d"], "dir 0o700")
            self.assertEqual(tree["d/f"], "file 0o600 " + sb.sha256_bytes(b"x"))
            self.assertEqual(tree["link"], "link d/f")
            (root / "d/f").write_text("z")
            changed = sb.tree_digest(root, exclude=["skip"])
            self.assertEqual(sb.describe_diff(tree, changed).count("\n"), 0)
            self.assertIn("d/f", sb.describe_diff(tree, changed))
            with self.assertRaises(sb.SandboxError):
                sb.assert_same_tree(tree, changed, "tree")

    def test_missing_root_is_empty(self):
        self.assertEqual(sb.tree_digest(Path("/nonexistent/onebox-sandbox-test")), {})


class SandboxTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ob-sbt-")
        work = Path(self.tmp.name)
        binary = work / "fake-onebox"
        binary.write_text("#!/bin/false\n")
        binary.chmod(0o755)
        self.s = sb.Sandbox(work / "s", binary, binary)

    def tearDown(self):
        self.s.cleanup()
        self.tmp.cleanup()

    def helper(self, name, *args, stdin=""):
        return subprocess.run([str(self.s.helpers / name), *args], env=self.s.env, input=stdin,
                              capture_output=True, text=True, timeout=30)

    def test_environment_is_isolated(self):
        env = self.s.env
        self.assertEqual(env["PATH"], str(self.s.helpers))
        self.assertEqual(env["ONEBOX_INIT"], "none")
        self.assertEqual(env["ONEBOX_DIR"], str(self.s.etc))
        for key, value in env.items():
            if key.startswith("ONEBOX_") and key in sb.LAYOUT:
                self.assertTrue(value.startswith(str(self.s.root)), key)
        self.assertNotIn("GH_TOKEN", env)
        self.assertEqual([k for k in env if k.startswith("ONEBOX_TEST")], [])

    def test_helpers_need_no_environment(self):
        # Onebox starts daemons with a cleared environment and PATH=SAFE_PATH;
        # a helper they reach still records into its own sandbox.
        proc = subprocess.run([str(self.s.helpers / "ufw"), "status"], env={"PATH": "/usr/bin:/bin"},
                              capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(self.s.commands()[-1]["argv"], ["ufw", "status"])

    def test_iptables_store_semantics(self):
        rule = ["INPUT", "-p", "tcp", "--dport", "1", "-j", "ACCEPT"]
        self.assertEqual(self.helper("iptables", "-w", "5", "-C", *rule).returncode, 1)
        self.assertEqual(self.helper("iptables", "-w", "5", "-I", "INPUT", "1", *rule[1:]).returncode, 0)
        self.assertEqual(self.helper("iptables", "-w", "5", "-C", *rule).returncode, 0)
        listed = self.helper("iptables", "-w", "5", "-S", "INPUT").stdout
        self.assertEqual(listed.strip(), "-A " + " ".join(rule))
        self.assertEqual(self.helper("iptables", "-w", "5", "-D", *rule).returncode, 0)
        self.assertEqual(self.helper("iptables", "-w", "5", "-D", *rule).returncode, 1)
        self.assertEqual(self.s.firewall_rules(), {"iptables-filter.json": []})
        self.assertEqual(self.s.forbidden_calls(), [])
        self.assertEqual(self.helper("iptables", "-t", "nat", "-F").returncode, fx.BLOCKED_EXIT)
        self.assertEqual(self.s.forbidden_calls(), [["iptables", "-t", "nat", "-F"]])

    def test_refused_calls_of_emulated_programs_are_forbidden(self):
        # Onebox tolerates a failing firewall backend (best effort), so an
        # unsupported call must be reported by the sandbox itself.
        refused = [["ufw", "allow", "1/tcp"], ["iptables", "-t", "nat", "-F"],
                   ["iptables", "-w", "5", "-t", "nat", "-N", "X"], ["nft", "-f", "/dev/null"],
                   ["firewall-cmd", "--add-port=1/tcp"], ["crontab", "-"], ["crontab", "-r"],
                   ["ip", "route", "add", "default"], ["tail", "-f", "x"]]
        for argv in refused:
            with self.subTest(argv=argv):
                proc = self.helper(*argv)
                self.assertEqual(proc.returncode, fx.BLOCKED_EXIT)
                self.assertIn("BLOCKED", proc.stderr)
        self.assertEqual(self.helper("ufw", "status").returncode, 0)
        self.assertEqual(self.s.forbidden_calls(), refused)
        self.assertTrue(all(row["refused"] for row in self.s.refused()))

    def test_crontab_round_trip_stays_inside_the_sandbox(self):
        self.assertEqual(self.helper("crontab", "-l").returncode, 1)
        table = self.s.root / "tmp/new-table"
        table.write_text("@reboot true # onebox:boot:x\n")
        self.assertEqual(self.helper("crontab", str(table)).returncode, 0)
        self.assertEqual(self.helper("crontab", "-l").stdout, "@reboot true # onebox:boot:x\n")
        self.assertEqual(self.s.crontab(), ["@reboot true # onebox:boot:x"])
        outside = self.helper("crontab", "/etc/hostname")
        self.assertEqual(outside.returncode, fx.BLOCKED_EXIT)
        self.assertIn("outside the sandbox", outside.stderr)
        self.assertEqual(self.s.forbidden_calls(), [["crontab", "/etc/hostname"]])

    def test_blocked_programs_and_offline_curl(self):
        blocked = self.helper("systemctl", "restart", "nginx")
        self.assertEqual(blocked.returncode, fx.BLOCKED_EXIT)
        self.assertIn("BLOCKED", blocked.stderr)
        self.assertEqual(self.helper("curl", "-fsS", "https://api.ipify.org").returncode, 6)
        self.assertEqual(self.helper("curl", "-fsS", "https://example.com/x").returncode, 6)
        self.assertEqual(self.s.forbidden_calls(),
                         [["systemctl", "restart", "nginx"], ["curl", "-fsS", "https://example.com/x"]])

    def test_served_downloads_and_release(self):
        payload = self.s.root / "tmp/payload"
        payload.write_bytes(b"\x7fELF fake")
        self.s.publish_release(payload, "9.9.9")
        name = f"onebox-linux-{sb.release_arch()}-musl"
        url = f"https://github.com/{sb.REPOSITORY}/releases/download/v9.9.9/{name}"
        out = self.s.root / "tmp/out"
        self.assertEqual(self.helper("curl", "--output", str(out), url).returncode, 0)
        self.assertEqual(out.read_bytes(), b"\x7fELF fake")
        meta = self.s.root / "tmp/meta.json"
        api = f"https://api.github.com/repos/{sb.REPOSITORY}/releases/latest"
        self.assertEqual(self.helper("curl", "--output", str(meta), api).returncode, 0)
        asset = json.loads(meta.read_text())["assets"][0]
        self.assertEqual(asset["digest"], "sha256:" + sb.sha256_bytes(b"\x7fELF fake"))
        self.assertEqual(asset["browser_download_url"], url)
        self.assertEqual(self.s.forbidden_calls(), [])

    def test_commands_are_recorded_with_their_caller(self):
        self.helper("ufw", "status")
        rows = self.s.commands()
        self.assertEqual(rows[-1]["argv"], ["ufw", "status"])
        self.assertTrue(rows[-1]["caller"])

    def test_hang_point_freezes_one_call(self):
        with self.s.hang("ufw", "status") as frozen:
            proc = subprocess.Popen([str(self.s.helpers / "ufw"), "status"], env=self.s.env,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            pid = frozen(timeout=20)
            self.assertEqual(pid, proc.pid)
            self.assertIsNone(proc.poll())
            self.assertEqual(self.helper("ufw", "enable").returncode, fx.BLOCKED_EXIT)
        self.assertEqual(proc.wait(timeout=10), -9)
        self.assertEqual(self.helper("ufw", "status").returncode, 0)

    def test_node_lock_is_held_on_fd_198(self):
        self.s.etc.mkdir()
        with self.s.hold_node_lock() as env:
            self.assertEqual(env, {"ONEBOX_INHERITED_LOCK_FD": "198"})
            self.assertTrue(os.get_inheritable(sb.INHERITED_LOCK_FD))
            other = os.open(self.s.lock_path, os.O_RDWR)
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(other)
        other = os.open(self.s.lock_path, os.O_RDWR)
        try:
            fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(other)

    def test_start_failures_and_processes(self):
        self.s.fail_starts(2)
        self.assertEqual((self.s.root / "fail-start").read_text(), "2")
        # A process naming the sandbox on its command line counts as a sandbox process.
        sleeper = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)", str(self.s.root)])
        try:
            deadline = time.monotonic() + 5
            while sleeper.pid not in self.s.processes() and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertIn(sleeper.pid, self.s.processes())
            self.s.cleanup()
            self.assertIsNotNone(sleeper.wait(timeout=10))
        finally:
            sleeper.kill()

    def test_processes_match_whole_path_components(self):
        # lifecycle.py runs "<label>" and "<label>-v1" sandboxes side by side.
        sibling = sb.Sandbox(self.s.root.with_name(self.s.root.name + "-v1"), self.s.binary, self.s.binary)
        sleepers = [subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)", arg])
                    for arg in (f"{sibling.root}/x", str(sibling.root), f"--dir={self.s.root}/y")]
        try:
            deadline = time.monotonic() + 5
            while len(sibling.processes()) < 2 and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertEqual(sorted(sibling.processes()), sorted(p.pid for p in sleepers[:2]))
            self.assertEqual(self.s.processes(), [sleepers[2].pid])
        finally:
            for sleeper in sleepers:
                sleeper.kill()
                sleeper.wait()

    def test_logs_lists_the_service_logs(self):
        self.assertEqual(self.s.logs(), [])
        (self.s.root / "log").mkdir()
        for name in ("onebox-sing-box.log", "onebox-network.log"):
            (self.s.root / "log" / name).write_text("")
        self.assertEqual(self.s.logs(), ["onebox-network.log", "onebox-sing-box.log"])

    def test_pid_records(self):
        self.s.run_dir.mkdir()
        self.assertIsNone(self.s.pid_record("onebox-x"))
        (self.s.run_dir / "onebox-x.pid").write_text(json.dumps({"pid": os.getpid(), "start": 1}))
        self.assertIsNone(self.s.service_pid("onebox-x"))  # wrong start time
        (self.s.run_dir / "onebox-x.pid").write_text(str(os.getpid()))
        self.assertEqual(self.s.service_pid("onebox-x"), os.getpid())


IPTABLES_SAVE = """# Generated by iptables-save v1.8.10 (nf_tables) on Fri Oct  9 06:08:03 2026
*filter
:INPUT ACCEPT [282358:153519268]
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
COMMIT
# Completed on Fri Oct  9 06:08:03 2026
"""


class HostGuardTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ob-hgt-")
        self.work = Path(self.tmp.name)
        self.rules = self.work / "rules"
        self.rules.write_text(IPTABLES_SAVE)
        self.probes = [(shutil.which("cat"), str(self.rules))]
        binary = self.work / "fake-onebox"
        binary.write_text("#!/bin/false\n")
        binary.chmod(0o755)
        self.binary = binary

    def tearDown(self):
        self.tmp.cleanup()

    def test_counters_and_timestamps_are_not_changes(self):
        before = host.host_state(self.probes)
        self.rules.write_text(IPTABLES_SAVE.replace("282358:153519268", "282999:153600000")
                              .replace("06:08:03", "06:19:45")
                              + "table ip t {\n  counter packets 1 bytes 2\n"
                              + "  elements = { 192.0.2.1 timeout 1h expires 59m58s }\n}\n")
        changed = host.host_state(self.probes)
        self.rules.write_text(IPTABLES_SAVE + "table ip t {\n  counter packets 9 bytes 99\n"
                              + "  elements = { 192.0.2.1 timeout 1h expires 12m3s }\n}\n")
        self.assertEqual(host.state_changes(changed, host.host_state(self.probes)), [])
        self.assertEqual(len(host.state_changes(before, changed)), 1)

    def test_cleanup_fails_when_the_host_changed(self):
        s = sb.Sandbox(self.work / "s", self.binary, self.binary, host_probes=self.probes)
        s.cleanup()
        self.rules.write_text(IPTABLES_SAVE.replace("--dport 22", "--dport 443"))
        with self.assertRaises(sb.SandboxError) as raised:
            s.cleanup()
        self.assertIn("--dport 443", str(raised.exception))

    def test_default_probes_use_absolute_programs(self):
        for argv in host.host_probes():
            self.assertTrue(Path(argv[0]).is_absolute(), argv)
            self.assertNotEqual(Path(argv[0]).parent, host.SEAL_POINT)

    def test_tripwire_logs_refuses_and_fails_the_sandbox(self):
        tripwire = host.write_tripwire(self.work / "tripwire")
        self.assertIn("iptables", fx.TRIPWIRE)
        self.assertTrue({"crontab", "nft", "ufw", "systemctl", "sysctl"} <= set(fx.TRIPWIRE))
        self.assertFalse({"sh", "python3", "tail"} & set(fx.TRIPWIRE))
        s = sb.Sandbox(self.work / "s", self.binary, self.binary, tripwire=tripwire,
                       host_probes=self.probes)
        proc = subprocess.run([str(self.work / "tripwire/iptables"), "-A", "INPUT"], env={},
                              capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, fx.BLOCKED_EXIT)
        self.assertEqual([row["argv"] for row in tripwire.calls()], [["iptables", "-A", "INPUT"]])
        self.assertEqual(s.forbidden_calls(), [["(host)", "iptables", "-A", "INPUT"]])
        probe = subprocess.run([str(self.work / "tripwire/nginx"), "-T", "-q"], env={},
                               capture_output=True, text=True, timeout=30)
        self.assertEqual(probe.returncode, 1)
        self.assertEqual(tripwire.calls()[-1]["probe"], True)
        self.assertEqual(s.forbidden_calls(), [["(host)", "iptables", "-A", "INPUT"]])
        with self.assertRaises(sb.SandboxError):
            s.cleanup()
        later = sb.Sandbox(self.work / "later", self.binary, self.binary, tripwire=tripwire,
                           host_probes=self.probes)
        self.assertEqual(later.forbidden_calls(), [])
        later.cleanup()

    def test_check_seal_requires_the_tripwire_first_in_path(self):
        tripwire = host.write_tripwire(self.work / "tripwire")
        host.check_seal(tripwire, path=str(self.work / "tripwire"))
        self.assertEqual(tripwire.calls(), [])  # the check forgets its own call
        (self.work / "empty").mkdir()
        with self.assertRaises(host.HostError):
            host.check_seal(tripwire, path=str(self.work / "empty"))

    def test_seal_needs_root(self):
        with unittest.mock.patch("os.geteuid", return_value=1000), \
                self.assertRaises(host.SealUnavailable):
            host.seal(self.work)


class PortsTest(unittest.TestCase):
    def test_free_ports_are_distinct_and_bindable(self):
        used: set[int] = set()
        ports = [sb.free_port(used) for _ in range(3)]
        self.assertEqual(len(set(ports)), 3)
        self.assertEqual(used, set(ports))
        for port in ports:
            self.assertFalse(sb.port_open(port))


if __name__ == "__main__":
    unittest.main()
