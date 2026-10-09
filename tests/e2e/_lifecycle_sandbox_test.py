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
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _lifecycle_sandbox as sb  # noqa: E402


class ParseBlockYamlTest(unittest.TestCase):
    def test_accepts_the_emitted_subset(self):
        cases = [
            ("a: 1\nb: true\nc: null\nd: \"x\"\n", {"a": 1, "b": True, "c": None, "d": "x"}),
            ("list:\n  - 1\n  - \"two\"\n", {"list": [1, "two"]}),
            ("p:\n  - name: \"n\"\n    port: 443\n  - name: \"m\"\n", {"p": [{"name": "n", "port": 443}, {"name": "m"}]}),
            ("\"geosite:cn\":\n  - \"x\"\n", {"geosite:cn": ["x"]}),
            ("e: []\nf: {}\nneg: -5\n", {"e": [], "f": {}, "neg": -5}),
            ("outer:\n  inner:\n    deep: \"v\"\n  next: 2\n", {"outer": {"inner": {"deep": "v"}, "next": 2}}),
            ("- \"a\"\n- \"b\"\n", ["a", "b"]),
            ("x:\n  -\n    - 1\n", {"x": [[1]]}),
        ]
        for text, expected in cases:
            with self.subTest(text=text):
                self.assertEqual(sb.parse_block_yaml(text), expected)

    def test_rejects_everything_else(self):
        cases = [
            "",                        # empty document
            "a: bare\n",               # bare string scalar
            "a:\tb\n",                 # tab
            "a: 1\na: 2\n",            # duplicate key
            "a:\nb: 1\n",              # missing nested value
            "a: 1\n  b: 2\n",          # unexpected indentation
            "a: \"x\" y\n",            # trailing text after a string
            "{\"a\": 1}\n",            # flow mapping (JSON)
            "a: &anchor 1\n",          # anchors
        ]
        for text in cases:
            with self.subTest(text=text), self.assertRaises(ValueError):
                sb.parse_block_yaml(text)


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
        self.assertEqual(self.helper("iptables", "-t", "nat", "-F").returncode, sb.BLOCKED_EXIT)

    def test_crontab_round_trip_stays_inside_the_sandbox(self):
        self.assertEqual(self.helper("crontab", "-l").returncode, 1)
        table = self.s.root / "tmp/new-table"
        table.write_text("@reboot true # onebox:boot:x\n")
        self.assertEqual(self.helper("crontab", str(table)).returncode, 0)
        self.assertEqual(self.helper("crontab", "-l").stdout, "@reboot true # onebox:boot:x\n")
        self.assertEqual(self.s.crontab(), ["@reboot true # onebox:boot:x"])
        outside = self.helper("crontab", "/etc/hostname")
        self.assertNotEqual(outside.returncode, 0)
        self.assertIn("outside the sandbox", outside.stderr)

    def test_blocked_programs_and_offline_curl(self):
        blocked = self.helper("systemctl", "restart", "nginx")
        self.assertEqual(blocked.returncode, sb.BLOCKED_EXIT)
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
            self.assertEqual(self.helper("ufw", "enable").returncode, sb.BLOCKED_EXIT)
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

    def test_pid_records(self):
        self.s.run_dir.mkdir()
        self.assertIsNone(self.s.pid_record("onebox-x"))
        (self.s.run_dir / "onebox-x.pid").write_text(json.dumps({"pid": os.getpid(), "start": 1}))
        self.assertIsNone(self.s.service_pid("onebox-x"))  # wrong start time
        (self.s.run_dir / "onebox-x.pid").write_text(str(os.getpid()))
        self.assertEqual(self.s.service_pid("onebox-x"), os.getpid())


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
