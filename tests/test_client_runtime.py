"""Safety boundaries and state-machine behavior, without public network access."""
import copy
import http.server
import importlib.util
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("client_runtime", ROOT / "lib/client_runtime.py")
rt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rt)


class Tests(unittest.TestCase):
    def test_failures_are_consecutive(self):
        p = rt.FailoverPolicy(2, 3, 2, 60)
        self.assertEqual(p.update([True, True], 0), 0)
        self.assertEqual(p.update([False, True], 1), 0)
        self.assertEqual(p.update([True, True], 2), 0)
        self.assertEqual(p.update([False, True], 3), 0)
        self.assertEqual(p.update([False, True], 4), 0)
        self.assertEqual(p.update([False, True], 5), 1)

    def test_recovery_requires_streak_and_cooldown(self):
        p = rt.FailoverPolicy(2, 2, 3, 60)
        p.update([True, True], 0)
        p.update([False, True], 1)
        self.assertEqual(p.update([False, True], 2), 1)
        for t in (3, 4, 5, 61):
            self.assertEqual(p.update([True, True], t), 1)
        self.assertEqual(p.update([True, True], 62), 0)

    def test_dead_active_bypasses_cooldown_and_never_direct(self):
        p = rt.FailoverPolicy(2, 1, 1, 60)
        self.assertEqual(p.update([True, True], 0), 0)
        self.assertEqual(p.update([False, True], 1), 1)
        self.assertIsNone(p.update([False, False], 2))
        self.assertEqual(p.update([True, False], 3), 0)

    def test_never_select_unhealthy_backup(self):
        p = rt.FailoverPolicy(3, 1, 2, 0)
        p.update([True, False, True], 0)
        self.assertEqual(p.update([False, True, True], 1), 2)
        self.assertEqual(p.update([False, True, True], 2), 1)

    def test_native_outbound_only_and_unique_id(self):
        entry = {"id": "a", "core": "singbox", "transport": "tcp", "tag": "x",
                 "outbounds": [{"type": "vless", "tag": "x"}]}
        with tempfile.TemporaryDirectory() as work:
            path = Path(work) / "bundle.json"
            def save(items):
                path.write_text(json.dumps({"schema": 1, "entries": items}))
            save([entry])
            self.assertEqual(rt.load_bundle(path)["entries"][0]["id"], "a")
            save([entry, entry])
            with self.assertRaises(ValueError):
                rt.load_bundle(path)
            bad = copy.deepcopy(entry)
            bad["outbounds"][0]["type"] = "direct"
            save([bad])
            with self.assertRaises(ValueError):
                rt.load_bundle(path)
            path.write_bytes(b"a" * (rt.MAX_BUNDLE + 1))
            with self.assertRaises(ValueError):
                rt.load_bundle(path)

    def test_output_permissions_and_no_clobber(self):
        with tempfile.TemporaryDirectory() as work:
            path = Path(work) / "report.json"
            rt.private_json(path, {"ok": True})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                rt.private_json(path, {})
            link = Path(work) / "link.json"
            link.symlink_to(path)
            with self.assertRaises(FileExistsError):
                rt.private_json(link, {})

    def test_url_validation(self):
        for url in ("file:///etc/passwd", "https://user:secret@example.org", "https://x/#frag", "https://x/\r\nInjected:yes"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                rt.url_parts(url)

    def test_selection_defaults_and_invalid_ids(self):
        entries = [{"id": "quic", "transport": "udp"}, {"id": "tcp", "transport": "tcp"}, {"id": "more", "transport": "tcp"}]
        self.assertEqual([e["id"] for e in rt.ordered(entries, default_pair=True)], ["tcp", "quic"])
        self.assertEqual([e["id"] for e in rt.ordered(entries, "more,tcp")], ["more", "tcp"])
        for ids in ("tcp,tcp", "missing"):
            with self.assertRaises(ValueError):
                rt.ordered(entries, ids)

    def test_http_transfer_cap_and_reject_status(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(503 if self.path == "/failed" else 200)
                self.send_header("Content-Length", "200000")
                self.end_headers()
                try:
                    self.wfile.write(b"x" * 200000)
                except (BrokenPipeError, ConnectionResetError):
                    pass
            def log_message(self, *args):
                pass
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = "http://127.0.0.1:%d" % server.server_port
            result = rt.request(None, url, limit=1024)
            self.assertEqual(result["received_bytes"], 1024)
            self.assertTrue(result["ok"])
            self.assertFalse(rt.safe_request(None, url + "/failed")["ok"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_relay_half_close_and_response(self):
        a, left = socket.socketpair()
        right, b = socket.socketpair()
        errors = []
        def run():
            try:
                rt.relay(left, right)
            except Exception as exc:
                errors.append(exc)
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        try:
            for sock in (a, b):
                sock.settimeout(3)
            a.sendall(b"request")
            a.shutdown(socket.SHUT_WR)
            self.assertEqual(rt.read_exact(b, 7), b"request")
            self.assertEqual(b.recv(1), b"")
            b.sendall(b"response")
            b.shutdown(socket.SHUT_WR)
            self.assertEqual(rt.read_exact(a, 8), b"response")
            self.assertEqual(a.recv(1), b"")
            thread.join(3)
            self.assertFalse(thread.is_alive())
            self.assertFalse(errors)
        finally:
            for sock in (a, left, right, b):
                sock.close()


if __name__ == "__main__":
    unittest.main()
