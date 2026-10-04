"""Integration harness used by client-runtime-e2e.sh, isolated local fixtures."""
import argparse
import contextlib
import copy
import http.server
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading
import time

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("client_runtime", root / "lib/client_runtime.py")
rt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rt)
work, xr, sb, first_pid = sys.argv[1:]
work = Path(work)


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"onebox-real-proxy-test" if self.path == "/health" else b"x" * 1048576
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            for i in range(0, len(body), 8192):
                self.wfile.write(body[i:i + 8192])
                if self.path != "/health":
                    time.sleep(0.002)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_POST(self):
        remaining = int(self.headers["Content-Length"])
        while remaining:
            data = self.rfile.read(min(65536, remaining))
            if not data:
                return
            remaining -= len(data)
        self.send_response(204)
        self.end_headers()

    def log_message(self, *args):
        pass


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
url = "http://127.0.0.1:%d" % server.server_port
bundle = work / "bundle.json"
entries = rt.load_bundle(bundle)["entries"]
args = argparse.Namespace(xray=xr, singbox=sb, url=url + "/health", timeout=3, ca=None, samples=2,
                          entries=None, bytes=131072, download_url=url + "/data", upload_url=url + "/upload", output=None)
forwarder = None
restarted = None
try:
    with contextlib.redirect_stdout(io.StringIO()) as captured:
        result = rt.bench(entries, args)
    report = json.loads(captured.getvalue())
    assert result == 0, report
    for e in report["entries"]:
        assert e["request_failure_rate"] == 0, e
        assert e["transfers"]["download"]["received_bytes"] == 131072, e
        assert e["transfers"]["upload"]["sent_bytes"] == 131072, e
        assert e["loaded_ttfb_ms"] is not None, e
    print("PASS real-core handshake/download/upload/loaded-latency (%d entries)" % len(entries))
    tcp = [e for e in entries if "tcp-" in e["id"]]
    udp = [e for e in entries if "udp-" in e["id"]]
    selected = [tcp[0], udp[0] if udp else tcp[1]]
    wrong = copy.deepcopy(tcp[0])
    wrong["outbounds"][0]["settings"]["servers"][0]["password"] = "AAAAAAAAAAAAAAAAAAAAAA=="
    with rt.Core(wrong, args) as core:
        assert not rt.safe_request(core, args.url, args.timeout)["ok"]
    print("PASS wrong credentials cannot silently use direct connection")

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    log_path = work / "failover.log"
    with log_path.open("w") as log:
        forwarder = subprocess.Popen([sys.executable, str(root / "lib/client_runtime.py"), "failover", str(bundle),
                                      "--xray", xr, "--singbox", sb, "--entries", ",".join(e["id"] for e in selected),
                                      "--url", args.url, "--port", str(port), "--interval", "1", "--timeout", "1",
                                      "--failures", "2", "--recoveries", "2", "--cooldown", "3"], stdout=log, stderr=log)

    def wait_for(predicate, timeout=18):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return
            if forwarder.poll() is not None:
                raise AssertionError(log_path.read_text())
            time.sleep(0.1)
        raise AssertionError("timeout: " + log_path.read_text())

    def events():
        return [json.loads(line) for line in log_path.read_text().splitlines() if line.startswith("{")]

    def curl():
        result = subprocess.run(["curl", "--noproxy", "", "--socks5-hostname", "127.0.0.1:%d" % port,
                                 "-fsS", "--max-time", "4", args.url], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        assert result.returncode == 0 and result.stdout == b"onebox-real-proxy-test", result

    wait_for(lambda: any(e.get("event") == "ready" for e in events()))
    curl()
    os.kill(int(first_pid), signal.SIGTERM)
    wait_for(lambda: any(e.get("to") == selected[1]["id"] for e in events()))
    curl()
    print("PASS failover switches new TCP requests to live %s backup" % selected[1]["transport"])
    restarted = subprocess.Popen([xr, "run", "-c", str(work / "tcp-a.json")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    wait_for(lambda: sum(e.get("to") == tcp[0]["id"] for e in events()) >= 2)
    curl()
    print("PASS recovery returns to primary after streak and cooldown")
    forwarder.terminate()
    assert forwarder.wait(timeout=8) == 0
    print("PASS signal shuts down client cores and SOCKS listener")
finally:
    for proc in (forwarder, restarted):
        if proc and proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=8)
    server.shutdown()
    server.server_close()
    thread.join()
