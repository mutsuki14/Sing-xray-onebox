#!/usr/bin/env python3
"""Exercise generated frp configuration with real binaries and local fixtures."""

import base64
import hashlib
import http.client
import http.server
import json
from pathlib import Path
import re
import signal
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import threading
import time


MARKER = "onebox-frps-e2e-7d37c5"


def allocate(work):
    """Reserve both transports while choosing a small, contiguous allowed range."""
    held = []

    def reserve(port=0):
        tcp = socket.socket()
        tcp.bind(("127.0.0.1", port))
        actual = tcp.getsockname()[1]
        udp = socket.socket(type=socket.SOCK_DGRAM)
        try:
            udp.bind(("127.0.0.1", actual))
        except OSError:
            tcp.close()
            udp.close()
            raise
        held.extend((tcp, udp))
        return actual

    names = ["tcp_control", "web_control", "http_internal", "https", "redirect", "http_backend", "udp_backend"]
    ports = {name: reserve() for name in names}
    for _ in range(100):
        checkpoint = len(held)
        start = reserve()
        if start > 65525:
            held.pop().close()
            held.pop().close()
            continue
        try:
            for port in range(start + 1, start + 7):
                reserve(port)
        except OSError:
            while len(held) > checkpoint:
                held.pop().close()
            continue
        ports.update(range_start=start, range_end=start + 5)
        break
    else:
        raise RuntimeError("could not reserve a contiguous test range")
    (work / "ports.json").write_text(json.dumps(ports))
    print(" ".join(str(value) for value in ports.values()))
    for sock in held:
        sock.close()


def receive(sock, size):
    result = b""
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise EOFError("unexpected closed connection")
        result += chunk
    return result


class Backend(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.headers.get("Upgrade", "").lower() == "websocket":
            key = self.headers.get("Sec-WebSocket-Key", "")
            accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
            self.send_response(101)
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", accept)
            self.end_headers()
            self.wfile.flush()
            self.connection.settimeout(5)
            first, length = receive(self.connection, 2)
            if first != 0x81 or not length & 0x80 or length & 0x7F >= 126:
                raise ValueError("expected a short, masked text frame")
            mask = receive(self.connection, 4)
            payload = receive(self.connection, length & 0x7F)
            decoded = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
            self.connection.sendall(bytes((0x81, len(decoded))) + decoded)
            self.close_connection = True
            return
        body = json.dumps({"marker": MARKER, "host": self.headers.get("Host"),
                           "proto": self.headers.get("X-Forwarded-Proto"),
                           "forwarded_for": self.headers.get("X-Forwarded-For")}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Datagram(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)


class Runner:
    def __init__(self, work, frps, frpc, nginx):
        self.work, self.frps, self.frpc, self.nginx = work, frps, frpc, nginx
        self.ports = json.loads((work / "ports.json").read_text())
        self.processes, self.logs, self.servers = [], [], []
        self.passed = self.failed = 0

    def start(self, name, args, cwd=None):
        log = (self.work / (name + ".log")).open("wb")
        self.logs.append(log)
        process = subprocess.Popen(args, cwd=cwd, stdout=log, stderr=subprocess.STDOUT)
        self.processes.append(process)
        return process

    def close(self):
        for process in reversed(self.processes):
            if process.poll() is None:
                process.terminate()
        for process in reversed(self.processes):
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        for server in self.servers:
            server.shutdown()
            server.server_close()
        for log in self.logs:
            log.close()

    @staticmethod
    def eventually(action, timeout=12):
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            try:
                return action()
            except (OSError, EOFError, AssertionError, ValueError, http.client.HTTPException) as error:
                last = error
                time.sleep(0.1)
        raise AssertionError(f"deadline expired: {last}")

    def check(self, label, action):
        try:
            action()
            self.passed += 1
            print(f"[PASS] {label}", flush=True)
        except Exception as error:  # Continue to expose all independent regressions.
            self.failed += 1
            print(f"[FAIL] {label}: {error}", file=sys.stderr, flush=True)

    @staticmethod
    def listener(port, host="127.0.0.1"):
        with socket.create_connection((host, port), timeout=0.5):
            pass

    def get(self, port, tls=False, host="app.example.test", headers=None, path="/"):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        if tls:
            context = ssl.create_default_context(cafile=str(self.work / "web/web-cert.pem"))
            connection.sock = context.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=3),
                                                   server_hostname="app.example.test")
        connection.request("GET", path, headers={"Host": host, **(headers or {})})
        response = connection.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        connection.close()
        return result

    def content(self, port, tls=False, headers=None):
        status, _, body = self.get(port, tls, headers=headers)
        assert status == 200, status
        data = json.loads(body)
        assert data["marker"] == MARKER, data
        return data

    def prepare_clients(self):
        for config in self.work.glob("*/client-*/frpc.toml"):
            assert config.stat().st_mode & 0o777 == 0o600, f"unsafe config permissions: {config}"
            assert config.parent.stat().st_mode & 0o777 == 0o700, f"unsafe directory permissions: {config.parent}"
            ca = config.parent / "ca.pem"
            assert ca.stat().st_mode & 0o777 == 0o600, f"unsafe CA export permissions: {ca}"
            text = config.read_text()
            # Only connect through loopback; preserve the production serverName.
            text, count = re.subn(r'(?m)^serverAddr\s*=.*$', 'serverAddr = "127.0.0.1"', text)
            assert count == 1, "exported serverAddr missing or duplicated"
            # Every process must have a distinct proxy name, including the
            # modified out-of-range fixture derived from the valid TCP export.
            text, count = re.subn(r'(?m)^name\s*=.*$', f'name = "{config.parent.name}"', text)
            assert count == 1, "proxy name missing or duplicated"
            if config.parent.name == "client-bad-token":
                text, count = re.subn(r'(?m)^auth\.token\s*=.*$', 'auth.token = "incorrect-e2e-token"', text)
                assert count == 1, "auth.token missing"
            elif config.parent.name == "client-bad-ca":
                ca.write_bytes((self.work / "web/web-cert.pem").read_bytes())
            elif config.parent.name == "client-bad-name":
                text, count = re.subn(r'(?m)^transport\.tls\.serverName\s*=.*$',
                                     'transport.tls.serverName = "wrong.example.test"', text)
                assert count == 1, "TLS serverName missing"
            elif config.parent.name == "client-bad-port":
                text, count = re.subn(r'(?m)^remotePort\s*=.*$', f'remotePort = {self.ports["range_end"] + 1}', text)
                assert count == 1, "remotePort missing"
            config.write_text(text)
            result = subprocess.run([self.frpc, "verify", "-c", str(config)], cwd=config.parent,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)
            (config.parent / "verify.log").write_bytes(result.stdout)
            assert result.returncode == 0, f"frpc configuration rejected: {config.parent / 'verify.log'}"

    def udp_echo(self):
        with socket.socket(type=socket.SOCK_DGRAM) as sock:
            sock.settimeout(1)
            payload = (MARKER + "-udp").encode()
            sock.sendto(payload, ("127.0.0.1", self.ports["range_start"] + 1))
            assert sock.recv(65536) == payload, "UDP content mismatch"

    def control_tls(self, mode):
        """Use the same standard TLS handshake as the production health probe."""
        log_path = self.work / ("control-" + mode + "-tls.log")
        args = ["openssl", "s_client", "-connect", f'127.0.0.1:{self.ports[mode + "_control"]}',
                "-servername", "frp.example.test", "-verify_hostname", "frp.example.test",
                "-CAfile", str(self.work / mode / "ca.pem"), "-verify_return_error"]
        try:
            result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, timeout=4)
        except subprocess.TimeoutExpired as error:
            log_path.write_bytes(error.output or b"")
            raise AssertionError(f"standard control TLS handshake timed out: {log_path}") from error
        log_path.write_bytes(result.stdout)
        assert result.returncode == 0, f"control TLS CA/hostname verification failed: {log_path}"
        assert b"Verify return code: 0 (ok)" in result.stdout or b"Verification: OK" in result.stdout, \
            f"control TLS verification was not completed: {log_path}"

    def websocket_echo(self):
        context = ssl.create_default_context(cafile=str(self.work / "web/web-cert.pem"))
        with context.wrap_socket(socket.create_connection(("127.0.0.1", self.ports["https"]), timeout=3),
                                 server_hostname="app.example.test") as sock:
            key = base64.b64encode(b"frps-e2e-ws-test!").decode()
            sock.sendall((f"GET /websocket HTTP/1.1\r\nHost: app.example.test\r\nUpgrade: websocket\r\n"
                          f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
            header = b""
            while not header.endswith(b"\r\n\r\n"):
                header += receive(sock, 1)
                assert len(header) < 16384, "unbounded WebSocket response headers"
            assert b" 101 " in header.split(b"\r\n", 1)[0], header
            expected = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
            assert expected in header, "bad WebSocket accept key"
            payload, mask = (MARKER + "-websocket").encode(), b"\x13\x37\x42\x7f"
            encoded = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
            sock.sendall(struct.pack("BB", 0x81, 0x80 | len(payload)) + mask + encoded)
            opcode, length = receive(sock, 2)
            assert opcode == 0x81 and length == len(payload), "invalid echoed WebSocket frame"
            assert receive(sock, length) == payload, "WebSocket content mismatch"

    def denied_client(self, name, port, log_pattern):
        log_path = self.work / (name + ".log")
        # Require a real negative handshake/proxy result, not merely an absent
        # socket before the child process has had time to contact the server.
        self.eventually(lambda: self.assert_log(log_path, log_pattern))
        for _ in range(5):
            try:
                self.listener(port)
            except OSError:
                time.sleep(0.1)
                continue
            raise AssertionError(f"forbidden proxy opened port {port}")

    @staticmethod
    def assert_log(path, pattern):
        text = path.read_text(errors="replace") if path.exists() else ""
        assert re.search(pattern, text, re.I), f"expected rejection absent from {path.name}"

    def loopback_only(self):
        # The kernel's listener table proves the generated frps configuration
        # bound the internal HTTP service only to loopback, independent of DNS.
        port = self.ports["http_internal"]
        listeners = []
        for name in ("/proc/net/tcp", "/proc/net/tcp6"):
            for line in Path(name).read_text().splitlines()[1:]:
                fields = line.split()
                address, encoded_port = fields[1].split(":")
                if int(encoded_port, 16) == port and fields[3] == "0A":
                    listeners.append(address)
        assert listeners == ["0100007F"], f"unexpected HTTP bind addresses: {listeners}"

    def unknown_host(self):
        try:
            status, _, body = self.get(self.ports["https"], tls=True, host="unconfigured.example.test")
        except (OSError, http.client.HTTPException):
            return
        assert status >= 400 and MARKER.encode() not in body, "unknown Host exposed the configured website"

    def redirect(self):
        status, headers, _ = self.get(self.ports["redirect"], path="/hello?source=e2e")
        assert status in (301, 302, 307, 308), status
        location = next(value for key, value in headers.items() if key.lower() == "location")
        assert location == f'https://app.example.test:{self.ports["https"]}/hello?source=e2e', location

    def forwarded_headers(self):
        data = self.content(self.ports["https"], True,
                            {"X-Forwarded-Proto": "http", "X-Forwarded-For": "198.51.100.2"})
        assert data["host"] == "app.example.test", data
        assert data["proto"] == "https", data
        assert "198.51.100.2" not in (data["forwarded_for"] or ""), data

    def run(self):
        self.prepare_clients()
        print("[PASS] exported client configuration and credential permissions", flush=True)
        self.passed += 1
        for cls, handler, port in ((http.server.ThreadingHTTPServer, Backend, self.ports["http_backend"]),
                                   (socketserver.ThreadingUDPServer, Datagram, self.ports["udp_backend"])):
            server = cls(("127.0.0.1", port), handler)
            server.daemon_threads = True
            self.servers.append(server)
            threading.Thread(target=server.serve_forever, daemon=True).start()
        for mode in ("tcp", "web"):
            # FRPS_BIND_ADDR selects loopback through the production renderer;
            # leave the actual frps configuration byte-for-byte unchanged.
            self.start("frps-" + mode, [self.frps, "-c", str(self.work / mode / "frps.toml")])
            self.eventually(lambda mode=mode: self.listener(self.ports[mode + "_control"]))
            self.check(f"{mode} control health probe completes standard TLS with CA/hostname verification",
                       lambda mode=mode: self.eventually(lambda: self.control_tls(mode)))
        nginx_conf = self.work / "web/nginx.conf"
        text = re.sub(r'listen \[::\]:[0-9]+(?: ssl)?(?: default_server)?;', '', nginx_conf.read_text())
        text = re.sub(r'listen ([0-9]+)', r'listen 127.0.0.1:\1', text)
        nginx_conf.write_text(text)
        result = subprocess.run([self.nginx, "-t", "-p", str(self.work / "web") + "/", "-c", str(nginx_conf)],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)
        (self.work / "nginx-verify.log").write_bytes(result.stdout)
        assert result.returncode == 0, f"nginx configuration rejected: {self.work / 'nginx-verify.log'}"
        self.start("nginx", [self.nginx, "-p", str(self.work / "web") + "/", "-c", str(nginx_conf), "-g", "daemon off;"])
        self.eventually(lambda: self.listener(self.ports["https"]))
        for config in self.work.glob("*/client-*/frpc.toml"):
            self.start(config.parent.name, [self.frpc, "-c", str(config)], cwd=config.parent)
        self.check("authenticated TCP tunnel carries backend response",
                   lambda: self.eventually(lambda: self.content(self.ports["range_start"])))
        self.check("authenticated UDP tunnel echoes datagrams", lambda: self.eventually(self.udp_echo))
        self.check("domain HTTPS serves backend through nginx and frp",
                   lambda: self.eventually(lambda: self.content(self.ports["https"], True)))
        self.check("HTTPS preserves Host/protocol and discards forged forwarding identity", self.forwarded_headers)
        self.check("WebSocket upgrade and masked payload survive HTTPS/frp forwarding", self.websocket_echo)
        self.check("HTTP redirects preserve path, query and configured HTTPS port", self.redirect)
        self.check("unknown Host does not reach the configured backend", self.unknown_host)
        self.check("internal frps HTTP listener is loopback only", self.loopback_only)
        self.check("incorrect token cannot create a TCP proxy",
                   lambda: self.denied_client("client-bad-token", self.ports["range_start"] + 2, r"token.*(?:match|invalid|error)|authentication.*fail"))
        self.check("incorrect CA cannot authenticate the control server",
                   lambda: self.denied_client("client-bad-ca", self.ports["range_start"] + 3, r"x509|unknown authority|certificate.*verif"))
        self.check("incorrect TLS server name cannot authenticate the control server",
                   lambda: self.denied_client("client-bad-name", self.ports["range_start"] + 4, r"x509|certificate.*valid|certificate.*verif"))
        self.check("server enforces allowed remote port range",
                   lambda: self.denied_client("client-bad-port", self.ports["range_end"] + 1, r"(?:port.*(?:not allowed|not allow|denied)|port not)"))
        print(f"FRP E2E: {self.passed} passed, {self.failed} failed", flush=True)
        return self.failed == 0


def main():
    work = Path(sys.argv[2]).resolve()
    if sys.argv[1] == "allocate":
        allocate(work)
        return 0
    def terminated(signum, _frame):
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGTERM, terminated)
    runner = Runner(work, *sys.argv[3:6])
    try:
        return 0 if runner.run() else 1
    finally:
        runner.close()


if __name__ == "__main__":
    sys.exit(main())
