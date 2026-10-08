#!/usr/bin/env python3
"""Black-box policy and shared-port checks against real native proxy cores.

Uses the native matrix's isolated marker/PKI/process fixtures, never the old
shell implementation. Python is only the test driver. No root or host network
configuration changes are required. Set ONEBOX_TEST_BINARY,
ONEBOX_TEST_SINGBOX and ONEBOX_TEST_XRAY as for native_e2e.py.
"""
from __future__ import annotations

import argparse
import contextlib
import http.client
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import ssl
import struct
import tempfile
import threading

import native_e2e as matrix

# Logical destinations only: the fixture redirects allowed connections to
# loopback, so no packets are sent to these public addresses. Documentation
# ranges cannot be used here because the production policy blocks them too.
OWN_IP = "9.9.9.9"
PUBLIC_IP = "8.8.4.4"
RECORDS = {
    "private.policy.test": "127.0.0.1",
    "self.policy.test": OWN_IP,
    "public.policy.test": PUBLIC_IP,
}


class DNS:
    """Tiny authoritative UDP DNS fixture, with observable actual queries."""
    def __init__(self, port):
        self.port = port
        self.socket = socket.socket(type=socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", port))
        self.socket.settimeout(0.1)
        self.closed = threading.Event()
        self.lock = threading.Lock()
        self.queries = []
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while not self.closed.is_set():
            try:
                message, peer = self.socket.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                if len(message) < 12 or struct.unpack("!H", message[4:6])[0] != 1:
                    continue
                offset, labels = 12, []
                while message[offset]:
                    size = message[offset]
                    if size > 63:
                        raise ValueError("compressed question not supported")
                    offset += 1
                    labels.append(message[offset:offset + size].decode("ascii"))
                    offset += size
                offset += 1
                kind, cls = struct.unpack("!HH", message[offset:offset + 4])
                offset += 4
                name = ".".join(labels).lower()
                with self.lock:
                    self.queries.append((name, kind))
                answer = b""
                if name in RECORDS and kind == 1 and cls == 1:
                    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 0, 4) + socket.inet_aton(RECORDS[name])
                flags = 0x8180 if name in RECORDS else 0x8183
                response = message[:2] + struct.pack("!HHHHH", flags, 1, int(bool(answer)), 0, 0)
                self.socket.sendto(response + message[12:offset] + answer, peer)
            except (IndexError, ValueError, UnicodeError, struct.error, OSError):
                continue

    def queried(self, name):
        with self.lock:
            return (name, 1) in self.queries

    def reset(self):
        with self.lock:
            self.queries.clear()

    def close(self):
        self.closed.set()
        self.socket.close()
        self.thread.join(timeout=1)


def read_marker(stream, fixture, host):
    stream.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
    response = http.client.HTTPResponse(stream)
    response.begin()
    body = response.read(len(fixture.marker) + 1)
    if response.status != 200 or body != fixture.marker:
        raise AssertionError(f"unexpected marker response: HTTP {response.status}")


def proxy_marker(port, target, fixture):
    stream, _, _ = matrix.socks(port, 1, target, fixture.http_port, timeout=3)
    with stream:
        read_marker(stream, fixture, target)


def tls_marker(port, name, fixture):
    # Deliberately trust the test peer without hostname verification: negative
    # SNI tests must fail at the guard, never at local certificate validation.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(["http/1.1"])
    with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
        with context.wrap_socket(raw, server_hostname=name) as stream:
            read_marker(stream, fixture, name or "no-sni.test")


class Policy(matrix.Matrix):
    def __init__(self, root, binaries, args):
        super().__init__(root, binaries, args)
        self.dns = DNS(self.ports.get())

    def close(self):
        self.dns.close()
        super().close()

    def assert_traffic(self, name, action, expected, processes=()):
        error = None
        try:
            action()
            reached = True
        except (OSError, AssertionError, http.client.HTTPException) as exc:
            reached, error = False, str(exc)
        if any(not process.alive() for process in processes):
            self.record(name, False, "a core exited; connection failure is not policy rejection")
        elif reached != expected:
            detail = "unexpected successful marker response" if reached else (error or "no marker")
            self.record(name, False, detail + "\n" + "\n".join(p.tail() for p in processes))
        else:
            self.record(name, True)

    def launch_server(self, directory, core, config, port, env):
        path = directory / "server.json"
        matrix.write_json(path, config)
        binary = self.binaries[core]
        check = [binary, "check", "-c", path] if core == "singbox" else [binary, "run", "-test", "-c", path]
        matrix.run(check, env=env)
        process = matrix.Process([binary, "run", "-c", path], directory, env)
        try:
            process.wait_tcp(port)
            return process
        except Exception:
            process.close()
            raise

    def private_policy(self, core):
        # Route actions and deny rules come only from the real Rust renderer.
        # The terminal direct connection is redirected to our local HTTP peer
        # AFTER routing decisions, avoiding public traffic and host IP aliases.
        for blocked in [False, True]:
            self.dns.reset()
            name = f"private/{core}/{'on' if blocked else 'off'}"
            directory = self.root / name
            state, env = self.state(directory, "shadowsocks", core, "self")
            state.update(BLOCK_PRIVATE=str(int(blocked)), OWN_IP_CIDRS=json.dumps([OWN_IP + "/32"]))
            matrix.write_json(directory / "etc/state.json", {"values": state})
            config = self.cli(env, "render", "server", core)
            if core == "singbox":
                config["dns"]["servers"] = [{"type": "udp", "tag": "local", "server": "127.0.0.1", "server_port": self.dns.port}]
                config["route"]["rules"].append({"action": "route-options", "override_address": "127.0.0.1"})
            else:
                config["dns"] = {"servers": [{"address": "127.0.0.1", "port": self.dns.port}], "queryStrategy": "UseIPv4", "tag": "policy-fixture-dns"}
                # Internal DNS requests need their own direct transport to the
                # local fixture. Only that synthetic inbound tag bypasses the
                # generated rules; authenticated proxy requests cannot use it.
                config["outbounds"].append({"tag": "policy-dns-direct", "protocol": "freedom",
                                             "settings": {"finalRules": [{"action": "allow"}]}})
                config["routing"]["rules"].insert(0, {"type": "field", "inboundTag": ["policy-fixture-dns"], "outboundTag": "policy-dns-direct"})
                # The first/default direct outbound runs only after Xray's
                # generated IPIfNonMatch policy, including its DNS retry.
                config["outbounds"][0]["settings"] = {"redirect": "127.0.0.1:0", "finalRules": [{"action": "allow"}]}
            try:
                with self.launch_server(directory, core, config, int(state["PORT_shadowsocks"]), env) as server:
                    port = self.ports.get()
                    client = self.client_config(env, "shadowsocks", core, port)
                    with self.launch_client(directory / "client", core, client, env) as process:
                        process.wait_tcp(port)
                        peers = (server, process)
                        self.assert_traffic(name + "/public-before", lambda: proxy_marker(port, PUBLIC_IP, self.fixture), True, peers)
                        for label, target in [("private-ip", "127.0.0.1"), ("private-dns", "private.policy.test"),
                                              ("own-ip", OWN_IP), ("own-dns", "self.policy.test")]:
                            self.assert_traffic(name + "/" + label, lambda t=target: proxy_marker(port, t, self.fixture), not blocked, peers)
                        self.assert_traffic(name + "/public-dns-after", lambda: proxy_marker(port, "public.policy.test", self.fixture), True, peers)
                        self.assert_traffic(name + "/public-after", lambda: proxy_marker(port, PUBLIC_IP, self.fixture), True, peers)
                        if blocked:
                            for domain in RECORDS:
                                self.record(name + "/resolved-" + domain, self.dns.queried(domain), "" if self.dns.queried(domain) else "server never queried the fixture DNS")
            except Exception as error:
                self.record(name + "/startup", False, str(error))

    def shared_client(self, env, protocol, core, port):
        outbound = self.cli(env, "render", "outbound", protocol, core)
        if core == "singbox":
            return {"log": {"level": "warn"}, "dns": {"servers": [{"type": "local", "tag": "local"}]},
                    "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": port}],
                    "outbounds": [outbound], "route": {"final": outbound["tag"], "default_domain_resolver": "local"}}
        return {"log": {"loglevel": "warning"}, "inbounds": [{"listen": "127.0.0.1", "port": port,
                "protocol": "socks", "settings": {"udp": True}}], "outbounds": [outbound]}

    def shared_port(self, include_singbox=True):
        directory = self.root / "shared"
        state, env = self.state(directory, "vless-reality", "xray", "self")
        port = int(state["PORT_vless_reality"])
        state.update(PROTOCOLS="vless-reality vless-xhttp", PORT_vless_xhttp=str(port), CORE_vless_xhttp="xray",
                     XR_XHTTP_SOCK="@onebox-native-policy-" + secrets.token_hex(12))
        matrix.write_json(directory / "etc/state.json", {"values": state})
        guard = int(state["REALITY_GUARD_PORT"])
        try:
            with self.server(directory, "vless-reality", "xray", state, env) as server, contextlib.ExitStack() as stack:
                clients = []
                combinations = [("vless-reality", "xray"), ("vless-xhttp", "xray")]
                if include_singbox:
                    combinations.append(("vless-reality", "singbox"))
                for protocol, core in combinations:
                    local = self.ports.get()
                    client = self.shared_client(env, protocol, core, local)
                    process = stack.enter_context(self.launch_client(directory / (protocol + "-" + core), core, client, env))
                    process.wait_tcp(local)
                    clients.append((protocol + "/" + core, local, process))
                    self.assert_traffic("shared/" + protocol + "/" + core + "/before", lambda p=local: matrix.tcp_marker(p, self.fixture), True, (server, process))
                # Reference controls prove that wrong/no SNI are accepted by
                # the target itself. Their rejection is therefore the guard.
                for name, sni in [("correct-sni", "reality.test"), ("wrong-sni", "wrong.test"), ("no-sni", None)]:
                    self.assert_traffic("shared/reference/" + name, lambda n=sni: tls_marker(self.fixture.tls_port, n, self.fixture), True)
                    self.assert_traffic("shared/guard/" + name, lambda n=sni: tls_marker(guard, n, self.fixture), name == "correct-sni", (server,))
                self.assert_traffic("shared/ordinary-tls-fallback", lambda: tls_marker(port, "reality.test", self.fixture), True, (server,))
                for label, local, process in clients:
                    self.assert_traffic("shared/" + label + "/after", lambda p=local: matrix.tcp_marker(p, self.fixture), True, (server, process))
        except Exception as error:
            self.record("shared/startup", False, str(error))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--servers", type=lambda value: value.split(","), default=["singbox", "xray"])
    parser.add_argument("--skip-shared", action="store_true", help="run only private/self-address policy checks")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if not args.servers or any(core not in ("singbox", "xray") for core in args.servers):
        parser.error("--servers must contain singbox and/or xray")
    binaries = {
        "onebox": matrix.executable("onebox", "ONEBOX_TEST_BINARY", str(Path(__file__).resolve().parents[1] / "target/debug/onebox")),
        "singbox": matrix.executable("sing-box", "ONEBOX_TEST_SINGBOX", os.environ.get("SB") or shutil.which("sing-box")),
        "xray": matrix.executable("Xray", "ONEBOX_TEST_XRAY", os.environ.get("XR") or shutil.which("xray")),
    }
    required = set(args.servers) | {"onebox", "xray"}
    if not args.skip_shared:
        required.add("singbox")
    if any(not binaries.get(core) for core in required):
        parser.error("set ONEBOX_TEST_BINARY, ONEBOX_TEST_SINGBOX and ONEBOX_TEST_XRAY to native binaries")
    os.umask(0o077)
    root = Path(tempfile.mkdtemp(prefix="onebox-native-policy-"))
    tests = None
    try:
        tests = Policy(root, binaries, args)
        for core in args.servers:
            tests.private_policy(core)
        if not args.skip_shared:
            tests.shared_port()
        failures = sum(not result["ok"] for result in tests.results)
        if args.report:
            matrix.write_json(args.report, {"schema": 1, "scope": "native-policy-black-box", "results": tests.results, "failures": failures})
        print(f"Native policy: {len(tests.results)} checks, {failures} failures", flush=True)
        return int(failures > 0)
    finally:
        if tests:
            tests.close()
        if os.environ.get("KEEP") == "1":
            print(f"Preserved fixture directory: {root}", flush=True)
        else:
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
