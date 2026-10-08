#!/usr/bin/env python3
"""Native Rust CLI / real-core matrix, using only isolated loopback fixtures.

ONEBOX_TEST_BINARY=target/debug/onebox ONEBOX_TEST_SINGBOX=/path/sing-box \
ONEBOX_TEST_XRAY=/path/xray MH=/path/mihomo python3 tests/native_e2e.py

Python is a test dependency only. No legacy script is sourced or executed.
The target hostname and TEST-NET UDP address are rewritten exclusively by the
server under test, so a direct connection cannot satisfy either assertion.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import copy
import http.client
import http.server
import json
import os
from pathlib import Path
import random
import secrets
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid

PROTOCOLS = (
    "vless-reality", "vless-xhttp", "vless-grpc", "vless-ws", "vmess-ws",
    "trojan", "shadowsocks", "hysteria2", "tuic", "anytls", "shadowtls",
    "anytls-reality",
)
SINGBOX_ONLY = {"tuic", "anytls", "shadowtls", "anytls-reality"}
CERTIFICATE = {"vless-ws", "vmess-ws", "trojan", "hysteria2", "tuic", "anytls"}
REALITY = {"vless-reality", "vless-grpc", "vless-xhttp", "anytls-reality"}
UDP_TRANSPORT = {"hysteria2", "tuic"}
TARGET_NAME = "native-e2e.invalid"
TARGET_IP = "192.0.2.53"


def core_supported(protocol, core):
    return protocol != "vless-xhttp" if core == "singbox" else protocol not in SINGBOX_ONLY


def client_supported(protocol, client):
    if client == "mihomo":
        return protocol != "anytls-reality"
    return core_supported(protocol, client)


def run(argv, *, env=None, timeout=20):
    result = subprocess.run(
        [str(a) for a in argv], env=env, capture_output=True, timeout=timeout,
        stdin=subprocess.DEVNULL,
    )
    if result.returncode:
        message = result.stderr.decode(errors="replace")[-3000:]
        message += result.stdout.decode(errors="replace")[-1000:]
        raise AssertionError(f"{Path(str(argv[0])).name} failed ({result.returncode}): {message}")
    return result.stdout.decode()


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
    path.chmod(0o600)


class Ports:
    """Never allocate a listener in Linux's ephemeral source-port range."""
    def __init__(self):
        self.used = set()
        try:
            low, high = map(int, Path("/proc/sys/net/ipv4/ip_local_port_range").read_text().split())
        except (OSError, ValueError):
            low, high = 32768, 60999
        self.candidates = [p for p in range(10240, 65536) if not low <= p <= high]
        random.SystemRandom().shuffle(self.candidates)

    def get(self):
        while self.candidates:
            port = self.candidates.pop()
            if port in self.used:
                continue
            try:
                with socket.socket() as tcp, socket.socket(type=socket.SOCK_DGRAM) as udp:
                    tcp.bind(("127.0.0.1", port))
                    udp.bind(("127.0.0.1", port))
            except OSError:
                continue
            self.used.add(port)
            return port
        raise AssertionError("No non-ephemeral loopback listener ports are free")


class Process:
    def __init__(self, argv, directory, env):
        self.log_path = directory / "process.log"
        self.log = self.log_path.open("wb")
        self.child = subprocess.Popen(
            [str(a) for a in argv], cwd=directory, env=env,
            stdin=subprocess.DEVNULL, stdout=self.log, stderr=self.log,
            start_new_session=True,
        )

    def alive(self):
        return self.child.poll() is None

    def wait_tcp(self, port, timeout=8):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not self.alive():
                raise AssertionError("core exited during startup: " + self.tail())
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    return
            except OSError:
                time.sleep(0.03)
        raise AssertionError("core did not open its loopback listener: " + self.tail())

    def tail(self):
        self.log.flush()
        return self.log_path.read_text(errors="replace")[-3000:]

    def close(self):
        if self.child.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(self.child.pid, signal.SIGTERM)
            try:
                self.child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(self.child.pid, signal.SIGKILL)
                self.child.wait(timeout=3)
        self.log.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class Fixtures:
    def __init__(self, root, ports):
        self.root = root
        self.ports = ports
        self.marker = ("onebox-native-" + secrets.token_hex(24)).encode()
        self.http_port, self.tls_port, self.udp_port = ports.get(), ports.get(), ports.get()
        self.closed = threading.Event()
        self.servers, self.threads = [], []
        self.pki = root / "pki"
        self.pki.mkdir()
        self._certificates()
        marker = self.marker

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(marker)))
                self.end_headers()
                with contextlib.suppress(OSError):
                    self.wfile.write(marker)

            def log_message(self, *_):
                pass

        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.minimum_version = ssl.TLSVersion.TLSv1_3
        tls.set_alpn_protocols(["h2", "http/1.1"])
        tls.load_cert_chain(self.pki / "reality.test.pem", self.pki / "reality.test.key")

        class TLSHTTPServer(http.server.ThreadingHTTPServer):
            def finish_request(self, request, client_address):
                # REALITY legitimately uses incomplete target handshakes.
                # Handshake in each worker, never in the single accept loop.
                request.settimeout(8)
                try:
                    with tls.wrap_socket(request, server_side=True) as encrypted:
                        self.RequestHandlerClass(encrypted, client_address, self)
                except (OSError, ssl.SSLError):
                    pass

        for port, encrypted in [(self.http_port, False), (self.tls_port, True)]:
            kind = TLSHTTPServer if encrypted else http.server.ThreadingHTTPServer
            server = kind(("127.0.0.1", port), Handler)
            server.daemon_threads = True
            self.servers.append(server)
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
            thread.start()
            self.threads.append(thread)
        self.udp = socket.socket(type=socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", self.udp_port))
        self.udp.settimeout(0.1)
        thread = threading.Thread(target=self._udp, daemon=True)
        thread.start()
        self.threads.append(thread)

    def _certificates(self):
        pki = self.pki
        run(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", pki / "ca.key"])
        run(["openssl", "req", "-new", "-x509", "-sha256", "-days", "2", "-key", pki / "ca.key",
             "-out", pki / "ca.pem", "-subj", "/CN=Onebox isolated native E2E CA",
             "-addext", "basicConstraints=critical,CA:TRUE"])
        for name in ["reality.test", "onebox.test"]:
            run(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", pki / f"{name}.key"])
            run(["openssl", "req", "-new", "-key", pki / f"{name}.key", "-out", pki / f"{name}.csr", "-subj", f"/CN={name}"])
            ext = pki / f"{name}.ext"
            ext.write_text(f"subjectAltName=DNS:{name}\nextendedKeyUsage=serverAuth\n")
            run(["openssl", "x509", "-req", "-sha256", "-days", "2", "-in", pki / f"{name}.csr",
                 "-CA", pki / "ca.pem", "-CAkey", pki / "ca.key", "-CAcreateserial", "-extfile", ext,
                 "-out", pki / f"{name}.pem"])
        run(["openssl", "req", "-new", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
             "-nodes", "-days", "2", "-keyout", pki / "self.key", "-out", pki / "self.pem",
             "-subj", "/CN=onebox.test", "-addext", "subjectAltName=DNS:onebox.test"])
        bundle = (pki / "ca.pem").read_bytes()
        system = Path("/etc/ssl/certs/ca-certificates.crt")
        if system.exists():
            bundle += b"\n" + system.read_bytes()
        (pki / "bundle.pem").write_bytes(bundle)

    def _udp(self):
        while not self.closed.is_set():
            try:
                data, peer = self.udp.recvfrom(65535)
                self.udp.sendto(data, peer)
            except socket.timeout:
                continue
            except OSError:
                return

    def close(self):
        self.closed.set()
        self.udp.close()
        for server in self.servers:
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join(timeout=2)


def exact(sock, count):
    result = bytearray()
    while len(result) < count:
        block = sock.recv(count - len(result))
        if not block:
            raise OSError("premature EOF")
        result.extend(block)
    return bytes(result)


def address(sock, atyp):
    if atyp == 1:
        return socket.inet_ntop(socket.AF_INET, exact(sock, 4))
    if atyp == 4:
        return socket.inet_ntop(socket.AF_INET6, exact(sock, 16))
    if atyp == 3:
        return exact(sock, exact(sock, 1)[0]).decode("ascii")
    raise OSError("invalid SOCKS address")


def socks(port, command, target, target_port, timeout=5):
    stream = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        stream.sendall(b"\x05\x01\x00")
        if exact(stream, 2) != b"\x05\x00":
            raise OSError("SOCKS authentication failed")
        try:
            destination = b"\x01" + socket.inet_aton(target)
        except OSError:
            host = target.encode("ascii")
            destination = b"\x03" + bytes([len(host)]) + host
        stream.sendall(bytes([5, command, 0]) + destination + struct.pack("!H", target_port))
        reply = exact(stream, 4)
        if reply[:3] != b"\x05\x00\x00":
            raise OSError("SOCKS command rejected")
        host = address(stream, reply[3])
        peer_port = struct.unpack("!H", exact(stream, 2))[0]
        return stream, host, peer_port
    except Exception:
        stream.close()
        raise


def tcp_marker(proxy, fixture, timeout=5):
    stream, _, _ = socks(proxy, 1, TARGET_NAME, fixture.http_port, timeout)
    with stream:
        stream.sendall(f"GET / HTTP/1.1\r\nHost: {TARGET_NAME}:{fixture.http_port}\r\nUser-Agent: onebox-native-e2e/2\r\nAccept: */*\r\nConnection: close\r\n\r\n".encode())
        response = http.client.HTTPResponse(stream)
        response.begin()
        body = response.read(len(fixture.marker) + 1)
        if response.status != 200 or body != fixture.marker:
            raise AssertionError(f"HTTP marker mismatch (status={response.status})")


def udp_marker(proxy, fixture):
    stream, relay, relay_port = socks(proxy, 3, "0.0.0.0", 0)
    with stream:
        if relay in ("0.0.0.0", "::"):
            relay = "127.0.0.1"
        family = socket.AF_INET6 if ":" in relay else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as datagram:
            datagram.settimeout(2)
            payload = fixture.marker + secrets.token_bytes(16)
            header = b"\x00\x00\x00\x01" + socket.inet_aton(TARGET_IP) + struct.pack("!H", fixture.udp_port)
            for _ in range(3):
                datagram.sendto(header + payload, (relay, relay_port))
                try:
                    reply, _ = datagram.recvfrom(65535)
                except socket.timeout:
                    continue
                if reply[:3] == b"\x00\x00\x00" and reply.endswith(payload):
                    return
            raise AssertionError("no matching SOCKS UDP echo")


class Matrix:
    def __init__(self, root, binaries, args):
        self.root, self.binaries, self.args = root, binaries, args
        self.ports = Ports()
        self.fixture = Fixtures(root, self.ports)
        self.results = []
        self.env = dict(os.environ, SSL_CERT_FILE=str(self.fixture.pki / "bundle.pem"), NO_COLOR="1")
        self.env.pop("ONEBOX_SOURCE_ONLY", None)
        keys = run([binaries["xray"], "x25519"], env=self.env)
        self.private, self.public = self.parse_keys(keys)
        _, self.wrong_public = self.parse_keys(run([binaries["xray"], "x25519"], env=self.env))

    @staticmethod
    def parse_keys(text):
        pairs = dict((name.lower().strip(), value.strip()) for name, value in
                     (line.split(":", 1) for line in text.splitlines() if ":" in line))
        private = next(value for name, value in pairs.items() if "private" in name)
        public = next(value for name, value in pairs.items() if "public" in name)
        return private, public

    def record(self, name, success, detail=""):
        self.results.append({"name": name, "ok": success, "detail": detail})
        print(f"{'PASS' if success else 'FAIL'} {name}" + (f": {detail}" if detail else ""), flush=True)

    def state(self, directory, protocol, server, profile):
        directory.mkdir(parents=True)
        config_dir = directory / "etc"
        config_dir.mkdir()
        pki = self.fixture.pki
        state = {
            "PROTOCOLS": protocol, "SERVER_ADDR": "127.0.0.1", "SERVER_IPV4": "127.0.0.1", "SERVER_IPV6": "",
            "LISTEN_ADDR": "127.0.0.1", "NODE_NAME": "native-e2e", "UUID": str(uuid.uuid4()),
            "PASSWORD": secrets.token_hex(24), "SS_METHOD": "2022-blake3-aes-128-gcm",
            "SS_PASSWORD": base64.b64encode(secrets.token_bytes(16)).decode(),
            "SHADOWTLS_PASSWORD": secrets.token_hex(24), "SHADOWTLS_SS_PASSWORD": base64.b64encode(secrets.token_bytes(16)).decode(),
            "REALITY_PRIVATE_KEY": self.private, "REALITY_PUBLIC_KEY": self.public, "REALITY_SHORT_ID": secrets.token_hex(8),
            "REALITY_SNI": "reality.test", "REALITY_DEST": f"127.0.0.1:{self.fixture.tls_port}",
            "SHADOWTLS_SNI": "reality.test", "SHADOWTLS_DEST": f"127.0.0.1:{self.fixture.tls_port}",
            "REALITY_GUARD_PORT": str(self.ports.get()), "REALITY_SITE_ENABLED": "0", "REALITY_SITE_HTTPS": "0",
            "WS_PATH": "/native-ws", "VMESS_PATH": "/native-vmess", "XHTTP_PATH": "/native-xhttp", "GRPC_SERVICE": "native-grpc",
            "VMESS_TLS": "1" if profile == "ca" else "0", "HY2_OBFS": "1" if profile == "ca" else "0",
            "HY2_OBFS_PASSWORD": secrets.token_hex(24), "HY2_PROFILE": "auto", "RESOURCE_PROFILE": "balanced",
            "TLS_MODE": "custom" if profile == "ca" else "self", "TLS_SNI": "onebox.test", "DOMAIN": "onebox.test",
            "CERT_PINNED": "0" if profile == "ca" else "1", "CERT_FILE": str(pki / ("onebox.test.pem" if profile == "ca" else "self.pem")),
            "KEY_FILE": str(pki / ("onebox.test.key" if profile == "ca" else "self.key")),
            "BLOCK_PRIVATE": "0", "BLOCK_BT": "1", "SB_VERSION": "latest", "XR_VERSION": "latest",
            "PORT_" + protocol.replace("-", "_"): str(self.ports.get()),
            "CORE_" + protocol.replace("-", "_"): server,
        }
        write_json(config_dir / "state.json", {"values": state})
        env = dict(self.env, ONEBOX_DIR=str(config_dir), ONEBOX_BIN_DIR=str(directory / "bin"),
                   ONEBOX_LOG_DIR=str(directory / "log"), ONEBOX_RUN_DIR=str(directory / "run"),
                   ONEBOX_SITE_ROOT=str(directory / "www"), ONEBOX_SYSTEMD_DIR=str(directory / "systemd"),
                   ONEBOX_INITD_DIR=str(directory / "initd"))
        return state, env

    def cli(self, env, *args):
        return json.loads(run([self.binaries["onebox"], *args], env=env))

    def server(self, directory, protocol, server, state, env):
        config = self.cli(env, "render", "server", server)
        if os.environ.get("VERBOSE") == "1":
            config["log"]["level" if server == "singbox" else "loglevel"] = "debug"
        if server == "singbox":
            override = [
                {"domain": [TARGET_NAME], "action": "route-options", "override_address": "127.0.0.1"},
                {"ip_cidr": [TARGET_IP + "/32"], "action": "route-options", "override_address": "127.0.0.1"},
            ]
            config["route"]["rules"] = override + config["route"].get("rules", [])
        else:
            config["outbounds"].append({"tag": "native-target", "protocol": "freedom", "settings": {
                "redirect": "127.0.0.1:0", "finalRules": [{"action": "allow"}]}})
            config["routing"]["rules"] = [
                {"type": "field", "domain": ["full:" + TARGET_NAME], "outboundTag": "native-target"},
                {"type": "field", "ip": [TARGET_IP + "/32"], "outboundTag": "native-target"},
            ] + config["routing"].get("rules", [])
        path = directory / "server.json"
        write_json(path, config)
        binary = self.binaries[server]
        check = [binary, "check", "-c", path] if server == "singbox" else [binary, "run", "-test", "-c", path]
        run(check, env=env)
        process = Process([binary, "run", "-c", path], directory, env)
        try:
            if protocol not in UDP_TRANSPORT:
                process.wait_tcp(int(state["PORT_" + protocol.replace("-", "_")]))
            else:
                time.sleep(0.2)
                if not process.alive():
                    raise AssertionError("UDP server exited: " + process.tail())
            return process
        except Exception:
            process.close()
            raise

    def client_config(self, env, protocol, client, port):
        if client == "mihomo":
            full = self.cli(env, "client", "mihomo")
            proxies = full["proxies"]
            assert len(proxies) == 1
            return {"mixed-port": port, "bind-address": "127.0.0.1", "allow-lan": False, "mode": "rule",
                    "log-level": "warning", "ipv6": False, "dns": {"enable": False},
                    "proxies": proxies, "rules": ["MATCH," + proxies[0]["name"]]}
        outbound = self.cli(env, "render", "outbound", protocol, client)
        if client == "singbox":
            full = self.cli(env, "client", "singbox-notun")
            by_tag = {out["tag"]: out for out in full["outbounds"]}
            assert by_tag[outbound["tag"]] == outbound, "client/export disagrees with outbound renderer"
            outbounds = [outbound]
            if outbound.get("detour"):
                outbounds.append(by_tag[outbound["detour"]])
            return {"log": {"level": "warn"}, "dns": {"servers": [{"type": "local", "tag": "local"}]},
                    "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": port}], "outbounds": outbounds,
                    "route": {"final": outbound["tag"], "default_domain_resolver": "local"}}
        full = self.cli(env, "client", "xray")
        first = copy.deepcopy(full["outbounds"][0])
        first["tag"] = outbound["tag"]
        assert first == outbound, "client/export disagrees with outbound renderer"
        return {"log": {"loglevel": "warning"}, "inbounds": [{"listen": "127.0.0.1", "port": port,
                "protocol": "socks", "settings": {"udp": True, "ip": "127.0.0.1"}}], "outbounds": [outbound]}

    def launch_client(self, directory, client, config, env):
        directory.mkdir()
        path = directory / "client.json"
        if os.environ.get("VERBOSE") == "1":
            if client == "mihomo":
                config["log-level"] = "debug"
            else:
                config["log"]["level" if client == "singbox" else "loglevel"] = "debug"
        write_json(path, config)
        binary = self.binaries[client]
        if client == "singbox":
            check, start = [binary, "check", "-c", path], [binary, "run", "-c", path]
        elif client == "xray":
            check, start = [binary, "run", "-test", "-c", path], [binary, "run", "-c", path]
        else:
            check, start = [binary, "-t", "-d", directory, "-f", path], [binary, "-d", directory, "-f", path]
        run(check, env=env)
        return Process(start, directory, env)

    def case(self, protocol, server, profile):
        name = f"{profile}/{server}/{protocol}"
        directory = self.root / name
        state, env = self.state(directory, protocol, server, profile)
        try:
            bundle = self.cli(env, "render", "probe")
            assert bundle["schema"] == 1 and len(bundle["entries"]) == 1
            probe = bundle["entries"][0]
            expected = "udp" if protocol in UDP_TRANSPORT else "both" if protocol == "shadowsocks" else "tcp"
            assert probe["transport"] == expected and probe["id"] == protocol
            assert self.private not in json.dumps(bundle), "probe exports a server private key"
            if protocol in REALITY:
                assert probe["reality"]["sni"] == "reality.test"
            with self.server(directory, protocol, server, state, env) as process:
                for client in self.args.clients:
                    if client not in self.binaries or not client_supported(protocol, client):
                        continue
                    port = self.ports.get()
                    try:
                        config = self.client_config(env, protocol, client, port)
                        with self.launch_client(directory / client, client, config, env) as native:
                            native.wait_tcp(port)
                            for transport, request in [("tcp", tcp_marker), ("udp", udp_marker)]:
                                try:
                                    request(port, self.fixture)
                                    assert native.alive() and process.alive(), "core exited while relaying"
                                    self.record(f"{name}/{client}/{transport}", True)
                                except Exception as error:
                                    self.record(f"{name}/{client}/{transport}", False, str(error) + "\nCLIENT:\n" + native.tail() + "\nSERVER:\n" + process.tail())
                    except Exception as error:
                        self.record(f"{name}/{client}/start", False, str(error))
        except Exception as error:
            self.record(f"{name}/server", False, str(error))

    def negative(self):
        protocol = "anytls-reality"
        directory = self.root / "authentication"
        state, env = self.state(directory, protocol, "singbox", "self")
        try:
            with self.server(directory, protocol, "singbox", state, env) as server:
                for mode in ["positive-before", "wrong-public-key", "wrong-short-id", "wrong-password", "ordinary-tls", "positive-after"]:
                    port = self.ports.get()
                    config = self.client_config(env, protocol, "singbox", port)
                    outbound = config["outbounds"][0]
                    if mode == "wrong-public-key":
                        outbound["tls"]["reality"]["public_key"] = self.wrong_public
                    elif mode == "wrong-short-id":
                        sid = state["REALITY_SHORT_ID"]
                        outbound["tls"]["reality"]["short_id"] = ("1" if sid[0] == "0" else "0") + sid[1:]
                    elif mode == "wrong-password":
                        outbound["password"] += "-wrong"
                    elif mode == "ordinary-tls":
                        outbound["tls"].pop("reality")
                        outbound["tls"]["insecure"] = True
                    try:
                        with self.launch_client(directory / mode, "singbox", config, env) as process:
                            process.wait_tcp(port)
                            reached = False
                            try:
                                tcp_marker(port, self.fixture, timeout=3)
                                reached = True
                            except (OSError, AssertionError, http.client.HTTPException):
                                pass
                            assert process.alive() and server.alive(), "rejection was caused by a core crash"
                            assert reached == mode.startswith("positive"), "unexpected authentication result"
                            self.record(f"authentication/{mode}", True)
                    except Exception as error:
                        self.record(f"authentication/{mode}", False, str(error))
                for client in ["xray", "mihomo"]:
                    result = subprocess.run([self.binaries["onebox"], "client", client], env=env,
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
                    self.record(f"authentication/reject-{client}-export", result.returncode != 0 and not result.stdout)
        except Exception as error:
            self.record("authentication/server", False, str(error))

    def close(self):
        self.fixture.close()


def executable(name, env, default=None):
    value = os.environ.get(env, default)
    if not value:
        return None
    path = Path(value).expanduser().resolve()
    if not path.is_file() or not os.access(path, os.X_OK):
        raise SystemExit(f"{name} executable unavailable: set {env}")
    return str(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--protocols", type=lambda s: s.split(","), default=list(PROTOCOLS))
    parser.add_argument("--servers", type=lambda s: s.split(","), default=["singbox", "xray"])
    parser.add_argument("--clients", type=lambda s: s.split(","), default=["singbox", "xray", "mihomo"])
    parser.add_argument("--profiles", type=lambda s: s.split(","), default=["self", "ca"])
    parser.add_argument("--negative-only", action="store_true")
    parser.add_argument("--skip-negative", action="store_true")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    for values, allowed, label in [(args.protocols, PROTOCOLS, "protocol"), (args.servers, ["singbox", "xray"], "server"),
                                   (args.clients, ["singbox", "xray", "mihomo"], "client"), (args.profiles, ["self", "ca"], "profile")]:
        if not values or any(value not in allowed for value in values):
            parser.error(f"invalid {label} selection")
    binaries = {
        "onebox": executable("onebox", "ONEBOX_TEST_BINARY", str(Path(__file__).resolve().parents[1] / "target/debug/onebox")),
        "singbox": executable("sing-box", "ONEBOX_TEST_SINGBOX", os.environ.get("SB") or shutil.which("sing-box")),
        "xray": executable("Xray", "ONEBOX_TEST_XRAY", os.environ.get("XR") or shutil.which("xray")),
        "mihomo": executable("mihomo", "MH", shutil.which("mihomo")),
    }
    if not binaries["singbox"] or not binaries["xray"]:
        parser.error("set ONEBOX_TEST_SINGBOX and ONEBOX_TEST_XRAY to real native cores")
    binaries = {name: path for name, path in binaries.items() if path}
    if "mihomo" not in binaries and "mihomo" in args.clients:
        print("SKIP optional mihomo client (set MH to include it)", flush=True)
    os.umask(0o077)
    root = Path(tempfile.mkdtemp(prefix="onebox-native-e2e-"))
    matrix = None
    try:
        matrix = Matrix(root, binaries, args)
        if not args.negative_only:
            for profile in args.profiles:
                for protocol in args.protocols:
                    if profile == "ca" and protocol not in CERTIFICATE:
                        continue
                    for server in args.servers:
                        if core_supported(protocol, server):
                            matrix.case(protocol, server, profile)
        if not args.skip_negative and "anytls-reality" in args.protocols:
            matrix.negative()
        failures = sum(not result["ok"] for result in matrix.results)
        report = {"schema": 1, "scope": "isolated-loopback-native-rust-cli", "total": len(matrix.results),
                  "failures": failures, "mihomo": "mihomo" in binaries, "results": matrix.results}
        if args.report:
            write_json(args.report, report)
        print(f"Native E2E: {len(matrix.results)} checks, {failures} failures", flush=True)
        return int(failures > 0)
    finally:
        if matrix:
            matrix.close()
        if os.environ.get("KEEP") == "1":
            print(f"Preserved fixture directory: {root}", flush=True)
        else:
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
