#!/usr/bin/env python3
"""Shared helpers for the black-box suites in tests/e2e (not a suite itself).

Every suite drives the real ``onebox`` binary and real proxy cores against
loopback-only fixtures. This module provides the pieces the suites share:

* the CI tool contract (:func:`tool`, :data:`REQUIRE_FULL`): every
  ``ONEBOX_TEST_*`` variable names an executable; with
  ``ONEBOX_TEST_REQUIRE_FULL=1`` a missing tool, privilege or other skip
  reason is a failure, never a skip;
* :class:`Results`: PASS/FAIL/SKIP records, the summary line, the optional
  JSON report and the exit status (non-zero on any failure);
* :class:`Workspace`: ``umask 077`` plus a private temporary root that is
  removed afterwards unless ``KEEP=1``;
* :class:`Ports`: loopback ports outside the kernel's ephemeral range, so a
  core's outgoing connection can never steal a listener port;
* :class:`Pki`: throw-away CA, CA-signed and self-signed P-256 certificates
  generated with ``openssl`` for each run;
* fixture servers: :class:`MarkerFixtures` (HTTP, TLS 1.3 and UDP echo
  serving one random marker) and :class:`DnsFixture` (authoritative UDP DNS
  that records the queries it receives);
* :class:`Process`: a child in its own session, killed as a process group;
* a SOCKS5 client (:func:`socks_open`, :func:`socks_http_marker`,
  :func:`socks_udp_echo`) and :func:`tls_marker` for direct TLS checks;
* :class:`Layout` and :func:`run_onebox`: an isolated Onebox directory
  layout (every path variable points inside it) holding a v2
  ``{"values": …}`` or v3 schema-3 ``state.json`` and the proxy certificate
  at ``<ONEBOX_DIR>/tls/{cert,key}.pem``;
* :func:`load_yaml`: a strict reader for exactly the YAML subset the v3
  mihomo renderer emits (``client mihomo`` / ``client provider``).

``python3 tests/e2e/_harness.py`` runs this module's self-tests.

Changes from v2 (tests/native_e2e.py was both a suite and the library the
policy suite imported): the helpers live in this module; the mihomo exports
are read as YAML instead of JSON; the CI variable ``ONEBOX_TEST_MIHOMO``
replaces ``MH`` (the ``SB``/``XR`` fallbacks are gone); skips are failures
under ``ONEBOX_TEST_REQUIRE_FULL=1``; the HTTP fixtures no longer do a
reverse DNS lookup when they bind; the layout points every Onebox path
variable (not just seven) at the fixture.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import dataclasses
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
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import unittest.mock
import uuid

REPO = Path(__file__).resolve().parents[2]
REQUIRE_FULL = os.environ.get("ONEBOX_TEST_REQUIRE_FULL") == "1"
VERBOSE = os.environ.get("VERBOSE") == "1"
LOOPBACK = "127.0.0.1"


# ---------------------------------------------------------------------------
# Tool contract and results


class Unavailable(Exception):
    """A prerequisite (tool, privilege) is missing: skip, or fail under REQUIRE_FULL."""


def tool(env_var: str, *, path_names: tuple[str, ...] = (), default: str | None = None) -> str:
    """Return the executable named by ``env_var`` (absolute, resolved).

    A set but unusable variable is always an error (``SystemExit``): it is a
    misconfiguration, not a missing optional tool. An unset variable falls
    back to ``default`` and then to ``path_names`` on ``PATH`` unless
    ``ONEBOX_TEST_REQUIRE_FULL=1``, where CI must name every tool explicitly.
    Raises :class:`Unavailable` when nothing is found.
    """
    value = os.environ.get(env_var)
    if value:
        path = Path(value).expanduser().resolve()
        if not path.is_file() or not os.access(path, os.X_OK):
            raise SystemExit(f"{env_var} is not an executable file: {value}")
        return str(path)
    if REQUIRE_FULL:
        raise Unavailable(f"{env_var} is not set (ONEBOX_TEST_REQUIRE_FULL=1)")
    candidates = [default] if default else []
    candidates += [found for name in path_names if (found := shutil.which(name))]
    for candidate in candidates:
        path = Path(candidate).resolve()
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
    raise Unavailable(f"set {env_var} to an executable")


def onebox_binary() -> str:
    """``ONEBOX_TEST_BINARY``, default ``<repo>/target/debug/onebox``."""
    return tool("ONEBOX_TEST_BINARY", default=str(REPO / "target/debug/onebox"))


class Results:
    """Ordered check results of one suite run."""

    def __init__(self, title: str):
        self.title = title
        self.entries: list[dict] = []

    def record(self, name: str, ok: bool, detail: str = "") -> bool:
        self.entries.append({"name": name, "ok": bool(ok), "detail": detail})
        line = f"{'PASS' if ok else 'FAIL'} {name}" + (f": {detail}" if detail else "")
        print(line, flush=True)
        return bool(ok)

    def skip(self, name: str, reason: str) -> None:
        """A skipped check; a failure under ``ONEBOX_TEST_REQUIRE_FULL=1``."""
        if REQUIRE_FULL:
            self.record(name, False, f"skipped under ONEBOX_TEST_REQUIRE_FULL=1: {reason}")
            return
        self.entries.append({"name": name, "ok": True, "skipped": True, "detail": reason})
        print(f"SKIP {name}: {reason}", flush=True)

    def attempt(self, name: str, action) -> bool:
        """Run ``action()``; any exception is a failure of ``name``."""
        try:
            action()
        except Exception as error:  # noqa: BLE001 - every error fails this check
            return self.record(name, False, describe(error))
        return self.record(name, True)

    @property
    def failures(self) -> int:
        return sum(not entry["ok"] for entry in self.entries)

    @property
    def skipped(self) -> int:
        return sum(bool(entry.get("skipped")) for entry in self.entries)

    def finish(self, report: Path | None = None, **extra) -> int:
        """Print the summary, write the report and return the exit status."""
        checks = len(self.entries) - self.skipped
        print(f"{self.title}: {checks} checks, {self.failures} failures, "
              f"{self.skipped} skipped", flush=True)
        if report:
            write_json(report, {"schema": 1, "suite": self.title, "total": checks,
                                "failures": self.failures, "skipped": self.skipped,
                                **extra, "results": self.entries})
        return int(self.failures > 0 or not self.entries)


# Core name → (CI variable, names looked up on PATH outside REQUIRE_FULL).
TOOL_VARIABLES = {
    "singbox": ("ONEBOX_TEST_SINGBOX", ("sing-box",)),
    "xray": ("ONEBOX_TEST_XRAY", ("xray",)),
    "mihomo": ("ONEBOX_TEST_MIHOMO", ("mihomo",)),
}


def resolve_tools(results: Results, required, optional=()) -> dict[str, str] | None:
    """``onebox`` plus the named cores (keys of :data:`TOOL_VARIABLES`).

    A missing required tool is recorded as the failure ``prerequisites``
    (``None`` is returned); a missing optional one is a skip (a failure
    under REQUIRE_FULL) and is left out of the result.
    """
    tools = {}
    try:
        tools["onebox"] = onebox_binary()
        for name in required:
            variable, names = TOOL_VARIABLES[name]
            tools[name] = tool(variable, path_names=names)
    except Unavailable as error:
        results.record("prerequisites", False, str(error))
        return None
    for name in optional:
        variable, names = TOOL_VARIABLES[name]
        try:
            tools[name] = tool(variable, path_names=names)
        except Unavailable as error:
            results.skip(f"{name}-tool", str(error))
    return tools


def comma_list(allowed):
    """argparse type: a non-empty comma list of values from ``allowed``."""
    def parse(text: str) -> list[str]:
        values = [v for v in text.split(",") if v]
        if not values or any(v not in allowed for v in values):
            raise argparse.ArgumentTypeError(f"choose from {','.join(allowed)}")
        return values
    return parse


def describe(error: BaseException) -> str:
    text = str(error) or type(error).__name__
    return text if isinstance(error, AssertionError) else f"{type(error).__name__}: {text}"


class Workspace:
    """``umask 077`` and a private temporary root, removed unless ``KEEP=1``."""

    def __init__(self, prefix: str):
        self.prefix = prefix
        self.root: Path | None = None

    def __enter__(self) -> Path:
        os.umask(0o077)
        self.root = Path(tempfile.mkdtemp(prefix=self.prefix))
        return self.root

    def __exit__(self, *_):
        if self.root is None:
            return
        if os.environ.get("KEEP") == "1":
            print(f"Preserved fixture directory: {self.root}", flush=True)
        else:
            shutil.rmtree(self.root, ignore_errors=True)


# ---------------------------------------------------------------------------
# Commands and files


class CommandFailed(AssertionError):
    """A checked command exited non-zero."""


@dataclasses.dataclass
class Completed:
    argv: list[str]
    code: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.code == 0


def run(argv, *, env=None, timeout: float = 30, check: bool = True,
        input: bytes | None = None, cwd=None) -> Completed:
    """Run a command with captured, UTF-8 decoded output (stdin closed or ``input``)."""
    args = [str(a) for a in argv]
    result = subprocess.run(args, env=env, cwd=cwd, capture_output=True, timeout=timeout,
                            input=input, stdin=None if input is not None else subprocess.DEVNULL)
    done = Completed(args, result.returncode, result.stdout.decode(errors="replace"),
                     result.stderr.decode(errors="replace"))
    if check and not done.ok:
        raise CommandFailed(f"{Path(args[0]).name} {' '.join(args[1:3])} failed ({done.code}): "
                            f"{done.stderr[-3000:]}{done.stdout[-1000:]}")
    return done


def write_json(path: Path, value, mode: int = 0o600) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
    path.chmod(mode)


# ---------------------------------------------------------------------------
# Ports


def ephemeral_range() -> tuple[int, int]:
    try:
        low, high = map(int, Path("/proc/sys/net/ipv4/ip_local_port_range").read_text().split())
        return low, high
    except (OSError, ValueError):
        return 32768, 60999


class Ports:
    """Loopback ports free for TCP and UDP, never in the ephemeral range.

    Outgoing connections take source ports from the ephemeral range; a
    listener allocated there could be taken by a core's own connection
    between allocation and bind.
    """

    def __init__(self, low: int = 10240):
        start, end = ephemeral_range()
        self.used: set[int] = set()
        self.candidates = [p for p in range(low, 65536) if not start <= p <= end]
        random.SystemRandom().shuffle(self.candidates)

    def get(self) -> int:
        while self.candidates:
            port = self.candidates.pop()
            if port not in self.used and self.bindable(port):
                self.used.add(port)
                return port
        raise AssertionError("no non-ephemeral loopback ports are free")

    @staticmethod
    def bindable(port: int) -> bool:
        try:
            with socket.socket() as tcp, socket.socket(type=socket.SOCK_DGRAM) as udp:
                tcp.bind((LOOPBACK, port))
                udp.bind((LOOPBACK, port))
        except OSError:
            return False
        return True


# ---------------------------------------------------------------------------
# PKI


@dataclasses.dataclass(frozen=True)
class CertPair:
    cert: Path
    key: Path


class Pki:
    """Throw-away P-256 certificates valid for two days (generated per run)."""

    def __init__(self, directory: Path, ca_name: str = "Onebox isolated E2E CA"):
        self.dir = directory
        self.dir.mkdir(parents=True, exist_ok=True)
        self.ca = CertPair(self.dir / "ca.pem", self.dir / "ca.key")
        self._ec_key(self.ca.key)
        run(["openssl", "req", "-new", "-x509", "-sha256", "-days", "2", "-key", self.ca.key,
             "-out", self.ca.cert, "-subj", f"/CN={ca_name}",
             "-addext", "basicConstraints=critical,CA:TRUE"])
        self.bundle = self.dir / "bundle.pem"
        bundle = self.ca.cert.read_bytes()
        system = Path("/etc/ssl/certs/ca-certificates.crt")
        if system.is_file():
            bundle += b"\n" + system.read_bytes()
        self.bundle.write_bytes(bundle)

    @staticmethod
    def _ec_key(path: Path) -> None:
        run(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", path])

    def leaf(self, name: str) -> CertPair:
        """A CA-signed server certificate for DNS name ``name``."""
        pair = CertPair(self.dir / f"{name}.pem", self.dir / f"{name}.key")
        csr, ext = self.dir / f"{name}.csr", self.dir / f"{name}.ext"
        self._ec_key(pair.key)
        run(["openssl", "req", "-new", "-key", pair.key, "-out", csr, "-subj", f"/CN={name}"])
        ext.write_text(f"subjectAltName=DNS:{name}\nextendedKeyUsage=serverAuth\n")
        run(["openssl", "x509", "-req", "-sha256", "-days", "2", "-in", csr, "-CA", self.ca.cert,
             "-CAkey", self.ca.key, "-CAcreateserial", "-extfile", ext, "-out", pair.cert])
        return pair

    def self_signed(self, name: str, stem: str = "self") -> CertPair:
        """A self-signed certificate for ``name`` (what Onebox's self-signed mode deploys)."""
        pair = CertPair(self.dir / f"{stem}.pem", self.dir / f"{stem}.key")
        run(["openssl", "req", "-new", "-x509", "-newkey", "ec", "-pkeyopt",
             "ec_paramgen_curve:P-256", "-nodes", "-days", "2", "-keyout", pair.key,
             "-out", pair.cert, "-subj", f"/CN={name}", "-addext", f"subjectAltName=DNS:{name}"])
        return pair


# ---------------------------------------------------------------------------
# Fixture servers


def _marker_handler(marker: bytes):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def do_GET(self):  # noqa: N802 - http.server API
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(marker)))
            self.end_headers()
            with contextlib.suppress(OSError):
                self.wfile.write(marker)

        def log_message(self, *_):
            pass

    return Handler


class _HttpServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def server_bind(self):
        # HTTPServer.server_bind does a reverse DNS lookup (getfqdn), which
        # can stall for seconds on hosts without working DNS.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


class _TlsServer(_HttpServer):
    tls: ssl.SSLContext

    def finish_request(self, request, client_address):
        # REALITY legitimately leaves target handshakes incomplete: handshake
        # in each worker thread with a deadline, never in the accept loop.
        request.settimeout(8)
        try:
            with self.tls.wrap_socket(request, server_side=True) as encrypted:
                self.RequestHandlerClass(encrypted, client_address, self)
        except (OSError, ssl.SSLError):
            pass


class MarkerFixtures:
    """HTTP, TLS 1.3 (ALPN h2/http1.1) and UDP echo servers on loopback.

    HTTP and TLS answer every GET with :attr:`marker`; the UDP server echoes
    each datagram. ``tls_pair`` is the certificate the TLS server presents.
    """

    def __init__(self, ports: Ports, tls_pair: CertPair, prefix: str = "onebox-e2e-"):
        self.marker = (prefix + secrets.token_hex(24)).encode()
        self.http_port, self.tls_port, self.udp_port = ports.get(), ports.get(), ports.get()
        self.closed = threading.Event()
        self.servers: list[_HttpServer] = []
        self.threads: list[threading.Thread] = []
        handler = _marker_handler(self.marker)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.minimum_version = ssl.TLSVersion.TLSv1_3
        tls.set_alpn_protocols(["h2", "http/1.1"])
        tls.load_cert_chain(tls_pair.cert, tls_pair.key)
        plain = _HttpServer((LOOPBACK, self.http_port), handler)
        encrypted = _TlsServer((LOOPBACK, self.tls_port), handler)
        encrypted.tls = tls
        for server in (plain, encrypted):
            self.servers.append(server)
            self._thread(server.serve_forever, poll_interval=0.05)
        self.udp = socket.socket(type=socket.SOCK_DGRAM)
        self.udp.bind((LOOPBACK, self.udp_port))
        self.udp.settimeout(0.1)
        self._thread(self._echo)

    def _thread(self, target, **kwargs):
        thread = threading.Thread(target=target, kwargs=kwargs, daemon=True)
        thread.start()
        self.threads.append(thread)

    def _echo(self):
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


def dns_answer(message: bytes, records: dict[str, str]) -> tuple[bytes | None, tuple[str, int] | None]:
    """Answer one DNS query from ``records`` (lower-case name → IPv4).

    Returns ``(response, (name, qtype))``; ``(None, None)`` for anything that
    is not a single uncompressed question. Unknown names get NXDOMAIN, known
    names with another type an empty NOERROR answer.
    """
    try:
        if len(message) < 12 or struct.unpack("!H", message[4:6])[0] != 1:
            return None, None
        offset, labels = 12, []
        while message[offset]:
            size = message[offset]
            if size > 63:
                return None, None
            labels.append(message[offset + 1:offset + 1 + size].decode("ascii"))
            offset += 1 + size
        offset += 1
        qtype, qclass = struct.unpack("!HH", message[offset:offset + 4])
        offset += 4
    except (IndexError, UnicodeError, struct.error):
        return None, None
    name = ".".join(labels).lower()
    answer = b""
    if name in records and qtype == 1 and qclass == 1:
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 0, 4) + socket.inet_aton(records[name])
    flags = 0x8180 if name in records else 0x8183
    header = message[:2] + struct.pack("!HHHHH", flags, 1, int(bool(answer)), 0, 0)
    return header + message[12:offset] + answer, (name, qtype)


class DnsFixture:
    """Authoritative UDP DNS on loopback; records every query it answers."""

    def __init__(self, port: int, records: dict[str, str]):
        self.port = port
        self.records = {name.lower(): ip for name, ip in records.items()}
        self.socket = socket.socket(type=socket.SOCK_DGRAM)
        self.socket.bind((LOOPBACK, port))
        self.socket.settimeout(0.1)
        self.closed = threading.Event()
        self.lock = threading.Lock()
        self.queries: list[tuple[str, int]] = []
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while not self.closed.is_set():
            try:
                message, peer = self.socket.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            response, query = dns_answer(message, self.records)
            if response is None:
                continue
            with self.lock:
                self.queries.append(query)
            with contextlib.suppress(OSError):
                self.socket.sendto(response, peer)

    def queried(self, name: str, qtype: int = 1) -> bool:
        with self.lock:
            return (name.lower(), qtype) in self.queries

    def reset(self):
        with self.lock:
            self.queries.clear()

    def close(self):
        self.closed.set()
        self.socket.close()
        self.thread.join(timeout=1)


# ---------------------------------------------------------------------------
# Processes


class Process:
    """A child in a new session; :meth:`close` terminates its process group.

    Output goes to ``<directory>/<name>.log`` (shown by :meth:`tail` in
    failure details).
    """

    def __init__(self, argv, directory: Path, env, name: str = "process"):
        self.log_path = directory / f"{name}.log"
        self.log = self.log_path.open("wb")
        try:
            self.child = subprocess.Popen([str(a) for a in argv], cwd=directory, env=env,
                                          stdin=subprocess.DEVNULL, stdout=self.log,
                                          stderr=self.log, start_new_session=True)
        except Exception:
            self.log.close()
            raise

    def alive(self) -> bool:
        return self.child.poll() is None

    def wait_tcp(self, port: int, timeout: float = 8, host: str = LOOPBACK) -> None:
        """Wait until ``host:port`` accepts TCP; the child must stay alive."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not self.alive():
                raise AssertionError("process exited during startup: " + self.tail())
            try:
                with socket.create_connection((host, port), timeout=0.1):
                    return
            except OSError:
                time.sleep(0.03)
        raise AssertionError(f"process did not open {host}:{port}: " + self.tail())

    def wait_file(self, path: Path, content: str, timeout: float = 8) -> None:
        """Wait until ``path`` holds exactly ``content`` (a readiness marker)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not self.alive():
                raise AssertionError("process exited before finishing startup: " + self.tail())
            with contextlib.suppress(OSError):
                if path.is_file() and path.read_text() == content:
                    return
            time.sleep(0.01)
        raise AssertionError("process did not finish startup: " + self.tail())

    def stay_alive(self, seconds: float) -> None:
        """Startup check for UDP-only listeners: still running after ``seconds``."""
        time.sleep(seconds)
        if not self.alive():
            raise AssertionError("process exited during startup: " + self.tail())

    def tail(self, size: int = 3000) -> str:
        with contextlib.suppress(ValueError):
            self.log.flush()
        return self.log_path.read_text(errors="replace")[-size:]

    def close(self) -> None:
        # Only a live leader is signalled: after it has been reaped its PID
        # (and so the process-group ID) may belong to an unrelated session.
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


# ---------------------------------------------------------------------------
# SOCKS5 and marker requests


def recv_exact(sock: socket.socket, count: int) -> bytes:
    data = bytearray()
    while len(data) < count:
        block = sock.recv(count - len(data))
        if not block:
            raise OSError("premature EOF")
        data.extend(block)
    return bytes(data)


def socks_address(host: str) -> bytes:
    """SOCKS5 ATYP + address: IPv4, IPv6 or a domain name."""
    for family, atyp in ((socket.AF_INET, 1), (socket.AF_INET6, 4)):
        with contextlib.suppress(OSError):
            return bytes([atyp]) + socket.inet_pton(family, host)
    name = host.encode("ascii")
    if not 0 < len(name) < 256:
        raise ValueError(f"invalid SOCKS host name: {host!r}")
    return b"\x03" + bytes([len(name)]) + name


def _read_socks_address(sock: socket.socket, atyp: int) -> str:
    if atyp == 1:
        return socket.inet_ntop(socket.AF_INET, recv_exact(sock, 4))
    if atyp == 4:
        return socket.inet_ntop(socket.AF_INET6, recv_exact(sock, 16))
    if atyp == 3:
        return recv_exact(sock, recv_exact(sock, 1)[0]).decode("ascii")
    raise OSError("invalid SOCKS address type")


SOCKS_CONNECT, SOCKS_UDP_ASSOCIATE = 1, 3


def socks_open(proxy_port: int, command: int, host: str, port: int,
               timeout: float = 5) -> tuple[socket.socket, str, int]:
    """No-auth SOCKS5 handshake + command; returns (stream, bound host, bound port)."""
    stream = socket.create_connection((LOOPBACK, proxy_port), timeout=timeout)
    try:
        stream.sendall(b"\x05\x01\x00")
        if recv_exact(stream, 2) != b"\x05\x00":
            raise OSError("SOCKS authentication failed")
        stream.sendall(bytes([5, command, 0]) + socks_address(host) + struct.pack("!H", port))
        reply = recv_exact(stream, 4)
        if reply[:3] != b"\x05\x00\x00":
            raise OSError(f"SOCKS command rejected (reply {reply[1]})")
        bound = _read_socks_address(stream, reply[3])
        bound_port = struct.unpack("!H", recv_exact(stream, 2))[0]
        return stream, bound, bound_port
    except BaseException:
        stream.close()
        raise


def read_marker(stream, host: str, marker: bytes) -> None:
    """One HTTP/1.1 GET over ``stream``; expects 200 and exactly ``marker``."""
    stream.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: onebox-e2e/3\r\n"
                   "Accept: */*\r\nConnection: close\r\n\r\n".encode())
    response = http.client.HTTPResponse(stream)
    response.begin()
    body = response.read(len(marker) + 1)
    if response.status != 200 or body != marker:
        raise AssertionError(f"HTTP marker mismatch (status={response.status})")


def socks_http_marker(proxy_port: int, host: str, port: int, marker: bytes,
                      timeout: float = 10) -> None:
    """CONNECT ``host:port`` through the proxy, then :func:`read_marker`."""
    stream, _, _ = socks_open(proxy_port, SOCKS_CONNECT, host, port, timeout)
    with stream:
        read_marker(stream, f"{host}:{port}", marker)


def socks_udp_echo(proxy_port: int, ip: str, port: int, marker: bytes,
                   attempts: int = 3, wait: float = 2) -> None:
    """UDP ASSOCIATE, then a datagram to ``ip:port`` whose echo must come back."""
    stream, relay, relay_port = socks_open(proxy_port, SOCKS_UDP_ASSOCIATE, "0.0.0.0", 0)
    with stream:
        if relay in ("0.0.0.0", "::"):
            relay = LOOPBACK
        family = socket.AF_INET6 if ":" in relay else socket.AF_INET
        payload = marker + secrets.token_bytes(16)
        header = b"\x00\x00\x00" + socks_address(ip) + struct.pack("!H", port)
        with socket.socket(family, socket.SOCK_DGRAM) as datagram:
            datagram.settimeout(wait)
            for _ in range(attempts):
                datagram.sendto(header + payload, (relay, relay_port))
                try:
                    reply, _ = datagram.recvfrom(65535)
                except socket.timeout:
                    continue
                if reply[:3] == b"\x00\x00\x00" and reply.endswith(payload):
                    return
        raise AssertionError("no matching SOCKS UDP echo")


def tls_marker(port: int, server_name: str | None, marker: bytes, timeout: float = 3) -> None:
    """Direct TLS 1.3 to loopback ``port`` with SNI ``server_name`` (None: no SNI).

    The peer is deliberately not verified: negative SNI checks must fail at
    the server under test, never at local certificate validation.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(["http/1.1"])
    with socket.create_connection((LOOPBACK, port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=server_name) as stream:
            read_marker(stream, server_name or "no-sni.test", marker)


def reached(action) -> tuple[bool, str]:
    """Run a traffic ``action``; (True, "") on success, (False, reason) on a network failure."""
    try:
        action()
    except (OSError, AssertionError, http.client.HTTPException) as error:
        return False, describe(error)
    return True, ""


# ---------------------------------------------------------------------------
# Onebox layout


# Every Onebox path variable (src/paths.rs) except ONEBOX_SYSTEM_ROOT, which
# would hide the real /proc and /sys; suites that need it pass it in `extra`.
PATH_VARIABLES = {
    "ONEBOX_DIR": "etc/onebox",
    "ONEBOX_BIN_DIR": "opt/onebox/bin",
    "ONEBOX_LOG_DIR": "var/log/onebox",
    "ONEBOX_RUN_DIR": "run/onebox",
    "ONEBOX_SITE_ROOT": "var/lib/onebox-site",
    "ONEBOX_SYSTEMD_DIR": "etc/systemd/system",
    "ONEBOX_INITD_DIR": "etc/init.d",
    "ONEBOX_EXE": "usr/local/bin/onebox",
    "ONEBOX_FRPS_DIR": "etc/onebox-frp",
    "ONEBOX_FRPS_BIN_DIR": "opt/onebox-frp",
    "ONEBOX_FRPS_WEB_VAR": "var/lib/onebox-frp",
    "ONEBOX_FRPS_LOG_DIR": "var/log/onebox-frp",
    "ONEBOX_FRPS_RUN_DIR": "run/onebox-frp",
    "ONEBOX_BBR_DIR": "var/lib/onebox-bbr",
    "ONEBOX_BBR_CONF": "etc/sysctl.d/99-onebox-bbr.conf",
}

# Host variables that would change what the program does.
_LEAKY = ("GH_PROXY", "BASH_ENV", "ENV")


def clean_env(**extra: str) -> dict[str, str]:
    """``os.environ`` without ``ONEBOX_*`` / proxy-mirror variables, plus ``NO_COLOR=1``."""
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("ONEBOX_") and k not in _LEAKY}
    env["NO_COLOR"] = "1"
    env.update(extra)
    return env


class Layout:
    """An isolated Onebox installation layout under ``root``.

    Directories are created lazily by the program, except ``ONEBOX_DIR`` and
    its ``tls`` directory, which the fixture fills.
    """

    def __init__(self, root: Path, base_env: dict[str, str] | None = None):
        self.root = root
        self.paths = {name: root / rel for name, rel in PATH_VARIABLES.items()}
        self.etc = self.paths["ONEBOX_DIR"]
        self.tls = self.etc / "tls"
        self.state_path = self.etc / "state.json"
        self.base_env = dict(base_env) if base_env is not None else clean_env()
        self.tls.mkdir(parents=True, exist_ok=True, mode=0o700)

    def env(self, **extra: str) -> dict[str, str]:
        env = dict(self.base_env)
        env.update({name: str(path) for name, path in self.paths.items()})
        env.update(extra)
        return env

    def install_proxy_cert(self, pair: CertPair) -> CertPair:
        """Deploy ``pair`` where Onebox keeps the proxy certificate."""
        deployed = CertPair(self.tls / "cert.pem", self.tls / "key.pem")
        shutil.copyfile(pair.cert, deployed.cert)
        shutil.copyfile(pair.key, deployed.key)
        deployed.cert.chmod(0o644)
        deployed.key.chmod(0o600)
        return deployed

    def write_v2_state(self, values: dict[str, str]) -> None:
        """A v2 ``{"values": {KEY: "string"}}`` state (migrated by every command)."""
        if any(not isinstance(v, str) for v in values.values()):
            raise TypeError("v2 state values must be strings")
        write_json(self.state_path, {"values": values})

    def write_state(self, config: dict) -> None:
        """A v3 schema-3 ``state.json``."""
        if config.get("schema") != 3:
            raise ValueError("v3 state needs schema 3")
        write_json(self.state_path, config)

    def read_state(self) -> dict:
        return json.loads(self.state_path.read_text())


def run_onebox(binary: str, env: dict[str, str], *args: str, check: bool = True,
               timeout: float = 30, input: bytes | None = None) -> Completed:
    """Run ``onebox ARGS`` with ``env`` (normally :meth:`Layout.env`)."""
    return run([binary, *args], env=env, check=check, timeout=timeout, input=input)


def onebox_json(binary: str, env: dict[str, str], *args: str):
    """Run ``onebox ARGS`` and parse its stdout as JSON."""
    out = run_onebox(binary, env, *args).stdout
    try:
        return json.loads(out)
    except ValueError as error:
        raise AssertionError(f"onebox {' '.join(args)}: stdout is not JSON: {error}") from error


def onebox_yaml(binary: str, env: dict[str, str], *args: str):
    """Run ``onebox ARGS`` and parse its stdout with :func:`load_yaml`."""
    out = run_onebox(binary, env, *args).stdout
    try:
        return load_yaml(out)
    except YamlError as error:
        raise AssertionError(f"onebox {' '.join(args)}: stdout is not the expected YAML: {error}") from error


def x25519_pair(xray: str, env=None) -> tuple[str, str]:
    """(private, public) REALITY keys from ``xray x25519`` (old and new label styles)."""
    text = run([xray, "x25519"], env=env).stdout
    pairs = {name.strip().lower(): value.strip()
             for name, value in (line.split(":", 1) for line in text.splitlines() if ":" in line)}
    private = next((v for k, v in pairs.items() if "private" in k), None)
    public = next((v for k, v in pairs.items() if "public" in k), None)
    if not private or not public:
        raise AssertionError(f"unexpected xray x25519 output: {text!r}")
    return private, public


def random_ss_key(size: int = 16) -> str:
    """Base64 key for Shadowsocks 2022 / ShadowTLS (``size`` bytes)."""
    return base64.b64encode(secrets.token_bytes(size)).decode()


# ---------------------------------------------------------------------------
# Node fixtures (v2 and v3 state of the same node)

PROTOCOLS = (
    "vless-reality", "vless-xhttp", "vless-grpc", "vless-ws", "vmess-ws",
    "trojan", "shadowsocks", "hysteria2", "tuic", "anytls", "shadowtls",
    "anytls-reality",
)
SINGBOX_ONLY = frozenset({"tuic", "anytls", "shadowtls", "anytls-reality"})
# Protocols that always need the proxy certificate; VMess-WS needs it only
# with VMess TLS (src/domain/protocol.rs capability table).
CERTIFICATE_PROTOCOLS = frozenset({"vless-ws", "trojan", "hysteria2", "tuic", "anytls"})
REALITY_PROTOCOLS = frozenset({"vless-reality", "vless-grpc", "vless-xhttp", "anytls-reality"})
UDP_PROTOCOLS = frozenset({"hysteria2", "tuic"})
STATE_FORMS = ("v2", "v3")


def core_supports(core: str, protocol: str) -> bool:
    """Server-core support (spec A §2.3): Xray lacks four, sing-box lacks XHTTP."""
    return protocol != "vless-xhttp" if core == "singbox" else protocol not in SINGBOX_ONLY


def transport_of(protocol: str) -> str:
    """Probe-bundle transport of a protocol."""
    if protocol in UDP_PROTOCOLS:
        return "udp"
    return "both" if protocol == "shadowsocks" else "tcp"


@dataclasses.dataclass
class Inbound:
    protocol: str
    port: int
    core: str


@dataclasses.dataclass
class FixtureNode:
    """One loopback node, writable as a v2 ``{"values"}`` or v3 schema-3 state.

    Both forms describe the same node, so v3 must render them identically
    (the v2 form goes through the real migration on every command).
    ``proxy_cert`` is deployed to ``<ONEBOX_DIR>/tls``; ``custom_source`` is
    the import source recorded for a custom certificate.
    """

    inbounds: list[Inbound]
    reality_keys: tuple[str, str]
    reality_dest: str
    guard_port: int
    proxy_cert: CertPair
    tls_mode: str = "self"                 # "self" | "custom"
    custom_source: CertPair | None = None
    pinned: bool = True
    vmess_tls: bool = False
    hy2_obfs: bool = False
    block_private: bool = False
    block_bt: bool = True
    own_cidrs: list[str] = dataclasses.field(default_factory=list)
    reality_sni: str = "reality.test"
    shadowtls_sni: str = "reality.test"
    shadowtls_dest: str | None = None      # None: same as reality_dest
    tls_name: str = "onebox.test"
    node_name: str = "native-e2e"
    address: str = LOOPBACK
    paths: dict[str, str] = dataclasses.field(default_factory=lambda: {
        "ws": "/native-ws", "vmess": "/native-vmess", "xhttp": "/native-xhttp", "grpc": "native-grpc"})
    creds: dict[str, str] = dataclasses.field(default_factory=lambda: {
        "uuid": str(uuid.uuid4()),
        "password": secrets.token_hex(24),
        "ss_password": random_ss_key(),
        "shadowtls_password": secrets.token_hex(24),
        "shadowtls_ss_password": random_ss_key(),
        "hy2_obfs_password": secrets.token_hex(24),
        "clash_secret": secrets.token_hex(16),
        "short_id": secrets.token_hex(8),
    })

    def protocols(self) -> list[str]:
        return [inbound.protocol for inbound in self.inbounds]

    def inbound(self, protocol: str) -> Inbound:
        return next(i for i in self.inbounds if i.protocol == protocol)

    def needs_cert(self) -> bool:
        protocols = self.protocols()
        return (any(p in CERTIFICATE_PROTOCOLS for p in protocols)
                or ("vmess-ws" in protocols and self.vmess_tls))

    def hy2_profile(self) -> str | None:
        # Xray cannot apply Hysteria2 tuning: v3 rejects it, v2 ignored it.
        hy2 = [i for i in self.inbounds if i.protocol == "hysteria2"]
        return "auto" if hy2 and hy2[0].core == "singbox" else None

    def write(self, layout: Layout, form: str) -> None:
        """Deploy the certificate and write ``state.json`` in ``form`` (v2|v3)."""
        layout.install_proxy_cert(self.proxy_cert)
        if form == "v2":
            layout.write_v2_state(self.v2_values(layout))
        elif form == "v3":
            layout.write_state(self.v3_config())
        else:
            raise ValueError(f"unknown state form {form!r}")

    def v2_values(self, layout: Layout) -> dict[str, str]:
        """The keys a v2.0.1 install writes (spec A §3.4), all strings."""
        flag = lambda value: "1" if value else "0"  # noqa: E731
        private, public = self.reality_keys
        c, p = self.creds, self.paths
        values = {
            "PROTOCOLS": " ".join(self.protocols()), "SERVER_ADDR": self.address,
            "SERVER_IPV4": self.address, "SERVER_IPV6": "", "LISTEN_ADDR": self.address,
            "NODE_NAME": self.node_name, "UUID": c["uuid"], "PASSWORD": c["password"],
            "SS_METHOD": "2022-blake3-aes-128-gcm", "SS_PASSWORD": c["ss_password"],
            "SHADOWTLS_PASSWORD": c["shadowtls_password"],
            "SHADOWTLS_SS_PASSWORD": c["shadowtls_ss_password"], "CLASH_SECRET": c["clash_secret"],
            "REALITY_PRIVATE_KEY": private, "REALITY_PUBLIC_KEY": public,
            "REALITY_SHORT_ID": c["short_id"], "REALITY_SNI": self.reality_sni,
            "REALITY_DEST": self.reality_dest, "SHADOWTLS_SNI": self.shadowtls_sni,
            "SHADOWTLS_DEST": self.shadowtls_dest or self.reality_dest,
            "REALITY_GUARD_PORT": str(self.guard_port), "REALITY_SITE_ENABLED": "0",
            "REALITY_SITE_HTTPS": "0", "WS_PATH": p["ws"], "VMESS_PATH": p["vmess"],
            "XHTTP_PATH": p["xhttp"], "GRPC_SERVICE": p["grpc"],
            "VMESS_TLS": flag(self.vmess_tls), "HY2_OBFS": flag(self.hy2_obfs),
            "HY2_OBFS_PASSWORD": c["hy2_obfs_password"], "HY2_PROFILE": self.hy2_profile() or "",
            "RESOURCE_PROFILE": "balanced", "TLS_MODE": self.tls_mode, "TLS_SNI": self.tls_name,
            "DOMAIN": self.tls_name, "CERT_PINNED": flag(self.pinned),
            "CERT_FILE": str(layout.tls / "cert.pem"), "KEY_FILE": str(layout.tls / "key.pem"),
            "BLOCK_PRIVATE": flag(self.block_private), "BLOCK_BT": flag(self.block_bt),
        }
        if self.own_cidrs:
            values["OWN_IP_CIDRS"] = json.dumps(self.own_cidrs)
        if self.tls_mode == "custom" and self.custom_source:
            values["CUSTOM_CERT"] = str(self.custom_source.cert)
            values["CUSTOM_KEY"] = str(self.custom_source.key)
        for inbound in self.inbounds:
            key = inbound.protocol.replace("-", "_")
            values[f"PORT_{key}"] = str(inbound.port)
            values[f"CORE_{key}"] = inbound.core
        return values

    def v3_tls(self) -> dict | None:
        if not self.needs_cert():
            return None
        if self.tls_mode == "self":
            return {"mode": {"type": "self-signed", "sni": self.tls_name}, "pinned": True}
        source = self.custom_source or self.proxy_cert
        return {"mode": {"type": "custom", "domain": self.tls_name, "cert": str(source.cert),
                         "key": str(source.key)}, "pinned": self.pinned}

    def v3_config(self) -> dict:
        """The same node as a schema-3 ``NodeConfig`` (src/domain/config.rs)."""
        private, public = self.reality_keys
        c, p = self.creds, self.paths
        protocols = self.protocols()
        reality = any(proto in REALITY_PROTOCOLS for proto in protocols)
        return {
            "schema": 3, "node_name": self.node_name,
            "server": {"addr": self.address, "ipv4": self.address, "ipv6": None,
                       "ipv4_warp": False, "ipv6_warp": False},
            "listen": self.address,
            "inbounds": [dataclasses.asdict(inbound) for inbound in self.inbounds],
            "creds": {
                "uuid": c["uuid"], "password": c["password"],
                "ss_method": "2022-blake3-aes-128-gcm", "ss_password": c["ss_password"],
                "hy2_obfs_password": c["hy2_obfs_password"],
                "shadowtls_password": c["shadowtls_password"],
                "shadowtls_ss_password": c["shadowtls_ss_password"],
                "clash_secret": c["clash_secret"],
                "reality": ({"private_key": private, "public_key": public,
                             "short_id": c["short_id"]} if reality else None),
                "ws_path": p["ws"], "vmess_path": p["vmess"], "xhttp_path": p["xhttp"],
                "grpc_service": p["grpc"],
            },
            "reality": {"sni": self.reality_sni, "dest": self.reality_dest,
                        "guard_port": self.guard_port},
            "shadowtls": {"sni": self.shadowtls_sni,
                          "dest": self.shadowtls_dest or self.reality_dest},
            "site": None,
            "tls": self.v3_tls(),
            "vmess_tls": self.vmess_tls and "vmess-ws" in protocols,
            # v2's DOMAIN is the Host header of plain VMess-WS clients.
            "vmess_host": self.tls_name if "vmess-ws" in protocols else None,
            "hy2": {"obfs": self.hy2_obfs, "hop": None, "profile": self.hy2_profile(),
                    "up_mbps": None, "down_mbps": None},
            "resource_profile": "balanced",
            "routing": {"block_private": self.block_private, "block_bt": self.block_bt,
                        "own_cidrs": list(self.own_cidrs)},
            "subscription": None,
            "versions": {},
            "installed_at": 0,
        }


# ---------------------------------------------------------------------------
# Proxy cores (sing-box, Xray, mihomo)

CORES = ("singbox", "xray", "mihomo")


def core_check(kind: str, binary: str, path: Path, env) -> None:
    """The core's own configuration check (a failure raises CommandFailed)."""
    argv = {
        "singbox": [binary, "check", "-c", path],
        "xray": [binary, "run", "-test", "-c", path],
        "mihomo": [binary, "-t", "-d", path.parent, "-f", path],
    }[kind]
    run(argv, env=env)


def core_start(kind: str, binary: str, path: Path, env, name: str = "core") -> Process:
    """Check ``path`` and start the core in ``path.parent``.

    mihomo opens its listener before it has applied the configuration and
    closes early connections, and its "configuration complete" log only
    means parsing ended. Its ``-post-up`` hook runs after ApplyConfig
    returns, so the marker file it writes proves readiness without warming
    up or retrying proxy traffic (mihomo v1.19.32 main.go / hub/executor).
    """
    core_check(kind, binary, path, env)
    directory = path.parent
    if kind == "mihomo":
        ready = directory / "mihomo.ready"
        # Fixed shell command; cwd is this fixture directory.
        argv = [binary, "-d", directory, "-f", path, "-post-up", "printf ready > mihomo.ready"]
        process = Process(argv, directory, env, name)
        try:
            process.wait_file(ready, "ready")
        except BaseException:
            process.close()
            raise
        return process
    return Process([binary, "run", "-c", path], directory, env, name)


def set_log_level(kind: str, config: dict, level: str) -> None:
    if kind == "mihomo":
        config["log-level"] = level
    elif kind == "singbox":
        config.setdefault("log", {})["level"] = level
    else:
        config.setdefault("log", {})["loglevel"] = level


def socks_client(kind: str, port: int, outbounds: list[dict], *, udp_ip: bool = True) -> dict:
    """A client core with a loopback SOCKS5 inbound on ``port`` and only ``outbounds``.

    For mihomo ``outbounds`` are its ``proxies`` entries and every request
    goes to the first one. ``udp_ip`` sets Xray's UDP relay address.
    """
    first = outbounds[0]
    if kind == "singbox":
        return {"log": {"level": "warn"}, "dns": {"servers": [{"type": "local", "tag": "local"}]},
                "inbounds": [{"type": "socks", "listen": LOOPBACK, "listen_port": port}],
                "outbounds": outbounds,
                "route": {"final": first["tag"], "default_domain_resolver": "local"}}
    if kind == "xray":
        settings = {"udp": True, **({"ip": LOOPBACK} if udp_ip else {})}
        return {"log": {"loglevel": "warning"},
                "inbounds": [{"listen": LOOPBACK, "port": port, "protocol": "socks",
                              "settings": settings}],
                "outbounds": outbounds}
    return {"mixed-port": port, "bind-address": LOOPBACK, "allow-lan": False, "mode": "rule",
            "log-level": "warning", "ipv6": False, "dns": {"enable": False},
            "proxies": outbounds, "rules": ["MATCH," + first["name"]]}


# Logical targets of the relay checks. Only the server under test rewrites
# them to the loopback fixtures (rewrite_targets), so a direct connection
# can never satisfy a check.
TARGET_NAME = "native-e2e.invalid"
TARGET_IP = "192.0.2.53"


def rewrite_targets(kind: str, config: dict) -> None:
    """Make a rendered server send TARGET_NAME / TARGET_IP to loopback (test-only edit)."""
    if kind == "singbox":
        rewrite = [
            {"domain": [TARGET_NAME], "action": "route-options", "override_address": LOOPBACK},
            {"ip_cidr": [TARGET_IP + "/32"], "action": "route-options", "override_address": LOOPBACK},
        ]
        config["route"]["rules"] = rewrite + config["route"].get("rules", [])
        return
    config["outbounds"].append({"tag": "native-target", "protocol": "freedom", "settings": {
        "redirect": f"{LOOPBACK}:0", "finalRules": [{"action": "allow"}]}})
    config["routing"]["rules"] = [
        {"type": "field", "domain": ["full:" + TARGET_NAME], "outboundTag": "native-target"},
        {"type": "field", "ip": [TARGET_IP + "/32"], "outboundTag": "native-target"},
    ] + config["routing"].get("rules", [])


def abstract_socket_bound(name: str) -> bool:
    """Whether the abstract unix socket ``@name`` is bound in this network namespace."""
    try:
        lines = Path("/proc/net/unix").read_text().splitlines()[1:]
    except OSError:
        return False
    return any(line.split()[-1] == "@" + name for line in lines if len(line.split()) >= 8)


class Bench:
    """Fixtures shared by the proxy suites.

    ``tools`` maps ``onebox``/``singbox``/``xray``/``mihomo`` to executables
    (``xray`` is required: it generates the REALITY keys). Provides ports,
    the PKI (``reality.test`` leaf for the TLS fixture, CA-signed and
    self-signed ``onebox.test``), the marker servers, REALITY keys plus an
    unrelated public key for negative checks, and a base environment that
    trusts the test CA through ``SSL_CERT_FILE``.
    """

    def __init__(self, root: Path, tools: dict[str, str], results: Results,
                 marker_prefix: str = "onebox-e2e-"):
        self.root, self.tools, self.results = root, tools, results
        self.ports = Ports()
        self.pki = Pki(root / "pki")
        self.reality_cert = self.pki.leaf("reality.test")
        self.ca_cert = self.pki.leaf("onebox.test")
        self.self_cert = self.pki.self_signed("onebox.test")
        self.fixture = MarkerFixtures(self.ports, self.reality_cert, prefix=marker_prefix)
        self.base_env = clean_env(SSL_CERT_FILE=str(self.pki.bundle))
        self.keys = x25519_pair(tools["xray"], self.base_env)
        self.wrong_public = x25519_pair(tools["xray"], self.base_env)[1]

    def close(self) -> None:
        self.fixture.close()

    def node(self, protocols: list[tuple[str, str]], *, custom_ca: bool = False,
             **overrides) -> FixtureNode:
        """A node with fresh ports for ``(protocol, core)`` pairs.

        ``custom_ca`` selects the CA-signed custom certificate (not pinned,
        VMess over TLS, Hysteria2 obfuscation) instead of the self-signed one.
        REALITY and ShadowTLS hand shakes go to the TLS marker fixture.
        """
        cert = self.ca_cert if custom_ca else self.self_cert
        settings = dict(
            inbounds=[Inbound(p, self.ports.get(), core) for p, core in protocols],
            reality_keys=self.keys, reality_dest=f"{LOOPBACK}:{self.fixture.tls_port}",
            guard_port=self.ports.get(), proxy_cert=cert,
            tls_mode="custom" if custom_ca else "self",
            custom_source=cert if custom_ca else None, pinned=not custom_ca,
            vmess_tls=custom_ca, hy2_obfs=custom_ca)
        settings.update(overrides)
        return FixtureNode(**settings)

    def layout(self, directory: Path) -> Layout:
        """A fresh case directory with an isolated layout in ``<directory>/root``."""
        directory.mkdir(parents=True)
        return Layout(directory / "root", self.base_env)

    def onebox(self, env, *args):
        return onebox_json(self.tools["onebox"], env, *args)

    def outbound(self, env, protocol: str, core: str) -> dict:
        return self.onebox(env, "render", "outbound", protocol, core)

    def server_config(self, env, kind: str) -> dict:
        """``render server`` with :func:`rewrite_targets` and an informative log level."""
        config = self.onebox(env, "render", "server", kind)
        # Keep fixture connection diagnostics in the log for failure reports.
        set_log_level(kind, config, "debug" if VERBOSE else "info")
        rewrite_targets(kind, config)
        return config

    def target_tcp(self, proxy_port: int, timeout: float = 10) -> None:
        """HTTP marker from TARGET_NAME through the SOCKS proxy on ``proxy_port``.

        Xray's REALITY library samples post-handshake target records for five
        seconds on cold start, then polls that cache every five seconds; a
        five-second deadline races it. Hence a ten-second single attempt,
        without warming up or retrying.
        https://github.com/XTLS/REALITY/blob/9234c772ba8f/record_detect.go
        """
        socks_http_marker(proxy_port, TARGET_NAME, self.fixture.http_port, self.fixture.marker,
                          timeout)

    def target_udp(self, proxy_port: int) -> None:
        """UDP echo from TARGET_IP through the SOCKS proxy on ``proxy_port``."""
        socks_udp_echo(proxy_port, TARGET_IP, self.fixture.udp_port, self.fixture.marker)

    def start(self, kind: str, directory: Path, config: dict, env, name: str) -> Process:
        """Write ``config`` to ``<directory>/<name>.json``, check it and start the core."""
        directory.mkdir(parents=True, exist_ok=True)
        if VERBOSE:
            set_log_level(kind, config, "debug")
        path = directory / f"{name}.json"
        write_json(path, config)
        return core_start(kind, self.tools[kind], path, env, name)

    def start_server(self, kind: str, directory: Path, config: dict, env,
                     node: FixtureNode) -> Process:
        """:meth:`start` a server core and wait for the node's first TCP listener
        (a UDP-only node: the core must survive 0.2 s)."""
        process = self.start(kind, directory, config, env, "server")
        try:
            tcp = [i for i in node.inbounds if i.protocol not in UDP_PROTOCOLS]
            if tcp:
                process.wait_tcp(tcp[0].port)
            else:
                process.stay_alive(0.2)
            return process
        except BaseException:
            process.close()
            raise

    def start_client(self, kind: str, directory: Path, config: dict, env, port: int) -> Process:
        """:meth:`start` a client core and wait for its SOCKS listener ``port``."""
        process = self.start(kind, directory, config, env, "client")
        try:
            process.wait_tcp(port)
            return process
        except BaseException:
            process.close()
            raise


# ---------------------------------------------------------------------------
# YAML subset reader


class YamlError(ValueError):
    """The text is not in the YAML subset the v3 mihomo renderer emits."""


def load_yaml(text: str):
    """Parse the block-style YAML subset of ``src/render/yaml.rs``.

    Accepted: two-space block mappings and sequences (a collection inside a
    sequence starts on the dash line), plain keys ``[A-Za-z_][A-Za-z0-9_.-]*``
    or JSON-quoted keys, JSON double-quoted strings, integers / floats,
    ``true``/``false``/``null``, ``[]`` and ``{}``. Anything else (plain
    string scalars, flow collections, tabs, comments, anchors, duplicate keys,
    odd indentation, a missing final newline) is rejected, so the reader can
    only accept output whose meaning is unambiguous to any YAML parser.
    """
    if not text.endswith("\n") or text.endswith("\n\n"):
        raise YamlError("document must end with exactly one newline")
    lines = []
    for number, raw in enumerate(text[:-1].split("\n"), 1):
        if "\t" in raw or raw != raw.rstrip(" ") or not raw.strip():
            raise YamlError(f"line {number}: tab, trailing space or blank line")
        stripped = raw.lstrip(" ")
        indent = len(raw) - len(stripped)
        if indent % 2:
            raise YamlError(f"line {number}: odd indentation")
        lines.append([indent, stripped, number])
    if len(lines) == 1 and not _is_entry(lines[0][1]) and not lines[0][1].startswith("- "):
        return _scalar(lines[0][1], lines[0][2])
    reader = _YamlLines(lines)
    value = reader.block(0)
    if reader.pos != len(lines):
        raise YamlError(f"line {lines[reader.pos][2]}: unexpected indentation")
    return value


class _YamlLines:
    def __init__(self, lines):
        self.lines = lines
        self.pos = 0

    def peek(self):
        return self.lines[self.pos] if self.pos < len(self.lines) else None

    def block(self, indent):
        line = self.peek()
        if line is None or line[0] != indent:
            raise YamlError(f"expected a block at indentation {indent}")
        return self.sequence(indent) if line[1].startswith("- ") else self.mapping(indent)

    def sequence(self, indent):
        items = []
        while (line := self.peek()) and line[0] == indent and line[1].startswith("- "):
            content = line[1][2:]
            if content.startswith("- ") or _is_entry(content):
                # The nested collection starts on the dash line: re-read
                # that line as if it were indented past the dash.
                self.lines[self.pos] = [indent + 2, content, line[2]]
                items.append(self.block(indent + 2))
            else:
                items.append(_scalar(content, line[2]))
                self.pos += 1
        return items

    def mapping(self, indent):
        result = {}
        while (line := self.peek()) and line[0] == indent and not line[1].startswith("- "):
            key, rest = _split_key(line[1], line[2])
            if key in result:
                raise YamlError(f"line {line[2]}: duplicate key {key!r}")
            self.pos += 1
            if rest == "":
                child = self.peek()
                if child is None or child[0] != indent + 2:
                    raise YamlError(f"line {line[2]}: missing block for {key!r}")
                result[key] = self.block(indent + 2)
            elif rest.startswith(" ") and not rest.startswith("  "):
                result[key] = _scalar(rest[1:], line[2])
            else:
                raise YamlError(f"line {line[2]}: expected one space after the colon")
        return result


_PLAIN_KEY_FIRST = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_")
_PLAIN_KEY_REST = _PLAIN_KEY_FIRST | set("0123456789.-")
_YAML11_WORDS = {"y", "n", "yes", "no", "on", "off", "true", "false", "null", "~", "<<", "="}


def _is_entry(text: str) -> bool:
    try:
        _split_key(text, 0)
    except YamlError:
        return False
    return True


def _quoted_end(text: str) -> int | None:
    escaped = False
    for index, char in enumerate(text[1:], 1):
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            return index + 1
    return None


def _split_key(text: str, number: int) -> tuple[str, str]:
    if text.startswith('"'):
        end = _quoted_end(text)
        if end is None or text[end:end + 1] != ":":
            raise YamlError(f"line {number}: not a mapping entry")
        return _json_string(text[:end], number), text[end + 1:]
    key, colon, rest = text.partition(":")
    plain = (key and key[0] in _PLAIN_KEY_FIRST and set(key) <= _PLAIN_KEY_REST
             and key.lower() not in _YAML11_WORDS)
    if not colon or not plain:
        raise YamlError(f"line {number}: not a mapping entry")
    return key, rest


def _json_string(text: str, number: int) -> str:
    try:
        value = json.loads(text)
    except ValueError as error:
        raise YamlError(f"line {number}: invalid quoted string: {error}") from error
    if not isinstance(value, str):
        raise YamlError(f"line {number}: expected a string")
    return value


def _scalar(text: str, number: int):
    fixed = {"null": None, "true": True, "false": False}
    if text in fixed:
        return fixed[text]
    if text == "[]":
        return []
    if text == "{}":
        return {}
    if text.startswith('"'):
        if _quoted_end(text) != len(text):
            raise YamlError(f"line {number}: text after a quoted string")
        return _json_string(text, number)
    try:
        value = json.loads(text)
    except ValueError:
        value = None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value
    raise YamlError(f"line {number}: plain scalar {text!r} is never emitted")


# ---------------------------------------------------------------------------
# Self-tests (python3 tests/e2e/_harness.py)


class YamlReaderTests(unittest.TestCase):
    def test_documents_round_trip(self):
        cases = [
            ("a: 1\n", {"a": 1}),
            ("- 1\n- \"x\"\n", [1, "x"]),
            ("proxies:\n  - name: \"n\"\n    port: 443\n    tls: true\n    alpn:\n      - \"h2\"\n"
             "rules:\n  - \"MATCH,n\"\n",
             {"proxies": [{"name": "n", "port": 443, "tls": True, "alpn": ["h2"]}],
              "rules": ["MATCH,n"]}),
            ("- - 1\n  - 2\n- {}\n- []\n", [[1, 2], {}, []]),
            ("\"yes\": null\n\"a b\": -1.5\n", {"yes": None, "a b": -1.5}),
            ("k: \"\\u0007\\\"q\\\\\"\n", {"k": "\u0007\"q\\"}),
            ("\"x\"\n", "x"),
            ("ws-opts:\n  headers:\n    Host: \"h.test\"\n", {"ws-opts": {"headers": {"Host": "h.test"}}}),
        ]
        for text, expected in cases:
            with self.subTest(text=text):
                self.assertEqual(load_yaml(text), expected)

    def test_rejects_ambiguous_or_malformed_text(self):
        bad = [
            "a: 1",                 # no final newline
            "a: 1\n\n",             # blank line
            "a: plain\n",           # plain string scalar
            "a: yes\n",             # YAML 1.1 boolean
            "yes: 1\n",             # keyword key
            "a: [1]\n",             # flow sequence
            "a: 1\na: 2\n",         # duplicate key
            "a:\n   b: 1\n",        # odd indentation
            "a:\n    b: 1\n",       # skipped level
            "a:  1\n",              # two spaces
            "a: 1 # c\n",           # comment
            "\ta: 1\n",             # tab
            "a: \"x\" y\n",         # text after string
            "a:\n",                 # missing block
            "- 1\nb: 2\n",          # mixed collection kinds
            "a: 1 \n",              # trailing space
        ]
        for text in bad:
            with self.subTest(text=text), self.assertRaises(YamlError):
                load_yaml(text)


class SocksAndDnsTests(unittest.TestCase):
    def test_socks_addresses(self):
        self.assertEqual(socks_address("127.0.0.1"), b"\x01\x7f\x00\x00\x01")
        self.assertEqual(socks_address("::1"), b"\x04" + b"\x00" * 15 + b"\x01")
        self.assertEqual(socks_address("a.test"), b"\x03\x06a.test")
        with self.assertRaises(ValueError):
            socks_address("x" * 256)

    @staticmethod
    def query(name: str, qtype: int = 1) -> bytes:
        labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
        return b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + labels + b"\x00" + struct.pack("!HH", qtype, 1)

    def test_dns_answers(self):
        records = {"a.test": "192.0.2.1"}
        response, query = dns_answer(self.query("A.test"), records)
        self.assertEqual(query, ("a.test", 1))
        self.assertEqual(response[:2], b"\x12\x34")
        self.assertEqual(struct.unpack("!H", response[2:4])[0], 0x8180)
        self.assertTrue(response.endswith(socket.inet_aton("192.0.2.1")))
        response, query = dns_answer(self.query("b.test"), records)
        self.assertEqual(struct.unpack("!H", response[2:4])[0], 0x8183)
        self.assertEqual(struct.unpack("!H", response[6:8])[0], 0)
        response, query = dns_answer(self.query("a.test", 28), records)
        self.assertEqual((struct.unpack("!H", response[6:8])[0], query), (0, ("a.test", 28)))
        self.assertEqual(dns_answer(b"\x00" * 5, records), (None, None))

    def test_ports_avoid_ephemeral_range(self):
        low, high = ephemeral_range()
        ports = Ports()
        values = {ports.get() for _ in range(5)}
        self.assertEqual(len(values), 5)
        self.assertTrue(all(not low <= p <= high and p >= 10240 for p in values))


class ToolContractTests(unittest.TestCase):
    def test_set_but_unusable_variable_is_fatal(self):
        with unittest.mock.patch.dict(os.environ, {"ONEBOX_TEST_X": "/nonexistent/x"}):
            with self.assertRaises(SystemExit):
                tool("ONEBOX_TEST_X")

    def test_unset_variable(self):
        with unittest.mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ONEBOX_TEST_X", None)
            if REQUIRE_FULL:
                with self.assertRaises(Unavailable):
                    tool("ONEBOX_TEST_X", path_names=("sh",))
            else:
                self.assertTrue(tool("ONEBOX_TEST_X", path_names=("sh",)).endswith("sh"))
                with self.assertRaises(Unavailable):
                    tool("ONEBOX_TEST_X", path_names=("onebox-no-such-tool",))

    def test_clean_env_drops_onebox_variables(self):
        with unittest.mock.patch.dict(os.environ, {"ONEBOX_DIR": "/etc/x", "GH_PROXY": "p"}):
            env = clean_env(A="1")
        self.assertNotIn("ONEBOX_DIR", env)
        self.assertNotIn("GH_PROXY", env)
        self.assertEqual((env["NO_COLOR"], env["A"]), ("1", "1"))


if __name__ == "__main__":
    sys.exit(unittest.main())
