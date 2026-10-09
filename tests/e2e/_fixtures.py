#!/usr/bin/env python3
"""Loopback fixtures and network clients of the black-box suites (not a suite).

* :class:`Pki`: throw-away CA, CA-signed and self-signed P-256 certificates
  generated with ``openssl`` for each run;
* :class:`MarkerFixtures` (HTTP, TLS 1.3 and UDP echo serving one random
  marker) and :class:`DnsFixture` (authoritative UDP DNS that records the
  queries it receives), both on top of :class:`UdpServer`;
* a SOCKS5 client (:func:`socks_open`, :func:`socks_http_marker`,
  :func:`socks_udp_echo`) and :func:`tls_marker` for direct TLS checks;
* :func:`abstract_socket_bound` for fixed abstract unix sockets.

Socket timeouts are caught as ``socket.timeout``: it is an alias of
``TimeoutError`` only since Python 3.10, and on 3.8/3.9 an ``except
TimeoutError`` would let the first idle poll end a server thread.
"""
from __future__ import annotations

import contextlib
import dataclasses
import http.client
import http.server
import secrets
import socket
import socketserver
import ssl
import struct
import tempfile
import threading
import time
import unittest
from pathlib import Path

from _harness import LOOPBACK, Ports, describe, run

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


class UdpServer:
    """A loopback UDP socket served by a daemon thread until :meth:`close`.

    ``handler(datagram)`` returns the reply (``None``: no reply). The short
    receive timeout only lets the thread notice :meth:`close`.
    """

    def __init__(self, port: int, handler):
        self.port = port
        self.handler = handler
        self.socket = socket.socket(type=socket.SOCK_DGRAM)
        self.socket.bind((LOOPBACK, port))
        self.socket.settimeout(0.1)
        self.closed = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while not self.closed.is_set():
            try:
                data, peer = self.socket.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            reply = self.handler(data)
            if reply is not None:
                with contextlib.suppress(OSError):
                    self.socket.sendto(reply, peer)

    def close(self):
        self.closed.set()
        self.socket.close()
        self.thread.join(timeout=2)


def _marker_handler(marker: bytes):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def do_GET(self):  # http.server dispatches on this name
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
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05},
                                      daemon=True)
            thread.start()
            self.threads.append(thread)
        self.udp = UdpServer(self.udp_port, lambda data: data)

    def close(self):
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
        self.lock = threading.Lock()
        self.queries: list[tuple[str, int]] = []
        self.server = UdpServer(port, self._answer)

    def _answer(self, message: bytes) -> bytes | None:
        response, query = dns_answer(message, self.records)
        if response is not None:
            with self.lock:
                self.queries.append(query)
        return response

    def queried(self, name: str, qtype: int = 1) -> bool:
        with self.lock:
            return (name.lower(), qtype) in self.queries

    def reset(self):
        with self.lock:
            self.queries.clear()

    def close(self):
        self.server.close()


def abstract_socket_bound(name: str) -> bool:
    """Whether the abstract unix socket ``@name`` is bound in this network namespace."""
    try:
        lines = Path("/proc/net/unix").read_text().splitlines()[1:]
    except OSError:
        return False
    return any(line.split()[-1] == "@" + name for line in lines if len(line.split()) >= 8)


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
    """UDP ASSOCIATE, then a datagram to ``ip:port`` whose echo must come back.

    A lost datagram is resent (``attempts`` in all, ``wait`` seconds each).
    """
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
    with socket.create_connection((LOOPBACK, port), timeout=timeout) as raw, \
            context.wrap_socket(raw, server_hostname=server_name) as stream:
        read_marker(stream, server_name or "no-sni.test", marker)


def reached(action) -> tuple[bool, str]:
    """Run a traffic ``action``; (True, "") on success, (False, reason) on a network failure."""
    try:
        action()
    except (OSError, AssertionError, http.client.HTTPException) as error:
        return False, describe(error)
    return True, ""


# ---------------------------------------------------------------------------
# Self-tests (python3 tests/e2e/_selftest.py)


def dns_query(name: str, qtype: int = 1) -> bytes:
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
    header = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    return header + labels + b"\x00" + struct.pack("!HH", qtype, 1)


class _LossySocksRelay:
    """A no-auth SOCKS5 UDP ASSOCIATE server whose relay drops the first datagram."""

    def __init__(self, ports: Ports):
        self.port = ports.get()
        self.received = 0
        self.listener = socket.create_server((LOOPBACK, self.port))
        self.relay = UdpServer(ports.get(), self._relay)
        self.thread = threading.Thread(target=self._accept, daemon=True)
        self.thread.start()

    def _relay(self, datagram: bytes) -> bytes | None:
        self.received += 1
        return datagram if self.received > 1 else None

    def _accept(self):
        with contextlib.suppress(OSError):
            stream, _ = self.listener.accept()
            with stream:
                recv_exact(stream, 3)
                stream.sendall(b"\x05\x00")
                recv_exact(stream, 10)          # UDP ASSOCIATE 0.0.0.0:0
                stream.sendall(b"\x05\x00\x00" + socks_address(LOOPBACK)
                               + struct.pack("!H", self.relay.port))
                stream.recv(1)                  # hold the association open

    def close(self):
        # shutdown() wakes a pending accept(); close() alone does not on Linux.
        with contextlib.suppress(OSError):
            self.listener.shutdown(socket.SHUT_RDWR)
        self.listener.close()
        self.relay.close()
        self.thread.join(timeout=2)


class SocksAndDnsTests(unittest.TestCase):
    def test_socks_addresses(self):
        self.assertEqual(socks_address("127.0.0.1"), b"\x01\x7f\x00\x00\x01")
        self.assertEqual(socks_address("::1"), b"\x04" + b"\x00" * 15 + b"\x01")
        self.assertEqual(socks_address("a.test"), b"\x03\x06a.test")
        with self.assertRaises(ValueError):
            socks_address("x" * 256)

    def test_dns_answers(self):
        records = {"a.test": "192.0.2.1"}
        response, query = dns_answer(dns_query("A.test"), records)
        self.assertEqual(query, ("a.test", 1))
        self.assertEqual(response[:2], b"\x12\x34")
        self.assertEqual(struct.unpack("!H", response[2:4])[0], 0x8180)
        self.assertTrue(response.endswith(socket.inet_aton("192.0.2.1")))
        response, query = dns_answer(dns_query("b.test"), records)
        self.assertEqual(struct.unpack("!H", response[2:4])[0], 0x8183)
        self.assertEqual(struct.unpack("!H", response[6:8])[0], 0)
        response, query = dns_answer(dns_query("a.test", 28), records)
        self.assertEqual((struct.unpack("!H", response[6:8])[0], query), (0, ("a.test", 28)))
        self.assertEqual(dns_answer(b"\x00" * 5, records), (None, None))

    def test_servers_survive_idle_timeouts(self):
        # Several 0.1 s receive timeouts pass before the first datagram.
        ports = Ports()
        dns = DnsFixture(ports.get(), {"a.test": "192.0.2.1"})
        echo = UdpServer(ports.get(), lambda data: data[::-1])
        try:
            time.sleep(0.25)
            self.assertTrue(dns.server.thread.is_alive() and echo.thread.is_alive())
            with socket.socket(type=socket.SOCK_DGRAM) as client:
                client.settimeout(2)
                client.sendto(dns_query("a.test"), (LOOPBACK, dns.port))
                self.assertTrue(client.recv(512).endswith(socket.inet_aton("192.0.2.1")))
                client.sendto(b"abc", (LOOPBACK, echo.port))
                self.assertEqual(client.recv(512), b"cba")
            self.assertTrue(dns.queried("A.TEST"))
        finally:
            dns.close()
            echo.close()
        self.assertFalse(dns.server.thread.is_alive() or echo.thread.is_alive())

    def test_udp_echo_resends_a_lost_datagram(self):
        relay = _LossySocksRelay(Ports())
        try:
            socks_udp_echo(relay.port, "192.0.2.1", 9, b"marker", attempts=2, wait=0.15)
            self.assertEqual(relay.received, 2)
        finally:
            relay.close()

    def test_marker_fixtures_serve_http_tls_and_udp(self):
        with tempfile.TemporaryDirectory() as directory:
            pki = Pki(Path(directory))
            fixtures = MarkerFixtures(Ports(), pki.self_signed("fixture.test"))
            try:
                with socket.create_connection((LOOPBACK, fixtures.http_port), timeout=3) as stream:
                    read_marker(stream, "fixture.test", fixtures.marker)
                tls_marker(fixtures.tls_port, "fixture.test", fixtures.marker)
                with socket.socket(type=socket.SOCK_DGRAM) as client:
                    client.settimeout(2)
                    client.sendto(b"ping", (LOOPBACK, fixtures.udp_port))
                    self.assertEqual(client.recv(16), b"ping")
            finally:
                fixtures.close()

    def test_abstract_socket_detection(self):
        name = "onebox-harness-" + secrets.token_hex(6)
        self.assertFalse(abstract_socket_bound(name))
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.bind("\0" + name)
            self.assertTrue(abstract_socket_bound(name))


if __name__ == "__main__":
    unittest.main()
