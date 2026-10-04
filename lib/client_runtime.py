"""Onebox client-side probes and ordered TCP failover (Python 3.8+, stdlib only).

Embedded in onebox.sh by scripts/embed-runtime.py. No server private keys are
needed. Native clients remain responsible for transport, crypto and DNS.
"""
import argparse
import concurrent.futures
import copy
import hashlib
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import secrets
import select
import shutil
import signal
import socket
import socketserver
import ssl
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

MAX_BUNDLE = 2 * 1024 * 1024
STOP = threading.Event()


class UserError(ValueError):
    """Only fixed, non-secret messages may be presented to the user."""


def private_json(path, data):
    """Never overwrite a user file or follow a destination symlink."""
    raw = (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(raw)


def load_bundle(path):
    with open(path, "rb") as src:
        raw = src.read(MAX_BUNDLE + 1)
    if len(raw) > MAX_BUNDLE:
        raise UserError("探测配置超过 2 MiB")
    obj = json.loads(raw)
    if not isinstance(obj, dict) or type(obj.get("schema")) is not int or obj["schema"] != 1 or not isinstance(obj.get("entries"), list):
        raise UserError("探测配置 schema 无效")
    entries = obj["entries"]
    if not 1 <= len(entries) <= 32:
        raise UserError("配置需要 1 至 32 个入口")
    seen = set()
    for e in entries:
        if not isinstance(e, dict) or not isinstance(e.get("id"), str) or not re.fullmatch(r"[a-zA-Z0-9_.-]{1,80}", e["id"]) or e["id"] in seen:
            raise UserError("入口 ID 无效或重复")
        seen.add(e["id"])
        if e.get("core") not in ("singbox", "xray") or e.get("transport") not in ("tcp", "udp", "both"):
            raise UserError("入口类型无效")
        outs = e.get("outbounds")
        if not isinstance(outs, list) or not 1 <= len(outs) <= 2:
            raise UserError("入口出站无效")
        # Only supported proxy protocols: never accept a direct/block outbound.
        allowed = {"vless", "vmess", "trojan", "shadowsocks", "hysteria2", "tuic", "anytls", "shadowtls"}
        if e["core"] == "xray":
            allowed = {"vless", "vmess", "trojan", "shadowsocks", "hysteria"}
        key = "type" if e["core"] == "singbox" else "protocol"
        if any(not isinstance(o, dict) or o.get(key) not in allowed for o in outs):
            raise UserError("出站包含未支持的协议")
        if e.get("tag") != outs[0].get("tag"):
            raise UserError("出站标签不匹配")
    return obj


def ordered(entries, order=None, default_pair=False):
    if order:
        ids = order.split(",")
        by_id = {e["id"]: e for e in entries}
        if len(set(ids)) != len(ids) or any(i not in by_id for i in ids):
            raise UserError("--entries 包含未知或重复的 ID（先执行 probe list）")
        return [by_id[i] for i in ids]
    if default_pair:
        tcp = [e for e in entries if e["transport"] in ("tcp", "both")]
        udp = [e for e in entries if e["transport"] == "udp"]
        return (tcp[:1] + udp[:1]) or entries[:1]
    return entries


def read_exact(sock, n):
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise OSError("连接提前关闭")
        data.extend(chunk)
    return bytes(data)


def socks_address(sock, atyp):
    if atyp == 1:
        return socket.inet_ntop(socket.AF_INET, read_exact(sock, 4))
    if atyp == 4:
        return socket.inet_ntop(socket.AF_INET6, read_exact(sock, 16))
    if atyp == 3:
        return read_exact(sock, read_exact(sock, 1)[0]).decode("ascii")
    raise OSError("SOCKS 地址类型无效")


def socks_login(port, token, timeout):
    sock = socket.create_connection(("127.0.0.1", port), timeout)
    try:
        sock.sendall(b"\x05\x01\x02")
        if read_exact(sock, 2) != b"\x05\x02":
            raise OSError("SOCKS 认证方式不匹配")
        raw = token.encode("ascii")
        sock.sendall(b"\x01\x07onebox-" + bytes([len(raw)]) + raw)
        if read_exact(sock, 2) != b"\x01\x00":
            raise OSError("SOCKS 认证失败")
        return sock
    except Exception:
        sock.close()
        raise


def socks_connect(core, host, port, timeout):
    sock = socks_login(core.port, core.token, timeout)
    try:
        try:
            ip = ipaddress.ip_address(host)
            address = (b"\x01" if ip.version == 4 else b"\x04") + ip.packed
        except ValueError:
            raw = host.encode("idna")
            if not 1 <= len(raw) <= 255:
                raise UserError("域名长度无效")
            address = b"\x03" + bytes([len(raw)]) + raw
        sock.sendall(b"\x05\x01\x00" + address + struct.pack("!H", port))
        response = read_exact(sock, 4)
        if response[:3] != b"\x05\x00\x00":
            raise OSError("代理拒绝连接")
        socks_address(sock, response[3])
        read_exact(sock, 2)
        return sock
    except Exception:
        sock.close()
        raise


class Core:
    def __init__(self, entry, args):
        self.entry, self.args = entry, args
        self.proc, self.work = None, None
        self.port = 0
        self.token = secrets.token_hex(24)

    def __enter__(self):
        try:
            return self.start()
        except Exception:
            self.__exit__(None, None, None)
            raise

    def start(self):
        name = self.entry["core"]
        binary = getattr(self.args, name) or shutil.which("sing-box" if name == "singbox" else "xray")
        if not binary:
            raise UserError("缺少客户端内核: " + name)
        binary = str(Path(binary).resolve())
        self.work = tempfile.TemporaryDirectory(prefix="onebox-client-")
        with socket.socket() as reserve:
            reserve.bind(("127.0.0.1", 0))
            self.port = reserve.getsockname()[1]
        outs = copy.deepcopy(self.entry["outbounds"])
        if name == "singbox":
            config = {"log": {"disabled": True}, "dns": {"servers": [{"type": "local", "tag": "local"}]},
                      "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": self.port,
                                    "users": [{"username": "onebox-", "password": self.token}]}],
                      "outbounds": outs, "route": {"final": self.entry["tag"], "default_domain_resolver": "local"}}
            run = [binary, "run", "-c", "config.json", "-D", self.work.name]
            check = [binary, "check", "-c", "config.json", "-D", self.work.name]
        else:
            config = {"log": {"loglevel": "none"},
                      "inbounds": [{"protocol": "socks", "listen": "127.0.0.1", "port": self.port,
                                    "settings": {"auth": "password", "accounts": [{"user": "onebox-", "pass": self.token}], "udp": False}}],
                      "outbounds": outs}
            run = [binary, "run", "-c", "config.json"]
            check = [binary, "run", "-test", "-c", "config.json"]
        private_json(Path(self.work.name) / "config.json", config)
        result = subprocess.run(check, cwd=self.work.name, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        if result.returncode:
            raise UserError("客户端配置校验失败（请检查内核版本；未打印含凭据的日志）")
        self.proc = subprocess.Popen(run, cwd=self.work.name, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline and not STOP.is_set():
            if self.proc.poll() is not None:
                raise UserError("客户端内核启动失败")
            try:
                with socks_login(self.port, self.token, 0.3):
                    return self
            except OSError:
                STOP.wait(0.05)
        raise UserError("客户端内核启动超时")

    def __exit__(self, *unused):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        if self.work:
            self.work.cleanup()

    def resources(self):
        try:
            fields = Path("/proc/%d/stat" % self.proc.pid).read_text().rsplit(")", 1)[1].split()
            return {"cpu_seconds": (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK"),
                    "rss_bytes": int(fields[21]) * os.sysconf("SC_PAGE_SIZE")}
        except (OSError, ValueError, IndexError, AttributeError):
            return {"cpu_seconds": None, "rss_bytes": None}


def url_parts(url):
    p = urllib.parse.urlsplit(url)
    if p.scheme not in ("http", "https") or not p.hostname or p.username is not None or p.password is not None or p.fragment:
        raise UserError("测试 URL 必须为不含账号或片段的 HTTP(S) URL")
    if any(ord(c) < 33 or ord(c) == 127 for c in url):
        raise UserError("测试 URL 包含空白或控制字符")
    _ = p.port
    return p


def request(core, url, timeout=8, limit=0, upload=0, cafile=None, direct=None):
    """Bound bytes/time, no redirect, proxy-side DNS, no ambient proxy settings.

    setup_ms includes the proxy path and origin TLS. It is not the native
    protocol's isolated handshake time. TTFB starts before connecting.
    """
    p = url_parts(url)
    started = time.monotonic()
    port = p.port or (443 if p.scheme == "https" else 80)
    sock = None
    try:
        sock = socks_connect(core, p.hostname, port, timeout) if core else socket.create_connection(direct or (p.hostname, port), timeout)
        if p.scheme == "https":
            ctx = ssl.create_default_context(cafile=cafile)
            ctx.set_alpn_protocols(["http/1.1"])
            sock = ctx.wrap_socket(sock, server_hostname=p.hostname)
        setup = time.monotonic() - started
        path = urllib.parse.urlunsplit(("", "", p.path or "/", p.query, ""))
        host = p.netloc
        headers = ["%s %s HTTP/1.1" % ("POST" if upload else "GET", path), "Host: " + host,
                   "Connection: close", "Accept-Encoding: identity", "User-Agent: onebox-probe/1"]
        if upload:
            headers += ["Content-Length: %d" % upload, "Content-Type: application/octet-stream"]
        elif limit:
            headers += ["Range: bytes=0-%d" % (limit - 1)]
        sock.settimeout(max(0.01, timeout - (time.monotonic() - started)))
        sock.sendall(("\r\n".join(headers) + "\r\n\r\n").encode("ascii"))
        sent = 0
        payload = os.urandom(65536) if upload else b""
        while sent < upload:
            sock.settimeout(max(0.01, timeout - (time.monotonic() - started)))
            chunk = payload[:min(len(payload), upload - sent)]
            sock.sendall(chunk)
            sent += len(chunk)
        response = http.client.HTTPResponse(sock)
        response.begin()
        # HTTP headers are the first application response bytes.
        ttfb = time.monotonic() - started
        received, digest = 0, hashlib.sha256()
        while received < limit:
            remaining = timeout - (time.monotonic() - started)
            if remaining <= 0:
                raise TimeoutError()
            sock.settimeout(remaining)
            chunk = response.read(min(65536, limit - received))
            if not chunk:
                break
            digest.update(chunk)
            received += len(chunk)
        duration = time.monotonic() - started
        return {"ok": 200 <= response.status < 300, "status": response.status,
                "setup_ms": round(setup * 1000, 3), "ttfb_ms": round(ttfb * 1000, 3),
                "total_ms": round(duration * 1000, 3), "received_bytes": received, "sent_bytes": sent,
                "download_mbps": round(received * 8 / max(duration, 1e-9) / 1e6, 3),
                "upload_mbps": round(sent * 8 / max(duration, 1e-9) / 1e6, 3),
                "body_sha256": digest.hexdigest(), "location": response.getheader("Location", "")}
    finally:
        if sock:
            sock.close()


def safe_request(*args, **kwargs):
    try:
        return request(*args, **kwargs)
    except (OSError, ValueError, http.client.HTTPException) as exc:
        # Exceptions can contain target URLs/credentials. Only expose the type.
        return {"ok": False, "error": type(exc).__name__}


def distribution(values):
    if not values:
        return None
    values = sorted(values)
    return {"median": round(statistics.median(values), 3), "p95": values[math.ceil(len(values) * 0.95) - 1]}


def bench(entries, args):
    report = {"schema": 1, "scope": "current-machine-to-proxy-to-origin", "entries": [],
              "note": "请求失败率不是网络丢包率；setup 包含代理路径与目标 TLS；吞吐包含建连开销；CPU/RSS 仅本机客户端内核。"}
    for e in ordered(entries, args.entries):
        if STOP.is_set():
            break
        row = {"id": e["id"]}
        try:
            with Core(e, args) as core:
                before = core.resources()
                samples = []
                for _ in range(args.samples):
                    if STOP.is_set():
                        break
                    samples.append(safe_request(core, args.url, args.timeout, cafile=args.ca))
                if not samples:
                    raise UserError("测试已停止")
                row["samples"] = [{k: s[k] for k in ("ok", "status", "setup_ms", "ttfb_ms", "error") if k in s} for s in samples]
                row["request_failure_rate"] = sum(not s["ok"] for s in samples) / len(samples)
                row["ttfb_ms"] = distribution([s["ttfb_ms"] for s in samples if s["ok"]])
                loaded, transfer = [], {}
                for name, url, limit, upload in (("download", args.download_url, args.bytes, 0), ("upload", args.upload_url, 0, args.bytes)):
                    if STOP.is_set():
                        break
                    if not url:
                        continue
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                        task = pool.submit(safe_request, core, url, args.timeout, limit, upload, args.ca)
                        while not task.done() and len(loaded) < args.samples * 2 and not STOP.is_set():
                            sample = safe_request(core, args.url, args.timeout, cafile=args.ca)
                            if sample["ok"]:
                                loaded.append(sample["ttfb_ms"])
                            STOP.wait(0.1)
                        transfer[name] = {k: v for k, v in task.result().items() if k not in ("body_sha256", "location")}
                row["transfers"] = transfer
                row["loaded_ttfb_ms"] = distribution(loaded)
                after = core.resources()
                row["client_rss_bytes_at_end"] = after["rss_bytes"]
                row["client_cpu_seconds"] = None if before["cpu_seconds"] is None or after["cpu_seconds"] is None else round(after["cpu_seconds"] - before["cpu_seconds"], 3)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            row["error"] = str(exc) if isinstance(exc, UserError) else "client_start_failed: 检查该入口所需内核、版本及配置"
        report["entries"].append(row)
        if STOP.is_set():
            break
    report["cancelled"] = STOP.is_set()
    if args.output:
        private_json(args.output, report)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 130 if STOP.is_set() else int(any(e.get("error") or e.get("request_failure_rate", 1) > 0 or any(not v["ok"] for v in e.get("transfers", {}).values()) for e in report["entries"]))


class FailoverPolicy:
    """A switch never migrates or terminates an existing connection."""
    def __init__(self, count, failures=3, recoveries=3, cooldown=60):
        self.failures, self.recoveries, self.cooldown = failures, recoveries, cooldown
        self.bad, self.good = [0] * count, [0] * count
        self.available, self.active = [False] * count, None
        self.last_switch = float("-inf")

    def update(self, results, now):
        for i, ok in enumerate(results):
            self.good[i] = self.good[i] + 1 if ok else 0
            self.bad[i] = 0 if ok else self.bad[i] + 1
            if ok and (self.last_switch == float("-inf") or self.good[i] >= self.recoveries):
                self.available[i] = True
            if self.bad[i] >= self.failures:
                self.available[i] = False
        candidates = [i for i, ok in enumerate(results) if ok and self.available[i]]
        old = self.active
        if old is None or not self.available[old]:
            self.active = candidates[0] if candidates else None
        elif candidates and candidates[0] < old and now - self.last_switch >= self.cooldown and self.good[candidates[0]] >= self.recoveries:
            self.active = candidates[0]
        if old != self.active:
            self.last_switch = now
        return self.active


def relay(left, right):
    """Bounded buffers, half-close propagation and a five-minute idle limit."""
    sockets = (left, right)
    buffers = {left: bytearray(), right: bytearray()}
    readable = set(sockets)
    closed_write = set()
    last = time.monotonic()
    for s in sockets:
        s.setblocking(False)
    while not STOP.is_set() and time.monotonic() - last < 300:
        for src, dst in ((left, right), (right, left)):
            if src not in readable and not buffers[dst] and dst not in closed_write:
                dst.shutdown(socket.SHUT_WR)
                closed_write.add(dst)
        if not readable and not any(buffers.values()):
            return
        readers = [s for s in readable if len(buffers[right if s is left else left]) < 262144]
        writers = [s for s in sockets if buffers[s]]
        ready_r, ready_w, _ = select.select(readers, writers, [], 1)
        for s in ready_r:
            chunk = s.recv(65536)
            if chunk:
                buffers[right if s is left else left].extend(chunk)
                last = time.monotonic()
            else:
                readable.remove(s)
        for s in ready_w:
            sent = s.send(buffers[s])
            del buffers[s][:sent]
            last = time.monotonic()


class Front(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler):
        self.slots = threading.BoundedSemaphore(128)
        super().__init__(address, handler)

    def process_request(self, request_socket, address):
        if self.slots.acquire(False):
            super().process_request(request_socket, address)
        else:
            self.shutdown_request(request_socket)

    def process_request_thread(self, *args):
        try:
            super().process_request_thread(*args)
        finally:
            self.slots.release()

    def handle_error(self, *args):
        pass  # No tracebacks containing destination information.


def failover(entries, args):
    entries = ordered(entries, args.entries, default_pair=True)
    if not 2 <= len(entries) <= 8:
        raise UserError("回退需要 2 至 8 个入口；可用 --entries 指定顺序，或 probe merge 合并不同服务器配置")
    cores = []
    policy = FailoverPolicy(len(entries), args.failures, args.recoveries, args.cooldown)
    lock = threading.Lock()
    try:
        for e in entries:
            cores.append(Core(e, args).__enter__())

        def health_round():
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(cores)) as pool:
                results = list(pool.map(lambda c: safe_request(c, args.url, args.timeout, cafile=args.ca)["ok"], cores))
            with lock:
                old = policy.active
                new = policy.update(results, time.monotonic())
            if old != new:
                print(json.dumps({"event": "switch", "from": entries[old]["id"] if old is not None else None,
                                  "to": entries[new]["id"] if new is not None else None}, ensure_ascii=False), flush=True)

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                upstream = None
                try:
                    self.request.settimeout(5)
                    head = read_exact(self.request, 2)
                    if head[0] != 5 or not head[1]:
                        return
                    methods = read_exact(self.request, head[1])
                    if 0 not in methods:
                        self.request.sendall(b"\x05\xff")
                        return
                    self.request.sendall(b"\x05\x00")
                    req = read_exact(self.request, 4)
                    if req[:3] != b"\x05\x01\x00":
                        self.request.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
                        return
                    host = socks_address(self.request, req[3])
                    port = struct.unpack("!H", read_exact(self.request, 2))[0]
                    with lock:
                        active = policy.active
                    if active is None:
                        raise OSError("无健康入口")
                    upstream = socks_connect(cores[active], host, port, args.timeout)
                    self.request.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
                    relay(self.request, upstream)
                except (OSError, ValueError):
                    try:
                        self.request.sendall(b"\x05\x04\x00\x01" + b"\x00" * 6)
                    except OSError:
                        pass
                finally:
                    if upstream:
                        upstream.close()

        health_round()
        with Front(("127.0.0.1", args.port), Handler) as server:
            print(json.dumps({"event": "ready", "socks": "127.0.0.1:%d" % args.port,
                              "entries": [e["id"] for e in entries], "tcp_only": True}, ensure_ascii=False), flush=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                while not STOP.wait(args.interval):
                    health_round()
            finally:
                server.shutdown()
                thread.join()
    finally:
        for core in reversed(cores):
            core.__exit__(None, None, None)
    return 0


def tls_probe(host, port, sni, timeout, ca):
    ctx = ssl.create_default_context(cafile=ca)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    with socket.create_connection((host, port), timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=sni) as sock:
            return {"tls": sock.version(), "alpn": sock.selected_alpn_protocol(),
                    "certificate_sha256": hashlib.sha256(sock.getpeercert(binary_form=True)).hexdigest()}


def reality(entries, args):
    rows = []
    for e in ordered(entries, args.entries):
        meta = e.get("reality")
        if not meta:
            continue
        row = {"id": e["id"], "checks": {}, "warnings": []}
        checks = row["checks"]
        try:
            ordinary = tls_probe(meta["host"], meta["port"], meta["sni"], args.timeout, args.ca)
            checks["ordinary_tls13_valid_certificate"] = True
            checks["ordinary_h2"] = ordinary["alpn"] == "h2"
            if meta.get("reference_host"):
                reference = tls_probe(meta["reference_host"], meta["reference_port"], meta["sni"], args.timeout, args.ca)
                checks["same_certificate"] = ordinary["certificate_sha256"] == reference["certificate_sha256"]
                checks["same_alpn"] = ordinary["alpn"] == reference["alpn"]
                url = "https://%s/" % meta["sni"]
                first = request(None, url, args.timeout, 65536, cafile=args.ca, direct=(meta["host"], meta["port"]))
                second = request(None, url, args.timeout, 65536, cafile=args.ca, direct=(meta["reference_host"], meta["reference_port"]))
                checks["same_http_status"] = first["status"] == second["status"]
                checks["same_redirect"] = first["location"] == second["location"]
                if first["body_sha256"] != second["body_sha256"]:
                    row["warnings"].append("前 64 KiB 内容不同；动态页面可能正常，需核对有无特有错误页")
            else:
                row["warnings"].append("自建站未开放可比较的 HTTPS 入口；可在服务器执行本地检查")
        except (OSError, ValueError, http.client.HTTPException) as exc:
            checks["ordinary_or_reference_probe"] = False
            row["warnings"].append(type(exc).__name__)
        try:
            with Core(e, args) as core:
                checks["authenticated_proxy"] = safe_request(core, args.url, args.timeout, cafile=args.ca)["ok"]
            wrong = copy.deepcopy(e)
            outbound = wrong["outbounds"][0]
            if e["core"] == "singbox":
                cfg, key = outbound["tls"]["reality"], "short_id"
            else:
                cfg, key = outbound["streamSettings"]["realitySettings"], "shortId"
            old = cfg[key]
            cfg[key] = secrets.token_hex(8)
            while cfg[key] == old:
                cfg[key] = secrets.token_hex(8)
            with Core(wrong, args) as core:
                checks["wrong_short_id_rejected"] = not safe_request(core, args.url, args.timeout, cafile=args.ca)["ok"]
        except (OSError, ValueError, subprocess.SubprocessError):
            checks["authentication_test_completed"] = False
        rows.append(row)
    if not rows:
        raise UserError("配置中没有 REALITY 入口")
    result = {"schema": 1, "scope": args.scope, "entries": rows,
              "note": "普通 TLS 回落与错误 short ID 的代理拒绝分别测试；不证明不可识别或公网可达。"}
    if args.output:
        private_json(args.output, result)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if any(not all(r["checks"].values()) for r in rows) else (2 if any(r["warnings"] for r in rows) else 0)


def bounded(low, high):
    def parse(value):
        number = int(value)
        if not low <= number <= high:
            raise argparse.ArgumentTypeError("必须在 %d..%d 之间" % (low, high))
        return number
    return parse


def main(argv=None):
    parser = argparse.ArgumentParser(prog="onebox", description="Onebox 客户端工具；需要 Python 3.8+ 和所选入口对应的 sing-box / Xray")
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("bench", "failover", "reality"):
        cmd = sub.add_parser(command)
        cmd.add_argument("bundle")
        cmd.add_argument("--entries", help="probe list 中的 ID，以逗号分隔；回退优先级从左到右")
        cmd.add_argument("--singbox", help="sing-box 可执行文件路径")
        cmd.add_argument("--xray", help="Xray 可执行文件路径")
        cmd.add_argument("--url", default="https://www.gstatic.com/generate_204", help="端到端健康测试 URL，需要返回 2xx；不会跟随跳转")
        cmd.add_argument("--timeout", type=bounded(1, 60), default=8)
        cmd.add_argument("--ca", help="测试目标的自有 CA 文件（不关闭证书校验）")
        if command != "failover":
            cmd.add_argument("--output", help="新建 0600 JSON 报告，不覆盖文件")
        if command == "bench":
            cmd.add_argument("--samples", type=bounded(1, 20), default=5)
            cmd.add_argument("--download-url", help="可选下载测试端点；最多读取 --bytes 字节")
            cmd.add_argument("--upload-url", help="可选、由你授权接收 POST 数据的上传端点")
            cmd.add_argument("--bytes", type=bounded(1024, 67108864), default=4194304)
        elif command == "failover":
            cmd.add_argument("--port", type=bounded(1024, 65535), default=2080)
            cmd.add_argument("--interval", type=bounded(1, 3600), default=15)
            cmd.add_argument("--failures", type=bounded(1, 20), default=3)
            cmd.add_argument("--recoveries", type=bounded(1, 20), default=3)
            cmd.add_argument("--cooldown", type=bounded(0, 3600), default=60)
        else:
            cmd.add_argument("--scope", choices=("server-local", "current-machine-to-server"), default="current-machine-to-server")
    show = sub.add_parser("list")
    show.add_argument("bundle")
    merge = sub.add_parser("merge")
    merge.add_argument("output")
    merge.add_argument("bundles", nargs="+")
    args = parser.parse_args(argv)
    if getattr(args, "output", None) and os.path.lexists(args.output):
        raise UserError("输出文件已存在；请选择新文件路径")
    if args.command == "merge":
        entries = []
        for i, path in enumerate(args.bundles, 1):
            for e in load_bundle(path)["entries"]:
                e["id"] = "n%d-%s" % (i, e["id"])
                if len(e["id"]) > 80:
                    raise UserError("合并后的入口 ID 超过 80 字符，请使用原始导出配置")
                entries.append(e)
        if len(entries) > 32:
            raise UserError("合并后不能超过 32 个入口")
        private_json(args.output, {"schema": 1, "entries": entries})
        return 0
    entries = load_bundle(args.bundle)["entries"]
    if args.command == "list":
        for e in entries:
            print("%s\t%s\t%s" % (e["id"], e["transport"], e["core"]))
        return 0
    url_parts(args.url)
    for attr in ("download_url", "upload_url"):
        if getattr(args, attr, None):
            url_parts(getattr(args, attr))
    return {"bench": bench, "failover": failover, "reality": reality}[args.command](entries, args)


def stop_signal(*unused):
    STOP.set()


if __name__ == "__main__":
    signal.signal(signal.SIGINT, stop_signal)
    signal.signal(signal.SIGTERM, stop_signal)
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        # Do not print exception strings: malformed configs/URLs can contain secrets.
        message = str(error) if isinstance(error, UserError) else "客户端工具失败 (%s)；检查参数、配置和客户端内核版本。" % type(error).__name__
        print("[错误] " + message, file=sys.stderr)
        sys.exit(1)
