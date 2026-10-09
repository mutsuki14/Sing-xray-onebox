"""Sandbox shared by the lifecycle and upgrade black-box suites.

A sandbox is an isolated Onebox installation under one temporary directory:
every path override points inside it, ``ONEBOX_INIT=none`` makes Onebox run
its own daemon supervisor instead of an init system, and ``PATH`` contains
only *recorder* helpers. Each helper appends its argv to ``commands.jsonl``
and then either emulates a host tool against files inside the sandbox (``ip``,
``ufw``, ``firewall-cmd``, ``nft``, ``iptables``/``ip6tables``, ``crontab``,
``tail``, an offline ``curl``), passes a read-only tool through (``openssl``,
``uname``, ``id``, ``getent``) or refuses: package managers, init tools,
``wget``, shells, interpreters, ``sysctl`` and the like print ``BLOCKED …``
and exit 97, so an unexpected host mutation fails closed.

Fixture programs compiled with ``rustc`` (neither implements a protocol):

* the *core* reports ``sing-box version 1.14.2``, accepts ``check``, and on
  ``run`` binds every ``"listen_port"`` of its configuration on 127.0.0.1 and
  sleeps. The next N starts fail (exit 74) while ``<sandbox>/fail-start``
  holds N. Onebox starts daemons with a cleared environment, so the core finds
  that counter next to its configuration directory, not through a variable.
* the *front* stands in for nginx as v2's ip-mode subscription front
  (``onebox-subscription-web``): it forwards ``/sub/`` requests from the
  configured ``listen`` ports to the ``proxy_pass`` Unix socket. v2 cannot
  supervise a real nginx without an init system (v2 bug E-8.1#2: nginx
  rewrites its argv into a process title, so v2 never sees it running); the
  front keeps its argv, as v2 expects.

Changes from the v2 helpers (tests/native_lifecycle.py):
- the start-failure counter lives next to the configuration
  (``<ONEBOX_DIR>/../fail-start``): v3 daemons never inherit the caller's
  environment (v2 bug E-8.1#3), so ``ONEBOX_TEST_START_FAILURES`` cannot
  reach them;
- ``commands.jsonl`` rows are objects ``{"argv": [...], "caller": ...}``
  naming the executable that ran the command (v2 or v3);
- ``curl`` is an offline network instead of a blocked program: public-address
  probes fail like a host without connectivity, and only URLs registered with
  ``Sandbox.serve_downloads`` are "downloaded" (the v2 self-update flow);
- ``id``/``getent`` pass through (the v2 subscription needs the nginx worker
  identity); a *hang point* freezes one helper call so a suite can crash an
  apply at a deterministic stage;
- cleanup kills every process whose executable or command line lies inside
  the sandbox (v2 only matched the core).
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.parse
from typing import Iterable, Iterator, Mapping, Sequence

FAKE_CORE_SOURCE = r'''
// Lifecycle fixture core: NOT a protocol implementation.
use std::collections::BTreeSet;
use std::net::TcpListener;
use std::path::Path;
use std::{env, fs, process, thread, time::Duration};

fn fail(message: &str) -> ! {
    eprintln!("fixture core: {message}");
    process::exit(2)
}

/// Value after `-c`/`--config`.
fn config_path(args: &[String]) -> String {
    match args.windows(2).find(|w| w[0] == "-c" || w[0] == "--config") {
        Some(w) => w[1].clone(),
        None => fail("missing -c CONFIG"),
    }
}

/// Every numeric `"listen_port"` value of a JSON document.
fn listen_ports(text: &str) -> BTreeSet<u16> {
    let mut ports = BTreeSet::new();
    for tail in text.split("\"listen_port\"").skip(1) {
        let value = tail.trim_start().trim_start_matches(':').trim_start();
        let digits: String = value.chars().take_while(|c| c.is_ascii_digit()).collect();
        match digits.parse::<u16>() {
            Ok(port) => {
                ports.insert(port);
            }
            Err(_) => fail("non-numeric listen_port"),
        }
    }
    ports
}

/// Consumes one injected start failure from `<config dir>/../fail-start`.
fn injected_failure(config: &str) -> bool {
    let Some(root) = Path::new(config).parent().and_then(Path::parent) else {
        return false;
    };
    let counter = root.join("fail-start");
    let remaining = fs::read_to_string(&counter)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(0);
    if remaining == 0 {
        return false;
    }
    if fs::write(&counter, (remaining - 1).to_string()).is_err() {
        fail("cannot update fail-start");
    }
    true
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|a| a == "version") {
        println!("sing-box version 1.14.2");
        return;
    }
    let config = config_path(&args);
    let text = fs::read_to_string(&config).unwrap_or_else(|_| fail("configuration unreadable"));
    if !text.contains("\"inbounds\"") {
        fail("configuration has no inbounds");
    }
    if args.iter().any(|a| a == "check") {
        return;
    }
    if injected_failure(&config) {
        process::exit(74);
    }
    let ports = listen_ports(&text);
    if ports.is_empty() {
        fail("no listen_port");
    }
    let _listeners: Vec<TcpListener> = ports
        .into_iter()
        .map(|p| TcpListener::bind(("127.0.0.1", p)).unwrap_or_else(|_| fail("port in use")))
        .collect();
    loop {
        thread::sleep(Duration::from_secs(60));
    }
}
'''

FAKE_FRONT_SOURCE = r'''
// Fixture stand-in for v2's ip-mode subscription nginx: NOT nginx. It reads
// the `listen` ports and the `proxy_pass "http://unix:PATH:"` socket of its
// configuration and forwards `/sub/` requests there, one thread each.
use std::collections::BTreeSet;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::{env, fs, process, thread};

fn fail(message: &str) -> ! {
    eprintln!("fixture front: {message}");
    process::exit(1)
}

fn arg_after(args: &[String], flag: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == flag).map(|w| w[1].clone())
}

fn listen_ports(conf: &str) -> BTreeSet<u16> {
    let mut ports = BTreeSet::new();
    for tail in conf.split("listen ").skip(1) {
        let token = tail.split(|c| c == ';' || c == ' ').next().unwrap_or("");
        let digits = token.rsplit(':').next().unwrap_or("");
        if let Ok(port) = digits.parse::<u16>() {
            ports.insert(port);
        }
    }
    ports
}

fn upstream(conf: &str) -> Option<String> {
    let rest = conf.split("proxy_pass \"http://unix:").nth(1)?;
    Some(rest.split(":\"").next()?.to_string())
}

/// Reads the request head (bounded); None on EOF or error.
fn read_head(client: &mut TcpStream) -> Option<Vec<u8>> {
    let mut head = Vec::new();
    let mut chunk = [0u8; 1024];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = client.read(&mut chunk).ok()?;
        if n == 0 || head.len() > 8192 {
            return None;
        }
        head.extend_from_slice(&chunk[..n]);
    }
    Some(head)
}

fn serve(mut client: TcpStream, socket: &str) -> io::Result<()> {
    let Some(head) = read_head(&mut client) else { return Ok(()) };
    if !head.starts_with(b"GET /sub/") && !head.starts_with(b"HEAD /sub/") {
        return client.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    }
    let mut backend = UnixStream::connect(socket)?;
    backend.write_all(&head)?;
    io::copy(&mut backend, &mut client)?;
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|a| a == "-v" || a == "-V") {
        eprintln!("nginx version: onebox-fixture-front");
        return;
    }
    let path = arg_after(&args, "-c").unwrap_or_else(|| fail("missing -c CONFIG"));
    let conf = fs::read_to_string(&path).unwrap_or_else(|_| fail("configuration unreadable"));
    let ports = listen_ports(&conf);
    let socket = upstream(&conf).unwrap_or_else(|| fail("no proxy_pass unix socket"));
    if ports.is_empty() {
        fail("no listen port");
    }
    if args.iter().any(|a| a == "-t") {
        eprintln!("nginx: configuration file {path} test is successful");
        return;
    }
    if arg_after(&args, "-s").is_some() {
        fail("signals are not supported");
    }
    let mut workers = Vec::new();
    for port in ports {
        let listener = TcpListener::bind(("127.0.0.1", port)).unwrap_or_else(|_| fail("port in use"));
        let socket = socket.clone();
        workers.push(thread::spawn(move || {
            for client in listener.incoming().flatten() {
                let socket = socket.clone();
                thread::spawn(move || {
                    let _ = serve(client, &socket);
                });
            }
        }));
    }
    for worker in workers {
        let _ = worker.join();
    }
}
'''

# The recorder. Its interpreter is given by the shebang line written in front
# of it, so it never depends on the sandbox PATH (which holds no python3).
RECORDER_SOURCE = r'''
import json, os, pathlib, sys, time

root = pathlib.Path(os.environ["ONEBOX_TEST_ROOT"])
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]


def caller():
    try:
        return os.readlink("/proc/%d/exe" % os.getppid())
    except OSError:
        return ""


with (root / "commands.jsonl").open("a") as log:
    log.write(json.dumps({"argv": [name, *args], "caller": caller()}) + "\n")


def inside(value):
    path = pathlib.Path(value).resolve()
    if not path.is_relative_to(root):
        raise SystemExit("path outside the sandbox: %s" % path)
    return path


def hang_point():
    """Freeze while <root>/hang-point names this call (see Sandbox.hang)."""
    try:
        wanted = (root / "hang-point").read_text().split()
    except OSError:
        return
    if wanted and wanted[0] == name and args[: len(wanted) - 1] == wanted[1:]:
        (root / "hang.pid").write_text(str(os.getpid()))
        time.sleep(600)
        raise SystemExit(98)


hang_point()
passthrough = json.loads(os.environ["ONEBOX_TEST_PASSTHROUGH"])
if name in passthrough:
    os.execv(passthrough[name], [name, *args])
if name == "ip" and args[:2] in (["-j", "address"], ["-j", "addr"]):
    print('[{"ifname":"eth0","addr_info":[{"family":"inet","local":"198.18.0.1","prefixlen":15}]}]')
    raise SystemExit(0)
if name == "ufw" and args[:1] == ["status"]:
    print("Status: inactive")
    raise SystemExit(0)
if name == "firewall-cmd" and args == ["--state"]:
    print("not running")
    raise SystemExit(252)
if name == "nft" and args in (["-j", "list", "ruleset"], ["-j", "-a", "list", "ruleset"]):
    print('{"nftables":[]}')
    raise SystemExit(0)
if name in ("iptables", "ip6tables"):
    if args[:2] == ["-w", "5"]:
        args = args[2:]
    table = "filter"
    if args[:1] == ["-t"]:
        table, args = args[1], args[2:]
    store = root / ("%s-%s.json" % (name, table))
    rows = json.loads(store.read_text()) if store.exists() else []
    op = args[0] if args else ""
    if op == "-S":
        for row in rows:
            print(" ".join(row))
        raise SystemExit(0)
    row = ["-A", *args[1:]]
    if op == "-I" and len(args) > 2 and args[2].isdigit():
        row = ["-A", args[1], *args[3:]]
    if op == "-C":
        raise SystemExit(0 if row in rows else 1)
    if op in ("-I", "-A"):
        rows.append(row)
    elif op == "-D":
        if row not in rows:
            raise SystemExit(1)
        rows.remove(row)
    else:
        print("BLOCKED unsupported firewall operation %r" % args, file=sys.stderr)
        raise SystemExit(97)
    store.write_text(json.dumps(rows))
    raise SystemExit(0)
if name == "crontab":
    table = root / "crontab.txt"
    if args == ["-l"]:
        if table.exists():
            sys.stdout.write(table.read_text())
            raise SystemExit(0)
        print("no crontab for root", file=sys.stderr)
        raise SystemExit(1)
    if len(args) == 1 and args[0] != "-":
        table.write_text(inside(args[0]).read_text())
        raise SystemExit(0)
if name == "tail" and args[:3] == ["-n", "200", "--"] and len(args) == 4:
    lines = inside(args[3]).read_text(errors="replace").splitlines(keepends=True)
    sys.stdout.write("".join(lines[-200:]))
    raise SystemExit(0)
if name == "curl":
    served_file = root / "downloads.json"
    served = json.loads(served_file.read_text()) if served_file.exists() else {}
    url = args[-1] if args else ""
    if url in served and "--output" in args:
        target = inside(args[args.index("--output") + 1])
        target.write_bytes(pathlib.Path(served[url]).read_bytes())
        raise SystemExit(0)
    print("curl: (6) Could not resolve host (offline sandbox)", file=sys.stderr)
    raise SystemExit(6)
print("BLOCKED unexpected external operation: %s %r" % (name, args), file=sys.stderr)
raise SystemExit(97)
'''

# Programs reachable through PATH. Everything neither emulated nor passed
# through is blocked (exit 97) and must never appear in commands.jsonl.
EMULATED = ("ip", "ufw", "firewall-cmd", "nft", "iptables", "ip6tables", "crontab", "tail", "curl")
PASSTHROUGH = ("openssl", "uname", "id", "getent")
BLOCKED = (
    "wget", "systemctl", "service", "rc-service", "rc-update", "openrc",
    "apt-get", "apt", "dpkg", "dnf", "yum", "apk", "pacman", "zypper", "rpm",
    "sysctl", "modprobe", "tc", "bash", "sh", "dash", "python", "python3",
    "nginx", "acme.sh", "socat", "unzip", "reboot", "shutdown", "journalctl",
)
BLOCKED_EXIT = 97
# Address probes Onebox may attempt (they fail offline and are tolerated).
ADDRESS_PROBES = ("https://api.ipify.org", "https://api6.ipify.org")

# Path overrides (relative to the sandbox root). v2 ignores the ones it does
# not know (BBR).
LAYOUT = {
    "ONEBOX_DIR": "etc",
    "ONEBOX_BIN_DIR": "bin",
    "ONEBOX_LOG_DIR": "log",
    "ONEBOX_RUN_DIR": "run",
    "ONEBOX_SITE_ROOT": "www",
    "ONEBOX_SYSTEMD_DIR": "systemd",
    "ONEBOX_INITD_DIR": "initd",
    "ONEBOX_EXE": "manager/onebox",
    "ONEBOX_FRPS_DIR": "frp/etc",
    "ONEBOX_FRPS_BIN_DIR": "frp/bin",
    "ONEBOX_FRPS_WEB_VAR": "frp/www",
    "ONEBOX_FRPS_LOG_DIR": "frp/log",
    "ONEBOX_FRPS_RUN_DIR": "frp/run",
    "ONEBOX_BBR_DIR": "bbr",
    "ONEBOX_BBR_CONF": "sysctl.d/99-onebox-bbr.conf",
}
# Variables never inherited from the caller (besides every ONEBOX_*).
STRIPPED = ("GH_PROXY", "GH_TOKEN", "GITHUB_TOKEN", "BASH_ENV", "ENV", "CF_Token", "CF_Account_ID",
            "CF_Key", "CF_Email", "ACME_HOME", "TMPDIR", "NO_COLOR", "LANG", "LC_ALL", "LANGUAGE")
# sun_path is 108 bytes; v2 refuses socket paths over 100 bytes.
SOCKET_PATH_MAX = 100
# File descriptor of an inherited node lock (v2 update-script protocol).
INHERITED_LOCK_FD = 198
REPOSITORY = "mutsuki14/Sing-xray-onebox"


class SandboxError(AssertionError):
    """A sandbox expectation failed."""


def require_full() -> bool:
    """ONEBOX_TEST_REQUIRE_FULL=1 turns every skip into a failure (CI)."""
    return os.environ.get("ONEBOX_TEST_REQUIRE_FULL") == "1"


def skip_or_fail(reason: str) -> None:
    """Print a skip, or fail under ONEBOX_TEST_REQUIRE_FULL=1."""
    if require_full():
        raise SandboxError(f"ONEBOX_TEST_REQUIRE_FULL=1 but {reason}")
    print(f"SKIP {reason}")


def full_run_blocker() -> str | None:
    """Why the root-only phases cannot run here, or None."""
    if os.geteuid() != 0:
        return "the full phase requires root"
    if not proc_matches(os.getpid(), sys.executable):
        return "the PID namespace and the mounted /proc do not match"
    return None


def proc_matches(pid: int, executable: str | os.PathLike) -> bool:
    """True when /proc/PID/exe is EXECUTABLE."""
    try:
        return Path(f"/proc/{pid}/exe").resolve() == Path(executable).resolve()
    except OSError:
        return False


def executable(value: str | None, what: str) -> Path | None:
    """VALUE as an existing executable file, None when unset."""
    if not value:
        return None
    path = Path(value).resolve()
    if not path.is_file() or not os.access(path, os.X_OK):
        raise SandboxError(f"{what} is not an executable file: {path}")
    return path


def compile_fixture(source: str, name: str, workdir: Path) -> Path:
    """Compile a fixture program with $RUSTC (or rustc from PATH)."""
    rustc = os.environ.get("RUSTC") or shutil.which("rustc")
    if not rustc:
        raise SandboxError("rustc is required for the fixture programs (set RUSTC)")
    src, out = workdir / f"{name}.rs", workdir / name
    src.write_text(source)
    subprocess.run([rustc, "--edition", "2021", "-O", str(src), "-o", str(out)],
                   check=True, stdin=subprocess.DEVNULL)
    return out


def compile_fake_core(workdir: Path) -> Path:
    return compile_fixture(FAKE_CORE_SOURCE, "fixture-core", workdir)


def compile_fake_front(workdir: Path) -> Path:
    return compile_fixture(FAKE_FRONT_SOURCE, "fixture-front", workdir)


def free_port(used: set[int], start: int = 22000, end: int = 32000) -> int:
    """A port free for TCP and UDP on all addresses, outside USED."""
    for port in range(start, end):
        if port in used:
            continue
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp, \
                    socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                tcp.bind(("0.0.0.0", port))
                udp.bind(("0.0.0.0", port))
        except OSError:
            continue
        used.add(port)
        return port
    raise SandboxError("no free test port")


def port_open(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
            return True
    except OSError:
        return False


def wait_listening(port: int, expected: bool = True, timeout: float = 8.0) -> None:
    """Wait until 127.0.0.1:PORT accepts (or refuses) TCP connections."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if port_open(port) == expected:
            return
        time.sleep(0.05)
    raise SandboxError(f"port {port}: expected listening={expected}")


def http_get(url: str, timeout: float = 5.0) -> tuple[int, bytes]:
    """Plain HTTP GET (no proxy): (status, body)."""
    import http.client

    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "http" or not parts.hostname:
        raise SandboxError(f"not a plain HTTP URL: {url}")
    conn = http.client.HTTPConnection(parts.hostname, parts.port or 80, timeout=timeout)
    try:
        conn.request("GET", parts.path or "/")
        response = conn.getresponse()
        return response.status, response.read()
    finally:
        conn.close()


def wait_http(url: str, status: int = 200, timeout: float = 8.0) -> bytes:
    """Poll URL until it answers STATUS; returns the body."""
    end = time.monotonic() + timeout
    last: object = None
    while time.monotonic() < end:
        try:
            got, body = http_get(url)
            if got == status:
                return body
            last = got
        except OSError as error:
            last = error
        time.sleep(0.1)
    raise SandboxError(f"{url}: expected HTTP {status}, last result {last!r}")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def tree_digest(root: Path, exclude: Iterable[str] = ()) -> dict[str, str]:
    """Relative path → kind, mode and content digest for a whole tree.

    EXCLUDE holds relative paths (files or whole subtrees) that change
    legitimately; symlinks are recorded by target.
    """
    skipped = tuple(exclude)
    result: dict[str, str] = {}
    if not root.exists():
        return result
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if any(rel == s or rel.startswith(s + "/") for s in skipped):
            continue
        mode = oct(path.lstat().st_mode & 0o7777)
        if path.is_symlink():
            result[rel] = f"link {os.readlink(path)}"
        elif path.is_dir():
            result[rel] = f"dir {mode}"
        elif path.is_socket():
            result[rel] = f"socket {mode}"
        else:
            result[rel] = f"file {mode} {sha256_file(path)}"
    return result


def describe_diff(before: Mapping[str, str], after: Mapping[str, str]) -> str:
    """One line per path whose entry differs."""
    lines = [f"  {key}: {before.get(key)} -> {after.get(key)}"
             for key in sorted(set(before) | set(after)) if before.get(key) != after.get(key)]
    return "\n".join(lines)


def assert_same_tree(before: Mapping[str, str], after: Mapping[str, str], what: str) -> None:
    if before != after:
        raise SandboxError(f"{what} changed:\n{describe_diff(before, after)}")


def parse_block_yaml(text: str):
    """Strictly parse the block-style YAML Onebox emits (mihomo, provider).

    Supported: nested block mappings and sequences (``- key: value`` items
    included), JSON-quoted keys and strings, bare keys, integers, booleans,
    null and the empty flow collections ``[]``/``{}``. Anything else (tabs,
    bare string scalars, anchors, flow content) is a ValueError, so a format
    regression cannot pass as "parsed".
    """
    lines = []
    for number, raw in enumerate(text.splitlines(), 1):
        if not raw.strip():
            continue
        if "\t" in raw:
            raise ValueError(f"line {number}: tab character")
        lines.append([len(raw) - len(raw.lstrip(" ")), raw.strip(), number])
    if not lines:
        raise ValueError("empty document")
    value, pos = _yaml_block(lines, 0, lines[0][0])
    if pos != len(lines):
        raise ValueError(f"line {lines[pos][2]}: unexpected indentation")
    return value


def _yaml_block(lines: list, pos: int, indent: int):
    if lines[pos][1] == "-" or lines[pos][1].startswith("- "):
        return _yaml_sequence(lines, pos, indent)
    return _yaml_mapping(lines, pos, indent)


def _yaml_nested(lines: list, pos: int, indent: int):
    """The block below an entry whose value is on the following lines."""
    if pos >= len(lines) or lines[pos][0] <= indent:
        raise ValueError(f"line {lines[pos - 1][2]}: missing nested value")
    return _yaml_block(lines, pos, lines[pos][0])


def _yaml_sequence(lines: list, pos: int, indent: int):
    items = []
    while pos < len(lines) and lines[pos][0] == indent and (lines[pos][1] == "-" or lines[pos][1].startswith("- ")):
        rest = lines[pos][1][1:].lstrip(" ")
        if not rest:
            value, pos = _yaml_nested(lines, pos + 1, indent)
        elif _yaml_key(rest) is not None:
            # "- key: value" opens a mapping whose content column is after "- ".
            lines[pos] = [indent + 2, rest, lines[pos][2]]
            value, pos = _yaml_mapping(lines, pos, indent + 2)
        else:
            value, pos = _yaml_scalar(rest, lines[pos][2]), pos + 1
        items.append(value)
    return items, pos


def _yaml_mapping(lines: list, pos: int, indent: int):
    mapping: dict = {}
    while pos < len(lines) and lines[pos][0] == indent:
        text, number = lines[pos][1], lines[pos][2]
        parsed = _yaml_key(text)
        if parsed is None:
            raise ValueError(f"line {number}: expected 'key: value'")
        key, rest = parsed
        if key in mapping:
            raise ValueError(f"line {number}: duplicate key {key!r}")
        if rest:
            mapping[key], pos = _yaml_scalar(rest, number), pos + 1
        else:
            mapping[key], pos = _yaml_nested(lines, pos + 1, indent)
    return mapping, pos


def _yaml_key(text: str) -> tuple[str, str] | None:
    """(key, rest) of 'key: rest' / 'key:'; None when TEXT is no entry."""
    if text.startswith('"'):
        try:
            key, end = json.JSONDecoder().raw_decode(text)
        except ValueError:
            return None
        tail = text[end:]
    else:
        end = 0
        while end < len(text) and (text[end].isalnum() or text[end] in "_.-/+"):
            end += 1
        key, tail = text[:end], text[end:]
        if not key:
            return None
    if tail == ":":
        return str(key), ""
    if tail.startswith(": "):
        return str(key), tail[2:].strip()
    return None


def _yaml_scalar(text: str, number: int):
    if text.startswith('"'):
        value, end = json.JSONDecoder().raw_decode(text)
        if text[end:].strip():
            raise ValueError(f"line {number}: trailing text after string")
        return value
    fixed = {"true": True, "false": False, "null": None, "[]": [], "{}": {}}
    if text in fixed:
        return fixed[text]
    if text.lstrip("-").isdigit():
        return int(text)
    raise ValueError(f"line {number}: unsupported scalar {text!r}")


def release_arch() -> str:
    """Release asset architecture of this machine (v2/v3 naming)."""
    machine = platform.machine()
    names = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64",
             "i686": "386", "i586": "386", "i386": "386", "armv7l": "armv7"}
    if machine not in names:
        raise SandboxError(f"no release asset for {machine}")
    return names[machine]


class Sandbox:
    """One isolated Onebox installation (see the module documentation)."""

    def __init__(self, root: Path, binary: Path, core: Path, *, front: Path | None = None):
        self.root, self.binary, self.core = root, binary, core
        root.mkdir(parents=True)
        for rel in ("tmp", "home"):
            (root / rel).mkdir(mode=0o700)
        socket_path = self.run_dir / "subscription.sock"
        if len(str(socket_path).encode()) > SOCKET_PATH_MAX:
            raise SandboxError(f"sandbox path too long for Unix sockets: {socket_path} "
                               "(use a shorter TMPDIR)")
        self.env = self._environment(front)
        self._write_helpers()

    # ----- construction -------------------------------------------------

    def _environment(self, front: Path | None) -> dict[str, str]:
        env = {k: v for k, v in os.environ.items()
               if not k.startswith("ONEBOX_") and k not in STRIPPED}
        env.update({k: str(self.root / v) for k, v in LAYOUT.items()})
        passthrough = {name: real for name in PASSTHROUGH if (real := shutil.which(name))}
        env.update(
            ONEBOX_INIT="none",
            ONEBOX_AUTO="1",
            ONEBOX_SINGBOX_BIN=str(self.core),
            ONEBOX_TEST_ROOT=str(self.root),
            ONEBOX_TEST_PASSTHROUGH=json.dumps(passthrough),
            HOME=str(self.root / "home"),
            TMPDIR=str(self.root / "tmp"),
            NO_COLOR="1",
            LANG="C.UTF-8",
            PATH=str(self.helpers),
        )
        if front:
            env["ONEBOX_NGINX_BIN"] = str(front)
        return env

    def _write_helpers(self) -> None:
        self.helpers.mkdir()
        source = "#!" + sys.executable + " -I\n" + RECORDER_SOURCE
        for name in (*EMULATED, *PASSTHROUGH, *BLOCKED):
            path = self.helpers / name
            path.write_text(source)
            path.chmod(0o755)

    # ----- layout -------------------------------------------------------

    @property
    def helpers(self) -> Path:
        return self.root / "helpers"

    @property
    def etc(self) -> Path:
        return self.root / "etc"

    @property
    def run_dir(self) -> Path:
        return self.root / "run"

    @property
    def exe(self) -> Path:
        return self.root / "manager/onebox"

    @property
    def state_path(self) -> Path:
        return self.etc / "state.json"

    @property
    def journal_dir(self) -> Path:
        return self.etc / ".transaction"

    @property
    def lock_path(self) -> Path:
        return self.etc / ".apply.lock"

    # ----- running Onebox ----------------------------------------------

    def run(self, *args: str, success: bool | None = True, binary: Path | None = None,
            env: Mapping[str, str] | None = None, pass_fds: Sequence[int] = (),
            timeout: float = 180) -> subprocess.CompletedProcess:
        """Run Onebox (v3 unless BINARY) with --yes appended.

        SUCCESS: True requires exit 0, False a non-zero exit, None anything.
        """
        program = binary or self.binary
        argv = [str(program), *args, "--yes"]
        proc = subprocess.run(argv, env=dict(self.env, **(env or {})), stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=timeout,
                              pass_fds=tuple(pass_fds))
        label = f"{program.name} {' '.join(args)}"
        if success is True and proc.returncode:
            raise SandboxError(f"{label} failed ({proc.returncode}):\n"
                               f"{proc.stderr[-6000:]}\n{proc.stdout[-2000:]}")
        if success is False and not proc.returncode:
            raise SandboxError(f"{label} unexpectedly succeeded:\n"
                               f"{proc.stderr[-3000:]}\n{proc.stdout[-2000:]}")
        return proc

    def spawn(self, *args: str, binary: Path | None = None,
              pass_fds: Sequence[int] = ()) -> subprocess.Popen:
        """Start Onebox in the background (crash tests)."""
        program = binary or self.binary
        return subprocess.Popen([str(program), *args, "--yes"], env=self.env,
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, pass_fds=tuple(pass_fds))

    @contextlib.contextmanager
    def hold_node_lock(self) -> Iterator[dict[str, str]]:
        """Hold ROOT/.apply.lock on fd 198, as v2's update-script does.

        Yields the environment entry announcing the inherited lock; pass it
        with ``pass_fds=(INHERITED_LOCK_FD,)``.
        """
        fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.dup2(fd, INHERITED_LOCK_FD, inheritable=True)
            try:
                yield {"ONEBOX_INHERITED_LOCK_FD": str(INHERITED_LOCK_FD)}
            finally:
                os.close(INHERITED_LOCK_FD)
        finally:
            os.close(fd)

    def install_exe(self, binary: Path) -> None:
        """Atomically replace the installed manager (as a self-update does)."""
        temp = self.exe.with_name(".onebox-test-new")
        shutil.copyfile(binary, temp)
        temp.chmod(0o755)
        os.replace(temp, self.exe)

    # ----- observations -------------------------------------------------

    def state(self) -> dict:
        return json.loads(self.state_path.read_text())

    def commands(self) -> list[dict]:
        log = self.root / "commands.jsonl"
        if not log.exists():
            return []
        return [json.loads(line) for line in log.read_text().splitlines() if line]

    def forbidden_calls(self) -> list[list[str]]:
        """Recorded calls that must never happen: blocked programs, and curl
        for anything but an address probe or a served download."""
        served_file = self.root / "downloads.json"
        served = json.loads(served_file.read_text()) if served_file.exists() else {}
        bad = []
        for row in self.commands():
            argv = row["argv"]
            if argv[0] in BLOCKED:
                bad.append(argv)
            elif argv[0] == "curl" and argv[-1] not in ADDRESS_PROBES and argv[-1] not in served:
                bad.append(argv)
        return bad

    def crontab(self) -> list[str]:
        table = self.root / "crontab.txt"
        return table.read_text().splitlines() if table.exists() else []

    def firewall_rules(self) -> dict[str, list]:
        return {p.name: json.loads(p.read_text()) for p in sorted(self.root.glob("ip*tables-*.json"))}

    def pid_record(self, service: str) -> dict | None:
        """The supervisor's PID record of SERVICE, None when absent."""
        try:
            raw = json.loads((self.run_dir / f"{service}.pid").read_text())
        except (OSError, ValueError):
            return None
        return raw if isinstance(raw, dict) else {"pid": raw}

    def service_pid(self, service: str) -> int | None:
        """PID of SERVICE when its record names a live process."""
        record = self.pid_record(service)
        if not record:
            return None
        pid = int(record.get("pid", 0))
        fields = _stat_fields(pid)
        if not fields or fields[0] == "Z":
            return None
        if "start" in record and int(fields[19]) != int(record["start"]):
            return None
        return pid

    def process_exe(self, pid: int) -> Path:
        return Path(os.readlink(f"/proc/{pid}/exe").removesuffix(" (deleted)"))

    # ----- fault injection ---------------------------------------------

    def fail_starts(self, count: int) -> None:
        """Make the next COUNT fixture-core starts exit 74."""
        (self.root / "fail-start").write_text(str(count))

    @contextlib.contextmanager
    def hang(self, program: str, *args: str) -> Iterator:
        """Freeze the next call of PROGRAM (with leading ARGS).

        Yields ``wait(timeout) -> pid`` returning once a helper is frozen;
        leaving the block removes the hang point and kills that helper.
        """
        marker, pidfile = self.root / "hang-point", self.root / "hang.pid"
        pidfile.unlink(missing_ok=True)
        marker.write_text(" ".join((program, *args)))

        def wait(timeout: float = 60) -> int:
            end = time.monotonic() + timeout
            while time.monotonic() < end:
                with contextlib.suppress(OSError, ValueError):
                    return int(pidfile.read_text())
                time.sleep(0.05)
            raise SandboxError(f"hang point {program} {' '.join(args)} never reached")

        try:
            yield wait
        finally:
            marker.unlink(missing_ok=True)
            with contextlib.suppress(OSError, ValueError):
                os.kill(int(pidfile.read_text()), signal.SIGKILL)
            pidfile.unlink(missing_ok=True)

    def serve_downloads(self, files: Mapping[str, Path]) -> None:
        """Let the curl helper "download" FILES (exact URL → local file)."""
        (self.root / "downloads.json").write_text(json.dumps({k: str(v) for k, v in files.items()}))

    def publish_release(self, binary: Path, version: str) -> None:
        """Serve a GitHub release of BINARY as the latest stable Onebox."""
        tag, name = f"v{version}", f"onebox-linux-{release_arch()}-musl"
        url = f"https://github.com/{REPOSITORY}/releases/download/{tag}/{name}"
        data = binary.read_bytes()
        release = {
            "tag_name": tag, "draft": False, "prerelease": False,
            "body": f"Onebox {version} (sandbox fixture release)",
            "assets": [{"name": name, "browser_download_url": url, "size": len(data),
                        "digest": "sha256:" + sha256_bytes(data)}],
        }
        meta = self.root / "release.json"
        meta.write_text(json.dumps(release))
        self.serve_downloads({
            f"https://api.github.com/repos/{REPOSITORY}/releases/latest": meta,
            url: binary,
        })

    # ----- cleanup -----------------------------------------------------

    def processes(self) -> list[int]:
        """PIDs whose executable or command line lies inside the sandbox."""
        marker = str(self.root).encode()
        found = []
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit() or int(entry.name) == os.getpid():
                continue
            try:
                cmdline = (entry / "cmdline").read_bytes()
                exe = os.readlink(entry / "exe").encode()
            except OSError:
                continue
            if exe.startswith(marker) or marker in cmdline:
                found.append(int(entry.name))
        return found

    def cleanup(self) -> None:
        """Terminate every sandbox process (SIGTERM, then SIGKILL)."""
        for sig in (signal.SIGTERM, signal.SIGKILL):
            pids = self.processes()
            for pid in pids:
                with contextlib.suppress(OSError):
                    os.kill(pid, sig)
            end = time.monotonic() + 3
            while pids and time.monotonic() < end:
                pids = [p for p in pids if (f := _stat_fields(p)) and f[0] != "Z"]
                time.sleep(0.05)


def _stat_fields(pid: int) -> list[str] | None:
    """/proc/PID/stat fields after the command name (state first)."""
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    except (OSError, IndexError):
        return None
