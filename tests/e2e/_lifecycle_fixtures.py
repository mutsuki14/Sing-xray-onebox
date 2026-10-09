"""Fixture programs and helper scripts of the lifecycle and upgrade suites.

Compiled with ``rustc`` (neither implements a protocol):

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

Python scripts (their interpreter is the shebang line, so they never depend
on a PATH; their configuration is written into them, so they also work for
children whose environment Onebox cleared):

* the *recorder*, installed under every program name of the sandbox PATH
  (``_lifecycle_sandbox``): it logs each call to ``commands.jsonl``, emulates
  the host tool against files inside the sandbox, passes a read-only tool
  through or refuses the call: a refusal is also logged (``refused.jsonl``)
  and exits 97;
* the *tripwire* (``_lifecycle_host``), which logs and refuses every call.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

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

# CONFIG = {"root": sandbox root, "passthrough": {name: real path}} is
# written above this source (see helper_script).
RECORDER_SOURCE = r'''
import os, pathlib, sys, time

root = pathlib.Path(CONFIG["root"])
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]


def caller():
    try:
        return os.readlink("/proc/%d/exe" % os.getppid())
    except OSError:
        return ""


def record(log_name, **extra):
    with (root / log_name).open("a") as log:
        log.write(json.dumps({"argv": [name, *args], "caller": caller(), **extra}) + "\n")


def refuse(what):
    """Log the refused call, then fail like a blocked program."""
    record("refused.jsonl", refused=True)
    print("BLOCKED %s: %s %r" % (what, name, args), file=sys.stderr)
    raise SystemExit(97)


def inside(value):
    path = pathlib.Path(value).resolve()
    if not path.is_relative_to(root):
        refuse("path outside the sandbox")
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


def iptables(rest):
    """iptables/ip6tables against <root>/<name>-<table>.json (rule lists)."""
    if rest[:2] == ["-w", "5"]:
        rest = rest[2:]
    table = "filter"
    if rest[:1] == ["-t"] and len(rest) > 1:
        table, rest = rest[1], rest[2:]
    store = root / ("%s-%s.json" % (name, table))
    rows = json.loads(store.read_text()) if store.exists() else []
    op = rest[0] if rest else ""
    if op == "-S":
        for row in rows:
            print(" ".join(row))
        raise SystemExit(0)
    row = ["-A", *rest[1:]]
    if op == "-I" and len(rest) > 2 and rest[2].isdigit():
        row = ["-A", rest[1], *rest[3:]]
    if op == "-C":
        raise SystemExit(0 if row in rows else 1)
    if op in ("-I", "-A"):
        rows.append(row)
    elif op == "-D":
        if row not in rows:
            raise SystemExit(1)
        rows.remove(row)
    else:
        refuse("unsupported firewall operation")
    store.write_text(json.dumps(rows))
    raise SystemExit(0)


def crontab():
    table = root / "crontab.txt"
    if args == ["-l"]:
        if table.exists():
            sys.stdout.write(table.read_text())
            raise SystemExit(0)
        print("no crontab for root", file=sys.stderr)
        raise SystemExit(1)
    if len(args) == 1 and not args[0].startswith("-"):
        table.write_text(inside(args[0]).read_text())
        raise SystemExit(0)


def curl():
    served_file = root / "downloads.json"
    served = json.loads(served_file.read_text()) if served_file.exists() else {}
    url = args[-1] if args else ""
    if url in served and "--output" in args:
        target = inside(args[args.index("--output") + 1])
        target.write_bytes(pathlib.Path(served[url]).read_bytes())
        raise SystemExit(0)
    print("curl: (6) Could not resolve host (offline sandbox)", file=sys.stderr)
    raise SystemExit(6)


record("commands.jsonl")
hang_point()
if name in CONFIG["passthrough"]:
    os.execv(CONFIG["passthrough"][name], [name, *args])
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
    iptables(args)
if name == "crontab":
    crontab()
if name == "tail" and args[:3] == ["-n", "200", "--"] and len(args) == 4:
    lines = inside(args[3]).read_text(errors="replace").splitlines(keepends=True)
    sys.stdout.write("".join(lines[-200:]))
    raise SystemExit(0)
if name == "curl":
    curl()
refuse("unexpected external operation")
'''

# CONFIG = {"log": calls file, "probes": [argv, ...]} is written above this
# source. A listed read-only probe fails quietly (exit 1, as on a host
# without the program's configuration) and is logged as such.
TRIPWIRE_SOURCE = r'''
import os, pathlib, sys

try:
    caller = os.readlink("/proc/%d/exe" % os.getppid())
except OSError:
    caller = ""
argv = [pathlib.Path(sys.argv[0]).name, *sys.argv[1:]]
probe = argv in CONFIG["probes"]
with open(CONFIG["log"], "a") as log:
    log.write(json.dumps({"argv": argv, "caller": caller, "probe": probe}) + "\n")
if probe:
    print("tripwire: read-only host probe refused: %r" % argv, file=sys.stderr)
    raise SystemExit(1)
print("BLOCKED host program %s: a process escaped the sandbox PATH" % sys.argv[0], file=sys.stderr)
raise SystemExit(97)
'''

# Program names of the sandbox PATH. Everything neither emulated nor passed
# through is refused (exit 97) and must never appear in commands.jsonl.
EMULATED = ("ip", "ufw", "firewall-cmd", "nft", "iptables", "ip6tables", "crontab", "tail", "curl")
PASSTHROUGH = ("openssl", "uname", "id", "getent")
BLOCKED = (
    "wget", "systemctl", "service", "rc-service", "rc-update", "openrc", "update-rc.d",
    "systemd-run", "apt-get", "apt", "dpkg", "dnf", "yum", "apk", "pacman", "zypper", "rpm",
    "sysctl", "modprobe", "tc", "update-grub", "iptables-save", "iptables-restore",
    "ip6tables-save", "ip6tables-restore", "ipset", "bash", "sh", "dash", "python", "python3",
    "nginx", "acme.sh", "socat", "unzip", "reboot", "shutdown", "journalctl",
)
BLOCKED_EXIT = 97
# Never replaced by the tripwire: children may need them, and they cannot
# change the host by themselves.
_TRIPWIRE_EXEMPT = ("bash", "sh", "dash", "python", "python3", "tail")
TRIPWIRE = tuple(sorted(set(EMULATED + BLOCKED) - set(_TRIPWIRE_EXEMPT)))
# Read-only host probes a daemon may make. The subscription worker serving a
# Unix socket asks nginx for its worker account (src/host/nginx.rs
# `worker`), and a daemon's cleared environment holds no ONEBOX_NGINX_BIN,
# so it looks nginx up in SAFE_PATH. The tripwire never runs it.
TRIPWIRE_PROBES = (("nginx", "-T", "-q"),)


def helper_script(source: str, config: dict) -> str:
    """SOURCE as an executable script with CONFIG written into it."""
    return (f"#!{sys.executable} -I\nimport json\n"
            f"CONFIG = json.loads({json.dumps(json.dumps(config))})\n{source}")


def install_scripts(directory: Path, names, text: str) -> None:
    """Install TEXT as executable DIRECTORY/NAME for every name."""
    for name in names:
        path = directory / name
        path.write_text(text)
        path.chmod(0o755)


def install_recorders(directory: Path, root: Path) -> None:
    """The sandbox PATH: one recorder per program name (module docs)."""
    passthrough = {name: real for name in PASSTHROUGH if (real := shutil.which(name))}
    text = helper_script(RECORDER_SOURCE, {"root": str(root), "passthrough": passthrough})
    install_scripts(directory, (*EMULATED, *PASSTHROUGH, *BLOCKED), text)


def install_tripwires(directory: Path, log: Path) -> None:
    """One tripwire per TRIPWIRE name, logging to LOG."""
    config = {"log": str(log), "probes": [list(p) for p in TRIPWIRE_PROBES]}
    install_scripts(directory, TRIPWIRE, helper_script(TRIPWIRE_SOURCE, config))


class FixtureError(AssertionError):
    """A fixture program could not be built."""


def compile_fixture(source: str, name: str, workdir: Path) -> Path:
    """Compile a fixture program with $RUSTC (or rustc from PATH)."""
    rustc = os.environ.get("RUSTC") or shutil.which("rustc")
    if not rustc:
        raise FixtureError("rustc is required for the fixture programs (set RUSTC)")
    src, out = workdir / f"{name}.rs", workdir / name
    src.write_text(source)
    subprocess.run([rustc, "--edition", "2021", "-O", str(src), "-o", str(out)],
                   check=True, stdin=subprocess.DEVNULL)
    return out


def compile_fake_core(workdir: Path) -> Path:
    return compile_fixture(FAKE_CORE_SOURCE, "fixture-core", workdir)


def compile_fake_front(workdir: Path) -> Path:
    return compile_fixture(FAKE_FRONT_SOURCE, "fixture-front", workdir)
