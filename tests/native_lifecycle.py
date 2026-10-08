#!/usr/bin/env python3
"""Exercise the native CLI lifecycle without touching host services/firewalls.

Default: compile a small Rust lifecycle fixture (NOT a protocol implementation).
Pass --singbox /path/sing-box, or ONEBOX_TEST_SINGBOX, for real-core validation.
CI should use --require-full to reject a non-root or mismatched /proc namespace.
The separate native_e2e.py suite verifies actual protocol handshakes/traffic.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time


FAKE_CORE = r'''
use std::{env,fs,net::TcpListener,thread,time::Duration,collections::BTreeSet};
fn main() {
    let a:Vec<String>=env::args().collect();
    if a.iter().any(|s|s=="version") {println!("sing-box version 1.14.2");return}
    let cfg=a.windows(2).find(|w|w[0]=="-c"||w[0]=="--config").map(|w|w[1].clone()).expect("config required");
    let text=fs::read_to_string(cfg).expect("configuration readable");
    assert!(text.contains("\"inbounds\""),"lifecycle fixture requires an inbounds document");
    if a.iter().any(|s|s=="check") {return}
    if let Ok(path)=env::var("ONEBOX_TEST_START_FAILURES") {
        let remaining=fs::read_to_string(&path).unwrap_or_default().trim().parse::<u32>().unwrap_or(0);
        if remaining>0 {fs::write(path,(remaining-1).to_string()).unwrap();std::process::exit(74)}
    }
    let mut ports=BTreeSet::new();
    for tail in text.split("\"listen_port\"").skip(1) {
        let value=tail.trim_start().strip_prefix(':').unwrap().trim_start();
        let digits:String=value.chars().take_while(|c|c.is_ascii_digit()).collect();
        ports.insert(digits.parse::<u16>().expect("numeric listen_port"));
    }
    assert!(!ports.is_empty());
    let _listeners:Vec<TcpListener>=ports.into_iter().map(|p|TcpListener::bind(("127.0.0.1",p)).expect("port available")).collect();
    loop {thread::sleep(Duration::from_secs(60));}
}
'''

# PATH contains this directory only. Every executable reachable by name is
# either this recorder or an explicitly whitelisted, read-only/system-local
# program. An unexpected package/service/download operation fails closed.
HELPER = r'''
import json,os,pathlib,platform,sys
root=pathlib.Path(os.environ["ONEBOX_TEST_ROOT"])
name=pathlib.Path(sys.argv[0]).name
a=sys.argv[1:]
with (root/"commands.jsonl").open("a") as f:f.write(json.dumps([name,*a])+"\n")
def inside(value):
    p=pathlib.Path(value).resolve()
    if not p.is_relative_to(root):raise RuntimeError("path outside fixture: "+str(p))
    return p
if name=="openssl":os.execv(os.environ["ONEBOX_TEST_OPENSSL"],[name,*a])
if name=="uname":print(platform.machine());sys.exit(0)
if name=="ip" and a==["-j","address","show","scope","global"]:
    print('[{"addr_info":[{"local":"198.18.0.1"}]}]');sys.exit(0)
if name=="ufw" and a[:1]==["status"]:print("Status: inactive");sys.exit(0)
if name=="firewall-cmd" and a==["--state"]:sys.exit(1)
if name=="nft" and a in (["-j","list","ruleset"],["-j","-a","list","ruleset"]):
    print('{"nftables":[]}');sys.exit(0)
if name in ("iptables","ip6tables"):
    if a[:2]==["-w","5"]:a=a[2:]
    table="filter"
    if a[:1]==["-t"]:table=a[1];a=a[2:]
    file=root/(name+"-"+table+".json")
    rows=json.loads(file.read_text()) if file.exists() else []
    if a[0]=="-S":
        for row in rows:print(" ".join(row))
        sys.exit(0)
    op=a[0];row=["-A",*a[1:]]
    if op=="-I" and len(a)>2 and a[2].isdigit():row=["-A",a[1],*a[3:]]
    if op=="-C":sys.exit(0 if row in rows else 1)
    if op in ("-I","-A"):rows.append(row)
    elif op=="-D":
        if row not in rows:sys.exit(1)
        rows.remove(row)
    else:raise RuntimeError("unsupported firewall fixture operation")
    file.write_text(json.dumps(rows));sys.exit(0)
if name=="crontab":
    file=root/"crontab.txt"
    if a==["-l"]:
        if file.exists():print(file.read_text(),end="");sys.exit(0)
        print("no crontab for test",file=sys.stderr);sys.exit(1)
    if len(a)==1:file.write_text(inside(a[0]).read_text());sys.exit(0)
if name=="tail" and a[:3]==["-n","200","--"]:
    print("".join(inside(a[3]).read_text().splitlines(keepends=True)[-200:]),end="");sys.exit(0)
print("BLOCKED unexpected external operation: "+name+" "+repr(a),file=sys.stderr)
sys.exit(97)
'''


def call(argv, env, *, success=True, timeout=50):
    p = subprocess.run([str(v) for v in argv], env=env, stdin=subprocess.DEVNULL,
                       capture_output=True, text=True, timeout=timeout)
    if success and p.returncode:
        raise AssertionError(f"{argv[1:]} failed ({p.returncode}):\n{p.stderr[-5000:]}\n{p.stdout[-1000:]}")
    if not success and not p.returncode:
        raise AssertionError(f"{argv[1:]} unexpectedly succeeded")
    return p


def proc_matches(pid, executable):
    try:
        return Path(f"/proc/{pid}/exe").resolve() == Path(executable).resolve()
    except OSError:
        return False


def free_port(used):
    for port in range(22000, 32000):
        if port in used:
            continue
        try:
            with socket.socket() as s:
                s.bind(("0.0.0.0", port))
            used.add(port)
            return port
        except OSError:
            pass
    raise AssertionError("No free test ports")


def listening(port, expected=True):
    end = time.monotonic() + 5
    while time.monotonic() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                alive = True
        except OSError:
            alive = False
        if alive == expected:
            return
        time.sleep(0.05)
    raise AssertionError(f"port {port}: expected listening={expected}")


class Fixture:
    def __init__(self, root, binary, core):
        self.root, self.binary, self.core = root, binary, core
        root.mkdir()
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith("ONEBOX_") and k not in ("GH_PROXY", "BASH_ENV", "ENV")}
        paths = {"ONEBOX_DIR": "etc", "ONEBOX_BIN_DIR": "bin", "ONEBOX_LOG_DIR": "log",
                 "ONEBOX_RUN_DIR": "run", "ONEBOX_SITE_ROOT": "www", "ONEBOX_SYSTEMD_DIR": "systemd",
                 "ONEBOX_INITD_DIR": "initd", "ONEBOX_EXE": "manager/onebox", "ONEBOX_FRPS_DIR": "frp/etc",
                 "ONEBOX_FRPS_BIN_DIR": "frp/bin", "ONEBOX_FRPS_WEB_VAR": "frp/www",
                 "ONEBOX_FRPS_LOG_DIR": "frp/log", "ONEBOX_FRPS_RUN_DIR": "frp/run"}
        self.env.update({k: str(root / v) for k, v in paths.items()})
        self.env.update(ONEBOX_INIT="none", ONEBOX_AUTO="1", ONEBOX_SINGBOX_BIN=str(core),
                        ONEBOX_TEST_ROOT=str(root), ONEBOX_TEST_OPENSSL=shutil.which("openssl") or "",
                        ONEBOX_TEST_START_FAILURES=str(root / "fail-start"))
        helpers = root / "helpers"
        helpers.mkdir()
        source = "#!" + sys.executable + "\n" + HELPER
        for name in ("openssl", "uname", "ip", "ufw", "firewall-cmd", "nft", "iptables", "ip6tables",
                     "crontab", "curl", "wget", "tail", "systemctl", "rc-service", "rc-update",
                     "apt-get", "dnf", "yum", "apk", "pacman", "zypper", "sysctl", "modprobe",
                     "bash", "sh", "python", "python3", "nginx", "reboot", "shutdown"):
            path = helpers / name
            path.write_text(source)
            path.chmod(0o755)
        self.env["PATH"] = str(helpers)

    @property
    def etc(self):
        return self.root / "etc"

    def run(self, *args, **kwargs):
        return call([self.binary, *args, "--yes"], self.env, **kwargs)

    def state(self):
        return json.loads((self.etc / "state.json").read_text())["values"]

    def cleanup(self):
        # Only terminate a process after matching both executable and this
        # fixture's configuration. Never trust a PID file by itself.
        for path in (self.root / "run").glob("*.pid"):
            try:
                raw = json.loads(path.read_text())
                pid = raw["pid"] if isinstance(raw, dict) else raw
                exe = self.root / "bin/sing-box"
                cmd = Path(f"/proc/{pid}/cmdline").read_bytes()
                if proc_matches(pid, exe) and str(self.etc / "sing-box.json").encode() in cmd:
                    os.kill(pid, signal.SIGTERM)
            except (OSError, ValueError, KeyError):
                pass


def full_lifecycle(f, fake):
    ports = set()
    first, second, additional, rejected = [free_port(ports) for _ in range(4)]
    f.run("install", "--protocols", "vless-reality", "--core", "singbox", "--addr", "127.0.0.1",
          "--sni", "www.microsoft.com", "--port", f"vless-reality={first}", "--no-bbr")
    original = f.state()
    assert original["PORT_vless_reality"] == str(first)
    listening(first)
    assert (f.root / "manager/onebox").read_bytes()[:4] == b"\x7fELF"
    assert (f.etc / "state.json").stat().st_mode & 0o777 == 0o600
    assert (f.etc / "client/sing-box.json").exists()

    f.run("port", "vless-reality", str(second))
    listening(second)
    listening(first, False)
    assert f.state()["UUID"] == original["UUID"]
    f.run("add", "anytls-reality", "--port", f"anytls-reality={additional}")
    listening(additional)
    assert "anytls-reality" in f.state()["PROTOCOLS"]
    singbox = json.loads(f.run("client", "singbox").stdout)
    assert any(v.get("type") == "anytls" for v in singbox["outbounds"])
    assert "anytls-reality://" not in f.run("client", "links").stdout

    backup_id = f.run("backup", "lifecycle-checkpoint").stdout.strip().splitlines()[-1]
    f.run("port", "vless-reality", str(rejected))
    f.run("restore", backup_id)
    assert f.state()["PORT_vless_reality"] == str(second)
    listening(second)
    listening(rejected, False)

    # Two bad requests must leave the same healthy generation intact.
    stable = (f.etc / "state.json").read_bytes()
    for _ in range(2):
        f.run("port", "vless-reality", str(additional), success=False)
        assert (f.etc / "state.json").read_bytes() == stable
        listening(second)

    if fake:
        # Fail both the new process and its first rollback restart, retaining
        # the journal; the explicit recovery retry must restore old state.
        (f.root / "fail-start").write_text("2")
        f.run("port", "vless-reality", str(rejected), success=False)
        assert (f.etc / ".transaction").is_dir(), "failed rollback must retain recovery journal"
        f.run("recover")
        assert not (f.etc / ".transaction").exists()
        assert f.state()["PORT_vless_reality"] == str(second)
        listening(second)
        listening(additional)
        listening(rejected, False)

    # Emulate a running v1 no-init install: bare numeric PID, no service JSON,
    # printf-%q-compatible shell literals and the same live core/config.
    before = f.state()
    legacy = {k: v for k, v in before.items() if k not in ("CUSTOM_CERT", "CUSTOM_KEY")}
    (f.etc / "onebox.conf").write_text("\n".join(k + "=" + shlex.quote(v) for k, v in legacy.items()) + "\n")
    (f.etc / "state.json").unlink()
    pidfile = f.root / "run/onebox-sing-box.pid"
    old_pid = json.loads(pidfile.read_text())["pid"]
    pidfile.write_text(str(old_pid) + "\n")
    shutil.rmtree(f.etc / "services")
    f.run("regen")
    migrated = f.state()
    for key in ("UUID", "PASSWORD", "REALITY_PRIVATE_KEY", "REALITY_PUBLIC_KEY", "PROTOCOLS"):
        assert migrated[key] == before[key], key
    assert (f.etc / "onebox.conf.pre-rust").is_file()
    assert isinstance(json.loads(pidfile.read_text()), dict)
    listening(second)
    f.run("uninstall")
    assert not (f.etc / "state.json").exists()
    assert not (f.etc / "onebox.conf").exists()
    listening(second, False)
    listening(additional, False)
    assert not (f.etc / "services/onebox-sing-box.json").exists()
    assert list((f.etc / "backups").iterdir()), "uninstall must retain backups"
    assert not any(json.loads(p.read_text()) for p in f.root.glob("*tables-*.json"))
    commands = [json.loads(line) for line in (f.root / "commands.jsonl").read_text().splitlines()]
    assert all(row[0] not in ("bash", "sh", "python", "python3", "systemctl", "reboot", "sysctl") for row in commands)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", default=os.environ.get("ONEBOX_TEST_BINARY", "target/debug/onebox"))
    p.add_argument("--singbox", default=os.environ.get("ONEBOX_TEST_SINGBOX"))
    p.add_argument("--require-full", action="store_true")
    p.add_argument("--keep", action="store_true")
    args = p.parse_args()
    binary = Path(args.binary).resolve()
    assert binary.is_file(), f"Build the native CLI first: {binary}"
    root = Path(tempfile.mkdtemp(prefix="onebox-native-lifecycle-"))
    fixture = None
    try:
        fake = not args.singbox
        if fake:
            rustc = os.environ.get("RUSTC") or shutil.which("rustc")
            assert rustc, "rustc is required for the lifecycle-only fixture"
            source, core = root / "fixture.rs", root / "fixture-core"
            source.write_text(FAKE_CORE)
            subprocess.run([rustc, "--edition", "2021", "-O", str(source), "-o", str(core)], check=True)
        else:
            core = Path(args.singbox).resolve()
            assert core.is_file(), f"Missing real sing-box binary: {core}"
        fixture = Fixture(root / "instance", binary, core)
        # These must never enter installation even with --yes.
        fixture.run("install", "--help")
        fixture.run("plan", "--protocols", "anytls-reality", "--port", "anytls-reality=22443", "--json")
        fixture.run("add", "anytls-reality", "--dry-run", success=False)
        assert not fixture.etc.exists(), "read-only CLI invocations changed the installation"
        reason = None
        if os.geteuid() != 0:
            reason = "install requires root"
        elif not proc_matches(os.getpid(), sys.executable):
            reason = "PID namespace and mounted /proc do not match"
        if reason:
            if args.require_full:
                raise AssertionError(reason)
            print("PASS native read-only CLI; SKIP full lifecycle: " + reason)
            return
        full_lifecycle(fixture, fake)
        print("PASS native lifecycle, backups, recovery retry, legacy no-init migration and uninstall; "
              + ("Rust fixture core (protocol validation excluded)" if fake else "real sing-box core"))
    finally:
        if fixture:
            fixture.cleanup()
        if args.keep:
            print("Fixture retained:", root)
        else:
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    main()
