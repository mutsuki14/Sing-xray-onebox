#!/usr/bin/env python3
"""Node lifecycle black-box suite: install, changes, backups, rollback,
recovery, v2 migration and uninstall, run in an isolated sandbox.

Port of v2 ``tests/native_lifecycle.py`` (see ``_lifecycle_sandbox`` for the
sandbox: ``ONEBOX_INIT=none``, isolated paths, a stripped environment and a
PATH of recording helpers in which host-mutating programs exit 97).

Phases:
* read-only (no root): ``install --help``, ``plan --json`` and a rejected
  ``add --dry-run`` never create ``ONEBOX_DIR``;
* full (root), once with the compiled fixture core and, when
  ``ONEBOX_TEST_SINGBOX`` (or ``--singbox``) names a real sing-box, once more
  with it: install, port change, ``add anytls-reality``, client exports,
  backup/restore, conflicting port changes, (fixture core only) an injected
  start failure whose rollback also fails and ``recover``, a v2 state +
  subscription migration through ``regen``, the 1.x refusal and uninstall.

``ONEBOX_TEST_REQUIRE_FULL=1`` turns every skip (not root, no real core) into
a failure.

Changes from v2 (deliberate, COMPLETENESS G27/G11):
- ``client mihomo`` is YAML (parsed strictly) instead of JSON;
- the v1 ``onebox.conf`` migration phase is replaced by a v2
  ``{"values"}`` state + ``subscription/settings.json`` migration (v1 is no
  longer migrated: an ``onebox.conf``-only host gets the exact 1.x message);
- uninstall is checked against the v3 keep/remove list;
- every recorded external call is checked: no blocked program ever runs and
  ``curl`` is only used for the public-address probe.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _lifecycle_sandbox as sb  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
V1_MESSAGE = (
    "检测到 Onebox 1.x 配置（onebox.conf）。3.x 只能从 2.x 升级：请先执行 curl -fsSL "
    "https://raw.githubusercontent.com/mutsuki14/Sing-xray-onebox/v2.0.1/onebox.sh -o onebox-v2.sh "
    "&& sh onebox-v2.sh regen，再更新到 3.x。"
)
UNINSTALL_MESSAGE = "代理已卸载，网站内容和备份保留于原目录；FRP 可用 onebox frps 管理"
NODE_SERVICES = ("onebox-sing-box", "onebox-xray", "onebox-subscription", "onebox-subscription-web",
                 "onebox-site", "onebox-network")


def check(condition: object, message: str) -> None:
    if not condition:
        raise sb.SandboxError(message)


def inbound_port(state: dict, protocol: str) -> int | None:
    for inbound in state["inbounds"]:
        if inbound["protocol"] == protocol:
            return inbound["port"]
    return None


# ----- read-only phase ---------------------------------------------------

def read_only_phase(s: sb.Sandbox) -> None:
    """Read-only invocations never create the installation, even with --yes."""
    s.run("install", "--help")
    plan = s.run("plan", "--protocols", "anytls-reality", "--port", "anytls-reality=22443", "--json")
    planned = json.loads(plan.stdout)
    check(planned["dry_run"] is True, "plan --json is not marked as a dry run")
    check([(p["protocol"], p["port"]) for p in planned["protocols"]] == [("anytls-reality", 22443)],
          f"unexpected plan: {planned['protocols']}")
    rejected = s.run("add", "anytls-reality", "--dry-run", success=False)
    check("--dry-run" in rejected.stderr, f"add --dry-run failed for another reason:\n{rejected.stderr}")
    check(not s.etc.exists(), "read-only CLI invocations created ONEBOX_DIR")
    check(not s.forbidden_calls(), f"read-only phase ran forbidden programs: {s.forbidden_calls()}")


# ----- full phase --------------------------------------------------------

class Ports:
    """The four test ports of v2's suite, plus the subscription port."""

    def __init__(self) -> None:
        used: set[int] = set()
        self.first, self.second, self.additional, self.rejected, self.subscription = (
            sb.free_port(used) for _ in range(5))


def install_phase(s: sb.Sandbox, ports: Ports) -> dict:
    s.run("install", "--protocols", "vless-reality", "--core", "singbox", "--addr", "127.0.0.1",
          "--sni", "www.microsoft.com", "--port", f"vless-reality={ports.first}", "--no-bbr")
    state = s.state()
    check(state["schema"] == 3, "state.json is not schema 3")
    check(inbound_port(state, "vless-reality") == ports.first, "installed port not recorded")
    sb.wait_listening(ports.first)
    check(s.exe.read_bytes()[:4] == b"\x7fELF", "ONEBOX_EXE is not an ELF program")
    check(s.state_path.stat().st_mode & 0o777 == 0o600, "state.json is not 0600")
    check((s.etc / "client/sing-box.json").is_file(), "client/sing-box.json missing")
    check(s.service_pid("onebox-sing-box"), "no live PID record for onebox-sing-box")
    check(any(line.endswith("# onebox:boot:onebox-sing-box") for line in s.crontab()),
          "no-init autostart line missing")
    return state


def port_phase(s: sb.Sandbox, ports: Ports, original: dict) -> None:
    s.run("port", "vless-reality", str(ports.second))
    sb.wait_listening(ports.second)
    sb.wait_listening(ports.first, False)
    state = s.state()
    check(state["creds"]["uuid"] == original["creds"]["uuid"], "port change rotated the UUID")
    check(state["creds"]["reality"] == original["creds"]["reality"], "port change rotated REALITY keys")


def add_phase(s: sb.Sandbox, ports: Ports) -> None:
    s.run("add", "anytls-reality", "--port", f"anytls-reality={ports.additional}")
    sb.wait_listening(ports.additional)
    check(inbound_port(s.state(), "anytls-reality") == ports.additional, "added protocol not recorded")
    singbox = json.loads(s.run("client", "singbox").stdout)
    check(any(o.get("type") == "anytls" for o in singbox["outbounds"]), "sing-box client lacks anytls")
    check("anytls-reality://" not in s.run("client", "links").stdout, "links contain anytls-reality")
    mihomo = s.run("client", "mihomo").stdout
    try:
        json.loads(mihomo)
        raise sb.SandboxError("client mihomo is JSON; v3 emits YAML")
    except ValueError:
        pass
    doc = sb.parse_block_yaml(mihomo)
    proxies = doc["proxies"]
    check([p["type"] for p in proxies] == ["vless"], f"mihomo proxies: {proxies}")
    check(proxies[0]["port"] == ports.second, "mihomo proxy port is stale")


def backup_restore_phase(s: sb.Sandbox, ports: Ports) -> None:
    backup_id = s.run("backup", "lifecycle-checkpoint").stdout.strip().splitlines()[-1]
    check((s.etc / "backups" / backup_id / "manifest.json").is_file(), f"backup {backup_id} missing")
    s.run("port", "vless-reality", str(ports.rejected))
    sb.wait_listening(ports.rejected)
    s.run("restore", backup_id)
    check(inbound_port(s.state(), "vless-reality") == ports.second, "restore kept the new port")
    sb.wait_listening(ports.second)
    sb.wait_listening(ports.rejected, False)


def conflict_phase(s: sb.Sandbox, ports: Ports) -> None:
    """Two conflicting requests leave the same healthy generation intact."""
    stable = s.state_path.read_bytes()
    for _ in range(2):
        refused = s.run("port", "vless-reality", str(ports.additional), success=False)
        check("端口" in refused.stderr, f"refused for another reason:\n{refused.stderr}")
        check(s.state_path.read_bytes() == stable, "a rejected port change modified state.json")
        check(not s.journal_dir.exists(), "a rejected port change left a journal")
        sb.wait_listening(ports.second)


def recovery_phase(s: sb.Sandbox, ports: Ports) -> None:
    """Fail the new start and the rollback restart; recover restores the rest."""
    stable = s.state_path.read_bytes()
    s.fail_starts(2)
    failed = s.run("port", "vless-reality", str(ports.rejected), success=False)
    check("恢复未完成" in failed.stderr, f"the rollback should have failed too:\n{failed.stderr}")
    check(s.journal_dir.is_dir(), "a failed rollback must retain the recovery journal")
    s.run("recover")
    check(not s.journal_dir.exists(), "recover left the journal behind")
    check(s.state_path.read_bytes() == stable, "recover did not restore state.json")
    sb.wait_listening(ports.second)
    sb.wait_listening(ports.additional)
    sb.wait_listening(ports.rejected, False)


# ----- v2 migration ------------------------------------------------------

def v2_values(state: dict, subscription_port: int) -> dict[str, str]:
    """The v2.0.1 ``state.json`` values describing the same node (the key set
    v2 writes for an install with an ip-mode subscription)."""
    creds, reality, routing = state["creds"], state["creds"]["reality"], state["routing"]
    values = {
        "BLOCK_BT": "1" if routing["block_bt"] else "0",
        "BLOCK_PRIVATE": "1" if routing["block_private"] else "0",
        "CLASH_SECRET": creds["clash_secret"],
        "GRPC_SERVICE": creds["grpc_service"],
        "HY2_OBFS_PASSWORD": creds["hy2_obfs_password"],
        "INSTALLED_AT": str(state["installed_at"]),
        "LISTEN_ADDR": state["listen"],
        "NODE_NAME": state["node_name"],
        "OWN_IP_CIDRS": json.dumps(routing["own_cidrs"], separators=(",", ":")),
        "PASSWORD": creds["password"],
        "PROTOCOLS": " ".join(i["protocol"] for i in state["inbounds"]),
        "REALITY_DEST": state["reality"]["dest"],
        "REALITY_GUARD_PORT": str(state["reality"]["guard_port"]),
        "REALITY_PRIVATE_KEY": reality["private_key"],
        "REALITY_PUBLIC_KEY": reality["public_key"],
        "REALITY_SHORT_ID": reality["short_id"],
        "REALITY_SITE_ENABLED": "0",
        "REALITY_SITE_TITLE": "山间手记",
        "REALITY_SNI": state["reality"]["sni"],
        "RESOURCE_PROFILE": "balanced",
        "SB_VERSION": state["versions"]["singbox"],
        "SERVER_ADDR": state["server"]["addr"],
        "SERVER_IPV4": state["server"]["ipv4"],
        "SHADOWTLS_DEST": f"{state['shadowtls']['sni']}:443",
        "SHADOWTLS_PASSWORD": creds["shadowtls_password"],
        "SHADOWTLS_SNI": state["shadowtls"]["sni"],
        "SHADOWTLS_SS_PASSWORD": creds["shadowtls_ss_password"],
        "SS_METHOD": creds["ss_method"],
        "SS_PASSWORD": creds["ss_password"],
        "SUBSCRIPTION_DOMAIN": "127.0.0.1",
        "SUBSCRIPTION_ENABLED": "1",
        "SUBSCRIPTION_HTTP": "0",
        "SUBSCRIPTION_MODE": "ip",
        "SUBSCRIPTION_PORT": str(subscription_port),
        "TLS_SNI": "www.bing.com",
        "UUID": creds["uuid"],
        "VMESS_PATH": creds["vmess_path"],
        "WS_PATH": creds["ws_path"],
        "XHTTP_PATH": creds["xhttp_path"],
    }
    for inbound in state["inbounds"]:
        key = inbound["protocol"].replace("-", "_")
        values[f"PORT_{key}"] = str(inbound["port"])
        values[f"CORE_{key}"] = inbound["core"]
    return values


def v2_settings(port: int, device_hash: str) -> dict:
    """v2 ``subscription/settings.json`` (ip mode, one device)."""
    return {
        "enabled": True, "mode": "ip", "domain": "127.0.0.1", "port": port, "method": "none",
        "custom_cert": None, "custom_key": None,
        "devices": [{"id": "0123456789abcdef", "name": "phone", "hash": device_hash,
                     "created": 1760000000}],
    }


def write_v2_node(s: sb.Sandbox, before: dict, ports: Ports) -> tuple[bytes, str]:
    """Turn the installation into what v2.0.1 leaves on disk: v2 state and
    subscription settings, v2 cron markers, no v3 device store or specs."""
    token = secrets.token_hex(32)
    state_bytes = json.dumps({"values": v2_values(before, ports.subscription)}, indent=2).encode()
    s.state_path.write_bytes(state_bytes)
    subdir = s.etc / "subscription"
    shutil.rmtree(subdir, ignore_errors=True)
    subdir.mkdir(mode=0o700)
    settings = v2_settings(ports.subscription, sb.sha256_bytes(token.encode()))
    (subdir / "settings.json").write_text(json.dumps(settings, indent=2))
    (subdir / "settings.json").chmod(0o600)
    shutil.rmtree(s.etc / "services")
    exe = s.exe
    (s.root / "crontab.txt").write_text("\n".join([
        "0 1 * * * /usr/bin/true # admin job",
        f"@reboot '{exe}' service onebox-sing-box start >/dev/null 2>&1 # onebox-rust:onebox-sing-box",
        f"@reboot '{exe}' service onebox-network start >/dev/null 2>&1 # onebox-rust:onebox-network",
        f"17 4 * * * '{exe}' cert renew proxy --cron >/dev/null 2>&1 # onebox-native-cert-proxy",
    ]) + "\n")
    return state_bytes, token


def v2_migration_phase(s: sb.Sandbox, ports: Ports) -> None:
    before = s.state()
    state_bytes, token = write_v2_node(s, before, ports)
    s.run("regen")
    migrated = s.state()
    check(migrated["schema"] == 3, "regen did not write schema 3")
    for field in ("uuid", "password", "reality", "ss_password", "clash_secret"):
        check(migrated["creds"][field] == before["creds"][field], f"migration changed creds.{field}")
    check(migrated["inbounds"] == before["inbounds"], "migration changed protocols, ports or cores")
    expected_endpoint = {"mode": {"type": "ip", "address": "127.0.0.1"}, "port": ports.subscription}
    check(migrated["subscription"] == expected_endpoint,
          f"subscription endpoint not migrated: {migrated['subscription']}")
    v2_copy = s.etc / "state.v2.json"
    check(v2_copy.read_bytes() == state_bytes, "state.v2.json is not the original v2 state")
    check(v2_copy.stat().st_mode & 0o777 == 0o600, "state.v2.json is not 0600")
    devices = json.loads((s.etc / "subscription/devices.json").read_text())["devices"]
    v2_devices = v2_settings(ports.subscription, sb.sha256_bytes(token.encode()))["devices"]
    check(devices == v2_devices, f"devices not migrated verbatim: {devices}")
    check((s.etc / "subscription/settings.json").is_file(), "v3 must leave v2 settings.json alone")
    specs = sorted(p.stem for p in (s.etc / "services").glob("*.json"))
    check(specs == ["onebox-network", "onebox-sing-box", "onebox-subscription"],
          f"service specs not rewritten: {specs}")
    cron = s.crontab()
    check(cron[0] == "0 1 * * * /usr/bin/true # admin job", f"foreign cron line moved: {cron}")
    check(not any("# onebox-rust:" in line or "# onebox-native-cert-" in line for line in cron),
          f"v2 cron markers survived: {cron}")
    check(any(line.endswith("# onebox:boot:onebox-sing-box") for line in cron), "boot line not retagged")
    sb.wait_listening(ports.second)
    sb.wait_listening(ports.additional)
    url = f"http://127.0.0.1:{ports.subscription}/sub/{token}/singbox"
    body = json.loads(sb.wait_http(url))
    check(any(o.get("type") == "anytls" for o in body["outbounds"]), "subscription serves a stale config")
    check(sb.http_get(f"http://127.0.0.1:{ports.subscription}/sub/{'0' * 64}/singbox")[0] == 404,
          "an unknown token was served")


# ----- 1.x refusal and uninstall ------------------------------------------

def v1_refusal_phase(s: sb.Sandbox) -> None:
    """An onebox.conf-only host gets the exact 1.x message and no changes."""
    s.etc.mkdir(mode=0o700)
    (s.etc / "onebox.conf").write_text("PROTOCOLS='vless-reality'\nUUID='00000000-0000-4000-8000-000000000000'\n")
    before = sb.tree_digest(s.etc)
    for command in (("regen",), ("info",)):
        proc = s.run(*command, success=False)
        check(V1_MESSAGE in proc.stderr, f"{command[0]}: missing the 1.x message:\n{proc.stderr}")
    # The node lock file may be created on the way; nothing else may change.
    after = sb.tree_digest(s.etc, exclude=(".apply.lock",))
    sb.assert_same_tree(before, after, "ONEBOX_DIR of a 1.x host")
    check(not s.forbidden_calls(), f"forbidden external calls: {s.forbidden_calls()}")


def uninstall_phase(s: sb.Sandbox, ports: Ports) -> None:
    """Remove the node, keep site content, backups, ledgers and the manager."""
    backups_before = set(os.listdir(s.etc / "backups"))
    # Website content (site root and ROOT/site backups) survives uninstall.
    kept = [s.root / "www/keep.html", s.etc / "site/content-backups/keep"]
    for path in kept:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("user content\n")
    proc = s.run("uninstall")
    check(UNINSTALL_MESSAGE in proc.stdout, f"uninstall message missing:\n{proc.stdout}")
    for path in kept:
        check(path.read_text() == "user content\n", f"uninstall removed {path}")
    for port in (ports.second, ports.additional, ports.subscription):
        sb.wait_listening(port, False)
    for rel in ("state.json", "state.v2.json", "onebox.conf", "sing-box.json", "xray.json", "client",
                "subscription", "services", "tls", ".transaction"):
        check(not (s.etc / rel).exists(), f"uninstall left {rel}")
    check(not (s.run_dir / "subscription.sock").exists(), "uninstall left the subscription socket")
    check(not (s.root / "bin/sing-box").exists(), "uninstall left the core binary")
    for service in NODE_SERVICES:
        check(s.service_pid(service) is None, f"{service} still running after uninstall")
    backups = set(os.listdir(s.etc / "backups"))
    check(backups_before < backups, "uninstall must keep old backups and add a safety backup")
    labels = [json.loads((s.etc / "backups" / b / "manifest.json").read_text())["label"]
              for b in backups - backups_before]
    check(labels == ["before-uninstall"], f"unexpected safety backups: {labels}")
    check(not (s.root / "onebox-subscription-acme").exists(), "uninstall left the subscription webroot")
    check(s.exe.is_file(), "uninstall removed the manager (FRP units still call it)")
    check((s.etc / "firewall-v2.json").is_file(), "uninstall removed the firewall ledger")
    check(not any(s.firewall_rules().values()), f"firewall rules left: {s.firewall_rules()}")
    check(not any("# onebox" in line for line in s.crontab()), f"cron lines left: {s.crontab()}")
    check(s.crontab() == ["0 1 * * * /usr/bin/true # admin job"], "uninstall touched foreign cron lines")
    check(not s.processes(), f"sandbox processes left: {s.processes()}")


def full_lifecycle(s: sb.Sandbox, fixture_core: bool) -> None:
    ports = Ports()
    original = install_phase(s, ports)
    port_phase(s, ports, original)
    add_phase(s, ports)
    backup_restore_phase(s, ports)
    conflict_phase(s, ports)
    if fixture_core:
        recovery_phase(s, ports)
    v2_migration_phase(s, ports)
    uninstall_phase(s, ports)
    check(not s.forbidden_calls(), f"forbidden external calls: {s.forbidden_calls()}")


# ----- driver ------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--binary", default=os.environ.get("ONEBOX_TEST_BINARY", str(REPO / "target/debug/onebox")))
    p.add_argument("--singbox", default=os.environ.get("ONEBOX_TEST_SINGBOX"),
                   help="real sing-box for the second pass (default $ONEBOX_TEST_SINGBOX)")
    p.add_argument("--keep", action="store_true", help="keep the sandbox directory")
    return p.parse_args()


def run_pass(work: Path, label: str, binary: Path, core: Path, fixture_core: bool) -> None:
    sandbox = sb.Sandbox(work / label, binary, core)
    try:
        full_lifecycle(sandbox, fixture_core)
        refusal = sb.Sandbox(work / f"{label}-v1", binary, core)
        try:
            v1_refusal_phase(refusal)
        finally:
            refusal.cleanup()
    finally:
        sandbox.cleanup()
    print(f"PASS lifecycle ({label}): install, port, add, exports, backup/restore, conflicts, "
          + ("start-failure recovery, " if fixture_core else "")
          + "v2 migration, 1.x refusal, uninstall")


def main() -> int:
    args = parse_args()
    binary = sb.executable(args.binary, "the Onebox binary (--binary / ONEBOX_TEST_BINARY)")
    real_core = sb.executable(args.singbox, "ONEBOX_TEST_SINGBOX")
    work = Path(tempfile.mkdtemp(prefix="onebox-lifecycle-"))
    try:
        build = work / "build"
        build.mkdir()
        fixture_core = sb.compile_fake_core(build)
        read_only = sb.Sandbox(work / "read-only", binary, fixture_core)
        read_only_phase(read_only)
        print("PASS lifecycle read-only CLI")
        blocker = sb.full_run_blocker()
        if blocker:
            sb.skip_or_fail(f"full lifecycle: {blocker}")
            return 0
        run_pass(work, "fixture-core", binary, fixture_core, True)
        if real_core:
            run_pass(work, "real-sing-box", binary, real_core, False)
        else:
            sb.skip_or_fail("real-core lifecycle pass: ONEBOX_TEST_SINGBOX is not set")
        return 0
    finally:
        if args.keep:
            print(f"sandbox kept: {work}")
        else:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
