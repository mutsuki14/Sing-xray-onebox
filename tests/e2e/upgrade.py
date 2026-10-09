#!/usr/bin/env python3
"""In-place upgrade black-box suite: nodes installed by Onebox v2.0.1 are
upgraded, rolled back and recovered by v3 (COMPLETENESS G7, ARCHITECTURE §7).

Every scenario starts from a fresh sandbox (see ``_lifecycle_sandbox``) in
which the real v2.0.1 binary (``ONEBOX_TEST_V2_BINARY`` or ``--v2``) installs
VLESS-REALITY, enables an ip-mode subscription and adds a second device:

1. ``regen``: v3 regenerates the node while this process holds
   ``ROOT/.apply.lock`` and hands it over as fd 198 with
   ``ONEBOX_INHERITED_LOCK_FD=198`` (exactly what v2's update-script does
   after replacing the manager): credentials, ports and device hashes are
   kept, ``devices.json`` is written, ``state.v2.json`` and v2's
   ``settings.json`` are kept, cron lines are retagged ``# onebox:`` (no
   ``renew`` line for a REALITY-only node, G17), service specs are
   rewritten (the v2 nginx front is retired), the core and subscription
   ports stay open in v2's firewall ledger and the subscription worker is
   restarted on the new binary, serving the old device URLs directly. Then
   v3 restores a backup v2.0.1 took before the upgrade (ARCH §7.3);
2. ``rollback`` (fixture core only): the same child fails to start the new
   core; v3 rolls back to byte-identical v2 files, exits non-zero, leaves no
   journal and does not start the worker (G6: the parent owns it);
3. ``v2-journal``: v2 is SIGKILLed in the middle of a port change (frozen in
   apply-network); v3 ``recover`` restores the v2 files and services;
4. ``self-update-journal``: v2's own ``update-script`` installs v3 from a
   served fixture release and is SIGKILLed while the v3 child regenerates
   (journal phase ``replaced`` plus the child's journal); v3 ``recover``
   rolls the child back, restores the v2 manager and configuration, runs
   v2's ``regen`` and exits 75 (the running image is not the restored one);
   the node's files match the v2 node again;
5. ``update-script``: v2's ``update-script`` completes the upgrade to v3;
6. ``update-script-rollback`` (fixture core only): the same, but the v3
   child fails to start the core: it rolls its own journal back and exits
   non-zero, the real v2 parent recovers (ARCH §7.1: ``更新失败，已恢复原程序``)
   and the node's files, manager and services are v2's again.

After every scenario no forbidden program was called (``forbidden_calls``)
and ``log/`` holds exactly the logs of the node's services.

The fixture-core pass always runs; with ``ONEBOX_TEST_SINGBOX`` a second pass
repeats every scenario that needs no injected start failure with the real
sing-box. ``ONEBOX_TEST_REQUIRE_FULL=1`` turns every skip into a failure,
including a host where the host programs cannot be masked
(``_lifecycle_host.seal``).

Notes: v2 cannot supervise a real nginx without an init system (v2 bug
E-8.1#2), so its ip-mode subscription front is the sandbox's fixture front.
The self-update journals of scenarios 4 and 6 are written by v2.0.1 itself,
not hand-made, so their snapshots are the exact v2 format v3 must validate.
Every v2 regen rewrites ``subscription/published.json`` (its publication
time), so file comparisons after one leave that file out.
"""
from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import re
import shutil
import signal
import sys
import tempfile
from typing import Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _lifecycle_fixtures as fx  # noqa: E402
import _lifecycle_host as host  # noqa: E402
import _lifecycle_sandbox as sb  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
V2_VERSION = "2.0.1"
STALE_MESSAGE = "自更新恢复已完成；当前进程仍是被替换版本，请重新执行命令以使用恢复后的程序"
EXIT_STALE = 75
TOKEN = re.compile(r"/sub/([0-9a-f]{64})/base64")
ADMIN_CRON = "0 1 * * * /usr/bin/true # admin job"
# Rewritten by every v2 regen (it records when the snapshot was published),
# so a v2 parent's or a recovery's regen changes it.
PUBLISHED = "subscription/published.json"
# The daemons every scenario runs: log/ must hold exactly their logs, so a daemon
# nobody expects (a second core, a front v3 should have retired) fails.
# Oneshots such as onebox-network log nowhere; the host guard covers them.
SERVICE_LOGS = ["onebox-sing-box.log", "onebox-subscription-web.log", "onebox-subscription.log"]


def check(condition: object, message: str) -> None:
    if not condition:
        raise sb.SandboxError(message)


@dataclass
class Tools:
    v2: Path
    v3: Path
    v3_version: str
    core: Path
    front: Path
    fixture_core: bool
    tripwire: host.Tripwire | None = None


@dataclass
class V2Node:
    """A sandbox with a running v2.0.1 node and what v2 reported."""

    sandbox: sb.Sandbox
    tools: Tools
    core_port: int
    spare_port: int
    sub_port: int
    tokens: list[str] = field(default_factory=list)
    state_bytes: bytes = b""
    settings_bytes: bytes = b""

    @property
    def values(self) -> dict[str, str]:
        return json.loads(self.state_bytes)["values"]

    def url(self, token: str, fmt: str = "base64") -> str:
        return f"http://127.0.0.1:{self.sub_port}/sub/{token}/{fmt}"


def install_v2(root: Path, tools: Tools) -> V2Node:
    s = sb.Sandbox(root, tools.v3, tools.core, front=tools.front, tripwire=tools.tripwire)
    used: set[int] = set()
    node = V2Node(s, tools, *(sb.free_port(used) for _ in range(3)))
    v2 = tools.v2
    s.run("install", "--protocols", "vless-reality", "--core", "singbox", "--addr", "127.0.0.1",
          "--sni", "www.microsoft.com", "--port", f"vless-reality={node.core_port}", "--no-bbr",
          binary=v2)
    enabled = s.run("subscription", "enable", "--mode", "ip", "--address", "127.0.0.1",
                    "--port", str(node.sub_port), binary=v2)
    added = s.run("subscription", "add", "phone", binary=v2)
    node.tokens = [TOKEN.search(out.stdout).group(1) for out in (enabled, added)]
    node.state_bytes = s.state_path.read_bytes()
    node.settings_bytes = (s.etc / "subscription/settings.json").read_bytes()
    check(node.values["SUBSCRIPTION_MODE"] == "ip", "v2 did not enable the ip subscription")
    sb.wait_listening(node.core_port)
    assert_devices_served(node)
    return node


# ----- observations ------------------------------------------------------

def assert_devices_served(node: V2Node) -> None:
    """Every device URL serves the node's links; an unknown token is 404."""
    for token in node.tokens:
        links = base64.b64decode(sb.wait_http(node.url(token))).decode()
        check(f"vless://{node.values['UUID']}@127.0.0.1:{node.core_port}" in links,
              f"device URL serves unexpected links: {links[:200]}")
    status, _ = sb.http_get(node.url("0" * 64))
    check(status == 404, f"an unknown token got HTTP {status}")


def lock_files(root: Path) -> list[str]:
    """Empty flock targets (``*.lock``) below ROOT, created on demand by
    whichever version takes the lock first; they carry no node state."""
    return [p.relative_to(root).as_posix() for p in root.rglob("*.lock")
            if p.is_file() and p.stat().st_size == 0]


def v2_files(s: sb.Sandbox, exclude: tuple[str, ...] = ()) -> dict[str, object]:
    """Everything a v2 node owns that a rollback must restore byte for byte
    (EXCLUDE: ONEBOX_DIR paths a v2 regen rewrites legitimately)."""
    return {
        "etc": sb.tree_digest(s.etc, exclude=[*lock_files(s.etc), *exclude]),
        "bin": sb.tree_digest(s.root / "bin"),
        "crontab": s.crontab(),
        "firewall": s.firewall_rules(),
    }


def cron_groups(lines: list[str]) -> tuple[list[str], list[str]]:
    """(foreign lines in order, Onebox lines sorted)."""
    owned = sorted(line for line in lines if "# onebox" in line)
    return [line for line in lines if "# onebox" not in line], owned


def assert_same_files(before: dict, after: dict, what: str, *, cron_order: bool = True) -> None:
    """Compare two ``v2_files`` pictures. CRON_ORDER=False compares Onebox's
    own cron lines as a set: a v2 journal records no positions, so v3 puts
    each restored group where it currently is (documented in
    ``host::cron::transaction``); foreign lines keep their order either way."""
    for key in before:
        old, new = before[key], after[key]
        if key == "etc":
            sb.assert_same_tree(old, new, f"{what}: ONEBOX_DIR")
            continue
        if key == "crontab" and not cron_order:
            old, new = cron_groups(old), cron_groups(new)
        check(old == new, f"{what}: {key} changed:\n{old}\n{new}")


def add_admin_cron(s: sb.Sandbox) -> None:
    """Put a foreign line in front of v2's cron lines."""
    table = s.root / "crontab.txt"
    table.write_text(ADMIN_CRON + "\n" + table.read_text())


def assert_no_journals(s: sb.Sandbox) -> None:
    check(not s.journal_dir.exists(), "a configuration journal was left behind")
    check(not (s.etc / ".self-update.json").exists(), "a self-update journal was left behind")
    work = list(s.exe.parent.glob(".onebox-update-*"))
    check(not work, f"self-update work directories left: {work}")


def assert_clean_calls(s: sb.Sandbox) -> None:
    check(not s.forbidden_calls(), f"forbidden external calls: {s.forbidden_calls()}")


def parent_pid(pid: int) -> int:
    return int(Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[1])


def assert_migrated(node: V2Node, worker_before: dict, front_before: int) -> None:
    """The node now runs v3 with everything v2 had."""
    s, values = node.sandbox, node.values
    state = s.state()
    check(state["schema"] == 3, "the upgrade did not write schema 3")
    creds = state["creds"]
    check(creds["uuid"] == values["UUID"] and creds["password"] == values["PASSWORD"],
          "the upgrade changed the UUID or password")
    check(creds["reality"] == {"private_key": values["REALITY_PRIVATE_KEY"],
                               "public_key": values["REALITY_PUBLIC_KEY"],
                               "short_id": values["REALITY_SHORT_ID"]}, "REALITY keys changed")
    check(state["inbounds"] == [{"protocol": "vless-reality", "port": node.core_port, "core": "singbox"}],
          f"inbounds changed: {state['inbounds']}")
    check(state["subscription"] == {"mode": {"type": "ip", "address": "127.0.0.1"}, "port": node.sub_port},
          f"subscription endpoint changed: {state['subscription']}")
    devices = json.loads((s.etc / "subscription/devices.json").read_text())["devices"]
    check(devices == json.loads(node.settings_bytes)["devices"], f"devices not migrated: {devices}")
    check((s.etc / "state.v2.json").read_bytes() == node.state_bytes, "state.v2.json is not v2's state")
    check((s.etc / "subscription/settings.json").read_bytes() == node.settings_bytes,
          "v3 rewrote v2's settings.json")
    assert_v3_services(node, worker_before, front_before)
    # ARCH §7.4: v3 keeps using v2's firewall ledger; ip mode serves the
    # subscription itself, so its port must be open too.
    s.assert_proxy_ports_open([node.core_port, node.sub_port])
    sb.wait_listening(node.core_port)
    assert_devices_served(node)
    assert_no_journals(s)


def assert_v3_services(node: V2Node, worker_before: dict, front_before: int) -> None:
    """Units, cron lines and processes are v3's; WORKER_BEFORE is the v2
    worker's PID record, FRONT_BEFORE the PID of v2's subscription front."""
    s = node.sandbox
    cron = s.crontab()
    check(not any("# onebox-rust:" in line for line in cron), f"v2 cron markers survived: {cron}")
    for service in ("onebox-sing-box", "onebox-network", "onebox-subscription"):
        check(any(line.endswith(f"# onebox:boot:{service}") for line in cron), f"no boot line for {service}")
    # G17: only an ACME or custom certificate needs the renew line.
    check(not any(line.endswith("# onebox:renew") for line in cron), f"REALITY-only node got a renew line: {cron}")
    check(not any("onebox-subscription-web" in line for line in cron), "the v2 front still autostarts")
    check(not (s.etc / "subscription/nginx.conf").exists(), "the v2 front config survived")
    expected = {  # service → (program, args) of the specs v3 writes without an init system
        "onebox-network": (s.exe, ["net-apply"]),
        "onebox-sing-box": (s.root / "bin/sing-box", ["run", "--disable-color", "-c", str(s.etc / "sing-box.json")]),
        "onebox-subscription": (s.exe, ["subscription", "serve"]),
    }
    specs = {p.stem: json.loads(p.read_text()) for p in (s.etc / "services").glob("*.json")}
    check(set(specs) == set(expected), f"service specs after the upgrade: {sorted(specs)}")
    for name, (program, args) in expected.items():
        check((specs[name]["program"], specs[name]["args"]) == (str(program), args),
              f"unexpected {name} spec: {specs[name]}")
    worker = s.service_pid("onebox-subscription")
    check(worker and s.pid_record("onebox-subscription") != worker_before,
          "the subscription worker was not restarted (same PID record)")
    check(s.process_exe(worker) == s.exe, "the worker does not run the installed manager")
    check(sb.sha256_file(s.exe) == sb.sha256_file(node.tools.v3), "the installed manager is not v3")
    check(not sb.proc_matches(front_before, node.tools.front), "the v2 front is still running")
    check(s.service_pid("onebox-subscription-web") is None, "a subscription front still runs")


def assert_restored_v2(node: V2Node, before: dict) -> None:
    """The v2 node of BEFORE (``v2_files`` without PUBLISHED) runs again
    on the v2 manager after a failed or interrupted upgrade."""
    s, tools = node.sandbox, node.tools
    assert_no_journals(s)
    check(sb.sha256_file(s.exe) == sb.sha256_file(tools.v2), "the v2 manager was not restored")
    check(s.state()["values"] == node.values, "the v2 state was not restored")
    # v2's regen rewrites its own cron lines (positions are not kept).
    assert_same_files(before, v2_files(s, exclude=(PUBLISHED,)), "the restored v2 node", cron_order=False)
    check(s.crontab()[0] == ADMIN_CRON, f"a foreign cron line moved: {s.crontab()}")
    sb.wait_listening(node.core_port)
    worker = s.service_pid("onebox-subscription")
    check(worker and s.process_exe(worker) == s.exe, "the worker does not run the restored manager")
    assert_devices_served(node)


# ----- scenarios ---------------------------------------------------------

def v2_subscription_services(s: sb.Sandbox) -> tuple[dict, int]:
    """(PID record of v2's worker, PID of v2's front); both must run."""
    worker, front = s.pid_record("onebox-subscription"), s.service_pid("onebox-subscription-web")
    check(worker and s.service_pid("onebox-subscription") and front,
          "the v2 subscription services are not running")
    return worker, front


def scenario_regen(node: V2Node) -> None:
    """(1) v3 regen as the self-update child of a v2 parent; then v3
    restores a backup the real v2.0.1 wrote (ARCH §7.3)."""
    s = node.sandbox
    worker, front = v2_subscription_services(s)
    backup_id = s.run("backup", "pre-upgrade", binary=node.tools.v2).stdout.strip().splitlines()[-1]
    check((s.etc / "backups" / backup_id / "manifest.json").is_file(), f"no v2 backup {backup_id}")
    s.install_exe(node.tools.v3)
    with s.hold_node_lock() as lock_env:
        busy = s.run("recover", success=False)
        check("另一个配置操作正在进行" in busy.stderr, f"the held lock was not honored:\n{busy.stderr}")
        s.run("regen", binary=s.exe, env=lock_env, pass_fds=(sb.INHERITED_LOCK_FD,))
    assert_migrated(node, worker, front)
    s.run("port", "vless-reality", str(node.spare_port))
    sb.wait_listening(node.spare_port)
    s.run("restore", backup_id)
    inbounds = s.state()["inbounds"]
    check(inbounds == [{"protocol": "vless-reality", "port": node.core_port, "core": "singbox"}],
          f"restoring the v2 backup did not bring the port back: {inbounds}")
    sb.wait_listening(node.core_port)
    sb.wait_listening(node.spare_port, False)
    assert_devices_served(node)


def scenario_rollback(node: V2Node) -> None:
    """(2) a failed child regen leaves byte-identical v2 files and leaves
    the worker to the parent (G6); scenario 6 runs the real parent."""
    s = node.sandbox
    before = v2_files(s)
    s.install_exe(node.tools.v3)
    s.fail_starts(1)
    with s.hold_node_lock() as lock_env:
        failed = s.run("regen", binary=s.exe, env=lock_env, pass_fds=(sb.INHERITED_LOCK_FD,), success=False)
    check("配置未应用，已恢复原状态" in failed.stderr, f"unexpected failure:\n{failed.stderr}")
    assert_no_journals(s)
    assert_same_files(before, v2_files(s), "a failed upgrade")
    sb.wait_listening(node.core_port)
    check(s.service_pid("onebox-sing-box"), "the old core is not running")
    check(s.service_pid("onebox-subscription") is None,
          "a self-update child's rollback must leave the worker to the parent (G6)")


def scenario_v2_journal(node: V2Node) -> None:
    """(3) v3 recovers a journal v2 left when it was killed mid-apply."""
    s = node.sandbox
    add_admin_cron(s)
    before = v2_files(s)
    with s.hang("ufw", "status") as frozen:
        v2 = s.spawn("port", "vless-reality", str(node.spare_port), binary=node.tools.v2)
        frozen()
        v2.kill()
        v2.wait()
    journal = json.loads((s.journal_dir / "journal.json").read_text())
    check(journal.get("version") == 1, f"not a v2 journal: version {journal.get('version')}")
    # Frozen in apply-network: new configuration committed, old core stopped.
    check(journal.get("phase") == "apply-network", f"unexpected v2 phase {journal.get('phase')}")
    sb.wait_listening(node.core_port, False)
    s.run("recover")
    assert_no_journals(s)
    assert_same_files(before, v2_files(s), "recovering a v2 journal", cron_order=False)
    check(s.crontab()[0] == ADMIN_CRON, "recovery moved a foreign cron line")
    sb.wait_listening(node.core_port)
    sb.wait_listening(node.spare_port, False)
    worker = s.service_pid("onebox-subscription")
    check(worker and sb.sha256_file(s.process_exe(worker)) == sb.sha256_file(node.tools.v2),
          "the recovered worker is not v2's")
    assert_devices_served(node)


def scenario_self_update_journal(node: V2Node) -> None:
    """(4) v3 recovers a v2 self-update killed during the v3 child's regen."""
    s, tools = node.sandbox, node.tools
    add_admin_cron(s)
    before = v2_files(s, exclude=(PUBLISHED,))
    s.publish_release(tools.v3, tools.v3_version)
    with s.hang("ufw", "status") as frozen:
        parent = s.spawn("update-script", binary=tools.v2)
        child = parent_pid(frozen())
        check(sb.proc_matches(child, s.exe), "the frozen command does not come from the v3 child")
        parent.kill()
        os.kill(child, signal.SIGKILL)
        parent.wait()
    record = json.loads((s.etc / ".self-update.json").read_text())
    check(record["version"] == 1 and record["phase"] == "replaced", f"unexpected record: {record}")
    work = s.exe.parent / record["work"]
    check((work / "old").is_file() and (work / "config").is_dir(), f"incomplete work directory {work}")
    check(record["old_sha256"] == sb.sha256_file(tools.v2), "the record does not name v2 as old")
    check(sb.sha256_file(s.exe) == record["new_sha256"] == sb.sha256_file(tools.v3), "EXE is not v3")
    child_journal = json.loads((s.journal_dir / "journal.json").read_text())
    check(child_journal.get("phase") == "apply-network", f"unexpected child journal: {child_journal.get('phase')}")
    proc = s.run("recover", success=None)
    check(proc.returncode == EXIT_STALE, f"recover exited {proc.returncode}:\n{proc.stderr}\n{proc.stdout}")
    check(STALE_MESSAGE in proc.stderr + proc.stdout, f"missing the stale-process message:\n{proc.stderr}")
    assert_restored_v2(node, before)


def scenario_update_script(node: V2Node) -> None:
    """(5) v2's update-script upgrades to v3 end to end."""
    s, tools = node.sandbox, node.tools
    worker, front = v2_subscription_services(s)
    s.publish_release(tools.v3, tools.v3_version)
    proc = s.run("update-script", binary=tools.v2)
    check(f"程序已更新到 {tools.v3_version}" in proc.stdout, f"unexpected output:\n{proc.stdout}")
    check("程序更新已完成；请重新执行 onebox 以使用新版本" in proc.stdout, "missing the completion message")
    assert_migrated(node, worker, front)


def scenario_update_script_rollback(node: V2Node) -> None:
    """(6) v2's update-script installs v3, whose child regen fails to start
    the core: v3 rolls its own journal back and exits non-zero, then the v2
    parent recovers (ARCH §7.1) and the node runs v2 again."""
    s, tools = node.sandbox, node.tools
    add_admin_cron(s)
    before = v2_files(s, exclude=(PUBLISHED,))
    s.publish_release(tools.v3, tools.v3_version)
    s.fail_starts(1)
    proc = s.run("update-script", binary=tools.v2, success=False)
    check("更新失败，已恢复原程序" in proc.stderr, f"unexpected failure:\n{proc.stderr}\n{proc.stdout}")
    check("配置未应用，已恢复原状态" in proc.stderr, f"the v3 child did not roll back:\n{proc.stderr}")
    assert_restored_v2(node, before)


Scenario = Callable[[V2Node], None]
SCENARIOS: list[tuple[str, Scenario, bool]] = [
    # (name, function, needs the fixture core)
    ("regen", scenario_regen, False),
    ("rollback", scenario_rollback, True),
    ("v2-journal", scenario_v2_journal, False),
    ("self-update-journal", scenario_self_update_journal, False),
    ("update-script", scenario_update_script, False),
    ("update-script-rollback", scenario_update_script_rollback, True),
]


# ----- driver ------------------------------------------------------------

def run_pass(work: Path, label: str, tools: Tools) -> None:
    for name, scenario, needs_fixture in SCENARIOS:
        if needs_fixture and not tools.fixture_core:
            continue
        node = install_v2(work / f"{label}-{name}", tools)
        try:
            scenario(node)
            assert_clean_calls(node.sandbox)
            logs = node.sandbox.logs()
            check(logs == SERVICE_LOGS, f"unexpected service logs: {logs}")
        finally:
            node.sandbox.cleanup()
        print(f"PASS upgrade ({label}): {name}")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--binary", default=os.environ.get("ONEBOX_TEST_BINARY", str(REPO / "target/debug/onebox")))
    p.add_argument("--v2", default=os.environ.get("ONEBOX_TEST_V2_BINARY"),
                   help="Onebox v2.0.1 binary (default $ONEBOX_TEST_V2_BINARY)")
    p.add_argument("--singbox", default=os.environ.get("ONEBOX_TEST_SINGBOX"),
                   help="real sing-box for the second pass (default $ONEBOX_TEST_SINGBOX)")
    p.add_argument("--keep", action="store_true", help="keep the sandbox directories")
    return p.parse_args()


def version_of(binary: Path) -> str:
    import subprocess

    return subprocess.run([str(binary), "version"], capture_output=True, text=True, check=True,
                          stdin=subprocess.DEVNULL).stdout.strip()


def main() -> int:
    args = parse_args()
    v3 = sb.executable(args.binary, "the Onebox binary (--binary / ONEBOX_TEST_BINARY)")
    v2 = sb.executable(args.v2, "ONEBOX_TEST_V2_BINARY")
    real_core = sb.executable(args.singbox, "ONEBOX_TEST_SINGBOX")
    if v2 is None:
        sb.skip_or_fail("upgrade suite: ONEBOX_TEST_V2_BINARY is not set")
        return 0
    check(version_of(v2) == V2_VERSION, f"{v2} is not Onebox {V2_VERSION}")
    blocker = sb.full_run_blocker()
    if blocker:
        sb.skip_or_fail(f"upgrade suite: {blocker}")
        return 0
    work = Path(tempfile.mkdtemp(prefix="onebox-upgrade-"))
    try:
        tripwire = sb.seal_host(work)
        build = work / "build"
        build.mkdir()
        fixture_core, front = fx.compile_fake_core(build), fx.compile_fake_front(build)
        version = version_of(v3)
        run_pass(work, "fixture-core", Tools(v2, v3, version, fixture_core, front, True, tripwire))
        if real_core:
            run_pass(work, "real-sing-box", Tools(v2, v3, version, real_core, front, False, tripwire))
        else:
            sb.skip_or_fail("real-core upgrade pass: ONEBOX_TEST_SINGBOX is not set")
        return 0
    finally:
        if args.keep:
            print(f"sandboxes kept: {work}")
        else:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
