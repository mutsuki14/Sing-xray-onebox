#!/usr/bin/env python3
"""Egress policy and the shared REALITY + XHTTP port, against real cores.

    ONEBOX_TEST_BINARY=target/debug/onebox ONEBOX_TEST_SINGBOX=/path/sing-box \\
    ONEBOX_TEST_XRAY=/path/xray python3 tests/e2e/policy.py

``private/<core>/<off|on>``: a Shadowsocks node whose server and client run
on the same core, with the private-address policy off and on and the own
address ``9.9.9.9/32``. Every target is logical: an authoritative DNS
fixture answers ``private.policy.test`` → 127.0.0.1, ``self.policy.test`` →
9.9.9.9 and ``public.policy.test`` → 8.8.4.4, and an allowed connection is
redirected to the loopback HTTP fixture only *after* the generated routing
decided, so no packet leaves the host. Public targets must always be
reached; private and own addresses (literal or resolved) exactly when the
policy is off; with the policy on, each fixture name must actually have
been resolved (domain rules are enforced on resolved addresses). A core
crash is a failure, never a rejection. Documentation ranges cannot serve as
public targets because the production policy blocks them too.

``shared/<form>/*``: Xray hosts ``vless-reality`` and ``vless-xhttp`` on
the same TCP port (XHTTP behind the REALITY fallback). Xray clients of both
and a sing-box REALITY client reach the target before and after the guard
checks. Reference checks prove the TLS fixture itself accepts a correct,
wrong or missing SNI, so through the REALITY guard port only the correct
SNI may pass; plain TLS with the REALITY SNI to the proxy port must fall
back to the real target.

State shapes: with ``--states mixed`` (the default) each shape meets each
policy state — sing-box runs the policy off from a v2 ``{"values"}`` state
and on from a v3 state, Xray the other way round — so ``BLOCK_PRIVATE=1``
and ``OWN_IP_CIDRS`` go through the real migration on a core where they
change the result. The shared port runs from both shapes (the v2 shape
has ``PORT_vless_xhttp == PORT_vless_reality``). Every ``render`` of a
fixture must print nothing on stderr, so a lossy migration, which only
warns, fails the case.

Options: ``--servers singbox,xray``, ``--skip-shared``, ``--states
mixed|v2|v3``, ``--report FILE``. Environment as for protocols.py.

Changes from v2 (tests/native_policy.py): fixtures come from the ``_*.py``
modules instead of importing the protocol suite; the XHTTP fallback socket
is the fixed ``@onebox-xhttp`` (v3 dropped ``XR_XHTTP_SOCK``), so each
shared case first checks that no other process holds it and runs on its
own; v3 schema-3 states are exercised next to migrated v2 states; the
harness self-tests run first (``harness/self-test``).
"""
from __future__ import annotations

import argparse
import contextlib
import sys
from pathlib import Path

from _bench import Bench, set_log_level, socks_client
from _fixtures import DnsFixture, abstract_socket_bound, reached, socks_http_marker, tls_marker
from _harness import LOOPBACK, VERBOSE, Process, Results, Workspace, comma_list, describe, resolve_tools
from _node import STATE_FORMS, FixtureNode
from _selftest import self_test

OWN_IP = "9.9.9.9"
PUBLIC_IP = "8.8.4.4"
RECORDS = {
    "private.policy.test": "127.0.0.1",
    "self.policy.test": OWN_IP,
    "public.policy.test": PUBLIC_IP,
}
XHTTP_SOCKET = "onebox-xhttp"
SERVERS = ("singbox", "xray")
# (core, policy on) → state shape under --states mixed: each shape meets
# each policy state, and each core runs both shapes.
MIXED_PRIVATE_FORMS = {
    ("singbox", False): "v2", ("singbox", True): "v3",
    ("xray", False): "v3", ("xray", True): "v2",
}


class Policy(Bench):
    def __init__(self, root: Path, tools: dict[str, str], args, results: Results):
        super().__init__(root, tools, results, marker_prefix="onebox-policy-")
        self.args = args
        try:
            self.dns = DnsFixture(self.ports.get(), RECORDS)
        except BaseException:
            super().close()
            raise

    def close(self):
        self.dns.close()
        super().close()

    def private_form(self, core: str, blocked: bool) -> str:
        if self.args.states != "mixed":
            return self.args.states
        return MIXED_PRIVATE_FORMS[(core, blocked)]

    def shared_forms(self) -> tuple[str, ...]:
        return STATE_FORMS if self.args.states == "mixed" else (self.args.states,)

    def expect(self, name: str, action, expected: bool, processes=()) -> None:
        """Record whether ``action`` reached the marker exactly when ``expected``."""
        ok, error = reached(action)
        if any(not process.alive() for process in processes):
            self.results.record(name, False, "a core exited; a connection failure is not a "
                                "policy rejection\n" + "\n".join(p.tail() for p in processes))
        elif ok != expected:
            detail = "unexpected successful marker response" if ok else (error or "no marker")
            self.results.record(name, False, detail + "\n" + "\n".join(p.tail() for p in processes))
        else:
            self.results.record(name, True)

    def check_render(self, name: str, env, node: FixtureNode, form: str) -> bool:
        """``render probe`` of the fixture state lists exactly the node's protocols
        and prints nothing on stderr (no migration warning)."""
        def check():
            entries = self.onebox(env, "render", "probe", quiet=True)["entries"]
            ids = [entry["id"] for entry in entries]
            assert ids == node.protocols(), f"probe lists {ids}"
        return self.results.attempt(f"{name}/render[{form}]", check)

    def marker_via(self, proxy_port: int, target: str) -> None:
        socks_http_marker(proxy_port, target, self.fixture.http_port, self.fixture.marker,
                          timeout=3)

    # -- private / own addresses ---------------------------------------------

    def policy_server_config(self, env, core: str) -> dict:
        """The rendered server with the fixture DNS and the post-routing redirect.

        Route actions and deny rules come only from the real renderer.
        """
        config = self.onebox(env, "render", "server", core, quiet=True)
        set_log_level(core, config, "debug" if VERBOSE else "info")
        if core == "singbox":
            config["dns"]["servers"] = [{"type": "udp", "tag": "local", "server": LOOPBACK,
                                         "server_port": self.dns.port}]
            config["route"]["rules"].append({"action": "route-options",
                                             "override_address": LOOPBACK})
            return config
        config["dns"] = {"servers": [{"address": LOOPBACK, "port": self.dns.port}],
                         "queryStrategy": "UseIPv4", "tag": "policy-fixture-dns"}
        # Internal DNS queries need their own direct transport to the
        # fixture; only that synthetic inbound tag bypasses the generated
        # rules, authenticated proxy requests cannot use it.
        config["outbounds"].append({"tag": "policy-dns-direct", "protocol": "freedom",
                                    "settings": {"finalRules": [{"action": "allow"}]}})
        config["routing"]["rules"].insert(0, {"type": "field", "inboundTag": ["policy-fixture-dns"],
                                              "outboundTag": "policy-dns-direct"})
        # The first (default) direct outbound runs only after Xray's
        # generated IPIfNonMatch policy, including its DNS retry.
        config["outbounds"][0]["settings"] = {"redirect": f"{LOOPBACK}:0",
                                              "finalRules": [{"action": "allow"}]}
        return config

    def private_policy(self, core: str) -> None:
        for blocked in (False, True):
            name = f"private/{core}/{'on' if blocked else 'off'}"
            self.dns.reset()
            try:
                self.private_case(name, core, blocked, self.private_form(core, blocked))
            except Exception as error:  # noqa: BLE001 - recorded as this case's failure
                self.results.record(name + "/startup", False, describe(error))

    def private_case(self, name: str, core: str, blocked: bool, form: str) -> None:
        directory = self.root / name
        layout = self.layout(directory)
        node = self.node([("shadowsocks", core)], block_private=blocked,
                         own_cidrs=[OWN_IP + "/32"])
        node.write(layout, form)
        env = layout.env()
        if not self.check_render(name, env, node, form):
            return
        config = self.policy_server_config(env, core)
        with self.start_server(core, directory, config, env, node) as server:
            port = self.ports.get()
            client_config = socks_client(core, port, [self.outbound(env, "shadowsocks", core)])
            with self.start_client(core, directory / "client", client_config, env, port) as client:
                peers = (server, client)
                self.expect(f"{name}/public-before",
                            lambda: self.marker_via(port, PUBLIC_IP), True, peers)
                for label, target in (("private-ip", "127.0.0.1"),
                                      ("private-dns", "private.policy.test"),
                                      ("own-ip", OWN_IP), ("own-dns", "self.policy.test")):
                    self.expect(f"{name}/{label}", lambda t=target: self.marker_via(port, t),
                                not blocked, peers)
                self.expect(f"{name}/public-dns-after",
                            lambda: self.marker_via(port, "public.policy.test"), True, peers)
                self.expect(f"{name}/public-after",
                            lambda: self.marker_via(port, PUBLIC_IP), True, peers)
        if blocked:
            for domain in RECORDS:
                queried = self.dns.queried(domain)
                self.results.record(f"{name}/resolved-{domain}", queried,
                                    "" if queried else "server never queried the fixture DNS")

    # -- shared REALITY + XHTTP port -------------------------------------------

    def shared_port(self, include_singbox: bool) -> None:
        for form in self.shared_forms():
            name = f"shared/{form}"
            try:
                self.shared_case(name, include_singbox, form)
            except Exception as error:  # noqa: BLE001
                self.results.record(f"{name}/startup", False, describe(error))

    def shared_case(self, name: str, include_singbox: bool, form: str) -> None:
        # The XHTTP fallback listens on a fixed abstract socket; a second
        # holder (a real Onebox node, another test run) would take the
        # fallback traffic.
        assert not abstract_socket_bound(XHTTP_SOCKET), \
            f"abstract socket @{XHTTP_SOCKET} is already in use; stop the other Xray first"
        directory = self.root / name
        layout = self.layout(directory)
        node = self.node([("vless-reality", "xray"), ("vless-xhttp", "xray")])
        port = node.inbound("vless-reality").port
        node.inbound("vless-xhttp").port = port
        node.write(layout, form)
        env = layout.env()
        if not self.check_render(name, env, node, form):
            return
        combinations = [("vless-reality", "xray"), ("vless-xhttp", "xray")]
        if include_singbox:
            combinations.append(("vless-reality", "singbox"))
        with self.start_server("xray", directory, self.server_config(env, "xray"), env, node) as server, \
                contextlib.ExitStack() as stack:
            clients = []
            for protocol, core in combinations:
                local = self.ports.get()
                config = socks_client(core, local, [self.outbound(env, protocol, core)],
                                      udp_ip=False)
                label = f"{protocol}/{core}"
                client = stack.enter_context(self.start_client(
                    core, directory / f"{protocol}-{core}", config, env, local))
                clients.append((label, local, client))
                self.expect(f"{name}/{label}/before",
                            lambda p=local: self.target_tcp(p), True, (server, client))
            self.guard_checks(name, port, node.guard_port, server)
            for label, local, client in clients:
                self.expect(f"{name}/{label}/after", lambda p=local: self.target_tcp(p), True,
                            (server, client))

    def guard_checks(self, name: str, port: int, guard: int, server: Process) -> None:
        """Wrong or missing SNI is accepted by the target itself, so its
        rejection through the guard port is the guard's doing."""
        marker = self.fixture.marker
        for check, sni in (("correct-sni", "reality.test"), ("wrong-sni", "wrong.test"),
                           ("no-sni", None)):
            self.expect(f"{name}/reference/{check}",
                        lambda n=sni: tls_marker(self.fixture.tls_port, n, marker), True)
            self.expect(f"{name}/guard/{check}", lambda n=sni: tls_marker(guard, n, marker),
                        check == "correct-sni", (server,))
        self.expect(f"{name}/ordinary-tls-fallback",
                    lambda: tls_marker(port, "reality.test", marker), True, (server,))


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--servers", type=comma_list(SERVERS), default=list(SERVERS))
    parser.add_argument("--skip-shared", action="store_true",
                        help="run only the private/own-address policy checks")
    parser.add_argument("--states", choices=("mixed", *STATE_FORMS), default="mixed")
    parser.add_argument("--report", type=Path)
    return parser.parse_args(argv)


def run_suite(args, results: Results) -> None:
    self_test(results)
    # Xray generates the REALITY keys; the shared case also needs sing-box.
    required = set(args.servers) | {"xray"} | (set() if args.skip_shared else {"singbox"})
    tools = resolve_tools(results, sorted(required))
    if tools is None:
        return
    with Workspace("onebox-e2e-policy-") as root:
        try:
            policy = Policy(root, tools, args, results)
        except Exception as error:  # noqa: BLE001 - fixture set-up failed
            results.record("setup", False, describe(error))
            return
        try:
            for core in args.servers:
                policy.private_policy(core)
            if not args.skip_shared:
                policy.shared_port(include_singbox=True)
        finally:
            policy.close()


def main(argv=None) -> int:
    args = parse_args(argv)
    results = Results("Policy E2E")
    # Any unexpected error is recorded, so the summary line always appears.
    with results.guard("suite"):
        run_suite(args, results)
    return results.finish(args.report)


if __name__ == "__main__":
    sys.exit(main())
