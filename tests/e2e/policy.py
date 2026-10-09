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

``shared/*``: Xray hosts ``vless-reality`` and ``vless-xhttp`` on the same
TCP port (XHTTP behind the REALITY fallback). Xray clients of both and a
sing-box REALITY client reach the target before and after the guard
checks. Reference checks prove the TLS fixture itself accepts a correct,
wrong or missing SNI, so through the REALITY guard port only the correct
SNI may pass; plain TLS with the REALITY SNI to the proxy port must fall
back to the real target.

Options: ``--servers singbox,xray``, ``--skip-shared``, ``--states
mixed|v2|v3`` (mixed: v2 with the policy off, v3 with it on and for the
shared port), ``--report FILE``. Environment as for protocols.py.

Changes from v2 (tests/native_policy.py): fixtures come from ``_harness``
instead of importing the protocol suite; the XHTTP fallback socket is the
fixed ``@onebox-xhttp`` (v3 dropped ``XR_XHTTP_SOCK``), so the shared case
first checks that no other process holds it and runs on its own; v3
schema-3 states are exercised next to migrated v2 states.
"""
from __future__ import annotations

import argparse
import contextlib
from pathlib import Path
import sys

import _harness as h

OWN_IP = "9.9.9.9"
PUBLIC_IP = "8.8.4.4"
RECORDS = {
    "private.policy.test": "127.0.0.1",
    "self.policy.test": OWN_IP,
    "public.policy.test": PUBLIC_IP,
}
XHTTP_SOCKET = "onebox-xhttp"
SERVERS = ("singbox", "xray")


class Policy(h.Bench):
    def __init__(self, root: Path, tools: dict[str, str], args, results: h.Results):
        super().__init__(root, tools, results, marker_prefix="onebox-policy-")
        self.args = args
        self.dns = h.DnsFixture(self.ports.get(), RECORDS)

    def close(self):
        self.dns.close()
        super().close()

    def form(self, preferred: str) -> str:
        return preferred if self.args.states == "mixed" else self.args.states

    def expect(self, name: str, action, expected: bool, processes=()) -> None:
        """Record whether ``action`` reached the marker exactly when ``expected``."""
        ok, error = h.reached(action)
        if any(not process.alive() for process in processes):
            self.results.record(name, False, "a core exited; a connection failure is not a "
                                "policy rejection\n" + "\n".join(p.tail() for p in processes))
        elif ok != expected:
            detail = "unexpected successful marker response" if ok else (error or "no marker")
            self.results.record(name, False, detail + "\n" + "\n".join(p.tail() for p in processes))
        else:
            self.results.record(name, True)

    def check_render(self, name: str, env, node: h.FixtureNode, form: str) -> None:
        """``render probe`` of the fixture state lists exactly the node's protocols."""
        def check():
            entries = self.onebox(env, "render", "probe")["entries"]
            ids = [entry["id"] for entry in entries]
            assert ids == node.protocols(), f"probe lists {ids}"
        if not self.results.attempt(f"{name}/render[{form}]", check):
            raise AssertionError("the fixture state does not render")

    def marker_via(self, proxy_port: int, target: str) -> None:
        h.socks_http_marker(proxy_port, target, self.fixture.http_port, self.fixture.marker,
                            timeout=3)

    # -- private / own addresses ---------------------------------------------

    def policy_server_config(self, env, core: str) -> dict:
        """The rendered server with the fixture DNS and the post-routing redirect.

        Route actions and deny rules come only from the real renderer.
        """
        config = self.onebox(env, "render", "server", core)
        h.set_log_level(core, config, "debug" if h.VERBOSE else "info")
        if core == "singbox":
            config["dns"]["servers"] = [{"type": "udp", "tag": "local", "server": h.LOOPBACK,
                                         "server_port": self.dns.port}]
            config["route"]["rules"].append({"action": "route-options",
                                             "override_address": h.LOOPBACK})
            return config
        config["dns"] = {"servers": [{"address": h.LOOPBACK, "port": self.dns.port}],
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
        config["outbounds"][0]["settings"] = {"redirect": f"{h.LOOPBACK}:0",
                                              "finalRules": [{"action": "allow"}]}
        return config

    def private_policy(self, core: str) -> None:
        for blocked in (False, True):
            name = f"private/{core}/{'on' if blocked else 'off'}"
            self.dns.reset()
            try:
                self.private_case(name, core, blocked, self.form("v3" if blocked else "v2"))
            except Exception as error:  # noqa: BLE001 - recorded as this case's failure
                self.results.record(name + "/startup", False, h.describe(error))

    def private_case(self, name: str, core: str, blocked: bool, form: str) -> None:
        directory = self.root / name
        layout = self.layout(directory)
        node = self.node([("shadowsocks", core)], block_private=blocked,
                         own_cidrs=[OWN_IP + "/32"])
        node.write(layout, form)
        env = layout.env()
        self.check_render(name, env, node, form)
        config = self.policy_server_config(env, core)
        with self.start_server(core, directory, config, env, node) as server:
            port = self.ports.get()
            client_config = h.socks_client(core, port, [self.outbound(env, "shadowsocks", core)])
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
        try:
            self.shared_case(include_singbox, self.form("v3"))
        except Exception as error:  # noqa: BLE001
            self.results.record("shared/startup", False, h.describe(error))

    def shared_case(self, include_singbox: bool, form: str) -> None:
        # The XHTTP fallback listens on a fixed abstract socket; a second
        # holder (a real Onebox node, another test run) would take the
        # fallback traffic.
        assert not h.abstract_socket_bound(XHTTP_SOCKET), \
            f"abstract socket @{XHTTP_SOCKET} is already in use; stop the other Xray first"
        directory = self.root / "shared"
        layout = self.layout(directory)
        node = self.node([("vless-reality", "xray"), ("vless-xhttp", "xray")])
        port = node.inbound("vless-reality").port
        node.inbound("vless-xhttp").port = port
        node.write(layout, form)
        env = layout.env()
        self.check_render("shared", env, node, form)
        combinations = [("vless-reality", "xray"), ("vless-xhttp", "xray")]
        if include_singbox:
            combinations.append(("vless-reality", "singbox"))
        with self.start_server("xray", directory, self.server_config(env, "xray"), env, node) as server, \
                contextlib.ExitStack() as stack:
            clients = []
            for protocol, core in combinations:
                local = self.ports.get()
                config = h.socks_client(core, local, [self.outbound(env, protocol, core)],
                                        udp_ip=False)
                label = f"{protocol}/{core}"
                client = stack.enter_context(self.start_client(
                    core, directory / f"{protocol}-{core}", config, env, local))
                clients.append((label, local, client))
                self.expect(f"shared/{label}/before",
                            lambda p=local: self.target_tcp(p), True, (server, client))
            self.guard_checks(port, node.guard_port, server)
            for label, local, client in clients:
                self.expect(f"shared/{label}/after", lambda p=local: self.target_tcp(p), True,
                            (server, client))

    def guard_checks(self, port: int, guard: int, server: h.Process) -> None:
        """Wrong or missing SNI is accepted by the target itself, so its
        rejection through the guard port is the guard's doing."""
        marker = self.fixture.marker
        for name, sni in (("correct-sni", "reality.test"), ("wrong-sni", "wrong.test"),
                          ("no-sni", None)):
            self.expect(f"shared/reference/{name}",
                        lambda n=sni: h.tls_marker(self.fixture.tls_port, n, marker), True)
            self.expect(f"shared/guard/{name}", lambda n=sni: h.tls_marker(guard, n, marker),
                        name == "correct-sni", (server,))
        self.expect("shared/ordinary-tls-fallback",
                    lambda: h.tls_marker(port, "reality.test", marker), True, (server,))


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--servers", type=h.comma_list(SERVERS), default=list(SERVERS))
    parser.add_argument("--skip-shared", action="store_true",
                        help="run only the private/own-address policy checks")
    parser.add_argument("--states", choices=("mixed", *h.STATE_FORMS), default="mixed")
    parser.add_argument("--report", type=Path)
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    results = h.Results("Policy E2E")
    # Xray generates the REALITY keys; the shared case also needs sing-box.
    required = set(args.servers) | {"xray"} | (set() if args.skip_shared else {"singbox"})
    tools = h.resolve_tools(results, sorted(required))
    if tools is None:
        return results.finish(args.report)
    with h.Workspace("onebox-e2e-policy-") as root:
        policy = Policy(root, tools, args, results)
        try:
            for core in args.servers:
                policy.private_policy(core)
            if not args.skip_shared:
                policy.shared_port(include_singbox=True)
        finally:
            policy.close()
    return results.finish(args.report)


if __name__ == "__main__":
    sys.exit(main())
