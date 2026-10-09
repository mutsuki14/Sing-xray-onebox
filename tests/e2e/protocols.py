#!/usr/bin/env python3
"""Protocol x server core x client matrix with real cores, loopback only.

    ONEBOX_TEST_BINARY=target/debug/onebox ONEBOX_TEST_SINGBOX=/path/sing-box \\
    ONEBOX_TEST_XRAY=/path/xray ONEBOX_TEST_MIHOMO=/path/mihomo python3 tests/e2e/protocols.py

For every protocol each supporting server core (sing-box, Xray) runs the
configuration ``onebox render server`` produced, and every supporting client
(sing-box, Xray, mihomo) runs the outbound the ``client`` exports contain.
Each pair must relay TCP (HTTP marker via SOCKS5 CONNECT) and UDP (SOCKS5
UDP ASSOCIATE echo). The target name ``native-e2e.invalid`` and the TEST-NET
address ``192.0.2.53`` are rewritten to the loopback fixtures exclusively by
the server under test, so a direct connection cannot pass either check.

Profiles: ``self`` (every protocol, self-signed pinned certificate, plain
VMess, no Hysteria2 obfuscation) and ``ca`` (the six certificate protocols,
CA-signed certificate trusted through ``SSL_CERT_FILE``, VMess over TLS,
Hysteria2 obfuscation). A negative suite (``authentication/*``) proves that
AnyTLS-REALITY rejects wrong keys, short IDs, passwords and ordinary TLS.

States alternate between the v2 ``{"values"}`` shape (migrated by every
command) and the v3 schema-3 shape, so each server core runs both; every v3
case also checks that both shapes of the same node render identically.

Options: ``--protocols``, ``--servers``, ``--clients``, ``--profiles``
(comma lists), ``--states mixed|v2|v3``, ``--negative-only``,
``--skip-negative``, ``--report FILE``. Environment: ``VERBOSE=1`` (debug
core logs), ``KEEP=1`` (keep the fixture directory),
``ONEBOX_TEST_REQUIRE_FULL=1`` (a missing mihomo is a failure).

Changes from v2 (tests/native_e2e.py): helpers moved to ``_harness``; the
mihomo export is parsed as YAML and must agree with ``client provider``;
the proxy certificate lives in ``<ONEBOX_DIR>/tls``; v3 schema-3 states
are exercised next to migrated v2 states; ``render probe`` is recorded as
its own check per case; the mihomo variable is ``ONEBOX_TEST_MIHOMO``.
"""
from __future__ import annotations

import argparse
import copy
import dataclasses
import json
import sys
from pathlib import Path

import _harness as h

SERVERS = ("singbox", "xray")
CLIENTS = ("singbox", "xray", "mihomo")


@dataclasses.dataclass(frozen=True)
class Profile:
    name: str
    protocols: frozenset[str]
    custom_ca: bool         # see h.Bench.node


PROFILES = {
    "self": Profile("self", frozenset(h.PROTOCOLS), custom_ca=False),
    "ca": Profile("ca", h.CERTIFICATE_PROTOCOLS | {"vmess-ws"}, custom_ca=True),
}


def client_supports(client: str, protocol: str) -> bool:
    if client == "mihomo":
        return protocol != "anytls-reality"
    return h.core_supports(client, protocol)


def plan(args) -> list[tuple[Profile, str, str, str]]:
    """(profile, protocol, server, state form) of every server case, in run order.

    With ``--states mixed`` the form alternates per (profile, server), so
    every server core runs both forms whenever it has two or more cases.
    """
    cases, counters = [], {}
    for profile in (PROFILES[name] for name in args.profiles):
        for protocol in args.protocols:
            if protocol not in profile.protocols:
                continue
            for server in args.servers:
                if not h.core_supports(server, protocol):
                    continue
                index = counters.get((profile.name, server), 0)
                counters[(profile.name, server)] = index + 1
                form = args.states if args.states != "mixed" else h.STATE_FORMS[index % 2]
                cases.append((profile, protocol, server, form))
    return cases


class Matrix(h.Bench):
    def __init__(self, root: Path, tools: dict[str, str], args, results: h.Results):
        super().__init__(root, tools, results, marker_prefix="onebox-native-")
        self.args = args

    # -- server ---------------------------------------------------------------

    def start_node(self, directory: Path, node: h.FixtureNode, server: str, env) -> h.Process:
        return self.start_server(server, directory, self.server_config(env, server), env, node)

    # -- clients --------------------------------------------------------------

    def client_outbounds(self, env, protocol: str, client: str) -> list[dict]:
        """The client's outbound(s), checked against the matching ``client`` export."""
        if client == "mihomo":
            full = h.onebox_yaml(self.tools["onebox"], env, "client", "mihomo")
            provider = h.onebox_yaml(self.tools["onebox"], env, "client", "provider")
            proxies = full["proxies"]
            assert len(proxies) == 1, f"expected one mihomo proxy, got {len(proxies)}"
            assert provider == {"proxies": proxies}, "client provider disagrees with client mihomo"
            return proxies
        outbound = self.outbound(env, protocol, client)
        if client == "singbox":
            full = self.onebox(env, "client", "singbox-notun")
            by_tag = {out["tag"]: out for out in full["outbounds"]}
            assert by_tag.get(outbound["tag"]) == outbound, \
                "client singbox-notun disagrees with render outbound"
            detour = outbound.get("detour")
            return [outbound] + ([by_tag[detour]] if detour else [])
        full = self.onebox(env, "client", "xray")
        first = copy.deepcopy(full["outbounds"][0])
        first["tag"] = outbound["tag"]
        assert first == outbound, "client xray disagrees with render outbound"
        return [outbound]

    # -- cases ----------------------------------------------------------------

    def check_probe(self, env, protocol: str) -> None:
        bundle = self.onebox(env, "render", "probe")
        assert bundle["schema"] == 1 and len(bundle["entries"]) == 1, "unexpected probe bundle"
        probe = bundle["entries"][0]
        assert probe["id"] == protocol, f"probe id {probe['id']}"
        assert probe["transport"] == h.transport_of(protocol), f"probe transport {probe['transport']}"
        assert self.keys[0] not in json.dumps(bundle), "probe exports the server private key"
        if protocol in h.REALITY_PROTOCOLS:
            assert probe["reality"]["sni"] == "reality.test", "probe REALITY SNI"

    def check_v2_parity(self, layout: h.Layout, node: h.FixtureNode, server: str) -> None:
        """The v2 shape of the same node (migrated) renders exactly like the v3 shape.

        Both shapes are rendered in the same layout (server configurations
        contain the certificate paths); the v3 state is in place afterwards.
        """
        commands = (("render", "server", server), ("render", "probe"))
        env = layout.env()
        try:
            node.write(layout, "v2")
            migrated = [self.onebox(env, *args) for args in commands]
        finally:
            node.write(layout, "v3")
        for args, expected in zip(commands, migrated):
            assert self.onebox(env, *args) == expected, \
                f"`{' '.join(args)}` differs between the v3 and the migrated v2 state"

    def case(self, profile: Profile, protocol: str, server: str, form: str) -> None:
        name = f"{profile.name}/{server}/{protocol}"
        directory = self.root / name
        layout = self.layout(directory)
        node = self.node([(protocol, server)], custom_ca=profile.custom_ca)
        node.write(layout, form)
        env = layout.env()
        if not self.results.attempt(f"{name}/probe[{form}]", lambda: self.check_probe(env, protocol)):
            return
        if form == "v3":
            self.results.attempt(f"{name}/v3-matches-v2",
                                 lambda: self.check_v2_parity(layout, node, server))
        try:
            with self.start_node(directory, node, server, env) as process:
                for client in self.args.clients:
                    if client in self.tools and client_supports(client, protocol):
                        self.client_checks(name, directory, protocol, client, process, env)
        except Exception as error:  # noqa: BLE001 - recorded as this case's failure
            self.results.record(f"{name}/server", False, h.describe(error))

    def client_checks(self, name, directory, protocol, client, server, env) -> None:
        port = self.ports.get()
        try:
            config = h.socks_client(client, port, self.client_outbounds(env, protocol, client))
            with self.start_client(client, directory / client, config, env, port) as native:
                for transport, request in (("tcp", self.target_tcp), ("udp", self.target_udp)):
                    label = f"{name}/{client}/{transport}"
                    try:
                        request(port)
                        assert native.alive() and server.alive(), "core exited while relaying"
                        self.results.record(label, True)
                    except Exception as error:  # noqa: BLE001
                        self.results.record(label, False, f"{h.describe(error)}\nCLIENT:\n"
                                            f"{native.tail()}\nSERVER:\n{server.tail()}")
        except Exception as error:  # noqa: BLE001
            self.results.record(f"{name}/{client}/start", False, h.describe(error))

    # -- negative -------------------------------------------------------------

    NEGATIVE_MODES = ("positive-before", "wrong-public-key", "wrong-short-id",
                      "wrong-password", "ordinary-tls", "positive-after")

    def tamper(self, outbound: dict, mode: str, node: h.FixtureNode) -> None:
        tls = outbound["tls"]
        if mode == "wrong-public-key":
            tls["reality"]["public_key"] = self.wrong_public
        elif mode == "wrong-short-id":
            sid = node.creds["short_id"]
            tls["reality"]["short_id"] = ("1" if sid[0] == "0" else "0") + sid[1:]
        elif mode == "wrong-password":
            outbound["password"] += "-wrong"
        elif mode == "ordinary-tls":
            tls.pop("reality")
            tls["insecure"] = True

    def negative(self, form: str) -> None:
        protocol = "anytls-reality"
        directory = self.root / "authentication"
        layout = self.layout(directory)
        node = self.node([(protocol, "singbox")])
        node.write(layout, form)
        env = layout.env()
        try:
            with self.start_node(directory, node, "singbox", env) as server:
                for mode in self.NEGATIVE_MODES:
                    self.negative_mode(directory, mode, node, server, env)
                for client in ("xray", "mihomo"):
                    result = h.run_onebox(self.tools["onebox"], env, "client", client, check=False)
                    ok = result.code != 0 and not result.stdout
                    self.results.record(f"authentication/reject-{client}-export", ok, "" if ok else
                                        f"exit {result.code}, stdout {result.stdout[:200]!r}")
        except Exception as error:  # noqa: BLE001
            self.results.record("authentication/server", False, h.describe(error))

    def negative_mode(self, directory, mode, node, server, env) -> None:
        port = self.ports.get()
        try:
            outbounds = self.client_outbounds(env, "anytls-reality", "singbox")
            self.tamper(outbounds[0], mode, node)
            config = h.socks_client("singbox", port, outbounds)
            with self.start_client("singbox", directory / mode, config, env, port) as client:
                ok, _ = h.reached(lambda: self.target_tcp(port, timeout=3))
                assert client.alive() and server.alive(), "rejection was caused by a core crash"
                assert ok == mode.startswith("positive"), \
                    "reached the target" if ok else "did not reach the target"
                self.results.record(f"authentication/{mode}", True)
        except Exception as error:  # noqa: BLE001
            self.results.record(f"authentication/{mode}", False, h.describe(error))


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--protocols", type=h.comma_list(h.PROTOCOLS), default=list(h.PROTOCOLS))
    parser.add_argument("--servers", type=h.comma_list(SERVERS), default=list(SERVERS))
    parser.add_argument("--clients", type=h.comma_list(CLIENTS), default=list(CLIENTS))
    parser.add_argument("--profiles", type=h.comma_list(tuple(PROFILES)), default=list(PROFILES))
    parser.add_argument("--states", choices=("mixed", *h.STATE_FORMS), default="mixed")
    parser.add_argument("--negative-only", action="store_true")
    parser.add_argument("--skip-negative", action="store_true")
    parser.add_argument("--report", type=Path)
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    results = h.Results("Protocol E2E")
    optional = ["mihomo"] if "mihomo" in args.clients else []
    tools = h.resolve_tools(results, ["singbox", "xray"], optional)
    if tools is None:
        return results.finish(args.report)
    with h.Workspace("onebox-e2e-protocols-") as root:
        try:
            matrix = Matrix(root, tools, args, results)
        except Exception as error:  # noqa: BLE001 - fixture set-up failed
            results.record("setup", False, h.describe(error))
            return results.finish(args.report)
        try:
            if not args.negative_only:
                for profile, protocol, server, form in plan(args):
                    matrix.case(profile, protocol, server, form)
            if not args.skip_negative and "anytls-reality" in args.protocols:
                matrix.negative("v2" if args.states == "v2" else "v3")
        finally:
            matrix.close()
    return results.finish(args.report, mihomo="mihomo" in tools)


if __name__ == "__main__":
    sys.exit(main())
