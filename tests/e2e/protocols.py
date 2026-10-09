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
from pathlib import Path
import sys

import _harness as h

TARGET_NAME = "native-e2e.invalid"
TARGET_IP = "192.0.2.53"
SERVERS = ("singbox", "xray")
CLIENTS = ("singbox", "xray", "mihomo")


@dataclasses.dataclass(frozen=True)
class Profile:
    name: str
    protocols: frozenset[str]
    custom_ca: bool         # CA-signed custom certificate instead of self-signed

    @property
    def vmess_tls(self) -> bool:
        return self.custom_ca


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


class Matrix:
    def __init__(self, root: Path, tools: dict[str, str], args, results: h.Results):
        self.root, self.tools, self.args, self.results = root, tools, args, results
        self.ports = h.Ports()
        self.pki = h.Pki(root / "pki")
        self.reality_cert = self.pki.leaf("reality.test")
        self.ca_cert = self.pki.leaf("onebox.test")
        self.self_cert = self.pki.self_signed("onebox.test")
        self.fixture = h.MarkerFixtures(self.ports, self.reality_cert, prefix="onebox-native-")
        self.base_env = h.clean_env(SSL_CERT_FILE=str(self.pki.bundle))
        self.keys = h.x25519_pair(tools["xray"], self.base_env)
        self.wrong_public = h.x25519_pair(tools["xray"], self.base_env)[1]

    def close(self):
        self.fixture.close()

    # -- fixtures -----------------------------------------------------------

    def node(self, protocols: list[tuple[str, str]], profile: Profile) -> h.FixtureNode:
        """A node with fresh ports and credentials for ``(protocol, core)`` pairs."""
        cert = self.ca_cert if profile.custom_ca else self.self_cert
        return h.FixtureNode(
            inbounds=[h.Inbound(p, self.ports.get(), core) for p, core in protocols],
            reality_keys=self.keys,
            reality_dest=f"{h.LOOPBACK}:{self.fixture.tls_port}",
            guard_port=self.ports.get(),
            proxy_cert=cert,
            tls_mode="custom" if profile.custom_ca else "self",
            custom_source=cert if profile.custom_ca else None,
            pinned=not profile.custom_ca,
            vmess_tls=profile.vmess_tls,
            hy2_obfs=profile.custom_ca,
        )

    def layout(self, directory: Path) -> h.Layout:
        directory.mkdir(parents=True)
        return h.Layout(directory / "root", self.base_env)

    def onebox(self, env, *args):
        return h.onebox_json(self.tools["onebox"], env, *args)

    # -- server ---------------------------------------------------------------

    def server_config(self, env, server: str) -> dict:
        """``render server`` plus the test-only target rewrites."""
        config = self.onebox(env, "render", "server", server)
        # Keep fixture connection diagnostics in the log for failure reports.
        h.set_log_level(server, config, "debug" if h.VERBOSE else "info")
        if server == "singbox":
            rewrite = [
                {"domain": [TARGET_NAME], "action": "route-options", "override_address": h.LOOPBACK},
                {"ip_cidr": [TARGET_IP + "/32"], "action": "route-options",
                 "override_address": h.LOOPBACK},
            ]
            config["route"]["rules"] = rewrite + config["route"].get("rules", [])
        else:
            config["outbounds"].append({"tag": "native-target", "protocol": "freedom", "settings": {
                "redirect": f"{h.LOOPBACK}:0", "finalRules": [{"action": "allow"}]}})
            config["routing"]["rules"] = [
                {"type": "field", "domain": ["full:" + TARGET_NAME], "outboundTag": "native-target"},
                {"type": "field", "ip": [TARGET_IP + "/32"], "outboundTag": "native-target"},
            ] + config["routing"].get("rules", [])
        return config

    def start_server(self, directory: Path, node: h.FixtureNode, server: str, env) -> h.Process:
        path = directory / "server.json"
        h.write_json(path, self.server_config(env, server))
        process = h.core_start(server, self.tools[server], path, env, "server")
        try:
            tcp = [i for i in node.inbounds if i.protocol not in h.UDP_PROTOCOLS]
            if tcp:
                process.wait_tcp(tcp[0].port)
            else:
                process.stay_alive(0.2)
            return process
        except BaseException:
            process.close()
            raise

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
        outbound = self.onebox(env, "render", "outbound", protocol, client)
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

    def start_client(self, directory: Path, client: str, config: dict, env) -> h.Process:
        directory.mkdir()
        if h.VERBOSE:
            h.set_log_level(client, config, "debug")
        path = directory / "client.json"
        h.write_json(path, config)
        return h.core_start(client, self.tools[client], path, env, "client")

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
        node = self.node([(protocol, server)], profile)
        node.write(layout, form)
        env = layout.env()
        if not self.results.attempt(f"{name}/probe[{form}]", lambda: self.check_probe(env, protocol)):
            return
        if form == "v3":
            self.results.attempt(f"{name}/v3-matches-v2",
                                 lambda: self.check_v2_parity(layout, node, server))
        try:
            with self.start_server(directory, node, server, env) as process:
                for client in self.args.clients:
                    if client in self.tools and client_supports(client, protocol):
                        self.client_checks(name, directory, protocol, client, process, env)
        except Exception as error:  # noqa: BLE001 - recorded as this case's failure
            self.results.record(f"{name}/server", False, h.describe(error))

    def client_checks(self, name, directory, protocol, client, server, env) -> None:
        port = self.ports.get()
        try:
            config = h.socks_client(client, port, self.client_outbounds(env, protocol, client))
            with self.start_client(directory / client, client, config, env) as native:
                native.wait_tcp(port)
                for transport, request in (("tcp", self.tcp_marker), ("udp", self.udp_marker)):
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

    def tcp_marker(self, port: int, timeout: float = 10) -> None:
        # Xray's REALITY library samples post-handshake target records for
        # five seconds on cold start, then polls that cache every five
        # seconds; a five-second deadline races it. Keep the ten-second
        # single-attempt budget, without warming up or retrying.
        # https://github.com/XTLS/REALITY/blob/9234c772ba8f/record_detect.go
        h.socks_http_marker(port, TARGET_NAME, self.fixture.http_port, self.fixture.marker, timeout)

    def udp_marker(self, port: int) -> None:
        h.socks_udp_echo(port, TARGET_IP, self.fixture.udp_port, self.fixture.marker)

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
        node = self.node([(protocol, "singbox")], PROFILES["self"])
        node.write(layout, form)
        env = layout.env()
        try:
            with self.start_server(directory, node, "singbox", env) as server:
                for mode in self.NEGATIVE_MODES:
                    self.negative_mode(directory, mode, node, server, env)
                for client in ("xray", "mihomo"):
                    result = h.run_onebox(self.tools["onebox"], env, "client", client, check=False)
                    self.results.record(f"authentication/reject-{client}-export",
                                        result.code != 0 and not result.stdout,
                                        f"exit {result.code}, stdout {result.stdout[:200]!r}")
        except Exception as error:  # noqa: BLE001
            self.results.record("authentication/server", False, h.describe(error))

    def negative_mode(self, directory, mode, node, server, env) -> None:
        port = self.ports.get()
        try:
            outbounds = self.client_outbounds(env, "anytls-reality", "singbox")
            self.tamper(outbounds[0], mode, node)
            config = h.socks_client("singbox", port, outbounds)
            with self.start_client(directory / mode, "singbox", config, env) as client:
                client.wait_tcp(port)
                ok, _ = h.reached(lambda: self.tcp_marker(port, timeout=3))
                assert client.alive() and server.alive(), "rejection was caused by a core crash"
                assert ok == mode.startswith("positive"), \
                    "reached the target" if ok else "did not reach the target"
                self.results.record(f"authentication/{mode}", True)
        except Exception as error:  # noqa: BLE001
            self.results.record(f"authentication/{mode}", False, h.describe(error))


def comma_list(allowed):
    def parse(text: str) -> list[str]:
        values = [v for v in text.split(",") if v]
        if not values or any(v not in allowed for v in values):
            raise argparse.ArgumentTypeError(f"choose from {','.join(allowed)}")
        return values
    return parse


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--protocols", type=comma_list(h.PROTOCOLS), default=list(h.PROTOCOLS))
    parser.add_argument("--servers", type=comma_list(SERVERS), default=list(SERVERS))
    parser.add_argument("--clients", type=comma_list(CLIENTS), default=list(CLIENTS))
    parser.add_argument("--profiles", type=comma_list(tuple(PROFILES)), default=list(PROFILES))
    parser.add_argument("--states", choices=("mixed", *h.STATE_FORMS), default="mixed")
    parser.add_argument("--negative-only", action="store_true")
    parser.add_argument("--skip-negative", action="store_true")
    parser.add_argument("--report", type=Path)
    return parser.parse_args(argv)


def resolve_tools(args, results: h.Results) -> dict[str, str] | None:
    """Required: onebox, sing-box, Xray. mihomo is optional unless REQUIRE_FULL."""
    tools = {}
    try:
        tools["onebox"] = h.onebox_binary()
        tools["singbox"] = h.tool("ONEBOX_TEST_SINGBOX", path_names=("sing-box",))
        tools["xray"] = h.tool("ONEBOX_TEST_XRAY", path_names=("xray",))
    except h.Unavailable as error:
        results.record("prerequisites", False, str(error))
        return None
    if "mihomo" in args.clients:
        try:
            tools["mihomo"] = h.tool("ONEBOX_TEST_MIHOMO", path_names=("mihomo",))
        except h.Unavailable as error:
            results.skip("mihomo-client", str(error))
    return tools


def main(argv=None) -> int:
    args = parse_args(argv)
    results = h.Results("Protocol E2E")
    tools = resolve_tools(args, results)
    if tools is None:
        return results.finish(args.report)
    with h.Workspace("onebox-e2e-protocols-") as root:
        matrix = Matrix(root, tools, args, results)
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
