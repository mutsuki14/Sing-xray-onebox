#!/usr/bin/env python3
"""Proxy-core configurations and the shared proxy-suite bench (not a suite).

* :func:`core_start` / :func:`core_check`: run sing-box, Xray or mihomo on
  a configuration after the core's own check;
* :func:`socks_client`: a client core with a loopback SOCKS5 inbound;
* :func:`rewrite_targets`: the test-only edit that sends the logical
  targets to the loopback fixtures, applied to the server under test only;
* :class:`Bench`: ports, PKI, marker fixtures, REALITY keys and the
  ``onebox render`` / core start helpers the proxy suites share.
"""
from __future__ import annotations

import unittest
from pathlib import Path

from _fixtures import MarkerFixtures, Pki, socks_http_marker, socks_udp_echo
from _harness import (LOOPBACK, VERBOSE, Ports, Process, Results, clean_env, run,
                      write_json)
from _node import (UDP_PROTOCOLS, FixtureNode, Inbound, Layout, onebox_json,
                   x25519_pair)

# ---------------------------------------------------------------------------
# Proxy cores (sing-box, Xray, mihomo)

CORES = ("singbox", "xray", "mihomo")


def core_check(kind: str, binary: str, path: Path, env) -> None:
    """The core's own configuration check (a failure raises CommandFailed)."""
    argv = {
        "singbox": [binary, "check", "-c", path],
        "xray": [binary, "run", "-test", "-c", path],
        "mihomo": [binary, "-t", "-d", path.parent, "-f", path],
    }[kind]
    run(argv, env=env)


def core_start(kind: str, binary: str, path: Path, env, name: str = "core") -> Process:
    """Check ``path`` and start the core in ``path.parent``.

    mihomo opens its listener before it has applied the configuration and
    closes early connections, and its "configuration complete" log only
    means parsing ended. Its ``-post-up`` hook runs after ApplyConfig
    returns, so the marker file it writes proves readiness without warming
    up or retrying proxy traffic (mihomo v1.19.32 main.go / hub/executor).
    """
    core_check(kind, binary, path, env)
    directory = path.parent
    if kind == "mihomo":
        ready = directory / "mihomo.ready"
        # Fixed shell command; cwd is this fixture directory.
        argv = [binary, "-d", directory, "-f", path, "-post-up", "printf ready > mihomo.ready"]
        process = Process(argv, directory, env, name)
        try:
            process.wait_file(ready, "ready")
        except BaseException:
            process.close()
            raise
        return process
    return Process([binary, "run", "-c", path], directory, env, name)


def set_log_level(kind: str, config: dict, level: str) -> None:
    if kind == "mihomo":
        config["log-level"] = level
    elif kind == "singbox":
        config.setdefault("log", {})["level"] = level
    else:
        config.setdefault("log", {})["loglevel"] = level


def socks_client(kind: str, port: int, outbounds: list[dict], *, udp_ip: bool = True) -> dict:
    """A client core with a loopback SOCKS5 inbound on ``port`` and only ``outbounds``.

    For mihomo ``outbounds`` are its ``proxies`` entries and every request
    goes to the first one. ``udp_ip`` sets Xray's UDP relay address.
    """
    first = outbounds[0]
    if kind == "singbox":
        return {"log": {"level": "warn"}, "dns": {"servers": [{"type": "local", "tag": "local"}]},
                "inbounds": [{"type": "socks", "listen": LOOPBACK, "listen_port": port}],
                "outbounds": outbounds,
                "route": {"final": first["tag"], "default_domain_resolver": "local"}}
    if kind == "xray":
        settings = {"udp": True, **({"ip": LOOPBACK} if udp_ip else {})}
        return {"log": {"loglevel": "warning"},
                "inbounds": [{"listen": LOOPBACK, "port": port, "protocol": "socks",
                              "settings": settings}],
                "outbounds": outbounds}
    return {"mixed-port": port, "bind-address": LOOPBACK, "allow-lan": False, "mode": "rule",
            "log-level": "warning", "ipv6": False, "dns": {"enable": False},
            "proxies": outbounds, "rules": ["MATCH," + first["name"]]}


# Logical targets of the relay checks. Only the server under test rewrites
# them to the loopback fixtures (rewrite_targets), so a direct connection
# can never satisfy a check.
TARGET_NAME = "native-e2e.invalid"
TARGET_IP = "192.0.2.53"


def rewrite_targets(kind: str, config: dict) -> None:
    """Make a rendered server send TARGET_NAME / TARGET_IP to loopback (test-only edit)."""
    if kind == "singbox":
        rewrite = [
            {"domain": [TARGET_NAME], "action": "route-options", "override_address": LOOPBACK},
            {"ip_cidr": [TARGET_IP + "/32"], "action": "route-options", "override_address": LOOPBACK},
        ]
        config["route"]["rules"] = rewrite + config["route"].get("rules", [])
        return
    config["outbounds"].append({"tag": "native-target", "protocol": "freedom", "settings": {
        "redirect": f"{LOOPBACK}:0", "finalRules": [{"action": "allow"}]}})
    config["routing"]["rules"] = [
        {"type": "field", "domain": ["full:" + TARGET_NAME], "outboundTag": "native-target"},
        {"type": "field", "ip": [TARGET_IP + "/32"], "outboundTag": "native-target"},
    ] + config["routing"].get("rules", [])


class Bench:
    """Fixtures shared by the proxy suites.

    ``tools`` maps ``onebox``/``singbox``/``xray``/``mihomo`` to executables
    (``xray`` is required: it generates the REALITY keys). Provides ports,
    the PKI (``reality.test`` leaf for the TLS fixture, CA-signed and
    self-signed ``onebox.test``), the marker servers, REALITY keys plus an
    unrelated public key for negative checks, and a base environment that
    trusts the test CA through ``SSL_CERT_FILE``.
    """

    def __init__(self, root: Path, tools: dict[str, str], results: Results,
                 marker_prefix: str = "onebox-e2e-"):
        self.root, self.tools, self.results = root, tools, results
        self.ports = Ports()
        self.pki = Pki(root / "pki")
        self.reality_cert = self.pki.leaf("reality.test")
        self.ca_cert = self.pki.leaf("onebox.test")
        self.self_cert = self.pki.self_signed("onebox.test")
        self.fixture = MarkerFixtures(self.ports, self.reality_cert, prefix=marker_prefix)
        try:
            self.base_env = clean_env(SSL_CERT_FILE=str(self.pki.bundle))
            self.keys = x25519_pair(tools["xray"], self.base_env)
            self.wrong_public = x25519_pair(tools["xray"], self.base_env)[1]
        except BaseException:
            self.fixture.close()
            raise

    def close(self) -> None:
        self.fixture.close()

    def node(self, protocols: list[tuple[str, str]], *, custom_ca: bool = False,
             **overrides) -> FixtureNode:
        """A node with fresh ports for ``(protocol, core)`` pairs.

        ``custom_ca`` selects the CA-signed custom certificate (not pinned,
        VMess over TLS, Hysteria2 obfuscation) instead of the self-signed one.
        REALITY and ShadowTLS hand shakes go to the TLS marker fixture.
        """
        cert = self.ca_cert if custom_ca else self.self_cert
        settings = {
            "inbounds": [Inbound(p, self.ports.get(), core) for p, core in protocols],
            "reality_keys": self.keys, "reality_dest": f"{LOOPBACK}:{self.fixture.tls_port}",
            "guard_port": self.ports.get(), "proxy_cert": cert,
            "tls_mode": "custom" if custom_ca else "self",
            "custom_source": cert if custom_ca else None, "pinned": not custom_ca,
            "vmess_tls": custom_ca, "hy2_obfs": custom_ca,
        }
        settings.update(overrides)
        return FixtureNode(**settings)

    def layout(self, directory: Path) -> Layout:
        """A fresh case directory with an isolated layout in ``<directory>/root``."""
        directory.mkdir(parents=True)
        return Layout(directory / "root", self.base_env)

    def onebox(self, env, *args, quiet: bool = False):
        """``onebox ARGS`` parsed as JSON (``quiet``: nothing may go to stderr)."""
        return onebox_json(self.tools["onebox"], env, *args, quiet=quiet)

    def outbound(self, env, protocol: str, core: str) -> dict:
        return self.onebox(env, "render", "outbound", protocol, core, quiet=True)

    def server_config(self, env, kind: str) -> dict:
        """``render server`` with :func:`rewrite_targets` and an informative log level."""
        config = self.onebox(env, "render", "server", kind, quiet=True)
        # Keep fixture connection diagnostics in the log for failure reports.
        set_log_level(kind, config, "debug" if VERBOSE else "info")
        rewrite_targets(kind, config)
        return config

    def target_tcp(self, proxy_port: int, timeout: float = 10) -> None:
        """HTTP marker from TARGET_NAME through the SOCKS proxy on ``proxy_port``.

        Xray's REALITY library samples post-handshake target records for five
        seconds on cold start, then polls that cache every five seconds; a
        five-second deadline races it. Hence a ten-second single attempt,
        without warming up or retrying.
        https://github.com/XTLS/REALITY/blob/9234c772ba8f/record_detect.go
        """
        socks_http_marker(proxy_port, TARGET_NAME, self.fixture.http_port, self.fixture.marker,
                          timeout)

    def target_udp(self, proxy_port: int) -> None:
        """UDP echo from TARGET_IP through the SOCKS proxy on ``proxy_port``."""
        socks_udp_echo(proxy_port, TARGET_IP, self.fixture.udp_port, self.fixture.marker)

    def start(self, kind: str, directory: Path, config: dict, env, name: str) -> Process:
        """Write ``config`` to ``<directory>/<name>.json``, check it and start the core."""
        directory.mkdir(parents=True, exist_ok=True)
        if VERBOSE:
            set_log_level(kind, config, "debug")
        path = directory / f"{name}.json"
        write_json(path, config)
        return core_start(kind, self.tools[kind], path, env, name)

    def start_server(self, kind: str, directory: Path, config: dict, env,
                     node: FixtureNode) -> Process:
        """:meth:`start` a server core and wait for the node's first TCP listener
        (a UDP-only node: the core must survive 0.2 s)."""
        process = self.start(kind, directory, config, env, "server")
        try:
            tcp = [i for i in node.inbounds if i.protocol not in UDP_PROTOCOLS]
            if tcp:
                process.wait_tcp(tcp[0].port)
            else:
                process.stay_alive(0.2)
            return process
        except BaseException:
            process.close()
            raise

    def start_client(self, kind: str, directory: Path, config: dict, env, port: int) -> Process:
        """:meth:`start` a client core and wait for its SOCKS listener ``port``."""
        process = self.start(kind, directory, config, env, "client")
        try:
            process.wait_tcp(port)
            return process
        except BaseException:
            process.close()
            raise


# ---------------------------------------------------------------------------
# Self-tests (python3 tests/e2e/_selftest.py)


class CoreConfigTests(unittest.TestCase):
    def test_rewrite_targets(self):
        singbox = {"route": {"rules": [{"action": "sniff"}]}}
        rewrite_targets("singbox", singbox)
        self.assertEqual([r.get("action") for r in singbox["route"]["rules"]],
                         ["route-options", "route-options", "sniff"])
        xray = {"outbounds": [{"tag": "direct"}], "routing": {"rules": [{"outboundTag": "block"}]}}
        rewrite_targets("xray", xray)
        self.assertEqual(xray["outbounds"][-1]["tag"], "native-target")
        self.assertEqual([r["outboundTag"] for r in xray["routing"]["rules"]],
                         ["native-target", "native-target", "block"])

    def test_socks_clients_use_the_first_outbound(self):
        outbounds = [{"tag": "a", "name": "a"}, {"tag": "b", "name": "b"}]
        self.assertEqual(socks_client("singbox", 1, outbounds)["route"]["final"], "a")
        self.assertEqual(socks_client("mihomo", 1, outbounds)["rules"], ["MATCH,a"])
        xray = socks_client("xray", 1, outbounds, udp_ip=False)
        self.assertEqual(xray["inbounds"][0]["settings"], {"udp": True})

    def test_log_levels(self):
        configs = {kind: {} for kind in ("singbox", "xray", "mihomo")}
        for kind, config in configs.items():
            set_log_level(kind, config, "info")
        self.assertEqual(configs, {"singbox": {"log": {"level": "info"}},
                                   "xray": {"log": {"loglevel": "info"}},
                                   "mihomo": {"log-level": "info"}})


if __name__ == "__main__":
    unittest.main()
