#!/usr/bin/env python3
"""The isolated Onebox layout and node fixtures of the black-box suites (not a suite).

* :class:`Layout` and :func:`run_onebox`: an isolated Onebox directory
  layout (every path variable points inside it) holding a v2
  ``{"values": …}`` or v3 schema-3 ``state.json`` and the proxy certificate
  at ``<ONEBOX_DIR>/tls/{cert,key}.pem``. Constructing a layout touches
  nothing on disk, so a suite can assert that a command did not create
  ``ONEBOX_DIR``;
* :class:`FixtureNode`: one loopback node, writable in both state shapes,
  plus the protocol tables the suites plan their cases with.
"""
from __future__ import annotations

import base64
import dataclasses
import json
import secrets
import shutil
import stat
import tempfile
import unittest
import unittest.mock
import uuid
from pathlib import Path

from _fixtures import CertPair
from _harness import LOOPBACK, Completed, clean_env, run, write_json
from _yaml import YamlError, load_yaml

# ---------------------------------------------------------------------------
# Onebox layout


# Every Onebox path variable (src/paths.rs) except ONEBOX_SYSTEM_ROOT, which
# would hide the real /proc and /sys; suites that need it pass it in `extra`.
PATH_VARIABLES = {
    "ONEBOX_DIR": "etc/onebox",
    "ONEBOX_BIN_DIR": "opt/onebox/bin",
    "ONEBOX_LOG_DIR": "var/log/onebox",
    "ONEBOX_RUN_DIR": "run/onebox",
    "ONEBOX_SITE_ROOT": "var/lib/onebox-site",
    "ONEBOX_SYSTEMD_DIR": "etc/systemd/system",
    "ONEBOX_INITD_DIR": "etc/init.d",
    "ONEBOX_EXE": "usr/local/bin/onebox",
    "ONEBOX_FRPS_DIR": "etc/onebox-frp",
    "ONEBOX_FRPS_BIN_DIR": "opt/onebox-frp",
    "ONEBOX_FRPS_WEB_VAR": "var/lib/onebox-frp",
    "ONEBOX_FRPS_LOG_DIR": "var/log/onebox-frp",
    "ONEBOX_FRPS_RUN_DIR": "run/onebox-frp",
    "ONEBOX_BBR_DIR": "var/lib/onebox-bbr",
    "ONEBOX_BBR_CONF": "etc/sysctl.d/99-onebox-bbr.conf",
}


class Layout:
    """An isolated Onebox installation layout under ``root``.

    Nothing is created up front: the program creates its directories, and
    the fixture writers create ``ONEBOX_DIR`` (and its ``tls`` directory)
    when they first write into it.
    """

    def __init__(self, root: Path, base_env: dict[str, str] | None = None):
        self.root = root
        self.paths = {name: root / rel for name, rel in PATH_VARIABLES.items()}
        self.etc = self.paths["ONEBOX_DIR"]
        self.tls = self.etc / "tls"
        self.state_path = self.etc / "state.json"
        self.base_env = dict(base_env) if base_env is not None else clean_env()

    def env(self, **extra: str) -> dict[str, str]:
        env = dict(self.base_env)
        env.update({name: str(path) for name, path in self.paths.items()})
        env.update(extra)
        return env

    def install_proxy_cert(self, pair: CertPair) -> CertPair:
        """Deploy ``pair`` where Onebox keeps the proxy certificate."""
        self.tls.mkdir(parents=True, exist_ok=True, mode=0o700)
        deployed = CertPair(self.tls / "cert.pem", self.tls / "key.pem")
        shutil.copyfile(pair.cert, deployed.cert)
        shutil.copyfile(pair.key, deployed.key)
        deployed.cert.chmod(0o644)
        deployed.key.chmod(0o600)
        return deployed

    def write_v2_state(self, values: dict[str, str]) -> None:
        """A v2 ``{"values": {KEY: "string"}}`` state (migrated by every command)."""
        if any(not isinstance(v, str) for v in values.values()):
            raise TypeError("v2 state values must be strings")
        self._write_state({"values": values})

    def write_state(self, config: dict) -> None:
        """A v3 schema-3 ``state.json``."""
        if config.get("schema") != 3:
            raise ValueError("v3 state needs schema 3")
        self._write_state(config)

    def _write_state(self, document: dict) -> None:
        self.etc.mkdir(parents=True, exist_ok=True, mode=0o700)
        write_json(self.state_path, document)

    def read_state(self) -> dict:
        return json.loads(self.state_path.read_text())


def run_onebox(binary: str, env: dict[str, str], *args: str, check: bool = True,
               timeout: float = 30, input: bytes | None = None) -> Completed:
    """Run ``onebox ARGS`` with ``env`` (normally :meth:`Layout.env`)."""
    return run([binary, *args], env=env, check=check, timeout=timeout, input=input)


def _quiet_stdout(binary: str, env: dict[str, str], args, quiet: bool) -> str:
    done = run_onebox(binary, env, *args)
    if quiet and done.stderr:
        # A render of a valid fixture has nothing to say; for a v2 state
        # this catches lossy migrations, which only warn.
        raise AssertionError(f"onebox {' '.join(args)}: unexpected stderr: {done.stderr[-2000:]}")
    return done.stdout


def onebox_json(binary: str, env: dict[str, str], *args: str, quiet: bool = False):
    """Run ``onebox ARGS`` and parse its stdout as JSON.

    ``quiet``: the command must also print nothing on stderr.
    """
    out = _quiet_stdout(binary, env, args, quiet)
    try:
        return json.loads(out)
    except ValueError as error:
        raise AssertionError(f"onebox {' '.join(args)}: stdout is not JSON: {error}") from error


def onebox_yaml(binary: str, env: dict[str, str], *args: str, quiet: bool = False):
    """Run ``onebox ARGS`` and parse its stdout with :func:`load_yaml`."""
    out = _quiet_stdout(binary, env, args, quiet)
    try:
        return load_yaml(out)
    except YamlError as error:
        raise AssertionError(f"onebox {' '.join(args)}: stdout is not the expected YAML: {error}") from error


def x25519_pair(xray: str, env=None) -> tuple[str, str]:
    """(private, public) REALITY keys from ``xray x25519`` (old and new label styles)."""
    text = run([xray, "x25519"], env=env).stdout
    pairs = {name.strip().lower(): value.strip()
             for name, value in (line.split(":", 1) for line in text.splitlines() if ":" in line)}
    private = next((v for k, v in pairs.items() if "private" in k), None)
    public = next((v for k, v in pairs.items() if "public" in k), None)
    if not private or not public:
        raise AssertionError(f"unexpected xray x25519 output: {text!r}")
    return private, public


def random_ss_key(size: int = 16) -> str:
    """Base64 key for Shadowsocks 2022 / ShadowTLS (``size`` bytes)."""
    return base64.b64encode(secrets.token_bytes(size)).decode()


# ---------------------------------------------------------------------------
# Node fixtures (v2 and v3 state of the same node)

PROTOCOLS = (
    "vless-reality", "vless-xhttp", "vless-grpc", "vless-ws", "vmess-ws",
    "trojan", "shadowsocks", "hysteria2", "tuic", "anytls", "shadowtls",
    "anytls-reality",
)
SINGBOX_ONLY = frozenset({"tuic", "anytls", "shadowtls", "anytls-reality"})
# Protocols that always need the proxy certificate; VMess-WS needs it only
# with VMess TLS (src/domain/protocol.rs capability table).
CERTIFICATE_PROTOCOLS = frozenset({"vless-ws", "trojan", "hysteria2", "tuic", "anytls"})
REALITY_PROTOCOLS = frozenset({"vless-reality", "vless-grpc", "vless-xhttp", "anytls-reality"})
UDP_PROTOCOLS = frozenset({"hysteria2", "tuic"})
STATE_FORMS = ("v2", "v3")


def core_supports(core: str, protocol: str) -> bool:
    """Server-core support (spec A §2.3): Xray lacks four, sing-box lacks XHTTP."""
    return protocol != "vless-xhttp" if core == "singbox" else protocol not in SINGBOX_ONLY


def transport_of(protocol: str) -> str:
    """Probe-bundle transport of a protocol."""
    if protocol in UDP_PROTOCOLS:
        return "udp"
    return "both" if protocol == "shadowsocks" else "tcp"


@dataclasses.dataclass
class Inbound:
    protocol: str
    port: int
    core: str


@dataclasses.dataclass
class FixtureNode:
    """One loopback node, writable as a v2 ``{"values"}`` or v3 schema-3 state.

    Both forms describe the same node, so v3 must render them identically
    (the v2 form goes through the real migration on every command).
    ``proxy_cert`` is deployed to ``<ONEBOX_DIR>/tls``; ``custom_source`` is
    the import source recorded for a custom certificate.
    """

    inbounds: list[Inbound]
    reality_keys: tuple[str, str]
    reality_dest: str
    guard_port: int
    proxy_cert: CertPair
    tls_mode: str = "self"                 # "self" | "custom"
    custom_source: CertPair | None = None
    pinned: bool = True
    vmess_tls: bool = False
    hy2_obfs: bool = False
    block_private: bool = False
    block_bt: bool = True
    own_cidrs: list[str] = dataclasses.field(default_factory=list)
    reality_sni: str = "reality.test"
    shadowtls_sni: str = "reality.test"
    shadowtls_dest: str | None = None      # None: same as reality_dest
    tls_name: str = "onebox.test"
    node_name: str = "native-e2e"
    address: str = LOOPBACK
    paths: dict[str, str] = dataclasses.field(default_factory=lambda: {
        "ws": "/native-ws", "vmess": "/native-vmess", "xhttp": "/native-xhttp", "grpc": "native-grpc"})
    creds: dict[str, str] = dataclasses.field(default_factory=lambda: {
        "uuid": str(uuid.uuid4()),
        "password": secrets.token_hex(24),
        "ss_password": random_ss_key(),
        "shadowtls_password": secrets.token_hex(24),
        "shadowtls_ss_password": random_ss_key(),
        "hy2_obfs_password": secrets.token_hex(24),
        "clash_secret": secrets.token_hex(16),
        "short_id": secrets.token_hex(8),
    })

    def protocols(self) -> list[str]:
        return [inbound.protocol for inbound in self.inbounds]

    def inbound(self, protocol: str) -> Inbound:
        return next(i for i in self.inbounds if i.protocol == protocol)

    def needs_cert(self) -> bool:
        protocols = self.protocols()
        return (any(p in CERTIFICATE_PROTOCOLS for p in protocols)
                or ("vmess-ws" in protocols and self.vmess_tls))

    def hy2_profile(self) -> str | None:
        # Xray cannot apply Hysteria2 tuning: v3 rejects it, v2 ignored it.
        hy2 = [i for i in self.inbounds if i.protocol == "hysteria2"]
        return "auto" if hy2 and hy2[0].core == "singbox" else None

    def write(self, layout: Layout, form: str) -> None:
        """Deploy the certificate and write ``state.json`` in ``form`` (v2|v3)."""
        layout.install_proxy_cert(self.proxy_cert)
        if form == "v2":
            layout.write_v2_state(self.v2_values(layout))
        elif form == "v3":
            layout.write_state(self.v3_config())
        else:
            raise ValueError(f"unknown state form {form!r}")

    def v2_values(self, layout: Layout) -> dict[str, str]:
        """The keys a v2.0.1 install writes (spec A §3.4), all strings."""
        def flag(value: bool) -> str:
            return "1" if value else "0"

        private, public = self.reality_keys
        c, p = self.creds, self.paths
        values = {
            "PROTOCOLS": " ".join(self.protocols()), "SERVER_ADDR": self.address,
            "SERVER_IPV4": self.address, "SERVER_IPV6": "", "LISTEN_ADDR": self.address,
            "NODE_NAME": self.node_name, "UUID": c["uuid"], "PASSWORD": c["password"],
            "SS_METHOD": "2022-blake3-aes-128-gcm", "SS_PASSWORD": c["ss_password"],
            "SHADOWTLS_PASSWORD": c["shadowtls_password"],
            "SHADOWTLS_SS_PASSWORD": c["shadowtls_ss_password"], "CLASH_SECRET": c["clash_secret"],
            "REALITY_PRIVATE_KEY": private, "REALITY_PUBLIC_KEY": public,
            "REALITY_SHORT_ID": c["short_id"], "REALITY_SNI": self.reality_sni,
            "REALITY_DEST": self.reality_dest, "SHADOWTLS_SNI": self.shadowtls_sni,
            "SHADOWTLS_DEST": self.shadowtls_dest or self.reality_dest,
            "REALITY_GUARD_PORT": str(self.guard_port), "REALITY_SITE_ENABLED": "0",
            "REALITY_SITE_HTTPS": "0", "WS_PATH": p["ws"], "VMESS_PATH": p["vmess"],
            "XHTTP_PATH": p["xhttp"], "GRPC_SERVICE": p["grpc"],
            "VMESS_TLS": flag(self.vmess_tls), "HY2_OBFS": flag(self.hy2_obfs),
            "HY2_OBFS_PASSWORD": c["hy2_obfs_password"], "HY2_PROFILE": self.hy2_profile() or "",
            "RESOURCE_PROFILE": "balanced", "TLS_MODE": self.tls_mode, "TLS_SNI": self.tls_name,
            "DOMAIN": self.tls_name, "CERT_PINNED": flag(self.pinned),
            "CERT_FILE": str(layout.tls / "cert.pem"), "KEY_FILE": str(layout.tls / "key.pem"),
            "BLOCK_PRIVATE": flag(self.block_private), "BLOCK_BT": flag(self.block_bt),
        }
        if self.own_cidrs:
            values["OWN_IP_CIDRS"] = json.dumps(self.own_cidrs)
        if self.tls_mode == "custom" and self.custom_source:
            values["CUSTOM_CERT"] = str(self.custom_source.cert)
            values["CUSTOM_KEY"] = str(self.custom_source.key)
        for inbound in self.inbounds:
            key = inbound.protocol.replace("-", "_")
            values[f"PORT_{key}"] = str(inbound.port)
            values[f"CORE_{key}"] = inbound.core
        return values

    def v3_tls(self) -> dict | None:
        if not self.needs_cert():
            return None
        if self.tls_mode == "self":
            return {"mode": {"type": "self-signed", "sni": self.tls_name}, "pinned": True}
        source = self.custom_source or self.proxy_cert
        return {"mode": {"type": "custom", "domain": self.tls_name, "cert": str(source.cert),
                         "key": str(source.key)}, "pinned": self.pinned}

    def v3_config(self) -> dict:
        """The same node as a schema-3 ``NodeConfig`` (src/domain/config.rs)."""
        private, public = self.reality_keys
        c, p = self.creds, self.paths
        protocols = self.protocols()
        reality = any(proto in REALITY_PROTOCOLS for proto in protocols)
        return {
            "schema": 3, "node_name": self.node_name,
            "server": {"addr": self.address, "ipv4": self.address, "ipv6": None,
                       "ipv4_warp": False, "ipv6_warp": False},
            "listen": self.address,
            "inbounds": [dataclasses.asdict(inbound) for inbound in self.inbounds],
            "creds": {
                "uuid": c["uuid"], "password": c["password"],
                "ss_method": "2022-blake3-aes-128-gcm", "ss_password": c["ss_password"],
                "hy2_obfs_password": c["hy2_obfs_password"],
                "shadowtls_password": c["shadowtls_password"],
                "shadowtls_ss_password": c["shadowtls_ss_password"],
                "clash_secret": c["clash_secret"],
                "reality": ({"private_key": private, "public_key": public,
                             "short_id": c["short_id"]} if reality else None),
                "ws_path": p["ws"], "vmess_path": p["vmess"], "xhttp_path": p["xhttp"],
                "grpc_service": p["grpc"],
            },
            "reality": {"sni": self.reality_sni, "dest": self.reality_dest,
                        "guard_port": self.guard_port},
            "shadowtls": {"sni": self.shadowtls_sni,
                          "dest": self.shadowtls_dest or self.reality_dest},
            "site": None,
            "tls": self.v3_tls(),
            "vmess_tls": self.vmess_tls and "vmess-ws" in protocols,
            # v2's DOMAIN is the Host header of plain VMess-WS clients.
            "vmess_host": self.tls_name if "vmess-ws" in protocols else None,
            "hy2": {"obfs": self.hy2_obfs, "hop": None, "profile": self.hy2_profile(),
                    "up_mbps": None, "down_mbps": None},
            "resource_profile": "balanced",
            "routing": {"block_private": self.block_private, "block_bt": self.block_bt,
                        "own_cidrs": list(self.own_cidrs)},
            "subscription": None,
            "versions": {},
            "installed_at": 0,
        }



# ---------------------------------------------------------------------------
# Self-tests (python3 tests/e2e/_selftest.py)


class LayoutTests(unittest.TestCase):
    def test_construction_touches_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "root"
            layout = Layout(root, {"PATH": "/bin"})
            self.assertFalse(root.exists())
            env = layout.env(EXTRA="1")
            self.assertEqual(env["ONEBOX_DIR"], str(root / "etc/onebox"))
            self.assertEqual((env["PATH"], env["EXTRA"]), ("/bin", "1"))
            self.assertFalse(root.exists())

    def test_writers_create_private_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            source = CertPair(Path(directory) / "c.pem", Path(directory) / "k.pem")
            source.cert.write_text("cert")
            source.key.write_text("key")
            layout = Layout(Path(directory) / "root", {})
            deployed = layout.install_proxy_cert(source)
            self.assertEqual(stat.S_IMODE(layout.tls.stat().st_mode), 0o700)
            self.assertEqual((stat.S_IMODE(deployed.cert.stat().st_mode),
                              stat.S_IMODE(deployed.key.stat().st_mode)), (0o644, 0o600))
            other = Layout(Path(directory) / "other", {})
            other.write_v2_state({"PROTOCOLS": "trojan"})
            self.assertEqual(other.read_state(), {"values": {"PROTOCOLS": "trojan"}})
            self.assertFalse(other.tls.exists())
            with self.assertRaises(TypeError):
                other.write_v2_state({"PORT_trojan": 443})
            with self.assertRaises(ValueError):
                other.write_state({"schema": 2})


class FixtureNodeTests(unittest.TestCase):
    PAIR = CertPair(Path("/pki/c.pem"), Path("/pki/k.pem"))

    def node(self, inbounds, **overrides):
        return FixtureNode(inbounds=[Inbound(p, 20000 + i, c) for i, (p, c) in enumerate(inbounds)],
                           reality_keys=("priv", "pub"), reality_dest="127.0.0.1:1",
                           guard_port=2, proxy_cert=self.PAIR, **overrides)

    def test_certificate_and_tuning_rules(self):
        cases = [
            ([("vmess-ws", "xray")], {}, False, None),
            ([("vmess-ws", "xray")], {"vmess_tls": True}, True, None),
            ([("hysteria2", "xray")], {}, True, None),
            ([("hysteria2", "singbox")], {}, True, "auto"),
            ([("vless-reality", "xray")], {}, False, None),
        ]
        for inbounds, overrides, cert, profile in cases:
            with self.subTest(inbounds=inbounds, overrides=overrides):
                node = self.node(inbounds, **overrides)
                self.assertEqual(node.needs_cert(), cert)
                self.assertEqual(node.hy2_profile(), profile)
                config = node.v3_config()
                self.assertEqual(config["tls"] is not None, cert)
                self.assertEqual(config["hy2"]["profile"], profile)

    def test_v3_shape(self):
        node = self.node([("vless-reality", "xray"), ("vless-xhttp", "xray")],
                         own_cidrs=["9.9.9.9/32"], block_private=True)
        config = node.v3_config()
        self.assertEqual(config["schema"], 3)
        self.assertEqual(config["inbounds"][1], {"protocol": "vless-xhttp", "port": 20001, "core": "xray"})
        self.assertEqual(config["creds"]["reality"]["public_key"], "pub")
        self.assertEqual(config["routing"], {"block_private": True, "block_bt": True,
                                             "own_cidrs": ["9.9.9.9/32"]})
        self.assertIsNone(self.node([("trojan", "xray")]).v3_config()["creds"]["reality"])
        custom = self.node([("trojan", "xray")], tls_mode="custom", custom_source=self.PAIR,
                           pinned=False).v3_config()["tls"]
        self.assertEqual(custom, {"mode": {"type": "custom", "domain": "onebox.test",
                                           "cert": "/pki/c.pem", "key": "/pki/k.pem"},
                                  "pinned": False})

    def test_v2_shape(self):
        layout = unittest.mock.Mock(tls=Path("/r/tls"))
        node = self.node([("shadowsocks", "singbox"), ("vless-reality", "xray")],
                         own_cidrs=["9.9.9.9/32"])
        values = node.v2_values(layout)
        self.assertTrue(all(isinstance(v, str) for v in values.values()))
        self.assertEqual(values["PROTOCOLS"], "shadowsocks vless-reality")
        self.assertEqual((values["PORT_vless_reality"], values["CORE_vless_reality"]), ("20001", "xray"))
        self.assertEqual(values["CERT_FILE"], "/r/tls/cert.pem")
        self.assertEqual(values["OWN_IP_CIDRS"], '["9.9.9.9/32"]')
        self.assertEqual((values["BLOCK_PRIVATE"], values["BLOCK_BT"]), ("0", "1"))
        self.assertNotIn("CUSTOM_CERT", values)


if __name__ == "__main__":
    unittest.main()
