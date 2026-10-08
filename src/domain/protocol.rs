//! Protocols, cores, transports and client formats with one capability table.
//!
//! The protocol order, ids and titles are a compatibility contract: menu
//! numbers and `--protocols` ids are the same as in v1/v2.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Core {
    #[serde(rename = "singbox")]
    Singbox,
    #[serde(rename = "xray")]
    Xray,
}

impl Core {
    pub const ALL: [Core; 2] = [Core::Singbox, Core::Xray];

    /// Identifier used in state, CLI and display.
    pub fn id(self) -> &'static str {
        match self {
            Core::Singbox => "singbox",
            Core::Xray => "xray",
        }
    }
    /// Binary and config file stem.
    pub fn binary(self) -> &'static str {
        match self {
            Core::Singbox => "sing-box",
            Core::Xray => "xray",
        }
    }
    pub fn service(self) -> &'static str {
        match self {
            Core::Singbox => "onebox-sing-box",
            Core::Xray => "onebox-xray",
        }
    }
    pub fn title(self) -> &'static str {
        match self {
            Core::Singbox => "sing-box",
            Core::Xray => "Xray",
        }
    }
}

impl FromStr for Core {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "singbox" | "sing-box" => Ok(Core::Singbox),
            "xray" => Ok(Core::Xray),
            _ => Err(Error::Msg(format!("未知内核: {s}"))),
        }
    }
}

impl fmt::Display for Core {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

/// Which L4 namespaces a listener occupies. TCP and UDP ports are independent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Tcp,
    Udp,
    Both,
}

impl Transport {
    pub fn tcp(self) -> bool {
        self != Transport::Udp
    }
    pub fn udp(self) -> bool {
        self != Transport::Tcp
    }
    pub fn overlaps(self, other: Transport) -> bool {
        (self.tcp() && other.tcp()) || (self.udp() && other.udp())
    }
    pub fn id(self) -> &'static str {
        match self {
            Transport::Tcp => "tcp",
            Transport::Udp => "udp",
            Transport::Both => "both",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Protocol {
    #[serde(rename = "vless-reality")]
    VlessReality,
    #[serde(rename = "vless-xhttp")]
    VlessXhttp,
    #[serde(rename = "vless-grpc")]
    VlessGrpc,
    #[serde(rename = "vless-ws")]
    VlessWs,
    #[serde(rename = "vmess-ws")]
    VmessWs,
    #[serde(rename = "trojan")]
    Trojan,
    #[serde(rename = "shadowsocks")]
    Shadowsocks,
    #[serde(rename = "hysteria2")]
    Hysteria2,
    #[serde(rename = "tuic")]
    Tuic,
    #[serde(rename = "anytls")]
    Anytls,
    #[serde(rename = "shadowtls")]
    Shadowtls,
    #[serde(rename = "anytls-reality")]
    AnytlsReality,
}

struct Caps {
    id: &'static str,
    title: &'static str,
    cores: &'static [Core],
    reality: bool,
    certificate: bool,
    transport: Transport,
}

const SB: &[Core] = &[Core::Singbox];
const XR: &[Core] = &[Core::Xray];
const BOTH: &[Core] = &[Core::Singbox, Core::Xray];

impl Protocol {
    /// Canonical order (menu numbering 1..=12).
    pub const ALL: [Protocol; 12] = [
        Protocol::VlessReality,
        Protocol::VlessXhttp,
        Protocol::VlessGrpc,
        Protocol::VlessWs,
        Protocol::VmessWs,
        Protocol::Trojan,
        Protocol::Shadowsocks,
        Protocol::Hysteria2,
        Protocol::Tuic,
        Protocol::Anytls,
        Protocol::Shadowtls,
        Protocol::AnytlsReality,
    ];

    fn caps(self) -> Caps {
        use Protocol::*;
        let c = |id, title, cores, reality, certificate, transport| Caps {
            id,
            title,
            cores,
            reality,
            certificate,
            transport,
        };
        match self {
            VlessReality => c(
                "vless-reality",
                "VLESS-Reality-Vision",
                BOTH,
                true,
                false,
                Transport::Tcp,
            ),
            VlessXhttp => c(
                "vless-xhttp",
                "VLESS-XHTTP-Reality",
                XR,
                true,
                false,
                Transport::Tcp,
            ),
            VlessGrpc => c(
                "vless-grpc",
                "VLESS-gRPC-Reality",
                BOTH,
                true,
                false,
                Transport::Tcp,
            ),
            VlessWs => c(
                "vless-ws",
                "VLESS-WS-TLS",
                BOTH,
                false,
                true,
                Transport::Tcp,
            ),
            VmessWs => c("vmess-ws", "VMess-WS", BOTH, false, false, Transport::Tcp),
            Trojan => c("trojan", "Trojan-TLS", BOTH, false, true, Transport::Tcp),
            Shadowsocks => c(
                "shadowsocks",
                "Shadowsocks-2022",
                BOTH,
                false,
                false,
                Transport::Both,
            ),
            Hysteria2 => c("hysteria2", "Hysteria2", BOTH, false, true, Transport::Udp),
            Tuic => c("tuic", "TUIC-v5", SB, false, true, Transport::Udp),
            Anytls => c("anytls", "AnyTLS", SB, false, true, Transport::Tcp),
            Shadowtls => c(
                "shadowtls",
                "ShadowTLS-v3",
                SB,
                false,
                false,
                Transport::Tcp,
            ),
            AnytlsReality => c(
                "anytls-reality",
                "AnyTLS-REALITY",
                SB,
                true,
                false,
                Transport::Tcp,
            ),
        }
    }

    pub fn id(self) -> &'static str {
        self.caps().id
    }
    pub fn title(self) -> &'static str {
        self.caps().title
    }
    /// Supported server cores; the first is the default.
    pub fn cores(self) -> &'static [Core] {
        self.caps().cores
    }
    pub fn supports_core(self, core: Core) -> bool {
        self.cores().contains(&core)
    }
    pub fn reality(self) -> bool {
        self.caps().reality
    }
    /// Always needs a TLS certificate. VMess-WS needs one only when
    /// `NodeConfig::vmess_tls` is set; see `NodeConfig::needs_cert`.
    pub fn certificate(self) -> bool {
        self.caps().certificate
    }
    pub fn transport(self) -> Transport {
        self.caps().transport
    }
    /// 1-based menu number.
    pub fn number(self) -> usize {
        Protocol::ALL
            .iter()
            .position(|p| *p == self)
            .map_or(0, |i| i + 1)
    }
    pub fn from_number(n: usize) -> Option<Protocol> {
        n.checked_sub(1).and_then(|i| Protocol::ALL.get(i).copied())
    }
}

impl FromStr for Protocol {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Protocol::ALL
            .into_iter()
            .find(|p| p.id() == s)
            .ok_or_else(|| Error::Msg(format!("未知协议: {s}")))
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

/// Client export formats.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ClientFormat {
    Links,
    Base64,
    Mihomo,
    Provider,
    Singbox,
    SingboxNoTun,
    Xray,
}

impl ClientFormat {
    pub const ALL: [ClientFormat; 7] = [
        ClientFormat::Links,
        ClientFormat::Base64,
        ClientFormat::Mihomo,
        ClientFormat::Provider,
        ClientFormat::Singbox,
        ClientFormat::SingboxNoTun,
        ClientFormat::Xray,
    ];

    /// Formats served by the remote subscription, in v2 order.
    pub const REMOTE: [ClientFormat; 6] = [
        ClientFormat::Base64,
        ClientFormat::Mihomo,
        ClientFormat::Provider,
        ClientFormat::Singbox,
        ClientFormat::SingboxNoTun,
        ClientFormat::Xray,
    ];

    /// Canonical id (CLI argument, subscription URL segment).
    pub fn id(self) -> &'static str {
        match self {
            ClientFormat::Links => "links",
            ClientFormat::Base64 => "base64",
            ClientFormat::Mihomo => "mihomo",
            ClientFormat::Provider => "provider",
            ClientFormat::Singbox => "singbox",
            ClientFormat::SingboxNoTun => "singbox-notun",
            ClientFormat::Xray => "xray",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            ClientFormat::Links => "分享链接",
            ClientFormat::Base64 => "Base64 订阅",
            ClientFormat::Mihomo => "mihomo / Clash Meta 完整配置",
            ClientFormat::Provider => "mihomo proxy-provider",
            ClientFormat::Singbox => "sing-box 完整配置（TUN）",
            ClientFormat::SingboxNoTun => "sing-box 完整配置（仅代理端口）",
            ClientFormat::Xray => "Xray 客户端配置",
        }
    }

    /// Accepts the canonical id and the v2 aliases.
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "links" | "link" => ClientFormat::Links,
            "base64" | "sub" => ClientFormat::Base64,
            "mihomo" | "clash" => ClientFormat::Mihomo,
            "provider" => ClientFormat::Provider,
            "singbox" | "sing-box" => ClientFormat::Singbox,
            "singbox-notun" | "sing-box-notun" => ClientFormat::SingboxNoTun,
            "xray" => ClientFormat::Xray,
            _ => return Err(Error::Msg(format!("未知客户端格式: {s}"))),
        })
    }

    /// File name inside `ROOT/client/` (v2 names).
    pub fn file_name(self) -> &'static str {
        match self {
            ClientFormat::Links => "links.txt",
            ClientFormat::Base64 => "sub.txt",
            ClientFormat::Mihomo => "mihomo.yaml",
            ClientFormat::Provider => "provider.yaml",
            ClientFormat::Singbox => "sing-box.json",
            ClientFormat::SingboxNoTun => "sing-box-notun.json",
            ClientFormat::Xray => "xray.json",
        }
    }

    pub fn content_type(self) -> &'static str {
        match self {
            ClientFormat::Links | ClientFormat::Base64 => "text/plain; charset=utf-8",
            ClientFormat::Mihomo | ClientFormat::Provider => "text/yaml; charset=utf-8",
            ClientFormat::Singbox | ClientFormat::SingboxNoTun | ClientFormat::Xray => {
                "application/json; charset=utf-8"
            }
        }
    }

    /// Capability table (v2 `Protocol::supports`).
    pub fn supports(self, protocol: Protocol) -> bool {
        use Protocol::*;
        match self {
            ClientFormat::Singbox | ClientFormat::SingboxNoTun => protocol != VlessXhttp,
            ClientFormat::Xray => !matches!(protocol, Tuic | Anytls | AnytlsReality | Shadowtls),
            ClientFormat::Mihomo | ClientFormat::Provider => protocol != AnytlsReality,
            ClientFormat::Links | ClientFormat::Base64 => {
                !matches!(protocol, AnytlsReality | Shadowtls)
            }
        }
    }
}

impl fmt::Display for ClientFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbering_is_a_compatibility_contract() {
        assert_eq!(Protocol::ALL[10], Protocol::Shadowtls);
        assert_eq!(Protocol::ALL[11], Protocol::AnytlsReality);
        assert_eq!(Protocol::from_number(1), Some(Protocol::VlessReality));
        assert_eq!(Protocol::from_number(13), None);
        assert_eq!(Protocol::Tuic.number(), 9);
    }

    #[test]
    fn ids_roundtrip_and_serde_agree() {
        for p in Protocol::ALL {
            assert_eq!(p.id().parse::<Protocol>().unwrap(), p);
            assert_eq!(serde_json::to_value(p).unwrap(), serde_json::json!(p.id()));
        }
        assert_eq!("sing-box".parse::<Core>().unwrap(), Core::Singbox);
        assert!("clash".parse::<Core>().is_err());
    }

    #[test]
    fn capabilities_match_v2() {
        assert_eq!(Protocol::VlessXhttp.cores(), &[Core::Xray]);
        assert_eq!(Protocol::Hysteria2.cores()[0], Core::Singbox);
        assert!(!ClientFormat::Singbox.supports(Protocol::VlessXhttp));
        assert!(!ClientFormat::Links.supports(Protocol::Shadowtls));
        assert!(ClientFormat::Mihomo.supports(Protocol::Shadowtls));
        assert!(!ClientFormat::Xray.supports(Protocol::Anytls));
        assert!(Transport::Both.overlaps(Transport::Udp));
        assert!(!Transport::Tcp.overlaps(Transport::Udp));
    }
}
