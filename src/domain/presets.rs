//! Install presets 1–7 and the per-protocol core assignment rule.
//!
//! Preset protocol lists are a compatibility contract with v2: they are stored
//! in the listed order (not canonical order), and the preferred core decides
//! which core hosts each protocol that both cores support.
//!
//! Changes from v2: the error for an unknown preset no longer claims 1–6 are
//! the only presets while advertising 7; the custom preset is a distinct
//! [`Selection`] so callers cannot forget to ask for the protocol list.

use super::protocol::{Core, Protocol};
use crate::error::Result;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Preset {
    /// Menu number (1-based).
    pub number: u8,
    /// Short v2 name (`Reality+Hy2+TUIC`, `Xray经典`, …).
    pub name: &'static str,
    /// One-line description shown by the install wizard.
    pub description: &'static str,
    /// Protocols in storage order.
    pub protocols: &'static [Protocol],
    /// Preferred core for protocols that both cores support.
    pub core: Core,
}

use Protocol::*;

pub const PRESETS: [Preset; 6] = [
    Preset {
        number: 1,
        name: "Reality+Hy2+TUIC",
        description: "Reality + Hysteria2 + TUIC（推荐，无需域名）",
        protocols: &[VlessReality, Hysteria2, Tuic],
        core: Core::Singbox,
    },
    Preset {
        number: 2,
        name: "Xray经典",
        description: "Xray 经典：Reality + XHTTP + Shadowsocks（Vision 与 XHTTP 共用 443）",
        protocols: &[VlessReality, VlessXhttp, Shadowsocks],
        core: Core::Xray,
    },
    Preset {
        number: 3,
        name: "双内核",
        description: "双内核：Xray 承载 Reality/XHTTP，sing-box 承载 Hysteria2/TUIC/AnyTLS",
        protocols: &[VlessReality, VlessXhttp, Hysteria2, Tuic, Anytls],
        core: Core::Xray,
    },
    Preset {
        number: 4,
        name: "sing-box全家桶",
        description: "sing-box 全家桶：9 种协议，含 ShadowTLS 与 VMess-WS",
        protocols: &[
            VlessReality,
            VlessGrpc,
            Trojan,
            Shadowsocks,
            Hysteria2,
            Tuic,
            Anytls,
            Shadowtls,
            VmessWs,
        ],
        core: Core::Singbox,
    },
    Preset {
        number: 5,
        name: "CDN",
        description: "CDN：VLESS-WS-TLS + VMess-WS（可套 CDN，建议使用域名证书）",
        protocols: &[VlessWs, VmessWs],
        core: Core::Singbox,
    },
    Preset {
        number: 6,
        name: "仅Reality",
        description: "仅 Reality：Xray 单协议，最简部署",
        protocols: &[VlessReality],
        core: Core::Xray,
    },
];

/// Menu number of the custom preset.
pub const CUSTOM: u8 = 7;
pub const CUSTOM_NAME: &str = "自定义";
pub const CUSTOM_DESCRIPTION: &str = "自定义：从 12 种协议中自由组合";
/// Preferred core for custom selections and explicit protocol lists.
pub const CUSTOM_CORE: Core = Core::Singbox;
/// Preset used without a terminal and without `--preset`/`--protocols`.
pub const DEFAULT: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Selection {
    Preset(&'static Preset),
    /// Preset 7: the caller must obtain an explicit protocol list.
    Custom,
}

/// Resolve a menu number (1–7).
pub fn select(number: u32) -> Result<Selection> {
    if number == u32::from(CUSTOM) {
        return Ok(Selection::Custom);
    }
    PRESETS
        .iter()
        .find(|p| u32::from(p.number) == number)
        .map(Selection::Preset)
        .ok_or_else(|| "预设应为 1–7，7 为自定义协议组合".into())
}

/// Wizard lines for presets 1–7 (`description` of each, custom last).
pub fn menu_items() -> Vec<String> {
    PRESETS
        .iter()
        .map(|p| p.description.to_owned())
        .chain(std::iter::once(CUSTOM_DESCRIPTION.to_owned()))
        .collect()
}

/// v2's one-line menu: `1) Reality+Hy2+TUIC  2) Xray经典 … 7) 自定义`.
pub fn compact_menu() -> String {
    PRESETS
        .iter()
        .map(|p| (p.number, p.name))
        .chain(std::iter::once((CUSTOM, CUSTOM_NAME)))
        .map(|(n, name)| format!("{n}) {name}"))
        .collect::<Vec<_>>()
        .join("  ")
}

/// Core for `protocol` given the preferred core. Hysteria2 defaults to
/// sing-box (v2 rule: Xray cannot apply Hysteria2 tuning) unless `override_core`
/// names a supported core; other protocols use `preferred` when supported,
/// else their first supported core.
pub fn assign_core(protocol: Protocol, preferred: Core, override_core: Option<Core>) -> Core {
    if let Some(core) = override_core.filter(|c| protocol.supports_core(*c)) {
        return core;
    }
    if protocol == Hysteria2 {
        return Core::Singbox;
    }
    if protocol.supports_core(preferred) {
        preferred
    } else {
        protocol.cores()[0]
    }
}

/// Deduplicate and sort into canonical (menu) order. Explicit lists and custom
/// selections are stored canonically; only presets keep their listed order.
pub fn canonical(list: &[Protocol]) -> Vec<Protocol> {
    Protocol::ALL
        .into_iter()
        .filter(|p| list.contains(p))
        .collect()
}

/// Parse `--protocols` text: ids separated by commas and/or whitespace.
pub fn parse_protocols(text: &str) -> Result<Vec<Protocol>> {
    let parsed = text
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .map(str::parse)
        .collect::<Result<Vec<Protocol>>>()?;
    let list = canonical(&parsed);
    ensure!(!list.is_empty(), "至少选择一种协议");
    Ok(list)
}

/// Parse custom-menu numbers (`"1 3,5"`, 1-based) into a canonical list.
pub fn parse_numbers(text: &str) -> Result<Vec<Protocol>> {
    let parsed = text
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .map(|n| {
            n.parse::<usize>()
                .ok()
                .and_then(Protocol::from_number)
                .ok_or_else(|| crate::Error::msg(format!("编号无效: {n}")))
        })
        .collect::<Result<Vec<Protocol>>>()?;
    let list = canonical(&parsed);
    ensure!(!list.is_empty(), "至少选择一种协议");
    Ok(list)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn preset(n: u32) -> &'static Preset {
        match select(n).unwrap() {
            Selection::Preset(p) => p,
            Selection::Custom => panic!("custom"),
        }
    }

    #[test]
    fn preset_lists_match_v2_storage_order() {
        let ids = |n| {
            preset(n)
                .protocols
                .iter()
                .map(|p| p.id())
                .collect::<Vec<_>>()
                .join(" ")
        };
        assert_eq!(ids(1), "vless-reality hysteria2 tuic");
        assert_eq!(ids(2), "vless-reality vless-xhttp shadowsocks");
        assert_eq!(ids(3), "vless-reality vless-xhttp hysteria2 tuic anytls");
        assert_eq!(
            ids(4),
            "vless-reality vless-grpc trojan shadowsocks hysteria2 tuic anytls shadowtls vmess-ws"
        );
        assert_eq!(ids(5), "vless-ws vmess-ws");
        assert_eq!(ids(6), "vless-reality");
        let cores: Vec<Core> = (1..=6).map(|n| preset(n).core).collect();
        use Core::*;
        assert_eq!(cores, [Singbox, Xray, Xray, Singbox, Singbox, Xray]);
    }

    #[test]
    fn selection_errors() {
        assert_eq!(select(7).unwrap(), Selection::Custom);
        for bad in [0, 8, 100] {
            assert!(select(bad).unwrap_err().to_string().contains("1–7"));
        }
    }

    #[test]
    fn menus() {
        let items = menu_items();
        assert_eq!(items.len(), 7);
        assert_eq!(items[0], "Reality + Hysteria2 + TUIC（推荐，无需域名）");
        assert_eq!(
            compact_menu(),
            "1) Reality+Hy2+TUIC  2) Xray经典  3) 双内核  4) sing-box全家桶  5) CDN  6) 仅Reality  7) 自定义"
        );
    }

    #[test]
    fn core_assignment_rule() {
        use Core::*;
        let cases = [
            (Hysteria2, Xray, None, Singbox),
            (Hysteria2, Singbox, Some(Xray), Xray),
            (VlessReality, Xray, None, Xray),
            (VlessXhttp, Singbox, None, Xray),
            (Tuic, Xray, None, Singbox),
            (Tuic, Singbox, Some(Xray), Singbox),
            (Shadowsocks, Xray, None, Xray),
            (AnytlsReality, Xray, None, Singbox),
        ];
        for (protocol, preferred, over, want) in cases {
            assert_eq!(assign_core(protocol, preferred, over), want, "{protocol}");
        }
        // Preset 3 is dual-core.
        let p = preset(3);
        let assigned: Vec<Core> = p
            .protocols
            .iter()
            .map(|x| assign_core(*x, p.core, None))
            .collect();
        assert_eq!(assigned, [Xray, Xray, Singbox, Singbox, Singbox]);
    }

    #[test]
    fn explicit_lists_are_canonical_and_deduplicated() {
        assert_eq!(
            parse_protocols("anytls-reality,anytls,anytls").unwrap(),
            [Anytls, AnytlsReality]
        );
        assert_eq!(
            parse_protocols(" tuic  vless-reality,hysteria2 ").unwrap(),
            [VlessReality, Hysteria2, Tuic]
        );
        assert_eq!(
            parse_protocols(" , ").unwrap_err().to_string(),
            "至少选择一种协议"
        );
        assert_eq!(
            parse_protocols("vless").unwrap_err().to_string(),
            "未知协议: vless"
        );
        assert_eq!(
            parse_numbers("12 1,1").unwrap(),
            [VlessReality, AnytlsReality]
        );
        assert!(parse_numbers("0").is_err());
        assert!(parse_numbers("13").is_err());
        assert!(parse_numbers("x").is_err());
    }
}
