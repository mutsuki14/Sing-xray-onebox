//! Typed readers over the v2 key/value bag: website, proxy certificate,
//! tuning, routing, versions and unknown keys.

use super::fields::{protocol_key, V2};
use crate::domain::config::*;
use crate::domain::defaults;
use crate::domain::protocol::{Core, Protocol};
use crate::domain::validate::{valid_cidr, valid_domain, valid_label, valid_text, valid_version};
use crate::error::Result;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Every key v2 persisted on purpose (spec A §3.4.1 and §3.4.2), besides the
/// `PORT_`/`CORE_` families and transient intent keys.
const KNOWN_KEYS: &[&str] = &[
    "PROTOCOLS",
    "SERVER_ADDR",
    "SERVER_IPV4",
    "SERVER_IPV6",
    "SERVER_IPV4_WARP",
    "SERVER_IPV6_WARP",
    "NODE_NAME",
    "LISTEN_ADDR",
    "UUID",
    "PASSWORD",
    "SS_METHOD",
    "SS_PASSWORD",
    "REALITY_PRIVATE_KEY",
    "REALITY_PUBLIC_KEY",
    "REALITY_SHORT_ID",
    "REALITY_SNI",
    "REALITY_DEST",
    "REALITY_SITE_ENABLED",
    "REALITY_SITE_DOMAIN",
    "REALITY_SITE_PORT",
    "REALITY_SITE_TITLE",
    "REALITY_SITE_HTTPS",
    "WS_PATH",
    "VMESS_PATH",
    "XHTTP_PATH",
    "GRPC_SERVICE",
    "HY2_OBFS",
    "HY2_OBFS_PASSWORD",
    "HY2_HOP",
    "HY2_PROFILE",
    "HY2_UP_MBPS",
    "HY2_DOWN_MBPS",
    "RESOURCE_PROFILE",
    "SHADOWTLS_SNI",
    "SHADOWTLS_DEST",
    "SHADOWTLS_PASSWORD",
    "SHADOWTLS_SS_PASSWORD",
    "TLS_MODE",
    "DOMAIN",
    "TLS_SNI",
    "CERT_FILE",
    "KEY_FILE",
    "ACME_METHOD",
    "SB_VERSION",
    "XR_VERSION",
    "BLOCK_PRIVATE",
    "BLOCK_BT",
    "REALITY_GUARD_PORT",
    "VMESS_TLS",
    "CLASH_SECRET",
    "CERT_PINNED",
    "OWN_IP_CIDRS",
    "INSTALLED_AT",
    "SB_VERSION_WANT",
    "XR_VERSION_WANT",
    "CUSTOM_CERT",
    "CUSTOM_KEY",
    "SITE_ACME_METHOD",
    "SITE_CUSTOM_CERT",
    "SITE_CUSTOM_KEY",
    "SITE_TEMPLATE",
    "SITE_THEME",
    "SITE_DESCRIPTION",
    "SITE_LAST_CONTENT_BACKUP",
    "SUBSCRIPTION_ENABLED",
    "SUBSCRIPTION_MODE",
    "SUBSCRIPTION_DOMAIN",
    "SUBSCRIPTION_PORT",
    "SUBSCRIPTION_HTTP",
    "XR_XHTTP_SOCK",
];

impl V2<'_> {
    /// `REALITY_SITE_*` / `SITE_*` → `SiteConfig` while a REALITY inbound
    /// exists (v2 ignored the site otherwise).
    pub(super) fn site(&mut self, cfg: &mut NodeConfig) -> Result<()> {
        let enabled = self.flag("REALITY_SITE_ENABLED");
        if !enabled || !cfg.any_reality() {
            if enabled {
                self.warn("v2 网站已随 REALITY 协议停用，网站设置未迁移");
            }
            self.drop_stale_site_target(cfg);
            return Ok(());
        }
        let raw = self.get("REALITY_SITE_DOMAIN").trim();
        let domain = raw.to_ascii_lowercase();
        ensure!(
            valid_domain(&domain),
            "v2 字段 REALITY_SITE_DOMAIN 无效: {raw}"
        );
        let internal_port = self.site_port(&cfg.reality.dest);
        let site = SiteConfig {
            domain,
            internal_port,
            https_entry: matches!(self.get("REALITY_SITE_HTTPS").trim(), "" | "1"),
            title: self.text_or("REALITY_SITE_TITLE", defaults::SITE_TITLE, valid_label),
            template: self.keyword("SITE_TEMPLATE", defaults::SITE_TEMPLATE),
            theme: self.keyword("SITE_THEME", defaults::SITE_THEME),
            description: self.text_or("SITE_DESCRIPTION", "", valid_text),
            cert: self.site_cert()?,
            last_content_backup: self.backup_id(),
        };
        cfg.reality.sni = site.domain.clone();
        cfg.reality.dest = defaults::site_dest(internal_port);
        cfg.site = Some(site);
        Ok(())
    }

    /// v2 `del` of the last REALITY protocol only cleared
    /// `REALITY_SITE_ENABLED` and left the target on the stopped site
    /// (`REALITY_SNI` = site domain, `REALITY_DEST` = `127.0.0.1:N`, spec B
    /// §3.5); a later `add` kept it, so REALITY handshaked against a closed
    /// loopback port. Such a target goes back to the default. Other loopback
    /// targets (local test servers) are kept.
    fn drop_stale_site_target(&mut self, cfg: &mut NodeConfig) {
        let site_domain = self.get("REALITY_SITE_DOMAIN").trim().to_ascii_lowercase();
        let loopback = cfg.reality.dest.host == Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
        if site_domain.is_empty() || cfg.reality.sni != site_domain || !loopback {
            return;
        }
        let stale = cfg.reality.dest.to_string();
        cfg.reality = defaults::reality_target(cfg.reality.guard_port);
        let update = if cfg.any_reality() {
            "；请更新客户端"
        } else {
            ""
        };
        self.warn(format!(
            "v2 REALITY 目标仍指向已停用的自建站 {stale}，已改为默认目标 {}{update}",
            cfg.reality.dest
        ));
    }

    /// The port v2 rendered: `REALITY_DEST` `127.0.0.1:N`, else
    /// `REALITY_SITE_PORT`, else the v3 default.
    fn site_port(&mut self, dest: &HostPort) -> u16 {
        if dest.host == Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)) {
            return dest.port;
        }
        self.parse_lenient::<u16>("REALITY_SITE_PORT")
            .filter(|p| *p != 0)
            .unwrap_or(defaults::SITE_INTERNAL_PORT)
    }

    fn site_cert(&mut self) -> Result<WebCert> {
        match self.get("SITE_ACME_METHOD").trim() {
            "" | "http" | "standalone" => Ok(WebCert::Http01),
            "cf" => Ok(WebCert::Cloudflare),
            "custom" => {
                let sources = [
                    ("SITE_CUSTOM_CERT", self.nonempty("SITE_CUSTOM_CERT")),
                    ("SITE_CUSTOM_KEY", self.nonempty("SITE_CUSTOM_KEY")),
                ];
                let deployed = deployed_pair(&self.deployed.site);
                let (cert, key) = self.source_pair("网站", sources, deployed);
                Ok(WebCert::Custom { cert, key })
            }
            other => bail!("v2 字段 SITE_ACME_METHOD 无效: {other}"),
        }
    }

    /// A custom certificate source pair. v2 stored `--cert/--key` verbatim
    /// and read them relative to the working directory of whichever command
    /// ran (spec F §3.9), so a missing or relative source is replaced by the
    /// copy v2 deployed, which is what the node served. The certificate is
    /// server-side only, so this never blocks the upgrade.
    pub(super) fn source_pair(
        &mut self,
        label: &str,
        sources: [(&str, Option<&str>); 2],
        deployed: (PathBuf, PathBuf),
    ) -> (PathBuf, PathBuf) {
        let [(cert_key, cert), (key_key, key)] = sources;
        if let (Some(cert), Some(key)) = (cert, key) {
            let (cert, key) = (PathBuf::from(cert), PathBuf::from(key));
            if usable_path(&cert) && usable_path(&key) {
                return (cert, key);
            }
        }
        let shown = |v: Option<&str>| v.map_or_else(|| "（缺失）".to_owned(), |v| format!("{v:?}"));
        self.warn(format!(
            "v2 {label}自备证书路径 {cert_key}={} {key_key}={} 缺失或不是绝对路径，已改用已部署的 {} 和 {}",
            shown(cert),
            shown(key),
            deployed.0.display(),
            deployed.1.display()
        ));
        deployed
    }

    fn backup_id(&mut self) -> Option<String> {
        let id = self.nonempty("SITE_LAST_CONTENT_BACKUP")?;
        if id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            Some(id.to_owned())
        } else {
            self.warn(format!(
                "v2 字段 SITE_LAST_CONTENT_BACKUP 无效，已忽略: {id:?}"
            ));
            None
        }
    }

    fn text_or(&mut self, key: &str, default: &str, valid: fn(&str) -> bool) -> String {
        match self.nonempty(key) {
            Some(text) if valid(text) => text.to_owned(),
            Some(text) => {
                self.warn(format!("v2 字段 {key} 无效，已使用默认值: {text:?}"));
                default.to_owned()
            }
            None => default.to_owned(),
        }
    }

    fn keyword<T: FromStr>(&mut self, key: &str, default: T) -> T {
        self.parse_lenient(key).unwrap_or(default)
    }

    /// `VMESS_TLS` (with v2's `upgrade()` pinning rule) and the proxy
    /// certificate (`TLS_MODE` / `ACME_METHOD` / `DOMAIN` / `TLS_SNI` /
    /// `CUSTOM_*` / `CERT_PINNED`), present iff a protocol needs it.
    pub(super) fn tls(&mut self, cfg: &mut NodeConfig) -> Result<()> {
        let mode = self.get("TLS_MODE").trim();
        cfg.vmess_tls = cfg.has(Protocol::VmessWs)
            && match self.get("VMESS_TLS").trim() {
                "1" => true,
                "" => matches!(mode, "acme" | "custom"),
                _ => false,
            };
        self.vmess_host(cfg);
        if !cfg.needs_cert() {
            return Ok(());
        }
        let mode = match mode {
            "" | "self" => ProxyCertMode::SelfSigned {
                sni: self.tls_sni(),
            },
            "acme" => ProxyCertMode::Acme {
                domain: self.cert_domain()?,
                method: self.acme_method()?,
            },
            "custom" => {
                let domain = self.cert_domain()?;
                let (cert, key) = self.proxy_custom_pair();
                ProxyCertMode::Custom { domain, cert, key }
            }
            other => bail!("v2 字段 TLS_MODE 无效: {other}"),
        };
        let pinned = !mode.is_domain_cert() || self.flag("CERT_PINNED");
        cfg.tls = Some(ProxyTls { mode, pinned });
        Ok(())
    }

    /// v2 plain VMess-WS clients send `Host: DOMAIN` (spec C §3.2, §3.3,
    /// §3.5); `DOMAIN` keeps that role in `vmess_host` while VMess-WS is
    /// enabled (also on TLS, where it applies again once VMess turns plain,
    /// as in v2).
    fn vmess_host(&mut self, cfg: &mut NodeConfig) {
        if !cfg.has(Protocol::VmessWs) {
            return;
        }
        let Some(raw) = self.nonempty("DOMAIN") else {
            return;
        };
        let host = raw.to_ascii_lowercase();
        if valid_domain(&host) {
            cfg.vmess_host = Some(host);
        } else if !cfg.vmess_tls {
            self.warn(format!(
                "v2 字段 DOMAIN 不是有效域名，VMess-WS 不再发送该 Host 头: {raw}"
            ));
        }
    }

    fn tls_sni(&mut self) -> String {
        match self.nonempty("TLS_SNI").map(str::to_ascii_lowercase) {
            Some(sni) if valid_domain(&sni) => sni,
            Some(sni) => {
                self.warn(format!(
                    "v2 字段 TLS_SNI 无效，已改为 {}: {sni}",
                    defaults::TLS_SNI
                ));
                defaults::TLS_SNI.to_owned()
            }
            None => defaults::TLS_SNI.to_owned(),
        }
    }

    /// `DOMAIN`; empty falls back to `TLS_SNI` like v2's `tls_name`.
    fn cert_domain(&mut self) -> Result<String> {
        match self.nonempty("DOMAIN") {
            Some(raw) => {
                let domain = raw.to_ascii_lowercase();
                ensure!(valid_domain(&domain), "v2 字段 DOMAIN 无效: {raw}");
                Ok(domain)
            }
            None => {
                let sni = self.tls_sni();
                self.warn(format!("v2 状态缺少 DOMAIN，证书域名已使用 {sni}"));
                Ok(sni)
            }
        }
    }

    fn acme_method(&self) -> Result<AcmeMethod> {
        match self.get("ACME_METHOD").trim() {
            "" | "standalone" | "http" => Ok(AcmeMethod::Http01),
            "cf" => Ok(AcmeMethod::Cloudflare),
            other => bail!("v2 字段 ACME_METHOD 无效: {other}"),
        }
    }

    /// `CUSTOM_CERT` / `CUSTOM_KEY`; v2 itself fell back to the deployed
    /// copy `CERT_FILE` / `KEY_FILE` when they were empty.
    fn proxy_custom_pair(&mut self) -> (PathBuf, PathBuf) {
        let recorded = [self.nonempty("CERT_FILE"), self.nonempty("KEY_FILE")]
            .map(|v| v.map(PathBuf::from).filter(|p| usable_path(p)));
        let deployed = match recorded {
            [Some(cert), Some(key)] => (cert, key),
            _ => deployed_pair(&self.deployed.proxy),
        };
        let sources = [
            ("CUSTOM_CERT", self.nonempty("CUSTOM_CERT")),
            ("CUSTOM_KEY", self.nonempty("CUSTOM_KEY")),
        ];
        self.source_pair("代理", sources, deployed)
    }

    /// Hysteria2 options, tuning and the resource profile. Values v2 could
    /// not apply are dropped with a warning.
    pub(super) fn tuning(&mut self, cfg: &mut NodeConfig) {
        let mut hy2 = Hy2Settings {
            obfs: self.flag("HY2_OBFS"),
            hop: self.hop(),
            profile: self.parse_lenient("HY2_PROFILE"),
            up_mbps: None,
            down_mbps: None,
        };
        let up = self.mbps("HY2_UP_MBPS");
        let down = self.mbps("HY2_DOWN_MBPS");
        if hy2.profile == Some(Hy2Profile::Measured) {
            if up.is_some() && down.is_some() {
                (hy2.up_mbps, hy2.down_mbps) = (up, down);
            } else {
                self.warn("Hysteria2 measured 档位缺少有效带宽，已取消调优");
                hy2.profile = None;
            }
        }
        let mut resource = self.keyword("RESOURCE_PROFILE", ResourceProfile::Balanced);
        if cfg.core_of(Protocol::Hysteria2) == Some(Core::Xray) {
            let tuned = hy2.profile.is_some() || resource != ResourceProfile::Balanced;
            if tuned {
                self.warn("Xray 承载的 Hysteria2 不支持调优（v2 会忽略），已取消调优设置");
            }
            hy2.profile = None;
            (hy2.up_mbps, hy2.down_mbps) = (None, None);
            resource = ResourceProfile::Balanced;
        }
        cfg.hy2 = hy2;
        cfg.resource_profile = resource;
    }

    fn hop(&mut self) -> Option<PortRange> {
        let raw = self.nonempty("HY2_HOP")?;
        match raw.parse::<PortRange>() {
            Ok(r) if r.start >= defaults::HOP_MIN_START && r.start < r.end => Some(r),
            _ => {
                self.warn(format!("v2 字段 HY2_HOP 无效，已忽略: {raw}"));
                None
            }
        }
    }

    /// Integer Mbps in 1..=10000; anything else (v2 accepted floats and
    /// values up to 100000 it could not render) is dropped.
    fn mbps(&mut self, key: &str) -> Option<u32> {
        let raw = self.nonempty(key)?;
        let value = raw
            .parse::<u32>()
            .ok()
            .filter(|v| defaults::HY2_MBPS.contains(v));
        if value.is_none() {
            self.warn(format!("{key} 不是 1–10000 的整数，已忽略: {raw}"));
        }
        value
    }

    pub(super) fn routing(&mut self) -> Routing {
        Routing {
            block_private: self.get("BLOCK_PRIVATE").trim() != "0",
            block_bt: self.get("BLOCK_BT").trim() != "0",
            own_cidrs: self.own_cidrs(),
        }
    }

    /// `OWN_IP_CIDRS`: a JSON array string, or its inner list without brackets.
    fn own_cidrs(&mut self) -> Vec<String> {
        let Some(raw) = self.nonempty("OWN_IP_CIDRS") else {
            return Vec::new();
        };
        let mut good: Vec<String> = Vec::new();
        let mut bad: Vec<String> = Vec::new();
        for entry in cidr_entries(raw) {
            if !valid_cidr(&entry) {
                bad.push(entry);
            } else if !good.contains(&entry) {
                good.push(entry);
            }
        }
        if !bad.is_empty() {
            self.warn(format!(
                "OWN_IP_CIDRS 含无效条目，已忽略: {}",
                bad.join(", ")
            ));
        }
        good
    }

    pub(super) fn versions(&mut self) -> CoreVersions {
        let singbox = self.version("SB_VERSION");
        let xray = self.version("XR_VERSION");
        CoreVersions {
            singbox_pin: self.pin("SB_VERSION_WANT", Core::Singbox, singbox.as_deref()),
            xray_pin: self.pin("XR_VERSION_WANT", Core::Xray, xray.as_deref()),
            singbox,
            xray,
        }
    }

    fn version(&mut self, key: &str) -> Option<String> {
        let raw = self.nonempty(key)?;
        if valid_version(raw) {
            Some(raw.to_owned())
        } else {
            self.warn(format!("v2 字段 {key} 无效，已忽略: {raw:?}"));
            None
        }
    }

    /// `*_VERSION_WANT` (one leading `v` stripped, as v2 did before using
    /// it); `latest` means no pin.
    ///
    /// v2 persisted the pin forever while `onebox update` ignored it, so a
    /// pin that differs from the installed core is stale: keeping it would
    /// only repeat the "更换指定版本" hint on every apply. It is kept when it
    /// matches the installed version or nothing is recorded as installed
    /// (the next install of that core honors it).
    fn pin(&mut self, key: &str, core: Core, installed: Option<&str>) -> Option<String> {
        let raw = self.version(key)?;
        let pin = without_v(&raw);
        if pin == "latest" || pin.is_empty() {
            return None;
        }
        match installed {
            Some(current) if without_v(current) != pin => {
                self.warn(format!(
                    "v2 固定的 {} 版本 {pin} 与已安装 {current} 不一致，已取消固定",
                    core.title()
                ));
                None
            }
            _ => Some(pin.to_owned()),
        }
    }

    pub(super) fn report_unknown_keys(&mut self) {
        let unknown: Vec<&str> = self
            .values()
            .keys()
            .map(String::as_str)
            .filter(|k| !known_key(k))
            .collect();
        if !unknown.is_empty() {
            self.warn(format!("已忽略未知的 v2 字段: {}", unknown.join(", ")));
        }
    }
}

/// A version without one leading `v` (`v1.12.0` and `1.12.0` are the same
/// release for v2 and for `host::cores`).
fn without_v(version: &str) -> &str {
    version.strip_prefix('v').unwrap_or(version)
}

/// `cert.pem` / `key.pem` in a v2 deployment directory.
pub(super) fn deployed_pair(dir: &Path) -> (PathBuf, PathBuf) {
    (dir.join("cert.pem"), dir.join("key.pem"))
}

/// Absolute and printable, as `NodeConfig::validate` requires.
fn usable_path(path: &Path) -> bool {
    path.is_absolute() && path.to_str().is_some_and(valid_text)
}

/// Entries of `OWN_IP_CIDRS`: JSON array, bracket-less JSON list, or a plain
/// comma/space separated list.
fn cidr_entries(raw: &str) -> Vec<String> {
    let json = if raw.starts_with('[') {
        raw.to_owned()
    } else {
        format!("[{raw}]")
    };
    serde_json::from_str::<Vec<String>>(&json).unwrap_or_else(|_| {
        raw.split(|c: char| c == ',' || c.is_whitespace())
            .map(|s| s.trim_matches(|c| matches!(c, '"' | '[' | ']')))
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect()
    })
}

fn known_key(key: &str) -> bool {
    let transient = key.starts_with("__")
        || key.starts_with("CERT_RENEW_")
        || key.contains("_PENDING")
        || key == "SUBSCRIPTION_SETTINGS_EXPECTED";
    let per_protocol = key
        .strip_prefix("PORT_")
        .or_else(|| key.strip_prefix("CORE_"))
        .is_some_and(|suffix| Protocol::ALL.iter().any(|p| protocol_key(*p) == suffix));
    transient || per_protocol || KNOWN_KEYS.contains(&key)
}
