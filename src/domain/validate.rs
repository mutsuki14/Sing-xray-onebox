//! `NodeConfig::validate`: every structural invariant of a configuration.
//!
//! Port conflicts are checked by `PortPlan::validate` (they also depend on
//! FRP reservations); everything else that must hold for a configuration to be
//! saved, rendered or applied is checked here, once, with Chinese messages
//! (v2 wording where v2 had one, spec A §2.10 / §5.1).
//!
//! Changes from v2: v2 validated only protocols, ports and cores; domains,
//! credentials, REALITY keys, Hysteria2 bandwidth (accepted floats it could
//! not render, C-8.1 #1), certificate presence and subscription consistency
//! were checked late or never.

use super::config::*;
use super::credentials as creds;
use super::defaults;
use super::protocol::{Core, Protocol};
use crate::error::Result;
use std::net::IpAddr;
use std::path::Path;

/// Longest accepted node name / site title (characters).
const MAX_LABEL_CHARS: usize = 128;

impl NodeConfig {
    pub fn validate(&self) -> Result<()> {
        check_schema(self.schema)?;
        self.check_inbounds()?;
        self.check_identity()?;
        self.check_credentials()?;
        self.check_reality()?;
        ensure!(valid_domain(&self.shadowtls.sni), "ShadowTLS SNI 域名无效");
        self.check_site()?;
        self.check_tls()?;
        self.check_hy2()?;
        self.check_subscription()?;
        self.check_routing()?;
        self.check_versions()
    }

    fn check_inbounds(&self) -> Result<()> {
        ensure!(!self.inbounds.is_empty(), "配置缺少协议列表");
        for (i, inbound) in self.inbounds.iter().enumerate() {
            let p = inbound.protocol;
            ensure!(
                !self.inbounds[..i].iter().any(|x| x.protocol == p),
                "协议重复"
            );
            ensure!(inbound.port != 0, "{p} 端口无效");
            ensure!(p.supports_core(inbound.core), "{p} 不支持 {}", inbound.core);
        }
        Ok(())
    }

    fn check_identity(&self) -> Result<()> {
        ensure!(
            valid_label(&self.node_name),
            "节点名称不能为空或超过 128 个字符，且不能包含控制字符"
        );
        let server = &self.server;
        match server.addr {
            Host::Ip(IpAddr::V4(v4)) => {
                ensure!(server.ipv4 == Some(v4), "连接地址与记录的 IPv4 不一致")
            }
            Host::Ip(IpAddr::V6(v6)) => {
                ensure!(server.ipv6 == Some(v6), "连接地址与记录的 IPv6 不一致")
            }
            Host::Domain(_) => {}
        }
        Ok(())
    }

    fn check_credentials(&self) -> Result<()> {
        let c = &self.creds;
        ensure!(creds::valid_uuid(&c.uuid), "UUID 格式无效");
        ensure!(creds::valid_secret(&c.password), "节点密码无效");
        ensure!(
            creds::valid_ss_method(&c.ss_method),
            "Shadowsocks 加密方式无效: {}",
            c.ss_method
        );
        ensure!(
            creds::valid_ss_key(&c.ss_method, &c.ss_password),
            "Shadowsocks 密钥与加密方式不匹配"
        );
        ensure!(
            creds::valid_secret(&c.hy2_obfs_password),
            "Hysteria2 混淆密码无效"
        );
        ensure!(
            creds::valid_secret(&c.shadowtls_password),
            "ShadowTLS 密码无效"
        );
        ensure!(
            creds::valid_ss_key(defaults::SHADOWTLS_SS_METHOD, &c.shadowtls_ss_password),
            "ShadowTLS 的 Shadowsocks 密钥无效"
        );
        ensure!(creds::valid_secret(&c.clash_secret), "Clash API 密钥无效");
        for (name, path) in [
            ("WS", &c.ws_path),
            ("VMess", &c.vmess_path),
            ("XHTTP", &c.xhttp_path),
        ] {
            ensure!(creds::valid_path(path), "{name} 路径无效: {path}");
        }
        ensure!(
            creds::valid_grpc_service(&c.grpc_service),
            "gRPC 服务名无效"
        );
        Ok(())
    }

    fn check_reality(&self) -> Result<()> {
        match (&self.creds.reality, self.any_reality()) {
            (Some(keys), true) => creds::check_reality_keys(keys)?,
            (None, true) => bail!("缺少 REALITY 密钥"),
            (Some(_), false) => bail!("未启用 REALITY 协议时不应保留 REALITY 密钥"),
            (None, false) => {}
        }
        ensure!(valid_domain(&self.reality.sni), "REALITY SNI 域名无效");
        ensure!(
            !self.uses_guard() || self.reality.guard_port != 0,
            "REALITY guard 端口缺失或与代理冲突"
        );
        Ok(())
    }

    fn check_site(&self) -> Result<()> {
        let Some(site) = &self.site else {
            return Ok(());
        };
        ensure!(
            self.any_reality() && valid_domain(&site.domain),
            "自建站需要 REALITY 协议及有效域名"
        );
        ensure!(
            site.internal_port >= defaults::SITE_INTERNAL_PORT_MIN,
            "网站内部 TLS 端口必须大于等于 1024"
        );
        ensure!(
            valid_label(&site.title),
            "网站标题不能为空或超过 128 个字符，且不能包含控制字符"
        );
        ensure!(valid_text(&site.description), "网站描述不能包含控制字符");
        check_web_cert(&site.cert)?;
        if let Some(id) = &site.last_content_backup {
            ensure!(valid_backup_id(id), "网站备份 ID 无效");
        }
        let dest = defaults::site_dest(site.internal_port);
        ensure!(
            self.reality.sni == site.domain && self.reality.dest == dest,
            "自建站启用时 REALITY 目标必须为 {dest}，SNI 必须为网站域名"
        );
        Ok(())
    }

    fn check_tls(&self) -> Result<()> {
        ensure!(
            !self.vmess_tls || self.has(Protocol::VmessWs),
            "VMess TLS 仅适用于 VMess-WS"
        );
        if let Some(host) = &self.vmess_host {
            ensure!(valid_domain(host), "VMess Host 域名无效");
        }
        let Some(tls) = &self.tls else {
            ensure!(!self.needs_cert(), "当前协议需要代理 TLS 证书");
            return Ok(());
        };
        ensure!(self.needs_cert(), "当前协议无需代理 TLS 证书");
        match &tls.mode {
            ProxyCertMode::SelfSigned { sni } => {
                ensure!(valid_domain(sni), "自签证书域名无效");
                ensure!(tls.pinned, "自签证书必须由客户端固定指纹");
            }
            ProxyCertMode::Acme { domain, .. } => {
                ensure!(valid_domain(domain), "证书域名无效");
            }
            ProxyCertMode::Custom { domain, cert, key } => {
                ensure!(valid_domain(domain), "证书域名无效");
                ensure!(absolute(cert) && absolute(key), "证书路径必须为绝对路径");
            }
        }
        Ok(())
    }

    fn check_hy2(&self) -> Result<()> {
        let hy2 = &self.hy2;
        if let Some(hop) = hy2.hop {
            ensure!(
                hop.start >= defaults::HOP_MIN_START && hop.start < hop.end,
                "跳跃端口范围无效"
            );
        }
        for mbps in [hy2.up_mbps, hy2.down_mbps].into_iter().flatten() {
            ensure!(
                defaults::HY2_MBPS.contains(&mbps),
                "Hysteria2 带宽必须为 1–10000 的整数 Mbps"
            );
        }
        let has_mbps = hy2.up_mbps.is_some() || hy2.down_mbps.is_some();
        if hy2.profile == Some(Hy2Profile::Measured) {
            ensure!(
                hy2.up_mbps.is_some() && hy2.down_mbps.is_some(),
                "measured 需要 --up 和 --down"
            );
        } else {
            ensure!(!has_mbps, "仅 measured 档位可设置带宽");
        }
        if self.core_of(Protocol::Hysteria2) == Some(Core::Xray) {
            ensure!(
                hy2.profile.is_none(),
                "Xray 承载的 Hysteria2 不支持带宽调优，请改用 sing-box 承载"
            );
            ensure!(
                self.resource_profile == ResourceProfile::Balanced,
                "Xray 承载的 Hysteria2 不支持资源调优，请改用 sing-box 承载"
            );
        }
        Ok(())
    }

    fn check_subscription(&self) -> Result<()> {
        let Some(sub) = &self.subscription else {
            return Ok(());
        };
        ensure!(sub.port != 0, "订阅端口无效");
        match &sub.mode {
            SubscriptionMode::Site => {
                ensure!(
                    self.site_active().is_some(),
                    "没有可复用的自建站，请使用 --mode ip --address IP，或 --mode standalone --domain 域名 --tls cf|http|custom"
                );
                ensure!(
                    sub.port == self.site_public_port(),
                    "当前变更会改变订阅 URL 端口；请先关闭订阅，完成端口调整后重新启用并更新客户端 URL"
                );
            }
            SubscriptionMode::Ip { address } => check_subscription_ip(address)?,
            SubscriptionMode::Standalone {
                domain,
                cert,
                http01_port80,
            } => {
                ensure!(valid_domain(domain), "订阅域名无效");
                ensure!(
                    *http01_port80 == (*cert == WebCert::Http01),
                    "订阅证书方式无效"
                );
                check_web_cert(cert)?;
            }
        }
        Ok(())
    }

    fn check_routing(&self) -> Result<()> {
        for cidr in &self.routing.own_cidrs {
            ensure!(valid_cidr(cidr), "本机地址列表格式无效: {cidr}");
        }
        Ok(())
    }

    fn check_versions(&self) -> Result<()> {
        let v = &self.versions;
        for version in [&v.singbox, &v.xray, &v.singbox_pin, &v.xray_pin]
            .into_iter()
            .flatten()
        {
            ensure!(valid_version(version), "内核版本无效: {version}");
        }
        Ok(())
    }
}

/// `schema` must be the current one; newer files come from a newer program.
pub fn check_schema(schema: u32) -> Result<()> {
    ensure!(
        schema <= SCHEMA,
        "配置由更新版本的 Onebox 写入（schema {schema}），请先更新程序"
    );
    ensure!(schema == SCHEMA, "配置 schema 无效: {schema}");
    Ok(())
}

fn check_web_cert(cert: &WebCert) -> Result<()> {
    if let WebCert::Custom { cert, key } = cert {
        ensure!(absolute(cert) && absolute(key), "证书路径必须为绝对路径");
    }
    Ok(())
}

/// Subscription address rules (spec G §2.3 `parse_address`).
pub fn check_subscription_ip(address: &IpAddr) -> Result<()> {
    ensure!(
        !address.is_unspecified() && !address.is_multicast(),
        "订阅地址不能是未指定地址或组播地址"
    );
    if let IpAddr::V6(v6) = address {
        ensure!(
            v6.to_ipv4_mapped().is_none(),
            "订阅地址应使用 IPv4 形式，不能是 IPv4 映射的 IPv6 地址"
        );
    }
    Ok(())
}

/// Lower-case DNS name (IP literals rejected), see `sys::text::valid_domain`.
pub fn valid_domain(s: &str) -> bool {
    crate::sys::text::valid_domain(s)
}

/// No control characters (prompts and option values are sanitized the same way).
pub fn valid_text(s: &str) -> bool {
    !s.chars().any(char::is_control)
}

/// Non-empty, bounded, printable label (node name, site title).
pub fn valid_label(s: &str) -> bool {
    !s.trim().is_empty() && s.chars().count() <= MAX_LABEL_CHARS && valid_text(s)
}

/// Core version or pin: `1.12.0`, `v26.3.27`, `1.13.0-beta.1`.
pub fn valid_version(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+' | b'_'))
}

/// `ip/prefix` with a prefix that fits the address family.
pub fn valid_cidr(s: &str) -> bool {
    let Some((ip, prefix)) = s.split_once('/') else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => prefix <= 32,
        Ok(IpAddr::V6(_)) => prefix <= 128,
        Err(_) => false,
    }
}

fn valid_backup_id(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn absolute(path: &Path) -> bool {
    path.is_absolute() && path.to_str().is_some_and(valid_text)
}

#[cfg(test)]
mod tests;
