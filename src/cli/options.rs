//! Option specs shared by several commands and their typed parsing.
//!
//! Every value is turned into the planners' typed requests here, with v2's
//! messages where v2 had one. Commands declare only the options they use
//! (the parser rejects the rest).
//!
//! Changes from v2 (spec B §2.5, §3.3.2, B-9.1#7/#19): a bad port, preset or
//! bandwidth gives a Chinese message instead of Rust's `ParseIntError`
//! text; `--preset N` together with `--protocols` is an error unless `N`
//! is 7 (custom), where v2 silently ignored the preset; `--site-title`
//! without `--reality-site` and `--cert`/`--key` without `--tls custom` are
//! errors instead of dormant settings; relative certificate paths are made
//! absolute against the working directory.

use super::args::{Matches, OptSpec};
use crate::domain::config::{AcmeMethod, Host, HostPort, PortRange, SiteConfig, WebCert};
use crate::domain::plan::{OwnSite, ProxyCertChoice, RealityChoice};
use crate::domain::presets;
use crate::domain::protocol::{Core, Protocol};
use crate::error::{Error, Result};
use std::path::{Path, PathBuf};

pub const PRESET: OptSpec = OptSpec::value(
    "preset",
    "1-7",
    "协议组合编号；7 为自定义（无人值守时配合 --protocols）",
);
pub const PROTOCOLS: OptSpec = OptSpec::value("protocols", "列表", "协议列表，逗号或空格分隔");
pub const CORE: OptSpec =
    OptSpec::value("core", "singbox|xray", "两种内核都支持的协议优先使用的内核");
pub const ADDR: OptSpec = OptSpec::value(
    "addr",
    "IP或域名",
    "客户端连接地址（默认自动检测公网 IPv4，其次 IPv6）",
);
pub const NAME: OptSpec = OptSpec::value("name", "名称", "节点名称前缀（默认 onebox）");
pub const PORTS: OptSpec = OptSpec::value("port", "协议=端口", "指定协议端口").repeated();
pub const SNI: OptSpec = OptSpec::value(
    "sni",
    "域名",
    "REALITY 与 ShadowTLS 的伪装域名（握手目标 域名:443）",
);
pub const REALITY_DEST: OptSpec = OptSpec::value(
    "reality-dest",
    "主机:端口",
    "单独指定 REALITY 握手目标（SNI 不变）",
);
pub const REALITY_SITE: OptSpec = OptSpec::value(
    "reality-site",
    "域名",
    "以自有域名网站作为 REALITY 目标（域名需解析到本机）",
);
pub const SITE_TITLE: OptSpec =
    OptSpec::value("site-title", "标题", "自动生成主页的标题（默认 山间手记）");
pub const SITE_HTTPS: OptSpec = OptSpec::value(
    "site-https",
    "on|off",
    "网站的 HTTPS 443 入口（新建网站默认 on，已有网站保持原设置）",
);
pub const TLS: OptSpec = OptSpec::value(
    "tls",
    "self|acme|cf|custom",
    "代理证书：自签 / HTTP-01（http 同 acme）/ Cloudflare DNS / 自备",
);
pub const DOMAIN: OptSpec = OptSpec::value(
    "domain",
    "域名",
    "证书域名；不使用域名证书时作为 VMess-WS 客户端发送的 Host",
);
pub const CERT: OptSpec = OptSpec::value("cert", "文件", "自备证书的完整链");
pub const KEY: OptSpec = OptSpec::value("key", "文件", "自备证书的私钥（未加密）");
pub const HY2_HOP: OptSpec = OptSpec::value(
    "hy2-hop",
    "起-止",
    "Hysteria2 UDP 端口跳跃范围（起始 ≥ 1024）",
);
pub const HY2_OBFS: OptSpec = OptSpec::flag("hy2-obfs", "Hysteria2 启用 salamander 混淆");
pub const HY2_CORE: OptSpec = OptSpec::value(
    "hy2-core",
    "singbox|xray",
    "Hysteria2 的服务端内核（默认 sing-box）",
);
pub const SINGBOX_VERSION: OptSpec = OptSpec::value(
    "singbox-version",
    "版本|latest",
    "固定 sing-box 版本（默认最新稳定版）",
);
pub const XRAY_VERSION: OptSpec = OptSpec::value(
    "xray-version",
    "版本|latest",
    "固定 Xray 版本（默认 26.3.27）",
);
pub const NO_BBR: OptSpec = OptSpec::flag("no-bbr", "安装结束后不询问启用 BBR");
pub const FORCE: OptSpec = OptSpec::flag(
    "force",
    "已安装时允许 -y 重装（生成全新凭据并清除订阅设备）",
);
pub const JSON: OptSpec = OptSpec::flag("json", "仅预演：输出 JSON");
pub const WEB_TLS: OptSpec = OptSpec::value(
    "tls",
    "http|cf|custom",
    "证书方式：HTTP-01（默认）/ Cloudflare DNS / 自备",
);

/// Whether any of `names` was given (flags or values).
pub fn any(m: &Matches, names: &[&str]) -> bool {
    names
        .iter()
        .any(|n| m.flag(n) || m.value(n).is_some() || !m.values(n).is_empty())
}

/// A TCP/UDP port number (`1..=65535`).
pub fn port(text: &str) -> Result<u16> {
    let value: u16 = text
        .trim()
        .parse()
        .map_err(|_| Error::msg(format!("端口无效: {text}")))?;
    ensure!(value != 0, "端口不能为 0");
    Ok(value)
}

/// `--port P=N` values in argument order.
pub fn ports(m: &Matches) -> Result<Vec<(Protocol, u16)>> {
    let mut out: Vec<(Protocol, u16)> = Vec::new();
    for value in m.values("port") {
        let (protocol, number) = value
            .split_once('=')
            .ok_or_else(|| Error::msg("--port 格式为 协议=端口"))?;
        let number = port(number)?;
        let protocol: Protocol = protocol.trim().parse()?;
        ensure!(!out.iter().any(|(p, _)| *p == protocol), "重复指定协议端口");
        out.push((protocol, number));
    }
    Ok(out)
}

/// `--preset N`.
pub fn preset(m: &Matches) -> Result<Option<u32>> {
    m.value("preset")
        .map(|v| {
            v.trim()
                .parse::<u32>()
                .map_err(|_| Error::msg("预设应为 1–7，7 为自定义协议组合"))
        })
        .transpose()
}

/// `--protocols a,b,…` in canonical order.
pub fn protocols(m: &Matches) -> Result<Option<Vec<Protocol>>> {
    m.value("protocols")
        .map(presets::parse_protocols)
        .transpose()
}

/// A core option (`--core`, `--hy2-core`).
pub fn core(m: &Matches, name: &str) -> Result<Option<Core>> {
    m.value(name).map(str::parse).transpose()
}

/// A public address (`--addr`).
pub fn host(text: &str) -> Result<Host> {
    text.parse::<Host>()
        .map_err(|_| Error::msg("服务器地址应为 IP 或域名"))
}

/// `on` / `off`.
pub fn on_off(value: &str, name: &str) -> Result<bool> {
    match value {
        "on" => Ok(true),
        "off" => Ok(false),
        _ => Err(Error::msg(format!("{name} 应为 on/off"))),
    }
}

/// `--hy2-hop A-B`.
pub fn hop(m: &Matches) -> Result<Option<PortRange>> {
    m.value("hy2-hop").map(str::parse).transpose()
}

/// A version pin: the option, else the v2 environment default (G34).
pub fn version_pin(m: &Matches, name: &str, env: Option<String>) -> Option<String> {
    m.value(name).map(str::to_owned).or(env)
}

/// An absolute path (relative ones are taken from the working directory).
pub fn absolute(path: &str) -> PathBuf {
    let path = Path::new(path);
    if path.is_absolute() {
        return path.to_path_buf();
    }
    std::env::current_dir()
        .map(|cwd| cwd.join(path))
        .unwrap_or_else(|_| path.to_path_buf())
}

/// The proxy certificate options (`--tls --domain --cert --key`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CertArgs {
    pub choice: Option<ProxyCertChoice>,
    /// `--domain` without a domain certificate: the plain VMess-WS `Host`.
    pub vmess_host: Option<String>,
}

/// Parse the proxy certificate options. `default_domain` fills a missing
/// `--domain` for a domain certificate (`cert set` keeps the current one).
pub fn cert_args(m: &Matches, default_domain: Option<&str>) -> Result<CertArgs> {
    let domain = m.value("domain").map(str::trim).filter(|d| !d.is_empty());
    let files = (m.value("cert"), m.value("key"));
    let Some(method) = m.value("tls") else {
        ensure!(files == (None, None), "--cert/--key 需要 --tls custom");
        return Ok(CertArgs {
            choice: None,
            vmess_host: domain.map(str::to_owned),
        });
    };
    proxy_choice(method, domain.or(default_domain), files)
}

fn proxy_choice(
    method: &str,
    domain: Option<&str>,
    files: (Option<&str>, Option<&str>),
) -> Result<CertArgs> {
    let need_domain = || -> Result<String> {
        domain
            .map(str::to_owned)
            .ok_or_else(|| Error::msg(format!("--tls {method} 需要 --domain 域名")))
    };
    let acme = |method: AcmeMethod| -> Result<ProxyCertChoice> {
        Ok(ProxyCertChoice::Acme {
            domain: need_domain()?,
            method,
        })
    };
    if method != "custom" {
        ensure!(files == (None, None), "--cert/--key 需要 --tls custom");
    }
    let choice = match method {
        "self" => {
            return Ok(CertArgs {
                choice: Some(ProxyCertChoice::SelfSigned),
                vmess_host: domain.map(str::to_owned),
            })
        }
        "acme" | "http" => acme(AcmeMethod::Http01)?,
        "cf" => acme(AcmeMethod::Cloudflare)?,
        "custom" => {
            let (Some(cert), Some(key)) = files else {
                bail!("自备证书需要 --cert 和 --key");
            };
            ProxyCertChoice::Custom {
                domain: need_domain()?,
                cert: absolute(cert),
                key: absolute(key),
            }
        }
        _ => bail!("--tls 应为 self/acme/cf/custom"),
    };
    Ok(CertArgs {
        choice: Some(choice),
        vmess_host: None,
    })
}

/// A public web certificate (`--tls http|cf|custom --cert --key`; the
/// default is HTTP-01). Self-signed is refused: browsers and subscription
/// clients must trust the endpoint.
pub fn web_cert(m: &Matches) -> Result<WebCert> {
    web_cert_from(m.value("tls"), m.value("cert"), m.value("key"))
}

pub fn web_cert_from(
    method: Option<&str>,
    cert: Option<&str>,
    key: Option<&str>,
) -> Result<WebCert> {
    let method = method.unwrap_or("http");
    if method != "custom" {
        ensure!(
            cert.is_none() && key.is_none(),
            "--cert/--key 需要 --tls custom"
        );
    }
    match method {
        "http" | "acme" => Ok(WebCert::Http01),
        "cf" => Ok(WebCert::Cloudflare),
        "custom" => match (cert, key) {
            (Some(cert), Some(key)) => Ok(WebCert::Custom {
                cert: absolute(cert),
                key: absolute(key),
            }),
            _ => bail!("自备证书需要 --cert 和 --key"),
        },
        "self" => bail!("{}", crate::cert::PUBLIC_REQUIRED),
        _ => bail!("--tls 应为 http/cf/custom"),
    }
}

/// The REALITY / ShadowTLS handshake options.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RealityArgs {
    pub choice: RealityChoice,
    /// `--reality-dest` given together with `--sni`: applied after it.
    pub dest_after_sni: Option<HostPort>,
    /// `--sni` also moves the ShadowTLS handshake (v2).
    pub shadowtls_sni: Option<String>,
    /// `--site-https` without `--reality-site` (toggles an existing site).
    pub site_https: Option<bool>,
}

impl RealityArgs {
    /// Nothing was asked for.
    pub fn is_empty(&self) -> bool {
        *self == RealityArgs::default()
    }
}

/// Parse `--sni --reality-dest --reality-site --site-title --site-https`.
/// `site` is the node's current website: `--reality-site` keeps its
/// certificate method and HTTPS entrance (unless `--site-https` is given);
/// a newly enabled site uses HTTP-01 with the entrance on.
pub fn reality_args(m: &Matches, site: Option<&SiteConfig>) -> Result<RealityArgs> {
    let sni = m.value("sni");
    let dest = m.value("reality-dest").map(handshake_target).transpose()?;
    let https = m
        .value("site-https")
        .map(|v| on_off(v, "--site-https"))
        .transpose()?;
    if let Some(domain) = m.value("reality-site") {
        ensure!(
            sni.is_none() && dest.is_none(),
            "--reality-site 不能与 --sni/--reality-dest 同时指定"
        );
        let site = OwnSite {
            domain: domain.to_owned(),
            title: m.value("site-title").map(str::to_owned),
            https_entry: https.or(site.map(|s| s.https_entry)).unwrap_or(true),
            cert: site.map_or(WebCert::Http01, |s| s.cert.clone()),
        };
        return Ok(RealityArgs {
            choice: RealityChoice::OwnSite(site),
            ..RealityArgs::default()
        });
    }
    ensure!(
        m.value("site-title").is_none(),
        "--site-title 需要与 --reality-site 一起使用"
    );
    let mut args = RealityArgs {
        site_https: https,
        ..RealityArgs::default()
    };
    match (sni, dest) {
        (Some(sni), dest) => {
            args.choice = RealityChoice::Custom(sni.to_owned());
            args.shadowtls_sni = Some(sni.to_owned());
            args.dest_after_sni = dest;
        }
        (None, Some(dest)) => args.choice = RealityChoice::Dest(dest),
        (None, None) => {}
    }
    Ok(args)
}

/// `host:port` handshake target (v2 messages).
pub fn handshake_target(text: &str) -> Result<HostPort> {
    ensure!(text.contains(':'), "握手目标格式为 主机:端口");
    text.parse::<HostPort>()
        .map_err(|_| Error::msg("握手目标无效"))
}

#[cfg(test)]
mod tests;
