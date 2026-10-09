//! Subscription URLs and the text the CLI prints about them (spec G §2.4,
//! §2.5): the endpoint, per-format URLs, the sing-box import link, the
//! device URL block and `subscription info`.
//!
//! Everything here is derived from the node configuration — never from
//! `published.json` — so the URLs of a new device are complete even when
//! no snapshot exists yet.
//!
//! Changes from v2: the URL block also prints the raw token and lists every
//! format the configuration supports (v2 listed only formats found in
//! `published.json` and lost the token when that file was missing,
//! G-8.1#1); `info` shows creation times as UTC dates instead of raw Unix
//! seconds; the plaintext warning goes to stderr as a warning.

use super::devices::NewDevice;
use super::snapshot::supported_formats;
use crate::domain::config::{Device, NodeConfig, SubscriptionMode};
use crate::domain::protocol::ClientFormat;
use crate::sys::text::url_encode;
use crate::sys::time::format_utc;
use std::net::IpAddr;

/// v2's warning for plain-HTTP (ip-mode) subscriptions.
pub const PLAINTEXT_WARNING: &str = "IP 订阅使用 HTTP 明文传输，链路上的第三方可能读取订阅令牌和节点凭据；需要加密时可选择域名 HTTPS 模式。";
/// Closing line of every URL block (v2 text).
pub const TOKEN_NOTICE: &str =
    "令牌仅显示一次，请保存；设备撤销只阻止后续下载，不会收回已获取的代理凭据。";
/// Last line of `subscription info` (v2 text).
pub const FORMATS_LINE: &str = "格式: base64 / mihomo / provider / singbox / singbox-notun / xray；兼容性取决于已启用协议。设备令牌仅在创建或重置时显示。";
pub const UNCHANGED: &str = "订阅已启用；已有设备 URL 保持不变。";
pub const DISABLED: &str = "订阅已关闭；所有 URL 暂停访问。";
pub const REVOKED: &str = "设备订阅已撤销；已下载的代理凭据不受影响。";
pub const IP_RENEW: &str = "IP 订阅使用 HTTP，无需续期证书。";

/// `scheme://host[:port]` of the enabled subscription (`None` when off):
/// ip → `http`, default port 80, IPv6 bracketed; site and standalone →
/// `https`, default port 443. The port is omitted when it is the default.
pub fn endpoint(cfg: &NodeConfig) -> Option<String> {
    let sub = cfg.subscription.as_ref()?;
    let (scheme, default_port, host) = match &sub.mode {
        SubscriptionMode::Ip { address } => ("http", 80, ip_host(*address)),
        SubscriptionMode::Site => ("https", 443, cfg.site_active()?.domain.clone()),
        SubscriptionMode::Standalone { domain, .. } => ("https", 443, domain.clone()),
    };
    let suffix = match sub.port {
        port if port == default_port => String::new(),
        port => format!(":{port}"),
    };
    Some(format!("{scheme}://{host}{suffix}"))
}

/// An IP literal as URL host: canonical (mapped IPv6 shown as IPv4) and
/// IPv6 in brackets.
fn ip_host(address: IpAddr) -> String {
    match address.to_canonical() {
        IpAddr::V6(v6) => format!("[{v6}]"),
        IpAddr::V4(v4) => v4.to_string(),
    }
}

/// Whether the subscription is served over plain HTTP (ip mode).
pub fn plaintext(cfg: &NodeConfig) -> bool {
    matches!(
        cfg.subscription.as_ref().map(|s| &s.mode),
        Some(SubscriptionMode::Ip { .. })
    )
}

/// `{endpoint}/sub/{token}/{format}` for every supported remote format,
/// in v2 order. Empty when the subscription is off.
pub fn urls(cfg: &NodeConfig, token: &str) -> Vec<(ClientFormat, String)> {
    let Some(endpoint) = endpoint(cfg) else {
        return Vec::new();
    };
    supported_formats(cfg)
        .into_iter()
        .map(|f| (f, format!("{endpoint}/sub/{token}/{}", f.id())))
        .collect()
}

/// The one-tap sing-box import link for a `singbox` URL.
pub fn singbox_import_link(url: &str) -> String {
    format!(
        "sing-box://import-remote-profile?url={}#onebox",
        url_encode(url)
    )
}

/// The lines printed for a created or reset device (stdout): optional
/// `设备 ID`, the raw token, one URL per format, the sing-box import link,
/// then the one-time notice. The plaintext warning is separate
/// ([`warnings`]).
pub fn url_block(cfg: &NodeConfig, device: &NewDevice, with_id: bool) -> Vec<String> {
    let mut lines = Vec::new();
    if with_id {
        lines.push(format!("设备 ID: {}", device.id));
    }
    lines.push(format!("令牌: {}", device.token));
    let urls = urls(cfg, &device.token);
    for (format, url) in &urls {
        lines.push(format!("{format}: {url}"));
    }
    if let Some((_, url)) = urls.iter().find(|(f, _)| *f == ClientFormat::Singbox) {
        lines.push(format!("sing-box 导入: {}", singbox_import_link(url)));
    }
    lines.push(TOKEN_NOTICE.to_owned());
    lines
}

/// Warnings that accompany URLs of this configuration (stderr).
pub fn warnings(cfg: &NodeConfig) -> Vec<&'static str> {
    if plaintext(cfg) {
        vec![PLAINTEXT_WARNING]
    } else {
        Vec::new()
    }
}

/// What `subscription enable` reports when devices already exist.
pub fn enabled_message(old_endpoint: Option<&str>, cfg: &NodeConfig) -> String {
    let new = endpoint(cfg).unwrap_or_default();
    if old_endpoint == Some(new.as_str()) {
        UNCHANGED.to_owned()
    } else {
        format!(
            "订阅已启用；地址、端口或传输协议已改变，请把客户端已有订阅 URL 的入口改为 {new}，保留 /sub/ 后的令牌和格式；若已遗失旧 URL，可执行 subscription reset 设备ID 获取新链接。"
        )
    }
}

/// `subscription info` (stdout lines; the plaintext warning is separate).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubscriptionInfo {
    /// `ip` / `site` / `standalone`; `None` when off.
    pub mode: Option<&'static str>,
    pub endpoint: Option<String>,
    pub devices: Vec<Device>,
    /// Supported formats of the configuration.
    pub formats: Vec<ClientFormat>,
    pub plaintext: bool,
}

impl SubscriptionInfo {
    pub fn of(cfg: &NodeConfig, devices: Vec<Device>) -> SubscriptionInfo {
        SubscriptionInfo {
            mode: cfg.subscription.as_ref().map(|s| s.mode.id()),
            endpoint: endpoint(cfg),
            devices,
            formats: supported_formats(cfg),
            plaintext: plaintext(cfg),
        }
    }

    /// v2 layout: status line, one line per device, the formats line.
    pub fn lines(&self) -> Vec<String> {
        let head = match (self.mode, &self.endpoint) {
            (Some(mode), Some(endpoint)) => {
                format!("订阅: 启用；托管: {mode}；地址: {endpoint}")
            }
            _ => "订阅: 关闭".to_owned(),
        };
        let mut lines = vec![head];
        for d in &self.devices {
            lines.push(format!(
                "{}  {}  创建于 {}",
                d.id,
                d.name,
                format_utc(d.created)
            ));
        }
        lines.push(FORMATS_LINE.to_owned());
        lines
    }
}

#[cfg(test)]
mod tests;
