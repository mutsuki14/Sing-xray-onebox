//! `info`: the node information card.
//!
//! Keeps every line v2 printed (scripts read `地址:`, `REALITY SNI: … 公钥:
//! … ShortID: …`, `UUID:`, `密码:`) and adds a readable card: node and
//! address families, cores with versions and state, a protocol table
//! (core, transport, port, clients), the REALITY / ShadowTLS / TLS summary,
//! every credential a client may need, and next steps.
//!
//! Changes from v2 (spec B §2.6): the protocol lines became a table; the
//! card shows the handshake target, certificate mode, Shadowsocks /
//! ShadowTLS / Hysteria2 secrets and the clash API secret (the control
//! panel key `docs/clients.md` refers to), and the core state.

use crate::cli::args::{CommandSpec, Group, Matches, Root};
use crate::cli::session::{with_system, Session};
use crate::ctx::Ctx;
use crate::domain::config::{NodeConfig, ProxyCertMode};
use crate::domain::protocol::{ClientFormat, Core, Protocol};
use crate::error::Result;
use crate::ui::out::format_table;
use crate::VERSION;

pub const INFO: CommandSpec = CommandSpec::new("info", Group::Client, "节点信息、凭据与导出方式")
    .root(Root::NotRequired)
    .handler(info_command);

fn info_command(ctx: &Ctx, _m: &Matches) -> Result<()> {
    with_system(ctx, show)
}

/// Print the card of the installed node.
pub fn show(session: &Session) -> Result<()> {
    let loaded = session.load()?;
    session.data(&card(session, &loaded.config))
}

/// The client kinds v2 listed per protocol.
const CLIENT_KINDS: [(&str, ClientFormat); 4] = [
    ("singbox", ClientFormat::Singbox),
    ("xray", ClientFormat::Xray),
    ("mihomo", ClientFormat::Mihomo),
    ("link", ClientFormat::Links),
];

/// Live facts the card shows next to the configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreState {
    pub core: Core,
    pub version: Option<String>,
    pub running: bool,
}

/// The card for `cfg` with the cores' live state.
pub fn card(session: &Session, cfg: &NodeConfig) -> String {
    let cores: Vec<CoreState> = cfg
        .cores()
        .into_iter()
        .map(|core| CoreState {
            core,
            version: cfg.versions.installed(core).map(str::to_owned),
            running: session.live.running(core.service()),
        })
        .collect();
    render(cfg, &cores, &session.ctx.paths.clients().to_string_lossy())
}

/// The card text (pure).
pub fn render(cfg: &NodeConfig, cores: &[CoreState], client_dir: &str) -> String {
    let mut lines = vec![
        format!("Onebox {VERSION}  地址: {}", cfg.server.addr),
        identity_line(cfg),
        format!("内核: {}", core_summary(cores)),
        String::new(),
        protocol_table(cfg),
        String::new(),
    ];
    lines.extend(handshake_lines(cfg));
    lines.extend(credential_lines(cfg));
    if cfg.has(Protocol::AnytlsReality) {
        lines.push("AnyTLS-REALITY 请使用 sing-box 完整配置或远程配置订阅。".to_owned());
    }
    lines.push(format!("配置目录: {client_dir}"));
    lines.push("导出: onebox client singbox | mihomo | links".to_owned());
    lines.push("订阅: onebox subscription info".to_owned());
    lines.join("\n")
}

fn identity_line(cfg: &NodeConfig) -> String {
    let v4 = cfg
        .server
        .ipv4
        .map_or_else(|| "无".to_owned(), |ip| ip.to_string());
    let v6 = cfg
        .server
        .ipv6
        .map_or_else(|| "无".to_owned(), |ip| ip.to_string());
    format!("节点: {} · IPv4 {v4} · IPv6 {v6}", cfg.node_name)
}

fn core_summary(cores: &[CoreState]) -> String {
    cores
        .iter()
        .map(|c| {
            let version = c.version.as_deref().unwrap_or("版本未知");
            let state = if c.running { "运行中" } else { "已停止" };
            format!("{} {version}（{state}）", c.core.title())
        })
        .collect::<Vec<_>>()
        .join(" · ")
}

/// Clients able to import `protocol` (v2 ids).
pub fn clients(protocol: Protocol) -> String {
    CLIENT_KINDS
        .iter()
        .filter(|(_, f)| f.supports(protocol))
        .map(|(id, _)| *id)
        .collect::<Vec<_>>()
        .join(", ")
}

fn protocol_table(cfg: &NodeConfig) -> String {
    let rows: Vec<Vec<String>> = cfg
        .inbounds
        .iter()
        .map(|i| {
            vec![
                i.protocol.title().to_owned(),
                i.core.id().to_owned(),
                i.protocol.transport().id().to_owned(),
                i.port.to_string(),
                clients(i.protocol),
            ]
        })
        .collect();
    format_table(&["协议", "内核", "传输", "端口", "客户端"], &rows)
}

fn handshake_lines(cfg: &NodeConfig) -> Vec<String> {
    let mut lines = Vec::new();
    if let (true, Some(keys)) = (cfg.any_reality(), &cfg.creds.reality) {
        lines.push(format!(
            "REALITY SNI: {}  公钥: {}  ShortID: {}",
            cfg.reality.sni, keys.public_key, keys.short_id
        ));
        let target = match cfg.site_active() {
            Some(site) => format!("自有网站 {}（{}）", site.domain, cfg.reality.dest),
            None => cfg.reality.dest.to_string(),
        };
        lines.push(format!("REALITY 目标: {target}"));
    }
    if cfg.has(Protocol::Shadowtls) {
        lines.push(format!(
            "ShadowTLS 握手: {}（{}）",
            cfg.shadowtls.sni,
            cfg.shadowtls.effective_dest()
        ));
    }
    if let Some(tls) = cfg.tls.as_ref().filter(|_| cfg.needs_cert()) {
        let mode = match &tls.mode {
            ProxyCertMode::SelfSigned { sni } => format!("自签证书 {sni}"),
            ProxyCertMode::Acme { domain, .. } => format!("Let's Encrypt {domain}"),
            ProxyCertMode::Custom { domain, .. } => format!("自备证书 {domain}"),
        };
        let pin = if tls.pinned {
            "，客户端固定证书指纹"
        } else {
            ""
        };
        lines.push(format!("TLS: {mode}{pin}"));
    }
    lines
}

fn credential_lines(cfg: &NodeConfig) -> Vec<String> {
    let c = &cfg.creds;
    let mut lines = vec![format!("UUID: {}", c.uuid), format!("密码: {}", c.password)];
    if cfg.has(Protocol::Shadowsocks) {
        lines.push(format!(
            "SS-2022 密钥: {}（{}）",
            c.ss_password, c.ss_method
        ));
    }
    if cfg.has(Protocol::Shadowtls) {
        lines.push(format!("ShadowTLS 密码: {}", c.shadowtls_password));
    }
    if cfg.has(Protocol::Hysteria2) && cfg.hy2.obfs {
        lines.push(format!("Hysteria2 混淆密码: {}", c.hy2_obfs_password));
    }
    lines.push(format!("控制面板密钥: {}", c.clash_secret));
    lines
}

/// What to do next with a node (after install, in the menu).
pub fn next_steps(cfg: &NodeConfig) -> String {
    let supports = |f: ClientFormat| cfg.protocols().any(|p| f.supports(p));
    let mut steps: Vec<(&str, &str)> = Vec::new();
    if supports(ClientFormat::Mihomo) {
        steps.push(("onebox client mihomo", "导出 mihomo / Clash Meta 配置"));
    }
    if supports(ClientFormat::Singbox) {
        steps.push(("onebox client singbox", "导出 sing-box 配置"));
    }
    if supports(ClientFormat::Links) {
        steps.push(("onebox qr", "在终端显示分享链接二维码"));
    }
    if cfg.subscription.is_some() {
        steps.push(("onebox subscription info", "查看订阅地址与设备"));
    } else {
        steps.push((
            "onebox subscription enable",
            "启用远程订阅，客户端可自动更新",
        ));
    }
    steps.push(("onebox", "打开管理菜单"));
    let width = steps
        .iter()
        .map(|(c, _)| c.chars().count())
        .max()
        .unwrap_or(0);
    let mut lines = vec!["下一步:".to_owned()];
    lines.extend(
        steps
            .iter()
            .map(|(cmd, what)| format!("  {cmd:<width$}  {what}")),
    );
    lines.join("\n")
}

#[cfg(test)]
mod tests;
