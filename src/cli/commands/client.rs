//! Client exports: `client|config [格式]`, `qr`, and the hidden `render`
//! used by tests and golden comparisons.
//!
//! Changes from v2 (spec C §2.1, §2.4, B-9.1#18): QR codes are drawn in
//! process (no `qrencode`), each followed by its link; exports end with
//! exactly one newline (v2 printed two); the format menu lists only the
//! formats the node supports; `render` is read-only (a v2 state is migrated
//! in memory) and rejects extra words.

use crate::cli::args::{ArgSpec, CommandSpec, Group, Matches, Root};
use crate::cli::session::{with_system, Session};
use crate::ctx::Ctx;
use crate::domain::protocol::{ClientFormat, Core, Protocol};
use crate::error::{Error, Result};
use crate::render::{self, NodeSpec};

pub const ANYTLS_REALITY_NOTICE: &str =
    "此格式不包含 AnyTLS-REALITY，请使用 singbox 远程配置或完整 JSON";
const NO_LINKS: &str = "没有可生成二维码的通用链接，请使用 sing-box 配置";
const RENDER_USAGE: &str = "render 格式为 server/inbound/outbound/probe";

pub const CLIENT: CommandSpec = CommandSpec::new(
    "client",
    Group::Client,
    "导出客户端配置到标准输出（另见 qr）",
)
.aliases(&["config"])
.usage(&["client [mihomo|provider|singbox|singbox-notun|xray|links|sub|qr]"])
.args(&[ArgSpec::optional("格式", "省略时交互选择")])
.root(Root::NotRequired)
.handler(client_command);

pub const QR: CommandSpec = CommandSpec::new("qr", Group::Client, "在终端显示分享链接二维码")
    .root(Root::NotRequired)
    .handler(qr_command);

pub const RENDER: CommandSpec = CommandSpec::new("render", Group::Hidden, "渲染内部配置（测试用）")
    .usage(&[
        "render server [singbox|xray]",
        "render inbound 协议",
        "render outbound 协议 [singbox|xray]",
        "render probe",
    ])
    .args(&[
        ArgSpec::optional("类型", "server / inbound / outbound / probe"),
        ArgSpec::optional("参数", "协议或内核").many(),
    ])
    .root(Root::NotRequired)
    .handler(render_command);

/// What `client` exports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Export {
    Format(ClientFormat),
    Qr,
}

impl Export {
    pub fn parse(text: &str) -> Result<Export> {
        match text {
            "qr" => Ok(Export::Qr),
            other => ClientFormat::parse(other).map(Export::Format),
        }
    }
}

fn client_command(ctx: &Ctx, m: &Matches) -> Result<()> {
    let export = m.positional(0).map(Export::parse).transpose()?;
    with_system(ctx, |s| client(s, export))
}

fn qr_command(ctx: &Ctx, _m: &Matches) -> Result<()> {
    with_system(ctx, |s| client(s, Some(Export::Qr)))
}

/// `client [格式]`: the chosen export on stdout (menu when not given).
pub fn client(session: &Session, export: Option<Export>) -> Result<()> {
    let loaded = session.load()?;
    let spec = NodeSpec::load(&loaded.config, &session.ctx.paths)?;
    let export = match export {
        Some(export) => export,
        None => match choose(session, &spec)? {
            Some(export) => export,
            None => return Ok(()),
        },
    };
    match export {
        Export::Qr => qr(session, &spec),
        Export::Format(format) => {
            let anytls = spec.inbound(Protocol::AnytlsReality).is_some();
            if anytls && !matches!(format, ClientFormat::Singbox | ClientFormat::SingboxNoTun) {
                session.info(ANYTLS_REALITY_NOTICE);
            }
            session.data(&render::client(&spec, format)?)
        }
    }
}

/// The exports a node supports, in menu order (QR codes with links).
pub fn exports(spec: &NodeSpec) -> Vec<Export> {
    const ORDER: [ClientFormat; 7] = [
        ClientFormat::Mihomo,
        ClientFormat::Provider,
        ClientFormat::Singbox,
        ClientFormat::SingboxNoTun,
        ClientFormat::Xray,
        ClientFormat::Links,
        ClientFormat::Base64,
    ];
    let formats = spec.formats();
    let mut out: Vec<Export> = ORDER
        .into_iter()
        .filter(|f| formats.contains(f))
        .map(Export::Format)
        .collect();
    if formats.contains(&ClientFormat::Links) {
        out.push(Export::Qr);
    }
    out
}

fn label(export: Export) -> String {
    match export {
        Export::Qr => "qr  终端二维码（每条分享链接一个）".to_owned(),
        Export::Format(ClientFormat::Base64) => format!("sub  {}", ClientFormat::Base64.title()),
        Export::Format(f) => format!("{}  {}", f.id(), f.title()),
    }
}

/// The format menu; the default is mihomo when supported, else sing-box.
fn choose(session: &Session, spec: &NodeSpec) -> Result<Option<Export>> {
    let exports = exports(spec);
    let items: Vec<String> = exports.iter().map(|e| label(*e)).collect();
    let default = [ClientFormat::Mihomo, ClientFormat::Singbox]
        .into_iter()
        .find_map(|f| exports.iter().position(|e| *e == Export::Format(f)))
        .unwrap_or(0);
    let choice = session
        .ui()
        .select("选择客户端配置格式", &items, default, true)?;
    Ok(choice.and_then(|i| exports.get(i).copied()))
}

/// QR codes of every share link, each followed by the link. On a terminal
/// the codes carry explicit colors, so light themes do not invert them.
fn qr(session: &Session, spec: &NodeSpec) -> Result<()> {
    if spec.for_format(ClientFormat::Links).is_empty() {
        return Err(Error::msg(NO_LINKS));
    }
    let links = render::client(spec, ClientFormat::Links)?;
    let color = crate::ui::out::data_color_enabled();
    let mut blocks = Vec::new();
    for link in links.lines().filter(|l| !l.trim().is_empty()) {
        blocks.push(format!("{}{link}", crate::ui::qr::render(link, color)?));
    }
    session.data(&blocks.join("\n\n"))
}

/// What `render` prints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RenderTarget {
    Server(Core),
    Inbound(Protocol),
    Outbound(Protocol, Core),
    Probe,
}

/// Parse the `render` words (v2 defaults: `server`, core sing-box).
pub fn render_target(words: &[String]) -> Result<RenderTarget> {
    let word = |i: usize| words.get(i).map(String::as_str);
    let core = |i: usize| word(i).map_or(Ok(Core::Singbox), str::parse);
    let protocol =
        || -> Result<Protocol> { word(1).ok_or_else(|| Error::msg("需要协议"))?.parse() };
    let (target, used) = match word(0).unwrap_or("server") {
        "server" => (RenderTarget::Server(core(1)?), 2),
        "inbound" => (RenderTarget::Inbound(protocol()?), 2),
        "outbound" => (RenderTarget::Outbound(protocol()?, core(2)?), 3),
        "probe" => (RenderTarget::Probe, 1),
        _ => return Err(Error::msg(RENDER_USAGE)),
    };
    ensure!(words.len() <= used, "{RENDER_USAGE}");
    Ok(target)
}

fn render_command(ctx: &Ctx, m: &Matches) -> Result<()> {
    let target = render_target(&m.positionals)?;
    with_system(ctx, |s| render_out(s, target))
}

/// `render …`: pretty JSON on stdout.
pub fn render_out(session: &Session, target: RenderTarget) -> Result<()> {
    let loaded = session.load()?;
    let cfg = &loaded.config;
    let paths = &session.ctx.paths;
    let text = match target {
        RenderTarget::Server(core) => render::server_text(&NodeSpec::new(cfg, paths, None)?, core)?,
        RenderTarget::Inbound(p) => {
            render::pretty(&render::inbound(&NodeSpec::new(cfg, paths, None)?, p)?)?
        }
        RenderTarget::Outbound(p, core) => {
            render::pretty(&render::outbound(&NodeSpec::load(cfg, paths)?, p, core)?)?
        }
        RenderTarget::Probe => {
            render::probe::bundle(&NodeSpec::load(cfg, paths)?, false)?.to_json()?
        }
    };
    session.data(&text)
}

#[cfg(test)]
mod tests;
