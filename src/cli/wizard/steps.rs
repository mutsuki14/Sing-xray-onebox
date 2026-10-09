//! The individual wizard steps. Each fills the part of [`InstallArgs`] the
//! command line left open; headers are part of the first question of a
//! step so they appear right above it.

use crate::cli::commands::install::{Detected, InstallArgs};
use crate::cli::options::{self as opt};
use crate::cli::session::Session;
use crate::domain::config::{AcmeMethod, NodeConfig, ProxyCertMode, SiteConfig, WebCert};
use crate::domain::plan::{OwnSite, ProtocolChoice, ProxyCertChoice, RealityChoice};
use crate::domain::presets::{self, Selection};
use crate::domain::protocol::{Core, Protocol};
use crate::domain::validate::{valid_domain, valid_label};
use crate::domain::{defaults, plan};
use crate::error::{Error, Result};
use crate::ui::out::format_table;
use crate::ui::Prompter;
use std::path::PathBuf;

/// Menu index of the custom preset (`7)`).
const CUSTOM_INDEX: usize = presets::CUSTOM as usize - 1;

fn header(step: usize, title: &str, explanation: &str) -> String {
    format!("步骤 {step}/5 · {title}\n{explanation}")
}

/// The protocols a choice selects (storage order).
pub fn selected(choice: &ProtocolChoice) -> Result<Vec<Protocol>> {
    match choice {
        ProtocolChoice::List(list) => Ok(presets::canonical(list)),
        ProtocolChoice::Preset(n) => match presets::select(*n)? {
            Selection::Preset(p) => Ok(p.protocols.to_vec()),
            Selection::Custom => Ok(Vec::new()),
        },
    }
}

/// Step 1: the protocol combination (asked unless given, custom included).
pub fn protocols(ui: &dyn Prompter, args: &mut InstallArgs) -> Result<Vec<Protocol>> {
    let custom = ProtocolChoice::Preset(u32::from(presets::CUSTOM));
    if let Some(choice) = args.protocols.as_ref().filter(|c| **c != custom) {
        return selected(choice);
    }
    let title = header(
        1,
        "协议组合",
        "选择要启用的协议；推荐 1（无需域名），套 CDN 选 5，7 可自由组合",
    );
    let index = if args.protocols.is_some() {
        CUSTOM_INDEX
    } else {
        ui.select(&title, &presets::menu_items(), 0, false)?
            .unwrap_or(0)
    };
    if index != CUSTOM_INDEX {
        let number = index as u32 + 1;
        args.protocols = Some(ProtocolChoice::Preset(number));
        return selected(&ProtocolChoice::Preset(number));
    }
    let list = custom_list(ui, &title)?;
    if args.core.is_none() && list.iter().any(|p| p.cores().len() > 1) {
        args.core = Some(preferred_core(ui)?);
    }
    args.protocols = Some(ProtocolChoice::List(list.clone()));
    Ok(list)
}

fn custom_list(ui: &dyn Prompter, title: &str) -> Result<Vec<Protocol>> {
    let items: Vec<String> = Protocol::ALL
        .iter()
        .map(|p| match p {
            Protocol::AnytlsReality => format!("{} (仅 sing-box 完整配置)", p.title()),
            _ => p.title().to_owned(),
        })
        .collect();
    let title = format!("{title}\n自定义组合：输入一个或多个编号");
    let picked = ui.select_many(&title, &items, &[0])?;
    Ok(presets::canonical(
        &picked
            .iter()
            .filter_map(|&i| Protocol::ALL.get(i).copied())
            .collect::<Vec<_>>(),
    ))
}

fn preferred_core(ui: &dyn Prompter) -> Result<Core> {
    let items = ["sing-box（默认）".to_owned(), "Xray".to_owned()];
    let choice = ui.select("两种内核都支持的协议优先使用", &items, 0, false)?;
    Ok(if choice == Some(1) {
        Core::Xray
    } else {
        Core::Singbox
    })
}

/// Step 2: the REALITY target (only with a REALITY protocol and no
/// handshake option on the command line).
pub fn reality(ui: &dyn Prompter, args: &mut InstallArgs, list: &[Protocol]) -> Result<()> {
    if !list.iter().any(|p| p.reality()) || !args.reality.is_empty() {
        return Ok(());
    }
    let title = header(
        2,
        "伪装目标",
        "REALITY 借用一个真实 HTTPS 网站完成握手；客户端看到的是该网站的证书",
    );
    args.reality.choice = reality_menu(ui, &title, None)?;
    Ok(())
}

/// The REALITY target menu (install wizard, `add`, `sni`, menus).
///
/// `current` is a node whose REALITY target is in effect (`sni`): its
/// target is offered first and is what Enter picks (`保持当前目标`,
/// [`RealityChoice::Default`]), and the own-site questions default to its
/// website (domain, title, HTTPS entrance, certificate method), so
/// re-picking the site changes only what the user changes.
pub fn reality_menu(
    ui: &dyn Prompter,
    title: &str,
    current: Option<&NodeConfig>,
) -> Result<RealityChoice> {
    let mut items: Vec<String> = Vec::with_capacity(5);
    if current.is_some() {
        items.push("保持当前目标".into());
    }
    items.extend(
        [
            if current.is_some() {
                "Microsoft（www.microsoft.com）"
            } else {
                "Microsoft（www.microsoft.com，默认）"
            },
            "Apple（www.apple.com）",
            "自定义域名（支持 TLS 1.3 的大站）",
            "自有域名一键建站（域名需已解析到本机）",
        ]
        .map(String::from),
    );
    let index = ui.select(title, &items, 0, false)?.unwrap_or(0);
    let Some(index) = index.checked_sub(usize::from(current.is_some())) else {
        return Ok(RealityChoice::Default);
    };
    Ok(match index {
        1 => RealityChoice::Apple,
        2 => RealityChoice::Custom(ask_domain(ui, "握手域名", "域名无效")?),
        3 => RealityChoice::OwnSite(own_site(ui, current.and_then(|c| c.site_active()))?),
        _ => RealityChoice::Microsoft,
    })
}

/// The own-site questions; `current` (the active site) gives the defaults.
/// A title equal to the current one is returned as `None` (kept).
fn own_site(ui: &dyn Prompter, current: Option<&SiteConfig>) -> Result<OwnSite> {
    let domain = ui.input_with(
        "已解析到本机的自有域名",
        current.map_or("", |s| s.domain.as_str()),
        &|answer: &str| plan::normalize_domain(answer, "网站域名无效"),
    )?;
    let current_title = current.map_or(defaults::SITE_TITLE, |s| s.title.as_str());
    let title = ui.input_with("网站标题", current_title, &|t: &str| {
        if valid_label(t) {
            Ok(t.to_owned())
        } else {
            Err(Error::msg("网站标题不能为空或超过 128 个字符"))
        }
    })?;
    let title = Some(title).filter(|t| current.is_none() || t != current_title);
    let https_entry = ui.confirm(
        "开启网站 HTTPS 443 入口?",
        current.is_none_or(|s| s.https_entry),
    )?;
    Ok(OwnSite {
        domain,
        title,
        https_entry,
        cert: site_cert_with(ui, current.map(|s| &s.cert))?,
    })
}

/// The certificate of a public website (never self-signed).
pub fn site_cert(ui: &dyn Prompter) -> Result<WebCert> {
    site_cert_with(ui, None)
}

/// [`site_cert`] defaulting to `current` (a custom pair defaults to its
/// files); without one the default is HTTP-01.
pub fn site_cert_with(ui: &dyn Prompter, current: Option<&WebCert>) -> Result<WebCert> {
    let http01 = if current.is_some() {
        "Let's Encrypt HTTP-01（需要 TCP 80）"
    } else {
        "Let's Encrypt HTTP-01（默认，需要 TCP 80）"
    };
    let items = [
        http01,
        "Let's Encrypt Cloudflare DNS（域名托管在 Cloudflare）",
        "自备证书（已有证书文件）",
    ]
    .map(String::from);
    let default = match current {
        Some(WebCert::Cloudflare) => 1,
        Some(WebCert::Custom { .. }) => 2,
        Some(WebCert::Http01) | None => 0,
    };
    let (cert, key) = match current {
        Some(WebCert::Custom { cert, key }) => (Some(cert), Some(key)),
        _ => (None, None),
    };
    let title = "网站证书（公网网站必须使用正式证书）";
    Ok(
        match ui.select(title, &items, default, false)?.unwrap_or(default) {
            1 => WebCert::Cloudflare,
            2 => WebCert::Custom {
                cert: ask_file_with(ui, "完整证书链路径", cert)?,
                key: ask_file_with(ui, "私钥路径", key)?,
            },
            _ => WebCert::Http01,
        },
    )
}

/// Step 3: the proxy certificate (only when it can matter).
pub fn certificate(ui: &dyn Prompter, args: &mut InstallArgs, list: &[Protocol]) -> Result<()> {
    let needing: Vec<&str> = list
        .iter()
        .filter(|p| p.certificate())
        .map(|p| p.title())
        .collect();
    let vmess = list.contains(&Protocol::VmessWs);
    if args.cert.choice.is_some() || (needing.is_empty() && !vmess) {
        return Ok(());
    }
    let explanation = if needing.is_empty() {
        "VMess-WS 仅在使用域名证书时启用 TLS；没有域名请选自签（VMess 保持明文 WebSocket）"
            .to_owned()
    } else {
        format!("{} 需要 TLS 证书；没有域名时选自签即可", needing.join("、"))
    };
    let choice = cert_menu(ui, &header(3, "证书", &explanation))?;
    if choice == ProxyCertChoice::SelfSigned && vmess && args.cert.vmess_host.is_none() {
        args.cert.vmess_host = vmess_host(ui)?;
    }
    args.cert.choice = Some(choice);
    Ok(())
}

/// The proxy certificate menu (install wizard, `add`, `cert set`, menus).
pub fn cert_menu(ui: &dyn Prompter, title: &str) -> Result<ProxyCertChoice> {
    let items = [
        "自签证书（推荐，无需域名；客户端固定证书指纹）",
        "Let's Encrypt HTTP-01（域名需解析到本机，占用 TCP 80）",
        "Let's Encrypt Cloudflare DNS（域名托管在 Cloudflare）",
        "自备证书（已有证书文件）",
    ]
    .map(String::from);
    match ui.select(title, &items, 0, false)?.unwrap_or(0) {
        0 => Ok(ProxyCertChoice::SelfSigned),
        index => domain_cert(ui, index),
    }
}

fn domain_cert(ui: &dyn Prompter, index: usize) -> Result<ProxyCertChoice> {
    let domain = ask_domain(ui, "证书域名", "证书域名无效")?;
    Ok(match index {
        1 => ProxyCertChoice::Acme {
            domain,
            method: AcmeMethod::Http01,
        },
        2 => ProxyCertChoice::Acme {
            domain,
            method: AcmeMethod::Cloudflare,
        },
        _ => ProxyCertChoice::Custom {
            domain,
            cert: ask_file(ui, "完整证书链路径")?,
            key: ask_file(ui, "私钥路径")?,
        },
    })
}

fn vmess_host(ui: &dyn Prompter) -> Result<Option<String>> {
    let host = ui.input_with(
        "VMess-WS Host（套 CDN 时填写域名，留空不发送）",
        "",
        &|h: &str| {
            if h.is_empty() || valid_domain(&h.to_ascii_lowercase()) {
                Ok(h.to_ascii_lowercase())
            } else {
                Err(Error::msg("VMess Host 域名无效"))
            }
        },
    )?;
    Ok(Some(host).filter(|h| !h.is_empty()))
}

/// Step 4a: the connection address (the detected IP as the default).
/// With `--addr` nothing is asked, but the public IPs are still detected,
/// as an unattended install does: they decide the server's DNS families,
/// so `install --addr X` must give the same node with or without `-y`.
pub fn address(session: &Session, args: &InstallArgs) -> Result<Detected> {
    let mut detected = Detected::detect(session);
    if args.addr.is_some() {
        return Ok(detected);
    }
    let shown = |ip: Option<String>| ip.unwrap_or_else(|| "未检测到".to_owned());
    let title = header(
        4,
        "连接地址与端口",
        &format!(
            "检测到公网 IPv4 {} · IPv6 {}",
            shown(detected.ipv4.map(|ip| ip.to_string())),
            shown(detected.ipv6.map(|ip| ip.to_string()))
        ),
    );
    let default = detected
        .default_host()
        .map(|h| h.to_string())
        .unwrap_or_default();
    let check = |answer: &str| -> Result<String> {
        if answer.is_empty() {
            return Err(Error::msg("无法检测公网地址，请输入 IP 或域名"));
        }
        opt::host(answer).map(|h| h.to_string())
    };
    let prompt = format!("{title}\n客户端连接的公网 IP 或域名");
    let answer = session.ui().input_with(&prompt, &default, &check)?;
    detected.addr = Some(opt::host(&answer)?);
    Ok(detected)
}

/// Step 4b: optional custom ports. `plan` re-plans with the ports chosen so
/// far, so a conflicting port is refused while asking. Returns whether
/// ports were added.
pub fn ports(
    ui: &dyn Prompter,
    args: &mut InstallArgs,
    draft: &NodeConfig,
    plan: &dyn Fn(&InstallArgs) -> Result<NodeConfig>,
) -> Result<bool> {
    let assigned: Vec<String> = draft
        .inbounds
        .iter()
        .map(|i| {
            format!(
                "{} {}/{}",
                i.protocol.title(),
                i.port,
                i.protocol.transport().id()
            )
        })
        .collect();
    let prompt = format!("自动分配的端口: {}\n自定义端口？", assigned.join("、"));
    if !ui.confirm(&prompt, false)? {
        return Ok(false);
    }
    let mut changed = false;
    for inbound in &draft.inbounds {
        if args.ports.iter().any(|(p, _)| *p == inbound.protocol) {
            continue;
        }
        let check = |answer: &str| -> Result<String> {
            let port = opt::port(answer)?;
            let mut trial = args.clone();
            trial.ports.push((inbound.protocol, port));
            // The draft planned fine, so a failure is this port's fault.
            plan(&trial)
                .map(|_| port.to_string())
                .map_err(|_| Error::msg(format!("{} 端口不可用: {port}", inbound.protocol.title())))
        };
        let prompt = format!("{} 端口", inbound.protocol.title());
        let answer = ui.input_with(&prompt, &inbound.port.to_string(), &check)?;
        let port = opt::port(&answer)?;
        if port != inbound.port {
            changed = true;
        }
        args.ports.push((inbound.protocol, port));
    }
    Ok(changed)
}

/// Step 5: the summary shown with `确认安装？`.
pub fn summary(cfg: &NodeConfig) -> String {
    let rows: Vec<Vec<String>> = cfg
        .inbounds
        .iter()
        .map(|i| {
            vec![
                i.protocol.title().to_owned(),
                i.core.title().to_owned(),
                i.port.to_string(),
                i.protocol.transport().id().to_owned(),
            ]
        })
        .collect();
    let mut lines = vec![
        header(5, "确认", "确认后开始安装：下载内核、生成配置并启动服务"),
        format_table(&["协议", "内核", "端口", "传输"], &rows),
        format!("连接地址: {}", cfg.server.addr),
    ];
    if cfg.any_reality() {
        lines.push(format!("REALITY 目标: {}", reality_target(cfg)));
    }
    if let Some(tls) = cfg.tls.as_ref().filter(|_| cfg.needs_cert()) {
        lines.push(format!("证书: {}", cert_label(&tls.mode)));
    }
    if let Some(host) = cfg.vmess_host.as_ref().filter(|_| !cfg.vmess_tls) {
        lines.push(format!("VMess-WS Host: {host}"));
    }
    lines.push("确认安装？".to_owned());
    lines.join("\n")
}

fn reality_target(cfg: &NodeConfig) -> String {
    match cfg.site_active() {
        Some(site) => format!(
            "自有网站 {}（HTTPS 443 入口{}）",
            site.domain,
            if site.https_entry { "开启" } else { "关闭" }
        ),
        None => format!("{}（{}）", cfg.reality.sni, cfg.reality.dest),
    }
}

/// Short Chinese description of a proxy certificate mode.
pub fn cert_label(mode: &ProxyCertMode) -> String {
    match mode {
        ProxyCertMode::SelfSigned { sni } => format!("自签证书（{sni}）"),
        ProxyCertMode::Acme {
            domain,
            method: AcmeMethod::Http01,
        } => format!("Let's Encrypt HTTP-01（{domain}）"),
        ProxyCertMode::Acme { domain, .. } => format!("Let's Encrypt Cloudflare DNS（{domain}）"),
        ProxyCertMode::Custom { domain, .. } => format!("自备证书（{domain}）"),
    }
}

/// A validated, lower-cased domain.
pub fn ask_domain(ui: &dyn Prompter, prompt: &str, invalid: &str) -> Result<String> {
    ui.input_with(prompt, "", &|answer: &str| {
        plan::normalize_domain(answer, invalid)
    })
}

/// An existing regular file, as an absolute path.
pub fn ask_file(ui: &dyn Prompter, prompt: &str) -> Result<PathBuf> {
    ask_file_with(ui, prompt, None)
}

/// [`ask_file`] with `current` as the Enter default.
fn ask_file_with(ui: &dyn Prompter, prompt: &str, current: Option<&PathBuf>) -> Result<PathBuf> {
    let default = current.map(|p| p.to_string_lossy()).unwrap_or_default();
    let answer = ui.input_with(prompt, &default, &|answer: &str| {
        if answer.is_empty() {
            return Err(Error::msg("请输入文件路径"));
        }
        let path = opt::absolute(answer);
        if path.is_file() {
            Ok(path.to_string_lossy().into_owned())
        } else {
            Err(Error::msg(format!("文件不存在: {}", path.display())))
        }
    })?;
    Ok(PathBuf::from(answer))
}
