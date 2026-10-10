//! Feature submenus: subscription, website, backups, updates and the
//! reinstall/uninstall entry. Subscription, backups and updates belong to
//! independent modules and run fixed command lines; answers typed here are
//! validated and only ever passed as option values or after `--`.

use super::Menu;
use crate::cli::commands::install::{self, InstallArgs};
use crate::cli::commands::node;
use crate::cli::commands::site::{self, PageEdit, SiteAction};
use crate::cli::commands::uninstall;
use crate::cli::options as opt;
use crate::cli::registry;
use crate::cli::wizard::steps::{ask_domain, ask_domain_with, site_cert, site_cert_with};
use crate::domain::config::{NodeConfig, SiteTemplate, SiteTheme, WebCert};
use crate::domain::validate::{valid_label, valid_text};
use crate::domain::{defaults, plan};
use crate::error::{Error, Result};
use crate::site::ContentStore;
use crate::ui::menu::Entry;
use crate::VERSION;
use std::net::IpAddr;

const SITE_FOR_SUBSCRIPTION: &str = "请选择 ip、standalone，或已启用自建站时选择 site。";
const PLAINTEXT: &str = "HTTP 不加密订阅内容和令牌；需要加密传输时请选择 HTTPS 托管方式。";

fn entries(labels: &[&str]) -> Vec<Entry> {
    labels.iter().map(|l| Entry::new(*l)).collect()
}

impl Menu<'_> {
    fn heading_with(&self, title: &str, describe: impl FnOnce(&NodeConfig) -> String) -> String {
        match self.session.load() {
            Ok(loaded) => format!("{title}\n{}", describe(&loaded.config)),
            Err(e) => format!("{title}\n[错误] {}", e.report_text()),
        }
    }

    pub(super) fn subscription_menu(&self) -> Result<()> {
        let heading = || self.heading_with("远程订阅", subscription_state);
        let items = entries(&[
            "查看订阅地址与设备",
            "启用或修改托管方式",
            "新建设备",
            "撤销设备",
            "重置设备链接",
            "关闭订阅",
            "重新发布",
        ]);
        self.submenu(&heading, &items, &|i| match i {
            0 => self.dispatch(&["subscription", "info"]),
            1 => self.subscription_enable(),
            2 => {
                let name = self
                    .session
                    .ui()
                    .input_with("设备名称", "phone", &device_name)?;
                self.dispatch(&["subscription", "add", "--", &name])
            }
            3 | 4 => {
                self.dispatch(&["subscription", "info"])?;
                let id = self.session.ui().input_with("设备 ID", "", &device_id)?;
                let action = if i == 3 { "revoke" } else { "reset" };
                self.dispatch(&["subscription", action, "--", &id])
            }
            5 => self.dispatch(&["subscription", "disable"]),
            _ => self.dispatch(&["subscription", "publish"]),
        })
    }

    /// v2's enable dialog with validated answers.
    fn subscription_enable(&self) -> Result<()> {
        let cfg = self.loaded()?.config;
        let Some(mode) = self.subscription_mode(&cfg)? else {
            return Ok(());
        };
        let mut argv: Vec<String> = ["subscription", "enable", "--mode"]
            .map(String::from)
            .to_vec();
        argv.extend(self.mode_options(&cfg, mode)?);
        let words: Vec<&str> = argv.iter().map(String::as_str).collect();
        self.dispatch(&words)
    }

    /// 0 = ip, 1 = site (only with an active site), 2 = standalone.
    fn subscription_mode(&self, cfg: &NodeConfig) -> Result<Option<usize>> {
        let has_site = cfg.site_active().is_some();
        let items = [
            "ip（IP 直连 HTTP，无需域名）",
            "site（复用自建站 HTTPS）",
            "standalone（独立域名 HTTPS）",
        ]
        .map(String::from);
        loop {
            let default = usize::from(has_site);
            match self
                .session
                .ui()
                .select("订阅托管方式", &items, default, true)?
            {
                Some(1) if !has_site => self.session.warn(SITE_FOR_SUBSCRIPTION),
                choice => return Ok(choice),
            }
        }
    }

    /// The `--mode …` value and the options of that mode.
    fn mode_options(&self, cfg: &NodeConfig, mode: usize) -> Result<Vec<String>> {
        let ui = self.session.ui();
        let port_default = cfg
            .subscription
            .as_ref()
            .filter(|s| s.mode.id() != "site")
            .map_or(defaults::SUBSCRIPTION_PORT, |s| s.port)
            .to_string();
        let port_check = |p: &str| opt::port(p).map(|p| p.to_string());
        Ok(match mode {
            0 => {
                self.session.warn(PLAINTEXT);
                let default = plan::default_subscription_address(cfg)
                    .map(|ip| ip.to_string())
                    .unwrap_or_default();
                let prompt = "订阅 IP（IPv4 或 IPv6，无需方括号）";
                let address = ui.input_with(prompt, &default, &subscription_ip)?;
                let port = ui.input_with("HTTP 订阅端口", &port_default, &port_check)?;
                vec![
                    "ip".into(),
                    "--address".into(),
                    address,
                    "--port".into(),
                    port,
                ]
            }
            1 => vec!["site".into()],
            _ => {
                let domain = ask_domain(ui, "订阅域名（已解析到本机）", "订阅域名无效")?;
                let port = ui.input_with("HTTPS 端口", &port_default, &port_check)?;
                let mut options = vec![
                    "standalone".into(),
                    "--domain".into(),
                    domain,
                    "--port".into(),
                    port,
                ];
                options.extend(web_cert_args(&site_cert(ui)?));
                options
            }
        })
    }

    pub(super) fn site_menu(&self) -> Result<()> {
        let heading = || self.heading_with("自有域名网站", site_state);
        let items = entries(&[
            "查看网站",
            "启用网站",
            "关闭网站",
            "HTTPS 443 入口",
            "更换模板",
            "更换配色",
            "修改标题",
            "修改描述",
            "导入网站",
            "恢复内容",
            "预览主页",
            "续期证书",
        ]);
        self.submenu(&heading, &items, &|i| {
            let action = match self.site_action(i)? {
                Some(action) => action,
                None => return Ok(()),
            };
            site::run(self.session, action)
        })
    }

    /// The site action of menu entry `i`, asking its questions.
    fn site_action(&self, i: usize) -> Result<Option<SiteAction>> {
        let ui = self.session.ui();
        let site = self.loaded()?.config.site;
        Ok(Some(match i {
            0 => SiteAction::Info,
            // An existing site's domain, entrance and certificate method
            // are the defaults (Enter keeps them).
            1 => {
                let current = site.as_ref().map_or("", |s| s.domain.as_str());
                let prompt = "网站域名（已解析到本机）";
                let domain = ask_domain_with(ui, prompt, current, "网站域名无效")?;
                let current = site.as_ref().is_none_or(|s| s.https_entry);
                let https_entry = ui.confirm("开启网站 HTTPS 443 入口?", current)?;
                SiteAction::Enable {
                    domain,
                    cert: site_cert_with(ui, site.as_ref().map(|s| &s.cert))?,
                    https_entry,
                }
            }
            2 => SiteAction::Disable,
            3 => {
                let current = site.as_ref().is_none_or(|s| s.https_entry);
                SiteAction::Https(ui.confirm("开启网站 HTTPS 443 入口?", current)?)
            }
            4 => {
                let current = site
                    .as_ref()
                    .map_or(defaults::SITE_TEMPLATE, |s| s.template);
                let Some(template) = pick(ui, "选择模板", SiteTemplate::ALL, current)? else {
                    return Ok(None);
                };
                SiteAction::Template(PageEdit {
                    template: Some(template),
                    ..PageEdit::default()
                })
            }
            5 => {
                let current = site.as_ref().map_or(defaults::SITE_THEME, |s| s.theme);
                let Some(theme) = pick(ui, "选择配色", SiteTheme::ALL, current)? else {
                    return Ok(None);
                };
                SiteAction::Theme(theme)
            }
            6 => {
                let current = site.as_ref().map_or(defaults::SITE_TITLE, |s| &s.title);
                SiteAction::Title(ui.input_with("网站标题", current, &site_title)?)
            }
            7 => {
                let current = site.as_ref().map_or("", |s| &s.description);
                SiteAction::Description(ui.input_with("网站描述", current, &site_description)?)
            }
            8 => SiteAction::Import(ui.input_with("本地网站目录", "", &directory)?),
            9 => match self.content_backup()? {
                Some(id) => SiteAction::Restore(id),
                None => return Ok(None),
            },
            10 => SiteAction::Preview(PageEdit::default()),
            _ => SiteAction::Renew,
        }))
    }

    /// Pick a content backup (newest first).
    fn content_backup(&self) -> Result<Option<String>> {
        let backups = ContentStore::new(&self.session.ctx.paths).backups()?;
        if backups.is_empty() {
            return Err(Error::msg("没有网站备份"));
        }
        let items: Vec<String> = backups
            .iter()
            .map(|b| format!("{}（{}）", b.id, crate::sys::time::format_utc(b.created)))
            .collect();
        let choice = self
            .session
            .ui()
            .select("选择要恢复的网站备份", &items, 0, true)?;
        Ok(choice.and_then(|i| backups.get(i)).map(|b| b.id.clone()))
    }

    pub(super) fn backup_menu(&self) -> Result<()> {
        let heading = || {
            let paths = &self.session.ctx.paths;
            let mut text = format!("备份与恢复\n  快照目录 {}", paths.backups().display());
            let pending = match crate::apply::journal::pending(paths) {
                Ok(pending) => pending.any(),
                Err(_) => true,
            };
            if pending {
                text.push_str("\n  [警告] 存在未完成的操作，请先执行故障恢复");
            }
            text
        };
        let items = entries(&[
            "创建快照",
            "查看快照",
            "恢复快照",
            "故障恢复",
            "重新生成配置",
        ]);
        self.submenu(&heading, &items, &|i| match i {
            0 => {
                let label = self
                    .session
                    .ui()
                    .input_with("快照标签", "manual", &backup_label)?;
                self.dispatch(&["backup", "--", &label])
            }
            1 => self.dispatch(&["backups"]),
            2 => self.restore(),
            3 => self.dispatch(&["recover"]),
            _ => {
                self.session.require_root()?;
                node::run(self.session, Some(node::plan_regen(self.session)?))
            }
        })
    }

    pub(super) fn update_menu(&self) -> Result<()> {
        let heading = || match self.session.load_optional() {
            Ok(Some(loaded)) => format!("更新\n  {}", versions(&loaded.config)),
            _ => format!("更新\n  Onebox {VERSION}"),
        };
        let items = entries(&["检查程序更新", "更新程序", "更新内核", "切换更新渠道"]);
        self.submenu(&heading, &items, &|i| match i {
            0 => self.dispatch(&["update-check"]),
            1 => self.dispatch(&["update-script"]),
            2 => self.dispatch(&["update"]),
            _ => {
                let items = ["stable（正式版）", "testing（测试版）"].map(String::from);
                match self.session.ui().select("更新渠道", &items, 0, true)? {
                    Some(0) => self.dispatch(&["update-channel", "stable"]),
                    Some(_) => self.dispatch(&["update-channel", "testing"]),
                    None => Ok(()),
                }
            }
        })
    }

    pub(super) fn reinstall_menu(&self) -> Result<()> {
        let heading = || "重装 / 卸载".to_owned();
        let items = entries(&["重新安装（生成新凭据，清除订阅设备）", "卸载节点"]);
        self.submenu(&heading, &items, &|i| match i {
            0 => install::install(self.session, &InstallArgs::default()),
            _ => uninstall::uninstall(self.session, registry::UNINSTALL_BACKUP),
        })
    }
}

fn subscription_state(cfg: &NodeConfig) -> String {
    match &cfg.subscription {
        None => "  状态 未启用".to_owned(),
        Some(sub) => format!("  状态 已启用 · 托管 {} · 端口 {}", sub.mode.id(), sub.port),
    }
}

fn site_state(cfg: &NodeConfig) -> String {
    match (&cfg.site, cfg.site_active()) {
        (None, _) => "  状态 未启用（需要 REALITY 协议）".to_owned(),
        (Some(_), None) => "  状态 未生效（没有 REALITY 协议）".to_owned(),
        (Some(_), Some(site)) => format!(
            "  {} · HTTPS 443 入口{} · 模板 {} · 配色 {}\n  标题 {}",
            site.domain,
            if site.https_entry { "开启" } else { "关闭" },
            site.template,
            site.theme,
            site.title
        ),
    }
}

fn versions(cfg: &NodeConfig) -> String {
    let mut parts = vec![format!("Onebox {VERSION}")];
    for core in cfg.cores() {
        let version = cfg.versions.installed(core).unwrap_or("未知版本");
        parts.push(format!("{} {version}", core.title()));
    }
    parts.join(" · ")
}

/// A choice among keyword values with `current` as the default.
fn pick<T: Copy + PartialEq + std::fmt::Display>(
    ui: &dyn crate::ui::Prompter,
    title: &str,
    all: &[T],
    current: T,
) -> Result<Option<T>> {
    let items: Vec<String> = all.iter().map(|t| t.to_string()).collect();
    let default = all.iter().position(|t| *t == current).unwrap_or(0);
    Ok(ui
        .select(title, &items, default, true)?
        .and_then(|i| all.get(i).copied()))
}

fn web_cert_args(cert: &WebCert) -> Vec<String> {
    let mut args = vec!["--tls".to_owned(), cert.method().to_owned()];
    if let WebCert::Custom { cert, key } = cert {
        args.extend([
            "--cert".to_owned(),
            cert.to_string_lossy().into_owned(),
            "--key".to_owned(),
            key.to_string_lossy().into_owned(),
        ]);
    }
    args
}

/// Device names: 1–80 bytes, no control characters.
pub fn device_name(name: &str) -> Result<String> {
    if name.is_empty() || name.len() > 80 || !valid_text(name) {
        return Err(Error::msg("设备名称不能为空、超过 80 字节或包含控制字符"));
    }
    Ok(name.to_owned())
}

/// Device ids: 16 lowercase hex characters.
pub fn device_id(id: &str) -> Result<String> {
    let id = id.to_ascii_lowercase();
    if id.len() == 16 && id.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(id)
    } else {
        Err(Error::msg("设备 ID 应为 16 位十六进制"))
    }
}

/// An IP literal without brackets.
pub fn subscription_ip(text: &str) -> Result<String> {
    text.parse::<IpAddr>()
        .map(|ip| ip.to_canonical().to_string())
        .map_err(|_| {
            Error::msg("订阅地址必须是 IPv4 或 IPv6 字面地址，不能含域名、端口、路径或 zone ID")
        })
}

fn site_title(title: &str) -> Result<String> {
    if valid_label(title) {
        Ok(title.to_owned())
    } else {
        Err(Error::msg("网站标题不能为空或超过 128 个字符"))
    }
}

fn site_description(text: &str) -> Result<String> {
    if valid_text(text) {
        Ok(text.to_owned())
    } else {
        Err(Error::msg("网站描述不能包含控制字符"))
    }
}

fn directory(path: &str) -> Result<String> {
    let absolute = opt::absolute(path);
    if !path.is_empty() && absolute.is_dir() {
        Ok(absolute.to_string_lossy().into_owned())
    } else {
        Err(Error::msg(format!("目录不存在: {path}")))
    }
}

/// Backup labels: printable, at most 120 characters.
pub fn backup_label(label: &str) -> Result<String> {
    if label.is_empty() || label.chars().count() > 120 || !valid_text(label) {
        return Err(Error::msg(
            "快照标签不能为空、超过 120 个字符或包含控制字符",
        ));
    }
    Ok(label.to_owned())
}
