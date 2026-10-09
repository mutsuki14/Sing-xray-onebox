//! Node submenus: information and sharing, protocols, connection and
//! camouflage, services. They call the command modules directly.

use super::Menu;
use crate::cert::CertScopes;
use crate::cli::commands::client::{self, Export};
use crate::cli::commands::connection::{self, AddrArgs};
use crate::cli::commands::node::{self, AddArgs};
use crate::cli::commands::service::{self, Action};
use crate::cli::commands::{cert, info};
use crate::cli::options::RealityArgs;
use crate::domain::config::NodeConfig;
use crate::domain::protocol::{Core, Protocol};
use crate::error::Result;
use crate::ui::menu::Entry;
use crate::ui::out::format_table;

fn entries(labels: &[&str]) -> Vec<Entry> {
    labels.iter().map(|l| Entry::new(*l)).collect()
}

impl Menu<'_> {
    /// The configuration for a heading (an error line when unreadable).
    fn config_or(&self, describe: impl FnOnce(&NodeConfig) -> String) -> String {
        match self.session.load() {
            Ok(loaded) => describe(&loaded.config),
            Err(e) => format!("[错误] {}", e.report_text()),
        }
    }

    pub(super) fn info_menu(&self) -> Result<()> {
        let heading = || {
            self.config_or(|cfg| {
                format!(
                    "节点信息与分享\n  地址 {} · {} 个协议 · 节点名称 {}",
                    cfg.server.addr,
                    cfg.inbounds.len(),
                    cfg.node_name
                )
            })
        };
        let items = entries(&["查看节点信息", "导出客户端配置", "显示分享链接二维码"]);
        self.submenu(&heading, &items, &|i| match i {
            0 => info::show(self.session),
            1 => client::client(self.session, None),
            _ => client::client(self.session, Some(Export::Qr)),
        })
    }

    pub(super) fn protocol_menu(&self) -> Result<()> {
        let heading = || self.config_or(|cfg| format!("协议管理\n{}", protocol_table(cfg)));
        let items = entries(&["添加协议", "删除协议", "修改端口"]);
        self.submenu(&heading, &items, &|i| {
            self.session.require_root()?;
            match i {
                0 => node::add(self.session, None, &AddArgs::default()),
                1 => node::run(self.session, node::plan_del(self.session, None)?),
                _ => node::run(self.session, node::plan_port(self.session, None, None)?),
            }
        })
    }

    pub(super) fn connection_menu(&self) -> Result<()> {
        let heading = || self.config_or(connection_heading);
        let items = entries(&[
            "修改连接地址与节点名称",
            "更换伪装目标（REALITY / ShadowTLS）",
            "更换代理证书",
            "查看证书",
            "续期证书",
            "重置全部凭据",
        ]);
        self.submenu(&heading, &items, &|i| {
            let session = self.session;
            match i {
                3 => return cert::info(session),
                4 => return cert::renew(session, CertScopes::ALL, false),
                _ => session.require_root()?,
            }
            match i {
                0 => node::run(
                    session,
                    connection::plan_addr(session, &AddrArgs::default())?,
                ),
                1 => node::run(
                    session,
                    connection::plan_sni(session, &RealityArgs::default())?,
                ),
                2 => cert::set(session, None),
                _ => node::run(session, node::plan_reset(session)?),
            }
        })
    }

    pub(super) fn service_menu(&self) -> Result<()> {
        let heading = || self.config_or(|cfg| service_heading(self, cfg));
        let items = entries(&[
            "启动代理内核",
            "停止代理内核",
            "重启代理内核",
            "查看内核日志",
        ]);
        self.submenu(&heading, &items, &|i| match i {
            0 => service::cores(self.session, Action::Start),
            1 => service::cores(self.session, Action::Stop),
            2 => service::cores(self.session, Action::Restart),
            _ => self.core_log(),
        })
    }

    /// Logs of the only core, or of the chosen one.
    fn core_log(&self) -> Result<()> {
        let cores = self.loaded()?.config.cores();
        let core = match cores.as_slice() {
            [only] => *only,
            _ => {
                let items: Vec<String> = cores.iter().map(|c| c.title().to_owned()).collect();
                match self
                    .session
                    .ui()
                    .select("查看哪个内核的日志", &items, 0, true)?
                {
                    Some(i) => cores.get(i).copied().unwrap_or(Core::Singbox),
                    None => return Ok(()),
                }
            }
        };
        service::log(self.session, core)
    }
}

/// Protocol, core, port/transport rows.
pub fn protocol_table(cfg: &NodeConfig) -> String {
    let rows: Vec<Vec<String>> = cfg
        .inbounds
        .iter()
        .map(|i| {
            vec![
                i.protocol.title().to_owned(),
                i.core.title().to_owned(),
                format!("{}/{}", i.port, i.protocol.transport().id()),
            ]
        })
        .collect();
    format_table(&["协议", "内核", "端口"], &rows)
}

fn connection_heading(cfg: &NodeConfig) -> String {
    let mut lines = vec![
        "连接与伪装".to_owned(),
        format!(
            "  连接地址 {}（节点名称 {}）",
            cfg.server.addr, cfg.node_name
        ),
    ];
    if cfg.any_reality() {
        let target = match cfg.site_active() {
            Some(site) => format!("自有网站 {}", site.domain),
            None => format!("{}（{}）", cfg.reality.sni, cfg.reality.dest),
        };
        lines.push(format!("  REALITY 目标 {target}"));
    }
    if cfg.has(Protocol::Shadowtls) {
        lines.push(format!("  ShadowTLS 握手 {}", cfg.shadowtls.sni));
    }
    let tls = cfg.tls.as_ref().filter(|_| cfg.needs_cert()).map_or_else(
        || "无需代理证书".to_owned(),
        |t| crate::cli::wizard::steps::cert_label(&t.mode),
    );
    lines.push(format!("  TLS 证书 {tls}"));
    lines.join("\n")
}

fn service_heading(menu: &Menu, cfg: &NodeConfig) -> String {
    let mut names: Vec<&str> = cfg.cores().into_iter().map(|c| c.service()).collect();
    if cfg.site_active().is_some() {
        names.push(crate::host::service::SITE);
    }
    if cfg.subscription.is_some() {
        names.push(crate::host::service::SUBSCRIPTION);
    }
    let mut lines = vec!["服务".to_owned()];
    for name in names {
        let state = if menu.session.live.running(name) {
            "运行中"
        } else {
            "已停止"
        };
        lines.push(format!("  {name}: {state}"));
    }
    lines.join("\n")
}
