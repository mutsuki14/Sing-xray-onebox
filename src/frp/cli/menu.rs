//! The interactive FRP menu (G41): v2's eleven items as a numbered list
//! with `0) 返回`, headed by the current state. Items run the same
//! [`Action`]s as the command line; errors and cancellations of an item
//! stay in the menu, only cancelling the menu prompt itself leaves (130).

use super::{Action, Session};
use crate::error::{Error, Result};
use crate::frp::draft::Flags;
use crate::frp::export::ExportRequest;
use crate::frp::lifecycle::ServiceAction;
use crate::frp::model;
use crate::host::os::ROOT_REQUIRED;
use crate::host::service::FRPS;
use crate::ui::{out, BACK};

/// The menu entries in v2 order.
fn entries() -> Vec<(&'static str, Action)> {
    vec![
        (
            "安装/配置",
            Action::Configure {
                flags: Flags::default(),
                dry_run: false,
                plan: false,
            },
        ),
        ("状态", Action::Info),
        ("导出客户端", Action::Client(ExportRequest::default())),
        ("启动", Action::Service(ServiceAction::Start)),
        ("停止", Action::Service(ServiceAction::Stop)),
        ("重启", Action::Service(ServiceAction::Restart)),
        ("更新", Action::Update(None)),
        ("续期", Action::Renew { cron: false }),
        ("轮换 token", Action::RotateToken),
        ("日志", Action::Log),
        ("卸载", Action::Uninstall),
    ]
}

impl Session<'_> {
    /// Show the menu until `0) 返回` (module docs for the rules).
    pub(super) fn menu(&self) -> Result<()> {
        let entries = entries();
        let items: Vec<String> = entries.iter().map(|(label, _)| label.to_string()).collect();
        loop {
            let title = format!("FRP 服务端\n{}", self.headline());
            let Some(choice) = self.ctx().ui.select(&title, &items, BACK, true)? else {
                return Ok(());
            };
            let Some((_, action)) = entries.get(choice) else {
                continue;
            };
            let outcome = if action.requires_root() && !self.is_root {
                Err(Error::msg(ROOT_REQUIRED))
            } else {
                self.run(action.clone())
            };
            match outcome {
                Ok(()) => {}
                Err(e) if e.is_cancelled() => out::info("操作已取消"),
                Err(e) => out::error(e),
            }
        }
    }

    /// `web · frp.example.com:7000 · frps 运行中` (or why there is none).
    fn headline(&self) -> String {
        let paths = &self.ctx().paths;
        if !model::installed(paths) {
            return "未安装".to_owned();
        }
        match model::load(paths) {
            Ok(Some(state)) => {
                let mode = if state.is_web() { "web" } else { "tcp" };
                let running = if self.rt.services().running(FRPS) {
                    "运行中"
                } else {
                    "已停止"
                };
                format!(
                    "{mode} · {}:{} · frps {running}",
                    state.domain, state.bind_port
                )
            }
            Ok(None) => "未安装".to_owned(),
            Err(e) => format!("状态无法读取: {e}"),
        }
    }
}
