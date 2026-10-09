//! The interactive install wizard (ARCH §6.2): five steps, each headed
//! `步骤 i/5 · 标题` with a one-line explanation, asking only what the
//! command line did not decide:
//! 1. 协议组合 — presets with their descriptions; 7 = custom multi-select
//!    (plus the preferred core when it matters);
//! 2. 伪装目标 — only with a REALITY protocol: Microsoft, Apple, a custom
//!    domain or the own-domain website (title, HTTPS entrance, certificate);
//! 3. 证书 — only when a selected protocol needs a certificate (or VMess-WS
//!    could use one): self-signed is recommended without a domain;
//! 4. 连接地址与端口 — the detected public IP as an editable default, ports
//!    auto-assigned with an optional per-protocol override;
//! 5. 确认 — a summary table and `确认安装？`.
//!
//! Every free-text answer is validated and asked again on error; the
//! configuration is planned with the same planner as unattended installs,
//! so a summary always shows what will be applied.
//!
//! Changes from v2 (spec B §3.3): numbered steps with explanations instead
//! of bare prompts; the custom selection is a multi-select with the
//! protocol titles; the website certificate method is asked for the own
//! site; the summary and a final confirmation come before anything runs.

pub mod steps;

use crate::cli::commands::install::{plan_node, InstallArgs};
use crate::cli::session::Session;
use crate::domain::config::NodeConfig;
use crate::error::Result;

/// Run the wizard; `None` when the user declines the summary.
pub fn run(
    session: &Session,
    args: &InstallArgs,
    previous: Option<&NodeConfig>,
) -> Result<Option<NodeConfig>> {
    let ui = session.ui();
    let mut args = args.clone();
    let list = steps::protocols(ui, &mut args)?;
    steps::reality(ui, &mut args, &list)?;
    steps::certificate(ui, &mut args, &list)?;
    let detected = steps::address(session, &args)?;
    let plan = |args: &InstallArgs| -> Result<NodeConfig> {
        plan_node(
            session,
            &args.request(detected.clone()),
            args.reality.dest_after_sni.as_ref(),
            previous,
        )
    };
    let draft = plan(&args)?;
    let cfg = if steps::ports(ui, &mut args, &draft, &plan)? {
        plan(&args)?
    } else {
        draft
    };
    if ui.confirm(&steps::summary(&cfg), true)? {
        Ok(Some(cfg))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests;
