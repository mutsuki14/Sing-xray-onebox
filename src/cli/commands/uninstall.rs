//! `uninstall`: remove the proxy node, keeping what users keep (G11).
//!
//! Order: confirmation (default no; `-y` = yes) → node lock → recovery of
//! a leftover journal → refuse a pending self-update journal → the
//! `before-uninstall` backup (its failure aborts) → teardown, every step
//! attempted and failures reported together → only when everything went
//! well, `state.json` and `state.v2.json` last (so a failed uninstall can
//! simply be run again).
//!
//! A service that could not be removed (e.g. its stop timed out) keeps the
//! whole file phase from running: without an init system the supervisor
//! needs the service spec (`ROOT/services`) to find and stop the daemon,
//! and a missing spec reads as "already stopped" — deleting it would let
//! the re-run succeed while sing-box/Xray keep running and hold the ports.
//! The rules and crontab lines are still cleared; the re-run removes the
//! rest.
//!
//! Removed: the services `onebox-sing-box`, `onebox-xray`,
//! `onebox-subscription-web`, `onebox-subscription`, `onebox-site`,
//! `onebox-network`; the firewall owners `proxy` and `acme`; port hopping;
//! the node's crontab lines; `bin/{sing-box,xray}`, `ROOT/{sing-box,xray}.json`,
//! `ROOT/client`, `ROOT/subscription` (devices included),
//! `/var/lib/onebox-subscription-acme`, `RUN/subscription.sock`,
//! `ROOT/services`, `ROOT/tls` (the proxy private key) and `ROOT/onebox.conf`.
//! Kept: `ROOT/site` and the website content (with its backups),
//! `ROOT/backups`, the firewall ledgers, the `onebox` program, FRP, the
//! nginx package and BBR.
//!
//! Changes from v2 (spec B §3.13, B-9.1#17, F-8.1#24, G-8.1#12): the
//! backup is taken under the lock after recovery; `onebox-network` is
//! removed once; the proxy key, service specs and the subscription ACME
//! webroot no longer stay behind; a failing step no longer leaves a
//! half-removed node without its state file.

use crate::cli::args::{CommandSpec, Group, Matches};
use crate::cli::session::{with_system, Session};
use crate::ctx::Ctx;
use crate::domain::protocol::Core;
use crate::error::{Error, Result};
use crate::host::cron::{self, Crontab, Scope};
use crate::host::service::{NETWORK, SING_BOX, SITE, SUBSCRIPTION, SUBSCRIPTION_WEB, XRAY};
use crate::sys::fs::{remove_file_if_exists, remove_tree_if_exists};
use crate::sys::lock::{FileLock, BUSY_MESSAGE};

pub const PROMPT: &str = "卸载代理服务和配置？FRP 保持独立管理，网站内容与备份将保留";
pub const DONE: &str = "代理已卸载，网站内容和备份保留于原目录；FRP 可用 onebox frps 管理";
/// Services removed, each once.
const SERVICES: [&str; 6] = [
    SING_BOX,
    XRAY,
    SUBSCRIPTION_WEB,
    SUBSCRIPTION,
    SITE,
    NETWORK,
];
const FIREWALL_OWNERS: [&str; 2] = ["proxy", "acme"];
/// Why the files stayed after a failed service removal.
pub const FILES_KEPT: &str = "服务未能全部删除，已保留服务定义、内核与配置文件";

/// The backup taken under the node lock before anything is removed:
/// `crate::backup::create_locked` (wired in `cli::registry`).
pub type BackupHook = fn(&Ctx, &FileLock, &str) -> Result<String>;

pub const UNINSTALL: CommandSpec = CommandSpec::new(
    "uninstall",
    Group::Maintain,
    "卸载代理节点（保留网站内容、快照与 FRP）",
)
.handler(uninstall_command);

fn uninstall_command(ctx: &Ctx, _m: &Matches) -> Result<()> {
    with_system(ctx, |s| {
        uninstall(s, crate::cli::registry::UNINSTALL_BACKUP)
    })
}

/// Uninstall the node (see the module docs).
pub fn uninstall(session: &Session, backup: BackupHook) -> Result<()> {
    session.require_root()?;
    session.load()?;
    if !session.ui().confirm(PROMPT, false)? {
        return Ok(());
    }
    let ctx = session.ctx;
    let lock = FileLock::acquire(&ctx.paths.lock(), BUSY_MESSAGE)?;
    session.engine.recover_locked(ctx, &lock)?;
    crate::apply::journal::pending(&ctx.paths)?.refuse()?;
    let id = backup(ctx, &lock, "before-uninstall")?;
    session.info(format!("已保存快照 {id}"));
    let errors = teardown(session);
    if !errors.is_empty() {
        return Err(Error::msg(format!(
            "卸载未完成: {}；问题解决后可再次执行 onebox uninstall",
            errors.join("；")
        )));
    }
    let paths = &ctx.paths;
    remove_file_if_exists(&paths.state())?;
    remove_file_if_exists(&paths.state_v2_backup())?;
    session.data(DONE)
}

/// Every removal step; returns the failures. The files go only after
/// every service did (module docs).
fn teardown(session: &Session) -> Vec<String> {
    let ctx = session.ctx;
    let mut errors = Vec::new();
    let services = session.services();
    for name in SERVICES {
        if let Err(e) = services.remove(name) {
            errors.push(format!("删除 {name}: {e}"));
        }
    }
    let services_removed = errors.is_empty();
    for owner in FIREWALL_OWNERS {
        match crate::host::firewall::clear_owner(ctx, owner) {
            Ok(report) if report.failed.is_empty() => {}
            Ok(report) => errors.push(format!("防火墙规则 {owner}: {}", report.failed.join("; "))),
            Err(e) => errors.push(format!("防火墙规则 {owner}: {e}")),
        }
    }
    match crate::host::hop::clear(ctx) {
        Ok(report) if report.failed.is_empty() => {}
        Ok(report) => errors.push(format!("端口跳跃规则: {}", report.failed.join("; "))),
        Err(e) => errors.push(format!("端口跳跃规则: {e}")),
    }
    if cron::available(ctx) {
        if let Err(e) = Crontab::edit(ctx, |tab| Ok(tab.remove_scope(Scope::Node))) {
            errors.push(format!("计划任务: {e}"));
        }
    }
    if services_removed {
        errors.extend(remove_files(session));
    } else {
        errors.push(FILES_KEPT.to_owned());
    }
    errors
}

/// The node's files (module docs); the state files are removed later.
fn remove_files(session: &Session) -> Vec<String> {
    let paths = &session.ctx.paths;
    let mut files = vec![paths.legacy_v1_state(), paths.subscription_socket()];
    for core in Core::ALL {
        files.push(paths.core_bin(core));
        files.push(paths.core_config(core));
    }
    let trees = [
        paths.clients(),
        paths.subscription(),
        paths.subscription_acme(),
        paths.services(),
        paths.tls(),
    ];
    let file_results = files.iter().map(|f| (f, remove_file_if_exists(f)));
    let tree_results = trees.iter().map(|t| (t, remove_tree_if_exists(t)));
    file_results
        .chain(tree_results)
        .filter_map(|(path, result)| {
            result
                .err()
                .map(|e| format!("删除 {}: {e}", path.display()))
        })
        .collect()
}

#[cfg(test)]
mod tests;
