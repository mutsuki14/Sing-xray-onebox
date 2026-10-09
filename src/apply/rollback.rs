//! Rolling a node journal back (spec B §4.4): put every owned file, unit,
//! rule, crontab line and service state back to what the journal recorded.
//!
//! Phases, each persisted before its actions:
//! 1. (no phase) validate everything a rollback relies on — a corrupt
//!    snapshot or journal changes nothing and keeps the journal;
//! 2. `rollback-stop`: stop and disable the node services in the canonical
//!    stop order, only *disable* `onebox-network` (it may be the boot
//!    oneshot running this very recovery), clear the `acme` and `proxy`
//!    firewall owners and the hops (each attempted); a service-manager or
//!    ledger error aborts here with the journal kept, so files are never
//!    restored under running daemons;
//! 3. `rollback-files`: restore the snapshot, re-record firewall rules and
//!    hops that could not be removed, reload systemd;
//! 4. `rollback-services` (best effort): re-apply the old rules and hops,
//!    restore enable states (legacy `onebox-net`/`onebox-hop` included),
//!    the crontab, and start what was running in the canonical start order
//!    — every step is attempted; only a failed enable state, crontab or
//!    start keeps the journal;
//! 5. `rolled-back`, then the journal is removed.
//!
//! Changes from v2:
//! - `Journal::validate` (cron lines, old state, services, snapshot) runs
//!   before anything stops (v2 validated only the snapshot);
//! - firewall and hop rules that cannot be removed do not abort the
//!   rollback: they are reported as warnings and kept recorded in the
//!   restored ledgers, so the old rules' reconcile retires them;
//! - old rules that cannot be re-created do not keep the journal either
//!   (a warning says to run `net-apply`): otherwise every later recover,
//!   apply and boot would repeat the same failure and refuse; and one
//!   service that fails to start no longer leaves the services after it
//!   stopped and disabled (v2 stopped at the first error);
//! - a typed old configuration the current rules reject still has its
//!   files restored; only re-applying its network rules is skipped, with a
//!   warning (same for a v2 old state that cannot be migrated, and for an
//!   old state.json the apply could not read);
//! - under a lock inherited from a self-update parent, `onebox-subscription`
//!   is not started: the parent restores its own manager and starts it (G6);
//! - one canonical service order everywhere (B-9.1#24).

use super::journal::{self, Journal, OldState, Phase, LEGACY_NETWORK_SERVICES, SERVICES};
use super::network::{self, Leftovers};
use super::snapshot;
use super::transaction;
use crate::ctx::Ctx;
use crate::domain::NodeConfig;
use crate::error::{Context, Error, Result};
use crate::host::cron::{self, Scope};
use crate::host::service::{self as svc, Services, WAIT_RUNNING};
use crate::paths::Paths;
use crate::state::v2::{self as statev2, DeployedCerts};
use crate::sys::fs::read_bounded;
use crate::sys::lock::FileLock;
use crate::sys::rand::OsRandom;
use crate::ui::out;
use serde_json::Value;

/// Stop order: public entrances before their backends (v2).
pub const STOP_ORDER: [&str; 5] = [
    svc::SING_BOX,
    svc::XRAY,
    svc::SUBSCRIPTION_WEB,
    svc::SITE,
    svc::SUBSCRIPTION,
];
/// Start order: [`SERVICES`] without `onebox-network`, which a rollback
/// never starts (nor stops).
pub const START_ORDER: [&str; 5] = [
    svc::SUBSCRIPTION,
    svc::SITE,
    svc::SUBSCRIPTION_WEB,
    svc::SING_BOX,
    svc::XRAY,
];

/// Roll `journal` back; on success the journal is gone. `lock` tells
/// whether this process is a self-update child (G6).
pub fn rollback(ctx: &Ctx, lock: &FileLock, journal: &mut Journal) -> Result<()> {
    let paths = &ctx.paths;
    journal.validate_files(paths)?;
    let reapply = old_rules_config(paths, journal);
    let services = Services::detect(ctx);
    journal.set_phase(paths, Phase::RollbackStop)?;
    let left = stop_everything(ctx, &services)?;
    journal.set_phase(paths, Phase::RollbackFiles)?;
    restore_files(ctx, &services, journal, &left)?;
    journal.set_phase(paths, Phase::RollbackServices)?;
    restore_services(ctx, &services, lock, journal, reapply)?;
    journal.set_phase(paths, Phase::RolledBack)?;
    transaction::finish(paths)
}

/// What the old network rules are re-applied from, decided before anything
/// changes. `Skip` carries the reason they cannot be (shown as a warning).
enum Reapply {
    Nothing,
    Config(Box<NodeConfig>),
    /// v2 values; migrated once the snapshot restored the v2 subscription
    /// settings they belong with.
    V2(std::collections::BTreeMap<String, String>),
    Skip(String),
}

fn old_rules_config(paths: &Paths, journal: &Journal) -> Reapply {
    match journal.old() {
        // An apply over a state.json it could not read journals no old
        // configuration; the snapshot still restores the file.
        OldState::None if recorded_present(journal, &paths.state()) => {
            Reapply::Skip(UNREADABLE_OLD_STATE.to_owned())
        }
        OldState::None => Reapply::Nothing,
        OldState::Config(cfg) => match journal.check_old_config() {
            Ok(()) => Reapply::Config(Box::new(cfg.clone())),
            Err(e) => Reapply::Skip(e.to_string()),
        },
        OldState::V2(_) => match journal.v2_values() {
            Ok(Some(values)) => Reapply::V2(values),
            Ok(None) => Reapply::Nothing,
            Err(e) => Reapply::Skip(e.to_string()),
        },
    }
}

/// Why old rules are not re-applied when the old state.json was unreadable.
pub const UNREADABLE_OLD_STATE: &str = "原 state.json 无法读取";

/// Whether the journal's snapshot recorded `target` as present.
fn recorded_present(journal: &Journal, target: &std::path::Path) -> bool {
    journal.snapshot().entry(target).is_some_and(|e| e.present)
}

/// rollback-stop. Service errors abort (journal kept); unremovable rules
/// are returned for the warning summary and the ledger carry-over.
fn stop_everything(ctx: &Ctx, services: &Services) -> Result<Leftovers> {
    let mut errors = Vec::new();
    for name in STOP_ORDER {
        if !services.exists(name) {
            continue;
        }
        if let Err(e) = services.stop(name) {
            errors.push(format!("停止 {name}: {e}"));
        }
        if let Err(e) = services.disable(name) {
            errors.push(format!("停用 {name}: {e}"));
        }
    }
    if services.exists(svc::NETWORK) {
        if let Err(e) = services.disable(svc::NETWORK) {
            errors.push(format!("停用 {}: {e}", svc::NETWORK));
        }
    }
    let mut left = Leftovers::default();
    // Each part is attempted whatever the others did (v2 message prefixes).
    if let Err(e) = network::clear_owner(ctx, network::ACME_OWNER, &mut left) {
        errors.push(format!("清理 ACME 防火墙: {e}"));
    }
    if let Err(e) = network::clear_owner(ctx, network::PROXY_OWNER, &mut left) {
        errors.push(format!("清理当前网络: {e}"));
    }
    if let Err(e) = network::clear_hops(ctx, &mut left) {
        errors.push(format!("清理当前网络: {e}"));
    }
    ensure!(errors.is_empty(), "{}", errors.join("; "));
    if !left.is_empty() {
        out::warn(format!(
            "回滚时部分防火墙或端口跳跃规则未能删除，已保留记录，稍后重试: {}",
            left.messages.join("; ")
        ));
    }
    Ok(left)
}

/// rollback-files.
fn restore_files(
    ctx: &Ctx,
    services: &Services,
    journal: &Journal,
    left: &Leftovers,
) -> Result<()> {
    let paths = &ctx.paths;
    let allow = journal.allowlist(paths);
    snapshot::restore(journal.snapshot(), &journal::files_dir(paths), &allow)?;
    network::carry_over(ctx, left).context("保留未删除的防火墙规则记录失败")?;
    services.daemon_reload()
}

/// rollback-services, best effort: every step is attempted even when an
/// earlier one failed, so one broken service or rule does not leave the
/// rest of the node stopped and disabled. Old rules that cannot be
/// re-created only warn (the journal is still finished: keeping it would
/// make every later recover, apply and boot repeat the same failure and
/// refuse); a failed enable state, crontab restore or start fails the
/// rollback after everything was tried, with the journal kept.
fn restore_services(
    ctx: &Ctx,
    services: &Services,
    lock: &FileLock,
    journal: &Journal,
    reapply: Reapply,
) -> Result<()> {
    if let Err(e) = reapply_rules(ctx, reapply) {
        out::warn(format!(
            "旧防火墙规则恢复失败: {}；请执行 onebox net-apply 重试",
            e.report_text()
        ));
    }
    let mut errors = Vec::new();
    for name in SERVICES.iter().chain(LEGACY_NETWORK_SERVICES.iter()) {
        if !services.exists(name) {
            continue;
        }
        let result = if journal.enabled_services().iter().any(|n| n == name) {
            services
                .enable(name)
                .map_err(|e| format!("启用 {name}: {e}"))
        } else {
            services
                .disable(name)
                .map_err(|e| format!("停用 {name}: {e}"))
        };
        errors.extend(result.err());
    }
    if let Err(e) = cron::restore(ctx, &journal.cron(), Scope::Node) {
        errors.push(format!("恢复定时任务: {e}"));
    }
    for name in START_ORDER {
        if !journal.active_services().iter().any(|n| n == name) {
            continue;
        }
        if name == svc::SUBSCRIPTION && lock.is_inherited() {
            // A self-update child runs the new binary; the parent restores
            // its own manager and starts the worker with it (G6).
            continue;
        }
        let started = services
            .start(name)
            .and_then(|()| services.wait_running(name, WAIT_RUNNING));
        if let Err(e) = started {
            errors.push(format!("启动 {name}: {e}"));
        }
    }
    ensure!(errors.is_empty(), "{}", errors.join("; "));
    Ok(())
}

/// The old generation's firewall rules and hops (rules only: restored files
/// already hold its units and boot hooks).
fn reapply_rules(ctx: &Ctx, reapply: Reapply) -> Result<()> {
    let cfg = match reapply {
        Reapply::Nothing => return Ok(()),
        Reapply::Config(cfg) => *cfg,
        Reapply::V2(values) => match migrate_v2(&ctx.paths, &values) {
            Ok(cfg) => cfg,
            Err(e) => return skip_rules(&e.to_string()),
        },
        Reapply::Skip(reason) => return skip_rules(&reason),
    };
    network::apply_rules(ctx, &cfg)
}

fn skip_rules(reason: &str) -> Result<()> {
    out::warn(format!(
        "旧配置无法用于恢复防火墙规则（{reason}）；文件已恢复，请执行 onebox regen 重建规则"
    ));
    Ok(())
}

/// A version-1 journal's old state, migrated with the v2 subscription
/// settings the snapshot restored next to it.
fn migrate_v2(
    paths: &Paths,
    values: &std::collections::BTreeMap<String, String>,
) -> Result<NodeConfig> {
    let settings = match read_bounded(&paths.subscription_v2_settings(), 1024 * 1024) {
        Ok(bytes) => Some(serde_json::from_slice::<Value>(&bytes)?),
        Err(Error::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };
    let migrated = statev2::migrate(
        values,
        settings.as_ref(),
        &DeployedCerts::of(paths),
        &mut OsRandom,
    )?;
    Ok(migrated.config)
}
