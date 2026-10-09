//! prepare-state, replace-cores, prepare-cores, prepare-certificates.
//!
//! Changes from v2: replacement cores are checked before the journal
//! exists; a working core is never replaced by prepare-cores (G2); crash
//! leftovers (temp files next to every owned path, backup stages) are
//! swept just before the journal snapshot (E-8.1#16); TCP-80 holders of the
//! old generation — cores, site, subscription nginx, the ip-mode worker —
//! are stopped for any HTTP-01 user (G21).

use super::Run;
use crate::apply::network;
use crate::domain::config::SubscriptionMode;
use crate::domain::defaults::HTTP_PORT;
use crate::domain::ports::PortPlan;
use crate::domain::protocol::Core;
use crate::domain::NodeConfig;
use crate::error::{Context, Error, Result};
use crate::host::cores;
use crate::host::service as svc;
use crate::paths::Paths;
use crate::sys::fs::{copy_file, sweep_stale, TEMP_PREFIX};
use crate::sys::{net, signal};
use crate::ui::out;
use std::fs;
use std::path::Path;
use std::time::Duration;

/// Largest core binary accepted as a replacement (v2).
const MAX_CORE_BYTES: u64 = 512 * 1024 * 1024;
/// Atomic-write temp files younger than this may belong to a concurrent
/// writer outside the node lock (ledgers of other owners); older ones are
/// crash leftovers.
const TEMP_STALE_AFTER: Duration = Duration::from_secs(10 * 60);
/// Backup staging directories (`backups/.new-<id>`).
pub const BACKUP_STAGE_PREFIX: &str = ".new-";

/// prepare-state: the manager executable, a backup's files, subscription
/// devices (crash leftovers were swept before the journal was begun).
pub fn prepare_state(run: &mut Run) -> Result<()> {
    let ctx = run.ctx;
    run.features.install_self(ctx)?;
    if let Some(id) = run.intents.restore_backup.clone() {
        crate::backup::archive::restore_files(ctx, &id)?;
    }
    let migrated = run.intents.migrated_devices.as_deref();
    run.features
        .prepare_subscription(ctx, &run.cfg, migrated, run.intents.clear_devices)?;
    Ok(())
}

/// Crash leftovers, removed before the journal snapshot is taken (so they
/// are neither copied into it nor restored by a rollback): `atomic_write`
/// temp files next to any owned path — in `ROOT`, the site root and the
/// subscription ACME webroot (whole trees), and in the directories of the
/// snapshot targets outside them (manager, cores, units, init scripts) —
/// and backup staging directories (the node lock is held, so no backup is
/// being created). Failures only warn.
pub fn sweep_leftovers(paths: &Paths) {
    let mut failed = Vec::new();
    let flat = [
        paths.executable.parent().map(Path::to_path_buf),
        Some(paths.bin.clone()),
        Some(paths.systemd.clone()),
        Some(paths.initd.clone()),
    ];
    for dir in flat.into_iter().flatten() {
        sweep_temps(&dir, &mut failed);
    }
    for tree in [
        paths.root.clone(),
        paths.site_root.clone(),
        paths.subscription_acme(),
    ] {
        sweep_tree(&tree, SWEEP_DEPTH, &mut failed);
    }
    let stages = paths.backups();
    if let Err(e) = sweep_stale(&stages, BACKUP_STAGE_PREFIX, Duration::ZERO) {
        failed.push(format!("{}: {e}", stages.display()));
    }
    for failure in failed {
        out::warn(format!("清理残留临时文件失败 {failure}"));
    }
}

/// How deep [`sweep_leftovers`] descends into an owned tree.
const SWEEP_DEPTH: usize = 8;

fn sweep_temps(dir: &Path, failed: &mut Vec<String>) {
    if let Err(e) = sweep_stale(dir, TEMP_PREFIX, TEMP_STALE_AFTER) {
        failed.push(format!("{}: {e}", dir.display()));
    }
}

/// [`sweep_temps`] in `dir` and its real subdirectories (symlinks are not
/// followed), skipping hidden ones (journals, staging, locks) and user
/// backups, which are never part of a generation.
fn sweep_tree(dir: &Path, depth: usize, failed: &mut Vec<String>) {
    sweep_temps(dir, failed);
    let Some(below) = depth.checked_sub(1) else {
        return;
    };
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') || name == "backups" || name == "content-backups" {
            continue;
        }
        if entry.file_type().is_ok_and(|t| t.is_dir()) {
            sweep_tree(&entry.path(), below, failed);
        }
    }
}

/// Every replacement names a core of the configuration, at most once (v2
/// message). Checked before the journal is begun.
pub fn check_replacements(cfg: &NodeConfig, replace: &[(Core, std::path::PathBuf)]) -> Result<()> {
    for (i, (core, _)) in replace.iter().enumerate() {
        let duplicate = replace[..i].iter().any(|(c, _)| c == core);
        ensure!(cfg.uses(*core) && !duplicate, "待更新内核不在配置中或重复");
    }
    Ok(())
}

/// replace-cores: copy each verified candidate over the live binary (the
/// old one is in the snapshot).
pub fn replace_cores(run: &mut Run) -> Result<()> {
    check_replacements(&run.cfg, &run.intents.replace_cores)?;
    for (core, candidate) in &run.intents.replace_cores {
        let usable = fs::symlink_metadata(candidate)
            .is_ok_and(|m| m.file_type().is_file() && m.len() <= MAX_CORE_BYTES);
        ensure!(usable, "待更新内核文件无效");
        copy_file(candidate, &run.ctx.paths.core_bin(*core), 0o755)
            .with_context(|| format!("替换 {} 失败", core.title()))?;
    }
    Ok(())
}

/// prepare-cores: used cores present (downloaded only when missing or
/// broken), versions recorded, own addresses refreshed (a failing `ip`
/// fails the apply: the self-access policy is never silently weakened),
/// ports re-checked against FRP under the lock.
pub fn prepare_cores(run: &mut Run) -> Result<()> {
    let ctx = run.ctx;
    for core in run.cfg.cores() {
        let version = cores::ensure_installed(ctx, core, &run.cfg.versions)?;
        match core {
            Core::Singbox => run.cfg.versions.singbox = Some(version),
            Core::Xray => run.cfg.versions.xray = Some(version),
        }
    }
    run.cfg.routing.own_cidrs = net::own_global_cidrs(ctx).context("无法读取本机地址")?;
    let frp = crate::apply::frp_reservations(&ctx.paths)?;
    PortPlan::of(&run.cfg, &frp).validate()
}

/// prepare-certificates (G21, G8): when HTTP-01 needs TCP 80, stop the old
/// generation's holders of it and open it temporarily; then the
/// subscription, site and proxy certificates (credentials passed in, never
/// prompted; they are persisted inside snapshotted directories).
pub fn prepare_certificates(run: &mut Run) -> Result<()> {
    let ctx = run.ctx;
    if network::needs_http01_port80(&run.cfg) {
        stop_port80_holders(run)?;
        network::open_acme_port(ctx)?;
    }
    let cf = run.intents.cloudflare.clone();
    let renew = run.intents.renew;
    run.features
        .subscription_certificates(ctx, &run.cfg, renew.subscription, cf.as_ref())?;
    let content = run.intents.site_content.clone();
    run.features
        .site_prepare(ctx, &mut run.cfg, content.as_ref(), renew.site, cf.as_ref())?;
    signal::check()?;
    run.features
        .proxy_certificate(ctx, &mut run.cfg, renew.proxy, cf.as_ref())?;
    Ok(())
}

/// Stop old-generation services listening on TCP 80 that the new
/// generation does not keep there, so the built-in responder or the site's
/// bootstrap nginx can bind it. Rollback restarts whatever was running.
fn stop_port80_holders(run: &Run) -> Result<()> {
    let Some(old) = &run.old else {
        return Ok(());
    };
    for name in port80_holders(old, &run.cfg) {
        if run.services.running(name) {
            run.services
                .stop(name)
                .map_err(|e| Error::msg(format!("停止占用 80 端口的 {name} 失败: {e}")))?;
        }
    }
    Ok(())
}

/// Services of `old` holding TCP 80 that `new` does not keep holding it
/// in the same role: the site, the standalone subscription nginx (its
/// HTTP-01 server, or its HTTPS port — a generation needing TCP 80 for
/// HTTP-01 never keeps that at 80), the ip-mode subscription worker bound
/// to port 80, and cores with a TCP inbound on 80.
pub fn port80_holders(old: &NodeConfig, new: &NodeConfig) -> Vec<&'static str> {
    let mut holders = Vec::new();
    if old.site_active().is_some() && new.site_active().is_none() {
        holders.push(svc::SITE);
    }
    let on_80 = |cfg, mode| subscription_port(cfg, mode) == Some(HTTP_PORT);
    let gives_up = |mode| on_80(old, mode) && !on_80(new, mode);
    if gives_up(Mode::Standalone) || (standalone_port80(old) && !standalone_port80(new)) {
        holders.push(svc::SUBSCRIPTION_WEB);
    }
    if gives_up(Mode::Ip) {
        holders.push(svc::SUBSCRIPTION);
    }
    for core in Core::ALL {
        let on_80 = old
            .inbounds
            .iter()
            .any(|i| i.core == core && i.port == HTTP_PORT && i.protocol.transport().tcp());
        if on_80 {
            holders.push(core.service());
        }
    }
    holders
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Ip,
    Standalone,
}

/// The subscription's own TCP port when it is served in `mode`.
fn subscription_port(cfg: &NodeConfig, mode: Mode) -> Option<u16> {
    let sub = cfg.subscription.as_ref()?;
    let served = match sub.mode {
        SubscriptionMode::Ip { .. } => Mode::Ip,
        SubscriptionMode::Standalone { .. } => Mode::Standalone,
        SubscriptionMode::Site => return None,
    };
    (served == mode).then_some(sub.port)
}

fn standalone_port80(cfg: &NodeConfig) -> bool {
    cfg.subscription.as_ref().is_some_and(|s| {
        matches!(
            s.mode,
            SubscriptionMode::Standalone {
                http01_port80: true,
                ..
            }
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::config::WebCert;
    use crate::domain::fixtures::{self, ip_subscription, standalone_subscription, with_site};
    use crate::domain::protocol::Protocol;
    use std::path::PathBuf;

    #[test]
    fn replacements_must_be_used_and_unique() {
        let cfg = fixtures::config(&[(Protocol::VlessReality, 443, Core::Xray)]);
        let x = (Core::Xray, PathBuf::from("/tmp/x"));
        let s = (Core::Singbox, PathBuf::from("/tmp/s"));
        check_replacements(&cfg, &[]).unwrap();
        check_replacements(&cfg, std::slice::from_ref(&x)).unwrap();
        for bad in [vec![s], vec![x.clone(), x]] {
            assert_eq!(
                check_replacements(&cfg, &bad).unwrap_err().to_string(),
                "待更新内核不在配置中或重复"
            );
        }
    }

    #[test]
    fn port80_holders_are_what_the_new_generation_gives_up() {
        let reality = fixtures::config(&[
            (Protocol::VlessReality, 443, Core::Singbox),
            (Protocol::VlessWs, 80, Core::Xray),
        ]);
        let site = with_site(reality.clone(), "example.com", false);
        let mut sub = reality.clone();
        sub.subscription = Some(standalone_subscription(
            "s.example.com",
            8448,
            WebCert::Http01,
        ));
        let plain = fixtures::config(&[(Protocol::VlessReality, 443, Core::Singbox)]);
        let with_sub = |sub| {
            let mut cfg = plain.clone();
            cfg.subscription = Some(sub);
            cfg
        };
        // The ip-mode worker binds its port itself.
        let ip80 = with_sub(ip_subscription(80));
        let ip8448 = with_sub(ip_subscription(8448));
        // A standalone subscription whose HTTPS port is 80.
        let https80 = with_sub(standalone_subscription(
            "s.example.com",
            80,
            WebCert::Cloudflare,
        ));
        let http01 = with_sub(standalone_subscription(
            "s.example.com",
            8448,
            WebCert::Http01,
        ));
        let cases: [(&NodeConfig, &NodeConfig, &[&str]); 11] = [
            (&reality, &plain, &[svc::XRAY]),
            (&site, &plain, &[svc::SITE, svc::XRAY]),
            (
                &site,
                &with_site(plain.clone(), "example.com", false),
                &[svc::XRAY],
            ),
            (&sub, &plain, &[svc::SUBSCRIPTION_WEB, svc::XRAY]),
            (&plain, &site, &[]),
            (&ip80, &plain, &[svc::SUBSCRIPTION]),
            (&ip80, &ip8448, &[svc::SUBSCRIPTION]),
            (&ip80, &ip80, &[]),
            (&https80, &plain, &[svc::SUBSCRIPTION_WEB]),
            // Port 80 changes role (HTTPS → HTTP-01): the running nginx
            // cannot answer the challenges.
            (&https80, &http01, &[svc::SUBSCRIPTION_WEB]),
            (&http01, &http01, &[]),
        ];
        for (i, (old, new, expected)) in cases.into_iter().enumerate() {
            assert_eq!(port80_holders(old, new), expected, "case {i}");
        }
    }
}
