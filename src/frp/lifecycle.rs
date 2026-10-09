//! The FRP operations that change the host (spec H §5): apply (install,
//! configure, update, rotate-token), renew, start/stop/restart, uninstall,
//! the boot hook `frps net-apply` and crash recovery.
//!
//! Every mutation takes the FRP lock (`/etc/.onebox-frp.lock`, v2 path)
//! and first finishes an interrupted FRP transaction. FRP never takes the
//! node lock: it reads the node configuration only to avoid its ports, and
//! the node re-checks FRP's reservations under its own lock (G24). Callers
//! holding both take the node lock first.
//!
//! Apply order (v2's, with the prerequisites moved before the snapshot):
//! paths → recovery → packages, nginx (distro service neutralized,
//! H-8.1#2), cron daemon (checked up front, H-8.1#17), DNS → frps binary
//! (downloaded only when the version changes, H-8.1#4) → journal + snapshot
//! → stop services → port checks → directories, token, private CA,
//! binary, `frps.toml` + `frps verify`, `state.json`, `EXE` → units →
//! firewall → website certificate and nginx → start → health check → cron
//! → commit. Any error or signal rolls everything back.
//!
//! Changes from v2:
//! - Cloudflare credentials arrive resolved (the CLI looked them up or
//!   asked before the confirmation) and are persisted by the certificate
//!   engine inside the transaction, after the directories exist (H-8.1#1);
//! - `update` to the installed version changes nothing;
//! - switching to tcp mode removes the stale `nginx.conf` (the web
//!   certificate directory and its ACME account are kept for a switch back);
//! - a failed website renewal no longer rolls back the control
//!   certificate or restarts the services: the deployed pair is untouched
//!   by a failed renewal, and the failure is reported after the commit;
//! - manual renewals renew the website certificate even when not due
//!   (scheduled ones only when due), and custom website certificates are
//!   redeployed when their source files changed;
//! - `net-apply` refuses while a crashed FRP transaction waits for
//!   recovery (G24), and never waits for the FRP lock;
//! - v1 PID-file processes, the v1 firewall ledger and `FRP_ROOT/acme`
//!   are no longer migrated (v1 is not supported; the v1 `state.conf` is
//!   still read, G10).

use super::ca::control_cert;
use super::journal::{self, Phase};
use super::model::{self, FrpState, WebSettings, WebTls, NOT_INSTALLED};
use super::preflight::{check_dns, check_paths, check_ports};
use super::release::{self, Staged};
use super::render::{server_toml, NginxPhase};
use super::runtime::{mkdirs, Runtime, BUSY};
use super::txn::{recover_locked, Txn};
use crate::cert::{self, CfCredentials};
use crate::ctx::Ctx;
use crate::domain::config::WebCert;
use crate::error::{Error, Result};
use crate::host::cron::{self, Crontab, Scope};
use crate::host::service::{FRPS, FRP_WEB};
use crate::host::{fetch, firewall, nginx, pkg};
use crate::sys::exec::Cmd;
use crate::sys::fs::{atomic_write, copy_file, remove_file_if_exists, remove_tree_if_exists};
use crate::sys::lock::{inherited_lock_offered, FileLock};
use crate::sys::signal::{self, SignalScope};
use crate::ui::out;
use std::path::PathBuf;
use std::time::Duration;

const DEPLOYED: &str =
    "FRP 已部署。请运行 onebox frps client 导出客户端配置；网站 DNS 与云防火墙仍需由您配置。";
const VERIFY_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a scheduled renewal waits for another FRP operation.
pub const CRON_LOCK_WAIT: Duration = Duration::from_secs(600);

/// One configuration change.
#[derive(Clone, Debug, Default)]
pub struct Change {
    /// Generate a new token (all old clients stop working).
    pub rotate: bool,
    /// Cloudflare credentials for a DNS-01 website certificate.
    pub cloudflare: Option<CfCredentials>,
    /// For the journal and messages (`安装`, `更新`, …).
    pub reason: &'static str,
    /// Do nothing when the result would equal the installed deployment
    /// (`update` to the running version).
    pub skip_unchanged: bool,
}

/// `start` / `stop` / `restart`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceAction {
    Start,
    Stop,
    Restart,
}

/// The installed state (`NOT_INSTALLED` without one), notices printed.
pub fn installed_state(rt: &Runtime) -> Result<FrpState> {
    let state = model::load(rt.paths())?.ok_or_else(|| Error::msg(NOT_INSTALLED))?;
    for warning in state.warnings() {
        out::warn(warning);
    }
    Ok(state)
}

/// [`apply_locked`] with the FRP lock.
pub fn apply(rt: &Runtime, state: FrpState, change: Change) -> Result<()> {
    let lock = rt.lock()?;
    apply_locked(rt, &lock, state, change)
}

/// Make `state` the running FRP deployment (module docs for the order).
pub fn apply_locked(rt: &Runtime, lock: &FileLock, state: FrpState, change: Change) -> Result<()> {
    let ctx = rt.ctx;
    check_paths(rt.paths())?;
    recover_locked(rt, lock)?;
    let previous = model::load(rt.paths()).ok().flatten();
    match &previous {
        None => state.validate_draft()?,
        Some(previous) => state.validate_change(Some(previous))?,
    }
    let _signals = SignalScope::install()?;
    let nginx = prerequisites(rt, &state)?;
    check_dns(ctx, &state)?;
    signal::check()?;
    let staged = release::prepare(
        ctx,
        rt.env,
        &state.version,
        &rt.paths().frp_bin.join("frps"),
        &stage_parent(rt)?,
    )?;
    signal::check()?;
    if change.skip_unchanged && unchanged(previous.as_ref(), &state, &staged) {
        out::ok(format!("FRP 已是 {} 版本，无需更新", staged.version));
        return Ok(());
    }
    let mut txn = Txn::begin(rt, lock, change.reason, &journal::targets(rt.paths()))?;
    let mut state = state;
    match deploy(rt, lock, &mut txn, &mut state, &change, &staged, nginx) {
        Ok(()) => txn.commit()?,
        Err(e) => return Err(txn.abort(e)),
    }
    out::ok(DEPLOYED);
    Ok(())
}

/// The binary stays and the state would equal the installed one.
fn unchanged(previous: Option<&FrpState>, state: &FrpState, staged: &Staged) -> bool {
    let mut next = state.clone();
    next.version.clone_from(&staged.version);
    staged.binary.is_none() && previous == Some(&next)
}

/// Where downloads are staged: next to the FRP lock (not a noexec /tmp).
fn stage_parent(rt: &Runtime) -> Result<PathBuf> {
    let lock = rt.paths().frp_lock();
    lock.parent()
        .map(|p| p.to_path_buf())
        .ok_or_else(|| Error::msg("FRP 目录无父目录"))
}

/// Programs the deployment needs (installed when missing); returns the
/// nginx binary in web mode.
fn prerequisites(rt: &Runtime, state: &FrpState) -> Result<Option<PathBuf>> {
    let ctx = rt.ctx;
    fetch::ensure_curl_as(ctx, rt.root)?;
    let mut installer = pkg::Installer::with_root(ctx, rt.root);
    installer.ensure("openssl", "openssl")?;
    installer.ensure("ip", "iproute2")?;
    let nginx = if state.is_web() {
        Some(nginx::ensure_installed_with(ctx, rt.env, rt.root)?)
    } else {
        None
    };
    cron::ensure_scheduler_as(ctx, rt.init, rt.root)?;
    Ok(nginx)
}

/// Everything inside the apply transaction.
fn deploy(
    rt: &Runtime,
    lock: &FileLock,
    txn: &mut Txn,
    state: &mut FrpState,
    change: &Change,
    staged: &Staged,
    nginx: Option<PathBuf>,
) -> Result<()> {
    let services = rt.services();
    txn.phase(Phase::StopServices)?;
    services.stop(FRP_WEB)?;
    services.stop(FRPS)?;
    check_ports(rt.ctx, state)?;
    txn.phase(Phase::WriteFiles)?;
    write_files(rt, state, change, staged)?;
    txn.phase(Phase::ConfigureServices)?;
    services.write_all(&rt.defs(state, nginx.as_deref())?)?;
    if !state.is_web() && services.exists(FRP_WEB) {
        services.remove(FRP_WEB)?;
    }
    txn.phase(Phase::ApplyNetwork)?;
    firewall::reconcile_owner(rt.ctx, "frp", &state.firewall_ports())?;
    if let Some(web) = state.web().cloned() {
        txn.phase(Phase::ApplyWebsite)?;
        website(rt, state, &web, change.cloudflare.as_ref())?;
    }
    txn.phase(Phase::StartServices)?;
    rt.start(lock, FRPS)?;
    services.enable(FRPS)?;
    txn.phase(Phase::HealthCheck)?;
    rt.health(state, true)?;
    txn.phase(Phase::Finalize)?;
    rt.rewrite_cron(state)
}

/// Directories, token, private CA, binary, `frps.toml`, state, `EXE`.
fn write_files(rt: &Runtime, state: &mut FrpState, change: &Change, staged: &Staged) -> Result<()> {
    let ctx = rt.ctx;
    let paths = rt.paths();
    mkdirs(paths)?;
    if change.rotate || state.token.is_empty() {
        state.token = crate::sys::rand::hex(32)?;
    }
    control_cert(ctx, &paths.frp_root, &state.domain)?;
    signal::check()?;
    let binary = paths.frp_bin.join("frps");
    if let Some(new) = &staged.binary {
        copy_file(new, &binary, 0o755)?;
    }
    state.version.clone_from(&staged.version);
    let config = paths.frp_root.join("frps.toml");
    atomic_write(&config, server_toml(state, &paths.frp_root).as_bytes(), 0o600)?;
    let verify = Cmd::new(binary.to_string_lossy())
        .args(["verify", "-c"])
        .arg(config.to_string_lossy())
        .timeout(VERIFY_TIMEOUT);
    ctx.check(&verify)?;
    model::save(paths, state)?;
    (rt.install_self)(ctx)?;
    if !state.is_web() {
        remove_file_if_exists(&paths.frp_root.join("nginx.conf"))?;
    }
    Ok(())
}

/// The website certificate type of the FRP web settings.
pub fn web_cert(tls: &WebTls) -> WebCert {
    match tls {
        WebTls::Http01 => WebCert::Http01,
        WebTls::Cloudflare => WebCert::Cloudflare,
        WebTls::Custom { cert, key } => WebCert::Custom {
            cert: cert.into(),
            key: key.into(),
        },
    }
}

/// Issue or deploy the website certificate (HTTP-01 through the bootstrap
/// nginx on port 80), then run the full nginx.
fn website(
    rt: &Runtime,
    state: &FrpState,
    web: &WebSettings,
    cf: Option<&CfCredentials>,
) -> Result<()> {
    let paths = rt.paths();
    let services = rt.services();
    let webroot = paths.frp_web.join("www");
    let http01 = web.tls == WebTls::Http01;
    if http01 {
        rt.write_web_config(state, NginxPhase::Bootstrap)?;
        services.start(FRP_WEB)?;
    }
    cert::issue_domains(
        rt.ctx,
        &paths.frp_root.join("web-tls"),
        &web.app.cert_domains(),
        &web_cert(&web.tls),
        http01.then_some(webroot.as_path()),
        cf,
    )?;
    signal::check()?;
    services.stop(FRP_WEB)?;
    rt.write_web_config(state, NginxPhase::Full)?;
    services.start(FRP_WEB)?;
    services.enable(FRP_WEB)
}

/// Check (and when due renew) the control and website certificates.
/// `scheduled` = run by cron: website certificates only when due.
pub fn renew(rt: &Runtime, lock: &FileLock, scheduled: bool) -> Result<()> {
    check_paths(rt.paths())?;
    recover_locked(rt, lock)?;
    let state = installed_state(rt)?;
    let _signals = SignalScope::install()?;
    let mut txn = Txn::begin(rt, lock, "续期", &[rt.paths().frp_root.clone()])?;
    let web_failure = match renew_in(rt, lock, &mut txn, &state, scheduled) {
        Ok(failure) => {
            txn.commit()?;
            failure
        }
        Err(e) => return Err(txn.abort(e)),
    };
    if let Some(e) = web_failure {
        return Err(e.wrap("FRP 网站证书续期失败"));
    }
    out::ok("FRP 证书检查完成，私有 CA 保持不变。");
    Ok(())
}

/// The renewal inside its transaction; a website renewal failure is
/// returned (not raised) so the rest commits.
fn renew_in(
    rt: &Runtime,
    lock: &FileLock,
    txn: &mut Txn,
    state: &FrpState,
    scheduled: bool,
) -> Result<Option<Error>> {
    let services = rt.services();
    txn.phase(Phase::RenewCertificates)?;
    let changed = control_cert(rt.ctx, &rt.paths().frp_root, &state.domain)?;
    signal::check()?;
    let web_failure = match state.web() {
        Some(web) => renew_website(rt, state, web, scheduled).err(),
        None => None,
    };
    if changed && services.running(FRPS) {
        rt.restart(lock, FRPS)?;
        rt.health(state, false)?;
    }
    txn.phase(Phase::Finalize)?;
    rt.rewrite_cron(state)?;
    Ok(web_failure)
}

fn renew_website(rt: &Runtime, state: &FrpState, web: &WebSettings, scheduled: bool) -> Result<()> {
    let services = rt.services();
    if web.tls == WebTls::Http01 && !services.running(FRP_WEB) {
        out::info("FRP 网站已停止，本次跳过需要 HTTP 入口的续期。");
        return Ok(());
    }
    let dir = rt.paths().frp_root.join("web-tls");
    let issued = cert::CertDir::new(&dir).metadata()?.is_some();
    ensure!(
        issued,
        "旧版网站证书需先运行 onebox frps configure 迁移为原生证书管理"
    );
    if cert::renew_dir(rt.ctx, &dir, !scheduled, None)? {
        rt.write_web_config(state, NginxPhase::Full)?;
        if services.running(FRP_WEB) {
            services.restart(FRP_WEB)?;
        }
    }
    Ok(())
}

/// Start, stop or restart the FRP services (no transaction, H §5.8).
pub fn service(rt: &Runtime, lock: &FileLock, action: ServiceAction) -> Result<()> {
    check_paths(rt.paths())?;
    recover_locked(rt, lock)?;
    let state = installed_state(rt)?;
    let services = rt.services();
    if action != ServiceAction::Start {
        services.stop(FRP_WEB)?;
        services.stop(FRPS)?;
    }
    if action != ServiceAction::Stop {
        if !services.exists(FRPS) {
            // A layout v2 never started: adopt it with this version's units.
            services.write_all(&rt.defs(&state, None)?)?;
        }
        firewall::reconcile_owner(rt.ctx, "frp", &state.firewall_ports())?;
        if state.is_web() {
            services.start(FRP_WEB)?;
        }
        rt.start(lock, FRPS)?;
        rt.health(&state, true)?;
    }
    out::ok(match action {
        ServiceAction::Start => "FRP 服务已启动",
        ServiceAction::Stop => "FRP 服务已停止",
        ServiceAction::Restart => "FRP 服务已重启",
    });
    Ok(())
}

/// Remove FRP completely: services, firewall rules, cron lines and the
/// three trees (transactional), then the logs and runtime records.
pub fn uninstall(rt: &Runtime, lock: &FileLock) -> Result<()> {
    let paths = rt.paths();
    check_paths(paths)?;
    recover_locked(rt, lock)?;
    ensure!(model::installed(paths), "{NOT_INSTALLED}");
    let _signals = SignalScope::install()?;
    let mut txn = Txn::begin(rt, lock, "卸载", &journal::targets(paths))?;
    match teardown(rt, &mut txn) {
        Ok(()) => txn.commit()?,
        Err(e) => return Err(txn.abort(e)),
    }
    for dir in [&paths.frp_run, &paths.frp_log] {
        remove_tree_if_exists(dir)?;
    }
    out::ok("FRP 已卸载，代理与自建站保留。");
    Ok(())
}

fn teardown(rt: &Runtime, txn: &mut Txn) -> Result<()> {
    let paths = rt.paths();
    let services = rt.services();
    txn.phase(Phase::Teardown)?;
    services.stop(FRP_WEB)?;
    services.stop(FRPS)?;
    firewall::clear_owner(rt.ctx, "frp")?;
    if cron::available(rt.ctx) {
        Crontab::edit(rt.ctx, |tab| Ok(tab.remove_scope(Scope::Frp)))?;
    }
    services.remove(FRP_WEB)?;
    services.remove(FRPS)?;
    for dir in [&paths.frp_root, &paths.frp_bin, &paths.frp_web] {
        remove_tree_if_exists(dir)?;
    }
    signal::check()
}

/// `frps net-apply` (the `onebox-frps` pre-start hook): open the FRP
/// firewall ports of the installed state. It never waits for the FRP
/// lock — the operation that starts frps holds it — and refuses while a
/// crashed FRP transaction waits for `onebox recover` (G24): a journal is
/// "crashed" when nobody holds the lock.
pub fn net_apply(ctx: &Ctx) -> Result<()> {
    let paths = &ctx.paths;
    let _held = if inherited_lock_offered() {
        Some(FileLock::from_inherited(&paths.frp_lock())?)
    } else {
        match FileLock::acquire(&paths.frp_lock(), BUSY) {
            Ok(lock) => {
                ensure!(!journal::exists(paths), "{}", journal::PENDING);
                Some(lock)
            }
            Err(Error::Busy(_)) => None,
            Err(e) => return Err(e),
        }
    };
    let state = model::load(paths)?.ok_or_else(|| Error::msg(NOT_INSTALLED))?;
    firewall::reconcile_owner(ctx, "frp", &state.firewall_ports()).map(drop)
}

/// Roll back an interrupted FRP transaction (`onebox recover`, after the
/// node journal). Nothing to do without a journal.
pub fn recover(ctx: &Ctx) -> Result<()> {
    if !journal::exists(&ctx.paths) {
        return Ok(());
    }
    let rt = Runtime::system(ctx);
    let lock = rt.lock()?;
    recover_locked(&rt, &lock).map(drop)
}

#[cfg(test)]
mod tests;
