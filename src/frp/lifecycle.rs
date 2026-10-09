//! The FRP operations that change the host (spec H §5): apply (install,
//! configure, update, rotate-token, rotate-ca), renew, start/stop/restart, uninstall,
//! the boot hook `frps net-apply` and crash recovery.
//!
//! Every mutation takes the FRP lock (`/etc/.onebox-frp.lock`, v2 path)
//! and first finishes an interrupted FRP transaction. FRP never takes the
//! node lock: it reads the node configuration only to avoid its ports, and
//! the node re-checks FRP's reservations under its own lock (G24). Callers
//! holding both take the node lock first.
//!
//! Apply order (v2's, with the prerequisites moved before the snapshot):
//! paths → recovery → (for `update`: the release, stopping when nothing
//! changes) → packages, nginx (distro service neutralized,
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
//! - a change built from a state that another operation replaced in the
//!   meantime is refused (compare-and-swap under the FRP lock; v2 wrote the
//!   stale token back);
//! - `update` to the installed version changes nothing: only the release
//!   is resolved, before packages, the cron daemon or DNS are checked;
//! - switching to tcp mode removes the stale `nginx.conf` (the web
//!   certificate directory and its ACME account are kept for a switch back);
//! - a failed website renewal no longer rolls back the control
//!   certificate or restarts the services: the deployed pair is untouched
//!   by a failed renewal, and the failure is reported after the commit. A
//!   new pair the web nginx could not load (`nginx -t` or its restart
//!   failed) still rolls the whole renewal back, as in v2, so the next run
//!   retries instead of finding the pair not due;
//! - `renew --cron` prints nothing unless a certificate changed or
//!   something failed (v2 printed its summary line every night);
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
use super::runtime::{leftovers_only, mkdirs, Leftovers, Runtime, BUSY, FIREWALL_OWNER};
use super::txn::{self, recover_locked, Recovery, Txn};
use crate::cert::hooks::{renew_dir_with, web_spec};
use crate::cert::{CertDir, CfCredentials, Challenge, Trust};
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
/// The closing line of a renewal (v2 text).
const RENEWED: &str = "FRP 证书检查完成，私有 CA 保持不变。";
const VERIFY_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a scheduled renewal waits for another FRP operation.
pub const CRON_LOCK_WAIT: Duration = Duration::from_secs(600);

/// One configuration change.
#[derive(Clone, Debug, Default)]
pub struct Change {
    /// Generate a new token (all old clients stop working).
    pub rotate: bool,
    /// Replace the private CA (all exported clients must be exported
    /// again).
    pub rotate_ca: bool,
    /// Cloudflare credentials for a DNS-01 website certificate.
    pub cloudflare: Option<CfCredentials>,
    /// For the journal and messages (`安装`, `更新`, …).
    pub reason: &'static str,
    /// Do nothing when the result would equal the installed deployment
    /// (`update` to the version of the installed `frps` binary, the stored
    /// state otherwise unchanged).
    pub skip_unchanged: bool,
    /// The installed state the change was built from.
    pub expected: Expected,
}

/// The installed state a change was built from, compared with the state
/// on disk under the FRP lock: a `configure` that waited at its
/// confirmation while another administrator ran `rotate-token` must not
/// write the revoked token (or anything else) back.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Expected {
    /// No check (the caller read the state under the FRP lock).
    #[default]
    Any,
    /// FRP was not installed.
    Absent,
    /// The state as it was read.
    State(FrpState),
}

impl Expected {
    /// What a command read before taking the lock.
    pub fn of(read: Option<&FrpState>) -> Expected {
        match read {
            None => Expected::Absent,
            Some(state) => Expected::State(state.clone()),
        }
    }

    /// [`Error::Conflict`] unless `current` is still what was read.
    pub fn check(&self, current: Option<&FrpState>) -> Result<()> {
        let unchanged = match self {
            Expected::Any => true,
            Expected::Absent => current.is_none(),
            Expected::State(read) => current == Some(read),
        };
        if unchanged {
            Ok(())
        } else {
            Err(Error::Conflict)
        }
    }
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
    change.expected.check(previous.as_ref())?;
    match &previous {
        None => state.validate_draft()?,
        Some(previous) => state.validate_change(Some(previous))?,
    }
    let _signals = SignalScope::install()?;
    // `update` resolves the release first: when nothing would change, no
    // package, scheduler or DNS check may touch the host or fail it.
    let early = if change.skip_unchanged {
        fetch::ensure_curl_as(ctx, rt.root)?;
        let staged = stage(rt, &state)?;
        if unchanged(previous.as_ref(), &state, &staged) {
            out::ok(format!("FRP 已是 {} 版本，无需更新", staged.version));
            return Ok(());
        }
        Some(staged)
    } else {
        None
    };
    let nginx = prerequisites(rt, &state)?;
    check_dns(ctx, &state)?;
    signal::check()?;
    let staged = match early {
        Some(staged) => staged,
        None => stage(rt, &state)?,
    };
    signal::check()?;
    let mut state = state;
    Txn::run(
        rt,
        lock,
        change.reason,
        &journal::targets(rt.paths()),
        |txn| deploy(rt, lock, txn, &mut state, &change, &staged, nginx),
    )?;
    out::ok(DEPLOYED);
    Ok(())
}

/// The binary stays and the state would equal the installed one.
fn unchanged(previous: Option<&FrpState>, state: &FrpState, staged: &Staged) -> bool {
    let mut next = state.clone();
    next.version.clone_from(&staged.version);
    staged.binary.is_none() && previous == Some(&next)
}

/// The frps binary of `state.version`: the installed one, or a verified
/// download staged for the deployment.
fn stage(rt: &Runtime, state: &FrpState) -> Result<Staged> {
    release::prepare(
        rt.ctx,
        rt.env,
        &state.version,
        &rt.paths().frp_bin.join("frps"),
        &stage_parent(rt)?,
    )
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
    firewall::reconcile_owner(rt.ctx, FIREWALL_OWNER, &state.firewall_ports())?;
    if let Some(web) = state.web().cloned() {
        txn.phase(Phase::ApplyWebsite)?;
        website(rt, state, &web, change.cloudflare.as_ref())?;
    }
    txn.phase(Phase::StartServices)?;
    rt.start(lock, FRPS)?;
    services.enable(FRPS)?;
    txn.phase(Phase::HealthCheck)?;
    rt.health(state, true)?;
    txn.phase(Phase::WriteCron)?;
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
    if change.rotate_ca {
        super::ca::discard(&paths.frp_root)?;
    }
    control_cert(ctx, &paths.frp_root, &state.domain)?;
    signal::check()?;
    let binary = paths.frp_bin.join("frps");
    if let Some(new) = &staged.binary {
        copy_file(new, &binary, 0o755)?;
    }
    state.version.clone_from(&staged.version);
    let config = paths.frp_root.join("frps.toml");
    atomic_write(
        &config,
        server_toml(state, &paths.frp_root).as_bytes(),
        0o600,
    )?;
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
    // Custom pairs may use a private CA (v2 parity).
    let spec = web_spec(
        &web.app.cert_domains(),
        &web_cert(&web.tls),
        Challenge::Webroot(webroot),
        Trust::Pinned,
    );
    let dir = CertDir::new(paths.frp_root.join("web-tls"));
    rt.cert_engine().ensure(&dir, &spec, false, cf)?;
    signal::check()?;
    services.stop(FRP_WEB)?;
    rt.write_web_config(state, NginxPhase::Full)?;
    services.start(FRP_WEB)?;
    services.enable(FRP_WEB)
}

/// Check (and when due renew) the control and website certificates;
/// returns whether one of them changed. `scheduled` = run by cron: website
/// certificates only when due, and silent unless a certificate changed or
/// something failed.
pub fn renew(rt: &Runtime, lock: &FileLock, scheduled: bool) -> Result<bool> {
    check_paths(rt.paths())?;
    recover_locked(rt, lock)?;
    let state = installed_state(rt)?;
    let _signals = SignalScope::install()?;
    let targets = [rt.paths().frp_root.clone()];
    let renewed = Txn::run(rt, lock, "续期", &targets, |txn| {
        renew_in(rt, lock, txn, &state, scheduled)
    })?;
    if let Some(e) = renewed.web_failure {
        return Err(e.wrap("FRP 网站证书续期失败"));
    }
    if announced(scheduled, renewed.changed) {
        out::ok(RENEWED);
    }
    Ok(renewed.changed)
}

/// Whether a committed renewal prints its closing line: always when run by
/// hand, from cron only when a certificate changed (its log stays empty on
/// the other nights; failures are errors either way).
fn announced(scheduled: bool, changed: bool) -> bool {
    !scheduled || changed
}

/// What a committed renewal did.
struct Renewed {
    /// The control or the website certificate changed.
    changed: bool,
    /// The website renewal failed with the deployed pair untouched
    /// (reported after the commit).
    web_failure: Option<Error>,
}

/// The renewal inside its transaction; a website renewal failure is
/// returned (not raised) so the rest commits.
fn renew_in(
    rt: &Runtime,
    lock: &FileLock,
    txn: &mut Txn,
    state: &FrpState,
    scheduled: bool,
) -> Result<Renewed> {
    let services = rt.services();
    txn.phase(Phase::RenewCertificates)?;
    let control = control_cert(rt.ctx, &rt.paths().frp_root, &state.domain)?;
    signal::check()?;
    let (website, web_failure) = match state.web() {
        Some(web) => match renew_website(rt, state, web, scheduled)? {
            Ok(changed) => (changed, None),
            Err(e) => (false, Some(e)),
        },
        None => (false, None),
    };
    if control && services.running(FRPS) {
        rt.restart(lock, FRPS)?;
        rt.health(state, false)?;
    }
    txn.phase(Phase::WriteCron)?;
    rt.rewrite_cron(state)?;
    Ok(Renewed {
        changed: control || website,
        web_failure,
    })
}

/// Renew the website certificate; the inner value is whether the deployed
/// pair changed. A failed renewal leaves that pair untouched and is the
/// inner error (the rest of the renewal commits). A new pair nginx could
/// not be made to serve (`nginx -t` or the restart failed) is the outer
/// error, which rolls the whole renewal back, `web-tls` included:
/// committed, the running nginx would keep the old certificate while every
/// later scheduled run finds the deployed pair not due.
fn renew_website(
    rt: &Runtime,
    state: &FrpState,
    web: &WebSettings,
    scheduled: bool,
) -> Result<Result<bool>> {
    let services = rt.services();
    if web.tls == WebTls::Http01 && !services.running(FRP_WEB) {
        out::info("FRP 网站已停止，本次跳过需要 HTTP 入口的续期。");
        return Ok(Ok(false));
    }
    let dir = rt.paths().frp_root.join("web-tls");
    let renewed = CertDir::new(&dir).metadata().and_then(|issued| {
        ensure!(
            issued.is_some(),
            "旧版网站证书需先运行 onebox frps configure 迁移为原生证书管理"
        );
        renew_dir_with(&rt.cert_engine(), &dir, !scheduled, None)
    });
    if renewed.as_ref().is_ok_and(|changed| *changed) {
        rt.write_web_config(state, NginxPhase::Full)
            .and_then(|()| {
                if services.running(FRP_WEB) {
                    services.restart(FRP_WEB)
                } else {
                    Ok(())
                }
            })
            .map_err(|e| e.wrap("FRP 网站证书已续期，但网站服务未能加载新证书"))?;
    }
    Ok(renewed)
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
        firewall::reconcile_owner(rt.ctx, FIREWALL_OWNER, &state.firewall_ports())?;
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
/// three trees (transactional), then the logs and runtime records. Rules
/// the firewall refused to remove keep their ledger in an otherwise empty
/// `FRP_ROOT` and fail the command after everything else is gone; running
/// it again retries them ([`leftovers_only`]).
pub fn uninstall(rt: &Runtime, lock: &FileLock) -> Result<()> {
    let paths = rt.paths();
    check_paths(paths)?;
    recover_locked(rt, lock)?;
    if leftovers_only(paths) {
        return clear_leftovers(rt);
    }
    ensure!(model::installed(paths), "{NOT_INSTALLED}");
    let _signals = SignalScope::install()?;
    let left = Txn::run(rt, lock, "卸载", &journal::targets(paths), |txn| {
        teardown(rt, txn)
    })?;
    for dir in [&paths.frp_run, &paths.frp_log] {
        remove_tree_if_exists(dir)?;
    }
    ensure!(left.is_empty(), "{}", rules_left(rt, &left));
    out::ok("FRP 已卸载，代理与自建站保留。");
    Ok(())
}

fn teardown(rt: &Runtime, txn: &mut Txn) -> Result<Leftovers> {
    let paths = rt.paths();
    let services = rt.services();
    txn.phase(Phase::Teardown)?;
    services.stop(FRP_WEB)?;
    services.stop(FRPS)?;
    let left = rt.clear_firewall()?;
    if cron::available(rt.ctx) {
        Crontab::edit(rt.ctx, |tab| Ok(tab.remove_scope(Scope::Frp)))?;
    }
    services.remove(FRP_WEB)?;
    services.remove(FRPS)?;
    for dir in [&paths.frp_root, &paths.frp_bin, &paths.frp_web] {
        remove_tree_if_exists(dir)?;
    }
    rt.keep_leftovers(&left)?;
    signal::check()?;
    Ok(left)
}

/// The error of an uninstall whose firewall rules were not all removed.
fn rules_left(rt: &Runtime, left: &Leftovers) -> String {
    format!(
        "FRP 已卸载，但以下防火墙规则未能删除: {}；记录保留于 {}，修复防火墙后再次执行 onebox frps uninstall",
        left.messages.join("；"),
        firewall::ledger_path(rt.paths(), FIREWALL_OWNER).display()
    )
}

/// Retry the rules an earlier uninstall could not remove; `FRP_ROOT` goes
/// once none is left.
fn clear_leftovers(rt: &Runtime) -> Result<()> {
    let left = rt.clear_firewall()?;
    ensure!(left.is_empty(), "{}", rules_left(rt, &left));
    remove_tree_if_exists(&rt.paths().frp_root)?;
    out::ok("FRP 遗留的防火墙规则已删除");
    Ok(())
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
                // A committed journal whose cleanup failed is harmless; an
                // unfinished or unreadable one must be recovered first.
                let pending = journal::load(paths)
                    .map_or(true, |j| j.is_some_and(|j| !j.phase.is_finished()));
                ensure!(!pending, "{}", journal::PENDING);
                Some(lock)
            }
            Err(Error::Busy(_)) => None,
            Err(e) => return Err(e),
        }
    };
    let state = model::load(paths)?.ok_or_else(|| Error::msg(NOT_INSTALLED))?;
    firewall::reconcile_owner(ctx, FIREWALL_OWNER, &state.firewall_ports()).map(drop)
}

/// Roll back an interrupted FRP transaction (`onebox recover`, after the
/// node journal). Nothing to do without a journal. A rollback that
/// restored the files but could not restart, re-enable or re-open
/// everything is an error listing those steps (the journal is gone, so
/// FRP commands work again).
pub fn recover(ctx: &Ctx) -> Result<()> {
    if !journal::exists(&ctx.paths) {
        return Ok(());
    }
    let rt = Runtime::system(ctx);
    let lock = rt.lock()?;
    recover_with(&rt, &lock)
}

/// [`recover`] with an explicit runtime and the FRP lock held.
pub fn recover_with(rt: &Runtime, lock: &FileLock) -> Result<()> {
    match txn::recover(rt, lock)? {
        Recovery::Nothing => Ok(()),
        Recovery::RolledBack(missed) if missed.is_empty() => {
            out::ok("已恢复未完成的 FRP 事务");
            Ok(())
        }
        Recovery::RolledBack(missed) => Err(Error::msg(format!(
            "FRP 事务已回滚{}",
            txn::partly_restored(&missed)
        ))),
    }
}

#[cfg(test)]
mod tests;
