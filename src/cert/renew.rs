//! Renewal without an apply: `onebox renew --cron`, `cert renew
//! [proxy|site|subscription|all]` and the v2 cron forms.
//!
//! [`renew_all`] runs under the node lock (the CLI takes it and runs
//! `apply::recover_locked` first). Per target it renews only what is due —
//! or everything selected when forced — then restarts only the affected
//! running service: the cores for the proxy certificate, `onebox-site`,
//! `onebox-subscription-web`. HTTP-01 through the built-in responder opens
//! the temporary firewall owner `acme` for TCP 80 around the acme.sh call.
//!
//! The renewal deploys outside any transaction, so the pair it replaces is
//! kept: when a service does not come back with the new pair (restart or
//! `wait_running` fails), the old pair and metadata are put back and the
//! services restarted again, so the node serves what it served and the
//! next run finds the target due and retries (as the FRP website renewal
//! rolls back). Otherwise the new pair would stay deployed and recorded as
//! a success, a stopped service would stay stopped, and no later run would
//! touch the target for two months. The failure is reported either way.
//!
//! When the proxy certificate identity changes (the renewed pair needs
//! pinning where the clients of the stored configuration do not pin, or
//! the reverse, or the leaf SHA-256 changed while they pin), the report
//! says so: the caller must then run a full apply with the unchanged
//! configuration, which re-records the trust, republishes client
//! configurations and the subscription, and restarts the cores (renewal
//! does not restart them itself in that case).
//!
//! Cloudflare credentials: each DNS-01 target uses what is stored for its
//! directory (or the environment); the CLI resolves credentials for the
//! targets [`credentials_needed`] lists — prompting when interactive —
//! before it takes the lock, and passes them as `cf`, which only those
//! targets use (and store for later scheduled renewals).
//!
//! Changes from v2: no full apply per renewal (G-8.1#4) — a failed
//! restart rolls back only the target's pair, where v2's apply rolled back
//! everything; one cron line for
//! every target instead of three racing for the lock (F-8.1#8); a failing
//! target no longer hides the others; manual renewals are forced; a
//! renewal acme.sh defers while the certificate expires within 30 days is
//! a warning instead of a silent "unchanged".

use super::cloudflare::{self, CfCredentials};
use super::engine::{Engine, RenewKind, Renewal, RENEW_DEFERRED};
use super::hooks::{proxy_spec, served_by, subscription_acme_root, web_spec};
use super::method::{CertSpec, Challenge};
use super::openssl::{publicly_trusted, Trust};
use super::store::{CertDir, SavedPair};
use super::{CertScope, CertScopes};
use crate::ctx::Ctx;
use crate::domain::config::{NodeConfig, ProxyCertMode, SubscriptionMode};
use crate::domain::protocol::Transport;
use crate::error::{Error, Result};
use crate::host::firewall;
use crate::host::service::{Services, SITE, SUBSCRIPTION_WEB, WAIT_RUNNING};
use crate::render::tls::TlsMaterial;
use crate::sys::lock::FileLock;
use crate::ui::out;

/// Firewall owner of the temporary HTTP-01 allowance.
pub const ACME_OWNER: &str = "acme";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RenewOptions {
    pub targets: CertScopes,
    /// Run by cron: quiet unless something was renewed or failed.
    pub scheduled: bool,
    /// Renew even when not due (acme.sh `--force`).
    pub force: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RenewReport {
    pub renewed: Vec<CertScope>,
    /// Targets that were not due (or acme.sh found nothing to do).
    pub unchanged: Vec<CertScope>,
    pub failed: Vec<(CertScope, String)>,
    /// The caller must run a full apply (module docs).
    pub proxy_identity_changed: bool,
}

/// One configured certificate of the node.
struct Target {
    scope: CertScope,
    dir: CertDir,
    spec: CertSpec,
    /// Services to restart after a renewal (when running).
    services: Vec<&'static str>,
}

/// Renew the selected certificates of `cfg` (module docs). `cf` serves the
/// DNS-01 targets without credentials of their own. Errors only for a
/// missing node lock; per-target failures are in the report.
pub fn renew_all(
    ctx: &Ctx,
    lock: &FileLock,
    cfg: &NodeConfig,
    opts: &RenewOptions,
    cf: Option<&CfCredentials>,
) -> Result<RenewReport> {
    renew_all_with(&Engine::system(ctx), lock, cfg, opts, cf)
}

/// [`renew_all`] with an explicit engine.
pub fn renew_all_with(
    engine: &Engine,
    lock: &FileLock,
    cfg: &NodeConfig,
    opts: &RenewOptions,
    cf: Option<&CfCredentials>,
) -> Result<RenewReport> {
    lock.verify(&engine.ctx.paths.lock())?;
    let mut report = RenewReport::default();
    for target in targets(engine, cfg, opts.targets) {
        let before = (target.scope == CertScope::Proxy).then(|| identity(engine, &target));
        let given = cf.filter(|_| lacks_credentials(engine, &target));
        let renewed = renew_target(engine, &target, opts, given, &mut report);
        if let Some(before) = before.filter(|_| renewed.is_some()) {
            let after = identity(engine, &target);
            report.proxy_identity_changed = identity_changed(cfg, &before, &after);
            if report.proxy_identity_changed {
                continue;
            }
        }
        if let Some(renewed) = renewed {
            restart(engine, &target, renewed.previous.as_ref(), &mut report);
        }
    }
    Ok(report)
}

/// The DNS-01 targets among `opts` that would renew and have neither
/// stored nor environment credentials: the CLI resolves (prompts for)
/// credentials before [`renew_all`] when this is not empty. Read-only.
pub fn credentials_needed(ctx: &Ctx, cfg: &NodeConfig, opts: &RenewOptions) -> Vec<CertScope> {
    credentials_needed_with(&Engine::system(ctx), cfg, opts)
}

/// [`credentials_needed`] with an explicit engine.
pub fn credentials_needed_with(
    engine: &Engine,
    cfg: &NodeConfig,
    opts: &RenewOptions,
) -> Vec<CertScope> {
    targets(engine, cfg, opts.targets)
        .into_iter()
        .filter(|t| lacks_credentials(engine, t) && due(engine, t, opts))
        .map(|t| t.scope)
        .collect()
}

/// The DNS-01 targets an apply of `cfg` would issue or renew without
/// stored or environment credentials: every due one, plus the `forced`
/// scopes (`Intents.renew`) whether due or not. Read-only; see
/// [`cloudflare::resolve_for_apply`].
pub fn credentials_needed_for_apply(
    ctx: &Ctx,
    cfg: &NodeConfig,
    forced: CertScopes,
) -> Vec<CertScope> {
    credentials_needed_for_apply_with(&Engine::system(ctx), cfg, forced)
}

/// [`credentials_needed_for_apply`] with an explicit engine.
pub fn credentials_needed_for_apply_with(
    engine: &Engine,
    cfg: &NodeConfig,
    forced: CertScopes,
) -> Vec<CertScope> {
    let due = RenewOptions {
        targets: CertScopes::ALL,
        scheduled: false,
        force: false,
    };
    let mut needed = credentials_needed_with(engine, cfg, &due);
    if !forced.is_empty() {
        let forced = RenewOptions {
            targets: forced,
            scheduled: false,
            force: true,
        };
        needed.extend(credentials_needed_with(engine, cfg, &forced));
    }
    needed.sort_unstable();
    needed.dedup();
    needed
}

/// A DNS-01 target whose directory has no complete credentials (stored or
/// environment). An unreadable store is not "lacking": its error shows up
/// in the renewal itself.
fn lacks_credentials(engine: &Engine, t: &Target) -> bool {
    matches!(t.spec.challenge(), Some(Challenge::Cloudflare))
        && matches!(
            cloudflare::lookup_with(engine.ctx, t.dir.path(), engine.env),
            Ok(None)
        )
}

fn due(engine: &Engine, t: &Target, opts: &RenewOptions) -> bool {
    opts.force || engine.due(&t.dir, &t.spec).unwrap_or(true)
}

/// A renewal that deployed a new pair.
struct Renewed {
    /// The pair it replaced (module docs); `None` when that could not be
    /// read, so a failed restart cannot put it back.
    previous: Option<SavedPair>,
}

/// Renew one target; `Some` when the deployed pair changed.
fn renew_target(
    engine: &Engine,
    t: &Target,
    opts: &RenewOptions,
    cf: Option<&CfCredentials>,
    report: &mut RenewReport,
) -> Option<Renewed> {
    let label = t.scope.label();
    if !due(engine, t, opts) {
        report.unchanged.push(t.scope);
        if !opts.scheduled {
            out::info(format!("{label}未到续期时间"));
        }
        return None;
    }
    let kind = if opts.force {
        RenewKind::Forced
    } else {
        RenewKind::Scheduled
    };
    // A pair that cannot be read back is still renewed (that may be what
    // repairs it); only the rollback of a failed restart is lost.
    let previous = SavedPair::save(&t.dir).ok();
    let result = with_acme_port(engine, &t.spec, || engine.renew(&t.dir, &t.spec, kind, cf));
    match result {
        Ok(Renewal::Changed) => {
            report.renewed.push(t.scope);
            out::ok(format!("{label}已续期"));
            Some(Renewed { previous })
        }
        Ok(Renewal::Unchanged) => {
            report.unchanged.push(t.scope);
            if !opts.scheduled {
                out::info(format!("{label}无需更换"));
            }
            None
        }
        Ok(Renewal::Deferred) => {
            report.unchanged.push(t.scope);
            out::warn(format!("{label}未续期: {RENEW_DEFERRED}"));
            None
        }
        Err(e) => {
            out::warn(format!("{label}续期失败: {e}"));
            report.failed.push((t.scope, e.to_string()));
            None
        }
    }
}

/// The node's certificates selected by `scopes`, in order proxy, site,
/// subscription. A site-mode subscription renews with the site.
fn targets(engine: &Engine, cfg: &NodeConfig, scopes: CertScopes) -> Vec<Target> {
    let paths = &engine.ctx.paths;
    let mut out = Vec::new();
    if scopes.proxy {
        let dir = CertDir::proxy(paths);
        if let Some(spec) = proxy_spec(engine, cfg, &dir) {
            let services = cfg.cores().into_iter().map(|c| c.service()).collect();
            out.push(target(CertScope::Proxy, dir, spec, services));
        }
    }
    let sub_mode = cfg.subscription.as_ref().map(|s| &s.mode);
    let site_wanted =
        scopes.site || (scopes.subscription && sub_mode == Some(&SubscriptionMode::Site));
    if let Some(site) = cfg.site_active().filter(|_| site_wanted) {
        let dir = CertDir::site(paths);
        let http01 = served_by(engine, SITE, &paths.site_root, &dir);
        let spec = web_spec(
            std::slice::from_ref(&site.domain),
            &site.cert,
            http01,
            Trust::Public,
        );
        out.push(target(CertScope::Site, dir, spec, vec![SITE]));
    }
    if let Some(SubscriptionMode::Standalone {
        domain,
        cert,
        http01_port80,
    }) = sub_mode.filter(|_| scopes.subscription)
    {
        let dir = CertDir::subscription(paths);
        let http01 = if *http01_port80 {
            served_by(
                engine,
                SUBSCRIPTION_WEB,
                &subscription_acme_root(paths),
                &dir,
            )
        } else {
            Challenge::Responder(dir.responder_webroot())
        };
        let spec = web_spec(std::slice::from_ref(domain), cert, http01, Trust::Public);
        out.push(target(
            CertScope::Subscription,
            dir,
            spec,
            vec![SUBSCRIPTION_WEB],
        ));
    }
    out
}

fn target(scope: CertScope, dir: CertDir, spec: CertSpec, services: Vec<&'static str>) -> Target {
    Target {
        scope,
        dir,
        spec,
        services,
    }
}

/// Restart the target's running services. When one does not come back,
/// `previous` is put back and the same services are restarted again
/// (module docs); the failure is reported either way.
fn restart(engine: &Engine, t: &Target, previous: Option<&SavedPair>, report: &mut RenewReport) {
    let services = engine.services();
    // Chosen once: a failed restart leaves its service stopped, and the
    // restart with the old pair must start it again.
    let running: Vec<&str> = t
        .services
        .iter()
        .copied()
        .filter(|name| services.running(name))
        .collect();
    let Err(failure) = restart_all(&services, &running) else {
        return;
    };
    let label = t.scope.label();
    let rollback = match previous {
        None => "未能恢复续期前的证书: 没有续期前的证书副本".to_owned(),
        Some(saved) => match saved.restore() {
            Err(e) => format!("未能恢复续期前的证书: {e}"),
            Ok(()) => match restart_all(&services, &running) {
                Ok(()) => "已恢复续期前的证书（下次续期时重试）".to_owned(),
                Err(e) => format!("已恢复续期前的证书，但再次重启失败: {e}"),
            },
        },
    };
    let message = format!("{label}已续期，但{failure}；{rollback}");
    out::warn(&message);
    report.failed.push((t.scope, message));
}

/// Restart each of `names` and wait until it runs; the failures
/// (`重启 {name} 失败: …`) are joined into one error.
fn restart_all(services: &Services, names: &[&str]) -> Result<()> {
    let failures: Vec<String> = names
        .iter()
        .filter_map(|name| {
            let result = services
                .restart(name)
                .and_then(|()| services.wait_running(name, WAIT_RUNNING));
            result.err().map(|e| format!("重启 {name} 失败: {e}"))
        })
        .collect();
    match failures.is_empty() {
        true => Ok(()),
        false => Err(Error::msg(failures.join("，"))),
    }
}

/// Open TCP `http01_port` for the built-in responder around `call`.
fn with_acme_port<T>(
    engine: &Engine,
    spec: &CertSpec,
    call: impl FnOnce() -> Result<T>,
) -> Result<T> {
    if !spec.uses_responder() {
        return call();
    }
    let port = engine.http01_port;
    if let Err(e) =
        firewall::reconcile_owner(engine.ctx, ACME_OWNER, &[(port, port, Transport::Tcp)])
    {
        out::warn(format!("无法临时放行 TCP {port}: {e}"));
    }
    let result = call();
    if let Err(e) = firewall::clear_owner(engine.ctx, ACME_OWNER) {
        out::warn(format!("未能关闭临时放行的 TCP {port}: {e}"));
    }
    result
}

/// The proxy certificate identity: leaf pin and public trust.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Identity {
    pin: Option<String>,
    trusted: bool,
}

fn identity(engine: &Engine, t: &Target) -> Identity {
    let paths = &engine.ctx.paths;
    Identity {
        pin: TlsMaterial::deployed(paths)
            .ok()
            .map(|m| m.pin().to_owned()),
        trusted: publicly_trusted(engine.ctx, &t.dir.cert(), &t.dir.key(), t.spec.primary()),
    }
}

/// Whether clients rendered from `cfg` no longer match the renewed pair:
/// they pin (`cfg.tls.pinned`, what `NodeSpec` rendered) while the new pair
/// would not be pinned or the reverse (a full apply re-records the trust),
/// or they pin and the leaf changed. Compared with the stored flag rather
/// than the trust measured before the renewal, which a changed system CA
/// store may have moved since the last apply.
fn identity_changed(cfg: &NodeConfig, before: &Identity, after: &Identity) -> bool {
    let tls = cfg.tls.as_ref();
    let self_signed = tls.is_some_and(|t| matches!(t.mode, ProxyCertMode::SelfSigned { .. }));
    let pinned_now = tls.is_some_and(|t| t.pinned);
    let pinned_after = self_signed || !after.trusted;
    pinned_now != pinned_after || (pinned_now && before.pin != after.pin)
}

#[cfg(test)]
mod tests;
