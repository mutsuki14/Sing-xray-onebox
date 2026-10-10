//! Certificate commands: `cert [info|status]`, `cert set`, `cert renew
//! [proxy|site|subscription|all] [--cron]`, the v2 form `cert-renew …`
//! and the single cron entry `renew [--cron]`.
//!
//! Renewal (G9) never runs a full apply by itself: Cloudflare credentials
//! a due DNS-01 target lacks are resolved first (prompted when
//! interactive), then the node lock is taken (under `--cron` waiting up to
//! ten minutes), a leftover journal is recovered, `cert::renew_all` renews
//! what is due (or everything selected when run by hand) and restarts only
//! the affected service; a full apply with the unchanged configuration
//! follows only when the proxy certificate's identity changed (pin or
//! trust), so clients and the subscription carry the new pin. Under
//! `--cron` nothing is printed when nothing was due.
//!
//! Changes from v2 (spec F §2.1, F-8.1#3/#8, G-8.1#4, B-9.1#4): manual
//! renewals are forced; one cron entry instead of three racing jobs; a
//! failing target no longer hides the others and makes the command fail;
//! `cert info` also shows the standalone subscription certificate;
//! `cert set` without `--tls` asks interactively and is an error under
//! `-y` (v2 silently picked self-signed); `cert-renew subscription` renews
//! like `cert renew subscription`; when the republishing apply after a
//! proxy identity change is rolled back (or refused), the previous pair is
//! put back (the renewal deployed it outside the transaction, so the
//! apply's rollback kept the new one while clients still pinned the old
//! one) and the next renewal retries — but never after the apply
//! committed (clients already pin the new pair) or kept its journal (its
//! recovery restores the new pair; the error asks for `recover`, then
//! `regen`).

use crate::apply::engine::COMMITTED_UNCLEAN;
use crate::apply::journal;
use crate::cert::cloudflare::{self, CfCredentials};
use crate::cert::{self, CertDir, CertScopes, RenewOptions, RenewReport};
use crate::cli::args::{ArgSpec, CommandSpec, Group, Matches, OptSpec, Root};
use crate::cli::options as opt;
use crate::cli::session::{request, with_system, Session};
use crate::cli::wizard::steps;
use crate::ctx::Ctx;
use crate::domain::config::{NodeConfig, SubscriptionMode};
use crate::domain::plan;
use crate::error::{Error, Result};
use crate::host::service::WAIT_RUNNING;
use crate::state::{Loaded, StateStore};
use crate::sys::fs::{atomic_write, read_bounded, remove_file_if_exists};
use crate::sys::lock::{FileLock, BUSY_MESSAGE};
use std::time::Duration;

const CRON: OptSpec = OptSpec::flag(
    "cron",
    "计划任务模式：只续期到期的证书（30 天内到期，或自备证书已更新），无事可做时不输出",
);
const SET_NEEDS_TLS: &str = "cert set 需要 --tls self|acme|cf|custom";
/// How long a scheduled renewal waits for a concurrent operation.
const CRON_LOCK_WAIT: Duration = Duration::from_secs(600);
const CRON_LOCK_POLL: Duration = Duration::from_secs(5);
const TARGET_ARG: ArgSpec =
    ArgSpec::optional("目标", "proxy / site / subscription / all（默认 all）");

/// `cert::renew_all` (tests inject their own).
pub type Renewer =
    fn(&Ctx, &FileLock, &NodeConfig, &RenewOptions, Option<&CfCredentials>) -> Result<RenewReport>;

pub const CERT: CommandSpec = CommandSpec::new("cert", Group::Feature, "代理、网站与订阅证书")
    .usage(&[
        "cert [info]",
        "cert set [--tls self|acme|cf|custom --domain 域名 [--cert 文件 --key 文件]]",
        "cert renew [proxy|site|subscription|all] [--cron]",
    ])
    .options(&[CRON])
    .subcommands(&[
        CommandSpec::new("info", Group::Feature, "查看证书状态")
            .aliases(&["status"])
            .options(&[CRON])
            .root(Root::NotRequired)
            .handler(info_command),
        CommandSpec::new("set", Group::Feature, "更换代理证书方式")
            .options(&[opt::TLS, opt::DOMAIN, opt::CERT, opt::KEY])
            .handler(set_command),
        CommandSpec::new(
            "renew",
            Group::Feature,
            "立即强制续期证书（--cron 只续期 30 天内到期的）",
        )
        .args(&[TARGET_ARG])
        .options(&[CRON])
        .handler(renew_command),
    ])
    .root(Root::NotRequired)
    .handler(info_command);

pub const CERT_RENEW: CommandSpec =
    CommandSpec::new("cert-renew", Group::Hidden, "旧版续期命令（同 cert renew）")
        .args(&[TARGET_ARG])
        .options(&[CRON])
        .handler(renew_command);

pub const RENEW: CommandSpec = CommandSpec::new(
    "renew",
    Group::Maintain,
    "立即强制续期全部证书（计划任务每天执行 renew --cron，只续期 30 天内到期的）",
)
.options(&[CRON])
.handler(renew_all_command);

fn info_command(ctx: &Ctx, _m: &Matches) -> Result<()> {
    with_system(ctx, info)
}

/// `cert info`: the status of every certificate directory in use.
pub fn info(session: &Session) -> Result<()> {
    let loaded = session.load()?;
    let ctx = session.ctx;
    let paths = &ctx.paths;
    let mut sections = vec![
        ("代理证书", CertDir::proxy(paths)),
        ("网站证书", CertDir::site(paths)),
    ];
    let standalone = matches!(
        loaded.config.subscription.as_ref().map(|s| &s.mode),
        Some(SubscriptionMode::Standalone { .. })
    );
    let sub_dir = CertDir::subscription(paths);
    if standalone || sub_dir.cert().is_file() {
        sections.push(("订阅证书", sub_dir));
    }
    let mut lines = Vec::new();
    for (title, dir) in sections {
        lines.push(title.to_owned());
        match cert::store::status(ctx, &dir)? {
            Some(status) => lines.extend(status.lines().into_iter().map(|l| format!("  {l}"))),
            None => lines.push("  未配置证书".to_owned()),
        }
    }
    session.data(&lines.join("\n"))
}

fn set_command(ctx: &Ctx, m: &Matches) -> Result<()> {
    with_system(ctx, |s| {
        let loaded = s.load()?;
        let current = loaded
            .config
            .tls
            .as_ref()
            .map(|t| t.mode.server_name().to_owned())
            .filter(|_| {
                loaded
                    .config
                    .tls
                    .as_ref()
                    .is_some_and(|t| t.mode.is_domain_cert())
            });
        let given = opt::any(m, &["tls", "domain", "cert", "key"]);
        ensure!(!given || m.value("tls").is_some(), "{SET_NEEDS_TLS}");
        let args = given
            .then(|| opt::cert_args(m, current.as_deref()))
            .transpose()?;
        set(s, args)
    })
}

/// `cert set`: `None` asks for the method (interactive only).
pub fn set(session: &Session, args: Option<opt::CertArgs>) -> Result<()> {
    let loaded = session.load()?;
    let ui = session.ui();
    let args = match args {
        Some(args) => args,
        None if ui.interactive() => opt::CertArgs {
            choice: Some(steps::cert_menu(ui, "选择代理证书方式")?),
            vmess_host: None,
        },
        None => bail!("{SET_NEEDS_TLS}"),
    };
    let Some(choice) = args.choice else {
        bail!("{SET_NEEDS_TLS}");
    };
    let mut next = plan::set_proxy_cert(&loaded.config, &choice)?;
    if let Some(host) = &args.vmess_host {
        next = plan::set_vmess_host(&next, Some(host))?;
    }
    session.apply(request(&loaded, next, "更换代理证书"))
}

fn targets(m: &Matches) -> Result<CertScopes> {
    m.positional(0).map_or(Ok(CertScopes::ALL), str::parse)
}

fn renew_command(ctx: &Ctx, m: &Matches) -> Result<()> {
    let scopes = targets(m)?;
    with_system(ctx, |s| renew(s, scopes, m.flag("cron")))
}

fn renew_all_command(ctx: &Ctx, m: &Matches) -> Result<()> {
    with_system(ctx, |s| renew(s, CertScopes::ALL, m.flag("cron")))
}

/// Renew `scopes` (module docs) with `cert::renew_all`.
pub fn renew(session: &Session, scopes: CertScopes, cron: bool) -> Result<()> {
    renew_with(session, scopes, cron, cert::renew_all)
}

/// [`renew`] with an injected renewer.
pub fn renew_with(
    session: &Session,
    scopes: CertScopes,
    cron: bool,
    renewer: Renewer,
) -> Result<()> {
    session.require_root()?;
    let ctx = session.ctx;
    let opts = RenewOptions {
        targets: scopes,
        scheduled: cron,
        force: !cron,
    };
    let before = session.load()?;
    let needed = cert::credentials_needed(ctx, &before.config, &opts);
    // A scheduled run cannot ask: those targets fail and say why.
    let cf = if cron {
        None
    } else {
        cloudflare::resolve_needed(session.ui(), &needed)?
    };
    let path = ctx.paths.lock();
    let lock = if cron {
        FileLock::acquire_waiting(&path, BUSY_MESSAGE, CRON_LOCK_WAIT, CRON_LOCK_POLL)?
    } else {
        FileLock::acquire(&path, BUSY_MESSAGE)?
    };
    session.engine.recover_locked(ctx, &lock)?;
    let loaded = session.load()?;
    // The renewal deploys outside any transaction: keep the previous proxy
    // pair to put back if the republishing apply below does not happen.
    let saved = if scopes.proxy && loaded.config.tls.is_some() {
        Some(SavedPair::save(&CertDir::proxy(&ctx.paths))?)
    } else {
        None
    };
    let report = renewer(ctx, &lock, &loaded.config, &opts, cf.as_ref())?;
    if report.proxy_identity_changed {
        session.info("代理证书已更换，正在重新发布客户端配置");
        let mut req = request(&loaded, loaded.config.clone(), "证书续期");
        // The apply renews what is still due (e.g. a target that just
        // failed) and never prompts: it gets the credentials resolved above.
        req.intents.cloudflare = cf.clone();
        if let Err(e) = session.engine.apply_locked(ctx, &lock, req) {
            return Err(unpublished(session, &loaded, saved.as_ref(), e));
        }
    }
    summarize(session, &report, cron)
}

/// The renewed proxy pair is live but the apply that republishes clients
/// failed. What to do depends on how it left the node ([`Outcome`]):
/// rolled back (or refused before its journal existed, or cancelled), its
/// rollback kept whatever `ROOT/tls` held when it started — the new pair —
/// while clients still pin the old one: put the previous pair back and
/// restart the running cores, so the node serves what clients pin; the
/// next renewal finds the certificate due again and retries. Committed,
/// clients already pin the new pair: the error stays as it is. A kept
/// journal would restore the new pair on recovery: `ROOT/tls` is left
/// alone and the error asks for `recover`, then `regen`. Never claims a
/// restored state while the new pair is still live.
fn unpublished(
    session: &Session,
    loaded: &Loaded,
    saved: Option<&SavedPair>,
    error: Error,
) -> Error {
    match outcome(session.ctx, loaded, &error) {
        Outcome::Committed => return error,
        Outcome::Pending => return error.wrap(REPUBLISH_PENDING),
        Outcome::Unchanged => {}
    }
    let restored = saved
        .ok_or_else(|| Error::msg("没有续期前的证书副本"))
        .and_then(SavedPair::restore)
        .and_then(|()| restart_running_cores(session, &loaded.config));
    match restored {
        Ok(()) => error.wrap(PAIR_RESTORED),
        Err(e) => Error::msg(format!(
            "代理证书已更换，但重新发布客户端配置失败（{}），也未能恢复续期前的证书: {e}；\
             客户端固定的证书指纹已失效，请执行 onebox regen 重新发布",
            error.report_text()
        )),
    }
}

/// Context of a failed republish after the previous pair was put back.
pub const PAIR_RESTORED: &str = "客户端配置未重新发布，已恢复续期前的代理证书（下次续期时重试）";

/// Context of a failed republish whose journal was kept: its recovery
/// restores the new pair, which only `regen` publishes to the clients (no
/// later renewal does: the new pair is not due).
pub const REPUBLISH_PENDING: &str =
    "代理证书已更换，但客户端配置未重新发布；请先执行 onebox recover，再执行 onebox regen 重新发布";

/// How a failed republishing apply left the node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    /// Rolled back, or refused before its journal existed: `state.json`,
    /// the clients and the subscription are as they were.
    Unchanged,
    /// Committed (its cleanup failed): the clients pin the new pair.
    Committed,
    /// Its journal is kept (a rollback that did not finish), or the state
    /// cannot be told.
    Pending,
}

/// The [`Outcome`] of the failed apply that ended with `error`: committed
/// when it says so or `state.json` changed since `loaded`, pending while a
/// node journal exists, else unchanged.
fn outcome(ctx: &Ctx, loaded: &Loaded, error: &Error) -> Outcome {
    if error.to_string().starts_with(COMMITTED_UNCLEAN) {
        return Outcome::Committed;
    }
    match StateStore::current_hash(ctx) {
        Ok(hash) if hash != loaded.hash => return Outcome::Committed,
        Ok(_) => {}
        Err(_) => return Outcome::Pending,
    }
    match std::fs::symlink_metadata(journal::dir(&ctx.paths)) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Outcome::Unchanged,
        _ => Outcome::Pending,
    }
}

/// The deployed proxy pair and its metadata (`None`: the file did not
/// exist), as they were before a renewal.
struct SavedPair {
    files: Vec<(std::path::PathBuf, Option<Vec<u8>>)>,
}

impl SavedPair {
    fn save(dir: &CertDir) -> Result<SavedPair> {
        // Key before certificate, as pairs are deployed.
        let files = [dir.key(), dir.cert(), dir.metadata_file()]
            .into_iter()
            .map(|path| {
                let bytes = match std::fs::symlink_metadata(&path) {
                    Ok(_) => Some(read_bounded(&path, cert::store::PEM_MAX_BYTES)?),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                    Err(e) => return Err(Error::io(&path, e)),
                };
                Ok((path, bytes))
            })
            .collect::<Result<_>>()?;
        Ok(SavedPair { files })
    }

    fn restore(&self) -> Result<()> {
        for (path, bytes) in &self.files {
            match bytes {
                Some(bytes) => atomic_write(path, bytes, 0o600)?,
                None => {
                    remove_file_if_exists(path)?;
                }
            }
        }
        Ok(())
    }
}

/// Restart the node's running cores so they load the deployed pair.
fn restart_running_cores(session: &Session, cfg: &NodeConfig) -> Result<()> {
    let services = session.services();
    for core in cfg.cores() {
        let name = core.service();
        if session.live.running(name) {
            services.restart(name)?;
            services.wait_running(name, WAIT_RUNNING)?;
        }
    }
    Ok(())
}

/// The command's result: failures make it fail; a manual run with no
/// certificate at all says so.
fn summarize(session: &Session, report: &RenewReport, cron: bool) -> Result<()> {
    if !report.failed.is_empty() {
        let labels: Vec<&str> = report.failed.iter().map(|(s, _)| s.label()).collect();
        return Err(Error::msg(format!("证书续期失败: {}", labels.join("、"))));
    }
    let nothing = report.renewed.is_empty() && report.unchanged.is_empty();
    if nothing && !cron {
        session.info("没有需要续期的证书");
    }
    Ok(())
}

#[cfg(test)]
mod tests;
