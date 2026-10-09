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
//! like `cert renew subscription`.

use crate::cert::cloudflare::CfCredentials;
use crate::cert::{self, CertDir, CertScopes, RenewOptions, RenewReport};
use crate::cli::args::{ArgSpec, CommandSpec, Group, Matches, OptSpec, Root};
use crate::cli::options as opt;
use crate::cli::session::{request, resolve_cloudflare, with_system, Session};
use crate::cli::wizard::steps;
use crate::ctx::Ctx;
use crate::domain::config::{NodeConfig, SubscriptionMode};
use crate::domain::plan;
use crate::error::{Error, Result};
use crate::sys::lock::{FileLock, BUSY_MESSAGE};
use std::time::Duration;

const CRON: OptSpec = OptSpec::flag("cron", "计划任务模式：只续期到期证书，无事可做时不输出");
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
        CommandSpec::new("renew", Group::Feature, "续期证书（手动执行时强制续期）")
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
    "检查并续期全部证书（计划任务每天执行 renew --cron）",
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
        resolve_cloudflare(session.ui(), &needed)?
    };
    let path = ctx.paths.lock();
    let lock = if cron {
        FileLock::acquire_waiting(&path, BUSY_MESSAGE, CRON_LOCK_WAIT, CRON_LOCK_POLL)?
    } else {
        FileLock::acquire(&path, BUSY_MESSAGE)?
    };
    session.engine.recover_locked(ctx, &lock)?;
    let loaded = session.load()?;
    let report = renewer(ctx, &lock, &loaded.config, &opts, cf.as_ref())?;
    if report.proxy_identity_changed {
        session.info("代理证书已更换，正在重新发布客户端配置");
        let req = request(&loaded, loaded.config.clone(), "证书续期");
        session.engine.apply_locked(ctx, &lock, req)?;
    }
    summarize(session, &report, cron)
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
