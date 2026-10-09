//! Certificates in effect (expiry), the private nginx configurations and
//! the renewal cron line.
//!
//! The probes are generic — a [`CertProbe`], [`nginx_check`], a
//! [`RenewalJob`] — and exported through `diag::probe`, so feature modules
//! (FRP's website certificate, nginx and `frp-renew` line) produce the same
//! lines with the same thresholds as the node's.

use super::node::REGEN;
use super::{Check, Doctor};
use crate::cert::{self, CertDir, CertScope, Expiry, RenewNeed};
use crate::ctx::Ctx;
use crate::domain::config::SubscriptionMode;
use crate::domain::defaults::CERT_WARNING_DAYS;
use crate::domain::NodeConfig;
use crate::error::Error;
use crate::host::cron::{self, Crontab, Tag};
use crate::host::nginx;
use crate::paths::Paths;
use crate::site;
use crate::sys::time::format_utc;
use std::path::{Path, PathBuf};

pub const SITE_NGINX: &str = "网站 nginx 配置";
pub const SUBSCRIPTION_NGINX: &str = "订阅 nginx 配置";
pub const RENEWAL: &str = "证书自动续期";
const DAY: u64 = 86_400;

/// One certificate to check: its line's name and the commands that fix it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertProbe {
    /// The check name (`代理证书`, `FRP 网站证书`).
    pub name: String,
    /// The directory holding `cert.pem` and `key.pem`.
    pub dir: PathBuf,
    /// The command that renews it (`onebox cert renew proxy`).
    pub renew: String,
    /// The command that deploys a missing one (`onebox regen`).
    pub deploy: String,
}

impl CertProbe {
    /// A node certificate: renewed by `onebox cert renew {scope}`,
    /// deployed by `onebox regen`.
    pub fn node(scope: CertScope, dir: &CertDir) -> CertProbe {
        CertProbe {
            name: scope.label().to_owned(),
            dir: dir.path().to_path_buf(),
            renew: format!("onebox cert renew {}", scope.id()),
            deploy: REGEN.to_owned(),
        }
    }
}

/// The certificates `cfg` uses, with their directories: the proxy's when a
/// protocol needs one, the site's while the site is active, the standalone
/// subscription endpoint's (the site mode shares the site's).
pub fn certificates(cfg: &NodeConfig, paths: &Paths) -> Vec<(CertScope, CertDir)> {
    let mut list = Vec::new();
    if cfg.needs_cert() && cfg.tls.is_some() {
        list.push((CertScope::Proxy, CertDir::proxy(paths)));
    }
    if cfg.site_active().is_some() {
        list.push((CertScope::Site, CertDir::site(paths)));
    }
    if standalone(cfg) {
        list.push((CertScope::Subscription, CertDir::subscription(paths)));
    }
    list
}

fn standalone(cfg: &NodeConfig) -> bool {
    matches!(
        cfg.subscription.as_ref().map(|s| &s.mode),
        Some(SubscriptionMode::Standalone { .. })
    )
}

pub fn certificate_checks(doctor: &Doctor, cfg: &NodeConfig) -> Vec<Check> {
    certificates(cfg, &doctor.ctx.paths)
        .iter()
        .map(|(scope, dir)| certificate_check(doctor, &CertProbe::node(*scope, dir)))
        .collect()
}

/// The deployed certificate by remaining validity ([`expiry_check`]). A
/// missing certificate fails, and so does one `openssl` rejects (a corrupt
/// `cert.pem`); one that cannot be inspected (no `openssl`) is a warning,
/// never an abort (D-8.1#27).
pub fn certificate_check(doctor: &Doctor, probe: &CertProbe) -> Check {
    let name = probe.name.as_str();
    match cert::status(doctor.ctx, &probe.dir) {
        Ok(Some(status)) => expiry_check(probe, status.x509.expires_at, doctor.now),
        Ok(None) => Check::fail(
            name,
            format!(
                "证书不存在（{}）；执行 {}",
                CertDir::new(&probe.dir).cert().display(),
                probe.deploy
            ),
        ),
        Err(Error::Command { code, detail, .. }) => {
            let reason = detail
                .lines()
                .map(str::trim)
                .find(|l| !l.is_empty())
                .map_or_else(|| format!("openssl 退出码 {code}"), str::to_owned);
            Check::fail(
                name,
                format!("证书无法解析: {reason}；执行 {}", probe.renew),
            )
        }
        Err(e) => Check::warn(name, format!("无法检查证书: {e}")),
    }
}

/// Expired → failure; fewer than 7 whole days left → warning; else the
/// date. The predicate is [`Expiry`], shared with `cert info`.
pub fn expiry_check(probe: &CertProbe, expires_at: Option<u64>, now: u64) -> Check {
    let name = probe.name.as_str();
    let Some(at) = expires_at else {
        return Check::warn(name, "无法读取证书有效期");
    };
    let date = format_utc(at);
    let renew = format!("执行 {}", probe.renew);
    match Expiry::at(at, now, CERT_WARNING_DAYS) {
        Expiry::Expired => Check::fail(name, format!("已于 {date} 过期；{renew}")),
        Expiry::Expiring => {
            let days = at.saturating_sub(now).div_ceil(DAY).max(1);
            Check::warn(name, format!("将在 {days} 天内到期（{date}）；{renew}"))
        }
        Expiry::Valid => Check::pass(
            name,
            format!(
                "有效期至 {date}（剩余 {} 天）",
                at.saturating_sub(now) / DAY
            ),
        ),
    }
}

/// The private nginx instances `cfg` runs, as (check name, prefix,
/// configuration): the site's while it is active, the standalone
/// subscription's (both rendered and tested alike, K7).
pub fn nginx_configs(cfg: &NodeConfig, paths: &Paths) -> Vec<(&'static str, PathBuf, PathBuf)> {
    let mut list = Vec::new();
    if cfg.site_active().is_some() {
        list.push((SITE_NGINX, paths.site(), site::conf_file(paths)));
    }
    if standalone(cfg) {
        let prefix = paths.subscription();
        let conf = prefix.join("nginx.conf");
        list.push((SUBSCRIPTION_NGINX, prefix, conf));
    }
    list
}

pub fn nginx_checks(ctx: &Ctx, cfg: &NodeConfig) -> Vec<Check> {
    nginx_configs(cfg, &ctx.paths)
        .into_iter()
        .map(|(name, prefix, conf)| nginx_check(ctx, name, &prefix, &conf, REGEN))
        .collect()
}

/// `nginx -t` of an installed configuration (the file its service runs
/// with); `deploy` is the command that writes a missing one.
pub fn nginx_check(ctx: &Ctx, name: &str, prefix: &Path, conf: &Path, deploy: &str) -> Check {
    if !conf.is_file() {
        return Check::fail(
            name,
            format!("配置文件不存在（{}）；执行 {deploy}", conf.display()),
        );
    }
    match nginx::test(ctx, prefix, conf) {
        Ok(()) => Check::pass(name, "nginx -t 通过"),
        Err(e) => Check::fail(name, e.to_string()),
    }
}

/// A daily certificate renewal line in root's crontab.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenewalJob<'a> {
    /// The check name (`证书自动续期`, `FRP 续期任务`).
    pub name: &'a str,
    /// The ownership tag of its line.
    pub tag: Tag,
    /// Missing → failure (an ACME certificate will expire); else warning.
    pub required: bool,
    /// What goes wrong without it (`ACME 证书不会自动续期`).
    pub effect: &'a str,
    /// The command that installs it (`onebox regen`).
    pub fix: &'a str,
}

/// The node's `# onebox:renew` line for what `cert::renew_needed` says.
pub fn node_renewal_job(need: RenewNeed) -> RenewalJob<'static> {
    let required = need == RenewNeed::Required;
    RenewalJob {
        name: RENEWAL,
        tag: Tag::renew(),
        required,
        effect: if required {
            "ACME 证书不会自动续期"
        } else {
            "外部证书更新后不会自动部署"
        },
        fix: REGEN,
    }
}

/// The renewal line, when a certificate needs renewals (ACME → required,
/// custom → recommended).
pub fn renewal_check(doctor: &Doctor, cfg: &NodeConfig) -> Option<Check> {
    match cert::renew_needed(cfg) {
        RenewNeed::None => None,
        need => Some(renewal_job_check(doctor, &node_renewal_job(need))),
    }
}

/// Whether `job`'s line is installed and a cron daemon runs it.
pub fn renewal_job_check(doctor: &Doctor, job: &RenewalJob) -> Check {
    let ctx = doctor.ctx;
    let line = if cron::available(ctx) {
        Crontab::read(ctx)
            .map(|tab| tab.has(&job.tag))
            .map_err(|e| e.to_string())
    } else {
        Err("未找到 crontab".to_owned())
    };
    let scheduler = matches!(line, Ok(true)) && cron::scheduler_active(ctx, doctor.init);
    renewal_job_verdict(job, line, scheduler)
}

/// A missing line fails or warns per [`RenewalJob::required`]; a cron
/// daemon that does not seem to run is a warning (detection is heuristic).
pub fn renewal_job_verdict(job: &RenewalJob, line: Result<bool, String>, scheduler: bool) -> Check {
    let effect = job.effect;
    let missing = |detail: String| {
        if job.required {
            Check::fail(job.name, detail)
        } else {
            Check::warn(job.name, detail)
        }
    };
    match line {
        Err(e) => missing(format!("{e}，{effect}")),
        Ok(false) => missing(format!("缺少每日续期任务，{effect}；执行 {}", job.fix)),
        Ok(true) if !scheduler => Check::warn(
            job.name,
            format!("cron 未运行，续期任务不会执行（{effect}）；请启动系统 cron 服务"),
        ),
        Ok(true) => Check::pass(job.name, "已安装每日续期任务"),
    }
}

#[cfg(test)]
mod tests;
