//! Certificates in effect (expiry), the site's nginx configuration and the
//! renewal cron line.

use super::{Check, Doctor};
use crate::cert::{self, CertDir, CertScope, RenewNeed};
use crate::ctx::Ctx;
use crate::domain::config::SubscriptionMode;
use crate::domain::defaults::CERT_WARNING_DAYS;
use crate::domain::NodeConfig;
use crate::host::cron::{self, Crontab, Tag};
use crate::host::nginx;
use crate::paths::Paths;
use crate::site;
use crate::sys::time::format_utc;

pub const SITE_NGINX: &str = "网站 nginx 配置";
pub const RENEWAL: &str = "证书自动续期";
const DAY: u64 = 86_400;
/// A certificate expiring within this many seconds is a warning (7 days,
/// v2's `openssl x509 -checkend 604800`).
pub const WARN_SECS: u64 = CERT_WARNING_DAYS * DAY;

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
    let standalone = matches!(
        cfg.subscription.as_ref().map(|s| &s.mode),
        Some(SubscriptionMode::Standalone { .. })
    );
    if standalone {
        list.push((CertScope::Subscription, CertDir::subscription(paths)));
    }
    list
}

pub fn certificate_checks(doctor: &Doctor, cfg: &NodeConfig) -> Vec<Check> {
    certificates(cfg, &doctor.ctx.paths)
        .into_iter()
        .map(|(scope, dir)| certificate_check(doctor, scope, &dir))
        .collect()
}

/// A certificate that cannot be inspected (no `openssl`, unreadable file)
/// is a warning, never an abort (D-8.1#27); a missing one is a failure.
fn certificate_check(doctor: &Doctor, scope: CertScope, dir: &CertDir) -> Check {
    match cert::status(doctor.ctx, dir.path()) {
        Ok(Some(status)) => expiry_check(scope, status.x509.expires_at, doctor.now),
        Ok(None) => Check::fail(
            scope.label(),
            format!("证书不存在（{}）；执行 onebox regen", dir.cert().display()),
        ),
        Err(e) => Check::warn(scope.label(), format!("无法检查证书: {e}")),
    }
}

/// Expired → failure; expiring within 7 days → warning; else the date.
pub fn expiry_check(scope: CertScope, expires_at: Option<u64>, now: u64) -> Check {
    let name = scope.label();
    let Some(at) = expires_at else {
        return Check::warn(name, "无法读取证书有效期");
    };
    let date = format_utc(at);
    let renew = format!("执行 onebox cert renew {}", scope.id());
    if at <= now {
        return Check::fail(name, format!("已于 {date} 过期；{renew}"));
    }
    let left = at - now;
    if left < WARN_SECS {
        let days = left.div_ceil(DAY);
        return Check::warn(name, format!("将在 {days} 天内到期（{date}）；{renew}"));
    }
    Check::pass(name, format!("有效期至 {date}（剩余 {} 天）", left / DAY))
}

/// `nginx -t` of the installed site configuration (the file `onebox-site`
/// runs with), while the site is active.
pub fn site_nginx_check(ctx: &Ctx, cfg: &NodeConfig) -> Option<Check> {
    cfg.site_active()?;
    let conf = site::conf_file(&ctx.paths);
    if !conf.is_file() {
        return Some(Check::fail(
            SITE_NGINX,
            format!("配置文件不存在（{}）；执行 onebox regen", conf.display()),
        ));
    }
    Some(match nginx::test(ctx, &ctx.paths.site(), &conf) {
        Ok(()) => Check::pass(SITE_NGINX, "nginx -t 通过"),
        Err(e) => Check::fail(SITE_NGINX, e.to_string()),
    })
}

/// The `# onebox:renew` cron line, when a certificate needs renewals
/// (`cert::renew_needed`: ACME → required, custom → recommended).
pub fn renewal_check(doctor: &Doctor, cfg: &NodeConfig) -> Option<Check> {
    let need = cert::renew_needed(cfg);
    if need == RenewNeed::None {
        return None;
    }
    let ctx = doctor.ctx;
    let line = if cron::available(ctx) {
        Crontab::read(ctx)
            .map(|tab| tab.has(&Tag::renew()))
            .map_err(|e| e.to_string())
    } else {
        Err("未找到 crontab".to_owned())
    };
    let scheduler = matches!(line, Ok(true)) && cron::scheduler_active(ctx, doctor.init);
    Some(renewal_verdict(need, line, scheduler))
}

/// A missing line fails for ACME (the certificate will expire) and warns
/// for custom certificates (refreshed sources are not redeployed); a cron
/// daemon that does not seem to run is a warning (detection is heuristic).
pub fn renewal_verdict(need: RenewNeed, line: Result<bool, String>, scheduler: bool) -> Check {
    let effect = match need {
        RenewNeed::Required => "ACME 证书不会自动续期",
        _ => "外部证书更新后不会自动部署",
    };
    let missing = |detail: String| match need {
        RenewNeed::Required => Check::fail(RENEWAL, detail),
        _ => Check::warn(RENEWAL, detail),
    };
    match line {
        Err(e) => missing(format!("{e}，{effect}")),
        Ok(false) => missing(format!("缺少每日续期任务，{effect}；执行 onebox regen")),
        Ok(true) if !scheduler => Check::warn(
            RENEWAL,
            format!("cron 未运行，续期任务不会执行（{effect}）；请启动系统 cron 服务"),
        ),
        Ok(true) => Check::pass(RENEWAL, "已安装每日续期任务"),
    }
}

#[cfg(test)]
mod tests;
