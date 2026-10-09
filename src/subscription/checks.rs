//! `onebox doctor` checks of the remote subscription (none when it is off):
//! the worker (running, current program), the standalone web service and
//! certificate, the published snapshot against the configuration, the
//! device list, and the IPv6 family of an ip-mode address.
//!
//! Read-only: service queries, file reads and `openssl` for the
//! certificate dates.

use super::devices::DeviceStore;
use super::endpoint::endpoint;
use super::lifecycle::worker_is_current;
use super::snapshot::{self, supported_formats};
use super::{SERVICE, WEB_SERVICE};
use crate::cert::{CertDir, CertStatus, Engine};
use crate::ctx::Ctx;
use crate::diag::{Check, CheckStatus};
use crate::domain::defaults::CERT_WARNING_DAYS;
use crate::domain::plan::check_subscription_family;
use crate::domain::NodeConfig;
use crate::host::service::Services;

const WORKER: &str = "订阅服务";
const WEB: &str = "订阅 HTTPS 入口";
const SNAPSHOT: &str = "订阅快照";
const DEVICES: &str = "订阅设备";
const CERT: &str = "订阅证书";
const ADDRESS: &str = "订阅地址";

/// Every subscription check for `cfg` (empty when the subscription is off).
pub fn checks(ctx: &Ctx, cfg: &NodeConfig) -> Vec<Check> {
    checks_with(&Engine::system(ctx), cfg)
}

/// [`checks`] with an explicit engine (init system, environment).
pub fn checks_with(engine: &Engine, cfg: &NodeConfig) -> Vec<Check> {
    let Some(sub) = &cfg.subscription else {
        return Vec::new();
    };
    let paths = &engine.ctx.paths;
    let services = engine.services();
    let mut out = vec![address(cfg, paths), worker(&services, paths)];
    if matches!(sub.mode, crate::domain::config::SubscriptionMode::Standalone { .. }) {
        out.push(running(&services, WEB, WEB_SERVICE));
        out.push(certificate(engine));
    }
    out.push(published(cfg, paths));
    out.push(devices(paths));
    out
}

fn address(cfg: &NodeConfig, paths: &crate::paths::Paths) -> Check {
    let ipv6 = crate::sys::net::ipv6_available(&paths.system_root);
    match check_subscription_family(cfg, ipv6) {
        Ok(()) => Check::new(
            ADDRESS,
            CheckStatus::Pass,
            endpoint(cfg).unwrap_or_default(),
        ),
        Err(e) => Check::new(ADDRESS, CheckStatus::Fail, e.to_string()),
    }
}

fn running(services: &Services, name: &str, service: &str) -> Check {
    if services.running(service) {
        Check::new(name, CheckStatus::Pass, format!("{service} 运行中"))
    } else {
        Check::new(name, CheckStatus::Fail, format!("{service} 未运行"))
    }
}

fn worker(services: &Services, paths: &crate::paths::Paths) -> Check {
    let check = running(services, WORKER, SERVICE);
    if check.status != CheckStatus::Pass || worker_is_current(services, paths) {
        return check;
    }
    Check::new(
        WORKER,
        CheckStatus::Warn,
        "运行的不是当前安装的程序；执行 onebox subscription publish 重启",
    )
}

fn certificate(engine: &Engine) -> Check {
    let dir = CertDir::subscription(&engine.ctx.paths);
    match crate::cert::store::status(engine.ctx, &dir) {
        Ok(Some(status)) => cert_check(&status),
        Ok(None) => Check::new(CERT, CheckStatus::Fail, "证书不存在"),
        Err(e) => Check::new(CERT, CheckStatus::Fail, e.to_string()),
    }
}

/// Fail when expired, warn within 7 days, else pass with the days left.
pub fn cert_check(status: &CertStatus) -> Check {
    match (status.warning(CERT_WARNING_DAYS), status.days_left) {
        (Some(w), Some(days)) if days < 0 => Check::new(CERT, CheckStatus::Fail, w),
        (Some(w), _) => Check::new(CERT, CheckStatus::Warn, w),
        (None, days) => Check::new(
            CERT,
            CheckStatus::Pass,
            format!("剩余 {} 天", days.unwrap_or_default()),
        ),
    }
}

fn published(cfg: &NodeConfig, paths: &crate::paths::Paths) -> Check {
    let want: Vec<&str> = supported_formats(cfg).iter().map(|f| f.id()).collect();
    match snapshot::load(paths) {
        Ok(Some(s)) => {
            let have: Vec<&str> = s.published_formats().iter().map(|f| f.id()).collect();
            if have == want {
                Check::new(SNAPSHOT, CheckStatus::Pass, have.join(" / "))
            } else {
                Check::new(
                    SNAPSHOT,
                    CheckStatus::Warn,
                    "已发布格式与当前协议不一致；执行 onebox subscription publish",
                )
            }
        }
        Ok(None) => Check::new(
            SNAPSHOT,
            CheckStatus::Fail,
            "尚未发布；执行 onebox subscription publish",
        ),
        Err(e) => Check::new(SNAPSHOT, CheckStatus::Fail, e.to_string()),
    }
}

fn devices(paths: &crate::paths::Paths) -> Check {
    match DeviceStore::load(paths) {
        Ok(store) if store.is_empty() => Check::new(
            DEVICES,
            CheckStatus::Warn,
            "没有设备；执行 onebox subscription add 名称",
        ),
        Ok(store) => Check::new(
            DEVICES,
            CheckStatus::Pass,
            format!("{} 个设备", store.devices().len()),
        ),
        Err(e) => Check::new(DEVICES, CheckStatus::Fail, e.to_string()),
    }
}

#[cfg(test)]
mod tests;
