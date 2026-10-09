//! `onebox doctor` checks of the remote subscription (none when it is off):
//! whether the running worker is the installed program, the published
//! snapshot against the configuration, the device list, and the IPv6
//! family of an ip-mode address.
//!
//! Whether the worker and the standalone web service run, and the
//! standalone certificate, are the built-in doctor checks (`服务 …`,
//! `订阅证书`); they are not repeated here.
//!
//! Read-only: service queries and file reads.
//!
//! Changes from v2: new — v2's doctor did not look at the subscription.

use super::devices::DeviceStore;
use super::endpoint::endpoint;
use super::lifecycle::worker_is_current;
use super::snapshot::{self, supported_formats};
use super::SERVICE;
use crate::cert::Engine;
use crate::ctx::Ctx;
use crate::diag::{Check, CheckStatus};
use crate::domain::plan::check_subscription_family;
use crate::domain::NodeConfig;
use crate::host::service::Services;

const WORKER: &str = "订阅服务";
const SNAPSHOT: &str = "订阅快照";
const DEVICES: &str = "订阅设备";
const ADDRESS: &str = "订阅地址";

/// Every subscription check for `cfg` (empty when the subscription is off).
pub fn checks(ctx: &Ctx, cfg: &NodeConfig) -> Vec<Check> {
    checks_with(&Engine::system(ctx), cfg)
}

/// [`checks`] with an explicit engine (init system, environment).
pub fn checks_with(engine: &Engine, cfg: &NodeConfig) -> Vec<Check> {
    if cfg.subscription.is_none() {
        return Vec::new();
    }
    let paths = &engine.ctx.paths;
    let mut out = vec![address(cfg, paths)];
    out.extend(worker(&engine.services(), paths));
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

/// The running worker is the installed program (after a self-update it
/// keeps serving with the old one until restarted); nothing when it does
/// not run (the built-in `服务 onebox-subscription` check reports that).
fn worker(services: &Services, paths: &crate::paths::Paths) -> Option<Check> {
    if !services.running(SERVICE) {
        return None;
    }
    Some(if worker_is_current(services, paths) {
        Check::new(WORKER, CheckStatus::Pass, "运行当前安装的程序")
    } else {
        Check::new(
            WORKER,
            CheckStatus::Warn,
            "运行的不是当前安装的程序；执行 onebox subscription publish 重启",
        )
    })
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
