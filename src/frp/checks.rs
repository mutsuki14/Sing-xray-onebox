//! FRP checks for `onebox doctor` (none when FRP is not installed and no
//! transaction journal is left): a leftover transaction, the binary, the
//! services, the private CA and control certificate, the website
//! certificate and the renewal job. The state (readable, mode, warnings)
//! is the built-in `FRP 服务端` check.
//! Read-only: nothing is written, started or asked.
//!
//! Changes from v2: v2's `doctor` did not look at FRP at all.

use super::ca::{expires_within, ControlFiles};
use super::journal;
use super::model::{self, FrpState};
use super::release::binary_version;
use super::runtime::Runtime;
use crate::cert;
use crate::ctx::Ctx;
use crate::diag::{Check, CheckStatus};
use crate::domain::defaults::CERT_WARNING_DAYS;
use crate::host::cron::{self, Crontab, Tag};

const DAY: u64 = 86_400;
/// The CA must stay valid this long (the control certificate's window).
const CA_WINDOW: u64 = 30 * DAY;

fn check(name: &str, status: CheckStatus, detail: impl Into<String>) -> Check {
    Check::new(name, status, detail)
}

/// The doctor lines of FRP.
pub fn checks(ctx: &Ctx) -> Vec<Check> {
    checks_with(&Runtime::system(ctx))
}

/// [`checks`] with an explicit runtime. A leftover transaction journal is
/// reported even without an installation (a fresh install that crashed
/// before writing `state.json` leaves one, with partial trees).
pub fn checks_with(rt: &Runtime) -> Vec<Check> {
    let paths = rt.paths();
    let installed = model::installed(paths);
    if !installed && !journal::exists(paths) {
        return Vec::new();
    }
    let mut out = vec![journal_check(rt)];
    if !installed {
        return out;
    }
    // The state itself (readable, mode, warnings) is the built-in
    // `FRP 服务端` check; an unreadable one leaves nothing more to check.
    let Ok(Some(state)) = model::load(paths) else {
        return out;
    };
    out.push(binary_check(rt, &state));
    out.extend(service_checks(rt, &state));
    out.extend(control_checks(rt));
    if state.is_web() {
        out.push(web_cert_check(rt));
    }
    out.push(cron_check(rt));
    out
}

fn journal_check(rt: &Runtime) -> Check {
    let name = "FRP 事务";
    match journal::load(rt.paths()) {
        Ok(None) => check(name, CheckStatus::Pass, "无未完成事务"),
        Ok(Some(j)) if j.phase.is_finished() => check(
            name,
            CheckStatus::Warn,
            format!(
                "已结束的 FRP 事务（{}，阶段 {}）{}",
                j.reason,
                j.phase.id(),
                journal::CLEANUP
            ),
        ),
        Ok(Some(j)) => check(
            name,
            CheckStatus::Fail,
            format!(
                "未完成的 FRP 事务（{}，阶段 {}）；请执行 onebox recover",
                j.reason,
                j.phase.id()
            ),
        ),
        Err(e) => check(name, CheckStatus::Fail, format!("事务日志无法读取: {e}")),
    }
}

fn binary_check(rt: &Runtime, state: &FrpState) -> Check {
    let name = "frps 程序";
    match binary_version(rt.ctx, &rt.paths().frp_bin.join("frps")) {
        None => check(name, CheckStatus::Fail, "frps 缺失或无法运行"),
        Some(v) if v != state.version => check(
            name,
            CheckStatus::Warn,
            format!("frps {v} 与配置记录的 {} 不一致", state.version),
        ),
        Some(v) => check(name, CheckStatus::Pass, format!("frps {v}")),
    }
}

fn service_checks(rt: &Runtime, state: &FrpState) -> Vec<Check> {
    let services = rt.services();
    super::runtime::names(state)
        .into_iter()
        .map(|name| {
            if services.running(name) {
                check(name, CheckStatus::Pass, "运行中")
            } else {
                check(name, CheckStatus::Warn, "已停止；可执行 onebox frps start")
            }
        })
        .collect()
}

fn control_checks(rt: &Runtime) -> Vec<Check> {
    let files = ControlFiles::new(&rt.paths().frp_root);
    let ca = if expires_within(rt.ctx, &files.ca(), CA_WINDOW) {
        check(
            "FRP 私有 CA",
            CheckStatus::Fail,
            "无效或 30 天内到期；需执行 onebox frps rotate-ca 并重新导出所有客户端",
        )
    } else {
        check("FRP 私有 CA", CheckStatus::Pass, "有效")
    };
    let control = if expires_within(rt.ctx, &files.cert(), 0) {
        check(
            "FRP 控制证书",
            CheckStatus::Fail,
            "已过期或无法读取；请执行 onebox frps renew",
        )
    } else if expires_within(rt.ctx, &files.cert(), CERT_WARNING_DAYS * DAY) {
        check(
            "FRP 控制证书",
            CheckStatus::Warn,
            format!("{CERT_WARNING_DAYS} 天内到期；请执行 onebox frps renew"),
        )
    } else {
        check("FRP 控制证书", CheckStatus::Pass, "有效")
    };
    vec![ca, control]
}

fn web_cert_check(rt: &Runtime) -> Check {
    let name = "FRP 网站证书";
    match cert::status(rt.ctx, &rt.paths().frp_root.join("web-tls")) {
        Ok(None) => check(name, CheckStatus::Fail, "尚未部署网站证书"),
        Ok(Some(status)) => match status.warning(CERT_WARNING_DAYS) {
            Some(w) if status.days_left.is_some_and(|d| d < 0) => check(name, CheckStatus::Fail, w),
            Some(w) => check(name, CheckStatus::Warn, w),
            None => check(
                name,
                CheckStatus::Pass,
                format!("剩余 {} 天", status.days_left.unwrap_or_default()),
            ),
        },
        Err(e) => check(name, CheckStatus::Fail, e.to_string()),
    }
}

fn cron_check(rt: &Runtime) -> Check {
    let name = "FRP 续期任务";
    if !cron::available(rt.ctx) {
        return check(name, CheckStatus::Warn, "缺少 crontab，证书不会自动续期");
    }
    match Crontab::read(rt.ctx) {
        Ok(tab) if tab.has(&Tag::frp_renew()) => check(name, CheckStatus::Pass, "已安排"),
        Ok(_) => check(
            name,
            CheckStatus::Warn,
            "未找到续期计划任务；执行 onebox frps renew 可重新安排",
        ),
        Err(e) => check(name, CheckStatus::Warn, e.to_string()),
    }
}

#[cfg(test)]
mod tests;
