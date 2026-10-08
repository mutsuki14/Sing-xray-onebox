//! `bbr enable [queue]`: switch the running kernel to TCP BBR with the
//! chosen default qdisc and persist it in `ONEBOX_BBR_CONF`, as one sysctl
//! transaction (`host::sysctl`): on any failure the old congestion control,
//! qdisc and file (content and mode) are restored.
//!
//! Order (v2): OpenVZ refusal → config path must be a regular file or
//! absent → BBR lock → `bbr` available (else `modprobe tcp_bbr` and recheck)
//! → `modprobe sch_{queue}` (best effort) → transaction → conflict notices.
//!
//! Changes from v2: root is checked once by the caller (`geteuid`, no
//! `id -u`, I-8.1#2); a qdisc the kernel lacks gives a clear message (with
//! the raw `sysctl` line) instead of only a raw error (I-8.1#11), while any
//! other write failure (read-only `/proc/sys`) keeps the raw error; the
//! lock no longer validates the
//! sysctl path for kernel installs (I-8.1#13, the check lives here now).

use super::status::{conflict_notices, conflicts};
use super::{lock, preflight, Queue, AVAILABLE, CC, QDISC};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::host::sysctl::{self, Messages, Persist, SysctlTxn};
use crate::sys::exec::Cmd;
use crate::ui::out;

/// v2's wording for the BBR transaction.
pub const MESSAGES: Messages = Messages {
    unsafe_old: "无法安全保存原 TCP/队列参数",
    verify_failed: "BBR/队列应用校验失败，恢复原参数与配置",
    restore_value_failed: "恢复原 TCP/队列参数失败，请手动核对",
    restore_file_failed: "恢复 BBR 持久配置失败，请手动核对",
};

/// The transaction `enable` runs for `queue`.
pub fn transaction(ctx: &Ctx, queue: Queue) -> SysctlTxn {
    SysctlTxn::new(&[(QDISC, queue.id()), (CC, "bbr")])
        .persist_to(&ctx.paths.bbr_conf)
        .messages(MESSAGES)
        .hint(QDISC, unsupported_queue(queue))
}

/// The explanation for a qdisc the running kernel rejects (`host::sysctl`
/// appends the raw `sysctl` line), suggesting the other common queues.
pub fn unsupported_queue(queue: Queue) -> String {
    let others: Vec<&str> = [Queue::Fq, Queue::FqCodel]
        .into_iter()
        .filter(|q| *q != queue)
        .map(Queue::id)
        .collect();
    format!(
        "当前内核不支持队列 {id}（sch_{id} 不可用）；已恢复原参数，请改用 {}",
        others.join(" 或 "),
        id = queue.id()
    )
}

pub fn enable(ctx: &Ctx, queue: Queue) -> Result<()> {
    enable_with(ctx, queue, None)
}

/// [`enable`] with an injectable file writer (tests).
pub(super) fn enable_with(ctx: &Ctx, queue: Queue, persist: Option<&Persist<'_>>) -> Result<()> {
    if preflight::is_openvz(ctx) || detect_virt(ctx).as_deref() == Some("openvz") {
        return Err(Error::msg(
            "OpenVZ 无法修改内核拥塞控制，请在服务商面板开启 BBR",
        ));
    }
    match std::fs::symlink_metadata(&ctx.paths.bbr_conf) {
        Ok(meta) if !meta.is_file() => return Err(Error::msg("BBR 配置路径必须是普通文件")),
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            return Err(Error::io(&ctx.paths.bbr_conf, e))
        }
        _ => {}
    }
    let _lock = lock(ctx)?;
    ensure_bbr_available(ctx)?;
    // Best effort: a built-in qdisc has no module; the transaction reports
    // an unsupported one through its hint.
    let _ = ctx.run(&Cmd::new("modprobe").arg(format!("sch_{}", queue.id())));
    let txn = transaction(ctx, queue);
    match persist {
        Some(persist) => txn.commit_with(ctx, persist)?,
        None => txn.commit(ctx)?,
    }
    out::data(&format!(
        "TCP BBR + {} 已启用并保存 (BBR 版本取决于运行内核)\n默认队列用于新建队列；现有网卡的 tc/整形规则保持原状，可用 onebox bbr status 检查",
        queue.id()
    ))?;
    for notice in conflict_notices(&conflicts(ctx)) {
        out::warn(notice);
    }
    Ok(())
}

fn detect_virt(ctx: &Ctx) -> Option<String> {
    ctx.run(&Cmd::new("systemd-detect-virt"))
        .ok()
        .filter(|o| o.ok())
        .map(|o| o.stdout.trim().to_string())
}

fn bbr_listed(available: &str) -> bool {
    available.split_whitespace().any(|cc| cc == "bbr")
}

/// `bbr` must be an available congestion control, loading `tcp_bbr` once
/// if needed.
fn ensure_bbr_available(ctx: &Ctx) -> Result<()> {
    if bbr_listed(&sysctl::read(ctx, AVAILABLE).unwrap_or_default()) {
        return Ok(());
    }
    let _ = ctx.run(&Cmd::new("modprobe").arg("tcp_bbr"));
    if bbr_listed(&sysctl::read(ctx, AVAILABLE)?) {
        return Ok(());
    }
    Err(Error::msg(
        "当前内核未提供 BBR；支持的 VPS 可安装 v3 内核，容器请联系宿主机管理员",
    ))
}

#[cfg(test)]
mod tests;
