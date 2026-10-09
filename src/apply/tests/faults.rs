//! Failed applies: the old generation comes back byte for byte.

use super::*;
use crate::apply::harness::{singbox_only, two_cores, Fault};
use crate::apply::ApplyRequest;
use crate::state::StateHash;
use crate::sys::signal;

#[test]
fn a_failure_at_every_stage_and_at_the_final_save_restores_the_old_generation() {
    for point in uncommitted_points() {
        let host = installed_host();
        let before = host.world();
        host.features.inject(Fault::Fail(point.clone()));
        let err = host.apply(big_change(&host)).unwrap_err();
        let text = err_text(&err);
        assert!(
            text.starts_with("配置未应用，已恢复原状态: 注入故障"),
            "{point:?}: {text}"
        );
        assert_eq!(err.exit_code(), 1);
        assert_eq!(
            before.diff(&host.world()),
            Vec::<String>::new(),
            "{point:?}"
        );
        assert_no_journal(&host);
        // Recovery afterwards has nothing to do and changes nothing.
        host.features.clear();
        assert_eq!(recover_all(&host.ctx, &host.lock).unwrap(), Recovery::Nothing);
        assert_eq!(before.diff(&host.world()), Vec::<String>::new());
        assert_invariants(&host);
    }
    // The picture does see a change: the same request, committed.
    let host = installed_host();
    let before = host.world();
    host.apply(big_change(&host)).unwrap();
    let changed = before.diff(&host.world());
    for path in ["etc/state.json", "etc/xray.json", "onebox", "bin/sing-box", "etc/client/probe.json"] {
        assert!(changed.iter().any(|c| c == path), "{path}: {changed:?}");
    }
    assert!(changed.iter().any(|c| c.starts_with("units ")), "{changed:?}");
    assert!(changed.iter().any(|c| c.starts_with("iptables ")), "{changed:?}");
}

#[test]
fn failing_commands_in_each_stage_are_rolled_back() {
    let cases = [
        ("ip -j address", "无法读取本机地址"),
        ("sing-box check", "sing-box 配置校验失败"),
        ("systemctl stop onebox-xray", "systemctl 执行失败"),
        ("systemctl enable onebox-sing-box", "systemctl 执行失败"),
        ("iptables -w 5 -I INPUT", "iptables 执行失败"),
        ("systemctl enable onebox-network", "systemctl 执行失败"),
        ("systemctl start onebox-sing-box", "systemctl 执行失败"),
    ];
    for (needle, expected) in cases {
        let host = installed_host();
        let before = host.world();
        host.fail_command(needle);
        let req = host.change(singbox_only(), "修改");
        let text = err_text(&host.apply(req).unwrap_err());
        assert!(
            text.starts_with("配置未应用，已恢复原状态: ") && text.contains(expected),
            "{needle}: {text}"
        );
        host.clear_faults();
        assert_eq!(before.diff(&host.world()), Vec::<String>::new(), "{needle}");
        assert_no_journal(&host);
        assert_invariants(&host);
    }
}

#[test]
fn a_rollback_that_cannot_stop_keeps_the_journal_for_recover() {
    let host = installed_host();
    let before = host.world();
    host.features
        .inject(Fault::Fail(Checkpoint::Stage(Phase::StartCores)));
    // Only rollback-stop disables the network oneshot.
    host.fail_always("systemctl disable onebox-network");
    let text = err_text(&host.apply(host.change(singbox_only(), "修改")).unwrap_err());
    let dir = journal::dir(host.paths());
    assert!(text.starts_with("配置失败: 注入故障"), "{text}");
    assert!(
        text.contains("；恢复未完成: 停用 onebox-network: systemctl 执行失败"),
        "{text}"
    );
    assert!(
        text.ends_with(&format!("；事务日志保留于 {}，请执行 recover", dir.display())),
        "{text}"
    );
    let journal = journal::load(host.paths()).unwrap().unwrap();
    assert_eq!(journal.phase(), &Phase::RollbackStop);
    // Files were not restored under running services.
    assert_ne!(before.diff(&host.world()), Vec::<String>::new());
    // A later recover (the cause fixed) completes the rollback.
    host.clear_faults();
    assert_eq!(
        recover_all(&host.ctx, &host.lock).unwrap(),
        Recovery::RolledBack
    );
    assert_eq!(before.diff(&host.world()), Vec::<String>::new());
    assert_no_journal(&host);
    assert_invariants(&host);
}

#[test]
fn a_failed_recovery_names_the_kept_journal() {
    let host = installed_host();
    host.features
        .inject(Fault::Crash(Checkpoint::Stage(Phase::StartCores)));
    let req = host.change(singbox_only(), "修改");
    let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| host.apply(req)));
    assert!(crashed.is_err());
    host.clear_faults();
    host.fail_always("systemctl disable onebox-network");
    let err = recover_all(&host.ctx, &host.lock).unwrap_err().to_string();
    let dir = journal::dir(host.paths()).display().to_string();
    assert!(
        err.starts_with(&format!("未完成事务恢复失败；日志保留于 {dir}: 停用 onebox-network")),
        "{err}"
    );
    // A new apply refuses to start over the pending journal the same way.
    let err = host.apply(host.change(two_cores(), "再次修改")).unwrap_err();
    assert!(err.to_string().starts_with("未完成事务恢复失败"), "{err}");
}

#[test]
fn a_stale_expected_hash_changes_nothing() {
    let host = installed_host();
    let before = host.world();
    let mut req = host.change(singbox_only(), "修改");
    req.expected = StateHash::of(b"another generation");
    let err = host.apply(req).unwrap_err();
    assert!(matches!(err, Error::Conflict), "{err}");
    assert_eq!(err.to_string(), "配置已被其他操作修改，请重新读取后重试");
    assert!(host.history().is_empty(), "{:?}", host.history());
    assert!(host.features.calls().is_empty());
    assert_eq!(before.diff(&host.world()), Vec::<String>::new());
    assert_no_journal(&host);
    // A fresh install against an existing node is a conflict too.
    let fresh = ApplyRequest::new(two_cores(), StateHash::absent(), "安装");
    assert!(matches!(host.apply(fresh).unwrap_err(), Error::Conflict));
}

#[test]
fn a_signal_cancels_at_the_next_stage_and_keeps_exit_code_130() {
    let host = installed_host();
    let before = host.world();
    host.features.inject(Fault::Interrupt(Checkpoint::Stage(
        Phase::CheckConfigurations,
    )));
    let err = host.apply(host.change(singbox_only(), "修改")).unwrap_err();
    assert!(err.is_cancelled());
    assert_eq!(err.exit_code(), 130);
    assert_eq!(
        err.report_text(),
        format!("配置未应用，已恢复原状态: 操作被信号 {} 中断", libc::SIGINT)
    );
    // Cancelled before stop-old-services acted.
    let stopped = host.history().iter().any(|h| h == "systemctl stop onebox-xray");
    assert!(stopped, "rollback-stop stops the cores");
    assert_eq!(signal::pending(), None, "the consumed signal is cleared");
    assert_eq!(before.diff(&host.world()), Vec::<String>::new());
    assert_no_journal(&host);
    assert_invariants(&host);
}

#[test]
fn a_failed_first_install_leaves_nothing_behind() {
    let host = Host::new();
    let before = host.world();
    host.features
        .inject(Fault::Fail(Checkpoint::Stage(Phase::PublishSubscription)));
    let req = ApplyRequest::install(&host.ctx, two_cores(), "安装").unwrap();
    let text = err_text(&host.apply(req).unwrap_err());
    assert!(text.starts_with("配置未应用，已恢复原状态"), "{text}");
    // Only the configuration root existed (it holds the lock file).
    assert_eq!(before.diff(&host.world()), Vec::<String>::new());
    assert!(!exists(&host.paths().state()));
    assert_invariants(&host);
}

#[test]
fn a_failure_after_the_commit_point_is_not_rolled_back() {
    let host = installed_host();
    host.features
        .inject(Fault::Fail(Checkpoint::Stage(Phase::Finalize)));
    let text = err_text(&host.apply(host.change(singbox_only(), "修改")).unwrap_err());
    assert!(
        text.starts_with("配置已提交，但事务清理失败: 注入故障") && text.ends_with("；请执行 recover 清理"),
        "{text}"
    );
    assert_eq!(host.installed().inbounds, singbox_only().inbounds);
    let journal = journal::load(host.paths()).unwrap().unwrap();
    assert_eq!(journal.phase(), &Phase::Committed);
    host.features.clear();
    assert_eq!(recover_all(&host.ctx, &host.lock).unwrap(), Recovery::Finished);
    assert_no_journal(&host);
    assert_eq!(host.installed().inbounds, singbox_only().inbounds);
}
