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
        assert_eq!(
            recover_all(&host.ctx, &host.lock).unwrap(),
            Recovery::Nothing
        );
        assert_eq!(before.diff(&host.world()), Vec::<String>::new());
        assert_invariants(&host);
    }
    // The picture does see a change: the same request, committed.
    let host = installed_host();
    let before = host.world();
    host.apply(big_change(&host)).unwrap();
    let changed = before.diff(&host.world());
    for path in [
        "etc/state.json",
        "etc/xray.json",
        "onebox",
        "bin/sing-box",
        "etc/client/probe.json",
    ] {
        assert!(changed.iter().any(|c| c == path), "{path}: {changed:?}");
    }
    assert!(
        changed.iter().any(|c| c.starts_with("units ")),
        "{changed:?}"
    );
    assert!(
        changed.iter().any(|c| c.starts_with("iptables ")),
        "{changed:?}"
    );
    // The v2 renewal line is retired; foreign lines keep their place.
    assert_eq!(host.crontab(), "MAILTO=root\n0 1 * * * /usr/bin/foreign\n");
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
fn hand_edited_onebox_crontab_lines_never_make_a_failed_apply_unrecoverable() {
    use crate::host::cron::testing::lines;
    let host = installed_host();
    let exe = host.paths().executable.display().to_string();
    let v2 = |target: &str| lines::v2_cert(target).replace(lines::EXE, &exe);
    // Renewal disabled by commenting it out, a redirect edited by hand, and
    // an indented (but otherwise intact) v2 line.
    let commented = format!("#{}", v2("proxy"));
    let edited = v2("site").replace(">/dev/null", ">>/var/log/renew.log");
    let indented = format!("  {}", v2("subscription"));
    host.set_crontab(&format!(
        "MAILTO=root\n{commented}\n{edited}\n{indented}\n0 1 * * * /usr/bin/foreign\n"
    ));
    let before = host.world();
    // Fails after finalize rewrote the crontab.
    host.features.inject(Fault::Fail(Checkpoint::Saved));
    let text = err_text(&host.apply(big_change(&host)).unwrap_err());
    assert!(text.starts_with("配置未应用，已恢复原状态"), "{text}");
    assert_no_journal(&host);
    // Everything is back except the edited line, which a journal may never
    // reinstall; the comment was never touched.
    let mut expected = before.clone();
    expected.cron = before.cron.replace(&format!("{edited}\n"), "");
    assert_eq!(expected.diff(&host.world()), Vec::<String>::new());
    assert!(host.crontab().contains(&commented));
    host.features.clear();
    assert_eq!(
        recover_all(&host.ctx, &host.lock).unwrap(),
        Recovery::Nothing
    );
    // A later apply still works and leaves the comment alone.
    host.apply(host.change(two_cores(), "修改")).unwrap();
    assert!(host.crontab().contains(&commented));
    assert_no_journal(&host);
}

/// A second Ctrl+C or SIGTERM must not abort a rollback half-way (every
/// unit stopped and disabled): the rollback runs with INT/TERM/HUP blocked,
/// so no new signal is forwarded to its service-manager commands, while
/// the forward stages stay cancellable.
#[test]
fn rollbacks_run_with_cancellation_signals_blocked() {
    use crate::apply::harness::cancel_signals_blocked;
    let host = installed_host();
    let before = host.world();
    // Run by the forward path (configure-services) and by rollback-files.
    host.probe_signal_mask("systemctl daemon-reload");
    host.probe_signal_mask("systemctl stop onebox-sing-box");
    host.features
        .inject(Fault::Fail(Checkpoint::Stage(Phase::StartCores)));
    let text = err_text(&host.apply(big_change(&host)).unwrap_err());
    assert!(text.starts_with("配置未应用，已恢复原状态"), "{text}");
    let reloads = host.masks_seen("systemctl daemon-reload");
    assert_eq!(reloads.first(), Some(&false), "{reloads:?}");
    assert_eq!(reloads.last(), Some(&true), "{reloads:?}");
    let stops = host.masks_seen("systemctl stop onebox-sing-box");
    assert!(stops.contains(&true), "rollback-stop: {stops:?}");
    assert!(!cancel_signals_blocked(), "the mask is restored");
    assert_eq!(before.diff(&host.world()), Vec::<String>::new());
    // The same in a recovery of a crashed apply.
    host.features.clear();
    host.features
        .inject(Fault::Crash(Checkpoint::Stage(Phase::StartCores)));
    let req = big_change(&host);
    let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| host.apply(req)));
    assert!(crashed.is_err());
    host.features.clear();
    host.probe_signal_mask("systemctl start onebox-xray");
    assert_eq!(
        recover_all(&host.ctx, &host.lock).unwrap(),
        Recovery::RolledBack
    );
    let starts = host.masks_seen("systemctl start onebox-xray");
    assert!(
        !starts.is_empty() && starts.iter().all(|b| *b),
        "{starts:?}"
    );
    assert!(!cancel_signals_blocked());
    assert_eq!(before.diff(&host.world()), Vec::<String>::new());
}

#[test]
fn a_firewall_rule_the_rollback_cannot_remove_is_kept_recorded_and_retried() {
    let host = installed_host();
    let before = host.world();
    host.features
        .inject(Fault::Fail(Checkpoint::Stage(Phase::StartCores)));
    // The new generation's rule cannot be deleted in rollback-stop once.
    host.fail_command("iptables -w 5 -D INPUT -p tcp --dport 8443 ");
    let text = err_text(&host.apply(host.change(singbox_only(), "修改")).unwrap_err());
    assert!(text.starts_with("配置未应用，已恢复原状态"), "{text}");
    // The leftover went into the restored ledger, so re-applying the old
    // rules removed it: rules and ledger are the old ones exactly.
    assert!(host.faults.lock().unwrap().is_empty(), "the fault fired");
    let deletes = host
        .history()
        .iter()
        .filter(|h| h.starts_with("iptables -w 5 -D INPUT -p tcp --dport 8443 "))
        .count();
    assert_eq!(
        deletes, 2,
        "failed once, retried by the old rules' reconcile"
    );
    assert_eq!(before.diff(&host.world()), Vec::<String>::new());
    assert_no_journal(&host);
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
        text.ends_with(&format!(
            "；事务日志保留于 {}，请执行 recover",
            dir.display()
        )),
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
        err.starts_with(&format!(
            "未完成事务恢复失败；日志保留于 {dir}: 停用 onebox-network"
        )),
        "{err}"
    );
    // A new apply refuses to start over the pending journal the same way.
    let err = host
        .apply(host.change(two_cores(), "再次修改"))
        .unwrap_err();
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
    let stopped = host
        .history()
        .iter()
        .any(|h| h == "systemctl stop onebox-xray");
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
        text.starts_with("配置已提交，但事务清理失败: 注入故障")
            && text.ends_with("；请执行 recover 清理"),
        "{text}"
    );
    assert_eq!(host.installed().inbounds, singbox_only().inbounds);
    let journal = journal::load(host.paths()).unwrap().unwrap();
    assert_eq!(journal.phase(), &Phase::Committed);
    host.features.clear();
    assert_eq!(
        recover_all(&host.ctx, &host.lock).unwrap(),
        Recovery::Finished
    );
    assert_no_journal(&host);
    assert_eq!(host.installed().inbounds, singbox_only().inbounds);
}

/// A Ctrl+C before the journal exists (here: while the cron daemon is
/// probed for an ACME renewal) ends in a cancellation, exit 130, and does
/// not cancel the next operation of the session.
#[test]
fn a_signal_during_preflight_cancels_and_is_consumed() {
    use crate::domain::config::WebCert;
    use crate::domain::fixtures::{self, with_site};
    use crate::domain::protocol::{Core, Protocol};
    let host = installed_host();
    let before = host.world();
    let reality = fixtures::config(&[(Protocol::VlessReality, 443, Core::Singbox)]);
    let mut cfg = with_site(reality, "example.com", false);
    if let Some(site) = cfg.site.as_mut() {
        site.cert = WebCert::Cloudflare;
    }
    host.interrupt_command("systemctl is-active --quiet cron");
    let err = host.apply(host.change(cfg, "启用网站")).unwrap_err();
    assert!(err.is_cancelled(), "{err}");
    assert_eq!(err.exit_code(), 130);
    let text = err_text(&err);
    assert!(
        text.ends_with(&format!("（操作被信号 {} 中断）", libc::SIGINT)),
        "{text}"
    );
    assert_eq!(signal::pending(), None, "the signal is consumed");
    assert!(host.features.calls().is_empty(), "no stage ran");
    assert_eq!(before.diff(&host.world()), Vec::<String>::new());
    assert_no_journal(&host);
    // The next apply is not cancelled by it.
    host.apply(host.change(singbox_only(), "修改")).unwrap();
    assert_invariants(&host);
}
