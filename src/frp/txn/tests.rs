use super::*;
use crate::frp::journal::files_dir;
use crate::frp::testing::FakeHost;
use crate::host::firewall;
use crate::host::service::{FRPS, FRP_WEB};
use std::fs;

#[test]
fn messages_keep_cancellations() {
    let cancelled = decorate(Error::Cancelled.wrap("操作被信号 2 中断"), ROLLED_BACK);
    assert!(cancelled.is_cancelled());
    assert_eq!(cancelled.exit_code(), 130);
    assert_eq!(
        cancelled.report_text(),
        "操作被信号 2 中断；已恢复旧 FRP 配置与服务状态"
    );
    let plain = decorate(Error::msg("健康检查失败"), ROLLED_BACK);
    assert_eq!(plain.exit_code(), 1);
    assert_eq!(
        plain.to_string(),
        "健康检查失败；已恢复旧 FRP 配置与服务状态"
    );
}

#[test]
fn adoption_needs_markers_and_specs() {
    let h = FakeHost::new();
    let rt = h.runtime();
    let paths = rt.paths();
    refuse_adoption(&rt).unwrap();
    crate::frp::runtime::mkdirs(paths).unwrap();
    refuse_adoption(&rt).unwrap();
    fs::create_dir_all(&paths.initd).unwrap();
    let script = script_file(paths, FRP_WEB);
    fs::write(&script, "#!/sbin/openrc-run\n").unwrap();
    assert_eq!(
        refuse_adoption(&rt).unwrap_err().to_string(),
        format!("拒绝接管现有服务: {}", script.display())
    );
    let spec = ServiceDef::skeleton(paths, FRP_WEB).spec_path();
    fs::create_dir_all(spec.parent().unwrap()).unwrap();
    fs::write(&spec, "{}").unwrap();
    refuse_adoption(&rt).unwrap();
    fs::remove_file(paths.frp_web.join(MANAGED_FILE)).unwrap();
    assert!(refuse_adoption(&rt)
        .unwrap_err()
        .to_string()
        .starts_with("拒绝接管非本程序管理的目录"));
}

#[test]
fn rollback_removes_created_trees_with_their_skipped_files() {
    let h = FakeHost::new();
    let rt = h.runtime();
    let lock = rt.lock().unwrap();
    let paths = rt.paths();
    let txn = Txn::begin(&rt, &lock, "安装", &journal::targets(paths)).unwrap();
    crate::frp::runtime::mkdirs(paths).unwrap();
    // Names the snapshot never copies or deletes (pid file, acme.sh code).
    fs::write(paths.frp_root.join("nginx.pid"), "1").unwrap();
    fs::create_dir_all(paths.frp_root.join("web-tls/acme")).unwrap();
    fs::write(paths.frp_root.join("web-tls/acme/acme.sh"), "#!/bin/sh").unwrap();
    let err = txn.abort(Error::msg("失败"));
    assert_eq!(err.to_string(), format!("失败{ROLLED_BACK}"));
    for dir in [&paths.frp_root, &paths.frp_bin, &paths.frp_web] {
        assert!(!dir.exists(), "{}", dir.display());
    }
    assert!(!journal::exists(paths));
}

#[test]
fn rollback_restores_cron_lines_and_services() {
    let h = FakeHost::new();
    let rt = h.runtime();
    let paths = rt.paths();
    crate::frp::runtime::mkdirs(paths).unwrap();
    model::save(paths, &crate::frp::testing::tcp_state()).unwrap();
    let services = rt.services();
    services.write_all(&[ServiceDef::frps(paths)]).unwrap();
    services.enable(FRPS).unwrap();
    services.start(FRPS).unwrap();
    let line = crate::host::cron::line(
        "17 3 * * *",
        paths,
        rt.init,
        &["frps", "renew", "--cron"],
        &paths.frp_log.join("renew.log"),
        &crate::host::cron::Tag::frp_renew(),
    )
    .unwrap();
    h.set_crontab(&format!("MAILTO=root\n{line}\n0 1 * * * /bin/true\n"));
    let before_tab = h.crontab();
    let lock = rt.lock().unwrap();
    let mut txn = Txn::begin(&rt, &lock, "配置", &journal::targets(paths)).unwrap();
    txn.phase(Phase::StopServices).unwrap();
    services.stop(FRPS).unwrap();
    services.disable(FRPS).unwrap();
    crate::host::cron::Crontab::edit(rt.ctx, |tab| Ok(tab.remove_scope(Scope::Frp))).unwrap();
    let err = txn.abort(Error::msg("x"));
    assert!(err.to_string().ends_with(ROLLED_BACK));
    assert_eq!(h.crontab(), before_tab);
    assert!(h.running(FRPS) && h.enabled(FRPS));
}

#[test]
fn a_corrupt_snapshot_is_left_for_recover() {
    let h = FakeHost::new();
    let rt = h.runtime();
    let paths = rt.paths();
    crate::frp::runtime::mkdirs(paths).unwrap();
    fs::write(paths.frp_root.join("frps.toml"), "old").unwrap();
    let lock = rt.lock().unwrap();
    let txn = Txn::begin(&rt, &lock, "配置", &journal::targets(paths)).unwrap();
    fs::write(paths.frp_root.join("frps.toml"), "new").unwrap();
    fs::write(files_dir(paths).join("item-0/frps.toml"), "tampered").unwrap();
    let err = txn.abort(Error::msg("失败")).to_string();
    assert!(err.starts_with("失败；恢复未完成: "), "{err}");
    assert!(err.ends_with("请执行 onebox recover"), "{err}");
    assert!(journal::exists(paths));
    // Nothing was touched: the live file keeps the new content.
    assert_eq!(
        fs::read_to_string(paths.frp_root.join("frps.toml")).unwrap(),
        "new"
    );
    let err = recover_locked(&rt, &lock).unwrap_err().to_string();
    assert!(err.starts_with("FRP 事务恢复未完成"), "{err}");
}

#[test]
fn finished_journals_are_only_cleaned_up() {
    let h = FakeHost::new();
    let rt = h.runtime();
    let paths = rt.paths();
    let lock = rt.lock().unwrap();
    let mut journal = journal::create(paths, "x", journal::Before::default(), &[]).unwrap();
    journal.set_phase(paths, Phase::Committed).unwrap();
    assert!(!recover_locked(&rt, &lock).unwrap());
    assert!(!journal::exists(paths));
    Txn::run(&rt, &lock, "x", &[], |_| Ok(())).unwrap();
    assert!(!journal::exists(paths));
}

#[test]
fn a_finalized_journal_keeps_the_change() {
    // The commit record could not be written (full disk) and the process
    // ended: the journal says `finalize`, and recovery keeps the change.
    let h = FakeHost::new();
    let rt = h.runtime();
    let paths = rt.paths();
    crate::frp::runtime::mkdirs(paths).unwrap();
    fs::write(paths.frp_root.join("frps.toml"), "old").unwrap();
    let lock = rt.lock().unwrap();
    let mut txn = Txn::begin(&rt, &lock, "配置", &journal::targets(paths)).unwrap();
    txn.phase(Phase::WriteFiles).unwrap();
    fs::write(paths.frp_root.join("frps.toml"), "new").unwrap();
    txn.phase(Phase::Finalize).unwrap();
    drop(txn);
    assert!(journal::exists(paths));
    assert!(!recover_locked(&rt, &lock).unwrap());
    assert!(!journal::exists(paths));
    assert_eq!(
        fs::read_to_string(paths.frp_root.join("frps.toml")).unwrap(),
        "new"
    );
}

#[test]
fn run_records_finalize_before_committing_and_rolls_back_errors() {
    let h = FakeHost::new();
    let rt = h.runtime();
    let paths = rt.paths();
    crate::frp::runtime::mkdirs(paths).unwrap();
    fs::write(paths.frp_root.join("frps.toml"), "old").unwrap();
    let lock = rt.lock().unwrap();
    let phases = Txn::run(&rt, &lock, "配置", &journal::targets(paths), |txn| {
        fs::write(paths.frp_root.join("frps.toml"), "new").unwrap();
        Ok(txn.journal.phase.clone())
    })
    .unwrap();
    assert_eq!(phases, Phase::Prepared);
    assert!(!journal::exists(paths));
    let err = Txn::run(&rt, &lock, "配置", &journal::targets(paths), |_| {
        fs::write(paths.frp_root.join("frps.toml"), "broken").unwrap();
        Err::<(), _>(Error::msg("失败"))
    })
    .unwrap_err();
    assert_eq!(err.to_string(), format!("失败{ROLLED_BACK}"));
    assert_eq!(
        fs::read_to_string(paths.frp_root.join("frps.toml")).unwrap(),
        "new"
    );
}

/// An installed tcp state with a running, enabled `onebox-frps`.
fn installed(h: &FakeHost) {
    let rt = h.runtime();
    let paths = rt.paths();
    crate::frp::runtime::mkdirs(paths).unwrap();
    let state = crate::frp::testing::tcp_state();
    model::save(paths, &state).unwrap();
    firewall::reconcile_owner(rt.ctx, "frp", &state.firewall_ports()).unwrap();
    let services = rt.services();
    services.write_all(&[ServiceDef::frps(paths)]).unwrap();
    services.enable(FRPS).unwrap();
    services.start(FRPS).unwrap();
}

#[test]
fn failed_stops_and_firewall_clears_still_restore_the_files() {
    let h = FakeHost::new();
    installed(&h);
    let rt = h.runtime();
    let paths = rt.paths();
    let state_file = paths.frp_root.join("state.json");
    let original = fs::read(&state_file).unwrap();
    let lock = rt.lock().unwrap();
    let txn = Txn::begin(&rt, &lock, "配置", &journal::targets(paths)).unwrap();
    fs::write(&state_file, "{}").unwrap();
    // The stop times out and the firewall ledger is unreadable: v2's order
    // returned before the snapshot was restored.
    h.stick_unit(FRPS, true);
    fs::write(paths.frp_root.join("firewall-v2.json"), "{").unwrap();
    let err = txn.abort(Error::msg("失败")).to_string();
    assert!(err.starts_with(&format!("失败{PARTLY_RESTORED}")), "{err}");
    assert!(err.contains("停止 onebox-frps: "), "{err}");
    assert!(err.contains("清除 FRP 防火墙规则: "), "{err}");
    assert_eq!(fs::read(&state_file).unwrap(), original);
    assert!(!journal::exists(paths), "nothing is left for recover");
    // The restored ledger let the firewall come back; the service runs.
    assert!(!err.contains("恢复 FRP 防火墙规则"), "{err}");
    assert!(h.running(FRPS) && h.enabled(FRPS));
}

#[test]
fn services_that_cannot_restart_do_not_keep_the_journal() {
    let h = FakeHost::new();
    installed(&h);
    let rt = h.runtime();
    let paths = rt.paths();
    let lock = rt.lock().unwrap();
    {
        let _txn = Txn::begin(&rt, &lock, "配置", &journal::targets(paths)).unwrap();
        fs::write(paths.frp_root.join("frps.toml"), "half").unwrap();
        // Crash; afterwards the old unit no longer starts.
    }
    h.break_unit(FRPS, true);
    let Recovery::RolledBack(missed) = recover(&rt, &lock).unwrap() else {
        panic!("rolled back");
    };
    assert_eq!(missed.len(), 1, "{missed:?}");
    assert!(missed[0].starts_with("启动 onebox-frps: "), "{missed:?}");
    assert!(!journal::exists(paths));
    assert!(!paths.frp_root.join("frps.toml").exists());
    assert_eq!(recover(&rt, &lock).unwrap(), Recovery::Nothing);
}
