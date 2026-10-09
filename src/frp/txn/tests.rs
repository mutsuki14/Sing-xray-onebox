use super::*;
use crate::frp::journal::files_dir;
use crate::frp::testing::FakeHost;
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
    let Some(h) = FakeHost::new() else { return };
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
    let Some(h) = FakeHost::new() else { return };
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
    let Some(h) = FakeHost::new() else { return };
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
    let Some(h) = FakeHost::new() else { return };
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
    let Some(h) = FakeHost::new() else { return };
    let rt = h.runtime();
    let paths = rt.paths();
    let lock = rt.lock().unwrap();
    let mut journal = journal::create(paths, "x", journal::Before::default(), &[]).unwrap();
    journal.set_phase(paths, Phase::Committed).unwrap();
    assert!(!recover_locked(&rt, &lock).unwrap());
    assert!(!journal::exists(paths));
    let txn = Txn::begin(&rt, &lock, "x", &[]).unwrap();
    txn.commit().unwrap();
    assert!(!journal::exists(paths));
}
