use super::*;
use crate::cli::session::testing::{Bench, Call};
use crate::domain::fixtures::config;
use crate::domain::protocol::Protocol;
use crate::sys::exec::Output;
use std::fs;
fn fake_backup(_ctx: &Ctx, lock: &FileLock, label: &str) -> Result<String> {
    assert_eq!(label, "before-uninstall");
    assert!(
        lock.path().ends_with(".apply.lock"),
        "taken under the node lock"
    );
    Ok("1791000000-1a2b3c4d".into())
}

fn failing_backup(_ctx: &Ctx, _lock: &FileLock, _label: &str) -> Result<String> {
    Err(Error::msg("备份失败"))
}

fn node() -> Bench {
    let bench = Bench::installed(&config(&[(Protocol::VlessReality, 443, Core::Xray)]));
    let paths = &bench.ctx.paths;
    for file in [
        paths.core_bin(Core::Xray),
        paths.core_config(Core::Xray),
        paths.clients().join("links.txt"),
        paths.subscription().join("devices.json"),
        paths.tls().join("key.pem"),
        paths.services().join("onebox-xray.json"),
        paths.site().join("nginx.conf"),
        paths.site_root.join("index.html"),
        paths.backups().join("1-aaaaaaaa/manifest.json"),
        paths.state_v2_backup(),
    ] {
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, "x").unwrap();
    }
    bench
}

#[test]
fn declined_or_not_installed_does_nothing() {
    let bench = Bench::new();
    let err = uninstall(&bench.session(), fake_backup).unwrap_err();
    assert_eq!(err.to_string(), "尚未安装 Onebox，请先执行 onebox install");
    let bench = node();
    bench.answers(&[""]);
    uninstall(&bench.session(), fake_backup).unwrap();
    assert_eq!(bench.ui.prompts(), [PROMPT]);
    assert!(bench.ctx.paths.state().exists());
    assert!(bench.engine.calls().is_empty());
}

#[test]
fn removes_the_node_and_keeps_site_and_backups() {
    let bench = node();
    bench.unattended();
    uninstall(&bench.session(), fake_backup).unwrap();
    assert_eq!(bench.engine.calls(), [Call::RecoverLocked]);
    let paths = &bench.ctx.paths;
    for gone in [
        paths.state(),
        paths.state_v2_backup(),
        paths.core_bin(Core::Xray),
        paths.core_config(Core::Xray),
        paths.clients(),
        paths.subscription(),
        paths.tls(),
        paths.services(),
    ] {
        assert!(!gone.exists(), "{} should be removed", gone.display());
    }
    for kept in [
        paths.site().join("nginx.conf"),
        paths.site_root.join("index.html"),
        paths.backups().join("1-aaaaaaaa/manifest.json"),
    ] {
        assert!(kept.exists(), "{} should be kept", kept.display());
    }
    assert_eq!(bench.output(), DONE);
    assert_eq!(bench.notes(), ["[提示] 已保存快照 1791000000-1a2b3c4d"]);
}

#[test]
fn a_failed_backup_aborts_before_any_removal() {
    let bench = node();
    bench.unattended();
    let err = uninstall(&bench.session(), failing_backup).unwrap_err();
    assert_eq!(err.to_string(), "备份失败");
    assert!(bench.ctx.paths.state().exists());
    assert!(bench.ctx.paths.core_bin(Core::Xray).exists());
}

#[test]
fn teardown_failures_keep_the_state_for_a_retry() {
    let bench = node();
    bench.unattended();
    // The unit exists, so removal stops it; systemctl fails.
    let unit = bench.ctx.paths.systemd.join("onebox-xray.service");
    fs::create_dir_all(unit.parent().unwrap()).unwrap();
    fs::write(&unit, "[Unit]\n").unwrap();
    bench
        .exec
        .on("systemctl", &["stop"], Output::failure(1, "boom"));
    let err = uninstall(&bench.session(), fake_backup).unwrap_err();
    assert!(
        err.to_string()
            .starts_with("卸载未完成: 删除 onebox-xray: "),
        "{err}"
    );
    assert!(err
        .to_string()
        .ends_with("问题解决后可再次执行 onebox uninstall"));
    assert!(err.to_string().contains(FILES_KEPT), "{err}");
    let paths = &bench.ctx.paths;
    assert!(paths.state().exists(), "state kept for a re-run");
    for kept in [
        paths.services(),
        paths.core_bin(Core::Xray),
        paths.core_config(Core::Xray),
        paths.clients(),
    ] {
        assert!(kept.exists(), "{} kept for the re-run", kept.display());
    }
}

/// No init system: the supervisor finds the daemon through its spec. A
/// failed removal keeps the specs and binaries, so the re-run can still
/// stop the daemon; once it succeeds everything goes.
#[test]
fn without_init_a_failed_service_removal_keeps_what_the_rerun_needs() {
    use crate::host::init::InitSystem;
    use crate::host::service::{ServiceDef, Services};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let mut bench = node();
    bench.live.init = InitSystem::None;
    bench.unattended();
    let paths = bench.ctx.paths.clone();
    Services::new(&bench.ctx, InitSystem::None)
        .write(&ServiceDef::core(&paths, Core::Xray, false))
        .unwrap();
    let spec = paths.services().join("onebox-xray.json");
    assert!(spec.is_file());
    // Disabling autostart reads the crontab, which fails the first time.
    let broken = Arc::new(AtomicBool::new(true));
    let flag = Arc::clone(&broken);
    bench.exec.provide("crontab").on_fn(
        |cmd| cmd.program == "crontab",
        move |_| {
            Ok(if flag.load(Ordering::SeqCst) {
                Output::failure(2, "crontab 不可用")
            } else {
                Output::success("")
            })
        },
    );
    let err = uninstall(&bench.session(), fake_backup).unwrap_err();
    assert!(
        err.to_string()
            .starts_with("卸载未完成: 删除 onebox-xray: "),
        "{err}"
    );
    for kept in [
        paths.state(),
        spec.clone(),
        paths.core_bin(Core::Xray),
        paths.core_config(Core::Xray),
    ] {
        assert!(kept.exists(), "{} kept for the re-run", kept.display());
    }
    // The problem is fixed: the re-run removes everything.
    broken.store(false, Ordering::SeqCst);
    uninstall(&bench.session(), fake_backup).unwrap();
    for gone in [
        paths.state(),
        spec,
        paths.services(),
        paths.core_bin(Core::Xray),
    ] {
        assert!(!gone.exists(), "{} removed", gone.display());
    }
    assert_eq!(bench.output(), DONE);
}

#[test]
fn a_pending_self_update_is_refused() {
    let bench = node();
    bench.unattended();
    fs::write(bench.ctx.paths.self_update_journal(), "{}").unwrap();
    let err = uninstall(&bench.session(), fake_backup).unwrap_err();
    assert!(!err.to_string().is_empty());
    assert!(bench.ctx.paths.state().exists());
}

#[test]
fn needs_root() {
    let mut bench = node();
    bench.is_root = false;
    let err = uninstall(&bench.session(), fake_backup).unwrap_err();
    assert_eq!(err.to_string(), "此操作需要 root 权限");
}
