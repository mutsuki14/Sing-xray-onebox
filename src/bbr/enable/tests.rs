//! Ported v2 enable tests plus the OpenVZ and qdisc-hint fixes.

use super::*;
use crate::bbr::fixture::Fixture;
use crate::host::sysctl::fake::WriteFault;
use crate::sys::fs::atomic_write;
use std::path::Path;

fn write_then_fail(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    atomic_write(path, bytes, mode)?;
    Err(Error::msg("injected failure after atomic rename"))
}

#[test]
fn enables_all_supported_queues() {
    for queue in Queue::ALL {
        let f = Fixture::new();
        enable(&f.ctx, queue).unwrap();
        assert_eq!(f.sysctl.get(CC), "bbr");
        assert_eq!(f.sysctl.get(QDISC), queue.id());
        let text = std::fs::read_to_string(&f.ctx.paths.bbr_conf).unwrap();
        assert_eq!(
            text,
            format!(
                "# Managed by Onebox\nnet.core.default_qdisc = {}\nnet.ipv4.tcp_congestion_control = bbr\n",
                queue.id()
            )
        );
        assert!(f
            .calls("modprobe")
            .contains(&vec![format!("sch_{}", queue.id())]));
    }
}

#[test]
fn runtime_partial_failure_restores_both_values_and_file() {
    let f = Fixture::new();
    f.sysctl.state().next_write = Some(WriteFault::FailAt(1));
    assert!(enable(&f.ctx, Queue::Cake).is_err());
    f.assert_old_runtime();
    assert_eq!(f.sysctl_writes(), 3);
}

#[test]
fn failed_enable_restores_the_callers_signal_mask() {
    fn blocked() -> [bool; 3] {
        // SAFETY: queries this thread's mask into a zeroed sigset.
        unsafe {
            let mut current: libc::sigset_t = std::mem::zeroed();
            libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut current);
            [libc::SIGINT, libc::SIGTERM, libc::SIGHUP].map(|s| libc::sigismember(&current, s) == 1)
        }
    }
    let before = blocked();
    let f = Fixture::new();
    f.sysctl.state().next_write = Some(WriteFault::FailAt(1));
    assert!(enable(&f.ctx, Queue::Cake).is_err());
    assert_eq!(blocked(), before);
}

#[test]
fn runtime_readback_failure_rolls_back() {
    let f = Fixture::new();
    f.sysctl.state().next_write = Some(WriteFault::Ignore);
    let err = enable(&f.ctx, Queue::Cake).unwrap_err();
    assert_eq!(err.to_string(), "BBR/队列应用校验失败，恢复原参数与配置");
    f.assert_old_runtime();
}

#[test]
fn persistence_failure_restores_runtime_and_existing_mode() {
    let f = Fixture::new();
    assert!(enable_with(&f.ctx, Queue::Cake, Some(&write_then_fail)).is_err());
    f.assert_old_runtime();
}

#[test]
fn persistence_failure_removes_new_file() {
    let f = Fixture::new();
    std::fs::remove_file(&f.ctx.paths.bbr_conf).unwrap();
    assert!(enable_with(&f.ctx, Queue::Cake, Some(&write_then_fail)).is_err());
    assert!(!f.ctx.paths.bbr_conf.exists());
    assert_eq!(
        (f.sysctl.get(CC), f.sysctl.get(QDISC)),
        ("cubic".into(), "fq_codel".into())
    );
}

#[test]
fn rollback_attempts_second_value_even_if_first_restore_fails() {
    let f = Fixture::new();
    f.sysctl.state().fail_restore = Some(QDISC.into());
    let fail = |_: &Path, _: &[u8], _: u32| Err(Error::msg("persist failure"));
    assert!(enable_with(&f.ctx, Queue::Cake, Some(&fail)).is_err());
    assert_eq!(f.sysctl.get(CC), "cubic");
    assert!(f
        .calls("sysctl")
        .contains(&vec!["-w".to_string(), format!("{CC}=cubic")]));
}

#[test]
fn cannot_enable_without_bbr() {
    let f = Fixture::new();
    f.sysctl
        .state()
        .values
        .insert(AVAILABLE.into(), "reno cubic".into());
    assert_eq!(
        enable(&f.ctx, Queue::Fq).unwrap_err().to_string(),
        "当前内核未提供 BBR；支持的 VPS 可安装 v3 内核，容器请联系宿主机管理员"
    );
    assert_eq!(f.sysctl_writes(), 0);
    assert_eq!(f.calls("modprobe"), [vec!["tcp_bbr".to_string()]]);
    f.assert_old_runtime();
}

#[test]
fn missing_bbr_is_loaded_with_modprobe_first() {
    let f = Fixture::new();
    f.sysctl
        .state()
        .values
        .insert(AVAILABLE.into(), "reno cubic".into());
    f.loads_bbr.store(true, std::sync::atomic::Ordering::SeqCst);
    enable(&f.ctx, Queue::Fq).unwrap();
    assert_eq!(f.calls("modprobe")[0], ["tcp_bbr"]);
    assert_eq!(f.sysctl.get(CC), "bbr");
}

#[test]
fn rejects_unsafe_paths_and_concurrent_writer_before_mutation() {
    let f = Fixture::new();
    let lock = crate::bbr::lock(&f.ctx).unwrap();
    assert_eq!(
        enable(&f.ctx, Queue::Fq).unwrap_err().to_string(),
        "另一个 BBR 操作正在进行；稍后重试"
    );
    drop(lock);
    let conf = &f.ctx.paths.bbr_conf;
    let target = f.dir.join("untouched");
    std::fs::write(&target, "untouched").unwrap();
    std::fs::remove_file(conf).unwrap();
    std::os::unix::fs::symlink(&target, conf).unwrap();
    assert_eq!(
        enable(&f.ctx, Queue::Fq).unwrap_err().to_string(),
        "BBR 配置路径必须是普通文件"
    );
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "untouched");
    std::fs::remove_file(conf).unwrap();
    std::fs::create_dir(conf).unwrap();
    assert!(enable(&f.ctx, Queue::Fq).is_err());
    assert!(f.calls("sysctl").is_empty());
}

#[test]
fn openvz_is_refused_before_anything_changes() {
    let f = Fixture::new();
    f.write("/proc/vz/veinfo", b"");
    assert_eq!(
        enable(&f.ctx, Queue::Fq).unwrap_err().to_string(),
        "OpenVZ 无法修改内核拥塞控制，请在服务商面板开启 BBR"
    );
    f.write("/proc/bc/0", b"");
    f.host().detect_virt = Some("openvz".into());
    assert!(
        enable(&f.ctx, Queue::Fq).is_err(),
        "systemd-detect-virt says openvz"
    );
    assert!(f.calls("sysctl").is_empty());
    assert!(!f.ctx.paths.bbr_dir.exists(), "no lock taken");
    f.host().detect_virt = Some("kvm".into());
    enable(&f.ctx, Queue::Fq).unwrap();
}

#[test]
fn unsupported_qdisc_gets_a_clear_message() {
    let f = Fixture::new();
    f.sysctl.state().next_write = Some(WriteFault::FailAt(0));
    assert_eq!(
        enable(&f.ctx, Queue::FqPie).unwrap_err().to_string(),
        "当前内核不支持队列 fq_pie（sch_fq_pie 不可用）；已恢复原参数，请改用 fq 或 fq_codel"
    );
    f.assert_old_runtime();
}

#[test]
fn enable_creates_the_private_data_dir_and_lock() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    enable(&f.ctx, Queue::Fq).unwrap();
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&f.ctx.paths.bbr_dir), 0o700);
    assert_eq!(mode(&f.ctx.paths.bbr_dir.join("lock")), 0o600);
    assert_eq!(mode(&f.ctx.paths.bbr_conf), 0o644);
}
