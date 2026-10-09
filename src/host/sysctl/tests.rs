use super::fake::{FakeSysctl, WriteFault};
use super::*;
use crate::sys::fs::TempDir;
use std::os::unix::fs::PermissionsExt;

const QDISC: &str = "net.core.default_qdisc";
const CC: &str = "net.ipv4.tcp_congestion_control";

struct Fixture {
    dir: TempDir,
    ctx: Ctx,
    exec: std::sync::Arc<crate::sys::exec::FakeExec>,
    sysctl: FakeSysctl,
    file: PathBuf,
}

impl Fixture {
    /// Runtime `cubic` / `fq_codel`, an existing file `old config\n` (0600).
    fn new() -> Fixture {
        let dir = TempDir::new("sysctl").unwrap();
        let (ctx, exec, _) = Ctx::test(dir.path());
        let sysctl = FakeSysctl::install(&exec, &[(CC, "cubic"), (QDISC, "fq_codel")]);
        let file = dir.join("sysctl.d/99-test.conf");
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, "old config\n").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        Fixture {
            dir,
            ctx,
            exec,
            sysctl,
            file,
        }
    }

    fn txn(&self, queue: &str) -> SysctlTxn {
        SysctlTxn::new(&[(QDISC, queue), (CC, "bbr")]).persist_to(&self.file)
    }

    fn assert_untouched(&self) {
        assert_eq!(self.sysctl.get(CC), "cubic");
        assert_eq!(self.sysctl.get(QDISC), "fq_codel");
        assert_eq!(std::fs::read_to_string(&self.file).unwrap(), "old config\n");
        let mode = std::fs::metadata(&self.file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    fn writes(&self) -> Vec<Vec<String>> {
        self.sysctl.state().writes.clone()
    }
}

/// Persist like production, then fail (e.g. the directory fsync failed
/// after the rename).
fn write_then_fail(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    atomic_write(path, bytes, mode)?;
    Err(Error::msg("injected failure after atomic rename"))
}

/// Which of INT/TERM/HUP the calling thread blocks.
fn blocked() -> [bool; 3] {
    // SAFETY: queries this thread's mask into a zeroed sigset.
    unsafe {
        let mut current: libc::sigset_t = std::mem::zeroed();
        libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut current);
        [libc::SIGINT, libc::SIGTERM, libc::SIGHUP].map(|s| libc::sigismember(&current, s) == 1)
    }
}

#[test]
fn commits_runtime_and_file_in_one_write() {
    let f = Fixture::new();
    f.txn("cake").commit(&f.ctx).unwrap();
    assert_eq!(
        (f.sysctl.get(CC), f.sysctl.get(QDISC)),
        ("bbr".into(), "cake".into())
    );
    assert_eq!(
        std::fs::read_to_string(&f.file).unwrap(),
        "# Managed by Onebox\nnet.core.default_qdisc = cake\nnet.ipv4.tcp_congestion_control = bbr\n"
    );
    let mode = std::fs::metadata(&f.file).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o644, "previous mode not kept on success");
    assert_eq!(
        f.writes(),
        [vec![format!("{QDISC}=cake"), format!("{CC}=bbr")]]
    );
    assert_eq!(
        f.exec.history()[..2],
        [format!("sysctl -n {QDISC}"), format!("sysctl -n {CC}")]
    );
    assert!(
        f.exec.calls().iter().all(|c| c.is_c_locale()),
        "errno texts are matched in the C locale"
    );
}

#[test]
fn partial_runtime_failure_restores_both_values_and_leaves_the_file() {
    let f = Fixture::new();
    f.sysctl.state().next_write = Some(WriteFault::FailAt(1));
    let err = f.txn("cake").commit(&f.ctx).unwrap_err().to_string();
    assert!(err.starts_with("sysctl 执行失败 (1)"), "{err}");
    f.assert_untouched();
    assert_eq!(f.writes().len(), 3, "one apply plus one restore per key");
}

#[test]
fn readback_mismatch_rolls_back() {
    let f = Fixture::new();
    f.sysctl.state().next_write = Some(WriteFault::Ignore);
    let err = f.txn("cake").commit(&f.ctx).unwrap_err();
    assert_eq!(err.to_string(), Messages::GENERIC.verify_failed);
    f.assert_untouched();
}

#[test]
fn persistence_failure_restores_runtime_file_and_mode() {
    let f = Fixture::new();
    assert!(f.txn("cake").commit_with(&f.ctx, &write_then_fail).is_err());
    f.assert_untouched();
}

#[test]
fn persistence_failure_removes_a_new_file() {
    let f = Fixture::new();
    std::fs::remove_file(&f.file).unwrap();
    assert!(f.txn("cake").commit_with(&f.ctx, &write_then_fail).is_err());
    assert!(!f.file.exists());
    assert_eq!(
        (f.sysctl.get(CC), f.sysctl.get(QDISC)),
        ("cubic".into(), "fq_codel".into())
    );
}

#[test]
fn every_value_is_restored_even_when_one_restore_fails() {
    let f = Fixture::new();
    f.sysctl.state().fail_restore = Some(QDISC.into());
    let fail = |_: &Path, _: &[u8], _: u32| Err(Error::msg("persist failure"));
    assert!(f.txn("cake").commit_with(&f.ctx, &fail).is_err());
    assert_eq!(f.sysctl.get(CC), "cubic");
    assert!(f.writes().contains(&vec![format!("{CC}=cubic")]));
    assert!(f.writes().contains(&vec![format!("{QDISC}=fq_codel")]));
}

#[test]
fn signal_mask_is_restored_on_success_and_failure() {
    let before = blocked();
    let f = Fixture::new();
    f.txn("fq").commit(&f.ctx).unwrap();
    assert_eq!(blocked(), before);
    f.sysctl.state().next_write = Some(WriteFault::FailAt(1));
    assert!(f.txn("cake").commit(&f.ctx).is_err());
    assert_eq!(blocked(), before);
    let guard = BlockSignals::new().unwrap();
    assert_eq!(blocked(), [true; 3]);
    drop(guard);
    assert_eq!(blocked(), before);
}

#[test]
fn unsafe_old_values_abort_before_any_write() {
    let f = Fixture::new();
    f.sysctl
        .state()
        .values
        .insert(CC.into(), "cubic;reboot".into());
    let txn = f.txn("fq").messages(Messages {
        unsafe_old: "无法安全保存原 TCP/队列参数",
        ..Messages::GENERIC
    });
    assert_eq!(
        txn.commit(&f.ctx).unwrap_err().to_string(),
        "无法安全保存原 TCP/队列参数"
    );
    assert!(f.writes().is_empty());
    let bad = SysctlTxn::new(&[("net.core.default_qdisc", "fq\nx")]);
    assert!(bad.commit(&f.ctx).is_err());
    assert!(f.writes().is_empty());
}

#[test]
fn a_hint_explains_a_value_the_kernel_rejects() {
    let f = Fixture::new();
    f.sysctl.state().write_error = "No such file or directory".into();
    f.sysctl.state().next_write = Some(WriteFault::FailAt(0));
    let txn = f.txn("cake").hint(QDISC, "当前内核不支持队列 cake");
    assert_eq!(
        txn.commit(&f.ctx).unwrap_err().to_string(),
        "当前内核不支持队列 cake（sysctl: setting key \"net.core.default_qdisc\": No such file or directory）"
    );
    f.assert_untouched();
    f.sysctl.state().write_error = "Invalid argument".into();
    f.sysctl.state().next_write = Some(WriteFault::FailAt(0));
    let err = txn.commit(&f.ctx).unwrap_err().to_string();
    assert!(err.starts_with("当前内核不支持队列 cake（"), "{err}");
    // The qdisc was accepted (and echoed on stdout); another key failed.
    f.sysctl.state().next_write = Some(WriteFault::FailAt(1));
    let err = txn.commit(&f.ctx).unwrap_err().to_string();
    assert!(
        err.starts_with(
            "sysctl 执行失败 (1): sysctl: setting key \"net.ipv4.tcp_congestion_control\""
        ),
        "{err}"
    );
    f.assert_untouched();
}

#[test]
fn other_write_failures_keep_the_raw_error() {
    for errno in [
        "Read-only file system",
        "Operation not permitted",
        "Permission denied",
    ] {
        let f = Fixture::new();
        f.sysctl.state().write_error = errno.into();
        f.sysctl.state().next_write = Some(WriteFault::FailAt(0));
        let txn = f.txn("cake").hint(QDISC, "当前内核不支持队列 cake");
        assert_eq!(
            txn.commit(&f.ctx).unwrap_err().to_string(),
            format!("sysctl 执行失败 (1): sysctl: setting key \"net.core.default_qdisc\": {errno}")
        );
        f.assert_untouched();
    }
}

#[test]
fn hint_keys_match_whole_names_in_procps_and_busybox_messages() {
    let procps = "sysctl: setting key \"net.core.default_qdisc\": No such file or directory";
    let busybox =
        "sysctl: error setting key 'net.core.default_qdisc' to 'fq_pie': No such file or directory";
    assert_eq!(rejected_value(procps, QDISC), Some(procps));
    assert_eq!(
        rejected_value(&format!("x\n  {busybox}\n"), QDISC),
        Some(busybox)
    );
    let longer = "sysctl: setting key \"net.core.default_qdisc_x\": No such file or directory";
    assert_eq!(rejected_value(longer, QDISC), None);
    let stat = "sysctl: cannot stat /proc/sys/net/core/default_qdisc: No such file or directory";
    assert_eq!(
        rejected_value(stat, QDISC),
        None,
        "the key itself is missing"
    );
}

#[test]
fn persistence_path_must_be_a_regular_file() {
    let f = Fixture::new();
    let target = f.dir.join("target");
    std::fs::write(&target, "untouched").unwrap();
    std::fs::remove_file(&f.file).unwrap();
    std::os::unix::fs::symlink(&target, &f.file).unwrap();
    assert!(f.txn("fq").commit(&f.ctx).is_err());
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "untouched");
    std::fs::remove_file(&f.file).unwrap();
    std::fs::create_dir(&f.file).unwrap();
    assert!(f.txn("fq").commit(&f.ctx).is_err());
    assert!(f.writes().is_empty());
}

#[test]
fn runtime_only_and_multi_field_values() {
    let f = Fixture::new();
    f.sysctl
        .state()
        .values
        .insert("net.ipv4.tcp_rmem".into(), "4096\t131072\t6291456".into());
    SysctlTxn::new(&[("net.ipv4.tcp_rmem", "4096 262144 16777216")])
        .commit(&f.ctx)
        .unwrap();
    assert_eq!(f.sysctl.get("net.ipv4.tcp_rmem"), "4096 262144 16777216");
    assert_eq!(std::fs::read_to_string(&f.file).unwrap(), "old config\n");
    assert!(same_value("4096\t1 2", "4096 1  2") && !same_value("1 2", "1 3"));
}

#[test]
fn missing_sysctl_d_is_created_world_readable() {
    let f = Fixture::new();
    let file = f.dir.join("fresh/sysctl.d/99-onebox.conf");
    SysctlTxn::new(&[(QDISC, "fq")])
        .persist_to(&file)
        .commit(&f.ctx)
        .unwrap();
    let mode = std::fs::metadata(file.parent().unwrap())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o755);
}
