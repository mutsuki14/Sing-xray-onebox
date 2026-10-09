use super::*;
use crate::apply::snapshot::{node_targets, take, v2_fixed_targets};
use crate::apply::testing::{dir as mkdir, file};
use crate::sys::exec::{Exec, FakeExec, Output, SystemExec};
use crate::sys::fs::{sha256_hex, TempDir};
use crate::sys::lock::BUSY_MESSAGE;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::sync::Arc;

const OLD: &[u8] = b"\x7fELF old manager";
const NEW: &[u8] = b"\x7fELF new manager";
const CHILD_ROOT: &str = "ONEBOX_PROGRAM_JOURNAL_TEST_ROOT";

struct Fixture {
    _dir: TempDir,
    ctx: Ctx,
    exec: Arc<FakeExec>,
    lock: FileLock,
}

impl Fixture {
    /// An installed node (when `installed`) with the old manager in place.
    fn new(installed: bool) -> Fixture {
        let dir = TempDir::new("program-journal").unwrap();
        let (ctx, exec, _) = Ctx::test(dir.path());
        let paths = &ctx.paths;
        mkdir(&paths.root, 0o700);
        if installed {
            file(&paths.state(), 0o600, b"old-state");
            file(&paths.clients().join("links.txt"), 0o644, b"old-links");
        }
        file(&paths.executable, 0o755, OLD);
        exec.on("onebox", &["regen"], Output::success(""));
        let lock = FileLock::acquire(&paths.lock(), BUSY_MESSAGE).unwrap();
        Fixture {
            _dir: dir,
            ctx,
            exec,
            lock,
        }
    }

    fn paths(&self) -> &Paths {
        &self.ctx.paths
    }

    /// What the updater does up to writing the journal (G §5.2 steps 2–10).
    fn prepare(&self, version: u8, phase: ProgramPhase) -> (ProgramJournal, PathBuf) {
        let paths = self.paths();
        let (name, work) = create_work_dir(paths).unwrap();
        file(&work.join(OLD_FILE), 0o700, OLD);
        file(&work.join(NEW_FILE), 0o755, NEW);
        let snapshot = paths.state().exists().then(|| {
            take(
                &node_targets(paths),
                &work.join(CONFIG_DIR),
                &node_allowlist(paths),
            )
            .unwrap()
        });
        let mut journal =
            ProgramJournal::new(name, Some(sha256_hex(OLD)), sha256_hex(NEW), snapshot);
        journal.version = version;
        journal.phase = phase;
        write(paths, &journal).unwrap();
        (journal, work)
    }

    /// What a v2 updater does up to writing its (version 1) journal: it
    /// snapshots exactly v2's fixed targets.
    fn prepare_v2(&self, phase: ProgramPhase) -> (ProgramJournal, PathBuf) {
        let paths = self.paths();
        let (name, work) = create_work_dir(paths).unwrap();
        file(&work.join(OLD_FILE), 0o700, OLD);
        let snapshot = take(
            &v2_fixed_targets(paths),
            &work.join(CONFIG_DIR),
            &v2_node_allowlist(paths),
        )
        .unwrap();
        let mut journal =
            ProgramJournal::new(name, Some(sha256_hex(OLD)), sha256_hex(NEW), Some(snapshot));
        journal.version = V2_VERSION;
        journal.phase = phase;
        write(paths, &journal).unwrap();
        (journal, work)
    }

    /// The new manager is in place and its `regen` changed the configuration.
    fn replace_and_regenerate(&self) {
        let paths = self.paths();
        file(&paths.executable, 0o755, NEW);
        if paths.state().exists() {
            file(&paths.state(), 0o600, b"new-state");
            file(&paths.clients().join("links.txt"), 0o644, b"new-links");
            file(
                &paths.core_config(crate::domain::protocol::Core::Xray),
                0o600,
                b"{}",
            );
        }
    }

    /// Recover as a process whose image is neither manager (like a real
    /// recovery run by the new binary: "recovered, process stale"). A small
    /// stand-in image keeps the tests from hashing the test binary.
    fn recover(&self) -> Result<()> {
        recover_with(&self.ctx, &self.lock, &self.stale_image())
    }

    fn stale_image(&self) -> PathBuf {
        let image = self.paths().root.parent().unwrap().join("stale-image");
        file(&image, 0o755, b"\x7fELF test process");
        image
    }

    fn regens(&self) -> Vec<Cmd> {
        self.exec
            .calls()
            .into_iter()
            .filter(|c| c.args == ["regen"])
            .collect()
    }

    fn assert_restored(&self, work: &Path) {
        let paths = self.paths();
        assert_eq!(fs::read(&paths.executable).unwrap(), OLD);
        let mode = fs::metadata(&paths.executable)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o755);
        assert_eq!(fs::read(paths.state()).unwrap(), b"old-state");
        assert_eq!(
            fs::read(paths.clients().join("links.txt")).unwrap(),
            b"old-links"
        );
        assert!(!paths
            .core_config(crate::domain::protocol::Core::Xray)
            .exists());
        assert!(!journal_path(paths).exists());
        assert!(!work.exists());
    }
}

fn exit_code(result: Result<()>) -> i32 {
    match result {
        Err(Error::Exit { code, message }) => {
            assert_eq!(message, STALE_PROCESS);
            code
        }
        other => panic!("expected Exit, got {other:?}"),
    }
}

#[test]
fn every_uncommitted_crash_window_restores_the_old_manager() {
    // (phase, whether the new manager had been moved into place)
    let windows = [
        (ProgramPhase::Prepared, false),
        (ProgramPhase::Replacing, false),
        (ProgramPhase::Replacing, true),
        (ProgramPhase::Replaced, true),
        (ProgramPhase::Recovering, true),
        (ProgramPhase::Recovering, false),
    ];
    for (phase, replaced) in windows {
        let fx = Fixture::new(true);
        let (_, work) = fx.prepare(VERSION, phase);
        if replaced {
            fx.replace_and_regenerate();
        }
        assert_eq!(exit_code(fx.recover()), 75, "{phase:?}");
        fx.assert_restored(&work);
        let regens = fx.regens();
        assert_eq!(regens.len(), 1, "{phase:?}");
        let regen = &regens[0];
        assert_eq!(regen.program, fx.paths().executable.to_str().unwrap());
        assert_eq!(regen.inherit_lock_fd, Some(fx.lock.raw_fd()));
        assert!(regen.stream);
        assert!(regen.env.contains(&(
            "ONEBOX_DIR".into(),
            fx.paths().root.to_string_lossy().into()
        )));
        // Idempotent: nothing left to recover.
        fx.recover().unwrap();
        assert_eq!(fx.regens().len(), 1);
    }
}

#[test]
fn recovery_reports_success_when_this_process_is_the_restored_manager() {
    let fx = Fixture::new(true);
    let (_, work) = fx.prepare(VERSION, ProgramPhase::Replaced);
    fx.replace_and_regenerate();
    let image = fx.paths().root.join("image");
    file(&image, 0o755, OLD);
    let link = fx.paths().root.join("image-link");
    symlink(&image, &link).unwrap();
    recover_with(&fx.ctx, &fx.lock, &link).unwrap();
    fx.assert_restored(&work);
}

#[test]
fn committed_record_only_cleans_up() {
    let fx = Fixture::new(true);
    let (_, work) = fx.prepare(VERSION, ProgramPhase::Committed);
    fx.replace_and_regenerate();
    fx.recover().unwrap();
    assert_eq!(fs::read(&fx.paths().executable).unwrap(), NEW);
    assert_eq!(fs::read(fx.paths().state()).unwrap(), b"new-state");
    assert!(!journal_path(fx.paths()).exists());
    assert!(!work.exists());
    assert!(fx.exec.calls().is_empty());
    // A committed record whose program does not match is kept.
    let fx = Fixture::new(true);
    fx.prepare(VERSION, ProgramPhase::Committed);
    let err = fx.recover().unwrap_err().to_string();
    assert_eq!(err, "已提交的自更新程序不匹配，保留恢复记录");
    assert!(journal_path(fx.paths()).exists());
}

#[test]
fn failed_regeneration_keeps_the_record_for_a_retry() {
    let fx = Fixture::new(true);
    let (_, work) = fx.prepare(VERSION, ProgramPhase::Replaced);
    fx.replace_and_regenerate();
    let failing = Arc::new(FakeExec::new());
    failing.on("onebox", &["regen"], Output::failure(1, ""));
    let ctx = Ctx {
        exec: failing,
        ..fx.ctx.clone()
    };
    let err = recover_with(&ctx, &fx.lock, &fx.stale_image()).unwrap_err();
    assert!(
        err.to_string()
            .starts_with("恢复后的管理程序重新生成配置失败: onebox 执行失败 (1)"),
        "{err}"
    );
    let kept = load(fx.paths()).unwrap().unwrap();
    assert_eq!(kept.phase, ProgramPhase::Recovering);
    assert!(work.exists());
    assert_eq!(fs::read(&fx.paths().executable).unwrap(), OLD);
    // The retry completes the recovery.
    assert_eq!(exit_code(fx.recover()), 75);
    fx.assert_restored(&work);
}

#[test]
fn uninstalled_host_recovers_the_program_only() {
    // Updated without an installation: the old manager comes back, no regen.
    let fx = Fixture::new(false);
    let (journal, work) = fx.prepare(VERSION, ProgramPhase::Replaced);
    assert!(journal.snapshot.is_none());
    file(&fx.paths().executable, 0o755, NEW);
    assert_eq!(exit_code(fx.recover()), 75);
    assert_eq!(fs::read(&fx.paths().executable).unwrap(), OLD);
    assert!(fx.regens().is_empty());
    assert!(!work.exists());
    // The executable did not exist before: it is removed again.
    let fx = Fixture::new(false);
    fs::remove_file(&fx.paths().executable).unwrap();
    let (name, work) = create_work_dir(fx.paths()).unwrap();
    let journal = ProgramJournal::new(name, None, sha256_hex(NEW), None);
    write(fx.paths(), &journal).unwrap();
    file(&fx.paths().executable, 0o755, NEW);
    fx.recover().unwrap();
    assert!(!fx.paths().executable.exists());
    assert!(!work.exists() && !journal_path(fx.paths()).exists());
}

const PROXY_LEDGER: &[u8] = br#"{"rules":[{"backend":"iptables","port":443,"udp":false,"token":"onebox-proxy-0123456789abcdef"}]}"#;
const HOP_LEDGER: &[u8] = br#"[{"backend":"iptables","start":30000,"end":30100,"target":443,"token":"onebox-hop-0123456789abcdef"}]"#;
/// The rules the child regen created (after the snapshot was taken).
const NEW_PROXY_LEDGER: &[u8] = br#"{"rules":[{"backend":"iptables","port":80,"udp":false,"token":"onebox-proxy-fedcba9876543210"}]}"#;
const NEW_HOP_LEDGER: &[u8] = br#"[{"backend":"iptables","start":40000,"end":40100,"target":443,"token":"onebox-hop-fedcba9876543210"}]"#;

/// systemd with three node units, and the two v2 ledgers.
fn network_fixture() -> Fixture {
    let fx = Fixture::new(true);
    let paths = fx.paths().clone();
    mkdir(&paths.system("/run/systemd/system"), 0o755);
    for name in [svc::XRAY, svc::SITE, svc::SUBSCRIPTION, svc::NETWORK] {
        file(
            &paths.systemd.join(format!("{name}.service")),
            0o644,
            b"[Unit]",
        );
    }
    file(&paths.root.join("firewall-v2.json"), 0o600, PROXY_LEDGER);
    file(&paths.root.join("hop-v2.json"), 0o600, HOP_LEDGER);
    fx.exec
        .provide("iptables")
        .on("systemctl", &["stop"], Output::success(""));
    fx
}

fn is_iptables(c: &Cmd, op: &str) -> bool {
    c.program == "iptables" && c.args.iter().any(|a| a == op)
}

fn ledger(paths: &Paths, name: &str) -> serde_json::Value {
    serde_json::from_slice(&fs::read(paths.root.join(name)).unwrap()).unwrap()
}

#[test]
fn services_stop_in_v2_order_and_network_rules_are_cleared_first() {
    let fx = network_fixture();
    fx.exec.on_fn(
        |c| is_iptables(c, "-C") || is_iptables(c, "-D"),
        |_| Ok(Output::success("")),
    );
    let (_, work) = fx.prepare(VERSION, ProgramPhase::Replaced);
    fx.replace_and_regenerate();
    assert_eq!(exit_code(fx.recover()), 75);
    fx.assert_restored(&work);
    let history = fx.exec.history();
    let stops: Vec<&String> = history
        .iter()
        .filter(|c| c.starts_with("systemctl stop"))
        .collect();
    assert_eq!(
        stops,
        [
            "systemctl stop onebox-xray",
            "systemctl stop onebox-site",
            "systemctl stop onebox-subscription"
        ]
    );
    let position = |needle: &str| history.iter().position(|c| c.contains(needle)).unwrap();
    let deletes: Vec<&String> = history.iter().filter(|c| c.contains(" -D ")).collect();
    assert!(deletes
        .iter()
        .any(|c| c.contains("onebox-proxy-0123456789abcdef")));
    assert!(deletes
        .iter()
        .any(|c| c.contains("onebox-hop-0123456789abcdef")));
    assert!(position("systemctl stop onebox-subscription") < position(" -D "));
    // v2 order: the hops first, then the proxy rules.
    assert!(position("onebox-hop-0123456789abcdef") < position("onebox-proxy-0123456789abcdef"));
    assert!(position(" -D ") < position(" regen"));
}

#[test]
fn a_rule_left_behind_stops_the_recovery_before_anything_is_restored() {
    let fx = network_fixture();
    let deletes_work = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let works = deletes_work.clone();
    fx.exec
        .on_fn(|c| is_iptables(c, "-C"), |_| Ok(Output::success("")))
        .on_fn(
            |c| is_iptables(c, "-D"),
            move |_| {
                Ok(if works.load(std::sync::atomic::Ordering::SeqCst) {
                    Output::success("")
                } else {
                    Output::failure(4, "Another app is currently holding the xtables lock")
                })
            },
        );
    let (_, work) = fx.prepare(VERSION, ProgramPhase::Replaced);
    fx.replace_and_regenerate();
    // The child regen replaced the rules (a new token each).
    let paths = fx.paths().clone();
    file(
        &paths.root.join("firewall-v2.json"),
        0o600,
        NEW_PROXY_LEDGER,
    );
    file(&paths.root.join("hop-v2.json"), 0o600, NEW_HOP_LEDGER);
    let err = fx.recover().unwrap_err().to_string();
    assert!(err.starts_with(&format!("{RULES_LEFT}: ")), "{err}");
    assert!(
        err.contains("40000-40100/udp") && err.contains(" 80/tcp"),
        "{err}"
    );
    // Nothing was restored: the new manager, its state and its ledgers
    // (whose rules are still live) stay; the record waits for a retry.
    assert_eq!(fs::read(&paths.executable).unwrap(), NEW);
    assert_eq!(fs::read(paths.state()).unwrap(), b"new-state");
    let new_proxy: serde_json::Value = serde_json::from_slice(NEW_PROXY_LEDGER).unwrap();
    let new_hop: serde_json::Value = serde_json::from_slice(NEW_HOP_LEDGER).unwrap();
    assert_eq!(ledger(&paths, "firewall-v2.json"), new_proxy);
    assert_eq!(ledger(&paths, "hop-v2.json"), new_hop);
    assert_eq!(
        load(&paths).unwrap().unwrap().phase,
        ProgramPhase::Recovering
    );
    assert!(work.exists());
    assert!(fx.regens().is_empty());
    // Both kinds were attempted (v2 gave up at the first hop).
    let history = fx.exec.history();
    assert!(history
        .iter()
        .any(|c| c.contains(" -D ") && c.contains("onebox-hop-fedcba9876543210")));
    assert!(history
        .iter()
        .any(|c| c.contains(" -D ") && c.contains("onebox-proxy-fedcba9876543210")));
    // Once the rules can be removed, the retry restores everything.
    deletes_work.store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(exit_code(fx.recover()), 75);
    fx.assert_restored(&work);
    assert_eq!(fx.regens().len(), 1);
    let old_proxy: serde_json::Value = serde_json::from_slice(PROXY_LEDGER).unwrap();
    assert_eq!(ledger(&paths, "firewall-v2.json"), old_proxy);
}

#[test]
fn version_one_records_are_validated_against_the_v2_allowlist() {
    let fx = Fixture::new(true);
    let paths = fx.paths().clone();
    // A v2 updater snapshots exactly v2's fixed targets.
    let (name, work) = create_work_dir(&paths).unwrap();
    file(&work.join(OLD_FILE), 0o700, OLD);
    let snapshot = take(
        &v2_fixed_targets(&paths),
        &work.join(CONFIG_DIR),
        &v2_node_allowlist(&paths),
    )
    .unwrap();
    let mut v2 = ProgramJournal::new(name, Some(sha256_hex(OLD)), sha256_hex(NEW), Some(snapshot));
    v2.version = V2_VERSION;
    v2.validate(&paths).unwrap();
    // A v2 record missing one of v2's slots is a partial snapshot.
    let mut partial = v2.clone();
    partial.snapshot.as_mut().unwrap().entries.pop();
    assert_eq!(
        partial.validate(&paths).unwrap_err().to_string(),
        "快照缺少托管路径，拒绝部分恢复"
    );
    // The recorded targets of a v3 record only need to be owned paths.
    partial.version = VERSION;
    partial.validate(&paths).unwrap();
    // A v3 snapshot (with v3-only targets) is valid as v3, not as v2.
    let (mut v3, _) = fx.prepare(VERSION, ProgramPhase::Prepared);
    v3.validate(&paths).unwrap();
    v3.version = V2_VERSION;
    assert_eq!(
        v3.validate(&paths).unwrap_err().to_string(),
        "快照路径范围不合法"
    );
}

#[test]
fn invalid_records_are_refused_before_anything_changes() {
    type Edit = fn(&mut ProgramJournal, &Path);
    let cases: [(&str, Edit, &str); 11] = [
        ("version", |j, _| j.version = 3, INVALID),
        ("new digest", |j, _| j.new_sha256 = "xyz".into(), INVALID),
        ("missing old digest", |j, _| j.old_sha256.clear(), INVALID),
        (
            "old digest without old",
            |j, _| j.old_existed = false,
            INVALID,
        ),
        (
            "escaped work",
            |j, _| j.work = "../outside".into(),
            "更新工作目录前缀无效",
        ),
        (
            "bad work token",
            |j, _| j.work = format!("{WORK_PREFIX}zz"),
            "更新工作目录无效",
        ),
        (
            "tampered old",
            |_, w| fs::write(w.join(OLD_FILE), b"evil").unwrap(),
            "自更新旧程序备份 SHA256 不匹配，未更改当前程序",
        ),
        (
            "foreign executable",
            |j, _| j.new_sha256 = sha256_hex(b"other"),
            "当前程序已被其他操作替换，拒绝覆盖；请检查自更新记录",
        ),
        (
            "snapshot without old",
            |j, _| {
                j.old_existed = false;
                j.old_sha256.clear();
            },
            "已安装配置缺少可恢复的旧管理程序",
        ),
        (
            "tampered snapshot",
            |_, w| fs::write(w.join(CONFIG_DIR).join("item-0"), b"evil").unwrap(),
            "快照文件缺失或校验失败: item-0",
        ),
        (
            "foreign snapshot target",
            |j, _| j.snapshot.as_mut().unwrap().entries[1].target = "/etc/passwd".into(),
            "快照路径范围不合法",
        ),
    ];
    for (name, edit, expected) in cases {
        let fx = Fixture::new(true);
        let (mut journal, work) = fx.prepare(VERSION, ProgramPhase::Replaced);
        file(&fx.paths().executable, 0o755, NEW);
        edit(&mut journal, &work);
        write(fx.paths(), &journal).unwrap();
        let err = fx.recover().unwrap_err().to_string();
        assert_eq!(err, expected, "{name}");
        assert_eq!(fs::read(&fx.paths().executable).unwrap(), NEW, "{name}");
        assert_eq!(load(fx.paths()).unwrap().unwrap(), journal, "{name}");
        assert!(fx.exec.calls().is_empty(), "{name}");
    }
}

#[test]
fn symlinked_or_oversized_programs_are_refused() {
    let fx = Fixture::new(true);
    let (journal, work) = fx.prepare(VERSION, ProgramPhase::Replaced);
    let exe = &fx.paths().executable;
    // A symlinked work directory.
    fs::rename(&work, work.with_extension("real")).unwrap();
    symlink(work.with_extension("real"), &work).unwrap();
    let err = journal.validate(fx.paths()).unwrap_err().to_string();
    assert!(err.contains("不允许符号链接"), "{err}");
    fs::remove_file(&work).unwrap();
    fs::rename(work.with_extension("real"), &work).unwrap();
    // A symlinked executable.
    fs::remove_file(exe).unwrap();
    symlink(work.join(NEW_FILE), exe).unwrap();
    let err = journal.validate(fx.paths()).unwrap_err().to_string();
    assert!(err.contains("不允许符号链接"), "{err}");
    fs::remove_file(exe).unwrap();
    // An executable beyond the size limit.
    fs::File::create(exe)
        .unwrap()
        .set_len(PROGRAM_MAX_BYTES + 1)
        .unwrap();
    assert_eq!(
        journal.validate(fx.paths()).unwrap_err().to_string(),
        "当前程序超出自更新大小限制"
    );
    // A missing executable is fine (removed by a crash, restored from old).
    fs::remove_file(exe).unwrap();
    journal.validate(fx.paths()).unwrap();
    assert_eq!(exit_code(fx.recover()), 75);
    assert_eq!(fs::read(exe).unwrap(), OLD);
}

#[test]
fn load_and_write_keep_the_v2_format() {
    let dir = TempDir::new("program-journal-load").unwrap();
    let paths = Paths::isolated(dir.path());
    assert_eq!(load(&paths).unwrap(), None);
    let v2 = r#"{
  "version": 1,
  "work": ".onebox-update-0123456789abcdef01234567",
  "phase": "replaced",
  "old_existed": true,
  "old_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
  "new_sha256": "1111111111111111111111111111111111111111111111111111111111111111",
  "snapshot": { "entries": [ { "target": "/etc/onebox/state.json", "present": true, "slot": "item-0", "sha256": "2222222222222222222222222222222222222222222222222222222222222222" } ] }
}"#;
    file(&journal_path(&paths), 0o600, v2.as_bytes());
    let journal = load(&paths).unwrap().unwrap();
    assert_eq!(journal.version, V2_VERSION);
    assert_eq!(journal.phase, ProgramPhase::Replaced);
    assert_eq!(journal.snapshot.as_ref().unwrap().entries[0].slot, "item-0");
    write(&paths, &journal).unwrap();
    assert_eq!(load(&paths).unwrap().unwrap(), journal);
    let mode = fs::metadata(journal_path(&paths))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    let doc: serde_json::Value =
        serde_json::from_slice(&fs::read(journal_path(&paths)).unwrap()).unwrap();
    let keys: Vec<&String> = doc.as_object().unwrap().keys().collect();
    assert_eq!(
        keys,
        [
            "new_sha256",
            "old_existed",
            "old_sha256",
            "phase",
            "snapshot",
            "version",
            "work"
        ]
    );
    // Every phase keeps its v2 spelling.
    for (phase, text) in [
        (ProgramPhase::Prepared, "prepared"),
        (ProgramPhase::Replacing, "replacing"),
        (ProgramPhase::Replaced, "replaced"),
        (ProgramPhase::Committed, "committed"),
        (ProgramPhase::Recovering, "recovering"),
    ] {
        assert_eq!(serde_json::to_value(phase).unwrap(), text);
    }
    // No installation: `snapshot` is an explicit null (v2 requires it).
    let bare = ProgramJournal::new(
        format!("{WORK_PREFIX}{}", "a".repeat(24)),
        None,
        "1".repeat(64),
        None,
    );
    let doc = serde_json::to_value(&bare).unwrap();
    assert_eq!(doc["snapshot"], serde_json::Value::Null);
    assert_eq!(doc["version"], VERSION);
    assert_eq!(doc["phase"], "prepared");
    assert_eq!(doc["old_sha256"], "");
}

#[test]
fn malformed_or_oversized_records_are_errors() {
    let dir = TempDir::new("program-journal-bad").unwrap();
    let paths = Paths::isolated(dir.path());
    let path = journal_path(&paths);
    let base = r#""version":1,"work":".onebox-update-0123456789abcdef01234567","old_existed":false,"old_sha256":"","new_sha256":"1111111111111111111111111111111111111111111111111111111111111111","snapshot":null"#;
    for body in [
        format!(r#"{{{base},"phase":"replaced","extra":1}}"#),
        format!(r#"{{{base},"phase":"exploded"}}"#),
        format!(r#"{{{base}}}"#),
        "not json".to_owned(),
    ] {
        file(&path, 0o600, body.as_bytes());
        let err = load(&paths).unwrap_err().to_string();
        assert!(err.starts_with(INVALID), "{body}: {err}");
    }
    fs::File::create(&path)
        .unwrap()
        .set_len(JOURNAL_MAX_BYTES + 1)
        .unwrap();
    assert_eq!(
        load(&paths).unwrap_err().to_string(),
        "自更新恢复记录异常大"
    );
    fs::remove_file(&path).unwrap();
    symlink("/etc/passwd", &path).unwrap();
    assert!(load(&paths).is_err());
}

#[test]
fn set_phase_is_durable_and_work_dirs_are_private() {
    let fx = Fixture::new(false);
    let (mut journal, work) = fx.prepare(VERSION, ProgramPhase::Prepared);
    assert!(work.starts_with(fx.paths().executable.parent().unwrap()));
    let mode = fs::metadata(&work).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o700);
    journal
        .set_phase(fx.paths(), ProgramPhase::Replacing)
        .unwrap();
    assert_eq!(journal.phase, ProgramPhase::Replacing);
    assert_eq!(load(fx.paths()).unwrap().unwrap(), journal);
    journal.finish(fx.paths()).unwrap();
    assert!(!work.exists() && load(fx.paths()).unwrap().is_none());
}

/// Runs only inside the child started by
/// `inherited_lock_skips_the_parents_record`.
#[test]
fn inherited_lock_child() {
    let Some(root) = std::env::var_os(CHILD_ROOT) else {
        return;
    };
    let (ctx, exec, _) = Ctx::test(Path::new(&root));
    let lock = FileLock::from_inherited(&ctx.paths.lock()).unwrap();
    assert!(lock.is_inherited());
    recover_program_locked(&ctx, &lock).unwrap();
    assert!(exec.calls().is_empty());
    println!("inherited recovery skipped");
}

#[test]
fn inherited_lock_skips_the_parents_record() {
    if std::env::var_os(CHILD_ROOT).is_some() {
        return;
    }
    let fx = Fixture::new(true);
    let (journal, work) = fx.prepare(VERSION, ProgramPhase::Replaced);
    fx.replace_and_regenerate();
    let exe = std::env::current_exe().unwrap();
    let root = fx
        .paths()
        .root
        .parent()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let out = SystemExec
        .run(
            &Cmd::new(exe.to_str().unwrap())
                .args([
                    "--exact",
                    "apply::program_journal::tests::inherited_lock_child",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CHILD_ROOT, root)
                .inherit_lock(fx.lock.raw_fd()),
        )
        .unwrap();
    assert!(out.ok(), "{}\n{}", out.stdout, out.stderr);
    assert!(
        out.stdout.contains("inherited recovery skipped"),
        "{}",
        out.stdout
    );
    assert_eq!(load(fx.paths()).unwrap().unwrap(), journal);
    assert!(work.exists());
    assert_eq!(fs::read(&fx.paths().executable).unwrap(), NEW);
}

#[test]
fn a_pending_node_journal_is_refused_before_anything_changes() {
    let fx = Fixture::new(true);
    let (journal, work) = fx.prepare(VERSION, ProgramPhase::Replaced);
    fx.replace_and_regenerate();
    mkdir(&fx.paths().transaction(), 0o700);
    file(&fx.paths().transaction().join("journal.json"), 0o600, b"{}");
    let err = fx.recover().unwrap_err().to_string();
    assert_eq!(err, PENDING_MESSAGE);
    assert_eq!(load(fx.paths()).unwrap().unwrap(), journal);
    assert!(work.exists());
    assert_eq!(fs::read(&fx.paths().executable).unwrap(), NEW);
    assert_eq!(fs::read(fx.paths().state()).unwrap(), b"new-state");
    assert!(fx.exec.calls().is_empty());
    // Whatever the entry is (a file or a symlink, too).
    fs::remove_dir_all(fx.paths().transaction()).unwrap();
    symlink("/nonexistent", fx.paths().transaction()).unwrap();
    assert_eq!(fx.recover().unwrap_err().to_string(), PENDING_MESSAGE);
    fs::remove_file(fx.paths().transaction()).unwrap();
    assert_eq!(exit_code(fx.recover()), 75);
    fx.assert_restored(&work);
}

#[test]
fn a_foreign_lock_is_refused() {
    let fx = Fixture::new(true);
    fx.prepare(VERSION, ProgramPhase::Replaced);
    let other = TempDir::new("program-journal-other").unwrap();
    let foreign = FileLock::acquire(&other.join(".apply.lock"), BUSY_MESSAGE).unwrap();
    let err = recover_program_locked(&fx.ctx, &foreign).unwrap_err();
    assert_eq!(err.to_string(), "配置锁不属于当前实例");
    assert!(journal_path(fx.paths()).exists());
}

#[test]
fn only_3x_managers_take_part_in_a_self_update() {
    assert_eq!(semver("v3.0.1-rc1").unwrap(), (3, 0, 1));
    assert_eq!(semver("vv10.2.3").unwrap(), (10, 2, 3));
    for bad in ["", "3.0", "3.0.0.1", "3.x.0", "../../1", " 3.0.0"] {
        assert_eq!(
            semver(bad).unwrap_err().to_string(),
            "版本需要 major.minor.patch",
            "{bad:?}"
        );
    }
    for good in ["3.0.0", "v3.0.0", "3.1.0-rc1", "4.0.0"] {
        supported_target(good).unwrap();
        supported_installed(good).unwrap();
    }
    assert_eq!(
        supported_target("v2.0.1").unwrap_err().to_string(),
        "不支持自更新到 v2.0.1：2.x 及更早版本无法处理 3.x 的自更新恢复记录"
    );
    assert!(supported_target("1.9.9").is_err());
    assert_eq!(
        supported_installed("2.0.1").unwrap_err().to_string(),
        "已安装的管理程序为 2.0.1，请先执行 onebox update-script 由它升级到 3.x"
    );
    assert!(supported_installed("3.0").is_err());
}

/// v3-form node lines for the fixture's layout.
fn v3_node_lines(paths: &Paths) -> (String, String) {
    use crate::host::cron::{line, Tag};
    use crate::host::init::InitSystem;
    let renew = line(
        "17 4 * * *",
        paths,
        InitSystem::None,
        &["renew", "--cron"],
        &paths.log.join("renew.log"),
        &Tag::renew(),
    )
    .unwrap();
    let boot = line(
        "@reboot",
        paths,
        InitSystem::None,
        &["service", svc::XRAY, "start"],
        &paths.log.join("boot.log"),
        &Tag::boot(svc::XRAY).unwrap(),
    )
    .unwrap();
    (renew, boot)
}

#[test]
fn a_restored_2x_manager_regenerates_without_v3_cron_lines() {
    use crate::host::cron::testing::{fake_crontab, lines, text};
    let fx = Fixture::new(true);
    let paths = fx.paths().clone();
    let (_, work) = fx.prepare_v2(ProgramPhase::Replaced);
    fx.replace_and_regenerate();
    // The v3 child regen had rewritten the node's lines in its own form.
    let (renew, boot) = v3_node_lines(&paths);
    let v2_boot = format!(
        "@reboot env ONEBOX_DIR='{}' '{}' service onebox-xray start >/dev/null 2>&1 # onebox-rust:onebox-xray",
        paths.root.display(),
        paths.executable.display()
    );
    let kept = [
        "MAILTO=admin@example.com".to_owned(),
        v2_boot,
        lines::frp_renew(),
        "0 * * * * /usr/bin/backup.sh".to_owned(),
    ];
    let initial = format!(
        "{}\n{renew}\n{}\n{boot}\n{}\n{}\n",
        kept[0], kept[1], kept[2], kept[3]
    );
    let cron = fake_crontab(&fx.exec, Some(&initial));
    assert_eq!(exit_code(fx.recover()), 75);
    fx.assert_restored(&work);
    assert_eq!(text(&cron), format!("{}\n", kept.join("\n")));
    // Removed before the restored manager regenerates.
    let history = fx.exec.history();
    let installed = history
        .iter()
        .position(|c| c.starts_with("crontab ") && !c.ends_with(" -l"))
        .unwrap();
    let regen = history.iter().position(|c| c.ends_with(" regen")).unwrap();
    assert!(installed < regen, "{history:?}");
}

#[test]
fn a_restored_3x_manager_keeps_its_cron_lines() {
    use crate::host::cron::testing::{fake_crontab, text};
    let fx = Fixture::new(true);
    let (_, work) = fx.prepare(VERSION, ProgramPhase::Replaced);
    fx.replace_and_regenerate();
    let (renew, boot) = v3_node_lines(fx.paths());
    let initial = format!("{renew}\n{boot}\n");
    let cron = fake_crontab(&fx.exec, Some(&initial));
    assert_eq!(exit_code(fx.recover()), 75);
    fx.assert_restored(&work);
    assert_eq!(text(&cron), initial);
    assert!(!fx.exec.history().iter().any(|c| c.starts_with("crontab")));
}
