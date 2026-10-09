use super::*;
use crate::sys::fs::TempDir;

struct Fixture {
    _dir: TempDir,
    paths: Paths,
}

fn fixture() -> Fixture {
    let dir = TempDir::new("frp-journal").unwrap();
    let paths = Paths::isolated(dir.path());
    fs::create_dir_all(&paths.frp_root).unwrap();
    fs::write(paths.frp_root.join("state.json"), "{}").unwrap();
    fs::create_dir_all(&paths.systemd).unwrap();
    fs::write(unit_file(&paths, FRPS), "[Unit]\n").unwrap();
    Fixture { _dir: dir, paths }
}

fn before() -> Before {
    Before {
        active: vec![FRPS.into()],
        enabled: vec![FRPS.into(), FRP_WEB.into()],
        cron: CronSnapshot::default(),
    }
}

#[test]
fn journal_lives_next_to_the_lock() {
    let paths = Paths::from_lookup(|_| None).unwrap();
    assert_eq!(dir(&paths), PathBuf::from("/etc/.onebox-frp-journal"));
    assert_eq!(
        targets(&paths),
        [
            "/etc/onebox-frp",
            "/opt/onebox-frp",
            "/var/lib/onebox-frp",
            "/etc/systemd/system/onebox-frps.service",
            "/etc/init.d/onebox-frps",
            "/etc/systemd/system/onebox-frp-web.service",
            "/etc/init.d/onebox-frp-web",
        ]
        .map(PathBuf::from)
    );
    allowlist(&paths).check_scope().unwrap();
}

#[test]
fn create_publish_phase_and_remove() {
    let f = fixture();
    assert!(load(&f.paths).unwrap().is_none());
    assert!(!exists(&f.paths));
    let mut journal = create(&f.paths, "安装", before(), &targets(&f.paths)).unwrap();
    assert!(exists(&f.paths));
    assert_eq!(journal.phase, Phase::Prepared);
    let present: Vec<bool> = journal.snapshot.entries.iter().map(|e| e.present).collect();
    assert_eq!(present, [true, false, false, true, false, false, false]);
    journal.validate(&f.paths).unwrap();
    journal.set_phase(&f.paths, Phase::WriteFiles).unwrap();
    let loaded = load(&f.paths).unwrap().unwrap();
    assert_eq!(loaded, journal);
    assert_eq!(loaded.reason, "安装");
    // A second journal is refused while one is pending.
    let err = create(&f.paths, "x", before(), &targets(&f.paths)).unwrap_err();
    assert_eq!(err.to_string(), PENDING);
    remove(&f.paths).unwrap();
    assert!(!exists(&f.paths));
    // No staging directory was left next to the lock.
    let parent = dir(&f.paths).parent().unwrap().to_path_buf();
    let leftovers = fs::read_dir(&parent)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(STAGE_PREFIX))
        .count();
    assert_eq!(leftovers, 0);
}

#[test]
fn stale_staging_directories_are_swept() {
    let f = fixture();
    let parent = dir(&f.paths).parent().unwrap().to_path_buf();
    let stale = parent.join(format!("{STAGE_PREFIX}deadbeef"));
    fs::create_dir_all(stale.join("files")).unwrap();
    create(&f.paths, "安装", before(), std::slice::from_ref(&f.paths.frp_root)).unwrap();
    assert!(!stale.exists());
}

#[test]
fn foreign_targets_and_corruption_are_refused() {
    let f = fixture();
    let err = create(&f.paths, "x", before(), &[f.paths.root.join("state.json")]).unwrap_err();
    assert!(err.to_string().contains("快照路径范围不合法"), "{err}");
    assert!(!exists(&f.paths));

    let mut journal = create(&f.paths, "x", before(), std::slice::from_ref(&f.paths.frp_root)).unwrap();
    journal.active.push("onebox-xray".into());
    let path = dir(&f.paths).join(JOURNAL_FILE);
    fs::write(&path, serde_json::to_vec(&journal).unwrap()).unwrap();
    assert_eq!(
        load(&f.paths).unwrap_err().to_string(),
        "FRP 事务日志含未知服务"
    );
    fs::write(&path, "{").unwrap();
    let err = load(&f.paths).unwrap_err().to_string();
    assert!(err.starts_with("FRP 事务日志无效"), "{err}");
    fs::remove_file(&path).unwrap();
    let err = load(&f.paths).unwrap_err().to_string();
    assert!(err.starts_with("FRP 事务日志不完整"), "{err}");
}

#[test]
fn a_tampered_snapshot_fails_validation() {
    let f = fixture();
    let journal = create(&f.paths, "x", before(), std::slice::from_ref(&f.paths.frp_root)).unwrap();
    fs::write(files_dir(&f.paths).join("item-0/state.json"), "evil").unwrap();
    assert!(journal.validate(&f.paths).is_err());
}

#[test]
fn phases() {
    for phase in Phase::KNOWN {
        let text: String = phase.clone().into();
        assert_eq!(Phase::try_from(text).unwrap(), phase);
    }
    assert_eq!(
        Phase::try_from("future-step".to_owned()).unwrap(),
        Phase::Other("future-step".into())
    );
    assert!(Phase::try_from("Bad Phase".to_owned()).is_err());
    assert!(Phase::Committed.is_finished() && Phase::RolledBack.is_finished());
    assert!(!Phase::Other("x".into()).is_finished());
}
