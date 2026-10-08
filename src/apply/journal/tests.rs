use super::*;
use crate::apply::program_journal::{self, ProgramJournal};
use crate::apply::snapshot::{self, take, v2_fixed_targets, v2_node_allowlist_with};
use crate::apply::testing::{
    acme_deployment, acme_home, build_v2_layout, file, v2_journal_text, V2_STATE,
};
use crate::domain::fixtures::config;
use crate::domain::protocol::{Core, Protocol};
use crate::sys::fs::{sha256_hex, TempDir};
use std::os::unix::fs::{symlink, PermissionsExt};

const ALL: [Phase; 20] = [
    Phase::Prepared,
    Phase::PrepareState,
    Phase::ReplaceCores,
    Phase::PrepareCores,
    Phase::PrepareCertificates,
    Phase::CheckConfigurations,
    Phase::StopOldServices,
    Phase::CommitConfigurations,
    Phase::ConfigureServices,
    Phase::ApplyWebsite,
    Phase::ApplyNetwork,
    Phase::StartCores,
    Phase::PublishClients,
    Phase::PublishSubscription,
    Phase::Finalize,
    Phase::Committed,
    Phase::RollbackStop,
    Phase::RollbackFiles,
    Phase::RollbackServices,
    Phase::RolledBack,
];

fn tmp() -> TempDir {
    TempDir::new("journal-test").unwrap()
}

fn v3_journal() -> Journal {
    let cfg = config(&[(Protocol::VlessReality, 443, Core::Xray)]);
    Journal::new(
        "添加协议",
        Some(cfg),
        vec![svc::XRAY.into(), svc::NETWORK.into()],
        vec![svc::XRAY.into(), svc::NETWORK.into(), "onebox-net".into()],
        CronSnapshot {
            available: true,
            lines: vec!["17 4 * * * x # onebox:renew".into()],
            anchors: Some(vec![2]),
        },
        Snapshot::default(),
    )
}

fn keys(path: &Path) -> Vec<String> {
    let doc: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    doc.as_object().unwrap().keys().cloned().collect()
}

#[test]
fn phase_names_are_the_v2_names() {
    for phase in ALL {
        let json = serde_json::to_value(phase).unwrap();
        assert_eq!(json, phase.id(), "{phase:?}");
        let back: Phase = serde_json::from_value(json).unwrap();
        assert_eq!(back, phase);
        assert!(!phase.label().is_empty());
    }
    let finished: Vec<Phase> = ALL.into_iter().filter(|p| p.is_finished()).collect();
    assert_eq!(finished, [Phase::Committed, Phase::RolledBack]);
    let rollback: Vec<Phase> = ALL.into_iter().filter(|p| p.is_rollback()).collect();
    assert_eq!(rollback, Phase::ROLLBACK);
    assert_eq!(Phase::STAGES[..], ALL[1..15]);
    assert_eq!(Phase::CheckConfigurations.label(), "校验配置");
    assert!(serde_json::from_str::<Phase>("\"exploded\"").is_err());
}

#[test]
fn reads_a_journal_written_by_v2() {
    let dir_ = tmp();
    let root = dir_.path();
    let paths = build_v2_layout(root);
    let journal = parse(v2_journal_text(root).as_bytes()).unwrap();
    let Journal::V1(v1) = &journal else {
        panic!("expected a version-1 journal");
    };
    assert_eq!(journal.version(), V2_VERSION);
    assert_eq!(journal.phase(), Phase::PrepareCores);
    assert_eq!(journal.reason(), None);
    assert!(journal.active_services().is_empty());
    assert_eq!(
        journal.cron(),
        CronSnapshot {
            available: false,
            lines: vec![],
            anchors: None
        }
    );
    assert_eq!(journal.snapshot().entries.len(), 39);
    assert!(matches!(journal.old(), OldState::V2(_)));
    let values = journal.v2_values().unwrap().unwrap();
    assert_eq!(values["PORT_vless_reality"], "443");
    let original = crate::state::v2::v2_values_from_json(V2_STATE).unwrap();
    for (key, value) in &original {
        assert_eq!(values.get(key), Some(value), "{key}");
    }
    assert!(values.contains_key("__EXPECTED_STATE_HASH"));
    assert_eq!(journal.info().version, 1);
    assert!(v1.old_state.is_some());
    // Its snapshot is checked against v2's allowlist.
    assert_eq!(journal.allowlist(&paths), v2_node_allowlist(&paths));
    let mut targets = v2_fixed_targets(&paths);
    targets.push(acme_deployment(root));
    take(&targets, &files_dir(&paths)).unwrap();
    let mut recorded = journal.snapshot().clone();
    let deployment = recorded
        .entries
        .iter_mut()
        .find(|e| e.target == acme_deployment(root))
        .unwrap();
    // The deployment file embeds the capture root, so its digest differs.
    deployment.sha256 = snapshot::digest_tree(&acme_deployment(root)).unwrap();
    let allow = v2_node_allowlist_with(&paths, &[acme_home(root)]);
    snapshot::validate(&recorded, &files_dir(&paths), &allow).unwrap();
}

#[test]
fn a_v2_journal_keeps_its_shape_when_its_phase_changes() {
    let dir_ = tmp();
    let root = dir_.path();
    let paths = build_v2_layout(root);
    file(
        &dir(&paths).join(JOURNAL_FILE),
        0o600,
        v2_journal_text(root).as_bytes(),
    );
    let mut journal = load(&paths).unwrap().unwrap();
    journal.set_phase(&paths, Phase::RollbackStop).unwrap();
    assert_eq!(journal.phase(), Phase::RollbackStop);
    let path = dir(&paths).join(JOURNAL_FILE);
    let mut expected: Value = serde_json::from_str(&v2_journal_text(root)).unwrap();
    expected["phase"] = "rollback-stop".into();
    let written: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(written, expected);
    assert_eq!(
        keys(&path),
        [
            "active_services",
            "cron_available",
            "cron_lines",
            "enabled_services",
            "old_state",
            "phase",
            "snapshot",
            "version"
        ]
    );
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(load(&paths).unwrap().unwrap(), journal);
}

#[test]
fn first_install_v2_journal_has_no_old_state() {
    let text = r#"{"version":1,"old_state":null,"active_services":["onebox-network","onebox-net"],
        "enabled_services":["onebox-hop"],"cron_lines":["@reboot x # onebox-rust:onebox-xray"],
        "cron_available":true,"phase":"prepared","snapshot":{"entries":[]}}"#;
    let journal = parse(text.as_bytes()).unwrap();
    assert_eq!(journal.old(), OldState::None);
    assert_eq!(journal.v2_values().unwrap(), None);
    assert_eq!(
        journal.cron().lines,
        ["@reboot x # onebox-rust:onebox-xray"]
    );
    assert!(journal.cron().available);
    assert_eq!(journal.enabled_services(), ["onebox-hop"]);
}

#[test]
fn v3_journal_round_trips_typed() {
    let dir_ = tmp();
    let paths = Paths::isolated(dir_.path());
    let mut journal = v3_journal();
    assert_eq!(journal.phase(), Phase::Prepared);
    assert_eq!(journal.reason(), Some("添加协议"));
    assert!(matches!(journal.old(), OldState::Config(c) if c.inbounds.len() == 1));
    assert_eq!(journal.v2_values().unwrap(), None);
    assert_eq!(journal.allowlist(&paths), node_allowlist(&paths));
    // Staged first, then (after the rename) rewritten in place.
    let stage = paths.root.join(".transaction-new-0");
    write_in(&stage, &journal).unwrap();
    fs::rename(&stage, dir(&paths)).unwrap();
    assert_eq!(load(&paths).unwrap().unwrap(), journal);
    journal.set_phase(&paths, Phase::StartCores).unwrap();
    let loaded = load(&paths).unwrap().unwrap();
    assert_eq!(loaded, journal);
    assert_eq!(loaded.cron().anchors, Some(vec![2]));
    assert_eq!(
        keys(&dir(&paths).join(JOURNAL_FILE)),
        [
            "active_services",
            "cron",
            "enabled_services",
            "old_config",
            "phase",
            "reason",
            "snapshot",
            "version"
        ]
    );
    assert_eq!(
        loaded.info(),
        PhaseInfo {
            version: VERSION,
            phase: Phase::StartCores,
            reason: Some("添加协议".into())
        }
    );
}

#[test]
fn journals_naming_unknown_services_are_refused() {
    for (field, name) in [
        ("active_services", "onebox-frps"),
        ("enabled_services", "sshd"),
        ("active_services", "onebox-xray; rm -rf /"),
    ] {
        let mut doc = serde_json::to_value(match v3_journal() {
            Journal::V2(j) => j,
            Journal::V1(_) => unreachable!(),
        })
        .unwrap();
        doc[field] = serde_json::json!([name]);
        let err = parse(&serde_json::to_vec(&doc).unwrap()).unwrap_err();
        assert_eq!(err.to_string(), "事务日志含未知服务", "{name}");
    }
    // Every canonical and legacy name is accepted.
    let mut doc: Value = serde_json::from_str(&v2_journal_text(Path::new("/r"))).unwrap();
    let names: Vec<&str> = SERVICES
        .iter()
        .chain(&LEGACY_NETWORK_SERVICES)
        .copied()
        .collect();
    doc["active_services"] = serde_json::json!(names);
    doc["enabled_services"] = serde_json::json!(names);
    parse(&serde_json::to_vec(&doc).unwrap()).unwrap();
}

#[test]
fn malformed_journals_are_errors() {
    let unsupported = "不支持的事务日志版本";
    let cases = [
        (r#"{"version":0}"#, unsupported),
        (r#"{"version":3,"phase":"prepared"}"#, unsupported),
        (r#"{"phase":"prepared"}"#, unsupported),
        (r#"{"version":"1"}"#, unsupported),
        (r#"[1]"#, unsupported),
        (r#"{"version":1}"#, "事务日志无效"),
        ("not json", "事务日志无效"),
    ];
    for (text, prefix) in cases {
        let err = parse(text.as_bytes()).unwrap_err().to_string();
        assert!(err.starts_with(prefix), "{text}: {err}");
    }
    let mut doc: Value = serde_json::from_str(&v2_journal_text(Path::new("/r"))).unwrap();
    doc["phase"] = "exploded".into();
    let err = parse(&serde_json::to_vec(&doc).unwrap()).unwrap_err();
    assert!(err.to_string().starts_with("事务日志无效"), "{err}");
}

#[test]
fn load_distinguishes_absent_incomplete_and_oversized() {
    let dir_ = tmp();
    let paths = Paths::isolated(dir_.path());
    assert_eq!(load(&paths).unwrap(), None);
    fs::create_dir_all(dir(&paths)).unwrap();
    let err = load(&paths).unwrap_err().to_string();
    assert!(err.starts_with("事务日志不完整，未执行任何恢复"), "{err}");
    let path = dir(&paths).join(JOURNAL_FILE);
    fs::File::create(&path)
        .unwrap()
        .set_len(MAX_BYTES + 1)
        .unwrap();
    assert_eq!(load(&paths).unwrap_err().to_string(), "事务日志过大");
    fs::remove_file(&path).unwrap();
    symlink("/etc/passwd", &path).unwrap();
    let err = load(&paths).unwrap_err().to_string();
    assert!(err.starts_with("事务日志不完整"), "{err}");
    fs::remove_dir_all(dir(&paths)).unwrap();
    // A symlinked or non-directory journal path is refused.
    symlink(dir_.path(), dir(&paths)).unwrap();
    assert!(load(&paths)
        .unwrap_err()
        .to_string()
        .starts_with("事务目录无效"));
    fs::remove_file(dir(&paths)).unwrap();
    fs::write(dir(&paths), b"").unwrap();
    assert!(load(&paths)
        .unwrap_err()
        .to_string()
        .starts_with("事务目录无效"));
}

#[test]
fn pending_reports_both_journals_and_refuses_corrupt_ones() {
    let dir_ = tmp();
    let paths = Paths::isolated(dir_.path());
    let clean = pending(&paths).unwrap();
    assert_eq!(clean, Pending::default());
    assert!(!clean.any());
    clean.refuse().unwrap();
    // A node journal.
    fs::create_dir_all(dir(&paths)).unwrap();
    write(&paths, &v3_journal()).unwrap();
    let state = pending(&paths).unwrap();
    assert_eq!(
        state.config,
        Some(PhaseInfo {
            version: VERSION,
            phase: Phase::Prepared,
            reason: Some("添加协议".into())
        })
    );
    assert!(!state.program);
    assert_eq!(state.refuse().unwrap_err().to_string(), PENDING_MESSAGE);
    // A self-update journal.
    fs::remove_dir_all(dir(&paths)).unwrap();
    let journal = ProgramJournal::new(
        format!("{}{}", program_journal::WORK_PREFIX, "0".repeat(24)),
        None,
        sha256_hex(b"new"),
        None,
    );
    program_journal::write(&paths, &journal).unwrap();
    let state = pending(&paths).unwrap();
    assert_eq!(state.config, None);
    assert!(state.program && state.any());
    // Corrupt journals are errors, not "nothing pending".
    fs::write(program_journal::journal_path(&paths), b"{").unwrap();
    assert!(pending(&paths).is_err());
    fs::remove_file(program_journal::journal_path(&paths)).unwrap();
    fs::create_dir_all(dir(&paths)).unwrap();
    fs::write(dir(&paths).join(JOURNAL_FILE), b"{\"version\":9}").unwrap();
    assert_eq!(
        pending(&paths).unwrap_err().to_string(),
        "不支持的事务日志版本"
    );
}
