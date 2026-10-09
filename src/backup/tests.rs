use super::archive::{self, Manifest, MANIFEST, OWNED_MARKER};
use super::store::{self, BackupKind, KEEP, LEGACY_LABEL};
use super::*;
use crate::apply::harness::{singbox_only, two_cores, Fault, Host};
use crate::apply::testing::{dir as mkdir, file, V2_STATE};
use crate::apply::{journal, Checkpoint};
use crate::domain::protocol::Core;
use crate::error::Error;
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

fn create(host: &Host, label: &str) -> String {
    create_locked(&host.ctx, &host.lock, label).unwrap()
}

fn restore(host: &Host, id: &str) -> Result<()> {
    restore_with(&host.ctx, &host.lock, id, &host.features)
}

fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
}

/// A schema-2 backup directory written by hand (`files` = its inventory).
fn write_backup(host: &Host, id: &str, created: u64, state: &[u8], extra: &[(&str, &[u8])]) {
    let dir = host.paths().backups().join(id);
    file(&dir.join("state.json"), 0o600, state);
    for (rel, bytes) in extra {
        file(&dir.join(rel), 0o600, bytes);
    }
    let manifest = Manifest {
        schema: 2,
        label: format!("label {id}"),
        created,
        files: archive::inventory(&dir).unwrap(),
    };
    let json = serde_json::to_vec_pretty(&manifest).unwrap();
    file(&dir.join(MANIFEST), 0o600, &json);
}

#[test]
fn a_backup_holds_the_state_and_private_copies_with_a_manifest() {
    let host = Host::new();
    host.install(two_cores());
    file(&host.paths().tls().join("cert.pem"), 0o644, b"CERT");
    file(&host.paths().site().join("nginx.pid"), 0o644, b"1");
    let id = create(&host, "手动\u{7}备份");
    let (secs, hex) = id.split_once('-').unwrap();
    assert!(secs.parse::<u64>().is_ok() && hex.len() == 8, "{id}");
    let dir = host.paths().backups().join(&id);
    assert_eq!(mode(&dir), 0o700);
    assert_eq!(
        fs::read(dir.join("state.json")).unwrap(),
        fs::read(host.paths().state()).unwrap()
    );
    assert_eq!(fs::read(dir.join("tls/cert.pem")).unwrap(), b"CERT");
    assert_eq!(mode(&dir.join("tls/cert.pem")), 0o600);
    assert_eq!(mode(&dir.join("client")), 0o700);
    assert!(!dir.join("site/nginx.pid").exists());
    let manifest: Manifest =
        serde_json::from_slice(&fs::read(dir.join(MANIFEST)).unwrap()).unwrap();
    assert_eq!(manifest.schema, 2);
    assert_eq!(manifest.label, "手动备份");
    assert_eq!(manifest.files, archive::inventory(&dir).unwrap());
    assert!(manifest.files.contains_key("client/probe.json"));
    let listed = list(host.paths()).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(
        (
            listed[0].id.as_str(),
            listed[0].label.as_str(),
            listed[0].kind
        ),
        (id.as_str(), "手动备份", BackupKind::Current)
    );
    assert!(host.ui.prompts().is_empty());
}

#[test]
fn backups_need_a_node_and_no_pending_recovery() {
    let host = Host::new();
    assert!(matches!(
        create_locked(&host.ctx, &host.lock, "x").unwrap_err(),
        Error::NotInstalled
    ));
    host.install(two_cores());
    host.features
        .inject(Fault::Crash(Checkpoint::Stage(journal::Phase::StartCores)));
    let req = host.change(singbox_only(), "修改");
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| host.apply(req))).is_err());
    let err = create_locked(&host.ctx, &host.lock, "x").unwrap_err();
    assert_eq!(err.to_string(), journal::PENDING_MESSAGE);
    assert!(list(host.paths()).unwrap().is_empty());
}

#[test]
fn oversized_or_linked_content_is_refused_and_nothing_is_kept() {
    let host = Host::new();
    host.install(two_cores());
    let clients = host.paths().clients();
    for i in 0..archive::MAX_FILES {
        file(&clients.join(format!("f{i}")), 0o600, b"");
    }
    let err = create_locked(&host.ctx, &host.lock, "big").unwrap_err();
    assert_eq!(err.to_string(), "备份超过 4096 文件或 64 MiB 限制");
    assert_eq!(fs::read_dir(host.paths().backups()).unwrap().count(), 0);
    fs::remove_dir_all(&clients).unwrap();
    let big = host.paths().tls().join("big");
    mkdir(&host.paths().tls(), 0o700);
    fs::File::create(&big)
        .unwrap()
        .set_len(archive::MAX_BYTES)
        .unwrap();
    let err = create_locked(&host.ctx, &host.lock, "big").unwrap_err();
    assert_eq!(err.to_string(), "备份超过 4096 文件或 64 MiB 限制");
    fs::remove_file(&big).unwrap();
    file(&host.paths().tls().join("a"), 0o600, b"a");
    fs::hard_link(host.paths().tls().join("a"), host.paths().tls().join("b")).unwrap();
    let err = create_locked(&host.ctx, &host.lock, "linked").unwrap_err();
    assert_eq!(err.to_string(), "备份拒绝链接或特殊文件");
    assert_eq!(fs::read_dir(host.paths().backups()).unwrap().count(), 0);
}

#[test]
fn order_latest_and_rotation_follow_creation_time_not_names() {
    let host = Host::new();
    host.install(two_cores());
    let state = fs::read(host.paths().state()).unwrap();
    // The second id claims a newer time than its manifest; the manifest
    // wins. Both are older than anything created now.
    write_backup(&host, "1600000000-aaaaaaaa", 1_600_000_000, &state, &[]);
    write_backup(&host, "1900000000-bbbbbbbb", 1_500_000_000, &state, &[]);
    let v1 = host.paths().backups().join("20200101T000000Z-Ab12Cd");
    file(&v1.join("format"), 0o600, b"1\n");
    file(&v1.join("label"), 0o600, b"v1 label\n");
    let foreign = host.paths().backups().join("keep-me");
    file(&foreign.join("notes"), 0o600, b"mine");
    let ids: Vec<String> = list(host.paths())
        .unwrap()
        .into_iter()
        .map(|b| b.id)
        .collect();
    // 2020-01-01T00:00:00Z = 1577836800 sorts between the two although its
    // id sorts above every Unix-time id; a foreign directory is oldest.
    assert_eq!(
        ids,
        [
            "1600000000-aaaaaaaa",
            "20200101T000000Z-Ab12Cd",
            "1900000000-bbbbbbbb",
            "keep-me"
        ]
    );
    let listed = list(host.paths()).unwrap();
    assert_eq!(listed[1].label, "v1 label");
    assert_eq!(listed[1].kind, BackupKind::V1);
    assert_eq!(
        (listed[3].label.as_str(), listed[3].kind),
        (LEGACY_LABEL, BackupKind::Unknown)
    );
    assert_eq!(store::latest(host.paths()).unwrap(), "1600000000-aaaaaaaa");
    // Rotation keeps the newest recognizable backups, the new one and the
    // one a restore is about to use; foreign directories stay.
    let mut created = Vec::new();
    for _ in 0..KEEP {
        created.push(
            store::create_kept(&host.ctx, &host.lock, "x", Some("1900000000-bbbbbbbb")).unwrap(),
        );
    }
    let ids: Vec<String> = list(host.paths())
        .unwrap()
        .into_iter()
        .map(|b| b.id)
        .collect();
    assert!(ids.contains(&"1900000000-bbbbbbbb".to_owned()), "{ids:?}");
    assert!(ids.contains(&"keep-me".to_owned()), "{ids:?}");
    assert!(
        !ids.contains(&"20200101T000000Z-Ab12Cd".to_owned()),
        "{ids:?}"
    );
    assert!(!ids.contains(&"1600000000-aaaaaaaa".to_owned()), "{ids:?}");
    for id in &created {
        assert!(ids.contains(id), "{id} {ids:?}");
    }
}

/// Rotation deletes through a stage, so a deletion stopped part-way never
/// leaves a half-deleted backup under its id (an unknown entry that
/// rotation would never remove, still holding credentials and the TLS
/// key); the next backup sweeps what such a deletion left.
#[test]
fn rotation_leaves_no_half_deleted_backup_behind() {
    let host = Host::new();
    host.install(two_cores());
    let root = host.paths().backups();
    let stage = root.join(format!("{}1600000000-aaaaaaaa", store::STAGE_PREFIX));
    file(&stage.join("state.json"), 0o600, b"credentials");
    file(&stage.join("tls/key.pem"), 0o600, b"key");
    assert!(
        list(host.paths()).unwrap().is_empty(),
        "a stage is no backup"
    );
    let ids: Vec<String> = (0..=KEEP).map(|_| create(&host, "x")).collect();
    assert!(!stage.exists(), "swept by the next backup");
    let mut names: Vec<String> = fs::read_dir(&root)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    let mut kept = ids[1..].to_vec();
    kept.sort();
    assert_eq!(names, kept, "the oldest went, and no stage stayed");
}

#[test]
fn v1_timestamps_parse_to_unix_seconds() {
    for (id, secs) in [
        ("19700101T000000Z-x", Some(0)),
        ("20261001T120000Z-Ab12Cd", Some(1_790_856_000)),
        ("20000229T235959Z-y", Some(951_868_799)),
        ("20261301T120000Z-z", None),
        ("2026-10-01-z", None),
        ("1791000000-aaaa", None),
    ] {
        assert_eq!(store::v1_created(id), secs, "{id}");
    }
    assert_eq!(store::days_from_civil(1970, 1, 1), 0);
    assert_eq!(store::days_from_civil(2000, 3, 1), 11_017);
    for days in [-1_000_000i64, -1, 0, 59, 11_016, 20_000, 3_000_000] {
        let (y, m, d) = crate::sys::time::civil_from_days(days);
        assert_eq!(store::days_from_civil(y, m, d), days);
    }
}

#[test]
fn a_backup_round_trips_through_a_restore() {
    let host = Host::new();
    host.install(two_cores());
    let original = host.installed();
    file(&host.paths().tls().join("cert.pem"), 0o600, b"OLD CERT");
    let id = create(&host, "before change");
    host.apply(host.change(singbox_only(), "修改")).unwrap();
    file(&host.paths().tls().join("cert.pem"), 0o600, b"NEW CERT");
    file(
        &host.paths().subscription().join("devices.json"),
        0o600,
        b"[]",
    );
    restore(&host, &id).unwrap();
    assert_eq!(host.installed(), original);
    assert_eq!(
        fs::read(host.paths().tls().join("cert.pem")).unwrap(),
        b"OLD CERT"
    );
    // The backup had no subscription directory: no device survives.
    assert!(!host.paths().subscription().exists());
    assert!(host.paths().core_config(Core::Xray).is_file());
    // A safety copy of the replaced generation was taken first.
    let safety = list(host.paths()).unwrap();
    assert_eq!(safety.len(), 2);
    assert_eq!(safety[0].label, store::BEFORE_RESTORE);
    let calls = host.features.calls();
    assert!(calls
        .iter()
        .any(|c| c == "prepare_subscription migrated=0 clear=false"));
    assert!(host.ui.prompts().is_empty());
}

#[test]
fn a_backup_restores_over_an_unreadable_state_json() {
    let host = Host::new();
    host.install(two_cores());
    let original = host.installed();
    let id = create(&host, "good");
    for corrupt in [&b"{ not json"[..], br#"{"schema":2}"#] {
        file(&host.paths().state(), 0o600, corrupt);
        // A plain backup of it would not be restorable: still refused.
        assert!(create_locked(&host.ctx, &host.lock, "x").is_err());
        restore(&host, &id).unwrap();
        assert_eq!(host.installed(), original);
        // The safety copy keeps the unreadable file byte for byte, says so,
        // and replaced the previous such copy.
        let safety = list(host.paths()).unwrap();
        assert_eq!(
            safety[0].label,
            store::unreadable_label(store::BEFORE_RESTORE)
        );
        assert_eq!(safety[0].kind, BackupKind::Unrestorable);
        let kept = host
            .paths()
            .backups()
            .join(&safety[0].id)
            .join("state.json");
        assert_eq!(fs::read(kept).unwrap(), corrupt);
        let copies = safety.iter().filter(|b| b.kind != BackupKind::Current);
        assert_eq!(copies.count(), 1, "{safety:?}");
        assert_eq!(store::latest(host.paths()).unwrap(), id);
        assert_no_journal_left(&host);
    }
    // Without any state.json there is still nothing to restore over.
    fs::remove_file(host.paths().state()).unwrap();
    assert!(matches!(
        store::create_kept(&host.ctx, &host.lock, "x", None).unwrap_err(),
        Error::NotInstalled
    ));
}

/// Restores that keep failing over an unreadable state.json (a port
/// conflict, a certificate that cannot be issued) leave one labelled copy
/// of it: every good backup stays, and neither `latest` nor the menus'
/// list offers the copy, which could never be restored.
#[test]
fn failed_restores_over_an_unreadable_state_keep_every_good_backup() {
    let host = Host::new();
    host.install(two_cores());
    let original = host.installed();
    let good: Vec<String> = (0..KEEP)
        .map(|i| create(&host, &format!("good {i}")))
        .collect();
    let newest = good[KEEP - 1].clone();
    file(&host.paths().state(), 0o600, b"{ not json");
    host.features
        .inject(Fault::Fail(Checkpoint::Stage(journal::Phase::StartCores)));
    for _ in 0..2 {
        let err = restore(&host, &newest).unwrap_err();
        assert!(
            err.report_text().starts_with("配置未应用，已恢复原状态"),
            "{err}"
        );
        assert_eq!(fs::read(host.paths().state()).unwrap(), b"{ not json");
    }
    let listed = list(host.paths()).unwrap();
    let copy = &listed[0];
    assert_eq!(
        (copy.kind, copy.label.as_str()),
        (
            BackupKind::Unrestorable,
            store::unreadable_label(store::BEFORE_RESTORE).as_str()
        ),
        "{listed:?}"
    );
    let current: Vec<&str> = listed
        .iter()
        .filter(|b| b.kind == BackupKind::Current)
        .map(|b| b.id.as_str())
        .collect();
    let mut expected: Vec<&str> = good.iter().map(String::as_str).collect();
    expected.reverse();
    assert_eq!(current, expected, "{listed:?}");
    assert_eq!(listed.len(), KEEP + 1, "{listed:?}");
    assert_eq!(store::latest(host.paths()).unwrap(), newest);
    let offered = super::cli::restorable(&host.ctx).unwrap();
    assert!(offered.iter().all(|b| b.id != copy.id), "{offered:?}");
    assert_eq!(offered.len(), KEEP);
    // Once the cause is gone, `latest` restores the newest good backup.
    host.features.clear();
    restore(&host, "latest").unwrap();
    assert_eq!(host.installed(), original);
    let listed = list(host.paths()).unwrap();
    assert_eq!(listed.len(), KEEP + 1, "{listed:?}");
    assert_eq!(listed[0].kind, BackupKind::Unrestorable);
    assert_eq!(store::latest(host.paths()).unwrap(), newest);
}

fn assert_no_journal_left(host: &Host) {
    assert!(journal::load(host.paths()).unwrap().is_none());
}

#[test]
fn the_running_workers_listener_record_is_never_backed_up_or_restored() {
    use crate::subscription::server::listener_file;
    let host = Host::new();
    host.install(two_cores());
    let record = listener_file(host.paths());
    let subscription = host.paths().subscription();
    file(&record, 0o600, br#"{"tcp":{"port":8001}}"#);
    file(&subscription.join("devices.json"), 0o600, b"[]");
    let id = create(&host, "before port change");
    let dir = host.paths().backups().join(&id);
    assert!(dir.join("subscription/devices.json").is_file());
    assert!(!dir.join("subscription/listener.json").exists());
    // The worker moved meanwhile; the restore keeps its record, so
    // publish-subscription sees the listener change and restarts it.
    file(&record, 0o600, br#"{"tcp":{"port":8002}}"#);
    restore(&host, &id).unwrap();
    assert_eq!(fs::read(&record).unwrap(), br#"{"tcp":{"port":8002}}"#);
    assert_eq!(fs::read(subscription.join("devices.json")).unwrap(), b"[]");

    // A backup an earlier version wrote with the record inside, and one
    // without a subscription directory: the live record stays either way.
    let state = fs::read(host.paths().state()).unwrap();
    write_backup(
        &host,
        "1791000000-aaaaaaaa",
        1_791_000_000,
        &state,
        &[("subscription/listener.json", b"{\"unix\":null}")],
    );
    restore(&host, "1791000000-aaaaaaaa").unwrap();
    assert_eq!(fs::read(&record).unwrap(), br#"{"tcp":{"port":8002}}"#);
    write_backup(&host, "1791000001-bbbbbbbb", 1_791_000_001, &state, &[]);
    restore(&host, "1791000001-bbbbbbbb").unwrap();
    assert_eq!(fs::read(&record).unwrap(), br#"{"tcp":{"port":8002}}"#);
    assert!(!subscription.join("devices.json").exists());
}

#[test]
fn a_failed_restore_puts_everything_back() {
    let host = Host::new();
    host.install(two_cores());
    let id = create(&host, "base");
    host.apply(host.change(singbox_only(), "修改")).unwrap();
    file(&host.paths().tls().join("cert.pem"), 0o600, b"CURRENT");
    let before = host.world().without(&["etc/backups"]);
    host.features
        .inject(Fault::Fail(Checkpoint::Stage(journal::Phase::StartCores)));
    let err = restore(&host, &id).unwrap_err();
    assert!(
        err.report_text().starts_with("配置未应用，已恢复原状态"),
        "{err}"
    );
    assert_eq!(
        before.diff(&host.world().without(&["etc/backups"])),
        Vec::<String>::new()
    );
}

/// A minimal v2 state: the fixture's values with protocols that need no
/// certificate.
fn v2_state() -> Vec<u8> {
    let mut doc: Value = serde_json::from_slice(V2_STATE).unwrap();
    let values = doc["values"].as_object_mut().unwrap();
    values.insert("PROTOCOLS".into(), "vless-reality shadowsocks".into());
    values.insert("__EXPECTED_STATE_HASH".into(), "absent".into());
    values.remove("HY2_HOP");
    serde_json::to_vec_pretty(&doc).unwrap()
}

#[test]
fn a_backup_written_by_v2_is_migrated_with_its_own_devices() {
    let host = Host::new();
    host.install(singbox_only());
    file(
        &host.paths().site_root.join("index.html"),
        0o644,
        b"live site",
    );
    file(
        &host.paths().site_root.join(OWNED_MARKER),
        0o600,
        b"onebox\n",
    );
    let device = json!({
        "id": "0123456789abcdef",
        "name": "phone",
        "hash": "a".repeat(64),
        "created": 1_700_000_000u64
    });
    let settings = json!({"enabled": false, "devices": [device]}).to_string();
    let id = "1790000000-0a1b2c3d";
    write_backup(
        &host,
        id,
        1_790_000_000,
        &v2_state(),
        &[
            ("subscription/settings.json", settings.as_bytes()),
            ("tls/cert.pem", b"V2 CERT"),
            ("public/index.html", b"v2 site"),
        ],
    );
    let (resolved, preview) = preview(host.paths(), "latest").unwrap();
    assert_eq!(resolved, id);
    assert_eq!(preview.devices.as_ref().map(Vec::len), Some(1));
    restore(&host, "latest").unwrap();
    let restored = host.installed();
    assert_eq!(restored.creds.uuid, "6f2c1d3e-8a4b-4c5d-8e6f-0a1b2c3d4e5f");
    assert_eq!(restored.inbounds.len(), 2);
    assert_eq!(restored.inbounds[0].port, 443);
    // Devices from the backup's settings went through the transaction.
    let calls = host.features.calls();
    assert!(
        calls
            .iter()
            .any(|c| c == "prepare_subscription migrated=1 clear=false"),
        "{calls:?}"
    );
    let devices: Vec<Value> =
        serde_json::from_slice(&fs::read(host.paths().devices()).unwrap()).unwrap();
    assert_eq!(devices[0]["id"], "0123456789abcdef");
    assert_eq!(
        fs::read(host.paths().tls().join("cert.pem")).unwrap(),
        b"V2 CERT"
    );
    let index = host.paths().site_root.join("index.html");
    assert_eq!(fs::read(&index).unwrap(), b"v2 site");
    assert_eq!(mode(&index), 0o644);
    assert!(host.paths().site_root.join(OWNED_MARKER).is_file());
}

#[test]
fn unusable_backups_are_refused_before_anything_changes() {
    let host = Host::new();
    host.install(two_cores());
    let state = fs::read(host.paths().state()).unwrap();
    let v1 = host.paths().backups().join("20261001T120000Z-Ab12Cd");
    file(&v1.join("format"), 0o600, b"1\n");
    write_backup(
        &host,
        "1791000000-aaaaaaaa",
        1_791_000_000,
        &state,
        &[("tls/x", b"x")],
    );
    fs::write(
        host.paths().backups().join("1791000000-aaaaaaaa/tls/x"),
        b"tampered",
    )
    .unwrap();
    let before = host.world();
    let cases = [
        (
            "20261001T120000Z-Ab12Cd",
            archive::v1_refusal("20261001T120000Z-Ab12Cd"),
        ),
        ("1791000000-aaaaaaaa", "备份完整性校验失败".to_owned()),
        ("../etc", "备份 ID 无效".to_owned()),
        ("1791000001-ffffffff", "备份不存在".to_owned()),
    ];
    for (id, expected) in cases {
        assert_eq!(
            restore(&host, id).unwrap_err().to_string(),
            expected,
            "{id}"
        );
    }
    // `latest` is the newest schema-2 backup, validated like any other.
    assert_eq!(
        restore(&host, "latest").unwrap_err().to_string(),
        "备份完整性校验失败"
    );
    assert_eq!(before.diff(&host.world()), Vec::<String>::new());
}

#[test]
fn a_restore_never_overwrites_a_web_root_onebox_does_not_own() {
    let host = Host::new();
    host.install(two_cores());
    let state = fs::read(host.paths().state()).unwrap();
    write_backup(
        &host,
        "1791000000-aaaaaaaa",
        1_791_000_000,
        &state,
        &[("public/index.html", b"backup site")],
    );
    file(
        &host.paths().site_root.join("index.html"),
        0o644,
        b"admin's site",
    );
    let before = host.world().without(&["etc/backups"]);
    let err = restore(&host, "1791000000-aaaaaaaa").unwrap_err();
    assert!(
        err.report_text()
            .ends_with("恢复 public 失败: 拒绝覆盖非托管网站目录"),
        "{err}"
    );
    assert_eq!(
        before.diff(&host.world().without(&["etc/backups"])),
        Vec::<String>::new()
    );
}

#[test]
fn without_backups_there_is_no_latest() {
    let host = Host::new();
    assert!(list(host.paths()).unwrap().is_empty());
    assert_eq!(
        restore(&host, "latest").unwrap_err().to_string(),
        "没有备份"
    );
    let v1 = host.paths().backups().join("20200101T000000Z-Ab12Cd");
    file(&v1.join("format"), 0o600, b"1\n");
    assert_eq!(
        restore(&host, "latest").unwrap_err().to_string(),
        "没有备份"
    );
}
