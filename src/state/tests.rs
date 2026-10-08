use super::v2::fixtures;
use super::*;
use crate::domain::fixtures::config;
use crate::domain::protocol::{Core, Protocol};
use crate::sys::rand::SeqRandom;
use std::os::unix::fs::symlink;
use std::path::PathBuf;

/// Isolated layout under a fresh temp directory, removed on drop.
struct Layout {
    dir: PathBuf,
    paths: Paths,
}

impl Layout {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "onebox-state-{}",
            crate::sys::rand::hex(8).unwrap()
        ));
        fs::create_dir_all(&dir).unwrap();
        let paths = Paths::isolated(&dir);
        Layout { dir, paths }
    }

    fn write(&self, path: &Path, bytes: &[u8]) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }

    fn load(&self) -> Result<Option<Loaded>> {
        StateStore::load_from(&self.paths, &mut SeqRandom(5))
    }
}

impl Drop for Layout {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn node() -> NodeConfig {
    use Core::Singbox as SB;
    use Protocol::*;
    config(&[
        (VlessReality, 443, SB),
        (Hysteria2, 443, SB),
        (Tuic, 8443, SB),
    ])
}

#[test]
fn not_installed() {
    let l = Layout::new();
    assert!(l.load().unwrap().is_none());
    assert!(!StateStore::installed_at(&l.paths));
    assert_eq!(
        StateStore::current_hash_at(&l.paths).unwrap(),
        StateHash::absent()
    );
    assert!(StateHash::absent().is_absent());
}

#[test]
fn v1_only_is_explained() {
    let l = Layout::new();
    l.write(&l.paths.legacy_v1_state(), b"PROTOCOLS=vless-reality\n");
    assert!(StateStore::installed_at(&l.paths));
    assert_eq!(l.load().unwrap_err().to_string(), V1_MESSAGE);
}

#[test]
fn v3_round_trip_and_cas_hash() {
    let l = Layout::new();
    let cfg = node();
    StateStore::save_to(&l.paths, &cfg).unwrap();
    let state = l.paths.state();
    assert_eq!(mode(&state), 0o600);
    assert_eq!(mode(&l.paths.root), 0o700);
    let text = fs::read_to_string(&state).unwrap();
    assert!(text.ends_with("}\n") && text.contains("\n  \"schema\": 3,"));
    let loaded = l.load().unwrap().unwrap();
    assert_eq!(loaded.config, cfg);
    assert_eq!(loaded.origin, Origin::V3);
    assert_eq!(loaded.hash, StateStore::current_hash_at(&l.paths).unwrap());
    assert_eq!(loaded.hash, StateHash::of(text.as_bytes()));
    assert!(!state.with_file_name("state.v2.json").exists());

    let mut changed = cfg.clone();
    changed.node_name = "东京".into();
    StateStore::save_to(&l.paths, &changed).unwrap();
    assert_ne!(StateStore::current_hash_at(&l.paths).unwrap(), loaded.hash);
    assert!(StateStore::installed_at(&l.paths));
}

#[test]
fn save_validates_first_and_tightens_root() {
    let l = Layout::new();
    fs::create_dir_all(&l.paths.root).unwrap();
    fs::set_permissions(&l.paths.root, fs::Permissions::from_mode(0o755)).unwrap();
    let mut bad = node();
    bad.inbounds.clear();
    let e = StateStore::save_to(&l.paths, &bad).unwrap_err();
    assert_eq!(e.to_string(), "配置缺少协议列表");
    assert!(!l.paths.state().exists());
    StateStore::save_to(&l.paths, &node()).unwrap();
    assert_eq!(mode(&l.paths.root), 0o700);
}

#[test]
fn v2_migrates_on_load_and_keeps_original_on_first_save() {
    let l = Layout::new();
    let original = fixtures::file(&fixtures::preset1());
    l.write(&l.paths.state(), &original);
    let settings = fixtures::settings("ip", "203.0.113.10", 8448, "none");
    let settings_path = l.paths.subscription().join("settings.json");
    l.write(&settings_path, settings.to_string().as_bytes());

    let loaded = l.load().unwrap().unwrap();
    assert_eq!(loaded.hash, StateHash::of(&original));
    assert_eq!(loaded.hash, StateStore::current_hash_at(&l.paths).unwrap());
    let Origin::V2 { devices, warnings } = &loaded.origin else {
        panic!("v2 origin expected");
    };
    assert_eq!(devices.as_ref().map(Vec::len), Some(2));
    assert!(warnings.is_empty());
    assert_eq!(loaded.config.creds.uuid, fixtures::UUID);
    assert!(loaded.config.subscription.is_some());

    StateStore::save_to(&l.paths, &loaded.config).unwrap();
    let backup = l.paths.state_v2_backup();
    assert_eq!(fs::read(&backup).unwrap(), original);
    assert_eq!(mode(&backup), 0o600);
    let reloaded = l.load().unwrap().unwrap();
    assert_eq!(reloaded.origin, Origin::V3);
    assert_eq!(reloaded.config, loaded.config);
    assert_ne!(reloaded.hash, loaded.hash, "the CAS hash follows the file");

    // Later saves replace a v3 file: the kept original is never touched.
    StateStore::save_to(&l.paths, &reloaded.config).unwrap();
    assert_eq!(fs::read(&backup).unwrap(), original);
    // Not even when another v2 file shows up again (e.g. a v2 restore).
    let other = fixtures::file(&fixtures::with(
        fixtures::preset1(),
        &[("NODE_NAME", "other")],
    ));
    l.write(&l.paths.state(), &other);
    StateStore::save_to(&l.paths, &reloaded.config).unwrap();
    assert_eq!(fs::read(&backup).unwrap(), original);
}

#[test]
fn any_save_over_a_v2_file_keeps_it() {
    // The backup does not depend on the caller passing the v2 origin along:
    // a save built from scratch (e.g. a reinstall) still keeps the v2 bytes.
    let l = Layout::new();
    let original = fixtures::file(&fixtures::preset1());
    l.write(&l.paths.state(), &original);
    StateStore::save_to(&l.paths, &node()).unwrap();
    assert_eq!(fs::read(l.paths.state_v2_backup()).unwrap(), original);
    assert_eq!(l.load().unwrap().unwrap().config, node());

    // A v3 or unreadable predecessor is not backed up.
    for previous in [serde_json::to_vec(&node()).unwrap(), b"{oops".to_vec()] {
        let l = Layout::new();
        l.write(&l.paths.state(), &previous);
        StateStore::save_to(&l.paths, &node()).unwrap();
        assert!(!l.paths.state_v2_backup().exists());
    }
    // A failed validation writes nothing, not even the backup.
    let l = Layout::new();
    l.write(&l.paths.state(), &original);
    let mut bad = node();
    bad.inbounds.clear();
    assert!(StateStore::save_to(&l.paths, &bad).is_err());
    assert!(!l.paths.state_v2_backup().exists());
    assert_eq!(fs::read(l.paths.state()).unwrap(), original);
}

#[test]
fn v2_without_settings_has_no_devices() {
    let l = Layout::new();
    l.write(&l.paths.state(), &fixtures::file(&fixtures::preset1()));
    let loaded = l.load().unwrap().unwrap();
    assert!(matches!(loaded.origin, Origin::V2 { devices: None, .. }));
    let broken = l.paths.subscription().join("settings.json");
    l.write(&broken, b"{not json");
    assert!(l
        .load()
        .unwrap_err()
        .to_string()
        .starts_with("v2 订阅设置 settings.json 无效"));
}

#[test]
fn format_detection_errors() {
    let l = Layout::new();
    let cases: [(&[u8], &str); 5] = [
        (
            br#"{"schema":4,"node_name":"x"}"#,
            "配置由更新版本的 Onebox 写入（schema 4），请先更新程序",
        ),
        (br#"{"node_name":"x"}"#, "state.json 格式无法识别"),
        (b"[1,2]", "state.json 格式无法识别"),
        (br#"{"schema":"3"}"#, "state.json 的 schema 无效"),
        (br#"{"schema":2}"#, "配置 schema 无效: 2"),
    ];
    for (bytes, want) in cases {
        l.write(&l.paths.state(), bytes);
        assert_eq!(l.load().unwrap_err().to_string(), want);
    }
    l.write(&l.paths.state(), b"{oops");
    assert!(l
        .load()
        .unwrap_err()
        .to_string()
        .starts_with("state.json 无效"));
    l.write(&l.paths.state(), br#"{"schema":3}"#);
    assert!(l
        .load()
        .unwrap_err()
        .to_string()
        .starts_with("state.json 无效"));

    let mut invalid = serde_json::to_value(node()).unwrap();
    invalid["creds"]["uuid"] = serde_json::json!("bad");
    l.write(&l.paths.state(), invalid.to_string().as_bytes());
    assert_eq!(
        l.load().unwrap_err().to_string(),
        "state.json 校验失败: UUID 格式无效"
    );
}

#[test]
fn unknown_fields_are_tolerated() {
    let l = Layout::new();
    let mut doc = serde_json::to_value(node()).unwrap();
    doc["future_field"] = serde_json::json!({"x": 1});
    l.write(&l.paths.state(), doc.to_string().as_bytes());
    assert_eq!(l.load().unwrap().unwrap().config, node());
}

#[test]
fn symlinks_and_oversized_files_are_refused() {
    let l = Layout::new();
    let real = l.dir.join("real.json");
    fs::write(&real, serde_json::to_vec(&node()).unwrap()).unwrap();
    fs::create_dir_all(&l.paths.root).unwrap();
    symlink(&real, l.paths.state()).unwrap();
    assert!(
        StateStore::installed_at(&l.paths),
        "installed, so install refuses to overwrite"
    );
    assert!(l.load().is_err());
    assert!(StateStore::current_hash_at(&l.paths).is_err());
    let before = fs::read(&real).unwrap();
    assert!(
        StateStore::save_to(&l.paths, &node()).is_err(),
        "a save never replaces or follows a symlinked state.json"
    );
    assert_eq!(fs::read(&real).unwrap(), before);
    assert!(fs::symlink_metadata(l.paths.state())
        .unwrap()
        .file_type()
        .is_symlink());
    fs::remove_file(l.paths.state()).unwrap();

    l.write(
        &l.paths.state(),
        &vec![b' '; (STATE_MAX_BYTES + 1) as usize],
    );
    assert!(l
        .load()
        .unwrap_err()
        .to_string()
        .contains("文件类型或大小无效"));

    let other = Layout::new();
    fs::create_dir_all(&other.dir).unwrap();
    symlink(&l.paths.root, &other.paths.root).unwrap();
    let e = StateStore::save_to(&other.paths, &node()).unwrap_err();
    assert!(e.to_string().starts_with("不允许符号链接"));
}
