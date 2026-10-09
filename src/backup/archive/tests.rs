use super::*;
use crate::apply::testing::{dir as mkdir, file};
use crate::sys::fs::TempDir;
use std::os::unix::fs::symlink;

fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn ids_and_labels_follow_v2() {
    for (id, ok) in [
        ("1791000000-1a2b3c4d", true),
        ("20261001T120000Z-Ab12Cd", true),
        ("a_b-c", true),
        ("", false),
        ("../../etc", false),
        (".new-1", false),
        ("x y", false),
        (&"a".repeat(99), true),
        (&"a".repeat(100), false),
    ] {
        assert_eq!(id_valid(id), ok, "{id}");
    }
    assert_eq!(clean_label("手动\n备份\u{1b}[31m"), "手动备份[31m");
    assert_eq!(clean_label(&"标".repeat(130)).chars().count(), LABEL_MAX);
}

#[test]
fn the_skip_rule_keeps_acme_code_logs_and_nested_backups_out() {
    for (path, skipped) in [
        ("tls/acme/acme.sh", true),
        ("tls/acme/dnsapi", true),
        ("tls/acme/hook.sh", true),
        ("tls/acme/account.conf", false),
        ("tls/acme/example.com_ecc/fullchain.cer", false),
        ("site/content-backups", true),
        ("site/nginx.pid", true),
        ("site/error.log", true),
        ("site/index.sha256", false),
        ("client/run.sh", false),
        ("backups", true),
        // The running worker's listener record is runtime state; an
        // administrator's file of that name elsewhere is content.
        ("subscription/listener.json", true),
        ("/etc/onebox/backups/1-a/subscription/listener.json", true),
        ("subscription/devices.json", false),
        ("public/listener.json", false),
        ("listener.json", false),
    ] {
        assert_eq!(ignored(Path::new(path)), skipped, "{path}");
    }
    let paths = Paths::isolated(Path::new("/x"));
    assert!(ignored(&crate::subscription::server::listener_file(&paths)));
}

#[test]
fn private_copies_force_modes_and_refuse_links() {
    let tmp = TempDir::new("backup-copy").unwrap();
    let src = tmp.join("src");
    mkdir(&src.join("nested"), 0o755);
    file(&src.join("nested/a.txt"), 0o644, b"a");
    file(&src.join("error.log"), 0o644, b"log");
    let mut budget = Budget::BACKUP;
    copy_private(&src, &tmp.join("dst"), &mut budget).unwrap();
    assert_eq!(mode(&tmp.join("dst")), 0o700);
    assert_eq!(mode(&tmp.join("dst/nested")), 0o700);
    assert_eq!(mode(&tmp.join("dst/nested/a.txt")), 0o600);
    assert!(!tmp.join("dst/error.log").exists());
    assert_eq!(budget.files, MAX_FILES - 1);
    assert_eq!(budget.bytes, MAX_BYTES - 1);
    // Symlinks and hard links are refused (v2 message).
    symlink("/etc/passwd", src.join("link")).unwrap();
    let mut fresh = Budget::BACKUP;
    let err = copy_private(&src, &tmp.join("dst2"), &mut fresh).unwrap_err();
    assert_eq!(err.to_string(), "备份拒绝链接或特殊文件");
    fs::remove_file(src.join("link")).unwrap();
    fs::hard_link(src.join("nested/a.txt"), src.join("hard")).unwrap();
    let err = copy_private(&src, &tmp.join("dst3"), &mut fresh).unwrap_err();
    assert_eq!(err.to_string(), "备份拒绝链接或特殊文件");
}

#[test]
fn the_budget_counts_files_and_bytes() {
    let mut budget = Budget {
        files: 2,
        bytes: 10,
    };
    budget.take(4).unwrap();
    budget.take(6).unwrap();
    for (files, bytes, size) in [(0, 10, 0), (1, 3, 4)] {
        let mut b = Budget { files, bytes };
        assert_eq!(
            b.take(size).unwrap_err().to_string(),
            "备份超过 4096 文件或 64 MiB 限制"
        );
    }
    let _ = budget;
}

#[test]
fn inventories_hash_every_file_but_the_manifests() {
    let tmp = TempDir::new("backup-inventory").unwrap();
    let root = tmp.path();
    file(&root.join("state.json"), 0o600, b"{}");
    file(&root.join("tls/cert.pem"), 0o600, b"CERT");
    file(&root.join(MANIFEST), 0o600, b"ignored");
    file(&root.join("tls/manifest.json"), 0o600, b"nested is listed");
    let files = inventory(root).unwrap();
    assert_eq!(
        files.keys().collect::<Vec<_>>(),
        ["state.json", "tls/cert.pem", "tls/manifest.json"]
    );
    assert_eq!(files["tls/cert.pem"], crate::sys::fs::sha256_hex(b"CERT"));
    fs::write(root.join("tls/cert.pem"), b"TAMPERED").unwrap();
    assert_ne!(inventory(root).unwrap(), files);
    symlink("/etc/passwd", root.join("bad")).unwrap();
    assert_eq!(
        inventory(root).unwrap_err().to_string(),
        "备份包含不安全的文件类型"
    );
}

#[test]
fn kinds_are_told_apart_without_failing() {
    let tmp = TempDir::new("backup-kind").unwrap();
    let current = tmp.join("current");
    let manifest = Manifest {
        schema: SCHEMA,
        label: "manual".into(),
        created: 7,
        files: BTreeMap::new(),
    };
    file(
        &current.join(MANIFEST),
        0o600,
        &serde_json::to_vec_pretty(&manifest).unwrap(),
    );
    assert_eq!(kind(&current), Kind::Current(manifest));
    let v1 = tmp.join("v1");
    file(&v1.join("format"), 0o600, b"1\n");
    assert_eq!(kind(&v1), Kind::V1);
    let broken = tmp.join("broken");
    file(&broken.join(MANIFEST), 0o600, b"{");
    assert_eq!(kind(&broken), Kind::Unknown);
    mkdir(&tmp.join("empty"), 0o700);
    assert_eq!(kind(&tmp.join("empty")), Kind::Unknown);
}

#[test]
fn the_manifest_keeps_v2_field_names_and_order() {
    let manifest = Manifest {
        schema: 2,
        label: "manual".into(),
        created: 1_791_000_000,
        files: BTreeMap::from([("state.json".to_owned(), "ab".to_owned())]),
    };
    assert_eq!(
        serde_json::to_string(&manifest).unwrap(),
        r#"{"schema":2,"label":"manual","created":1791000000,"files":{"state.json":"ab"}}"#
    );
}

#[test]
fn removing_assets_keeps_skipped_entries_and_refuses_links() {
    let tmp = TempDir::new("backup-remove").unwrap();
    let site = tmp.join("site");
    file(&site.join("index.html"), 0o644, b"x");
    file(&site.join("content-backups/1/index.html"), 0o600, b"old");
    file(&site.join("nested/a"), 0o600, b"a");
    remove_assets(&site).unwrap();
    assert!(site.join("content-backups/1/index.html").is_file());
    assert!(!site.join("index.html").exists() && !site.join("nested").exists());
    symlink("/etc", site.join("link")).unwrap();
    assert_eq!(
        remove_assets(&site).unwrap_err().to_string(),
        "恢复目标包含符号链接"
    );
}

#[test]
fn web_targets_must_be_owned_or_empty() {
    let tmp = TempDir::new("backup-web").unwrap();
    let web = tmp.join("www");
    mkdir(&web, 0o755);
    check_web_target(&web).unwrap();
    file(&web.join("index.html"), 0o644, b"admin's site");
    assert_eq!(
        check_web_target(&web).unwrap_err().to_string(),
        "拒绝覆盖非托管网站目录"
    );
    file(&web.join(OWNED_MARKER), 0o600, b"onebox\n");
    check_web_target(&web).unwrap();
}

#[test]
fn restored_web_roots_are_world_readable() {
    let tmp = TempDir::new("backup-public").unwrap();
    let web = tmp.join("www");
    file(&web.join("assets/style.css"), 0o600, b"body{}");
    public_permissions(&web).unwrap();
    assert_eq!(mode(&web), 0o755);
    assert_eq!(mode(&web.join("assets")), 0o755);
    assert_eq!(mode(&web.join("assets/style.css")), 0o644);
}
