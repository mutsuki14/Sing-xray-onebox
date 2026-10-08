use super::*;
use crate::apply::testing::{
    acme_deployment, acme_home, build_v2_layout, dir, file, v2_journal_text, v2_paths,
};
use crate::sys::fs::{sha256_hex, TempDir};
use std::os::unix::fs::symlink;

type SnapshotEdit = fn(&mut Snapshot);
type PathsEdit = fn(&mut Paths);

fn tmp() -> TempDir {
    TempDir::new("snapshot-test").unwrap()
}

fn mode_of(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
}

/// v2 `transaction::digest_tree`, ported verbatim (whole-file reads and a
/// buffered manifest) as the oracle for the streaming implementation.
fn v2_digest_tree(path: &Path) -> String {
    fn walk(path: &Path, relative: &Path, manifest: &mut Vec<u8>) {
        let meta = fs::symlink_metadata(path).unwrap();
        assert!(!meta.file_type().is_symlink() && (meta.is_file() || meta.is_dir()));
        let rel = relative.to_str().unwrap().as_bytes();
        manifest.extend_from_slice(&(rel.len() as u64).to_be_bytes());
        manifest.extend_from_slice(rel);
        manifest.extend_from_slice(&(meta.permissions().mode() & 0o777).to_be_bytes());
        if meta.is_file() {
            manifest.push(b'f');
            manifest.extend_from_slice(sha256_hex(&fs::read(path).unwrap()).as_bytes());
        } else {
            manifest.push(b'd');
            let mut entries = fs::read_dir(path)
                .unwrap()
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap();
            entries.sort_by_key(|e| e.file_name());
            for entry in entries {
                walk(&entry.path(), &relative.join(entry.file_name()), manifest);
            }
        }
    }
    let mut bytes = Vec::new();
    walk(path, Path::new(""), &mut bytes);
    sha256_hex(&bytes)
}

/// The snapshot recorded in the v2 fixture journal, for a layout at `root`.
/// The deployment file embeds the layout root, so its digest is recomputed
/// with the v2 oracle.
fn v2_snapshot(root: &Path) -> Snapshot {
    let journal: serde_json::Value = serde_json::from_str(&v2_journal_text(root)).unwrap();
    let mut snapshot: Snapshot = serde_json::from_value(journal["snapshot"].clone()).unwrap();
    let deployment = acme_deployment(root);
    let entry = snapshot
        .entries
        .iter_mut()
        .find(|e| e.target == deployment)
        .unwrap();
    entry.sha256 = v2_digest_tree(&deployment);
    snapshot
}

fn v2_allow(root: &Path, paths: &Paths) -> Allowlist {
    v2_node_allowlist_with(paths, &[acme_home(root)])
}

/// v2's snapshot targets for the fixture layout: the fixed list plus the
/// owned acme.sh deployment.
fn v2_targets(root: &Path, paths: &Paths) -> Vec<PathBuf> {
    let mut targets = v2_fixed_targets(paths);
    targets.push(acme_deployment(root));
    targets
}

#[test]
fn digest_matches_the_v2_algorithm() {
    let dir_ = tmp();
    let root = dir_.join("tree");
    dir(&root, 0o750);
    file(&root.join("b"), 0o644, b"bee");
    file(&root.join("A"), 0o600, b"");
    file(&root.join("节点.txt"), 0o400, "中文".as_bytes());
    dir(&root.join("sub/empty"), 0o700);
    file(&root.join("sub/x.sh"), 0o755, &[0u8, 255, 10, 13]);
    fs::set_permissions(root.join("sub"), fs::Permissions::from_mode(0o711)).unwrap();
    assert_eq!(digest_tree(&root).unwrap(), v2_digest_tree(&root));
    let single = root.join("b");
    assert_eq!(digest_tree(&single).unwrap(), v2_digest_tree(&single));
    // The mode is part of the digest.
    let before = digest_tree(&root).unwrap();
    fs::set_permissions(&single, fs::Permissions::from_mode(0o640)).unwrap();
    assert_ne!(digest_tree(&root).unwrap(), before);
    assert_eq!(digest_tree(&root).unwrap(), v2_digest_tree(&root));
}

#[test]
fn digest_of_a_known_tree_is_pinned() {
    // Pinned value: a regression guard for the byte layout itself.
    let dir_ = tmp();
    let root = dir_.join("t");
    dir(&root, 0o700);
    file(&root.join("f"), 0o600, b"x");
    let expected = {
        let mut m = Vec::new();
        m.extend_from_slice(&0u64.to_be_bytes());
        m.extend_from_slice(&0o700u32.to_be_bytes());
        m.push(b'd');
        m.extend_from_slice(&1u64.to_be_bytes());
        m.extend_from_slice(b"f");
        m.extend_from_slice(&0o600u32.to_be_bytes());
        m.push(b'f');
        m.extend_from_slice(sha256_hex(b"x").as_bytes());
        sha256_hex(&m)
    };
    assert_eq!(digest_tree(&root).unwrap(), expected);
}

#[test]
fn digest_refuses_links_special_files_and_huge_files() {
    let dir_ = tmp();
    let root = dir_.join("t");
    dir(&root, 0o700);
    symlink("/etc/passwd", root.join("link")).unwrap();
    let err = digest_tree(&root).unwrap_err().to_string();
    assert_eq!(err, "快照摘要拒绝符号链接或特殊文件");
    fs::remove_file(root.join("link")).unwrap();
    let huge = root.join("huge");
    fs::File::create(&huge)
        .unwrap()
        .set_len(MAX_FILE_BYTES + 1)
        .unwrap();
    assert_eq!(
        digest_tree(&root).unwrap_err().to_string(),
        "快照单文件超过2GiB"
    );
}

#[test]
fn v3_snapshot_of_the_v2_layout_equals_the_v2_journal() {
    let dir_ = tmp();
    let root = dir_.path();
    let paths = build_v2_layout(root);
    let dest = root.join("snap");
    let taken = take(&v2_targets(root, &paths), &dest).unwrap();
    let recorded = v2_snapshot(root);
    assert_eq!(taken, recorded, "slots, presence and digests match v2");
    assert_eq!(taken.entries.len(), 39);
    // Skipped while copying exactly as v2 did.
    assert!(!dest.join("item-6/acme/acme.sh").exists());
    assert!(!dest.join("item-6/acme/dnsapi").exists());
    assert!(!dest.join("item-6/acme/hook.sh").exists());
    assert!(dest.join("item-6/acme/account.conf").is_file());
    assert!(!dest.join("item-7/nginx.pid").exists());
    assert!(!dest.join("item-7/content-backups").exists());
    let json: Snapshot =
        serde_json::from_slice(&fs::read(dest.join(SNAPSHOT_FILE)).unwrap()).unwrap();
    assert_eq!(json, taken);
    assert_eq!(mode_of(&dest.join(SNAPSHOT_FILE)), 0o600);
    assert_eq!(mode_of(&dest), 0o700);
    // The v2 journal validates against the v2 allowlist.
    validate(&recorded, &dest, &v2_allow(root, &paths)).unwrap();
}

#[test]
fn v2_fixed_targets_are_the_38_v2_slots_in_order() {
    let root = Path::new("/r");
    let paths = v2_paths(root);
    let journal: serde_json::Value = serde_json::from_str(&v2_journal_text(root)).unwrap();
    let recorded: Vec<PathBuf> = journal["snapshot"]["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| PathBuf::from(e["target"].as_str().unwrap()))
        .collect();
    let fixed = v2_fixed_targets(&paths);
    assert_eq!(fixed.len(), 38);
    assert_eq!(fixed[..], recorded[..38]);
    assert_eq!(recorded[38], acme_deployment(root));
    // v3 adds its own paths after the v2 slots.
    let targets = node_targets(&paths);
    assert_eq!(targets[..38], fixed[..]);
    assert_eq!(targets[38..], [paths.state_v2_backup()]);
}

#[test]
fn round_trip_restores_owned_files_and_keeps_skipped_ones() {
    let dir_ = tmp();
    let root = dir_.path();
    let paths = build_v2_layout(root);
    let targets = node_targets(&paths);
    let dest = root.join("snap");
    let snapshot = take(&targets, &dest).unwrap();
    let etc = &paths.root;
    // A later generation changes, adds and removes files.
    fs::write(etc.join("tls/cert.pem"), b"NEW").unwrap();
    fs::write(etc.join("tls/acme/acme.sh"), b"new-code").unwrap();
    fs::write(etc.join("tls/acme/account.conf"), b"new-account").unwrap();
    fs::remove_file(etc.join("client/nested/deeper/z")).unwrap();
    file(&etc.join("client/stale"), 0o600, b"stale");
    file(&etc.join("sing-box.json"), 0o600, b"{}");
    file(&paths.executable, 0o755, b"\x7fELF new");
    fs::write(etc.join("backups/keep"), b"backup-new").unwrap();
    fs::set_permissions(etc.join("client"), fs::Permissions::from_mode(0o700)).unwrap();
    let allow = node_allowlist(&paths);
    restore(&snapshot, &dest, &allow).unwrap();
    restore(&snapshot, &dest, &allow).unwrap();
    assert_eq!(fs::read(etc.join("tls/cert.pem")).unwrap(), b"CERT");
    assert_eq!(
        fs::read(etc.join("tls/acme/account.conf")).unwrap(),
        b"ACCOUNT"
    );
    assert_eq!(fs::read(etc.join("tls/acme/acme.sh")).unwrap(), b"new-code");
    assert_eq!(fs::read(etc.join("client/nested/deeper/z")).unwrap(), b"zz");
    assert_eq!(mode_of(&etc.join("client/nested/deeper/z")), 0o400);
    assert_eq!(mode_of(&etc.join("client")), 0o750);
    assert_eq!(mode_of(&etc.join("client/nested")), 0o711);
    assert!(!etc.join("client/stale").exists());
    assert!(
        !etc.join("sing-box.json").exists(),
        "absent targets are deleted"
    );
    assert!(!paths.executable.exists());
    assert_eq!(fs::read(etc.join("backups/keep")).unwrap(), b"backup-new");
    assert_eq!(fs::read(etc.join("site/nginx.pid")).unwrap(), b"123");
    assert_eq!(
        fs::read(paths.state()).unwrap(),
        crate::apply::testing::V2_STATE
    );
    assert_eq!(
        digest_tree(&etc.join("client")).unwrap(),
        snapshot.entries[5].sha256
    );
}

#[test]
fn a_file_is_restored_over_a_file_in_place() {
    let dir_ = tmp();
    let root = dir_.path();
    let exe = root.join("bin/onebox");
    file(&exe, 0o755, b"old");
    let dest = root.join("snap");
    let snapshot = take(std::slice::from_ref(&exe), &dest).unwrap();
    file(&exe, 0o700, b"new-and-longer");
    let allow = Allowlist::exact(vec![exe.clone()]);
    restore(&snapshot, &dest, &allow).unwrap();
    assert_eq!(fs::read(&exe).unwrap(), b"old");
    assert_eq!(mode_of(&exe), 0o755);
    // A directory where a file was snapshotted is replaced by the file.
    fs::remove_file(&exe).unwrap();
    file(&exe.join("inner"), 0o600, b"x");
    restore(&snapshot, &dest, &allow).unwrap();
    assert_eq!(fs::read(&exe).unwrap(), b"old");
}

#[test]
fn tampered_slots_are_rejected_before_live_files_change() {
    let dir_ = tmp();
    let root = dir_.path();
    let paths = build_v2_layout(root);
    let dest = root.join("snap");
    let snapshot = take(&node_targets(&paths), &dest).unwrap();
    fs::write(paths.state(), b"live-generation").unwrap();
    let allow = node_allowlist(&paths);
    let tampers: [fn(&Path); 4] = [
        |d| fs::write(d.join("item-0"), b"tampered").unwrap(),
        |d| {
            let cert = d.join("item-6/cert.pem");
            fs::set_permissions(cert, fs::Permissions::from_mode(0o644)).unwrap()
        },
        |d| fs::write(d.join("item-5/extra"), b"x").unwrap(),
        |d| fs::remove_dir_all(d.join("item-15")).unwrap(),
    ];
    for tamper in tampers {
        let copy = root.join("copy");
        let _ = fs::remove_dir_all(&copy);
        copy_tree(&dest, &copy, &|_| false, &CopyLimits::UNLIMITED).unwrap();
        tamper(&copy);
        let err = restore(&snapshot, &copy, &allow).unwrap_err().to_string();
        assert!(err.starts_with("快照文件缺失或校验失败: item-"), "{err}");
        assert_eq!(fs::read(paths.state()).unwrap(), b"live-generation");
    }
    // A symlink planted in a slot is refused by the digest walk.
    symlink("/etc/passwd", dest.join("item-5/evil")).unwrap();
    let err = validate(&snapshot, &dest, &allow).unwrap_err().to_string();
    assert_eq!(err, "快照摘要拒绝符号链接或特殊文件");
}

#[test]
fn allowlist_mismatches_are_rejected() {
    let dir_ = tmp();
    let root = dir_.path();
    let paths = build_v2_layout(root);
    let dest = root.join("snap");
    let snapshot = take(&node_targets(&paths), &dest).unwrap();
    let allow = node_allowlist(&paths);
    let scope = "快照路径范围不合法";
    let cases: [(&str, SnapshotEdit); 8] = [
        ("foreign target", |s| {
            s.entries[1].target = PathBuf::from("/etc/passwd")
        }),
        ("escape", |s| {
            s.entries[1].target = s.entries[1].target.join("../../x")
        }),
        ("hidden ROOT child", |s| {
            s.entries[1].target = s.entries[0].target.with_file_name(".self-update.json")
        }),
        ("user backups", |s| {
            s.entries[1].target = s.entries[0].target.with_file_name("backups")
        }),
        ("duplicate target", |s| {
            s.entries[1].target = s.entries[0].target.clone()
        }),
        ("duplicate slot", |s| s.entries[1].slot = "item-0".into()),
        ("slot escape", |s| s.entries[1].slot = "../item-0".into()),
        ("slot is the description", |s| {
            s.entries[1].slot = SNAPSHOT_FILE.into()
        }),
    ];
    for (name, edit) in cases {
        let mut bad = snapshot.clone();
        edit(&mut bad);
        let err = validate(&bad, &dest, &allow).unwrap_err().to_string();
        assert_eq!(err, scope, "{name}");
    }
    // An exact allowlist refuses a partial snapshot.
    let exact = Allowlist::exact(node_targets(&paths));
    validate(&snapshot, &dest, &exact).unwrap();
    let mut partial = snapshot.clone();
    partial.entries.pop();
    assert_eq!(
        validate(&partial, &dest, &exact).unwrap_err().to_string(),
        "快照缺少托管路径，拒绝部分恢复"
    );
    // v3 journals may record fewer or more targets (allowlist drift).
    validate(&partial, &dest, &allow).unwrap();
    // The v2 allowlist refuses a v3 snapshot (state.v2.json is not a v2 slot).
    assert_eq!(
        validate(&snapshot, &dest, &v2_allow(root, &paths))
            .unwrap_err()
            .to_string(),
        scope
    );
}

#[test]
fn v2_journal_needs_every_fixed_target_and_accepts_acme_deployments_by_pattern() {
    let dir_ = tmp();
    let root = dir_.path();
    let paths = build_v2_layout(root);
    let dest = root.join("snap");
    take(&v2_targets(root, &paths), &dest).unwrap();
    let snapshot = v2_snapshot(root);
    let allow = v2_allow(root, &paths);
    // The deployment is retired and the legacy hook removed after the
    // snapshot: the allowlist does not depend on what exists now.
    fs::write(acme_deployment(root), b"retired").unwrap();
    fs::remove_file(root.join("initd/local.d/onebox-hop.start")).unwrap();
    fs::write(root.join("initd/local.d/admin.start"), b"admin-changed").unwrap();
    restore(&snapshot, &dest, &allow).unwrap();
    assert!(fs::read_to_string(acme_deployment(root))
        .unwrap()
        .starts_with("# onebox-rust-retired-deployment="));
    assert_eq!(
        fs::read(root.join("initd/local.d/onebox-hop.start")).unwrap(),
        b"#!/bin/sh"
    );
    assert_eq!(mode_of(&root.join("initd/local.d/onebox-hop.start")), 0o755);
    assert_eq!(
        fs::read(root.join("initd/local.d/admin.start")).unwrap(),
        b"admin-changed"
    );
    // Without that acme.sh home the deployment entry is out of scope.
    let other_home = v2_node_allowlist_with(&paths, &[root.join("elsewhere")]);
    assert_eq!(
        validate(&snapshot, &dest, &other_home)
            .unwrap_err()
            .to_string(),
        "快照路径范围不合法"
    );
    // Missing one fixed slot is a partial snapshot.
    let mut partial = snapshot.clone();
    partial.entries.retain(|e| e.slot != "item-12");
    assert_eq!(
        validate(&partial, &dest, &allow).unwrap_err().to_string(),
        "快照缺少托管路径，拒绝部分恢复"
    );
}

#[test]
fn acme_deployment_pattern() {
    let home = PathBuf::from("/root/.acme.sh");
    let rule = TargetRule::AcmeDeployment { home: home.clone() };
    let list = Allowlist::default().with_rule(rule);
    let cases = [
        ("/root/.acme.sh/example.com_ecc/example.com.conf", true),
        ("/root/.acme.sh/Example.COM_ecc/Example.COM.conf", true),
        ("/root/.acme.sh/1.2.3.4_ecc/1.2.3.4.conf", true),
        ("/root/.acme.sh/example.com_ecc/other.com.conf", false),
        ("/root/.acme.sh/example.com/example.com.conf", false),
        ("/root/.acme.sh/example.com_ecc/example.com.conf/x", false),
        ("/root/.acme.sh/example.com_ecc", false),
        ("/root/.acme.sh/localhost_ecc/localhost.conf", false),
        ("/root/.acme.sh/-bad.com_ecc/-bad.com.conf", false),
        ("/root/.acme.sh/../etc_ecc/etc.conf", false),
        ("/root/other/example.com_ecc/example.com.conf", false),
    ];
    for (path, ok) in cases {
        assert_eq!(
            list.owned_root(Path::new(path)),
            ok.then(|| home.clone()),
            "{path}"
        );
    }
}

#[test]
fn node_allowlist_patterns() {
    let paths = v2_paths(Path::new("/r"));
    let list = node_allowlist(&paths);
    let cases = [
        ("/r/etc/state.json", Some("/r/etc")),
        ("/r/etc/state.v2.json", Some("/r/etc")),
        ("/r/etc/onebox.conf.pre-rust", Some("/r/etc")),
        ("/r/etc/firewall-v1-migrated", Some("/r/etc")),
        ("/r/etc/.transaction", None),
        ("/r/etc/.apply.lock", None),
        ("/r/etc/backups", None),
        ("/r/etc/tls/cert.pem", None),
        ("/r/www", Some("/r")),
        ("/r/usr/onebox", Some("/r/usr")),
        ("/r/onebox-subscription-acme", Some("/r")),
        ("/r/bin/sing-box", Some("/r/bin")),
        ("/r/bin/.core-x", None),
        ("/r/systemd/onebox-xray.service", Some("/r/systemd")),
        ("/r/systemd/onebox-net.service", Some("/r/systemd")),
        ("/r/systemd/sshd.service", None),
        ("/r/systemd/onebox-.service", None),
        ("/r/systemd/onebox-x.y.service", None),
        ("/r/initd/init.d/onebox-xray", Some("/r/initd/init.d")),
        ("/r/initd/init.d/onebox-xray.service", None),
        (
            "/r/initd/local.d/onebox-net.start",
            Some("/r/initd/local.d"),
        ),
        ("/r/initd/local.d/admin.start", None),
        ("/etc/passwd", None),
        ("relative/state.json", None),
    ];
    for (path, root) in cases {
        assert_eq!(
            list.owned_root(Path::new(path)),
            root.map(PathBuf::from),
            "{path}"
        );
    }
}

#[test]
fn broad_or_overlapping_roots_are_refused() {
    let base = v2_paths(Path::new("/r"));
    check_node_roots(&base).unwrap();
    let apart = "网站目录和配置目录不能互相包含";
    let cases: [(PathsEdit, &str); 5] = [
        (|p| p.root = "/etc".into(), "事务目录范围过大: /etc"),
        (|p| p.site_root = "/var".into(), "事务目录范围过大: /var"),
        (|p| p.systemd = "/".into(), "事务目录范围过大: /"),
        (|p| p.site_root = p.root.join("www"), apart),
        (|p| p.root = p.site_root.join("etc"), apart),
    ];
    for (edit, expected) in cases {
        let mut paths = base.clone();
        edit(&mut paths);
        assert_eq!(check_node_roots(&paths).unwrap_err().to_string(), expected);
        let dir_ = tmp();
        fs::create_dir(dir_.join("src")).unwrap();
        let err = validate(
            &Snapshot::default(),
            &dir_.join("src"),
            &node_allowlist(&paths),
        )
        .unwrap_err();
        assert_eq!(err.to_string(), expected);
    }
}

#[test]
fn symlinks_in_owned_trees_are_refused() {
    let dir_ = tmp();
    let root = dir_.path();
    let paths = build_v2_layout(root);
    // Inside a target: taking the snapshot fails.
    symlink("/etc/passwd", paths.clients().join("bad")).unwrap();
    let err = take(&node_targets(&paths), &root.join("snap")).unwrap_err();
    assert!(err.to_string().contains("不允许符号链接"), "{err}");
    fs::remove_file(paths.clients().join("bad")).unwrap();
    // A target that is itself a symlink.
    let link_target = root.join("elsewhere");
    dir(&link_target, 0o700);
    fs::rename(paths.clients(), root.join("client-moved")).unwrap();
    symlink(&link_target, paths.clients()).unwrap();
    assert!(take(&node_targets(&paths), &root.join("snap2")).is_err());
    fs::remove_file(paths.clients()).unwrap();
    fs::rename(root.join("client-moved"), paths.clients()).unwrap();
    // At restore time, a symlinked live target or acme.sh directory.
    let dest = root.join("snap3");
    take(&v2_targets(root, &paths), &dest).unwrap();
    let snapshot = v2_snapshot(root);
    let ecc = acme_home(root).join("example.com_ecc");
    fs::rename(&ecc, root.join("ecc-moved")).unwrap();
    symlink(root.join("ecc-moved"), &ecc).unwrap();
    let err = restore(&snapshot, &dest, &v2_allow(root, &paths)).unwrap_err();
    assert!(err.to_string().contains("不允许符号链接"), "{err}");
    fs::remove_file(&ecc).unwrap();
    fs::rename(root.join("ecc-moved"), &ecc).unwrap();
    fs::remove_file(paths.state()).unwrap();
    symlink("/etc/passwd", paths.state()).unwrap();
    let err = restore(&snapshot, &dest, &v2_allow(root, &paths)).unwrap_err();
    assert!(err.to_string().contains("不允许符号链接"), "{err}");
    assert!(fs::symlink_metadata(paths.state())
        .unwrap()
        .file_type()
        .is_symlink());
    // A symlinked snapshot directory.
    let link = root.join("snap-link");
    symlink(&dest, &link).unwrap();
    let err = validate(&snapshot, &link, &v2_allow(root, &paths)).unwrap_err();
    assert!(err.to_string().starts_with("快照目录无效"), "{err}");
}

#[test]
fn size_limit_is_enforced_while_copying() {
    let dir_ = tmp();
    let root = dir_.path();
    let big = root.join("data/big");
    dir(&root.join("data"), 0o700);
    fs::File::create(&big)
        .unwrap()
        .set_len(MAX_BYTES + 1)
        .unwrap();
    let err = take(&[root.join("data")], &root.join("snap")).unwrap_err();
    assert!(err.to_string().ends_with(TOO_LARGE), "{err}");
    assert!(!root.join("snap/item-0/big").exists());
    // The budget covers all targets together.
    fs::write(&big, b"123456").unwrap();
    file(&root.join("data2/second"), 0o600, b"789012");
    let both = [root.join("data"), root.join("data2")];
    take_within(&both, &root.join("snap2"), 12).unwrap();
    let err = take_within(&both, &root.join("snap3"), 11).unwrap_err();
    assert!(err.to_string().ends_with(TOO_LARGE), "{err}");
}

#[test]
fn targets_must_be_clean_unique_and_narrow() {
    let dir_ = tmp();
    let dest = dir_.join("snap");
    let a = dir_.join("a");
    for targets in [
        vec![PathBuf::from("relative")],
        vec![a.join("../b")],
        vec![a.clone(), a.clone()],
    ] {
        let err = take(&targets, &dest).unwrap_err().to_string();
        assert!(err.starts_with("快照路径范围不合法"), "{err}");
    }
    assert_eq!(
        take(&[PathBuf::from("/etc")], &dest)
            .unwrap_err()
            .to_string(),
        "事务目录范围过大: /etc"
    );
}

#[test]
fn skip_rule_matches_v2() {
    let cases = [
        ("tls/backups", true),
        ("site/content-backups", true),
        ("x/.transaction", true),
        ("x/.apply.lock", true),
        ("site/nginx.pid", true),
        ("site/error.log", true),
        ("site/access.log", true),
        ("tls/acme/acme.sh", true),
        ("tls/acme/dnsapi", true),
        ("tls/acme/deploy", true),
        ("tls/acme/notify", true),
        ("tls/acme/.git", true),
        ("tls/acme/certs/x.sh", true),
        ("tls/acme/.download-1234", true),
        ("tls/acme", false),
        ("tls/acme/account.conf", false),
        ("tls/acme/onebox-dns.json", false),
        ("tls/hook.sh", false),
        ("client/.download-1", false),
        ("state.json", false),
    ];
    for (rel, expected) in cases {
        assert_eq!(skipped(Path::new(rel)), expected, "{rel}");
    }
}
