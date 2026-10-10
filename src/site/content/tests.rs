use super::*;
use crate::sys::exec::Exec;
use crate::sys::fs::TempDir;

struct Site {
    dir: TempDir,
    paths: Paths,
}

fn site() -> Site {
    let dir = TempDir::new("site-content").unwrap();
    let paths = Paths::isolated(dir.path());
    Site { dir, paths }
}

fn read(path: impl AsRef<Path>) -> String {
    fs::read_to_string(path).unwrap()
}

fn mode(path: impl AsRef<Path>) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// An upload directory with `index.html` = `text` (and extra files), by
/// its canonical path (what `check_import` hands the apply).
fn upload(s: &Site, name: &str, text: &str) -> PathBuf {
    let dir = s.dir.join(name);
    fs::create_dir_all(dir.join("assets")).unwrap();
    fs::write(dir.join("index.html"), text).unwrap();
    fs::write(dir.join("assets/app.css"), "body{}").unwrap();
    fs::canonicalize(dir).unwrap()
}

#[test]
fn prepare_creates_owned_directories_and_refuses_foreign_content() {
    let s = site();
    let store = ContentStore::new(&s.paths);
    store.prepare().unwrap();
    assert_eq!(mode(store.web_root()), 0o755);
    assert_eq!(
        mode(store.web_root().join(".well-known/acme-challenge")),
        0o755
    );
    assert_eq!(mode(s.paths.site()), 0o700);
    assert_eq!(read(store.web_root().join(OWNED_MARKER)), "onebox\n");
    assert_eq!(mode(s.paths.site().join(OWNED_MARKER)), 0o600);
    store.prepare().unwrap();

    let other = site();
    fs::create_dir_all(&other.paths.site_root).unwrap();
    fs::write(other.paths.site_root.join("index.html"), "mine").unwrap();
    let err = ContentStore::new(&other.paths).prepare().unwrap_err();
    assert_eq!(err.to_string(), "网站目录含未托管内容，请改用 site import");

    for root in ["/", "/var/lib", "/tmp"] {
        let mut paths = s.paths.clone();
        paths.site_root = root.into();
        let err = ContentStore::new(&paths).check_paths().unwrap_err();
        assert_eq!(
            err.to_string(),
            "网站目录必须独立于私密配置和系统目录",
            "{root}"
        );
    }
    let mut inside = s.paths.clone();
    inside.site_root = s.paths.root.join("www");
    assert!(ContentStore::new(&inside).check_paths().is_err());
}

#[test]
fn default_homepage_is_written_only_when_absent() {
    let s = site();
    let store = ContentStore::new(&s.paths);
    store.prepare().unwrap();
    assert!(!store.is_generated().unwrap());
    assert!(store.ensure_default("<p>v1</p>").unwrap());
    assert_eq!(mode(store.index()), 0o644);
    assert!(store.is_generated().unwrap());
    assert!(!store.ensure_default("<p>v1</p>").unwrap());
    // Other settings do not touch an existing page (a publish does).
    assert!(!store.ensure_default("<p>v2</p>").unwrap());
    assert_eq!(read(store.index()), "<p>v1</p>");
    assert!(store.is_generated().unwrap());
    fs::write(store.index(), "hand edited").unwrap();
    assert!(!store.is_generated().unwrap());
    assert!(!store.ensure_default("<p>v3</p>").unwrap());
    assert_eq!(read(store.index()), "hand edited");
    fs::remove_file(store.index()).unwrap();
    assert!(store.ensure_default("<p>v4</p>").unwrap());
    assert_eq!(read(store.index()), "<p>v4</p>");
}

#[test]
fn restored_template_pages_survive_later_applies() {
    let s = site();
    let store = ContentStore::new(&s.paths);
    store.prepare().unwrap();
    // `site template docs --title A`, then `site template profile --title B`
    // (backs up the docs/A page), then `site restore <that backup>`.
    store.publish_template("docs A").unwrap();
    let docs = store.publish_template("profile B").unwrap();
    store.restore(&docs).unwrap();
    assert_eq!(read(store.index()), "docs A");
    assert!(store.is_generated().unwrap());
    // The next unrelated apply still renders profile/B from the settings.
    assert!(!store.ensure_default("profile B").unwrap());
    assert_eq!(read(store.index()), "docs A");
    assert!(store.is_generated().unwrap());
}

#[test]
fn import_keeps_challenges_backs_up_and_forces_modes() {
    let s = site();
    let store = ContentStore::new(&s.paths);
    store.prepare().unwrap();
    store.ensure_default("old").unwrap();
    let token = store.web_root().join(".well-known/acme-challenge/token");
    fs::write(&token, "challenge").unwrap();
    let src = upload(&s, "upload", "new");
    fs::create_dir_all(src.join("docs/.well-known")).unwrap();
    fs::write(src.join("docs/.well-known/security.txt"), "contact").unwrap();
    fs::create_dir_all(src.join(".well-known")).unwrap();
    fs::write(src.join(".well-known/evil"), "x").unwrap();
    fs::write(src.join(".onebox-site-owned"), "fake").unwrap();
    fs::set_permissions(
        src.join("assets/app.css"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();

    let id = store.import(&src).unwrap();
    assert_eq!(read(store.index()), "new");
    assert_eq!(read(&token), "challenge");
    assert!(!store.web_root().join(".well-known/evil").exists());
    assert_eq!(
        read(store.web_root().join("docs/.well-known/security.txt")),
        "contact"
    );
    assert_eq!(read(store.web_root().join(OWNED_MARKER)), "onebox\n");
    assert_eq!(mode(store.web_root().join("assets/app.css")), 0o644);
    assert_eq!(mode(store.web_root().join("assets")), 0o755);
    assert!(
        !store.index_hash_file().exists(),
        "imports are not generated"
    );
    let backup = store.backups_dir().join(&id);
    assert_eq!(read(backup.join("index.html")), "old");
    assert!(!backup.join(".well-known").exists() && !backup.join(OWNED_MARKER).exists());
    assert_eq!(mode(&backup), 0o700);
    assert!(fs::read_dir(s.paths.site_root.parent().unwrap())
        .unwrap()
        .all(|e| !e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".onebox-site-")));
}

#[test]
fn unsafe_sources_leave_the_live_site_untouched() {
    let s = site();
    let store = ContentStore::new(&s.paths);
    store.prepare().unwrap();
    store.ensure_default("live").unwrap();
    let src = upload(&s, "bad", "new");
    std::os::unix::fs::symlink("/etc/passwd", src.join("assets/secret")).unwrap();
    let err = store.import(&src).unwrap_err().to_string();
    assert!(err.starts_with("网站内容不能包含符号链接"), "{err}");
    fs::remove_file(src.join("assets/secret")).unwrap();
    // A hard link may name a file only root can read (no symlink needed).
    fs::create_dir_all(s.paths.tls()).unwrap();
    fs::write(s.paths.tls().join("key.pem"), "private").unwrap();
    fs::hard_link(s.paths.tls().join("key.pem"), src.join("assets/key.pem")).unwrap();
    let err = store.import(&src).unwrap_err().to_string();
    let linked = src.join("assets/key.pem");
    assert_eq!(err, format!("网站内容不能包含硬链接: {}", linked.display()));
    fs::remove_file(&linked).unwrap();
    let fifo = src.join("pipe");
    let made = crate::sys::exec::SystemExec
        .run(&crate::sys::exec::Cmd::new("mkfifo").arg(fifo.to_string_lossy()))
        .is_ok_and(|o| o.ok());
    if made {
        let err = store.import(&src).unwrap_err().to_string();
        assert!(err.starts_with("网站内容包含特殊文件"), "{err}");
        fs::remove_file(&fifo).unwrap();
    }
    fs::remove_file(src.join("index.html")).unwrap();
    assert_eq!(
        store.import(&src).unwrap_err().to_string(),
        "网站需要 index.html"
    );
    assert_eq!(read(store.index()), "live");
    assert!(store.backups().unwrap().is_empty());

    for bad in [
        s.paths.site_root.clone(),
        s.paths.site_root.join(".well-known"),
        PathBuf::from("/etc"),
        PathBuf::from("/"),
    ] {
        let err = store.import(&bad).unwrap_err().to_string();
        assert_eq!(err, "不允许递归导入或导入系统目录", "{}", bad.display());
    }
    fs::create_dir_all(s.paths.tls()).unwrap();
    fs::write(s.paths.tls().join("index.html"), "keys").unwrap();
    let err = store.import(&s.paths.tls()).unwrap_err().to_string();
    assert_eq!(err, "不能从 Onebox 配置目录导入网站");
    let err = store
        .import(&s.dir.join("missing"))
        .unwrap_err()
        .to_string();
    assert!(err.starts_with("导入目录不存在或不是目录"), "{err}");
}

/// The import source's parent is writable by another user, who swaps it
/// for a symlink to a private tree (with its own `index.html`): after the
/// CLI checked the source, and while the apply copies it. Neither may
/// publish the private tree.
#[test]
fn imports_refuse_a_swapped_parent_directory() {
    let s = site();
    let store = ContentStore::new(&s.paths);
    store.prepare().unwrap();
    store.ensure_default("live").unwrap();
    let src = upload(&s, "alice/site", "public");
    let alice = src.parent().unwrap().to_path_buf();
    let secret = upload(&s, "secret/site", "private");
    assert_eq!(store.check_import(&src).unwrap(), src, "the CLI's check");
    fs::rename(&alice, alice.with_file_name("real")).unwrap();
    std::os::unix::fs::symlink(secret.parent().unwrap(), &alice).unwrap();

    let err = store.import(&src).unwrap_err().to_string();
    assert_eq!(err, format!("导入目录在检查后被替换: {}", src.display()));
    // Swapped after the apply's own checks (which went by path and saw the
    // private tree): the copy opens the canonical path without symlinks.
    let err = store.publish(&src, false, true).unwrap_err().to_string();
    assert_eq!(err, format!("不允许符号链接: {}", alice.display()));
    assert_eq!(read(store.index()), "live");
    assert!(store.backups().unwrap().is_empty());

    fs::remove_file(&alice).unwrap();
    fs::rename(alice.with_file_name("real"), &alice).unwrap();
    store.import(&src).unwrap();
    assert_eq!(read(store.index()), "public");
}

#[test]
fn templates_and_restores_keep_the_generated_marker() {
    let s = site();
    let store = ContentStore::new(&s.paths);
    store.prepare().unwrap();
    store.publish_template("A").unwrap();
    assert!(store.is_generated().unwrap());
    let b_backup = store.publish_template("B").unwrap();
    assert!(store
        .backups_dir()
        .join(&b_backup)
        .join(BACKUP_INDEX_MARKER)
        .exists());
    let import_backup = store.import(&upload(&s, "u", "imported")).unwrap();
    assert!(!store.is_generated().unwrap());
    // Restoring the template-made page makes it generated again.
    let imported = store.restore(&import_backup).unwrap();
    assert_eq!(read(store.index()), "B");
    assert!(store.is_generated().unwrap());
    // Restoring the imported page does not.
    store.restore(&imported).unwrap();
    assert_eq!(read(store.index()), "imported");
    assert!(!store.is_generated().unwrap());
    assert!(fs::read_dir(s.paths.site()).unwrap().all(|e| !e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".content-")));
}

#[test]
fn backups_are_listed_newest_first_and_pruned() {
    let s = site();
    let store = ContentStore::new(&s.paths);
    store.prepare().unwrap();
    store.ensure_default("x").unwrap();
    assert_eq!(
        store.restore("latest").unwrap_err().to_string(),
        "没有网站备份"
    );
    fs::create_dir_all(store.backups_dir()).unwrap();
    for (i, secs) in [100u64, 300, 200].iter().enumerate() {
        let dir = store.backups_dir().join(format!("{secs}-0000000{i}"));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("index.html"), format!("at {secs}")).unwrap();
    }
    fs::create_dir_all(store.backups_dir().join("not-a-backup")).unwrap();
    fs::write(store.backups_dir().join("123-00000000"), "file, not dir").unwrap();
    let ids: Vec<String> = store.backups().unwrap().into_iter().map(|b| b.id).collect();
    assert_eq!(ids, ["300-00000001", "200-00000002", "100-00000000"]);
    store.restore("latest").unwrap();
    assert_eq!(read(store.index()), "at 300");
    assert_eq!(
        store.restore("../x").unwrap_err().to_string(),
        "无效备份 ID"
    );
    assert_eq!(
        store.restore("999-00000000").unwrap_err().to_string(),
        "网站备份不存在: 999-00000000"
    );
    for i in 0..12 {
        store.publish_template(&format!("page {i}")).unwrap();
    }
    assert_eq!(store.backups().unwrap().len(), KEEP_BACKUPS);
    assert!(backup_time("1760000000-0a1b2c3d") == Some(1_760_000_000));
    assert_eq!(backup_time("1760000000-xyz"), None);
}

#[test]
fn preview_is_private() {
    let s = site();
    let store = ContentStore::new(&s.paths);
    let path = store.preview("<html>").unwrap();
    assert_eq!(path, s.paths.site().join("preview.html"));
    assert_eq!(read(&path), "<html>");
    assert_eq!(mode(&path), 0o600);
}
