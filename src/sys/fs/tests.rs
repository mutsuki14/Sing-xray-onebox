use super::tree::copy_file_limited;
use super::*;
use std::os::unix::fs::symlink;

fn mode_of(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
}

fn tmp() -> TempDir {
    TempDir::new("fs-test").unwrap()
}

#[test]
fn atomic_write_and_bounded_read() {
    let dir = tmp();
    let file = dir.join("a/b/state.json");
    atomic_write(&file, b"{}", 0o600).unwrap();
    atomic_write(&file, b"{\"x\":1}", 0o600).unwrap();
    assert_eq!(read_bounded(&file, 100).unwrap(), b"{\"x\":1}");
    assert!(read_bounded(&file, 3).is_err());
    assert_eq!(mode_of(&file), 0o600);
    assert_eq!(mode_of(&dir.join("a")), 0o700);
    let link = dir.join("link");
    symlink(&file, &link).unwrap();
    assert!(read_bounded(&link, 100).is_err());
    assert!(read_bounded(dir.path(), 100).is_err());
    // No temp files survive.
    let names: Vec<_> = fs::read_dir(dir.join("a/b")).unwrap().collect();
    assert_eq!(names.len(), 1);
}

#[test]
fn atomic_write_sets_exact_mode_despite_umask() {
    let dir = tmp();
    let file = dir.join("x");
    atomic_write(&file, b"1", 0o644).unwrap();
    assert_eq!(mode_of(&file), 0o644);
    atomic_write(&file, b"2", 0o600).unwrap();
    assert_eq!(mode_of(&file), 0o600);
}

#[test]
fn atomic_write_replaces_a_symlink_instead_of_following_it() {
    let dir = tmp();
    let victim = dir.join("victim");
    fs::write(&victim, b"keep").unwrap();
    let link = dir.join("link");
    symlink(&victim, &link).unwrap();
    atomic_write(&link, b"new", 0o600).unwrap();
    assert_eq!(fs::read(&victim).unwrap(), b"keep");
    assert!(!is_symlink(&link));
    assert_eq!(fs::read(&link).unwrap(), b"new");
}

#[test]
fn atomic_write_failure_keeps_old_content() {
    let dir = tmp();
    let target = dir.join("dir-target");
    fs::create_dir(&target).unwrap();
    fs::write(target.join("inner"), b"x").unwrap();
    // rename(file, non-empty dir) fails; the directory must be untouched.
    assert!(atomic_write(&target, b"data", 0o600).is_err());
    assert!(target.join("inner").exists());
    let leftovers = fs::read_dir(dir.path())
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(TEMP_PREFIX)
        })
        .count();
    assert_eq!(leftovers, 0);
}

#[test]
fn exclusive_write() {
    let dir = tmp();
    let file = dir.join("out.yaml");
    write_new_exclusive(&file, b"a", 0o640).unwrap();
    assert_eq!(mode_of(&file), 0o640);
    let err = write_new_exclusive(&file, b"b", 0o600).unwrap_err();
    assert_eq!(err.to_string(), format!("目标已存在: {}", file.display()));
    assert_eq!(fs::read(&file).unwrap(), b"a");
    let link = dir.join("dangling");
    symlink(dir.join("nowhere"), &link).unwrap();
    assert!(write_new_exclusive(&link, b"x", 0o600).is_err());
    assert!(!dir.join("nowhere").exists());
}

#[test]
fn ensure_dir_modes_and_refusals() {
    let dir = tmp();
    let deep = dir.join("p/q/r");
    ensure_dir(&deep, 0o750).unwrap();
    assert_eq!(mode_of(&deep), 0o750);
    assert_eq!(mode_of(&dir.join("p")), 0o700);
    ensure_dir(&deep, 0o711).unwrap();
    assert_eq!(mode_of(&deep), 0o711);
    let link = dir.join("link");
    symlink(&deep, &link).unwrap();
    assert!(ensure_dir(&link, 0o700)
        .unwrap_err()
        .to_string()
        .contains("不允许符号链接"));
    let file = dir.join("file");
    fs::write(&file, b"").unwrap();
    assert!(ensure_dir(&file, 0o700)
        .unwrap_err()
        .to_string()
        .contains("不是目录"));
}

#[test]
fn following_reads_resolve_links_but_keep_type_and_size_rules() {
    let dir = tmp();
    // certbot layout: live/NAME/fullchain.pem -> ../../archive/NAME/fullchain1.pem
    let archive = dir.join("archive/a.example.com");
    let live = dir.join("live/a.example.com");
    fs::create_dir_all(&archive).unwrap();
    fs::create_dir_all(&live).unwrap();
    fs::write(archive.join("fullchain1.pem"), b"PEM").unwrap();
    symlink(
        "../../archive/a.example.com/fullchain1.pem",
        live.join("fullchain.pem"),
    )
    .unwrap();
    symlink(dir.path(), dir.join("to-dir")).unwrap();
    symlink(dir.join("nowhere"), dir.join("dangling")).unwrap();
    symlink(dir.join("loop"), dir.join("loop")).unwrap();
    let fifo = std::ffi::CString::new(dir.join("fifo").as_os_str().as_bytes()).unwrap();
    // SAFETY: valid NUL-terminated path; mkfifo has no other preconditions.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    let linked = live.join("fullchain.pem");
    assert!(
        read_bounded(&linked, 100).is_err(),
        "owned reads never follow"
    );
    let cases: [(&Path, u64, Option<&[u8]>); 7] = [
        (&linked, 100, Some(b"PEM")),
        (&archive.join("fullchain1.pem"), 100, Some(b"PEM")),
        (&linked, 2, None),
        (&dir.join("to-dir"), 100, None),
        (&dir.join("dangling"), 100, None),
        (&dir.join("loop"), 100, None),
        (&dir.join("fifo"), 100, None),
    ];
    for (path, max, want) in cases {
        let got = read_bounded_following(path, max);
        assert_eq!(got.as_deref().ok(), want, "{}", path.display());
    }
    let err = read_bounded_following(&dir.join("loop"), 100).unwrap_err();
    assert!(
        !err.to_string().contains("不允许符号链接"),
        "a loop is an I/O error here: {err}"
    );
}

#[test]
fn string_reads() {
    let dir = tmp();
    let file = dir.join("t");
    fs::write(&file, "节点").unwrap();
    assert_eq!(read_to_string_bounded(&file, 10).unwrap(), "节点");
    fs::write(&file, [0xff, 0xfe]).unwrap();
    assert!(read_to_string_bounded(&file, 10)
        .unwrap_err()
        .to_string()
        .contains("UTF-8"));
}

#[test]
fn removals() {
    let dir = tmp();
    let file = dir.join("f");
    fs::write(&file, b"").unwrap();
    assert!(remove_file_if_exists(&file).unwrap());
    assert!(!remove_file_if_exists(&file).unwrap());
    assert!(remove_file_if_exists(dir.path()).is_err());

    let tree = dir.join("tree");
    fs::create_dir_all(tree.join("a/b")).unwrap();
    fs::write(tree.join("a/b/c"), b"").unwrap();
    let outside = dir.join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("keep"), b"").unwrap();
    symlink(&outside, tree.join("a/link")).unwrap();
    assert!(remove_tree_if_exists(&tree).unwrap());
    assert!(!tree.exists());
    assert!(
        outside.join("keep").exists(),
        "links inside are not followed"
    );
    assert!(!remove_tree_if_exists(&tree).unwrap());

    let root_link = dir.join("root-link");
    symlink(&outside, &root_link).unwrap();
    assert!(remove_tree_if_exists(&root_link).is_err());
    assert!(outside.join("keep").exists());
}

#[test]
fn file_copy() {
    let dir = tmp();
    let src = dir.join("src");
    fs::write(&src, b"payload").unwrap();
    let dst = dir.join("new/dst");
    assert_eq!(copy_file(&src, &dst, 0o640).unwrap(), 7);
    assert_eq!(fs::read(&dst).unwrap(), b"payload");
    assert_eq!(mode_of(&dst), 0o640);
    let link = dir.join("link");
    symlink(&src, &link).unwrap();
    assert!(copy_file(&link, &dir.join("x"), 0o600).is_err());
}

#[test]
fn tree_copy_preserves_modes_and_skips() {
    let dir = tmp();
    let src = dir.join("src");
    fs::create_dir_all(src.join("sub/deeper")).unwrap();
    fs::write(src.join("a"), b"12345").unwrap();
    fs::set_permissions(src.join("a"), fs::Permissions::from_mode(0o640)).unwrap();
    fs::write(src.join("sub/b"), b"xy").unwrap();
    fs::set_permissions(src.join("sub/b"), fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(src.join("sub/skip.me"), b"no").unwrap();
    fs::set_permissions(src.join("sub"), fs::Permissions::from_mode(0o750)).unwrap();
    let dst = dir.join("dst");
    let skip = |p: &Path| p.extension().is_some_and(|e| e == "me");
    let stats = copy_tree(&src, &dst, &skip, &CopyLimits::UNLIMITED).unwrap();
    assert_eq!(
        stats,
        CopyStats {
            bytes: 7,
            entries: 4
        },
        "a, sub, sub/b, sub/deeper"
    );
    assert_eq!(fs::read(dst.join("a")).unwrap(), b"12345");
    assert_eq!(mode_of(&dst.join("a")), 0o640);
    assert_eq!(mode_of(&dst.join("sub/b")), 0o755);
    assert_eq!(mode_of(&dst.join("sub")), 0o750);
    assert!(dst.join("sub/deeper").is_dir());
    assert!(!dst.join("sub/skip.me").exists());
}

#[test]
fn tree_copy_applies_read_only_directory_modes_last() {
    let dir = tmp();
    let src = dir.join("src");
    fs::create_dir_all(src.join("ro")).unwrap();
    fs::write(src.join("ro/file"), b"x").unwrap();
    fs::set_permissions(src.join("ro"), fs::Permissions::from_mode(0o555)).unwrap();
    let dst = dir.join("dst");
    copy_tree(&src, &dst, &|_| false, &CopyLimits::UNLIMITED).unwrap();
    assert_eq!(fs::read(dst.join("ro/file")).unwrap(), b"x");
    assert_eq!(mode_of(&dst.join("ro")), 0o555);
    // Let TempDir clean up even when not running as root.
    for d in [src.join("ro"), dst.join("ro")] {
        fs::set_permissions(d, fs::Permissions::from_mode(0o755)).unwrap();
    }
}

#[test]
fn tree_copy_refuses_symlinks_and_special_files() {
    let dir = tmp();
    let src = dir.join("src");
    fs::create_dir(&src).unwrap();
    symlink("/etc/passwd", src.join("evil")).unwrap();
    let unlimited = &CopyLimits::UNLIMITED;
    let err = copy_tree(&src, &dir.join("dst"), &|_| false, unlimited).unwrap_err();
    assert!(err.to_string().contains("不允许符号链接"), "{err}");
    // Whitelisting by skip works.
    copy_tree(&src, &dir.join("dst2"), &|p| p.ends_with("evil"), unlimited).unwrap();

    let fifo_dir = dir.join("fifo");
    fs::create_dir(&fifo_dir).unwrap();
    let fifo = fifo_dir.join("pipe");
    let c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: valid NUL-terminated path; mkfifo has no other preconditions.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    let err = copy_tree(&fifo_dir, &dir.join("dst3"), &|_| false, unlimited).unwrap_err();
    assert!(err.to_string().contains("特殊文件"), "{err}");
}

/// An import source writable by another user: entries are swapped for
/// symlinks to a private directory while the tree is copied (`skip` runs
/// just before each child is opened). A swapped directory must not
/// redirect its remaining children; a swapped entry itself is refused.
#[test]
fn tree_copy_is_not_redirected_by_swaps_during_the_copy() {
    let dir = tmp();
    let secret = dir.join("secret");
    fs::create_dir(&secret).unwrap();
    for name in ["a1", "f"] {
        fs::write(secret.join(name), b"secret").unwrap();
    }
    // (entry whose skip call swaps, path replaced by a symlink, link target)
    let cases = [
        ("b/a1", "b", secret.clone(), Ok("public")),
        ("f", "f", secret.join("f"), Err("不允许符号链接")),
    ];
    for (i, (trigger, replaced, target, expected)) in cases.into_iter().enumerate() {
        let src = dir.join(format!("src{i}"));
        fs::create_dir_all(src.join("b")).unwrap();
        fs::write(src.join("b/a0"), b"a0").unwrap();
        fs::write(src.join("b/a1"), b"public").unwrap();
        fs::write(src.join("f"), b"public").unwrap();
        let swapped = std::cell::Cell::new(false);
        let swap = |p: &Path| {
            if p == src.join(trigger) && !swapped.replace(true) {
                fs::rename(src.join(replaced), dir.join(format!("moved{i}"))).unwrap();
                symlink(&target, src.join(replaced)).unwrap();
            }
            false
        };
        let dst = dir.join(format!("dst{i}"));
        let result = copy_tree(&src, &dst, &swap, &CopyLimits::UNLIMITED);
        assert!(swapped.get(), "{trigger}");
        match expected {
            Ok(content) => {
                result.unwrap();
                assert_eq!(fs::read(dst.join("b/a0")).unwrap(), b"a0");
                assert_eq!(fs::read(dst.join(trigger)).unwrap(), content.as_bytes());
            }
            Err(text) => {
                let err = result.unwrap_err().to_string();
                assert!(err.contains(text), "{trigger}: {err}");
                assert!(!dst.join(trigger).exists());
            }
        }
    }
}

/// A source whose ancestor another user owns: `open_dir_nofollow` refuses
/// a symlink anywhere in the path (where `O_NOFOLLOW` alone covers only
/// the last component), and `copy_tree_at` keeps reading the directory it
/// pinned after that ancestor is swapped for a symlink to a private tree.
#[test]
fn pinned_copies_ignore_swapped_ancestors() {
    let dir = tmp();
    let base = fs::canonicalize(dir.path()).unwrap();
    fs::create_dir_all(base.join("secret/site")).unwrap();
    fs::write(base.join("secret/site/key.pem"), b"private").unwrap();
    fs::create_dir_all(base.join("home/www/site")).unwrap();
    fs::write(base.join("home/www/site/index.html"), b"public").unwrap();
    fs::write(base.join("home/file"), b"").unwrap();
    symlink(base.join("secret"), base.join("home/alias")).unwrap();
    symlink(base.join("secret/site"), base.join("home/last")).unwrap();
    let cases: [(PathBuf, &str); 5] = [
        (base.join("home/alias/site"), "不允许符号链接: "),
        (base.join("home/last"), "不允许符号链接: "),
        (base.join("home/file/site"), "不是目录: "),
        (base.join("home/www/../www/site"), "需要规范路径: "),
        (PathBuf::from("home/www/site"), "需要绝对路径: "),
    ];
    for (path, want) in cases {
        let err = open_dir_nofollow(&path).unwrap_err().to_string();
        assert!(err.starts_with(want), "{}: {err}", path.display());
    }
    let err = open_dir_nofollow(&base.join("home/alias/site")).unwrap_err();
    assert_eq!(
        err.to_string(),
        format!("不允许符号链接: {}", base.join("home/alias").display())
    );

    let src = base.join("home/www/site");
    let pinned = open_dir_nofollow(&src).unwrap();
    fs::rename(base.join("home/www"), base.join("home/www.old")).unwrap();
    symlink(base.join("secret"), base.join("home/www")).unwrap();
    // By path, the source now names the private tree.
    assert!(src.join("key.pem").exists());
    let none = |_: &Path| false;
    let dst = base.join("dst");
    let stats = copy_tree_at(&pinned, &src, &dst, &none, &CopyLimits::UNLIMITED).unwrap();
    assert_eq!(stats.entries, 1);
    assert_eq!(fs::read(dst.join("index.html")).unwrap(), b"public");
    assert!(!dst.join("key.pem").exists());
    // `skip` and messages still see paths below `src`.
    let skip = |p: &Path| p == src.join("index.html");
    let skipped = copy_tree_at(
        &pinned,
        &src,
        &base.join("dst2"),
        &skip,
        &CopyLimits::UNLIMITED,
    );
    assert_eq!(skipped.unwrap().entries, 0);
}

#[test]
fn tree_copy_refuses_hard_links_when_asked() {
    let dir = tmp();
    let src = dir.join("src");
    fs::create_dir(&src).unwrap();
    fs::write(dir.join("private"), b"key").unwrap();
    fs::hard_link(dir.join("private"), src.join("linked")).unwrap();
    let none = |_: &Path| false;
    let strict = CopyLimits::UNLIMITED.refuse_hard_links();
    let err = copy_tree(&src, &dir.join("dst"), &none, &strict).unwrap_err();
    let linked = src.join("linked");
    assert_eq!(
        err.to_string(),
        format!("不允许硬链接: {}", linked.display())
    );
    assert!(!dir.join("dst/linked").exists());
    // Snapshots and backups of Onebox's own trees still copy them.
    copy_tree(&src, &dir.join("dst2"), &none, &CopyLimits::UNLIMITED).unwrap();
    assert_eq!(fs::read(dir.join("dst2/linked")).unwrap(), b"key");
}

#[test]
fn tree_copy_lists_every_name() {
    let dir = tmp();
    let src = dir.join("src");
    fs::create_dir(&src).unwrap();
    let odd = std::ffi::OsStr::from_bytes(b"caf\xe9");
    fs::write(src.join(odd), b"x").unwrap();
    for n in 0..300 {
        fs::write(src.join(format!("n{n}")), b"").unwrap();
    }
    let file = dir.join("single");
    fs::write(&file, b"root file").unwrap();
    let stats = copy_tree(&src, &dir.join("dst"), &|_| false, &CopyLimits::UNLIMITED).unwrap();
    assert_eq!(stats.entries, 301);
    assert_eq!(fs::read(dir.join("dst").join(odd)).unwrap(), b"x");
    assert!(dir.join("dst/n299").is_file());
    // A plain file as the root is copied too (snapshots of single files).
    let copied = copy_tree(&file, &dir.join("one"), &|_| false, &CopyLimits::UNLIMITED).unwrap();
    assert_eq!(copied.bytes, 9);
    assert_eq!(fs::read(dir.join("one")).unwrap(), b"root file");
}

/// src/{a (5 bytes), b (2 bytes), d/, d/c (3 bytes)}
fn sample_tree(dir: &TempDir) -> PathBuf {
    let src = dir.join("src");
    fs::create_dir_all(src.join("d")).unwrap();
    fs::write(src.join("a"), b"12345").unwrap();
    fs::write(src.join("b"), b"xy").unwrap();
    fs::write(src.join("d/c"), b"abc").unwrap();
    src
}

#[test]
fn tree_copy_enforces_limits_before_writing() {
    let dir = tmp();
    let src = sample_tree(&dir);
    let none = |_: &Path| false;
    let exact = copy_tree(&src, &dir.join("ok"), &none, &CopyLimits::new(10, 4)).unwrap();
    assert_eq!(
        exact,
        CopyStats {
            bytes: 10,
            entries: 4
        }
    );

    // Bytes: a (5) + b (2) fit in 6? No: b would make 7.
    let err = copy_tree(&src, &dir.join("bytes"), &none, &CopyLimits::new(6, 100)).unwrap_err();
    assert_eq!(
        err.to_string(),
        format!("复制内容超过上限: {}", src.join("b").display())
    );
    assert!(dir.join("bytes/a").exists());
    assert!(!dir.join("bytes/b").exists(), "rejected before writing");

    // Entries count directories too: a, b, d fit in 3; d/c does not.
    let err = copy_tree(&src, &dir.join("entries"), &none, &CopyLimits::new(100, 3)).unwrap_err();
    assert_eq!(
        err.to_string(),
        format!("复制内容超过上限: {}", src.join("d/c").display())
    );

    let limits = CopyLimits::new(1, 100).message("备份超过 4096 文件或 64 MiB 限制");
    let err = copy_tree(&src, &dir.join("custom"), &none, &limits).unwrap_err();
    assert_eq!(err.to_string(), "备份超过 4096 文件或 64 MiB 限制");
}

#[test]
fn file_copy_stops_at_the_limit_while_streaming() {
    // The size check before the copy can be outrun by a growing file; the
    // streaming guard must still stop and leave no destination behind.
    let dir = tmp();
    let src = dir.join("big");
    fs::write(&src, vec![1u8; 4096]).unwrap();
    let dst = dir.join("out/big");
    let open = || File::open(&src).unwrap();
    assert_eq!(copy_file_limited(open(), &dst, 0o600, 4095).unwrap(), None);
    assert!(!dst.exists());
    let leftovers = fs::read_dir(dir.join("out")).unwrap().count();
    assert_eq!(leftovers, 0, "temp file removed");
    assert_eq!(
        copy_file_limited(open(), &dst, 0o600, 4096).unwrap(),
        Some(4096)
    );
}

#[test]
fn tree_copy_refuses_a_destination_inside_the_source() {
    let dir = tmp();
    let src = sample_tree(&dir);
    let none = |_: &Path| false;
    let unlimited = &CopyLimits::UNLIMITED;
    for dst in [src.join("d/copy"), src.clone(), src.join("x/../d/y")] {
        let err = copy_tree(&src, &dst, &none, unlimited).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("复制目标不能位于源目录内: {}", dst.display())
        );
    }
    // Also through a symlinked alias of the source.
    let alias = dir.join("alias");
    symlink(&src, &alias).unwrap();
    assert!(copy_tree(&src, &alias.join("copy"), &none, unlimited).is_err());
    assert!(!src.join("d/copy").exists());

    // Allowed when the destination lies in a skipped subtree.
    fs::create_dir(src.join(".transaction")).unwrap();
    let staged = src.join(".transaction/snapshot");
    let skip = |p: &Path| p.ends_with(".transaction");
    let stats = copy_tree(&src, &staged, &skip, unlimited).unwrap();
    assert_eq!(stats.entries, 4);
    assert!(staged.join("d/c").exists());
    assert!(!staged.join(".transaction").exists());
    // A sibling with a common name prefix is not "inside".
    copy_tree(&src, &dir.join("src-copy"), &none, unlimited).unwrap();
}

#[test]
fn skip_aware_tree_removal() {
    let dir = tmp();
    let root = dir.join("root");
    fs::create_dir_all(root.join("acme/keep-me")).unwrap();
    fs::create_dir_all(root.join("tls/sub")).unwrap();
    fs::write(root.join("state.json"), b"{}").unwrap();
    fs::write(root.join("acme/account.json"), b"{}").unwrap();
    fs::write(root.join("acme/keep-me/acme.sh"), b"#!").unwrap();
    fs::write(root.join("tls/sub/cert.pem"), b"pem").unwrap();
    let skip = |p: &Path| p.ends_with("keep-me");
    remove_tree_contents(&root, &skip).unwrap();
    assert!(root.join("acme/keep-me/acme.sh").exists());
    assert!(!root.join("acme/account.json").exists());
    assert!(!root.join("state.json").exists());
    assert!(
        !root.join("tls").exists(),
        "emptied directories are removed"
    );
    assert!(root.is_dir(), "kept because it still holds skipped entries");

    remove_tree_contents(&root, &|_| false).unwrap();
    assert!(!root.exists());
    remove_tree_contents(&root, &|_| false).unwrap();

    let file = dir.join("single");
    fs::write(&file, b"x").unwrap();
    remove_tree_contents(&file, &|_| false).unwrap();
    assert!(!file.exists());
}

#[test]
fn tree_removal_refuses_links_before_deleting_anything() {
    let dir = tmp();
    let root = dir.join("root");
    fs::create_dir_all(root.join("a")).unwrap();
    fs::write(root.join("a/file"), b"x").unwrap();
    let outside = dir.join("outside");
    fs::write(&outside, b"keep").unwrap();
    symlink(&outside, root.join("z-link")).unwrap();
    let err = remove_tree_contents(&root, &|_| false).unwrap_err();
    assert!(err.to_string().contains("不允许符号链接"), "{err}");
    assert!(root.join("a/file").exists(), "nothing removed");
    assert!(outside.exists());
    // A skipped link is left alone.
    remove_tree_contents(&root, &|p| p.ends_with("z-link")).unwrap();
    assert!(!root.join("a").exists());
    assert!(is_symlink(&root.join("z-link")));
    let root_link = dir.join("root-link");
    symlink(&root, &root_link).unwrap();
    assert!(remove_tree_contents(&root_link, &|_| false).is_err());
}

#[test]
fn stale_sweep() {
    let dir = tmp();
    fs::write(dir.join(format!("{TEMP_PREFIX}a")), b"").unwrap();
    fs::create_dir(dir.join(format!("{TEMP_PREFIX}dir"))).unwrap();
    fs::write(dir.join("keep"), b"").unwrap();
    assert_eq!(
        sweep_stale(dir.path(), TEMP_PREFIX, Duration::from_secs(3600)).unwrap(),
        0,
        "fresh entries are kept"
    );
    assert_eq!(
        sweep_stale(dir.path(), TEMP_PREFIX, Duration::ZERO).unwrap(),
        2
    );
    assert!(dir.join("keep").exists());
    assert_eq!(
        sweep_stale(&dir.join("missing"), TEMP_PREFIX, Duration::ZERO).unwrap(),
        0
    );
    let err = sweep_stale(dir.path(), "", Duration::ZERO).unwrap_err();
    assert_eq!(err.to_string(), "清理前缀不能为空");
    assert!(dir.join("keep").exists());
}

#[test]
fn hashing() {
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    let dir = tmp();
    let file = dir.join("big");
    let data = vec![7u8; 200_000];
    fs::write(&file, &data).unwrap();
    assert_eq!(sha256_file(&file).unwrap(), sha256_hex(&data));
    let link = dir.join("link");
    symlink(&file, &link).unwrap();
    assert!(sha256_file(&link).is_err());
}

#[test]
fn owned_path_rule() {
    let dir = tmp();
    // The owned root's ancestors may be symlinks (e.g. /var/run → /run).
    let real = dir.join("real");
    fs::create_dir(&real).unwrap();
    let alias = dir.join("alias");
    symlink(&real, &alias).unwrap();
    let root = alias.join("onebox");
    fs::create_dir(&root).unwrap();
    check_owned(&root, &root).unwrap();
    check_owned(&root, &root.join("state.json")).unwrap();
    check_owned(&root, &root.join("not/yet/created")).unwrap();

    fs::create_dir(root.join("tls")).unwrap();
    symlink("/etc", root.join("tls/link")).unwrap();
    let err = check_owned(&root, &root.join("tls/link/passwd")).unwrap_err();
    assert!(err.to_string().contains("不允许符号链接"), "{err}");
    assert!(check_owned(&root, &root.join("tls/link")).is_err());

    assert!(check_owned(&root, &dir.join("elsewhere")).is_err());
    assert!(check_owned(&root, &root.join("a/../../x")).is_err());
}

#[test]
fn temp_dir_is_private_and_removed() {
    let path = {
        let t = TempDir::new("probe").unwrap();
        assert_eq!(mode_of(t.path()), 0o700);
        t.path().to_path_buf()
    };
    assert!(!path.exists());
}
