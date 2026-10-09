use super::*;

fn words(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

#[test]
fn registry_names_are_unique() {
    let mut names: Vec<&str> = COMMANDS
        .iter()
        .flat_map(|c| std::iter::once(c.name).chain(c.aliases.iter().copied()))
        .collect();
    let total = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), total);
}

fn path(path: &[&'static str]) -> Matches {
    Matches {
        path: path.to_vec(),
        ..Matches::default()
    }
}

#[test]
fn builtins_need_no_root_or_context() {
    for name in ["version", "help"] {
        let spec = find(COMMANDS, name).unwrap();
        assert!(!requires_root(spec, &Matches::default()));
        assert!(builtin(&path(&[name])).is_some());
        assert!(spec.handler.is_some());
    }
}

#[test]
fn nested_commands_named_like_builtins_are_not_taken_over() {
    assert!(builtin(&path(&["frps", "help"])).is_none());
    assert!(builtin(&path(&["update", "version"])).is_none());
    assert!(builtin(&path(&[])).is_none());
}

#[test]
fn chain_resolution() {
    let chain = resolve_chain(COMMANDS, &words(&["help"])).unwrap();
    assert_eq!(chain[0].name, "help");
    assert_eq!(
        resolve_chain(COMMANDS, &words(&["nope"]))
            .unwrap_err()
            .to_string(),
        "未知命令: nope；请执行 onebox help"
    );
    assert_eq!(
        resolve_chain(COMMANDS, &words(&["version", "x"]))
            .unwrap_err()
            .to_string(),
        "未知子命令: x；请执行 onebox version --help"
    );
    assert!(resolve_chain(COMMANDS, &[]).unwrap().is_empty());
}

#[test]
fn root_policy_variants() {
    fn needs_root_with_apply(m: &Matches) -> bool {
        m.flag("apply")
    }
    let spec =
        CommandSpec::new("tune", Group::Node, "调优").root(Root::Custom(needs_root_with_apply));
    let mut matches = Matches::default();
    assert!(!requires_root(&spec, &matches));
    matches.flags.push("apply");
    assert!(requires_root(&spec, &matches));
    let default = CommandSpec::new("install", Group::Node, "安装");
    assert!(
        requires_root(&default, &Matches::default()),
        "root by default"
    );
    let check = require_root();
    assert_eq!(check.is_ok(), crate::sys::process::is_root());
    if let Err(e) = check {
        assert_eq!(e.to_string(), "此操作需要 root 权限");
    }
}

/// The uninstall backup hook is the second wave-C integration point: once
/// the backup module provides `create_locked`, the hook must use it (it
/// still refuses here, so uninstall would stay broken without this test).
#[test]
fn uninstall_backup_hook_follows_the_backup_module() {
    fn sources(path: &std::path::Path, out: &mut String) {
        if path.is_dir() {
            for entry in std::fs::read_dir(path).unwrap().flatten() {
                sources(&entry.path(), out);
            }
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push_str(&std::fs::read_to_string(path).unwrap_or_default());
        }
    }
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut backup = String::new();
    sources(&src.join("backup.rs"), &mut backup);
    sources(&src.join("backup"), &mut backup);
    let provided = backup.contains("fn create_locked");
    let dir = crate::sys::fs::TempDir::new("registry-backup-hook").unwrap();
    let (ctx, _, _) = Ctx::test(dir.path());
    std::fs::create_dir_all(&ctx.paths.root).unwrap();
    let lock = crate::sys::lock::FileLock::acquire(&ctx.paths.lock(), "busy").unwrap();
    // In the isolated context a wired hook fails or succeeds, but never
    // with the placeholder's refusal.
    let unwired = matches!(
        UNINSTALL_BACKUP(&ctx, &lock, "before-uninstall"),
        Err(e) if e.to_string() == BACKUP_NOT_WIRED
    );
    assert!(
        !(provided && unwired),
        "crate::backup::create_locked exists: set cli::registry::UNINSTALL_BACKUP to it"
    );
}
