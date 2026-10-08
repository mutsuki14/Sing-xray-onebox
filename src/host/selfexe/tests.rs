use super::*;
use crate::sys::exec::{FakeExec, Output};
use crate::sys::fs::TempDir;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::Arc;

struct Fixture {
    dir: TempDir,
    ctx: Ctx,
    exec: Arc<FakeExec>,
}

fn fixture() -> Fixture {
    let dir = TempDir::new("selfexe").unwrap();
    let (ctx, exec, _) = Ctx::test(dir.path());
    Fixture { dir, ctx, exec }
}

/// A minimal "Linux program": ELF magic plus a header-sized body.
fn elf(tag: &str) -> Vec<u8> {
    let mut bytes = b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0\x02\0\x3e\0".to_vec();
    bytes.extend_from_slice(tag.as_bytes());
    bytes
}

impl Fixture {
    fn exe(&self) -> &Path {
        &self.ctx.paths.executable
    }

    /// The running image (a file elsewhere).
    fn image(&self, bytes: &[u8]) -> PathBuf {
        let path = self.dir.join("running");
        std::fs::write(&path, bytes).unwrap();
        path
    }

    fn installed(&self, bytes: &[u8]) {
        std::fs::write(self.exe(), bytes).unwrap();
    }

    /// What `EXE version` prints.
    fn reports(&self, output: Output) {
        let exe = self.exe().to_string_lossy().into_owned();
        self.exec.on(&exe, &["version"], output);
    }

    fn mode(&self) -> u32 {
        std::fs::metadata(self.exe()).unwrap().permissions().mode() & 0o777
    }
}

#[test]
fn installs_when_missing() {
    let f = fixture();
    let image = f.image(&elf("3.0.0"));
    assert!(install_from(&f.ctx, &image, "3.0.0").unwrap());
    assert_eq!(std::fs::read(f.exe()).unwrap(), elf("3.0.0"));
    assert_eq!(f.mode(), 0o755);
    assert!(f.exec.history().is_empty(), "nothing to ask a missing EXE");
}

impl Fixture {
    fn set_mode(&self, mode: u32) {
        std::fs::set_permissions(self.exe(), std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn inode(&self) -> u64 {
        std::fs::metadata(self.exe()).unwrap().ino()
    }
}

#[test]
fn the_same_program_is_left_alone() {
    // Same inode: the program runs from EXE itself.
    let f = fixture();
    f.installed(&elf("3.0.0"));
    f.set_mode(0o755);
    let exe = f.exe().to_path_buf();
    assert!(!install_from(&f.ctx, &exe, "3.0.0").unwrap());
    // Same bytes in another file (e.g. a copy run from /root).
    let image = f.image(&elf("3.0.0"));
    let inode = f.inode();
    assert!(!install_from(&f.ctx, &image, "3.0.0").unwrap());
    assert_eq!(f.inode(), inode, "not rewritten");
    assert!(f.exec.history().is_empty(), "no version probe needed");
    // A hard link is the same file too.
    let link = f.dir.join("link");
    std::fs::hard_link(f.exe(), &link).unwrap();
    assert!(!install_from(&f.ctx, &link, "3.0.0").unwrap());
}

#[test]
fn the_same_program_without_mode_0755_is_repaired() {
    // Identical bytes left 0644 by a manual `cp` / `install -m644` /
    // restore: units and cron could not run it.
    for mode in [0o644, 0o700, 0o4755] {
        let f = fixture();
        f.installed(&elf("3.0.0"));
        f.set_mode(mode);
        let inode = f.inode();
        let image = f.image(&elf("3.0.0"));
        assert!(install_from(&f.ctx, &image, "3.0.0").unwrap(), "{mode:o}");
        assert_eq!(f.mode(), 0o755);
        let full = std::fs::metadata(f.exe()).unwrap().permissions().mode();
        assert_eq!(full & 0o7777, 0o755, "setuid cleared too");
        assert_eq!(f.inode(), inode, "only the mode changes");
        assert_eq!(std::fs::read(f.exe()).unwrap(), elf("3.0.0"));
        assert!(!install_from(&f.ctx, &image, "3.0.0").unwrap(), "now done");
    }
    // The same inode (running from EXE) is repaired the same way.
    let f = fixture();
    f.installed(&elf("3.0.0"));
    f.set_mode(0o744);
    let exe = f.exe().to_path_buf();
    assert!(install_from(&f.ctx, &exe, "3.0.0").unwrap());
    assert_eq!(f.mode(), 0o755);
    assert!(f.exec.history().is_empty());
}

#[test]
fn a_symlink_to_the_running_program_is_accepted() {
    // v2 canonicalized both paths: a packaged or hand-made link from EXE
    // to the program actually run worked, and must keep working.
    let f = fixture();
    let image = f.image(&elf("3.0.0"));
    std::os::unix::fs::symlink(&image, f.exe()).unwrap();
    assert!(!install_from(&f.ctx, &image, "3.0.0").unwrap());
    assert!(f.exe().is_symlink(), "link kept");
    assert_eq!(std::fs::read(&image).unwrap(), elf("3.0.0"));
    assert!(f.exec.history().is_empty());

    // A link to another copy (even with the same bytes) or a dangling
    // link is refused, with a hint.
    let other = f.dir.join("copy");
    std::fs::write(&other, elf("3.0.0")).unwrap();
    let dangling = f.dir.join("gone");
    for target in [&other, &dangling] {
        std::fs::remove_file(f.exe()).unwrap();
        std::os::unix::fs::symlink(target, f.exe()).unwrap();
        let err = install_from(&f.ctx, &image, "3.0.0").unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("不允许符号链接: {}；请删除该链接后重试", f.exe().display())
        );
    }
    assert_eq!(std::fs::read(&other).unwrap(), elf("3.0.0"));
}

#[test]
fn older_or_unknown_installed_programs_are_replaced() {
    let cases = [
        Output::success("2.0.1\n"),
        Output::success("3.0.0-rc.1\n"),
        Output::success("3.0.0\n"),
        Output::success("not a version\n"),
        Output::success(""),
        Output::failure(126, "Exec format error"),
    ];
    for output in cases {
        let f = fixture();
        f.installed(&elf("old"));
        f.reports(output.clone());
        let image = f.image(&elf("3.0.0"));
        assert!(install_from(&f.ctx, &image, "3.0.0").unwrap(), "{output:?}");
        assert_eq!(std::fs::read(f.exe()).unwrap(), elf("3.0.0"));
        assert_eq!(f.mode(), 0o755);
        let probe = format!("{} version", f.exe().display());
        assert_eq!(f.exec.history(), [probe]);
        assert!(f.exec.calls()[0].timeout.is_some());
    }
}

#[test]
fn a_newer_installed_program_is_never_downgraded() {
    for (reported, running) in [
        ("3.0.1", "3.0.0"),
        ("v3.1.0", "3.0.9"),
        ("3.0.0", "3.0.0-rc.2"),
        ("4.0.0-beta.1", "3.9.9"),
    ] {
        let f = fixture();
        f.installed(&elf("newer"));
        f.reports(Output::success(format!("{reported}\n")));
        let image = f.image(&elf("older"));
        assert!(
            !install_from(&f.ctx, &image, running).unwrap(),
            "{reported}"
        );
        assert_eq!(std::fs::read(f.exe()).unwrap(), elf("newer"));
    }
}

#[test]
fn refusals_leave_exe_untouched() {
    let f = fixture();
    f.installed(&elf("old"));
    let image = f.image(b"#!/bin/sh\necho not elf\n");
    let err = install_from(&f.ctx, &image, "3.0.0").unwrap_err();
    assert_eq!(err.to_string(), "当前程序不是有效 Linux 二进制");
    assert_eq!(std::fs::read(f.exe()).unwrap(), elf("old"));
    let short = f.image(b"\x7fELF");
    assert!(install_from(&f.ctx, &short, "3.0.0").is_err());

    let f = fixture();
    let target = f.dir.join("elsewhere");
    std::fs::write(&target, elf("x")).unwrap();
    std::os::unix::fs::symlink(&target, f.exe()).unwrap();
    let image = f.image(&elf("3.0.0"));
    let err = install_from(&f.ctx, &image, "3.0.0").unwrap_err();
    assert_eq!(
        err.to_string(),
        format!("不允许符号链接: {}；请删除该链接后重试", f.exe().display())
    );
    assert_eq!(std::fs::read(&target).unwrap(), elf("x"));

    let f = fixture();
    std::fs::create_dir(f.exe()).unwrap();
    let image = f.image(&elf("3.0.0"));
    let err = install_from(&f.ctx, &image, "3.0.0").unwrap_err();
    assert_eq!(
        err.to_string(),
        format!("程序路径不是普通文件: {}", f.exe().display())
    );

    let f = fixture();
    let err = install_from(&f.ctx, &f.dir.join("gone"), "3.0.0").unwrap_err();
    assert!(err.to_string().starts_with("无法读取当前程序"), "{err}");
}

#[test]
fn missing_binary_directories_are_created_traversable() {
    let dir = TempDir::new("selfexe").unwrap();
    let (mut ctx, _exec, _) = Ctx::test(dir.path());
    ctx.paths.executable = dir.join("usr/local/bin/onebox");
    let image = dir.join("running");
    std::fs::write(&image, elf("3.0.0")).unwrap();
    assert!(install_from(&ctx, &image, "3.0.0").unwrap());
    for sub in ["usr", "usr/local", "usr/local/bin"] {
        let mode = std::fs::metadata(dir.join(sub))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o755, "{sub}");
    }
}

#[test]
fn install_self_copies_the_running_test_binary() {
    let f = fixture();
    assert!(install_self(&f.ctx).unwrap());
    let running = std::fs::read(SELF_EXE).unwrap();
    assert_eq!(std::fs::read(f.exe()).unwrap(), running);
    assert_eq!(f.mode(), 0o755);
    // Identical bytes now: nothing to do.
    assert!(!install_self(&f.ctx).unwrap());
}
