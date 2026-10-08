//! Installing the running program as `EXE` (`paths.executable`, default
//! `/usr/local/bin/onebox`), the path every service unit and cron line
//! calls. Used by the apply engine (prepare-state) and the FRP transaction.
//!
//! [`install_self`] copies `/proc/self/exe` — which still names the running
//! image after a self-update unlinked it — to `EXE`, atomically with mode
//! 0755, unless `EXE` already is this program. It never replaces a newer
//! installed program: running an older pinned launcher (`sh onebox.sh …`
//! fetches its own version) on a host that self-updated must not downgrade
//! the program the units run (G28).
//!
//! Changes from v2:
//! - "already this program" means the same file (device and inode) or
//!   identical bytes; v2 compared canonical paths only and rewrote `EXE`
//!   on every apply when run from another copy.
//! - a semver-newer installed program (`EXE version`) is kept with a
//!   warning instead of being overwritten.
//! - the image is size-capped before it is read into memory, and a missing
//!   parent directory is created 0755 (the binary directory must stay
//!   traversable), not 0700.
//! - only `EXE` itself must not be a symlink; its parent directories are
//!   trusted system paths (v2 refused a symlink anywhere in the path, which
//!   broke distributions with a linked `/usr/local`).

mod semver;

pub use semver::Semver;

use crate::ctx::Ctx;
use crate::error::{Context, Error, Result};
use crate::host::fetch::is_elf;
use crate::sys::exec::Cmd;
use crate::sys::fs as sysfs;
use crate::ui::out;
use std::fs::{File, Metadata};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Duration;

/// The running image, also after its file was replaced or unlinked.
pub const SELF_EXE: &str = "/proc/self/exe";
/// Largest program image accepted (the static release binary is ~10 MB).
pub const MAX_EXE_BYTES: u64 = 256 * 1024 * 1024;
const VERSION_TIMEOUT: Duration = Duration::from_secs(15);

/// Install the running program as `EXE`. `Ok(true)` when `EXE` was
/// written; `Ok(false)` when it already is this program or holds a newer
/// version (kept, with a warning).
pub fn install_self(ctx: &Ctx) -> Result<bool> {
    install_from(ctx, Path::new(SELF_EXE), crate::VERSION)
}

/// [`install_self`] with the running image and its version injected
/// (tests; `running` is what this program reports as `version`).
pub fn install_from(ctx: &Ctx, image: &Path, running: &str) -> Result<bool> {
    let exe = &ctx.paths.executable;
    let installed = installed_metadata(exe)?;
    let mut source = File::open(image)
        .map_err(|e| Error::io(image, e))
        .context("无法读取当前程序")?;
    let source_meta = source.metadata().map_err(|e| Error::io(image, e))?;
    if installed
        .as_ref()
        .is_some_and(|m| same_file(m, &source_meta))
    {
        return Ok(false);
    }
    let bytes = read_image(&mut source, image)?;
    ensure!(is_elf(&bytes), "当前程序不是有效 Linux 二进制");
    if let Some(meta) = &installed {
        if same_bytes(exe, meta, &bytes)? {
            return Ok(false);
        }
        if let Some(newer) = newer_installed(ctx, exe, running) {
            out::warn(format!(
                "已安装更新版本 {newer}，本次运行的程序较旧，未覆盖 {}",
                exe.display()
            ));
            return Ok(false);
        }
    }
    ensure_parent(exe)?;
    sysfs::atomic_write(exe, &bytes, 0o755)?;
    Ok(true)
}

/// `EXE`'s metadata; `None` when absent. A symlink or a non-file is
/// refused: `EXE` is an Onebox-owned file replaced by rename.
fn installed_metadata(exe: &Path) -> Result<Option<Metadata>> {
    match std::fs::symlink_metadata(exe) {
        Ok(m) if m.file_type().is_symlink() => {
            bail!("不允许符号链接: {}", exe.display())
        }
        Ok(m) if !m.is_file() => bail!("程序路径不是普通文件: {}", exe.display()),
        Ok(m) => Ok(Some(m)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::io(exe, e)),
    }
}

fn same_file(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino()
}

/// The whole image, at most [`MAX_EXE_BYTES`].
fn read_image(source: &mut File, image: &Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    source
        .take(MAX_EXE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| Error::io(image, e))?;
    ensure!(
        bytes.len() as u64 <= MAX_EXE_BYTES,
        "当前程序过大（超过 {MAX_EXE_BYTES} 字节）"
    );
    Ok(bytes)
}

/// `EXE` already holds exactly `bytes` (sizes compared first).
fn same_bytes(exe: &Path, meta: &Metadata, bytes: &[u8]) -> Result<bool> {
    if meta.len() != bytes.len() as u64 {
        return Ok(false);
    }
    Ok(sysfs::read_bounded(exe, MAX_EXE_BYTES)? == bytes)
}

/// The installed program's version when it is semver-newer than
/// `running`. A program that cannot run or report a version is not
/// "newer" (it is replaced).
fn newer_installed(ctx: &Ctx, exe: &Path, running: &str) -> Option<String> {
    let cmd = Cmd::new(exe.to_string_lossy())
        .arg("version")
        .timeout(VERSION_TIMEOUT);
    let output = ctx.run(&cmd).ok().filter(|o| o.ok())?;
    let reported = output.stdout.lines().next()?.trim().to_owned();
    let installed = Semver::parse(&reported)?;
    let current = Semver::parse(running)?;
    (installed > current).then_some(reported)
}

/// Missing binary directories are created traversable (0755), top down.
fn ensure_parent(exe: &Path) -> Result<()> {
    let Some(parent) = exe.parent() else {
        return Ok(());
    };
    let missing: Vec<&Path> = parent
        .ancestors()
        .take_while(|dir| !dir.as_os_str().is_empty() && !dir.exists())
        .collect();
    missing
        .iter()
        .rev()
        .try_for_each(|dir| sysfs::ensure_dir(dir, 0o755))
}

#[cfg(test)]
mod tests;
