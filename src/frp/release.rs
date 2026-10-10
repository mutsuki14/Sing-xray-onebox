//! The frps binary: which version to install, and a verified download of
//! the official `fatedier/frp` release (spec H §4.4).
//!
//! Trust chain (shared with the proxy cores, H-8.1#5): release metadata
//! from api.github.com, the canonical asset URL, the API `digest` or the
//! release's `frp_sha256_checksums.txt` fetched directly from github.com
//! ([`download_asset`](crate::host::fetch::download_asset)), then extraction of the one `frps` member
//! ([`extract_tar_gz`]) and `frps -v` == the release version.
//!
//! Changes from v2:
//! - nothing is downloaded when the installed `frps` already is the
//!   requested version (H-8.1#4): `configure`, `rotate-token` and an
//!   `update` to the installed version need no network;
//! - downloads use the hardened transport (`--proto =https`, size caps,
//!   `GH_PROXY` checked to be https and used for the payload only) and fall
//!   back to the release checksum file when the API has no digest (v2
//!   required the digest);
//! - the architecture comes from `uname -m` and the shared naming table
//!   (ARMv7 gets `arm_hf`), not from the compile target;
//! - the download is staged next to the FRP lock before the transaction
//!   starts, so a failed download changes nothing.

use super::model::check_version;
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::host::cores::extract_tar_gz;
use crate::host::fetch::{download_asset_with, github_release_with, Release, Which};
use crate::host::os::{Arch, EnvLookup};
use crate::sys::exec::Cmd;
use crate::sys::fs::{sweep_stale, TempDir};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const REPO: &str = "fatedier/frp";
/// The checksum file of every frp release.
pub const CHECKSUMS: &str = "frp_sha256_checksums.txt";
/// Largest package and binary accepted (v2: 256 MiB).
pub const PACKAGE_MAX: u64 = 256 * 1024 * 1024;
const STAGE_LABEL: &str = "frps-download";
const VERSION_TIMEOUT: Duration = Duration::from_secs(15);

/// What an apply does about the binary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BinaryPlan {
    /// The installed binary already is this version.
    Keep(String),
    /// Look this release up (and download it unless it turns out to be
    /// the installed version).
    Fetch(Which),
}

/// `requested` is `latest` or `0.x.y`; `installed` is what `frps -v` says.
pub fn plan(requested: &str, installed: Option<&str>) -> BinaryPlan {
    match (requested, installed) {
        ("latest", _) => BinaryPlan::Fetch(Which::Latest),
        (wanted, Some(have)) if wanted == have => BinaryPlan::Keep(wanted.to_owned()),
        (wanted, _) => BinaryPlan::Fetch(Which::Tag(format!("v{wanted}"))),
    }
}

/// The version an frps binary reports (`frps -v`), `None` when it is
/// missing or does not run.
pub fn binary_version(ctx: &Ctx, binary: &Path) -> Option<String> {
    if !fs::symlink_metadata(binary).is_ok_and(|m| m.is_file()) {
        return None;
    }
    let cmd = Cmd::new(binary.to_string_lossy())
        .arg("-v")
        .timeout(VERSION_TIMEOUT);
    let out = ctx.run(&cmd).ok().filter(|o| o.ok())?;
    Some(out.stdout.trim().to_owned()).filter(|v| !v.is_empty())
}

/// The binary an apply installs.
#[derive(Debug)]
pub struct Staged {
    /// The version that will run (concrete, never `latest`).
    pub version: String,
    /// The verified new binary; `None` keeps the installed one.
    pub binary: Option<PathBuf>,
    /// Holds the staging directory until the binary is installed.
    _stage: Option<TempDir>,
}

impl Staged {
    pub fn keep(version: &str) -> Staged {
        Staged {
            version: version.to_owned(),
            binary: None,
            _stage: None,
        }
    }
}

/// The checks of a release's metadata (v2 messages); returns the version.
pub fn check_release(release: &Release, requested: &str) -> Result<String> {
    ensure!(
        !release.draft && !release.prerelease,
        "拒绝非稳定 FRP Release"
    );
    let version = release
        .tag
        .strip_prefix('v')
        .ok_or_else(|| Error::msg("FRP Release 标签无效"))?;
    ensure!(version != "latest", "FRP Release 标签无效");
    check_version(version)?;
    ensure!(
        requested == "latest" || requested == version,
        "FRP Release 标签与请求不符"
    );
    Ok(version.to_owned())
}

/// Decide, and when needed download and verify, the frps binary for
/// `requested`. `installed` is the current `frp_bin/frps`; the download is
/// staged below `stage_parent`.
pub fn prepare(
    ctx: &Ctx,
    env: EnvLookup,
    requested: &str,
    installed: &Path,
    stage_parent: &Path,
) -> Result<Staged> {
    let current = binary_version(ctx, installed);
    let which = match plan(requested, current.as_deref()) {
        BinaryPlan::Keep(version) => return Ok(Staged::keep(&version)),
        BinaryPlan::Fetch(which) => which,
    };
    let arch = Arch::detect(ctx)?;
    let release = github_release_with(ctx, env, REPO, &which)?;
    let version = check_release(&release, requested)?;
    if current.as_deref() == Some(version.as_str()) {
        return Ok(Staged::keep(&version));
    }
    let name = arch
        .frp_asset(&version)
        .ok_or_else(|| Error::msg("FRP 不支持当前 CPU 架构"))?;
    let mut matching = release.assets.iter().filter(|a| a.name == name);
    let asset = match (matching.next(), matching.next()) {
        (Some(asset), None) => asset,
        _ => bail!("FRP 安装包缺失或重复"),
    };
    ensure!(asset.size > 0 && asset.size < PACKAGE_MAX, "FRP 包大小无效");
    sweep_stale(
        stage_parent,
        &format!("onebox-{STAGE_LABEL}-"),
        Duration::ZERO,
    )?;
    let stage = TempDir::new_in(stage_parent, STAGE_LABEL)?;
    let package = stage.join(&name);
    download_asset_with(ctx, env, REPO, &release, asset, &package, &|n| {
        n == CHECKSUMS
    })?;
    let binary = stage.join("frps");
    extract_tar_gz(&package, "frps", &binary, PACKAGE_MAX)?;
    fs::remove_file(&package).map_err(|e| Error::io(&package, e))?;
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o755))
        .map_err(|e| Error::io(&binary, e))?;
    ensure!(
        binary_version(ctx, &binary).as_deref() == Some(version.as_str()),
        "frps 二进制版本校验失败"
    );
    Ok(Staged {
        version,
        binary: Some(binary),
        _stage: Some(stage),
    })
}

#[cfg(test)]
mod tests;
