//! The one verification chain for release downloads, and downloads of
//! files whose hash is pinned in the code.
//!
//! [`download_asset`] is how release payloads are fetched (cores,
//! self-update, BBR kernels, FRP): the asset URL must be the canonical one
//! of the release; its expected SHA-256 is known *before* the payload is
//! fetched — from the API `digest`, or, for assets GitHub has no digest for,
//! from the release's checksum file fetched directly from github.com (never
//! through `GH_PROXY`, because it is then the trust anchor); and the file
//! is moved into place only after its size and hash matched.

use super::release::{check_size, checksum_for, is_sha256_hex, verify_file, Asset, Release};
use super::{fetch_to, Route, CHECKSUM_MAX_BYTES};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::host::os::{process_env, EnvLookup};
use crate::sys::fs::{self, TempDir};
use std::path::Path;

/// Picks a release's checksum file by asset name (`|n| n == "SHA256SUMS"`).
pub type ChecksumMatch<'a> = &'a dyn Fn(&str) -> bool;

/// Download and verify `asset` of `release` (published in `repo`) into
/// `dest`, replacing it atomically; returns the size. `checksum_file`
/// selects the release's checksum file, consulted only when the API has no
/// digest for the asset. The payload may come through `GH_PROXY`.
pub fn download_asset(
    ctx: &Ctx,
    repo: &str,
    release: &Release,
    asset: &Asset,
    dest: &Path,
    checksum_file: ChecksumMatch,
) -> Result<u64> {
    download_asset_with(ctx, &process_env, repo, release, asset, dest, checksum_file)
}

/// [`download_asset`] with an injected environment lookup.
pub fn download_asset_with(
    ctx: &Ctx,
    env: EnvLookup,
    repo: &str,
    release: &Release,
    asset: &Asset,
    dest: &Path,
    checksum_file: ChecksumMatch,
) -> Result<u64> {
    asset.check_url(repo, &release.tag)?;
    ensure!(asset.size > 0, "发行文件大小无效: {}", asset.name);
    let checksums = match asset.sha256()? {
        Some(_) => None,
        None => {
            let text = release_checksums_with(ctx, env, repo, release, checksum_file)?;
            let listed = text
                .as_deref()
                .is_some_and(|t| checksum_for(t, &asset.name).is_some());
            ensure!(listed, "{} 缺少 SHA256 校验信息，拒绝安装", asset.name);
            text
        }
    };
    let verify = |tmp: &Path| verify_file(tmp, asset, checksums.as_deref());
    fetch_to(
        ctx,
        env,
        &asset.url,
        dest,
        asset.size,
        Route::Payload,
        Some(&verify),
    )
}

/// The text of the release checksum file selected by `matches` (`None`
/// when the release has none), fetched directly from github.com and checked
/// against its metadata size (and digest, if the API has one).
pub fn release_checksums(
    ctx: &Ctx,
    repo: &str,
    release: &Release,
    matches: ChecksumMatch,
) -> Result<Option<String>> {
    release_checksums_with(ctx, &process_env, repo, release, matches)
}

/// [`release_checksums`] with an injected environment lookup.
pub fn release_checksums_with(
    ctx: &Ctx,
    env: EnvLookup,
    repo: &str,
    release: &Release,
    matches: ChecksumMatch,
) -> Result<Option<String>> {
    let Some(file) = release.assets.iter().find(|a| matches(&a.name)) else {
        return Ok(None);
    };
    file.check_url(repo, &release.tag)?;
    ensure!(
        file.size > 0 && file.size <= CHECKSUM_MAX_BYTES,
        "校验文件大小无效: {}",
        file.name
    );
    let dir = TempDir::new("checksums")?;
    let path = dir.join("checksums");
    let check = |tmp: &Path| match file.sha256()? {
        Some(_) => verify_file(tmp, file, None),
        None => check_size(tmp, file),
    };
    fetch_to(
        ctx,
        env,
        &file.url,
        &path,
        file.size,
        Route::Direct,
        Some(&check),
    )
    .map_err(|e| direct_only(e, env, file))?;
    Ok(Some(fs::read_to_string_bounded(&path, CHECKSUM_MAX_BYTES)?))
}

/// Say why a checksum file is not fetched through a configured proxy.
fn direct_only(e: Error, env: EnvLookup, file: &Asset) -> Error {
    if env("GH_PROXY").is_some() {
        e.wrap(format!(
            "该版本缺少 GitHub API 摘要，校验文件 {} 必须直连 GitHub 获取（不经 GH_PROXY）；\
             请改用带摘要的版本或检查直连网络",
            file.name
        ))
    } else {
        e.wrap(format!("获取校验文件 {} 失败", file.name))
    }
}

/// Download a file whose SHA-256 is pinned in the code (`sha256`, 64 hex)
/// into `dest`, replacing it only when the hash matches. Since the hash
/// authenticates the content, `use_proxy` lets `GH_PROXY` serve github.com
/// and raw.githubusercontent.com URLs.
pub fn download_pinned(
    ctx: &Ctx,
    url: &str,
    dest: &Path,
    max_bytes: u64,
    sha256: &str,
    use_proxy: bool,
) -> Result<u64> {
    download_pinned_with(ctx, &process_env, url, dest, max_bytes, sha256, use_proxy)
}

/// [`download_pinned`] with an injected environment lookup.
pub fn download_pinned_with(
    ctx: &Ctx,
    env: EnvLookup,
    url: &str,
    dest: &Path,
    max_bytes: u64,
    sha256: &str,
    use_proxy: bool,
) -> Result<u64> {
    ensure!(is_sha256_hex(sha256), "固定的 SHA256 格式无效");
    let expected = sha256.to_ascii_lowercase();
    let check = |tmp: &Path| {
        let actual = fs::sha256_file(tmp)?;
        ensure!(actual == expected, "下载文件 SHA256 不匹配: {url}");
        Ok(())
    };
    let route = if use_proxy {
        Route::Pinned
    } else {
        Route::Direct
    };
    fetch_to(ctx, env, url, dest, max_bytes, route, Some(&check))
}

#[cfg(test)]
mod tests;
