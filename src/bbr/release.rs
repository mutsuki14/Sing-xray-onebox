//! byJoey/Actions-bbr-v3 releases: tag grammar, kernel names, release
//! selection and the manifest trust rules.
//!
//! Trust boundary: release metadata always comes directly from
//! api.github.com; package bytes may come through `GH_PROXY` but must then
//! match the size and SHA-256 published in that metadata. Every rule below
//! is kept byte-for-byte from v2:
//! - a tag is `{arch}-{V}` (standard) or `{arch}-{V}-max` (Max) with V two
//!   or three dot-separated ASCII-digit components, validated before it is
//!   ever put into a URL (no `../latest`);
//! - the release must have exactly that `tag_name` and JSON `false` for
//!   `draft` and `prerelease` (missing or null is rejected);
//! - exactly one `linux-image-{kernel}_*_{deb}.deb` and one
//!   `linux-headers-{kernel}_*_{deb}.deb`, file names `[A-Za-z0-9_.+-]`,
//!   `browser_download_url` exactly the official asset URL, digest
//!   `sha256:` + 64 lowercase hex, size an integer in 1..=2 GiB.
//!
//! Changes from v2: the release list scans up to five pages and sorts all
//! matches together (v2 stopped at the first page with any match, so a
//! newer release published out of order on a later page was ignored,
//! I-8.1#10); a rate-limit answer names GitHub's message.

use super::REPO;
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use serde_json::Value;

/// Releases per API page; a shorter page is the last one.
const PAGE_SIZE: usize = 100;
const MAX_PAGES: u32 = 5;
/// Largest accepted package (2 GiB).
const MAX_PACKAGE_BYTES: u64 = 2_147_483_648;

/// Kernel architecture as named by the release tags and by dpkg.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Arch {
    pub tag: &'static str,
    pub deb: &'static str,
}

pub const X86_64: Arch = Arch {
    tag: "x86_64",
    deb: "amd64",
};
pub const ARM64: Arch = Arch {
    tag: "arm64",
    deb: "arm64",
};

impl Arch {
    /// Map `uname -m`.
    pub fn from_machine(machine: &str) -> Result<Arch> {
        match machine.trim() {
            "x86_64" => Ok(X86_64),
            "aarch64" => Ok(ARM64),
            _ => Err(Error::msg("Actions-bbr-v3 内核仅支持 x86_64 / aarch64")),
        }
    }

    pub fn detect(ctx: &Ctx) -> Result<Arch> {
        Arch::from_machine(&ctx.check(&crate::sys::exec::Cmd::new("uname").arg("-m"))?)
    }
}

/// Dot-separated ASCII digits, e.g. `7.2.10` → `[7, 2, 10]`.
pub fn version_parts(version: &str) -> Option<Vec<u64>> {
    version
        .split('.')
        .map(|part| {
            (!part.is_empty() && part.bytes().all(|c| c.is_ascii_digit()))
                .then(|| part.parse().ok())
                .flatten()
        })
        .collect()
}

/// The version of a tag matching `arch` and the standard/Max profile.
pub fn tag_version(tag: &str, arch: Arch, max: bool) -> Option<Vec<u64>> {
    let version = tag.strip_prefix(arch.tag)?.strip_prefix('-')?;
    let version = if max {
        version.strip_suffix("-max")?
    } else {
        version
    };
    let parts = version_parts(version)?;
    (parts.len() == 2 || parts.len() == 3).then_some(parts)
}

/// `{V}-joeyblog-bbrv3` or `{V}-joeyblog-bbrv3-max` for a valid tag.
pub fn kernel_name(tag: &str, arch: Arch, max: bool) -> Result<String> {
    let mismatch = || Error::msg("Release 标签与架构/标准或 Max 类型不匹配");
    tag_version(tag, arch, max).ok_or_else(mismatch)?;
    let version = tag
        .strip_prefix(arch.tag)
        .and_then(|v| v.strip_prefix('-'))
        .ok_or_else(mismatch)?;
    Ok(match version.strip_suffix("-max") {
        Some(base) if max => format!("{base}-joeyblog-bbrv3-max"),
        _ => format!("{version}-joeyblog-bbrv3"),
    })
}

/// The release list page URL (direct API, never proxied).
pub fn list_url(page: u32) -> String {
    format!("https://api.github.com/repos/{REPO}/releases?per_page={PAGE_SIZE}&page={page}")
}

/// The release-by-tag URL; `tag` must already be validated.
pub fn tag_url(tag: &str) -> String {
    format!("https://api.github.com/repos/{REPO}/releases/tags/{tag}")
}

/// Published tags for `arch`/profile, newest first, from up to five pages.
pub fn release_tags(
    arch: Arch,
    max: bool,
    fetch: &mut dyn FnMut(&str) -> Result<Value>,
) -> Result<Vec<String>> {
    let mut found: Vec<(Vec<u64>, String)> = Vec::new();
    for page in 1..=MAX_PAGES {
        let data = fetch(&list_url(page))?;
        let releases = data.as_array().ok_or_else(|| invalid_list(&data))?;
        found.extend(
            releases
                .iter()
                .filter(|r| r["draft"] == false && r["prerelease"] == false)
                .filter_map(|r| r["tag_name"].as_str())
                .filter_map(|tag| tag_version(tag, arch, max).map(|v| (v, tag.to_string()))),
        );
        if releases.len() < PAGE_SIZE {
            break;
        }
    }
    found.sort_by(|a, b| b.cmp(a));
    found.dedup_by(|a, b| a.1 == b.1);
    if found.is_empty() {
        return Err(Error::msg(format!(
            "最近 500 个 Release 中未找到 {} / {}；可指定完整 Release 标签",
            arch.tag,
            if max { "Max" } else { "标准版" }
        )));
    }
    Ok(found.into_iter().map(|(_, tag)| tag).collect())
}

fn invalid_list(data: &Value) -> Error {
    match data["message"].as_str() {
        Some(message) => Error::msg(format!(
            "GitHub Release 响应无效 (可能被 API 限流): {message}"
        )),
        None => Error::msg("GitHub Release 响应无效 (可能被 API 限流)"),
    }
}

/// One verified-by-metadata package of a release.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Asset {
    pub name: String,
    /// 64 lowercase hex characters (without `sha256:`).
    pub digest: String,
    pub size: u64,
    pub url: String,
    /// `linux-image-{kernel}` / `linux-headers-{kernel}`.
    pub package: String,
}

/// A release reduced to what may be installed: image first, then headers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub tag: String,
    pub kernel: String,
    pub assets: Vec<Asset>,
}

impl Manifest {
    /// Apply every trust rule (module docs) to a release-by-tag document.
    pub fn parse(data: &Value, tag: &str, arch: Arch, max: bool) -> Result<Manifest> {
        let kernel = kernel_name(tag, arch, max)?;
        if data["tag_name"].as_str() != Some(tag)
            || data["draft"] != false
            || data["prerelease"] != false
        {
            return Err(Error::msg("BBR Release 标签不匹配、尚未发布或为预发布版"));
        }
        let assets = data["assets"]
            .as_array()
            .ok_or_else(|| Error::msg("BBR Release 缺少包列表"))?;
        let assets = ["image", "headers"]
            .into_iter()
            .map(|kind| select_asset(assets, tag, &kernel, kind, arch))
            .collect::<Result<Vec<_>>>()?;
        Ok(Manifest {
            tag: tag.to_string(),
            kernel,
            assets,
        })
    }

    /// Download size of all packages in bytes.
    pub fn total(&self) -> u64 {
        self.assets.iter().map(|a| a.size).sum()
    }
}

fn select_asset(
    assets: &[Value],
    tag: &str,
    kernel: &str,
    kind: &str,
    arch: Arch,
) -> Result<Asset> {
    let package = format!("linux-{kind}-{kernel}");
    let prefix = format!("{package}_");
    let suffix = format!("_{}.deb", arch.deb);
    let candidates: Vec<&Value> = assets
        .iter()
        .filter(|a| {
            a["name"]
                .as_str()
                .is_some_and(|n| n.starts_with(&prefix) && n.ends_with(&suffix))
        })
        .collect();
    let [asset] = candidates.as_slice() else {
        return Err(Error::msg(format!(
            "BBR Release 必须恰好包含一个 {package} 包"
        )));
    };
    let name = asset["name"].as_str().unwrap_or_default();
    if !name
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || b"_.+-".contains(&c))
    {
        return Err(Error::msg("BBR 包文件名不安全"));
    }
    let url = format!("https://github.com/{REPO}/releases/download/{tag}/{name}");
    if asset["browser_download_url"].as_str() != Some(url.as_str()) {
        return Err(Error::msg("BBR 包下载地址不是指定的官方 Release 资产"));
    }
    let digest = asset["digest"]
        .as_str()
        .and_then(|s| s.strip_prefix("sha256:"))
        .filter(|s| s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
        .ok_or_else(|| Error::msg("BBR Release 缺少可信 SHA-256，拒绝安装"))?;
    let size = asset["size"]
        .as_u64()
        .filter(|n| (1..=MAX_PACKAGE_BYTES).contains(n))
        .ok_or_else(|| Error::msg("BBR 包大小无效"))?;
    Ok(Asset {
        name: name.to_string(),
        digest: digest.to_string(),
        size,
        url,
        package,
    })
}

#[cfg(test)]
mod tests;
