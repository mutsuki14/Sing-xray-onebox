//! GitHub release metadata (typed), asset URL pinning and file verification.
//!
//! Trust chain: metadata comes over direct TLS from api.github.com; an asset
//! is accepted only when its URL is exactly
//! `https://github.com/{repo}/releases/download/{tag}/{name}`, its size
//! equals the metadata and its SHA-256 matches the API `digest` or, when the
//! API has none (older releases), a checksum file of the same release.

use crate::error::{Context, Error, Result};
use serde::Deserialize;
use std::io::Read;
use std::path::Path;

/// Which release of a repository to look up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Which {
    /// The newest non-draft, non-prerelease release (`/releases/latest`).
    Latest,
    /// An exact tag such as `v1.14.2` or `testing`.
    Tag(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Asset {
    /// Plain file name (validated: usable as a path component).
    pub name: String,
    /// `browser_download_url`.
    pub url: String,
    pub size: u64,
    /// The API `digest` field verbatim (`sha256:<hex>`), when present.
    pub digest: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Release {
    pub tag: String,
    /// Missing in the metadata counts as `true` (fail safe).
    pub draft: bool,
    /// Missing in the metadata counts as `true` (fail safe).
    pub prerelease: bool,
    pub body: String,
    pub assets: Vec<Asset>,
}

/// One page of a repository's release list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleasePage {
    /// Entries that passed the same validation as a single release, in API
    /// order (newest first); malformed entries are left out because they
    /// can never be trusted.
    pub releases: Vec<Release>,
    /// How many entries the API returned, valid or not.
    pub entries: usize,
}

impl ReleasePage {
    /// Fewer entries than requested: there is no further page.
    pub fn is_last(&self, per_page: u32) -> bool {
        self.entries < per_page as usize
    }
}

#[derive(Deserialize)]
struct RawRelease {
    tag_name: Option<String>,
    draft: Option<bool>,
    prerelease: Option<bool>,
    body: Option<String>,
    assets: Option<Vec<RawAsset>>,
}

#[derive(Deserialize)]
struct RawAsset {
    name: Option<String>,
    browser_download_url: Option<String>,
    size: Option<u64>,
    digest: Option<String>,
}

impl Release {
    /// Parse a `/releases/latest` or `/releases/tags/{tag}` response.
    pub fn parse(json: &[u8]) -> Result<Release> {
        let raw: RawRelease =
            serde_json::from_slice(json).map_err(|e| Error::msg(format!("发行信息无效: {e}")))?;
        Release::from_raw(raw)
    }

    /// Parse a `/releases?per_page=…` response (a JSON array).
    pub fn parse_list(json: &[u8]) -> Result<ReleasePage> {
        let raw: Vec<serde_json::Value> = serde_json::from_slice(json)
            .map_err(|e| Error::msg(format!("响应不是发行数组: {e}")))?;
        let entries = raw.len();
        let releases = raw
            .into_iter()
            .filter_map(|v| serde_json::from_value::<RawRelease>(v).ok())
            .filter_map(|r| Release::from_raw(r).ok())
            .collect();
        Ok(ReleasePage { releases, entries })
    }

    fn from_raw(raw: RawRelease) -> Result<Release> {
        let tag = raw
            .tag_name
            .filter(|t| !t.is_empty())
            .ok_or_else(|| Error::msg("发行信息缺少版本"))?;
        let assets = raw
            .assets
            .ok_or_else(|| Error::msg("发行信息缺少文件"))?
            .into_iter()
            .map(Asset::from_raw)
            .collect::<Result<Vec<_>>>()?;
        Ok(Release {
            tag,
            draft: raw.draft.unwrap_or(true),
            prerelease: raw.prerelease.unwrap_or(true),
            body: raw.body.unwrap_or_default(),
            assets,
        })
    }

    /// The tag without one leading `v` (`v1.14.2` → `1.14.2`).
    pub fn version(&self) -> &str {
        self.tag.strip_prefix('v').unwrap_or(&self.tag)
    }

    pub fn asset(&self, name: &str) -> Option<&Asset> {
        self.assets.iter().find(|a| a.name == name)
    }

    /// The first of `names` this release ships.
    pub fn first_asset<S: AsRef<str>>(&self, names: &[S]) -> Option<&Asset> {
        names.iter().find_map(|n| self.asset(n.as_ref()))
    }
}

impl Asset {
    fn from_raw(raw: RawAsset) -> Result<Asset> {
        let name = raw
            .name
            .filter(|n| valid_file_name(n))
            .ok_or_else(|| Error::msg("文件名无效"))?;
        let url = raw
            .browser_download_url
            .ok_or_else(|| Error::msg("下载地址缺失"))?;
        let size = raw
            .size
            .ok_or_else(|| Error::msg(format!("发行文件缺少大小信息: {name}")))?;
        Ok(Asset {
            name,
            url,
            size,
            digest: raw.digest,
        })
    }

    /// `https://github.com/{repo}/releases/download/{tag}/{name}`.
    pub fn expected_url(repo: &str, tag: &str, name: &str) -> String {
        format!("https://github.com/{repo}/releases/download/{tag}/{name}")
    }

    /// Refuse an asset whose URL is not the canonical one for `repo`/`tag`.
    pub fn check_url(&self, repo: &str, tag: &str) -> Result<()> {
        if self.url == Asset::expected_url(repo, tag, &self.name) {
            Ok(())
        } else {
            Err(Error::msg(format!("发行文件地址不可信: {}", self.name)))
        }
    }

    /// The lower-case hex SHA-256 from the API `digest`. `None` when the API
    /// gave no digest or one of another algorithm; an error when it claims
    /// SHA-256 but is malformed (never silently skip a broken digest).
    pub fn sha256(&self) -> Result<Option<String>> {
        let Some(digest) = self.digest.as_deref() else {
            return Ok(None);
        };
        let Some(hex) = digest.strip_prefix("sha256:") else {
            return Ok(None);
        };
        if is_sha256_hex(hex) {
            Ok(Some(hex.to_ascii_lowercase()))
        } else {
            Err(Error::msg(format!(
                "发行文件 SHA256 格式无效: {}",
                self.name
            )))
        }
    }
}

/// A release file name usable as one path component.
fn valid_file_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.chars().any(char::is_control)
}

pub(crate) fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The SHA-256 for `name` in a checksum file, lower-case. Understands GNU
/// `sha256sum` lines (`<hex>  name`, `<hex> *name`), BSD lines
/// (`SHA256 (name) = <hex>`) and OpenSSL digest files without a file name
/// (`SHA2-256= <hex>`, Xray's `.dgst`; such a file describes exactly one
/// asset, so the caller picks it by name).
pub fn checksum_for(text: &str, name: &str) -> Option<String> {
    text.lines()
        .filter_map(|line| checksum_line(line.trim(), name))
        .next()
        .map(|hex| hex.to_ascii_lowercase())
}

fn checksum_line<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    if let Some((left, hex)) = line.split_once('=') {
        let hex = hex.trim();
        let left = left.trim();
        let bsd = left
            .strip_prefix("SHA256 (")
            .and_then(|rest| rest.strip_suffix(')'))
            .is_some_and(|file| file == name);
        let openssl = matches!(left, "SHA256" | "SHA2-256" | "SHA-256");
        return ((bsd || openssl) && is_sha256_hex(hex)).then_some(hex);
    }
    let mut words = line.split_whitespace();
    let hex = words.next()?;
    let file = words.next()?;
    let file = file.strip_prefix('*').unwrap_or(file);
    let file = file.strip_prefix("./").unwrap_or(file);
    (words.next().is_none() && file == name && is_sha256_hex(hex)).then_some(hex)
}

/// Verify a downloaded file: exact size, then SHA-256 from the API digest
/// or (fallback, G-8.1#6) from `checksums` (the release's checksum file).
pub fn verify_file(path: &Path, asset: &Asset, checksums: Option<&str>) -> Result<()> {
    check_size(path, asset)?;
    let expected = match asset.sha256()? {
        Some(hex) => hex,
        None => checksums
            .and_then(|text| checksum_for(text, &asset.name))
            .ok_or_else(|| Error::msg(format!("{} 缺少 SHA256 校验信息，拒绝安装", asset.name)))?,
    };
    let actual = crate::sys::fs::sha256_file(path)?;
    if actual != expected {
        return Err(Error::msg(format!(
            "下载文件 SHA256 不匹配: {}",
            asset.name
        )));
    }
    Ok(())
}

/// The file has exactly the size the metadata announced.
pub(crate) fn check_size(path: &Path, asset: &Asset) -> Result<()> {
    let size = std::fs::symlink_metadata(path)
        .map_err(|e| Error::io(path, e))?
        .len();
    if size == asset.size {
        Ok(())
    } else {
        Err(Error::msg(format!(
            "{} 大小与发行元信息不符（应为 {} 字节，实际 {size} 字节）",
            asset.name, asset.size
        )))
    }
}

/// ELF magic plus a minimal header length (v2 rule).
pub fn is_elf(bytes: &[u8]) -> bool {
    bytes.len() >= 20 && bytes.starts_with(b"\x7fELF")
}

/// `Err` unless `path` starts like a Linux ELF executable.
pub fn check_elf(path: &Path) -> Result<()> {
    let mut head = Vec::with_capacity(20);
    std::fs::File::open(path)
        .and_then(|f| f.take(20).read_to_end(&mut head))
        .map_err(|e| Error::io(path, e))
        .context("无法读取程序文件")?;
    if is_elf(&head) {
        Ok(())
    } else {
        Err(Error::msg(format!(
            "{} 不是 Linux ELF 程序",
            path.file_name().unwrap_or_default().to_string_lossy()
        )))
    }
}
