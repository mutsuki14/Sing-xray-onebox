//! HTTPS downloads through curl and GitHub release metadata.
//!
//! Every transfer is `curl --proto =https --proto-redir =https --tlsv1.2
//! -fL` (HTTPS only, also across redirects), into a temp file next to the
//! destination that is renamed into place only after the size cap, the
//! non-emptiness check and, for verified downloads, the hash check; partial
//! or unverified files are removed on every error. Transfers require curl;
//! flows that change the host call [`ensure_curl`] first, which installs a
//! missing curl as root (G14). Read-only lookups (previews, update checks)
//! never install anything.
//!
//! Proxy policy (`GH_PROXY`: an `https://` prefix, no whitespace), one rule
//! for every caller:
//! - API metadata (api.github.com) and release checksum files
//!   (`SHA256SUMS`, `.dgst`) always go direct to
//!   `https://github.com/{repo}/releases/download/{tag}/…`. They
//!   authenticate payloads; for assets the API has no digest for (older
//!   releases) the checksum file is the only trust anchor, so a mirror must
//!   never be able to swap it together with the payload (G26).
//! - release payloads from `https://github.com/` may use the proxy: their
//!   size and SHA-256 are known from direct sources before the download
//!   ([`download_asset`]) or are verified by the caller against direct
//!   metadata ([`download_paced_with`] for BBR packages).
//! - files whose SHA-256 is pinned in the code may also be fetched from
//!   `https://raw.githubusercontent.com/` through the proxy
//!   ([`download_pinned`]).
//!
//! `GH_TOKEN`, when set, authenticates API requests (higher rate limits);
//! it is handed to curl on stdin, never on the command line.
//!
//! Changes from v2:
//! - curl only: wget's `--https-only` does not apply to redirects
//!   (E-8.1#7), so there is no wget fallback; mutating flows install a
//!   missing curl ([`ensure_curl`]).
//! - transfer limits scale with the expected size (`--max-time` from a
//!   32 KiB/s floor, `--speed-limit` 1 KiB/s over 60 s) instead of a fixed
//!   300 s that failed on slow links; every download has a byte cap
//!   (`--max-filesize` plus a check of the result). Interactive downloads
//!   of large packages ([`Pace::Progress`]) show curl's progress bar and are
//!   bounded by the low-speed limit only.
//! - TLS 1.2 minimum; 15 s connect timeout.
//! - one verification chain for every release download
//!   ([`download_asset`]): the API digest is preferred and a release
//!   `SHA256SUMS`/`.dgst` is the fallback when the API has none (G-8.1#6);
//!   the checksum file must match its metadata size, and the payload is
//!   fetched only once its expected hash is known.
//! - release lists ([`github_releases`]) and raw API documents
//!   ([`github_api_json`]) share the API transport, token and rate-limit
//!   handling.
//! - hash-pinned files may use `GH_PROXY` for raw.githubusercontent.com
//!   (v2 never proxied them).
//! - temp files use the shared `.onebox-tmp-` prefix so crash leftovers are
//!   swept (E-8.1#16).
//! - API requests send `Accept`/`X-GitHub-Api-Version` and optional
//!   `GH_TOKEN`; rate-limit failures say how to raise the limit.

mod asset;
mod release;
#[cfg(test)]
pub(crate) mod testing;
mod transfer;

pub use asset::{
    download_asset, download_asset_with, download_pinned, download_pinned_with, release_checksums,
    release_checksums_with, ChecksumMatch,
};
pub use release::{
    check_elf, checksum_for, is_elf, verify_file, Asset, Release, ReleasePage, Which,
};
pub use transfer::{ensure_curl, ensure_curl_as, max_time, require_curl, Pace};

use crate::ctx::Ctx;
use crate::error::{Context, Error, Result};
use crate::host::os::{process_env, EnvLookup};
use crate::sys::fs::{self, TempDir};
use std::path::Path;
use transfer::{transfer, Check, Transfer};

/// Response size cap for GitHub API metadata (v2 value).
pub const API_MAX_BYTES: u64 = 16 * 1024 * 1024;
/// Cap for checksum files (`SHA256SUMS`, `.dgst`).
pub const CHECKSUM_MAX_BYTES: u64 = 1024 * 1024;
/// GitHub's largest page size for list endpoints.
pub const MAX_PER_PAGE: u32 = 100;
const GITHUB: &str = "https://github.com/";
const RAW_GITHUB: &str = "https://raw.githubusercontent.com/";
const API: &str = "https://api.github.com/";
const API_HEADERS: [&str; 2] = [
    "Accept: application/vnd.github+json",
    "X-GitHub-Api-Version: 2022-11-28",
];

/// Which URLs `GH_PROXY` may front for one transfer (module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Route {
    /// Never proxied: API metadata and checksum files.
    Direct,
    /// github.com release payloads verified against direct metadata.
    Payload,
    /// Files verified against a SHA-256 pinned in the code.
    Pinned,
}

impl Route {
    fn proxiable(self, url: &str) -> bool {
        match self {
            Route::Direct => false,
            Route::Payload => url.starts_with(GITHUB),
            Route::Pinned => url.starts_with(GITHUB) || url.starts_with(RAW_GITHUB),
        }
    }

    fn payload_if(use_proxy: bool) -> Route {
        if use_proxy {
            Route::Payload
        } else {
            Route::Direct
        }
    }
}

/// Download `url` to `dest` (replaced atomically) and return its size.
/// `use_proxy` routes github.com payloads through `GH_PROXY`; prefer
/// [`download_asset`] / [`download_pinned`], which also verify the file.
pub fn download(ctx: &Ctx, url: &str, dest: &Path, max_bytes: u64, use_proxy: bool) -> Result<u64> {
    download_with(ctx, &process_env, url, dest, max_bytes, use_proxy)
}

/// [`download`] with an injected environment lookup.
pub fn download_with(
    ctx: &Ctx,
    env: EnvLookup,
    url: &str,
    dest: &Path,
    max_bytes: u64,
    use_proxy: bool,
) -> Result<u64> {
    download_paced_with(ctx, env, url, dest, max_bytes, use_proxy, Pace::Bounded)
}

/// [`download_with`] with an explicit [`Pace`]: [`Pace::Progress`] shows
/// curl's progress bar and stops only on the low-speed limit (large
/// packages on slow links). The caller verifies the content (size and
/// SHA-256 from direct metadata) before using it.
pub fn download_paced_with(
    ctx: &Ctx,
    env: EnvLookup,
    url: &str,
    dest: &Path,
    max_bytes: u64,
    use_proxy: bool,
    pace: Pace,
) -> Result<u64> {
    let target = route_target(
        url,
        env("GH_PROXY").as_deref(),
        Route::payload_if(use_proxy),
    )?;
    let file = Transfer::file(url, target, dest, max_bytes);
    transfer(ctx, &Transfer { pace, ..file })
}

/// The shared verified-download path: proxy routing, transfer, check.
fn fetch_to(
    ctx: &Ctx,
    env: EnvLookup,
    url: &str,
    dest: &Path,
    max_bytes: u64,
    route: Route,
    check: Option<Check>,
) -> Result<u64> {
    let target = route_target(url, env("GH_PROXY").as_deref(), route)?;
    let file = Transfer::file(url, target, dest, max_bytes);
    transfer(ctx, &Transfer { check, ..file })
}

/// Release metadata of `repo` (`owner/name`) from api.github.com.
pub fn github_release(ctx: &Ctx, repo: &str, which: &Which) -> Result<Release> {
    github_release_with(ctx, &process_env, repo, which)
}

/// [`github_release`] with an injected environment lookup.
pub fn github_release_with(
    ctx: &Ctx,
    env: EnvLookup,
    repo: &str,
    which: &Which,
) -> Result<Release> {
    let url = release_url(repo, which)?;
    let body = api_get(ctx, env, repo, &url)?;
    Release::parse(&body).with_context(|| format!("{repo} 发行信息无效"))
}

/// One page (1-based) of `repo`'s releases, newest first
/// (`/releases?per_page=N&page=P`, at most [`MAX_PER_PAGE`] per page).
pub fn github_releases(ctx: &Ctx, repo: &str, page: u32, per_page: u32) -> Result<ReleasePage> {
    github_releases_with(ctx, &process_env, repo, page, per_page)
}

/// [`github_releases`] with an injected environment lookup.
pub fn github_releases_with(
    ctx: &Ctx,
    env: EnvLookup,
    repo: &str,
    page: u32,
    per_page: u32,
) -> Result<ReleasePage> {
    let url = releases_url(repo, page, per_page)?;
    let body = api_get(ctx, env, repo, &url)?;
    Release::parse_list(&body).with_context(|| format!("{repo} 发行列表无效"))
}

/// A GitHub API document under `https://api.github.com/repos/{repo}/` as
/// raw JSON, over the same transport as [`github_release`] (direct, API
/// headers, optional `GH_TOKEN`, [`API_MAX_BYTES`] cap, rate-limit hint).
/// For callers that apply their own trust rules to the document (BBR's
/// release manifests); everyone else should use the typed calls.
pub fn github_api_json(ctx: &Ctx, repo: &str, url: &str) -> Result<serde_json::Value> {
    github_api_json_with(ctx, &process_env, repo, url)
}

/// [`github_api_json`] with an injected environment lookup.
pub fn github_api_json_with(
    ctx: &Ctx,
    env: EnvLookup,
    repo: &str,
    url: &str,
) -> Result<serde_json::Value> {
    check_api_url(repo, url)?;
    let body = api_get(ctx, env, repo, url)?;
    serde_json::from_slice(&body)
        .map_err(|e| Error::msg(format!("{repo} 的 GitHub API 响应不是有效 JSON: {e}")))
}

/// GET an API URL (direct, API headers, optional token) into memory.
fn api_get(ctx: &Ctx, env: EnvLookup, repo: &str, url: &str) -> Result<Vec<u8>> {
    let config = env("GH_TOKEN").map(|t| token_config(&t)).transpose()?;
    let dir = TempDir::new("github-api")?;
    let dest = dir.join("response.json");
    let file = Transfer::file(url, url.to_owned(), &dest, API_MAX_BYTES);
    let request = Transfer {
        headers: &API_HEADERS,
        config,
        ..file
    };
    transfer(ctx, &request).map_err(|e| api_error(e, repo))?;
    fs::read_bounded(&dest, API_MAX_BYTES)
}

/// `https://api.github.com/repos/{repo}/releases/{latest|tags/TAG}`.
pub fn release_url(repo: &str, which: &Which) -> Result<String> {
    ensure!(valid_repo(repo), "GitHub 仓库名无效: {repo}");
    Ok(match which {
        Which::Latest => format!("{API}repos/{repo}/releases/latest"),
        Which::Tag(tag) => {
            ensure!(valid_tag(tag), "发行标签无效: {tag}");
            format!("{API}repos/{repo}/releases/tags/{tag}")
        }
    })
}

/// `https://api.github.com/repos/{repo}/releases?per_page=N&page=P`.
pub fn releases_url(repo: &str, page: u32, per_page: u32) -> Result<String> {
    ensure!(valid_repo(repo), "GitHub 仓库名无效: {repo}");
    ensure!(
        page >= 1 && (1..=MAX_PER_PAGE).contains(&per_page),
        "发行列表分页参数无效"
    );
    Ok(format!(
        "{API}repos/{repo}/releases?per_page={per_page}&page={page}"
    ))
}

/// `url` lies below `https://api.github.com/repos/{repo}/`: plain path
/// segments (no `.`/`..`, which curl would resolve into another
/// repository) and a simple query.
fn check_api_url(repo: &str, url: &str) -> Result<()> {
    ensure!(valid_repo(repo), "GitHub 仓库名无效: {repo}");
    let rest = url.strip_prefix(&format!("{API}repos/{repo}/"));
    let ok = rest.is_some_and(|rest| {
        let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
        path.split('/').all(valid_tag_segment)
            && query
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"=&_.-".contains(&b))
    });
    ensure!(ok, "元信息必须来自 api.github.com/repos/{repo}/");
    Ok(())
}

fn valid_segment(s: &str) -> bool {
    !s.is_empty()
        && s != "."
        && s != ".."
        && s.len() <= 100
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

fn valid_repo(repo: &str) -> bool {
    repo.split_once('/')
        .is_some_and(|(owner, name)| valid_segment(owner) && valid_segment(name))
}

/// Tags are interpolated into URLs: one path segment of a safe charset
/// (`v1.14.2`, `testing`, `x86_64-7.2.8-max`, `v1.0.0+build`).
fn valid_tag(tag: &str) -> bool {
    !tag.is_empty() && tag.len() <= 128 && !tag.starts_with(['.', '-']) && valid_tag_segment(tag)
}

/// One URL path segment that is a name or a tag (never `.` or `..`).
fn valid_tag_segment(s: &str) -> bool {
    !s.is_empty()
        && s != "."
        && s != ".."
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
}

/// An absolute `https://` URL without whitespace or control characters.
pub fn check_https(url: &str) -> Result<()> {
    let ok = url.len() > "https://".len()
        && url.starts_with("https://")
        && !url.chars().any(|c| c.is_whitespace() || c.is_control());
    ensure!(ok, "下载地址必须为 HTTPS");
    Ok(())
}

/// The URL curl fetches: github.com payloads behind `GH_PROXY` when
/// `use_proxy`; everything else unchanged. A bad `GH_PROXY` is an error only
/// when it would be used.
pub fn proxied(url: &str, gh_proxy: Option<&str>, use_proxy: bool) -> Result<String> {
    route_target(url, gh_proxy, Route::payload_if(use_proxy))
}

fn route_target(url: &str, gh_proxy: Option<&str>, route: Route) -> Result<String> {
    check_https(url)?;
    match gh_proxy.filter(|p| !p.is_empty()) {
        Some(proxy) if route.proxiable(url) => {
            check_https(proxy).map_err(|_| Error::msg("GH_PROXY 必须为 HTTPS 地址"))?;
            let sep = if proxy.ends_with('/') { "" } else { "/" };
            Ok(format!("{proxy}{sep}{url}"))
        }
        _ => Ok(url.to_owned()),
    }
}

/// curl config carrying the API token (read from stdin with `--config -`).
fn token_config(token: &str) -> Result<String> {
    let ok = !token.is_empty()
        && token.len() <= 255
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b));
    ensure!(ok, "GH_TOKEN 格式无效");
    Ok(format!("header = \"Authorization: Bearer {token}\"\n"))
}

/// Add a rate-limit hint to API failures.
fn api_error(e: Error, repo: &str) -> Error {
    let text = e.to_string();
    let limited = [" 403", " 429"].iter().any(|code| text.contains(code));
    let hint = if limited {
        "（GitHub API 拒绝或限流；可设置 GH_TOKEN 后重试）"
    } else {
        ""
    };
    e.wrap(format!("获取 {repo} 发行信息失败{hint}"))
}

#[cfg(test)]
mod tests;
