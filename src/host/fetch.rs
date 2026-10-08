//! HTTPS downloads through curl and GitHub release metadata.
//!
//! Every transfer is `curl --proto =https --proto-redir =https --tlsv1.2
//! -fLsS` (HTTPS only, also across redirects), into a temp file next to the
//! destination that is renamed into place only after the size cap, the
//! non-emptiness check and, for verified downloads, the hash check; partial
//! or unverified files are removed on every error.
//!
//! Proxy policy (`GH_PROXY`: an `https://` prefix, no whitespace), one rule
//! for every caller:
//! - API metadata (api.github.com) and release checksum files
//!   (`SHA256SUMS`, `.dgst`) always go direct. They authenticate payloads;
//!   for assets the API has no digest for (older releases) the checksum
//!   file is the only trust anchor, so a mirror must never be able to swap
//!   it together with the payload.
//! - release payloads from `https://github.com/` may use the proxy: their
//!   size and SHA-256 are known from direct sources before the download
//!   ([`download_asset`]).
//! - files whose SHA-256 is pinned in the code may also be fetched from
//!   `https://raw.githubusercontent.com/` through the proxy
//!   ([`download_pinned`]).
//!
//! `GH_TOKEN`, when set, authenticates API requests (higher rate limits);
//! it is handed to curl on stdin, never on the command line.
//!
//! Changes from v2:
//! - curl only: wget's `--https-only` does not apply to redirects
//!   (E-8.1#7), so there is no wget fallback.
//! - transfer limits scale with the expected size (`--max-time` from a
//!   32 KiB/s floor, `--speed-limit` 1 KiB/s over 60 s) instead of a fixed
//!   300 s that failed on slow links; every download has a byte cap
//!   (`--max-filesize` plus a check of the result).
//! - TLS 1.2 minimum; 15 s connect timeout.
//! - one verification chain for every release download
//!   ([`download_asset`]): the API digest is preferred and a release
//!   `SHA256SUMS`/`.dgst` is the fallback when the API has none (G-8.1#6);
//!   the checksum file must match its metadata size, and the payload is
//!   fetched only once its expected hash is known.
//! - release lists ([`github_releases`]) share the API transport, token and
//!   rate-limit handling.
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

pub use asset::{
    download_asset, download_asset_with, download_pinned, download_pinned_with, release_checksums,
    release_checksums_with, ChecksumMatch,
};
pub use release::{
    check_elf, checksum_for, is_elf, verify_file, Asset, Release, ReleasePage, Which,
};

use crate::ctx::Ctx;
use crate::error::{Context, Error, Result};
use crate::host::os::{process_env, EnvLookup};
use crate::sys::exec::{Cmd, Output};
use crate::sys::fs::{self, TempDir, TEMP_PREFIX};
use std::path::{Path, PathBuf};
use std::time::Duration;

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
/// Throughput floor used to derive `--max-time` from the size cap.
const MIN_RATE: u64 = 32 * 1024;
/// curl aborts a transfer slower than this many bytes/s for `STALL_SECS`.
const STALL_RATE: u64 = 1024;
const STALL_SECS: u64 = 60;
const MIN_MAX_TIME: u64 = 120;
const MAX_MAX_TIME: u64 = 2 * 60 * 60;
const RETRIES: u64 = 2;

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
}

/// Inspects the downloaded temp file before it is renamed into place.
type Check<'a> = &'a dyn Fn(&Path) -> Result<()>;

/// One curl transfer into `dest`.
struct Transfer<'a> {
    /// What the user asked for (used in messages).
    url: &'a str,
    /// What curl fetches (`url`, possibly behind `GH_PROXY`).
    target: String,
    dest: &'a Path,
    max_bytes: u64,
    headers: &'a [&'a str],
    /// curl config read from stdin (secret headers).
    config: Option<String>,
    check: Option<Check<'a>>,
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
    let route = if use_proxy {
        Route::Payload
    } else {
        Route::Direct
    };
    fetch_to(ctx, env, url, dest, max_bytes, route, None)
}

/// The shared download path: proxy routing, transfer, optional check.
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
    transfer(
        ctx,
        &Transfer {
            url,
            target,
            dest,
            max_bytes,
            headers: &[],
            config: None,
            check,
        },
    )
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

/// GET an API URL (direct, API headers, optional token) into memory.
fn api_get(ctx: &Ctx, env: EnvLookup, repo: &str, url: &str) -> Result<Vec<u8>> {
    let config = env("GH_TOKEN").map(|t| token_config(&t)).transpose()?;
    let dir = TempDir::new("github-api")?;
    let dest = dir.join("response.json");
    let fetched = transfer(
        ctx,
        &Transfer {
            url,
            target: url.to_owned(),
            dest: &dest,
            max_bytes: API_MAX_BYTES,
            headers: &API_HEADERS,
            config,
            check: None,
        },
    );
    fetched.map_err(|e| api_error(e, repo))?;
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
    !tag.is_empty()
        && tag.len() <= 128
        && !tag.starts_with(['.', '-'])
        && tag
            .bytes()
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
    let route = if use_proxy {
        Route::Payload
    } else {
        Route::Direct
    };
    route_target(url, gh_proxy, route)
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

/// `--max-time` for a transfer of at most `max_bytes`.
pub fn max_time(max_bytes: u64) -> Duration {
    let secs = 60 + max_bytes / MIN_RATE;
    Duration::from_secs(secs.clamp(MIN_MAX_TIME, MAX_MAX_TIME))
}

fn curl_cmd(t: &Transfer, output: &Path) -> Cmd {
    let limit = max_time(t.max_bytes);
    let mut cmd = Cmd::new("curl").args([
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
        "--tlsv1.2",
        "-fLsS",
        "--connect-timeout",
        "15",
    ]);
    cmd = cmd
        .args(["--max-time".to_string(), limit.as_secs().to_string()])
        .args(["--speed-limit".to_string(), STALL_RATE.to_string()])
        .args(["--speed-time".to_string(), STALL_SECS.to_string()])
        .args(["--retry".to_string(), RETRIES.to_string()])
        .args(["--max-filesize".to_string(), t.max_bytes.to_string()]);
    for header in t.headers {
        cmd = cmd.args(["-H", header]);
    }
    if let Some(config) = &t.config {
        cmd = cmd.args(["--config", "-"]).stdin_bytes(config.as_bytes());
    }
    // Hard bound for curl itself: every attempt may use its full budget.
    let hard = limit * (RETRIES as u32 + 1) + Duration::from_secs(30);
    cmd.arg("--output")
        .arg(output.to_string_lossy())
        .arg(&t.target)
        .timeout(hard)
}

fn transfer(ctx: &Ctx, t: &Transfer) -> Result<u64> {
    check_https(t.url)?;
    ensure!(t.max_bytes > 0, "下载大小上限无效");
    ensure!(ctx.has("curl"), "请先安装 curl");
    let parent = t
        .dest
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| Error::msg("下载目标缺少目录"))?;
    if !parent.exists() {
        fs::ensure_dir(parent, 0o700)?;
    }
    let tmp = temp_path(parent)?;
    let result = run_curl(ctx, t, &tmp).and_then(|()| finish(&tmp, t));
    if result.is_err() {
        let _ = fs::remove_file_if_exists(&tmp);
    }
    result
}

fn temp_path(dir: &Path) -> Result<PathBuf> {
    Ok(dir.join(format!(
        "{TEMP_PREFIX}download-{}",
        crate::sys::rand::hex(12)?
    )))
}

fn run_curl(ctx: &Ctx, t: &Transfer, output: &Path) -> Result<()> {
    let out = ctx.run(&curl_cmd(t, output))?;
    if out.ok() {
        Ok(())
    } else {
        Err(curl_error(t, &out))
    }
}

/// A Chinese message for a failed curl run (exit codes from curl(1)).
fn curl_error(t: &Transfer, out: &Output) -> Error {
    let via = if t.target != t.url {
        "（经 GH_PROXY）"
    } else {
        ""
    };
    let detail = last_line(&out.stderr);
    let message = match out.code {
        63 => format!(
            "下载内容超过大小上限（{} 字节）: {}{via}",
            t.max_bytes, t.url
        ),
        28 => format!("下载超时: {}{via}", t.url),
        crate::sys::exec::TIMEOUT_EXIT => format!("下载超时（已终止 curl）: {}{via}", t.url),
        _ if detail.is_empty() => format!("下载失败 (curl {}): {}{via}", out.code, t.url),
        _ => format!("下载失败: {}{via}: {detail}", t.url),
    };
    Error::msg(message)
}

fn last_line(text: &str) -> String {
    let line = text
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("");
    line.chars()
        .filter(|c| !c.is_control())
        .take(300)
        .collect::<String>()
        .trim()
        .to_string()
}

/// Size checks, then rename the temp file into place.
fn finish(tmp: &Path, t: &Transfer) -> Result<u64> {
    let size = match std::fs::symlink_metadata(tmp) {
        Ok(m) if m.is_file() => m.len(),
        Ok(_) => return Err(Error::msg("下载结果不是普通文件")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(e) => return Err(Error::io(tmp, e)),
    };
    ensure!(size > 0, "下载内容为空: {}", t.url);
    ensure!(
        size <= t.max_bytes,
        "下载内容超过大小上限（{} 字节）: {}",
        t.max_bytes,
        t.url
    );
    if let Some(check) = t.check {
        check(tmp)?;
    }
    // Durable before it becomes visible under the final name.
    std::fs::File::open(tmp)
        .and_then(|f| f.sync_all())
        .map_err(|e| Error::io(tmp, e))?;
    std::fs::rename(tmp, t.dest).map_err(|e| Error::io(t.dest, e))?;
    if let Some(parent) = t.dest.parent() {
        fs::fsync_dir(parent).map_err(|e| Error::io(parent, e))?;
    }
    Ok(size)
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
