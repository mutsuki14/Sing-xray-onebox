//! HTTPS access for BBR: GitHub API metadata and package downloads, behind
//! a trait so tests never touch the network.
//!
//! [`CurlFetcher`] is a small curl adapter local to BBR (the shared
//! `host::fetch` layer was built in parallel); it keeps v2's rules: HTTPS
//! only, also for redirects; metadata only from api.github.com and never
//! through `GH_PROXY`; packages may use `GH_PROXY`.
//!
//! Changes from v2: package downloads stream curl's progress bar and use a
//! low-speed limit instead of a 300 s hard cap, so a 100 MB kernel image on
//! a slow link no longer times out (I-8.1#8/#9); API errors report GitHub's
//! HTTP status and message (rate limits were an opaque "invalid response");
//! the wget fallback is gone (wget does not enforce HTTPS on redirects,
//! E-8.1#7).

use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::sys::exec::Cmd;
use serde_json::Value;
use std::path::Path;
use std::time::Duration;

/// API responses larger than this are refused.
const MAX_API_BYTES: u64 = 16 << 20;
const API_PREFIX: &str = "https://api.github.com/";

pub trait Fetcher {
    /// GET a GitHub API document (URL must be on api.github.com).
    fn json(&self, ctx: &Ctx, url: &str) -> Result<Value>;
    /// Download `url` to `dest` (at most `size` bytes).
    fn download(&self, ctx: &Ctx, url: &str, dest: &Path, size: u64) -> Result<()>;
}

/// curl through `Ctx::exec`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CurlFetcher {
    /// `GH_PROXY` prefix for package downloads.
    pub gh_proxy: Option<String>,
}

impl CurlFetcher {
    pub fn from_env() -> CurlFetcher {
        CurlFetcher {
            gh_proxy: std::env::var("GH_PROXY").ok().filter(|p| !p.is_empty()),
        }
    }

    /// The URL actually requested for a package.
    pub fn package_url(&self, url: &str) -> Result<String> {
        if !valid_https(url) {
            return Err(Error::msg("下载地址必须为 HTTPS"));
        }
        let Some(proxy) = &self.gh_proxy else {
            return Ok(url.to_string());
        };
        if !valid_https(proxy) {
            return Err(Error::msg("GH_PROXY 必须为 HTTPS 地址"));
        }
        let slash = if proxy.ends_with('/') { "" } else { "/" };
        Ok(format!("{proxy}{slash}{url}"))
    }
}

fn valid_https(url: &str) -> bool {
    url.starts_with("https://") && !url.chars().any(|c| c.is_whitespace() || c == '\0')
}

fn require_curl(ctx: &Ctx) -> Result<()> {
    if ctx.has("curl") {
        Ok(())
    } else {
        Err(Error::msg("请先安装 curl"))
    }
}

/// Shared curl safety options: HTTPS only (also after redirects).
const CURL_BASE: [&str; 9] = [
    "--silent",
    "--show-error",
    "--location",
    "--proto",
    "=https",
    "--proto-redir",
    "=https",
    "--connect-timeout",
    "10",
];

impl Fetcher for CurlFetcher {
    fn json(&self, ctx: &Ctx, url: &str) -> Result<Value> {
        if !url.starts_with(API_PREFIX) || !valid_https(url) {
            return Err(Error::msg("元信息必须来自 api.github.com"));
        }
        require_curl(ctx)?;
        let cmd = Cmd::new("curl")
            .args(CURL_BASE)
            .args([
                "--max-time",
                "60",
                "--retry",
                "2",
                "--max-filesize",
                MAX_API_BYTES.to_string().as_str(),
                "--header",
                "Accept: application/vnd.github+json",
                "--write-out",
                "\n%{http_code}",
                url,
            ])
            .timeout(Duration::from_secs(200));
        let body = ctx.check(&cmd)?;
        parse_api_response(&body)
    }

    fn download(&self, ctx: &Ctx, url: &str, dest: &Path, size: u64) -> Result<()> {
        let target = self.package_url(url)?;
        require_curl(ctx)?;
        let cmd = Cmd::new("curl")
            .args(CURL_BASE.iter().skip(1).copied())
            .args([
                "--fail",
                "--progress-bar",
                "--speed-limit",
                "1024",
                "--speed-time",
                "60",
                "--retry",
                "2",
                "--max-filesize",
            ])
            .arg(size.to_string())
            .arg("--output")
            .arg(dest.to_string_lossy())
            .arg(target)
            .stream();
        ctx.check(&cmd)?;
        let written = std::fs::symlink_metadata(dest)
            .map(|m| m.len())
            .unwrap_or(0);
        if written == 0 {
            return Err(Error::msg("下载内容为空"));
        }
        Ok(())
    }
}

/// Split curl's `--write-out "\n%{http_code}"` trailer off the body and
/// turn non-200 answers into errors carrying GitHub's message.
pub fn parse_api_response(output: &str) -> Result<Value> {
    let (body, status) = output
        .rsplit_once('\n')
        .ok_or_else(|| Error::msg("GitHub API 响应无效"))?;
    if body.len() as u64 > MAX_API_BYTES {
        return Err(Error::msg("API 响应过大"));
    }
    let status = status.trim();
    let doc: Option<Value> = serde_json::from_str(body).ok();
    if status == "200" {
        return doc.ok_or_else(|| Error::msg("GitHub API 响应不是有效 JSON"));
    }
    let message = doc
        .as_ref()
        .and_then(|d| d["message"].as_str())
        .unwrap_or("")
        .to_string();
    let limited = matches!(status, "403" | "429") && message.to_lowercase().contains("rate limit");
    Err(Error::msg(match (limited, message.is_empty()) {
        (true, _) => format!("GitHub API 限流，请稍后重试或指定完整 Release 标签: {message}"),
        (false, true) => format!("GitHub API 请求失败 (HTTP {status})"),
        (false, false) => format!("GitHub API 请求失败 (HTTP {status}): {message}"),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::exec::Output;
    use crate::sys::fs::TempDir;

    #[test]
    fn api_responses_and_errors() {
        let ok = parse_api_response("[{\"tag_name\":\"x\"}]\n200").unwrap();
        assert_eq!(ok[0]["tag_name"], "x");
        let limited =
            parse_api_response("{\"message\":\"API rate limit exceeded for 203.0.113.1.\"}\n403")
                .unwrap_err();
        assert_eq!(
            limited.to_string(),
            "GitHub API 限流，请稍后重试或指定完整 Release 标签: API rate limit exceeded for 203.0.113.1."
        );
        assert_eq!(
            parse_api_response("{\"message\":\"Not Found\"}\n404")
                .unwrap_err()
                .to_string(),
            "GitHub API 请求失败 (HTTP 404): Not Found"
        );
        assert_eq!(
            parse_api_response("<html>\n502").unwrap_err().to_string(),
            "GitHub API 请求失败 (HTTP 502)"
        );
        assert!(parse_api_response("not json\n200").is_err());
        assert!(parse_api_response("200").is_err());
    }

    #[test]
    fn api_requests_are_direct_https_with_curl() {
        let dir = TempDir::new("bbr-net").unwrap();
        let (ctx, exec, _) = Ctx::test(dir.path());
        let fetcher = CurlFetcher {
            gh_proxy: Some("https://proxy.example".into()),
        };
        for bad in ["https://github.com/x", "http://api.github.com/x"] {
            assert_eq!(
                fetcher.json(&ctx, bad).unwrap_err().to_string(),
                "元信息必须来自 api.github.com"
            );
        }
        assert_eq!(
            fetcher
                .json(&ctx, "https://api.github.com/x")
                .unwrap_err()
                .to_string(),
            "请先安装 curl"
        );
        exec.provide("curl");
        exec.on("curl", &[], Output::success("[]\n200"));
        let url = "https://api.github.com/repos/byJoey/Actions-bbr-v3/releases?per_page=100&page=1";
        assert_eq!(fetcher.json(&ctx, url).unwrap(), serde_json::json!([]));
        let call = &exec.calls()[0];
        assert_eq!(
            call.args.last().map(String::as_str),
            Some(url),
            "never proxied"
        );
        for flag in ["--proto", "=https", "--proto-redir", "--max-filesize"] {
            assert!(call.args.iter().any(|a| a == flag), "{flag}");
        }
        assert!(call.timeout.is_some());
    }

    #[test]
    fn package_downloads_may_use_gh_proxy() {
        let dir = TempDir::new("bbr-net").unwrap();
        let (ctx, exec, _) = Ctx::test(dir.path());
        exec.provide("curl");
        let dest = dir.join("pkg.deb");
        let written = dest.clone();
        exec.on_fn(
            |c| c.program == "curl",
            move |_| {
                std::fs::write(&written, b"deb").unwrap();
                Ok(Output::success(""))
            },
        );
        let url = "https://github.com/byJoey/Actions-bbr-v3/releases/download/t/pkg.deb";
        let fetcher = CurlFetcher {
            gh_proxy: Some("https://gh.example/".into()),
        };
        fetcher.download(&ctx, url, &dest, 3).unwrap();
        let call = &exec.calls()[0];
        assert_eq!(
            call.args.last().map(String::as_str),
            Some(format!("https://gh.example/{url}").as_str())
        );
        assert!(call.stream && call.args.contains(&"--fail".to_string()));
        assert!(call.args.windows(2).any(|w| w == ["--max-filesize", "3"]));
        assert_eq!(
            CurlFetcher {
                gh_proxy: Some("http://insecure".into())
            }
            .package_url(url)
            .unwrap_err()
            .to_string(),
            "GH_PROXY 必须为 HTTPS 地址"
        );
        assert_eq!(
            CurlFetcher::default().package_url(url).unwrap(),
            url,
            "no proxy configured"
        );
        assert!(CurlFetcher::default().package_url("http://x").is_err());
        std::fs::remove_file(&dest).unwrap();
        exec.on("curl", &[], Output::success(""));
        let (ctx2, exec2, _) = Ctx::test(dir.path());
        exec2.provide("curl").on("curl", &[], Output::success(""));
        assert_eq!(
            CurlFetcher::default()
                .download(&ctx2, url, &dir.join("empty.deb"), 3)
                .unwrap_err()
                .to_string(),
            "下载内容为空"
        );
        drop(ctx);
    }
}
