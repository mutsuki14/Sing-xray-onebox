//! HTTPS access for BBR: GitHub API metadata and package downloads, behind
//! a trait so tests never touch the network.
//!
//! [`CurlFetcher`] is a thin adapter over `host::fetch`, the one curl
//! transport: metadata comes directly from api.github.com through the
//! shared API path (`host::fetch::github_api_json_with`: API headers,
//! optional `GH_TOKEN` on stdin, 16 MiB cap, never `GH_PROXY`), and
//! packages through `host::fetch::download_paced_with` with `GH_PROXY`
//! allowed and [`Pace::Progress`] (curl's progress bar, bounded by the
//! low-speed limit only). BBR keeps its own trust rules on the raw
//! documents (`super::release`) and verifies every package's size and
//! SHA-256 from that metadata before dpkg sees it (`super::install`).
//!
//! curl is required, and installed only by [`Fetcher::prepare`], which
//! `install --apply` calls before its first request; `status`, `releases`
//! and an install preview never run a package manager (I-8.1#1).
//!
//! Changes from v2: package downloads stream curl's progress bar and use a
//! low-speed limit instead of a 300 s hard cap, so a 100 MB kernel image on
//! a slow link no longer times out (I-8.1#8/#9); API failures name the curl
//! error and suggest `GH_TOKEN` on rate limits (v2 said "invalid
//! response"); `install --apply` installs a missing curl; the wget fallback
//! is gone (wget does not enforce HTTPS on redirects, E-8.1#7).

use super::REPO;
use crate::ctx::Ctx;
use crate::error::Result;
use crate::host::fetch::{self, Pace};
use crate::host::os::process_env;
use serde_json::Value;
use std::path::Path;

pub trait Fetcher {
    /// Make the transport usable before a flow that changes the host
    /// (`install --apply`) sends its first request; `root` is the
    /// session's privilege. Read-only flows never call it.
    fn prepare(&self, ctx: &Ctx, root: bool) -> Result<()> {
        let _ = (ctx, root);
        Ok(())
    }
    /// GET a GitHub API document of the BBR repository (URL under
    /// `https://api.github.com/repos/{REPO}/`).
    fn json(&self, ctx: &Ctx, url: &str) -> Result<Value>;
    /// Download `url` to `dest` (at most `size` bytes).
    fn download(&self, ctx: &Ctx, url: &str, dest: &Path, size: u64) -> Result<()>;
}

/// `host::fetch` with the environment it needs captured once. `Debug`
/// never shows the token (ARCH §1: secrets are not printed).
#[derive(Clone, Default)]
pub struct CurlFetcher {
    /// `GH_PROXY` prefix for package downloads.
    pub gh_proxy: Option<String>,
    /// `GH_TOKEN` for API requests (higher rate limits).
    pub gh_token: Option<String>,
}

impl std::fmt::Debug for CurlFetcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CurlFetcher")
            .field("gh_proxy", &self.gh_proxy)
            .field("gh_token", &self.gh_token.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl CurlFetcher {
    pub fn from_env() -> CurlFetcher {
        CurlFetcher {
            gh_proxy: process_env("GH_PROXY"),
            gh_token: process_env("GH_TOKEN"),
        }
    }

    /// The captured variables as `host::fetch` looks them up.
    fn env(&self, key: &str) -> Option<String> {
        match key {
            "GH_PROXY" => self.gh_proxy.clone(),
            "GH_TOKEN" => self.gh_token.clone(),
            _ => None,
        }
    }
}

impl Fetcher for CurlFetcher {
    /// Install a missing curl as root (`host::fetch::ensure_curl_as`).
    fn prepare(&self, ctx: &Ctx, root: bool) -> Result<()> {
        fetch::ensure_curl_as(ctx, root)
    }

    fn json(&self, ctx: &Ctx, url: &str) -> Result<Value> {
        fetch::github_api_json_with(ctx, &|k| self.env(k), REPO, url)
    }

    fn download(&self, ctx: &Ctx, url: &str, dest: &Path, size: u64) -> Result<()> {
        let env = |k: &str| self.env(k);
        fetch::download_paced_with(ctx, &env, url, dest, size, true, Pace::Progress).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::fetch::testing::{output_arg, serve, url_arg, Reply};
    use crate::sys::exec::Output;
    use crate::sys::fs::TempDir;

    const PACKAGE: &str =
        "https://github.com/byJoey/Actions-bbr-v3/releases/download/x86_64-7.2.8/pkg.deb";

    fn proxied() -> CurlFetcher {
        CurlFetcher {
            gh_proxy: Some("https://gh.example/".into()),
            gh_token: Some("tok3n".into()),
        }
    }

    #[test]
    fn api_requests_are_direct_and_stay_in_the_bbr_repository() {
        let dir = TempDir::new("bbr-net").unwrap();
        let (ctx, exec, _) = Ctx::test(dir.path());
        let url = super::super::release::list_url(1);
        serve(&exec, vec![(url.clone(), Reply::body("[]"))]);
        assert_eq!(proxied().json(&ctx, &url).unwrap(), serde_json::json!([]));
        let call = &exec.calls()[0];
        assert_eq!(url_arg(call), url, "never proxied");
        let line = call.display();
        for flag in ["--proto =https", "--proto-redir =https", "--max-filesize"] {
            assert!(line.contains(flag), "{flag}");
        }
        assert!(line.contains("--config -") && !line.contains("tok3n"));
        assert!(call.timeout.is_some() && !call.stream);
        for bad in [
            "https://github.com/x",
            "http://api.github.com/repos/byJoey/Actions-bbr-v3/releases",
            "https://api.github.com/repos/other/repo/releases",
        ] {
            let err = proxied().json(&ctx, bad).unwrap_err();
            assert_eq!(
                err.to_string(),
                "元信息必须来自 api.github.com/repos/byJoey/Actions-bbr-v3/"
            );
        }
        assert_eq!(exec.calls().len(), 1, "refused URLs are never requested");
    }

    #[test]
    fn api_failures_explain_rate_limits() {
        let dir = TempDir::new("bbr-net").unwrap();
        let (ctx, exec, _) = Ctx::test(dir.path());
        let url = super::super::release::tag_url("x86_64-7.2.8");
        serve(&exec, vec![(url.clone(), Reply::http(403))]);
        let err = CurlFetcher::default().json(&ctx, &url).unwrap_err();
        assert!(err.to_string().contains("可设置 GH_TOKEN 后重试"), "{err}");
    }

    #[test]
    fn package_downloads_may_use_gh_proxy_and_show_progress() {
        let dir = TempDir::new("bbr-net").unwrap();
        let (ctx, exec, _) = Ctx::test(dir.path());
        let via = format!("https://gh.example/{PACKAGE}");
        serve(&exec, vec![(via.clone(), Reply::body("deb"))]);
        let dest = dir.join("pkg.deb");
        proxied().download(&ctx, PACKAGE, &dest, 3).unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"deb");
        let call = &exec.calls()[0];
        assert_eq!(url_arg(call), via);
        assert_ne!(
            output_arg(call).as_deref(),
            Some(dest.as_path()),
            "temp file"
        );
        assert!(call.stream && call.args.iter().any(|a| a == "--progress-bar"));
        assert!(call.args.windows(2).any(|w| w == ["--max-filesize", "3"]));
        assert!(!call.args.iter().any(|a| a == "--max-time"));
        assert!(!call.display().contains("tok3n"), "no token for packages");

        // Empty and oversized answers never reach the destination.
        let (ctx, exec, _) = Ctx::test(dir.path());
        serve(&exec, vec![(PACKAGE.to_owned(), Reply::body(""))]);
        let empty = dir.join("empty.deb");
        let err = CurlFetcher::default()
            .download(&ctx, PACKAGE, &empty, 3)
            .unwrap_err();
        assert_eq!(err.to_string(), format!("下载内容为空: {PACKAGE}"));
        assert!(!empty.exists());
        let bad_proxy = CurlFetcher {
            gh_proxy: Some("http://insecure".into()),
            gh_token: None,
        };
        let err = bad_proxy.download(&ctx, PACKAGE, &empty, 3).unwrap_err();
        assert_eq!(err.to_string(), "GH_PROXY 必须为 HTTPS 地址");
    }

    #[test]
    fn debug_output_redacts_the_token() {
        let shown = format!("{:?}", proxied());
        assert_eq!(
            shown,
            r#"CurlFetcher { gh_proxy: Some("https://gh.example/"), gh_token: Some("<redacted>") }"#
        );
        assert!(!format!("{:#?}", proxied()).contains("tok3n"));
        let none = format!("{:?}", CurlFetcher::default());
        assert!(none.contains("gh_token: None"), "{none}");
    }

    #[test]
    fn only_prepare_installs_curl() {
        // Lookups as root on a host without curl: a hint, no package manager.
        let dir = TempDir::new("bbr-net").unwrap();
        let (ctx, exec, _) = Ctx::test(dir.path());
        exec.provide("apt-get");
        let url = super::super::release::list_url(1);
        let err = proxied().json(&ctx, &url).unwrap_err();
        assert!(err.to_string().ends_with("请先安装 curl"), "{err}");
        let err = proxied()
            .download(&ctx, PACKAGE, &dir.join("pkg.deb"), 3)
            .unwrap_err();
        assert_eq!(err.to_string(), "请先安装 curl");
        assert!(exec.history().is_empty(), "{:?}", exec.history());

        // `prepare` (install --apply) installs it as root ...
        exec.on("apt-get", &[], Output::success(""));
        let err = proxied().prepare(&ctx, true).unwrap_err();
        assert_eq!(err.to_string(), "安装后仍未找到 curl");
        assert!(exec
            .history()
            .iter()
            .any(|c| c.ends_with("install -y curl")));
        // ... asks for it otherwise, and is a no-op once curl exists.
        exec.clear_history();
        let err = proxied().prepare(&ctx, false).unwrap_err();
        assert_eq!(err.to_string(), "请先安装 curl");
        exec.provide("curl");
        proxied().prepare(&ctx, true).unwrap();
        assert!(exec.history().is_empty());
    }

    #[test]
    fn environment_is_captured_once() {
        let fetcher = proxied();
        assert_eq!(
            fetcher.env("GH_PROXY").as_deref(),
            Some("https://gh.example/")
        );
        assert_eq!(fetcher.env("GH_TOKEN").as_deref(), Some("tok3n"));
        assert_eq!(fetcher.env("HOME"), None);
    }
}
