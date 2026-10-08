//! The curl transport through the public download calls.

use super::super::testing::{output_arg, routes, serve, url_arg, Reply};
use super::super::{download_paced_with, download_with};
use super::*;
use crate::sys::exec::{FakeExec, Output, Stdin};
use crate::sys::fs::TempDir;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

const ASSET_URL: &str =
    "https://github.com/mutsuki14/Sing-xray-onebox/releases/download/v2.0.1/onebox-linux-amd64-musl";

fn no_env(_: &str) -> Option<String> {
    None
}

fn env_with(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
    move |key| {
        pairs
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.to_string())
    }
}

fn setup() -> (TempDir, Ctx, Arc<FakeExec>) {
    let dir = TempDir::new("fetch-transfer").unwrap();
    let (ctx, exec, _) = Ctx::test(dir.path());
    (dir, ctx, exec)
}

fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn transfer_budget_scales_with_size() {
    assert_eq!(max_time(1024).as_secs(), 120, "floor");
    assert_eq!(max_time(32 * 1024 * 1024).as_secs(), 60 + 1024);
    assert_eq!(max_time(u64::MAX).as_secs(), 7200, "ceiling");
}

// ---- downloads ----------------------------------------------------------

#[test]
fn download_writes_atomically_with_exact_curl_arguments() {
    let (_d, ctx, exec) = setup();
    serve(&exec, routes([(ASSET_URL, Reply::body("binary"))]));
    let dest = ctx.paths.bin.join("new/pkg");
    let size = download_with(&ctx, &no_env, ASSET_URL, &dest, 1024, true).unwrap();
    assert_eq!(size, 6);
    assert_eq!(std::fs::read(&dest).unwrap(), b"binary");
    assert_eq!(entries(dest.parent().unwrap()), ["pkg"], "no temp left");
    let parent_mode = std::fs::metadata(dest.parent().unwrap())
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(parent_mode & 0o777, 0o700);

    let cmd = &exec.calls()[0];
    let tmp = output_arg(cmd).unwrap();
    assert!(tmp
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with(".onebox-tmp-download-"));
    assert_eq!(tmp.parent(), dest.parent());
    assert_eq!(
        cmd.display(),
        format!(
            "curl --proto =https --proto-redir =https --tlsv1.2 -fLsS --connect-timeout 15 \
             --max-time 120 --speed-limit 1024 --speed-time 60 --retry 2 --max-filesize 1024 \
             --output {} {ASSET_URL}",
            tmp.display()
        )
    );
    assert_eq!(cmd.timeout, Some(Duration::from_secs(390)));
    assert_eq!(cmd.stdin, Stdin::Null);
}

#[test]
fn download_uses_gh_proxy_only_for_payloads() {
    let (_d, ctx, exec) = setup();
    let proxied_url = format!("https://ghproxy.example/{ASSET_URL}");
    serve(&exec, vec![(proxied_url.clone(), Reply::body("via proxy"))]);
    let env = env_with(&[("GH_PROXY", "https://ghproxy.example")]);
    let dest = ctx.paths.bin.join("pkg");
    download_with(&ctx, &env, ASSET_URL, &dest, 100, true).unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), b"via proxy");
    assert_eq!(url_arg(&exec.calls()[0]), proxied_url);
    // Without `use_proxy` the original URL is fetched (and 404s here).
    let err = download_with(&ctx, &env, ASSET_URL, &dest, 100, false).unwrap_err();
    assert_eq!(
        err.to_string(),
        format!("下载失败: {ASSET_URL}: curl: (22) The requested URL returned error: 404")
    );
}

#[test]
fn download_failures_leave_nothing_behind() {
    let (_d, ctx, exec) = setup();
    let url = |p: &str| format!("https://github.com/o/r/releases/download/v1/{p}");
    serve(
        &exec,
        vec![
            (url("big"), Reply::body(vec![1u8; 11])),
            (url("empty"), Reply::body("")),
            (
                url("cap"),
                Reply::Fail(63, "curl: (63) Maximum file size exceeded".into()),
            ),
            (
                url("slow"),
                Reply::Fail(28, "curl: (28) Operation timed out".into()),
            ),
            (url("quiet"), Reply::Fail(6, String::new())),
        ],
    );
    let dir = ctx.paths.bin.clone();
    std::fs::create_dir_all(&dir).unwrap();
    let dest = dir.join("pkg");
    std::fs::write(&dest, b"old").unwrap();
    let cases = [
        (
            "big",
            format!("下载内容超过大小上限（10 字节）: {}", url("big")),
        ),
        ("empty", format!("下载内容为空: {}", url("empty"))),
        (
            "cap",
            format!("下载内容超过大小上限（10 字节）: {}", url("cap")),
        ),
        ("slow", format!("下载超时: {}", url("slow"))),
        ("quiet", format!("下载失败 (curl 6): {}", url("quiet"))),
    ];
    for (name, want) in cases {
        let err = download_with(&ctx, &no_env, &url(name), &dest, 10, true).unwrap_err();
        assert_eq!(err.to_string(), want);
        assert_eq!(entries(&dir), ["pkg"], "{name}: temp removed");
        assert_eq!(std::fs::read(&dest).unwrap(), b"old", "{name}: dest kept");
    }
}

#[test]
fn download_preconditions() {
    let (_d, ctx, exec) = setup();
    let dest = ctx.paths.bin.join("pkg");
    // Without curl and without a package manager: as root the install is
    // attempted (and fails here), otherwise the user is asked (G14).
    let err = download_with(&ctx, &no_env, ASSET_URL, &dest, 10, true).unwrap_err();
    assert!(err.to_string().ends_with("请先安装 curl"), "{err}");
    exec.provide("curl");
    let cases = [
        (
            "http://example.com/x",
            dest.clone(),
            10,
            "下载地址必须为 HTTPS",
        ),
        (ASSET_URL, dest.clone(), 0, "下载大小上限无效"),
        (ASSET_URL, PathBuf::from("pkg"), 10, "下载目标缺少目录"),
    ];
    for (url, dest, max, want) in cases {
        let err = download_with(&ctx, &no_env, url, &dest, max, true).unwrap_err();
        assert_eq!(err.to_string(), want);
    }
    assert!(exec.history().is_empty());
}

#[test]
fn curl_is_installed_on_demand() {
    // Present: nothing runs, whoever we are.
    let (_d, ctx, exec) = setup();
    exec.provide("curl");
    ensure_curl_as(&ctx, false).unwrap();
    assert!(exec.history().is_empty());

    // Missing and not root: ask for it, install nothing.
    let (_d, ctx, exec) = setup();
    exec.provide("apt-get");
    let err = ensure_curl_as(&ctx, false).unwrap_err();
    assert_eq!(err.to_string(), "请先安装 curl");
    assert!(exec.history().is_empty());

    // Missing as root: the distro package is installed.
    let (_d, ctx, exec) = setup();
    exec.provide("apt-get")
        .on("apt-get", &["update"], Output::success(""));
    let fake = Arc::clone(&exec);
    exec.on_fn(
        |c| c.program == "apt-get" && c.args.last().is_some_and(|a| a == "curl"),
        move |_| {
            fake.provide("curl");
            Ok(Output::success(""))
        },
    );
    ensure_curl_as(&ctx, true).unwrap();
    let history = exec.history();
    assert_eq!(history.len(), 2, "{history:?}");
    assert_eq!(history[0], "apt-get update");
    assert!(history[1].ends_with("install -y curl"), "{}", history[1]);
    assert!(ctx.has("curl"));

    // A failed install is reported as such.
    let (_d, ctx, exec) = setup();
    exec.provide("apk").on("apk", &[], Output::failure(1, ""));
    let err = ensure_curl_as(&ctx, true).unwrap_err();
    assert_eq!(err.to_string(), "安装 curl 失败: apk 执行失败 (1)");
}

#[test]
fn transfers_require_curl_but_never_install_it() {
    // Read-only lookups (previews, update checks) as root on a host
    // without curl: a hint, no package manager run (I-8.1#1).
    let (_d, ctx, exec) = setup();
    exec.provide("apt-get");
    let dest = ctx.paths.bin.join("pkg");
    let err = download_with(&ctx, &no_env, ASSET_URL, &dest, 10, true).unwrap_err();
    assert_eq!(err.to_string(), "请先安装 curl");
    let which = super::super::Which::Latest;
    let err =
        super::super::github_release_with(&ctx, &no_env, "SagerNet/sing-box", &which).unwrap_err();
    assert!(err.to_string().ends_with(": 请先安装 curl"), "{err}");
    assert!(exec.history().is_empty(), "{:?}", exec.history());
    assert!(!dest.exists());
    require_curl(&ctx).unwrap_err();
    exec.provide("curl");
    require_curl(&ctx).unwrap();
}

#[test]
fn progress_pace_streams_without_a_total_time_limit() {
    let (_d, ctx, exec) = setup();
    let env = env_with(&[("GH_PROXY", "https://ghproxy.example")]);
    let dest = ctx.paths.bin.join("pkg.deb");
    let proxied_url = format!("https://ghproxy.example/{ASSET_URL}");
    serve(&exec, vec![(proxied_url.clone(), Reply::body("kernel"))]);
    let size = download_paced_with(
        &ctx,
        &env,
        ASSET_URL,
        &dest,
        100 << 20,
        true,
        Pace::Progress,
    )
    .unwrap();
    assert_eq!(size, 6);
    assert_eq!(std::fs::read(&dest).unwrap(), b"kernel");
    let cmd = &exec.calls()[0];
    let tmp = output_arg(cmd).unwrap();
    assert_eq!(
        cmd.display(),
        format!(
            "curl --proto =https --proto-redir =https --tlsv1.2 -fL --progress-bar \
             --connect-timeout 15 --speed-limit 1024 --speed-time 60 --retry 2 \
             --max-filesize {} --output {} {proxied_url}",
            100u64 << 20,
            tmp.display()
        )
    );
    assert!(cmd.stream, "the progress bar reaches the terminal");
    // The hard bound only backs up curl's own low-speed abort.
    let slowest = (100u64 << 20) / 1024 + 60 + 60;
    assert_eq!(cmd.timeout, Some(Duration::from_secs(slowest * 3 + 30)));
    // The default pace keeps the quiet, time-limited transfer.
    assert_eq!(Pace::default(), Pace::Bounded);
}
