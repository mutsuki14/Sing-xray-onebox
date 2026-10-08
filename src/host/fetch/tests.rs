use super::testing::{output_arg, routes, serve, url_arg, Reply};
use super::*;
use crate::sys::exec::{FakeExec, Stdin};
use std::sync::Arc;

const ONEBOX_RELEASE: &str = include_str!("fixtures/onebox-v2.0.1.json");
const ONEBOX_SUMS: &str = include_str!("fixtures/onebox-v2.0.1.SHA256SUMS");
const XRAY_DGST: &str = include_str!("fixtures/Xray-linux-64.zip.dgst");
const REPO: &str = "mutsuki14/Sing-xray-onebox";
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
    let dir = TempDir::new("fetch").unwrap();
    let (ctx, exec, _) = Ctx::test(dir.path());
    (dir, ctx, exec)
}

// ---- release metadata -------------------------------------------------

#[test]
fn recorded_release_parses() {
    let release = Release::parse(ONEBOX_RELEASE.as_bytes()).unwrap();
    assert_eq!(release.tag, "v2.0.1");
    assert_eq!(release.version(), "2.0.1");
    assert!(!release.draft && !release.prerelease);
    assert!(release.body.contains("SHA256SUMS"));
    assert_eq!(release.assets.len(), 6);
    let amd64 = release.asset("onebox-linux-amd64-musl").unwrap();
    assert_eq!(amd64.size, 2_843_504);
    assert_eq!(amd64.url, ASSET_URL);
    assert_eq!(
        amd64.sha256().unwrap().as_deref(),
        Some("df929290d37855b5547940ce2b4b062f667526028b55351d901074d28cef881d")
    );
    amd64.check_url(REPO, "v2.0.1").unwrap();
    assert_eq!(
        amd64
            .check_url("evil/repo", "v2.0.1")
            .unwrap_err()
            .to_string(),
        "发行文件地址不可信: onebox-linux-amd64-musl"
    );
    assert_eq!(
        Asset::expected_url(REPO, "v2.0.1", "SHA256SUMS"),
        "https://github.com/mutsuki14/Sing-xray-onebox/releases/download/v2.0.1/SHA256SUMS"
    );
    let first = release.first_asset(&["missing", "SHA256SUMS", "BUILD-INFO.json"]);
    assert_eq!(first.unwrap().name, "SHA256SUMS");
    assert!(release.first_asset(&["missing"]).is_none());
}

#[test]
fn release_parse_errors() {
    let cases = [
        (r#"{"assets":[]}"#, "发行信息缺少版本"),
        (r#"{"tag_name":"","assets":[]}"#, "发行信息缺少版本"),
        (r#"{"tag_name":"v1"}"#, "发行信息缺少文件"),
        (
            r#"{"tag_name":"v1","assets":[{"name":"../x","browser_download_url":"u","size":1}]}"#,
            "文件名无效",
        ),
        (
            r#"{"tag_name":"v1","assets":[{"browser_download_url":"u","size":1}]}"#,
            "文件名无效",
        ),
        (
            r#"{"tag_name":"v1","assets":[{"name":"a","size":1}]}"#,
            "下载地址缺失",
        ),
        (
            r#"{"tag_name":"v1","assets":[{"name":"a","browser_download_url":"u"}]}"#,
            "发行文件缺少大小信息: a",
        ),
    ];
    for (json, want) in cases {
        let err = Release::parse(json.as_bytes()).unwrap_err().to_string();
        assert_eq!(err, want, "{json}");
    }
    assert!(Release::parse(b"[1,2]")
        .unwrap_err()
        .to_string()
        .starts_with("发行信息无效"));
    let bare = Release::parse(br#"{"tag_name":"testing","assets":[]}"#).unwrap();
    assert!(
        bare.draft && bare.prerelease,
        "missing flags fail safe as draft/prerelease"
    );
    assert_eq!(bare.version(), "testing");
}

#[test]
fn asset_digest_forms() {
    let asset = |digest: Option<&str>| Asset {
        name: "a".into(),
        url: String::new(),
        size: 1,
        digest: digest.map(str::to_owned),
    };
    let hex = "AB".repeat(32);
    assert_eq!(asset(None).sha256().unwrap(), None);
    assert_eq!(asset(Some("sha512:00")).sha256().unwrap(), None);
    assert_eq!(
        asset(Some(&format!("sha256:{hex}"))).sha256().unwrap(),
        Some("ab".repeat(32))
    );
    assert_eq!(
        asset(Some("sha256:1234")).sha256().unwrap_err().to_string(),
        "发行文件 SHA256 格式无效: a"
    );
}

#[test]
fn checksum_file_formats() {
    assert_eq!(
        checksum_for(ONEBOX_SUMS, "onebox-linux-armv7-musl").as_deref(),
        Some("15d15e7c1d9b2022d841fb07a600413f7becf1b2d55c4782247dc4b478d18b33")
    );
    assert_eq!(checksum_for(ONEBOX_SUMS, "onebox-linux-amd64"), None);
    assert_eq!(
        checksum_for(XRAY_DGST, "Xray-linux-64.zip").as_deref(),
        Some("23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae")
    );
    let hex = "0f".repeat(32);
    let upper = hex.to_ascii_uppercase();
    let cases = [
        (format!("{hex} *pkg.tar.gz"), Some(hex.clone())),
        (format!("{hex}  ./pkg.tar.gz"), Some(hex.clone())),
        (format!("SHA256 (pkg.tar.gz) = {upper}"), Some(hex.clone())),
        (format!("SHA256 (other.tar.gz) = {hex}"), None),
        (format!("SHA-256={hex}"), Some(hex.clone())),
        (format!("SHA1= {hex}"), None),
        (format!("{hex}  pkg.tar.gz extra"), None),
        ("1234  pkg.tar.gz".to_string(), None),
        (String::new(), None),
    ];
    for (text, want) in cases {
        assert_eq!(checksum_for(&text, "pkg.tar.gz"), want, "{text}");
    }
}

#[test]
fn file_verification() {
    let dir = TempDir::new("verify").unwrap();
    let path = dir.join("pkg");
    std::fs::write(&path, b"payload").unwrap();
    let sha = crate::sys::fs::sha256_hex(b"payload");
    let asset = |size: u64, digest: Option<String>| Asset {
        name: "pkg".into(),
        url: String::new(),
        size,
        digest,
    };
    verify_file(&path, &asset(7, Some(format!("sha256:{sha}"))), None).unwrap();
    let sums = format!("{sha}  pkg\n");
    let wrong_sums = format!("{}  pkg\n", "1".repeat(64));
    verify_file(&path, &asset(7, None), Some(&sums)).unwrap();
    let cases = [
        (
            asset(8, Some(format!("sha256:{sha}"))),
            None,
            "pkg 大小与发行元信息不符（应为 8 字节，实际 7 字节）",
        ),
        (
            asset(7, Some(format!("sha256:{}", "0".repeat(64)))),
            Some(sums.as_str()),
            "下载文件 SHA256 不匹配: pkg",
        ),
        (asset(7, None), None, "pkg 缺少 SHA256 校验信息，拒绝安装"),
        (
            asset(7, None),
            Some("deadbeef  pkg\n"),
            "pkg 缺少 SHA256 校验信息，拒绝安装",
        ),
        (
            asset(7, None),
            Some(wrong_sums.as_str()),
            "下载文件 SHA256 不匹配: pkg",
        ),
        (
            asset(7, Some("sha256:xyz".into())),
            Some(sums.as_str()),
            "发行文件 SHA256 格式无效: pkg",
        ),
    ];
    for (asset, sums, want) in cases {
        assert_eq!(
            verify_file(&path, &asset, sums).unwrap_err().to_string(),
            want
        );
    }
    assert!(verify_file(&dir.join("missing"), &asset(1, None), None).is_err());
}

#[test]
fn elf_detection() {
    let dir = TempDir::new("elf").unwrap();
    let mut elf = b"\x7fELF".to_vec();
    elf.resize(64, 0);
    assert!(is_elf(&elf));
    assert!(!is_elf(&elf[..19]));
    assert!(!is_elf(b"#!/bin/sh\necho not elf at all\n"));
    std::fs::write(dir.join("bin"), &elf).unwrap();
    std::fs::write(dir.join("script"), b"#!/bin/sh\nexit 0\n").unwrap();
    check_elf(&dir.join("bin")).unwrap();
    assert_eq!(
        check_elf(&dir.join("script")).unwrap_err().to_string(),
        "script 不是 Linux ELF 程序"
    );
    assert!(check_elf(&dir.join("missing")).is_err());
}

// ---- URLs and policy ----------------------------------------------------

#[test]
fn https_and_proxy_policy() {
    let gh = "https://github.com/o/r/releases/download/v1/a.tar.gz";
    let api = "https://api.github.com/repos/o/r/releases/latest";
    let raw = "https://raw.githubusercontent.com/o/r/v1/x.sh";
    let proxy = Some("https://ghproxy.example");
    type Case<'a> = (&'a str, Option<&'a str>, bool, Result<String, &'a str>);
    let cases: &[Case] = &[
        (gh, None, true, Ok(gh.to_string())),
        (gh, proxy, true, Ok(format!("https://ghproxy.example/{gh}"))),
        (
            gh,
            Some("https://p.example/x/"),
            true,
            Ok(format!("https://p.example/x/{gh}")),
        ),
        (gh, proxy, false, Ok(gh.to_string())),
        (gh, Some(""), true, Ok(gh.to_string())),
        (api, proxy, true, Ok(api.to_string())),
        (raw, proxy, true, Ok(raw.to_string())),
        (
            gh,
            Some("http://plain.example"),
            true,
            Err("GH_PROXY 必须为 HTTPS 地址"),
        ),
        (
            gh,
            Some("https://a b"),
            true,
            Err("GH_PROXY 必须为 HTTPS 地址"),
        ),
        (gh, Some("http://unused.example"), false, Ok(gh.to_string())),
        (
            "http://github.com/x",
            None,
            true,
            Err("下载地址必须为 HTTPS"),
        ),
        ("https://", None, true, Err("下载地址必须为 HTTPS")),
        (
            "https://a.example/x y",
            None,
            true,
            Err("下载地址必须为 HTTPS"),
        ),
        (
            "https://a.example/\n",
            None,
            true,
            Err("下载地址必须为 HTTPS"),
        ),
    ];
    for (url, gh_proxy, use_proxy, want) in cases {
        let got = proxied(url, *gh_proxy, *use_proxy).map_err(|e| e.to_string());
        assert_eq!(
            got,
            want.clone().map_err(str::to_owned),
            "{url} {gh_proxy:?}"
        );
    }
}

#[test]
fn release_urls_are_validated() {
    assert_eq!(
        release_url("SagerNet/sing-box", &Which::Latest).unwrap(),
        "https://api.github.com/repos/SagerNet/sing-box/releases/latest"
    );
    assert_eq!(
        release_url("XTLS/Xray-core", &Which::Tag("v26.3.27".into())).unwrap(),
        "https://api.github.com/repos/XTLS/Xray-core/releases/tags/v26.3.27"
    );
    assert!(release_url("a/b", &Which::Tag("x86_64-7.2.8-max".into())).is_ok());
    assert!(release_url("a/b", &Which::Tag("v1.0.0+meta".into())).is_ok());
    for repo in ["", "a", "a/b/c", "../b", "a/..", "a /b", "a/b?x"] {
        assert!(release_url(repo, &Which::Latest).is_err(), "{repo}");
    }
    for tag in ["", "../latest", "a/b", "v1 2", ".hidden", "-x", "v1%2f"] {
        let err = release_url("a/b", &Which::Tag(tag.into())).unwrap_err();
        assert_eq!(err.to_string(), format!("发行标签无效: {tag}"));
    }
}

// ---- GitHub API -----------------------------------------------------------

const API_URL: &str =
    "https://api.github.com/repos/mutsuki14/Sing-xray-onebox/releases/tags/v2.0.1";

#[test]
fn github_release_fetches_directly_with_api_headers() {
    let (_d, ctx, exec) = setup();
    serve(&exec, routes([(API_URL, Reply::body(ONEBOX_RELEASE))]));
    let env = env_with(&[("GH_PROXY", "https://ghproxy.example")]);
    let release = github_release_with(&ctx, &env, REPO, &Which::Tag("v2.0.1".into())).unwrap();
    assert_eq!(release.tag, "v2.0.1");
    let cmd = &exec.calls()[0];
    assert_eq!(url_arg(cmd), API_URL, "API never goes through GH_PROXY");
    let line = cmd.display();
    assert!(line.contains("-H Accept: application/vnd.github+json"));
    assert!(line.contains("-H X-GitHub-Api-Version: 2022-11-28"));
    assert!(line.contains("--max-filesize 16777216"));
    assert!(!line.contains("--config"));
    assert_eq!(cmd.stdin, Stdin::Null);
    // The private response directory is gone.
    assert!(!output_arg(cmd).unwrap().parent().unwrap().exists());
}

#[test]
fn raw_api_documents_share_the_api_transport() {
    let (_d, ctx, exec) = setup();
    let list = "https://api.github.com/repos/o/r/releases?per_page=100&page=2";
    let tag = "https://api.github.com/repos/o/r/releases/tags/x86_64-7.2.8-max";
    let limited = "https://api.github.com/repos/o/r/releases/tags/v9";
    serve(
        &exec,
        vec![
            (list.into(), Reply::body("[{\"tag_name\":\"x\"}]")),
            (tag.into(), Reply::body("not json")),
            (limited.into(), Reply::http(429)),
        ],
    );
    let env = env_with(&[("GH_PROXY", "https://ghproxy.example"), ("GH_TOKEN", "t0k")]);
    let doc = github_api_json_with(&ctx, &env, "o/r", list).unwrap();
    assert_eq!(doc[0]["tag_name"], "x");
    let cmd = &exec.calls()[0];
    assert_eq!(url_arg(cmd), list, "never proxied");
    assert!(cmd
        .display()
        .contains("-H X-GitHub-Api-Version: 2022-11-28"));
    assert!(cmd.display().contains("--config -"), "token on stdin");
    let err = github_api_json_with(&ctx, &env, "o/r", tag).unwrap_err();
    assert!(
        err.to_string()
            .starts_with("o/r 的 GitHub API 响应不是有效 JSON"),
        "{err}"
    );
    let err = github_api_json_with(&ctx, &env, "o/r", limited).unwrap_err();
    assert!(err.to_string().contains("可设置 GH_TOKEN 后重试"), "{err}");

    // Only plain paths below the repository; nothing is requested.
    exec.clear_history();
    let refused = [
        "https://api.github.com/repos/o/other/releases",
        "https://api.github.com/repos/o/r/../../x/y/releases",
        "https://api.github.com/repos/o/r/releases/./latest",
        "https://api.github.com/repos/o/r/",
        "https://api.github.com/repos/o/r/releases?page=1#x",
        "https://github.com/repos/o/r/releases",
        "http://api.github.com/repos/o/r/releases",
    ];
    for url in refused {
        let err = github_api_json_with(&ctx, &no_env, "o/r", url).unwrap_err();
        assert_eq!(
            err.to_string(),
            "元信息必须来自 api.github.com/repos/o/r/",
            "{url}"
        );
    }
    let err = github_api_json_with(&ctx, &no_env, "o/../r", list).unwrap_err();
    assert_eq!(err.to_string(), "GitHub 仓库名无效: o/../r");
    assert!(exec.history().is_empty());
}

#[test]
fn github_token_travels_on_stdin_only() {
    let (_d, ctx, exec) = setup();
    serve(&exec, routes([(API_URL, Reply::body(ONEBOX_RELEASE))]));
    let env = env_with(&[("GH_TOKEN", "ghp_secret123")]);
    github_release_with(&ctx, &env, REPO, &Which::Tag("v2.0.1".into())).unwrap();
    let cmd = &exec.calls()[0];
    assert!(!cmd.display().contains("ghp_secret123"));
    assert!(cmd.display().contains("--config -"));
    assert_eq!(
        cmd.stdin,
        Stdin::Bytes(b"header = \"Authorization: Bearer ghp_secret123\"\n".to_vec())
    );
    let bad = env_with(&[("GH_TOKEN", "x\" -o /etc/passwd")]);
    let err = github_release_with(&ctx, &bad, REPO, &Which::Latest).unwrap_err();
    assert_eq!(err.to_string(), "GH_TOKEN 格式无效");
    assert_eq!(exec.calls().len(), 1, "invalid token: no request");
}

#[test]
fn github_api_errors() {
    let (_d, ctx, exec) = setup();
    let latest = "https://api.github.com/repos/o/r/releases/latest";
    serve(
        &exec,
        vec![
            (latest.into(), Reply::http(403)),
            (
                "https://api.github.com/repos/o/r/releases/tags/v1".into(),
                Reply::body("{not json"),
            ),
        ],
    );
    let err = github_release_with(&ctx, &no_env, "o/r", &Which::Latest).unwrap_err();
    assert_eq!(
        err.to_string(),
        format!(
            "获取 o/r 发行信息失败（GitHub API 拒绝或限流；可设置 GH_TOKEN 后重试）: \
             下载失败: {latest}: curl: (22) The requested URL returned error: 403"
        )
    );
    let err = github_release_with(&ctx, &no_env, "o/r", &Which::Tag("v1".into())).unwrap_err();
    assert!(err
        .to_string()
        .starts_with("o/r 发行信息无效: 发行信息无效"));
    let err = github_release_with(&ctx, &no_env, "o/r", &Which::Tag("v2".into())).unwrap_err();
    assert!(
        !err.to_string().contains("GH_TOKEN"),
        "404 is not a rate limit"
    );
}

const BBR_REPO: &str = "byJoey/Actions-bbr-v3";
const BBR_PAGE: &str =
    "https://api.github.com/repos/byJoey/Actions-bbr-v3/releases?per_page=100&page=2";

#[test]
fn release_lists_skip_untrustworthy_entries() {
    let (_d, ctx, exec) = setup();
    let page = r#"[
        {"tag_name":"x86_64-7.2.8","draft":false,"prerelease":false,"assets":[]},
        {"tag_name":"x86_64-7.2.7","draft":false,"prerelease":false,
         "assets":[{"name":"../evil","browser_download_url":"u","size":1}]},
        {"tag_name":"arm64-7.2.8","assets":[]},
        {"name":"no tag"},
        42
    ]"#;
    serve(&exec, routes([(BBR_PAGE, Reply::body(page))]));
    let env = env_with(&[("GH_PROXY", "https://ghproxy.example"), ("GH_TOKEN", "t0k")]);
    let list = github_releases_with(&ctx, &env, BBR_REPO, 2, MAX_PER_PAGE).unwrap();
    let tags: Vec<&str> = list.releases.iter().map(|r| r.tag.as_str()).collect();
    assert_eq!(tags, ["x86_64-7.2.8", "arm64-7.2.8"]);
    assert!(
        list.releases[1].draft && list.releases[1].prerelease,
        "fail safe"
    );
    assert_eq!(list.entries, 5);
    assert!(list.is_last(MAX_PER_PAGE) && !list.is_last(5));
    let cmd = &exec.calls()[0];
    assert_eq!(url_arg(cmd), BBR_PAGE, "direct, never GH_PROXY");
    assert!(cmd
        .display()
        .contains("-H Accept: application/vnd.github+json"));
    assert!(cmd.display().contains("--config -"), "token on stdin");
}

#[test]
fn release_list_errors_and_urls() {
    let (_d, ctx, exec) = setup();
    let first = "https://api.github.com/repos/o/r/releases?per_page=30&page=1";
    serve(
        &exec,
        vec![
            (first.into(), Reply::body(r#"{"message":"Not Found"}"#)),
            (
                "https://api.github.com/repos/o/r/releases?per_page=30&page=2".into(),
                Reply::http(429),
            ),
        ],
    );
    let err = github_releases_with(&ctx, &no_env, "o/r", 1, 30).unwrap_err();
    assert!(
        err.to_string()
            .starts_with("o/r 发行列表无效: 响应不是发行数组: "),
        "{err}"
    );
    let err = github_releases_with(&ctx, &no_env, "o/r", 2, 30).unwrap_err();
    assert!(err.to_string().contains("可设置 GH_TOKEN 后重试"), "{err}");
    assert_eq!(releases_url("o/r", 3, 100).unwrap(), {
        "https://api.github.com/repos/o/r/releases?per_page=100&page=3"
    });
    for (repo, page, per_page) in [("o/r", 0, 10), ("o/r", 1, 0), ("o/r", 1, 101)] {
        let err = releases_url(repo, page, per_page).unwrap_err();
        assert_eq!(err.to_string(), "发行列表分页参数无效");
    }
    assert!(releases_url("../x", 1, 10).is_err());
}

/// Real curl against github.com (run with `cargo test -- --ignored`).
#[test]
#[ignore = "needs network access to github.com"]
fn real_download_verifies_against_recorded_metadata() {
    let dir = TempDir::new("fetch-real").unwrap();
    let ctx = Ctx {
        paths: crate::paths::Paths::isolated(dir.path()),
        exec: Arc::new(crate::sys::exec::SystemExec),
        ui: Arc::new(crate::ui::ScriptedPrompter::new(Vec::<String>::new())),
    };
    let release = Release::parse(ONEBOX_RELEASE.as_bytes()).unwrap();
    let asset = release.asset("SHA256SUMS").unwrap();
    asset.check_url(REPO, &release.tag).unwrap();
    let dest = dir.join("SHA256SUMS");
    let size = download_with(&ctx, &no_env, &asset.url, &dest, asset.size, true).unwrap();
    assert_eq!(size, asset.size);
    verify_file(&dest, asset, None).unwrap();
    assert_eq!(std::fs::read_to_string(&dest).unwrap(), ONEBOX_SUMS);
}
