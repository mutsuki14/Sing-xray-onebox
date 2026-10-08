use super::super::testing::{serve, url_arg, Reply};
use super::*;
use crate::sys::exec::FakeExec;
use crate::sys::fs::sha256_hex;
use std::sync::Arc;

const REPO: &str = "o/r";
const TAG: &str = "v1.0.0";
const PROXY: &str = "https://ghproxy.example";

fn url(name: &str) -> String {
    Asset::expected_url(REPO, TAG, name)
}

fn asset(name: &str, bytes: &[u8], digest: bool) -> Asset {
    Asset {
        name: name.into(),
        url: url(name),
        size: bytes.len() as u64,
        digest: digest.then(|| format!("sha256:{}", sha256_hex(bytes))),
    }
}

fn release(assets: Vec<Asset>) -> Release {
    Release {
        tag: TAG.into(),
        draft: false,
        prerelease: false,
        body: String::new(),
        assets,
    }
}

fn no_env(_: &str) -> Option<String> {
    None
}

fn with_proxy(key: &str) -> Option<String> {
    (key == "GH_PROXY").then(|| PROXY.to_owned())
}

fn proxied(u: &str) -> String {
    format!("{PROXY}/{u}")
}

struct Net {
    dir: TempDir,
    ctx: Ctx,
    exec: Arc<FakeExec>,
}

fn net(routes: Vec<(String, Reply)>) -> Net {
    let dir = TempDir::new("asset").unwrap();
    let (ctx, exec, _) = Ctx::test(dir.path());
    serve(&exec, routes);
    Net { dir, ctx, exec }
}

impl Net {
    fn urls(&self) -> Vec<String> {
        self.exec
            .calls()
            .iter()
            .map(|c| url_arg(c).to_owned())
            .collect()
    }
}

fn sums_named(n: &str) -> bool {
    n == "SHA256SUMS"
}

const PAYLOAD: &[u8] = b"release payload";

#[test]
fn digest_verified_payload_may_use_the_proxy() {
    let pkg = asset("pkg.tar.gz", PAYLOAD, true);
    let sums = asset("SHA256SUMS", b"unused", false);
    let rel = release(vec![pkg.clone(), sums]);
    let n = net(vec![(proxied(&pkg.url), Reply::body(PAYLOAD))]);
    let dest = n.dir.join("pkg.tar.gz");
    let size =
        download_asset_with(&n.ctx, &with_proxy, REPO, &rel, &pkg, &dest, &sums_named).unwrap();
    assert_eq!(size, PAYLOAD.len() as u64);
    assert_eq!(std::fs::read(&dest).unwrap(), PAYLOAD);
    assert_eq!(n.urls(), [proxied(&pkg.url)], "no checksum file needed");
}

#[test]
fn checksum_file_is_always_fetched_directly() {
    let pkg = asset("pkg.tar.gz", PAYLOAD, false);
    let text = format!("{}  pkg.tar.gz\n", sha256_hex(PAYLOAD));
    let sums = asset("SHA256SUMS", text.as_bytes(), false);
    let rel = release(vec![pkg.clone(), sums.clone()]);
    // The mirror would serve a matching pair of forged files.
    let forged = b"trojan".to_vec();
    let forged_sums = format!("{}  pkg.tar.gz\n", sha256_hex(&forged));
    let n = net(vec![
        (sums.url.clone(), Reply::body(text.clone())),
        (proxied(&sums.url), Reply::body(forged_sums)),
        (proxied(&pkg.url), Reply::body(PAYLOAD)),
    ]);
    let dest = n.dir.join("pkg.tar.gz");
    download_asset_with(&n.ctx, &with_proxy, REPO, &rel, &pkg, &dest, &sums_named).unwrap();
    assert_eq!(
        n.urls(),
        [sums.url.clone(), proxied(&pkg.url)],
        "checksums direct and first; only the payload via GH_PROXY"
    );

    // A mirror swapping the payload is caught by the direct checksum.
    let n = net(vec![
        (sums.url.clone(), Reply::body(text)),
        (proxied(&pkg.url), Reply::body(forged)),
    ]);
    let dest = n.dir.join("pkg.tar.gz");
    std::fs::write(&dest, b"old").unwrap();
    let err =
        download_asset_with(&n.ctx, &with_proxy, REPO, &rel, &pkg, &dest, &sums_named).unwrap_err();
    assert!(
        err.to_string()
            .starts_with("pkg.tar.gz 大小与发行元信息不符"),
        "{err}"
    );
    assert_eq!(std::fs::read(&dest).unwrap(), b"old", "dest untouched");
}

#[test]
fn unreachable_checksum_file_with_a_proxy_explains_the_rule() {
    let pkg = asset("pkg.tar.gz", PAYLOAD, false);
    let sums = asset("SHA256SUMS", b"0123456789", false);
    let rel = release(vec![pkg.clone(), sums.clone()]);
    let n = net(vec![
        (
            sums.url.clone(),
            Reply::Fail(7, "curl: (7) Failed to connect".into()),
        ),
        (proxied(&sums.url), Reply::body("0123456789")),
        (proxied(&pkg.url), Reply::body(PAYLOAD)),
    ]);
    let dest = n.dir.join("pkg.tar.gz");
    let err = download_asset_with(&n.ctx, &with_proxy, REPO, &rel, &pkg, &dest, &sums_named)
        .unwrap_err()
        .to_string();
    assert!(
        err.starts_with(
            "该版本缺少 GitHub API 摘要，校验文件 SHA256SUMS 必须直连 GitHub 获取（不经 GH_PROXY）；\
             请改用带摘要的版本或检查直连网络: 下载失败: "
        ),
        "{err}"
    );
    assert_eq!(
        n.urls(),
        std::slice::from_ref(&sums.url),
        "payload never fetched"
    );
    assert!(!dest.exists());

    let n = net(vec![]);
    let err = download_asset_with(&n.ctx, &no_env, REPO, &rel, &pkg, &dest, &sums_named)
        .unwrap_err()
        .to_string();
    assert!(err.starts_with("获取校验文件 SHA256SUMS 失败: "), "{err}");
}

#[test]
fn checksum_file_problems_stop_before_the_payload() {
    let pkg = asset("pkg.tar.gz", PAYLOAD, false);
    let good = format!("{}  pkg.tar.gz\n", sha256_hex(PAYLOAD));
    let other = format!("{}  other.tar.gz\n", sha256_hex(PAYLOAD));
    let cases: Vec<(Asset, Reply, String)> = vec![
        // Served file differs in size from the metadata.
        (
            asset("SHA256SUMS", good.as_bytes(), false),
            Reply::body(good.trim_end().to_owned()),
            "获取校验文件 SHA256SUMS 失败: SHA256SUMS 大小与发行元信息不符".into(),
        ),
        // Lists other files only.
        (
            asset("SHA256SUMS", other.as_bytes(), false),
            Reply::body(other.clone()),
            "pkg.tar.gz 缺少 SHA256 校验信息，拒绝安装".into(),
        ),
        // Has an API digest that does not match.
        (
            Asset {
                digest: Some(format!("sha256:{}", "0".repeat(64))),
                ..asset("SHA256SUMS", good.as_bytes(), false)
            },
            Reply::body(good.clone()),
            "获取校验文件 SHA256SUMS 失败: 下载文件 SHA256 不匹配: SHA256SUMS".into(),
        ),
        // Not the canonical URL of this release.
        (
            Asset {
                url: "https://evil.example/SHA256SUMS".into(),
                ..asset("SHA256SUMS", good.as_bytes(), false)
            },
            Reply::body(good.clone()),
            "发行文件地址不可信: SHA256SUMS".into(),
        ),
        // Implausible size.
        (
            Asset {
                size: CHECKSUM_MAX_BYTES + 1,
                ..asset("SHA256SUMS", good.as_bytes(), false)
            },
            Reply::body(good.clone()),
            "校验文件大小无效: SHA256SUMS".into(),
        ),
    ];
    for (sums, reply, want) in cases {
        let rel = release(vec![pkg.clone(), sums.clone()]);
        let n = net(vec![
            (sums.url.clone(), reply),
            (pkg.url.clone(), Reply::body(PAYLOAD)),
        ]);
        let dest = n.dir.join("pkg.tar.gz");
        let err = download_asset_with(&n.ctx, &no_env, REPO, &rel, &pkg, &dest, &sums_named)
            .unwrap_err()
            .to_string();
        assert!(err.starts_with(&want), "{err} / {want}");
        assert!(!n.urls().contains(&pkg.url), "{want}: payload not fetched");
    }

    // No checksum file at all.
    let rel = release(vec![pkg.clone()]);
    let n = net(vec![]);
    let err = download_asset_with(
        &n.ctx,
        &no_env,
        REPO,
        &rel,
        &pkg,
        &n.dir.join("x"),
        &sums_named,
    )
    .unwrap_err();
    assert_eq!(err.to_string(), "pkg.tar.gz 缺少 SHA256 校验信息，拒绝安装");
    assert!(n.urls().is_empty());
}

#[test]
fn payload_refusals() {
    let n = net(vec![]);
    let dest = n.dir.join("pkg");
    let mut pkg = asset("pkg", PAYLOAD, true);
    pkg.url = "https://github.com/evil/r/releases/download/v1.0.0/pkg".into();
    let rel = release(vec![pkg.clone()]);
    let err = download_asset_with(&n.ctx, &no_env, REPO, &rel, &pkg, &dest, &sums_named);
    assert_eq!(err.unwrap_err().to_string(), "发行文件地址不可信: pkg");
    let empty = asset("pkg", b"", true);
    let err = download_asset_with(&n.ctx, &no_env, REPO, &rel, &empty, &dest, &sums_named);
    assert_eq!(err.unwrap_err().to_string(), "发行文件大小无效: pkg");

    // Hash mismatch: the temp file is removed and nothing is installed.
    let pkg = Asset {
        digest: Some(format!("sha256:{}", "1".repeat(64))),
        ..asset("pkg", PAYLOAD, true)
    };
    let n = net(vec![(pkg.url.clone(), Reply::body(PAYLOAD))]);
    let dest = n.dir.join("out/pkg");
    let rel = release(vec![pkg.clone()]);
    let err = download_asset_with(&n.ctx, &no_env, REPO, &rel, &pkg, &dest, &sums_named);
    assert_eq!(err.unwrap_err().to_string(), "下载文件 SHA256 不匹配: pkg");
    assert_eq!(
        std::fs::read_dir(dest.parent().unwrap()).unwrap().count(),
        0
    );
}

// ---- pinned downloads -----------------------------------------------------

const ACME: &str = "https://raw.githubusercontent.com/acmesh-official/acme.sh/3.1.6/acme.sh";

#[test]
fn pinned_downloads_may_use_the_proxy_for_raw_files() {
    let body = b"#!/usr/bin/env sh\n# acme.sh\n".to_vec();
    let sha = sha256_hex(&body);
    let n = net(vec![
        (proxied(ACME), Reply::body(body.clone())),
        (ACME.to_owned(), Reply::body(body.clone())),
    ]);
    let dest = n.dir.join("acme.sh");
    download_pinned_with(&n.ctx, &with_proxy, ACME, &dest, 1 << 20, &sha, true).unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), body);
    let upper = sha.to_ascii_uppercase();
    download_pinned_with(&n.ctx, &with_proxy, ACME, &dest, 1 << 20, &upper, false).unwrap();
    assert_eq!(n.urls(), [proxied(ACME), ACME.to_owned()]);
}

#[test]
fn pinned_download_mismatch_keeps_the_old_file() {
    let n = net(vec![(proxied(ACME), Reply::body("tampered"))]);
    let dest = n.dir.join("acme.sh");
    std::fs::write(&dest, b"good old").unwrap();
    let pin = sha256_hex(b"expected");
    let err = download_pinned_with(&n.ctx, &with_proxy, ACME, &dest, 1 << 20, &pin, true);
    assert_eq!(
        err.unwrap_err().to_string(),
        format!("下载文件 SHA256 不匹配: {ACME}")
    );
    assert_eq!(std::fs::read(&dest).unwrap(), b"good old");
    let names: Vec<_> = std::fs::read_dir(n.dir.path()).unwrap().collect();
    assert_eq!(names.len(), 1, "temp removed");
    let err = download_pinned_with(&n.ctx, &no_env, ACME, &dest, 10, "abc", true);
    assert_eq!(err.unwrap_err().to_string(), "固定的 SHA256 格式无效");
}

#[test]
fn proxy_routes() {
    let gh = "https://github.com/o/r/releases/download/v1/a";
    let raw = "https://raw.githubusercontent.com/o/r/v1/a.sh";
    let api = "https://api.github.com/repos/o/r/releases";
    let other = "https://example.com/a";
    let cases = [
        (Route::Direct, gh, false),
        (Route::Direct, raw, false),
        (Route::Payload, gh, true),
        (Route::Payload, raw, false),
        (Route::Payload, api, false),
        (Route::Pinned, gh, true),
        (Route::Pinned, raw, true),
        (Route::Pinned, api, false),
        (Route::Pinned, other, false),
    ];
    for (route, u, via) in cases {
        let got = super::super::route_target(u, Some(PROXY), route).unwrap();
        let want = if via { proxied(u) } else { u.to_owned() };
        assert_eq!(got, want, "{route:?} {u}");
    }
}
