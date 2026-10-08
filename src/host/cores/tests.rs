use super::archive::{write_tar_gz, write_zip};
use super::*;
use crate::host::fetch::testing::{serve, url_arg, Reply};
use crate::sys::exec::{FakeExec, Output};
use crate::sys::fs::sha256_hex;
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

const SB_API: &str = "https://api.github.com/repos/SagerNet/sing-box/releases";
const XR_API: &str = "https://api.github.com/repos/XTLS/Xray-core/releases";

struct Fixture {
    dir: TempDir,
    ctx: Ctx,
    exec: Arc<FakeExec>,
    routes: Vec<(String, Reply)>,
}

fn fixture() -> Fixture {
    let dir = TempDir::new("cores").unwrap();
    let (ctx, exec, _) = Ctx::test(dir.path());
    exec.on("uname", &["-m"], Output::success("x86_64\n"));
    Fixture {
        dir,
        ctx,
        exec,
        routes: Vec::new(),
    }
}

impl Fixture {
    fn route(&mut self, url: impl Into<String>, reply: Reply) -> &mut Self {
        self.routes.push((url.into(), reply));
        self
    }

    /// Install the fake network (call once, after all routes).
    fn serve(&self) {
        serve(&self.exec, self.routes.clone());
    }

    fn staging(&self) -> PathBuf {
        let staging = self.dir.join("staging");
        std::fs::create_dir_all(&staging).unwrap();
        staging
    }

    fn curl_urls(&self) -> Vec<String> {
        self.exec
            .calls()
            .iter()
            .filter(|c| c.program == "curl")
            .map(|c| url_arg(c).to_owned())
            .collect()
    }
}

fn no_env(_: &str) -> Option<String> {
    None
}

fn fake_elf(tag: &str) -> Vec<u8> {
    let mut bytes = b"\x7fELF".to_vec();
    bytes.resize(32, 0);
    bytes.extend_from_slice(tag.as_bytes());
    bytes
}

/// `{binary} version` answers per binary path prefix (first match wins).
fn versions(exec: &FakeExec, answers: Vec<(PathBuf, Output)>) {
    exec.on_fn(
        |cmd| cmd.args == ["version"],
        move |cmd| {
            Ok(answers
                .iter()
                .find(|(p, _)| Path::new(&cmd.program).starts_with(p))
                .map(|(_, o)| o.clone())
                .unwrap_or_else(|| Output::failure(127, "no such binary")))
        },
    );
}

fn singbox_says(v: &str) -> Output {
    Output::success(format!(
        "sing-box version {v}\n\nEnvironment: go1.26.8 linux/amd64\n"
    ))
}

fn xray_says(v: &str) -> Output {
    Output::success(format!(
        "Xray {v} (Xray, Penetrates Everything.) d2758a0 (go1.26.1 linux/amd64)\nA unified platform for anti-censorship.\n"
    ))
}

fn asset_json(repo: &str, tag: &str, name: &str, bytes: &[u8], digest: bool) -> serde_json::Value {
    let mut asset = json!({
        "name": name,
        "size": bytes.len(),
        "browser_download_url": Asset::expected_url(repo, tag, name),
    });
    if digest {
        asset["digest"] = json!(format!("sha256:{}", sha256_hex(bytes)));
    }
    asset
}

use crate::host::fetch::Asset;

fn release_json(tag: &str, prerelease: bool, assets: Vec<serde_json::Value>) -> Reply {
    Reply::body(
        json!({"tag_name": tag, "draft": false, "prerelease": prerelease, "body": "", "assets": assets})
            .to_string(),
    )
}

fn singbox_tgz(dir: &TempDir, version: &str, binary: &[u8]) -> (String, Vec<u8>) {
    let name = format!("sing-box-{version}-linux-amd64-musl.tar.gz");
    let path = dir.join(&name);
    let inner = format!("sing-box-{version}-linux-amd64-musl/sing-box");
    write_tar_gz(
        &path,
        &[
            (
                &format!("sing-box-{version}-linux-amd64-musl/LICENSE"),
                b"x",
                tar::EntryType::Regular,
            ),
            (&inner, binary, tar::EntryType::Regular),
        ],
    );
    (name, std::fs::read(path).unwrap())
}

fn xray_zip(dir: &TempDir, binary: &[u8]) -> Vec<u8> {
    let path = dir.join("Xray-linux-64.zip");
    write_zip(
        &path,
        &[
            ("geoip.dat", b"geo", true, 0o100644),
            ("xray", binary, true, 0o100755),
        ],
    );
    std::fs::read(path).unwrap()
}

/// sing-box `version` release served with an API digest.
fn serve_singbox(f: &mut Fixture, version: &str, api: &str) -> Vec<u8> {
    let tag = format!("v{version}");
    let binary = fake_elf(&format!("sing-box {version}"));
    let (name, package) = singbox_tgz(&f.dir, version, &binary);
    let asset = asset_json(repo(Core::Singbox), &tag, &name, &package, true);
    f.route(api, release_json(&tag, false, vec![asset])).route(
        Asset::expected_url(repo(Core::Singbox), &tag, &name),
        Reply::body(package),
    );
    binary
}

// ---- versions -----------------------------------------------------------

#[test]
fn wanted_versions() {
    let cases = [
        (None, Ok(Wanted::Default)),
        (Some(""), Ok(Wanted::Default)),
        (Some(" latest "), Ok(Wanted::Latest)),
        (Some("v1.14.2"), Ok(Wanted::Exact("1.14.2".into()))),
        (Some("26.3.27"), Ok(Wanted::Exact("26.3.27".into()))),
        (
            Some("1.13.0-beta.2"),
            Ok(Wanted::Exact("1.13.0-beta.2".into())),
        ),
        (Some("../x1"), Err("版本格式无效: ../x1")),
        (Some("v"), Err("版本格式无效: v")),
        (Some("v.1"), Err("版本格式无效: v.1")),
        (Some("beta"), Err("版本格式无效: beta")),
        (Some("-1"), Err("版本格式无效: -1")),
    ];
    for (input, want) in cases {
        let got = Wanted::parse(input).map_err(|e| e.to_string());
        assert_eq!(got, want.map_err(str::to_owned), "{input:?}");
    }
    assert!(!version_valid(&"1".repeat(80)));
    assert!(Wanted::Default.satisfied_by("1.0"));
    assert!(Wanted::Latest.satisfied_by("1.0"));
    assert!(Wanted::Exact("1.0".into()).satisfied_by("1.0"));
    assert!(!Wanted::Exact("1.0".into()).satisfied_by("1.1"));
}

#[test]
fn version_output_parsing() {
    let cases = [
        (
            Core::Singbox,
            "sing-box version 1.14.2\n\nEnvironment: go",
            Some("1.14.2"),
        ),
        (
            Core::Singbox,
            "sing-box version v1.15.0-beta.1",
            Some("1.15.0-beta.1"),
        ),
        (Core::Singbox, "Xray 26.3.27 (Xray)", None),
        (Core::Singbox, "sing-box 1.14.2", None),
        (
            Core::Xray,
            "Xray 26.3.27 (Xray, Penetrates Everything.) d2758a0",
            Some("26.3.27"),
        ),
        (Core::Xray, "Xray v1.8.24 (Xray)", Some("1.8.24")),
        (Core::Xray, "", None),
        (Core::Xray, "Xray", None),
        (Core::Xray, "Xray ../../x", None),
    ];
    for (core, text, want) in cases {
        assert_eq!(parse_version(core, text).as_deref(), want, "{text}");
    }
}

#[test]
fn installed_version_runs_the_binary() {
    let f = fixture();
    let bin = f.dir.join("xray");
    versions(&f.exec, vec![(bin.clone(), xray_says("26.3.27"))]);
    assert_eq!(
        installed_version(&f.ctx, &bin, Core::Xray).unwrap(),
        "26.3.27"
    );
    let err = installed_version(&f.ctx, &bin, Core::Singbox).unwrap_err();
    assert_eq!(err.to_string(), "无法解析内核版本");
    let err = installed_version(&f.ctx, &f.dir.join("other"), Core::Xray).unwrap_err();
    assert!(err.to_string().starts_with("无法运行 Xray: "), "{err}");
    assert!(f
        .exec
        .calls()
        .iter()
        .all(|c| c.timeout == Some(VERSION_TIMEOUT)));
}

// ---- resolve --------------------------------------------------------------

#[test]
fn xray_defaults_to_the_tested_version() {
    let mut f = fixture();
    f.route(
        format!("{XR_API}/tags/v26.3.27"),
        release_json("v26.3.27", false, vec![]),
    )
    .route(
        format!("{XR_API}/tags/v1.8.24"),
        release_json("v1.8.24", false, vec![]),
    )
    .route(
        format!("{XR_API}/latest"),
        release_json("v26.4.1", false, vec![]),
    );
    f.serve();
    let resolve = |w| {
        resolve_with(&f.ctx, &no_env, Core::Xray, w)
            .unwrap()
            .version
    };
    assert_eq!(resolve(None), "26.3.27");
    assert_eq!(resolve(Some("v1.8.24")), "1.8.24");
    assert_eq!(resolve(Some("latest")), "26.4.1");
    assert_eq!(
        f.curl_urls(),
        [
            format!("{XR_API}/tags/v26.3.27"),
            format!("{XR_API}/tags/v1.8.24"),
            format!("{XR_API}/latest")
        ]
    );
}

#[test]
fn singbox_latest_with_fallback() {
    let mut f = fixture();
    f.route(
        format!("{SB_API}/latest"),
        release_json("v1.15.0", false, vec![]),
    );
    f.serve();
    let r = resolve_with(&f.ctx, &no_env, Core::Singbox, None).unwrap();
    assert_eq!(r.version, "1.15.0");
    assert_eq!(r.release().unwrap().tag, "v1.15.0");
    assert!(!r.is_offline());

    let mut f = fixture();
    f.route(format!("{SB_API}/latest"), Reply::http(403)).route(
        format!("{SB_API}/tags/v1.14.2"),
        release_json("v1.14.2", false, vec![]),
    );
    f.serve();
    let r = resolve_with(&f.ctx, &no_env, Core::Singbox, Some("latest")).unwrap();
    assert_eq!(r.version, "1.14.2", "fallback after a failed lookup");

    // Xray has no fallback.
    let mut f = fixture();
    f.route(format!("{XR_API}/latest"), Reply::http(403));
    f.serve();
    assert!(resolve_with(&f.ctx, &no_env, Core::Xray, Some("latest")).is_err());
}

#[test]
fn release_sanity_checks() {
    let mut f = fixture();
    f.route(
        format!("{SB_API}/tags/v1.13.0-beta.1"),
        release_json("v1.13.0-beta.1", true, vec![]),
    )
    .route(
        format!("{SB_API}/tags/v1.12.0"),
        release_json("v1.12.1", false, vec![]),
    )
    .route(
        format!("{SB_API}/tags/v1.11.0"),
        Reply::body(r#"{"tag_name":"v1.11.0","draft":true,"prerelease":false,"assets":[]}"#),
    )
    .route(
        format!("{SB_API}/tags/v1.10.0"),
        Reply::body(r#"{"tag_name":"v1.10.0","assets":[]}"#),
    );
    f.serve();
    let err = |w| {
        resolve_with(&f.ctx, &no_env, Core::Singbox, Some(w))
            .unwrap_err()
            .to_string()
    };
    assert_eq!(
        err("1.13.0-beta.1"),
        "sing-box v1.13.0-beta.1 是预发布版本，拒绝安装；请指定正式版本"
    );
    assert_eq!(
        err("1.12.0"),
        "发行版本与请求不符（请求 1.12.0，得到 1.12.1）"
    );
    assert_eq!(err("1.11.0"), "无效发行版本: v1.11.0");
    assert_eq!(
        err("1.10.0"),
        "无效发行版本: v1.10.0",
        "missing flags fail safe"
    );
    let calls = f.exec.calls().len();
    assert_eq!(err("../latest"), "版本格式无效: ../latest");
    assert_eq!(f.exec.calls().len(), calls, "no request for invalid input");
}

#[test]
fn offline_override_skips_the_network() {
    let f = fixture();
    let local = f.dir.join("local-sing-box");
    std::fs::write(&local, fake_elf("offline")).unwrap();
    versions(&f.exec, vec![(local.clone(), singbox_says("1.14.0"))]);
    let path = local.to_string_lossy().into_owned();
    let env = move |k: &str| (k == "ONEBOX_SINGBOX_BIN").then(|| path.clone());
    let r = resolve_with(&f.ctx, &env, Core::Singbox, Some("1.14.2")).unwrap();
    assert_eq!(r.version, "1.14.0", "parsed version, mismatch only warns");
    assert!(r.is_offline() && r.release().is_none());
    assert!(f.curl_urls().is_empty());

    let link = f.dir.join("link");
    std::os::unix::fs::symlink(&local, &link).unwrap();
    for bad in [
        link.to_string_lossy().into_owned(),
        "relative/sing-box".into(),
    ] {
        let shown = bad.clone();
        let env = move |k: &str| (k == "ONEBOX_SINGBOX_BIN").then(|| bad.clone());
        let err = resolve_with(&f.ctx, &env, Core::Singbox, None).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("本地内核必须是普通文件的绝对路径（ONEBOX_SINGBOX_BIN={shown}）")
        );
    }
}

// ---- download -------------------------------------------------------------

#[test]
fn singbox_download_extracts_a_verified_binary() {
    let mut f = fixture();
    let binary = serve_singbox(&mut f, "1.14.2", &format!("{SB_API}/tags/v1.14.2"));
    f.serve();
    let staging = f.staging();
    versions(&f.exec, vec![(staging.clone(), singbox_says("1.14.2"))]);
    let resolved = resolve_with(&f.ctx, &no_env, Core::Singbox, Some("v1.14.2")).unwrap();
    let path = download_with(&f.ctx, &no_env, &resolved, &staging).unwrap();
    assert_eq!(path, staging.join("sing-box"));
    assert_eq!(std::fs::read(&path).unwrap(), binary);
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o755);
    let left: Vec<_> = std::fs::read_dir(&staging).unwrap().collect();
    assert_eq!(left.len(), 1, "work dir removed");
    let pkg = "https://github.com/SagerNet/sing-box/releases/download/v1.14.2/\
               sing-box-1.14.2-linux-amd64-musl.tar.gz";
    assert_eq!(
        f.curl_urls(),
        [format!("{SB_API}/tags/v1.14.2"), pkg.to_string()]
    );
}

#[test]
fn package_downloads_honor_gh_proxy() {
    let mut f = fixture();
    let tag = "v1.14.2";
    let binary = fake_elf("sb");
    let (name, package) = singbox_tgz(&f.dir, "1.14.2", &binary);
    let url = Asset::expected_url(repo(Core::Singbox), tag, &name);
    let asset = asset_json(repo(Core::Singbox), tag, &name, &package, true);
    f.route(
        format!("{SB_API}/tags/{tag}"),
        release_json(tag, false, vec![asset]),
    )
    .route(format!("https://proxy.example/{url}"), Reply::body(package));
    f.serve();
    let staging = f.staging();
    versions(&f.exec, vec![(staging.clone(), singbox_says("1.14.2"))]);
    let env = |k: &str| (k == "GH_PROXY").then(|| "https://proxy.example".to_owned());
    let resolved = resolve_with(&f.ctx, &env, Core::Singbox, Some(tag)).unwrap();
    download_with(&f.ctx, &env, &resolved, &staging).unwrap();
    assert_eq!(
        f.curl_urls(),
        [
            format!("{SB_API}/tags/{tag}"),
            format!("https://proxy.example/{url}")
        ]
    );
}

/// Xray release without API digests but with `.dgst` files.
fn serve_xray_dgst(f: &mut Fixture, dgst: Option<String>) -> Vec<u8> {
    let tag = "v26.3.27";
    let binary = fake_elf("xray");
    let package = xray_zip(&f.dir, &binary);
    let name = "Xray-linux-64.zip";
    let mut assets = vec![asset_json(repo(Core::Xray), tag, name, &package, false)];
    let dgst_name = format!("{name}.dgst");
    if let Some(text) = dgst {
        assets.push(asset_json(
            repo(Core::Xray),
            tag,
            &dgst_name,
            text.as_bytes(),
            false,
        ));
        f.route(
            Asset::expected_url(repo(Core::Xray), tag, &dgst_name),
            Reply::body(text),
        );
    }
    f.route(
        format!("{XR_API}/tags/{tag}"),
        release_json(tag, false, assets),
    )
    .route(
        Asset::expected_url(repo(Core::Xray), tag, name),
        Reply::body(package.clone()),
    );
    package
}

#[test]
fn xray_checksum_file_fallback() {
    let mut f = fixture();
    let zip = xray_zip(&TempDir::new("zip").unwrap(), &fake_elf("xray"));
    let dgst = format!("MD5= 00\nSHA2-256= {}\n", sha256_hex(&zip));
    serve_xray_dgst(&mut f, Some(dgst));
    f.serve();
    let staging = f.staging();
    versions(&f.exec, vec![(staging.clone(), xray_says("26.3.27"))]);
    let resolved = resolve_with(&f.ctx, &no_env, Core::Xray, None).unwrap();
    let path = download_with(&f.ctx, &no_env, &resolved, &staging).unwrap();
    assert_eq!(std::fs::read(path).unwrap(), fake_elf("xray"));
    assert!(f.curl_urls()[2].ends_with("Xray-linux-64.zip.dgst"));
}

#[test]
fn xray_checksum_problems() {
    let cases = [
        (
            Some(format!("SHA2-256= {}\n", "0".repeat(64))),
            "下载文件 SHA256 不匹配: Xray-linux-64.zip",
        ),
        (
            Some("MD5= 00\n".to_string()),
            "Xray-linux-64.zip 缺少 SHA256 校验信息，拒绝安装",
        ),
        (None, "Xray-linux-64.zip 缺少 SHA256 校验信息，拒绝安装"),
    ];
    for (dgst, want) in cases {
        let mut f = fixture();
        serve_xray_dgst(&mut f, dgst);
        f.serve();
        let staging = f.staging();
        let resolved = resolve_with(&f.ctx, &no_env, Core::Xray, None).unwrap();
        let err = download_with(&f.ctx, &no_env, &resolved, &staging).unwrap_err();
        assert_eq!(err.to_string(), format!("Xray 26.3.27 安装失败: {want}"));
        assert_eq!(
            std::fs::read_dir(&staging).unwrap().count(),
            0,
            "cleaned up"
        );
    }
}

/// Serve a sing-box release whose single asset JSON is modified by `edit`.
fn broken_release(edit: impl FnOnce(&mut serde_json::Value, &mut Vec<u8>)) -> String {
    let mut f = fixture();
    let tag = "v1.14.2";
    let (name, mut package) = singbox_tgz(&f.dir, "1.14.2", &fake_elf("sb"));
    let mut asset = asset_json(repo(Core::Singbox), tag, &name, &package, true);
    edit(&mut asset, &mut package);
    f.route(
        format!("{SB_API}/tags/{tag}"),
        release_json(tag, false, vec![asset]),
    )
    .route(
        Asset::expected_url(repo(Core::Singbox), tag, &name),
        Reply::body(package),
    );
    f.serve();
    let staging = f.staging();
    versions(&f.exec, vec![(staging.clone(), singbox_says("1.14.2"))]);
    let resolved = resolve_with(&f.ctx, &no_env, Core::Singbox, Some(tag)).unwrap();
    let err = download_with(&f.ctx, &no_env, &resolved, &staging).unwrap_err();
    assert_eq!(std::fs::read_dir(&staging).unwrap().count(), 0);
    err.to_string()
}

#[test]
fn download_refusals() {
    let prefix = "sing-box 1.14.2 安装失败: ";
    let err = broken_release(|a, _| {
        a["browser_download_url"] = json!("https://evil.example/sing-box.tar.gz")
    });
    assert_eq!(
        err,
        format!("{prefix}发行文件地址不可信: sing-box-1.14.2-linux-amd64-musl.tar.gz")
    );
    let err = broken_release(|a, _| a["name"] = json!("sing-box-1.14.2-linux-arm64.tar.gz"));
    assert_eq!(err, format!("{prefix}找不到对应架构的内核 (amd64)"));
    let err = broken_release(|_, p| p.push(0));
    assert!(err.contains("下载内容超过大小上限"), "{err}");
    let err = broken_release(|a, _| a["digest"] = json!(format!("sha256:{}", "1".repeat(64))));
    assert_eq!(
        err,
        format!("{prefix}下载文件 SHA256 不匹配: sing-box-1.14.2-linux-amd64-musl.tar.gz")
    );
    let err = broken_release(|a, _| a["size"] = json!(PACKAGE_MAX + 1));
    assert_eq!(
        err,
        format!("{prefix}内核包过大: sing-box-1.14.2-linux-amd64-musl.tar.gz")
    );
}

#[test]
fn downloaded_binary_must_be_sane() {
    // Not an ELF executable.
    let mut f = fixture();
    let tag = "v1.14.2";
    let (name, package) = singbox_tgz(
        &f.dir,
        "1.14.2",
        b"#!/bin/sh\necho sing-box version 1.14.2\n",
    );
    let asset = asset_json(repo(Core::Singbox), tag, &name, &package, true);
    f.route(
        format!("{SB_API}/tags/{tag}"),
        release_json(tag, false, vec![asset]),
    )
    .route(
        Asset::expected_url(repo(Core::Singbox), tag, &name),
        Reply::body(package),
    );
    f.serve();
    let staging = f.staging();
    let resolved = resolve_with(&f.ctx, &no_env, Core::Singbox, Some(tag)).unwrap();
    let err = download_with(&f.ctx, &no_env, &resolved, &staging).unwrap_err();
    assert_eq!(
        err.to_string(),
        "sing-box 1.14.2 安装失败: sing-box 不是 Linux ELF 程序"
    );

    // Reports another version.
    let mut f = fixture();
    serve_singbox(&mut f, "1.14.2", &format!("{SB_API}/tags/v1.14.2"));
    f.serve();
    let staging = f.staging();
    versions(&f.exec, vec![(staging.clone(), singbox_says("1.13.9"))]);
    let resolved = resolve_with(&f.ctx, &no_env, Core::Singbox, Some(tag)).unwrap();
    let err = download_with(&f.ctx, &no_env, &resolved, &staging).unwrap_err();
    assert_eq!(
        err.to_string(),
        "sing-box 1.14.2 安装失败: 程序报告的版本为 1.13.9，与发行版本 1.14.2 不符"
    );
    let err = download_with(&f.ctx, &no_env, &resolved, &f.dir.join("nope")).unwrap_err();
    assert!(err.to_string().starts_with("内核暂存目录无效"));
}

#[test]
fn offline_download_copies_and_probes() {
    let f = fixture();
    let local = f.dir.join("xray-local");
    std::fs::write(&local, fake_elf("local xray")).unwrap();
    let staging = f.staging();
    versions(
        &f.exec,
        vec![
            (local.clone(), xray_says("25.1.1")),
            (staging.clone(), xray_says("25.1.1")),
        ],
    );
    let path = local.to_string_lossy().into_owned();
    let env = move |k: &str| (k == "ONEBOX_XRAY_BIN").then(|| path.clone());
    let resolved = resolve_with(&f.ctx, &env, Core::Xray, None).unwrap();
    let out = download_with(&f.ctx, &env, &resolved, &staging).unwrap();
    assert_eq!(std::fs::read(out).unwrap(), fake_elf("local xray"));
    assert!(f.curl_urls().is_empty());
}

// ---- ensure_installed -----------------------------------------------------

#[test]
fn ensure_installed_downloads_when_missing() {
    let mut f = fixture();
    let binary = serve_singbox(&mut f, "1.15.0", &format!("{SB_API}/latest"));
    f.serve();
    let bin = f.ctx.paths.bin.clone();
    versions(&f.exec, vec![(bin.clone(), singbox_says("1.15.0"))]);
    let v =
        ensure_installed_with(&f.ctx, &no_env, Core::Singbox, &CoreVersions::default()).unwrap();
    assert_eq!(v, "1.15.0");
    let live = f.ctx.paths.core_bin(Core::Singbox);
    assert_eq!(std::fs::read(&live).unwrap(), binary);
    let names: Vec<String> = std::fs::read_dir(&bin)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["sing-box"], "staging removed");

    // Installed and unpinned: nothing is fetched again.
    f.exec.clear_history();
    let v =
        ensure_installed_with(&f.ctx, &no_env, Core::Singbox, &CoreVersions::default()).unwrap();
    assert_eq!(v, "1.15.0");
    assert!(f.curl_urls().is_empty());
}

#[test]
fn ensure_installed_follows_the_pin() {
    let mut f = fixture();
    let binary = serve_singbox(&mut f, "1.14.2", &format!("{SB_API}/tags/v1.14.2"));
    f.serve();
    let live = f.ctx.paths.core_bin(Core::Singbox);
    std::fs::create_dir_all(live.parent().unwrap()).unwrap();
    std::fs::write(&live, fake_elf("old")).unwrap();
    let bin = f.ctx.paths.bin.clone();
    versions(
        &f.exec,
        vec![
            (live.clone(), singbox_says("1.13.0")),
            (bin, singbox_says("1.14.2")),
        ],
    );
    let pinned = CoreVersions {
        singbox_pin: Some("v1.14.2".into()),
        ..CoreVersions::default()
    };
    let v = ensure_installed_with(&f.ctx, &no_env, Core::Singbox, &pinned).unwrap();
    assert_eq!(v, "1.14.2");
    assert_eq!(std::fs::read(&live).unwrap(), binary, "replaced in place");

    // `latest` is satisfied by whatever is installed.
    let f = fixture();
    f.serve();
    let live = f.ctx.paths.core_bin(Core::Xray);
    std::fs::create_dir_all(live.parent().unwrap()).unwrap();
    std::fs::write(&live, fake_elf("x")).unwrap();
    versions(&f.exec, vec![(live, xray_says("26.1.1"))]);
    let latest = CoreVersions {
        xray_pin: Some("latest".into()),
        ..CoreVersions::default()
    };
    assert_eq!(
        ensure_installed_with(&f.ctx, &no_env, Core::Xray, &latest).unwrap(),
        "26.1.1"
    );
    assert!(f.curl_urls().is_empty());
}

#[test]
fn ensure_installed_replaces_a_broken_binary_and_refuses_odd_paths() {
    let mut f = fixture();
    let binary = fake_elf("xray new");
    let package = xray_zip(&f.dir, &binary);
    let tag = "v26.3.27";
    let name = "Xray-linux-64.zip";
    let asset = asset_json(repo(Core::Xray), tag, name, &package, true);
    f.route(
        format!("{XR_API}/tags/{tag}"),
        release_json(tag, false, vec![asset]),
    )
    .route(
        Asset::expected_url(repo(Core::Xray), tag, name),
        Reply::body(package),
    );
    f.serve();
    let live = f.ctx.paths.core_bin(Core::Xray);
    std::fs::create_dir_all(live.parent().unwrap()).unwrap();
    std::fs::write(&live, b"garbage").unwrap();
    let bin = f.ctx.paths.bin.clone();
    versions(
        &f.exec,
        vec![
            (
                live.clone(),
                Output::failure(126, "cannot execute binary file"),
            ),
            (bin, xray_says("26.3.27")),
        ],
    );
    let v = ensure_installed_with(&f.ctx, &no_env, Core::Xray, &CoreVersions::default()).unwrap();
    assert_eq!(v, "26.3.27");
    assert_eq!(std::fs::read(&live).unwrap(), binary);

    std::fs::remove_file(&live).unwrap();
    std::fs::create_dir(&live).unwrap();
    let err =
        ensure_installed_with(&f.ctx, &no_env, Core::Xray, &CoreVersions::default()).unwrap_err();
    assert_eq!(
        err.to_string(),
        format!("内核路径不是普通文件: {}", live.display())
    );
    let bad_pin = CoreVersions {
        xray_pin: Some("bad pin".into()),
        ..CoreVersions::default()
    };
    let err = ensure_installed_with(&f.ctx, &no_env, Core::Xray, &bad_pin).unwrap_err();
    assert_eq!(err.to_string(), "版本格式无效: bad pin");
}

// ---- config checks ----------------------------------------------------------

#[test]
fn check_config_commands_and_errors() {
    let f = fixture();
    let config = f.dir.join("sing-box.json");
    f.exec
        .on_fn(
            |c| c.program_name() == "sing-box" && c.args[0] == "check",
            |_| {
                Ok(Output::failure(
                    1,
                    "\x1b[31mFATAL\x1b[0m[0000] decode config at /x.json: inbounds[0]: unknown inbound type: bogus\n",
                ))
            },
        )
        .on_fn(
            |c| c.program_name() == "xray",
            |_| {
                Ok(Output {
                    code: 23,
                    stdout: "Xray 26.3.27 (Xray, Penetrates Everything.) d2758a0 (go1.26.1 linux/amd64)\n\
                             A unified platform for anti-censorship.\n\
                             2026/10/08 18:20:02.221502 [Info] infra/conf/serial: Reading config: x\n\
                             Failed to start: main: failed to load config files\n"
                        .into(),
                    stderr: String::new(),
                })
            },
        );
    let err = check_config(&f.ctx, Core::Singbox, &config).unwrap_err();
    assert_eq!(
        err.to_string(),
        "sing-box 配置校验失败: FATAL[0000] decode config at /x.json: inbounds[0]: unknown inbound type: bogus"
    );
    let err = check_config(&f.ctx, Core::Xray, &config).unwrap_err();
    assert_eq!(
        err.to_string(),
        "Xray 配置校验失败: Failed to start: main: failed to load config files"
    );
    let check_dir = f.ctx.paths.run.join("check");
    let calls = f.exec.history();
    assert_eq!(
        calls[0],
        format!(
            "{} check -D {} -c {}",
            f.ctx.paths.core_bin(Core::Singbox).display(),
            check_dir.display(),
            config.display()
        )
    );
    assert_eq!(
        calls[1],
        format!(
            "{} run -test -c {}",
            f.ctx.paths.core_bin(Core::Xray).display(),
            config.display()
        )
    );
    let mode = std::fs::metadata(&check_dir).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o700);
    let run_mode = std::fs::metadata(&f.ctx.paths.run)
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(run_mode & 0o777, 0o755, "run root stays traversable");
    assert!(f
        .exec
        .calls()
        .iter()
        .all(|c| c.timeout == Some(CHECK_TIMEOUT)));

    let staged = f.dir.join("candidate/xray");
    f.exec.clear_history();
    let ok = fixture();
    ok.exec
        .on("xray", &["run"], Output::success("Configuration OK."));
    check_config_with(&ok.ctx, Core::Xray, &staged, &config).unwrap();
    let quiet = fixture();
    quiet.exec.on("sing-box", &[], Output::failure(2, ""));
    let err = check_config(&quiet.ctx, Core::Singbox, &config).unwrap_err();
    assert_eq!(err.to_string(), "sing-box 配置校验失败: 退出码 2");
}

#[test]
fn check_summary_keeps_the_tail() {
    let text: String = (1..=20).map(|i| format!("line {i}\n")).collect();
    assert_eq!(
        check_summary(Core::Singbox, &text),
        (13..=20)
            .map(|i| format!("line {i}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert_eq!(
        check_summary(Core::Singbox, "\x1b[1;31mred\x1b[0m\r\n"),
        "red"
    );
    assert_eq!(
        check_summary(Core::Xray, &"x".repeat(5000)).chars().count(),
        2000
    );
}

/// Real binaries: `ONEBOX_TEST_SINGBOX=… ONEBOX_TEST_XRAY=… cargo test -- --ignored`.
#[test]
#[ignore = "needs real sing-box / xray binaries"]
fn real_cores_report_versions_and_check_configs() {
    let dir = TempDir::new("cores-real").unwrap();
    let ctx = Ctx {
        paths: crate::paths::Paths::isolated(dir.path()),
        exec: Arc::new(crate::sys::exec::SystemExec),
        ui: Arc::new(crate::ui::ScriptedPrompter::new(Vec::<String>::new())),
    };
    let ok = dir.join("ok.json");
    let bad = dir.join("bad.json");
    std::fs::write(&ok, "{}").unwrap();
    std::fs::write(&bad, r#"{"inbounds":[{"type":"bogus"}]}"#).unwrap();
    for (core, var) in [
        (Core::Singbox, "ONEBOX_TEST_SINGBOX"),
        (Core::Xray, "ONEBOX_TEST_XRAY"),
    ] {
        let Some(bin) = std::env::var_os(var) else {
            continue;
        };
        let bin = PathBuf::from(bin);
        let version = installed_version(&ctx, &bin, core).unwrap();
        assert!(version_valid(&version), "{version}");
        check_config_with(&ctx, core, &bin, &ok).unwrap();
        let err = check_config_with(&ctx, core, &bin, &bad)
            .unwrap_err()
            .to_string();
        assert!(
            err.starts_with(&format!("{} 配置校验失败: ", core.title())),
            "{err}"
        );
        assert!(!err.contains('\x1b') && !err.contains("[Info]"), "{err}");
    }
}

/// The whole pipeline with real curl, github.com and the real Xray
/// 26.3.27 package, using recorded metadata (api.github.com may be rate
/// limited): checksum-file fallback, zip extraction, version probe.
#[test]
#[ignore = "needs network access to github.com (x86_64 only)"]
fn real_xray_download_with_recorded_metadata() {
    const DGST: &str = include_str!("../fetch/fixtures/Xray-linux-64.zip.dgst");
    let dir = TempDir::new("cores-real").unwrap();
    let ctx = Ctx {
        paths: crate::paths::Paths::isolated(dir.path()),
        exec: Arc::new(crate::sys::exec::SystemExec),
        ui: Arc::new(crate::ui::ScriptedPrompter::new(Vec::<String>::new())),
    };
    let tag = "v26.3.27";
    let url = |name: &str| Asset::expected_url(repo(Core::Xray), tag, name);
    let metadata = json!({
        "tag_name": tag, "draft": false, "prerelease": false, "assets": [
            {"name": "Xray-linux-64.zip", "size": 21_136_402u64,
             "browser_download_url": url("Xray-linux-64.zip")},
            {"name": "Xray-linux-64.zip.dgst", "size": DGST.len(),
             "browser_download_url": url("Xray-linux-64.zip.dgst")},
        ]
    });
    let release = Release::parse(metadata.to_string().as_bytes()).unwrap();
    let resolved = accept_release(Core::Xray, release, Some("26.3.27")).unwrap();
    let staging = dir.join("staging");
    std::fs::create_dir(&staging).unwrap();
    let path = download_with(&ctx, &no_env, &resolved, &staging).unwrap();
    assert_eq!(
        installed_version(&ctx, &path, Core::Xray).unwrap(),
        "26.3.27"
    );
}
