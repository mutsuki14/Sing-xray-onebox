use super::*;
use crate::frp::testing::{
    asset_json, frps_versions, no_env, package, package_name, release_json, release_routes, API,
};
use crate::host::fetch::testing::{routes, serve, Reply};
use crate::sys::exec::{FakeExec, Output};
use std::sync::Arc;

struct Fixture {
    dir: TempDir,
    ctx: Ctx,
    exec: Arc<FakeExec>,
}

impl Fixture {
    fn new() -> Fixture {
        let dir = TempDir::new("frp-release").unwrap();
        let (ctx, exec, _) = Ctx::test(dir.path());
        exec.on("uname", &["-m"], Output::success("x86_64\n"));
        fs::create_dir_all(dir.join("stage")).unwrap();
        Fixture { dir, ctx, exec }
    }

    fn installed(&self) -> PathBuf {
        self.ctx.paths.frp_bin.join("frps")
    }

    /// Put an executable file at the installed path.
    fn install(&self) {
        fs::create_dir_all(&self.ctx.paths.frp_bin).unwrap();
        fs::write(self.installed(), b"old").unwrap();
    }

    fn prepare(&self, requested: &str) -> Result<Staged> {
        prepare(
            &self.ctx,
            &no_env,
            requested,
            &self.installed(),
            &self.dir.join("stage"),
        )
    }

    fn curls(&self) -> usize {
        self.exec
            .calls()
            .iter()
            .filter(|c| c.program == "curl")
            .count()
    }
}

#[test]
fn plans() {
    assert_eq!(
        plan("latest", Some("0.71.0")),
        BinaryPlan::Fetch(Which::Latest)
    );
    assert_eq!(
        plan("0.71.0", Some("0.71.0")),
        BinaryPlan::Keep("0.71.0".into())
    );
    assert_eq!(
        plan("0.72.0", Some("0.71.0")),
        BinaryPlan::Fetch(Which::Tag("v0.72.0".into()))
    );
    assert_eq!(
        plan("0.71.0", None),
        BinaryPlan::Fetch(Which::Tag("v0.71.0".into()))
    );
}

#[test]
fn the_installed_version_needs_no_network() {
    let f = Fixture::new();
    f.install();
    frps_versions(&f.exec, &f.installed(), Some("0.71.0"), "x");
    let staged = f.prepare("0.71.0").unwrap();
    assert_eq!((staged.version.as_str(), staged.binary), ("0.71.0", None));
    assert_eq!(f.curls(), 0);
}

#[test]
fn downloads_verifies_and_stages_the_binary() {
    let f = Fixture::new();
    serve(&f.exec, release_routes("0.71.0", false));
    frps_versions(&f.exec, &f.installed(), None, "0.71.0");
    let staged = f.prepare("0.71.0").unwrap();
    let binary = staged.binary.clone().unwrap();
    assert_eq!(fs::read(&binary).unwrap(), b"\x7fELF fake frps");
    let mode = fs::metadata(&binary).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o755);
    assert!(binary.starts_with(f.dir.join("stage")));
    // Only the binary is left in the stage; dropping it cleans up.
    let stage = binary.parent().unwrap().to_path_buf();
    assert_eq!(fs::read_dir(&stage).unwrap().count(), 1);
    drop(staged);
    assert!(!stage.exists());
}

#[test]
fn latest_equal_to_installed_keeps_the_binary() {
    let f = Fixture::new();
    f.install();
    serve(&f.exec, release_routes("0.72.0", true));
    frps_versions(&f.exec, &f.installed(), Some("0.72.0"), "x");
    let staged = f.prepare("latest").unwrap();
    assert_eq!((staged.version.as_str(), staged.binary), ("0.72.0", None));
    assert_eq!(f.curls(), 1, "metadata only");
}

#[test]
fn checksum_file_fallback() {
    let f = Fixture::new();
    let bytes = package("0.71.0");
    let name = package_name("0.71.0");
    let sums = format!("{}  {name}\n", crate::sys::fs::sha256_hex(&bytes));
    let doc = release_json(
        "0.71.0",
        vec![
            asset_json("0.71.0", &name, &bytes, false),
            asset_json("0.71.0", CHECKSUMS, sums.as_bytes(), false),
        ],
    );
    let base = "https://github.com/fatedier/frp/releases/download/v0.71.0";
    serve(
        &f.exec,
        routes([
            (&format!("{API}/tags/v0.71.0"), Reply::body(doc.to_string())),
            (&format!("{base}/{name}"), Reply::body(bytes)),
            (&format!("{base}/{CHECKSUMS}"), Reply::body(sums)),
        ]),
    );
    frps_versions(&f.exec, &f.installed(), None, "0.71.0");
    assert!(f.prepare("0.71.0").unwrap().binary.is_some());
}

#[test]
fn release_rules() {
    let release = |tag: &str, prerelease: bool| Release {
        tag: tag.into(),
        draft: false,
        prerelease,
        body: String::new(),
        assets: vec![],
    };
    assert_eq!(
        check_release(&release("v0.71.0", false), "latest").unwrap(),
        "0.71.0"
    );
    for (r, requested, message) in [
        (release("v0.71.0", true), "latest", "拒绝非稳定 FRP Release"),
        (release("0.71.0", false), "latest", "FRP Release 标签无效"),
        (
            release("v0.70.0", false),
            "latest",
            "FRP 版本须为 0.71.0 或更新的稳定版本",
        ),
        (
            release("v0.72.0", false),
            "0.71.0",
            "FRP Release 标签与请求不符",
        ),
    ] {
        assert_eq!(
            check_release(&r, requested).unwrap_err().to_string(),
            message
        );
    }
}

#[test]
fn bad_packages_are_refused() {
    // A version mismatch after extraction.
    let f = Fixture::new();
    serve(&f.exec, release_routes("0.71.0", false));
    frps_versions(&f.exec, &f.installed(), None, "0.70.9");
    assert_eq!(
        f.prepare("0.71.0").unwrap_err().to_string(),
        "frps 二进制版本校验失败"
    );
    // No package for this architecture.
    let f = Fixture::new();
    let doc = release_json("0.71.0", vec![]);
    serve(
        &f.exec,
        routes([(&format!("{API}/tags/v0.71.0"), Reply::body(doc.to_string()))]),
    );
    assert_eq!(
        f.prepare("0.71.0").unwrap_err().to_string(),
        "FRP 安装包缺失或重复"
    );
    // An unsupported CPU.
    let f = Fixture::new();
    let exec = Arc::new(FakeExec::new());
    exec.on("uname", &["-m"], Output::success("s390x\n"));
    serve(&exec, release_routes("0.71.0", false));
    let mut ctx = f.ctx.clone();
    ctx.exec = exec;
    let err = prepare(
        &ctx,
        &no_env,
        "0.71.0",
        &f.installed(),
        &f.dir.join("stage"),
    );
    assert_eq!(err.unwrap_err().to_string(), "FRP 不支持当前 CPU 架构");
}

#[test]
fn a_tampered_package_fails_the_digest() {
    let f = Fixture::new();
    let name = package_name("0.71.0");
    let doc = release_json(
        "0.71.0",
        vec![asset_json("0.71.0", &name, &package("0.71.0"), true)],
    );
    let mut evil = package("0.71.0");
    let last = evil.len() - 1;
    evil[last] ^= 1;
    let base = "https://github.com/fatedier/frp/releases/download/v0.71.0";
    serve(
        &f.exec,
        routes([
            (&format!("{API}/tags/v0.71.0"), Reply::body(doc.to_string())),
            (&format!("{base}/{name}"), Reply::body(evil)),
        ]),
    );
    assert!(f.prepare("0.71.0").is_err());
    let leftovers = fs::read_dir(f.dir.join("stage")).unwrap().count();
    assert_eq!(leftovers, 0);
}
