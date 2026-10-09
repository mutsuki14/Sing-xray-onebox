use super::*;
use crate::ctx::Ctx;
use crate::domain::fixtures;
use crate::domain::protocol::Protocol;
use crate::host::fetch::testing::{serve, url_arg, Reply};
use crate::host::fetch::Asset;
use crate::sys::exec::{FakeExec, Output};
use crate::sys::fs::{sha256_hex, TempDir};
use crate::ui::ScriptedPrompter;
use crate::update::testing::{
    answer_versions, program, write, Applied, FakeEngine, FakeEnv, Recover,
};
use serde_json::json;
use std::sync::Arc;

const SB_API: &str = "https://api.github.com/repos/SagerNet/sing-box/releases/latest";

fn sb(version: &str) -> String {
    format!("sing-box version {version}\n\nEnvironment: go1.26.8 linux/amd64\n")
}

fn xr(version: &str) -> String {
    format!("Xray {version} (Xray, Penetrates Everything.) 0000000 (go1.26.1 linux/amd64)\n")
}

fn says(core: Core, version: &str) -> Vec<u8> {
    program(&match core {
        Core::Singbox => sb(version),
        Core::Xray => xr(version),
    })
}

struct Fx {
    _dir: TempDir,
    ctx: Ctx,
    exec: Arc<FakeExec>,
    ui: Arc<ScriptedPrompter>,
    env: FakeEnv,
    engine: FakeEngine,
    loaded_hash: crate::state::StateHash,
}

impl Fx {
    /// A node using sing-box (VLESS-REALITY on 443) and/or Xray
    /// (Shadowsocks on 8388), with the given pins.
    fn new(cores: &[Core], singbox_pin: Option<&str>, xray_pin: Option<&str>) -> Fx {
        let dir = TempDir::new("core-update").unwrap();
        let (ctx, exec, ui) = Ctx::test(dir.path());
        exec.on("uname", &["-m"], Output::success("x86_64\n"));
        answer_versions(&exec);
        let inbounds: Vec<(Protocol, u16, Core)> = cores
            .iter()
            .map(|core| match core {
                Core::Singbox => (Protocol::VlessReality, 443, Core::Singbox),
                Core::Xray => (Protocol::Shadowsocks, 8388, Core::Xray),
            })
            .collect();
        let mut cfg = fixtures::config(&inbounds);
        cfg.versions.singbox_pin = singbox_pin.map(str::to_owned);
        cfg.versions.xray_pin = xray_pin.map(str::to_owned);
        StateStore::save(&ctx, &cfg).unwrap();
        let loaded_hash = StateStore::current_hash(&ctx).unwrap();
        Fx {
            _dir: dir,
            ctx,
            exec,
            ui,
            env: FakeEnv::default(),
            engine: FakeEngine::new(Recover::Nothing),
            loaded_hash,
        }
    }

    /// Both cores in use, sing-box 1.14.2 and Xray 26.3.27 installed.
    fn both() -> Fx {
        let fx = Fx::new(&[Core::Singbox, Core::Xray], None, None);
        fx.live(Core::Singbox, "1.14.2");
        fx.live(Core::Xray, "26.3.27");
        fx
    }

    fn live(&self, core: Core, version: &str) {
        write(&self.ctx.paths.core_bin(core), 0o755, &says(core, version));
    }

    /// `ONEBOX_SINGBOX_BIN` / `ONEBOX_XRAY_BIN` pointing at a local core.
    fn offline(&mut self, core: Core, version: &str) -> Vec<u8> {
        let path = self
            .ctx
            .paths
            .root
            .join(format!("offline/{}", core.binary()));
        let bytes = says(core, version);
        write(&path, 0o755, &bytes);
        self.env
            .set(cores::offline_env(core), path.to_string_lossy());
        bytes
    }

    fn run(&self, which: CoreSelection, version: Option<&str>, force: bool) -> Result<()> {
        let env = |key: &str| self.env.get(key);
        let updater = Updater {
            ctx: &self.ctx,
            env: &env,
            engine: &self.engine,
            on_phase: &|_| {},
        };
        updater.update_cores(which, version, force)
    }

    fn applied(&self) -> Vec<Applied> {
        self.engine.applied()
    }

    /// The single apply request.
    fn request(&self) -> Applied {
        let applied = self.applied();
        assert_eq!(applied.len(), 1, "exactly one transaction");
        applied[0].clone()
    }

    fn staging_dirs(&self) -> Vec<PathBuf> {
        match std::fs::read_dir(&self.ctx.paths.bin) {
            Err(_) => Vec::new(),
            Ok(entries) => entries
                .map(|e| e.unwrap().path())
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with(STAGING_PREFIX))
                })
                .collect(),
        }
    }

    fn curl_calls(&self) -> Vec<String> {
        self.exec
            .calls()
            .iter()
            .filter(|c| c.program == "curl")
            .map(|c| url_arg(c).to_owned())
            .collect()
    }
}

fn versions(applied: &Applied) -> &CoreVersions {
    &applied.request.config.versions
}

fn replaced(applied: &Applied) -> Vec<Core> {
    applied.staged.iter().map(|(core, ..)| *core).collect()
}

// ---- pure rules ----------------------------------------------------------

#[test]
fn selections() {
    let cases = [
        (None, Ok(CoreSelection::All)),
        (Some("all"), Ok(CoreSelection::All)),
        (Some("singbox"), Ok(CoreSelection::One(Core::Singbox))),
        (Some("sing-box"), Ok(CoreSelection::One(Core::Singbox))),
        (Some("xray"), Ok(CoreSelection::One(Core::Xray))),
        (Some("Xray"), Err(UNKNOWN_CORE)),
        (Some("1.14.2"), Err(UNKNOWN_CORE)),
    ];
    for (word, want) in cases {
        let got = CoreSelection::parse(word).map_err(|e| e.to_string());
        assert_eq!(got, want.map_err(str::to_owned), "{word:?}");
    }
    assert!(CoreSelection::All.includes(Core::Xray));
    assert!(!CoreSelection::One(Core::Singbox).includes(Core::Xray));
}

#[test]
fn targets_follow_the_pin_table() {
    use CoreSelection::{All, One};
    let exact = Wanted::Exact("1.13.0".into());
    let t = |core, selection, wanted: &Wanted, pin| {
        let t = target(core, selection, wanted, pin);
        (t.wanted, t.pin, t.lenient)
    };
    let s = |v: &str| v.to_owned();
    let cases = [
        // bare update: the pin, else the recommendation; pin unchanged
        (
            t(Core::Singbox, All, &Wanted::Default, Some("1.12.0")),
            (s("1.12.0"), Some(s("1.12.0")), true),
        ),
        (
            t(Core::Singbox, All, &Wanted::Default, None),
            (s("latest"), None, true),
        ),
        (
            t(Core::Xray, All, &Wanted::Default, None),
            (s("26.3.27"), None, true),
        ),
        // update CORE: the recommendation, pin cleared
        (
            t(
                Core::Xray,
                One(Core::Xray),
                &Wanted::Default,
                Some("26.4.0"),
            ),
            (s("26.3.27"), None, false),
        ),
        (
            t(
                Core::Singbox,
                One(Core::Singbox),
                &Wanted::Default,
                Some("1.12.0"),
            ),
            (s("latest"), None, false),
        ),
        // latest: pin cleared
        (
            t(Core::Xray, One(Core::Xray), &Wanted::Latest, Some("26.4.0")),
            (s("latest"), None, false),
        ),
        (
            t(Core::Singbox, All, &Wanted::Latest, Some("1.12.0")),
            (s("latest"), None, false),
        ),
        // VERSION: pinned
        (
            t(Core::Singbox, One(Core::Singbox), &exact, None),
            (s("1.13.0"), Some(s("1.13.0")), false),
        ),
        (
            t(Core::Singbox, All, &exact, Some("1.12.0")),
            (s("1.13.0"), Some(s("1.13.0")), false),
        ),
    ];
    for (got, want) in cases {
        assert_eq!(got, want);
    }
}

#[test]
fn decisions() {
    use Decision::*;
    let ok = |current, target, force, lenient| {
        decide(Core::Singbox, current, target, force, lenient).unwrap()
    };
    assert_eq!(ok(None, "1.0.0", false, false), Install);
    assert_eq!(ok(Some("1.14.2"), "1.14.3", false, false), Install);
    assert_eq!(ok(Some("1.14.2"), "1.14.2", false, false), Same);
    assert_eq!(ok(Some("1.14.2"), "1.14.2", true, false), Install);
    assert_eq!(ok(Some("1.14.2"), "1.14.1", true, false), Install);
    assert_eq!(ok(Some("1.14.2"), "1.14.1", false, true), KeepNewer);
    assert_eq!(ok(Some("1.13.0"), "1.13.0-beta.2", false, true), KeepNewer);
    // Not comparable: anything but equality installs.
    assert_eq!(ok(Some("1.12"), "1.11", false, false), Install);
    let err = decide(Core::Xray, Some("26.5.0"), "26.3.27", false, false).unwrap_err();
    assert_eq!(
        err.to_string(),
        "Xray 26.3.27 低于已安装的 26.5.0，拒绝降级；确认降级请追加 --force"
    );
}

#[test]
fn descriptions_and_prompt() {
    use Decision::*;
    let cases = [
        (Install, Some("1.14.2"), "1.14.3", "sing-box 1.14.2 → 1.14.3"),
        (Install, Some("1.14.2"), "1.14.2", "sing-box 1.14.2：重新安装"),
        (Install, None, "1.14.3", "sing-box：安装 1.14.3"),
        (Same, Some("1.14.2"), "1.14.2", "sing-box 1.14.2 已是目标版本"),
        (
            KeepNewer,
            Some("1.14.3"),
            "1.14.2",
            "sing-box 1.14.3 高于目标版本 1.14.2，保持不变；降级请执行 onebox update singbox 1.14.2 --force",
        ),
    ];
    for (decision, current, target, text) in cases {
        assert_eq!(describe(Core::Singbox, current, target, decision), text);
    }
    assert_eq!(
        xray_prompt("26.5.0"),
        "指定的 Xray 26.5.0 可能拒绝 sing-box REALITY 客户端；经过测试版本为 26.3.27，继续？"
    );
}

// ---- update flows ------------------------------------------------------------

#[test]
fn bare_update_installs_what_is_newer_and_keeps_what_is_current() {
    let mut fx = Fx::both();
    let staged = fx.offline(Core::Singbox, "1.14.3");
    fx.run(CoreSelection::All, None, false).unwrap();
    let applied = fx.request();
    assert_eq!(replaced(&applied), [Core::Singbox]);
    let (_, path, bytes) = &applied.staged[0];
    assert_eq!(bytes, &staged);
    let dir = path.parent().unwrap();
    assert_eq!(dir.parent().unwrap(), fx.ctx.paths.bin);
    let name = dir.file_name().unwrap().to_str().unwrap();
    let token = name.strip_prefix(STAGING_PREFIX).unwrap();
    assert!(token.len() == 24 && token.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(path.file_name().unwrap(), "sing-box");
    let v = versions(&applied);
    assert_eq!(v.singbox.as_deref(), Some("1.14.3"));
    assert_eq!(
        (v.singbox_pin.as_deref(), v.xray_pin.as_deref()),
        (None, None)
    );
    assert_eq!(applied.request.reason, REASON);
    assert_eq!(applied.request.expected, fx.loaded_hash);
    assert!(fx.staging_dirs().is_empty(), "removed after success");
    assert!(
        fx.ui.prompts().is_empty(),
        "the tested Xray needs no question"
    );
    assert!(fx.curl_calls().is_empty());
    assert_eq!(fx.engine.recover_calls(), 1);
}

#[test]
fn nothing_is_applied_when_everything_is_already_current() {
    let fx = Fx::new(&[Core::Singbox, Core::Xray], Some("1.14.2"), None);
    fx.live(Core::Singbox, "1.14.2");
    fx.live(Core::Xray, "26.3.27");
    fx.run(CoreSelection::All, None, false).unwrap();
    assert!(fx.applied().is_empty());
    assert!(fx.staging_dirs().is_empty());
    assert!(fx.curl_calls().is_empty(), "exact targets need no lookup");
}

#[test]
fn an_explicit_version_is_pinned_and_an_untested_xray_needs_consent() {
    for (answer, accepted) in [("y", true), ("n", false)] {
        let mut fx = Fx::both();
        let staged = fx.offline(Core::Xray, "26.4.0");
        fx.ui.push(answer);
        let result = fx.run(CoreSelection::One(Core::Xray), Some("v26.4.0"), false);
        assert_eq!(fx.ui.prompts(), [xray_prompt("26.4.0")]);
        if accepted {
            result.unwrap();
            let applied = fx.request();
            assert_eq!(replaced(&applied), [Core::Xray]);
            assert_eq!(applied.staged[0].2, staged);
            let v = versions(&applied);
            assert_eq!(v.xray_pin.as_deref(), Some("26.4.0"));
            assert_eq!(v.xray.as_deref(), Some("26.4.0"));
            assert_eq!(v.singbox_pin, None, "other cores untouched");
        } else {
            assert_eq!(result.unwrap_err().to_string(), CANCELLED);
            assert!(fx.applied().is_empty());
            assert!(fx.staging_dirs().is_empty());
        }
    }
    // -y accepts.
    let mut fx = Fx::both();
    fx.offline(Core::Xray, "26.4.0");
    fx.ui.set_assume_yes(true);
    fx.run(CoreSelection::One(Core::Xray), Some("26.4.0"), false)
        .unwrap();
    assert_eq!(fx.applied().len(), 1);
}

#[test]
fn the_tested_xray_needs_no_consent() {
    let mut fx = Fx::new(&[Core::Xray], None, None);
    fx.live(Core::Xray, "26.2.0");
    fx.offline(Core::Xray, "26.3.27");
    fx.run(CoreSelection::One(Core::Xray), None, false).unwrap();
    assert!(fx.ui.prompts().is_empty());
    assert_eq!(replaced(&fx.request()), [Core::Xray]);
}

#[test]
fn downgrades_need_force() {
    let mut fx = Fx::both();
    let err = fx
        .run(CoreSelection::One(Core::Singbox), Some("1.14.1"), false)
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "sing-box 1.14.1 低于已安装的 1.14.2，拒绝降级；确认降级请追加 --force"
    );
    assert!(fx.applied().is_empty() && fx.staging_dirs().is_empty());
    fx.offline(Core::Singbox, "1.14.1");
    fx.run(CoreSelection::One(Core::Singbox), Some("1.14.1"), true)
        .unwrap();
    let v = versions(&fx.request()).clone();
    assert_eq!(v.singbox_pin.as_deref(), Some("1.14.1"));
    assert_eq!(v.singbox.as_deref(), Some("1.14.1"));
}

#[test]
fn an_offline_core_older_than_installed_counts_as_a_downgrade() {
    // `latest` is resolved first; the decision uses what the binary says.
    let mut fx = Fx::both();
    fx.offline(Core::Singbox, "1.14.0");
    let err = fx
        .run(CoreSelection::One(Core::Singbox), Some("latest"), false)
        .unwrap_err();
    assert!(err.to_string().contains("拒绝降级"), "{err}");
}

#[test]
fn bare_update_keeps_a_newer_core_instead_of_failing() {
    let fx = Fx::new(&[Core::Singbox, Core::Xray], Some("1.14.2"), None);
    fx.live(Core::Singbox, "1.14.2");
    fx.live(Core::Xray, "26.5.0");
    fx.run(CoreSelection::All, None, false).unwrap();
    assert!(fx.applied().is_empty(), "nothing changes");
    assert!(fx.ui.prompts().is_empty());
    // Asking for that core explicitly refuses the downgrade.
    let err = fx
        .run(CoreSelection::One(Core::Xray), None, false)
        .unwrap_err();
    assert!(err
        .to_string()
        .starts_with("Xray 26.3.27 低于已安装的 26.5.0"));
}

#[test]
fn update_core_and_latest_clear_the_pin() {
    for version in [None, Some("latest")] {
        let mut fx = Fx::new(
            &[Core::Singbox, Core::Xray],
            Some("1.14.2"),
            Some("26.3.27"),
        );
        fx.live(Core::Singbox, "1.14.2");
        fx.live(Core::Xray, "26.3.27");
        fx.offline(Core::Singbox, "1.14.3");
        fx.run(CoreSelection::One(Core::Singbox), version, false)
            .unwrap();
        let applied = fx.request();
        assert_eq!(replaced(&applied), [Core::Singbox], "{version:?}");
        let v = versions(&applied);
        assert_eq!(v.singbox_pin, None, "{version:?}");
        assert_eq!(v.xray_pin.as_deref(), Some("26.3.27"), "{version:?}");
    }
    // A pin change alone is still applied (without replacing anything).
    let fx = Fx::new(&[Core::Xray], None, Some("26.3.27"));
    fx.live(Core::Xray, "26.3.27");
    fx.run(CoreSelection::One(Core::Xray), None, false).unwrap();
    let applied = fx.request();
    assert!(applied.request.intents.replace_cores.is_empty());
    assert_eq!(versions(&applied).xray_pin, None);
    assert!(fx.staging_dirs().is_empty());
}

#[test]
fn bare_update_follows_pins() {
    let mut fx = Fx::new(&[Core::Singbox], Some("1.14.3"), None);
    fx.live(Core::Singbox, "1.14.2");
    fx.offline(Core::Singbox, "1.14.3");
    fx.run(CoreSelection::All, None, false).unwrap();
    let applied = fx.request();
    assert_eq!(replaced(&applied), [Core::Singbox]);
    assert_eq!(versions(&applied).singbox_pin.as_deref(), Some("1.14.3"));
}

#[test]
fn only_cores_in_use_are_targets() {
    // An Xray binary left on disk is not part of the update (G-8.1#2).
    let mut fx = Fx::new(&[Core::Singbox], None, None);
    fx.live(Core::Singbox, "1.14.2");
    fx.live(Core::Xray, "26.2.0");
    fx.offline(Core::Singbox, "1.14.3");
    fx.run(CoreSelection::All, None, false).unwrap();
    assert_eq!(replaced(&fx.request()), [Core::Singbox]);
    let err = fx
        .run(CoreSelection::One(Core::Xray), None, false)
        .unwrap_err();
    assert_eq!(err.to_string(), "当前配置未使用 Xray，无需更新");
    // A missing live binary is simply installed.
    let mut fx = Fx::new(&[Core::Singbox], None, None);
    fx.offline(Core::Singbox, "1.14.3");
    fx.run(CoreSelection::All, None, false).unwrap();
    assert_eq!(replaced(&fx.request()), [Core::Singbox]);
}

#[test]
fn one_version_for_two_cores_is_refused() {
    let fx = Fx::both();
    let err = fx
        .run(CoreSelection::All, Some("1.14.3"), false)
        .unwrap_err();
    assert_eq!(err.to_string(), ONE_VERSION_TWO_CORES);
    // Fine when the node uses one core only, and `latest` fits both.
    let mut fx = Fx::new(&[Core::Singbox], None, None);
    fx.live(Core::Singbox, "1.14.2");
    fx.offline(Core::Singbox, "1.14.3");
    fx.run(CoreSelection::All, Some("1.14.3"), false).unwrap();
    assert_eq!(
        versions(&fx.request()).singbox_pin.as_deref(),
        Some("1.14.3")
    );
    let mut fx = Fx::both();
    fx.offline(Core::Singbox, "1.14.3");
    fx.offline(Core::Xray, "26.3.27");
    fx.run(CoreSelection::All, Some("latest"), false).unwrap();
    assert_eq!(replaced(&fx.request()), [Core::Singbox]);
}

#[test]
fn a_failed_transaction_keeps_the_verified_files() {
    let mut fx = Fx::both();
    fx.engine.apply_error = Some("内核启动失败");
    fx.offline(Core::Singbox, "1.14.3");
    let err = fx.run(CoreSelection::All, None, false).unwrap_err();
    assert_eq!(err.to_string(), "内核启动失败");
    let dirs = fx.staging_dirs();
    assert_eq!(dirs.len(), 1);
    assert_eq!(
        std::fs::read(dirs[0].join("sing-box")).unwrap(),
        says(Core::Singbox, "1.14.3")
    );
}

#[test]
fn errors_before_the_transaction() {
    let fx = Fx::both();
    let err = fx
        .run(CoreSelection::One(Core::Singbox), Some("../x1"), false)
        .unwrap_err();
    assert_eq!(err.to_string(), "版本格式无效: ../x1");
    assert_eq!(fx.engine.recover_calls(), 0, "checked before the locks");

    let held = FileLock::acquire(&fx.ctx.paths.update_lock(), "x").unwrap();
    let err = fx.run(CoreSelection::All, None, false).unwrap_err();
    assert!(matches!(&err, Error::Busy(m) if m == UPDATE_BUSY), "{err}");
    drop(held);

    let mut fx = Fx::both();
    fx.engine = FakeEngine::new(Recover::Refuse("存在未完成事务，请先 recover"));
    let err = fx.run(CoreSelection::All, None, false).unwrap_err();
    assert_eq!(err.to_string(), "存在未完成事务，请先 recover");

    let dir = TempDir::new("core-update-none").unwrap();
    let (ctx, _, _) = Ctx::test(dir.path());
    let engine = FakeEngine::new(Recover::Nothing);
    let env = |_: &str| None;
    let updater = Updater {
        ctx: &ctx,
        env: &env,
        engine: &engine,
        on_phase: &|_| {},
    };
    let err = updater
        .update_cores(CoreSelection::All, None, false)
        .unwrap_err();
    assert!(matches!(err, Error::NotInstalled), "{err}");
}

// ---- the network path ----------------------------------------------------------

fn singbox_package(version: &str, binary: &[u8]) -> (String, Vec<u8>) {
    let name = format!("sing-box-{version}-linux-amd64-musl.tar.gz");
    let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::fast(),
    ));
    let mut header = tar::Header::new_gnu();
    header.set_size(binary.len() as u64);
    header.set_mode(0o755);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_cksum();
    builder
        .append_data(
            &mut header,
            format!("sing-box-{version}-linux-amd64-musl/sing-box"),
            binary,
        )
        .unwrap();
    let package = builder.into_inner().unwrap().finish().unwrap();
    (name, package)
}

fn singbox_release(version: &str, name: &str, package: &[u8]) -> Reply {
    let tag = format!("v{version}");
    Reply::body(
        json!({
            "tag_name": tag,
            "draft": false,
            "prerelease": false,
            "body": "",
            "assets": [{
                "name": name,
                "size": package.len(),
                "browser_download_url": Asset::expected_url(cores::repo(Core::Singbox), &tag, name),
                "digest": format!("sha256:{}", sha256_hex(package)),
            }],
        })
        .to_string(),
    )
}

#[test]
fn releases_are_downloaded_and_verified_into_the_staging_directory() {
    let fx = Fx::both();
    let binary = says(Core::Singbox, "1.14.3");
    let (name, package) = singbox_package("1.14.3", &binary);
    let url = Asset::expected_url(cores::repo(Core::Singbox), "v1.14.3", &name);
    serve(
        &fx.exec,
        vec![
            (SB_API.into(), singbox_release("1.14.3", &name, &package)),
            (url.clone(), Reply::body(package.clone())),
        ],
    );
    fx.run(CoreSelection::All, None, false).unwrap();
    let applied = fx.request();
    assert_eq!(replaced(&applied), [Core::Singbox]);
    assert_eq!(applied.staged[0].2, binary);
    assert_eq!(versions(&applied).singbox.as_deref(), Some("1.14.3"));
    // Xray 26.3.27 is the target and installed: no lookup for it.
    assert_eq!(fx.curl_calls(), [SB_API.to_owned(), url]);
    assert!(fx.staging_dirs().is_empty());
}

#[test]
fn a_failed_download_leaves_no_staging_directory() {
    let fx = Fx::both();
    let binary = says(Core::Singbox, "1.14.3");
    let (name, package) = singbox_package("1.14.3", &binary);
    // The package is not served (404).
    serve(
        &fx.exec,
        vec![(SB_API.into(), singbox_release("1.14.3", &name, &package))],
    );
    let err = fx.run(CoreSelection::All, None, false).unwrap_err();
    assert!(err.to_string().contains("404"), "{err}");
    assert!(fx.applied().is_empty());
    assert!(fx.staging_dirs().is_empty());
}
