use super::*;
use crate::ctx::Ctx;
use crate::domain::fixtures;
use crate::domain::protocol::Protocol;
use crate::host::fetch::testing::{serve, url_arg, Reply};
use crate::host::fetch::Asset;
use crate::state::v2::fixtures as v2;
use crate::sys::exec::{FakeExec, Output};
use crate::sys::fs::{sha256_hex, TempDir};
use crate::ui::{Prompter, ScriptedPrompter, NO_TERMINAL};
use crate::update::testing::{
    answer_versions, program, write, Applied, FakeEngine, FakeEnv, Recover, Warnings,
};
use serde_json::json;
use std::sync::{Arc, Mutex};

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
    warnings: Warnings,
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
            warnings: Warnings::default(),
            loaded_hash,
        }
    }

    /// A node still in v2 form (sing-box only: v2 preset 1 with `pairs`),
    /// with a v2 subscription holding two devices.
    fn v2(pairs: &[(&str, &str)]) -> Fx {
        let fx = Fx::new(&[Core::Singbox], None, None);
        let values = v2::with(v2::preset1(), pairs);
        write(&fx.ctx.paths.state(), 0o600, &v2::file(&values));
        let settings = v2::settings("ip", "203.0.113.10", 8448, "none");
        write(
            &fx.ctx.paths.subscription().join("settings.json"),
            0o600,
            settings.to_string().as_bytes(),
        );
        Fx {
            loaded_hash: StateStore::current_hash(&fx.ctx).unwrap(),
            ..fx
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
            warn: &|m| self.warnings.push(m),
        };
        updater.update_cores(which, version, force)
    }

    /// Answer every confirmation with yes after running `hook`.
    fn on_confirm(&mut self, hook: impl Fn() + Send + Sync + 'static) {
        self.ctx.ui = Arc::new(Hooked(Box::new(hook)));
    }

    fn saved(&self) -> NodeConfig {
        StateStore::load_required(&self.ctx).unwrap().config
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

/// An interactive prompter that runs a hook, then says yes, on every
/// confirmation (to look at the locks or change the node meanwhile).
struct Hooked(Box<dyn Fn() + Send + Sync>);

impl Prompter for Hooked {
    fn interactive(&self) -> bool {
        true
    }
    fn assume_yes(&self) -> bool {
        false
    }
    fn input(&self, _: &str, _: &str) -> Result<String> {
        Err(Error::msg("unexpected input"))
    }
    fn input_with(&self, _: &str, _: &str, _: &dyn Fn(&str) -> Result<String>) -> Result<String> {
        Err(Error::msg("unexpected input"))
    }
    fn confirm(&self, _: &str, _: bool) -> Result<bool> {
        (self.0)();
        Ok(true)
    }
    fn select(&self, _: &str, _: &[String], _: usize, _: bool) -> Result<Option<usize>> {
        Err(Error::msg("unexpected select"))
    }
    fn select_many(&self, _: &str, _: &[String], _: &[usize]) -> Result<Vec<usize>> {
        Err(Error::msg("unexpected select"))
    }
    fn secret(&self, _: &str) -> Result<String> {
        Err(Error::msg("unexpected secret"))
    }
}

fn busy(path: &Path) -> bool {
    matches!(FileLock::acquire(path, "busy"), Err(Error::Busy(_)))
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
        xray_warning("26.5.0"),
        "指定的 Xray 26.5.0 可能拒绝 sing-box REALITY 客户端；经过测试版本为 26.3.27"
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
    // Once before planning, once more under the lock it commits under.
    assert_eq!(fx.engine.recover_calls(), 2);
    assert!(fx.warnings.all().is_empty());
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
        assert_eq!(fx.warnings.all(), [xray_warning("26.4.0")]);
        assert_eq!(fx.ui.prompts(), [CONTINUE]);
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
    // -y accepts, and the warning is still printed.
    let mut fx = Fx::both();
    fx.offline(Core::Xray, "26.4.0");
    fx.ui.set_assume_yes(true);
    fx.run(CoreSelection::One(Core::Xray), Some("26.4.0"), false)
        .unwrap();
    assert_eq!(fx.warnings.all(), [xray_warning("26.4.0")]);
    assert_eq!(replaced(&fx.request()), [Core::Xray]);
    // Without a terminal and without -y nobody can consent: refused after
    // the warning, before anything is downloaded.
    let mut fx = Fx::both();
    fx.offline(Core::Xray, "26.4.0");
    fx.ui.set_interactive(false);
    let err = fx
        .run(CoreSelection::One(Core::Xray), Some("26.4.0"), false)
        .unwrap_err();
    assert_eq!(err.to_string(), NO_TERMINAL);
    assert_eq!(fx.warnings.all(), [xray_warning("26.4.0")]);
    assert!(fx.applied().is_empty() && fx.staging_dirs().is_empty());
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
}

#[test]
fn a_pin_only_change_is_saved_without_a_transaction() {
    // `update xray` with the pinned 26.3.27 installed clears the pin
    // (`install --xray-version 26.3.27` set it): nothing restarts.
    let fx = Fx::new(&[Core::Xray], None, Some("26.3.27"));
    fx.live(Core::Xray, "26.3.27");
    fx.run(CoreSelection::One(Core::Xray), None, false).unwrap();
    assert!(fx.applied().is_empty(), "no apply for metadata");
    assert_eq!(fx.saved().versions.xray_pin, None);
    assert!(fx.staging_dirs().is_empty());
    assert_eq!(fx.engine.recover_calls(), 2);
    // `update singbox 1.14.2` with 1.14.2 installed sets the pin.
    let fx = Fx::both();
    fx.run(CoreSelection::One(Core::Singbox), Some("1.14.2"), false)
        .unwrap();
    assert!(fx.applied().is_empty());
    let saved = fx.saved();
    assert_eq!(saved.versions.singbox_pin.as_deref(), Some("1.14.2"));
    assert_eq!(saved.versions.xray_pin, None, "other pins untouched");
    let mut expected = fx::original(&fx);
    expected.versions.singbox_pin = Some("1.14.2".into());
    assert_eq!(saved, expected, "nothing else changes");
    assert!(fx.curl_calls().is_empty());
    // Running it again changes nothing at all.
    let hash = StateStore::current_hash(&fx.ctx).unwrap();
    fx.run(CoreSelection::One(Core::Singbox), Some("1.14.2"), false)
        .unwrap();
    assert_eq!(StateStore::current_hash(&fx.ctx).unwrap(), hash);
}

mod fx {
    use super::*;

    /// The configuration [`Fx::both`] starts from.
    pub fn original(fx: &Fx) -> NodeConfig {
        let mut cfg = fixtures::config(&[
            (Protocol::VlessReality, 443, Core::Singbox),
            (Protocol::Shadowsocks, 8388, Core::Xray),
        ]);
        cfg.installed_at = fx.saved().installed_at;
        cfg
    }
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
        warn: &|m| panic!("unexpected warning {m}"),
    };
    let err = updater
        .update_cores(CoreSelection::All, None, false)
        .unwrap_err();
    assert!(matches!(err, Error::NotInstalled), "{err}");
}

// ---- locks, concurrent changes, v2 configurations -------------------------

#[test]
fn the_node_lock_is_free_while_asking_and_downloading() {
    let mut fx = Fx::both();
    fx.offline(Core::Xray, "26.4.0");
    let paths = fx.ctx.paths.clone();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = seen.clone();
    fx.on_confirm(move || {
        let locks = (busy(&paths.lock()), busy(&paths.update_lock()));
        record.lock().unwrap().push(locks);
    });
    fx.run(CoreSelection::One(Core::Xray), Some("26.4.0"), false)
        .unwrap();
    // Renewals and device changes may take the node lock meanwhile; a
    // second update may not start.
    assert_eq!(*seen.lock().unwrap(), [(false, true)]);
    assert_eq!(replaced(&fx.request()), [Core::Xray]);
}

#[test]
fn a_change_while_asking_is_committed_on_top_when_the_plan_still_holds() {
    let mut fx = Fx::both();
    fx.offline(Core::Xray, "26.4.0");
    let ctx = fx.ctx.clone();
    fx.on_confirm(move || {
        let mut cfg = StateStore::load_required(&ctx).unwrap().config;
        cfg.node_name = "东京".into();
        StateStore::save(&ctx, &cfg).unwrap();
    });
    fx.run(CoreSelection::One(Core::Xray), Some("26.4.0"), false)
        .unwrap();
    let applied = fx.request();
    assert_eq!(applied.request.config.node_name, "东京");
    assert_eq!(
        applied.request.expected,
        StateStore::current_hash(&fx.ctx).unwrap(),
        "the CAS hash is the re-read one"
    );
    assert_eq!(versions(&applied).xray_pin.as_deref(), Some("26.4.0"));
}

#[test]
fn a_change_that_breaks_the_plan_is_a_conflict() {
    // The live Xray changed while the user was asked.
    let mut fx = Fx::both();
    fx.offline(Core::Xray, "26.4.0");
    let (live, bytes) = (
        fx.ctx.paths.core_bin(Core::Xray),
        says(Core::Xray, "26.3.28"),
    );
    fx.on_confirm(move || write(&live, 0o755, &bytes));
    let err = fx
        .run(CoreSelection::One(Core::Xray), Some("26.4.0"), false)
        .unwrap_err();
    assert!(matches!(err, Error::Conflict), "{err}");
    assert!(fx.applied().is_empty());
    // The verified download is kept and named, as after any failure.
    assert_eq!(fx.staging_dirs().len(), 1);
    let kept = format!(
        "已验证的内核更新文件保留: {}",
        fx.staging_dirs()[0].display()
    );
    assert_eq!(fx.warnings.all(), [xray_warning("26.4.0"), kept]);

    // The node stopped using the selected core meanwhile.
    let mut fx = Fx::both();
    fx.offline(Core::Xray, "26.4.0");
    let ctx = fx.ctx.clone();
    fx.on_confirm(move || {
        let mut cfg = StateStore::load_required(&ctx).unwrap().config;
        cfg.inbounds.retain(|i| i.core != Core::Xray);
        StateStore::save(&ctx, &cfg).unwrap();
    });
    let err = fx
        .run(CoreSelection::One(Core::Xray), Some("26.4.0"), false)
        .unwrap_err();
    assert_eq!(err.to_string(), "当前配置未使用 Xray，无需更新");
    assert!(fx.applied().is_empty());
}

#[test]
fn a_v2_configuration_shows_its_warnings_and_carries_its_devices() {
    let pairs = [("SB_VERSION", "1.14.2"), ("SB_VERSION_WANT", "1.12.0")];
    let mut fx = Fx::v2(&pairs);
    fx.live(Core::Singbox, "1.14.2");
    fx.offline(Core::Singbox, "1.14.3");
    let Origin::V2 { warnings, .. } = StateStore::load_required(&fx.ctx).unwrap().origin else {
        panic!("v2 expected");
    };
    assert!(warnings
        .contains(&"v2 固定的 sing-box 版本 1.12.0 与已安装 1.14.2 不一致，已取消固定".to_owned()));
    fx.run(CoreSelection::All, None, false).unwrap();
    assert_eq!(fx.warnings.all(), warnings, "printed once");
    let applied = fx.request();
    assert_eq!(replaced(&applied), [Core::Singbox]);
    assert_eq!(applied.request.expected, fx.loaded_hash);
    let devices = applied.request.intents.migrated_devices.clone();
    assert_eq!(devices.map(|d| d.len()), Some(2));
    assert_eq!(versions(&applied).singbox_pin, None);
}

#[test]
fn a_pin_change_on_a_v2_configuration_is_its_first_full_transaction() {
    let fx = Fx::v2(&[("SB_VERSION", "1.14.2")]);
    fx.live(Core::Singbox, "1.14.2");
    fx.run(CoreSelection::One(Core::Singbox), Some("1.14.2"), false)
        .unwrap();
    let applied = fx.request();
    assert!(applied.request.intents.replace_cores.is_empty());
    assert_eq!(versions(&applied).singbox_pin.as_deref(), Some("1.14.2"));
    assert!(applied.request.intents.migrated_devices.is_some());
    // Nothing was saved behind the transaction's back.
    assert_eq!(StateStore::current_hash(&fx.ctx).unwrap(), fx.loaded_hash);
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
