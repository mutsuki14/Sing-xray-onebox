//! The node lock around lookups and questions, changes made meanwhile,
//! configurations still in v2 form.

use super::*;

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

impl Fx {
    /// Answer every confirmation with yes after running `hook`.
    fn on_confirm(&mut self, hook: impl Fn() + Send + Sync + 'static) {
        self.ctx.ui = Arc::new(Hooked(Box::new(hook)));
    }
}

fn busy(path: &Path) -> bool {
    matches!(FileLock::acquire(path, "busy"), Err(Error::Busy(_)))
}

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
