//! Init system detection (systemd / OpenRC / none) with the `ONEBOX_INIT`
//! override.
//!
//! Order (v2): `ONEBOX_INIT` ∈ {systemd, openrc, none} wins; else
//! `/run/systemd/system` is a directory → systemd (the sd_booted(3) test);
//! else `/run/openrc` exists or `openrc-run` is on PATH → OpenRC; else none
//! (the built-in supervisor). Paths are read under `Paths::system_root`.
//!
//! Changes from v2: the result is a typed enum; the check runs under
//! `system_root` and `which` goes through `Exec` (testable); an
//! unrecognized `ONEBOX_INIT` value is still ignored (v2 parity), but
//! [`detect`] says so ([`override_error`], once per process) instead of
//! silently using another init system.

use crate::ctx::Ctx;
use crate::host::os::{process_env, EnvLookup};
use crate::ui::out;
use std::sync::atomic::{AtomicBool, Ordering};

/// Environment variable that forces the init system (also persisted into
/// units and cron lines by the service layer).
pub const ENV: &str = "ONEBOX_INIT";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum InitSystem {
    Systemd,
    Openrc,
    /// No init integration: Onebox supervises daemons itself.
    None,
}

impl InitSystem {
    pub const ALL: [InitSystem; 3] = [InitSystem::Systemd, InitSystem::Openrc, InitSystem::None];

    /// `systemd` | `openrc` | `none` (the `ONEBOX_INIT` spelling).
    pub fn id(self) -> &'static str {
        match self {
            InitSystem::Systemd => "systemd",
            InitSystem::Openrc => "openrc",
            InitSystem::None => "none",
        }
    }

    /// Parse an `ONEBOX_INIT` value (exact, lower-case).
    pub fn parse(value: &str) -> Option<InitSystem> {
        InitSystem::ALL.into_iter().find(|i| i.id() == value)
    }

    /// Detect with the process environment's `ONEBOX_INIT`, warning (once
    /// per process) when its value is ignored.
    pub fn detect(ctx: &Ctx) -> InitSystem {
        warn_ignored_override(&process_env, &OVERRIDE_WARNED, out::warn);
        detect_with(ctx, &process_env)
    }
}

impl std::fmt::Display for InitSystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.id())
    }
}

/// Detect the init system (see the module docs for the order).
pub fn detect(ctx: &Ctx) -> InitSystem {
    InitSystem::detect(ctx)
}

/// [`detect`] with an injected environment lookup.
pub fn detect_with(ctx: &Ctx, env: EnvLookup) -> InitSystem {
    if let Some(forced) = env(ENV).as_deref().and_then(InitSystem::parse) {
        return forced;
    }
    if ctx.paths.system("/run/systemd/system").is_dir() {
        return InitSystem::Systemd;
    }
    if ctx.paths.system("/run/openrc").exists() || ctx.has("openrc-run") {
        return InitSystem::Openrc;
    }
    InitSystem::None
}

/// [`override_error`] was printed by this process.
static OVERRIDE_WARNED: AtomicBool = AtomicBool::new(false);

/// Pass [`override_error`] to `warn` unless `warned` says it already was
/// (every command detects the init system several times).
fn warn_ignored_override(env: EnvLookup, warned: &AtomicBool, warn: impl FnOnce(String)) {
    if let Some(message) = override_error(env) {
        if !warned.swap(true, Ordering::Relaxed) {
            warn(message);
        }
    }
}

/// A message when `ONEBOX_INIT` is set to something [`detect`] ignores.
pub fn override_error(env: EnvLookup) -> Option<String> {
    let value = env(ENV)?;
    InitSystem::parse(&value)
        .is_none()
        .then(|| format!("{ENV} 只能是 systemd、openrc 或 none（当前为 {value}），已改用自动检测"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::fs::TempDir;
    use std::fs;

    fn env_of(value: Option<&'static str>) -> impl Fn(&str) -> Option<String> {
        move |key| (key == ENV).then(|| value.map(str::to_owned)).flatten()
    }

    #[test]
    fn ids_round_trip() {
        for init in InitSystem::ALL {
            assert_eq!(InitSystem::parse(init.id()), Some(init));
            assert_eq!(init.to_string(), init.id());
        }
        assert_eq!(InitSystem::parse("Systemd"), None);
        assert_eq!(InitSystem::parse(""), None);
    }

    #[test]
    fn detection_order() {
        let dir = TempDir::new("init").unwrap();
        let (ctx, exec, _) = Ctx::test(dir.path());
        let sys = ctx.paths.system_root.clone();
        let auto = env_of(None);

        assert_eq!(detect_with(&ctx, &auto), InitSystem::None);
        exec.provide("openrc-run");
        assert_eq!(detect_with(&ctx, &auto), InitSystem::Openrc, "openrc-run");
        fs::create_dir_all(sys.join("run")).unwrap();
        fs::write(sys.join("run/openrc"), "").unwrap();
        assert_eq!(detect_with(&ctx, &auto), InitSystem::Openrc);
        // A plain file is not the systemd runtime directory.
        fs::create_dir_all(sys.join("run/systemd")).unwrap();
        fs::write(sys.join("run/systemd/system"), "").unwrap();
        assert_eq!(detect_with(&ctx, &auto), InitSystem::Openrc);
        fs::remove_file(sys.join("run/systemd/system")).unwrap();
        fs::create_dir(sys.join("run/systemd/system")).unwrap();
        assert_eq!(detect_with(&ctx, &auto), InitSystem::Systemd);
    }

    #[test]
    fn override_wins_and_invalid_values_are_reported() {
        let dir = TempDir::new("init").unwrap();
        let (ctx, _, _) = Ctx::test(dir.path());
        fs::create_dir_all(ctx.paths.system("/run/systemd/system")).unwrap();
        assert_eq!(detect_with(&ctx, &env_of(Some("none"))), InitSystem::None);
        assert_eq!(
            detect_with(&ctx, &env_of(Some("openrc"))),
            InitSystem::Openrc
        );
        assert_eq!(
            detect_with(&ctx, &env_of(Some("upstart"))),
            InitSystem::Systemd,
            "unknown override falls back to detection"
        );
        assert_eq!(override_error(&env_of(Some("none"))), None);
        assert_eq!(override_error(&env_of(None)), None);
        assert_eq!(
            override_error(&env_of(Some("upstart"))).unwrap(),
            "ONEBOX_INIT 只能是 systemd、openrc 或 none（当前为 upstart），已改用自动检测"
        );
    }

    /// An ignored override is reported (once per process), a valid or
    /// absent one never.
    #[test]
    fn ignored_overrides_are_reported_once() {
        let cases: [(Option<&'static str>, bool); 7] = [
            (None, false),
            (Some("systemd"), false),
            (Some("openrc"), false),
            (Some("none"), false),
            (Some("None"), true),
            (Some("supervisor"), true),
            (Some("systemd "), true),
        ];
        for (value, reported) in cases {
            let warned = AtomicBool::new(false);
            let mut messages = Vec::new();
            for _ in 0..3 {
                warn_ignored_override(&env_of(value), &warned, |m| messages.push(m));
            }
            let want: Vec<String> = override_error(&env_of(value)).into_iter().collect();
            assert_eq!(messages, want, "{value:?}");
            assert_eq!(messages.len(), usize::from(reported), "{value:?}");
        }
    }
}
