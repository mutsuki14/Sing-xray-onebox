//! Filesystem roots. Defaults and `ONEBOX_*` overrides are identical to v2 so
//! an in-place upgrade finds every managed file; overrides are validated once
//! at startup instead of failing late (v2 accepted empty/relative values).

use crate::domain::protocol::Core;
use crate::error::Result;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Paths {
    pub root: PathBuf,
    pub bin: PathBuf,
    pub log: PathBuf,
    pub run: PathBuf,
    pub site_root: PathBuf,
    pub systemd: PathBuf,
    pub initd: PathBuf,
    pub executable: PathBuf,
    pub frp_root: PathBuf,
    pub frp_bin: PathBuf,
    pub frp_web: PathBuf,
    pub frp_log: PathBuf,
    pub frp_run: PathBuf,
    pub bbr_dir: PathBuf,
    pub bbr_conf: PathBuf,
    /// Prefix for reading system files (/etc/os-release, /proc, /sys, /boot);
    /// "/" in production, a fixture directory in tests.
    pub system_root: PathBuf,
}

/// Path variables persisted into service units and cron lines, in this order
/// (v2 order; `ONEBOX_INIT` is appended by the service layer).
pub const SERVICE_ENV_KEYS: [&str; 13] = [
    "ONEBOX_DIR",
    "ONEBOX_BIN_DIR",
    "ONEBOX_LOG_DIR",
    "ONEBOX_RUN_DIR",
    "ONEBOX_SITE_ROOT",
    "ONEBOX_SYSTEMD_DIR",
    "ONEBOX_INITD_DIR",
    "ONEBOX_EXE",
    "ONEBOX_FRPS_DIR",
    "ONEBOX_FRPS_BIN_DIR",
    "ONEBOX_FRPS_WEB_VAR",
    "ONEBOX_FRPS_LOG_DIR",
    "ONEBOX_FRPS_RUN_DIR",
];

impl Paths {
    /// Production layout with environment overrides.
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|key| std::env::var_os(key).map(PathBuf::from))
    }

    /// Same as [`Paths::from_env`] with an injectable lookup (tests).
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<PathBuf>) -> Result<Self> {
        let get = |key: &str, default: &str| -> Result<PathBuf> {
            match lookup(key) {
                None => Ok(PathBuf::from(default)),
                Some(value) => {
                    let ok = value.is_absolute()
                        && value.to_str().is_some()
                        && !value
                            .components()
                            .any(|c| c == std::path::Component::ParentDir);
                    ensure!(ok, "环境变量 {key} 必须是不含 .. 的绝对 UTF-8 路径");
                    Ok(value)
                }
            }
        };
        Ok(Paths {
            root: get("ONEBOX_DIR", "/etc/onebox")?,
            bin: get("ONEBOX_BIN_DIR", "/opt/onebox/bin")?,
            log: get("ONEBOX_LOG_DIR", "/var/log/onebox")?,
            run: get("ONEBOX_RUN_DIR", "/run/onebox")?,
            site_root: get("ONEBOX_SITE_ROOT", "/var/lib/onebox-site")?,
            systemd: get("ONEBOX_SYSTEMD_DIR", "/etc/systemd/system")?,
            initd: get("ONEBOX_INITD_DIR", "/etc/init.d")?,
            executable: get("ONEBOX_EXE", "/usr/local/bin/onebox")?,
            frp_root: get("ONEBOX_FRPS_DIR", "/etc/onebox-frp")?,
            frp_bin: get("ONEBOX_FRPS_BIN_DIR", "/opt/onebox-frp")?,
            frp_web: get("ONEBOX_FRPS_WEB_VAR", "/var/lib/onebox-frp")?,
            frp_log: get("ONEBOX_FRPS_LOG_DIR", "/var/log/onebox-frp")?,
            frp_run: get("ONEBOX_FRPS_RUN_DIR", "/run/onebox-frp")?,
            bbr_dir: get("ONEBOX_BBR_DIR", "/var/lib/onebox-bbr")?,
            bbr_conf: get("ONEBOX_BBR_CONF", "/etc/sysctl.d/99-onebox-bbr.conf")?,
            system_root: get("ONEBOX_SYSTEM_ROOT", "/")?,
        })
    }

    /// Self-contained layout under `root` for tests (mirrors v2 `isolated`).
    pub fn isolated(root: &Path) -> Self {
        let p = |s: &str| root.join(s);
        Paths {
            root: p("etc"),
            bin: p("bin"),
            log: p("log"),
            run: p("run"),
            site_root: p("www"),
            systemd: p("systemd"),
            initd: p("initd"),
            executable: p("onebox"),
            frp_root: p("frp/etc"),
            frp_bin: p("frp/bin"),
            frp_web: p("frp/web"),
            frp_log: p("frp/log"),
            frp_run: p("frp/run"),
            bbr_dir: p("bbr"),
            bbr_conf: p("sysctl.d/99-onebox-bbr.conf"),
            system_root: p("system"),
        }
    }

    /// Ordered `(KEY, value)` path variables for units and cron (never secrets).
    pub fn service_env(&self) -> Vec<(String, String)> {
        let values = [
            &self.root,
            &self.bin,
            &self.log,
            &self.run,
            &self.site_root,
            &self.systemd,
            &self.initd,
            &self.executable,
            &self.frp_root,
            &self.frp_bin,
            &self.frp_web,
            &self.frp_log,
            &self.frp_run,
        ];
        SERVICE_ENV_KEYS
            .iter()
            .zip(values)
            .map(|(k, v)| (k.to_string(), v.to_string_lossy().into_owned()))
            .collect()
    }

    /// A system file such as `/etc/os-release` under [`Paths::system_root`].
    pub fn system(&self, absolute: &str) -> PathBuf {
        self.system_root.join(absolute.trim_start_matches('/'))
    }

    pub fn state(&self) -> PathBuf {
        self.root.join("state.json")
    }
    /// v1 state file; only detected to print the upgrade-path message.
    pub fn legacy_v1_state(&self) -> PathBuf {
        self.root.join("onebox.conf")
    }
    pub fn state_v2_backup(&self) -> PathBuf {
        self.root.join("state.v2.json")
    }
    pub fn lock(&self) -> PathBuf {
        self.root.join(".apply.lock")
    }
    pub fn transaction(&self) -> PathBuf {
        self.root.join(".transaction")
    }
    pub fn self_update_journal(&self) -> PathBuf {
        self.root.join(".self-update.json")
    }
    pub fn update_lock(&self) -> PathBuf {
        self.run.join("update.lock")
    }
    pub fn update_channel(&self) -> PathBuf {
        self.root.join("update-channel")
    }
    pub fn clients(&self) -> PathBuf {
        self.root.join("client")
    }
    pub fn tls(&self) -> PathBuf {
        self.root.join("tls")
    }
    pub fn site(&self) -> PathBuf {
        self.root.join("site")
    }
    pub fn subscription(&self) -> PathBuf {
        self.root.join("subscription")
    }
    /// v2 subscription settings with the v2 device list (read-only input
    /// for the migration and the worker): `ROOT/subscription/settings.json`.
    pub fn subscription_v2_settings(&self) -> PathBuf {
        self.subscription().join("settings.json")
    }
    /// Subscription devices (token hashes): `ROOT/subscription/devices.json`.
    pub fn devices(&self) -> PathBuf {
        self.subscription().join("devices.json")
    }
    /// The snapshot the subscription worker serves (v2 name and shape):
    /// `ROOT/subscription/published.json`.
    pub fn published(&self) -> PathBuf {
        self.subscription().join("published.json")
    }
    /// The subscription worker's unix socket behind nginx (site and
    /// standalone modes): `RUN/subscription.sock`.
    pub fn subscription_socket(&self) -> PathBuf {
        self.run.join("subscription.sock")
    }
    /// HTTP-01 webroot of the standalone subscription: a sibling of the site
    /// root (`/var/lib/onebox-subscription-acme` by default, v2 layout).
    pub fn subscription_acme(&self) -> PathBuf {
        self.site_root.with_file_name("onebox-subscription-acme")
    }
    pub fn services(&self) -> PathBuf {
        self.root.join("services")
    }
    pub fn backups(&self) -> PathBuf {
        self.root.join("backups")
    }
    pub fn core_bin(&self, core: Core) -> PathBuf {
        self.bin.join(core.binary())
    }
    pub fn core_config(&self, core: Core) -> PathBuf {
        self.root.join(format!("{}.json", core.binary()))
    }
    pub fn frp_lock(&self) -> PathBuf {
        let parent = self.frp_root.parent().unwrap_or_else(|| Path::new("/"));
        parent.join(".onebox-frp.lock")
    }
    /// The FRP transaction journal (`frp::journal`), next to the FRP lock.
    pub fn frp_journal(&self) -> PathBuf {
        self.frp_lock().with_file_name(".onebox-frp-journal")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_v2_layout() {
        let p = Paths::from_lookup(|_| None).unwrap();
        assert_eq!(p.state(), PathBuf::from("/etc/onebox/state.json"));
        assert_eq!(
            p.core_bin(Core::Singbox),
            PathBuf::from("/opt/onebox/bin/sing-box")
        );
        assert_eq!(
            p.core_config(Core::Xray),
            PathBuf::from("/etc/onebox/xray.json")
        );
        assert_eq!(p.frp_lock(), PathBuf::from("/etc/.onebox-frp.lock"));
        assert_eq!(p.frp_journal(), PathBuf::from("/etc/.onebox-frp-journal"));
        let derived = [
            (p.subscription_acme(), "/var/lib/onebox-subscription-acme"),
            (p.subscription_socket(), "/run/onebox/subscription.sock"),
            (p.devices(), "/etc/onebox/subscription/devices.json"),
            (
                p.subscription_v2_settings(),
                "/etc/onebox/subscription/settings.json",
            ),
            (p.published(), "/etc/onebox/subscription/published.json"),
        ];
        for (got, want) in derived {
            assert_eq!(got, PathBuf::from(want));
        }
        assert_eq!(
            p.subscription_acme(),
            PathBuf::from("/var/lib/onebox-subscription-acme")
        );
        let custom = Paths::from_lookup(|k| {
            (k == "ONEBOX_SITE_ROOT").then(|| PathBuf::from("/srv/www/site"))
        })
        .unwrap();
        assert_eq!(
            custom.subscription_acme(),
            PathBuf::from("/srv/www/onebox-subscription-acme")
        );
        assert_eq!(p.service_env().len(), 13);
        assert_eq!(
            p.system("/etc/os-release"),
            PathBuf::from("/etc/os-release")
        );
    }

    #[test]
    fn subscription_paths_follow_overrides() {
        let p = Paths::from_lookup(|k| match k {
            "ONEBOX_SITE_ROOT" => Some(PathBuf::from("/srv/www/site")),
            "ONEBOX_RUN_DIR" => Some(PathBuf::from("/tmp/run")),
            _ => None,
        })
        .unwrap();
        assert_eq!(
            p.subscription_acme(),
            PathBuf::from("/srv/www/onebox-subscription-acme")
        );
        assert_eq!(
            p.subscription_socket(),
            PathBuf::from("/tmp/run/subscription.sock")
        );
        let isolated = Paths::isolated(Path::new("/t"));
        assert_eq!(
            isolated.subscription_acme(),
            PathBuf::from("/t/onebox-subscription-acme")
        );
        // A site root of "/" has no file name: the sibling is still absolute.
        let top = Paths::from_lookup(|k| (k == "ONEBOX_SITE_ROOT").then(|| PathBuf::from("/")));
        assert_eq!(
            top.unwrap().subscription_acme(),
            PathBuf::from("/onebox-subscription-acme")
        );
    }

    #[test]
    fn rejects_relative_override() {
        let err =
            Paths::from_lookup(|k| (k == "ONEBOX_DIR").then(|| PathBuf::from("etc"))).unwrap_err();
        assert!(err.to_string().contains("ONEBOX_DIR"));
    }
}
