//! Test support: a crontab held in memory behind [`FakeExec`] rules.

use crate::sys::exec::{FakeExec, Output};
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};

/// The fake crontab's state; `None` = the user has no crontab yet.
pub type CronState = Arc<Mutex<Option<String>>>;

/// Answer `crontab -l` from the state and `crontab FILE` by storing FILE
/// (which must be a private 0600 file). Also makes `crontab` available.
pub fn fake_crontab(exec: &FakeExec, initial: Option<&str>) -> CronState {
    let state: CronState = Arc::new(Mutex::new(initial.map(str::to_owned)));
    exec.provide("crontab");
    let list = state.clone();
    exec.on_fn(
        |cmd| cmd.program == "crontab" && cmd.args == ["-l"],
        move |_| {
            Ok(match list.lock().unwrap().as_ref() {
                Some(text) => Output::success(text.clone()),
                None => Output::failure(1, "no crontab for root\n"),
            })
        },
    );
    let install = state.clone();
    exec.on_fn(
        |cmd| cmd.program == "crontab" && cmd.args.len() == 1 && cmd.args[0] != "-l",
        move |cmd| {
            let path = std::path::Path::new(&cmd.args[0]);
            let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "crontab temp files are private");
            *install.lock().unwrap() = Some(std::fs::read_to_string(path).unwrap());
            Ok(Output::success(""))
        },
    );
    state
}

/// The installed text (`""` when none).
pub fn text(state: &CronState) -> String {
    state.lock().unwrap().clone().unwrap_or_default()
}

/// Real owned lines of every form (default layout).
pub mod lines {
    use crate::host::cron::{line, Tag};
    use crate::host::init::InitSystem;
    use crate::paths::Paths;
    use crate::sys::text::quote_shell;
    use std::path::Path;

    fn default_paths() -> Paths {
        Paths::from_lookup(|_| None).unwrap()
    }

    pub const EXE: &str = "/usr/local/bin/onebox";

    fn env(init: &str) -> String {
        let mut env: Vec<String> = default_paths()
            .service_env()
            .into_iter()
            .map(|(k, v)| format!("{k}={}", quote_shell(&v)))
            .collect();
        env.push(format!("ONEBOX_INIT='{init}'"));
        env.join(" ")
    }

    pub fn v3(tag: &Tag, args: &[&str]) -> String {
        line(
            "@reboot",
            &default_paths(),
            InitSystem::None,
            args,
            Path::new("/var/log/onebox/boot.log"),
            tag,
        )
        .unwrap()
    }

    pub fn renew() -> String {
        renew_for(&default_paths())
    }

    pub fn renew_for(paths: &Paths) -> String {
        line(
            "17 4 * * *",
            paths,
            InitSystem::Systemd,
            &["renew", "--cron"],
            &paths.log.join("renew.log"),
            &Tag::renew(),
        )
        .unwrap()
    }

    pub fn boot(service: &str) -> String {
        v3(&Tag::boot(service).unwrap(), &["service", service, "start"])
    }

    pub fn frp_renew() -> String {
        line(
            "17 3 * * *",
            &default_paths(),
            InitSystem::Systemd,
            &["frps", "renew", "--cron"],
            Path::new("/var/log/onebox-frp/renew.log"),
            &Tag::frp_renew(),
        )
        .unwrap()
    }

    pub fn v2_cert(target: &str) -> String {
        let job = if target == "subscription" {
            "subscription renew --cron".to_owned()
        } else {
            format!("cert renew {target} --cron")
        };
        format!("17 4 * * * {EXE} {job} >/dev/null 2>&1 # onebox-native-cert-{target}")
    }

    pub fn v2_boot(service: &str) -> String {
        format!(
            "@reboot env {} '{EXE}' service {service} start >/dev/null 2>&1 # onebox-rust:{service}",
            env("none")
        )
    }

    pub fn v2_frp(renew: bool) -> String {
        let (schedule, job, log, marker) = if renew {
            ("17 3 * * *", "frps renew --cron", "renew", "renew")
        } else {
            ("@reboot", "frps start", "boot", "boot")
        };
        format!(
            "{schedule} env {} '{EXE}' {job} >>'/var/log/onebox-frp/{log}.log' 2>&1 # onebox-frps-{marker}",
            env("systemd")
        )
    }

    pub const RETIRED: &str =
        "0 0 * * * /etc/onebox/tls/acme/acme.sh --cron --home /etc/onebox/tls/acme > /dev/null";
}
