//! [`FakeHost`]: the host of the lifecycle tests — systemd, OpenRC or no
//! init system (the built-in supervisor over a fake `/proc`), a crontab,
//! the frp and acme.sh releases, DNS pointing at the host, a fake nginx
//! (whose `-t` runs are recorded) and iptables, and a fake openssl for the
//! private CA (the real one with a test CA as the public store on
//! request, for certificates the cert engine has to verify).

use super::fakes::{
    crontab_cmd, frps_cmd, guard, rc_service, rc_update, systemctl, FakeSignals, HostExec,
};
use super::{openssl, release_routes};
use crate::cert::testing::{test_release, TestCa, FAKE_ACME, FAKE_DNS_CF};
use crate::ctx::Ctx;
use crate::frp::runtime::{Health, Runtime};
use crate::host::fetch::testing::{serve, Reply};
use crate::host::init::InitSystem;
use crate::host::supervisor::{Supervisor, Timing};
use crate::sys::exec::{Cmd, Exec, FakeExec, Output, SystemExec};
use crate::sys::fs::TempDir;
use crate::ui::ScriptedPrompter;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct FakeHost {
    pub dir: TempDir,
    pub ctx: Ctx,
    pub exec: Arc<FakeExec>,
    pub ui: Arc<ScriptedPrompter>,
    pub init: InitSystem,
    /// systemd / OpenRC unit states (unused without an init system).
    pub units: Arc<Mutex<Units>>,
    pub crontab: Arc<Mutex<Option<String>>>,
    /// The TLS health check succeeds while this is true.
    pub healthy: Arc<AtomicBool>,
    /// iptables accepts rule changes while this is true.
    pub firewall_ok: Arc<AtomicBool>,
    /// `nginx.conf` as each `nginx -t` saw it, in order.
    pub nginx_tests: Arc<Mutex<Vec<String>>>,
    /// The CA the real openssl trusts as its public store.
    pub ca: Option<TestCa>,
}

/// Service states of the fake systemd / OpenRC.
#[derive(Debug, Default)]
pub struct Units {
    pub running: BTreeSet<String>,
    pub enabled: BTreeSet<String>,
    /// Units whose start fails.
    pub broken: BTreeSet<String>,
    /// Units whose stop fails (they keep running).
    pub stuck: BTreeSet<String>,
}

impl FakeHost {
    /// systemd, fake openssl.
    pub fn new() -> FakeHost {
        FakeHost::build(InitSystem::Systemd, false)
    }

    /// `init`, fake openssl.
    pub fn with_init(init: InitSystem) -> FakeHost {
        FakeHost::build(init, false)
    }

    /// systemd with the real openssl trusting a test CA; `None` when
    /// openssl is missing.
    pub fn with_real_openssl() -> Option<FakeHost> {
        FakeHost::real_openssl(InitSystem::Systemd)
    }

    /// `init` with the real openssl trusting a test CA; `None` when openssl
    /// is missing.
    pub fn real_openssl(init: InitSystem) -> Option<FakeHost> {
        crate::cert::testing::have_openssl().then(|| FakeHost::build(init, true))
    }

    fn build(init: InitSystem, real_openssl: bool) -> FakeHost {
        let dir = TempDir::new("frp-host").unwrap();
        let (base, exec, ui) = Ctx::test(dir.path());
        let host_exec = HostExec {
            fake: exec.clone(),
            system_root: base.paths.system_root.clone(),
            clock: AtomicU64::new(0),
        };
        let ctx = Ctx {
            exec: Arc::new(host_exec),
            ..base
        };
        let ca = real_openssl.then(|| TestCa::create(&dir.join("test-ca")));
        let host = FakeHost {
            dir,
            ctx,
            exec,
            ui,
            init,
            units: Default::default(),
            crontab: Default::default(),
            healthy: Arc::new(AtomicBool::new(true)),
            firewall_ok: Arc::new(AtomicBool::new(true)),
            nginx_tests: Default::default(),
            ca,
        };
        host.proc();
        host.script();
        host
    }

    /// Empty socket tables (no port is in use) and a cron daemon process.
    fn proc(&self) {
        let net = self.ctx.paths.system("/proc/net");
        std::fs::create_dir_all(&net).unwrap();
        for table in ["tcp", "tcp6", "udp", "udp6"] {
            std::fs::write(net.join(table), "  sl  local_address rem_address   st\n").unwrap();
        }
        let cron = self.ctx.paths.system("/proc/7");
        std::fs::create_dir_all(&cron).unwrap();
        std::fs::write(cron.join("comm"), "cron\n").unwrap();
    }

    fn script(&self) {
        let exec = &self.exec;
        for program in ["curl", "openssl", "ip", "crontab", "nginx", "iptables"] {
            exec.provide(program);
        }
        self.service_managers();
        let crontab = self.crontab.clone();
        exec.on_fn(
            |c| c.program == "crontab",
            move |c| crontab_cmd(&crontab, &c.args),
        );
        self.openssl();
        exec.on_fn(
            |c| c.program.ends_with("/frps"),
            |c| Ok(frps_cmd(&c.program, &c.args)),
        );
        // The pre-start hook of `onebox-frps` (no init: run by Onebox).
        let exe = self.ctx.paths.executable.to_string_lossy().into_owned();
        exec.on_fn(
            move |c| c.program == exe && c.args == ["frps", "net-apply"],
            |_| Ok(Output::success("")),
        );
        exec.on("uname", &["-m"], Output::success("x86_64\n"));
        exec.on(
            "ip",
            &["-j", "address", "show"],
            Output::success(r#"[{"addr_info":[{"local":"192.0.2.1"}]}]"#),
        );
        exec.on(
            "getent",
            &["ahosts"],
            Output::success("192.0.2.1 STREAM x\n"),
        );
        exec.on("getent", &[], Output::failure(2, ""));
        self.nginx();
        exec.on("id", &["-u", "www-data"], Output::success("33\n"));
        exec.on("id", &["-gn", "www-data"], Output::success("www-data\n"));
        exec.on("id", &[], Output::failure(1, "no such user"));
        self.iptables();
        let mut routes = release_routes("0.71.0", true);
        let acme = test_release();
        routes.push((acme.script.url, Reply::body(FAKE_ACME)));
        routes.push((acme.dns_cf.url, Reply::body(FAKE_DNS_CF)));
        serve(exec, routes);
    }

    fn service_managers(&self) {
        guard(&self.units).running.insert("cron".into());
        for (program, fake) in [
            (
                "systemctl",
                systemctl as fn(&Mutex<Units>, &[String]) -> Output,
            ),
            ("rc-service", rc_service),
            ("rc-update", rc_update),
        ] {
            let units = self.units.clone();
            self.exec.on_fn(
                move |c| c.program == program,
                move |c| Ok(fake(&units, &c.args)),
            );
        }
    }

    /// The health check's `s_client` follows `healthy`; every other call
    /// goes to the private-CA fake, or to the real openssl (test CA as the
    /// default store, no timeout: see `cert::testing::HybridExec`).
    fn openssl(&self) {
        let healthy = self.healthy.clone();
        self.exec.on_fn(
            |c| c.program == "openssl" && c.args.first().is_some_and(|a| a == "s_client"),
            move |_| {
                Ok(if healthy.load(Ordering::SeqCst) {
                    Output::success("CONNECTION ESTABLISHED\n")
                } else {
                    Output::failure(1, "verify error")
                })
            },
        );
        match &self.ca {
            Some(ca) => {
                let store = ca.cert.to_string_lossy().into_owned();
                self.exec.on_fn(
                    |c| c.program == "openssl",
                    move |c| {
                        let mut real = c.clone().env("SSL_CERT_FILE", store.as_str());
                        real.timeout = None;
                        SystemExec.run(&real)
                    },
                );
            }
            None => {
                self.exec
                    .on_fn(|c| c.program == "openssl", |c| Ok(openssl::run(&c.args)));
            }
        }
    }

    /// `nginx -t` records the configuration it tested; `-T` finds no user.
    fn nginx(&self) {
        let tests = self.nginx_tests.clone();
        self.exec.on_fn(
            |c| c.program_name() == "nginx" && c.args.first().is_some_and(|a| a == "-t"),
            move |c| {
                let conf = arg_after(c, "-c")
                    .map(std::fs::read_to_string)
                    .transpose()?;
                guard(&tests).push(conf.unwrap_or_default());
                Ok(Output::success(""))
            },
        );
        self.exec.on("nginx", &["-T"], Output::failure(1, ""));
    }

    fn iptables(&self) {
        self.exec.on(
            "iptables",
            &["-w", "5", "-S", "INPUT"],
            Output::success("-P INPUT ACCEPT\n"),
        );
        self.exec.on_fn(
            |c| c.program == "iptables" && c.args.iter().any(|a| a == "-C"),
            |_| Ok(Output::failure(1, "")),
        );
        let firewall_ok = self.firewall_ok.clone();
        self.exec.on_fn(
            |c| c.program == "iptables",
            move |c| {
                let change = c.args.iter().any(|a| a == "-I" || a == "-D");
                Ok(if change && !firewall_ok.load(Ordering::SeqCst) {
                    Output::failure(4, "iptables: Resource temporarily unavailable.")
                } else {
                    Output::success("")
                })
            },
        );
    }

    /// The lifecycle runtime of this host: one health probe, no copy of
    /// the test binary, the fake signals and the fake acme.sh release.
    pub fn runtime(&self) -> Runtime<'_> {
        let signals = Arc::new(FakeSignals {
            system_root: self.ctx.paths.system_root.clone(),
        });
        let timing = Timing {
            term_grace: Duration::from_millis(50),
            kill_grace: Duration::from_millis(50),
            poll: Duration::from_millis(5),
            lock_wait: Duration::from_millis(200),
        };
        Runtime {
            ctx: &self.ctx,
            init: self.init,
            env: &super::no_env,
            root: true,
            health: Health {
                attempts: 1,
                interval: Duration::ZERO,
            },
            install_self: |_| Ok(false),
            supervisor: Supervisor::with(&self.ctx, signals, timing),
            acme: test_release(),
        }
    }

    pub fn crontab(&self) -> String {
        guard(&self.crontab).clone().unwrap_or_default()
    }

    pub fn set_crontab(&self, text: &str) {
        *guard(&self.crontab) = Some(text.to_owned());
    }

    /// Whether `unit` runs: the unit state, or without an init system a
    /// verified supervisor record.
    pub fn running(&self, unit: &str) -> bool {
        match self.init {
            InitSystem::None => self.runtime().services().running(unit),
            _ => guard(&self.units).running.contains(unit),
        }
    }

    /// Whether `unit` starts at boot: enabled, or its `boot:` cron line.
    pub fn enabled(&self, unit: &str) -> bool {
        match self.init {
            InitSystem::None => self
                .crontab()
                .lines()
                .any(|l| l.ends_with(&format!("# onebox:boot:{unit}"))),
            _ => guard(&self.units).enabled.contains(unit),
        }
    }

    pub fn break_unit(&self, unit: &str, broken: bool) {
        let mut units = guard(&self.units);
        if broken {
            units.broken.insert(unit.to_owned());
        } else {
            units.broken.remove(unit);
        }
    }

    pub fn stick_unit(&self, unit: &str, stuck: bool) {
        let mut units = guard(&self.units);
        if stuck {
            units.stuck.insert(unit.to_owned());
        } else {
            units.stuck.remove(unit);
        }
    }

    pub fn set_firewall_ok(&self, ok: bool) {
        self.firewall_ok.store(ok, Ordering::SeqCst);
    }

    pub fn set_healthy(&self, healthy: bool) {
        self.healthy.store(healthy, Ordering::SeqCst);
    }

    /// Command lines that ran (`Cmd::display`).
    pub fn history(&self) -> Vec<String> {
        self.exec.history()
    }

    /// Forget the commands that ran (and what `nginx -t` saw).
    pub fn clear_history(&self) {
        self.exec.clear_history();
        guard(&self.nginx_tests).clear();
    }

    /// The commands that ran, `nginx -t` runs shown as
    /// `nginx -t bootstrap|full` after the configuration they tested.
    pub fn timeline(&self) -> Vec<String> {
        let tests = guard(&self.nginx_tests).clone();
        let mut tested = tests.iter();
        self.exec
            .calls()
            .iter()
            .map(|c| {
                if c.program_name() == "nginx" && c.args.first().is_some_and(|a| a == "-t") {
                    let conf = tested.next().map(String::as_str).unwrap_or("");
                    let phase = if conf.contains("ssl_certificate") {
                        "full"
                    } else {
                        "bootstrap"
                    };
                    format!("nginx -t {phase}")
                } else {
                    c.display()
                }
            })
            .collect()
    }

    /// A publicly trusted (test CA) pair for `names` in `{dir}/{label}`.
    pub fn public_pair(&self, label: &str, names: &[&str]) -> (PathBuf, PathBuf) {
        let ca = self.ca.as_ref().expect("a host with the real openssl");
        ca.leaf(&self.dir.join(label), names, 90, false)
    }
}

fn arg_after<'c>(cmd: &'c Cmd, flag: &str) -> Option<&'c str> {
    let at = cmd.args.iter().position(|a| a == flag)?;
    cmd.args.get(at + 1).map(String::as_str)
}
