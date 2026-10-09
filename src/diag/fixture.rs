//! Test fixture: an installed node in an isolated layout, behind a
//! [`FakeExec`] that answers like a healthy host of its init system
//! (systemd by default; OpenRC, or none with the supervisor's PID records,
//! `/proc` entries and `# onebox:boot:NAME` lines).
//!
//! [`Node::new`] / [`Node::with_init`] write the files (state, core
//! binaries and configs, the program, units/scripts/specs, certificates,
//! nginx configs); [`Node::finish`] adds the healthy-host rules. FakeExec
//! answers with the first matching rule, so a test scripts its faults
//! between the two.

use super::node::Role;
use super::{Check, CheckStatus, Diagnosis, Doctor};
use crate::cert::CertDir;
use crate::ctx::Ctx;
use crate::domain::config::{AcmeMethod, ProxyCertMode, ProxyTls};
use crate::domain::fixtures;
use crate::domain::{Core, NodeConfig, Protocol};
use crate::host::cron::testing::{fake_crontab, lines, CronState};
use crate::host::init::InitSystem;
use crate::host::service::{
    unit_file, ServiceDef, Services, NETWORK, SITE, SUBSCRIPTION, SUBSCRIPTION_WEB, XRAY,
};
use crate::host::supervisor::fixture::FakeProc;
use crate::host::supervisor::PidRecord;
use crate::state::StateStore;
use crate::sys::exec::{FakeExec, Output};
use crate::sys::fs::TempDir;
use crate::sys::time::Civil;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

/// The fixed "now" of every diagnosis (2027-01-15).
pub const NOW: u64 = 1_800_000_000;
pub const DAY: u64 = 86_400;
/// Certificates of a healthy node expire 90 days after [`NOW`].
pub const VALID_UNTIL: u64 = NOW + 90 * DAY;
pub const SINGBOX_VERSION: &str = "1.14.2";
pub const XRAY_VERSION: &str = "26.3.27";

/// What the fake crontab holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cron {
    /// The renewal line when a certificate needs it.
    Healthy,
    /// A crontab without Onebox lines.
    Empty,
    /// No `crontab` program at all.
    Missing,
}

pub struct Node {
    /// Keeps the layout alive.
    _dir: TempDir,
    pub ctx: Ctx,
    pub fake: Arc<FakeExec>,
    pub cfg: NodeConfig,
    pub init: InitSystem,
    pub cron: Cron,
    pub crontab: Option<CronState>,
    /// Without init: daemons [`Node::finish`] leaves stopped.
    pub stopped: Vec<&'static str>,
}

/// PIDs of the fake supervised daemons (no init); the cron daemon's is
/// [`CRON_PID`].
const FIRST_PID: u32 = 4100;
pub const CRON_PID: u32 = 99;

/// REALITY + Hysteria2 on sing-box, XHTTP on Xray: two cores, a
/// self-signed proxy certificate.
pub fn two_core_config() -> NodeConfig {
    let mut cfg = fixtures::config(&[
        (Protocol::VlessReality, 443, Core::Singbox),
        (Protocol::Hysteria2, 8443, Core::Singbox),
        (Protocol::VlessXhttp, 2053, Core::Xray),
    ]);
    cfg.versions.singbox = Some(SINGBOX_VERSION.into());
    cfg.versions.xray = Some(XRAY_VERSION.into());
    cfg
}

/// The two-core node with an ACME (Cloudflare) proxy certificate.
pub fn acme_config() -> NodeConfig {
    let mut cfg = two_core_config();
    cfg.tls = Some(ProxyTls {
        mode: ProxyCertMode::Acme {
            domain: "proxy.example.net".into(),
            method: AcmeMethod::Cloudflare,
        },
        pinned: false,
    });
    cfg
}

/// openssl's `notAfter` text for `secs` (`Jan 15 08:00:00 2027 GMT`).
pub fn openssl_date(secs: u64) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let c = Civil::from_unix(secs);
    format!(
        "{} {:>2} {:02}:{:02}:{:02} {} GMT",
        MONTHS[(c.month - 1) as usize],
        c.day,
        c.hour,
        c.minute,
        c.second,
        c.year
    )
}

/// `openssl x509 … -subject -issuer -dates` output.
pub fn x509_output(subject: &str, expires: u64) -> Output {
    Output::success(format!(
        "subject=CN = {subject}\nissuer=CN = {subject}\nnotBefore={}\nnotAfter={}\n",
        openssl_date(expires - 365 * DAY),
        openssl_date(expires)
    ))
}

fn write(path: &Path, content: &str, mode: u32) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

impl Node {
    /// The files of an installed `cfg` on systemd (no rules yet).
    pub fn new(cfg: NodeConfig) -> Node {
        Node::with_init(cfg, InitSystem::Systemd)
    }

    /// The files of an installed `cfg` under `init` (no rules yet).
    pub fn with_init(cfg: NodeConfig, init: InitSystem) -> Node {
        let dir = TempDir::new("diag-node").unwrap();
        let (ctx, fake, _) = Ctx::test(dir.path());
        StateStore::save(&ctx, &cfg).unwrap();
        let paths = &ctx.paths;
        for core in cfg.cores() {
            write(&paths.core_bin(core), "#!/bin/false\n", 0o755);
            write(&paths.core_config(core), "{}\n", 0o600);
        }
        write(&paths.executable, "#!/bin/false\n", 0o755);
        write_services(&ctx, &cfg, init);
        for (_, cert_dir) in super::tls::certificates(&cfg, paths) {
            write(&cert_dir.cert(), "-----BEGIN CERTIFICATE-----\n", 0o600);
            write(&cert_dir.key(), "-----BEGIN PRIVATE KEY-----\n", 0o600);
        }
        for (_, _, conf) in super::tls::nginx_configs(&cfg, paths) {
            write(&conf, "events {}\n", 0o600);
        }
        Node {
            _dir: dir,
            ctx,
            fake,
            cfg,
            init,
            cron: Cron::Healthy,
            crontab: None,
            stopped: Vec::new(),
        }
    }

    /// A healthy two-core node.
    pub fn healthy() -> Node {
        Node::new(two_core_config()).finish()
    }

    /// Add the rules of a healthy host after the test's own.
    pub fn finish(mut self) -> Node {
        let fake = &self.fake;
        fake.on(
            "sing-box",
            &["version"],
            Output::success(format!(
                "sing-box version {SINGBOX_VERSION}\n\nEnvironment: go1.25\n"
            )),
        )
        .on("sing-box", &["check"], Output::success(""))
        .on(
            "xray",
            &["version"],
            Output::success(format!(
                "Xray {XRAY_VERSION} (Xray, Penetrates Everything.)\n"
            )),
        )
        .on(
            "xray",
            &["run", "-test"],
            Output::success("Configuration OK.\n"),
        )
        .on(
            "onebox",
            &["version"],
            Output::success(format!("{}\n", crate::VERSION)),
        )
        .on("nginx", &["-t"], Output::success(""))
        .on("uname", &["-m"], Output::success("x86_64\n"))
        .on("uname", &["-r"], Output::success("6.1.0-18-amd64\n"))
        .provide("nginx");
        fake.on_fn(
            |cmd| cmd.program == "openssl" && cmd.args.iter().any(|a| a == "-dates"),
            |_| Ok(x509_output("www.bing.com", VALID_UNTIL)),
        );
        let boot_lines = self.healthy_services();
        self.crontab = match self.cron {
            Cron::Missing => None,
            Cron::Empty => Some(fake_crontab(&self.fake, Some("MAILTO=root\n"))),
            Cron::Healthy => Some(fake_crontab(
                &self.fake,
                Some(&format!(
                    "MAILTO=root\n{}\n{boot_lines}",
                    lines::renew_for(&self.ctx.paths)
                )),
            )),
        };
        self
    }

    /// Init-specific answers of running, enabled services and a running
    /// cron daemon; returns the crontab's boot lines (no init).
    fn healthy_services(&self) -> String {
        let fake = &self.fake;
        let required = super::node::required_services(&self.cfg);
        match self.init {
            InitSystem::Systemd => {
                fake.on("systemctl", &["is-active", "--quiet"], Output::success(""))
                    .on("systemctl", &["is-enabled"], Output::success("enabled\n"));
                String::new()
            }
            InitSystem::Openrc => {
                let listing: String = required
                    .iter()
                    .map(|(name, _)| format!(" {name:>24} | default\n"))
                    .collect();
                fake.on("rc-update", &["show", "default"], Output::success(listing))
                    .on("rc-service", &[], Output::success(" * status: started\n"));
                String::new()
            }
            InitSystem::None => {
                let proc = FakeProc::new(&self.ctx.paths.system_root);
                let cron = proc.dir(CRON_PID);
                fs::create_dir_all(&cron).unwrap();
                fs::write(cron.join("comm"), "crond\n").unwrap();
                let services = Services::new(&self.ctx, InitSystem::None);
                for (i, (name, role)) in required.iter().enumerate() {
                    if *role == Role::Daemon && !self.stopped.contains(name) {
                        let (def, _) = services.load(name).unwrap();
                        supervise(&proc, &def, FIRST_PID + i as u32);
                    }
                }
                required
                    .iter()
                    .map(|(name, _)| format!("{}\n", lines::boot(name)))
                    .collect()
            }
        }
    }

    pub fn doctor(&self) -> Doctor<'_> {
        Doctor {
            ctx: &self.ctx,
            init: self.init,
            now: NOW,
        }
    }

    /// Diagnose without extra providers.
    pub fn diagnose(&self) -> Diagnosis {
        self.doctor().diagnose(&[], &mut |_| {}).unwrap()
    }

    /// The certificate directory of the proxy (tests overriding openssl).
    pub fn proxy_cert(&self) -> String {
        CertDir::proxy(&self.ctx.paths)
            .cert()
            .to_string_lossy()
            .into_owned()
    }
}

/// Units (systemd), scripts and specs (OpenRC) or specs (no init) of the
/// services `cfg` needs.
fn write_services(ctx: &Ctx, cfg: &NodeConfig, init: InitSystem) {
    let paths = &ctx.paths;
    let required = super::node::required_services(cfg);
    if init == InitSystem::Systemd {
        for (name, _) in required {
            write(&unit_file(paths, name), "[Unit]\n", 0o644);
        }
        return;
    }
    let nginx = paths.bin.join("nginx");
    write(&nginx, "#!/bin/false\n", 0o755);
    let defs: Vec<ServiceDef> = required
        .iter()
        .map(|(name, _)| match *name {
            NETWORK => ServiceDef::network(paths),
            SITE => ServiceDef::site(paths, &nginx),
            SUBSCRIPTION => ServiceDef::subscription(paths),
            SUBSCRIPTION_WEB => ServiceDef::subscription_web(paths, &nginx),
            XRAY => ServiceDef::core(paths, Core::Xray, false),
            _ => ServiceDef::core(paths, Core::Singbox, false),
        })
        .collect();
    Services::new(ctx, init).write_all(&defs).unwrap();
}

/// A live process of `def` with the supervisor's PID record naming it.
fn supervise(proc: &FakeProc, def: &ServiceDef, pid: u32) {
    let start = 1000 + u64::from(pid);
    let program = def.program().to_string_lossy().into_owned();
    let mut argv = vec![program.as_str()];
    argv.extend(def.args().iter().map(String::as_str));
    proc.add(pid, start, def.program(), &argv);
    let record = serde_json::to_string(&PidRecord { pid, start }).unwrap();
    write(&def.pid_file(), &record, 0o600);
}

/// The only check called `name`.
pub fn check<'a>(checks: &'a [Check], name: &str) -> &'a Check {
    let found: Vec<&Check> = checks.iter().filter(|c| c.name == name).collect();
    assert_eq!(found.len(), 1, "{name}: {checks:#?}");
    found[0]
}

/// Names of the checks with `status`.
pub fn with_status(checks: &[Check], status: CheckStatus) -> Vec<&str> {
    checks
        .iter()
        .filter(|c| c.status == status)
        .map(|c| c.name.as_str())
        .collect()
}
