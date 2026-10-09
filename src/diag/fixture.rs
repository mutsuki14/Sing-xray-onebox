//! Test fixture: an installed node in an isolated layout, behind a
//! [`FakeExec`] that answers like a healthy systemd host.
//!
//! [`Node::new`] writes the files (state, core binaries and configs, the
//! program, units, certificates, site config); [`Node::finish`] adds the
//! healthy-host rules. FakeExec answers with the first matching rule, so a
//! test scripts its faults between the two.

use super::{Check, CheckStatus, Diagnosis, Doctor};
use crate::cert::CertDir;
use crate::ctx::Ctx;
use crate::domain::fixtures;
use crate::domain::{Core, NodeConfig, Protocol};
use crate::host::cron::testing::{fake_crontab, lines, CronState};
use crate::host::init::InitSystem;
use crate::host::service::unit_file;
use crate::site;
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
    pub dir: TempDir,
    pub ctx: Ctx,
    pub fake: Arc<FakeExec>,
    pub cfg: NodeConfig,
    pub cron: Cron,
    pub crontab: Option<CronState>,
}

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
    /// The files of an installed `cfg` (no rules yet).
    pub fn new(cfg: NodeConfig) -> Node {
        let dir = TempDir::new("diag-node").unwrap();
        let (ctx, fake, _) = Ctx::test(dir.path());
        StateStore::save(&ctx, &cfg).unwrap();
        let paths = &ctx.paths;
        for core in cfg.cores() {
            write(&paths.core_bin(core), "#!/bin/false\n", 0o755);
            write(&paths.core_config(core), "{}\n", 0o600);
        }
        write(&paths.executable, "#!/bin/false\n", 0o755);
        for (name, _) in super::node::required_services(&cfg) {
            write(&unit_file(paths, name), "[Unit]\n", 0o644);
        }
        for (_, cert_dir) in super::tls::certificates(&cfg, paths) {
            write(&cert_dir.cert(), "-----BEGIN CERTIFICATE-----\n", 0o600);
            write(&cert_dir.key(), "-----BEGIN PRIVATE KEY-----\n", 0o600);
        }
        if cfg.site_active().is_some() {
            write(&site::conf_file(paths), "events {}\n", 0o600);
        }
        Node {
            dir,
            ctx,
            fake,
            cfg,
            cron: Cron::Healthy,
            crontab: None,
        }
    }

    /// A healthy two-core node.
    pub fn healthy() -> Node {
        Node::new(two_core_config()).finish()
    }

    /// Add the rules of a healthy systemd host after the test's own.
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
        .on("systemctl", &["is-active", "--quiet"], Output::success(""))
        .on("systemctl", &["is-enabled"], Output::success("enabled\n"))
        .on("nginx", &["-t"], Output::success(""))
        .on("uname", &["-m"], Output::success("x86_64\n"))
        .on("uname", &["-r"], Output::success("6.1.0-18-amd64\n"))
        .provide("nginx");
        fake.on_fn(
            |cmd| cmd.program == "openssl" && cmd.args.iter().any(|a| a == "-dates"),
            |_| Ok(x509_output("www.bing.com", VALID_UNTIL)),
        );
        self.crontab = match self.cron {
            Cron::Missing => None,
            Cron::Empty => Some(fake_crontab(fake, Some("MAILTO=root\n"))),
            Cron::Healthy => Some(fake_crontab(
                fake,
                Some(&format!(
                    "MAILTO=root\n{}\n",
                    lines::renew_for(&self.ctx.paths)
                )),
            )),
        };
        self
    }

    pub fn doctor(&self) -> Doctor<'_> {
        Doctor {
            ctx: &self.ctx,
            init: InitSystem::Systemd,
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
