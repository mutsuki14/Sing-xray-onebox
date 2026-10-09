//! `onebox support`: a JSON report for bug reports, written to
//! `ROOT/support-{unix}-{hex}.json` (0600, created exclusively, trailing
//! newline, keys sorted at every level as v2's were).
//!
//! It holds the program version, host facts, the configured protocols,
//! ports and cores (with versions), certificate methods, feature flags,
//! whether a recovery is pending, and every doctor check. Typed fields are
//! identifiers, ports and versions only; the free-form check names and
//! details go through the [`Redactor`] (credentials, IP addresses and
//! domain names of the node and FRP, then any IP literal or domain-shaped
//! word) and are capped in length. Nothing is uploaded.

use super::redact::Redactor;
use super::{Check, CheckFn, Diagnosis, Doctor};
use crate::apply::journal;
use crate::domain::config::{AcmeMethod, ProxyCertMode, SubscriptionMode, WebCert};
use crate::domain::NodeConfig;
use crate::error::{Error, Result};
use crate::host::cores;
use crate::host::os::{self, HostFacts, OsInfo};
use crate::sys::fs::{ensure_dir, write_new_exclusive};
use crate::sys::rand::{OsRandom, Random};
use serde::Serialize;
use std::path::{Path, PathBuf};

/// Version of the report layout (v2's implicit layout is 1).
pub const SUPPORT_SCHEMA: u32 = 2;
/// The report's promise (v2 wording).
pub const SUPPORT_NOTE: &str =
    "No credentials, IP addresses, domain names, logs or certificate contents are included.";
/// Longest check detail kept, in characters.
const DETAIL_MAX: usize = 600;
/// Random file-name suffixes tried before giving up.
const NAME_ATTEMPTS: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SupportReport {
    pub schema: u32,
    pub program_version: &'static str,
    /// Unix seconds.
    pub generated_at: u64,
    pub host: HostInfo,
    /// `v3` / `v2` (not yet regenerated) / `invalid` / `absent`.
    pub state: &'static str,
    pub protocols: Vec<ProtocolRow>,
    pub cores: Vec<CoreRow>,
    pub certificates: CertModes,
    pub features: Features,
    /// A node or self-update journal is pending (or unreadable).
    pub pending_recovery: bool,
    /// A configuration operation held the node lock during the diagnosis
    /// (its failures were reported as warnings).
    pub operation_running: bool,
    /// Every doctor check, redacted.
    pub checks: Vec<Check>,
    pub note: &'static str,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct HostInfo {
    /// `uname -m`.
    pub arch: Option<String>,
    pub container: Option<String>,
    /// `systemd` / `openrc` / `none`.
    pub init: &'static str,
    /// `uname -r`.
    pub kernel: Option<String>,
    /// os-release `ID`.
    pub os: Option<String>,
    /// os-release `VERSION_ID`.
    pub version: Option<String>,
    /// `systemd-detect-virt` (none when not virtualized or unknown).
    pub virtualization: Option<String>,
    pub wsl: bool,
}

impl HostInfo {
    /// Probes that fail leave their field empty (v2 aborted on `uname`).
    pub fn detect(doctor: &Doctor) -> HostInfo {
        let ctx = doctor.ctx;
        let release = OsInfo::load(ctx);
        let facts = HostFacts::detect(ctx);
        let non_empty = |s: String| (!s.is_empty()).then_some(s);
        HostInfo {
            arch: os::machine(ctx).ok(),
            container: facts.container,
            init: doctor.init.id(),
            kernel: os::kernel_release(ctx).ok(),
            os: non_empty(release.id),
            version: non_empty(release.version_id),
            virtualization: facts.virtualization,
            wsl: facts.wsl,
        }
    }
}

/// One inbound (v2 keys).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProtocolRow {
    pub core: &'static str,
    /// `tcp` / `udp` / `both`.
    pub network: &'static str,
    pub port: u16,
    pub protocol: &'static str,
}

/// One used core.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CoreRow {
    pub core: &'static str,
    /// A version pin is configured.
    pub pinned: bool,
    pub running: bool,
    /// What the binary reports; none when missing or broken.
    pub version: Option<String>,
}

/// Certificate methods in effect (`self-signed`, `acme-http01`,
/// `acme-cloudflare`, `custom`); none when unused.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct CertModes {
    pub proxy: Option<&'static str>,
    pub site: Option<&'static str>,
    pub subscription: Option<&'static str>,
}

impl CertModes {
    pub fn of(cfg: &NodeConfig) -> CertModes {
        let proxy = cfg
            .tls
            .as_ref()
            .filter(|_| cfg.needs_cert())
            .map(|tls| match &tls.mode {
                ProxyCertMode::SelfSigned { .. } => "self-signed",
                ProxyCertMode::Acme { method, .. } => acme_id(*method),
                ProxyCertMode::Custom { .. } => "custom",
            });
        let subscription = match cfg.subscription.as_ref().map(|s| &s.mode) {
            Some(SubscriptionMode::Standalone { cert, .. }) => Some(web_cert_id(cert)),
            _ => None,
        };
        CertModes {
            proxy,
            site: cfg.site_active().map(|s| web_cert_id(&s.cert)),
            subscription,
        }
    }
}

fn acme_id(method: AcmeMethod) -> &'static str {
    match method {
        AcmeMethod::Http01 => "acme-http01",
        AcmeMethod::Cloudflare => "acme-cloudflare",
    }
}

fn web_cert_id(cert: &WebCert) -> &'static str {
    match cert {
        WebCert::Http01 => acme_id(AcmeMethod::Http01),
        WebCert::Cloudflare => acme_id(AcmeMethod::Cloudflare),
        WebCert::Custom { .. } => "custom",
    }
}

/// Which optional features are enabled.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Features {
    pub frp: bool,
    /// The own-domain website is active.
    pub site: bool,
    pub subscription: bool,
    /// `ip` / `site` / `standalone`.
    pub subscription_mode: Option<&'static str>,
}

impl Features {
    pub fn of(cfg: Option<&NodeConfig>, frp: bool) -> Features {
        let mode = cfg
            .and_then(|c| c.subscription.as_ref())
            .map(|s| match s.mode {
                SubscriptionMode::Ip { .. } => "ip",
                SubscriptionMode::Site => "site",
                SubscriptionMode::Standalone { .. } => "standalone",
            });
        Features {
            frp,
            site: cfg.is_some_and(|c| c.site_active().is_some()),
            subscription: mode.is_some(),
            subscription_mode: mode,
        }
    }
}

pub fn protocol_rows(cfg: &NodeConfig) -> Vec<ProtocolRow> {
    cfg.inbounds
        .iter()
        .map(|inbound| ProtocolRow {
            core: inbound.core.id(),
            network: inbound.protocol.transport().id(),
            port: inbound.port,
            protocol: inbound.protocol.id(),
        })
        .collect()
}

fn core_rows(doctor: &Doctor, cfg: &NodeConfig) -> Vec<CoreRow> {
    let services = doctor.services();
    cfg.cores()
        .into_iter()
        .map(|core| {
            let bin = doctor.ctx.paths.core_bin(core);
            let version = bin
                .is_file()
                .then(|| cores::installed_version(doctor.ctx, &bin, core).ok())
                .flatten();
            CoreRow {
                core: core.id(),
                pinned: cfg.versions.pin(core).is_some(),
                running: services.running(core.service()),
                version,
            }
        })
        .collect()
}

/// A check with its texts redacted and the detail capped.
pub fn redact_check(redactor: &Redactor, check: &Check) -> Check {
    let detail = redactor.redact(&check.detail);
    let detail = match detail.char_indices().nth(DETAIL_MAX) {
        Some((cut, _)) => format!("{}…", &detail[..cut]),
        None => detail,
    };
    Check::new(redactor.redact(&check.name), check.status, detail)
}

impl SupportReport {
    pub fn build(doctor: &Doctor, diagnosis: &Diagnosis) -> SupportReport {
        let survey = &diagnosis.survey;
        let cfg = survey.config();
        let redactor = Redactor::for_node(cfg, survey.frp.state());
        SupportReport {
            schema: SUPPORT_SCHEMA,
            program_version: crate::VERSION,
            generated_at: doctor.now,
            host: HostInfo::detect(doctor),
            state: survey.node.id(),
            protocols: cfg.map(protocol_rows).unwrap_or_default(),
            cores: cfg.map(|c| core_rows(doctor, c)).unwrap_or_default(),
            certificates: cfg.map(CertModes::of).unwrap_or_default(),
            features: Features::of(cfg, survey.frp.installed()),
            pending_recovery: journal::pending(&doctor.ctx.paths).map_or(true, |p| p.any()),
            operation_running: diagnosis.operation_running,
            checks: diagnosis
                .checks
                .iter()
                .map(|c| redact_check(&redactor, c))
                .collect(),
            note: SUPPORT_NOTE,
        }
    }

    /// Pretty JSON with sorted keys and a trailing newline.
    pub fn to_json(&self) -> Result<String> {
        // Through `Value`: its maps are sorted (serde_json without
        // `preserve_order`), struct fields would keep declaration order.
        let value = serde_json::to_value(self)?;
        let mut text = serde_json::to_string_pretty(&value)?;
        text.push('\n');
        Ok(text)
    }
}

/// `support-{unix}-{suffix}.json`.
pub fn report_name(now: u64, suffix: &str) -> String {
    format!("support-{now}-{suffix}.json")
}

/// Create the report under `root` with a fresh random suffix (0600,
/// O_EXCL: an existing file is never replaced). `root` is created 0700
/// when missing (a host with only FRP installed).
pub fn write_report(root: &Path, now: u64, text: &str, rng: &mut dyn Random) -> Result<PathBuf> {
    if !root.is_dir() {
        ensure_dir(root, 0o700)?;
    }
    for _ in 0..NAME_ATTEMPTS {
        let path = root.join(report_name(now, &rng.hex(6)?));
        if std::fs::symlink_metadata(&path).is_ok() {
            continue;
        }
        write_new_exclusive(&path, text.as_bytes(), 0o600)?;
        return Ok(path);
    }
    Err(Error::msg("无法生成诊断文件名"))
}

/// See [`super::support_with`].
pub(super) fn write_support(doctor: &Doctor, extra: &[CheckFn]) -> Result<PathBuf> {
    let diagnosis = doctor.diagnose(extra, &mut |_| {})?;
    let report = SupportReport::build(doctor, &diagnosis);
    write_report(
        &doctor.ctx.paths.root,
        doctor.now,
        &report.to_json()?,
        &mut OsRandom,
    )
}

#[cfg(test)]
mod tests;
