//! The certificate engine: brings one directory to its [`CertSpec`]
//! (`ensure`, used by applies) or renews it (`renew`, used by renewals),
//! records metadata, and never prompts.
//!
//! Decision rules (fix the v2 drift between `issue`, `renew` and
//! `renewal_due`):
//! - a pair whose metadata matches the spec (or that has no metadata, e.g.
//!   migrated from v2) and that validates is kept; ACME pairs are renewed
//!   when they expire within 30 days or when forced, self-signed pairs are
//!   regenerated when they expire within 30 days;
//! - anything else is issued anew (ACME `--issue --force`, a new
//!   self-signed pair); [`Engine::will_contact_acme`] answers in advance
//!   whether acme.sh will run (the site starts its bootstrap nginx then);
//! - when acme.sh answers "not due" (exit 2), the pair it holds is still
//!   deployed if it differs (v2 did the same): a renewal whose deployment
//!   failed earlier is picked up instead of being reported as "unchanged"
//!   forever. If the deployed pair still expires within 30 days, the
//!   attempt is [`Renewal::Deferred`], not a success;
//! - custom pairs are validated and deployed from their sources whenever
//!   they differ from the deployed pair; a source deleted after deployment
//!   keeps the deployed pair while it still serves the recorded names;
//! - renewal is due when the pair is invalid, expires within 30 days, does
//!   not match the spec, or (custom) its readable sources changed. A custom
//!   source that vanished is not "due" (v2 failed every night, F-8.1#22).

use super::acme::{self, AcmeRelease, Request};
use super::cloudflare::{self, CfCredentials};
use super::method::{CertSpec, Challenge, Source};
use super::openssl::{missing_file, Trust};
use super::selfsigned;
use super::store::{deployable_chain, install_pair, valid_for, CertDir, Metadata, PEM_MAX_BYTES};
use crate::ctx::Ctx;
use crate::domain::defaults::RENEWAL_WINDOW_SECS;
use crate::error::Result;
use crate::host::init::{self, InitSystem};
use crate::host::os::{process_env, EnvLookup};
use crate::host::service::Services;
use crate::sys::fs::{read_bounded, read_bounded_following};
use crate::sys::time::now;
use crate::ui::out;
use std::path::Path;

/// An ACME pair valid for less than a day is reissued rather than renewed;
/// a custom pair whose source vanished is kept only while valid that long.
const REISSUE_SECS: u64 = 24 * 60 * 60;
pub const ISSUE_FAILED: &str = "签发失败；原部署证书保持不变";
pub const RENEW_FAILED: &str = "续期失败；原证书未替换";
/// Recorded (and shown) when acme.sh found nothing to renew although the
/// deployed certificate expires within 30 days.
pub const RENEW_DEFERRED: &str = "acme.sh 认为尚未到续期时间，证书未更换（30 天内到期）";

/// External facts and knobs of certificate operations.
pub struct Engine<'a> {
    pub ctx: &'a Ctx,
    pub release: AcmeRelease,
    /// TCP port of the built-in responder (80; tests use a free port).
    pub http01_port: u16,
    pub env: EnvLookup<'a>,
    pub init: InitSystem,
}

/// How a renewal was asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RenewKind {
    /// Due-driven (cron, or an apply finding the pair near expiry): acme.sh
    /// may answer "not due" (exit 2), which changes nothing.
    Scheduled,
    /// The user asked: acme.sh gets `--force`.
    Forced,
}

/// What an attempt on a certificate directory achieved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Renewal {
    /// A different pair is deployed now.
    Changed,
    /// The deployed pair satisfies the spec and stays.
    Unchanged,
    /// acme.sh answered "not due" and held nothing newer, yet the deployed
    /// pair expires within 30 days (acme.sh keeps its own schedule): nothing
    /// changed, and the attempt is not recorded as a success.
    Deferred,
}

impl Renewal {
    pub fn changed(self) -> bool {
        self == Renewal::Changed
    }

    fn from_changed(changed: bool) -> Renewal {
        if changed {
            Renewal::Changed
        } else {
            Renewal::Unchanged
        }
    }
}

impl<'a> Engine<'a> {
    /// Production engine: pinned acme.sh, TCP 80, process environment.
    pub fn system(ctx: &'a Ctx) -> Engine<'a> {
        Engine {
            ctx,
            release: AcmeRelease::pinned(),
            http01_port: super::http01::HTTP_PORT,
            env: &process_env,
            init: init::detect(ctx),
        }
    }

    pub fn services(&self) -> Services<'a> {
        Services::new(self.ctx, self.init)
    }

    /// Bring `dir` to `spec` (see the module docs); `force` renews a valid
    /// ACME pair anyway. Returns whether the deployed pair changed; a
    /// deferred renewal is a warning, not an error.
    pub fn ensure(
        &self,
        dir: &CertDir,
        spec: &CertSpec,
        force: bool,
        cf: Option<&CfCredentials>,
    ) -> Result<bool> {
        spec.check()?;
        dir.ensure()?;
        let credentials = self.credentials(dir, spec, cf)?;
        let previous = self.previous(dir);
        let mut metadata = Metadata::attempt(spec, previous.as_ref(), now());
        let result = self.ensure_pair(dir, spec, previous.as_ref(), force, credentials.as_ref());
        let outcome = self.record(dir, &mut metadata, result, ISSUE_FAILED)?;
        if outcome == Renewal::Deferred {
            out::warn(format!("{}: {RENEW_DEFERRED}", spec.primary()));
        }
        Ok(outcome.changed())
    }

    fn ensure_pair(
        &self,
        dir: &CertDir,
        spec: &CertSpec,
        previous: Option<&Metadata>,
        force: bool,
        credentials: Option<&CfCredentials>,
    ) -> Result<Renewal> {
        let matches = previous.is_none_or(|m| m.matches(spec));
        match &spec.source {
            Source::Custom { cert, key } => self.custom(dir, spec, previous, cert, key),
            Source::SelfSigned => {
                if matches && self.ready(dir, spec, RENEWAL_WINDOW_SECS) {
                    Ok(Renewal::Unchanged)
                } else {
                    selfsigned::generate(self.ctx, dir, &spec.domains).map(Renewal::from_changed)
                }
            }
            Source::Acme(challenge) => match self.acme_request(dir, spec, matches, force) {
                Some(request) => self.acme(dir, spec, challenge, request, credentials),
                None => Ok(Renewal::Unchanged),
            },
        }
    }

    /// What [`Engine::ensure`] asks acme.sh for (`None`: keep the pair).
    fn acme_request(
        &self,
        dir: &CertDir,
        spec: &CertSpec,
        matches: bool,
        force: bool,
    ) -> Option<Request> {
        if !(matches && self.ready(dir, spec, REISSUE_SECS)) {
            return Some(Request::Issue);
        }
        (force || !self.ready(dir, spec, RENEWAL_WINDOW_SECS)).then_some(Request::Renew { force })
    }

    /// Whether [`Engine::ensure`] with `force` would run acme.sh for `spec`
    /// (an issuance, or a forced or due renewal). Read-only; the same rule
    /// `ensure` follows, so a caller that must serve HTTP-01 first (the
    /// site's bootstrap nginx) starts it exactly when acme.sh will run.
    pub fn will_contact_acme(&self, dir: &CertDir, spec: &CertSpec, force: bool) -> bool {
        let previous = dir.metadata().ok().flatten();
        let matches = previous.is_none_or(|m| m.matches(spec));
        spec.challenge().is_some() && self.acme_request(dir, spec, matches, force).is_some()
    }

    /// Renew `dir` towards `spec` (no due check; see [`Engine::due`]).
    pub fn renew(
        &self,
        dir: &CertDir,
        spec: &CertSpec,
        kind: RenewKind,
        cf: Option<&CfCredentials>,
    ) -> Result<Renewal> {
        spec.check()?;
        dir.ensure()?;
        let credentials = self.credentials(dir, spec, cf)?;
        let previous = self.previous(dir);
        let mut metadata = Metadata::attempt(spec, previous.as_ref(), now());
        let matches = previous.as_ref().is_none_or(|m| m.matches(spec));
        let result = match &spec.source {
            Source::Custom { .. } | Source::SelfSigned => {
                self.ensure_pair(dir, spec, previous.as_ref(), false, None)
            }
            Source::Acme(challenge) => {
                let request = if matches && dir.has_pair() {
                    Request::Renew {
                        force: kind == RenewKind::Forced,
                    }
                } else {
                    Request::Issue
                };
                self.acme(dir, spec, challenge, request, credentials.as_ref())
            }
        };
        self.record(dir, &mut metadata, result, RENEW_FAILED)
    }

    /// Whether `dir` needs a renewal towards `spec` (read-only).
    pub fn due(&self, dir: &CertDir, spec: &CertSpec) -> Result<bool> {
        let matches = self.previous(dir).is_none_or(|m| m.matches(spec));
        Ok(match &spec.source {
            Source::Custom { cert, key } => self.custom_changed(dir, cert, key),
            _ => !matches || !self.ready(dir, spec, RENEWAL_WINDOW_SECS),
        })
    }

    /// The deployed pair serves every name of `spec` for `secs` more seconds.
    pub fn ready(&self, dir: &CertDir, spec: &CertSpec, secs: u64) -> bool {
        valid_for(self.ctx, dir, &spec.domains, spec.trust, secs)
    }

    /// Deploy a custom pair from its sources. A source deleted after it was
    /// deployed (Onebox holds a copy) keeps the deployed pair while the
    /// metadata records the same names and sources and the pair stays valid
    /// for a day; any other missing source fails, naming the path.
    fn custom(
        &self,
        dir: &CertDir,
        spec: &CertSpec,
        previous: Option<&Metadata>,
        cert: &Path,
        key: &Path,
    ) -> Result<Renewal> {
        let Some(missing) = [cert, key].into_iter().find(|p| !readable(p)) else {
            let changed = install_pair(self.ctx, dir, cert, key, &spec.domains, spec.trust)?;
            return Ok(Renewal::from_changed(changed));
        };
        let recorded = previous.is_some_and(|m| {
            m.matches(spec)
                && m.source_cert.as_deref() == Some(cert)
                && m.source_key.as_deref() == Some(key)
        });
        if recorded && self.ready(dir, spec, REISSUE_SECS) {
            out::warn(format!(
                "自备证书文件不存在: {}；继续使用已部署的证书",
                missing.display()
            ));
            return Ok(Renewal::Unchanged);
        }
        Err(missing_file(missing))
    }

    /// Readable custom sources that would deploy different bytes (sources
    /// read through symlinks, as `install_pair` reads them).
    fn custom_changed(&self, dir: &CertDir, cert: &Path, key: &Path) -> bool {
        let Ok(chain) = deployable_chain(self.ctx, cert, key) else {
            return false;
        };
        let deployed = read_bounded(&dir.cert(), PEM_MAX_BYTES).ok();
        let key_now = read_bounded(&dir.key(), PEM_MAX_BYTES).ok();
        let key_new = read_bounded_following(key, PEM_MAX_BYTES).ok();
        deployed.as_deref() != Some(chain.as_bytes()) || key_now != key_new
    }

    /// Run acme.sh and deploy what it holds (module docs: "not due").
    fn acme(
        &self,
        dir: &CertDir,
        spec: &CertSpec,
        challenge: &Challenge,
        request: Request,
        credentials: Option<&CfCredentials>,
    ) -> Result<Renewal> {
        let issued = acme::obtain(self, dir, &spec.domains, challenge, request, credentials)?;
        let (cert, key) = acme::issued_pair(dir, spec.primary());
        let held = cert.is_file() && key.is_file();
        let changed = match issued || held {
            true => install_pair(self.ctx, dir, &cert, &key, &spec.domains, Trust::Public)?,
            false => false,
        };
        Ok(match (issued, changed) {
            (true, _) | (_, true) => Renewal::from_changed(changed),
            _ if self.ready(dir, spec, RENEWAL_WINDOW_SECS) => Renewal::Unchanged,
            _ => Renewal::Deferred,
        })
    }

    /// Cloudflare credentials for DNS-01 specs (resolved and persisted).
    fn credentials(
        &self,
        dir: &CertDir,
        spec: &CertSpec,
        cf: Option<&CfCredentials>,
    ) -> Result<Option<CfCredentials>> {
        match spec.source {
            Source::Acme(Challenge::Cloudflare) => {
                cloudflare::resolve(self.ctx, dir.path(), cf, self.env).map(Some)
            }
            _ => Ok(None),
        }
    }

    /// Previous metadata; a corrupt file counts as none (with a warning).
    fn previous(&self, dir: &CertDir) -> Option<Metadata> {
        dir.metadata().unwrap_or_else(|e| {
            out::warn(format!("{e}；将按新证书处理"));
            None
        })
    }

    /// Save metadata for the attempt: the success time, the deferral text
    /// (keeping the previous success time), or the fixed failure text (best
    /// effort) before returning the error.
    fn record(
        &self,
        dir: &CertDir,
        metadata: &mut Metadata,
        result: Result<Renewal>,
        failed: &str,
    ) -> Result<Renewal> {
        match result {
            Ok(outcome) => {
                if outcome == Renewal::Deferred {
                    metadata.last_error = Some(RENEW_DEFERRED.to_owned());
                } else {
                    metadata.last_success = now();
                    metadata.last_error = None;
                }
                dir.save_metadata(metadata)?;
                Ok(outcome)
            }
            Err(e) => {
                metadata.last_error = Some(failed.to_owned());
                let _ = dir.save_metadata(metadata);
                Err(e)
            }
        }
    }
}

/// A regular file this process can open.
fn readable(path: &Path) -> bool {
    path.is_file() && std::fs::File::open(path).is_ok()
}

#[cfg(test)]
mod tests;
