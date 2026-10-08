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
//!   self-signed pair);
//! - custom pairs are validated and deployed from their sources whenever
//!   they differ from the deployed pair;
//! - renewal is due when the pair is invalid, expires within 30 days, does
//!   not match the spec, or (custom) its readable sources changed. A custom
//!   source that vanished is not "due" (v2 failed every night, F-8.1#22).

use super::acme::{self, AcmeRelease, Request};
use super::cloudflare::{self, CfCredentials};
use super::method::{CertSpec, Challenge, Source};
use super::openssl::Trust;
use super::selfsigned;
use super::store::{deployable_chain, install_pair, valid_for, CertDir, Metadata, PEM_MAX_BYTES};
use crate::ctx::Ctx;
use crate::domain::defaults::RENEWAL_WINDOW_SECS;
use crate::error::Result;
use crate::host::init::{self, InitSystem};
use crate::host::os::{process_env, EnvLookup};
use crate::host::service::Services;
use crate::sys::fs::read_bounded;
use crate::sys::time::now;
use crate::ui::out;

/// An ACME pair valid for less than a day is reissued rather than renewed.
const REISSUE_SECS: u64 = 24 * 60 * 60;
pub const ISSUE_FAILED: &str = "签发失败；原部署证书保持不变";
pub const RENEW_FAILED: &str = "续期失败；原证书未替换";

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
    /// ACME pair anyway. Returns whether the deployed pair changed.
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
        let matches = previous.as_ref().is_none_or(|m| m.matches(spec));
        let result = self.ensure_pair(dir, spec, matches, force, credentials.as_ref());
        self.record(dir, &mut metadata, result, ISSUE_FAILED)
    }

    fn ensure_pair(
        &self,
        dir: &CertDir,
        spec: &CertSpec,
        matches: bool,
        force: bool,
        credentials: Option<&CfCredentials>,
    ) -> Result<bool> {
        match &spec.source {
            Source::Custom { cert, key } => {
                install_pair(self.ctx, dir, cert, key, &spec.domains, spec.trust)
            }
            Source::SelfSigned => {
                if matches && self.ready(dir, spec, RENEWAL_WINDOW_SECS) {
                    Ok(false)
                } else {
                    selfsigned::generate(self.ctx, dir, &spec.domains)
                }
            }
            Source::Acme(challenge) => {
                if !(matches && self.ready(dir, spec, REISSUE_SECS)) {
                    return self.acme(dir, spec, challenge, Request::Issue, credentials);
                }
                if force || !self.ready(dir, spec, RENEWAL_WINDOW_SECS) {
                    let request = Request::Renew { force };
                    return self.acme(dir, spec, challenge, request, credentials);
                }
                Ok(false)
            }
        }
    }

    /// Renew `dir` towards `spec` (no due check; see [`Engine::due`]).
    pub fn renew(
        &self,
        dir: &CertDir,
        spec: &CertSpec,
        kind: RenewKind,
        cf: Option<&CfCredentials>,
    ) -> Result<bool> {
        spec.check()?;
        dir.ensure()?;
        let credentials = self.credentials(dir, spec, cf)?;
        let previous = self.previous(dir);
        let mut metadata = Metadata::attempt(spec, previous.as_ref(), now());
        let matches = previous.as_ref().is_none_or(|m| m.matches(spec));
        let result = match &spec.source {
            Source::Custom { .. } | Source::SelfSigned => {
                self.ensure_pair(dir, spec, matches, false, None)
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

    /// Readable custom sources that would deploy different bytes.
    fn custom_changed(&self, dir: &CertDir, cert: &std::path::Path, key: &std::path::Path) -> bool {
        let Ok(chain) = deployable_chain(self.ctx, cert, key) else {
            return false;
        };
        let deployed = read_bounded(&dir.cert(), PEM_MAX_BYTES).ok();
        let key_now = read_bounded(&dir.key(), PEM_MAX_BYTES).ok();
        let key_new = read_bounded(key, PEM_MAX_BYTES).ok();
        deployed.as_deref() != Some(chain.as_bytes()) || key_now != key_new
    }

    fn acme(
        &self,
        dir: &CertDir,
        spec: &CertSpec,
        challenge: &Challenge,
        request: Request,
        credentials: Option<&CfCredentials>,
    ) -> Result<bool> {
        if !acme::obtain(self, dir, &spec.domains, challenge, request, credentials)? {
            return Ok(false);
        }
        let (cert, key) = acme::issued_pair(dir, spec.primary());
        install_pair(self.ctx, dir, &cert, &key, &spec.domains, Trust::Public)
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

    /// Save metadata for the attempt: success time, or the fixed failure
    /// text (best effort) before returning the error.
    fn record(
        &self,
        dir: &CertDir,
        metadata: &mut Metadata,
        result: Result<bool>,
        failed: &str,
    ) -> Result<bool> {
        match result {
            Ok(changed) => {
                metadata.last_success = now();
                metadata.last_error = None;
                dir.save_metadata(metadata)?;
                Ok(changed)
            }
            Err(e) => {
                metadata.last_error = Some(failed.to_owned());
                let _ = dir.save_metadata(metadata);
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests;
