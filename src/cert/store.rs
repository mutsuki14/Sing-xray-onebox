//! Certificate directories: the deployed pair (`cert.pem` + `key.pem`,
//! 0600, directory 0700), the v2 `certificate.json` metadata, atomic pair
//! deployment with rollback, and status facts.
//!
//! Directories (v2 layout, unchanged): proxy `ROOT/tls`, site `ROOT/site`,
//! subscription `ROOT/subscription/tls`, FRP web `FRP_ROOT/web-tls`; each
//! has its own acme.sh home `<D>/acme`.
//!
//! Invariants:
//! - a pair is replaced only after the new pair validated for every name;
//!   the key is written before the certificate and both are restored (or
//!   removed when they did not exist) if either write fails;
//! - the deployed `cert.pem` holds only `CERTIFICATE` blocks, the
//!   key-matching leaf first (`TlsMaterial::with_leaf_first`), so the file's
//!   first certificate is what TLS servers send and what clients pin;
//! - metadata never holds credentials, and `last_error` is fixed text.
//!
//! Changes from v2: custom chains given CA-first are deployed leaf-first
//! (v2 copied them as they were, so nginx and the cores served the CA, and
//! clients pinned it); stray private keys inside a custom `cert.pem` are
//! dropped; unchanged pairs are not rewritten; status shows parsed dates
//! and the remaining days (v2 printed raw epoch seconds, F-8.1#27).

use super::method::{CertSpec, MethodId, Source};
use super::openssl::{self, Trust, X509Info};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::paths::Paths;
use crate::render::spec::{CERT_FILE, KEY_FILE};
use crate::render::tls::TlsMaterial;
use crate::sys::fs::{atomic_write, ensure_dir, read_bounded, remove_file_if_exists};
use crate::sys::time::{format_utc, now};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const METADATA_FILE: &str = "certificate.json";
/// acme.sh `--home`/`--config-home` below a certificate directory.
pub const ACME_HOME: &str = "acme";
/// Webroot the built-in responder serves when no Onebox nginx owns one.
pub const RESPONDER_WEBROOT: &str = "acme/http01";
/// Certificate chains and keys are small files.
pub const PEM_MAX_BYTES: u64 = 1024 * 1024;
const METADATA_MAX_BYTES: u64 = 64 * 1024;

/// One certificate directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertDir {
    path: PathBuf,
}

impl CertDir {
    pub fn new(path: impl Into<PathBuf>) -> CertDir {
        CertDir { path: path.into() }
    }
    /// `ROOT/tls` (proxy).
    pub fn proxy(paths: &Paths) -> CertDir {
        CertDir::new(paths.tls())
    }
    /// `ROOT/site` (own-domain website; also the site's config directory).
    pub fn site(paths: &Paths) -> CertDir {
        CertDir::new(paths.site())
    }
    /// `ROOT/subscription/tls` (standalone subscription endpoint).
    pub fn subscription(paths: &Paths) -> CertDir {
        CertDir::new(paths.subscription().join("tls"))
    }
    /// `FRP_ROOT/web-tls` (FRP web mode).
    pub fn frp_web(paths: &Paths) -> CertDir {
        CertDir::new(paths.frp_root.join("web-tls"))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn cert(&self) -> PathBuf {
        self.path.join(CERT_FILE)
    }
    pub fn key(&self) -> PathBuf {
        self.path.join(KEY_FILE)
    }
    pub fn metadata_file(&self) -> PathBuf {
        self.path.join(METADATA_FILE)
    }
    pub fn acme_home(&self) -> PathBuf {
        self.path.join(ACME_HOME)
    }
    pub fn responder_webroot(&self) -> PathBuf {
        self.path.join(RESPONDER_WEBROOT)
    }

    /// Create the directory (0700); a symlink or file in its place is refused.
    pub fn ensure(&self) -> Result<()> {
        ensure_dir(&self.path, 0o700)
    }

    /// Both deployed files exist as regular files.
    pub fn has_pair(&self) -> bool {
        let regular = |p: PathBuf| std::fs::symlink_metadata(p).is_ok_and(|m| m.is_file());
        regular(self.cert()) && regular(self.key())
    }

    /// The recorded metadata; `None` when the file does not exist.
    pub fn metadata(&self) -> Result<Option<Metadata>> {
        let path = self.metadata_file();
        if std::fs::symlink_metadata(&path).is_err() {
            return Ok(None);
        }
        let bytes = read_bounded(&path, METADATA_MAX_BYTES)?;
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| Error::msg(format!("证书元数据无效 {}: {e}", path.display())))
    }

    /// Write `certificate.json` (pretty JSON, 0600, v2 field order).
    pub fn save_metadata(&self, metadata: &Metadata) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(metadata)?;
        atomic_write(&self.metadata_file(), &bytes, 0o600)
    }

    /// Deploy `chain` + `key`; returns whether the deployed bytes changed.
    /// Key first, then certificate; on failure both are restored.
    pub fn deploy(&self, chain: &[u8], key: &[u8]) -> Result<bool> {
        self.ensure()?;
        let (cert_path, key_path) = (self.cert(), self.key());
        let old_cert = read_bounded(&cert_path, PEM_MAX_BYTES).ok();
        let old_key = read_bounded(&key_path, PEM_MAX_BYTES).ok();
        if old_cert.as_deref() == Some(chain) && old_key.as_deref() == Some(key) {
            return Ok(false);
        }
        let result = atomic_write(&key_path, key, 0o600)
            .and_then(|()| atomic_write(&cert_path, chain, 0o600));
        if let Err(e) = result {
            for (path, old) in [(&cert_path, old_cert), (&key_path, old_key)] {
                let _ = match old {
                    Some(bytes) => atomic_write(path, &bytes, 0o600),
                    None => remove_file_if_exists(path).map(|_| ()),
                };
            }
            return Err(e);
        }
        Ok(true)
    }
}

/// `certificate.json` (v2 shape; fields serialize in this order).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metadata {
    pub domains: Vec<String>,
    pub method: MethodId,
    #[serde(default)]
    pub webroot: Option<PathBuf>,
    #[serde(default)]
    pub source_cert: Option<PathBuf>,
    #[serde(default)]
    pub source_key: Option<PathBuf>,
    #[serde(default)]
    pub last_attempt: u64,
    #[serde(default)]
    pub last_success: u64,
    /// Fixed Chinese text only (never tool output).
    #[serde(default)]
    pub last_error: Option<String>,
}

impl Metadata {
    /// Metadata for an attempt at `spec`, keeping the previous success time.
    pub fn attempt(spec: &CertSpec, previous: Option<&Metadata>, at: u64) -> Metadata {
        let (source_cert, source_key) = match &spec.source {
            Source::Custom { cert, key } => (Some(cert.clone()), Some(key.clone())),
            _ => (None, None),
        };
        Metadata {
            domains: spec.domains.clone(),
            method: spec.method(),
            webroot: spec
                .challenge()
                .and_then(|c| c.webroot())
                .map(Path::to_path_buf),
            source_cert,
            source_key,
            last_attempt: at,
            last_success: previous.map_or(0, |p| p.last_success),
            last_error: None,
        }
    }

    /// Same names and the same kind of certificate (the HTTP-01 responder
    /// may differ): a valid deployed pair can then be kept.
    pub fn matches(&self, spec: &CertSpec) -> bool {
        self.domains == spec.domains && self.method.same_kind(spec.method())
    }
}

/// The chain to deploy from a source pair: every `CERTIFICATE` block of
/// `cert`, the block matching `key` first (found by public key).
pub fn deployable_chain(ctx: &Ctx, cert: &Path, key: &Path) -> Result<String> {
    if let Some(missing) = [cert, key].into_iter().find(|p| !p.is_file()) {
        return Err(openssl::missing_file(missing));
    }
    let text = String::from_utf8(read_bounded(cert, PEM_MAX_BYTES)?)
        .map_err(|_| Error::msg("证书文件不是有效的 PEM 文本"))?;
    let material = TlsMaterial::from_pem(&text)?;
    let leaf = openssl::leaf_index(ctx, &material, key)?;
    Ok(material.with_leaf_first(leaf)?.to_pem())
}

/// Validate a source pair for every name and deploy it into `dir`
/// (chain normalized leaf-first). Returns whether the deployed pair changed.
pub fn install_pair(
    ctx: &Ctx,
    dir: &CertDir,
    cert: &Path,
    key: &Path,
    names: &[String],
    trust: Trust,
) -> Result<bool> {
    dir.ensure()?;
    let chain = deployable_chain(ctx, cert, key)?;
    let key_bytes = read_bounded(key, PEM_MAX_BYTES)?;
    let staged = dir
        .path()
        .join(format!(".stage-{}.pem", crate::sys::rand::hex(8)?));
    let result = atomic_write(&staged, chain.as_bytes(), 0o600).and_then(|()| {
        names
            .iter()
            .try_for_each(|name| openssl::validate_pair(ctx, &staged, key, name, trust))
    });
    let _ = remove_file_if_exists(&staged);
    result?;
    dir.deploy(chain.as_bytes(), &key_bytes)
}

/// The deployed pair is valid for every name with `trust` and does not
/// expire within `secs` seconds.
pub fn valid_for(ctx: &Ctx, dir: &CertDir, names: &[String], trust: Trust, secs: u64) -> bool {
    dir.has_pair()
        && names
            .iter()
            .all(|n| openssl::validate_pair(ctx, &dir.cert(), &dir.key(), n, trust).is_ok())
        && !openssl::expires_within(ctx, &dir.cert(), secs)
}

/// What `cert info` shows and `doctor` checks for one directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertStatus {
    pub dir: PathBuf,
    pub x509: X509Info,
    /// Whole days until expiry (negative once expired).
    pub days_left: Option<i64>,
    pub metadata: Option<Metadata>,
}

impl CertStatus {
    /// Human-readable lines (Chinese).
    pub fn lines(&self) -> Vec<String> {
        let mut lines = vec![
            format!("主题: {}", self.x509.subject),
            format!("签发者: {}", self.x509.issuer),
        ];
        let until = self
            .x509
            .expires_at
            .map(format_utc)
            .unwrap_or_else(|| self.x509.not_after.clone());
        lines.push(match self.days_left {
            Some(days) if days < 0 => format!("到期: {until}（已过期）"),
            Some(days) => format!("到期: {until}（剩余 {days} 天）"),
            None => format!("到期: {until}"),
        });
        if let Some(m) = &self.metadata {
            let success = match m.last_success {
                0 => "无".to_owned(),
                at => format_utc(at),
            };
            let result = m.last_error.as_deref().unwrap_or("成功");
            lines.push(format!("域名: {}", m.domains.join(", ")));
            lines.push(format!(
                "方式: {}；上次成功: {success}；结果: {result}",
                m.method.label()
            ));
        }
        lines
    }

    /// `doctor`'s warning: expired, or expiring within `warn_days` (the
    /// [`Expiry`] predicate every expiry check shares).
    pub fn warning(&self, warn_days: u64) -> Option<String> {
        let Some(days) = self.days_left else {
            return Some("无法读取证书有效期".to_owned());
        };
        match Expiry::of_days(days, warn_days) {
            Expiry::Expired => Some("证书已过期".to_owned()),
            Expiry::Expiring => Some(format!("证书将在 {days} 天内到期")),
            Expiry::Valid => None,
        }
    }
}

/// Where a certificate stands against a warning window. The one predicate
/// of `cert info`, `doctor` and the feature checks, so they agree at the
/// boundary: expired once `notAfter` has passed, expiring while fewer than
/// `warn_days` whole days remain (`openssl x509 -checkend`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expiry {
    Expired,
    Expiring,
    Valid,
}

impl Expiry {
    /// From the whole days left ([`days_until`]).
    pub fn of_days(days_left: i64, warn_days: u64) -> Expiry {
        if days_left < 0 {
            Expiry::Expired
        } else if days_left < warn_days as i64 {
            Expiry::Expiring
        } else {
            Expiry::Valid
        }
    }

    /// From the expiry time (unix seconds) measured at `now`.
    pub fn at(expires_at: u64, now: u64, warn_days: u64) -> Expiry {
        Expiry::of_days(days_until(expires_at, now), warn_days)
    }
}

/// Status of `dir`; `None` without a deployed `cert.pem`.
pub fn status(ctx: &Ctx, dir: &CertDir) -> Result<Option<CertStatus>> {
    if !dir.cert().is_file() {
        return Ok(None);
    }
    let x509 = openssl::x509_info(ctx, &dir.cert())?;
    let days_left = x509.expires_at.map(|at| days_until(at, now()));
    Ok(Some(CertStatus {
        dir: dir.path().to_path_buf(),
        x509,
        days_left,
        metadata: dir.metadata().ok().flatten(),
    }))
}

/// Whole days from `now` until `at` (rounded down, negative when past).
pub fn days_until(at: u64, now: u64) -> i64 {
    (at as i64 - now as i64).div_euclid(86_400)
}

/// Whole days the deployed certificate of `dir` remains valid.
pub fn days_left(ctx: &Ctx, dir: &CertDir) -> Result<i64> {
    let info = openssl::x509_info(ctx, &dir.cert())?;
    let at = info
        .expires_at
        .ok_or_else(|| Error::msg("无法读取证书有效期"))?;
    Ok(days_until(at, now()))
}

#[cfg(test)]
mod tests;
