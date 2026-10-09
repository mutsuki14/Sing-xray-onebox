//! acme.sh 3.1.6 as the ACME client (Let's Encrypt, ECDSA P-256).
//!
//! Layout (v2, so certificates v2 issued keep their renewal state): every
//! certificate directory `D` has its own acme.sh home `D/acme`
//! (`--home`/`--config-home`), `D/acme/certs` (`--cert-home`), the script
//! `D/acme/acme.sh` and `D/acme/dnsapi/dns_cf.sh`. acme.sh installs no cron
//! job of its own; Onebox schedules renewals.
//!
//! Arguments (F §4.6.3): base `--home H --config-home H --cert-home H/certs
//! --server letsencrypt`, then
//! - issue: `--issue -d D1 [-d …] --keylength ec-256 --force` plus
//!   `--webroot W` or `--dns dns_cf`;
//! - renew: `--renew -d D1 [-d …] --ecc`, plus `--force` when forced. A
//!   renewal falls back to an issuance when acme.sh has no domain
//!   configuration yet or its recorded `Le_Webroot` is not the challenge
//!   now wanted (acme.sh `--renew` always reuses the recorded one).
//!
//! Exit code 2 is acme.sh's "not due yet": a success without new files for
//! a renewal that is not forced, a failure otherwise. Output is captured and
//! never printed raw: failures show the last lines with every credential
//! value and every long token-like word replaced by `***`.
//!
//! The command runs with a cleared environment: `PATH`, a short allowlist
//! (`HOME`, locale, proxy and CA-bundle variables) and, for DNS-01, the
//! Cloudflare credentials of this one call.
//!
//! Changes from v2: both scripts are pinned by SHA-256 (v2 only checked
//! sizes and shebangs, F-8.1#12) and an existing unverified copy is
//! replaced; manual renewals pass `--force` (F-8.1#3); HTTP-01 without an
//! Onebox nginx uses the built-in responder with `--webroot` instead of
//! `--standalone` (F-8.1#4/#5); credentials only reach acme.sh's own
//! environment (F-8.1#11); a failure shows a redacted tail of acme.sh's
//! output instead of only the exit code.

use super::cloudflare::CfCredentials;
use super::engine::Engine;
use super::http01::Responder;
use super::method::Challenge;
use super::store::CertDir;
use crate::error::{Error, Result};
use crate::host::fetch;
use crate::sys::exec::{Cmd, Output, SAFE_PATH};
use crate::sys::fs::{ensure_dir, read_bounded, remove_tree_if_exists, sha256_file};
use crate::ui::out;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

const RAW: &str = "https://raw.githubusercontent.com/acmesh-official/acme.sh";
/// acme.sh may wait minutes for DNS propagation.
const ACME_TIMEOUT: Duration = Duration::from_secs(20 * 60);
/// Lines of acme.sh output shown with a failure.
const TAIL_LINES: usize = 8;
const TAIL_LINE_CHARS: usize = 200;
/// Token-like words at least this long are hidden from failure output.
const LONG_WORD: usize = 24;
const DOMAIN_CONF_MAX: u64 = 256 * 1024;
/// Variables acme.sh may need from the caller's environment.
const FORWARD_ENV: [&str; 14] = [
    "HOME",
    "LANG",
    "LC_ALL",
    "TZ",
    "http_proxy",
    "https_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "no_proxy",
    "NO_PROXY",
    "all_proxy",
    "ALL_PROXY",
    "SSL_CERT_FILE",
    "CURL_CA_BUNDLE",
];

/// A file fetched over HTTPS and accepted only with this SHA-256.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinnedFile {
    pub url: String,
    pub sha256: String,
    pub max_bytes: u64,
}

/// The acme.sh release Onebox runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcmeRelease {
    pub script: PinnedFile,
    pub dns_cf: PinnedFile,
}

impl AcmeRelease {
    /// acme.sh 3.1.6 (294737 + 7331 bytes).
    pub fn pinned() -> AcmeRelease {
        let version = crate::domain::defaults::ACME_SH_VERSION;
        AcmeRelease {
            script: PinnedFile {
                url: format!("{RAW}/{version}/acme.sh"),
                sha256: "c7d68b021cfd6380ea83a82962abde5b484779fee0b97d38681dfa1396bbc8d7".into(),
                max_bytes: 1024 * 1024,
            },
            dns_cf: PinnedFile {
                url: format!("{RAW}/{version}/dnsapi/dns_cf.sh"),
                sha256: "9628ee8238cb3f9cfa1b1a985c0e9593436a3e4f8a9d65a6f775b981be9e76c8".into(),
                max_bytes: 64 * 1024,
            },
        }
    }
}

/// What to ask acme.sh for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request {
    Issue,
    Renew { force: bool },
}

/// Make sure `home` holds the pinned scripts; returns the acme.sh path.
pub fn install(engine: &Engine, home: &Path) -> Result<PathBuf> {
    ensure_dir(home, 0o700)?;
    ensure_dir(&home.join("dnsapi"), 0o700)?;
    let script = home.join("acme.sh");
    fetch_pinned(engine, &engine.release.script, &script)?;
    fetch_pinned(
        engine,
        &engine.release.dns_cf,
        &home.join("dnsapi/dns_cf.sh"),
    )?;
    Ok(script)
}

/// Keep `dest` when it already has the pinned hash, else download it
/// directly from GitHub (no `GH_PROXY`); executable by root only.
fn fetch_pinned(engine: &Engine, file: &PinnedFile, dest: &Path) -> Result<()> {
    let current = std::fs::symlink_metadata(dest).is_ok_and(|m| m.is_file())
        && sha256_file(dest).is_ok_and(|h| h == file.sha256);
    if !current {
        fetch::download_pinned(
            engine.ctx,
            &file.url,
            dest,
            file.max_bytes,
            &file.sha256,
            false,
        )
        .map_err(|e| e.wrap("下载 acme.sh 失败"))?;
    }
    std::fs::set_permissions(dest, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| Error::io(dest, e))
}

/// acme.sh's directory for the primary name (`certs/{primary}_ecc`).
pub fn issued_dir(dir: &CertDir, primary: &str) -> PathBuf {
    dir.acme_home().join("certs").join(format!("{primary}_ecc"))
}

/// `(fullchain.cer, {primary}.key)` written by acme.sh.
pub fn issued_pair(dir: &CertDir, primary: &str) -> (PathBuf, PathBuf) {
    let issued = issued_dir(dir, primary);
    (
        issued.join("fullchain.cer"),
        issued.join(format!("{primary}.key")),
    )
}

/// The `Le_Webroot` acme.sh recorded for the primary name (a path,
/// `dns_cf`, or `no` for v2's standalone mode).
pub fn recorded_challenge(dir: &CertDir, primary: &str) -> Option<String> {
    let conf = issued_dir(dir, primary).join(format!("{primary}.conf"));
    let text = String::from_utf8(read_bounded(&conf, DOMAIN_CONF_MAX).ok()?).ok()?;
    text.lines().find_map(|line| {
        let value = line.trim().strip_prefix("Le_Webroot=")?;
        let unquoted = value
            .strip_prefix('\'')
            .and_then(|v| v.strip_suffix('\''))
            .unwrap_or(value);
        Some(unquoted.to_owned())
    })
}

/// How acme.sh records `challenge` as `Le_Webroot`.
fn challenge_marker(challenge: &Challenge) -> String {
    match challenge.webroot() {
        Some(webroot) => webroot.to_string_lossy().into_owned(),
        None => "dns_cf".to_owned(),
    }
}

/// The argument list (module docs).
pub fn args(
    home: &Path,
    domains: &[String],
    challenge: &Challenge,
    request: Request,
) -> Vec<String> {
    let home_s = home.to_string_lossy().into_owned();
    let mut args: Vec<String> = vec![
        "--home".into(),
        home_s.clone(),
        "--config-home".into(),
        home_s,
        "--cert-home".into(),
        home.join("certs").to_string_lossy().into_owned(),
        "--server".into(),
        "letsencrypt".into(),
    ];
    args.push(match request {
        Request::Issue => "--issue".into(),
        Request::Renew { .. } => "--renew".into(),
    });
    for domain in domains {
        args.extend(["-d".to_owned(), domain.clone()]);
    }
    match request {
        Request::Renew { force } => {
            args.push("--ecc".into());
            if force {
                args.push("--force".into());
            }
        }
        Request::Issue => {
            args.extend(["--keylength", "ec-256", "--force"].map(String::from));
            match challenge.webroot() {
                Some(webroot) => {
                    args.extend(["--webroot".into(), webroot.to_string_lossy().into_owned()])
                }
                None => args.extend(["--dns".into(), "dns_cf".into()]),
            }
        }
    }
    args
}

/// Run acme.sh for `domains`; `Ok(true)` when it produced new files to
/// deploy (see [`issued_pair`]), `Ok(false)` for an unforced renewal that
/// was not due — the pair acme.sh holds may still be newer than the
/// deployed one (a deployment that failed after an earlier renewal), so
/// the engine deploys it in both cases.
pub fn obtain(
    engine: &Engine,
    dir: &CertDir,
    domains: &[String],
    challenge: &Challenge,
    request: Request,
    credentials: Option<&CfCredentials>,
) -> Result<bool> {
    let home = dir.acme_home();
    let script = install(engine, &home)?;
    ensure_dir(&home.join("certs"), 0o700)?;
    let primary = domains.first().map(String::as_str).unwrap_or("");
    let request = match request {
        Request::Renew { .. }
            if recorded_challenge(dir, primary).as_deref()
                != Some(&challenge_marker(challenge)) =>
        {
            Request::Issue
        }
        other => other,
    };
    let cmd = command(
        engine,
        &script,
        &home,
        domains,
        challenge,
        request,
        credentials,
    );
    let action = match request {
        Request::Issue => "申请",
        Request::Renew { .. } => "续期",
    };
    out::info(format!(
        "正在通过 Let's Encrypt {action}证书 {primary}（可能需要几分钟）"
    ));
    let output = with_challenge(engine, dir, challenge, || engine.ctx.run(&cmd))?;
    match (output.code, request) {
        (0, _) => Ok(true),
        (2, Request::Renew { force: false }) => Ok(false),
        (code, _) => Err(failure(code, &output, credentials)),
    }
}

fn command(
    engine: &Engine,
    script: &Path,
    home: &Path,
    domains: &[String],
    challenge: &Challenge,
    request: Request,
    credentials: Option<&CfCredentials>,
) -> Cmd {
    let mut cmd = Cmd::new(script.to_string_lossy())
        .args(args(home, domains, challenge, request))
        .clear_env()
        .env("PATH", SAFE_PATH)
        .timeout(ACME_TIMEOUT);
    for key in FORWARD_ENV {
        if let Some(value) = (engine.env)(key) {
            cmd = cmd.env(key, value);
        }
    }
    if matches!(challenge, Challenge::Cloudflare) {
        for (key, value) in credentials.map(CfCredentials::env).unwrap_or_default() {
            cmd = cmd.env(key, value);
        }
    }
    cmd
}

/// Run `call` while the built-in responder serves a responder challenge.
/// The responder webroot inside the certificate directory is emptied
/// afterwards; another webroot (the site's) is left to acme.sh's cleanup.
fn with_challenge(
    engine: &Engine,
    dir: &CertDir,
    challenge: &Challenge,
    call: impl FnOnce() -> Result<Output>,
) -> Result<Output> {
    let Challenge::Responder(webroot) = challenge else {
        return call();
    };
    ensure_dir(
        webroot,
        if webroot.starts_with(dir.path()) {
            0o700
        } else {
            0o755
        },
    )?;
    let responder = Responder::start(webroot, engine.http01_port, &engine.ctx.paths.system_root)?;
    let result = call();
    responder.stop();
    if webroot.starts_with(dir.acme_home()) {
        let _ = remove_tree_if_exists(&webroot.join(".well-known"));
    }
    result
}

fn failure(code: i32, out: &Output, credentials: Option<&CfCredentials>) -> Error {
    let secrets = credentials.map(CfCredentials::secrets).unwrap_or_default();
    let tail = redacted_tail(out, &secrets);
    let mut message = format!("ACME 验证或签发失败，退出码 {code}；请检查 DNS、端口及账户配置");
    if !tail.is_empty() {
        message.push_str("\nacme.sh 输出（已隐去凭据）:");
        for line in tail {
            message.push_str("\n  ");
            message.push_str(&line);
        }
    }
    Error::msg(message)
}

/// The last lines of acme.sh's output with credentials hidden: each
/// `secrets` value, `KEY=value` pairs of credential-like keys, and every
/// long token-like word become `***`; control characters and ANSI colors
/// are dropped.
pub fn redacted_tail(out: &Output, secrets: &[String]) -> Vec<String> {
    let text = format!("{}\n{}", out.stdout, out.stderr);
    let lines: Vec<String> = text
        .lines()
        .map(|line| redact_line(&strip_ansi(line), secrets))
        .filter(|line| !line.is_empty())
        .collect();
    lines[lines.len().saturating_sub(TAIL_LINES)..].to_vec()
}

fn strip_ansi(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if chars.peek() == Some(&'[') {
                chars.next();
                for x in chars.by_ref() {
                    if x.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
        } else if !c.is_control() {
            out.push(c);
        }
    }
    out
}

fn redact_line(line: &str, secrets: &[String]) -> String {
    let mut line = line.trim().to_owned();
    for secret in secrets.iter().filter(|s| s.len() >= 4) {
        line = line.replace(secret.as_str(), "***");
    }
    let words: Vec<String> = line.split(' ').map(redact_word).collect();
    let line = words.join(" ");
    line.chars().take(TAIL_LINE_CHARS).collect()
}

/// `CF_Token='…'`-style assignments and long token-like runs.
fn redact_word(word: &str) -> String {
    let sensitive_key = |k: &str| {
        let k = k.to_ascii_lowercase();
        ["token", "key", "secret", "password", "auth", "email"]
            .iter()
            .any(|s| k.contains(s))
    };
    if let Some((key, _)) = word.split_once(['=', ':']) {
        if sensitive_key(key) && word.len() > key.len() + 1 {
            return format!("{key}{}***", &word[key.len()..key.len() + 1]);
        }
    }
    let mut out = String::new();
    let mut run = String::new();
    let flush = |run: &mut String, out: &mut String| {
        if run.len() >= LONG_WORD {
            out.push_str("***");
        } else {
            out.push_str(run);
        }
        run.clear();
    };
    for c in word.chars() {
        if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
            run.push(c);
        } else {
            flush(&mut run, &mut out);
            out.push(c);
        }
    }
    flush(&mut run, &mut out);
    out
}

#[cfg(test)]
mod tests;
