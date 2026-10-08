//! openssl invocations: pair validation (F §4.6.1, exact v2 checks), the
//! key-matching leaf of a chain, expiry windows and certificate facts.
//!
//! Every call goes through `Ctx::exec` with a timeout. PEM blocks are fed on
//! stdin where possible so no temporary copy of a certificate is needed.
//!
//! Changes from v2: failures have Chinese messages that say which check
//! failed (`证书已过期`, `证书与 NAME 不匹配…: hostname mismatch`) instead
//! of the raw `openssl 执行失败 (2): …` text; certificate dates are parsed
//! so status output and `doctor` can show the remaining days.

use super::method::valid_name;
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::render::tls::TlsMaterial;
use crate::sys::exec::{Cmd, Output};
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(30);
/// Host name checked for a wildcard name `*.base` (v2).
const WILDCARD_PROBE: &str = "onebox-cert-check";

/// Which trust a deployed pair must satisfy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trust {
    /// Verifies against the system CA store (ACME, public web endpoints).
    Public,
    /// The chain in the file is its own trust anchor (self-signed or a
    /// private CA; clients pin the leaf).
    Pinned,
}

fn openssl() -> Cmd {
    Cmd::new("openssl").timeout(TIMEOUT)
}

fn path_arg(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// The first meaningful line of openssl's complaint, without control chars.
fn detail(out: &Output) -> String {
    let text = format!("{}\n{}", out.stderr, out.stdout);
    let line = text
        .lines()
        .map(str::trim)
        .find_map(|l| l.split_once("lookup:").map(|(_, rest)| rest.trim()))
        .or_else(|| text.lines().map(str::trim).rfind(|l| !l.is_empty()))
        .unwrap_or("");
    let clean: String = line.chars().filter(|c| !c.is_control()).take(200).collect();
    if clean.is_empty() {
        format!("退出码 {}", out.code)
    } else {
        clean
    }
}

/// v2 `validate_pair`: valid name; both files exist; not expired; the
/// certificate's public key is the key's; `openssl verify -purpose
/// sslserver` for the name (`-verify_ip` for IP literals, the probe host
/// `onebox-cert-check.BASE` for `*.BASE`) against the system store
/// (`Public`) or the file's own chain (`Pinned`, `-partial_chain`); a
/// wildcard must be a literal `DNS:*.BASE` SAN entry.
pub fn validate_pair(ctx: &Ctx, cert: &Path, key: &Path, name: &str, trust: Trust) -> Result<()> {
    if !valid_name(name) {
        return Err(Error::msg("证书域名无效"));
    }
    if !cert.is_file() || !key.is_file() {
        return Err(Error::msg("证书或私钥文件不存在"));
    }
    let cert_s = path_arg(cert);
    let unexpired =
        ctx.run(&openssl().args(["x509", "-in", &cert_s, "-noout", "-checkend", "0"]))?;
    if !unexpired.ok() {
        return Err(Error::msg("证书已过期或无法读取"));
    }
    let cert_key = ctx.check(&openssl().args(["x509", "-in", &cert_s, "-pubkey", "-noout"]))?;
    if cert_key.trim() != key_pubkey(ctx, key)?.trim() {
        return Err(Error::msg("证书与私钥不匹配"));
    }
    verify(ctx, &cert_s, name, trust)?;
    if name.starts_with("*.") {
        let text = ctx.check(&openssl().args(["x509", "-in", &cert_s, "-noout", "-text"]))?;
        let wanted = format!("DNS:{name}");
        if !text
            .split(|c: char| c == ',' || c.is_whitespace())
            .any(|token| token == wanted)
        {
            return Err(Error::msg("证书缺少要求的泛域名 SAN"));
        }
    }
    Ok(())
}

fn verify(ctx: &Ctx, cert: &str, name: &str, trust: Trust) -> Result<()> {
    let check_name = match name.strip_prefix("*.") {
        Some(base) => format!("{WILDCARD_PROBE}.{base}"),
        None => name.to_owned(),
    };
    let flag = if name.parse::<IpAddr>().is_ok() {
        "-verify_ip"
    } else {
        "-verify_hostname"
    };
    let mut cmd = openssl().args(["verify", "-purpose", "sslserver", flag, &check_name]);
    cmd = match trust {
        Trust::Public => cmd.args(["-untrusted", cert]),
        Trust::Pinned => cmd.args(["-partial_chain", "-trusted", cert]),
    };
    let out = ctx.run(&cmd.arg(cert))?;
    if out.ok() {
        return Ok(());
    }
    let why = detail(&out);
    Err(Error::msg(match trust {
        Trust::Public => format!("证书未通过公共 CA 验证或与 {name} 不匹配: {why}"),
        Trust::Pinned => format!("证书与 {name} 不匹配或不能用于 TLS 服务器: {why}"),
    }))
}

/// Whether the pair verifies against the system CA store for `name`
/// (feeds `ProxyTls::record_trust`, v2 cert.rs:805-813).
pub fn publicly_trusted(ctx: &Ctx, cert: &Path, key: &Path, name: &str) -> bool {
    validate_pair(ctx, cert, key, name, Trust::Public).is_ok()
}

/// `openssl x509 -checkend SECS`: true when the certificate expires within
/// `secs` seconds, or cannot be read at all (it is not usable either way).
pub fn expires_within(ctx: &Ctx, cert: &Path, secs: u64) -> bool {
    let cmd = openssl().args([
        "x509",
        "-in",
        &path_arg(cert),
        "-noout",
        "-checkend",
        &secs.to_string(),
    ]);
    !ctx.run(&cmd).is_ok_and(|out| out.ok())
}

/// The public key of a private key file (`openssl pkey -pubout`).
pub fn key_pubkey(ctx: &Ctx, key: &Path) -> Result<String> {
    let out = ctx.run(&openssl().args(["pkey", "-in", &path_arg(key), "-pubout"]))?;
    if !out.ok() {
        return Err(Error::msg("私钥无效或无法读取"));
    }
    Ok(out.stdout)
}

/// The public key of one PEM certificate block (fed on stdin).
pub fn cert_pubkey(ctx: &Ctx, pem: &str) -> Result<String> {
    let cmd = openssl()
        .args(["x509", "-noout", "-pubkey"])
        .stdin_bytes(pem.as_bytes());
    let out = ctx.run(&cmd)?;
    if !out.ok() {
        return Err(Error::msg("证书链包含无法解析的证书"));
    }
    Ok(out.stdout)
}

/// Index of the certificate whose public key belongs to `key` (the leaf),
/// so a chain given CA-first can be deployed leaf-first.
pub fn leaf_index(ctx: &Ctx, chain: &TlsMaterial, key: &Path) -> Result<usize> {
    let wanted = key_pubkey(ctx, key)?;
    for (index, pem) in chain.pems().iter().enumerate() {
        if cert_pubkey(ctx, pem)?.trim() == wanted.trim() {
            return Ok(index);
        }
    }
    Err(Error::msg("证书与私钥不匹配"))
}

/// Facts shown by `cert info` and checked by `doctor`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct X509Info {
    pub subject: String,
    pub issuer: String,
    /// openssl's text, e.g. `Oct  8 18:19:13 2026 GMT`.
    pub not_before: String,
    pub not_after: String,
    /// `not_after` as unix seconds when it could be parsed.
    pub expires_at: Option<u64>,
}

/// `openssl x509 -noout -subject -issuer -dates` of the first certificate.
pub fn x509_info(ctx: &Ctx, cert: &Path) -> Result<X509Info> {
    let text = ctx.check(&openssl().args([
        "x509",
        "-in",
        &path_arg(cert),
        "-noout",
        "-subject",
        "-issuer",
        "-dates",
    ]))?;
    Ok(parse_x509_info(&text))
}

/// Parse the `key=value` lines printed by [`x509_info`]'s command.
pub fn parse_x509_info(text: &str) -> X509Info {
    let mut info = X509Info::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().to_owned();
        match key.trim() {
            "subject" => info.subject = value,
            "issuer" => info.issuer = value,
            "notBefore" => info.not_before = value,
            "notAfter" => info.not_after = value,
            _ => {}
        }
    }
    info.expires_at = parse_date(&info.not_after);
    info
}

/// openssl's `Mon DD HH:MM:SS YYYY GMT` as unix seconds (None if malformed
/// or before 1970).
pub fn parse_date(text: &str) -> Option<u64> {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let words: Vec<&str> = text.split_whitespace().collect();
    let [month, day, time, year, "GMT"] = words.as_slice() else {
        return None;
    };
    let month = MONTHS.iter().position(|m| m == month)? as u32 + 1;
    let day: u32 = day.parse().ok().filter(|d| (1..=31).contains(d))?;
    let year: i64 = year.parse().ok()?;
    let mut clock = time.split(':').map(|p| p.parse::<u64>().ok());
    let (h, m, s) = (clock.next()??, clock.next()??, clock.next()??);
    if clock.next().is_some() || h > 23 || m > 59 || s > 60 {
        return None;
    }
    let days = days_from_civil(year, month, day);
    let secs = days.checked_mul(86_400)? + (h * 3600 + m * 60 + s) as i64;
    u64::try_from(secs).ok()
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`; inverse of `sys::time::civil_from_days`).
pub fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (i64::from(month) + 9) % 12;
    let doy = (153 * mp + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests;
