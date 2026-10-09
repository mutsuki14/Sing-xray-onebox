//! Cloudflare DNS-01 credentials.
//!
//! Credentials stay per certificate directory, in the v2 layout:
//! `<D>/acme/onebox-dns.json` (compact JSON object, sorted keys, 0600; the
//! FRP web certificate uses its own directory too). [`lookup`] merges, later
//! sources winning (F §4.6.5):
//! 1. the v1-era acme.sh home `$ACME_HOME` or `/root/.acme.sh`
//!    `account.conf` (proxy directory only),
//! 2. `<D>/../acme/account.conf`,
//! 3. `<D>/acme/account.conf` (acme.sh saves `SAVED_CF_*` there),
//! 4. `<D>/acme/onebox-dns.json`,
//! 5. the process environment (`CF_Token`, `CF_Key`, `CF_Email`,
//!    `CF_Account_ID`, `CF_Zone_ID`).
//!
//! `account.conf` files are parsed as data and never sourced: a value is
//! accepted only if it is 1–1024 bytes of `[A-Za-z0-9@._+-]` after one
//! level of matching quotes is removed (`$(…)`, `; cmd` are ignored).
//!
//! Changes from v2: credentials are resolved before an apply (the CLI
//! prompts, the apply engine never does) and handed to acme.sh only through
//! that command's environment — v2 exported them with `std::env::set_var`
//! into the whole process, so every later child (curl, nginx, the cores)
//! inherited the token (F-8.1#11); `Debug` output of [`CfCredentials`]
//! never shows values.

use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::host::os::{process_env, EnvLookup};
use crate::sys::fs::{atomic_write, ensure_dir, read_bounded};
use crate::ui::{out, Prompter};
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

/// Every credential key acme.sh's `dns_cf` reads.
pub const KEYS: [&str; 5] = [
    "CF_Token",
    "CF_Key",
    "CF_Email",
    "CF_Account_ID",
    "CF_Zone_ID",
];
pub const STORE_FILE: &str = "acme/onebox-dns.json";
/// Error when DNS validation is chosen without usable credentials (v2 text).
pub const MISSING: &str =
    "Cloudflare DNS 验证缺少凭据，请提供 CF_Token（可同时提供 CF_Account_ID），或在交互终端输入";
const TOKEN_PROMPT: &str = "Cloudflare API Token";
const ACCOUNT_PROMPT: &str = "Cloudflare Account ID（可留空自动查询）";
const BAD_TOKEN: &str = "Cloudflare API Token 不能为空或含控制字符";
const BAD_ACCOUNT: &str = "Cloudflare Account ID 应为 32 位十六进制值";
const FILE_MAX: u64 = 256 * 1024;
const VALUE_MAX: usize = 1024;
const TOKEN_ATTEMPTS: usize = 3;

/// A merged set of Cloudflare credentials (key → value, sorted).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct CfCredentials {
    values: BTreeMap<String, String>,
}

impl fmt::Debug for CfCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CfCredentials")
            .field("keys", &self.values.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl CfCredentials {
    /// An API token credential (what the prompt produces).
    pub fn token(token: &str, account_id: Option<&str>) -> Result<CfCredentials> {
        if !valid_value(token) {
            return Err(Error::msg(BAD_TOKEN));
        }
        let mut c = CfCredentials::default();
        c.values.insert("CF_Token".into(), token.to_owned());
        if let Some(id) = account_id.filter(|id| !id.is_empty()) {
            if !valid_account(id) {
                return Err(Error::msg(BAD_ACCOUNT));
            }
            c.values.insert("CF_Account_ID".into(), id.to_owned());
        }
        Ok(c)
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(String::as_str)
    }

    /// `CF_Token`, or `CF_Key` together with `CF_Email`.
    pub fn is_complete(&self) -> bool {
        self.values.contains_key("CF_Token")
            || (self.values.contains_key("CF_Key") && self.values.contains_key("CF_Email"))
    }

    /// The variables for acme.sh's environment, sorted by key.
    pub fn env(&self) -> Vec<(String, String)> {
        self.values
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Values that must never appear in output.
    pub fn secrets(&self) -> Vec<String> {
        self.values.values().cloned().collect()
    }

    /// Insert values accepted by `valid` (later calls win).
    fn absorb(&mut self, pairs: BTreeMap<String, String>, valid: fn(&str) -> bool) {
        for (key, value) in pairs {
            if KEYS.contains(&key.as_str()) && valid(&value) {
                self.values.insert(key, value);
            }
        }
    }

    fn to_json(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&self.values)?)
    }
}

/// JSON/environment values: non-empty, bounded, no control characters.
fn valid_value(value: &str) -> bool {
    !value.is_empty() && value.len() <= VALUE_MAX && !value.chars().any(char::is_control)
}

/// `account.conf` values: the v2 data-only character set.
fn valid_conf_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= VALUE_MAX
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"@._+-".contains(&b))
}

fn valid_account(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Parse `KEY=VALUE` / `SAVED_KEY='VALUE'` lines of an acme.sh
/// `account.conf` without interpreting them (see the module docs).
pub fn parse_account_conf(text: &str) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    for line in text.lines() {
        let Some((key, value)) = line.trim().split_once('=') else {
            continue;
        };
        let key = key.strip_prefix("SAVED_").unwrap_or(key);
        if !KEYS.contains(&key) {
            continue;
        }
        let value = value.trim();
        let quoted = value.len() >= 2
            && ((value.starts_with('\'') && value.ends_with('\''))
                || (value.starts_with('"') && value.ends_with('"')));
        let value = if quoted {
            &value[1..value.len() - 1]
        } else {
            value
        };
        if valid_conf_value(value) {
            values.insert(key.to_owned(), value.to_owned());
        }
    }
    values
}

/// The stored credential file of certificate directory `dir`.
pub fn store_path(dir: &Path) -> PathBuf {
    dir.join(STORE_FILE)
}

/// Stored and environment credentials for `dir`; `None` unless complete.
/// Never prompts.
pub fn lookup(ctx: &Ctx, dir: &Path) -> Result<Option<CfCredentials>> {
    lookup_with(ctx, dir, &process_env)
}

/// [`lookup`] with an injected environment.
pub fn lookup_with(ctx: &Ctx, dir: &Path, env: EnvLookup) -> Result<Option<CfCredentials>> {
    let merged = merged_with(ctx, dir, env)?;
    Ok(merged.is_complete().then_some(merged))
}

/// Everything stored and in the environment for `dir`, complete or not.
fn merged_with(ctx: &Ctx, dir: &Path, env: EnvLookup) -> Result<CfCredentials> {
    let mut merged = CfCredentials::default();
    for conf in account_files(ctx, dir, env) {
        if let Ok(bytes) = read_bounded(&conf, FILE_MAX) {
            merged.absorb(
                parse_account_conf(&String::from_utf8_lossy(&bytes)),
                valid_conf_value,
            );
        }
    }
    let stored = store_path(dir);
    if std::fs::symlink_metadata(&stored).is_ok() {
        let bytes = read_bounded(&stored, FILE_MAX)?;
        let saved: BTreeMap<String, String> = serde_json::from_slice(&bytes).map_err(|e| {
            Error::msg(format!("Cloudflare 凭据文件无效 {}: {e}", stored.display()))
        })?;
        merged.absorb(saved, valid_value);
    }
    let from_env: BTreeMap<String, String> = KEYS
        .iter()
        .filter_map(|k| env(k).map(|v| (k.to_string(), v)))
        .collect();
    merged.absorb(from_env, valid_value);
    Ok(merged)
}

/// `account.conf` files in merge order (earliest first).
fn account_files(ctx: &Ctx, dir: &Path, env: EnvLookup) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if dir == ctx.paths.tls() {
        let legacy = env("ACME_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| ctx.paths.system("/root/.acme.sh"));
        files.push(legacy.join("account.conf"));
    }
    if let Some(parent) = dir.parent() {
        files.push(parent.join("acme/account.conf"));
    }
    files.push(dir.join("acme/account.conf"));
    files
}

/// Ask for an API token (no echo) and an optional account ID. Under `-y`
/// the secret prompt fails with "无人值守模式请通过环境变量提供凭据".
pub fn prompt(ui: &dyn Prompter) -> Result<CfCredentials> {
    let mut attempts = 0;
    let token = loop {
        let token = ui.secret(TOKEN_PROMPT)?;
        if valid_value(&token) {
            break token;
        }
        attempts += 1;
        if attempts >= TOKEN_ATTEMPTS {
            return Err(Error::msg(BAD_TOKEN));
        }
        out::warn(BAD_TOKEN);
    };
    let check = |answer: &str| -> Result<String> {
        if answer.is_empty() || valid_account(answer) {
            Ok(answer.to_owned())
        } else {
            Err(Error::msg(BAD_ACCOUNT))
        }
    };
    let account = ui.input_with(ACCOUNT_PROMPT, "", &check)?;
    CfCredentials::token(&token, Some(&account))
}

/// Store `credentials` for `dir` (`<D>/acme` 0700, file 0600, sorted keys).
pub fn persist(dir: &Path, credentials: &CfCredentials) -> Result<()> {
    ensure_dir(dir, 0o700)?;
    ensure_dir(&dir.join("acme"), 0o700)?;
    atomic_write(&store_path(dir), &credentials.to_json()?, 0o600)
}

/// The credentials an issuance for `dir` uses: the stored and environment
/// ones with `given` (resolved by the CLI, when complete) laid over them —
/// so a stored `CF_Zone_ID` or `CF_Account_ID` survives a new token (v2
/// merged the same way) — persisted so later scheduled renewals find them.
/// Never prompts.
pub fn resolve(
    ctx: &Ctx,
    dir: &Path,
    given: Option<&CfCredentials>,
    env: EnvLookup,
) -> Result<CfCredentials> {
    let mut credentials = merged_with(ctx, dir, env)?;
    if let Some(given) = given.filter(|c| c.is_complete()) {
        credentials.absorb(given.values.clone(), valid_value);
    }
    if !credentials.is_complete() {
        return Err(Error::msg(MISSING));
    }
    persist(dir, &credentials)?;
    Ok(credentials)
}

#[cfg(test)]
mod tests;
