//! OS facts: os-release, architecture naming tables, virtualization/container
//! detection, root checks, and the environment lookup used by `host`.
//!
//! System files are read under `Paths::system_root`, so tests run against
//! fixture trees; programs (`uname`, `systemd-detect-virt`) go through
//! `Ctx::exec`.
//!
//! Changes from v2:
//! - os-release values are unquoted like the shell does (escapes inside
//!   double quotes) and `/usr/lib/os-release` is the fallback (os-release(5));
//!   v2 stripped every quote character from both ends.
//! - `ID_LIKE` and `PRETTY_NAME` are exposed; a missing `ID` is shown as
//!   `linux` instead of an empty string in messages.
//! - virtualization facts also cover containers announced through
//!   `/proc/1/environ`, podman (`/run/.containerenv`), OpenVZ (`/proc/vz`
//!   without `/proc/bc`) and WSL; v2 only knew `systemd-detect-virt` and
//!   `/.dockerenv`.
//! - one architecture table serves every artifact (sing-box, Xray, FRP,
//!   Onebox releases, BBRv3); v2 FRP used the compile-time target instead of
//!   `uname -m` and mapped x86 to a `386` asset that frp does not publish.

mod arch;
mod virt;

pub use arch::{Arch, BbrArch};
pub use virt::HostFacts;

use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::sys::exec::Cmd;
use std::time::Duration;

/// Message of [`require_root`] (v2 wording).
pub const ROOT_REQUIRED: &str = "此操作需要 root 权限";
/// Upper bound for small system text files (os-release, cpuinfo, environ).
const SYSTEM_FILE_MAX: u64 = 1024 * 1024;
/// Short-lived informational commands (`uname`, `systemd-detect-virt`).
pub(crate) const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Environment lookup injected into functions that read `ONEBOX_*`,
/// `GH_PROXY` or `GH_TOKEN`, so tests never touch the process environment.
pub type EnvLookup<'a> = &'a dyn Fn(&str) -> Option<String>;

/// The process environment as an [`EnvLookup`]: a variable that is unset,
/// empty or not UTF-8 counts as absent.
pub fn process_env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

/// Identification from os-release(5).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OsInfo {
    /// `ID`, lower-case (`debian`, `ubuntu`, `alpine`, `rocky`, …); may be empty.
    pub id: String,
    /// `ID_LIKE`, split on whitespace (`["rhel", "centos", "fedora"]`).
    pub id_like: Vec<String>,
    /// `VERSION_ID` (`12`, `22.04`, `3.20.1`); may be empty.
    pub version_id: String,
    /// `PRETTY_NAME` (`Debian GNU/Linux 12 (bookworm)`); may be empty.
    pub pretty_name: String,
}

impl OsInfo {
    /// Read `{system_root}/etc/os-release`, else `/usr/lib/os-release`.
    /// A host without either file yields an empty [`OsInfo`].
    pub fn load(ctx: &Ctx) -> OsInfo {
        ["/etc/os-release", "/usr/lib/os-release"]
            .iter()
            .find_map(|p| {
                crate::sys::fs::read_to_string_bounded(&ctx.paths.system(p), SYSTEM_FILE_MAX).ok()
            })
            .map(|text| OsInfo::parse(&text))
            .unwrap_or_default()
    }

    /// Parse os-release text: `KEY=value` lines, `#` comments, values
    /// optionally single- or double-quoted (shell rules).
    pub fn parse(text: &str) -> OsInfo {
        let mut info = OsInfo::default();
        for (key, value) in text.lines().filter_map(parse_assignment) {
            match key {
                "ID" => info.id = value.to_ascii_lowercase(),
                "ID_LIKE" => {
                    info.id_like = value
                        .split_whitespace()
                        .map(str::to_ascii_lowercase)
                        .collect()
                }
                "VERSION_ID" => info.version_id = value,
                "PRETTY_NAME" => info.pretty_name = value,
                _ => {}
            }
        }
        info
    }

    /// Name used in messages such as `{os}: 未找到受支持的包管理器…`.
    pub fn label(&self) -> &str {
        if self.id.is_empty() {
            "linux"
        } else {
            &self.id
        }
    }

    /// `ID` or one of `ID_LIKE` equals `family` (`debian`, `rhel`, `alpine`…).
    pub fn is_like(&self, family: &str) -> bool {
        self.id == family || self.id_like.iter().any(|l| l == family)
    }
}

/// One os-release line → `(KEY, unquoted value)`; comments, blank lines and
/// malformed keys yield `None`.
fn parse_assignment(line: &str) -> Option<(&str, String)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let (key, raw) = line.split_once('=')?;
    let key_ok = !key.is_empty()
        && key
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
    key_ok.then(|| (key, unquote(raw.trim())))
}

/// Shell-style unquoting of an os-release value: `'…'` is literal; inside
/// `"…"` a backslash escapes `"`, `\`, `$` and `` ` ``; unquoted values are
/// taken as they are.
fn unquote(raw: &str) -> String {
    if raw.len() >= 2 && raw.starts_with('\'') && raw.ends_with('\'') {
        return raw[1..raw.len() - 1].to_string();
    }
    if !(raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"')) {
        return raw.to_string();
    }
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw[1..raw.len() - 1].chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some(e @ ('"' | '\\' | '$' | '`')) => out.push(e),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// True when running with root privileges (effective uid 0).
pub fn is_root() -> bool {
    crate::sys::process::is_root()
}

/// `Err("此操作需要 root 权限")` unless running as root.
pub fn require_root() -> Result<()> {
    require_root_with(is_root())
}

/// [`require_root`] with the privilege fact injected (tests).
pub fn require_root_with(root: bool) -> Result<()> {
    if root {
        Ok(())
    } else {
        Err(Error::msg(ROOT_REQUIRED))
    }
}

/// `uname -m`, trimmed.
pub fn machine(ctx: &Ctx) -> Result<String> {
    uname(ctx, "-m")
}

/// `uname -r` (running kernel release), trimmed.
pub fn kernel_release(ctx: &Ctx) -> Result<String> {
    uname(ctx, "-r")
}

fn uname(ctx: &Ctx, flag: &str) -> Result<String> {
    let out = ctx.check(&Cmd::new("uname").arg(flag).timeout(PROBE_TIMEOUT))?;
    let value = out.trim();
    if value.is_empty() {
        return Err(Error::msg(format!("uname {flag} 没有输出")));
    }
    Ok(value.to_string())
}

/// Read a small system file under `system_root` (`None` if unreadable).
pub(crate) fn read_system_file(ctx: &Ctx, absolute: &str) -> Option<String> {
    let bytes = crate::sys::fs::read_bounded(&ctx.paths.system(absolute), SYSTEM_FILE_MAX).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests;
