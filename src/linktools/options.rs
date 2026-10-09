//! Typed options of `bench`, `failover` and `reality-check`: the v2 flag
//! names, ranges and defaults (spec D §2.3), read from parsed [`Matches`].
//! Menus build the same structs directly.
//!
//! Changes from v2 (flag applicability itself is enforced by each command's
//! option schema in `cli`):
//! - numbers must be decimal digits and the range error names the flag
//!   (`--timeout 必须是 1..60 之间的整数`; v2 accepted `+5` and said only
//!   `参数必须在 1..60 之间`, D-8.1#13);
//! - an invalid `--scope` value says so (v2: `未知或不适用的参数: --scope`,
//!   D-8.1#14), and `--scope current-machine-to-server` without a bundle is
//!   rejected instead of being silently replaced by `server-local`
//!   (D-8.1#15); the rule lives in [`RealityOptions::scope`], which
//!   `reality::run` applies too, so options a menu builds directly cannot
//!   label a loopback check `current-machine-to-server`;
//! - `--output` must not exist AND its directory must exist, so the save
//!   after a long run cannot fail on a typo (D-8.1#7);
//! - `--ca` must name an existing regular file (v2 passed anything to curl
//!   and openssl, which then failed every request).

use super::bundle::split_ids;
use super::core_client::CoreBinaries;
use super::url::TestUrl;
use crate::cli::args::Matches;
use crate::error::Result;
use std::fs;
use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};

pub const ENTRIES: &str = "entries";
pub const SINGBOX: &str = "singbox";
pub const XRAY: &str = "xray";
pub const URL: &str = "url";
pub const TIMEOUT: &str = "timeout";
pub const CA: &str = "ca";
pub const OUTPUT: &str = "output";
pub const SAMPLES: &str = "samples";
pub const DOWNLOAD_URL: &str = "download-url";
pub const UPLOAD_URL: &str = "upload-url";
pub const BYTES: &str = "bytes";
pub const PORT: &str = "port";
pub const INTERVAL: &str = "interval";
pub const FAILURES: &str = "failures";
pub const RECOVERIES: &str = "recoveries";
pub const COOLDOWN: &str = "cooldown";
pub const SCOPE: &str = "scope";

pub const TIMEOUT_RANGE: RangeInclusive<u64> = 1..=60;
pub const SAMPLES_RANGE: RangeInclusive<u64> = 1..=20;
pub const BYTES_RANGE: RangeInclusive<u64> = 1024..=67_108_864;
pub const PORT_RANGE: RangeInclusive<u64> = 1024..=65535;
pub const INTERVAL_RANGE: RangeInclusive<u64> = 1..=3600;
pub const STREAK_RANGE: RangeInclusive<u64> = 1..=20;
pub const COOLDOWN_RANGE: RangeInclusive<u64> = 0..=3600;

/// Options every tool takes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Common {
    /// The probe bundle; `None` only for the server-local REALITY check.
    pub bundle: Option<PathBuf>,
    /// `--entries`, split on `,` (trimmed when selecting).
    pub entries: Option<Vec<String>>,
    pub binaries: CoreBinaries,
    /// Health URL; must answer 2xx.
    pub url: TestUrl,
    /// Seconds: curl connect/total timeout, openssl timeout, upstream
    /// SOCKS connect timeout of failover.
    pub timeout: u64,
    pub ca: Option<PathBuf>,
}

impl Default for Common {
    fn default() -> Common {
        Common {
            bundle: None,
            entries: None,
            binaries: CoreBinaries::default(),
            url: TestUrl::default_health(),
            timeout: 8,
            ca: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BenchOptions {
    pub common: Common,
    pub output: Option<PathBuf>,
    pub samples: usize,
    pub download: Option<TestUrl>,
    pub upload: Option<TestUrl>,
    pub bytes: u64,
}

impl Default for BenchOptions {
    fn default() -> BenchOptions {
        BenchOptions {
            common: Common::default(),
            output: None,
            samples: 5,
            download: None,
            upload: None,
            bytes: 4_194_304,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FailoverOptions {
    pub common: Common,
    /// Local SOCKS5 port (127.0.0.1 only).
    pub port: u16,
    /// Seconds between the end of one health round and the next.
    pub interval: u64,
    pub failures: u32,
    pub recoveries: u32,
    /// Seconds since the last switch before switching back.
    pub cooldown: u64,
}

impl Default for FailoverOptions {
    fn default() -> FailoverOptions {
        FailoverOptions {
            common: Common::default(),
            port: 2080,
            interval: 15,
            failures: 3,
            recoveries: 3,
            cooldown: 60,
        }
    }
}

/// The `scope` string of a REALITY report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    ServerLocal,
    CurrentMachineToServer,
}

impl Scope {
    pub fn id(self) -> &'static str {
        match self {
            Scope::ServerLocal => "server-local",
            Scope::CurrentMachineToServer => "current-machine-to-server",
        }
    }

    pub fn parse(value: &str) -> Result<Scope> {
        match value {
            "server-local" => Ok(Scope::ServerLocal),
            "current-machine-to-server" => Ok(Scope::CurrentMachineToServer),
            _ => bail!("--scope 只能是 server-local 或 current-machine-to-server"),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RealityOptions {
    pub common: Common,
    pub output: Option<PathBuf>,
    /// `--scope`; `None` derives it from the input (see
    /// [`RealityOptions::scope`]).
    pub scope: Option<Scope>,
}

impl RealityOptions {
    /// The report scope. With a bundle: the explicit choice, else
    /// `current-machine-to-server`. Without one the installed node is
    /// checked over loopback, so only `server-local` is possible and an
    /// explicit `current-machine-to-server` is an error.
    pub fn scope(&self) -> Result<Scope> {
        match (&self.common.bundle, self.scope) {
            (Some(_), scope) => Ok(scope.unwrap_or(Scope::CurrentMachineToServer)),
            (None, None | Some(Scope::ServerLocal)) => Ok(Scope::ServerLocal),
            (None, Some(Scope::CurrentMachineToServer)) => {
                bail!("省略探测配置时只能执行本机回环检查（--scope server-local）")
            }
        }
    }
}

/// A decimal integer option in `range` (digits only).
pub fn number(m: &Matches, flag: &str, range: RangeInclusive<u64>, default: u64) -> Result<u64> {
    let Some(text) = m.value(flag) else {
        return Ok(default);
    };
    let parsed = (!text.is_empty() && text.len() <= 20 && text.bytes().all(|b| b.is_ascii_digit()))
        .then(|| text.parse::<u64>().ok())
        .flatten()
        .filter(|v| range.contains(v));
    parsed.ok_or_else(|| {
        crate::error::Error::msg(format!(
            "--{flag} 必须是 {}..{} 之间的整数",
            range.start(),
            range.end()
        ))
    })
}

fn url(m: &Matches, flag: &str) -> Result<Option<TestUrl>> {
    m.value(flag).map(TestUrl::parse).transpose()
}

impl Common {
    pub fn from_matches(m: &Matches) -> Result<Common> {
        let ca = m.value(CA).map(PathBuf::from);
        if let Some(path) = &ca {
            ensure!(
                fs::metadata(path).is_ok_and(|meta| meta.is_file()),
                "--ca 文件不存在或不是普通文件: {}",
                path.display()
            );
        }
        Ok(Common {
            bundle: m.positional(0).map(PathBuf::from),
            entries: m.value(ENTRIES).map(split_ids),
            binaries: CoreBinaries {
                singbox: m.value(SINGBOX).map(PathBuf::from),
                xray: m.value(XRAY).map(PathBuf::from),
            },
            url: url(m, URL)?.unwrap_or_else(TestUrl::default_health),
            timeout: number(m, TIMEOUT, TIMEOUT_RANGE, 8)?,
            ca,
        })
    }
}

/// `--output`: a new file in an existing directory.
pub fn output(m: &Matches) -> Result<Option<PathBuf>> {
    let Some(path) = m.value(OUTPUT).map(PathBuf::from) else {
        return Ok(None);
    };
    check_output(&path)?;
    Ok(Some(path))
}

/// The report target must be new (a dangling symlink counts as existing)
/// and its directory must exist.
pub fn check_output(path: &Path) -> Result<()> {
    ensure!(
        fs::symlink_metadata(path).is_err(),
        "输出文件已存在；请选择新文件路径"
    );
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    ensure!(dir.is_dir(), "输出文件所在目录不存在: {}", dir.display());
    Ok(())
}

impl BenchOptions {
    pub fn from_matches(m: &Matches) -> Result<BenchOptions> {
        Ok(BenchOptions {
            common: Common::from_matches(m)?,
            output: output(m)?,
            samples: number(m, SAMPLES, SAMPLES_RANGE, 5)? as usize,
            download: url(m, DOWNLOAD_URL)?,
            upload: url(m, UPLOAD_URL)?,
            bytes: number(m, BYTES, BYTES_RANGE, 4_194_304)?,
        })
    }
}

impl FailoverOptions {
    pub fn from_matches(m: &Matches) -> Result<FailoverOptions> {
        Ok(FailoverOptions {
            common: Common::from_matches(m)?,
            port: number(m, PORT, PORT_RANGE, 2080)? as u16,
            interval: number(m, INTERVAL, INTERVAL_RANGE, 15)?,
            failures: number(m, FAILURES, STREAK_RANGE, 3)? as u32,
            recoveries: number(m, RECOVERIES, STREAK_RANGE, 3)? as u32,
            cooldown: number(m, COOLDOWN, COOLDOWN_RANGE, 60)?,
        })
    }
}

impl RealityOptions {
    pub fn from_matches(m: &Matches) -> Result<RealityOptions> {
        let common = Common::from_matches(m)?;
        let scope = m.value(SCOPE).map(Scope::parse).transpose()?;
        let opts = RealityOptions {
            common,
            output: None,
            scope,
        };
        opts.scope()?;
        Ok(RealityOptions {
            output: output(m)?,
            ..opts
        })
    }
}

#[cfg(test)]
mod tests;
