//! The curl transport: one HTTPS transfer into a temp file next to the
//! destination, checked, then renamed into place (module docs of
//! `host::fetch` for the rules).
//!
//! curl is installed on demand (G14): every download and API call goes
//! through [`transfer`], which makes sure `curl` exists first — installing
//! the `curl` package as root, or asking for it otherwise.

use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::host::pkg;
use crate::sys::exec::{Cmd, Output};
use crate::sys::fs::{self, TEMP_PREFIX};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Throughput floor used to derive `--max-time` from the size cap.
const MIN_RATE: u64 = 32 * 1024;
/// curl aborts a transfer slower than this many bytes/s for `STALL_SECS`.
const STALL_RATE: u64 = 1024;
const STALL_SECS: u64 = 60;
const MIN_MAX_TIME: u64 = 120;
const MAX_MAX_TIME: u64 = 2 * 60 * 60;
const RETRIES: u64 = 2;
/// Slack for connecting, redirects and curl's own start-up per attempt.
const ATTEMPT_SLACK_SECS: u64 = 60;

/// How a transfer reports progress and bounds its duration.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Pace {
    /// Quiet (`-sS`, output captured) with a total `--max-time` derived
    /// from the size cap ([`max_time`]).
    #[default]
    Bounded,
    /// curl's progress bar on the terminal (output streamed) and no total
    /// time limit: only the low-speed abort (1 KiB/s over 60 s) ends a slow
    /// transfer. For large interactive downloads on slow links (BBR kernel
    /// packages, I-8.1#8/#9).
    Progress,
}

/// Inspects the downloaded temp file before it is renamed into place.
pub(super) type Check<'a> = &'a dyn Fn(&Path) -> Result<()>;

/// One curl transfer into `dest`.
pub(super) struct Transfer<'a> {
    /// What the user asked for (used in messages).
    pub url: &'a str,
    /// What curl fetches (`url`, possibly behind `GH_PROXY`).
    pub target: String,
    pub dest: &'a Path,
    pub max_bytes: u64,
    pub headers: &'a [&'a str],
    /// curl config read from stdin (secret headers).
    pub config: Option<String>,
    pub check: Option<Check<'a>>,
    pub pace: Pace,
}

/// `--max-time` for a [`Pace::Bounded`] transfer of at most `max_bytes`.
pub fn max_time(max_bytes: u64) -> Duration {
    let secs = 60 + max_bytes / MIN_RATE;
    Duration::from_secs(secs.clamp(MIN_MAX_TIME, MAX_MAX_TIME))
}

/// Hard bound for the curl process: every attempt may use its full
/// budget. For [`Pace::Progress`] the budget is what the low-speed limit
/// allows (curl itself always gives up first).
fn hard_timeout(pace: Pace, max_bytes: u64) -> Duration {
    let attempts = RETRIES as u32 + 1;
    let slack = Duration::from_secs(30);
    match pace {
        Pace::Bounded => max_time(max_bytes) * attempts + slack,
        Pace::Progress => {
            let slowest = (max_bytes / STALL_RATE)
                .saturating_add(STALL_SECS)
                .saturating_add(ATTEMPT_SLACK_SECS);
            Duration::from_secs(slowest.saturating_mul(attempts.into())) + slack
        }
    }
}

pub(super) fn curl_cmd(t: &Transfer, output: &Path) -> Cmd {
    let mut cmd =
        Cmd::new("curl").args(["--proto", "=https", "--proto-redir", "=https", "--tlsv1.2"]);
    cmd = match t.pace {
        Pace::Bounded => cmd.arg("-fLsS"),
        Pace::Progress => cmd.args(["-fL", "--progress-bar"]),
    };
    cmd = cmd.args(["--connect-timeout", "15"]);
    if t.pace == Pace::Bounded {
        let limit = max_time(t.max_bytes).as_secs().to_string();
        cmd = cmd.args(["--max-time".to_string(), limit]);
    }
    cmd = cmd
        .args(["--speed-limit".to_string(), STALL_RATE.to_string()])
        .args(["--speed-time".to_string(), STALL_SECS.to_string()])
        .args(["--retry".to_string(), RETRIES.to_string()])
        .args(["--max-filesize".to_string(), t.max_bytes.to_string()]);
    for header in t.headers {
        cmd = cmd.args(["-H", header]);
    }
    if let Some(config) = &t.config {
        cmd = cmd.args(["--config", "-"]).stdin_bytes(config.as_bytes());
    }
    cmd = cmd
        .arg("--output")
        .arg(output.to_string_lossy())
        .arg(&t.target)
        .timeout(hard_timeout(t.pace, t.max_bytes));
    match t.pace {
        Pace::Bounded => cmd,
        Pace::Progress => cmd.stream(),
    }
}

/// Run one transfer: preconditions, curl into a temp file, checks, rename.
pub(super) fn transfer(ctx: &Ctx, t: &Transfer) -> Result<u64> {
    super::check_https(t.url)?;
    ensure!(t.max_bytes > 0, "下载大小上限无效");
    ensure_curl_as(ctx, crate::host::os::is_root())?;
    let parent = t
        .dest
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| Error::msg("下载目标缺少目录"))?;
    if !parent.exists() {
        fs::ensure_dir(parent, 0o700)?;
    }
    let tmp = temp_path(parent)?;
    let result = run_curl(ctx, t, &tmp).and_then(|()| finish(&tmp, t));
    if result.is_err() {
        let _ = fs::remove_file_if_exists(&tmp);
    }
    result
}

/// Make sure `curl` is on PATH: root installs the `curl` package (there
/// is no wget fallback, E-8.1#7); anyone else is asked to install it.
pub fn ensure_curl_as(ctx: &Ctx, root: bool) -> Result<()> {
    if ctx.has("curl") {
        return Ok(());
    }
    ensure!(root, "请先安装 curl");
    pkg::ensure_as(ctx, "curl", "curl", true)
}

fn temp_path(dir: &Path) -> Result<PathBuf> {
    Ok(dir.join(format!(
        "{TEMP_PREFIX}download-{}",
        crate::sys::rand::hex(12)?
    )))
}

fn run_curl(ctx: &Ctx, t: &Transfer, output: &Path) -> Result<()> {
    let out = ctx.run(&curl_cmd(t, output))?;
    if out.ok() {
        Ok(())
    } else {
        Err(curl_error(t, &out))
    }
}

/// A Chinese message for a failed curl run (exit codes from curl(1)).
fn curl_error(t: &Transfer, out: &Output) -> Error {
    let via = if t.target != t.url {
        "（经 GH_PROXY）"
    } else {
        ""
    };
    let detail = last_line(&out.stderr);
    let message = match out.code {
        63 => format!(
            "下载内容超过大小上限（{} 字节）: {}{via}",
            t.max_bytes, t.url
        ),
        28 => format!("下载超时: {}{via}", t.url),
        crate::sys::exec::TIMEOUT_EXIT => format!("下载超时（已终止 curl）: {}{via}", t.url),
        _ if detail.is_empty() => format!("下载失败 (curl {}): {}{via}", out.code, t.url),
        _ => format!("下载失败: {}{via}: {detail}", t.url),
    };
    Error::msg(message)
}

fn last_line(text: &str) -> String {
    let line = text
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("");
    line.chars()
        .filter(|c| !c.is_control())
        .take(300)
        .collect::<String>()
        .trim()
        .to_string()
}

/// Size checks, then rename the temp file into place.
fn finish(tmp: &Path, t: &Transfer) -> Result<u64> {
    let size = match std::fs::symlink_metadata(tmp) {
        Ok(m) if m.is_file() => m.len(),
        Ok(_) => return Err(Error::msg("下载结果不是普通文件")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(e) => return Err(Error::io(tmp, e)),
    };
    ensure!(size > 0, "下载内容为空: {}", t.url);
    ensure!(
        size <= t.max_bytes,
        "下载内容超过大小上限（{} 字节）: {}",
        t.max_bytes,
        t.url
    );
    if let Some(check) = t.check {
        check(tmp)?;
    }
    // Durable before it becomes visible under the final name.
    std::fs::File::open(tmp)
        .and_then(|f| f.sync_all())
        .map_err(|e| Error::io(tmp, e))?;
    std::fs::rename(tmp, t.dest).map_err(|e| Error::io(t.dest, e))?;
    if let Some(parent) = t.dest.parent() {
        fs::fsync_dir(parent).map_err(|e| Error::io(parent, e))?;
    }
    Ok(size)
}

#[cfg(test)]
mod tests;
