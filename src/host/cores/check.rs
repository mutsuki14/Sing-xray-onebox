//! Config checks with a core binary: `sing-box check -D DIR -c FILE` /
//! `xray run -test -c FILE`, with the core's own message on failure.
//!
//! sing-box needs a working directory (`-D`): the apply engine uses the
//! private `{run}/check`, while read-only callers such as `doctor` pass a
//! directory of their own ([`check_config_in`]) so a health check never
//! creates files under the run root (D-8.1#30). Xray needs none.
//!
//! Changes from v2: failures carry the meaningful tail of the core's output
//! (ANSI colors, info logs and Xray's banner removed); a check is bounded
//! by a 60 s timeout; `doctor` no longer creates `{run}/check`.

use crate::ctx::Ctx;
use crate::domain::protocol::Core;
use crate::error::{Error, Result};
use crate::sys::exec::Cmd;
use crate::sys::fs as sysfs;
use std::path::{Path, PathBuf};
use std::time::Duration;

const CHECK_TIMEOUT: Duration = Duration::from_secs(60);

/// Validate `config` with the installed core binary (work dir `{run}/check`).
pub fn check_config(ctx: &Ctx, core: Core, config: &Path) -> Result<()> {
    check_config_with(ctx, core, &ctx.paths.core_bin(core), config)
}

/// Validate `config` with `binary` (e.g. a staged update candidate), work
/// dir `{run}/check` (created 0700; the run root 0755 when missing).
pub fn check_config_with(ctx: &Ctx, core: Core, binary: &Path, config: &Path) -> Result<()> {
    let workdir = match core {
        Core::Singbox => Some(run_check_dir(ctx)?),
        Core::Xray => None,
    };
    run_check(ctx, core, binary, config, workdir.as_deref())
}

/// Validate `config` with the installed core binary, using the existing
/// directory `workdir` as sing-box's working directory; nothing is created
/// under the run root (doctor passes a private `TempDir`).
pub fn check_config_in(ctx: &Ctx, core: Core, config: &Path, workdir: &Path) -> Result<()> {
    ensure!(workdir.is_dir(), "校验工作目录无效: {}", workdir.display());
    run_check(ctx, core, &ctx.paths.core_bin(core), config, Some(workdir))
}

/// `{run}/check`, created on demand.
fn run_check_dir(ctx: &Ctx) -> Result<PathBuf> {
    // The run root stays traversable (0755, as v2 created it) for other
    // users of it such as nginx workers; only `check` is private.
    if !ctx.paths.run.exists() {
        sysfs::ensure_dir(&ctx.paths.run, 0o755)?;
    }
    let dir = ctx.paths.run.join("check");
    sysfs::ensure_dir(&dir, 0o700)?;
    Ok(dir)
}

fn check_cmd(core: Core, binary: &Path, config: &Path, workdir: Option<&Path>) -> Cmd {
    let program = binary.to_string_lossy();
    let config = config.to_string_lossy().into_owned();
    let cmd = match (core, workdir) {
        (Core::Singbox, Some(dir)) => {
            Cmd::new(program).args(["check", "-D", &dir.to_string_lossy(), "-c", &config])
        }
        (Core::Singbox, None) => Cmd::new(program).args(["check", "-c", &config]),
        (Core::Xray, _) => Cmd::new(program).args(["run", "-test", "-c", &config]),
    };
    cmd.timeout(CHECK_TIMEOUT)
}

fn run_check(
    ctx: &Ctx,
    core: Core,
    binary: &Path,
    config: &Path,
    workdir: Option<&Path>,
) -> Result<()> {
    let result = ctx.run(&check_cmd(core, binary, config, workdir))?;
    if result.ok() {
        return Ok(());
    }
    let text = if result.stderr.trim().is_empty() {
        &result.stdout
    } else {
        &result.stderr
    };
    let detail = check_summary(core, text);
    let detail = if detail.is_empty() {
        format!("退出码 {}", result.code)
    } else {
        detail
    };
    Err(Error::msg(format!(
        "{} 配置校验失败: {detail}",
        core.title()
    )))
}

/// The meaningful tail of a core's check output: ANSI sequences, info
/// logs and Xray's banner removed, at most 8 lines / 2000 characters.
pub fn check_summary(core: Core, text: &str) -> String {
    let lines: Vec<String> = text
        .lines()
        .map(strip_ansi)
        .map(|l| l.trim().to_owned())
        .filter(|l| !l.is_empty() && !l.contains("[Info]") && !l.contains("[Debug]"))
        .filter(|l| {
            core != Core::Xray || !(l.starts_with("Xray ") || l.starts_with("A unified platform"))
        })
        .collect();
    let tail = &lines[lines.len().saturating_sub(8)..];
    tail.join("\n").chars().take(2000).collect()
}

fn strip_ansi(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // CSI: ESC [ params final-byte(@..~).
            if chars.next() == Some('[') {
                for x in chars.by_ref() {
                    if ('@'..='~').contains(&x) {
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

#[cfg(test)]
mod tests;
