//! Making sure scheduled jobs will actually run: the `crontab` program and
//! a running cron daemon.
//!
//! Changes from v2: one check for node and FRP (v2's two disagreed on unit
//! names, and FRP's lacked `cronie`/`dcron`, H-8.1#17); the no-init check
//! reads `/proc/*/comm` below `system_root` instead of running `pgrep`.

use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::host::init::InitSystem;
use crate::sys::exec::Cmd;
use std::fs;
use std::time::Duration;

pub const NOT_RUNNING: &str = "cron 未运行，无法启用证书自动续期；请启动系统 cron 服务";

/// Service names of cron daemons across distributions.
const SYSTEMD_UNITS: [&str; 3] = ["cron", "crond", "cronie"];
const OPENRC_SCRIPTS: [&str; 4] = ["crond", "cronie", "dcron", "cron"];
/// Process names (`/proc/*/comm`) of cron daemons.
const DAEMON_NAMES: [&str; 4] = ["cron", "crond", "cronie", "dcron"];
const TIMEOUT: Duration = Duration::from_secs(60);

/// Install `crontab` when missing (through `ensure_package(ctx, command,
/// package)`, i.e. `host::pkg`, which maps `cron` per distribution) and
/// make sure a cron daemon runs, starting and enabling it when the init
/// system can.
pub fn ensure_available(
    ctx: &Ctx,
    init: InitSystem,
    ensure_package: &dyn Fn(&Ctx, &str, &str) -> Result<()>,
) -> Result<()> {
    if !super::available(ctx) {
        ensure_package(ctx, "crontab", "cron")?;
    }
    scheduler_running(ctx, init)
}

/// v2 `scheduler_ready`: systemd — a cron unit is active, else one can be
/// `enable --now`ed; OpenRC — the first cron script that starts is added to
/// the default runlevel; no init — a cron process exists.
pub fn scheduler_running(ctx: &Ctx, init: InitSystem) -> Result<()> {
    let ready = match init {
        InitSystem::Systemd => systemd_cron(ctx),
        InitSystem::Openrc => openrc_cron(ctx)?,
        InitSystem::None => cron_process(ctx),
    };
    if ready {
        Ok(())
    } else {
        Err(Error::msg(NOT_RUNNING))
    }
}

fn succeeds(ctx: &Ctx, program: &str, args: &[&str]) -> bool {
    let cmd = Cmd::new(program)
        .args(args.iter().copied())
        .timeout(TIMEOUT);
    ctx.run(&cmd).is_ok_and(|out| out.ok())
}

fn systemd_cron(ctx: &Ctx) -> bool {
    SYSTEMD_UNITS
        .into_iter()
        .any(|unit| succeeds(ctx, "systemctl", &["is-active", "--quiet", unit]))
        || SYSTEMD_UNITS
            .into_iter()
            .any(|unit| succeeds(ctx, "systemctl", &["enable", "--now", unit]))
}

fn openrc_cron(ctx: &Ctx) -> Result<bool> {
    let Some(script) = OPENRC_SCRIPTS
        .into_iter()
        .find(|script| succeeds(ctx, "rc-service", &[*script, "start"]))
    else {
        return Ok(false);
    };
    let enable = Cmd::new("rc-update")
        .args(["add", script, "default"])
        .timeout(TIMEOUT);
    ctx.check(&enable)?;
    Ok(true)
}

/// A cron daemon among the processes under `system_root/proc`.
fn cron_process(ctx: &Ctx) -> bool {
    let Ok(entries) = fs::read_dir(ctx.paths.system("/proc")) else {
        return false;
    };
    entries.flatten().any(|entry| {
        fs::read_to_string(entry.path().join("comm"))
            .is_ok_and(|comm| DAEMON_NAMES.contains(&comm.trim()))
    })
}
