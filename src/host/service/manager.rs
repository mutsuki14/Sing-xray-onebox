//! [`Services`]: one interface over systemd, OpenRC and the built-in
//! supervisor (no init), spec E §4.5.

use super::logs;
use super::{
    render_openrc, render_systemd, script_file, service_env, unit_file, validate_name, ServiceDef,
    ServiceSpec, SPEC_MAX_BYTES,
};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::host::cron::{self, Crontab, Tag};
use crate::host::init::{self, InitSystem};
use crate::host::supervisor::Supervisor;
use crate::sys::exec::{Cmd, Output};
use crate::sys::fs::{atomic_write, check_owned, read_bounded, remove_file_if_exists};
use crate::ui::out;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

/// Queries (`is-active`, `is-enabled`, `status`, journal reads).
const QUERY_TIMEOUT: Duration = Duration::from_secs(30);
/// Actions; a oneshot start runs the whole network restore.
const ACTION_TIMEOUT: Duration = Duration::from_secs(300);
/// `systemctl stop` of a unit systemd never loaded.
const SYSTEMD_NOT_LOADED: i32 = 5;
const NO_AUTOSTART: &str =
    "未找到 init 或 crontab；服务不会开机自启，重启后请执行 onebox net-apply && onebox start";
const NO_LOG: &str = "服务日志尚不存在";

/// Service operations for one init system.
pub struct Services<'a> {
    ctx: &'a Ctx,
    init: InitSystem,
    supervisor: Supervisor<'a>,
}

impl<'a> Services<'a> {
    pub fn new(ctx: &'a Ctx, init: InitSystem) -> Self {
        Self::with_supervisor(ctx, init, Supervisor::new(ctx))
    }

    /// Services of the detected init system.
    pub fn detect(ctx: &'a Ctx) -> Self {
        Self::new(ctx, init::detect(ctx))
    }

    /// With a custom supervisor (tests: fake signals, short timeouts).
    pub fn with_supervisor(ctx: &'a Ctx, init: InitSystem, supervisor: Supervisor<'a>) -> Self {
        Services {
            ctx,
            init,
            supervisor,
        }
    }

    pub fn init(&self) -> InitSystem {
        self.init
    }

    /// The environment persisted for services of this init system.
    pub fn env(&self) -> Vec<(String, String)> {
        service_env(&self.ctx.paths, self.init)
    }

    /// Write the unit/script and spec of `def`, then reload systemd once.
    pub fn write(&self, def: &ServiceDef) -> Result<()> {
        self.write_all(std::slice::from_ref(def))
    }

    /// [`write`](Services::write) for several services with one reload.
    pub fn write_all(&self, defs: &[ServiceDef]) -> Result<()> {
        let env = self.env();
        for def in defs {
            self.write_files(def, &env)?;
        }
        if !defs.is_empty() {
            self.daemon_reload()?;
        }
        Ok(())
    }

    fn write_files(&self, def: &ServiceDef, env: &[(String, String)]) -> Result<()> {
        def.validate()?;
        let spec = def.spec(env);
        spec.validate()?;
        let spec_path = def.spec_path();
        check_spec_path(&spec_path)?;
        let paths = &self.ctx.paths;
        match self.init {
            InitSystem::Systemd => {
                let unit = render_systemd(def, env)?;
                atomic_write(&unit_file(paths, &def.name), unit.as_bytes(), 0o644)?;
            }
            InitSystem::Openrc => {
                let script = render_openrc(def, env)?;
                super::prepare_dir(&def.log_dir)?;
                atomic_write(&script_file(paths, &def.name), script.as_bytes(), 0o755)?;
            }
            InitSystem::None => {}
        }
        atomic_write(&spec_path, &serde_json::to_vec_pretty(&spec)?, 0o600)
    }

    /// The definition and environment persisted for `name`.
    pub fn load(&self, name: &str) -> Result<(ServiceDef, Vec<(String, String)>)> {
        validate_name(name)?;
        let skeleton = ServiceDef::skeleton(&self.ctx.paths, name);
        let path = skeleton.spec_path();
        check_spec_path(&path)?;
        let bytes = read_bounded(&path, SPEC_MAX_BYTES).map_err(|e| match e {
            Error::Io { ref source, .. } if source.kind() == std::io::ErrorKind::NotFound => {
                Error::msg(format!("服务尚未配置: {name}"))
            }
            other => other,
        })?;
        let spec: ServiceSpec = serde_json::from_slice(&bytes)?;
        let def = ServiceDef::from_spec(&self.ctx.paths, name, &spec)?;
        let env = if spec.environment.is_empty() {
            self.env()
        } else {
            spec.environment
        };
        Ok((def, env))
    }

    /// A spec that loads, a unit file or an OpenRC script exists.
    pub fn exists(&self, name: &str) -> bool {
        if validate_name(name).is_err() {
            return false;
        }
        let paths = &self.ctx.paths;
        self.load(name).is_ok()
            || is_file(&unit_file(paths, name))
            || is_file(&script_file(paths, name))
    }

    pub fn running(&self, name: &str) -> bool {
        if validate_name(name).is_err() {
            return false;
        }
        match self.init {
            InitSystem::Systemd => self.query_ok("systemctl", &["is-active", "--quiet", name]),
            InitSystem::Openrc => {
                self.query_ok("rc-service", &[name, "status"]) && self.openrc_child_alive(name)
            }
            InitSystem::None => self
                .load(name)
                .is_ok_and(|(def, _)| self.supervisor.running(&def)),
        }
    }

    /// OpenRC may report a supervised service as started while its child is
    /// gone; trust a recorded child PID only while that process exists.
    fn openrc_child_alive(&self, name: &str) -> bool {
        let file = self
            .ctx
            .paths
            .system("/run/openrc/options")
            .join(name)
            .join("child_pid");
        match fs::read_to_string(file) {
            Ok(text) => text.trim().parse::<u32>().is_ok_and(|pid| {
                pid > 1
                    && crate::host::supervisor::identity::process_start(
                        &self.ctx.paths.system_root,
                        pid,
                    )
                    .is_some()
            }),
            Err(_) => true,
        }
    }

    /// Whether `name` starts at boot. systemd: `is-enabled` exit 0 (codes
    /// above 4 are errors); OpenRC: listed in the default runlevel; no
    /// init: its autostart crontab line exists.
    pub fn enabled(&self, name: &str) -> Result<bool> {
        if !self.exists(name) {
            return Ok(false);
        }
        match self.init {
            InitSystem::Systemd => {
                let out = self.query("systemctl", &["is-enabled", name])?;
                if out.code > 4 {
                    return Err(Error::msg(format!("无法读取 {name} 自启状态")));
                }
                Ok(out.ok())
            }
            InitSystem::Openrc => self.in_default_runlevel(name),
            InitSystem::None => {
                if !cron::available(self.ctx) {
                    return Ok(false);
                }
                Ok(Crontab::read(self.ctx)?.has(&Tag::boot(name)?))
            }
        }
    }

    pub fn start(&self, name: &str) -> Result<()> {
        validate_name(name)?;
        match self.init {
            InitSystem::Systemd => self.act("systemctl", &["start", name]),
            InitSystem::Openrc => self.act("rc-service", &[name, "start"]),
            InitSystem::None => {
                let (def, env) = self.load(name)?;
                self.supervisor.start(&def, &env)
            }
        }
    }

    /// Stop `name`; a service that is not installed is already stopped.
    pub fn stop(&self, name: &str) -> Result<()> {
        validate_name(name)?;
        match self.init {
            InitSystem::Systemd => {
                let out = self.run("systemctl", &["stop", name], ACTION_TIMEOUT)?;
                if out.ok() || out.code == SYSTEMD_NOT_LOADED {
                    Ok(())
                } else {
                    Err(command_error("systemctl", out))
                }
            }
            InitSystem::Openrc => {
                if !is_file(&script_file(&self.ctx.paths, name)) {
                    return Ok(());
                }
                self.act("rc-service", &[name, "stop"])
            }
            InitSystem::None => match self.load(name) {
                Ok((def, _)) => self.supervisor.stop(&def),
                Err(_) if !is_file(&self.spec_path(name)) => Ok(()),
                Err(e) => Err(e),
            },
        }
    }

    pub fn restart(&self, name: &str) -> Result<()> {
        validate_name(name)?;
        match self.init {
            InitSystem::Systemd => self.act("systemctl", &["restart", name]),
            InitSystem::Openrc => self.act("rc-service", &[name, "restart"]),
            InitSystem::None => {
                let (def, env) = self.load(name)?;
                self.supervisor.restart(&def, &env)
            }
        }
    }

    pub fn enable(&self, name: &str) -> Result<()> {
        validate_name(name)?;
        match self.init {
            InitSystem::Systemd => self.act("systemctl", &["enable", name]),
            InitSystem::Openrc => self.act("rc-update", &["add", name, "default"]),
            InitSystem::None => self.enable_boot_line(name),
        }
    }

    /// Disable autostart; a service that was never enabled (or whose unit
    /// file is gone) is left alone.
    pub fn disable(&self, name: &str) -> Result<()> {
        validate_name(name)?;
        match self.init {
            InitSystem::Systemd => {
                if !is_file(&unit_file(&self.ctx.paths, name)) {
                    return Ok(());
                }
                self.act("systemctl", &["disable", name])
            }
            InitSystem::Openrc => {
                if !self.in_default_runlevel(name)? {
                    return Ok(());
                }
                self.act("rc-update", &["del", name, "default"])
            }
            InitSystem::None => {
                if !cron::available(self.ctx) {
                    return Ok(());
                }
                let mut tab = Crontab::read(self.ctx)?;
                tab.remove(&Tag::boot(name)?);
                tab.save(self.ctx).map(|_| ())
            }
        }
    }

    /// Stop, disable and delete `name` (spec, unit, script). Missing
    /// services and units systemd never loaded are fine.
    pub fn remove(&self, name: &str) -> Result<()> {
        validate_name(name)?;
        if !self.exists(name) {
            return Ok(());
        }
        self.stop(name)?;
        self.disable(name)?;
        let paths = &self.ctx.paths;
        remove_file_if_exists(&self.spec_path(name))?;
        let unit_removed = remove_file_if_exists(&unit_file(paths, name))?;
        remove_file_if_exists(&script_file(paths, name))?;
        if unit_removed {
            self.daemon_reload()?;
        }
        Ok(())
    }

    /// Poll [`running`](Services::running) until `timeout`.
    pub fn wait_running(&self, name: &str, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            if self.running(name) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(Error::msg(format!("{name} 未能正常运行")));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// `{name}: 运行中` / `{name}: 已停止`.
    pub fn status_line(&self, name: &str) -> String {
        let state = if self.running(name) {
            "运行中"
        } else {
            "已停止"
        };
        format!("{name}: {state}")
    }

    /// The last `lines` log lines: the journal under systemd, else the
    /// first log file found (`{log_dir}/{name}.log`, then older places).
    pub fn logs(&self, name: &str, lines: usize) -> Result<String> {
        validate_name(name)?;
        if self.init == InitSystem::Systemd {
            let count = lines.to_string();
            let args = ["--no-pager", "-n", count.as_str(), "-u", name];
            let cmd = Cmd::new("journalctl").args(args).timeout(QUERY_TIMEOUT);
            return self.ctx.check(&cmd);
        }
        let def = ServiceDef::skeleton(&self.ctx.paths, name);
        let path = logs::find(&def.log_candidates()).ok_or_else(|| Error::msg(NO_LOG))?;
        logs::tail(&path, lines)
    }

    /// `systemctl daemon-reload` (systemd only).
    pub fn daemon_reload(&self) -> Result<()> {
        match self.init {
            InitSystem::Systemd => self.act("systemctl", &["daemon-reload"]),
            _ => Ok(()),
        }
    }

    /// Autostart without an init system: an `@reboot` line running
    /// `onebox service NAME start`, logging to `{log_dir}/boot.log`.
    fn enable_boot_line(&self, name: &str) -> Result<()> {
        let (def, _) = self.load(name)?;
        if !cron::available(self.ctx) {
            out::warn(NO_AUTOSTART);
            return Ok(());
        }
        super::prepare_dir(&def.log_dir)?;
        let tag = Tag::boot(name)?;
        let line = cron::line(
            "@reboot",
            &self.ctx.paths,
            self.init,
            &["service", name, "start"],
            &def.log_dir.join("boot.log"),
            &tag,
        )?;
        let mut tab = Crontab::read(self.ctx)?;
        tab.replace(&tag, &[line])?;
        tab.save(self.ctx).map(|_| ())
    }

    fn in_default_runlevel(&self, name: &str) -> Result<bool> {
        let cmd = Cmd::new("rc-update")
            .args(["show", "default"])
            .timeout(QUERY_TIMEOUT);
        let listing = self.ctx.check(&cmd)?;
        Ok(listing
            .lines()
            .any(|line| line.split_whitespace().next() == Some(name)))
    }

    fn spec_path(&self, name: &str) -> std::path::PathBuf {
        ServiceDef::skeleton(&self.ctx.paths, name).spec_path()
    }

    fn run(&self, program: &str, args: &[&str], timeout: Duration) -> Result<Output> {
        let cmd = Cmd::new(program)
            .args(args.iter().copied())
            .timeout(timeout);
        self.ctx.run(&cmd)
    }

    fn query(&self, program: &str, args: &[&str]) -> Result<Output> {
        self.run(program, args, QUERY_TIMEOUT)
    }

    fn query_ok(&self, program: &str, args: &[&str]) -> bool {
        self.query(program, args).is_ok_and(|out| out.ok())
    }

    /// Run a service-manager action; a non-zero exit is an error.
    fn act(&self, program: &str, args: &[&str]) -> Result<()> {
        let out = self.run(program, args, ACTION_TIMEOUT)?;
        if out.ok() {
            Ok(())
        } else {
            Err(command_error(program, out))
        }
    }
}

fn command_error(program: &str, out: Output) -> Error {
    let detail = if out.stderr.trim().is_empty() {
        out.stdout
    } else {
        out.stderr
    };
    Error::Command {
        program: program.to_owned(),
        code: out.code,
        detail,
    }
}

/// Specs live directly in an Onebox-owned directory (`ROOT/services`,
/// `FRP_ROOT/services`): no symlink below that root.
fn check_spec_path(path: &Path) -> Result<()> {
    let owned_root = path
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| Error::msg(format!("服务配置路径无效: {}", path.display())))?;
    check_owned(owned_root, path)
}

/// A regular file itself (a symlink does not count).
fn is_file(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_file())
}

#[cfg(test)]
mod tests;
