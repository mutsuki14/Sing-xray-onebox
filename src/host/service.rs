//! Service definitions as data, pure systemd/OpenRC renderers, and the
//! service manager for systemd, OpenRC and the built-in supervisor.
//!
//! Every Onebox service is a [`ServiceDef`]: program, arguments, ordering
//! and the traits v2 kept in scattered `match name` blocks — pre-start
//! command, runtime directories, restart-prevent status, FRP run/log/spec
//! directories, how the supervisor recognizes the process (nginx master
//! title included), legacy PID and log files, which configuration lock its
//! start takes. The traits of the known services live in one table
//! (`known.rs`) and nowhere else: a definition only comes from a
//! constructor or from its persisted spec (both go through the table), and
//! its fields are read-only, so a unit, an OpenRC script and the supervisor
//! always see the same service.
//!
//! The spec JSON (`{spec_dir}/{name}.json`, 0600) keeps the v2 shape
//! `{program, args, after, environment}`: v2 and v3 read each other's
//! files, and its environment is validated against the path allowlist so no
//! credential is ever persisted into a unit, script or cron line.
//!
//! Changes from v2:
//! - `After=`/`Wants=` (and OpenRC `depend()`) have no trailing space when a
//!   service has no dependencies;
//! - every daemon starts with the same open-files limit where the host
//!   allows it: systemd `LimitNOFILE=1048576` (systemd clamps it), the
//!   OpenRC `start_pre` raises the limit to 1048576 or, when the hard limit
//!   cannot be raised (unprivileged containers), to the hard limit (v2's
//!   `rc_ulimit='-n 65535'` differed from systemd, E-8.1#12; a fixed
//!   `rc_ulimit` above the hard limit would fail as a whole), and the
//!   supervisor does the same for the daemons it spawns (v2 set nothing);
//! - nginx services create their temp-path parent (`RUN/nginx-{scope}`)
//!   before every start (`/run` is tmpfs, F-8.1#2);
//! - no `reload` action: units define no `ExecReload` (E-8.1#11);
//! - removing a service tolerates units systemd never loaded and disabling
//!   a unit that does not exist is a no-op (E-8.1#10);
//! - service-manager commands run with timeouts;
//! - specs are no longer inferred for v1 installs without spec files (v1 is
//!   no longer supported), so a missing spec means "not configured".

mod known;
mod logs;
mod manager;
mod render;

pub use manager::{Services, WAIT_RUNNING};
pub use render::{render_openrc, render_systemd, NOFILE_LIMIT};

use crate::error::{Error, Result};
use crate::host::init::InitSystem;
use crate::paths::{Paths, SERVICE_ENV_KEYS};
use crate::sys::text::quote_unit;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub const SING_BOX: &str = "onebox-sing-box";
pub const XRAY: &str = "onebox-xray";
pub const SITE: &str = "onebox-site";
pub const NETWORK: &str = "onebox-network";
pub const SUBSCRIPTION: &str = "onebox-subscription";
pub const SUBSCRIPTION_WEB: &str = "onebox-subscription-web";
pub const FRPS: &str = "onebox-frps";
pub const FRP_WEB: &str = "onebox-frp-web";

/// The environment variable naming the init system a unit was written for.
pub use crate::host::init::ENV as INIT_ENV;
/// systemd targets a service may be ordered after.
pub const TARGETS: [&str; 2] = ["network-online.target", "nss-lookup.target"];
/// Largest spec JSON accepted (v2 specs are ~1.5 KiB).
const SPEC_MAX_BYTES: u64 = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceKind {
    /// A long-running process, restarted on failure.
    Daemon,
    /// A run-to-completion action at boot (systemd `Type=oneshot` with
    /// `RemainAfterExit`); the supervisor runs it synchronously.
    Oneshot,
}

/// The independent configuration a service or crontab line belongs to.
/// Each has its own lock and transaction: the proxy node and the FRP
/// server manager.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Scope {
    Node,
    Frp,
}

impl Scope {
    /// The scope's configuration lock (`ROOT/.apply.lock`,
    /// `/etc/.onebox-frp.lock`).
    pub fn lock_path(self, paths: &Paths) -> PathBuf {
        match self {
            Scope::Node => paths.lock(),
            Scope::Frp => paths.frp_lock(),
        }
    }
}

/// How the built-in supervisor recognizes the service's process, on top of
/// the PID record's start time and the executable path.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Identity {
    /// argv[1] must be this word (cores: `run`).
    pub subcommand: Option<String>,
    /// The configuration the process runs with: every `-c`/`--config`/
    /// `-config` (and `--config=`/`-config=`) must name it, at least once.
    /// `None`: argv[1..] must equal the definition's args exactly.
    pub config: Option<PathBuf>,
    /// nginx replaces its argv with one title (`nginx: master process …`);
    /// accept the title of an invocation of this definition.
    pub nginx_title: bool,
}

/// One service. Built by the constructors in `known.rs` (or
/// [`ServiceDef::from_spec`]); read through the accessors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceDef {
    name: String,
    description: String,
    program: PathBuf,
    args: Vec<String>,
    after: Vec<String>,
    after_firewall: bool,
    kind: ServiceKind,
    banner: Option<String>,
    pre_start: Option<Vec<String>>,
    runtime_dirs: Vec<PathBuf>,
    restart_prevent_status: Option<i32>,
    run_dir: PathBuf,
    log_dir: PathBuf,
    spec_dir: PathBuf,
    identity: Identity,
    legacy_pid_files: Vec<PathBuf>,
    log_files: Vec<PathBuf>,
    scope: Scope,
    takes_lock: Option<Scope>,
}

impl ServiceDef {
    pub fn name(&self) -> &str {
        &self.name
    }

    /// systemd `Description=`.
    pub fn description(&self) -> &str {
        &self.description
    }

    pub fn program(&self) -> &Path {
        &self.program
    }

    pub fn args(&self) -> &[String] {
        &self.args
    }

    /// Onebox services (`onebox-*`) or one of [`TARGETS`].
    pub fn after(&self) -> &[String] {
        &self.after
    }

    /// Also start after the host firewall services, which would otherwise
    /// flush rules restored at boot.
    pub fn after_firewall(&self) -> bool {
        self.after_firewall
    }

    pub fn kind(&self) -> ServiceKind {
        self.kind
    }

    /// OpenRC `ebegin` text while a oneshot runs (default: description).
    pub fn banner(&self) -> Option<&str> {
        self.banner.as_deref()
    }

    /// Command (argv) run before every start; its failure fails the start.
    pub fn pre_start(&self) -> Option<&[String]> {
        self.pre_start.as_deref()
    }

    /// Directories (0755) created before every start, before the pre-start
    /// command: runtime state under the tmpfs `/run`.
    pub fn runtime_dirs(&self) -> &[PathBuf] {
        &self.runtime_dirs
    }

    /// Exit status after which the daemon must not be restarted (Xray 23 =
    /// invalid configuration).
    pub fn restart_prevent_status(&self) -> Option<i32> {
        self.restart_prevent_status
    }

    /// Supervisor PID records and locks.
    pub fn run_dir(&self) -> &Path {
        &self.run_dir
    }

    /// `{name}.log` (supervisor and OpenRC output) and `boot.log`.
    pub fn log_dir(&self) -> &Path {
        &self.log_dir
    }

    /// Where `{name}.json` lives.
    pub fn spec_dir(&self) -> &Path {
        &self.spec_dir
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// PID files written by others (nginx `pid`, v1 FRP); read to find the
    /// process, removed on stop, never written.
    pub fn legacy_pid_files(&self) -> &[PathBuf] {
        &self.legacy_pid_files
    }

    /// Older log locations, consulted after `{log_dir}/{name}.log`.
    pub fn log_files(&self) -> &[PathBuf] {
        &self.log_files
    }

    /// The configuration this service belongs to: changes to it are
    /// serialized by that scope's lock.
    pub fn scope(&self) -> Scope {
        self.scope
    }

    /// The configuration lock the service's own start commands take
    /// (`onebox-network` runs `onebox net-apply`: node; `onebox-frps`
    /// runs `onebox frps net-apply`: FRP). A caller holding that lock must
    /// not start or restart the service through systemd/OpenRC (the helper
    /// would find the lock busy); see [`Services::start_with_lock`].
    pub fn takes_lock(&self) -> Option<Scope> {
        self.takes_lock
    }

    pub fn spec_path(&self) -> PathBuf {
        self.spec_dir.join(format!("{}.json", self.name))
    }

    /// The supervisor's own PID record.
    pub fn pid_file(&self) -> PathBuf {
        self.run_dir.join(format!("{}.pid", self.name))
    }

    /// Daemon output (supervisor and OpenRC).
    pub fn log_file(&self) -> PathBuf {
        self.log_dir.join(format!("{}.log", self.name))
    }

    /// Log candidates in lookup order.
    pub fn log_candidates(&self) -> Vec<PathBuf> {
        std::iter::once(self.log_file())
            .chain(self.log_files.iter().cloned())
            .collect()
    }

    /// The spec persisted for this definition with `env`.
    pub fn spec(&self, env: &[(String, String)]) -> ServiceSpec {
        ServiceSpec {
            program: path_string(&self.program),
            args: self.args.clone(),
            after: self.after.clone(),
            environment: env.to_vec(),
        }
    }

    /// Every invariant a unit, script or spec relies on: a valid name, an
    /// absolute program, no line breaks in any word, valid dependencies,
    /// absolute runtime directories.
    pub fn validate(&self) -> Result<()> {
        validate_name(&self.name)?;
        validate_command(&path_string(&self.program), &self.args)?;
        for dependency in &self.after {
            validate_dependency(dependency)?;
        }
        if let Some(pre) = &self.pre_start {
            let (program, args) = pre
                .split_first()
                .ok_or_else(|| Error::msg("服务预启动命令为空"))?;
            validate_command(program, args)?;
        }
        for dir in &self.runtime_dirs {
            let text = path_string(dir);
            if !dir.is_absolute() {
                return Err(Error::msg("服务运行目录必须是绝对路径"));
            }
            reject_breaks(&text)?;
        }
        for text in [&self.description, self.banner.as_deref().unwrap_or("")] {
            reject_breaks(text)?;
        }
        Ok(())
    }
}

/// The persisted service description (v2 shape).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceSpec {
    pub program: String,
    pub args: Vec<String>,
    pub after: Vec<String>,
    #[serde(default)]
    pub environment: Vec<(String, String)>,
}

impl ServiceSpec {
    /// v2 `validate_spec`: absolute program, no line breaks, known
    /// dependencies, and an environment of allowlisted, unique path
    /// variables only (never credentials such as `CF_Token`).
    pub fn validate(&self) -> Result<()> {
        if !Path::new(&self.program).is_absolute() {
            return Err(Error::msg("服务程序必须是绝对路径"));
        }
        validate_command(&self.program, &self.args)?;
        for dependency in &self.after {
            validate_dependency(dependency)?;
        }
        validate_env(&self.environment)
    }
}

/// The parent of an nginx service's temp paths (`client_body`, `proxy`,
/// `fastcgi`, `uwsgi`, `scgi`; nginx creates those leaves itself), v2's
/// `nginx_runtime(scope)` layout: `RUN/nginx-{scope}` with `scope` ∈
/// `site`, `subscription`, `frp`. The service creates it before every
/// start; renderers of nginx configs must use this path.
pub fn nginx_runtime_dir(paths: &Paths, scope: &str) -> PathBuf {
    paths.run.join(format!("nginx-{scope}"))
}

/// The word following `flag` in `args`.
pub(crate) fn arg_after<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    let index = args.iter().position(|a| a == flag)?;
    args.get(index + 1).map(String::as_str)
}

/// Paths are validated UTF-8 at startup (`Paths::from_env`).
fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Names: `onebox-` followed by `[A-Za-z0-9-]+`.
pub fn validate_name(name: &str) -> Result<()> {
    let ok = name.strip_prefix("onebox-").is_some_and(|rest| {
        !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    });
    if ok {
        Ok(())
    } else {
        Err(Error::msg("服务名无效"))
    }
}

fn validate_dependency(name: &str) -> Result<()> {
    if TARGETS.contains(&name) {
        Ok(())
    } else {
        validate_name(name)
    }
}

fn validate_command(program: &str, args: &[String]) -> Result<()> {
    if !Path::new(program).is_absolute() {
        return Err(Error::msg("服务程序必须是绝对路径"));
    }
    reject_breaks(program)?;
    args.iter().try_for_each(|a| reject_breaks(a))
}

/// NUL/CR/LF would let a value start a new unit directive or script line.
fn reject_breaks(text: &str) -> Result<()> {
    quote_unit(text).map(|_| ())
}

/// Whether `key` may be persisted into units, specs and cron lines.
pub fn env_key_allowed(key: &str) -> bool {
    SERVICE_ENV_KEYS.contains(&key) || key == INIT_ENV
}

/// The service environment: the allowlisted path variables (each at most
/// once) and `ONEBOX_INIT` ∈ {none, systemd, openrc}.
pub fn validate_env(env: &[(String, String)]) -> Result<()> {
    let mut seen = BTreeSet::new();
    for (key, value) in env {
        if !env_key_allowed(key) || !seen.insert(key.as_str()) {
            return Err(Error::msg("服务环境变量不在路径白名单或重复"));
        }
        reject_breaks(value)?;
        if key == INIT_ENV && InitSystem::parse(value).is_none() {
            return Err(Error::msg("服务 init 环境值无效"));
        }
    }
    Ok(())
}

/// The 14 variables persisted into units, specs and cron lines: the 13 path
/// roots in v2 order, then `ONEBOX_INIT`. Built from `Paths` only, never
/// from the caller's environment.
pub fn service_env(paths: &Paths, init: InitSystem) -> Vec<(String, String)> {
    let mut env = paths.service_env();
    env.push((INIT_ENV.to_owned(), init.id().to_owned()));
    env
}

/// systemd unit file of `name`.
pub fn unit_file(paths: &Paths, name: &str) -> PathBuf {
    paths.systemd.join(format!("{name}.service"))
}

/// OpenRC script of `name`.
pub fn script_file(paths: &Paths, name: &str) -> PathBuf {
    paths.initd.join(name)
}

/// Create a runtime/log directory and its missing ancestors (0755: nginx
/// workers traverse the run directory) unless it already exists; existing
/// modes are left alone. The directory itself must not be a symlink
/// (ancestors such as `/var/run` may be).
pub(crate) fn prepare_dir(path: &Path) -> Result<()> {
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir()) {
        return Ok(());
    }
    let mut missing = vec![path];
    missing.extend(
        path.ancestors()
            .skip(1)
            .take_while(|p| !p.as_os_str().is_empty() && !p.is_dir()),
    );
    for dir in missing.into_iter().rev() {
        crate::sys::fs::ensure_dir(dir, 0o755)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
