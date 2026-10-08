//! Service definitions as data, pure systemd/OpenRC renderers, and the
//! service manager for systemd, OpenRC and the built-in supervisor.
//!
//! Every Onebox service is a [`ServiceDef`]: program, arguments, ordering
//! and the traits v2 kept in scattered `match name` blocks — pre-start
//! command, restart-prevent status, FRP run/log/spec directories, how the
//! supervisor recognizes the process (nginx master title included), legacy
//! PID and log files. The traits of the known services live in one table
//! ([`ServiceDef::new`]) that serves both the constructors and definitions
//! reloaded from their spec JSON, so the supervisor and `onebox service …`
//! see exactly what the installer wrote.
//!
//! The spec JSON (`{spec_dir}/{name}.json`, 0600) keeps the v2 shape
//! `{program, args, after, environment}`: v2 and v3 read each other's
//! files, and its environment is validated against the path allowlist so no
//! credential is ever persisted into a unit, script or cron line.
//!
//! Changes from v2:
//! - `After=`/`Wants=` (and OpenRC `depend()`) have no trailing space when a
//!   service has no dependencies;
//! - one open-files limit for every init: `LimitNOFILE=1048576` and
//!   `rc_ulimit='-n 1048576'` (v2 OpenRC used 65535, E-8.1#12; a failing
//!   `ulimit` under OpenRC only warns, the daemon still starts);
//! - no `reload` action: units define no `ExecReload` (E-8.1#11);
//! - removing a service tolerates units systemd never loaded and disabling
//!   a unit that does not exist is a no-op (E-8.1#10);
//! - service-manager commands run with timeouts;
//! - specs are no longer inferred for v1 installs without spec files (v1 is
//!   no longer supported), so a missing spec means "not configured".

mod logs;
mod manager;
mod render;

pub use manager::{Services, WAIT_RUNNING};
pub use render::{render_openrc, render_systemd, NOFILE_LIMIT};

use crate::domain::protocol::Core;
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
pub const INIT_ENV: &str = "ONEBOX_INIT";
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceDef {
    pub name: String,
    /// systemd `Description=`.
    pub description: String,
    pub program: PathBuf,
    pub args: Vec<String>,
    /// Onebox services (`onebox-*`) or one of [`TARGETS`].
    pub after: Vec<String>,
    /// Also start after the host firewall services, which would otherwise
    /// flush rules restored at boot.
    pub after_firewall: bool,
    pub kind: ServiceKind,
    /// OpenRC `ebegin` text while a oneshot runs (default: description).
    pub banner: Option<String>,
    /// Command (argv) run before every start; its failure fails the start.
    pub pre_start: Option<Vec<String>>,
    /// Exit status after which the daemon must not be restarted (Xray 23 =
    /// invalid configuration).
    pub restart_prevent_status: Option<i32>,
    /// Supervisor PID records and locks.
    pub run_dir: PathBuf,
    /// `{name}.log` (supervisor and OpenRC output) and `boot.log`.
    pub log_dir: PathBuf,
    /// Where `{name}.json` lives.
    pub spec_dir: PathBuf,
    pub identity: Identity,
    /// PID files written by others (nginx `pid`, v1 FRP); read to find the
    /// process, removed on stop, never written.
    pub legacy_pid_files: Vec<PathBuf>,
    /// Older log locations, consulted after `{log_dir}/{name}.log`.
    pub log_files: Vec<PathBuf>,
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

impl ServiceDef {
    /// A definition of `name` with the traits Onebox associates with it
    /// (the single table of per-service knowledge).
    pub fn new(
        paths: &Paths,
        name: &str,
        program: impl Into<PathBuf>,
        args: Vec<String>,
        after: Vec<String>,
    ) -> ServiceDef {
        let mut def = ServiceDef {
            name: name.to_owned(),
            description: format!("Onebox {name}"),
            program: program.into(),
            args,
            after,
            after_firewall: false,
            kind: ServiceKind::Daemon,
            banner: None,
            pre_start: None,
            restart_prevent_status: None,
            run_dir: paths.run.clone(),
            log_dir: paths.log.clone(),
            spec_dir: paths.services(),
            identity: Identity::default(),
            legacy_pid_files: Vec::new(),
            log_files: Vec::new(),
        };
        apply_traits(&mut def, paths);
        def
    }

    /// The traits of `name` without a command: where its spec, PID, lock and
    /// log files are, for services that may not be configured (yet).
    pub fn skeleton(paths: &Paths, name: &str) -> ServiceDef {
        ServiceDef::new(paths, name, PathBuf::new(), Vec::new(), Vec::new())
    }

    /// `onebox-sing-box` / `onebox-xray`, after the website when it serves
    /// the REALITY target.
    pub fn core(paths: &Paths, core: Core, after_site: bool) -> ServiceDef {
        let config = path_string(&paths.core_config(core));
        let args = match core {
            Core::Singbox => vec!["run", "--disable-color", "-c", config.as_str()],
            Core::Xray => vec!["run", "-c", config.as_str()],
        };
        let after = if after_site {
            vec![SITE.to_owned()]
        } else {
            vec![]
        };
        ServiceDef::new(
            paths,
            core.service(),
            paths.core_bin(core),
            owned(&args),
            after,
        )
    }

    /// The private nginx serving the own-domain website.
    pub fn site(paths: &Paths, nginx: &Path) -> ServiceDef {
        let args = nginx_args(&paths.site());
        ServiceDef::new(paths, SITE, nginx, args, vec![])
    }

    /// Boot-time restoration of firewall and hop rules (`onebox net-apply`).
    pub fn network(paths: &Paths) -> ServiceDef {
        let args = owned(&["net-apply"]);
        ServiceDef::new(paths, NETWORK, &paths.executable, args, vec![])
    }

    /// The subscription worker (`onebox subscription serve`).
    pub fn subscription(paths: &Paths) -> ServiceDef {
        let args = owned(&["subscription", "serve"]);
        ServiceDef::new(paths, SUBSCRIPTION, &paths.executable, args, vec![])
    }

    /// The nginx front of the subscription worker.
    pub fn subscription_web(paths: &Paths, nginx: &Path) -> ServiceDef {
        let args = nginx_args(&paths.subscription());
        let after = vec![SUBSCRIPTION.to_owned()];
        ServiceDef::new(paths, SUBSCRIPTION_WEB, nginx, args, after)
    }

    /// The FRP server.
    pub fn frps(paths: &Paths) -> ServiceDef {
        let config = path_string(&paths.frp_root.join("frps.toml"));
        let args = owned(&["-c", config.as_str()]);
        ServiceDef::new(paths, FRPS, paths.frp_bin.join("frps"), args, vec![])
    }

    /// The nginx of FRP web mode.
    pub fn frp_web(paths: &Paths, nginx: &Path) -> ServiceDef {
        let args = nginx_args(&paths.frp_root);
        ServiceDef::new(paths, FRP_WEB, nginx, args, vec![])
    }

    /// Rebuild a definition from its persisted spec (validated first).
    pub fn from_spec(paths: &Paths, name: &str, spec: &ServiceSpec) -> Result<ServiceDef> {
        validate_name(name)?;
        spec.validate()?;
        Ok(ServiceDef::new(
            paths,
            name,
            &spec.program,
            spec.args.clone(),
            spec.after.clone(),
        ))
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

    /// Every invariant a unit, script or spec relies on: a valid name, an
    /// absolute program, no line breaks in any word, valid dependencies.
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
        for text in [&self.description, self.banner.as_deref().unwrap_or("")] {
            reject_breaks(text)?;
        }
        Ok(())
    }
}

/// Per-service traits (see the module docs). Identity configs are taken
/// from the definition's own `-c` argument so they always match how the
/// process was started.
fn apply_traits(def: &mut ServiceDef, paths: &Paths) {
    let config = arg_after(&def.args, "-c").map(PathBuf::from);
    match def.name.as_str() {
        SING_BOX | XRAY => {
            def.identity = Identity {
                subcommand: def.args.first().cloned(),
                config,
                nginx_title: false,
            };
            let legacy = if def.name == SING_BOX {
                "singbox.log"
            } else {
                "xray.log"
            };
            def.log_files = vec![paths.log.join(legacy)];
            if def.name == XRAY {
                def.restart_prevent_status = Some(23);
            }
        }
        SITE => {
            def.identity = nginx_identity(config);
            def.legacy_pid_files = vec![paths.site().join("nginx.pid")];
            def.log_files = vec![paths.site().join("error.log")];
        }
        SUBSCRIPTION_WEB => def.identity = nginx_identity(config),
        NETWORK => {
            def.kind = ServiceKind::Oneshot;
            def.description = "Onebox network rule restoration".into();
            def.banner = Some("Restoring Onebox network rules".into());
            def.after_firewall = true;
        }
        FRPS => {
            frp_dirs(def, paths);
            let exe = path_string(&paths.executable);
            def.pre_start = Some(owned(&[exe.as_str(), "frps", "net-apply"]));
            def.identity.config = config;
            def.legacy_pid_files = vec![paths.frp_run.join("frps.pid")];
            def.log_files = vec![paths.frp_log.join("frps.log")];
        }
        FRP_WEB => {
            frp_dirs(def, paths);
            def.identity = nginx_identity(config);
            def.legacy_pid_files = vec![paths.frp_root.join("nginx.pid")];
            def.log_files = vec![
                paths.frp_log.join("nginx.log"),
                paths.frp_log.join("nginx-error.log"),
                paths.frp_root.join("error.log"),
            ];
        }
        _ => {}
    }
}

fn frp_dirs(def: &mut ServiceDef, paths: &Paths) {
    def.run_dir = paths.frp_run.clone();
    def.log_dir = paths.frp_log.clone();
    def.spec_dir = paths.frp_root.join("services");
}

fn nginx_identity(config: Option<PathBuf>) -> Identity {
    Identity {
        subcommand: None,
        config,
        nginx_title: true,
    }
}

/// `-p {prefix} -c {prefix}/nginx.conf -g "daemon off;"` (foreground nginx).
fn nginx_args(prefix: &Path) -> Vec<String> {
    let config = path_string(&prefix.join("nginx.conf"));
    let prefix = path_string(prefix);
    owned(&[
        "-p",
        prefix.as_str(),
        "-c",
        config.as_str(),
        "-g",
        "daemon off;",
    ])
}

/// The word following `flag` in `args`.
pub(crate) fn arg_after<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    let index = args.iter().position(|a| a == flag)?;
    args.get(index + 1).map(String::as_str)
}

fn owned(words: &[&str]) -> Vec<String> {
    words.iter().map(|w| w.to_string()).collect()
}

/// Paths are validated UTF-8 at startup (`Paths::from_env`).
fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
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

/// The service environment: the allowlisted path variables (each at most
/// once) and `ONEBOX_INIT` ∈ {none, systemd, openrc}.
pub fn validate_env(env: &[(String, String)]) -> Result<()> {
    let mut seen = BTreeSet::new();
    for (key, value) in env {
        let allowed = SERVICE_ENV_KEYS.contains(&key.as_str()) || key == INIT_ENV;
        if !allowed || !seen.insert(key.as_str()) {
            return Err(Error::msg("服务环境变量不在路径白名单或重复"));
        }
        reject_breaks(value)?;
        if key == INIT_ENV && !matches!(value.as_str(), "none" | "systemd" | "openrc") {
            return Err(Error::msg("服务 init 环境值无效"));
        }
    }
    Ok(())
}

/// The `ONEBOX_INIT` spelling of an init system.
pub fn init_value(init: InitSystem) -> &'static str {
    match init {
        InitSystem::Systemd => "systemd",
        InitSystem::Openrc => "openrc",
        InitSystem::None => "none",
    }
}

/// The 14 variables persisted into units, specs and cron lines: the 13 path
/// roots in v2 order, then `ONEBOX_INIT`. Built from `Paths` only, never
/// from the caller's environment.
pub fn service_env(paths: &Paths, init: InitSystem) -> Vec<(String, String)> {
    let mut env = paths.service_env();
    env.push((INIT_ENV.to_owned(), init_value(init).to_owned()));
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

/// Create a runtime/log directory (0755: nginx workers traverse the run
/// directory) unless it already exists; existing modes are left alone.
pub(crate) fn prepare_dir(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => Ok(()),
        _ => crate::sys::fs::ensure_dir(path, 0o755),
    }
}

#[cfg(test)]
mod tests;
