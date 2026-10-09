//! What the FRP lifecycle needs from the host, in one injectable place
//! ([`Runtime`]), and the host-facing steps shared by apply, renew,
//! service control and rollback: the service definitions and start
//! rules, the TLS health check, the web nginx configuration and the FRP
//! crontab lines.
//!
//! Changes from v2:
//! - one FRP cron line per job in the v3 format (`# onebox:frp-renew`,
//!   running with the fixed PATH and the service variables); v2's
//!   `@reboot … frps start # onebox-frps-boot` is removed under systemd and
//!   OpenRC (the units are enabled, H-8.1#12) and replaced by the
//!   per-service `boot:onebox-frps`/`boot:onebox-frp-web` lines without an
//!   init system (G25);
//! - `onebox-frps` starts with its `frps net-apply` pre-start hook; a caller
//!   holding the FRP lock hands it to the hook when Onebox supervises the
//!   service itself (no init), and the hook never waits for it otherwise;
//! - the nginx worker account and IPv6 listeners follow the shared host
//!   answers; the web directories get mode 0755 only where nginx needs them.

use super::model::{FrpState, WebSettings};
use super::render::{nginx_conf, NginxLayout, NginxPhase};
use crate::ctx::Ctx;
use crate::domain::defaults::FRP_RENEW_CRON;
use crate::error::Result;
use crate::host::cron::{self, Crontab, Tag};
use crate::host::init::{self, InitSystem};
use crate::host::os::{self, process_env, EnvLookup};
use crate::host::service::{ServiceDef, Services, FRPS, FRP_WEB};
use crate::host::{nginx, selfexe};
use crate::paths::Paths;
use crate::sys::exec::Cmd;
use crate::sys::fs::{atomic_write, ensure_dir};
use crate::sys::lock::FileLock;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Contention message of the FRP lock (v2 wording).
pub const BUSY: &str = "另一个 FRP 管理操作正在进行";

/// How the TLS health check retries (v2: 10 × 300 ms).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Health {
    pub attempts: u32,
    pub interval: Duration,
}

impl Health {
    pub const DEFAULT: Health = Health {
        attempts: 10,
        interval: Duration::from_millis(300),
    };
}

/// The host facts and effects of the lifecycle (tests replace them).
pub struct Runtime<'a> {
    pub ctx: &'a Ctx,
    pub init: InitSystem,
    /// `GH_PROXY`, `GH_TOKEN`, `ONEBOX_NGINX_BIN`, Cloudflare variables.
    pub env: EnvLookup<'a>,
    /// Running as root (package installs).
    pub root: bool,
    pub health: Health,
    /// Copies the running program to `EXE` (the hook and cron call it).
    pub install_self: fn(&Ctx) -> Result<bool>,
}

impl<'a> Runtime<'a> {
    /// The production runtime.
    pub fn system(ctx: &'a Ctx) -> Runtime<'a> {
        Runtime {
            ctx,
            init: init::detect(ctx),
            env: &process_env,
            root: os::is_root(),
            health: Health::DEFAULT,
            install_self: selfexe::install_self,
        }
    }

    pub fn paths(&self) -> &Paths {
        &self.ctx.paths
    }

    pub fn services(&self) -> Services<'a> {
        Services::new(self.ctx, self.init)
    }

    /// The FRP lock, non-blocking.
    pub fn lock(&self) -> Result<FileLock> {
        FileLock::acquire(&self.paths().frp_lock(), BUSY)
    }

    /// The FRP lock, waiting up to `wait` (scheduled renewals).
    pub fn lock_waiting(&self, wait: Duration) -> Result<FileLock> {
        FileLock::acquire_waiting(
            &self.paths().frp_lock(),
            BUSY,
            wait,
            Duration::from_secs(5),
        )
    }

    /// Start `name`. `onebox-frps`'s pre-start hook gets the held FRP lock
    /// when the supervisor runs it; under systemd/OpenRC the hook finds the
    /// lock busy and proceeds (see `lifecycle::net_apply`).
    pub fn start(&self, lock: &FileLock, name: &str) -> Result<()> {
        let services = self.services();
        if name == FRPS && self.init == InitSystem::None {
            services.start_with_lock(name, lock)
        } else {
            services.start(name)
        }
    }

    /// Restart `name` (same lock rule as [`Runtime::start`]).
    pub fn restart(&self, lock: &FileLock, name: &str) -> Result<()> {
        let services = self.services();
        if name == FRPS && self.init == InitSystem::None {
            services.restart_with_lock(name, lock)
        } else {
            services.restart(name)
        }
    }

    pub fn nginx(&self) -> Result<PathBuf> {
        nginx::binary_with(self.ctx, self.env)
    }

    /// The FRP services `state` runs (`onebox-frp-web` in web mode).
    pub fn defs(&self, state: &FrpState, nginx: Option<&Path>) -> Result<Vec<ServiceDef>> {
        let paths = self.paths();
        let mut defs = vec![ServiceDef::frps(paths)];
        if state.is_web() {
            let nginx = match nginx {
                Some(path) => path.to_path_buf(),
                None => self.nginx()?,
            };
            defs.push(ServiceDef::frp_web(paths, &nginx));
        }
        Ok(defs)
    }

    /// frps accepts TLS with the private CA for the control domain, and
    /// the services run (H §4.10).
    pub fn health(&self, state: &FrpState, check_web: bool) -> Result<()> {
        let addr = match state.bind_addr {
            super::model::BindAddr::AnyV6 | super::model::BindAddr::LoopbackV6 => "[::1]",
            _ => "127.0.0.1",
        };
        let ca = self.paths().frp_root.join("ca.pem");
        let cmd = Cmd::new("openssl")
            .args(["s_client", "-connect"])
            .arg(format!("{addr}:{}", state.bind_port))
            .args(["-servername", &state.domain])
            .args(["-verify_hostname", &state.domain])
            .arg("-CAfile")
            .arg(ca.to_string_lossy())
            .args(["-verify_return_error", "-brief"])
            .timeout(Duration::from_secs(4));
        let services = self.services();
        for attempt in 0..self.health.attempts {
            let tls = self.ctx.run(&cmd).is_ok_and(|o| o.ok());
            let web = !check_web || !state.is_web() || services.running(FRP_WEB);
            if tls && services.running(FRPS) && web {
                return Ok(());
            }
            if attempt + 1 < self.health.attempts {
                std::thread::sleep(self.health.interval);
            }
        }
        bail!("FRP 启动或私有 CA / TLS 健康检查失败")
    }

    /// Write `nginx.conf` for `phase` (and the web directories) and test it.
    pub fn write_web_config(&self, state: &FrpState, phase: NginxPhase) -> Result<()> {
        let Some(web) = state.web() else {
            return Ok(());
        };
        let paths = self.paths();
        let www = paths.frp_web.join("www");
        for dir in [
            paths.frp_web.clone(),
            www.clone(),
            www.join(".well-known"),
            www.join(".well-known/acme-challenge"),
            paths.frp_web.join("tmp"),
        ] {
            ensure_dir(&dir, 0o755)?;
        }
        let conf = paths.frp_root.join("nginx.conf");
        atomic_write(&conf, self.nginx_text(state, web, phase)?.as_bytes(), 0o600)?;
        nginx::test(self.ctx, &paths.frp_root, &conf)
    }

    fn nginx_text(&self, state: &FrpState, web: &WebSettings, phase: NginxPhase) -> Result<String> {
        let paths = self.paths();
        let worker = nginx::worker(self.ctx)?.to_string();
        let ipv6 = state.bind_addr == super::model::BindAddr::AnyV6
            || crate::sys::net::ipv6_available(&paths.system_root);
        let layout = NginxLayout {
            frp_root: &paths.frp_root,
            frp_web: &paths.frp_web,
            worker: &worker,
            ipv6,
        };
        Ok(nginx_conf(web, &layout, phase))
    }

    /// The FRP crontab lines (G25): the daily renewal in v3 format, no
    /// `frp-boot` line, and without an init system one autostart line per
    /// service `state` runs.
    pub fn rewrite_cron(&self, state: &FrpState) -> Result<()> {
        ensure!(cron::available(self.ctx), "缺少 crontab，无法安排证书续期");
        let paths = self.paths();
        let renew = cron::line(
            FRP_RENEW_CRON,
            paths,
            self.init,
            &["frps", "renew", "--cron"],
            &paths.frp_log.join("renew.log"),
            &Tag::frp_renew(),
        )?;
        let mut boots = Vec::new();
        if self.init == InitSystem::None {
            for name in names(state) {
                let tag = Tag::boot(name)?;
                let line = cron::line(
                    "@reboot",
                    paths,
                    self.init,
                    &["service", name, "start"],
                    &paths.frp_log.join("boot.log"),
                    &tag,
                )?;
                boots.push((tag, line));
            }
        }
        let web_boot = Tag::boot(FRP_WEB)?;
        let tcp_mode = !state.is_web();
        Crontab::edit(self.ctx, |tab| {
            tab.replace(&Tag::frp_renew(), &[renew])?;
            tab.remove(&Tag::frp_boot());
            for (tag, line) in &boots {
                tab.replace(tag, std::slice::from_ref(line))?;
            }
            if tcp_mode {
                tab.remove(&web_boot);
            }
            Ok(())
        })
    }
}

/// The FRP service names `state` runs.
pub fn names(state: &FrpState) -> Vec<&'static str> {
    if state.is_web() {
        vec![FRPS, FRP_WEB]
    } else {
        vec![FRPS]
    }
}

/// The FRP trees (0700, `.managed` markers) and the log/run directories.
pub fn mkdirs(paths: &Paths) -> Result<()> {
    for dir in [&paths.frp_root, &paths.frp_bin, &paths.frp_web] {
        ensure_dir(dir, 0o700)?;
        atomic_write(
            &dir.join(super::model::MANAGED_FILE),
            b"Managed by Onebox FRP\n",
            0o600,
        )?;
    }
    for dir in [&paths.frp_log, &paths.frp_run] {
        ensure_dir(dir, 0o700)?;
    }
    Ok(())
}
