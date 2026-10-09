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
//!   init system (G25). Those lines are rewritten only while they exist (or
//!   replace v2's `frp-boot`), so a renewal keeps an autostart the
//!   administrator disabled;
//! - `frp` firewall rules that could not be removed stay recorded
//!   ([`Leftovers`]): a rollback writes them back into the restored ledger,
//!   and an uninstall keeps `FRP_ROOT` holding only `.managed` and the
//!   ledger, so that `frps uninstall` (or the next install) retries them
//!   (v2 deleted their record with `FRP_ROOT`);
//! - `onebox-frps` starts with its `frps net-apply` pre-start hook; a caller
//!   holding the FRP lock hands it to the hook when Onebox supervises the
//!   service itself (no init), and the hook never waits for it otherwise;
//! - the nginx worker account and IPv6 listeners follow the shared host
//!   answers; the web directories get mode 0755 only where nginx needs them.

use super::model::{FrpState, WebSettings, MANAGED_FILE};
use super::render::{nginx_conf, NginxLayout, NginxPhase};
use crate::cert::acme::AcmeRelease;
use crate::cert::http01::HTTP_PORT;
use crate::cert::Engine;
use crate::ctx::Ctx;
use crate::domain::defaults::FRP_RENEW_CRON;
use crate::error::Result;
use crate::host::cron::{self, Crontab, Tag};
use crate::host::firewall::{self, ledger_path, Entry, Ledger};
use crate::host::init::{self, InitSystem};
use crate::host::os::{self, process_env, EnvLookup};
use crate::host::service::{ServiceDef, Services, FRPS, FRP_WEB};
use crate::host::supervisor::Supervisor;
use crate::host::{nginx, selfexe};
use crate::paths::Paths;
use crate::sys::exec::Cmd;
use crate::sys::fs::{atomic_write, ensure_dir};
use crate::sys::lock::FileLock;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Contention message of the FRP lock (v2 wording).
pub const BUSY: &str = "另一个 FRP 管理操作正在进行";
/// The firewall owner of the FRP rules (ledger `FRP_ROOT/firewall-v2.json`).
pub const FIREWALL_OWNER: &str = "frp";
const MANAGED_TEXT: &[u8] = b"Managed by Onebox FRP\n";

/// How long [`Runtime::lock`] waits for a concurrent holder.
const LOCK_GRACE: Duration = Duration::from_secs(2);

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
    /// Runs the services without an init system.
    pub supervisor: Supervisor<'a>,
    /// The acme.sh release the website certificates use.
    pub acme: AcmeRelease,
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
            supervisor: Supervisor::new(ctx),
            acme: AcmeRelease::pinned(),
        }
    }

    pub fn paths(&self) -> &Paths {
        &self.ctx.paths
    }

    pub fn services(&self) -> Services<'a> {
        Services::with_supervisor(self.ctx, self.init, self.supervisor.clone())
    }

    /// The certificate engine for the website certificate (HTTP-01 always
    /// through the web nginx's webroot, never the built-in responder).
    pub fn cert_engine(&self) -> Engine<'a> {
        Engine {
            ctx: self.ctx,
            release: self.acme.clone(),
            http01_port: HTTP_PORT,
            env: self.env,
            init: self.init,
        }
    }

    /// The FRP lock. Contention fails after a short grace period, which
    /// also covers a lock that was just released while a child forked by
    /// another thread still held its descriptor.
    pub fn lock(&self) -> Result<FileLock> {
        FileLock::acquire_waiting(
            &self.paths().frp_lock(),
            BUSY,
            LOCK_GRACE,
            Duration::from_millis(100),
        )
    }

    /// The FRP lock, waiting up to `wait` (scheduled renewals).
    pub fn lock_waiting(&self, wait: Duration) -> Result<FileLock> {
        FileLock::acquire_waiting(&self.paths().frp_lock(), BUSY, wait, Duration::from_secs(5))
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
    /// service `state` runs. Those lines are the enablement that
    /// `Services::enable`/`disable` keep (apply enables both services
    /// before this runs): only existing groups are rewritten (the v2
    /// per-service lines included) and v2's `frp-boot` line is converted,
    /// so a renewal never re-enables a service the administrator disabled.
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
            // v2 started FRP at boot through this one line.
            let converted = tab.remove(&Tag::frp_boot());
            for (tag, line) in &boots {
                if converted || tab.has(tag) {
                    tab.replace(tag, std::slice::from_ref(line))?;
                }
            }
            if tcp_mode {
                tab.remove(&web_boot);
            }
            Ok(())
        })
    }

    /// Remove every `frp` firewall rule; the ones that could not be
    /// removed are returned (and were printed as warnings). Errors are
    /// ledger and lock problems.
    pub fn clear_firewall(&self) -> Result<Leftovers> {
        let report = firewall::clear_owner(self.ctx, FIREWALL_OWNER)?;
        if report.failed.is_empty() {
            return Ok(Leftovers::default());
        }
        let path = ledger_path(self.paths(), FIREWALL_OWNER);
        Ok(Leftovers {
            entries: Ledger::load(&path, FIREWALL_OWNER)?.entries,
            messages: report.failed,
        })
    }

    /// Record `left` in the FRP ledger again after `FRP_ROOT`, which holds
    /// it, was restored or removed, so that a later reconcile or clear
    /// retries those rules instead of forgetting them. A missing `FRP_ROOT`
    /// comes back holding only `.managed` and the ledger ([`leftovers_only`]).
    pub fn keep_leftovers(&self, left: &Leftovers) -> Result<()> {
        if left.is_empty() {
            return Ok(());
        }
        let root = &self.paths().frp_root;
        if std::fs::symlink_metadata(root).is_err() {
            ensure_dir(root, 0o700)?;
            atomic_write(&root.join(MANAGED_FILE), MANAGED_TEXT, 0o600)?;
        }
        let mut ledger = Ledger::load(&ledger_path(self.paths(), FIREWALL_OWNER), FIREWALL_OWNER)?;
        let fresh: Vec<Entry> = left
            .entries
            .iter()
            .filter(|e| !ledger.entries.iter().any(|k| k.rule.token == e.rule.token))
            .cloned()
            .collect();
        if fresh.is_empty() {
            return Ok(());
        }
        ledger.entries.extend(fresh);
        ledger.save()
    }
}

/// `frp` firewall rules that could not be removed (ufw disabled, firewalld
/// stopped, …): still live and still recorded in the FRP ledger.
#[derive(Debug, Default)]
pub struct Leftovers {
    /// Their ledger entries.
    pub entries: Vec<Entry>,
    /// What failed, one line per rule.
    pub messages: Vec<String>,
}

impl Leftovers {
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }
}

/// What an uninstall that could not remove every firewall rule leaves
/// behind (and a rolled-back first install with such rules): `FRP_ROOT`
/// holding nothing but `.managed`, the FRP firewall ledger and its lock.
pub fn leftovers_only(paths: &Paths) -> bool {
    let managed = paths.frp_root.join(MANAGED_FILE);
    let ledger = ledger_path(paths, FIREWALL_OWNER);
    let allowed = [
        managed.clone(),
        ledger.clone(),
        ledger.with_extension("lock"),
    ];
    let Ok(entries) = std::fs::read_dir(&paths.frp_root) else {
        return false;
    };
    for entry in entries {
        match entry {
            Ok(entry) if allowed.contains(&entry.path()) => {}
            _ => return false,
        }
    }
    let is_file = |p: &Path| std::fs::symlink_metadata(p).is_ok_and(|m| m.is_file());
    is_file(&managed) && is_file(&ledger)
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
        atomic_write(&dir.join(MANAGED_FILE), MANAGED_TEXT, 0o600)?;
    }
    for dir in [&paths.frp_log, &paths.frp_run] {
        ensure_dir(dir, 0o700)?;
    }
    Ok(())
}
