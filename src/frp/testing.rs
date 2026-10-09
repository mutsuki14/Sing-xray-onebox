//! Shared fixtures of the FRP unit tests: sample states, a fake frp
//! release (API document and package served through the fake curl) and a
//! tar.gz builder.

use super::model::{AppDomain, BindAddr, FrpState, Mode, WebSettings, WebTls};
use super::runtime::{Health, Runtime};
use crate::ctx::Ctx;
use crate::domain::config::PortRange;
use crate::error::Result;
use crate::host::fetch::testing::{serve, Reply};
use crate::host::fetch::Asset;
use crate::host::init::InitSystem;
use crate::sys::exec::{Exec, FakeExec, Output, SystemExec};
use crate::sys::fs::{sha256_hex, TempDir};
use crate::ui::ScriptedPrompter;
use serde_json::json;
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

pub const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
pub const API: &str = "https://api.github.com/repos/fatedier/frp/releases";

pub fn no_env(_: &str) -> Option<String> {
    None
}

pub fn tcp_state() -> FrpState {
    FrpState::new(
        "frp.example.com".into(),
        TOKEN.into(),
        BindAddr::AnyV4,
        Mode::Tcp {
            range: PortRange {
                start: 20000,
                end: 20010,
            },
        },
    )
}

pub fn web_state(tls: WebTls) -> FrpState {
    FrpState::new(
        "frp.example.com".into(),
        TOKEN.into(),
        BindAddr::AnyV4,
        Mode::Web(WebSettings::new(
            AppDomain::Single {
                domain: "app.example.com".into(),
            },
            tls,
        )),
    )
}

/// A gzip tar with the given `(path, bytes)` regular files (mode 0755).
pub fn tar_gz(members: &[(&str, &[u8])]) -> Vec<u8> {
    let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    let mut builder = tar::Builder::new(gz);
    for (name, data) in members {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o755);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder.append_data(&mut header, name, *data).unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap()
}

/// The official package name for amd64.
pub fn package_name(version: &str) -> String {
    format!("frp_{version}_linux_amd64.tar.gz")
}

/// The bytes of a fake `frps` that "reports" `version`.
pub fn fake_frps(version: &str) -> Vec<u8> {
    format!("\x7fELF fake frps {version}").into_bytes()
}

/// The package of `version` holding a fake `frps`.
pub fn package(version: &str) -> Vec<u8> {
    let dir = format!("frp_{version}_linux_amd64");
    tar_gz(&[
        (&format!("{dir}/LICENSE"), b"license"),
        (&format!("{dir}/frps"), &fake_frps(version)),
        (&format!("{dir}/frpc"), b"\x7fELF fake frpc"),
    ])
}

/// The API document of release `v{version}` with the given assets.
pub fn release_json(version: &str, assets: Vec<serde_json::Value>) -> serde_json::Value {
    json!({
        "tag_name": format!("v{version}"),
        "draft": false,
        "prerelease": false,
        "body": "",
        "assets": assets,
    })
}

/// One asset entry; `digest` adds the API SHA-256.
pub fn asset_json(version: &str, name: &str, bytes: &[u8], digest: bool) -> serde_json::Value {
    let tag = format!("v{version}");
    let mut asset = json!({
        "name": name,
        "size": bytes.len(),
        "browser_download_url": Asset::expected_url("fatedier/frp", &tag, name),
    });
    if digest {
        asset["digest"] = json!(format!("sha256:{}", sha256_hex(bytes)));
    }
    asset
}

/// Routes serving release `version` (by tag, and as `latest` when
/// `latest`) with its package and an API digest.
pub fn release_routes(version: &str, latest: bool) -> Vec<(String, Reply)> {
    let bytes = package(version);
    let name = package_name(version);
    let doc = release_json(version, vec![asset_json(version, &name, &bytes, true)]).to_string();
    let mut routes = vec![
        (format!("{API}/tags/v{version}"), Reply::body(doc.clone())),
        (
            Asset::expected_url("fatedier/frp", &format!("v{version}"), &name),
            Reply::body(bytes),
        ),
    ];
    if latest {
        routes.push((format!("{API}/latest"), Reply::body(doc)));
    }
    routes
}

/// `{binary} -v` answers: binaries below `stage` report `staged`, the
/// installed one (`installed`) reports `current` (`None` = it fails).
pub fn frps_versions(
    exec: &crate::sys::exec::FakeExec,
    installed: &Path,
    current: Option<&str>,
    staged: &str,
) {
    let installed = installed.to_path_buf();
    let current = current.map(str::to_owned);
    let staged = staged.to_owned();
    exec.on_fn(
        |cmd| cmd.program.ends_with("/frps") && cmd.args == ["-v"],
        move |cmd| {
            use crate::sys::exec::Output;
            if Path::new(&cmd.program) == installed {
                return Ok(match &current {
                    Some(v) => Output::success(format!("{v}\n")),
                    None => Output::failure(126, "exec format error"),
                });
            }
            Ok(Output::success(format!("{staged}\n")))
        },
    );
}

/// A fake host for lifecycle tests: systemd with tracked unit states, a
/// crontab, the frp release, DNS pointing at the host, a fake nginx and
/// iptables, and the real openssl for the private CA.
pub struct FakeHost {
    pub dir: TempDir,
    pub ctx: Ctx,
    pub exec: Arc<FakeExec>,
    pub ui: Arc<ScriptedPrompter>,
    pub units: Arc<Mutex<Units>>,
    pub crontab: Arc<Mutex<Option<String>>>,
    /// The TLS health check succeeds while this is true.
    pub healthy: Arc<AtomicBool>,
}

/// systemd unit states of the fake host.
#[derive(Debug, Default)]
pub struct Units {
    pub running: BTreeSet<String>,
    pub enabled: BTreeSet<String>,
    /// Units whose start fails.
    pub broken: BTreeSet<String>,
}

fn guard<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl FakeHost {
    /// `None` when the real openssl is missing.
    pub fn new() -> Option<FakeHost> {
        if !crate::cert::testing::have_openssl() {
            return None;
        }
        let dir = TempDir::new("frp-host").unwrap();
        let (ctx, exec, ui) = Ctx::test(dir.path());
        let host = FakeHost {
            dir,
            ctx,
            exec,
            ui,
            units: Default::default(),
            crontab: Default::default(),
            healthy: Arc::new(AtomicBool::new(true)),
        };
        host.proc_net();
        host.script();
        Some(host)
    }

    /// Empty socket tables: no port is in use.
    fn proc_net(&self) {
        let net = self.ctx.paths.system("/proc/net");
        std::fs::create_dir_all(&net).unwrap();
        for table in ["tcp", "tcp6", "udp", "udp6"] {
            std::fs::write(net.join(table), "  sl  local_address rem_address   st\n").unwrap();
        }
    }

    fn script(&self) {
        let exec = &self.exec;
        for program in ["curl", "openssl", "ip", "crontab", "nginx", "iptables"] {
            exec.provide(program);
        }
        guard(&self.units).running.insert("cron".into());
        let units = self.units.clone();
        exec.on_fn(
            |c| c.program == "systemctl",
            move |c| Ok(systemctl(&units, &c.args)),
        );
        let crontab = self.crontab.clone();
        exec.on_fn(
            |c| c.program == "crontab",
            move |c| crontab_cmd(&crontab, &c.args),
        );
        let healthy = self.healthy.clone();
        exec.on_fn(
            |c| c.program == "openssl" && c.args.first().is_some_and(|a| a == "s_client"),
            move |_| {
                Ok(if healthy.load(Ordering::SeqCst) {
                    Output::success("CONNECTION ESTABLISHED\n")
                } else {
                    Output::failure(1, "verify error")
                })
            },
        );
        exec.on_fn(|c| c.program == "openssl", |c| SystemExec.run(c));
        exec.on_fn(
            |c| c.program.ends_with("/frps"),
            |c| Ok(fake_frps_cmd(&c.program, &c.args)),
        );
        exec.on("uname", &["-m"], Output::success("x86_64\n"));
        exec.on(
            "ip",
            &["-j", "address", "show"],
            Output::success(r#"[{"addr_info":[{"local":"192.0.2.1"}]}]"#),
        );
        exec.on(
            "getent",
            &["ahosts"],
            Output::success("192.0.2.1 STREAM x\n"),
        );
        exec.on("getent", &[], Output::failure(2, ""));
        exec.on("nginx", &["-T"], Output::failure(1, ""));
        exec.on("nginx", &["-t"], Output::success(""));
        exec.on("id", &["-u", "www-data"], Output::success("33\n"));
        exec.on("id", &["-gn", "www-data"], Output::success("www-data\n"));
        exec.on("id", &[], Output::failure(1, "no such user"));
        exec.on(
            "iptables",
            &["-w", "5", "-S", "INPUT"],
            Output::success("-P INPUT ACCEPT\n"),
        );
        exec.on_fn(
            |c| c.program == "iptables" && c.args.iter().any(|a| a == "-C"),
            |_| Ok(Output::failure(1, "")),
        );
        exec.on("iptables", &[], Output::success(""));
        serve(exec, release_routes("0.71.0", true));
    }

    pub fn runtime(&self) -> Runtime<'_> {
        Runtime {
            ctx: &self.ctx,
            init: InitSystem::Systemd,
            env: &no_env,
            root: true,
            health: Health {
                attempts: 1,
                interval: Duration::ZERO,
            },
            install_self: |_| Ok(false),
        }
    }

    pub fn crontab(&self) -> String {
        guard(&self.crontab).clone().unwrap_or_default()
    }

    pub fn set_crontab(&self, text: &str) {
        *guard(&self.crontab) = Some(text.to_owned());
    }

    pub fn running(&self, unit: &str) -> bool {
        guard(&self.units).running.contains(unit)
    }

    pub fn enabled(&self, unit: &str) -> bool {
        guard(&self.units).enabled.contains(unit)
    }

    pub fn break_unit(&self, unit: &str, broken: bool) {
        let mut units = guard(&self.units);
        if broken {
            units.broken.insert(unit.to_owned());
        } else {
            units.broken.remove(unit);
        }
    }

    pub fn set_healthy(&self, healthy: bool) {
        self.healthy.store(healthy, Ordering::SeqCst);
    }

    /// Command lines that ran (`Cmd::display`).
    pub fn history(&self) -> Vec<String> {
        self.exec.history()
    }
}

/// A fake frps: `-v` prints the version its file carries (see
/// [`fake_frps`]); `verify` accepts any configuration.
fn fake_frps_cmd(program: &str, args: &[String]) -> Output {
    match args.first().map(String::as_str) {
        Some("-v") => match std::fs::read(program) {
            Ok(bytes) => {
                let text = String::from_utf8_lossy(&bytes).into_owned();
                let version = text.rsplit(' ').next().unwrap_or("").to_owned();
                Output::success(format!("{version}\n"))
            }
            Err(_) => Output::failure(127, "not found"),
        },
        Some("verify") => Output::success("frps: the configuration file is syntax ok\n"),
        _ => Output::failure(2, "unexpected frps call"),
    }
}

fn systemctl(units: &Mutex<Units>, args: &[String]) -> Output {
    let mut u = guard(units);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let ok = Output::success("");
    match args.as_slice() {
        ["is-active", "--quiet", name] if u.running.contains(*name) => ok,
        ["is-active", ..] => Output::failure(3, ""),
        ["is-enabled", name] if u.enabled.contains(*name) => Output::success("enabled\n"),
        ["is-enabled", _] => Output::failure(1, "disabled\n"),
        ["start" | "restart", name] if u.broken.contains(*name) => {
            Output::failure(1, format!("Job for {name} failed"))
        }
        ["start" | "restart", name] => {
            u.running.insert(name.to_string());
            ok
        }
        ["stop", name] => {
            u.running.remove(*name);
            ok
        }
        ["enable", "--now", _] | ["daemon-reload"] => ok,
        ["enable", name] => {
            u.enabled.insert(name.to_string());
            ok
        }
        ["disable", name] => {
            u.enabled.remove(*name);
            ok
        }
        _ => Output::failure(1, "unexpected systemctl call"),
    }
}

fn crontab_cmd(crontab: &Mutex<Option<String>>, args: &[String]) -> Result<Output> {
    let mut tab = guard(crontab);
    Ok(match args.first().map(String::as_str) {
        Some("-l") => match tab.as_ref() {
            Some(text) => Output::success(text.clone()),
            None => Output::failure(1, "no crontab for root"),
        },
        Some(file) => {
            *tab = Some(std::fs::read_to_string(file)?);
            Output::success("")
        }
        None => Output::failure(1, "usage"),
    })
}
