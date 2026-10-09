//! Shared fixtures of the subscription tests: an isolated node with a
//! scripted host (systemd, nginx, worker account), configurations per mode
//! and device helpers.

use crate::apply::journal::{self, Journal};
use crate::ctx::Ctx;
use crate::domain::config::{Device, NodeConfig, SubscriptionConfig, SubscriptionMode, WebCert};
use crate::domain::fixtures::{config, ip_subscription, standalone_subscription, with_site};
use crate::domain::protocol::{Core, Protocol};
use crate::host::cron::CronSnapshot;
use crate::state::StateStore;
use crate::sys::exec::{FakeExec, Output};
use crate::sys::fs::TempDir;
use crate::sys::lock::{FileLock, BUSY_MESSAGE};
use crate::ui::ScriptedPrompter;
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// A token of 64 lowercase hex characters.
pub const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// An isolated node.
pub struct Node {
    pub dir: TempDir,
    pub ctx: Ctx,
    pub fake: Arc<FakeExec>,
    pub ui: Arc<ScriptedPrompter>,
}

impl Node {
    pub fn new(label: &str) -> Node {
        let dir = TempDir::new(label).unwrap();
        let (ctx, fake, ui) = Ctx::test(dir.path());
        Node { dir, ctx, fake, ui }
    }

    pub fn save(&self, cfg: &NodeConfig) {
        StateStore::save(&self.ctx, cfg).unwrap();
    }

    pub fn lock(&self) -> FileLock {
        FileLock::acquire(&self.ctx.paths.lock(), BUSY_MESSAGE).unwrap()
    }

    /// Leave a pending node journal behind.
    pub fn pending_journal(&self) {
        let journal = Journal::new(
            "测试",
            None,
            vec![],
            vec![],
            CronSnapshot {
                available: false,
                lines: vec![],
                anchors: None,
            },
            Default::default(),
        );
        let dir = self.ctx.paths.transaction();
        std::fs::create_dir_all(&dir).unwrap();
        journal::write(&self.ctx.paths, &journal).unwrap();
    }

    pub fn systemd(&self, main_pid: u32) -> Systemd {
        systemd(&self.fake, &self.ctx.paths, main_pid)
    }

    pub fn nginx(&self) {
        nginx(&self.fake);
    }

    pub fn listening(&self, ports: &[u16]) {
        listening(&self.ctx.paths, ports);
    }

    /// `/proc/PID/exe` of the system root pointing at `target`.
    pub fn proc_exe(&self, pid: u32, target: &Path) {
        let dir = self.ctx.paths.system(&format!("/proc/{pid}"));
        std::fs::create_dir_all(&dir).unwrap();
        let link = dir.join("exe");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(target, link).unwrap();
    }

    /// A (new) program file at `EXE`, replacing any old one by rename like
    /// a self-update does.
    pub fn install_exe(&self) {
        let exe = &self.ctx.paths.executable;
        std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
        let temp = exe.with_extension("new");
        std::fs::write(&temp, b"\x7fELF fake").unwrap();
        std::fs::rename(temp, exe).unwrap();
    }
}

/// Script systemd on `fake`: services become active once started or
/// restarted and inactive once stopped; `MainPID` is `main_pid`.
pub fn systemd(fake: &FakeExec, paths: &crate::paths::Paths, main_pid: u32) -> Systemd {
    let state = Systemd::default();
    std::fs::create_dir_all(paths.system("/run/systemd/system")).unwrap();
    let active = state.active.clone();
    let actions = state.actions.clone();
    fake.on_fn(
        |c| c.program == "systemctl",
        move |c| Ok(systemctl(c.args.as_slice(), &active, &actions, main_pid)),
    );
    state
}

/// nginx (old syntax), the `www-data` worker and its group on `fake`.
pub fn nginx(fake: &FakeExec) {
    fake.provide("nginx")
        .on("id", &["-u", "www-data"], Output::success("33\n"))
        .on("id", &["-gn", "www-data"], Output::success("www-data\n"))
        .on(
            "getent",
            &["group", "www-data"],
            Output::success("www-data:x:33:\n"),
        )
        .on("nginx", &["-T"], Output::failure(1, ""))
        .on("nginx", &["-t"], Output::success(""))
        .on_fn(
            |c| c.program_name() == "nginx" && c.args == ["-v"],
            |_| Ok(Output::failure(0, "nginx version: nginx/1.24.0 (Ubuntu)\n")),
        );
}

/// `/proc/net/tcp` of the system root with LISTEN sockets on `ports`.
pub fn listening(paths: &crate::paths::Paths, ports: &[u16]) {
    let net = paths.system("/proc/net");
    std::fs::create_dir_all(&net).unwrap();
    let mut table = String::from("  sl  local_address rem_address   st\n");
    for (i, port) in ports.iter().enumerate() {
        table.push_str(&format!("   {i}: 00000000:{port:04X} 00000000:0000 0A 0\n"));
    }
    std::fs::write(net.join("tcp"), table).unwrap();
}

/// What the scripted systemd saw.
#[derive(Clone, Default)]
pub struct Systemd {
    pub active: Arc<Mutex<BTreeSet<String>>>,
    pub actions: Arc<Mutex<Vec<String>>>,
}

impl Systemd {
    pub fn activate(&self, name: &str) {
        self.active.lock().unwrap().insert(name.to_owned());
    }

    /// `"{verb} {unit}"` of every state-changing call, in order.
    pub fn actions(&self) -> Vec<String> {
        self.actions.lock().unwrap().clone()
    }
}

fn systemctl(
    args: &[String],
    active: &Mutex<BTreeSet<String>>,
    actions: &Mutex<Vec<String>>,
    main_pid: u32,
) -> Output {
    let verb = args.first().map(String::as_str).unwrap_or_default();
    let unit = args.last().cloned().unwrap_or_default();
    let mut active = active.lock().unwrap();
    match verb {
        "is-active" => {
            return if active.contains(&unit) {
                Output::success("")
            } else {
                Output::failure(3, "")
            };
        }
        "show" => return Output::success(format!("MainPID={main_pid}\n")),
        "is-enabled" => return Output::failure(1, "disabled\n"),
        "start" | "restart" => {
            active.insert(unit.clone());
        }
        "stop" => {
            active.remove(&unit);
        }
        _ => {}
    }
    if verb != "daemon-reload" {
        actions.lock().unwrap().push(format!("{verb} {unit}"));
    }
    Output::success("")
}

/// VLESS-REALITY on 443 (sing-box): every remote format is supported.
pub fn reality() -> NodeConfig {
    config(&[(Protocol::VlessReality, 443, Core::Singbox)])
}

pub fn with_subscription(mut cfg: NodeConfig, sub: SubscriptionConfig) -> NodeConfig {
    cfg.subscription = Some(sub);
    cfg
}

/// [`reality`] with an ip-mode subscription on `port`.
pub fn ip(port: u16) -> NodeConfig {
    with_subscription(reality(), ip_subscription(port))
}

/// [`reality`] with a standalone subscription.
pub fn standalone(cert: WebCert, port: u16) -> NodeConfig {
    with_subscription(
        reality(),
        standalone_subscription("sub.example.com", port, cert),
    )
}

/// REALITY on 8443 with the own site (HTTPS entry) and a site-mode
/// subscription.
pub fn site() -> NodeConfig {
    let cfg = with_site(
        config(&[(Protocol::VlessReality, 8443, Core::Xray)]),
        "www.example.com",
        true,
    );
    let port = cfg.site_public_port();
    with_subscription(
        cfg,
        SubscriptionConfig {
            mode: SubscriptionMode::Site,
            port,
        },
    )
}

/// Deterministic, well-spread randomness (xorshift64) for tests that create
/// many ids.
pub struct Xorshift(pub u64);

impl crate::sys::rand::Random for Xorshift {
    fn fill(&mut self, buf: &mut [u8]) -> crate::error::Result<()> {
        for b in buf {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            *b = (self.0 >> 24) as u8;
        }
        Ok(())
    }
}

/// A device whose token is `token`.
pub fn device(id: &str, name: &str, token: &str) -> Device {
    Device {
        id: id.to_owned(),
        name: name.to_owned(),
        hash: crate::subscription::devices::token_hash(token),
        created: 1_760_000_000,
    }
}
