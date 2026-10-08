//! Shared BBR test fixture: a fixture system root, a scripted host (the v2
//! `MockRunner` rebuilt on `FakeExec`) and a fake GitHub.

use super::net::Fetcher;
use super::release::{tag_url, Arch, X86_64};
use super::{Session, AVAILABLE, CC, QDISC, REPO};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::host::sysctl::fake::FakeSysctl;
use crate::sys::exec::{Cmd, FakeExec, Output};
use crate::sys::fs::TempDir;
use crate::ui::ScriptedPrompter;
use serde_json::{json, Value};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

pub const ARCH: Arch = X86_64;
pub const TAG: &str = "x86_64-7.2.8";
pub const KERNEL: &str = "7.2.8-joeyblog-bbrv3";
pub const OLD_KERNEL: &str = "6.1.0-old";
/// Every package of the fake release has these bytes.
pub const PACKAGE: &[u8] = b"package";

/// Knobs of the scripted host (defaults: a healthy Debian 12 amd64 VPS).
pub struct Host {
    pub fail_apt: usize,
    pub apt_calls: usize,
    pub simulation: String,
    pub fail_grub: bool,
    /// What `apt-get install` leaves behind (dpkg status of both packages).
    pub installed_status: String,
    /// `apt-get install` creates the new kernel's boot files.
    pub creates_files: bool,
    /// `update-grub` adds a menu entry for the new kernel.
    pub adds_entry: bool,
    pub deb_package: Option<String>,
    pub deb_arch: String,
    pub deb_version: String,
    pub fail_deb: bool,
    pub df_available: String,
    /// `df` answer for the download staging directory, when different.
    pub df_staging: Option<String>,
    pub virtualized: bool,
    pub detect_virt: Option<String>,
    pub secure_boot: Option<String>,
    pub machine: String,
}

impl Default for Host {
    fn default() -> Self {
        Host {
            fail_apt: 0,
            apt_calls: 0,
            simulation: format!(
                "Inst linux-image-{KERNEL} (7.2.8-1 localhost [amd64])\nInst linux-headers-{KERNEL} (7.2.8-1 localhost [amd64])\nConf linux-image-{KERNEL} (7.2.8-1 localhost [amd64])\n"
            ),
            fail_grub: false,
            installed_status: "install ok installed".into(),
            creates_files: true,
            adds_entry: true,
            deb_package: None,
            deb_arch: "amd64".into(),
            deb_version: "7.2.8-1".into(),
            fail_deb: false,
            df_available: "99999999".into(),
            df_staging: None,
            virtualized: false,
            detect_virt: None,
            secure_boot: None,
            machine: "x86_64".into(),
        }
    }
}

pub struct Fixture {
    pub dir: TempDir,
    pub ctx: Ctx,
    pub exec: Arc<FakeExec>,
    pub ui: Arc<ScriptedPrompter>,
    pub sysctl: FakeSysctl,
    pub host: Arc<Mutex<Host>>,
    pub github: FakeGithub,
    /// `modprobe tcp_bbr` makes `bbr` available.
    pub loads_bbr: Arc<AtomicBool>,
}

impl Fixture {
    /// Runtime `cubic`/`fq_codel` with `bbr` available, the persisted file
    /// `old config\n` (0600), unattended (`-y`) like v2's tests.
    pub fn new() -> Fixture {
        let dir = TempDir::new("bbr").unwrap();
        let (ctx, exec, ui) = Ctx::test(dir.path());
        ui.set_assume_yes(true);
        let sysctl = FakeSysctl::install(
            &exec,
            &[
                (CC, "cubic"),
                (QDISC, "fq_codel"),
                (AVAILABLE, "reno cubic bbr"),
            ],
        );
        std::fs::create_dir_all(&ctx.paths.system_root).unwrap();
        let conf = &ctx.paths.bbr_conf;
        std::fs::create_dir_all(conf.parent().unwrap()).unwrap();
        std::fs::write(conf, "old config\n").unwrap();
        std::fs::set_permissions(conf, std::fs::Permissions::from_mode(0o600)).unwrap();
        for tool in super::preflight::TOOLS {
            exec.provide(tool);
        }
        let loads_bbr = Arc::new(AtomicBool::new(false));
        let (loads, model) = (Arc::clone(&loads_bbr), sysctl.clone());
        exec.on_fn(
            |c| c.program_name() == "modprobe" && c.args == ["tcp_bbr"],
            move |_| {
                if loads.load(Ordering::SeqCst) {
                    model
                        .state()
                        .values
                        .insert(AVAILABLE.into(), "reno cubic bbr".into());
                }
                Ok(Output::success(""))
            },
        );
        let host = Arc::new(Mutex::new(Host::default()));
        script_host(&exec, &host, &ctx.paths.system_root);
        Fixture {
            dir,
            ctx,
            exec,
            ui,
            sysctl,
            host,
            github: FakeGithub::new(),
            loads_bbr,
        }
    }

    pub fn host(&self) -> MutexGuard<'_, Host> {
        self.host.lock().unwrap()
    }

    pub fn session(&self) -> Session<'_> {
        Session {
            ctx: &self.ctx,
            fetcher: &self.github,
            is_root: true,
        }
    }

    pub fn at(&self, path: &str) -> std::path::PathBuf {
        self.ctx.paths.system(path)
    }

    pub fn write(&self, path: &str, content: &[u8]) {
        let file = self.at(path);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, content).unwrap();
    }

    /// Boot files (vmlinuz, initrd, modules) and a GRUB entry for `kernel`.
    pub fn boot(&self, kernel: &str) {
        boot_files(&self.ctx.paths.system_root, kernel);
        let grub = self.at("/boot/grub/grub.cfg");
        let mut text = std::fs::read_to_string(&grub).unwrap_or_default();
        text.push_str(&format!("linux /boot/vmlinuz-{kernel} root=test\n"));
        std::fs::create_dir_all(grub.parent().unwrap()).unwrap();
        std::fs::write(grub, text).unwrap();
    }

    /// A host that passes every preflight check.
    pub fn eligible(&self) {
        self.write("/etc/os-release", b"ID=debian\nVERSION_ID=\"12\"\n");
        self.boot(OLD_KERNEL);
    }

    /// Arguments of every recorded call of `program`.
    pub fn calls(&self, program: &str) -> Vec<Vec<String>> {
        self.exec
            .calls()
            .into_iter()
            .filter(|c| c.program_name() == program)
            .map(|c| c.args)
            .collect()
    }

    pub fn programs(&self) -> Vec<String> {
        self.exec.calls().iter().map(Cmd::program_name).collect()
    }

    /// Runtime values and the persisted file are exactly as at the start.
    pub fn assert_old_runtime(&self) {
        assert_eq!(self.sysctl.get(CC), "cubic");
        assert_eq!(self.sysctl.get(QDISC), "fq_codel");
        let conf = &self.ctx.paths.bbr_conf;
        assert_eq!(std::fs::read_to_string(conf).unwrap(), "old config\n");
        let mode = std::fs::metadata(conf).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    pub fn sysctl_writes(&self) -> usize {
        self.sysctl.state().writes.len()
    }
}

fn boot_files(root: &Path, kernel: &str) {
    for (path, content) in [
        (format!("boot/vmlinuz-{kernel}"), "kernel\n"),
        (format!("boot/initrd.img-{kernel}"), "initrd\n"),
    ] {
        let file = root.join(path);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, content).unwrap();
    }
    std::fs::create_dir_all(root.join(format!("lib/modules/{kernel}"))).unwrap();
}

/// Answers for every program BBR runs besides `sysctl`.
fn script_host(exec: &FakeExec, host: &Arc<Mutex<Host>>, root: &Path) {
    let host = Arc::clone(host);
    let root = root.to_path_buf();
    exec.on_fn(
        |c| c.program_name() != "sysctl",
        move |c| Ok(answer(&mut host.lock().unwrap(), &root, c)),
    );
}

fn failure() -> Output {
    Output::failure(1, "injected failure")
}

fn answer(host: &mut Host, root: &Path, c: &Cmd) -> Output {
    let arg = |n: usize| c.args.get(n).map(String::as_str).unwrap_or_default();
    match c.program_name().as_str() {
        "uname" if arg(0) == "-m" => Output::success(format!("{}\n", host.machine)),
        "uname" => Output::success(format!("{OLD_KERNEL}\n")),
        "systemd-detect-virt" if arg(0) == "--container" => {
            if host.virtualized {
                Output::success("lxc\n")
            } else {
                failure()
            }
        }
        "systemd-detect-virt" => match &host.detect_virt {
            Some(v) => Output::success(format!("{v}\n")),
            None => failure(),
        },
        "modprobe" => Output::success(""),
        "modinfo" => Output::success("3\n"),
        "tc" => Output::success("qdisc fq_codel 0: root\n"),
        "mokutil" => host
            .secure_boot
            .clone()
            .map(Output::success)
            .unwrap_or_else(failure),
        "df" => {
            let staging = c.args.iter().any(|a| a.contains("onebox-download-"));
            let available = match (&host.df_staging, staging) {
                (Some(value), true) => value,
                _ => &host.df_available,
            };
            Output::success(format!(
                "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/test 999999999 0 {available} 0% /\n"
            ))
        }
        "dpkg-deb" => dpkg_deb(host, arg(1), arg(2)),
        "dpkg-query" => Output::success(host.installed_status.clone()),
        "dpkg" => Output::success("amd64\n"),
        "apt-get" => apt(host, root, c),
        "update-grub" => update_grub(host, root),
        _ => Output::failure(
            127,
            format!("test blocked unexpected program: {}", c.display()),
        ),
    }
}

fn dpkg_deb(host: &Host, file: &str, field: &str) -> Output {
    if host.fail_deb {
        return failure();
    }
    let name = Path::new(file)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    match field {
        "Package" => Output::success(
            host.deb_package
                .clone()
                .unwrap_or_else(|| name.split('_').next().unwrap_or_default().to_string()),
        ),
        "Architecture" => Output::success(host.deb_arch.clone()),
        "Version" => Output::success(host.deb_version.clone()),
        _ => failure(),
    }
}

fn apt(host: &mut Host, root: &Path, c: &Cmd) -> Output {
    host.apt_calls += 1;
    if host.apt_calls == host.fail_apt {
        return failure();
    }
    if c.args.iter().any(|a| a == "--simulate") {
        return Output::success(host.simulation.clone());
    }
    if host.creates_files {
        boot_files(root, KERNEL);
    }
    Output::success("")
}

fn update_grub(host: &Host, root: &Path) -> Output {
    if host.fail_grub {
        return failure();
    }
    if host.adds_entry {
        let grub = root.join("boot/grub/grub.cfg");
        let mut text = std::fs::read_to_string(&grub).unwrap_or_default();
        text.push_str(&format!("\tlinux\t/boot/vmlinuz-{KERNEL} root=UUID=x ro\n"));
        std::fs::write(grub, text).unwrap();
    }
    Output::success("")
}

/// The fake release document for [`TAG`].
pub fn release() -> Value {
    let digest = crate::sys::fs::sha256_hex(PACKAGE);
    let assets: Vec<Value> = ["image", "headers"]
        .iter()
        .map(|kind| {
            let name = format!("linux-{kind}-{KERNEL}_7.2.8-1_amd64.deb");
            json!({
                "name": name,
                "digest": format!("sha256:{digest}"),
                "size": PACKAGE.len(),
                "browser_download_url": format!("https://github.com/{REPO}/releases/download/{TAG}/{name}"),
            })
        })
        .collect();
    json!({"tag_name": TAG, "draft": false, "prerelease": false, "assets": assets})
}

/// A fake GitHub: the release list pages, the [`release`] document and
/// package bytes; records every request.
pub struct FakeGithub {
    pub pages: Mutex<Vec<Value>>,
    pub release: Mutex<Value>,
    pub package: Mutex<Vec<u8>>,
    pub requests: Mutex<Vec<String>>,
}

impl FakeGithub {
    pub fn new() -> FakeGithub {
        FakeGithub {
            pages: Mutex::new(vec![json!([
                {"tag_name": TAG, "draft": false, "prerelease": false}
            ])]),
            release: Mutex::new(release()),
            package: Mutex::new(PACKAGE.to_vec()),
            requests: Mutex::new(Vec::new()),
        }
    }

    pub fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

impl Fetcher for FakeGithub {
    fn json(&self, _ctx: &Ctx, url: &str) -> Result<Value> {
        self.requests.lock().unwrap().push(url.to_string());
        if url == tag_url(TAG) {
            return Ok(self.release.lock().unwrap().clone());
        }
        let page = url
            .rsplit_once("&page=")
            .and_then(|(_, p)| p.parse::<usize>().ok())
            .ok_or_else(|| Error::msg(format!("GitHub API 请求失败 (HTTP 404): {url}")))?;
        Ok(self
            .pages
            .lock()
            .unwrap()
            .get(page - 1)
            .cloned()
            .unwrap_or_else(|| json!([])))
    }

    fn download(&self, _ctx: &Ctx, url: &str, dest: &Path, _size: u64) -> Result<()> {
        self.requests.lock().unwrap().push(url.to_string());
        std::fs::write(dest, &*self.package.lock().unwrap()).map_err(|e| Error::io(dest, e))
    }
}
