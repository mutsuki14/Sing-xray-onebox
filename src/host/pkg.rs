//! Distro package installation (apt-get/dnf/yum/apk/pacman/zypper),
//! non-interactive, with the installer's output streamed to the terminal.
//!
//! The first available manager wins, in this order (spec B §3.1):
//!
//! | manager | command | `cron` | `iproute2` |
//! |---|---|---|---|
//! | apt-get | `apt-get update` (once per process) + `apt-get -o DPkg::Lock::Timeout=60 install -y PKG` | `cron` | — |
//! | dnf | `dnf install -y PKG` | `cronie` | `iproute` |
//! | yum | `yum install -y PKG` | `cronie` | `iproute` |
//! | apk | `apk add --no-cache PKG` | `dcron` | — |
//! | pacman | `pacman -Sy --noconfirm PKG` | `cronie` | — |
//! | zypper | `zypper --non-interactive install PKG` | `cron` | — |
//!
//! (`cron`, `cronie` and `crontab` all name "the cron package".)
//!
//! Changes from v2:
//! - `apt-get update` runs once per process instead of before every
//!   package, and its failure (one broken third-party repository) is a
//!   warning: the install itself decides.
//! - apt runs with `DEBIAN_FRONTEND=noninteractive` and keeps existing
//!   configuration files (`--force-confdef --force-confold`), so neither
//!   debconf nor dpkg can stop at a prompt; v2 could hang or fail there.
//! - installer output is streamed instead of captured, so long installs
//!   show progress; each run is bounded by a 30-minute timeout.
//! - a missing `ID` in os-release is shown as `linux` in the
//!   "no package manager" message instead of an empty prefix.

use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::host::os::{self, OsInfo};
use crate::sys::exec::Cmd;
use crate::ui::out;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Upper bound for one package-manager run.
const INSTALL_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// Whether `apt-get update` already ran in this process. An atomic memo
/// (not shared state anyone reads back): at worst a second update runs.
static APT_REFRESHED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Manager {
    AptGet,
    Dnf,
    Yum,
    Apk,
    Pacman,
    Zypper,
}

impl Manager {
    /// Detection priority (v2 order).
    pub const ALL: [Manager; 6] = [
        Manager::AptGet,
        Manager::Dnf,
        Manager::Yum,
        Manager::Apk,
        Manager::Pacman,
        Manager::Zypper,
    ];

    pub fn program(self) -> &'static str {
        match self {
            Manager::AptGet => "apt-get",
            Manager::Dnf => "dnf",
            Manager::Yum => "yum",
            Manager::Apk => "apk",
            Manager::Pacman => "pacman",
            Manager::Zypper => "zypper",
        }
    }

    /// The first manager found on PATH.
    pub fn detect(ctx: &Ctx) -> Option<Manager> {
        Manager::ALL.into_iter().find(|m| ctx.has(m.program()))
    }

    /// The distro's name for a generic package name.
    pub fn package_name(self, package: &str) -> &str {
        let cron = matches!(package, "cron" | "cronie" | "crontab");
        match self {
            Manager::AptGet | Manager::Zypper if cron => "cron",
            Manager::Dnf | Manager::Yum | Manager::Pacman if cron => "cronie",
            Manager::Apk if cron => "dcron",
            Manager::Dnf | Manager::Yum if package == "iproute2" => "iproute",
            _ => package,
        }
    }

    /// The install command for `package` (already mapped or not).
    pub fn install_cmd(self, package: &str) -> Cmd {
        let name = self.package_name(package);
        let cmd = match self {
            Manager::AptGet => apt("apt-get").args([
                "-o",
                "DPkg::Lock::Timeout=60",
                "-o",
                "Dpkg::Options::=--force-confdef",
                "-o",
                "Dpkg::Options::=--force-confold",
                "install",
                "-y",
                name,
            ]),
            Manager::Dnf | Manager::Yum => Cmd::new(self.program()).args(["install", "-y", name]),
            Manager::Apk => Cmd::new("apk").args(["add", "--no-cache", name]),
            Manager::Pacman => Cmd::new("pacman").args(["-Sy", "--noconfirm", name]),
            Manager::Zypper => Cmd::new("zypper").args(["--non-interactive", "install", name]),
        };
        cmd.stream().timeout(INSTALL_TIMEOUT)
    }

    /// The index refresh that must precede the first install (apt only).
    pub fn refresh_cmd(self) -> Option<Cmd> {
        (self == Manager::AptGet).then(|| {
            apt("apt-get")
                .arg("update")
                .stream()
                .timeout(INSTALL_TIMEOUT)
        })
    }
}

impl std::fmt::Display for Manager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.program())
    }
}

fn apt(program: &str) -> Cmd {
    Cmd::new(program).env("DEBIAN_FRONTEND", "noninteractive")
}

/// Make sure `command` is on PATH, installing `package` when it is not
/// (root required then).
pub fn ensure(ctx: &Ctx, command: &str, package: &str) -> Result<()> {
    ensure_as(ctx, command, package, os::is_root())
}

/// [`ensure`] with the privilege fact injected (callers' tests).
pub fn ensure_as(ctx: &Ctx, command: &str, package: &str, root: bool) -> Result<()> {
    ensure_with(ctx, command, package, root, &APT_REFRESHED)
}

/// [`ensure`] with the privilege fact and the apt-refresh memo injected.
pub fn ensure_with(
    ctx: &Ctx,
    command: &str,
    package: &str,
    root: bool,
    refreshed: &AtomicBool,
) -> Result<()> {
    if ctx.has(command) {
        return Ok(());
    }
    os::require_root_with(root)?;
    let manager = Manager::detect(ctx).ok_or_else(|| {
        Error::msg(format!(
            "{}: 未找到受支持的包管理器，请先安装 {package}",
            OsInfo::load(ctx).label()
        ))
    })?;
    install_with(ctx, manager, package, refreshed)?;
    if !ctx.has(command) {
        return Err(Error::msg(format!("安装后仍未找到 {command}")));
    }
    Ok(())
}

/// Install `package` with `manager`, refreshing the apt index first if
/// this process has not done so yet.
fn install_with(ctx: &Ctx, manager: Manager, package: &str, refreshed: &AtomicBool) -> Result<()> {
    if let Some(refresh) = manager.refresh_cmd() {
        if !refreshed.swap(true, Ordering::SeqCst) {
            out::info("正在更新软件包索引（apt-get update）…");
            let result = ctx.run(&refresh)?;
            if !result.ok() {
                out::warn(format!(
                    "apt-get update 失败 ({})，继续尝试安装 {package}",
                    result.code
                ));
            }
        }
    }
    let name = manager.package_name(package);
    out::info(format!("正在安装 {name}（{manager}）…"));
    let cmd = manager.install_cmd(package);
    let result = ctx.run(&cmd)?;
    if result.ok() {
        return Ok(());
    }
    Err(Error::Command {
        program: cmd.program_name(),
        code: result.code,
        detail: result.stderr,
    }
    .wrap(format!("安装 {name} 失败")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::exec::{FakeExec, Output};
    use crate::sys::fs::TempDir;
    use std::sync::Arc;

    fn setup(managers: &[&str]) -> (TempDir, Ctx, Arc<FakeExec>) {
        let dir = TempDir::new("pkg").unwrap();
        let (ctx, exec, _) = Ctx::test(dir.path());
        for m in managers {
            exec.provide(m);
        }
        (dir, ctx, exec)
    }

    /// `program … package` succeeds and makes `command` appear on PATH.
    fn installs(
        exec: &Arc<FakeExec>,
        program: &'static str,
        package: &'static str,
        command: &'static str,
    ) {
        let fake = Arc::clone(exec);
        exec.on_fn(
            move |cmd| cmd.program == program && cmd.args.last().is_some_and(|a| a == package),
            move |_| {
                fake.provide(command);
                Ok(Output::success(""))
            },
        );
    }

    #[test]
    fn package_name_mapping() {
        let cases = [
            (Manager::AptGet, "crontab", "cron"),
            (Manager::AptGet, "iproute2", "iproute2"),
            (Manager::Dnf, "cron", "cronie"),
            (Manager::Yum, "iproute2", "iproute"),
            (Manager::Dnf, "iproute2", "iproute"),
            (Manager::Apk, "cronie", "dcron"),
            (Manager::Apk, "iproute2", "iproute2"),
            (Manager::Pacman, "crontab", "cronie"),
            (Manager::Zypper, "cronie", "cron"),
            (Manager::Zypper, "nginx", "nginx"),
        ];
        for (manager, package, want) in cases {
            assert_eq!(manager.package_name(package), want, "{manager} {package}");
        }
    }

    #[test]
    fn install_commands_match_the_table() {
        let cases = [
            (
                Manager::AptGet,
                "apt-get -o DPkg::Lock::Timeout=60 -o Dpkg::Options::=--force-confdef \
                 -o Dpkg::Options::=--force-confold install -y cron",
            ),
            (Manager::Dnf, "dnf install -y cronie"),
            (Manager::Yum, "yum install -y cronie"),
            (Manager::Apk, "apk add --no-cache dcron"),
            (Manager::Pacman, "pacman -Sy --noconfirm cronie"),
            (Manager::Zypper, "zypper --non-interactive install cron"),
        ];
        for (manager, want) in cases {
            let cmd = manager.install_cmd("crontab");
            assert_eq!(cmd.display(), want);
            assert!(cmd.stream && cmd.timeout == Some(INSTALL_TIMEOUT));
            let noninteractive = cmd
                .env
                .contains(&("DEBIAN_FRONTEND".into(), "noninteractive".into()));
            assert_eq!(noninteractive, manager == Manager::AptGet);
            assert_eq!(manager.refresh_cmd().is_some(), manager == Manager::AptGet);
        }
        let refresh = Manager::AptGet.refresh_cmd().unwrap();
        assert_eq!(refresh.display(), "apt-get update");
        assert_eq!(
            refresh.env,
            [("DEBIAN_FRONTEND".into(), "noninteractive".into())]
        );
    }

    #[test]
    fn detection_follows_priority() {
        let (_d, ctx, _) = setup(&["zypper", "yum", "dnf"]);
        assert_eq!(Manager::detect(&ctx), Some(Manager::Dnf));
        let (_d, ctx, _) = setup(&[]);
        assert_eq!(Manager::detect(&ctx), None);
    }

    #[test]
    fn present_command_needs_nothing() {
        let (_d, ctx, exec) = setup(&["curl"]);
        ensure_with(&ctx, "curl", "curl", false, &AtomicBool::new(false)).unwrap();
        assert!(exec.history().is_empty(), "no root check, no commands");
    }

    #[test]
    fn missing_command_requires_root() {
        let (_d, ctx, _) = setup(&["apt-get"]);
        let err = ensure_with(&ctx, "nginx", "nginx", false, &AtomicBool::new(false)).unwrap_err();
        assert_eq!(err.to_string(), "此操作需要 root 权限");
    }

    #[test]
    fn apt_updates_once_per_process() {
        let (_d, ctx, exec) = setup(&["apt-get"]);
        exec.on("apt-get", &["update"], Output::success(""));
        installs(&exec, "apt-get", "iproute2", "ip");
        installs(&exec, "apt-get", "openssl", "openssl");
        let refreshed = AtomicBool::new(false);
        ensure_with(&ctx, "ip", "iproute2", true, &refreshed).unwrap();
        // A second package in the same process skips the index refresh.
        ensure_with(&ctx, "openssl", "openssl", true, &refreshed).unwrap();
        let history = exec.history();
        assert_eq!(history.len(), 3);
        assert_eq!(history[0], "apt-get update");
        assert!(history[1].ends_with("install -y iproute2"));
        assert!(history[2].ends_with("install -y openssl"));
        assert!(refreshed.load(Ordering::SeqCst));
    }

    #[test]
    fn failed_apt_update_is_not_fatal() {
        let (_d, ctx, exec) = setup(&["apt-get"]);
        exec.on("apt-get", &["update"], Output::failure(100, ""));
        installs(&exec, "apt-get", "curl", "curl");
        ensure_with(&ctx, "curl", "curl", true, &AtomicBool::new(false)).unwrap();
        assert_eq!(exec.history().len(), 2);
    }

    #[test]
    fn rpm_family_maps_iproute() {
        let (_d, ctx, exec) = setup(&["yum"]);
        installs(&exec, "yum", "iproute", "ip");
        ensure_with(&ctx, "ip", "iproute2", true, &AtomicBool::new(false)).unwrap();
        assert_eq!(exec.history(), ["yum install -y iproute"]);
    }

    #[test]
    fn install_failure_and_missing_command_after_install() {
        let (_d, ctx, exec) = setup(&["apk"]);
        exec.on("apk", &[], Output::failure(1, ""));
        let err = ensure_with(&ctx, "nginx", "nginx", true, &AtomicBool::new(false)).unwrap_err();
        assert_eq!(err.to_string(), "安装 nginx 失败: apk 执行失败 (1)");

        let (_d, ctx, exec) = setup(&["pacman"]);
        exec.on("pacman", &[], Output::success(""));
        let err = ensure_with(&ctx, "crontab", "cron", true, &AtomicBool::new(false)).unwrap_err();
        assert_eq!(err.to_string(), "安装后仍未找到 crontab");
        assert_eq!(exec.history(), ["pacman -Sy --noconfirm cronie"]);
    }

    #[test]
    fn no_package_manager_names_the_os() {
        let (_d, ctx, _) = setup(&[]);
        let err = ensure_with(&ctx, "curl", "curl", true, &AtomicBool::new(false)).unwrap_err();
        assert_eq!(
            err.to_string(),
            "linux: 未找到受支持的包管理器，请先安装 curl"
        );
        let release = ctx.paths.system("/etc/os-release");
        std::fs::create_dir_all(release.parent().unwrap()).unwrap();
        std::fs::write(&release, "ID=gentoo\n").unwrap();
        let err = ensure_with(&ctx, "curl", "curl", true, &AtomicBool::new(false)).unwrap_err();
        assert_eq!(
            err.to_string(),
            "gentoo: 未找到受支持的包管理器，请先安装 curl"
        );
    }
}
