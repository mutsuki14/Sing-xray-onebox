//! Distro package installation (apt-get/dnf/yum/apk/pacman/zypper),
//! non-interactive, with the installer's output streamed to the terminal.
//!
//! The first available manager wins, in this order (spec B §3.1):
//!
//! | manager | command | `cron` | `iproute2` |
//! |---|---|---|---|
//! | apt-get | `apt-get update` (once per batch) + `apt-get -o DPkg::Lock::Timeout=60 install -y PKG` | `cron` | — |
//! | dnf | `dnf install -y PKG` | `cronie` | `iproute` |
//! | yum | `yum install -y PKG` | `cronie` | `iproute` |
//! | apk | `apk add --no-cache PKG` | `dcron` | — |
//! | pacman | `pacman -Sy --noconfirm PKG` | `cronie` | — |
//! | zypper | `zypper --non-interactive install PKG` | `cron` | — |
//!
//! (`cron`, `cronie` and `crontab` all name "the cron package".)
//!
//! Changes from v2:
//! - `apt-get update` runs once per batch ([`Installer`], [`ensure_all`])
//!   instead of before every package, and only when something must be
//!   installed. Its failure (one broken third-party repository) is a
//!   warning — the install itself decides — and it is tried again before
//!   the batch's next install. No global state: the memo lives in the
//!   batch.
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
use std::time::Duration;

/// Upper bound for one package-manager run.
const INSTALL_TIMEOUT: Duration = Duration::from_secs(30 * 60);

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
/// (root required then). Several packages in one flow: [`ensure_all`].
pub fn ensure(ctx: &Ctx, command: &str, package: &str) -> Result<()> {
    Installer::new(ctx).ensure(command, package)
}

/// [`ensure()`] with the privilege fact injected (callers' tests).
pub fn ensure_as(ctx: &Ctx, command: &str, package: &str, root: bool) -> Result<()> {
    Installer::with_root(ctx, root).ensure(command, package)
}

/// [`ensure()`] for `(command, package)` pairs, in order, sharing one
/// package-index refresh.
pub fn ensure_all(ctx: &Ctx, wanted: &[(&str, &str)]) -> Result<()> {
    let mut installer = Installer::new(ctx);
    wanted
        .iter()
        .try_for_each(|(command, package)| installer.ensure(command, package))
}

/// A batch of installs that refreshes the apt index at most once (after
/// a successful refresh).
pub struct Installer<'a> {
    ctx: &'a Ctx,
    root: bool,
    refreshed: bool,
}

impl<'a> Installer<'a> {
    pub fn new(ctx: &'a Ctx) -> Installer<'a> {
        Installer::with_root(ctx, os::is_root())
    }

    /// With the privilege fact injected (tests).
    pub fn with_root(ctx: &'a Ctx, root: bool) -> Installer<'a> {
        Installer {
            ctx,
            root,
            refreshed: false,
        }
    }

    /// Make sure `command` is on PATH, installing `package` when it is not.
    pub fn ensure(&mut self, command: &str, package: &str) -> Result<()> {
        let ctx = self.ctx;
        if ctx.has(command) {
            return Ok(());
        }
        os::require_root_with(self.root)?;
        let manager = Manager::detect(ctx).ok_or_else(|| {
            Error::msg(format!(
                "{}: 未找到受支持的包管理器，请先安装 {package}",
                OsInfo::load(ctx).label()
            ))
        })?;
        self.install(manager, package)?;
        if !ctx.has(command) {
            return Err(Error::msg(format!("安装后仍未找到 {command}")));
        }
        Ok(())
    }

    /// Install `package` with `manager`, refreshing the apt index first
    /// unless this batch already did so successfully.
    fn install(&mut self, manager: Manager, package: &str) -> Result<()> {
        let ctx = self.ctx;
        if let Some(refresh) = manager.refresh_cmd().filter(|_| !self.refreshed) {
            out::info("正在更新软件包索引（apt-get update）…");
            let result = ctx.run(&refresh)?;
            if result.ok() {
                self.refreshed = true;
            } else {
                out::warn(format!(
                    "apt-get update 失败 ({})，继续尝试安装 {package}",
                    result.code
                ));
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
        ensure_as(&ctx, "curl", "curl", false).unwrap();
        assert!(exec.history().is_empty(), "no root check, no commands");
    }

    #[test]
    fn missing_command_requires_root() {
        let (_d, ctx, _) = setup(&["apt-get"]);
        let err = ensure_as(&ctx, "nginx", "nginx", false).unwrap_err();
        assert_eq!(err.to_string(), "此操作需要 root 权限");
    }

    #[test]
    fn apt_updates_once_per_batch() {
        let (_d, ctx, exec) = setup(&["apt-get"]);
        exec.on("apt-get", &["update"], Output::success(""));
        installs(&exec, "apt-get", "iproute2", "ip");
        installs(&exec, "apt-get", "openssl", "openssl");
        let mut batch = Installer::with_root(&ctx, true);
        batch.ensure("ip", "iproute2").unwrap();
        // A second package in the same batch skips the index refresh.
        batch.ensure("openssl", "openssl").unwrap();
        let history = exec.history();
        assert_eq!(history.len(), 3);
        assert_eq!(history[0], "apt-get update");
        assert!(history[1].ends_with("install -y iproute2"));
        assert!(history[2].ends_with("install -y openssl"));
        // Present commands need nothing, not even a refresh.
        exec.clear_history();
        Installer::with_root(&ctx, true)
            .ensure("ip", "iproute2")
            .unwrap();
        assert!(exec.history().is_empty());
    }

    #[test]
    fn failed_apt_update_is_not_fatal_and_is_retried() {
        let (_d, ctx, exec) = setup(&["apt-get"]);
        exec.on("apt-get", &["update"], Output::failure(100, ""));
        installs(&exec, "apt-get", "curl", "curl");
        installs(&exec, "apt-get", "socat", "socat");
        let mut batch = Installer::with_root(&ctx, true);
        batch.ensure("curl", "curl").unwrap();
        batch.ensure("socat", "socat").unwrap();
        let updates = exec
            .history()
            .iter()
            .filter(|c| c.as_str() == "apt-get update")
            .count();
        assert_eq!(updates, 2, "a failed refresh is tried again");
        assert_eq!(exec.history().len(), 4);
    }

    #[test]
    fn separate_calls_are_separate_batches() {
        let (_d, ctx, exec) = setup(&["apt-get"]);
        exec.on("apt-get", &["update"], Output::success(""));
        installs(&exec, "apt-get", "curl", "curl");
        exec.on(
            "apt-get",
            &[],
            Output::failure(100, "E: Unable to locate package"),
        );
        let err = Installer::with_root(&ctx, true)
            .ensure("curl", "curl")
            .and_then(|()| ensure_as(&ctx, "nope", "nope", true))
            .unwrap_err();
        assert!(err.to_string().starts_with("安装 nope 失败"), "{err}");
        let refreshes = exec
            .history()
            .iter()
            .filter(|c| c.as_str() == "apt-get update")
            .count();
        assert_eq!(refreshes, 2, "separate calls are separate batches");
        let (_d, ctx, exec) = setup(&["curl", "openssl"]);
        ensure_all(&ctx, &[("curl", "curl"), ("openssl", "openssl")]).unwrap();
        assert!(exec.history().is_empty());
    }

    #[test]
    fn rpm_family_maps_iproute() {
        let (_d, ctx, exec) = setup(&["yum"]);
        installs(&exec, "yum", "iproute", "ip");
        ensure_as(&ctx, "ip", "iproute2", true).unwrap();
        assert_eq!(exec.history(), ["yum install -y iproute"]);
    }

    #[test]
    fn install_failure_and_missing_command_after_install() {
        let (_d, ctx, exec) = setup(&["apk"]);
        exec.on("apk", &[], Output::failure(1, ""));
        let err = ensure_as(&ctx, "nginx", "nginx", true).unwrap_err();
        assert_eq!(err.to_string(), "安装 nginx 失败: apk 执行失败 (1)");

        let (_d, ctx, exec) = setup(&["pacman"]);
        exec.on("pacman", &[], Output::success(""));
        let err = ensure_as(&ctx, "crontab", "cron", true).unwrap_err();
        assert_eq!(err.to_string(), "安装后仍未找到 crontab");
        assert_eq!(exec.history(), ["pacman -Sy --noconfirm cronie"]);
    }

    #[test]
    fn no_package_manager_names_the_os() {
        let (_d, ctx, _) = setup(&[]);
        let err = ensure_as(&ctx, "curl", "curl", true).unwrap_err();
        assert_eq!(
            err.to_string(),
            "linux: 未找到受支持的包管理器，请先安装 curl"
        );
        let release = ctx.paths.system("/etc/os-release");
        std::fs::create_dir_all(release.parent().unwrap()).unwrap();
        std::fs::write(&release, "ID=gentoo\n").unwrap();
        let err = ensure_as(&ctx, "curl", "curl", true).unwrap_err();
        assert_eq!(
            err.to_string(),
            "gentoo: 未找到受支持的包管理器，请先安装 curl"
        );
    }
}
