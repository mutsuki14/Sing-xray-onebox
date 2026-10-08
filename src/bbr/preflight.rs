//! BBRv3 kernel install eligibility, as a list of individual checks in v2's
//! order with v2's thresholds: container/WSL, Debian 12+ / Ubuntu 24.04+,
//! x86_64/aarch64, required tools, dpkg architecture, a bootable fallback
//! (GRUB + current kernel, initrd and modules, no device tree), Secure Boot
//! disabled, 512 MiB free on /boot and 2 GiB on /.
//!
//! Changes from v2: every check is reported on its own line (v2 stopped at
//! the first failure with one generic message for five different boot
//! problems, I-8.1#4); the first failure's message is still the error.
//! Tools are looked up through `Ctx::has`, so tests and cron's PATH agree
//! (I-8.1#3). `/proc/version` and the kernel release are scanned only for
//! WSL markers: they describe the host kernel's build machine, so words like
//! `docker` there were false positives (I-8.1#14); container words are still
//! looked for in `/proc/1/cgroup`.

use super::release::Arch;
use super::shown;
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::sys::exec::Cmd;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Free space needed on /boot and / (KiB).
pub const BOOT_MIN_KIB: u64 = 524_288;
pub const ROOT_MIN_KIB: u64 = 2_097_152;
/// Programs the install needs.
pub const TOOLS: [&str; 6] = [
    "apt-get",
    "dpkg",
    "dpkg-deb",
    "dpkg-query",
    "update-grub",
    "df",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Pass(String),
    Fail(String),
    /// Not checked because an earlier check failed.
    Skip(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Check {
    pub label: &'static str,
    pub outcome: Outcome,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// The detected architecture (also needed to pick releases).
    pub arch: Option<Arch>,
    pub checks: Vec<Check>,
}

impl Report {
    /// The first failure's message (v2's error for the same host).
    pub fn first_failure(&self) -> Option<&str> {
        self.checks.iter().find_map(|c| match &c.outcome {
            Outcome::Fail(message) => Some(message.as_str()),
            _ => None,
        })
    }

    pub fn passed(&self) -> bool {
        self.checks
            .iter()
            .all(|c| matches!(c.outcome, Outcome::Pass(_)))
    }

    /// `Ok(arch)` when every check passed, else the first failure.
    pub fn result(&self) -> Result<Arch> {
        if let Some(message) = self.first_failure() {
            return Err(Error::msg(message));
        }
        self.arch
            .filter(|_| self.passed())
            .ok_or_else(|| Error::msg("BBRv3 内核安装检查未完成"))
    }

    /// One line per check: `[通过] 系统版本: Debian 12`.
    pub fn render(&self) -> String {
        self.checks
            .iter()
            .map(|c| {
                let (tag, text) = match &c.outcome {
                    Outcome::Pass(t) => ("[通过]", t),
                    Outcome::Fail(t) => ("[失败]", t),
                    Outcome::Skip(t) => ("[跳过]", t),
                };
                format!("{tag} {}: {text}", c.label)
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Run every check (read-only: only probes files and runs queries).
pub fn run(ctx: &Ctx) -> Report {
    let mut checks = Vec::new();
    let mut push = |label, result| {
        checks.push(Check {
            label,
            outcome: result,
        })
    };
    push("运行环境", outcome(check_container(ctx)));
    push(
        "系统版本",
        outcome(read_os_release(ctx).and_then(|f| supported_os(&f))),
    );
    let arch = Arch::detect(ctx);
    push(
        "内核架构",
        outcome(
            arch.as_ref()
                .map(|a| format!("{} / {}", a.tag, a.deb))
                .map_err(clone_error),
        ),
    );
    let tools = check_tools(ctx);
    let tools_ok = tools.is_ok();
    push("安装工具", outcome(tools));
    push(
        "软件包架构",
        match (&arch, tools_ok) {
            (Ok(arch), true) => outcome(check_dpkg_arch(ctx, *arch)),
            _ => Outcome::Skip("需要先通过架构与工具检查".into()),
        },
    );
    push("引导回退", outcome(check_boot(ctx)));
    push("Secure Boot", outcome(secure_boot_disabled(ctx)));
    let root = ctx.paths.system("/");
    push(
        "/boot 空间",
        outcome(space(ctx, &ctx.paths.system("/boot"), BOOT_MIN_KIB)),
    );
    push("根分区空间", outcome(space(ctx, &root, ROOT_MIN_KIB)));
    Report {
        arch: arch.ok(),
        checks,
    }
}

fn outcome(result: Result<String>) -> Outcome {
    match result {
        Ok(detail) => Outcome::Pass(detail),
        Err(e) => Outcome::Fail(e.to_string()),
    }
}

fn clone_error(e: &Error) -> Error {
    Error::msg(e.to_string())
}

fn exists(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// Containers and WSL share the host kernel.
fn check_container(ctx: &Ctx) -> Result<String> {
    if is_container(ctx) {
        Err(Error::msg(
            "容器/WSL 共享宿主机内核，不能在此安装 BBRv3 内核",
        ))
    } else {
        Ok("独立内核".into())
    }
}

pub fn is_container(ctx: &Ctx) -> bool {
    let at = |p: &str| ctx.paths.system(p);
    let virt = Cmd::new("systemd-detect-virt").args(["--container", "--quiet"]);
    if ctx.run(&virt).is_ok_and(|o| o.ok()) {
        return true;
    }
    if [".dockerenv", "run/.containerenv", "run/systemd/container"]
        .iter()
        .any(|p| exists(&at(p)))
        || is_openvz(ctx)
    {
        return true;
    }
    let lower = |p: &str| {
        std::fs::read_to_string(at(p))
            .unwrap_or_default()
            .to_ascii_lowercase()
    };
    let wsl = ["proc/version", "proc/sys/kernel/osrelease"]
        .iter()
        .any(|p| ["microsoft", "wsl"].iter().any(|w| lower(p).contains(w)));
    let cgroup = lower("proc/1/cgroup");
    wsl || ["docker", "lxc", "kubepods", "containerd", "libpod"]
        .iter()
        .any(|w| cgroup.contains(w))
}

/// OpenVZ: `/proc/vz` without `/proc/bc`.
pub fn is_openvz(ctx: &Ctx) -> bool {
    exists(&ctx.paths.system("/proc/vz")) && !exists(&ctx.paths.system("/proc/bc"))
}

/// `/etc/os-release` fields; values lose matching outer quotes (no escape
/// processing, like v2).
pub fn parse_os_release(text: &str) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        let quoted = value.len() >= 2
            && ((value.starts_with('"') && value.ends_with('"'))
                || (value.starts_with('\'') && value.ends_with('\'')));
        let value = if quoted {
            &value[1..value.len() - 1]
        } else {
            value
        };
        fields.insert(key.trim().to_string(), value.to_string());
    }
    fields
}

fn read_os_release(ctx: &Ctx) -> Result<BTreeMap<String, String>> {
    let path = ctx.paths.system("/etc/os-release");
    let text = std::fs::read_to_string(&path)
        .map_err(|e| Error::msg(format!("无法读取 /etc/os-release: {}", Error::from(e))))?;
    Ok(parse_os_release(&text))
}

/// Debian 12+ (codename fallback for testing/unstable) or Ubuntu 24.04+.
pub fn supported_os(fields: &BTreeMap<String, String>) -> Result<String> {
    let get = |k: &str| fields.get(k).map(String::as_str).unwrap_or_default();
    let id = get("ID");
    let version = match (id, get("VERSION_ID")) {
        ("debian", "") => match get("VERSION_CODENAME") {
            "bookworm" => "12",
            "trixie" => "13",
            "forky" => "14",
            "sid" | "unstable" => "999",
            _ => "",
        },
        (_, version) => version,
    };
    let mut parts = super::release::version_parts(version)
        .ok_or_else(|| Error::msg("系统版本未知，需要 Debian 12+ / Ubuntu 24.04+"))?;
    parts.resize(parts.len().max(2), 0);
    match id {
        "debian" if parts[0] >= 12 => Ok(format!("Debian {version}")),
        "ubuntu" if (parts[0], parts[1]) >= (24, 4) => Ok(format!("Ubuntu {version}")),
        _ => Err(Error::msg(
            "BBRv3 内核安装仅支持 Debian 12+ / Ubuntu 24.04+ (其他系统仍可启用自带 BBR)",
        )),
    }
}

fn check_tools(ctx: &Ctx) -> Result<String> {
    match TOOLS.iter().find(|t| !ctx.has(t)) {
        Some(missing) => Err(Error::msg(format!(
            "安装 BBRv3 缺少 {missing}，请先安装对应系统包"
        ))),
        None => Ok(TOOLS.join(" ")),
    }
}

fn check_dpkg_arch(ctx: &Ctx, arch: Arch) -> Result<String> {
    let deb = ctx.check(&Cmd::new("dpkg").arg("--print-architecture"))?;
    if deb.trim() == arch.deb {
        Ok(arch.deb.to_string())
    } else {
        Err(Error::msg("系统用户空间架构与内核架构不匹配"))
    }
}

/// The generic v2 message, followed by what exactly is missing.
fn boot_error(detail: &str) -> Error {
    Error::msg(format!(
        "仅支持已有 GRUB、当前内核/模块/initrd 可供回退的常规 VPS；不自动处理设备树、U-Boot 或厂商内核（{detail}）"
    ))
}

fn check_boot(ctx: &Ctx) -> Result<String> {
    let release = ctx
        .check(&Cmd::new("uname").arg("-r"))
        .map_err(|e| boot_error(&format!("无法读取运行内核版本: {e}")))?;
    let kernel = release.trim();
    boot_ready(ctx, kernel)?;
    Ok(format!("GRUB，可回退到 {kernel}"))
}

fn nonempty_file(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.len() > 0)
}

/// The boot files of `kernel` (`vmlinuz`, `initrd.img`, modules dir), or
/// the first one missing.
pub fn missing_kernel_file(ctx: &Ctx, kernel: &str) -> Option<PathBuf> {
    let at = |p: String| ctx.paths.system(&p);
    let vmlinuz = at(format!("/boot/vmlinuz-{kernel}"));
    let initrd = at(format!("/boot/initrd.img-{kernel}"));
    let modules = at(format!("/lib/modules/{kernel}"));
    if !nonempty_file(&vmlinuz) {
        Some(vmlinuz)
    } else if !nonempty_file(&initrd) {
        Some(initrd)
    } else if !modules.is_dir() {
        Some(modules)
    } else {
        None
    }
}

/// The running kernel must stay bootable as a fallback.
pub fn boot_ready(ctx: &Ctx, kernel: &str) -> Result<()> {
    let safe = !kernel.is_empty()
        && kernel
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b));
    if !safe {
        return Err(boot_error(&format!("运行内核名称无效: {kernel}")));
    }
    if exists(&ctx.paths.system("/proc/device-tree")) {
        return Err(boot_error("检测到设备树 /proc/device-tree"));
    }
    if !nonempty_file(&ctx.paths.system("/boot/grub/grub.cfg")) {
        return Err(boot_error("缺少 /boot/grub/grub.cfg"));
    }
    if let Some(missing) = missing_kernel_file(ctx, kernel) {
        return Err(boot_error(&format!("缺少 {}", shown(ctx, &missing))));
    }
    Ok(())
}

/// Fails closed: an enabled EFI variable wins; without a proven "disabled"
/// state (efivars or `mokutil --sb-state`) the state is unknown.
pub fn secure_boot_disabled(ctx: &Ctx) -> Result<String> {
    let efi = ctx.paths.system("/sys/firmware/efi");
    match std::fs::metadata(&efi) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok("传统 BIOS 引导".into()),
        Err(e) => return Err(Error::io(&efi, e)),
        Ok(_) => {}
    }
    let (mut disabled, mut unknown) = (false, false);
    if let Ok(entries) = std::fs::read_dir(efi.join("efivars")) {
        for entry in entries.flatten() {
            if !entry
                .file_name()
                .to_string_lossy()
                .starts_with("SecureBoot-")
            {
                continue;
            }
            match std::fs::read(entry.path())
                .ok()
                .and_then(|v| v.get(4).copied())
            {
                Some(0) => disabled = true,
                Some(1) => {
                    return Err(Error::msg(
                        "Secure Boot 已启用，不能安装未经本机信任签名的内核",
                    ))
                }
                _ => unknown = true,
            }
        }
    }
    if disabled && !unknown {
        return Ok("未启用".into());
    }
    let mok = ctx.run(&Cmd::new("mokutil").arg("--sb-state"));
    if let Some(out) = mok.ok().filter(|o| o.ok()) {
        let has = |line: &str| out.stdout.lines().any(|l| l.trim() == line);
        if has("SecureBoot disabled") && !has("SecureBoot enabled") {
            return Ok("未启用 (mokutil)".into());
        }
    }
    Err(Error::msg(
        "Secure Boot 状态不明，不能安装未经本机信任签名的内核",
    ))
}

/// `df -Pk -- path`: the 4th field of the second non-empty line must be at
/// least `minimum_kib`.
pub fn space(ctx: &Ctx, path: &Path, minimum_kib: u64) -> Result<String> {
    let label = shown(ctx, path);
    let failure = || {
        Error::msg(format!(
            "{label} 空间不足或无法读取 (至少需要 {minimum_kib} KiB 可用空间)"
        ))
    };
    let out = ctx
        .run(
            &Cmd::new("df")
                .args(["-Pk", "--"])
                .arg(path.to_string_lossy()),
        )
        .map_err(|_| failure())?;
    let available = out
        .ok()
        .then(|| {
            out.stdout
                .lines()
                .filter(|l| !l.trim().is_empty())
                .nth(1)
                .and_then(|l| l.split_whitespace().nth(3))
                .and_then(|v| v.parse::<u64>().ok())
        })
        .flatten();
    match available {
        Some(kib) if kib >= minimum_kib => Ok(format!("可用 {} MiB", kib / 1024)),
        _ => Err(failure()),
    }
}

#[cfg(test)]
mod tests;
