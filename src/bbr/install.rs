//! `bbr install [latest|TAG] [--max] [--apply]`: preview, then (with
//! `--apply`) download, verify and install a BBRv3 kernel image + headers.
//! Never reboots, never changes the GRUB default, never removes packages.
//!
//! Flow: preflight report → resolve the tag (validated before any URL) →
//! release manifest → plan + checks printed (preview ends here) → BBR lock →
//! download each package and verify size + SHA-256 before dpkg touches it,
//! then its `dpkg-deb` fields → `apt-get --simulate` shown → confirmation →
//! preflight again (the wait may be long) → `apt-get install` → dpkg status,
//! boot files, `update-grub`, GRUB entry → `last-install.tsv`.
//!
//! Changes from v2:
//! - the apt simulation runs and is summarized BEFORE the confirmation, so
//!   the user sees extra repository dependencies before agreeing (I-8.1#7);
//!   packages are therefore downloaded first;
//! - apt/dpkg output is streamed, `DEBIAN_FRONTEND=noninteractive` is set,
//!   and apt runs in its own session while Ctrl+C is ignored with a notice:
//!   interrupting dpkg mid-configure could leave the system unbootable
//!   (I-8.1#8);
//! - downloads are staged under `ONEBOX_BBR_DIR` (disk) instead of `$TMPDIR`
//!   (often a small tmpfs); stale staging directories are swept;
//! - a preview shows every eligibility check instead of only the first
//!   failure; preview needs no root (I-8.1#1/#4).

use super::net::Fetcher;
use super::preflight::{self, missing_kernel_file};
use super::release::{kernel_name, release_tags, tag_url, Arch, Asset, Manifest};
use super::{lock, Session, REPO};
use crate::error::{Error, Result};
use crate::sys::exec::{Cmd, Output};
use crate::sys::fs::{atomic_write, sha256_file, sweep_stale, TempDir};
use crate::sys::signal;
use crate::ui::out;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Extra free space needed in the staging directory (KiB).
const STAGING_SLACK_KIB: u64 = 262_144;
const STAGING_LABEL: &str = "download";
const RECORD: &str = "last-install.tsv";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallRequest {
    /// `latest` or a full release tag.
    pub desired: String,
    pub max: bool,
    pub apply: bool,
}

pub(super) fn install(session: &Session<'_>, req: &InstallRequest) -> Result<()> {
    let ctx = session.ctx;
    let report = preflight::run(ctx);
    let arch = report.arch.ok_or_else(|| {
        Error::msg(
            report
                .first_failure()
                .unwrap_or("Actions-bbr-v3 内核仅支持 x86_64 / aarch64"),
        )
    })?;
    let manifest = resolve(session.fetcher, ctx, req, arch)?;
    out::data(&plan_text(&manifest, req.max))?;
    out::data(&format!("安装检查:\n{}", report.render()))?;
    if let Some(failure) = report.first_failure() {
        return Err(Error::msg(failure));
    }
    if !req.apply {
        return out::data("预览完成；加 --apply 执行安装，无人值守同时加 -y。不会自动重启。");
    }
    apply(session, &manifest, arch)
}

/// Resolve `latest`, validate the tag, then fetch and check the manifest.
fn resolve(
    fetcher: &dyn Fetcher,
    ctx: &crate::ctx::Ctx,
    req: &InstallRequest,
    arch: Arch,
) -> Result<Manifest> {
    let tag = if req.desired == "latest" {
        let mut fetch = |url: &str| fetcher.json(ctx, url);
        release_tags(arch, req.max, &mut fetch)?
            .into_iter()
            .next()
            .ok_or_else(|| Error::msg("未找到可用的 BBRv3 Release"))?
    } else {
        req.desired.clone()
    };
    // Validate before the request so user input cannot alter the API path.
    kernel_name(&tag, arch, req.max)?;
    let data = fetcher.json(ctx, &tag_url(&tag))?;
    Manifest::parse(&data, &tag, arch, req.max)
}

/// The preview lines (v2 wording).
pub fn plan_text(manifest: &Manifest, max: bool) -> String {
    let mut lines = vec![
        format!("来源: https://github.com/{REPO}"),
        format!("Release: {}", manifest.tag),
        format!("目标内核: {}", manifest.kernel),
        format!(
            "下载合计: {} MiB；安装 image + headers，保留全部旧内核。",
            manifest.total().div_ceil(1_048_576)
        ),
    ];
    if max {
        lines.push("Max 为激进吞吐实验版，可能增加延迟、丢包和带宽争抢；仅用于自有链路实验".into());
    }
    lines.push("保留现有 GRUB 默认项设置；重启时可能需要在控制台手动选择新内核。".into());
    lines.join("\n")
}

fn apply(session: &Session<'_>, manifest: &Manifest, arch: Arch) -> Result<()> {
    let ctx = session.ctx;
    let _lock = lock(ctx)?;
    let _ = sweep_stale(
        &ctx.paths.bbr_dir,
        &format!("onebox-{STAGING_LABEL}-"),
        Duration::from_secs(24 * 3600),
    );
    let work = TempDir::new_in(&ctx.paths.bbr_dir, STAGING_LABEL)?;
    let needed = manifest.total().div_ceil(1024) + STAGING_SLACK_KIB;
    preflight::space(ctx, work.path(), needed)?;
    let mut packages = Vec::new();
    for asset in &manifest.assets {
        let file = work.join(&asset.name);
        out::info(format!("下载 {}", asset.name));
        session
            .fetcher
            .download(ctx, &asset.url, &file, asset.size)?;
        verify_package(ctx, &file, asset, arch)?;
        packages.push(file);
    }
    let simulation = simulate(ctx, &packages)?;
    out::data(&simulation_text(&simulation, manifest))?;
    confirm(session, &manifest.tag)?;
    let again = preflight::run(ctx);
    if again.arch != Some(arch) {
        return Err(Error::msg("确认期间系统架构发生变化，取消安装"));
    }
    if let Err(e) = again.result() {
        out::line(again.render());
        return Err(e);
    }
    install_kernel(session, &manifest.kernel, &packages)?;
    write_record(ctx, manifest);
    let running = ctx
        .check(&Cmd::new("uname").arg("-r"))
        .map(|k| k.trim().to_string())
        .ok()
        .filter(|k| !k.is_empty())
        .unwrap_or_else(|| "未知".into());
    out::data(&format!(
        "已安装 {}；当前仍运行 {running}。请手动重启，再执行 onebox bbr status / onebox bbr enable fq\n若新内核无法启动，请从 VPS 控制台的 GRUB Advanced options 选择保留的旧内核",
        manifest.kernel
    ))
}

fn confirm(session: &Session<'_>, tag: &str) -> Result<()> {
    let prompt = format!("安装 {tag}？请确认有 VPS 控制台与快照，安装后需手动重启");
    if session.ctx.ui.confirm(&prompt, false)? {
        Ok(())
    } else {
        Err(Error::msg("已取消 BBRv3 内核安装"))
    }
}

/// Size, then SHA-256 (dpkg-deb never sees unverified bytes), then the
/// package's own Package/Version/Architecture fields.
pub fn verify_package(ctx: &crate::ctx::Ctx, file: &Path, asset: &Asset, arch: Arch) -> Result<()> {
    let regular =
        std::fs::symlink_metadata(file).is_ok_and(|m| m.is_file() && m.len() == asset.size);
    if !regular {
        return Err(Error::msg("内核包类型或大小不匹配，未执行安装"));
    }
    if sha256_file(file)? != asset.digest {
        return Err(Error::msg("内核包 SHA-256 不匹配，未执行安装"));
    }
    let field = |name: &str| -> Result<String> {
        let cmd = Cmd::new("dpkg-deb")
            .arg("-f")
            .arg(file.to_string_lossy())
            .arg(name);
        Ok(ctx.check(&cmd)?.trim().to_string())
    };
    let package = field("Package")?;
    let version = field("Version")?;
    let actual_arch = field("Architecture")?;
    let matches = package == asset.package
        && actual_arch == arch.deb
        && !version.is_empty()
        && !version.chars().any(char::is_whitespace)
        && asset.name == format!("{package}_{version}_{}.deb", arch.deb)
        && file.file_name().and_then(|n| n.to_str()) == Some(asset.name.as_str());
    if !matches {
        return Err(Error::msg(
            "内核包 Package/架构/版本/文件名不匹配，未执行安装",
        ));
    }
    Ok(())
}

fn apt(args: &[&str], packages: &[PathBuf]) -> Cmd {
    Cmd::new("apt-get")
        .args(args.iter().copied())
        .args(packages.iter().map(|p| p.to_string_lossy().into_owned()))
        .env("DEBIAN_FRONTEND", "noninteractive")
}

/// One package apt would install (`Inst name [old] (new …)`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Planned {
    pub package: String,
    pub version: String,
}

/// `apt-get --simulate`; `--no-remove` makes apt refuse any removal.
fn simulate(ctx: &crate::ctx::Ctx, packages: &[PathBuf]) -> Result<Vec<Planned>> {
    require_pair(packages)?;
    let cmd = apt(
        &[
            "--simulate",
            "--no-remove",
            "--no-install-recommends",
            "install",
        ],
        packages,
    );
    parse_simulation(&ctx.check(&cmd)?)
}

fn require_pair(packages: &[PathBuf]) -> Result<()> {
    if packages.len() == 2 {
        Ok(())
    } else {
        Err(Error::msg("安装需要已验证的 image + headers 两个包"))
    }
}

/// `Inst` lines of an apt simulation; any `Remv` line aborts.
pub fn parse_simulation(text: &str) -> Result<Vec<Planned>> {
    let mut planned = Vec::new();
    for line in text.lines() {
        if line.starts_with("Remv ") {
            return Err(Error::msg("apt 预演需要删除软件包，已取消安装"));
        }
        let Some(rest) = line.strip_prefix("Inst ") else {
            continue;
        };
        let package = rest
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_string();
        let version = rest
            .split_once('(')
            .and_then(|(_, v)| v.split_whitespace().next())
            .unwrap_or_default()
            .to_string();
        planned.push(Planned { package, version });
    }
    Ok(planned)
}

/// The simulation summary shown before the confirmation.
pub fn simulation_text(planned: &[Planned], manifest: &Manifest) -> String {
    if planned.is_empty() {
        return "apt 预演: 没有需要安装或升级的软件包".into();
    }
    let extra = planned
        .iter()
        .filter(|p| !manifest.assets.iter().any(|a| a.package == p.package))
        .count();
    let mut lines = vec![if extra == 0 {
        format!("apt 预演: 将安装 {} 个软件包", planned.len())
    } else {
        format!(
            "apt 预演: 将安装或升级 {} 个软件包（含 {extra} 个来自软件源的依赖）",
            planned.len()
        )
    }];
    lines.extend(
        planned
            .iter()
            .map(|p| format!("  {} {}", p.package, p.version)),
    );
    lines.join("\n")
}

/// Install, then prove the result: dpkg status, boot files, GRUB entry.
fn install_kernel(session: &Session<'_>, kernel: &str, packages: &[PathBuf]) -> Result<()> {
    let ctx = session.ctx;
    require_pair(packages)?;
    let cmd = apt(
        &[
            "-o",
            "DPkg::Lock::Timeout=60",
            "--no-remove",
            "--no-install-recommends",
            "install",
            "-y",
        ],
        packages,
    );
    let out = run_protected(ctx, cmd)?;
    if !out.ok() {
        return Err(Error::msg(format!(
            "内核安装失败；保留旧内核，请检查 apt/dpkg 日志，不要重启: apt-get 执行失败 ({})",
            out.code
        )));
    }
    for kind in ["image", "headers"] {
        let query =
            Cmd::new("dpkg-query").args(["-W", "-f=${Status}", &format!("linux-{kind}-{kernel}")]);
        if ctx.check(&query)?.trim() != "install ok installed" {
            return Err(Error::msg("内核包未完成配置，请修复 apt/dpkg 后再重启"));
        }
    }
    if missing_kernel_file(ctx, kernel).is_some() {
        return Err(Error::msg(
            "新内核/initrd/模块不完整；旧内核仍保留，请修复引导后再重启",
        ));
    }
    ctx.check(&Cmd::new("update-grub")).map_err(|e| {
        Error::msg(format!(
            "更新 GRUB 失败；旧内核仍保留，请修复引导后再重启: {e}"
        ))
    })?;
    let grub = std::fs::read_to_string(ctx.paths.system("/boot/grub/grub.cfg"))
        .map_err(|e| Error::io(ctx.paths.system("/boot/grub/grub.cfg"), e))?;
    if !grub_has_kernel(&grub, kernel) {
        return Err(Error::msg(
            "GRUB 中未找到新内核；旧内核仍保留，请修复引导后再重启",
        ));
    }
    Ok(())
}

/// A `linux`/`linuxefi`/`linux16` line whose image is exactly
/// `vmlinuz-{kernel}` (comments and `vmlinuz-{kernel}-other` do not count).
pub fn grub_has_kernel(grub: &str, kernel: &str) -> bool {
    let target = format!("vmlinuz-{kernel}");
    grub.lines().any(|line| {
        let mut words = line.split_whitespace();
        matches!(words.next(), Some("linux" | "linuxefi" | "linux16"))
            && words.next().is_some_and(|word| {
                word.trim_matches(|c| c == '\'' || c == '"')
                    .rsplit('/')
                    .next()
                    == Some(target.as_str())
            })
    })
}

/// Run apt/dpkg with inherited output in its own session (the terminal's
/// Ctrl+C cannot reach dpkg); our own INT/TERM/HUP only print a notice
/// while it runs.
fn run_protected(ctx: &crate::ctx::Ctx, cmd: Cmd) -> Result<Output> {
    let _scope = signal::SignalScope::install()?;
    let mut child = ctx.exec.spawn(&cmd.stream())?;
    let mut warned = false;
    loop {
        if let Some(out) = child.wait_timeout(Duration::from_millis(500))? {
            signal::clear();
            return Ok(out);
        }
        if signal::pending().is_some() {
            signal::clear();
            if !warned {
                out::warn("正在安装内核，中断 apt/dpkg 可能导致系统无法启动；请等待安装完成");
                warned = true;
            }
        }
    }
}

/// `last-install.tsv`: `{name}\tsha256:{digest}\t{size}\t{url}` per package.
pub fn record_text(manifest: &Manifest) -> String {
    manifest
        .assets
        .iter()
        .map(|a| format!("{}\tsha256:{}\t{}\t{}\n", a.name, a.digest, a.size, a.url))
        .collect()
}

fn write_record(ctx: &crate::ctx::Ctx, manifest: &Manifest) {
    let path = ctx.paths.bbr_dir.join(RECORD);
    if let Err(e) = atomic_write(&path, record_text(manifest).as_bytes(), 0o600) {
        out::warn(format!("安装成功，但未能保存下载校验记录: {e}"));
    }
}

#[cfg(test)]
mod tests;
