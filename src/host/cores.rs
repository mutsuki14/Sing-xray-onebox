//! sing-box / Xray release resolution, verified download and extraction,
//! version probing and config checks.
//!
//! Flow: [`resolve`] turns a wanted version (none = default, `latest`,
//! `1.2.3`/`v1.2.3`) into a concrete version plus its verified-to-be-sane
//! release metadata; [`download`] fetches the package for this CPU, checks
//! URL, size and SHA-256, extracts only the core binary, probes its
//! version and leaves it at `{staging}/{binary}`; [`ensure_installed`] is
//! the apply-engine entry (download only when the binary is missing or
//! broken; a working core is never replaced there).
//! `ONEBOX_SINGBOX_BIN` / `ONEBOX_XRAY_BIN` replace the download with a
//! local file (offline installs, tests).
//!
//! Replacing a working core is the update path (`onebox update CORE [VER]`):
//! [`resolve`] with `Some(VER)` or `Some("latest")` (strict, never falls
//! back), compare [`Resolved::version`] with the installed one (downgrade and
//! Xray-version policy), then [`download`] into a staging directory and hand
//! the staged binary to the apply engine (`Intents.replace_cores`) together
//! with the new pin. [`download_to`] is resolve + download in one call.
//!
//! Changes from v2:
//! - prereleases are refused (E-8.1#15); a failed `latest` lookup for
//!   sing-box falls back to 1.14.2 only when installing without a specific
//!   version ([`resolve`] without a wish, or [`ensure_installed`] for a
//!   missing core), and says so; `resolve(…, Some("latest"))`, the core
//!   update path, fails instead of quietly downgrading (G-8.1#3).
//! - the offline override reports the parsed version instead of the first
//!   output line, refuses symlinks, and warns when it differs from the pin.
//! - `ensure_installed` re-downloads a binary that cannot run (v2 only
//!   checked that the file existed); like v2 it never replaces a working
//!   core because of a pin (G2).
//! - the downloaded binary must report the release's version.
//! - Xray zips are read in-process (no `unzip` package); only the core
//!   binary is extracted from either package.
//! - `check_config` errors carry the core's own message (ANSI colors and
//!   Xray's banner removed); [`check_config_in`] checks with a caller's work
//!   dir so `doctor` creates nothing under the run root (D-8.1#30).
//! - staging directories are `onebox-core-*` temp dirs removed on drop;
//!   crash leftovers in the bin directory are swept, v2's `.core-*` too.
//! - archive errors name the binary instead of saying "内核" (reused for
//!   FRP packages).

mod archive;
mod check;

pub use archive::{extract_tar_gz, extract_zip};
pub use check::{check_config, check_config_in, check_config_with, check_summary};

use crate::ctx::Ctx;
use crate::domain::config::CoreVersions;
use crate::domain::defaults::{SINGBOX_FALLBACK_VERSION, XRAY_TESTED_VERSION};
use crate::domain::protocol::Core;
use crate::error::{Context, Error, Result};
use crate::host::fetch::{self, Release, Which};
use crate::host::os::{process_env, Arch, EnvLookup};
use crate::sys::exec::Cmd;
use crate::sys::fs::{self as sysfs, TempDir};
use crate::ui::out;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Largest release package accepted (sing-box ≈ 33 MB, Xray ≈ 21 MB).
pub const PACKAGE_MAX: u64 = 256 * 1024 * 1024;
/// Largest extracted core binary accepted (sing-box ≈ 92 MB).
pub const BINARY_MAX: u64 = 512 * 1024 * 1024;
/// Name prefix (inside `{bin}` or a caller's staging dir) of work dirs.
pub const WORK_PREFIX: &str = "onebox-core-";
const VERSION_TIMEOUT: Duration = Duration::from_secs(15);
/// v2's staging dirs beside the core binaries (`.core-<24hex>`).
const V2_STAGING_PREFIX: &str = ".core-";
/// Work dirs older than this are crash leftovers.
const STALE_AFTER: Duration = Duration::from_secs(60 * 60);

pub fn repo(core: Core) -> &'static str {
    match core {
        Core::Singbox => "SagerNet/sing-box",
        Core::Xray => "XTLS/Xray-core",
    }
}

/// Environment variable naming a local binary to install instead.
pub fn offline_env(core: Core) -> &'static str {
    match core {
        Core::Singbox => "ONEBOX_SINGBOX_BIN",
        Core::Xray => "ONEBOX_XRAY_BIN",
    }
}

/// What the user asked for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Wanted {
    /// No preference: Xray 26.3.27 (tested), sing-box latest.
    Default,
    Latest,
    Exact(String),
}

impl Wanted {
    /// `None`/empty → default, `latest`, else a version (`v` stripped).
    pub fn parse(wanted: Option<&str>) -> Result<Wanted> {
        match wanted.map(str::trim) {
            None | Some("") => Ok(Wanted::Default),
            Some("latest") => Ok(Wanted::Latest),
            Some(v) => normalize_version(v).map(Wanted::Exact),
        }
    }

    /// Whether an installed `version` satisfies this wish without a lookup.
    pub fn satisfied_by(&self, version: &str) -> bool {
        match self {
            Wanted::Default | Wanted::Latest => true,
            Wanted::Exact(v) => v == version,
        }
    }
}

/// Strip one leading `v` and validate with the one version grammar
/// ([`version_valid`]: 1–64 chars of `[A-Za-z0-9._-]`, starting
/// alphanumeric, with at least one digit).
pub fn normalize_version(raw: &str) -> Result<String> {
    let v = raw.strip_prefix('v').unwrap_or(raw);
    ensure!(version_valid(v), "版本格式无效: {raw}");
    Ok(v.to_owned())
}

/// `domain::validate::valid_version`, the grammar `NodeConfig::validate`
/// also enforces for recorded versions and pins.
pub use crate::domain::validate::valid_version as version_valid;

/// Where a resolved core comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Source {
    Release(Release),
    Offline(PathBuf),
}

/// A concrete core version ready to [`download`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolved {
    pub core: Core,
    pub version: String,
    source: Source,
}

impl Resolved {
    pub fn is_offline(&self) -> bool {
        matches!(self.source, Source::Offline(_))
    }
    pub fn release(&self) -> Option<&Release> {
        match &self.source {
            Source::Release(r) => Some(r),
            Source::Offline(_) => None,
        }
    }
}

/// Resolve `wanted` to a concrete, non-prerelease version.
pub fn resolve(ctx: &Ctx, core: Core, wanted: Option<&str>) -> Result<Resolved> {
    resolve_with(ctx, &process_env, core, wanted)
}

/// [`resolve`] with an injected environment lookup.
pub fn resolve_with(
    ctx: &Ctx,
    env: EnvLookup,
    core: Core,
    wanted: Option<&str>,
) -> Result<Resolved> {
    let wanted = Wanted::parse(wanted)?;
    if let Some(source) = env(offline_env(core)) {
        return resolve_offline(ctx, core, Path::new(&source), &wanted);
    }
    match (wanted, core) {
        (Wanted::Exact(v), _) => resolve_exact(ctx, env, core, &v),
        (Wanted::Default, Core::Xray) => resolve_exact(ctx, env, core, XRAY_TESTED_VERSION),
        // Only "no preference" may fall back: an explicit `latest` (core
        // update) must not quietly become an older version.
        (Wanted::Default, Core::Singbox) => resolve_latest(ctx, env, core).or_else(|e| {
            out::warn(format!(
                "无法获取 sing-box 最新版本（{e}），改用 {SINGBOX_FALLBACK_VERSION}"
            ));
            resolve_exact(ctx, env, core, SINGBOX_FALLBACK_VERSION)
        }),
        (Wanted::Latest, _) => resolve_latest(ctx, env, core),
    }
}

fn resolve_exact(ctx: &Ctx, env: EnvLookup, core: Core, version: &str) -> Result<Resolved> {
    let which = Which::Tag(format!("v{version}"));
    let release = fetch::github_release_with(ctx, env, repo(core), &which)?;
    accept_release(core, release, Some(version))
}

fn resolve_latest(ctx: &Ctx, env: EnvLookup, core: Core) -> Result<Resolved> {
    let release = fetch::github_release_with(ctx, env, repo(core), &Which::Latest)?;
    accept_release(core, release, None)
}

/// Release sanity: valid tag, not a draft or prerelease, matches the request.
fn accept_release(core: Core, release: Release, requested: Option<&str>) -> Result<Resolved> {
    let version = release.version().to_owned();
    ensure!(
        version_valid(&version) && !release.draft,
        "无效发行版本: {}",
        release.tag
    );
    ensure!(
        !release.prerelease,
        "{} {} 是预发布版本，拒绝安装；请指定正式版本",
        core.title(),
        release.tag
    );
    if let Some(want) = requested {
        ensure!(
            version == want,
            "发行版本与请求不符（请求 {want}，得到 {version}）"
        );
    }
    Ok(Resolved {
        core,
        version,
        source: Source::Release(release),
    })
}

fn resolve_offline(ctx: &Ctx, core: Core, source: &Path, wanted: &Wanted) -> Result<Resolved> {
    check_offline_source(core, source)?;
    let version = installed_version(ctx, source, core)?;
    if !wanted.satisfied_by(&version) {
        out::warn(format!(
            "{} 指定的本地内核版本为 {version}，与要求的版本不同",
            offline_env(core)
        ));
    }
    Ok(Resolved {
        core,
        version,
        source: Source::Offline(source.to_path_buf()),
    })
}

fn check_offline_source(core: Core, source: &Path) -> Result<()> {
    let regular = source.is_absolute()
        && std::fs::symlink_metadata(source).is_ok_and(|m| m.file_type().is_file());
    ensure!(
        regular,
        "本地内核必须是普通文件的绝对路径（{}={}）",
        offline_env(core),
        source.display()
    );
    Ok(())
}

/// Download, verify and extract `resolved` into `{staging_dir}/{binary}`
/// (mode 0755; an existing file there is replaced atomically).
pub fn download(ctx: &Ctx, resolved: &Resolved, staging_dir: &Path) -> Result<PathBuf> {
    download_with(ctx, &process_env, resolved, staging_dir)
}

/// [`download`] with an injected environment lookup (`GH_PROXY`).
pub fn download_with(
    ctx: &Ctx,
    env: EnvLookup,
    resolved: &Resolved,
    staging_dir: &Path,
) -> Result<PathBuf> {
    ensure!(
        staging_dir.is_dir(),
        "内核暂存目录无效: {}",
        staging_dir.display()
    );
    // The work dir (package, checksums, extracted binary) is removed on
    // every path when it drops.
    let work = TempDir::new_in(staging_dir, "core")?;
    stage_binary(ctx, env, resolved, &work, staging_dir)
        .with_context(|| format!("{} {} 安装失败", resolved.core.title(), resolved.version))
}

fn stage_binary(
    ctx: &Ctx,
    env: EnvLookup,
    resolved: &Resolved,
    work: &TempDir,
    staging_dir: &Path,
) -> Result<PathBuf> {
    let core = resolved.core;
    let binary = work.join(core.binary());
    match &resolved.source {
        Source::Offline(path) => {
            check_offline_source(core, path)?;
            sysfs::copy_file(path, &binary, 0o700)?;
        }
        Source::Release(release) => fetch_binary(ctx, env, core, release, work, &binary)?,
    }
    finish_binary(ctx, resolved, &binary, staging_dir)
}

/// The update path in one call: `resolve(Some(version))` (`version` may be
/// `latest`; strict) + [`download`] into `staging_dir`. The live binary is
/// never touched; returns `{staging_dir}/{binary}`.
pub fn download_to(ctx: &Ctx, core: Core, version: &str, staging_dir: &Path) -> Result<PathBuf> {
    let resolved = resolve(ctx, core, Some(version))?;
    download(ctx, &resolved, staging_dir)
}

/// Package for this CPU → verified download → extracted binary at `out`.
fn fetch_binary(
    ctx: &Ctx,
    env: EnvLookup,
    core: Core,
    release: &Release,
    work: &TempDir,
    out: &Path,
) -> Result<()> {
    let arch = Arch::detect(ctx)?;
    let names = match core {
        Core::Singbox => arch.singbox_assets(release.version()),
        Core::Xray => vec![arch.xray_asset()],
    };
    ensure!(
        !names.is_empty(),
        "{} 没有 {arch} 架构的发行包",
        core.title()
    );
    let asset = release
        .first_asset(&names)
        .ok_or_else(|| Error::msg(format!("找不到对应架构的内核 ({arch})")))?;
    asset.check_url(repo(core), &release.tag)?;
    ensure!(asset.size <= PACKAGE_MAX, "内核包过大: {}", asset.name);
    let package = work.join(&asset.name);
    out::info(format!("正在下载 {}…", asset.name));
    let sums = |n: &str| is_checksum_file(core, &asset.name, n);
    fetch::download_asset_with(ctx, env, repo(core), release, asset, &package, &sums)?;
    match core {
        Core::Singbox => extract_tar_gz(&package, core.binary(), out, BINARY_MAX)?,
        Core::Xray => extract_zip(&package, core.binary(), out, BINARY_MAX)?,
    };
    Ok(())
}

/// The release file holding the checksum of package `name` when the API
/// has no digest (Xray: `{name}.dgst`; sing-box: `*checksums*` or
/// `sha256sums.txt`).
fn is_checksum_file(core: Core, name: &str, candidate: &str) -> bool {
    match core {
        Core::Xray => candidate.strip_suffix(".dgst") == Some(name),
        Core::Singbox => candidate.contains("checksums") || candidate == "sha256sums.txt",
    }
}

/// ELF check, probe the version, then move into `{staging}/{binary}`.
fn finish_binary(ctx: &Ctx, resolved: &Resolved, binary: &Path, staging: &Path) -> Result<PathBuf> {
    fetch::check_elf(binary)?;
    set_mode(binary, 0o755)?;
    let got = installed_version(ctx, binary, resolved.core)?;
    ensure!(
        got == resolved.version,
        "程序报告的版本为 {got}，与发行版本 {} 不符",
        resolved.version
    );
    let dest = staging.join(resolved.core.binary());
    std::fs::rename(binary, &dest).map_err(|e| Error::io(&dest, e))?;
    sysfs::fsync_dir(staging).map_err(|e| Error::io(staging, e))?;
    Ok(dest)
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| Error::io(path, e))
}

/// Version reported by `{path} version` (sing-box: 3rd word of line 1,
/// Xray: 2nd word; leading `v` stripped).
pub fn installed_version(ctx: &Ctx, path: &Path, core: Core) -> Result<String> {
    let cmd = Cmd::new(path.to_string_lossy())
        .arg("version")
        .timeout(VERSION_TIMEOUT);
    let stdout = ctx
        .check(&cmd)
        .with_context(|| format!("无法运行 {}", core.title()))?;
    parse_version(core, &stdout).ok_or_else(|| Error::msg("无法解析内核版本"))
}

/// Parse `version` output: `sing-box version 1.14.2` / `Xray 26.3.27 (…)`.
pub fn parse_version(core: Core, output: &str) -> Option<String> {
    let line = output.lines().next()?;
    let words: Vec<&str> = line.split_whitespace().collect();
    let token = match core {
        Core::Singbox if words.get(..2) == Some(&["sing-box", "version"]) => words.get(2),
        Core::Xray if words.first() == Some(&"Xray") => words.get(1),
        _ => None,
    }?;
    let version = token.strip_prefix('v').unwrap_or(token);
    version_valid(version).then(|| version.to_owned())
}

/// Make sure the core binary exists and return its version (the apply
/// engine's prepare-cores hook).
///
/// The binary is downloaded only when it is missing or cannot report a
/// version, in the wanted version: the pin (`versions.pin(core)`), else
/// `ONEBOX_SINGBOX_VERSION` / `ONEBOX_XRAY_VERSION` ([`version_env`], v2
/// parity for scripted installs), else the default. A working binary is
/// never replaced here, not even when it differs from the pin (v2 parity;
/// a migrated v2 pin is often older than the installed core and must not
/// downgrade it or make an upgrade depend on GitHub): only the hint
/// `已安装 … ；更换指定版本请执行 onebox update …` is printed.
///
/// Changing a working core is `onebox update`'s job: it passes the staged
/// binary in `Intents.replace_cores` and must store the matching pin (or
/// clear it) in the same apply, or this hint repeats on every apply.
pub fn ensure_installed(ctx: &Ctx, core: Core, versions: &CoreVersions) -> Result<String> {
    ensure_installed_with(ctx, &process_env, core, versions)
}

/// [`ensure_installed`] with an injected environment lookup.
pub fn ensure_installed_with(
    ctx: &Ctx,
    env: EnvLookup,
    core: Core,
    versions: &CoreVersions,
) -> Result<String> {
    let wish = wished_version(env, core, versions);
    sweep_leftovers(&ctx.paths.bin);
    let live = ctx.paths.core_bin(core);
    if let Some(current) = current_version(ctx, core, &live)? {
        match keep_notice(core, &current, &wish) {
            Some(warning) => out::warn(warning),
            None => out::info(format!("{} {current} 已安装", core.title())),
        }
        return Ok(current);
    }
    // Only a download needs the wish to be valid.
    let wish = wish?;
    // Installing a missing core, `latest` means "any version": like v2 a
    // failed lookup may still fall back (only `onebox update` is strict).
    let wanted = match &wish {
        Some(Wanted::Exact(v)) => Some(v.as_str()),
        Some(Wanted::Latest | Wanted::Default) | None => None,
    };
    let resolved = resolve_with(ctx, env, core, wanted)?;
    sysfs::ensure_dir(&ctx.paths.bin, 0o755)?;
    let stage = TempDir::new_in(&ctx.paths.bin, "core-stage")?;
    let staged = download_with(ctx, env, &resolved, stage.path())?;
    std::fs::rename(&staged, &live).map_err(|e| Error::io(&live, e))?;
    sysfs::fsync_dir(&ctx.paths.bin).map_err(|e| Error::io(&ctx.paths.bin, e))?;
    out::ok(format!("已安装 {} {}", core.title(), resolved.version));
    Ok(resolved.version)
}

/// The warning for a working core that is kept: [`pin_hint`] when it
/// differs from an exact wish; a malformed wish (pin or environment) only
/// warns, because nothing has to be downloaded (v2 printed its hint and
/// went on). `None`: the core satisfies the wish.
pub fn keep_notice(core: Core, current: &str, wish: &Result<Option<Wanted>>) -> Option<String> {
    match wish {
        Ok(wish) => pin_hint(core, current, wish.as_ref()),
        Err(e) => Some(format!("{e}；已保留已安装的 {} {current}", core.title())),
    }
}

/// v2's hint when a working core differs from the exact version wished
/// (pin or environment); `None` when it satisfies the wish.
pub fn pin_hint(core: Core, current: &str, wish: Option<&Wanted>) -> Option<String> {
    match wish {
        Some(Wanted::Exact(v)) if v != current => Some(format!(
            "已安装 {} {current}；更换指定版本请执行 onebox update {} {v}",
            core.title(),
            core.id()
        )),
        _ => None,
    }
}

/// Environment variable naming the version to install when nothing is
/// pinned (`ONEBOX_SINGBOX_VERSION` / `ONEBOX_XRAY_VERSION`).
pub fn version_env(core: Core) -> &'static str {
    match core {
        Core::Singbox => "ONEBOX_SINGBOX_VERSION",
        Core::Xray => "ONEBOX_XRAY_VERSION",
    }
}

/// The pin, else the environment's wish; `None` means "no preference".
fn wished_version(env: EnvLookup, core: Core, versions: &CoreVersions) -> Result<Option<Wanted>> {
    if let Some(pin) = versions.pin(core) {
        return Wanted::parse(Some(pin)).map(Some);
    }
    let Some(value) = env(version_env(core)) else {
        return Ok(None);
    };
    Wanted::parse(Some(&value))
        .map(Some)
        .with_context(|| format!("环境变量 {}", version_env(core)))
}

/// Remove crash leftovers next to the live cores: v3 work dirs and v2's
/// `.core-*` staging dirs (with their `.download-*` files; E-8.1#16).
fn sweep_leftovers(bin: &Path) {
    for prefix in [WORK_PREFIX, V2_STAGING_PREFIX] {
        let _ = sysfs::sweep_stale(bin, prefix, STALE_AFTER);
    }
}

/// The live binary's version; `None` when it is missing or cannot report
/// one (then it is downloaded again).
fn current_version(ctx: &Ctx, core: Core, live: &Path) -> Result<Option<String>> {
    match std::fs::symlink_metadata(live) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Error::io(live, e)),
        Ok(m) if !m.file_type().is_file() => {
            bail!("内核路径不是普通文件: {}", live.display())
        }
        Ok(_) => {}
    }
    match installed_version(ctx, live, core) {
        Ok(v) => Ok(Some(v)),
        Err(e) => {
            out::warn(format!("现有 {} 无法使用（{e}），将重新下载", core.title()));
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests;
