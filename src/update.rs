//! Verified, staged software replacement with recovery on failed regeneration.
use crate::{
    context::Context,
    model::{Core, State},
    platform, transaction, util, workflow, Result, REPOSITORY, VERSION,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs,
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::{Path, PathBuf},
};

fn channel_path(ctx: &Context) -> PathBuf {
    ctx.paths.root.join("update-channel")
}
fn channel(ctx: &Context, explicit: Option<&str>) -> Result<String> {
    let p = channel_path(ctx);
    util::safe_path(&p)?;
    let value = if let Some(v) = explicit {
        v.to_owned()
    } else if p.exists() {
        fs::read_to_string(p)?.trim().into()
    } else {
        "stable".into()
    };
    if matches!(value.as_str(), "stable" | "testing") {
        Ok(value)
    } else {
        Err("更新渠道仅支持 stable/testing".into())
    }
}
fn semver(v: &str) -> Result<(u64, u64, u64)> {
    let main = v
        .trim_start_matches('v')
        .split('-')
        .next()
        .ok_or("版本无效")?;
    let fields = main
        .split('.')
        .map(str::parse::<u64>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if fields.len() != 3 {
        return Err("版本需要 major.minor.patch".into());
    }
    Ok((fields[0], fields[1], fields[2]))
}
fn temp_near(path: &Path, prefix: &str) -> Result<PathBuf> {
    let root = path.parent().ok_or("文件路径没有父目录")?;
    fs::create_dir_all(root)?;
    let dir = root.join(format!(".{prefix}-{}", util::random_hex(12)?));
    fs::create_dir(&dir)?;
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    // The recovery record lives elsewhere; persist this directory entry
    // before it can refer to snapshots below it across a power failure.
    fs::File::open(root)?.sync_all()?;
    Ok(dir)
}
fn update_lock(ctx: &Context) -> Result<fs::File> {
    let path = ctx.paths.run.join("update.lock");
    util::safe_path(&path)?;
    fs::create_dir_all(&ctx.paths.run)?;
    let f = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("另一个更新正在进行".into());
    }
    Ok(f)
}
struct ConfigSnapshot {
    snapshot: transaction::Snapshot,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProgramJournal {
    version: u8,
    work: String,
    phase: String,
    old_existed: bool,
    old_sha256: String,
    new_sha256: String,
    snapshot: Option<transaction::Snapshot>,
}
fn program_journal_path(ctx: &Context) -> PathBuf {
    ctx.paths.root.join(".self-update.json")
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}
impl ProgramJournal {
    fn directory(&self, ctx: &Context) -> Result<PathBuf> {
        let token = self
            .work
            .strip_prefix(".onebox-update-")
            .ok_or("更新工作目录前缀无效")?;
        if token.len() != 24 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("更新工作目录无效".into());
        }
        let path = ctx
            .paths
            .executable
            .parent()
            .ok_or("程序没有父目录")?
            .join(&self.work);
        util::safe_path(&path)?;
        Ok(path)
    }
    fn save(&self, ctx: &Context) -> Result<()> {
        util::atomic_write(
            &program_journal_path(ctx),
            &serde_json::to_vec_pretty(self)?,
            0o600,
        )
    }
    fn set_phase(&mut self, ctx: &Context, phase: &str) -> Result<()> {
        let mut updated = self.clone();
        updated.phase = phase.into();
        updated.save(ctx)?;
        *self = updated;
        Ok(())
    }
    fn validate(&self, ctx: &Context) -> Result<PathBuf> {
        if self.version != 1
            || !matches!(
                self.phase.as_str(),
                "prepared" | "replacing" | "replaced" | "recovering" | "committed"
            )
            || !valid_digest(&self.new_sha256)
            || self.old_existed && !valid_digest(&self.old_sha256)
            || !self.old_existed && !self.old_sha256.is_empty()
        {
            return Err("自更新恢复记录无效".into());
        }
        let directory = self.directory(ctx)?;
        if self.old_existed {
            let old = directory.join("old");
            util::safe_path(&old)?;
            if fs::metadata(&old)?.len() > 128 * 1024 * 1024
                || util::sha256(&fs::read(old)?) != self.old_sha256
            {
                return Err("自更新旧程序备份 SHA256 不匹配，未更改当前程序".into());
            }
        }
        if let Some(snapshot) = &self.snapshot {
            transaction::validate_snapshot(ctx, snapshot, &directory.join("config"))?;
        }
        util::safe_path(&ctx.paths.executable)?;
        if ctx.paths.executable.exists() {
            if fs::metadata(&ctx.paths.executable)?.len() > 128 * 1024 * 1024 {
                return Err("当前程序超出自更新大小限制".into());
            }
            let hash = util::sha256(&fs::read(&ctx.paths.executable)?);
            if hash != self.old_sha256 && hash != self.new_sha256 {
                return Err("当前程序已被其他操作替换，拒绝覆盖；请检查自更新记录".into());
            }
        }
        Ok(directory)
    }
    fn finish(&self, ctx: &Context) -> Result<()> {
        let directory = self.directory(ctx)?;
        fs::remove_file(program_journal_path(ctx))?;
        fs::File::open(&ctx.paths.root)?.sync_all()?;
        if let Err(error) = fs::remove_dir_all(&directory) {
            eprintln!(
                "自更新已完成，临时文件清理失败 {}: {error}",
                directory.display()
            );
        }
        Ok(())
    }
}
fn load_program_journal(ctx: &Context) -> Result<Option<ProgramJournal>> {
    let path = program_journal_path(ctx);
    util::safe_path(&path)?;
    if !path.exists() {
        return Ok(None);
    }
    if fs::metadata(&path)?.len() > 8 * 1024 * 1024 {
        return Err("自更新恢复记录异常大".into());
    }
    Ok(Some(serde_json::from_slice(&fs::read(path)?)?))
}
/// Called after the normal configuration journal has been recovered. A child
/// explicitly holding its parent's verified lock performs regeneration and
/// must not roll back that parent's still-active program replacement.
pub fn recover_locked(ctx: &Context, lock: &transaction::Lock) -> Result<()> {
    lock.verify(ctx)?;
    let Some(mut journal) = load_program_journal(ctx)? else {
        return Ok(());
    };
    let directory = journal.validate(ctx)?;
    if lock.is_inherited() {
        return Ok(());
    }
    if journal.phase == "committed" {
        if !ctx.paths.executable.is_file()
            || util::sha256(&fs::read(&ctx.paths.executable)?) != journal.new_sha256
        {
            return Err("已提交的自更新程序不匹配，保留恢复记录".into());
        }
        return journal.finish(ctx);
    }
    journal.set_phase(ctx, "recovering")?;
    if journal.snapshot.is_some() {
        for name in [
            "onebox-sing-box",
            "onebox-xray",
            "onebox-subscription-web",
            "onebox-site",
            "onebox-subscription",
        ] {
            if platform::exists(ctx, name) {
                platform::service(ctx, name, "stop")?;
            }
        }
        crate::network::clear_rules(ctx)?;
    }
    // Restore the manager first only after the configuration journal has been
    // handled by workflow::recover_locked. Its own snapshot may contain the
    // replacement manager, so reversing this order would restore it again.
    if journal.old_existed {
        util::atomic_write(
            &ctx.paths.executable,
            &fs::read(directory.join("old"))?,
            0o755,
        )?;
    } else if ctx.paths.executable.exists() {
        fs::remove_file(&ctx.paths.executable)?;
        fs::File::open(ctx.paths.executable.parent().ok_or("程序没有父目录")?)?.sync_all()?;
    }
    if let Some(snapshot) = &journal.snapshot {
        transaction::restore_snapshot(ctx, snapshot, &directory.join("config"))?;
        if !journal.old_existed {
            return Err("已安装配置缺少可恢复的旧管理程序".into());
        }
        // Execute the restored manager so its install_self cannot replace it
        // with the newer, still-mapped executable of this recovery process.
        let output = ctx.run_with_lock(
            util::path_str(&ctx.paths.executable)?,
            &["regen"],
            lock.as_raw_fd(),
        )?;
        print!("{output}");
    }
    journal.finish(ctx)?;
    println!("已恢复中断前的管理程序与配置");
    if journal.old_existed
        && util::sha256(
            &fs::read("/proc/self/exe").or_else(|_| fs::read(std::env::current_exe()?))?,
        ) != journal.old_sha256
    {
        return Err(crate::ExitError::new(
            75,
            "自更新恢复已完成；当前进程仍是被替换版本，请重新执行命令以使用恢复后的程序",
        )
        .into());
    }
    Ok(())
}
struct SignalGuard {
    old: libc::sigset_t,
}
impl SignalGuard {
    fn new() -> Result<Self> {
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            let mut old: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            for s in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
                libc::sigaddset(&mut set, s);
            }
            let rc = libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut old);
            if rc != 0 {
                return Err(std::io::Error::from_raw_os_error(rc).into());
            }
            Ok(Self { old })
        }
    }
}
impl Drop for SignalGuard {
    fn drop(&mut self) {
        unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &self.old, std::ptr::null_mut());
        }
    }
}
impl ConfigSnapshot {
    fn capture(ctx: &Context, directory: &Path) -> Result<Self> {
        Ok(Self {
            snapshot: transaction::snapshot_files(ctx, directory)?,
        })
    }
}
fn verify_asset(asset: &Value, bytes: &[u8]) -> Result<()> {
    if asset["size"].as_u64() != Some(bytes.len() as u64) {
        return Err("发布文件大小不匹配".into());
    }
    let digest = asset["digest"]
        .as_str()
        .and_then(|s| s.strip_prefix("sha256:"))
        .ok_or("发布文件缺少可信 SHA256")?;
    if digest != util::sha256(bytes) {
        return Err("发布文件 SHA256 不匹配".into());
    }
    Ok(())
}
fn binary_header(bytes: &[u8]) -> Result<()> {
    if bytes.len() < 20 || &bytes[..4] != b"\x7fELF" {
        return Err("发布文件不是 Linux ELF 程序".into());
    }
    Ok(())
}
fn release_asset<'a>(release: &'a Value, arch: &str) -> Result<&'a Value> {
    let name = format!("onebox-linux-{arch}-musl");
    release["assets"]
        .as_array()
        .ok_or("发布信息缺少文件")?
        .iter()
        .find(|a| a["name"].as_str() == Some(name.as_str()))
        .ok_or_else(|| format!("此发布缺少 {name}；保持已安装程序").into())
}
fn self_release(ctx: &Context, ch: &str) -> Result<Value> {
    let suffix = if ch == "stable" {
        "latest"
    } else {
        "tags/testing"
    };
    let r = platform::github_json(
        ctx,
        &format!("https://api.github.com/repos/{REPOSITORY}/releases/{suffix}"),
    )?;
    if r["draft"] != false || ch == "stable" && r["prerelease"] != false {
        return Err("更新来源不是指定渠道的有效发布".into());
    }
    Ok(r)
}
fn installed_program_version(ctx: &Context) -> Result<String> {
    if ctx.paths.executable.is_file() {
        let output = ctx.run(util::path_str(&ctx.paths.executable)?, &["version"])?;
        let v = output.trim().trim_start_matches('v');
        semver(v)?;
        Ok(v.into())
    } else {
        Ok(VERSION.into())
    }
}
struct Replacement {
    live: PathBuf,
    #[cfg(test)]
    backup: PathBuf,
    existed: bool,
    replaced: bool,
}
impl Replacement {
    fn snapshot(live: &Path, backup: &Path) -> Result<Self> {
        util::safe_path(live)?;
        let existed = live.exists();
        if existed {
            util::atomic_write(backup, &fs::read(live)?, 0o700)?;
        }
        Ok(Self {
            live: live.into(),
            #[cfg(test)]
            backup: backup.into(),
            existed,
            replaced: false,
        })
    }
    fn replace(&mut self, new: &Path) -> Result<()> {
        self.replaced = true;
        util::atomic_write(&self.live, &fs::read(new)?, 0o755)
    }
    #[cfg(test)]
    fn restore(&mut self) -> Result<()> {
        if !self.replaced {
            return Ok(());
        }
        if self.existed {
            util::atomic_write(&self.live, &fs::read(&self.backup)?, 0o755)?;
        } else if self.live.exists() {
            fs::remove_file(&self.live)?;
        }
        self.replaced = false;
        Ok(())
    }
}
fn program_update(ctx: &Context, args: &[String], check: bool) -> Result<()> {
    if args.len() > 1 {
        return Err("只接受一个更新渠道".into());
    }
    let ch = channel(ctx, args.first().map(String::as_str))?;
    let r = self_release(ctx, &ch)?;
    let arch = platform::architecture(ctx, Core::Singbox)?;
    let asset = release_asset(&r, &arch)?;
    let tag = r["tag_name"].as_str().ok_or("发布缺少标签")?;
    let url = asset["browser_download_url"]
        .as_str()
        .ok_or("发布缺少下载地址")?;
    let name = asset["name"].as_str().ok_or("发布缺少文件名")?;
    if url != format!("https://github.com/{REPOSITORY}/releases/download/{tag}/{name}") {
        return Err("发布文件地址与仓库不匹配".into());
    }
    let old = installed_program_version(ctx)?;
    let remote = if ch == "stable" {
        semver(tag)?;
        tag.trim_start_matches('v').to_owned()
    } else {
        "testing".into()
    };
    println!("更新渠道: {ch}\n当前版本: {old}\n发布版本: {remote}");
    if let Some(body) = r["body"].as_str() {
        for line in body.lines().take(12) {
            println!(
                "  {}",
                line.chars()
                    .filter(|c| !c.is_control())
                    .take(200)
                    .collect::<String>()
            );
        }
    }
    if ch == "stable" && semver(&remote)? < semver(&old)? {
        return Err("已安装版本更高，拒绝降级".into());
    }
    if check {
        println!("仅检查，未下载或替换程序");
        return Ok(());
    }
    platform::require_root()?;
    let _lock = update_lock(ctx)?;
    let mutation_lock = transaction::acquire(ctx)?;
    workflow::recover_locked(ctx, &mutation_lock)?;
    let dir = temp_near(&ctx.paths.executable, "onebox-update")?;
    let old = installed_program_version(ctx)?;
    let result = (|| -> Result<()> {
        let new = dir.join("new");
        platform::download(ctx, url, &new)?;
        let data = fs::read(&new)?;
        verify_asset(asset, &data)?;
        binary_header(&data)?;
        if ctx.paths.executable.is_file() && fs::read(&ctx.paths.executable)? == data {
            println!("已是当前发布的最新内容");
            return Ok(());
        }
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&new, fs::Permissions::from_mode(0o755))?;
        let new_version = ctx.run(util::path_str(&new)?, &["version"])?;
        let nv = new_version.trim();
        if semver(nv)? < semver(&old)? {
            return Err("下载程序版本低于已安装版本，拒绝降级".into());
        }
        if ch == "stable" && semver(nv)? != semver(&remote)? {
            return Err("发布标签与程序版本不一致".into());
        }
        let mut replacement = Replacement::snapshot(&ctx.paths.executable, &dir.join("old"))?;
        let installed = ctx.paths.state().exists() || ctx.paths.legacy_state().exists();
        if installed && !replacement.existed {
            return Err("已有配置但管理程序缺失，请先重新安装原程序再更新".into());
        }
        let config = if installed {
            Some(ConfigSnapshot::capture(ctx, &dir.join("config"))?)
        } else {
            None
        };
        let mut journal = ProgramJournal {
            version: 1,
            work: dir
                .file_name()
                .and_then(|v| v.to_str())
                .ok_or("更新目录名称无效")?
                .into(),
            phase: "prepared".into(),
            old_existed: replacement.existed,
            old_sha256: if replacement.existed {
                util::sha256(&fs::read(dir.join("old"))?)
            } else {
                String::new()
            },
            new_sha256: util::sha256(&data),
            snapshot: config.map(|v| v.snapshot),
        };
        // Durable intent and validated preimages exist before the first live
        // rename. A crash at any following instruction remains recoverable.
        journal.save(ctx)?;
        let _signals = SignalGuard::new()?;
        let apply = (|| -> Result<()> {
            journal.set_phase(ctx, "replacing")?;
            replacement.replace(&new)?;
            journal.set_phase(ctx, "replaced")?;
            if installed {
                let output = ctx.run_with_lock(
                    util::path_str(&ctx.paths.executable)?,
                    &["regen"],
                    mutation_lock.as_raw_fd(),
                )?;
                print!("{output}");
            }
            journal.set_phase(ctx, "committed")?;
            journal.finish(ctx)?;
            Ok(())
        })();
        if let Err(error) = apply {
            if journal.phase == "committed" {
                return Err(format!(
                    "程序更新已提交，但恢复记录清理失败: {error}；请执行 recover 完成清理"
                )
                .into());
            }
            // Recover the child's configuration transaction first. Its image
            // may include the new manager; the durable outer record restores
            // the manager and pre-update schema only after that child settles.
            if let Err(recovery) = workflow::recover_locked(ctx, &mutation_lock) {
                return Err(format!(
                    "更新失败: {error}；恢复需要重试: {recovery}；备份: {}",
                    dir.display()
                )
                .into());
            }
            return Err(format!("更新失败，已恢复原程序: {error}").into());
        }
        println!("程序已更新到 {nv}");
        // Continuing an interactive menu in this old mapped executable would
        // let install_self silently overwrite the successful upgrade.
        Err(crate::ExitError::new(0, "程序更新已完成；请重新执行 onebox 以使用新版本").into())
    })();
    if result.is_ok()
        || result
            .as_ref()
            .err()
            .and_then(|e| e.downcast_ref::<crate::ExitError>())
            .is_some_and(|e| e.code == 0)
    {
        let _ = fs::remove_dir_all(&dir);
    } else {
        eprintln!("更新工作目录保留供恢复: {}", dir.display());
    }
    result
}
fn core_update(ctx: &Context, args: &[String]) -> Result<()> {
    if args.len() > 2 {
        return Err("用法: onebox update [singbox|xray] [版本]".into());
    }
    platform::require_root()?;
    let _update_lock = update_lock(ctx)?;
    let mutation_lock = transaction::acquire(ctx)?;
    workflow::recover_locked(ctx, &mutation_lock)?;
    let which = args.first().map(String::as_str).unwrap_or("all");
    if !matches!(which, "all" | "singbox" | "sing-box" | "xray") {
        return Err("未知内核".into());
    }
    let state: State = crate::state::load(ctx)?;
    let targets = [Core::Singbox, Core::Xray]
        .into_iter()
        .filter(|c| {
            (which == "all" || which == c.as_str() || which == c.binary())
                && (state.uses(*c) || ctx.paths.core_bin(*c).exists())
        })
        .collect::<Vec<_>>();
    if targets.is_empty() {
        return Err("所选内核未安装".into());
    }
    let dir = temp_near(&ctx.paths.bin.join("placeholder"), "core-update")?;
    let result = (|| -> Result<()> {
        let mut staged = Vec::new();
        // All downloads are verified before the workflow snapshots the old
        // binaries and applies replacements inside its single transaction.
        for core in &targets {
            let wanted = args
                .get(1)
                .map(String::as_str)
                .unwrap_or(if *core == Core::Xray {
                    platform::TESTED_XRAY
                } else {
                    "latest"
                });
            if *core == Core::Xray && wanted != platform::TESTED_XRAY {
                eprintln!(
                    "指定的 Xray {wanted} 可能拒绝 sing-box REALITY 客户端；经过测试版本为 {}",
                    platform::TESTED_XRAY
                );
            }
            let path = dir.join(core.binary());
            platform::prepare_core(ctx, *core, wanted, &path)?;
            staged.push((*core, path));
        }
        workflow::apply_with_cores_locked(ctx, &state, &mutation_lock, &staged)?;
        println!("内核更新完成");
        Ok(())
    })();
    if result.is_ok() {
        let _ = fs::remove_dir_all(&dir);
    } else {
        eprintln!("已验证的内核更新文件保留: {}", dir.display());
    }
    result
}
/// args starts with the original CLI verb, followed by its arguments.
pub fn command(ctx: &Context, args: &[String]) -> Result<()> {
    let action = args.first().map(String::as_str).ok_or("缺少更新命令")?;
    let rest = &args[1..];
    match action {
        "update" => core_update(ctx, rest),
        "update-script" => program_update(ctx, rest, false),
        "update-check" => program_update(ctx, rest, true),
        "update-channel" => {
            if rest.len() > 1 {
                return Err("用法: update-channel [stable|testing]".into());
            }
            let ch = channel(ctx, rest.first().map(String::as_str))?;
            if !rest.is_empty() {
                util::atomic_write(&channel_path(ctx), format!("{ch}\n").as_bytes(), 0o600)?;
            }
            println!("当前更新渠道: {ch}");
            Ok(())
        }
        _ => Err("未知更新命令".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn versions_reject_malformed_and_compare_numerically() {
        assert!(semver("1.99.1").unwrap() < semver("2.0.0").unwrap());
        assert!(semver("../../1").is_err());
        assert!(semver("2.0").is_err());
    }
    #[test]
    fn artifact_integrity_is_required() {
        let data = b"a";
        assert!(verify_asset(
            &serde_json::json!({"size":1,"digest":format!("sha256:{}",util::sha256(data))}),
            data
        )
        .is_ok());
        assert!(verify_asset(&serde_json::json!({"size":1}), data).is_err());
    }
    #[test]
    fn rollback_restores_original_bytes() {
        let d = std::env::temp_dir().join(format!(
            "onebox-update-test-{}",
            util::random_hex(8).unwrap()
        ));
        fs::create_dir(&d).unwrap();
        let live = d.join("live");
        let new = d.join("new");
        fs::write(&live, b"old").unwrap();
        fs::write(&new, b"new").unwrap();
        let mut replacement = Replacement::snapshot(&live, &d.join("backup")).unwrap();
        replacement.replace(&new).unwrap();
        assert_eq!(fs::read(&live).unwrap(), b"new");
        replacement.restore().unwrap();
        assert_eq!(fs::read(&live).unwrap(), b"old");
        fs::remove_dir_all(d).unwrap();
    }
}

#[cfg(test)]
mod recovery_tests {
    use super::*;
    use crate::context::Paths;
    #[test]
    fn configuration_recovery_undoes_failed_schema_migration() {
        let root = std::env::temp_dir().join(format!(
            "onebox-recovery-test-{}",
            util::random_hex(8).unwrap()
        ));
        let ctx = Context {
            paths: Paths::isolated(&root),
            ..Context::default()
        };
        fs::create_dir_all(&ctx.paths.root).unwrap();
        fs::write(ctx.paths.legacy_state(), b"old-state").unwrap();
        fs::create_dir_all(ctx.paths.clients()).unwrap();
        fs::write(ctx.paths.clients().join("config.json"), b"old-client").unwrap();
        fs::create_dir_all(ctx.paths.root.join("subscription")).unwrap();
        fs::write(
            ctx.paths.root.join("subscription/settings.json"),
            b"old-device-tokens",
        )
        .unwrap();
        fs::create_dir_all(&ctx.paths.bin).unwrap();
        fs::write(ctx.paths.core_bin(Core::Singbox), b"old-core").unwrap();
        let snapshot = ConfigSnapshot::capture(&ctx, &root.join("snapshot")).unwrap();
        fs::write(ctx.paths.state(), b"new-schema").unwrap();
        fs::write(ctx.paths.legacy_state(), b"changed").unwrap();
        fs::write(ctx.paths.clients().join("config.json"), b"changed-client").unwrap();
        fs::write(
            ctx.paths.root.join("subscription/settings.json"),
            b"changed-device-tokens",
        )
        .unwrap();
        fs::write(ctx.paths.core_bin(Core::Singbox), b"changed-core").unwrap();
        transaction::restore_snapshot(&ctx, &snapshot.snapshot, &root.join("snapshot")).unwrap();
        assert!(!ctx.paths.state().exists());
        assert_eq!(fs::read(ctx.paths.legacy_state()).unwrap(), b"old-state");
        assert_eq!(
            fs::read(ctx.paths.clients().join("config.json")).unwrap(),
            b"old-client"
        );
        assert_eq!(
            fs::read(ctx.paths.root.join("subscription/settings.json")).unwrap(),
            b"old-device-tokens"
        );
        assert_eq!(
            fs::read(ctx.paths.core_bin(Core::Singbox)).unwrap(),
            b"old-core"
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn concurrent_updates_are_rejected() {
        let root = std::env::temp_dir().join(format!(
            "onebox-update-lock-test-{}",
            util::random_hex(8).unwrap()
        ));
        let ctx = Context {
            paths: Paths::isolated(&root),
            ..Context::default()
        };
        let first = update_lock(&ctx).unwrap();
        assert!(update_lock(&ctx).is_err());
        drop(first);
        assert!(update_lock(&ctx).is_ok());
        fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod persistent_recovery_tests {
    use super::*;
    use crate::context::Paths;
    fn fixture(phase: &str) -> (PathBuf, Context, ProgramJournal) {
        let root = std::env::temp_dir().join(format!(
            "onebox-persistent-update-{}",
            util::random_hex(8).unwrap()
        ));
        fs::create_dir_all(&root).unwrap();
        let ctx = Context {
            paths: Paths::isolated(&root),
            ..Context::default()
        };
        let work = temp_near(&ctx.paths.executable, "onebox-update").unwrap();
        fs::write(work.join("old"), b"trusted old executable").unwrap();
        fs::write(&ctx.paths.executable, b"verified new executable").unwrap();
        let journal = ProgramJournal {
            version: 1,
            work: work.file_name().unwrap().to_str().unwrap().into(),
            phase: phase.into(),
            old_existed: true,
            old_sha256: util::sha256(b"trusted old executable"),
            new_sha256: util::sha256(b"verified new executable"),
            snapshot: None,
        };
        journal.save(&ctx).unwrap();
        (root, ctx, journal)
    }
    #[test]
    fn every_uncommitted_crash_window_restores_old_manager() {
        for phase in ["prepared", "replacing", "replaced", "recovering"] {
            let (root, ctx, journal) = fixture(phase);
            let lock = transaction::acquire(&ctx).unwrap();
            let error = workflow::recover_locked(&ctx, &lock).unwrap_err();
            assert_eq!(error.downcast_ref::<crate::ExitError>().unwrap().code, 75);
            assert_eq!(
                fs::read(&ctx.paths.executable).unwrap(),
                b"trusted old executable"
            );
            assert!(!program_journal_path(&ctx).exists());
            assert!(!journal.directory(&ctx).unwrap().exists());
            assert!(workflow::recover_locked(&ctx, &lock).is_ok());
            fs::remove_dir_all(root).unwrap();
        }
    }
    #[test]
    fn committed_record_cleans_up_without_downgrading() {
        let (root, ctx, journal) = fixture("committed");
        let lock = transaction::acquire(&ctx).unwrap();
        workflow::recover_locked(&ctx, &lock).unwrap();
        assert_eq!(
            fs::read(&ctx.paths.executable).unwrap(),
            b"verified new executable"
        );
        assert!(!program_journal_path(&ctx).exists());
        assert!(!journal.directory(&ctx).unwrap().exists());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn corrupted_backup_is_rejected_before_program_changes() {
        let (root, ctx, journal) = fixture("replaced");
        fs::write(journal.directory(&ctx).unwrap().join("old"), b"corrupt").unwrap();
        let lock = transaction::acquire(&ctx).unwrap();
        assert!(recover_locked(&ctx, &lock)
            .unwrap_err()
            .to_string()
            .contains("SHA256"));
        assert_eq!(
            fs::read(&ctx.paths.executable).unwrap(),
            b"verified new executable"
        );
        assert!(program_journal_path(&ctx).exists());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn unrelated_program_and_escaped_backup_paths_are_not_overwritten() {
        let (root, ctx, mut journal) = fixture("replaced");
        fs::write(&ctx.paths.executable, b"unrelated replacement").unwrap();
        let lock = transaction::acquire(&ctx).unwrap();
        assert!(recover_locked(&ctx, &lock).is_err());
        journal.work = "../outside".into();
        journal.save(&ctx).unwrap();
        assert!(recover_locked(&ctx, &lock).is_err());
        assert_eq!(
            fs::read(&ctx.paths.executable).unwrap(),
            b"unrelated replacement"
        );
        fs::remove_dir_all(root).unwrap();
    }
}
