//! Persistent, bounded snapshots of Onebox-owned files. Recovery never sources
//! state as shell code and never follows a symlink from the snapshot tree.
use crate::{
    context::Context,
    model::{Core, State},
    util, Result,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Component, Path, PathBuf},
};

pub const SERVICES: &[&str] = &[
    "onebox-sing-box",
    "onebox-xray",
    "onebox-site",
    "onebox-network",
    "onebox-subscription",
    "onebox-subscription-web",
];
// Legacy network units are snapshotted and their enablement is restored, but
// must never be started/stopped as normal services during migration: the old
// oneshot may itself be running this transaction.
pub const LEGACY_NETWORK_SERVICES: &[&str] = &["onebox-net", "onebox-hop"];
const ROOT_ITEMS: &[&str] = &[
    "state.json",
    "onebox.conf",
    "onebox.conf.pre-rust",
    "sing-box.json",
    "xray.json",
    "client",
    "tls",
    "site",
    "subscription",
    "services",
    "firewall-v2.json",
    "firewall-acme.json",
    "firewall.list",
    "firewall-v1-migrated",
    "hop-v2.json",
];

pub struct Lock(File, bool);
impl Lock {
    pub fn is_inherited(&self) -> bool {
        self.1
    }
    pub fn as_raw_fd(&self) -> i32 {
        self.0.as_raw_fd()
    }
    pub fn verify(&self, ctx: &Context) -> Result<()> {
        let path = ctx.paths.root.join(".apply.lock");
        util::safe_path(&path)?;
        let actual = fs::metadata(path)?;
        let held = self.0.metadata()?;
        if !actual.is_file() || held.dev() != actual.dev() || held.ino() != actual.ino() {
            return Err("配置锁不属于当前实例".into());
        }
        Ok(())
    }
}
// Closing the final descriptor releases flock. Explicit LOCK_UN would also
// release a parent's lock when this descriptor was inherited during update.
pub fn acquire(ctx: &Context) -> Result<Lock> {
    util::safe_path(&ctx.paths.root)?;
    fs::create_dir_all(&ctx.paths.root)?;
    let path = ctx.paths.root.join(".apply.lock");
    util::safe_path(&path)?;
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    if let Some(raw) = std::env::var_os("ONEBOX_INHERITED_LOCK_FD") {
        let fd: i32 = raw.to_str().ok_or("继承锁描述符不是有效数字")?.parse()?;
        if fd != 198 {
            return Err("继承锁描述符无效".into());
        }
        let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        if duplicate < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let inherited = unsafe { File::from_raw_fd(duplicate) };
        let expected = file.metadata()?;
        let actual = inherited.metadata()?;
        if !actual.is_file() || actual.dev() != expected.dev() || actual.ino() != expected.ino() {
            return Err("继承锁与当前实例不匹配".into());
        }
        if unsafe { libc::flock(inherited.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("继承锁无法获得独占权限".into());
        }
        // Only a verified reserved descriptor is consumed. The private copy
        // is CLOEXEC, so subsequent core/systemctl children cannot leak it.
        unsafe {
            libc::close(fd);
        }
        std::env::remove_var("ONEBOX_INHERITED_LOCK_FD");
        return Ok(Lock(inherited, true));
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("另一个配置操作正在进行；稍后重试".into());
    }
    Ok(Lock(file, false))
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotEntry {
    pub target: PathBuf,
    pub present: bool,
    pub slot: String,
    pub sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Snapshot {
    pub entries: Vec<SnapshotEntry>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Journal {
    pub version: u8,
    pub old_state: Option<State>,
    pub active_services: Vec<String>,
    pub enabled_services: Vec<String>,
    pub cron_lines: Vec<String>,
    pub cron_available: bool,
    pub phase: String,
    pub snapshot: Snapshot,
}
pub fn directory(ctx: &Context) -> PathBuf {
    ctx.paths.root.join(".transaction")
}
fn manifest(ctx: &Context) -> PathBuf {
    directory(ctx).join("journal.json")
}

/// The allowlist is derived from this invocation's Context, never trusted from
/// a journal supplied by another machine or a hand-edited absolute path.
fn targets(ctx: &Context) -> Result<Vec<PathBuf>> {
    let mut out = ROOT_ITEMS
        .iter()
        .map(|s| ctx.paths.root.join(s))
        .collect::<Vec<_>>();
    out.push(ctx.paths.site_root.clone());
    out.push(ctx.paths.executable.clone());
    out.push(
        ctx.paths
            .site_root
            .with_file_name("onebox-subscription-acme"),
    );
    for core in [Core::Singbox, Core::Xray] {
        out.push(ctx.paths.core_bin(core));
    }
    for name in SERVICES {
        out.push(ctx.paths.systemd.join(format!("{name}.service")));
        out.push(ctx.paths.initd.join(name));
    }
    for path in crate::platform::boot::legacy_paths(ctx)? {
        if !out.contains(&path) {
            out.push(path);
        }
    }
    for path in crate::cert::legacy_deployment_paths(ctx)? {
        if !out.iter().any(|owned| path.starts_with(owned)) {
            out.push(path);
        }
    }
    Ok(out)
}
fn safe_roots(ctx: &Context) -> Result<()> {
    for root in [
        &ctx.paths.root,
        &ctx.paths.bin,
        &ctx.paths.site_root,
        &ctx.paths.systemd,
        &ctx.paths.initd,
    ] {
        util::safe_path(root)?;
        if root.parent().is_none()
            || ["/", "/etc", "/usr", "/var", "/home", "/root", "/tmp"]
                .iter()
                .any(|v| root == Path::new(v))
        {
            return Err(format!("事务目录范围过大: {}", root.display()).into());
        }
    }
    if ctx.paths.site_root.starts_with(&ctx.paths.root)
        || ctx.paths.root.starts_with(&ctx.paths.site_root)
    {
        return Err("网站目录和配置目录不能互相包含".into());
    }
    Ok(())
}
fn skip(path: &Path) -> bool {
    // Never recurse into backup generations, live sockets/PIDs/logs or ACME
    // code; preserve its cert/account/CA metadata for future renewals.
    let name = path.file_name().and_then(|v| v.to_str()).unwrap_or("");
    if matches!(
        name,
        "backups"
            | "content-backups"
            | ".transaction"
            | ".apply.lock"
            | "nginx.pid"
            | "error.log"
            | "access.log"
    ) {
        return true;
    }
    if path.components().any(|c| c.as_os_str() == "acme") {
        return matches!(name, "acme.sh" | "dnsapi" | "deploy" | "notify" | ".git")
            || name.ends_with(".sh")
            || name.starts_with(".download-");
    }
    false
}
fn copy_tree(source: &Path, dest: &Path, bytes: &mut u64) -> Result<()> {
    let meta = fs::symlink_metadata(source)?;
    if meta.file_type().is_symlink() {
        return Err(format!("快照拒绝符号链接: {}", source.display()).into());
    }
    if meta.is_dir() {
        fs::create_dir_all(dest)?;
        fs::set_permissions(
            dest,
            fs::Permissions::from_mode(meta.permissions().mode() & 0o777),
        )?;
        for item in fs::read_dir(source)? {
            let item = item?;
            if !skip(&item.path()) {
                copy_tree(&item.path(), &dest.join(item.file_name()), bytes)?;
            }
        }
        File::open(dest)?.sync_all()?;
    } else if meta.is_file() {
        *bytes = bytes.checked_add(meta.len()).ok_or("快照大小溢出")?;
        if *bytes > 2 * 1024 * 1024 * 1024 {
            return Err("快照超过 2 GiB，请先清理托管目录".into());
        }
        util::atomic_write(dest, &fs::read(source)?, meta.permissions().mode() & 0o777)?;
    } else {
        return Err(format!("快照拒绝特殊文件: {}", source.display()).into());
    }
    Ok(())
}
fn remove_included(path: &Path) -> Result<()> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    if meta.file_type().is_symlink() {
        return Err(format!("恢复拒绝符号链接: {}", path.display()).into());
    }
    if meta.is_dir() {
        for item in fs::read_dir(path)? {
            let item = item?;
            if !skip(&item.path()) {
                remove_included(&item.path())?;
            }
        }
        if fs::read_dir(path)?.next().is_none() {
            fs::remove_dir(path)?;
        }
    } else if meta.is_file() {
        fs::remove_file(path)?;
    } else {
        return Err(format!("恢复遇到特殊文件: {}", path.display()).into());
    }
    Ok(())
}
pub fn snapshot_files(ctx: &Context, destination: &Path) -> Result<Snapshot> {
    safe_roots(ctx)?;
    util::safe_path(destination)?;
    fs::create_dir_all(destination)?;
    fs::set_permissions(destination, fs::Permissions::from_mode(0o700))?;
    let mut entries = Vec::new();
    let mut bytes = 0;
    for (i, target) in targets(ctx)?.into_iter().enumerate() {
        util::safe_path(&target)?;
        let present = match fs::symlink_metadata(&target) {
            Ok(_) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(e.into()),
        };
        let slot = format!("item-{i}");
        if present {
            copy_tree(&target, &destination.join(&slot), &mut bytes)?;
        }
        let sha256 = if present {
            digest_tree(&destination.join(&slot))?
        } else {
            String::new()
        };
        entries.push(SnapshotEntry {
            target,
            present,
            slot,
            sha256,
        });
    }
    let snapshot = Snapshot { entries };
    util::atomic_write(
        &destination.join("snapshot.json"),
        &serde_json::to_vec_pretty(&snapshot)?,
        0o600,
    )?;
    Ok(snapshot)
}
pub fn validate_snapshot(ctx: &Context, snapshot: &Snapshot, source: &Path) -> Result<()> {
    safe_roots(ctx)?;
    util::safe_path(source)?;
    let allowed = targets(ctx)?.into_iter().collect::<BTreeSet<_>>();
    let mut found = BTreeSet::new();
    for entry in &snapshot.entries {
        if !allowed.contains(&entry.target)
            || !found.insert(entry.target.clone())
            || entry.slot.is_empty()
            || entry.slot.components_bad()
        {
            return Err("快照路径范围不合法".into());
        }
        util::safe_path(&entry.target)?;
        let saved = source.join(&entry.slot);
        util::safe_path(&saved)?;
        if entry.present && (!saved.exists() || digest_tree(&saved)? != entry.sha256) {
            return Err(format!("快照文件缺失或校验失败: {}", entry.slot).into());
        }
    }
    if found != allowed {
        return Err("快照缺少托管路径，拒绝部分恢复".into());
    }
    // Validate the complete source before touching live files, including deep
    // symlinks and corrupt file types. A temporary copy is intentionally not
    // required: read-only inspection keeps large core snapshots bounded.
    for entry in &snapshot.entries {
        if entry.present {
            validate_tree(&source.join(&entry.slot))?;
        }
    }
    Ok(())
}
pub fn restore_snapshot(ctx: &Context, snapshot: &Snapshot, source: &Path) -> Result<()> {
    validate_snapshot(ctx, snapshot, source)?;
    let mut errors = Vec::new();
    for entry in &snapshot.entries {
        let result = (|| -> Result<()> {
            remove_included(&entry.target)?;
            if entry.present {
                copy_tree(&source.join(&entry.slot), &entry.target, &mut 0)?;
            }
            Ok(())
        })();
        if let Err(e) = result {
            errors.push(format!("{}: {e}", entry.target.display()));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!("文件恢复不完整: {}", errors.join("; ")).into())
    }
}
trait SlotCheck {
    fn components_bad(&self) -> bool;
}
impl SlotCheck for String {
    fn components_bad(&self) -> bool {
        let mut p = Path::new(self).components();
        !matches!(p.next(), Some(Component::Normal(_))) || p.next().is_some()
    }
}
fn validate_tree(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() || (!meta.is_dir() && !meta.is_file()) {
        return Err("快照含符号链接或特殊文件".into());
    }
    if meta.is_dir() {
        for item in fs::read_dir(path)? {
            validate_tree(&item?.path())?;
        }
    }
    Ok(())
}
fn digest_tree(path: &Path) -> Result<String> {
    fn walk(path: &Path, relative: &Path, manifest: &mut Vec<u8>) -> Result<()> {
        let meta = fs::symlink_metadata(path)?;
        if meta.file_type().is_symlink() || (!meta.is_file() && !meta.is_dir()) {
            return Err("快照摘要拒绝符号链接或特殊文件".into());
        }
        let rel = util::path_str(relative)?.as_bytes();
        manifest.extend_from_slice(&(rel.len() as u64).to_be_bytes());
        manifest.extend_from_slice(rel);
        manifest.extend_from_slice(&(meta.permissions().mode() & 0o777).to_be_bytes());
        if meta.is_file() {
            if meta.len() > 2 * 1024 * 1024 * 1024 {
                return Err("快照单文件超过2GiB".into());
            }
            manifest.push(b'f');
            manifest.extend_from_slice(util::sha256(&fs::read(path)?).as_bytes());
        } else {
            manifest.push(b'd');
            let mut entries = fs::read_dir(path)?.collect::<std::result::Result<Vec<_>, _>>()?;
            entries.sort_by_key(|e| e.file_name());
            for entry in entries {
                walk(&entry.path(), &relative.join(entry.file_name()), manifest)?;
            }
        }
        Ok(())
    }
    let mut bytes = Vec::new();
    walk(path, Path::new(""), &mut bytes)?;
    Ok(util::sha256(&bytes))
}
pub fn begin(
    ctx: &Context,
    old_state: Option<State>,
    active_services: Vec<String>,
    enabled_services: Vec<String>,
    cron_lines: Vec<String>,
    cron_available: bool,
) -> Result<Journal> {
    let root = directory(ctx);
    if root.exists() {
        return Err("检测到未完成事务，请先恢复".into());
    }
    let stage = ctx
        .paths
        .root
        .join(format!(".transaction-new-{}", util::random_hex(12)?));
    let result = (|| -> Result<Journal> {
        fs::create_dir(&stage)?;
        fs::set_permissions(&stage, fs::Permissions::from_mode(0o700))?;
        let snapshot = snapshot_files(ctx, &stage.join("files"))?;
        let journal = Journal {
            version: 1,
            old_state,
            active_services,
            enabled_services,
            cron_lines,
            cron_available,
            phase: "prepared".into(),
            snapshot,
        };
        util::atomic_write(
            &stage.join("journal.json"),
            &serde_json::to_vec_pretty(&journal)?,
            0o600,
        )?;
        File::open(&stage)?.sync_all()?;
        fs::rename(&stage, &root)?;
        File::open(&ctx.paths.root)?.sync_all()?;
        Ok(journal)
    })();
    if stage.exists() {
        let _ = fs::remove_dir_all(stage);
    }
    result
}
pub fn load(ctx: &Context) -> Result<Option<Journal>> {
    let dir = directory(ctx);
    util::safe_path(&dir)?;
    if !dir.exists() {
        return Ok(None);
    }
    let bytes =
        fs::read(manifest(ctx)).map_err(|e| format!("事务日志不完整，未执行任何恢复: {e}"))?;
    if bytes.len() > 4 * 1024 * 1024 {
        return Err("事务日志过大".into());
    }
    let j: Journal = serde_json::from_slice(&bytes)?;
    if j.version != 1 {
        return Err("不支持的事务日志版本".into());
    }
    for name in j.active_services.iter().chain(&j.enabled_services) {
        if !SERVICES.contains(&name.as_str()) && !LEGACY_NETWORK_SERVICES.contains(&name.as_str()) {
            return Err("事务日志含未知服务".into());
        }
    }
    Ok(Some(j))
}
impl Journal {
    pub fn set_phase(&mut self, ctx: &Context, phase: &str) -> Result<()> {
        let mut next = self.clone();
        next.phase = phase.into();
        util::atomic_write(&manifest(ctx), &serde_json::to_vec_pretty(&next)?, 0o600)?;
        self.phase = next.phase;
        Ok(())
    }
    pub fn restore_files(&self, ctx: &Context) -> Result<()> {
        restore_snapshot(ctx, &self.snapshot, &directory(ctx).join("files"))
    }
    pub fn validate_files(&self, ctx: &Context) -> Result<()> {
        validate_snapshot(ctx, &self.snapshot, &directory(ctx).join("files"))
    }
    pub fn finish(&self, ctx: &Context) -> Result<()> {
        fs::remove_dir_all(directory(ctx))?;
        File::open(&ctx.paths.root)?.sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::Paths;
    fn fixture() -> (Context, PathBuf) {
        let root =
            std::env::temp_dir().join(format!("onebox-txn-{}", util::random_hex(8).unwrap()));
        let c = Context {
            paths: Paths::isolated(&root),
            ..Context::default()
        };
        fs::create_dir_all(&c.paths.root).unwrap();
        (c, root)
    }
    #[test]
    fn restores_owned_files_but_never_backup_or_acme_code() {
        let (c, r) = fixture();
        fs::create_dir_all(c.paths.tls().join("acme/certs")).unwrap();
        fs::create_dir_all(c.paths.root.join("backups")).unwrap();
        fs::write(c.paths.tls().join("cert.pem"), b"old").unwrap();
        fs::write(c.paths.tls().join("acme/acme.sh"), b"old-code").unwrap();
        fs::write(
            c.paths.tls().join("acme/certs/account.conf"),
            b"old-account",
        )
        .unwrap();
        let j = begin(&c, None, vec![], vec![], vec![], false).unwrap();
        fs::write(c.paths.tls().join("cert.pem"), b"new").unwrap();
        fs::write(c.paths.tls().join("acme/acme.sh"), b"new-code").unwrap();
        fs::write(
            c.paths.tls().join("acme/certs/account.conf"),
            b"new-account",
        )
        .unwrap();
        fs::write(c.paths.root.join("backups/untouched"), b"backup").unwrap();
        j.restore_files(&c).unwrap();
        j.restore_files(&c).unwrap();
        assert_eq!(fs::read(c.paths.tls().join("cert.pem")).unwrap(), b"old");
        assert_eq!(
            fs::read(c.paths.tls().join("acme/acme.sh")).unwrap(),
            b"new-code"
        );
        assert_eq!(
            fs::read(c.paths.tls().join("acme/certs/account.conf")).unwrap(),
            b"old-account"
        );
        assert!(c.paths.root.join("backups/untouched").exists());
        j.finish(&c).unwrap();
        fs::remove_dir_all(r).unwrap();
    }
    #[test]
    fn incomplete_journal_and_escape_paths_fail_closed() {
        let (c, r) = fixture();
        fs::create_dir(directory(&c)).unwrap();
        assert!(load(&c).is_err());
        fs::remove_dir(directory(&c)).unwrap();
        let mut j = begin(&c, None, vec![], vec![], vec![], false).unwrap();
        j.snapshot.entries[0].target = PathBuf::from("/etc/passwd");
        assert!(j.restore_files(&c).is_err());
        fs::remove_dir_all(r).unwrap();
    }
    #[test]
    fn refuses_deep_symlinks_before_publishing_journal() {
        let (c, r) = fixture();
        fs::create_dir_all(c.paths.clients()).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", c.paths.clients().join("bad")).unwrap();
        assert!(begin(&c, None, vec![], vec![], vec![], false).is_err());
        assert!(!directory(&c).exists());
        fs::remove_dir_all(r).unwrap();
    }
    #[test]
    fn lock_is_nonblocking_and_released() {
        let (c, r) = fixture();
        let l = acquire(&c).unwrap();
        assert!(acquire(&c).is_err());
        drop(l);
        assert!(acquire(&c).is_ok());
        fs::remove_dir_all(r).unwrap();
    }
    #[test]
    fn inherited_lock_keeps_parent_exclusion_and_rejects_other_instance() {
        use std::os::unix::process::CommandExt;
        const CHILD: &str = "ONEBOX_LOCK_TEST_ROOT";
        const ISOLATED: &str = "ONEBOX_LOCK_TEST_ISOLATED";
        if std::env::var_os(ISOLATED).is_none() {
            // A concurrent test's fork briefly inherits every CLOEXEC fd until
            // exec, which legitimately delays the final flock close. Keep the
            // close-release assertion in a process without unrelated forks.
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "transaction::tests::inherited_lock_keeps_parent_exclusion_and_rejects_other_instance", "--nocapture"])
                .env(ISOLATED, "1").output().unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        if let Some(root) = std::env::var_os(CHILD) {
            let c = Context {
                paths: Paths::isolated(Path::new(&root)),
                ..Context::default()
            };
            if std::env::var_os("ONEBOX_LOCK_TEST_REJECT").is_some() {
                assert!(acquire(&c).is_err());
                return;
            }
            let lock = acquire(&c).unwrap();
            assert!(lock.is_inherited());
            assert_ne!(
                unsafe { libc::fcntl(lock.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
                0
            );
            assert_eq!(unsafe { libc::fcntl(198, libc::F_GETFD) }, -1);
            assert!(std::env::var_os("ONEBOX_INHERITED_LOCK_FD").is_none());
            lock.verify(&c).unwrap();
            drop(lock);
            return;
        }
        let (c, root) = fixture();
        let (other, other_root) = fixture();
        let lock = acquire(&c).unwrap();
        assert!(!lock.is_inherited());
        let fd = lock.as_raw_fd();
        for reject in [false, true] {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command.args(["--exact", "transaction::tests::inherited_lock_keeps_parent_exclusion_and_rejects_other_instance", "--nocapture"])
                .env(CHILD, if reject { &other_root } else { &root }).env("ONEBOX_INHERITED_LOCK_FD", "198");
            if reject {
                command.env("ONEBOX_LOCK_TEST_REJECT", "1");
            }
            unsafe {
                command.pre_exec(move || {
                    if libc::dup2(fd, 198) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::fcntl(198, libc::F_SETFD, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let output = command.output().unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(acquire(&c).is_err(), "child must not unlock parent");
        }
        assert!(lock.verify(&other).is_err());
        drop(lock);
        assert!(acquire(&c).is_ok());
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(other_root).unwrap();
    }
    #[test]
    fn legacy_acme_deployment_is_restorable_after_old_state_retirement() {
        const CHILD: &str = "ONEBOX_LEGACY_ACME_TRANSACTION_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let home = std::env::temp_dir()
                .join(format!("onebox-old-acme-{}", util::random_hex(8).unwrap()));
            fs::create_dir(&home).unwrap();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "transaction::tests::legacy_acme_deployment_is_restorable_after_old_state_retirement", "--nocapture"])
                .env(CHILD, "1").env("ACME_HOME", &home).output().unwrap();
            fs::remove_dir_all(home).unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let (ctx, root) = fixture();
        let home = PathBuf::from(std::env::var_os("ACME_HOME").unwrap());
        fs::write(ctx.paths.legacy_state(), b"old-state").unwrap();
        let deployment = home.join("example.com_ecc/example.com.conf");
        let old = format!(
            "Le_RealFullChainPath='{}'\nLe_RealKeyPath='{}'\nLe_ReloadCmd=''\n",
            ctx.paths.tls().join("cert.pem").display(),
            ctx.paths.tls().join("key.pem").display()
        );
        util::atomic_write(&deployment, old.as_bytes(), 0o600).unwrap();
        let unrelated = home.join("other.example.com_ecc/other.example.com.conf");
        util::atomic_write(
            &unrelated,
            b"Le_RealFullChainPath='/etc/unrelated.pem'\nLe_RealKeyPath='/etc/unrelated.key'\n",
            0o600,
        )
        .unwrap();
        let journal = begin(&ctx, None, vec![], vec![], vec![], false).unwrap();
        assert!(journal
            .snapshot
            .entries
            .iter()
            .any(|e| e.target == deployment));
        assert!(!journal
            .snapshot
            .entries
            .iter()
            .any(|e| e.target == unrelated));
        crate::cert::disable_legacy_deployments(&ctx).unwrap();
        fs::remove_file(ctx.paths.legacy_state()).unwrap();
        journal.validate_files(&ctx).unwrap();
        journal.restore_files(&ctx).unwrap();
        assert_eq!(fs::read_to_string(deployment).unwrap(), old);
        assert_eq!(fs::read(ctx.paths.legacy_state()).unwrap(), b"old-state");
        assert!(fs::read_to_string(unrelated)
            .unwrap()
            .contains("/etc/unrelated.pem"));
        journal.finish(&ctx).unwrap();
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn corrupted_snapshot_is_rejected_before_live_files_change() {
        let (c, r) = fixture();
        fs::write(c.paths.state(), b"original").unwrap();
        let j = begin(&c, None, vec![], vec![], vec![], false).unwrap();
        fs::write(c.paths.state(), b"live-generation").unwrap();
        let entry = j
            .snapshot
            .entries
            .iter()
            .find(|e| e.target == c.paths.state())
            .unwrap();
        fs::write(directory(&c).join("files").join(&entry.slot), b"tampered").unwrap();
        assert!(j
            .restore_files(&c)
            .unwrap_err()
            .to_string()
            .contains("校验"));
        assert_eq!(fs::read(c.paths.state()).unwrap(), b"live-generation");
        assert!(directory(&c).exists());
        fs::remove_dir_all(r).unwrap();
    }
    #[test]
    fn legacy_boot_snapshot_restores_only_exact_hooks_after_removal() {
        let (ctx, root) = fixture();
        let hooks = crate::platform::boot::legacy_paths(&ctx).unwrap();
        assert_eq!(hooks.len(), 6);
        for (index, path) in hooks.iter().enumerate() {
            util::atomic_write(path, format!("old-hook-{index}\n").as_bytes(), 0o755).unwrap();
        }
        let unrelated = ctx
            .paths
            .initd
            .parent()
            .unwrap()
            .join("local.d/admin.start");
        util::atomic_write(&unrelated, b"admin-original\n", 0o755).unwrap();
        let journal = begin(&ctx, None, vec![], vec![], vec![], false).unwrap();
        assert!(hooks.iter().all(|path| journal
            .snapshot
            .entries
            .iter()
            .filter(|entry| entry.target == *path)
            .count()
            == 1));
        assert!(!journal
            .snapshot
            .entries
            .iter()
            .any(|entry| unrelated.starts_with(&entry.target)));
        for path in &hooks {
            fs::remove_file(path).unwrap();
        }
        fs::write(&unrelated, b"admin-concurrent-change\n").unwrap();
        // The allowlist must remain stable after migration removed every hook.
        journal.validate_files(&ctx).unwrap();
        journal.restore_files(&ctx).unwrap();
        for (index, path) in hooks.iter().enumerate() {
            assert_eq!(
                fs::read(path).unwrap(),
                format!("old-hook-{index}\n").as_bytes()
            );
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o755
            );
        }
        assert_eq!(fs::read(unrelated).unwrap(), b"admin-concurrent-change\n");
        journal.finish(&ctx).unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
