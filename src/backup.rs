use crate::{context::Context, model::State, state, ui, util, workflow, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};

#[derive(Serialize, Deserialize)]
struct Manifest {
    schema: u8,
    label: String,
    created: u64,
    files: BTreeMap<String, String>,
}
fn directory(ctx: &Context) -> PathBuf {
    ctx.paths.root.join("backups")
}
fn id_valid(id: &str) -> bool {
    !id.is_empty()
        && id.len() < 100
        && id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_".contains(&c))
}
fn relative_valid(path: &str) -> bool {
    !path.is_empty()
        && Path::new(path)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
}
fn ignored(path: &Path) -> bool {
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    matches!(
        name,
        "backups" | "content-backups" | "nginx.pid" | "access.log" | "error.log"
    ) || (path.components().any(|c| c.as_os_str() == "acme")
        && (name.ends_with(".sh") || matches!(name, "dnsapi" | "deploy" | "notify" | ".git")))
}
fn copy(source: &Path, dest: &Path, count: &mut usize, bytes: &mut u64) -> Result<()> {
    let m = fs::symlink_metadata(source)?;
    if m.file_type().is_symlink()
        || (!m.is_file() && !m.is_dir())
        || (m.is_file() && m.nlink() != 1)
    {
        return Err("备份拒绝链接或特殊文件".into());
    }
    if m.is_dir() {
        fs::create_dir_all(dest)?;
        fs::set_permissions(dest, fs::Permissions::from_mode(0o700))?;
        for e in fs::read_dir(source)? {
            let e = e?;
            if !ignored(&e.path()) {
                copy(&e.path(), &dest.join(e.file_name()), count, bytes)?;
            }
        }
    } else {
        *count += 1;
        *bytes += m.len();
        if *count > 4096 || *bytes > 64 * 1024 * 1024 {
            return Err("备份超过 4096 文件或 64 MiB 限制".into());
        }
        util::atomic_write(dest, &fs::read(source)?, 0o600)?;
    }
    Ok(())
}
fn public_permissions(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || (!metadata.is_file() && !metadata.is_dir()) {
        return Err("网站恢复包含链接或特殊文件".into());
    }
    if metadata.is_dir() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
        for entry in fs::read_dir(path)? {
            public_permissions(&entry?.path())?;
        }
    } else {
        fs::set_permissions(path, fs::Permissions::from_mode(0o644))?;
    }
    Ok(())
}
fn inventory(root: &Path, path: &Path, out: &mut BTreeMap<String, String>) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    if m.file_type().is_symlink()
        || (!m.is_file() && !m.is_dir())
        || (m.is_file() && m.nlink() != 1)
    {
        return Err("备份包含不安全的文件类型".into());
    }
    if m.is_dir() {
        for e in fs::read_dir(path)? {
            inventory(root, &e?.path(), out)?;
        }
    } else {
        let rel = path
            .strip_prefix(root)?
            .to_str()
            .ok_or("备份文件名不是UTF-8")?;
        if rel != "manifest.json" && rel != "manifest" {
            out.insert(rel.to_string(), util::sha256(&fs::read(path)?));
        }
    }
    Ok(())
}
fn paths(ctx: &Context) -> [(&'static str, PathBuf); 5] {
    [
        ("tls", ctx.paths.tls()),
        ("site", ctx.paths.site()),
        ("public", ctx.paths.site_root.clone()),
        ("subscription", ctx.paths.root.join("subscription")),
        ("client", ctx.paths.clients()),
    ]
}
pub fn create(ctx: &Context, label: &str) -> Result<String> {
    create_kept(ctx, label, None)
}
fn create_kept(ctx: &Context, label: &str, keep: Option<&str>) -> Result<String> {
    let _lock = crate::transaction::acquire(ctx)?;
    if crate::transaction::load(ctx)?.is_some() || ctx.paths.root.join(".self-update.json").exists()
    {
        return Err("存在未完成事务，请先 recover".into());
    }
    let s = state::load(ctx)?;
    let id = format!("{}-{}", util::now(), util::random_hex(4)?);
    let root = directory(ctx);
    util::safe_path(&root)?;
    fs::create_dir_all(&root)?;
    let stage = root.join(format!(".new-{id}"));
    fs::create_dir(&stage)?;
    fs::set_permissions(&stage, fs::Permissions::from_mode(0o700))?;
    let result = (|| -> Result<()> {
        util::atomic_write(
            &stage.join("state.json"),
            &serde_json::to_vec_pretty(&s)?,
            0o600,
        )?;
        let mut count = 1;
        let mut bytes = 0;
        for (name, path) in paths(ctx) {
            if path.exists() {
                copy(&path, &stage.join(name), &mut count, &mut bytes)?;
            }
        }
        let mut files = BTreeMap::new();
        inventory(&stage, &stage, &mut files)?;
        let m = Manifest {
            schema: 2,
            label: label
                .chars()
                .filter(|c| !c.is_control())
                .take(120)
                .collect(),
            created: util::now(),
            files,
        };
        util::atomic_write(
            &stage.join("manifest.json"),
            &serde_json::to_vec_pretty(&m)?,
            0o600,
        )?;
        fs::rename(&stage, root.join(&id))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&stage);
    }
    result?;
    let mut ids = ids(ctx)?;
    ids.sort();
    ids.reverse();
    for old in ids.into_iter().skip(5) {
        if old != id && keep != Some(old.as_str()) {
            fs::remove_dir_all(root.join(old))?;
        }
    }
    Ok(id)
}
fn ids(ctx: &Context) -> Result<Vec<String>> {
    if !directory(ctx).exists() {
        return Ok(vec![]);
    }
    let mut result = Vec::new();
    for e in fs::read_dir(directory(ctx))? {
        let e = e?;
        if e.file_type()?.is_dir() {
            if let Some(id) = e.file_name().to_str() {
                if id_valid(id) {
                    result.push(id.into());
                }
            }
        }
    }
    result.sort();
    Ok(result)
}
pub fn list(ctx: &Context) -> Result<()> {
    for id in ids(ctx)?.into_iter().rev() {
        let path = directory(ctx).join(&id);
        let label = fs::read(path.join("manifest.json"))
            .ok()
            .and_then(|v| serde_json::from_slice::<Manifest>(&v).ok())
            .map(|v| v.label)
            .unwrap_or_else(|| {
                fs::read_to_string(path.join("label"))
                    .unwrap_or_else(|_| "旧版本备份".into())
                    .trim()
                    .into()
            });
        println!("{id}\t{label}");
    }
    Ok(())
}
fn resolve(ctx: &Context, id: &str) -> Result<(String, PathBuf)> {
    let id = if id == "latest" {
        ids(ctx)?.last().ok_or("没有备份")?.clone()
    } else {
        id.to_string()
    };
    if !id_valid(&id) {
        return Err("备份 ID 无效".into());
    }
    let path = directory(ctx).join(&id);
    util::safe_path(&path)?;
    if !path.is_dir() {
        return Err("备份不存在".into());
    }
    Ok((id, path))
}
fn validate(ctx: &Context, path: &Path) -> Result<State> {
    let mut actual = BTreeMap::new();
    inventory(path, path, &mut actual)?;
    if path.join("manifest.json").is_file() {
        let m: Manifest = serde_json::from_slice(&fs::read(path.join("manifest.json"))?)?;
        if m.schema != 2 || m.files != actual {
            return Err("备份完整性校验失败".into());
        }
        let s: State = serde_json::from_slice(&fs::read(path.join("state.json"))?)?;
        s.validate()?;
        Ok(s)
    } else {
        if fs::read_to_string(path.join("format"))?.trim() != "1" {
            return Err("未知旧备份格式".into());
        }
        let locations = fs::read_to_string(path.join("paths"))?;
        if locations.trim_end()
            != format!(
                "{}\n{}",
                ctx.paths.root.display(),
                ctx.paths.site_root.display()
            )
        {
            return Err("旧快照只能恢复到原管理路径".into());
        }
        let bytes = fs::read(path.join("manifest"))?;
        let mut chunks = bytes.split(|v| *v == 0).collect::<Vec<_>>();
        if chunks.last() == Some(&&b""[..]) {
            chunks.pop();
        }
        if chunks.len() % 2 != 0 {
            return Err("旧备份清单不完整".into());
        }
        let mut expected = BTreeMap::new();
        for pair in chunks.chunks(2) {
            let hash = std::str::from_utf8(pair[0])?;
            let rel = std::str::from_utf8(pair[1])?;
            if !relative_valid(rel) || expected.insert(rel.into(), hash.into()).is_some() {
                return Err("旧备份路径或重复条目无效".into());
            }
        }
        if expected != actual {
            return Err("旧备份完整性校验失败".into());
        }
        state::parse_nul(&fs::read(path.join("state.dat"))?)
    }
}
pub fn restore(ctx: &Context, id: &str) -> Result<()> {
    let (id, path) = resolve(ctx, id)?;
    let mut s = validate(ctx, &path)?;
    if !ui::confirm(ctx, &format!("恢复备份 {id}？当前配置会先备份"), false)? {
        return Ok(());
    }
    if state::installed(ctx) {
        create_kept(ctx, "before-restore", Some(&id))?;
    }
    s.set("RESTORE_PENDING_ID", id);
    state::attach_expected(ctx, &mut s)?;
    workflow::apply(ctx, &s)?;
    println!("备份已恢复");
    Ok(())
}
/// Called only after the workflow's rollback snapshot has been committed.
pub fn prepare_restore(ctx: &Context, s: &mut State) -> Result<()> {
    let Some(id) = s.values.remove("RESTORE_PENDING_ID") else {
        return Ok(());
    };
    let (_, path) = resolve(ctx, &id)?;
    validate(ctx, &path)?;
    for (name, target) in paths(ctx) {
        if name == "client" {
            continue;
        }
        let source = path.join(name);
        if !source.exists() {
            if name == "subscription" && target.exists() {
                remove_assets(&target)?;
            }
            continue;
        }
        util::safe_path(&target)?;
        if target.exists() {
            if (name == "public" || name == "site")
                && !target.join(".onebox-site-owned").exists()
                && fs::read_dir(&target)?.next().is_some()
            {
                return Err("拒绝覆盖非托管网站目录".into());
            }
            remove_assets(&target)?;
        }
        copy(&source, &target, &mut 0, &mut 0)?;
        if name == "public" {
            public_permissions(&target)?;
        }
        if name == "site" || name == "public" {
            util::atomic_write(&target.join(".onebox-site-owned"), b"onebox\n", 0o600)?;
        }
    }
    Ok(())
}
fn remove_assets(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    if m.file_type().is_symlink() {
        return Err("恢复目标包含符号链接".into());
    }
    if m.is_dir() {
        for e in fs::read_dir(path)? {
            let e = e?;
            if !ignored(&e.path()) {
                remove_assets(&e.path())?;
            }
        }
        if fs::read_dir(path)?.next().is_none() {
            fs::remove_dir(path)?
        }
    } else if m.is_file() {
        fs::remove_file(path)?
    } else {
        return Err("恢复目标包含特殊文件".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn restores_public_read_permissions_without_exposing_private_backup() {
        let root = std::env::temp_dir().join(format!(
            "onebox-backup-mode-{}",
            util::random_hex(6).unwrap()
        ));
        let source = root.join("backup");
        fs::create_dir_all(source.join("assets")).unwrap();
        util::atomic_write(&source.join("assets/style.css"), b"body{}", 0o600).unwrap();
        let public = root.join("public");
        copy(&source, &public, &mut 0, &mut 0).unwrap();
        public_permissions(&public).unwrap();
        assert_eq!(
            fs::metadata(public.join("assets")).unwrap().mode() & 0o777,
            0o755
        );
        assert_eq!(
            fs::metadata(public.join("assets/style.css"))
                .unwrap()
                .mode()
                & 0o777,
            0o644
        );
        assert_eq!(
            fs::metadata(source.join("assets/style.css"))
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn validates_ids_and_relative_paths() {
        assert!(!id_valid("../../etc"));
        assert!(!relative_valid("/etc/passwd"));
        assert!(!relative_valid("foo/../bar"));
        assert!(id_valid("1791000000-abcd"));
    }
    #[test]
    fn inventory_detects_tamper_and_links() {
        let p =
            std::env::temp_dir().join(format!("onebox-backup-{}", util::random_hex(5).unwrap()));
        fs::create_dir(&p).unwrap();
        fs::write(p.join("a"), b"before").unwrap();
        let mut a = BTreeMap::new();
        inventory(&p, &p, &mut a).unwrap();
        fs::write(p.join("a"), b"after").unwrap();
        let mut b = BTreeMap::new();
        inventory(&p, &p, &mut b).unwrap();
        assert_ne!(a, b);
        std::os::unix::fs::symlink("/etc/passwd", p.join("bad")).unwrap();
        assert!(inventory(&p, &p, &mut b).is_err());
        fs::remove_dir_all(p).unwrap();
    }
}
