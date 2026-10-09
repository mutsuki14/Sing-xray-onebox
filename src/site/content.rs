//! The website's content: the web root (`site_root`, 0755 dirs / 0644
//! files), the generated homepage marker `ROOT/site/index.sha256`, content
//! backups `ROOT/site/content-backups/<unix>-<8 hex>/` and the preview
//! file `ROOT/site/preview.html`.
//!
//! Publishing (template, import, restore) is staged: the new tree is
//! copied into a sibling `.onebox-site-<id>` of the web root, the live
//! `.well-known` (pending ACME challenges) is carried over, the live root
//! is backed up, then the two trees are swapped atomically
//! (`renameat2(RENAME_EXCHANGE)`, or two renames with rollback where the
//! filesystem lacks it). Sources may not contain symlinks, special files or
//! hard links and are limited to 256 MiB; they are read through descriptors
//! (`copy_tree`), so a source another user can write cannot redirect the
//! copy by swapping a directory for a symlink midway. Modes are forced to
//! 0755/0644. Publishing
//! only happens inside an apply, after the transaction snapshot, so an
//! interruption is rolled back with everything else.
//!
//! `index.sha256` holds the SHA-256 of a generated `index.html`; while it
//! matches, the homepage counts as generated (`site title` may replace it);
//! imports remove it. An existing `index.html` is only ever replaced by an
//! explicit publish: the default homepage is written only when there is
//! none (v2, user edits survive `regen`), and title / template / theme /
//! description changes reach the page through `SiteContent::Template`,
//! which the CLI sets with them (v2 published the page in the same apply).
//! The settings are therefore never compared with the page: a restored
//! backup stays as it was even though the configuration names other
//! settings.
//!
//! Changes from v2:
//! - only the 10 newest content backups are kept (v2 never pruned,
//!   F-8.1#20);
//! - a backup remembers whether its homepage was generated, so restoring
//!   it keeps `site title` working (v2 dropped the marker, F-8.1#20);
//! - `.well-known` and Onebox markers are skipped only at the top level of
//!   an import (v2 dropped nested `.well-known` directories, F-8.1#19);
//! - imports from inside the private configuration tree (`ROOT`, FRP root)
//!   are refused, not only from `/etc` itself;
//! - hard links in a source are refused and sources are copied through
//!   descriptors, not by path (v2 copied whatever a swapped path named);
//! - error messages name the offending path.

use crate::error::{Error, Result};
use crate::paths::Paths;
use crate::sys::fs::{
    atomic_write, copy_tree, ensure_dir, read_bounded, remove_file_if_exists,
    remove_tree_if_exists, rename_exchange, sha256_hex, CopyLimits,
};
use crate::sys::time::now;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Marker proving Onebox owns a directory (`onebox\n`, 0600).
pub const OWNED_MARKER: &str = ".onebox-site-owned";
/// Inside a content backup: the generated homepage's hash.
pub const BACKUP_INDEX_MARKER: &str = ".onebox-index.sha256";
/// Content backups kept after a publish.
pub const KEEP_BACKUPS: usize = 10;
const MAX_CONTENT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_CONTENT_ENTRIES: usize = 100_000;
const LIMIT_MESSAGE: &str = "网站内容超过 256 MiB 或 100000 个文件";
const INDEX_MAX: u64 = 16 * 1024 * 1024;
/// Directories never imported from (v2 list plus kernel trees).
const SYSTEM_DIRS: [&str; 10] = [
    "/", "/etc", "/usr", "/var", "/root", "/home", "/proc", "/sys", "/dev", "/boot",
];
/// Web roots that would expose or clobber system trees (v2 `paths_safe`).
const UNSAFE_ROOTS: [&str; 8] = [
    "/", "/etc", "/var", "/var/lib", "/usr", "/home", "/root", "/tmp",
];

/// One content backup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContentBackup {
    /// `<unix seconds>-<8 hex>`.
    pub id: String,
    pub created: u64,
    pub path: PathBuf,
}

/// The website content of one node.
pub struct ContentStore<'a> {
    paths: &'a Paths,
}

impl<'a> ContentStore<'a> {
    pub fn new(paths: &'a Paths) -> ContentStore<'a> {
        ContentStore { paths }
    }

    pub fn web_root(&self) -> &Path {
        &self.paths.site_root
    }
    fn site_dir(&self) -> PathBuf {
        self.paths.site()
    }
    pub fn index(&self) -> PathBuf {
        self.web_root().join("index.html")
    }
    pub fn index_hash_file(&self) -> PathBuf {
        self.site_dir().join("index.sha256")
    }
    pub fn backups_dir(&self) -> PathBuf {
        self.site_dir().join("content-backups")
    }
    pub fn preview_file(&self) -> PathBuf {
        self.site_dir().join("preview.html")
    }

    /// v2 `paths_safe`: the web root is a dedicated directory, neither a
    /// system directory nor inside (or around) the private configuration.
    pub fn check_paths(&self) -> Result<()> {
        let root = self.web_root();
        let unsafe_root = root.parent().is_none()
            || UNSAFE_ROOTS.iter().any(|p| root == Path::new(p))
            || root.starts_with(&self.paths.root)
            || self.paths.root.starts_with(root);
        if unsafe_root {
            return Err(Error::msg("网站目录必须独立于私密配置和系统目录"));
        }
        Ok(())
    }

    /// Create the site directories and ownership markers. A non-empty web
    /// root without the marker was not made by Onebox: refused.
    pub fn prepare(&self) -> Result<()> {
        self.check_paths()?;
        ensure_dir(&self.site_dir(), 0o700)?;
        let root = self.web_root();
        let foreign = root.exists()
            && !root.join(OWNED_MARKER).exists()
            && fs::read_dir(root)
                .map_err(|e| Error::io(root, e))?
                .next()
                .is_some();
        if foreign {
            return Err(Error::msg("网站目录含未托管内容，请改用 site import"));
        }
        for dir in [
            root.to_path_buf(),
            root.join(".well-known"),
            root.join(".well-known/acme-challenge"),
        ] {
            ensure_dir(&dir, 0o755)?;
        }
        atomic_write(&root.join(OWNED_MARKER), b"onebox\n", 0o600)?;
        atomic_write(&self.site_dir().join(OWNED_MARKER), b"onebox\n", 0o600)
    }

    /// Whether `index.html` is still the generated homepage.
    pub fn is_generated(&self) -> Result<bool> {
        let Ok(saved) = read_bounded(&self.index_hash_file(), 1024) else {
            return Ok(false);
        };
        let Ok(index) = read_bounded(&self.index(), INDEX_MAX) else {
            return Ok(false);
        };
        Ok(String::from_utf8_lossy(&saved).trim() == sha256_hex(&index))
    }

    /// Write the homepage `html` (marked generated) when there is no
    /// `index.html` at all; an existing page is left alone whatever it is
    /// (module docs). Returns whether it was written.
    pub fn ensure_default(&self, html: &str) -> Result<bool> {
        let index = self.index();
        if fs::symlink_metadata(&index).is_ok() {
            return Ok(false);
        }
        atomic_write(&index, html.as_bytes(), 0o644)?;
        self.write_hash(html.as_bytes())?;
        Ok(true)
    }

    fn write_hash(&self, index: &[u8]) -> Result<()> {
        atomic_write(&self.index_hash_file(), sha256_hex(index).as_bytes(), 0o600)
    }

    /// Publish a generated homepage; returns the backup id of the old content.
    pub fn publish_template(&self, html: &str) -> Result<String> {
        let source = self
            .site_dir()
            .join(format!(".content-{}", crate::sys::rand::hex(8)?));
        let result = ensure_dir(&source, 0o700)
            .and_then(|()| atomic_write(&source.join("index.html"), html.as_bytes(), 0o644))
            .and_then(|()| self.publish(&source, true));
        let _ = remove_tree_if_exists(&source);
        result
    }

    /// Publish a local directory (`site import`).
    pub fn import(&self, source: &Path) -> Result<String> {
        let source = self.check_import(source)?;
        self.publish(&source, false)
    }

    /// Restore a content backup (`latest` = newest); returns the id of the
    /// backup taken of the content it replaced.
    pub fn restore(&self, which: &str) -> Result<String> {
        let backup = self.find_backup(which)?;
        let generated = match read_bounded(&backup.path.join(BACKUP_INDEX_MARKER), 1024) {
            Ok(hash) => read_bounded(&backup.path.join("index.html"), INDEX_MAX)
                .is_ok_and(|index| String::from_utf8_lossy(&hash).trim() == sha256_hex(&index)),
            Err(_) => false,
        };
        self.publish(&backup.path, generated)
    }

    /// Content backups, newest first.
    pub fn backups(&self) -> Result<Vec<ContentBackup>> {
        let dir = self.backups_dir();
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(Error::io(&dir, e)),
        };
        let mut backups = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| Error::io(&dir, e))?;
            let id = entry.file_name().to_string_lossy().into_owned();
            let is_dir = entry.file_type().is_ok_and(|t| t.is_dir());
            if let Some(created) = backup_time(&id).filter(|_| is_dir) {
                backups.push(ContentBackup {
                    path: entry.path(),
                    id,
                    created,
                });
            }
        }
        backups.sort_by(|a, b| (b.created, &b.id).cmp(&(a.created, &a.id)));
        Ok(backups)
    }

    /// Write `html` to `ROOT/site/preview.html` (0600) and return the path.
    pub fn preview(&self, html: &str) -> Result<PathBuf> {
        let path = self.preview_file();
        atomic_write(&path, html.as_bytes(), 0o600)?;
        Ok(path)
    }

    fn find_backup(&self, which: &str) -> Result<ContentBackup> {
        let backups = self.backups()?;
        if which == "latest" {
            return backups
                .into_iter()
                .next()
                .ok_or_else(|| Error::msg("没有网站备份"));
        }
        if which.is_empty()
            || !which
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(Error::msg("无效备份 ID"));
        }
        backups
            .into_iter()
            .find(|b| b.id == which)
            .ok_or_else(|| Error::msg(format!("网站备份不存在: {which}")))
    }

    /// The canonical import source, refusing recursion, system and private
    /// configuration directories (the CLI checks this before an apply).
    pub fn check_import(&self, source: &Path) -> Result<PathBuf> {
        let canonical = fs::canonicalize(source)
            .ok()
            .filter(|p| p.is_dir())
            .ok_or_else(|| Error::msg(format!("导入目录不存在或不是目录: {}", source.display())))?;
        let root =
            fs::canonicalize(self.web_root()).unwrap_or_else(|_| self.web_root().to_path_buf());
        let recursive =
            canonical == root || root.starts_with(&canonical) || canonical.starts_with(&root);
        if recursive || SYSTEM_DIRS.iter().any(|p| canonical == Path::new(p)) {
            return Err(Error::msg("不允许递归导入或导入系统目录"));
        }
        let private = [&self.paths.root, &self.paths.frp_root]
            .into_iter()
            .any(|p| {
                let p = fs::canonicalize(p).unwrap_or_else(|_| p.clone());
                canonical.starts_with(&p) || p.starts_with(&canonical)
            });
        if private {
            return Err(Error::msg("不能从 Onebox 配置目录导入网站"));
        }
        Ok(canonical)
    }

    /// Stage `source`, back up the live root, swap them (module docs).
    fn publish(&self, source: &Path, generated: bool) -> Result<String> {
        self.check_paths()?;
        scan(source, true)?;
        if !fs::symlink_metadata(source.join("index.html")).is_ok_and(|m| m.is_file()) {
            return Err(Error::msg("网站需要 index.html"));
        }
        let id = format!("{}-{}", now(), crate::sys::rand::hex(4)?);
        let stage = self.web_root().with_file_name(format!(".onebox-site-{id}"));
        let result = self.publish_staged(source, &stage, &id, generated);
        let _ = remove_tree_if_exists(&stage);
        result?;
        self.prune()?;
        Ok(id)
    }

    fn publish_staged(&self, source: &Path, stage: &Path, id: &str, generated: bool) -> Result<()> {
        let limits = CopyLimits::new(MAX_CONTENT_BYTES, MAX_CONTENT_ENTRIES).message(LIMIT_MESSAGE);
        // The source may be writable by another user: copy_tree reads it
        // through descriptors, so swapping its directories for symlinks
        // during the copy cannot reach outside it, and hard links (which
        // could name a file only root may read) are refused there as well.
        let from_source = limits.refuse_hard_links();
        copy_tree(source, stage, &|p| top_level_skip(source, p), &from_source)?;
        let live_challenges = self.web_root().join(".well-known");
        if live_challenges.is_dir() {
            copy_tree(
                &live_challenges,
                &stage.join(".well-known"),
                &|_| false,
                &limits,
            )?;
        }
        force_modes(stage)?;
        atomic_write(&stage.join(OWNED_MARKER), b"onebox\n", 0o600)?;
        self.backup_live(id, &limits)?;
        self.swap(stage)?;
        if generated {
            self.write_hash(&read_bounded(&self.index(), INDEX_MAX)?)
        } else {
            remove_file_if_exists(&self.index_hash_file()).map(|_| ())
        }
    }

    /// Copy the live root into `content-backups/<id>` (dir 0700).
    fn backup_live(&self, id: &str, limits: &CopyLimits) -> Result<()> {
        let root = self.web_root();
        if !root.exists() {
            return Ok(());
        }
        ensure_dir(&self.backups_dir(), 0o700)?;
        let backup = self.backups_dir().join(id);
        copy_tree(root, &backup, &|p| top_level_skip(root, p), limits)?;
        if self.is_generated()? {
            let hash = sha256_hex(&read_bounded(&self.index(), INDEX_MAX)?);
            atomic_write(&backup.join(BACKUP_INDEX_MARKER), hash.as_bytes(), 0o600)?;
        }
        ensure_dir(&backup, 0o700)
    }

    /// Put `stage` in place of the live root; the old tree ends up at
    /// `stage` (removed by the caller).
    fn swap(&self, stage: &Path) -> Result<()> {
        let root = self.web_root();
        if !root.exists() {
            return fs::rename(stage, root).map_err(|e| Error::io(root, e));
        }
        if rename_exchange(stage, root).is_ok() {
            return Ok(());
        }
        let old = stage.with_extension("old");
        fs::rename(root, &old).map_err(|e| Error::io(root, e))?;
        if let Err(e) = fs::rename(stage, root) {
            let _ = fs::rename(&old, root);
            return Err(Error::io(root, e));
        }
        fs::rename(&old, stage).map_err(|e| Error::io(stage, e))
    }

    /// Keep the [`KEEP_BACKUPS`] newest backups.
    fn prune(&self) -> Result<()> {
        for old in self.backups()?.into_iter().skip(KEEP_BACKUPS) {
            remove_tree_if_exists(&old.path)?;
        }
        Ok(())
    }
}

/// `<unix>-<8 hex>` → unix seconds.
fn backup_time(id: &str) -> Option<u64> {
    let (secs, suffix) = id.split_once('-')?;
    let hex_ok = suffix.len() == 8 && suffix.bytes().all(|b| b.is_ascii_hexdigit());
    hex_ok.then(|| secs.parse().ok()).flatten()
}

/// Skipped at the top level of a published or backed-up tree: pending
/// ACME challenges and Onebox's own markers.
fn top_level_skip(base: &Path, path: &Path) -> bool {
    path.parent() == Some(base)
        && path.file_name().is_some_and(|n| {
            let n = n.to_string_lossy();
            n == ".well-known" || n.starts_with(".onebox-")
        })
}

/// Refuse symlinks, special files and hard links anywhere in `dir` (v2
/// messages; hard links are new). A check by path, for clear messages
/// before anything is staged; the copy enforces the same rules itself.
fn scan(dir: &Path, top: bool) -> Result<()> {
    for entry in fs::read_dir(dir).map_err(|e| Error::io(dir, e))? {
        let path = entry.map_err(|e| Error::io(dir, e))?.path();
        if top && top_level_skip(dir, &path) {
            continue;
        }
        let meta = fs::symlink_metadata(&path).map_err(|e| Error::io(&path, e))?;
        if meta.file_type().is_symlink() {
            return Err(Error::msg(format!(
                "网站内容不能包含符号链接: {}",
                path.display()
            )));
        }
        if meta.is_dir() {
            scan(&path, false)?;
        } else if !meta.is_file() {
            return Err(Error::msg(format!(
                "网站内容包含特殊文件: {}",
                path.display()
            )));
        } else if meta.nlink() > 1 {
            return Err(Error::msg(format!(
                "网站内容不能包含硬链接: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

/// Directories 0755, files 0644 (the web root is world-readable content).
fn force_modes(dir: &Path) -> Result<()> {
    for entry in fs::read_dir(dir).map_err(|e| Error::io(dir, e))? {
        let path = entry.map_err(|e| Error::io(dir, e))?.path();
        let meta = fs::symlink_metadata(&path).map_err(|e| Error::io(&path, e))?;
        if meta.is_dir() {
            force_modes(&path)?;
        }
        let mode = if meta.is_dir() { 0o755 } else { 0o644 };
        fs::set_permissions(&path, fs::Permissions::from_mode(mode))
            .map_err(|e| Error::io(&path, e))?;
    }
    fs::set_permissions(dir, fs::Permissions::from_mode(0o755)).map_err(|e| Error::io(dir, e))
}

#[cfg(test)]
mod tests;
