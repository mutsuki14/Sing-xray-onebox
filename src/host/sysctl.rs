//! sysctl transactions: change several kernel parameters together, verify
//! them, persist them to a `sysctl.d` file, and put everything back if any
//! step fails.
//!
//! Order (the critical section runs with INT/TERM/HUP blocked, so a signal
//! cannot stop us between two writes and leave a half-applied state; a
//! pending signal is delivered once the section ends):
//! 1. read the current value of every key (`sysctl -n`) and snapshot the
//!    persistence file (bytes + mode, or absence);
//! 2. one `sysctl -w k1=v1 k2=v2 …` call;
//! 3. read every key back and compare;
//! 4. write the file (`# Managed by Onebox` + `key = value` lines, 0644);
//! 5. on any failure: `sysctl -w key=old` for every key individually (each
//!    attempted even when another fails) and restore the old file bytes and
//!    mode, or remove a file that did not exist. Restore failures are
//!    printed as warnings with the value to fix by hand.
//!
//! Changes from v2 (where this lived inside `bbr.rs`): generic over keys so
//! other features can reuse it; a key-specific hint can replace the raw
//! `sysctl` error (BBR uses it for qdiscs the kernel lacks, I-8.1#11);
//! values may contain spaces (multi-field keys such as `tcp_rmem`).

use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::sys::exec::Cmd;
use crate::sys::fs::{atomic_write, ensure_dir, read_bounded, remove_file_if_exists};
use crate::sys::signal::BlockSignals;
use crate::ui::out;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Persistence files are tiny; refuse to snapshot anything large.
const MAX_FILE_BYTES: u64 = 1 << 20;
/// Mode of the persisted `sysctl.d` file.
pub const FILE_MODE: u32 = 0o644;

/// User-facing texts of a transaction (features keep their own wording).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Messages {
    /// An old value cannot be written back safely.
    pub unsafe_old: &'static str,
    /// Read-back after `sysctl -w` did not match.
    pub verify_failed: &'static str,
    /// Prefix of the warning for a value that could not be restored.
    pub restore_value_failed: &'static str,
    /// Prefix of the warning for a file that could not be restored.
    pub restore_file_failed: &'static str,
}

impl Messages {
    pub const GENERIC: Messages = Messages {
        unsafe_old: "无法安全保存原内核参数",
        verify_failed: "内核参数应用校验失败，已恢复原参数与配置",
        restore_value_failed: "恢复原内核参数失败，请手动核对",
        restore_file_failed: "恢复 sysctl 持久配置失败，请手动核对",
    };
}

/// Writes the persistence file: `(path, bytes, mode)`.
pub type Persist<'a> = dyn Fn(&Path, &[u8], u32) -> Result<()> + 'a;

/// A set of kernel parameters to change atomically (see module docs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SysctlTxn {
    /// `(key, value)` in application, persistence and restore order.
    pub settings: Vec<(String, String)>,
    /// The `sysctl.d` file to write; `None` changes runtime values only.
    pub file: Option<PathBuf>,
    pub messages: Messages,
    /// `(key, message)`: when `sysctl -w` fails naming `key`, report
    /// `message` instead of the raw error.
    pub hints: Vec<(String, String)>,
}

/// The current value of `key` (`sysctl -n`, trimmed).
pub fn read(ctx: &Ctx, key: &str) -> Result<String> {
    Ok(ctx
        .check(&Cmd::new("sysctl").args(["-n", key]))?
        .trim()
        .to_string())
}

/// Keys are dotted names; values are words or space-separated numbers.
/// Both end up as `sysctl -w key=value` arguments and in the sysctl.d file.
fn safe_key(key: &str) -> bool {
    !key.is_empty()
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b))
}

fn safe_value(value: &str) -> bool {
    !value.trim().is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-:/ \t".contains(&b))
}

/// Whitespace-insensitive comparison (`sysctl -n` prints tabs between fields).
fn same_value(a: &str, b: &str) -> bool {
    a.split_whitespace().eq(b.split_whitespace())
}

/// What existed at the persistence path before the transaction.
type FileSnapshot = Option<(Vec<u8>, u32)>;

impl SysctlTxn {
    pub fn new(settings: &[(&str, &str)]) -> SysctlTxn {
        SysctlTxn {
            settings: settings
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            file: None,
            messages: Messages::GENERIC,
            hints: Vec::new(),
        }
    }

    pub fn persist_to(mut self, file: impl Into<PathBuf>) -> SysctlTxn {
        self.file = Some(file.into());
        self
    }

    pub fn messages(mut self, messages: Messages) -> SysctlTxn {
        self.messages = messages;
        self
    }

    pub fn hint(mut self, key: &str, message: impl Into<String>) -> SysctlTxn {
        self.hints.push((key.to_string(), message.into()));
        self
    }

    /// The persisted file: a marker line plus `key = value` per setting.
    pub fn file_content(&self) -> String {
        let mut text = String::from("# Managed by Onebox\n");
        for (key, value) in &self.settings {
            text.push_str(&format!("{key} = {value}\n"));
        }
        text
    }

    /// Run the transaction, persisting with an atomic write.
    pub fn commit(&self, ctx: &Ctx) -> Result<()> {
        self.commit_with(ctx, &persist_file)
    }

    /// Run the transaction with an injectable file writer (tests simulate a
    /// write that fails after the rename).
    pub fn commit_with(&self, ctx: &Ctx, persist: &Persist<'_>) -> Result<()> {
        self.validate()?;
        let old = self.read_old(ctx)?;
        let snapshot = self.snapshot()?;
        let _blocked = BlockSignals::new()?;
        if let Err(e) = self.apply(ctx) {
            self.restore_values(ctx, &old);
            return Err(e);
        }
        let Some(file) = &self.file else {
            return Ok(());
        };
        if let Err(e) = persist(file, self.file_content().as_bytes(), FILE_MODE) {
            self.restore_values(ctx, &old);
            self.restore_file(file, &snapshot);
            return Err(e);
        }
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        for (key, value) in &self.settings {
            if !safe_key(key) || !safe_value(value) {
                return Err(Error::msg(format!("内核参数无效: {key}={value}")));
            }
        }
        Ok(())
    }

    fn read_old(&self, ctx: &Ctx) -> Result<Vec<String>> {
        let mut old = Vec::with_capacity(self.settings.len());
        for (key, _) in &self.settings {
            let value = read(ctx, key)?;
            if !safe_value(&value) {
                return Err(Error::msg(self.messages.unsafe_old));
            }
            old.push(value);
        }
        Ok(old)
    }

    fn snapshot(&self) -> Result<FileSnapshot> {
        let Some(file) = &self.file else {
            return Ok(None);
        };
        match std::fs::symlink_metadata(file) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::io(file, e)),
            Ok(meta) if !meta.is_file() => Err(Error::msg(format!(
                "sysctl 配置路径必须是普通文件: {}",
                file.display()
            ))),
            Ok(meta) => Ok(Some((
                read_bounded(file, MAX_FILE_BYTES)?,
                meta.permissions().mode() & 0o777,
            ))),
        }
    }

    /// One `sysctl -w` with every setting, then read every key back.
    fn apply(&self, ctx: &Ctx) -> Result<()> {
        let assignments = self.settings.iter().map(|(k, v)| format!("{k}={v}"));
        let cmd = Cmd::new("sysctl").arg("-w").args(assignments);
        let out = ctx.run(&cmd)?;
        if !out.ok() {
            let text = format!("{}{}", out.stderr, out.stdout);
            if let Some((_, hint)) = self.hints.iter().find(|(key, _)| text.contains(key)) {
                return Err(Error::msg(hint.clone()));
            }
            return Err(Error::Command {
                program: "sysctl".into(),
                code: out.code,
                detail: if out.stderr.trim().is_empty() {
                    out.stdout
                } else {
                    out.stderr
                },
            });
        }
        for (key, value) in &self.settings {
            if !same_value(&read(ctx, key)?, value) {
                return Err(Error::msg(self.messages.verify_failed));
            }
        }
        Ok(())
    }

    /// Write every old value back individually; one failure must not skip
    /// the others.
    fn restore_values(&self, ctx: &Ctx, old: &[String]) {
        for ((key, _), value) in self.settings.iter().zip(old) {
            let assignment = format!("{key}={value}");
            let restored = ctx.run(&Cmd::new("sysctl").args(["-w", &assignment]));
            if !restored.is_ok_and(|out| out.ok()) {
                out::warn(format!(
                    "{}: {assignment}",
                    self.messages.restore_value_failed
                ));
            }
        }
    }

    fn restore_file(&self, file: &Path, snapshot: &FileSnapshot) {
        let restored = match snapshot {
            Some((bytes, mode)) => atomic_write(file, bytes, *mode),
            None => remove_file_if_exists(file).map(drop),
        };
        if let Err(e) = restored {
            out::warn(format!("{}: {e}", self.messages.restore_file_failed));
        }
    }
}

/// Default writer: a missing `sysctl.d` directory is created 0755 (it is
/// read by system tools), then the file is replaced atomically.
fn persist_file(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        if !parent.exists() {
            ensure_dir(parent, 0o755)?;
        }
    }
    atomic_write(path, bytes, mode)
}

#[cfg(test)]
pub(crate) mod fake;
#[cfg(test)]
mod tests;
