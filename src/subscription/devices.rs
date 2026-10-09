//! Subscription devices: who may download the published snapshot.
//!
//! Each device holds a 16-hex id, a name and the SHA-256 of its bearer
//! token (64 lowercase hex characters from `/dev/urandom`); the token itself
//! is never stored and is shown exactly once, when the device is created or
//! reset.
//!
//! Storage: `ROOT/subscription/devices.json` (`{"schema":1,"devices":[…]}`,
//! pretty JSON, 0600, atomic). Until v3 writes that file, the device list
//! of a v2 node is read from v2's `subscription/settings.json`, read-only:
//! the first device change (or the first apply carrying the migrated
//! devices) writes `devices.json`, which from then on is the only source.
//! v3 never writes `settings.json`, so a v2 binary restored by a failed
//! upgrade still finds its own file.
//!
//! Device changes run under the node lock and refuse a pending journal
//! (`存在未完成配置事务，请先执行 recover 后修改订阅设备`); the store is read
//! after the lock is taken, so a concurrent revoke cannot be overwritten by
//! an add.
//!
//! Changes from v2:
//! - devices live outside the endpoint settings (state.json) because they
//!   change without a transaction;
//! - the name rule counts bytes, as v2 did, and now says so (G-8.1#13);
//!   names are trimmed; device ids are unique;
//! - the worker honors v2's `enabled` flag when it serves from v2's
//!   settings, and fails closed on any invalid device data.

use crate::ctx::Ctx;
use crate::domain::config::Device;
use crate::error::{Context, Error, Result};
use crate::paths::Paths;
use crate::sys::fs::{atomic_write, ensure_dir, read_bounded, sha256_hex};
use crate::sys::lock::FileLock;
use crate::sys::rand::{OsRandom, Random};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

/// Most devices a node keeps (v2 limit).
pub const MAX_DEVICES: usize = 256;
/// Longest device name in bytes (v2 limit; a Chinese character takes 3).
pub const NAME_MAX_BYTES: usize = 80;
/// Schema of `devices.json`.
pub const SCHEMA: u32 = 1;
/// Refusal while a node or self-update journal is pending (v2 text).
pub const PENDING: &str = "存在未完成配置事务，请先执行 recover 后修改订阅设备";
pub const NOT_ENABLED: &str = "请先 subscription enable";
pub const UNKNOWN_ID: &str = "设备 ID 不存在";
pub const BAD_NAME: &str = "设备名称应为 1–80 字节且不能含控制字符（一个汉字占 3 字节）";
pub const DUPLICATE_NAME: &str = "设备名称已存在";
pub const TOO_MANY: &str = "设备数量超过限制";
const INVALID: &str = "订阅设备数据无效";
const FILE_MAX: u64 = 1024 * 1024;
/// Hex characters of a token (32 random bytes).
const TOKEN_BYTES: usize = 32;
const ID_BYTES: usize = 8;

/// A device just created or reset: the only time its token is known.
#[derive(Clone, PartialEq, Eq)]
pub struct NewDevice {
    pub id: String,
    pub name: String,
    pub token: String,
}

impl std::fmt::Debug for NewDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewDevice")
            .field("id", &self.id)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// Where a loaded device list came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// `devices.json` (v3).
    Devices,
    /// v2 `settings.json`, read-only.
    V2Settings,
    /// Neither file exists.
    Empty,
}

/// `devices.json` on disk.
#[derive(Serialize, Deserialize)]
struct DevicesFile {
    schema: u32,
    devices: Vec<Device>,
}

/// The device part of v2 `settings.json` (other fields are ignored).
#[derive(Deserialize)]
struct V2Settings {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    devices: Vec<Device>,
}

/// The node's devices, as loaded from disk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceStore {
    devices: Vec<Device>,
    source: Source,
}

impl DeviceStore {
    /// `devices.json`, else v2 `settings.json` (invalid v2 entries are
    /// skipped, as the v2 migration does), else empty.
    pub fn load(paths: &Paths) -> Result<DeviceStore> {
        if let Some(bytes) = read_optional(&paths.devices())? {
            let devices = parse_devices(&bytes)?;
            return Ok(DeviceStore {
                devices,
                source: Source::Devices,
            });
        }
        match read_optional(&paths.subscription_v2_settings())? {
            Some(bytes) => Ok(DeviceStore {
                devices: valid_v2_devices(parse_v2(&bytes)?.devices),
                source: Source::V2Settings,
            }),
            None => Ok(DeviceStore {
                devices: Vec::new(),
                source: Source::Empty,
            }),
        }
    }

    pub fn devices(&self) -> &[Device] {
        &self.devices
    }

    pub fn source(&self) -> Source {
        self.source
    }

    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    /// Write `devices` as `devices.json` (validated; `subscription/` is
    /// created or tightened to 0700).
    pub fn write(paths: &Paths, devices: &[Device]) -> Result<()> {
        validate_all(devices)?;
        ensure_dir(&paths.subscription(), 0o700)?;
        let file = DevicesFile {
            schema: SCHEMA,
            devices: devices.to_vec(),
        };
        let mut text = serde_json::to_string_pretty(&file)?;
        text.push('\n');
        atomic_write(&paths.devices(), text.as_bytes(), 0o600)
    }

    /// Persist this store as `devices.json`.
    pub fn save(&self, paths: &Paths) -> Result<()> {
        Self::write(paths, &self.devices)
    }

    /// Add a device named `name` (trimmed) with a fresh token.
    pub fn create(&mut self, name: &str, rng: &mut dyn Random, now: u64) -> Result<NewDevice> {
        let name = name.trim();
        ensure!(valid_name(name), "{BAD_NAME}");
        ensure!(
            !self.devices.iter().any(|d| d.name == name),
            "{DUPLICATE_NAME}"
        );
        ensure!(self.devices.len() < MAX_DEVICES, "{TOO_MANY}");
        let id = self.fresh_id(rng)?;
        let token = rng.hex(TOKEN_BYTES)?;
        self.devices.push(Device {
            id: id.clone(),
            name: name.to_owned(),
            hash: token_hash(&token),
            created: now,
        });
        Ok(NewDevice {
            id,
            name: name.to_owned(),
            token,
        })
    }

    /// Remove the device with exactly this id.
    pub fn revoke(&mut self, id: &str) -> Result<Device> {
        let index = self
            .devices
            .iter()
            .position(|d| d.id == id)
            .ok_or_else(|| Error::msg(UNKNOWN_ID))?;
        Ok(self.devices.remove(index))
    }

    /// Give the device a new token (the old URLs stop working at once).
    pub fn reset(&mut self, id: &str, rng: &mut dyn Random, now: u64) -> Result<NewDevice> {
        let token = rng.hex(TOKEN_BYTES)?;
        let device = self
            .devices
            .iter_mut()
            .find(|d| d.id == id)
            .ok_or_else(|| Error::msg(UNKNOWN_ID))?;
        device.hash = token_hash(&token);
        device.created = now;
        Ok(NewDevice {
            id: device.id.clone(),
            name: device.name.clone(),
            token,
        })
    }

    /// A random id no device has (collisions of 64-bit ids are retried).
    fn fresh_id(&self, rng: &mut dyn Random) -> Result<String> {
        for _ in 0..8 {
            let id = rng.hex(ID_BYTES)?;
            if !self.devices.iter().any(|d| d.id == id) {
                return Ok(id);
            }
        }
        Err(Error::msg("无法生成唯一的设备 ID"))
    }
}

/// The device list (`devices.json`, else v2 `settings.json`).
pub fn list(paths: &Paths) -> Result<Vec<Device>> {
    Ok(DeviceStore::load(paths)?.devices)
}

/// `subscription add NAME`: requires an enabled subscription.
pub fn add(ctx: &Ctx, lock: &FileLock, name: &str) -> Result<NewDevice> {
    add_with(ctx, lock, name, &mut OsRandom, crate::sys::time::now())
}

/// [`add`] with injected randomness and clock.
pub fn add_with(
    ctx: &Ctx,
    lock: &FileLock,
    name: &str,
    rng: &mut dyn Random,
    now: u64,
) -> Result<NewDevice> {
    guard(ctx, lock)?;
    let loaded = crate::state::StateStore::load_required(ctx)?;
    ensure!(loaded.config.subscription.is_some(), "{NOT_ENABLED}");
    mutate(&ctx.paths, |store| store.create(name, rng, now))
}

/// `subscription revoke ID`: does not require an enabled subscription.
pub fn revoke(ctx: &Ctx, lock: &FileLock, id: &str) -> Result<()> {
    guard(ctx, lock)?;
    mutate(&ctx.paths, |store| store.revoke(id).map(|_| ()))
}

/// `subscription reset ID`: a new token for an existing device.
pub fn reset(ctx: &Ctx, lock: &FileLock, id: &str) -> Result<NewDevice> {
    reset_with(ctx, lock, id, &mut OsRandom, crate::sys::time::now())
}

/// [`reset`] with injected randomness and clock.
pub fn reset_with(
    ctx: &Ctx,
    lock: &FileLock,
    id: &str,
    rng: &mut dyn Random,
    now: u64,
) -> Result<NewDevice> {
    guard(ctx, lock)?;
    mutate(&ctx.paths, |store| store.reset(id, rng, now))
}

/// The caller holds the node lock and no transaction is pending.
fn guard(ctx: &Ctx, lock: &FileLock) -> Result<()> {
    lock.verify(&ctx.paths.lock())?;
    ensure!(
        !crate::apply::journal::pending(&ctx.paths)?.any(),
        "{PENDING}"
    );
    Ok(())
}

/// Load, change and write the store. The new state is on disk before the
/// caller sees (and prints) a token, so a printed token always works.
fn mutate<T>(paths: &Paths, change: impl FnOnce(&mut DeviceStore) -> Result<T>) -> Result<T> {
    let mut store = DeviceStore::load(paths)?;
    let result = change(&mut store)?;
    store.save(paths)?;
    Ok(result)
}

/// The devices the HTTP worker authorizes right now: `devices.json`, else
/// the devices of an *enabled* v2 `settings.json`. Anything unreadable or
/// invalid authorizes nobody (fail closed).
pub fn serving(paths: &Paths) -> Vec<Device> {
    match read_optional(&paths.devices()) {
        Ok(Some(bytes)) => return parse_devices(&bytes).unwrap_or_default(),
        Ok(None) => {}
        Err(_) => return Vec::new(),
    }
    match read_optional(&paths.subscription_v2_settings()) {
        Ok(Some(bytes)) => match parse_v2(&bytes) {
            Ok(settings) if settings.enabled => valid_v2_devices(settings.devices),
            _ => Vec::new(),
        },
        _ => Vec::new(),
    }
}

/// `sha256(token)` as 64 lowercase hex (the token's ASCII bytes are hashed).
pub fn token_hash(token: &str) -> String {
    sha256_hex(token.as_bytes())
}

/// Whether `token` belongs to any device. Every stored hash is compared
/// in full, without early exit, so timing reveals neither which device
/// matched nor how much of a hash did.
pub fn authorized(devices: &[Device], token: &str) -> bool {
    let hash = token_hash(token);
    devices.iter().fold(false, |found, d| {
        found | constant_time_eq(hash.as_bytes(), d.hash.as_bytes())
    })
}

/// Branch-free byte comparison (length mismatch is not secret).
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// 1–80 bytes without control characters.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= NAME_MAX_BYTES && !name.chars().any(char::is_control)
}

/// v2 `validate_settings` device rules.
pub fn valid_device(d: &Device) -> bool {
    lower_hex(&d.id, ID_BYTES * 2) && lower_hex(&d.hash, 64) && valid_name(&d.name)
}

/// Exactly `len` characters of `[0-9a-f]`.
pub fn lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn validate_all(devices: &[Device]) -> Result<()> {
    ensure!(devices.len() <= MAX_DEVICES, "订阅设备超过 256 个");
    let mut ids = BTreeSet::new();
    for d in devices {
        ensure!(valid_device(d) && ids.insert(d.id.as_str()), "{INVALID}");
    }
    Ok(())
}

fn parse_devices(bytes: &[u8]) -> Result<Vec<Device>> {
    let file: DevicesFile = serde_json::from_slice(bytes).context(INVALID)?;
    ensure!(
        file.schema <= SCHEMA,
        "订阅设备由更新版本的 Onebox 写入（schema {}），请先更新程序",
        file.schema
    );
    validate_all(&file.devices)?;
    Ok(file.devices)
}

fn parse_v2(bytes: &[u8]) -> Result<V2Settings> {
    serde_json::from_slice(bytes).context("v2 订阅设置 settings.json 无效")
}

/// Valid v2 devices with unique ids, in order, at most 256.
fn valid_v2_devices(list: Vec<Device>) -> Vec<Device> {
    let mut seen = BTreeSet::new();
    list.into_iter()
        .filter(|d| valid_device(d) && seen.insert(d.id.clone()))
        .take(MAX_DEVICES)
        .collect()
}

/// The file's bytes, `None` when it does not exist (symlinks refused).
fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::io(path, e)),
        Ok(_) => read_bounded(path, FILE_MAX).map(Some),
    }
}

#[cfg(test)]
mod tests;
