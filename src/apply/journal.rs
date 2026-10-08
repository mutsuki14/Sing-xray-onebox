//! The node transaction journal `ROOT/.transaction/journal.json`: types,
//! loading and validation of its contents. Staging, the stage list,
//! rollback and recovery live in the apply engine.
//!
//! Layout (v2, kept):
//! ```text
//! ROOT/.transaction/         0700, published by renaming a staged directory
//!   journal.json             0600, pretty JSON (this module)
//!   files/snapshot.json      the snapshot of every owned path
//!   files/item-0 … item-N    the snapshot slots
//! ```
//! Two versions are read:
//! - version 1 (written by v2.x): `old_state` is v2's `{"values":{…}}`,
//!   kept as raw JSON for the engine to migrate with `state::v2`; cron is
//!   `cron_lines` + `cron_available`; snapshots are validated against v2's
//!   allowlist. A version-1 journal is rewritten in version-1 shape (only
//!   its phase changes), so it stays what v2 wrote;
//! - version 2 (written by v3): adds the change `reason`, records the old
//!   configuration typed (`old_config`), cron lines with their positions
//!   (`cron`), and validates snapshots against owned-root patterns of the
//!   recorded targets.
//!
//! Changes from v2:
//! - the phase is a typed enum (unknown phases are refused instead of being
//!   rolled back blindly);
//! - a `.transaction` that is not a real directory is refused;
//! - the recorded old state is checked when the journal is read (v2 noticed
//!   a malformed one only in `rollback-services`, after stopping services
//!   and restoring files), and [`Journal::validate`] checks everything a
//!   rollback needs before the first rollback phase;
//! - [`pending`] reports both journals for the operations that must not run
//!   while a recovery is due (backup, doctor, uninstall, device changes) and
//!   treats a corrupt journal as an error, never as "nothing pending".

use crate::apply::program_journal;
use crate::apply::snapshot::{self, node_allowlist, v2_node_allowlist, Allowlist, Snapshot};
use crate::domain::config::NodeConfig;
use crate::error::{Context, Error, Result};
use crate::host::cron::CronSnapshot;
use crate::host::service as svc;
use crate::paths::Paths;
use crate::sys::fs::{atomic_write, read_bounded};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

/// Version written by v3.
pub const VERSION: u8 = 2;
/// Version written by v2.x.
pub const V2_VERSION: u8 = 1;
/// Largest journal accepted (v2).
pub const MAX_BYTES: u64 = 4 * 1024 * 1024;
pub const JOURNAL_FILE: &str = "journal.json";
/// The snapshot directory inside the journal directory.
pub const FILES_DIR: &str = "files";
/// Node services in canonical (start) order.
pub const SERVICES: [&str; 6] = [
    svc::SUBSCRIPTION,
    svc::SITE,
    svc::SUBSCRIPTION_WEB,
    svc::SING_BOX,
    svc::XRAY,
    svc::NETWORK,
];
/// v1 network boot units: their enablement is journaled and restored, but
/// they are never started or stopped.
pub const LEGACY_NETWORK_SERVICES: [&str; 2] = ["onebox-net", "onebox-hop"];
/// Refusal of operations that must wait for `onebox recover` (v2 wording).
pub const PENDING_MESSAGE: &str = "存在未完成事务，请先 recover";

/// Journal phases with their v2 names: the stages in order, then the
/// terminal and rollback phases.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    Prepared,
    PrepareState,
    ReplaceCores,
    PrepareCores,
    PrepareCertificates,
    CheckConfigurations,
    StopOldServices,
    CommitConfigurations,
    ConfigureServices,
    ApplyWebsite,
    ApplyNetwork,
    StartCores,
    PublishClients,
    PublishSubscription,
    Finalize,
    Committed,
    RollbackStop,
    RollbackFiles,
    RollbackServices,
    RolledBack,
}

impl Phase {
    /// The apply stages in execution order (`replace-cores` only runs with
    /// replacement cores).
    pub const STAGES: [Phase; 14] = [
        Phase::PrepareState,
        Phase::ReplaceCores,
        Phase::PrepareCores,
        Phase::PrepareCertificates,
        Phase::CheckConfigurations,
        Phase::StopOldServices,
        Phase::CommitConfigurations,
        Phase::ConfigureServices,
        Phase::ApplyWebsite,
        Phase::ApplyNetwork,
        Phase::StartCores,
        Phase::PublishClients,
        Phase::PublishSubscription,
        Phase::Finalize,
    ];
    /// The rollback phases in execution order.
    pub const ROLLBACK: [Phase; 4] = [
        Phase::RollbackStop,
        Phase::RollbackFiles,
        Phase::RollbackServices,
        Phase::RolledBack,
    ];

    /// The v2 journal name (`prepare-state`, `rolled-back`, …).
    pub fn id(self) -> &'static str {
        use Phase::*;
        match self {
            Prepared => "prepared",
            PrepareState => "prepare-state",
            ReplaceCores => "replace-cores",
            PrepareCores => "prepare-cores",
            PrepareCertificates => "prepare-certificates",
            CheckConfigurations => "check-configurations",
            StopOldServices => "stop-old-services",
            CommitConfigurations => "commit-configurations",
            ConfigureServices => "configure-services",
            ApplyWebsite => "apply-website",
            ApplyNetwork => "apply-network",
            StartCores => "start-cores",
            PublishClients => "publish-clients",
            PublishSubscription => "publish-subscription",
            Finalize => "finalize",
            Committed => "committed",
            RollbackStop => "rollback-stop",
            RollbackFiles => "rollback-files",
            RollbackServices => "rollback-services",
            RolledBack => "rolled-back",
        }
    }

    /// Progress label (`[3/14] 准备证书…`).
    pub fn label(self) -> &'static str {
        use Phase::*;
        match self {
            Prepared => "开始事务",
            PrepareState => "准备",
            ReplaceCores => "替换内核",
            PrepareCores => "准备内核",
            PrepareCertificates => "准备证书",
            CheckConfigurations => "校验配置",
            StopOldServices => "停止旧服务",
            CommitConfigurations => "写入配置",
            ConfigureServices => "配置服务",
            ApplyWebsite => "应用网站",
            ApplyNetwork => "应用防火墙",
            StartCores => "启动内核",
            PublishClients => "发布客户端配置",
            PublishSubscription => "发布订阅",
            Finalize => "完成",
            Committed => "已提交",
            RollbackStop => "回滚：停止服务",
            RollbackFiles => "回滚：恢复文件",
            RollbackServices => "回滚：恢复服务",
            RolledBack => "已回滚",
        }
    }

    /// Only cleanup is left (`committed` / `rolled-back`): recovery removes
    /// the journal without rolling anything back.
    pub fn is_finished(self) -> bool {
        matches!(self, Phase::Committed | Phase::RolledBack)
    }

    /// A rollback had started.
    pub fn is_rollback(self) -> bool {
        Phase::ROLLBACK.contains(&self)
    }
}

/// A journal written by v3.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalV2 {
    pub version: u8,
    /// What the change was (`安装`, `添加协议`, …).
    pub reason: String,
    pub phase: Phase,
    /// The configuration before the change; `None` for a first install.
    pub old_config: Option<NodeConfig>,
    pub active_services: Vec<String>,
    pub enabled_services: Vec<String>,
    /// The owned crontab lines before the change, with their positions.
    pub cron: CronSnapshot,
    /// The snapshot in `files/` (its entries are the recorded target list).
    pub snapshot: Snapshot,
}

/// A journal written by v2.x (field names and order as v2 wrote them).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalV1 {
    pub version: u8,
    /// v2's `{"values":{…}}` (including internal `__*` keys), `None` for a
    /// first install; migrated by the engine when it is needed.
    pub old_state: Option<Value>,
    pub active_services: Vec<String>,
    pub enabled_services: Vec<String>,
    pub cron_lines: Vec<String>,
    pub cron_available: bool,
    pub phase: Phase,
    pub snapshot: Snapshot,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Journal {
    V1(JournalV1),
    /// Boxed: a typed configuration makes it much larger than `V1`.
    V2(Box<JournalV2>),
}

/// The configuration a journal recorded as "before".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OldState<'a> {
    /// First install: nothing existed.
    None,
    Config(&'a NodeConfig),
    /// v2's raw state document (version-1 journals).
    V2(&'a Value),
}

/// Where a pending journal stopped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PhaseInfo {
    pub version: u8,
    pub phase: Phase,
    pub reason: Option<String>,
}

/// Recovery work left behind by an interrupted operation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Pending {
    /// The node journal, if any.
    pub config: Option<PhaseInfo>,
    /// A self-update journal exists.
    pub program: bool,
}

impl Pending {
    pub fn any(&self) -> bool {
        self.config.is_some() || self.program
    }

    /// [`PENDING_MESSAGE`] when anything is pending.
    pub fn refuse(&self) -> Result<()> {
        ensure!(!self.any(), "{PENDING_MESSAGE}");
        Ok(())
    }
}

impl Journal {
    /// A new v3 journal in phase `prepared`.
    pub fn new(
        reason: &str,
        old_config: Option<NodeConfig>,
        active_services: Vec<String>,
        enabled_services: Vec<String>,
        cron: CronSnapshot,
        snapshot: Snapshot,
    ) -> Journal {
        Journal::V2(Box::new(JournalV2 {
            version: VERSION,
            reason: reason.to_owned(),
            phase: Phase::Prepared,
            old_config,
            active_services,
            enabled_services,
            cron,
            snapshot,
        }))
    }

    pub fn version(&self) -> u8 {
        match self {
            Journal::V1(j) => j.version,
            Journal::V2(j) => j.version,
        }
    }

    pub fn phase(&self) -> Phase {
        match self {
            Journal::V1(j) => j.phase,
            Journal::V2(j) => j.phase,
        }
    }

    /// The change being applied (v3 journals only).
    pub fn reason(&self) -> Option<&str> {
        match self {
            Journal::V1(_) => None,
            Journal::V2(j) => Some(&j.reason),
        }
    }

    pub fn old(&self) -> OldState<'_> {
        let old = match self {
            Journal::V1(j) => j.old_state.as_ref().map(OldState::V2),
            Journal::V2(j) => j.old_config.as_ref().map(OldState::Config),
        };
        old.unwrap_or(OldState::None)
    }

    pub fn active_services(&self) -> &[String] {
        match self {
            Journal::V1(j) => &j.active_services,
            Journal::V2(j) => &j.active_services,
        }
    }

    pub fn enabled_services(&self) -> &[String] {
        match self {
            Journal::V1(j) => &j.enabled_services,
            Journal::V2(j) => &j.enabled_services,
        }
    }

    /// The journaled cron lines (v2 journals carry no positions).
    pub fn cron(&self) -> CronSnapshot {
        match self {
            Journal::V1(j) => CronSnapshot {
                available: j.cron_available,
                lines: j.cron_lines.clone(),
                anchors: None,
            },
            Journal::V2(j) => j.cron.clone(),
        }
    }

    pub fn snapshot(&self) -> &Snapshot {
        match self {
            Journal::V1(j) => &j.snapshot,
            Journal::V2(j) => &j.snapshot,
        }
    }

    /// The allowlist its snapshot is validated against: v2's fixed list for
    /// journals v2 wrote, owned-root patterns for v3's.
    pub fn allowlist(&self, paths: &Paths) -> Allowlist {
        match self {
            Journal::V1(_) => v2_node_allowlist(paths),
            Journal::V2(_) => node_allowlist(paths),
        }
    }

    pub fn info(&self) -> PhaseInfo {
        PhaseInfo {
            version: self.version(),
            phase: self.phase(),
            reason: self.reason().map(str::to_owned),
        }
    }

    /// The v2 values of a version-1 journal's old state (`None` for a first
    /// install or a v3 journal), for `state::v2::migrate`.
    pub fn v2_values(&self) -> Result<Option<BTreeMap<String, String>>> {
        match self.old() {
            OldState::V2(doc) => {
                let bytes = serde_json::to_vec(doc)?;
                crate::state::v2::v2_values_from_json(&bytes).map(Some)
            }
            OldState::None | OldState::Config(_) => Ok(None),
        }
    }

    /// Durably move to `phase`; the in-memory phase changes only after the
    /// journal was written.
    pub fn set_phase(&mut self, paths: &Paths, phase: Phase) -> Result<()> {
        let mut next = self.clone();
        match &mut next {
            Journal::V1(j) => j.phase = phase,
            Journal::V2(j) => j.phase = phase,
        }
        write(paths, &next)?;
        *self = next;
        Ok(())
    }

    fn to_json(&self) -> Result<Vec<u8>> {
        Ok(match self {
            Journal::V1(j) => serde_json::to_vec_pretty(j)?,
            Journal::V2(j) => serde_json::to_vec_pretty(j)?,
        })
    }

    /// Everything a rollback relies on, checked before the engine changes
    /// anything: service names, the recorded old state, and the snapshot in
    /// `files/` against [`Journal::allowlist`]. The engine calls this before
    /// entering `rollback-stop` (v2 ran `validate_files` there), so a
    /// malformed journal never stops services and then aborts half-way.
    pub fn validate(&self, paths: &Paths) -> Result<()> {
        self.validate_with(paths, &self.allowlist(paths))
    }

    /// [`Journal::validate`] against an explicit snapshot allowlist (tests,
    /// or acme.sh homes other than [`acme_homes`](crate::apply::snapshot::acme_homes)).
    pub fn validate_with(&self, paths: &Paths, allow: &Allowlist) -> Result<()> {
        self.check_services()?;
        self.check_old_state()?;
        snapshot::validate(self.snapshot(), &files_dir(paths), allow)
    }

    /// The recorded old state is usable by a rollback: v2's document of
    /// string values (version 1, what `state::v2::migrate` needs) or a
    /// configuration that passes `NodeConfig::validate` (version 2).
    fn check_old_state(&self) -> Result<()> {
        match self.old() {
            OldState::None => Ok(()),
            OldState::V2(_) => self.v2_values().map(drop),
            OldState::Config(cfg) => cfg.validate(),
        }
        .context("事务日志记录的旧配置无效")
    }

    /// Every journaled service is a node service or a legacy network unit
    /// (their names reach service-manager commands).
    fn check_services(&self) -> Result<()> {
        let known = |name: &String| {
            SERVICES.contains(&name.as_str()) || LEGACY_NETWORK_SERVICES.contains(&name.as_str())
        };
        let all_known = self
            .active_services()
            .iter()
            .chain(self.enabled_services())
            .all(known);
        ensure!(all_known, "事务日志含未知服务");
        Ok(())
    }
}

/// `ROOT/.transaction`.
pub fn dir(paths: &Paths) -> PathBuf {
    paths.transaction()
}

/// `ROOT/.transaction/files`, the snapshot of the pending journal.
pub fn files_dir(paths: &Paths) -> PathBuf {
    dir(paths).join(FILES_DIR)
}

fn incomplete(e: impl std::fmt::Display) -> Error {
    Error::msg(format!("事务日志不完整，未执行任何恢复: {e}"))
}

/// The pending journal, `None` when there is none. A journal directory
/// without a readable, valid journal is an error.
pub fn load(paths: &Paths) -> Result<Option<Journal>> {
    let dir = dir(paths);
    match fs::symlink_metadata(&dir) {
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Error::io(&dir, e)),
        Ok(m) if m.file_type().is_symlink() || !m.is_dir() => {
            bail!("事务目录无效: {}", dir.display())
        }
        Ok(_) => {}
    }
    let path = dir.join(JOURNAL_FILE);
    let meta = fs::symlink_metadata(&path).map_err(|e| incomplete(Error::io(&path, e)))?;
    ensure!(meta.len() <= MAX_BYTES, "事务日志过大");
    let bytes = read_bounded(&path, MAX_BYTES).map_err(incomplete)?;
    parse(&bytes).map(Some)
}

/// Parse a journal of either version and check its contents (service
/// names and old state; the snapshot is checked by [`Journal::validate`],
/// which hashes every slot).
pub fn parse(bytes: &[u8]) -> Result<Journal> {
    let doc: Value = serde_json::from_slice(bytes).context("事务日志无效")?;
    let journal = match doc.get("version").and_then(Value::as_u64) {
        Some(1) => Journal::V1(serde_json::from_value(doc).context("事务日志无效")?),
        Some(2) => Journal::V2(Box::new(
            serde_json::from_value(doc).context("事务日志无效")?,
        )),
        _ => bail!("不支持的事务日志版本"),
    };
    journal.check_services()?;
    journal.check_old_state()?;
    Ok(journal)
}

/// Atomically (re)write the pending journal (pretty JSON, 0600).
pub fn write(paths: &Paths, journal: &Journal) -> Result<()> {
    write_in(&dir(paths), journal)
}

/// Write `journal` as `{dir}/journal.json` (a staging directory while the
/// journal is being created).
pub fn write_in(dir: &Path, journal: &Journal) -> Result<()> {
    atomic_write(&dir.join(JOURNAL_FILE), &journal.to_json()?, 0o600)
}

/// What recovery is due: the node journal's phase and whether a self-update
/// journal exists. A corrupt journal of either kind is an error.
pub fn pending(paths: &Paths) -> Result<Pending> {
    Ok(Pending {
        config: load(paths)?.map(|j| j.info()),
        program: program_journal::load(paths)?.is_some(),
    })
}

#[cfg(test)]
mod tests;
