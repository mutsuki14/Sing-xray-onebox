//! `onebox update [singbox|sing-box|xray|all] [VERSION] [--force]`: replace
//! the proxy cores the configuration uses (spec G §2.10, §5.3).
//!
//! Targets per selected core in use:
//!
//! | invocation                    | target                         | pin afterwards |
//! |-------------------------------|--------------------------------|----------------|
//! | `update` / `update all`       | the pin, else recommended      | unchanged      |
//! | `update CORE`                 | recommended                    | cleared        |
//! | `update {CORE,all} latest`    | latest release                 | cleared        |
//! | `update {CORE,all} VERSION`   | VERSION                        | VERSION        |
//!
//! Recommended = Xray 26.3.27 (tested with sing-box REALITY clients),
//! sing-box latest. A target older than the installed core is refused
//! without `--force`; bare `update` / `all` keeps a newer installed core
//! instead (with a hint), so a deliberately newer core never breaks the
//! routine update. A target equal to the installed version is not
//! reinstalled unless `--force`. An Xray target other than 26.3.27 prints
//! a warning (always, `-y` included) and asks to continue (`-y` accepts).
//! Every target is resolved, confirmed and downloaded (verified) into
//! `BIN/.core-update-<24hex>` before one apply transaction swaps the
//! binaries (`Intents.replace_cores`) together with the updated pins; a
//! failed transaction keeps the staged files. When no binary changes and
//! only pins do, the configuration is saved without a transaction
//! (`已更新固定版本`): pins only steer later installs, nothing restarts.
//!
//! Locks: the update lock for the whole run; the node lock twice — first
//! to recover leftovers and read the configuration, then, after the
//! lookups, the question and the downloads (which may take minutes and must
//! not block renewals or device changes meanwhile), to recover again,
//! re-read the configuration and commit. The plan must still hold then
//! (same targets and pins, same live core versions), else
//! `Error::Conflict`; the apply's compare-and-swap uses the re-read hash.
//!
//! Changes from v2:
//! - only cores the configuration uses are targets (G-8.1#2: an unused
//!   binary left on disk made v2's transaction refuse the update);
//! - pins are honored and maintained (G2, G-8.1#3); downgrades need
//!   `--force`; `latest` never quietly falls back to an older version;
//! - the Xray warning is a confirmation and compares the resolved version
//!   (v2 compared the raw argument, so `v26.3.27` warned, G-8.1#4);
//! - `all VERSION` is refused when it would apply one version to both
//!   cores (G-8.1#5); unknown core names are refused before any lock;
//! - an exact target that is already installed (or kept, or a refused
//!   downgrade) is decided without a release lookup; nothing is downloaded
//!   or applied when every target is already installed and no pin changes;
//!   a pin change alone is saved without restarting anything (a node still
//!   in v2 form gets the full transaction: it is its first v3 change);
//! - the node lock is not held during lookups, the question and downloads;
//! - staging is announced as kept only when it still holds a verified
//!   binary (v2 also announced an empty directory). Kept directories are
//!   `.core-*` leftovers that `host::cores` sweeps after an hour.

use super::{selfupdate, Updater, UPDATE_BUSY};
use crate::apply::ApplyRequest;
use crate::domain::config::CoreVersions;
use crate::domain::defaults::XRAY_TESTED_VERSION;
use crate::domain::protocol::Core;
use crate::domain::version::Semver;
use crate::domain::NodeConfig;
use crate::error::{Error, Result};
use crate::host::cores::{self, Resolved, Wanted};
use crate::host::fetch;
use crate::state::{Loaded, Origin, StateStore};
use crate::sys::fs::{ensure_dir, fsync_dir, remove_tree_if_exists};
use crate::sys::lock::{FileLock, BUSY_MESSAGE};
use crate::ui::out;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

/// Progress label of the apply transaction.
pub const REASON: &str = "更新内核";
pub const DONE: &str = "内核更新完成";
pub const NOTHING_TO_DO: &str = "所选内核已是目标版本，无需更新";
pub const UNKNOWN_CORE: &str = "未知内核";
pub const CANCELLED: &str = "已取消内核更新";
/// Success of a pin-only change (no transaction).
pub const PINS_SAVED: &str = "已更新固定版本";
/// The question after [`xray_warning`].
pub const CONTINUE: &str = "继续？";
/// Name prefix of the staging directory inside `BIN` (v2 layout).
pub const STAGING_PREFIX: &str = ".core-update-";
const ONE_VERSION_TWO_CORES: &str =
    "版本号只适用于单个内核，请执行 onebox update singbox 版本 或 onebox update xray 版本";

/// Which cores `update` targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreSelection {
    /// Every core the configuration uses (`update`, `update all`).
    All,
    One(Core),
}

impl CoreSelection {
    /// `None`/`all` → all; `singbox`/`sing-box`/`xray` → that core.
    pub fn parse(word: Option<&str>) -> Result<CoreSelection> {
        match word {
            None | Some("all") => Ok(CoreSelection::All),
            Some("singbox" | "sing-box") => Ok(CoreSelection::One(Core::Singbox)),
            Some("xray") => Ok(CoreSelection::One(Core::Xray)),
            Some(_) => Err(Error::msg(UNKNOWN_CORE)),
        }
    }

    pub fn includes(self, core: Core) -> bool {
        match self {
            CoreSelection::All => true,
            CoreSelection::One(one) => one == core,
        }
    }
}

/// The version one core is updated to, and its pin afterwards.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub core: Core,
    /// What to resolve: an exact version or `latest`.
    pub wanted: String,
    pub pin: Option<String>,
    /// Bare `update` / `all`: keep a newer installed core instead of
    /// refusing the downgrade.
    pub lenient: bool,
}

/// The recommended version of `core` for updates (strict: `latest` never
/// falls back).
pub fn recommended(core: Core) -> &'static str {
    match core {
        Core::Singbox => "latest",
        Core::Xray => XRAY_TESTED_VERSION,
    }
}

/// The target of `core` for this invocation (table in the module docs).
pub fn target(core: Core, selection: CoreSelection, wanted: &Wanted, pin: Option<&str>) -> Target {
    let (wanted, pin, lenient) = match (wanted, selection) {
        (Wanted::Latest, _) => ("latest".to_owned(), None, false),
        (Wanted::Exact(v), _) => (v.clone(), Some(v.clone()), false),
        (Wanted::Default, CoreSelection::All) => match pin {
            Some(p) => (p.to_owned(), Some(p.to_owned()), true),
            None => (recommended(core).to_owned(), None, true),
        },
        (Wanted::Default, CoreSelection::One(_)) => (recommended(core).to_owned(), None, false),
    };
    Target {
        core,
        wanted,
        pin,
        lenient,
    }
}

/// The targets among the cores `cfg` uses.
pub fn targets(cfg: &NodeConfig, selection: CoreSelection, wanted: &Wanted) -> Result<Vec<Target>> {
    let list: Vec<Target> = cfg
        .cores()
        .into_iter()
        .filter(|core| selection.includes(*core))
        .map(|core| target(core, selection, wanted, cfg.versions.pin(core)))
        .collect();
    if let CoreSelection::One(core) = selection {
        ensure!(
            !list.is_empty(),
            "当前配置未使用 {}，无需更新",
            core.title()
        );
    }
    ensure!(!list.is_empty(), "所选内核未安装");
    let exact_for_two = matches!(wanted, Wanted::Exact(_)) && list.len() > 1;
    ensure!(!exact_for_two, "{ONE_VERSION_TWO_CORES}");
    Ok(list)
}

/// What to do with one core.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Download and swap in the target.
    Install,
    /// Already the target version.
    Same,
    /// The installed core is newer than a lenient target: keep it.
    KeepNewer,
}

/// The downgrade / reinstall policy. Versions that are not semantic
/// versions can only be compared for equality.
pub fn decide(
    core: Core,
    current: Option<&str>,
    target: &str,
    force: bool,
    lenient: bool,
) -> Result<Decision> {
    let Some(current) = current else {
        return Ok(Decision::Install);
    };
    if force {
        return Ok(Decision::Install);
    }
    if current == target {
        return Ok(Decision::Same);
    }
    let older = matches!(
        (Semver::parse(target), Semver::parse(current)),
        (Some(t), Some(c)) if t < c
    );
    match (older, lenient) {
        (false, _) => Ok(Decision::Install),
        (true, true) => Ok(Decision::KeepNewer),
        (true, false) => Err(Error::msg(format!(
            "{} {target} 低于已安装的 {current}，拒绝降级；确认降级请追加 --force",
            core.title()
        ))),
    }
}

/// The decision for one target. Invariant: `decision == Install` implies
/// `resolved` is set (the release or offline binary to stage).
#[derive(Clone, Debug)]
struct Plan {
    target: Target,
    current: Option<String>,
    /// The version the decision is about (the resolved one when looked up).
    version: String,
    decision: Decision,
    resolved: Option<Resolved>,
}

impl Plan {
    /// What to stage, when this plan installs.
    fn source(&self) -> Option<&Resolved> {
        self.resolved
            .as_ref()
            .filter(|_| self.decision == Decision::Install)
    }

    fn installs(&self) -> bool {
        self.source().is_some()
    }

    /// A user-facing line describing the plan.
    fn describe(&self) -> String {
        describe(
            self.target.core,
            self.current.as_deref(),
            &self.version,
            self.decision,
        )
    }
}

/// `sing-box 1.14.2 → 1.14.3` and friends.
pub fn describe(core: Core, current: Option<&str>, target: &str, decision: Decision) -> String {
    let title = core.title();
    match (decision, current) {
        (Decision::Install, Some(current)) if current == target => {
            format!("{title} {target}：重新安装")
        }
        (Decision::Install, Some(current)) => format!("{title} {current} → {target}"),
        (Decision::Install, None) => format!("{title}：安装 {target}"),
        (Decision::Same, _) => format!("{title} {target} 已是目标版本"),
        (Decision::KeepNewer, current) => format!(
            "{title} {} 高于目标版本 {target}，保持不变；降级请执行 onebox update {} {target} --force",
            current.unwrap_or("?"),
            core.id()
        ),
    }
}

/// The warning before installing an Xray other than the tested version
/// (followed by [`CONTINUE`]).
pub fn xray_warning(version: &str) -> String {
    format!(
        "指定的 Xray {version} 可能拒绝 sing-box REALITY 客户端；经过测试版本为 {XRAY_TESTED_VERSION}"
    )
}

/// How a core update ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Committed {
    /// The apply transaction ran.
    Applied,
    /// Only pins changed; saved without a transaction.
    Pins,
    /// Nothing left to change.
    Nothing,
}

/// `cfg` with the plans' pins and the installed versions of replaced cores.
fn updated_config(cfg: &NodeConfig, plans: &[Plan]) -> NodeConfig {
    let mut next = cfg.clone();
    for plan in plans {
        let core = plan.target.core;
        *pin_mut(&mut next.versions, core) = plan.target.pin.clone();
        if plan.installs() {
            *installed_mut(&mut next.versions, core) = Some(plan.version.clone());
        }
    }
    next
}

fn pin_mut(versions: &mut CoreVersions, core: Core) -> &mut Option<String> {
    match core {
        Core::Singbox => &mut versions.singbox_pin,
        Core::Xray => &mut versions.xray_pin,
    }
}

fn installed_mut(versions: &mut CoreVersions, core: Core) -> &mut Option<String> {
    match core {
        Core::Singbox => &mut versions.singbox,
        Core::Xray => &mut versions.xray,
    }
}

impl Updater<'_> {
    /// `onebox update …` (see the module docs). Root is the caller's
    /// business.
    pub fn update_cores(
        &self,
        selection: CoreSelection,
        version: Option<&str>,
        force: bool,
    ) -> Result<()> {
        let wanted = Wanted::parse(version)?;
        let _update = FileLock::acquire(&self.ctx.paths.update_lock(), UPDATE_BUSY)?;
        let loaded = {
            let lock = self.node_lock()?;
            let loaded = self.recover_and_load(&lock)?;
            selfupdate::sweep_unreferenced(&self.ctx.paths);
            loaded
        };
        if let Origin::V2 { warnings, .. } = &loaded.origin {
            warnings.iter().for_each(|w| (self.warn)(w));
        }
        let targets = targets(&loaded.config, selection, &wanted)?;
        let plans = self.plan(targets, force)?;
        self.confirm(&plans)?;
        let unchanged = updated_config(&loaded.config, &plans) == loaded.config;
        let outcome = if !plans.iter().any(Plan::installs) && unchanged {
            Committed::Nothing
        } else {
            self.stage_and_commit(selection, &wanted, &plans)?
        };
        out::ok(match outcome {
            Committed::Applied => DONE,
            Committed::Pins => PINS_SAVED,
            Committed::Nothing => NOTHING_TO_DO,
        });
        Ok(())
    }

    fn node_lock(&self) -> Result<FileLock> {
        FileLock::acquire(&self.ctx.paths.lock(), BUSY_MESSAGE)
    }

    /// Finish leftovers under the node lock, then read the configuration.
    fn recover_and_load(&self, lock: &FileLock) -> Result<Loaded> {
        self.engine.recover(self.ctx, lock)?;
        StateStore::load_required(self.ctx)
    }

    /// Decide what to do with every target, resolving releases only where
    /// the decision needs them.
    fn plan(&self, targets: Vec<Target>, force: bool) -> Result<Vec<Plan>> {
        let mut curl_ready = false;
        let mut plans = Vec::with_capacity(targets.len());
        for target in targets {
            let plan = self.plan_one(target, force, &mut curl_ready)?;
            out::info(plan.describe());
            plans.push(plan);
        }
        Ok(plans)
    }

    /// An exact target is decided before any lookup (already installed,
    /// kept, or a refused downgrade need no network); otherwise the release
    /// (or offline binary) is resolved and the decision is taken on the
    /// version it really has.
    fn plan_one(&self, target: Target, force: bool, curl_ready: &mut bool) -> Result<Plan> {
        let core = target.core;
        let current = self.current_version(core);
        if target.wanted != "latest" {
            let early = decide(
                core,
                current.as_deref(),
                &target.wanted,
                force,
                target.lenient,
            )?;
            if early != Decision::Install {
                return Ok(Plan {
                    version: target.wanted.clone(),
                    target,
                    current,
                    decision: early,
                    resolved: None,
                });
            }
        }
        if !*curl_ready && (self.env)(cores::offline_env(core)).is_none() {
            fetch::ensure_curl(self.ctx)?;
            *curl_ready = true;
        }
        let resolved = cores::resolve_with(self.ctx, self.env, core, Some(&target.wanted))?;
        let decision = decide(
            core,
            current.as_deref(),
            &resolved.version,
            force,
            target.lenient,
        )?;
        Ok(Plan {
            version: resolved.version.clone(),
            target,
            current,
            decision,
            resolved: Some(resolved),
        })
    }

    /// The live core's version; `None` when it is missing or cannot run
    /// (then any target installs it).
    fn current_version(&self, core: Core) -> Option<String> {
        let live = self.ctx.paths.core_bin(core);
        let present = std::fs::symlink_metadata(&live).is_ok_and(|m| m.is_file());
        present
            .then(|| cores::installed_version(self.ctx, &live, core).ok())
            .flatten()
    }

    /// Warn about (always, `-y` included) and ask before installing an
    /// Xray other than the tested version.
    fn confirm(&self, plans: &[Plan]) -> Result<()> {
        let untested = plans.iter().find(|p| {
            p.installs() && p.target.core == Core::Xray && p.version != XRAY_TESTED_VERSION
        });
        if let Some(plan) = untested {
            (self.warn)(&xray_warning(&plan.version));
            ensure!(self.ctx.ui.confirm(CONTINUE, false)?, "{CANCELLED}");
        }
        Ok(())
    }

    /// Download every installing plan into a fresh staging directory, then
    /// commit. The staging directory is removed on success and kept (and
    /// named) on failure when it holds a verified binary.
    fn stage_and_commit(
        &self,
        selection: CoreSelection,
        wanted: &Wanted,
        plans: &[Plan],
    ) -> Result<Committed> {
        let installing: Vec<(Core, &Resolved)> = plans
            .iter()
            .filter_map(|p| p.source().map(|r| (p.target.core, r)))
            .collect();
        let staging = if installing.is_empty() {
            None
        } else {
            Some(create_staging(&self.ctx.paths.bin)?)
        };
        let result = self
            .download_all(staging.as_deref(), &installing)
            .and_then(|staged| self.commit(selection, wanted, plans, staged));
        if let Some(dir) = &staging {
            settle_staging(dir, result.is_ok(), self.warn);
        }
        result
    }

    /// Under the node lock again: recover, re-read the configuration, check
    /// that the plan still holds, then persist it — through one apply
    /// transaction, or for a pin-only change of a v3 configuration by
    /// saving it (the lock is held and the configuration was just read, so
    /// nothing can have changed it meanwhile).
    fn commit(
        &self,
        selection: CoreSelection,
        wanted: &Wanted,
        plans: &[Plan],
        staged: Vec<(Core, PathBuf)>,
    ) -> Result<Committed> {
        let lock = self.node_lock()?;
        let loaded = self.recover_and_load(&lock)?;
        self.check_unchanged(&loaded.config, selection, wanted, plans)?;
        let config = updated_config(&loaded.config, plans);
        if staged.is_empty() {
            if config == loaded.config {
                return Ok(Committed::Nothing);
            }
            if loaded.origin == Origin::V3 {
                StateStore::save(self.ctx, &config)?;
                return Ok(Committed::Pins);
            }
        }
        let mut req = ApplyRequest::from_loaded(&loaded, config, REASON);
        req.intents.replace_cores = staged;
        self.engine.apply(self.ctx, &lock, req)?;
        Ok(Committed::Applied)
    }

    /// The plan was made without the node lock: it still holds when `cfg`
    /// yields the same targets (cores in use, pins) and the live cores
    /// report the versions the decisions were based on.
    fn check_unchanged(
        &self,
        cfg: &NodeConfig,
        selection: CoreSelection,
        wanted: &Wanted,
        plans: &[Plan],
    ) -> Result<()> {
        let now = targets(cfg, selection, wanted)?;
        let same_targets =
            now.len() == plans.len() && now.iter().zip(plans).all(|(t, p)| *t == p.target);
        let same_cores = same_targets
            && plans
                .iter()
                .all(|p| self.current_version(p.target.core) == p.current);
        if same_cores {
            Ok(())
        } else {
            Err(Error::Conflict)
        }
    }

    /// Download and verify each core into `dir` (`{dir}/{binary}`).
    fn download_all(
        &self,
        dir: Option<&Path>,
        installing: &[(Core, &Resolved)],
    ) -> Result<Vec<(Core, PathBuf)>> {
        let Some(dir) = dir else {
            return Ok(Vec::new());
        };
        installing
            .iter()
            .map(|(core, resolved)| {
                cores::download_with(self.ctx, self.env, resolved, dir).map(|path| (*core, path))
            })
            .collect()
    }
}

/// `BIN/.core-update-<24hex>` (0700), created fresh.
fn create_staging(bin: &Path) -> Result<PathBuf> {
    if !bin.exists() {
        ensure_dir(bin, 0o755)?;
    }
    let dir = bin.join(format!("{STAGING_PREFIX}{}", crate::sys::rand::hex(12)?));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .map_err(|e| Error::io(&dir, e))?;
    fsync_dir(bin).map_err(|e| Error::io(bin, e))?;
    Ok(dir)
}

/// Remove the staging directory, except after a failure that left a
/// verified binary in it (v2 message).
fn settle_staging(dir: &Path, succeeded: bool, warn: &dyn Fn(&str)) {
    let holds_binary = Core::ALL
        .iter()
        .any(|core| dir.join(core.binary()).is_file());
    if !succeeded && holds_binary {
        warn(&format!("已验证的内核更新文件保留: {}", dir.display()));
    } else {
        let _ = remove_tree_if_exists(dir);
    }
}

#[cfg(test)]
mod tests;
