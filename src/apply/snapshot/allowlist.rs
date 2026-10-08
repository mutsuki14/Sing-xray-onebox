//! Which targets a snapshot may restore, and below which owned root each of
//! them must be free of symlinks.
//!
//! Two kinds of journals exist:
//! - written by v2 (config journal version 1, `.self-update.json` version
//!   1): v2 required the snapshot's target set to *equal* the allowlist it
//!   recomputed from its context. [`v2_node_allowlist`] is that list (38
//!   fixed targets in v2 slot order) plus a pattern rule for the retired
//!   acme.sh deployment files v2 snapshotted on hosts that came from v1
//!   (E-8.1#5: those paths are validated by pattern, never recomputed);
//! - written by v3: the journal records its own target list and every target
//!   must match one of the owned-root patterns of [`node_allowlist`], so a
//!   newer v3 adding a path cannot make an older one refuse its journal.

use crate::error::{Error, Result};
use crate::paths::Paths;
use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

/// Directories a snapshot rule may never cover as a whole (v2 `safe_roots`).
const BROAD_ROOTS: [&str; 7] = ["/", "/etc", "/usr", "/var", "/home", "/root", "/tmp"];

/// v2 `transaction::ROOT_ITEMS`, in slot order.
const V2_ROOT_ITEMS: [&str; 15] = [
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

/// v2 `transaction::SERVICES`, in slot order (not the start order).
const V2_SERVICES: [&str; 6] = [
    "onebox-sing-box",
    "onebox-xray",
    "onebox-site",
    "onebox-network",
    "onebox-subscription",
    "onebox-subscription-web",
];

/// v1 network boot hooks (v2 `platform::boot::NAMES`).
const LEGACY_HOOKS: [&str; 2] = ["onebox-net", "onebox-hop"];

/// The acme.sh home v2 used when `ACME_HOME` was unset.
pub const DEFAULT_ACME_HOME: &str = "/root/.acme.sh";

/// How the file name of a [`TargetRule::Child`] must look.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameRule {
    /// `[A-Za-z0-9][A-Za-z0-9._-]*`, except `backups` (user backups are
    /// never part of a snapshot). Hidden names are refused: they are locks,
    /// journals and staging directories.
    Plain,
    /// `onebox-[A-Za-z0-9-]+` followed by `suffix` (unit files, init
    /// scripts, `local.d` hooks).
    Service { suffix: &'static str },
}

impl NameRule {
    fn accepts(self, name: &str) -> bool {
        match self {
            NameRule::Plain => {
                name != "backups"
                    && name
                        .bytes()
                        .next()
                        .is_some_and(|b| b.is_ascii_alphanumeric())
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            }
            NameRule::Service { suffix } => name
                .strip_suffix(suffix)
                .and_then(|stem| stem.strip_prefix("onebox-"))
                .is_some_and(|rest| {
                    !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                }),
        }
    }
}

/// One way a target may be accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TargetRule {
    /// Exactly this path; symlink checks start at its parent.
    Exact(PathBuf),
    /// A direct child of `dir` whose name satisfies `names`.
    Child { dir: PathBuf, names: NameRule },
    /// `{home}/{domain}_ecc/{domain}.conf` (a retired acme.sh deployment);
    /// symlink checks start at `home`.
    AcmeDeployment { home: PathBuf },
}

impl TargetRule {
    /// The owned root of `target` when this rule accepts it.
    fn owned_root(&self, target: &Path) -> Option<PathBuf> {
        match self {
            TargetRule::Exact(path) => (path == target).then(|| parent(target)).flatten(),
            TargetRule::Child { dir, names } => {
                let name = target.file_name()?.to_str()?;
                (target.parent() == Some(dir.as_path()) && names.accepts(name)).then(|| dir.clone())
            }
            TargetRule::AcmeDeployment { home } => {
                let rel = target.strip_prefix(home).ok()?;
                let mut parts = rel.components().map(|c| match c {
                    Component::Normal(name) => name.to_str(),
                    _ => None,
                });
                let (dir, file) = (parts.next()??, parts.next()??);
                let domain = dir.strip_suffix("_ecc")?;
                (parts.next().is_none()
                    && v2_valid_domain(domain)
                    && file.strip_suffix(".conf") == Some(domain))
                .then(|| home.clone())
            }
        }
    }

    /// The directory (or path) this rule exposes to restores.
    fn scope(&self) -> &Path {
        match self {
            TargetRule::Exact(path) => path,
            TargetRule::Child { dir, .. } => dir,
            TargetRule::AcmeDeployment { home } => home,
        }
    }
}

/// The targets a snapshot may contain: every `required` path exactly once,
/// plus any number of paths accepted by `rules`. `roots` are configured
/// directories that must not be system directories, and each `apart` pair
/// must not contain one another (v2 `safe_roots`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Allowlist {
    required: Vec<PathBuf>,
    rules: Vec<TargetRule>,
    roots: Vec<PathBuf>,
    apart: Vec<(PathBuf, PathBuf, &'static str)>,
}

impl Allowlist {
    /// Exactly `targets` (each once, all of them).
    pub fn exact(targets: Vec<PathBuf>) -> Allowlist {
        Allowlist {
            required: targets,
            ..Allowlist::default()
        }
    }

    /// Additionally accept the targets `rule` matches.
    pub fn with_rule(mut self, rule: TargetRule) -> Allowlist {
        self.rules.push(rule);
        self
    }

    /// Refuse to work when `root` is `/` or a system directory.
    pub fn guard_root(mut self, root: PathBuf) -> Allowlist {
        self.roots.push(root);
        self
    }

    /// Refuse to work (with `message`) when `a` and `b` contain one another.
    pub fn keep_apart(mut self, a: PathBuf, b: PathBuf, message: &'static str) -> Allowlist {
        self.apart.push((a, b, message));
        self
    }

    pub fn required(&self) -> &[PathBuf] {
        &self.required
    }

    pub fn rules(&self) -> &[TargetRule] {
        &self.rules
    }

    /// The owned root below which `target` must not contain a symlink, or
    /// `None` when the allowlist does not accept `target`.
    pub fn owned_root(&self, target: &Path) -> Option<PathBuf> {
        if !is_clean_absolute(target) {
            return None;
        }
        if self.required.iter().any(|p| p == target) {
            return parent(target);
        }
        self.rules.iter().find_map(|rule| rule.owned_root(target))
    }

    /// Error unless every required target is in `found`.
    pub(super) fn check_complete(&self, found: &BTreeSet<&Path>) -> Result<()> {
        if self.required.iter().all(|p| found.contains(p.as_path())) {
            Ok(())
        } else {
            Err(Error::msg("快照缺少托管路径，拒绝部分恢复"))
        }
    }

    /// Refuse an allowlist that would let a snapshot replace a whole system
    /// directory (a misconfigured `ONEBOX_DIR=/etc` must not make `/etc`
    /// restorable) or whose roots overlap.
    pub fn check_scope(&self) -> Result<()> {
        let scopes = self
            .required
            .iter()
            .chain(&self.roots)
            .map(PathBuf::as_path)
            .chain(self.rules.iter().map(TargetRule::scope));
        for scope in scopes {
            check_not_broad(scope)?;
        }
        for (a, b, message) in &self.apart {
            if a.starts_with(b) || b.starts_with(a) {
                return Err(Error::msg(*message));
            }
        }
        Ok(())
    }
}

/// `事务目录范围过大` unless `path` is narrower than a system directory.
pub(super) fn check_not_broad(path: &Path) -> Result<()> {
    if path.parent().is_none() || BROAD_ROOTS.iter().any(|root| path == Path::new(root)) {
        return Err(Error::msg(format!("事务目录范围过大: {}", path.display())));
    }
    Ok(())
}

/// Absolute, without `.`/`..` and not the root directory itself.
pub(super) fn is_clean_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path.parent().is_some()
        && path
            .components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
}

fn parent(path: &Path) -> Option<PathBuf> {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
}

/// v2 `util::valid_domain` (case-insensitive, IP literals accepted): the
/// acme.sh directories v2 snapshotted were named with it.
fn v2_valid_domain(s: &str) -> bool {
    s.len() <= 253
        && s.contains('.')
        && !s.ends_with('.')
        && s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// `INITD/../local.d`, where v1 kept OpenRC boot hooks.
fn local_d(paths: &Paths) -> PathBuf {
    paths
        .initd
        .parent()
        .unwrap_or_else(|| Path::new("/"))
        .join("local.d")
}

/// The v2 standalone-subscription ACME webroot, a sibling of the site root.
pub fn subscription_acme_dir(paths: &Paths) -> PathBuf {
    paths.site_root.with_file_name("onebox-subscription-acme")
}

/// v2's 38 fixed snapshot targets in v2 slot order: 15 `ROOT` items, the
/// site root, the manager executable, the subscription ACME webroot, both
/// core binaries, the unit file and init script of each of the 6 node
/// services, and the 6 v1 boot hooks (skipped when already listed).
pub fn v2_fixed_targets(paths: &Paths) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = V2_ROOT_ITEMS.iter().map(|s| paths.root.join(s)).collect();
    out.push(paths.site_root.clone());
    out.push(paths.executable.clone());
    out.push(subscription_acme_dir(paths));
    out.push(paths.bin.join("sing-box"));
    out.push(paths.bin.join("xray"));
    for name in V2_SERVICES {
        out.push(paths.systemd.join(format!("{name}.service")));
        out.push(paths.initd.join(name));
    }
    let local = local_d(paths);
    let hooks = LEGACY_HOOKS
        .iter()
        .map(|n| paths.systemd.join(format!("{n}.service")))
        .chain(LEGACY_HOOKS.iter().map(|n| paths.initd.join(n)))
        .chain(
            LEGACY_HOOKS
                .iter()
                .map(|n| local.join(format!("{n}.start"))),
        )
        .collect::<Vec<_>>();
    for hook in hooks {
        if !out.contains(&hook) {
            out.push(hook);
        }
    }
    out
}

/// acme.sh homes whose retired Onebox deployments v2 may have snapshotted:
/// `$ACME_HOME` (when it is a clean absolute path) and `/root/.acme.sh`.
pub fn acme_homes() -> Vec<PathBuf> {
    let mut homes = Vec::new();
    if let Some(home) = std::env::var_os("ACME_HOME").map(PathBuf::from) {
        if is_clean_absolute(&home) && home.to_str().is_some() {
            homes.push(home);
        }
    }
    let default = PathBuf::from(DEFAULT_ACME_HOME);
    if !homes.contains(&default) {
        homes.push(default);
    }
    homes
}

/// The configured node roots v2 `safe_roots` guarded: none may be a system
/// directory, and the site root and `ROOT` must not contain one another.
fn guard_node_roots(list: Allowlist, paths: &Paths) -> Allowlist {
    [
        &paths.root,
        &paths.bin,
        &paths.site_root,
        &paths.systemd,
        &paths.initd,
    ]
    .into_iter()
    .fold(list, |list, root| list.guard_root(root.clone()))
    .keep_apart(
        paths.root.clone(),
        paths.site_root.clone(),
        "网站目录和配置目录不能互相包含",
    )
}

/// The allowlist for snapshots written by v2 (G1): the 38 fixed targets,
/// each required, plus retired acme.sh deployments under [`acme_homes`].
pub fn v2_node_allowlist(paths: &Paths) -> Allowlist {
    v2_node_allowlist_with(paths, &acme_homes())
}

/// [`v2_node_allowlist`] with explicit acme.sh homes (tests).
pub fn v2_node_allowlist_with(paths: &Paths, acme_homes: &[PathBuf]) -> Allowlist {
    let list = acme_homes
        .iter()
        .fold(Allowlist::exact(v2_fixed_targets(paths)), |list, home| {
            list.with_rule(TargetRule::AcmeDeployment { home: home.clone() })
        });
    guard_node_roots(list, paths)
}

/// The owned-root patterns v3 node journals are validated against: plain
/// children of `ROOT` and of the core directory, the site root, the
/// executable, the subscription ACME webroot, and `onebox-*` unit files,
/// init scripts and `local.d` hooks.
pub fn node_allowlist(paths: &Paths) -> Allowlist {
    let child = |dir: &Path, names| TargetRule::Child {
        dir: dir.to_path_buf(),
        names,
    };
    let list = Allowlist::default()
        .with_rule(child(&paths.root, NameRule::Plain))
        .with_rule(TargetRule::Exact(paths.site_root.clone()))
        .with_rule(TargetRule::Exact(paths.executable.clone()))
        .with_rule(TargetRule::Exact(subscription_acme_dir(paths)))
        .with_rule(child(&paths.bin, NameRule::Plain))
        .with_rule(child(
            &paths.systemd,
            NameRule::Service { suffix: ".service" },
        ))
        .with_rule(child(&paths.initd, NameRule::Service { suffix: "" }))
        .with_rule(child(
            &local_d(paths),
            NameRule::Service { suffix: ".start" },
        ));
    guard_node_roots(list, paths)
}
