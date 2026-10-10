//! Which targets a snapshot may restore, and below which owned root each of
//! them must be free of symlinks.
//!
//! Two kinds of journals exist:
//! - written by v2 (config journal version 1, `.self-update.json` version
//!   1): v2 required the snapshot's target set to *equal* the allowlist it
//!   recomputed from its context. [`v2_node_allowlist`] is that list (38
//!   fixed targets in v2 slot order) plus pattern rules for the retired
//!   acme.sh deployment files v2 snapshotted on hosts that came from v1
//!   (E-8.1#5: those paths are validated by pattern against the recorded
//!   path alone — v2 recomputed them from `$ACME_HOME`, which the boot
//!   service did not carry);
//! - written by v3: the journal records its own target list and every target
//!   must be accepted by [`node_allowlist`] (any plain `ROOT` child, exactly
//!   the node-owned paths elsewhere), so a v3 adding or dropping a `ROOT`
//!   item cannot make another v3 refuse its journal, while no journal can
//!   direct a write to a path the node does not own (E §5.8).
//!
//! [`take`](super::take) checks its targets against the same allowlist that
//! later validates the snapshot, so a snapshot that was taken can always be
//! restored.

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

/// `[A-Za-z0-9][A-Za-z0-9._-]*`, except `backups` (user backups are never
/// part of a snapshot). Hidden names are refused: they are locks, journals
/// and staging directories.
fn plain_name(name: &str) -> bool {
    name != "backups"
        && name
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

/// One way a target may be accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TargetRule {
    /// Exactly this path; symlink checks start at its parent.
    Exact(PathBuf),
    /// A direct child of `dir` with a plain name (see `plain_name`).
    Child { dir: PathBuf },
    /// `{home}/{domain}_ecc/{domain}.conf` (a retired acme.sh deployment);
    /// symlink checks start at `home`.
    AcmeDeployment { home: PathBuf },
    /// `{home}/{domain}_ecc/{domain}.conf` under any directory that is
    /// recognisably an acme.sh home ([`is_acme_home`]), is not a system
    /// directory and neither contains nor lies inside any of `outside`
    /// (Onebox's own trees, whose acme.sh copies are snapshotted with them);
    /// symlink checks start at that home.
    AnyAcmeDeployment { outside: Vec<PathBuf> },
}

impl TargetRule {
    /// The owned root of `target` when this rule accepts it.
    fn owned_root(&self, target: &Path) -> Option<PathBuf> {
        match self {
            TargetRule::Exact(path) => (path == target).then(|| parent(target)).flatten(),
            TargetRule::Child { dir } => {
                let name = target.file_name()?.to_str()?;
                (target.parent() == Some(dir.as_path()) && plain_name(name)).then(|| dir.clone())
            }
            TargetRule::AcmeDeployment { home } => {
                (deployment_home(target)? == home).then(|| home.clone())
            }
            TargetRule::AnyAcmeDeployment { outside } => {
                let home = deployment_home(target)?;
                let apart = outside
                    .iter()
                    .all(|o| !home.starts_with(o) && !o.starts_with(home));
                (apart && check_not_broad(home).is_ok() && is_acme_home(home))
                    .then(|| home.to_path_buf())
            }
        }
    }

    /// The directory (or path) this rule exposes to restores; `None` when
    /// it depends on the target (checked per target instead).
    fn scope(&self) -> Option<&Path> {
        match self {
            TargetRule::Exact(path) => Some(path),
            TargetRule::Child { dir } => Some(dir),
            TargetRule::AcmeDeployment { home } => Some(home),
            TargetRule::AnyAcmeDeployment { .. } => None,
        }
    }
}

/// The acme.sh home of `target` when it is `{home}/{domain}_ecc/{domain}.conf`
/// with a domain v2 accepted.
fn deployment_home(target: &Path) -> Option<&Path> {
    let file = target.file_name()?.to_str()?;
    let dir = target.parent()?;
    let domain = dir.file_name()?.to_str()?.strip_suffix("_ecc")?;
    let home = dir.parent()?;
    (v2_valid_domain(domain) && file.strip_suffix(".conf") == Some(domain)).then_some(home)
}

/// Whether `home` holds a regular `acme.sh` or `account.conf` (not
/// following symlinks): what every acme.sh installation has.
pub fn is_acme_home(home: &Path) -> bool {
    ["acme.sh", "account.conf"].iter().any(|name| {
        std::fs::symlink_metadata(home.join(name)).is_ok_and(|m| m.file_type().is_file())
    })
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
            .chain(self.rules.iter().filter_map(TargetRule::scope));
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
fn check_not_broad(path: &Path) -> Result<()> {
    if path.parent().is_none() || BROAD_ROOTS.iter().any(|root| path == Path::new(root)) {
        return Err(Error::msg(format!("事务目录范围过大: {}", path.display())));
    }
    Ok(())
}

/// Absolute, without `.`/`..` and not the root directory itself.
fn is_clean_absolute(path: &Path) -> bool {
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

/// The standalone-subscription ACME webroot (v2 slot item-17): defined
/// once, by [`Paths::subscription_acme`].
pub fn subscription_acme_dir(paths: &Paths) -> PathBuf {
    paths.subscription_acme()
}

/// v2's 38 fixed snapshot targets in v2 slot order: 15 `ROOT` items, the
/// site root, the manager executable, the subscription ACME webroot, both
/// core binaries, the unit file and init script of each of the 6 node
/// services, and the 6 v1 boot hooks (skipped when already listed).
pub fn v2_fixed_targets(paths: &Paths) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = V2_ROOT_ITEMS.iter().map(|s| paths.root.join(s)).collect();
    out.push(paths.site_root.clone());
    out.push(paths.executable.clone());
    out.push(paths.subscription_acme());
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

/// The configured node directories: v2 `safe_roots` guarded them, and no
/// acme.sh home may overlap them.
fn node_roots(paths: &Paths) -> [PathBuf; 5] {
    [
        paths.root.clone(),
        paths.bin.clone(),
        paths.site_root.clone(),
        paths.systemd.clone(),
        paths.initd.clone(),
    ]
}

/// The configured node roots v2 `safe_roots` guarded: none may be a system
/// directory, and the site root and `ROOT` must not contain one another.
fn guard_node_roots(list: Allowlist, paths: &Paths) -> Allowlist {
    node_roots(paths)
        .into_iter()
        .fold(list, Allowlist::guard_root)
        .keep_apart(
            paths.root.clone(),
            paths.site_root.clone(),
            "网站目录和配置目录不能互相包含",
        )
}

/// The allowlist for snapshots written by v2 (G1): the 38 fixed targets,
/// each required, plus retired acme.sh deployments under v2's default home
/// [`DEFAULT_ACME_HOME`] or under any other recognisable acme.sh home
/// ([`TargetRule::AnyAcmeDeployment`]). Nothing depends on the process
/// environment: a journal v2 wrote with a custom `ACME_HOME` validates in
/// a boot `net-apply`, which runs without it.
pub fn v2_node_allowlist(paths: &Paths) -> Allowlist {
    v2_node_allowlist_with(paths, &[PathBuf::from(DEFAULT_ACME_HOME)]).with_rule(
        TargetRule::AnyAcmeDeployment {
            outside: node_roots(paths).to_vec(),
        },
    )
}

/// The 38 fixed targets plus deployments under exactly `acme_homes` (no
/// recognition rule).
pub fn v2_node_allowlist_with(paths: &Paths, acme_homes: &[PathBuf]) -> Allowlist {
    let list = acme_homes
        .iter()
        .fold(Allowlist::exact(v2_fixed_targets(paths)), |list, home| {
            list.with_rule(TargetRule::AcmeDeployment { home: home.clone() })
        });
    guard_node_roots(list, paths)
}

/// What v3 node journals are validated against: any plain child of `ROOT`
/// (ROOT belongs to the node as a whole), plus exactly the node-owned paths
/// outside it — the site root, the executable, the subscription ACME
/// webroot, the two core binaries, and the unit files, init scripts and
/// `local.d` hooks of the node services and the v1 boot hooks (the
/// non-`ROOT` part of [`v2_fixed_targets`]). Other `onebox-*` units (FRP
/// has its own transaction) and other files in the core directory can
/// therefore never be overwritten or deleted by a node journal. A path v3
/// adds outside `ROOT` must be added here, and names are never removed, so
/// that newer managers keep accepting older journals.
pub fn node_allowlist(paths: &Paths) -> Allowlist {
    let outside_root = v2_fixed_targets(paths)
        .into_iter()
        .filter(|t| t.parent() != Some(paths.root.as_path()));
    let list = outside_root.fold(
        Allowlist::default().with_rule(TargetRule::Child {
            dir: paths.root.clone(),
        }),
        |list, target| list.with_rule(TargetRule::Exact(target)),
    );
    guard_node_roots(list, paths)
}
