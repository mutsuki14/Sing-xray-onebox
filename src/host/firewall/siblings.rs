//! Rules recorded by the other Onebox owners, for backends where a port is
//! one shared object rather than a rule of its own.
//!
//! ufw keeps one rule per spec (adding it again only replaces the
//! comment), and firewalld one entry per port range and zone — since 0.9
//! it even merges overlapping ranges into one entry and splits an entry
//! when part of it is removed. When two owners want the same port
//! (typically `proxy` and the temporary `acme` owner on TCP 80), the port
//! must stay open until neither wants it: an owner that finds the port
//! already open for another owner records it as shared instead of treating
//! it as an administrator rule, and an owner that no longer wants it leaves
//! the ports other owners still record in place (handing the ufw comment
//! back; for firewalld see `Firewalld::release`). v2 closed TCP 80 after a
//! certificate issuance on such hosts when `acme` was cleared after `proxy`
//! had adopted the port.
//!
//! Sibling ledgers are read without their locks: their writers replace them
//! atomically, and owners that share ports (`proxy`, `acme`) are reconciled
//! one after another under the node lock.

use super::{Entry, Ledger, Location, PortSpan};
use crate::ctx::Ctx;
use std::path::{Path, PathBuf};

#[derive(Debug, Default)]
pub(super) struct Siblings(Vec<Entry>);

/// Every `firewall-*.json` beside ours and in the standard ledger homes.
fn sibling_paths(ctx: &Ctx, ours: &Path) -> Vec<PathBuf> {
    let mut dirs = vec![ctx.paths.root.clone(), ctx.paths.frp_root.clone()];
    if let Some(parent) = ours.parent() {
        dirs.push(parent.to_path_buf());
    }
    dirs.sort();
    dirs.dedup();
    let mut found = Vec::new();
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = entry.path();
            if name.starts_with("firewall-") && name.ends_with(".json") && path != ours {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

impl Siblings {
    /// The other owners' entries. An unreadable sibling ledger only means
    /// less sharing knowledge; its own owner reports it.
    pub fn load(ctx: &Ctx, ours: &Path) -> Siblings {
        let entries = sibling_paths(ctx, ours)
            .iter()
            .filter_map(|path| Ledger::load(path, "").ok())
            .flat_map(|ledger| ledger.entries)
            .collect();
        Siblings(entries)
    }

    /// Another owner's record of exactly `span` at a ufw location (the
    /// same ufw rule).
    pub fn ufw_holder(&self, location: &Location, span: PortSpan) -> Option<&Entry> {
        if !matches!(location, Location::Ufw(_)) {
            return None;
        }
        self.0
            .iter()
            .find(|e| e.location == *location && e.rule.range() == span)
    }

    /// The spans other owners record at `location`.
    pub fn spans_at<'a>(&'a self, location: &'a Location) -> impl Iterator<Item = PortSpan> + 'a {
        self.0
            .iter()
            .filter(move |e| e.location == *location)
            .map(|e| e.rule.range())
    }
}
