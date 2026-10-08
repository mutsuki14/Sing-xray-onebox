//! Rules recorded by the other Onebox owners, for backends where a port is
//! one shared object rather than a rule of its own.
//!
//! firewalld has exactly one entry per port and zone, and ufw keeps one rule
//! per spec (adding it again only replaces the comment). When two owners
//! want the same port (typically `proxy` and the temporary `acme` owner on
//! TCP 80), the port must stay open until neither wants it: an owner that
//! finds the port held by another owner records it as shared instead of
//! treating it as an administrator rule, and an owner that no longer wants
//! it leaves it in place (handing the ufw comment back) while another owner
//! still records it. v2 closed TCP 80 after a certificate issuance on such
//! hosts when `acme` was cleared after `proxy` had adopted the port.
//!
//! Sibling ledgers are read without their locks: their writers replace them
//! atomically, and owners that share ports (`proxy`, `acme`) are reconciled
//! one after another under the node lock.

use super::ufw;
use super::{Entry, Ledger, Location, PortSpan};
use crate::ctx::Ctx;
use crate::error::Result;
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

    /// Another owner's record of `span` at a shared-object `location`.
    pub fn holder(&self, location: &Location, span: PortSpan) -> Option<&Entry> {
        if !matches!(location, Location::Firewalld(_) | Location::Ufw(_)) {
            return None;
        }
        self.0
            .iter()
            .find(|e| e.location == *location && e.rule.range() == span)
    }

    /// Stop wanting `entry` while `holder` still does: firewalld keeps the
    /// port as it is; ufw gets the holder's token back on the rule.
    pub fn hand_over(ctx: &Ctx, entry: &Entry, holder: &Entry) -> Result<()> {
        match entry.location {
            Location::Ufw(_) => ufw::recomment(ctx, &entry.rule, &holder.rule.token),
            _ => Ok(()),
        }
    }
}
