//! The transactional apply engine for node changes: journal, snapshot,
//! ordered stages, rollback, recovery and the boot-time network restore.
//!
//! Entry points ([`apply`], [`apply_locked`], [`recover`], [`recover_locked`],
//! [`boot`]) live in `request.rs`; [`engine`] drives one apply,
//! [`stages`](self) holds the stage table, [`rollback`] and [`recover`]
//! undo interrupted ones, [`network`] the firewall/hop rules shared by all
//! of them, [`features`] the seam to certificates, website and subscription.
//!
//! Invariant (G12): nothing reachable from these entry points asks the
//! prompter a question; progress and warnings go to stderr only.
//!
//! Changes from v2 (details in each module): typed intents instead of magic
//! state keys; one canonical service order; preconditions checked before
//! the journal exists; v3 journals (version 2) record their reason, the
//! typed old configuration, positioned cron lines and their own target list;
//! cancellation keeps exit code 130 and a pending signal never outlives a
//! failed operation; rollbacks are best effort where v2 stopped at the
//! first problem (rules or hops that cannot be removed are kept recorded,
//! old rules that cannot be re-created only warn, every service is still
//! enabled and started); boot waits for the node lock; HTTP-01 stops old
//! TCP-80 holders whatever certificate needs the port (G21).

pub mod boot;
pub mod engine;
pub mod features;
pub mod journal;
pub mod network;
pub mod program_journal;
pub mod recover;
mod request;
pub mod rollback;
pub mod snapshot;
mod stages;
pub mod transaction;

pub use features::{Checkpoint, Features, SystemFeatures};
pub use request::{
    apply, apply_locked, boot, frp_reservations, node_lock, recover, recover_locked, ApplyRequest,
    Intents,
};

#[cfg(test)]
pub(crate) mod harness;
#[cfg(test)]
pub(crate) mod testing;
#[cfg(test)]
mod tests;
