//! Independent FRP server manager (`onebox frps`, spec H): a managed
//! `frps` with its own state, lock, transaction, services, firewall owner,
//! certificates and cron lines, separate from the proxy node.
//!
//! - `web` mode: public HTTPS for application domains through a private
//!   nginx (`onebox-frp-web`) in front of frps' loopback vhost port;
//! - `tcp` mode: public TCP/UDP forwarding inside a port range;
//! - the control channel always uses forced TLS with a private CA Onebox
//!   creates and pins in every exported client, plus a 64-hex token that
//!   also authenticates heartbeats and work connections.
//!
//! Modules: [`model`] (state, leaf), [`draft`] (flat editable form and
//! flags), [`steps`] + [`wizard`] + [`export`] (interaction), [`render`]
//! (frps.toml, nginx.conf, client bundle, summary), [`ca`], [`preflight`],
//! [`release`], [`journal`] + [`txn`] (transactions and recovery),
//! [`runtime`] (host effects), [`lifecycle`] (operations), [`cli`]
//! (command tree, handlers, menu), [`checks`] (doctor).
//!
//! Public entry points used by other packages: [`cli_spec`] (the `frps`
//! tree for the registry), [`menu`] (G41), [`net_apply`] (the
//! `onebox-frps` pre-start hook), [`recover`] (`onebox recover`, after the
//! node journal), [`checks`] (`onebox doctor`), and the leaf
//! [`model::installed`] / [`model::reservations`].
//!
//! Changes from v2 (details in each module): H-8.1#1 a fresh `--tls cf`
//! install works and nothing is written before the confirmation; #2 the
//! distro nginx service no longer holds 80/443; #3 `--dry-run`/`--help`
//! work; #4 the wildcard summary names the export's default label `www`;
//! #5 nothing is downloaded when the version is unchanged; #6 downloads use
//! the shared hardened transport; #7 node ports come from the node's port
//! authority; #8 web mode reserves no forwarding range; #9 unit adoption
//! needs the spec; #11/#12 cron lines are matched consistently and boot
//! starts once; #14 a cleanup failure never fails a successful change;
//! #15 new names must be DNS domains; #16 precise messages; #17 the cron
//! daemon is checked before anything changes; G24 transactions are
//! journaled and recovered after a crash; G25 FRP cron lines are rewritten
//! in v3 form.

pub mod ca;
pub mod checks;
pub mod cli;
pub mod draft;
pub mod export;
pub mod journal;
pub mod lifecycle;
pub mod model;
pub mod preflight;
pub mod release;
pub mod render;
pub mod runtime;
pub mod steps;
#[cfg(test)]
pub(crate) mod testing;
pub mod txn;
pub mod wizard;

#[cfg(test)]
mod e2e;

pub use checks::checks;
pub use cli::{cli_spec, Action, COMMAND};
pub use lifecycle::{net_apply, recover};

use crate::ctx::Ctx;
use crate::error::Result;

/// The FRP menu (bare `frps` with a terminal; status without one).
pub fn menu(ctx: &Ctx) -> Result<()> {
    cli::run(ctx, Action::Menu)
}
