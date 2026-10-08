//! Onebox: sing-box / Xray proxy server installer and manager for Linux.
//!
//! Layering (no cycles): `sys` → `domain` → `state`/`render` → `host` →
//! `cert`/`site`/`subscription` → `apply` → `backup`/`update` → `cli`.
//! `frp`, `bbr`, `linktools` and `diag` depend on lower layers only.

#[macro_use]
pub mod error;

pub mod apply;
pub mod backup;
pub mod bbr;
pub mod cert;
pub mod cli;
pub mod ctx;
pub mod diag;
pub mod domain;
pub mod frp;
pub mod host;
pub mod linktools;
pub mod paths;
pub mod render;
pub mod site;
pub mod state;
pub mod subscription;
pub mod sys;
pub mod ui;
pub mod update;

pub use ctx::Ctx;
pub use error::{Error, Result};

/// Manager version; also the release tag (`v{VERSION}`) and bootstrap pin.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// GitHub repository used for self-update and release URLs.
pub const REPOSITORY: &str = "mutsuki14/Sing-xray-onebox";
