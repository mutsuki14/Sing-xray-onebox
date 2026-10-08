//! Client-side link tools (spec D): `probe export|list|merge`, `bench`,
//! `failover` and `reality-check`. Every measurement runs through a
//! temporary native sing-box/Xray client core with a random-credential
//! loopback SOCKS5 inbound — never directly — and every child process is
//! killed with its process group on timeout, cancellation or drop.
//!
//! Layout (spec D §8.3):
//! - [`bundle`]: bundle load/merge/export/list, entry selection, private
//!   (O_EXCL, 0600, no symlink) output files; the bundle type and its
//!   validation are `render::probe`'s;
//! - [`options`] / [`url`]: typed tool options with v2 names, ranges and
//!   defaults; strict HTTP(S) test URLs;
//! - [`core_client`]: the temporary client cores ([`core_client::Launcher`]
//!   / [`core_client::Proxy`] abstract them for the drivers);
//! - [`socks`]: SOCKS5 client and CONNECT-only server codecs;
//! - [`http_probe`]: curl invocations with the explicit body cap;
//! - [`stats`], [`report`]: rounding, distributions, report structs and the
//!   exit-code mapping;
//! - [`bench`], [`failover`], [`reality`]: the drivers;
//! - [`cancel`]: the run's cancellation token over `sys::signal`;
//! - [`cli`]: command specs and handlers ([`COMMANDS`] for the registry).
//!
//! Exit codes (v2): bench 0 / 1 failures / 130 cancelled; failover 0 on
//! Ctrl+C (normal stop) / 1 listener error; reality-check 0 / 1 failure or
//! no REALITY entry / 2 warnings only / 130 cancelled.
//!
//! Changes from v2 (each module lists its own; summary of D-8.1):
//! #1 per-tool help; #2 failover's Ctrl+C = 0 kept and documented; #3 the
//! warnings-only exit is printed as `[警告]` (error.rs); #4 explicit curl
//! body cap; #5 rounded p95; #6 loaded latency per transfer; #7 report
//! printed before it is saved, output directory checked up front; #8 real
//! error causes in reports and errors (credentials redacted); #9 Ctrl+C
//! during core startup is a cancellation; #10 one process-group kill
//! routine; #11 port-reservation race retried; #12 trimmed `--entries`;
//! #13 digits-only numbers, flag named in range errors; #14/#15 `--scope`
//! validation; #16 `probe merge` needs two inputs, clear overlong-id
//! error; #17 Ctrl+C before the first REALITY entry is 130; #18 missing h2
//! is a warning; #19 parsed TLS version; #20 parameterized probe errors;
//! #21 executable check and documented lookup order; #22 over-capacity
//! clients get `05 FF`; #23 blocking relay without busy polling; #24
//! explicit cancel token; #25 bounded statistics read.

pub mod bench;
pub mod bundle;
pub mod cancel;
pub mod cli;
pub mod core_client;
pub mod failover;
pub mod http_probe;
pub mod options;
pub mod reality;
pub mod report;
pub mod socks;
pub mod stats;
pub mod url;

pub use cli::{BENCH, COMMANDS, FAILOVER, PROBE, REALITY_CHECK};

#[cfg(test)]
pub(crate) mod testutil;
