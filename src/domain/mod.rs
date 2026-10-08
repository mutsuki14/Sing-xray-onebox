//! Pure, typed domain model. No I/O in this module tree: no filesystem, no
//! processes, no clock (callers pass `now`), randomness only through
//! `&mut dyn sys::rand::Random`.

pub mod config;
pub mod credentials;
pub mod defaults;
pub mod plan;
pub mod ports;
pub mod presets;
pub mod protocol;
pub mod validate;

#[cfg(test)]
pub(crate) mod fixtures;

pub use config::NodeConfig;
pub use protocol::{ClientFormat, Core, Protocol, Transport};
