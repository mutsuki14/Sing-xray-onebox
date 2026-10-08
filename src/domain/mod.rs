//! Pure, typed domain model. No I/O in this module tree.

pub mod config;
pub mod credentials;
pub mod defaults;
pub mod plan;
pub mod ports;
pub mod presets;
pub mod protocol;
pub mod validate;

pub use config::NodeConfig;
pub use protocol::{ClientFormat, Core, Protocol, Transport};
