//! Command specs and handlers of the node commands (install, protocols,
//! clients, services, certificates, website, maintenance). Each module
//! exposes `const` [`CommandSpec`](super::args::CommandSpec)s for the
//! registry and `pub fn`s the menus call directly.

pub mod info;
pub mod install;
