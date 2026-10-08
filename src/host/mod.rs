//! Host integration: OS facts, init systems and services, packages, downloads,
//! cron, firewall, port hopping, sysctl, proxy cores and nginx. Everything
//! that runs a program goes through `Ctx::exec` so it can be faked in tests.

pub mod cores;
pub mod cron;
pub mod fetch;
pub mod firewall;
pub mod hop;
pub mod init;
pub mod nginx;
pub mod os;
pub mod pkg;
pub mod service;
pub mod supervisor;
pub mod sysctl;
