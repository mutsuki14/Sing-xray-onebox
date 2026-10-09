//! Low-level, OS-facing primitives without domain knowledge.

pub mod exec;
pub mod fs;
pub mod lock;
pub mod net;
pub mod process;
pub mod rand;
pub mod signal;
#[cfg(test)]
pub(crate) mod testenv;
pub mod text;
pub mod time;
pub mod tty;
