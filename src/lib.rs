pub mod backup;
pub mod bbr;
pub mod cert;
pub mod cli;
pub mod context;
pub mod diagnostics;
pub mod frp;
pub mod model;
pub mod network;
pub mod platform;
pub mod render;
pub mod runtime;
pub mod site;
pub mod state;
pub mod subscription;
pub mod transaction;
pub mod ui;
pub mod update;
pub mod util;
pub mod workflow;
pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const REPOSITORY: &str = "mutsuki14/Sing-xray-onebox";

#[derive(Debug)]
pub struct ExitError {
    pub code: i32,
    pub message: String,
}
impl ExitError {
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}
impl std::fmt::Display for ExitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for ExitError {}
