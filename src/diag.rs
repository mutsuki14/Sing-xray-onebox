//! Diagnostics: doctor checks and the support bundle (WP-C6). The check
//! types are shared so feature modules can contribute checks.

/// Outcome of one doctor check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
}

/// One line of `onebox doctor` output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Check {
    pub name: String,
    pub status: CheckStatus,
    pub detail: String,
}

impl Check {
    pub fn new(name: impl Into<String>, status: CheckStatus, detail: impl Into<String>) -> Self {
        Check {
            name: name.into(),
            status,
            detail: detail.into(),
        }
    }
}
