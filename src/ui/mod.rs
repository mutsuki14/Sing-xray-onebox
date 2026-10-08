//! Interaction layer: the [`Prompter`] trait with terminal, unattended and
//! scripted implementations, output conventions, secret input and QR codes.

pub mod out;
pub mod qr;
pub mod secret;

use crate::error::Result;
use std::sync::Arc;

pub trait Prompter: Send + Sync {
    /// False under `-y` or when no terminal is available.
    fn interactive(&self) -> bool;
    fn assume_yes(&self) -> bool;
    /// Free text; sanitized; empty answer → `default`. EOF → `Error::Cancelled`.
    fn input(&self, prompt: &str, default: &str) -> Result<String>;
    /// Like `input` but validates; re-asks on error when interactive, fails under `-y`.
    fn input_with(
        &self,
        prompt: &str,
        default: &str,
        check: &dyn Fn(&str) -> Result<String>,
    ) -> Result<String>;
    /// y/n. Under `-y` returns true (v2 parity); see `confirm_danger` for the exception.
    fn confirm(&self, prompt: &str, default: bool) -> Result<bool>;
    /// Numbered single choice over `items` (1-based display); returns the 0-based index.
    /// When `back` is true a `0) 返回` entry is offered and returns `None`.
    fn select(
        &self,
        title: &str,
        items: &[String],
        default: usize,
        back: bool,
    ) -> Result<Option<usize>>;
    /// Numbered multi choice ("1 3 5" / "1,3"); returns sorted, deduplicated 0-based indexes.
    fn select_many(&self, title: &str, items: &[String], default: &[usize]) -> Result<Vec<usize>>;
    /// No-echo input from the controlling terminal. Under `-y` → error.
    fn secret(&self, prompt: &str) -> Result<String>;
}

/// The prompter used by the real binary.
pub fn system_prompter(_assume_yes: bool) -> Arc<dyn Prompter> {
    todo!("WP-A1: TtyPrompter / AutoPrompter")
}
