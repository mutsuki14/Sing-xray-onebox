//! Ctrl+C at a question inside a menu action cancels that action (G5).
//!
//! `main` leaves SIGINT at its default, so without handlers Ctrl+C ends
//! the process wherever it is pressed. The menu wraps its prompter in
//! [`Interruptible`]: while a question waits for an answer, the recording
//! handlers of [`SignalScope`] are installed, so the read returns `EINTR`
//! and the question fails with `Error::Cancelled` — the menu then prints
//! `[提示]` and goes back (a cancelled menu prompt still leaves with 130).
//! The handlers are held only during questions: Ctrl+C while an action
//! works keeps its usual effect (the action's own scope, or the default).
//! A signal this wrapper turned into the error is cleared, so the next
//! apply does not find it pending.

use crate::error::{Error, Result};
use crate::sys::signal::{self, SignalScope};
use crate::ui::Prompter;
use std::sync::Arc;

/// What a question cancelled by a signal reports (`[提示] …` in the menu).
pub const CANCELLED: &str = "操作已取消";

/// A prompter whose questions are cancelled by SIGINT/SIGTERM/SIGHUP.
pub struct Interruptible {
    inner: Arc<dyn Prompter>,
}

impl Interruptible {
    pub fn new(inner: Arc<dyn Prompter>) -> Interruptible {
        Interruptible { inner }
    }

    /// Ask `question` with the recording handlers installed; a signal
    /// received meanwhile (also one that arrived outside the blocking
    /// read) cancels the question.
    fn guarded<T>(&self, question: impl FnOnce(&dyn Prompter) -> Result<T>) -> Result<T> {
        let before = signal::received();
        // Without handlers the default disposition applies, as before.
        let scope = SignalScope::install().ok();
        let answer = question(self.inner.as_ref());
        let interrupted =
            scope.is_some() && signal::received() != before && signal::pending().is_some();
        if interrupted {
            signal::clear();
        }
        drop(scope);
        if interrupted {
            // Not the bare EOF form (`输入结束，操作已取消`).
            return Err(Error::Cancelled.wrap(CANCELLED));
        }
        answer
    }
}

impl Prompter for Interruptible {
    fn interactive(&self) -> bool {
        self.inner.interactive()
    }

    fn assume_yes(&self) -> bool {
        self.inner.assume_yes()
    }

    fn input(&self, prompt: &str, default: &str) -> Result<String> {
        self.guarded(|ui| ui.input(prompt, default))
    }

    fn input_with(
        &self,
        prompt: &str,
        default: &str,
        check: &dyn Fn(&str) -> Result<String>,
    ) -> Result<String> {
        self.guarded(|ui| ui.input_with(prompt, default, check))
    }

    fn confirm(&self, prompt: &str, default: bool) -> Result<bool> {
        self.guarded(|ui| ui.confirm(prompt, default))
    }

    fn select(
        &self,
        title: &str,
        items: &[String],
        default: usize,
        back: bool,
    ) -> Result<Option<usize>> {
        self.guarded(|ui| ui.select(title, items, default, back))
    }

    fn select_many(&self, title: &str, items: &[String], default: &[usize]) -> Result<Vec<usize>> {
        self.guarded(|ui| ui.select_many(title, items, default))
    }

    fn secret(&self, prompt: &str) -> Result<String> {
        self.guarded(|ui| ui.secret(prompt))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::ScriptedPrompter;

    /// A terminal whose user presses Ctrl+C while the question is shown
    /// (the answer typed before it is ignored).
    struct CtrlC(ScriptedPrompter);

    impl Prompter for CtrlC {
        fn interactive(&self) -> bool {
            true
        }
        fn assume_yes(&self) -> bool {
            false
        }
        fn input(&self, prompt: &str, default: &str) -> Result<String> {
            // SAFETY: raising a cancellation signal; the wrapper under test
            // must have its recording handler installed (else the test
            // process ends, which is the bug).
            unsafe {
                libc::raise(libc::SIGINT);
            }
            self.0.input(prompt, default)
        }
        fn input_with(
            &self,
            prompt: &str,
            default: &str,
            check: &dyn Fn(&str) -> Result<String>,
        ) -> Result<String> {
            self.0.input_with(prompt, default, check)
        }
        fn confirm(&self, prompt: &str, default: bool) -> Result<bool> {
            self.0.confirm(prompt, default)
        }
        fn select(
            &self,
            title: &str,
            items: &[String],
            default: usize,
            back: bool,
        ) -> Result<Option<usize>> {
            self.0.select(title, items, default, back)
        }
        fn select_many(
            &self,
            title: &str,
            items: &[String],
            default: &[usize],
        ) -> Result<Vec<usize>> {
            self.0.select_many(title, items, default)
        }
        fn secret(&self, prompt: &str) -> Result<String> {
            self.0.secret(prompt)
        }
    }

    #[test]
    fn ctrl_c_at_a_question_cancels_it_and_is_cleared() {
        let _signals = signal::TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        signal::clear();
        let inner = CtrlC(ScriptedPrompter::new(["typed", ""]));
        let ui = Interruptible::new(Arc::new(inner));
        let err = ui.input("ShadowTLS-v3 端口", "8443").unwrap_err();
        assert!(err.is_cancelled());
        assert_eq!(err.exit_code(), 130);
        assert_eq!(err.report_text(), CANCELLED);
        assert_eq!(signal::pending(), None, "the next apply is not cancelled");
        // Questions without a signal answer normally.
        assert!(ui.confirm("继续？", true).unwrap());
        assert!(ui.interactive() && !ui.assume_yes());
    }
}
