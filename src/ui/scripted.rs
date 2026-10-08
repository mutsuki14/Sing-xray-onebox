//! Scripted prompter for tests: queued answers are consumed in order and
//! every prompt is recorded.
//!
//! Mode is decided by two flags (both adjustable after construction so a
//! test can reconfigure the prompter it got from `Ctx::test`):
//! - `assume_yes` → behaves exactly like `AutoPrompter { assume_yes: true }`;
//! - not `interactive` → behaves like `AutoPrompter { assume_yes: false }`;
//! - otherwise answers are popped from the queue and parsed like terminal
//!   input (invalid answers are recorded in `errors()` and the next answer
//!   is used, mirroring the terminal's re-ask loop). An empty queue means
//!   EOF → `Error::Cancelled`.

use super::{
    format_menu, parse_confirm, parse_select, parse_select_many, select_hint, AutoPrompter,
    Prompter,
};
use crate::error::{Error, Result};
use crate::sys::text::sanitize_input;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

#[derive(Default)]
struct Script {
    answers: VecDeque<String>,
    prompts: Vec<String>,
    errors: Vec<String>,
    menus: Vec<String>,
}

pub struct ScriptedPrompter {
    script: Mutex<Script>,
    interactive: AtomicBool,
    assume_yes: AtomicBool,
}

impl ScriptedPrompter {
    /// Interactive prompter answering with `answers` in order.
    pub fn new<I, S>(answers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        ScriptedPrompter {
            script: Mutex::new(Script {
                answers: answers.into_iter().map(Into::into).collect(),
                ..Script::default()
            }),
            interactive: AtomicBool::new(true),
            assume_yes: AtomicBool::new(false),
        }
    }

    /// Prompter emulating `-y`.
    pub fn unattended() -> Self {
        let ui = Self::new(Vec::<String>::new());
        ui.set_assume_yes(true);
        ui
    }

    pub fn set_interactive(&self, value: bool) {
        self.interactive.store(value, Ordering::SeqCst);
    }

    /// Setting `assume_yes` also makes the prompter non-interactive.
    pub fn set_assume_yes(&self, value: bool) {
        self.assume_yes.store(value, Ordering::SeqCst);
        if value {
            self.set_interactive(false);
        }
    }

    /// Queue more answers.
    pub fn push(&self, answer: impl Into<String>) {
        self.lock().answers.push_back(answer.into());
    }

    pub fn extend<I, S>(&self, answers: I)
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.lock()
            .answers
            .extend(answers.into_iter().map(Into::into));
    }

    /// Every prompt text / selection title asked so far.
    pub fn prompts(&self) -> Vec<String> {
        self.lock().prompts.clone()
    }

    /// Error messages a terminal would have printed before re-asking.
    pub fn errors(&self) -> Vec<String> {
        self.lock().errors.clone()
    }

    /// Menus shown by `select`/`select_many` (as `format_menu` renders them).
    pub fn menus(&self) -> Vec<String> {
        self.lock().menus.clone()
    }

    /// Answers not consumed yet.
    pub fn remaining(&self) -> usize {
        self.lock().answers.len()
    }

    fn lock(&self) -> MutexGuard<'_, Script> {
        self.script.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The emulated unattended prompter, when the flags ask for one.
    fn auto(&self) -> Option<AutoPrompter> {
        let assume_yes = self.assume_yes.load(Ordering::SeqCst);
        let interactive = self.interactive.load(Ordering::SeqCst);
        (assume_yes || !interactive).then_some(AutoPrompter { assume_yes })
    }

    fn record(&self, prompt: &str) {
        self.lock().prompts.push(prompt.to_string());
    }

    fn record_error(&self, message: String) {
        self.lock().errors.push(message);
    }

    fn next(&self) -> Result<String> {
        self.lock().answers.pop_front().ok_or(Error::Cancelled)
    }

    /// Pop answers until `parse` accepts one; rejected answers record `hint`.
    fn ask_until<T>(&self, hint: &str, parse: impl Fn(&str) -> Option<T>) -> Result<T> {
        loop {
            let answer = sanitize_input(&self.next()?);
            match parse(&answer) {
                Some(value) => return Ok(value),
                None => self.record_error(hint.to_string()),
            }
        }
    }
}

impl Prompter for ScriptedPrompter {
    fn interactive(&self) -> bool {
        self.interactive.load(Ordering::SeqCst) && !self.assume_yes.load(Ordering::SeqCst)
    }

    fn assume_yes(&self) -> bool {
        self.assume_yes.load(Ordering::SeqCst)
    }

    fn input(&self, prompt: &str, default: &str) -> Result<String> {
        self.record(prompt);
        if let Some(auto) = self.auto() {
            return auto.input(prompt, default);
        }
        let answer = sanitize_input(&self.next()?);
        Ok(if answer.is_empty() {
            default.to_string()
        } else {
            answer
        })
    }

    fn input_with(
        &self,
        prompt: &str,
        default: &str,
        check: &dyn Fn(&str) -> Result<String>,
    ) -> Result<String> {
        if let Some(auto) = self.auto() {
            self.record(prompt);
            return auto.input_with(prompt, default, check);
        }
        loop {
            let value = self.input(prompt, default)?;
            match check(&value) {
                Ok(valid) => return Ok(valid),
                Err(e) if e.is_cancelled() => return Err(e),
                Err(e) => self.record_error(e.to_string()),
            }
        }
    }

    fn confirm(&self, prompt: &str, default: bool) -> Result<bool> {
        self.record(prompt);
        if let Some(auto) = self.auto() {
            return auto.confirm(prompt, default);
        }
        self.ask_until("请输入 y 或 n", |a| parse_confirm(a, default))
    }

    fn select(
        &self,
        title: &str,
        items: &[String],
        default: usize,
        back: bool,
    ) -> Result<Option<usize>> {
        self.record(title);
        self.lock().menus.push(format_menu(title, items, back));
        if let Some(auto) = self.auto() {
            return auto.select(title, items, default, back);
        }
        if items.is_empty() && !back {
            return Err(Error::msg("没有可选择的项目"));
        }
        let hint = select_hint(items.len(), back);
        self.ask_until(&hint, |a| parse_select(a, items.len(), default, back))
    }

    fn select_many(&self, title: &str, items: &[String], default: &[usize]) -> Result<Vec<usize>> {
        self.record(title);
        self.lock().menus.push(format_menu(title, items, false));
        if let Some(auto) = self.auto() {
            return auto.select_many(title, items, default);
        }
        self.ask_until("编号无效", |a| {
            parse_select_many(a, items.len(), default)
        })
    }

    fn secret(&self, prompt: &str) -> Result<String> {
        self.record(prompt);
        if let Some(auto) = self.auto() {
            return auto.secret(prompt);
        }
        self.next()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::{BAD_DEFAULT, NO_TERMINAL, UNATTENDED_SECRET};

    fn items(n: usize) -> Vec<String> {
        (1..=n).map(|i| format!("p{i}")).collect()
    }

    #[test]
    fn answers_are_consumed_in_order() {
        let ui = ScriptedPrompter::new([
            "  node-1 \x1b[A",
            "",
            "maybe",
            "n",
            "9",
            "0",
            "2 1",
            "s3cr3t",
        ]);
        assert!(ui.interactive() && !ui.assume_yes());
        assert_eq!(ui.input("名称", "onebox").unwrap(), "node-1");
        assert_eq!(ui.input("地址", "1.2.3.4").unwrap(), "1.2.3.4");
        assert!(!ui.confirm("继续？", true).unwrap());
        assert_eq!(ui.errors(), ["请输入 y 或 n"]);
        assert_eq!(ui.select("协议", &items(3), 0, true).unwrap(), None);
        assert_eq!(ui.errors()[1], "请输入 0–3");
        assert_eq!(ui.select_many("多选", &items(3), &[]).unwrap(), [0, 1]);
        assert_eq!(ui.secret("令牌").unwrap(), "s3cr3t");
        assert_eq!(ui.remaining(), 0);
        assert_eq!(
            ui.prompts(),
            ["名称", "地址", "继续？", "协议", "多选", "令牌"]
        );
        assert_eq!(ui.menus()[0], "协议\n  1) p1\n  2) p2\n  3) p3\n  0) 返回");
        assert!(
            ui.input("x", "y").unwrap_err().is_cancelled(),
            "empty queue = EOF"
        );
    }

    #[test]
    fn validation_re_asks() {
        let ui = ScriptedPrompter::new(["abc", "70000", "8443"]);
        let port = |s: &str| -> Result<String> {
            match s.parse::<u16>() {
                Ok(p) if p > 0 => Ok(p.to_string()),
                _ => Err(Error::msg(format!("端口无效: {s}"))),
            }
        };
        assert_eq!(ui.input_with("端口", "443", &port).unwrap(), "8443");
        assert_eq!(ui.errors(), ["端口无效: abc", "端口无效: 70000"]);
        assert_eq!(ui.prompts().len(), 3);
    }

    #[test]
    fn invalid_multi_selection_re_asks() {
        let ui = ScriptedPrompter::new(["7", "1"]);
        assert_eq!(ui.select_many("t", &items(2), &[1]).unwrap(), [0]);
        assert_eq!(ui.errors(), ["编号无效"]);
    }

    #[test]
    fn unattended_mode_matches_auto_prompter() {
        let ui = ScriptedPrompter::unattended();
        assert!(!ui.interactive() && ui.assume_yes());
        assert_eq!(ui.input("名称", "onebox").unwrap(), "onebox");
        assert!(ui.confirm("x", false).unwrap());
        assert_eq!(ui.select("t", &items(2), 1, false).unwrap(), Some(1));
        assert_eq!(
            ui.select("t", &items(2), 5, false).unwrap_err().to_string(),
            BAD_DEFAULT
        );
        assert_eq!(ui.secret("s").unwrap_err().to_string(), UNATTENDED_SECRET);
        assert_eq!(ui.prompts().len(), 5);
    }

    #[test]
    fn non_interactive_mode_fails_like_no_terminal() {
        let ui = ScriptedPrompter::new(["ignored"]);
        ui.set_interactive(false);
        assert_eq!(ui.input("x", "d").unwrap_err().to_string(), NO_TERMINAL);
        assert_eq!(ui.remaining(), 1);
        ui.set_interactive(true);
        assert_eq!(ui.input("x", "d").unwrap(), "ignored");
    }
}
