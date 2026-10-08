//! Non-interactive prompter: `-y` answers every question with its default;
//! without `-y` (and without a terminal) every question fails with a hint.

use super::{check_many_defaults, Prompter, BAD_DEFAULT, NO_TERMINAL, UNATTENDED_SECRET};
use crate::error::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AutoPrompter {
    pub assume_yes: bool,
}

impl AutoPrompter {
    fn require_yes(&self) -> Result<()> {
        if self.assume_yes {
            Ok(())
        } else {
            Err(Error::msg(NO_TERMINAL))
        }
    }
}

impl Prompter for AutoPrompter {
    fn interactive(&self) -> bool {
        false
    }

    fn assume_yes(&self) -> bool {
        self.assume_yes
    }

    fn input(&self, _prompt: &str, default: &str) -> Result<String> {
        self.require_yes()?;
        Ok(default.to_string())
    }

    /// Under `-y` the default must pass validation; there is nobody to re-ask.
    fn input_with(
        &self,
        _prompt: &str,
        default: &str,
        check: &dyn Fn(&str) -> Result<String>,
    ) -> Result<String> {
        self.require_yes()?;
        check(default)
    }

    /// v2 parity: `-y` approves every ordinary confirmation, whatever its
    /// default (destructive ones use `confirm_danger`).
    fn confirm(&self, _prompt: &str, _default: bool) -> Result<bool> {
        self.require_yes()?;
        Ok(true)
    }

    fn select(
        &self,
        _title: &str,
        items: &[String],
        default: usize,
        _back: bool,
    ) -> Result<Option<usize>> {
        self.require_yes()?;
        if default < items.len() {
            Ok(Some(default))
        } else {
            Err(Error::msg(BAD_DEFAULT))
        }
    }

    fn select_many(&self, _title: &str, items: &[String], default: &[usize]) -> Result<Vec<usize>> {
        self.require_yes()?;
        check_many_defaults(items.len(), default)?;
        let mut picked = default.to_vec();
        picked.sort_unstable();
        picked.dedup();
        Ok(picked)
    }

    fn secret(&self, _prompt: &str) -> Result<String> {
        Err(Error::msg(if self.assume_yes {
            UNATTENDED_SECRET
        } else {
            NO_TERMINAL
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn items() -> Vec<String> {
        vec!["a".into(), "b".into()]
    }

    #[test]
    fn assume_yes_uses_defaults() {
        let ui = AutoPrompter { assume_yes: true };
        assert!(!ui.interactive());
        assert!(ui.assume_yes());
        assert_eq!(ui.input("名称", "onebox").unwrap(), "onebox");
        assert!(ui.confirm("删除？", false).unwrap());
        assert_eq!(ui.select("t", &items(), 1, true).unwrap(), Some(1));
        assert_eq!(
            ui.select("t", &items(), 2, false).unwrap_err().to_string(),
            BAD_DEFAULT
        );
        assert_eq!(ui.select_many("t", &items(), &[1, 0, 1]).unwrap(), [0, 1]);
        assert!(ui.select_many("t", &items(), &[2]).is_err());
        assert_eq!(
            ui.secret("令牌").unwrap_err().to_string(),
            UNATTENDED_SECRET
        );
    }

    #[test]
    fn assume_yes_validates_default_once() {
        let ui = AutoPrompter { assume_yes: true };
        let upper = |s: &str| Ok(s.to_uppercase());
        assert_eq!(ui.input_with("x", "abc", &upper).unwrap(), "ABC");
        let reject = |_: &str| -> Result<String> { Err(Error::msg("端口无效")) };
        assert_eq!(
            ui.input_with("x", "0", &reject).unwrap_err().to_string(),
            "端口无效"
        );
    }

    #[test]
    fn without_terminal_everything_fails_with_hint() {
        let ui = AutoPrompter { assume_yes: false };
        assert!(!ui.interactive() && !ui.assume_yes());
        let id = |s: &str| Ok(s.to_string());
        for result in [
            ui.input("x", "d").map(|_| ()),
            ui.input_with("x", "d", &id).map(|_| ()),
            ui.confirm("x", true).map(|_| ()),
            ui.select("x", &items(), 0, false).map(|_| ()),
            ui.select_many("x", &items(), &[]).map(|_| ()),
            ui.secret("x").map(|_| ()),
        ] {
            assert_eq!(result.unwrap_err().to_string(), NO_TERMINAL);
        }
    }
}
