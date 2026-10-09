//! The one step engine behind the configuration wizard and the
//! interactive client export (H-8.3#7: v2 had two copies), with v2's
//! keys: Enter keeps the default, `b` goes back one step, `q` (or EOF)
//! cancels.
//!
//! A [`Form`] is a numbered list of steps. [`run`] asks them in order:
//! a finished step moves on, [`Answer::Back`] returns to the previous one,
//! a cancellation aborts, and any other error is printed (`[错误] …`) and
//! the form continues at [`Form::retry_at`] (the same step by default).
//! Field prompts re-ask by themselves until the answer parses, printing
//! v2's hint lines.
//!
//! Changes from v2: the engine refuses to run without a terminal (v2 had
//! `-y` branches deep inside the prompts); the hints are printed on stderr
//! next to the prompt as before.

use crate::domain::config::PortRange;
use crate::error::{Error, Result};
use crate::frp::model::MAX_RANGE_PORTS;
use crate::sys::text::valid_domain;
use crate::ui::{out, Prompter};

/// What the user answered to one prompt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answer<T> {
    Value(T),
    /// `b`: go back one step.
    Back,
}

impl<T> Answer<T> {
    /// Apply `f` to a value; `Back` stays `Back`.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Answer<U> {
        match self {
            Answer::Value(v) => Answer::Value(f(v)),
            Answer::Back => Answer::Back,
        }
    }
}

/// Unwrap a value or return `Back` from the enclosing step.
macro_rules! value {
    ($answer:expr) => {
        match $answer {
            $crate::frp::steps::Answer::Value(v) => v,
            $crate::frp::steps::Answer::Back => return Ok($crate::frp::steps::Answer::Back),
        }
    };
}
pub(crate) use value;

/// One free-text answer: `b`/`B` → [`Answer::Back`], `q`/`Q` → cancelled.
pub fn ask(ui: &dyn Prompter, prompt: &str, default: &str) -> Result<Answer<String>> {
    let value = ui.input(prompt, default)?;
    match value.to_ascii_lowercase().as_str() {
        "q" => Err(Error::Cancelled),
        "b" => Ok(Answer::Back),
        _ => Ok(Answer::Value(value)),
    }
}

/// [`ask`] until `parse` accepts the answer; each rejection prints `hint`.
/// Without a terminal an unacceptable default is `unattended` (nobody can
/// be asked again).
fn ask_until<T>(
    ui: &dyn Prompter,
    prompt: &str,
    default: &str,
    hint: &str,
    unattended: &str,
    parse: impl Fn(&str) -> Option<T>,
) -> Result<Answer<T>> {
    loop {
        let answer = value!(ask(ui, prompt, default)?);
        if let Some(parsed) = parse(&answer) {
            return Ok(Answer::Value(parsed));
        }
        if !ui.interactive() {
            return Err(Error::msg(unattended));
        }
        out::line(hint);
    }
}

/// A number in `min..=max` (v2 `choose`).
pub fn choose(
    ui: &dyn Prompter,
    prompt: &str,
    default: u32,
    min: u32,
    max: u32,
) -> Result<Answer<u32>> {
    let hint = format!("请输入 {min}–{max}，b 返回，q 取消");
    ask_until(
        ui,
        prompt,
        &default.to_string(),
        &hint,
        "默认选项无效",
        |a| a.parse::<u32>().ok().filter(|n| (min..=max).contains(n)),
    )
}

/// A port; 0 only when `zero` (v2 `ask_port`).
pub fn ask_port(ui: &dyn Prompter, prompt: &str, default: u16, zero: bool) -> Result<Answer<u16>> {
    let hint = format!("端口范围为 {}–65535", u8::from(!zero));
    ask_until(
        ui,
        prompt,
        &default.to_string(),
        &hint,
        "默认端口无效",
        |a| a.parse::<u16>().ok().filter(|p| zero || *p > 0),
    )
}

/// A DNS name, lower-cased (v2 `ask_domain`; IP literals are refused,
/// H-8.1#15).
pub fn ask_domain(ui: &dyn Prompter, prompt: &str, default: &str) -> Result<Answer<String>> {
    ask_until(
        ui,
        prompt,
        default,
        "请输入完整域名，不包含协议、路径或 *.",
        "默认域名无效",
        |a| Some(a.to_ascii_lowercase()).filter(|d| valid_domain(d)),
    )
}

/// `a-b` with `0 < a <= b` and at most 1000 ports (the wizard's range).
pub fn parse_range(answer: &str) -> Option<PortRange> {
    let (a, b) = answer.split_once('-')?;
    let (start, end) = (a.trim().parse::<u16>().ok()?, b.trim().parse::<u16>().ok()?);
    (start > 0 && end >= start && u32::from(end - start) < MAX_RANGE_PORTS)
        .then_some(PortRange { start, end })
}

/// A forwarding range (v2 wizard step 3, tcp mode).
pub fn ask_range(ui: &dyn Prompter, prompt: &str, default: PortRange) -> Result<Answer<PortRange>> {
    ask_until(
        ui,
        prompt,
        &default.to_string(),
        "请输入递增端口范围，最多 1000 个，例如 20000-20100",
        "默认端口范围无效",
        parse_range,
    )
}

/// A numbered list of steps (see the module docs).
pub trait Form {
    /// How many steps there are.
    fn steps(&self) -> usize;
    /// Ask step `index`.
    fn step(&mut self, ui: &dyn Prompter, index: usize) -> Result<Answer<()>>;
    /// Where to continue after step `index` failed.
    fn retry_at(&self, index: usize) -> usize {
        index
    }
}

/// Run `form` to its end (module docs). Needs a terminal.
pub fn run(ui: &dyn Prompter, form: &mut dyn Form) -> Result<()> {
    ensure!(ui.interactive(), "{}", crate::ui::NO_TERMINAL);
    let mut index = 0;
    while index < form.steps() {
        match form.step(ui, index) {
            Ok(Answer::Value(())) => index += 1,
            Ok(Answer::Back) => index = index.saturating_sub(1),
            Err(e) if e.is_cancelled() => return Err(e),
            Err(e) => {
                out::error(&e);
                index = form.retry_at(index);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::ScriptedPrompter;

    #[test]
    fn keys_back_and_cancel() {
        let ui = ScriptedPrompter::new(["", "B", "q", "value"]);
        assert_eq!(ask(&ui, "x", "d").unwrap(), Answer::Value("d".into()));
        assert_eq!(ask(&ui, "x", "d").unwrap(), Answer::Back);
        assert!(ask(&ui, "x", "d").unwrap_err().is_cancelled());
        assert_eq!(ask(&ui, "x", "d").unwrap(), Answer::Value("value".into()));
        assert!(ask(&ui, "x", "d").unwrap_err().is_cancelled(), "EOF");
    }

    #[test]
    fn fields_re_ask_until_valid() {
        let ui = ScriptedPrompter::new(["3", "x", "2", "0", "70000", "443", "0"]);
        assert_eq!(choose(&ui, "模式", 1, 1, 2).unwrap(), Answer::Value(2));
        assert_eq!(
            ask_port(&ui, "端口", 7000, false).unwrap(),
            Answer::Value(443)
        );
        assert_eq!(ask_port(&ui, "端口", 80, true).unwrap(), Answer::Value(0));
        assert_eq!(
            ui.prompts(),
            ["模式", "模式", "模式", "端口", "端口", "端口", "端口"]
        );
        let ui = ScriptedPrompter::new(["https://x", "1.2.3.4", "B", "App.Example.COM"]);
        assert_eq!(ask_domain(&ui, "域名", "").unwrap(), Answer::Back);
        assert_eq!(
            ask_domain(&ui, "域名", "").unwrap(),
            Answer::Value("app.example.com".into())
        );
    }

    #[test]
    fn unattended_defaults_must_be_valid() {
        let ui = ScriptedPrompter::unattended();
        assert_eq!(choose(&ui, "x", 1, 1, 2).unwrap(), Answer::Value(1));
        assert_eq!(
            choose(&ui, "x", 5, 1, 2).unwrap_err().to_string(),
            "默认选项无效"
        );
        assert_eq!(
            ask_port(&ui, "x", 0, false).unwrap_err().to_string(),
            "默认端口无效"
        );
        assert_eq!(
            ask_domain(&ui, "x", "").unwrap_err().to_string(),
            "默认域名无效"
        );
    }

    #[test]
    fn ranges() {
        for (text, ok) in [
            ("20000-20100", true),
            ("1-1000", true),
            ("1-1001", false),
            ("0-10", false),
            ("10-9", false),
            ("10", false),
            ("a-b", false),
        ] {
            assert_eq!(parse_range(text).is_some(), ok, "{text}");
        }
        let ui = ScriptedPrompter::new(["5-1", ""]);
        let default = PortRange {
            start: 20000,
            end: 20100,
        };
        assert_eq!(
            ask_range(&ui, "范围", default).unwrap(),
            Answer::Value(default)
        );
    }

    /// Three steps recording what ran; step 1 fails once, step 2 goes back once.
    struct Probe {
        log: Vec<usize>,
        failed: bool,
        backed: bool,
    }

    impl Form for Probe {
        fn steps(&self) -> usize {
            3
        }
        fn step(&mut self, ui: &dyn Prompter, index: usize) -> Result<Answer<()>> {
            self.log.push(index);
            let _ = value!(ask(ui, "s", "")?);
            if index == 1 && !self.failed {
                self.failed = true;
                bail!("第一次失败");
            }
            if index == 2 && !self.backed {
                self.backed = true;
                return Ok(Answer::Back);
            }
            Ok(Answer::Value(()))
        }
    }

    #[test]
    fn engine_moves_back_retries_and_cancels() {
        let ui = ScriptedPrompter::new(["", "", "", "", "", "", ""]);
        let mut probe = Probe {
            log: vec![],
            failed: false,
            backed: false,
        };
        run(&ui, &mut probe).unwrap();
        assert_eq!(probe.log, [0, 1, 1, 2, 1, 2]);
        // `b` on the first step stays there.
        let ui = ScriptedPrompter::new(["b", "q"]);
        let mut probe = Probe {
            log: vec![],
            failed: true,
            backed: true,
        };
        assert!(run(&ui, &mut probe).unwrap_err().is_cancelled());
        assert_eq!(probe.log, [0, 0]);
        let ui = ScriptedPrompter::unattended();
        assert!(run(&ui, &mut probe).is_err(), "needs a terminal");
    }
}
