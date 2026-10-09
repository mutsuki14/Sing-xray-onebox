//! Interaction layer: the [`Prompter`] trait with terminal, unattended and
//! scripted implementations, output conventions, secret input and QR codes.
//!
//! Changes from v2: one shared buffered reader per session (B-9.1#22, v2
//! lost read-ahead by building a reader per question); prompts go to the
//! controlling terminal whenever there is one, so redirecting stderr cannot
//! hide a question that is waiting for input; validation errors re-ask
//! instead of aborting; `-y` keeps v2's "confirm → yes" rule except for
//! [`confirm_danger`], which requires an explicit `--force` (B-9.1#10).

pub mod auto;
pub mod menu;
pub mod out;
pub mod qr;
pub mod scripted;
pub mod secret;
pub mod tty;

pub use auto::AutoPrompter;
pub use scripted::ScriptedPrompter;
pub use tty::TtyPrompter;

use crate::error::{Error, Result};
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
    /// When `back` is true a `0) 返回` entry is offered and returns `None`; with
    /// `default` = [`BACK`] it is also what Enter (and `-y`) picks.
    fn select(
        &self,
        title: &str,
        items: &[String],
        default: usize,
        back: bool,
    ) -> Result<Option<usize>>;
    /// Numbered multi choice ("1 3 5" / "1,3"); returns sorted, deduplicated 0-based indexes.
    /// Every implementation rejects a `default` index `>= items.len()` with [`BAD_DEFAULT`].
    fn select_many(&self, title: &str, items: &[String], default: &[usize]) -> Result<Vec<usize>>;
    /// No-echo input from the controlling terminal. Under `-y` → error.
    fn secret(&self, prompt: &str) -> Result<String>;
}

/// Error when neither `-y` nor a terminal is available.
pub const NO_TERMINAL: &str = "当前没有交互终端，请通过参数提供配置并使用 -y";
/// Error for secrets requested in unattended mode.
pub const UNATTENDED_SECRET: &str = "无人值守模式请通过环境变量提供凭据";
/// Error when an unattended selection's default is out of range.
pub const BAD_DEFAULT: &str = "默认选项无效";
/// A [`Prompter::select`] default that makes `0) 返回` the default choice
/// (menus whose Enter leaves, like v2's `[默认: 0]`); needs `back`.
pub const BACK: usize = usize::MAX;

/// `select_many` defaults must index `items` (a caller bug otherwise; the
/// result would be used to index the same list).
pub fn check_many_defaults(count: usize, default: &[usize]) -> Result<()> {
    if default.iter().any(|&i| i >= count) {
        return Err(Error::msg(BAD_DEFAULT));
    }
    Ok(())
}

/// Confirmation for destructive actions that `-y` alone must not approve
/// (e.g. reinstalling over a node, which regenerates every credential):
/// `force` approves; under `-y` without `force` the action is refused with
/// `refuse_message`; otherwise the user is asked with default "no".
pub fn confirm_danger(
    ui: &dyn Prompter,
    prompt: &str,
    force: bool,
    refuse_message: &str,
) -> Result<bool> {
    if force {
        return Ok(true);
    }
    if ui.assume_yes() {
        return Err(Error::msg(refuse_message));
    }
    ui.confirm(prompt, false)
}

/// The prompter used by the real binary: unattended under `-y`, terminal
/// prompts when stdin or `/dev/tty` is usable, otherwise unattended without
/// defaults (every question fails with a hint to use `-y`).
pub fn system_prompter(assume_yes: bool) -> Arc<dyn Prompter> {
    if assume_yes {
        return Arc::new(AutoPrompter { assume_yes: true });
    }
    match TtyPrompter::open() {
        Some(tty) => Arc::new(tty),
        None => Arc::new(AutoPrompter { assume_yes: false }),
    }
}

/// `"{prompt} [默认: {default}]: "`, or `"{prompt}: "` without a default.
pub fn input_prompt(prompt: &str, default: &str) -> String {
    if default.is_empty() {
        format!("{prompt}: ")
    } else {
        format!("{prompt} [默认: {default}]: ")
    }
}

/// `"{prompt} [Y/n]: "` / `"{prompt} [y/N]: "`.
pub fn confirm_prompt(prompt: &str, default: bool) -> String {
    format!("{prompt} [{}]: ", if default { "Y/n" } else { "y/N" })
}

/// Interpret a y/n answer (already sanitized). `None` = not understood.
pub fn parse_confirm(answer: &str, default: bool) -> Option<bool> {
    match answer.trim().to_lowercase().as_str() {
        "" => Some(default),
        "y" | "yes" | "是" => Some(true),
        "n" | "no" | "否" => Some(false),
        _ => None,
    }
}

/// The numbered list shown by `select`/`select_many`: optional title line,
/// then `  1) item` with right-aligned numbers and an optional `  0) 返回`.
pub fn format_menu(title: &str, items: &[String], back: bool) -> String {
    let width = items.len().max(1).to_string().len();
    let mut lines = Vec::with_capacity(items.len() + 2);
    if !title.is_empty() {
        lines.push(title.to_string());
    }
    for (i, item) in items.iter().enumerate() {
        lines.push(format!("  {:>width$}) {item}", i + 1));
    }
    if back {
        lines.push(format!("  {:>width$}) 返回", 0));
    }
    lines.join("\n")
}

/// `"请选择 [默认: N]: "` (1-based; `0` for [`BACK`] with `back`), without a
/// bracket when there is no valid default.
pub fn select_prompt(count: usize, default: usize, back: bool) -> String {
    if default < count {
        format!("请选择 [默认: {}]: ", default + 1)
    } else if back && default == BACK {
        "请选择 [默认: 0]: ".to_string()
    } else {
        "请选择: ".to_string()
    }
}

/// Re-ask hint for an invalid single choice.
pub fn select_hint(count: usize, back: bool) -> String {
    format!("请输入 {}–{count}", if back { 0 } else { 1 })
}

/// Interpret a single-choice answer. `Some(None)` = back, `None` = invalid.
pub fn parse_select(
    answer: &str,
    count: usize,
    default: usize,
    back: bool,
) -> Option<Option<usize>> {
    let answer = answer.trim();
    if answer.is_empty() {
        if default < count {
            return Some(Some(default));
        }
        return (back && default == BACK).then_some(None);
    }
    match answer.parse::<usize>().ok()? {
        0 if back => Some(None),
        n if (1..=count).contains(&n) => Some(Some(n - 1)),
        _ => None,
    }
}

/// `"选择编号，以空格或逗号分隔 [默认: 1 3]: "` (only defaults below `count`).
pub fn select_many_prompt(count: usize, default: &[usize]) -> String {
    let shown: Vec<String> = valid_defaults(count, default)
        .iter()
        .map(|i| (i + 1).to_string())
        .collect();
    if shown.is_empty() {
        "选择编号，以空格或逗号分隔: ".to_string()
    } else {
        format!("选择编号，以空格或逗号分隔 [默认: {}]: ", shown.join(" "))
    }
}

/// Interpret a multi-choice answer ("1 3", "1,3", "1，3"); an empty answer
/// selects `default` (indexes `>= count` are never returned). `None` = some
/// number is invalid.
pub fn parse_select_many(answer: &str, count: usize, default: &[usize]) -> Option<Vec<usize>> {
    let tokens: Vec<&str> = answer
        .split(|c: char| c.is_whitespace() || matches!(c, ',' | '，' | '、'))
        .filter(|t| !t.is_empty())
        .collect();
    if tokens.is_empty() {
        return Some(valid_defaults(count, default));
    }
    let mut picked = Vec::with_capacity(tokens.len());
    for token in tokens {
        match token.parse::<usize>() {
            Ok(n) if (1..=count).contains(&n) => picked.push(n - 1),
            _ => return None,
        }
    }
    Some(normalize(&picked))
}

/// Sorted, deduplicated defaults below `count`.
fn valid_defaults(count: usize, default: &[usize]) -> Vec<usize> {
    let valid: Vec<usize> = default.iter().copied().filter(|&i| i < count).collect();
    normalize(&valid)
}

/// Sorted, deduplicated copy.
fn normalize(indexes: &[usize]) -> Vec<usize> {
    let mut v = indexes.to_vec();
    v.sort_unstable();
    v.dedup();
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn items(n: usize) -> Vec<String> {
        (1..=n).map(|i| format!("项目{i}")).collect()
    }

    #[test]
    fn prompt_formats() {
        assert_eq!(
            input_prompt("节点名称", "onebox"),
            "节点名称 [默认: onebox]: "
        );
        assert_eq!(input_prompt("域名", ""), "域名: ");
        assert_eq!(confirm_prompt("继续？", true), "继续？ [Y/n]: ");
        assert_eq!(confirm_prompt("删除？", false), "删除？ [y/N]: ");
        assert_eq!(select_prompt(3, 0, false), "请选择 [默认: 1]: ");
        assert_eq!(select_prompt(3, 7, true), "请选择: ");
        assert_eq!(select_prompt(3, BACK, true), "请选择 [默认: 0]: ");
        assert_eq!(select_prompt(3, BACK, false), "请选择: ");
        assert_eq!(select_hint(5, false), "请输入 1–5");
        assert_eq!(select_hint(5, true), "请输入 0–5");
        assert_eq!(
            select_many_prompt(3, &[2, 0, 2]),
            "选择编号，以空格或逗号分隔 [默认: 1 3]: "
        );
        assert_eq!(select_many_prompt(3, &[]), "选择编号，以空格或逗号分隔: ");
        assert_eq!(
            select_many_prompt(2, &[0, 5]),
            "选择编号，以空格或逗号分隔 [默认: 1]: ",
            "invalid defaults are never shown"
        );
    }

    #[test]
    fn menu_numbers_are_right_aligned() {
        assert_eq!(
            format_menu("协议", &items(2), true),
            "协议\n  1) 项目1\n  2) 项目2\n  0) 返回"
        );
        let menu = format_menu("", &items(11), true);
        let lines: Vec<&str> = menu.lines().collect();
        assert_eq!(lines[0], "   1) 项目1");
        assert_eq!(lines[10], "  11) 项目11");
        assert_eq!(lines[11], "   0) 返回");
    }

    #[test]
    fn confirm_answers() {
        for (answer, default, expected) in [
            ("", true, Some(true)),
            ("", false, Some(false)),
            ("y", false, Some(true)),
            ("YES", false, Some(true)),
            ("是", false, Some(true)),
            ("n", true, Some(false)),
            ("No", true, Some(false)),
            ("否", true, Some(false)),
            ("maybe", true, None),
            ("1", true, None),
        ] {
            assert_eq!(parse_confirm(answer, default), expected, "{answer:?}");
        }
    }

    #[test]
    fn select_answers() {
        for (answer, back, expected) in [
            ("", false, Some(Some(1))),
            ("1", false, Some(Some(0))),
            ("3", false, Some(Some(2))),
            ("4", false, None),
            ("0", false, None),
            ("0", true, Some(None)),
            ("x", true, None),
            ("-1", true, None),
            (" 2 ", false, Some(Some(1))),
        ] {
            assert_eq!(parse_select(answer, 3, 1, back), expected, "{answer:?}");
        }
        assert_eq!(
            parse_select("", 3, 3, false),
            None,
            "invalid default needs input"
        );
        assert_eq!(parse_select("", 3, BACK, true), Some(None), "Enter = back");
        assert_eq!(parse_select("", 3, BACK, false), None);
        assert_eq!(parse_select("2", 3, BACK, true), Some(Some(1)));
    }

    #[test]
    fn multi_select_answers() {
        for (answer, expected) in [
            ("", Some(vec![0, 2])),
            ("  ", Some(vec![0, 2])),
            ("2", Some(vec![1])),
            ("3 1", Some(vec![0, 2])),
            ("1,2,2", Some(vec![0, 1])),
            ("1，3、4", Some(vec![0, 2, 3])),
            ("5", None),
            ("0", None),
            ("1 x", None),
        ] {
            assert_eq!(
                parse_select_many(answer, 4, &[2, 0]),
                expected,
                "{answer:?}"
            );
        }
        assert_eq!(parse_select_many("", 2, &[0, 5]), Some(vec![0]));
    }

    #[test]
    fn out_of_range_multi_defaults_are_rejected_by_every_prompter() {
        let tty = TtyPrompter::from_streams(std::io::Cursor::new(b"\n".to_vec()), std::io::sink());
        let scripted = ScriptedPrompter::new([""]);
        let auto = AutoPrompter { assume_yes: true };
        let unattended = ScriptedPrompter::unattended();
        let prompters: [(&str, &dyn Prompter); 4] = [
            ("tty", &tty),
            ("scripted", &scripted),
            ("auto", &auto),
            ("scripted -y", &unattended),
        ];
        for (name, ui) in prompters {
            let err = ui.select_many("协议", &items(2), &[1, 5]).unwrap_err();
            assert_eq!(err.to_string(), BAD_DEFAULT, "{name}");
            assert_eq!(
                ui.select_many("协议", &items(2), &[1]).unwrap(),
                [1],
                "{name}: valid defaults still work"
            );
        }
        assert!(check_many_defaults(2, &[0, 1]).is_ok());
        assert!(check_many_defaults(0, &[]).is_ok());
    }

    #[test]
    fn danger_rule() {
        let unattended = ScriptedPrompter::unattended();
        assert!(confirm_danger(&unattended, "重装？", true, "需要 --force").unwrap());
        assert_eq!(
            confirm_danger(&unattended, "重装？", false, "需要 --force")
                .unwrap_err()
                .to_string(),
            "需要 --force"
        );
        let user = ScriptedPrompter::new(["y"]);
        assert!(confirm_danger(&user, "重装？", false, "x").unwrap());
        assert_eq!(user.prompts(), ["重装？"]);
        let user = ScriptedPrompter::new([""]);
        assert!(
            !confirm_danger(&user, "重装？", false, "x").unwrap(),
            "default is no"
        );
    }

    #[test]
    fn system_prompter_honors_assume_yes() {
        let ui = system_prompter(true);
        assert!(ui.assume_yes());
        assert!(!ui.interactive());
    }
}
