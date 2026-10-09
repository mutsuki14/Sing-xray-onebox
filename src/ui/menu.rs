//! Numbered menus whose `0` entry has its own label (`0) 退出` in the main
//! menu, `0) 返回` in submenus), built on [`Prompter::input_with`].
//!
//! [`Prompter::select`] always labels `0` "返回"; the main menu needs "退出"
//! and a heading block (header lines, current values) above the items. The
//! whole block is the prompt text, so a terminal shows it again after an
//! invalid answer, a scripted prompter records it, and `-y` takes the
//! default without showing anything.

use super::Prompter;
use crate::error::{Error, Result};
use crate::sys::text::{display_width, pad_right};

/// One menu entry: a label and an optional explanation shown in a second,
/// aligned column.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub label: String,
    pub hint: String,
}

impl Entry {
    pub fn new(label: impl Into<String>) -> Entry {
        Entry {
            label: label.into(),
            hint: String::new(),
        }
    }

    pub fn with_hint(label: impl Into<String>, hint: impl Into<String>) -> Entry {
        Entry {
            label: label.into(),
            hint: hint.into(),
        }
    }
}

/// The menu text: `heading` lines, then `N) label  hint` with right-aligned
/// numbers and an aligned hint column, then `0) {zero}`.
pub fn render(heading: &str, entries: &[Entry], zero: &str) -> String {
    let width = entries.len().max(1).to_string().len();
    let label_width = entries
        .iter()
        .filter(|e| !e.hint.is_empty())
        .map(|e| display_width(&e.label))
        .max()
        .unwrap_or(0);
    let mut lines: Vec<String> = Vec::with_capacity(entries.len() + 2);
    if !heading.is_empty() {
        lines.push(heading.to_string());
    }
    for (i, entry) in entries.iter().enumerate() {
        let number = format!("{:>width$})", i + 1);
        lines.push(if entry.hint.is_empty() {
            format!(" {number} {}", entry.label)
        } else {
            format!(
                " {number} {}  {}",
                pad_right(&entry.label, label_width),
                entry.hint
            )
        });
    }
    lines.push(format!(" {:>width$}) {zero}", 0));
    lines.join("\n")
}

/// Interpret an answer: `Some(None)` = 0, `Some(Some(i))` = entry `i`
/// (0-based), `None` = invalid.
pub fn parse(answer: &str, count: usize) -> Option<Option<usize>> {
    match answer.trim().parse::<usize>().ok()? {
        0 => Some(None),
        n if n <= count => Some(Some(n - 1)),
        _ => None,
    }
}

/// Show the menu and return the chosen entry (`None` for `0`). Enter picks
/// `0`. An invalid answer prints `请输入 0–N` and asks again; EOF cancels.
pub fn choose(
    ui: &dyn Prompter,
    heading: &str,
    entries: &[Entry],
    zero: &str,
) -> Result<Option<usize>> {
    let prompt = format!("{}\n请选择", render(heading, entries, zero));
    let count = entries.len();
    let check = |answer: &str| -> Result<String> {
        match parse(answer, count) {
            Some(_) => Ok(answer.trim().to_string()),
            None => Err(Error::msg(format!("请输入 0–{count}"))),
        }
    };
    let answer = ui.input_with(&prompt, "0", &check)?;
    Ok(parse(&answer, count).flatten())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::ScriptedPrompter;

    fn entries() -> Vec<Entry> {
        vec![
            Entry::with_hint("节点信息与分享", "查看节点、导出客户端配置"),
            Entry::new("远程订阅"),
            Entry::with_hint("服务", "状态、日志"),
        ]
    }

    #[test]
    fn renders_aligned_columns() {
        assert_eq!(
            render("标题", &entries(), "退出"),
            "标题\n 1) 节点信息与分享  查看节点、导出客户端配置\n 2) 远程订阅\n 3) 服务            状态、日志\n 0) 退出"
        );
        let many: Vec<Entry> = (1..=11).map(|i| Entry::new(format!("项{i}"))).collect();
        let text = render("", &many, "返回");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "  1) 项1");
        assert_eq!(lines[10], " 11) 项11");
        assert_eq!(lines[11], "  0) 返回");
    }

    #[test]
    fn answers() {
        for (answer, expected) in [
            ("0", Some(None)),
            ("1", Some(Some(0))),
            (" 3 ", Some(Some(2))),
            ("4", None),
            ("x", None),
            ("-1", None),
            ("", None),
        ] {
            assert_eq!(parse(answer, 3), expected, "{answer:?}");
        }
    }

    #[test]
    fn choose_re_asks_and_defaults_to_zero() {
        let ui = ScriptedPrompter::new(["9", "x", "2", ""]);
        assert_eq!(choose(&ui, "菜单", &entries(), "返回").unwrap(), Some(1));
        assert_eq!(ui.errors(), ["请输入 0–3", "请输入 0–3"]);
        assert!(ui.prompts()[0].starts_with("菜单\n 1) 节点信息与分享"));
        assert!(ui.prompts()[0].ends_with(" 0) 返回\n请选择"));
        assert_eq!(choose(&ui, "菜单", &entries(), "返回").unwrap(), None);
        assert!(choose(&ui, "菜单", &entries(), "返回")
            .unwrap_err()
            .is_cancelled());
    }

    #[test]
    fn unattended_takes_zero() {
        let ui = ScriptedPrompter::unattended();
        assert_eq!(choose(&ui, "", &entries(), "退出").unwrap(), None);
    }
}
