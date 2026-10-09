//! `onebox doctor` output: one line per check, a summary, v2's closing
//! hint, and the exit status.
//!
//! Lines go to stdout (they are the command's result), colored only when
//! stdout is a terminal and `NO_COLOR` is unset. A multi-line detail (a
//! core's own error output) continues on indented lines.

use super::{Check, CheckFn, CheckStatus, Doctor};
use crate::error::{Error, Result};
use crate::ui::out::{self, color_allowed, paint, Style};
use std::io::IsTerminal;

/// Printed after the checks (v2 wording).
pub const DOCTOR_HINT: &str =
    "公网 DNS、防火墙和客户端真实连通性请配合 onebox reality-check / bench 检查。";
/// Continuation lines start under the check name (`[通过] ` is 7 columns).
const INDENT: &str = "       ";

/// How many checks ended in each status.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tally {
    pub pass: usize,
    pub warn: usize,
    pub fail: usize,
}

impl Tally {
    pub fn of(checks: &[Check]) -> Tally {
        let mut tally = Tally::default();
        for check in checks {
            match check.status {
                CheckStatus::Pass => tally.pass += 1,
                CheckStatus::Warn => tally.warn += 1,
                CheckStatus::Fail => tally.fail += 1,
            }
        }
        tally
    }

    /// `Err("体检发现 {n} 个需要处理的问题")` iff a check failed (v2
    /// wording; warnings do not count).
    pub fn verdict(&self) -> Result<()> {
        if self.fail == 0 {
            Ok(())
        } else {
            Err(Error::Msg(format!(
                "体检发现 {} 个需要处理的问题",
                self.fail
            )))
        }
    }
}

fn style(status: CheckStatus) -> Style {
    match status {
        CheckStatus::Pass => Style::Green,
        CheckStatus::Warn => Style::Yellow,
        CheckStatus::Fail => Style::Red,
    }
}

/// `[通过] {name}: {detail}`; further detail lines are indented.
pub fn format_check(check: &Check, color: bool) -> String {
    let tag = paint(check.status.tag(), style(check.status), color);
    let mut lines = check.detail.lines().map(str::trim_end);
    let head = match lines.next().filter(|l| !l.trim().is_empty()) {
        Some(first) => format!("{tag} {}: {first}", check.name),
        None => format!("{tag} {}", check.name),
    };
    std::iter::once(head)
        .chain(
            lines
                .filter(|l| !l.trim().is_empty())
                .map(|l| format!("{INDENT}{}", l.trim_start())),
        )
        .collect::<Vec<_>>()
        .join("\n")
}

/// `体检完成：通过 5 项，警告 1 项，失败 0 项`.
pub fn summary_line(tally: &Tally) -> String {
    format!(
        "体检完成：通过 {} 项，警告 {} 项，失败 {} 项",
        tally.pass, tally.warn, tally.fail
    )
}

fn stdout_color() -> bool {
    color_allowed(
        std::io::stdout().is_terminal(),
        std::env::var_os("NO_COLOR").as_deref(),
    )
}

/// Diagnose, printing each check as it completes, then the summary and
/// the hint; the verdict decides the exit status.
pub(super) fn run_doctor(doctor: &Doctor, extra: &[CheckFn]) -> Result<()> {
    let color = stdout_color();
    let mut printed: Result<()> = Ok(());
    let mut print = |check: &Check| {
        if printed.is_ok() {
            printed = out::data(&format_check(check, color));
        }
    };
    let diagnosis = doctor.diagnose(extra, &mut print)?;
    printed?;
    let tally = diagnosis.tally();
    out::data(&summary_line(&tally))?;
    out::data(DOCTOR_HINT)?;
    tally.verdict()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_by_status_with_and_without_detail() {
        let cases = [
            (
                Check::pass("节点配置", "1 个协议：tuic"),
                "[通过] 节点配置: 1 个协议：tuic",
            ),
            (
                Check::warn("代理证书", "将在 3 天内到期"),
                "[警告] 代理证书: 将在 3 天内到期",
            ),
            (
                Check::fail("服务 onebox-xray", "未运行"),
                "[失败] 服务 onebox-xray: 未运行",
            ),
            (Check::pass("FRP 服务端", ""), "[通过] FRP 服务端"),
            (Check::pass("x", "  \n"), "[通过] x"),
        ];
        for (check, want) in cases {
            assert_eq!(format_check(&check, false), want);
        }
    }

    #[test]
    fn multi_line_details_are_indented_and_blank_lines_dropped() {
        let check = Check::fail(
            "sing-box 配置",
            "sing-box 配置校验失败: decode\n\n  line 2  \nline 3",
        );
        assert_eq!(
            format_check(&check, false),
            "[失败] sing-box 配置: sing-box 配置校验失败: decode\n       line 2\n       line 3"
        );
    }

    #[test]
    fn tags_are_colored_by_status() {
        assert_eq!(
            format_check(&Check::pass("a", "b"), true),
            "\x1b[32m[通过]\x1b[0m a: b"
        );
        assert_eq!(
            format_check(&Check::warn("a", "b"), true),
            "\x1b[33m[警告]\x1b[0m a: b"
        );
        assert_eq!(
            format_check(&Check::fail("a", "b"), true),
            "\x1b[31m[失败]\x1b[0m a: b"
        );
    }

    #[test]
    fn tally_summary_and_verdict() {
        let checks = [
            Check::pass("a", ""),
            Check::pass("b", ""),
            Check::warn("c", ""),
            Check::fail("d", ""),
            Check::fail("e", ""),
        ];
        let tally = Tally::of(&checks);
        assert_eq!(
            tally,
            Tally {
                pass: 2,
                warn: 1,
                fail: 2
            }
        );
        assert_eq!(
            summary_line(&tally),
            "体检完成：通过 2 项，警告 1 项，失败 2 项"
        );
        assert_eq!(
            tally.verdict().unwrap_err().to_string(),
            "体检发现 2 个需要处理的问题"
        );
        let warnings_only = Tally::of(&checks[..3]);
        assert!(warnings_only.verdict().is_ok(), "warnings do not fail");
        assert!(Tally::of(&[]).verdict().is_ok());
    }
}
