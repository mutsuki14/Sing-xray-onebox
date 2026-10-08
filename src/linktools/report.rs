//! JSON reports of `bench` and `reality-check` (schema 1, keys sorted,
//! v2 `scope`/`note` strings) and the one place that maps a run's outcome
//! to the exit code (spec D §2.4, §2.6, §2.10).
//!
//! Changes from v2:
//! - the report is printed first and saved second, so a failing save
//!   never loses the measurements (D-8.1#7); a save failure is exit 1
//!   unless the run was cancelled or failed anyway (then it is printed
//!   and the run's own code wins);
//! - cancellation is checked before "no REALITY entries", so Ctrl+C
//!   before the first entry is 130, not 1 (D-8.1#17).

use super::bundle::{json_text, write_private};
use crate::error::{Error, Result, EXIT_CANCELLED, EXIT_WARNINGS};
use crate::ui::out;
use serde::Serialize;
use std::path::Path;

pub const SCHEMA: u32 = 1;
pub const BENCH_SCOPE: &str = "current-machine-to-proxy-to-origin";
pub const BENCH_NOTE: &str = "请求失败率不是网络丢包率；setup 包含代理路径与目标 TLS；吞吐包含建连开销；CPU/RSS 仅本机客户端内核。";
pub const REALITY_NOTE: &str =
    "普通 TLS 回落与错误 short ID 的代理拒绝分别测试；不证明不可识别或公网可达。";

/// A tool report. Serialized through `serde_json::Value`, so every object
/// (including the entries) has sorted keys, as v2.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Report<E> {
    pub cancelled: bool,
    pub entries: Vec<E>,
    pub note: &'static str,
    pub schema: u32,
    pub scope: String,
}

impl<E: Serialize> Report<E> {
    pub fn new(scope: &str, note: &'static str, entries: Vec<E>, cancelled: bool) -> Report<E> {
        Report {
            cancelled,
            entries,
            note,
            schema: SCHEMA,
            scope: scope.to_owned(),
        }
    }

    /// Pretty JSON + `"\n"`, the text printed and saved.
    pub fn text(&self) -> Result<String> {
        json_text(&serde_json::to_value(self)?)
    }
}

/// Print `text` on stdout, then save it to `output` (new 0600 file).
pub fn publish(text: &str, output: Option<&Path>) -> Result<()> {
    out::data(text.trim_end_matches('\n'))?;
    match output {
        Some(path) => write_private(path, text).map_err(|e| e.wrap("报告已打印，但保存失败")),
        None => Ok(()),
    }
}

/// Which tool's messages to use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tool {
    Bench,
    Reality,
}

impl Tool {
    fn cancelled(self) -> &'static str {
        match self {
            Tool::Bench => "测试已取消",
            Tool::Reality => "REALITY 检查已取消",
        }
    }

    fn failed(self) -> &'static str {
        match self {
            Tool::Bench => "部分入口测试失败，详见 JSON 报告",
            Tool::Reality => "REALITY 检查失败，详见 JSON 报告",
        }
    }
}

pub const REALITY_WARNINGS: &str = "REALITY 检查完成，请核对报告中的警告。";

/// What a run found.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    pub cancelled: bool,
    pub failed: bool,
    pub warned: bool,
}

/// The exit of a run: 130 cancelled, 1 failed (or report not saved),
/// 2 warnings only (`reality-check`), else success.
pub fn conclude(tool: Tool, outcome: Outcome, published: Result<()>) -> Result<()> {
    if let Err(e) = published {
        if !(outcome.cancelled || outcome.failed) {
            return Err(e);
        }
        out::error(e);
    }
    if outcome.cancelled {
        return Err(Error::exit(EXIT_CANCELLED, tool.cancelled()));
    }
    if outcome.failed {
        return Err(Error::msg(tool.failed()));
    }
    if outcome.warned && tool == Tool::Reality {
        return Err(Error::exit(EXIT_WARNINGS, REALITY_WARNINGS));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::fs::TempDir;
    use serde_json::json;

    #[derive(Serialize)]
    struct Row {
        id: &'static str,
        b: u8,
        a: u8,
    }

    #[test]
    fn reports_serialize_sorted_with_a_trailing_newline() {
        let report = Report::new(
            BENCH_SCOPE,
            BENCH_NOTE,
            vec![Row {
                id: "x",
                b: 2,
                a: 1,
            }],
            false,
        );
        let text = report.text().unwrap();
        assert!(text.ends_with("}\n") && !text.ends_with("\n\n"));
        let keys: Vec<&str> = text
            .lines()
            .filter(|l| l.starts_with("  \"") || l.starts_with("      \""))
            .map(|l| l.trim().split('"').nth(1).unwrap())
            .collect();
        assert_eq!(
            keys,
            [
                "cancelled",
                "entries",
                "a",
                "b",
                "id",
                "note",
                "schema",
                "scope"
            ]
        );
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            value,
            json!({"cancelled": false, "entries": [{"a": 1, "b": 2, "id": "x"}],
                "note": BENCH_NOTE, "schema": 1, "scope": "current-machine-to-proxy-to-origin"})
        );
    }

    #[test]
    fn publishing_prints_before_saving() {
        let dir = TempDir::new("linktools-test").unwrap();
        let path = dir.join("r.json");
        publish("{}\n", Some(&path)).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{}\n");
        let err = publish("{}\n", Some(&path)).unwrap_err();
        assert!(
            err.to_string()
                .starts_with("报告已打印，但保存失败: 目标已存在"),
            "{err}"
        );
        publish("{}\n", None).unwrap();
    }

    fn code(result: Result<()>) -> (i32, String) {
        match result {
            Ok(()) => (0, String::new()),
            Err(e) => (e.exit_code(), e.to_string()),
        }
    }

    #[test]
    fn outcomes_map_to_v2_exit_codes() {
        let o = |cancelled, failed, warned| Outcome {
            cancelled,
            failed,
            warned,
        };
        let cases = [
            (Tool::Bench, o(false, false, false), 0, ""),
            (
                Tool::Bench,
                o(false, true, false),
                1,
                "部分入口测试失败，详见 JSON 报告",
            ),
            (Tool::Bench, o(true, true, false), 130, "测试已取消"),
            (Tool::Bench, o(false, false, true), 0, ""),
            (Tool::Reality, o(false, false, true), 2, REALITY_WARNINGS),
            (
                Tool::Reality,
                o(false, true, true),
                1,
                "REALITY 检查失败，详见 JSON 报告",
            ),
            (
                Tool::Reality,
                o(true, false, true),
                130,
                "REALITY 检查已取消",
            ),
        ];
        for (tool, outcome, exit, message) in cases {
            assert_eq!(
                code(conclude(tool, outcome, Ok(()))),
                (exit, message.to_string()),
                "{tool:?} {outcome:?}"
            );
        }
    }

    #[test]
    fn save_failures_fail_a_clean_run_only() {
        let saved = || Err(Error::msg("报告已打印，但保存失败: x"));
        let clean = Outcome::default();
        assert_eq!(
            code(conclude(Tool::Bench, clean, saved())),
            (1, "报告已打印，但保存失败: x".into())
        );
        let warned = Outcome {
            warned: true,
            ..clean
        };
        assert_eq!(code(conclude(Tool::Reality, warned, saved())).0, 1);
        let cancelled = Outcome {
            cancelled: true,
            ..clean
        };
        assert_eq!(code(conclude(Tool::Bench, cancelled, saved())).0, 130);
        let failed = Outcome {
            failed: true,
            ..clean
        };
        assert_eq!(
            code(conclude(Tool::Reality, failed, saved())),
            (1, "REALITY 检查失败，详见 JSON 报告".into())
        );
    }
}
