//! Output conventions. Notices, progress, headings and tables go to stderr
//! (`[完成]`/`[提示]`/`[警告]`/`[错误]` prefixes); command results go to
//! stdout through [`data`]. ANSI colors only when stderr is a terminal and
//! `NO_COLOR` is unset or empty.
//!
//! The `format_*` functions are pure (tested); the printing wrappers are thin.
//! Diagnostics on stderr are best effort: a closed stderr never aborts the
//! operation (v2's `eprintln!` would panic).

use crate::error::Result;
use crate::sys::text::{display_width, pad_right};
use std::fmt::Display;
use std::io::{self, IsTerminal, Write};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Style {
    Green,
    Cyan,
    Yellow,
    Red,
    Bold,
}

impl Style {
    fn code(self) -> &'static str {
        match self {
            Style::Green => "32",
            Style::Cyan => "36",
            Style::Yellow => "33",
            Style::Red => "31",
            Style::Bold => "1",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Ok,
    Info,
    Warn,
    Error,
}

impl Level {
    pub fn tag(self) -> &'static str {
        match self {
            Level::Ok => "[完成]",
            Level::Info => "[提示]",
            Level::Warn => "[警告]",
            Level::Error => "[错误]",
        }
    }

    fn style(self) -> Style {
        match self {
            Level::Ok => Style::Green,
            Level::Info => Style::Cyan,
            Level::Warn => Style::Yellow,
            Level::Error => Style::Red,
        }
    }
}

/// Wrap `text` in an SGR sequence when `color` is on.
pub fn paint(text: &str, style: Style, color: bool) -> String {
    if color {
        format!("\x1b[{}m{text}\x1b[0m", style.code())
    } else {
        text.to_string()
    }
}

/// Color policy: terminal and no non-empty `NO_COLOR` (no-color.org).
pub fn color_allowed(is_terminal: bool, no_color: Option<&std::ffi::OsStr>) -> bool {
    is_terminal && no_color.is_none_or(|v| v.is_empty())
}

/// Whether stdout output (command results such as QR codes) may be colored.
pub fn data_color_enabled() -> bool {
    color_allowed(
        io::stdout().is_terminal(),
        std::env::var_os("NO_COLOR").as_deref(),
    )
}

/// Whether stderr output should be colored.
pub fn color_enabled() -> bool {
    color_allowed(
        io::stderr().is_terminal(),
        std::env::var_os("NO_COLOR").as_deref(),
    )
}

/// `[完成] message` (tag colored).
pub fn format_status(level: Level, message: &str, color: bool) -> String {
    format!("{} {message}", paint(level.tag(), level.style(), color))
}

/// `[3/14] 准备证书…`
pub fn format_step(index: usize, total: usize, label: &str, color: bool) -> String {
    format!(
        "{} {label}…",
        paint(&format!("[{index}/{total}]"), Style::Bold, color)
    )
}

/// Title with a rule of matching display width underneath.
pub fn format_heading(title: &str, color: bool) -> String {
    format!(
        "{}\n{}",
        paint(title, Style::Bold, color),
        "-".repeat(display_width(title))
    )
}

/// Two-column key/value block, keys padded to the widest key.
pub fn format_kv<K: AsRef<str>, V: AsRef<str>>(rows: &[(K, V)]) -> String {
    let width = rows
        .iter()
        .map(|(k, _)| display_width(k.as_ref()))
        .max()
        .unwrap_or(0);
    rows.iter()
        .map(|(k, v)| format!("  {}  {}", pad_right(k.as_ref(), width), v.as_ref()))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Column table: header, dashed rule, rows; columns separated by two
/// spaces and aligned by display width; the last column is not padded.
/// Rows shorter than the header are padded with empty cells.
pub fn format_table<R, S>(headers: &[&str], rows: &[R]) -> String
where
    R: AsRef<[S]>,
    S: AsRef<str>,
{
    let columns = headers.len();
    let cell = |row: &R, i: usize| -> String {
        row.as_ref()
            .get(i)
            .map(|s| s.as_ref().to_string())
            .unwrap_or_default()
    };
    let widths: Vec<usize> = (0..columns)
        .map(|i| {
            rows.iter()
                .map(|r| display_width(&cell(r, i)))
                .chain(std::iter::once(display_width(headers[i])))
                .max()
                .unwrap_or(0)
        })
        .collect();
    let line = |cells: Vec<String>| -> String {
        let last = cells.len().saturating_sub(1);
        cells
            .iter()
            .enumerate()
            .map(|(i, c)| {
                if i == last {
                    c.clone()
                } else {
                    pad_right(c, widths[i])
                }
            })
            .collect::<Vec<_>>()
            .join("  ")
    };
    let mut lines = vec![
        line(headers.iter().map(|h| h.to_string()).collect()),
        line(widths.iter().map(|w| "-".repeat(*w)).collect()),
    ];
    lines.extend(
        rows.iter()
            .map(|r| line((0..columns).map(|i| cell(r, i)).collect())),
    );
    lines.join("\n")
}

fn emit(text: &str) {
    let mut err = io::stderr().lock();
    let _ = writeln!(err, "{text}");
    let _ = err.flush();
}

pub fn status(level: Level, message: impl Display) {
    emit(&format_status(level, &message.to_string(), color_enabled()));
}

pub fn ok(message: impl Display) {
    status(Level::Ok, message);
}

pub fn info(message: impl Display) {
    status(Level::Info, message);
}

pub fn warn(message: impl Display) {
    status(Level::Warn, message);
}

pub fn error(message: impl Display) {
    status(Level::Error, message);
}

pub fn step(index: usize, total: usize, label: &str) {
    emit(&format_step(index, total, label, color_enabled()));
}

pub fn heading(title: &str) {
    emit(&format_heading(title, color_enabled()));
}

pub fn kv<K: AsRef<str>, V: AsRef<str>>(rows: &[(K, V)]) {
    emit(&format_kv(rows));
}

pub fn table<R: AsRef<[S]>, S: AsRef<str>>(headers: &[&str], rows: &[R]) {
    emit(&format_table(headers, rows));
}

/// A plain line on stderr (explanations, blank separators).
pub fn line(text: impl Display) {
    emit(&text.to_string());
}

/// Command output on stdout, followed by a newline. A consumer that went
/// away (`onebox client links | head -1`) is not an error.
pub fn data(text: &str) -> Result<()> {
    let mut out = io::stdout().lock();
    let result = writeln!(out, "{text}").and_then(|()| out.flush());
    match result {
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        other => Ok(other?),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn status_lines() {
        assert_eq!(
            format_status(Level::Ok, "安装完成", false),
            "[完成] 安装完成"
        );
        assert_eq!(format_status(Level::Info, "x", false), "[提示] x");
        assert_eq!(format_status(Level::Warn, "x", false), "[警告] x");
        assert_eq!(format_status(Level::Error, "x", false), "[错误] x");
        assert_eq!(
            format_status(Level::Ok, "好", true),
            "\x1b[32m[完成]\x1b[0m 好"
        );
        assert_eq!(
            format_status(Level::Error, "坏", true),
            "\x1b[31m[错误]\x1b[0m 坏"
        );
    }

    #[test]
    fn steps_and_headings() {
        assert_eq!(format_step(3, 14, "准备证书", false), "[3/14] 准备证书…");
        assert_eq!(format_step(1, 2, "a", true), "\x1b[1m[1/2]\x1b[0m a…");
        assert_eq!(format_heading("节点信息", false), "节点信息\n--------");
        assert_eq!(format_heading("FRP", false), "FRP\n---");
    }

    #[test]
    fn color_policy() {
        assert!(color_allowed(true, None));
        assert!(color_allowed(true, Some(OsStr::new(""))));
        assert!(!color_allowed(true, Some(OsStr::new("1"))));
        assert!(!color_allowed(false, None));
        assert_eq!(paint("x", Style::Cyan, false), "x");
        assert_eq!(paint("x", Style::Yellow, true), "\x1b[33mx\x1b[0m");
    }

    #[test]
    fn key_values_align_by_display_width() {
        let rows = [
            ("地址", "203.0.113.10"),
            ("node", "onebox"),
            ("协议数量", "3"),
        ];
        assert_eq!(
            format_kv(&rows),
            "  地址      203.0.113.10\n  node      onebox\n  协议数量  3"
        );
        assert_eq!(format_kv::<&str, &str>(&[]), "");
    }

    #[test]
    fn tables_align_cjk_and_skip_trailing_padding() {
        let rows = vec![
            vec!["vless-reality".to_string(), "sing-box".into(), "443".into()],
            vec!["hysteria2".to_string(), "Xray".into(), "8443".into()],
        ];
        assert_eq!(
            format_table(&["协议", "内核", "端口"], &rows),
            "协议           内核      端口\n\
             -------------  --------  ----\n\
             vless-reality  sing-box  443\n\
             hysteria2      Xray      8443"
        );
        let short: Vec<Vec<&str>> = vec![vec!["只有一列"]];
        assert_eq!(
            format_table(&["名称", "值"], &short),
            "名称      值\n--------  --\n只有一列  "
        );
    }
}
