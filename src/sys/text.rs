//! Text helpers: validation, quoting, sanitizing and terminal column widths.
//!
//! Changes from v2: quoting helpers live in one place (v2 had three copies);
//! `valid_domain` rejects IP literals; `display_width` lets tables align
//! Chinese text instead of padding by bytes.

use crate::error::{Error, Result};

/// DNS name check: ≤ 253 chars, at least two labels, labels 1–63 chars of
/// `[a-z0-9-]` not starting/ending with `-`, alphabetic TLD. Unlike v2, IP
/// literals (all-numeric TLD) are rejected. Callers lower-case first.
pub fn valid_domain(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 || s.ends_with('.') || !s.contains('.') {
        return false;
    }
    let labels: Vec<&str> = s.split('.').collect();
    let tld_alpha = labels
        .last()
        .is_some_and(|t| t.bytes().any(|b| b.is_ascii_lowercase()));
    labels.iter().all(|l| valid_label(l)) && tld_alpha
}

/// One DNS label: 1–63 chars of `[a-z0-9-]`, not starting or ending with `-`.
pub fn valid_label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && !s.starts_with('-')
        && !s.ends_with('-')
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// POSIX shell single-quoting: `it's` → `'it'\''s'`. Safe for any input
/// (the shell never interprets anything inside single quotes).
pub fn quote_shell(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Reject characters that would let a value start a new unit directive.
fn reject_unit_breaks(s: &str) -> Result<()> {
    if s.contains(['\0', '\n', '\r']) {
        return Err(Error::msg("服务参数包含控制字符"));
    }
    Ok(())
}

/// One systemd `ExecStart=` word: double-quoted with `\` `"` escaped and the
/// systemd specifiers `%` and `$` doubled so they are taken literally.
pub fn quote_unit(s: &str) -> Result<String> {
    reject_unit_breaks(s)?;
    Ok(format!(
        "\"{}\"",
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
            .replace('$', "$$")
    ))
}

/// The quoted operand of an `Environment=` line: `"KEY=VALUE"`. Environment=
/// expands `%` specifiers but not `$`, so only `\` `"` `%` are escaped.
pub fn quote_unit_env(key: &str, value: &str) -> Result<String> {
    let key_ok = !key.is_empty()
        && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && !key.as_bytes()[0].is_ascii_digit();
    if !key_ok {
        return Err(Error::msg(format!("环境变量名无效: {key}")));
    }
    reject_unit_breaks(value)?;
    Ok(format!(
        "\"{key}={}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
    ))
}

/// Percent-encode everything except the RFC 3986 unreserved set
/// (`A-Z a-z 0-9 - _ . ~`), byte-wise over UTF-8, uppercase hex.
pub fn url_encode(s: &str) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(b as char);
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// Clean a line typed at a prompt (v2 `ui::sanitize`, kept exactly):
/// `ESC [`/`ESC O` sequences are dropped up to and including their final
/// ASCII letter or `~` (arrow keys, colors); any other ESC is dropped alone;
/// other control characters are dropped; the result is trimmed.
pub fn sanitize_input(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if matches!(chars.peek(), Some('[') | Some('O')) {
                chars.next();
                for x in chars.by_ref() {
                    if x.is_ascii_alphabetic() || x == '~' {
                        break;
                    }
                }
            }
        } else if !c.is_control() {
            out.push(c);
        }
    }
    out.trim().to_string()
}

/// A command-line value that must be plain text (no control characters).
pub fn plain(s: &str) -> Result<String> {
    if s.chars().any(char::is_control) {
        return Err(Error::msg("参数不能包含控制字符"));
    }
    Ok(s.to_owned())
}

/// Escape `%` for a crontab command field (cron turns a bare `%` into a newline).
pub fn cron_escape(s: &str) -> String {
    s.replace('%', "\\%")
}

/// Terminal columns needed to print `s`: East Asian wide and fullwidth
/// characters take two columns, combining marks and control characters
/// none. ANSI CSI sequences (`ESC [ … letter`) are skipped so colored text
/// aligns like plain text.
pub fn display_width(s: &str) -> usize {
    let mut width = 0;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' && chars.peek() == Some(&'[') {
            chars.next();
            for x in chars.by_ref() {
                if x.is_ascii_alphabetic() {
                    break;
                }
            }
            continue;
        }
        width += char_width(c);
    }
    width
}

fn char_width(c: char) -> usize {
    let cp = c as u32;
    if c.is_control() || is_zero_width(cp) {
        0
    } else if is_wide(cp) {
        2
    } else {
        1
    }
}

fn is_zero_width(cp: u32) -> bool {
    matches!(cp,
        0x0300..=0x036F   // combining diacritics
        | 0x200B..=0x200F // zero-width space/joiners, direction marks
        | 0xFE00..=0xFE0F // variation selectors
    )
}

/// East Asian Wide (W) and Fullwidth (F) blocks that matter for our output:
/// CJK, Hangul, kana, fullwidth forms, CJK punctuation and common emoji.
fn is_wide(cp: u32) -> bool {
    matches!(cp,
        0x1100..=0x115F
        | 0x2E80..=0x303E
        | 0x3041..=0x33FF
        | 0x3400..=0x4DBF
        | 0x4E00..=0x9FFF
        | 0xA000..=0xA4CF
        | 0xAC00..=0xD7A3
        | 0xF900..=0xFAFF
        | 0xFE30..=0xFE4F
        | 0xFF00..=0xFF60
        | 0xFFE0..=0xFFE6
        | 0x1F300..=0x1F64F
        | 0x1F900..=0x1F9FF
        | 0x20000..=0x3FFFD
    )
}

/// Pad `s` with spaces on the right to `width` display columns.
pub fn pad_right(s: &str, width: usize) -> String {
    let have = display_width(s);
    let mut out = String::with_capacity(s.len() + width.saturating_sub(have));
    out.push_str(s);
    out.extend(std::iter::repeat_n(' ', width.saturating_sub(have)));
    out
}

/// Pad `s` with spaces on the left to `width` display columns.
pub fn pad_left(s: &str, width: usize) -> String {
    let have = display_width(s);
    let mut out: String = std::iter::repeat_n(' ', width.saturating_sub(have)).collect();
    out.push_str(s);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains() {
        assert!(valid_domain("www.example.com"));
        assert!(valid_domain("xn--fiqs8s.cn"));
        assert!(!valid_domain("1.2.3.4"));
        assert!(!valid_domain("example"));
        assert!(!valid_domain("example.com."));
        assert!(!valid_domain("-a.example.com"));
        assert!(!valid_domain("Example.com"));
    }

    #[test]
    fn labels() {
        for (label, ok) in [
            ("a", true),
            ("a-b", true),
            ("0day", true),
            ("", false),
            ("-a", false),
            ("a-", false),
            ("A", false),
            ("a_b", false),
            (&"a".repeat(63), true),
            (&"a".repeat(64), false),
        ] {
            assert_eq!(valid_label(label), ok, "{label}");
        }
    }

    #[test]
    fn shell_quoting() {
        for (input, quoted) in [
            ("", "''"),
            ("plain", "'plain'"),
            ("it's", "'it'\\''s'"),
            ("$(rm -rf /) `x` \"y\"", "'$(rm -rf /) `x` \"y\"'"),
            ("中文 空格", "'中文 空格'"),
        ] {
            assert_eq!(quote_shell(input), quoted);
        }
    }

    #[test]
    fn shell_quoting_round_trips_through_sh() {
        let tricky = "a'b\"c$HOME`id`\\n %s 中";
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("printf %s {}", quote_shell(tricky)))
            .output()
            .unwrap();
        assert_eq!(String::from_utf8(out.stdout).unwrap(), tricky);
    }

    #[test]
    fn unit_quoting() {
        assert_eq!(quote_unit("/usr/bin/x").unwrap(), "\"/usr/bin/x\"");
        assert_eq!(quote_unit(r#"a\b"c%d$e"#).unwrap(), r#""a\\b\"c%%d$$e""#);
        assert_eq!(quote_unit("daemon off;").unwrap(), "\"daemon off;\"");
        for bad in ["a\nb", "a\rb", "a\0b"] {
            assert_eq!(
                quote_unit(bad).unwrap_err().to_string(),
                "服务参数包含控制字符"
            );
        }
    }

    #[test]
    fn unit_env_quoting() {
        assert_eq!(
            quote_unit_env("ONEBOX_DIR", "/etc/onebox").unwrap(),
            "\"ONEBOX_DIR=/etc/onebox\""
        );
        assert_eq!(
            quote_unit_env("K", r#"a\b"c%d$e"#).unwrap(),
            r#""K=a\\b\"c%%d$e""#
        );
        assert!(quote_unit_env("K", "a\nb").is_err());
        assert!(quote_unit_env("", "x").is_err());
        assert!(quote_unit_env("A=B", "x").is_err());
        assert!(quote_unit_env("1A", "x").is_err());
    }

    #[test]
    fn url_encoding() {
        for (input, encoded) in [
            ("abc-_.~XYZ019", "abc-_.~XYZ019"),
            ("a b", "a%20b"),
            ("a/b?c=d&e", "a%2Fb%3Fc%3Dd%26e"),
            ("节点", "%E8%8A%82%E7%82%B9"),
            ("+#%", "%2B%23%25"),
        ] {
            assert_eq!(url_encode(input), encoded);
        }
    }

    #[test]
    fn sanitizing() {
        for (input, clean) in [
            (" name\x1b[A\x1b[31m\r\t", "name"),
            ("中文", "中文"),
            ("a\x1bOPb", "ab"),
            ("a\x1b[1;5~b", "ab"),
            ("a\x1bxb", "axb"),
            ("\x1b", ""),
            ("a\x07b\u{7f}c", "abc"),
            ("  spaced  out  ", "spaced  out"),
            ("x\x1b[", "x"),
        ] {
            assert_eq!(sanitize_input(input), clean, "{input:?}");
        }
    }

    #[test]
    fn plain_values() {
        assert_eq!(plain("节点 1").unwrap(), "节点 1");
        assert_eq!(
            plain("a\tb").unwrap_err().to_string(),
            "参数不能包含控制字符"
        );
        assert!(plain("a\u{1b}[31m").is_err());
    }

    #[test]
    fn cron_escaping() {
        assert_eq!(cron_escape("date +%s%%"), "date +\\%s\\%\\%");
        assert_eq!(cron_escape("plain"), "plain");
    }

    #[test]
    fn widths() {
        for (input, width) in [
            ("", 0),
            ("abc", 3),
            ("节点", 4),
            ("a节b", 4),
            ("ｆｕｌｌ", 8),
            ("e\u{301}", 1),
            ("\x1b[32m完成\x1b[0m", 4),
            ("한국", 4),
            ("，。", 4),
        ] {
            assert_eq!(display_width(input), width, "{input:?}");
        }
    }

    #[test]
    fn padding() {
        assert_eq!(pad_right("节点", 6), "节点  ");
        assert_eq!(pad_right("abc", 2), "abc");
        assert_eq!(pad_left("7", 3), "  7");
        assert_eq!(pad_left("节", 3), " 节");
    }
}
