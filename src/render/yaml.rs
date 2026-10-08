//! A small block-style YAML emitter for the mihomo documents.
//!
//! Output rules (always valid YAML 1.1 and 1.2, whatever the data):
//! - mappings and sequences in block style, two-space indentation; a
//!   mapping or sequence inside a sequence starts on the dash line;
//! - every string *value* is a double-quoted scalar with escapes, so no
//!   value can ever be read as a number, boolean, null, anchor or comment;
//! - keys are plain when they consist of `[A-Za-z0-9_.-]`, start with a
//!   letter or `_`, and are not a YAML 1.1 keyword (`yes`, `off`, …);
//!   otherwise quoted the same way;
//! - numbers and booleans are bare, null is `null`, empty collections are
//!   `[]` / `{}`.
//!
//! Escaping: `"` `\` and the YAML-meaningful control and line-separator
//! characters (C0, DEL, C1, U+2028/U+2029, U+FEFF, U+FFFE/U+FFFF) are
//! escaped; all other characters are written as UTF-8.

use serde_json::{Map, Value};
use std::fmt::Write;

/// Indentation step.
const INDENT: usize = 2;

/// Render `value` as a YAML document ending in exactly one newline.
pub fn to_yaml(value: &Value) -> String {
    let mut out = String::new();
    match value {
        Value::Object(map) if !map.is_empty() => mapping(&mut out, map, 0),
        Value::Array(items) if !items.is_empty() => sequence(&mut out, items, 0),
        scalar => {
            out.push_str(&inline(scalar));
            out.push('\n');
        }
    }
    out
}

/// Scalar or empty collection on one line.
fn inline(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => quote(s),
        Value::Array(_) => "[]".to_owned(),
        Value::Object(_) => "{}".to_owned(),
    }
}

fn is_block(value: &Value) -> bool {
    match value {
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
        _ => false,
    }
}

fn pad(out: &mut String, indent: usize) {
    out.extend(std::iter::repeat_n(' ', indent));
}

/// Mapping whose first key is written at the current position (the caller
/// already indented it, or placed a `- ` before it).
fn mapping_inline(out: &mut String, map: &Map<String, Value>, indent: usize) {
    for (i, (key, value)) in map.iter().enumerate() {
        if i > 0 {
            pad(out, indent);
        }
        out.push_str(&key_text(key));
        out.push(':');
        if is_block(value) {
            out.push('\n');
            block(out, value, indent + INDENT);
        } else {
            out.push(' ');
            out.push_str(&inline(value));
            out.push('\n');
        }
    }
}

fn mapping(out: &mut String, map: &Map<String, Value>, indent: usize) {
    pad(out, indent);
    mapping_inline(out, map, indent);
}

fn sequence(out: &mut String, items: &[Value], indent: usize) {
    for item in items {
        pad(out, indent);
        sequence_item(out, item, indent);
    }
}

/// `- item`; nested collections continue on the dash line, their later
/// lines indented past the dash.
fn sequence_item(out: &mut String, item: &Value, indent: usize) {
    out.push_str("- ");
    let inner = indent + INDENT;
    match item {
        Value::Object(map) if !map.is_empty() => mapping_inline(out, map, inner),
        Value::Array(items) if !items.is_empty() => {
            for (i, nested) in items.iter().enumerate() {
                if i > 0 {
                    pad(out, inner);
                }
                sequence_item(out, nested, inner);
            }
        }
        scalar => {
            out.push_str(&inline(scalar));
            out.push('\n');
        }
    }
}

fn block(out: &mut String, value: &Value, indent: usize) {
    match value {
        Value::Object(map) => mapping(out, map, indent),
        Value::Array(items) => sequence(out, items, indent),
        scalar => {
            pad(out, indent);
            out.push_str(&inline(scalar));
            out.push('\n');
        }
    }
}

/// YAML 1.1 words that plain scalars would turn into booleans or null.
const KEYWORDS: [&str; 12] = [
    "y", "n", "yes", "no", "on", "off", "true", "false", "null", "~", "<<", "=",
];

fn plain_key(key: &str) -> bool {
    let first_ok = key
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
    first_ok
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
        && !KEYWORDS.contains(&key.to_ascii_lowercase().as_str())
}

fn key_text(key: &str) -> String {
    if plain_key(key) {
        key.to_owned()
    } else {
        quote(key)
    }
}

/// Characters that must not appear raw inside a double-quoted scalar:
/// outside YAML's printable set, or line breaks in YAML 1.1.
fn needs_escape(c: char) -> bool {
    matches!(c,
        '\0'..='\u{1f}' | '\u{7f}'..='\u{9f}' | '\u{2028}' | '\u{2029}' | '\u{feff}'
        | '\u{fffe}' | '\u{ffff}')
}

/// Double-quoted scalar with JSON-compatible escapes.
pub fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if needs_escape(c) => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Test-only reader for exactly the subset [`to_yaml`] emits, used to prove
/// the emitted text round-trips to the same value.
#[cfg(test)]
pub(crate) mod reader;

#[cfg(test)]
mod tests;
