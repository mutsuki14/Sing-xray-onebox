//! Parser for the YAML subset `to_yaml` emits (tests only): block mappings
//! and sequences with two-space steps, collections starting on a dash line,
//! JSON-style double-quoted strings, plain keys, bare scalars, `[]`, `{}`.

use serde_json::{Map, Value};

struct Lines {
    lines: Vec<(usize, String)>,
    pos: usize,
}

/// Parse `text` back into a value; `Err` describes the first unexpected line.
pub(crate) fn parse(text: &str) -> Result<Value, String> {
    let lines: Vec<(usize, String)> = text
        .lines()
        .map(|l| {
            let trimmed = l.trim_start_matches(' ');
            (l.len() - trimmed.len(), trimmed.to_owned())
        })
        .collect();
    if lines.len() == 1 && !lines[0].1.starts_with("- ") && !is_entry(&lines[0].1) {
        return scalar(&lines[0].1);
    }
    let mut state = Lines { lines, pos: 0 };
    let value = block(&mut state, 0)?;
    match state.lines.get(state.pos) {
        None => Ok(value),
        Some(line) => Err(format!("trailing line {line:?}")),
    }
}

fn is_entry(text: &str) -> bool {
    split_key(text).is_ok()
}

fn block(s: &mut Lines, indent: usize) -> Result<Value, String> {
    match s.lines.get(s.pos) {
        Some((i, text)) if *i == indent && text.starts_with("- ") => sequence(s, indent),
        Some((i, _)) if *i == indent => mapping(s, indent),
        other => Err(format!("expected block at indent {indent}, got {other:?}")),
    }
}

fn sequence(s: &mut Lines, indent: usize) -> Result<Value, String> {
    let mut items = Vec::new();
    while let Some((i, text)) = s.lines.get(s.pos).cloned() {
        if i != indent || !text.starts_with("- ") {
            break;
        }
        let content = text[2..].to_owned();
        if content.starts_with("- ") || is_entry(&content) {
            // The nested collection starts on the dash line: re-read that
            // line as if it were indented past the dash.
            s.lines[s.pos] = (indent + 2, content);
            items.push(block(s, indent + 2)?);
        } else {
            items.push(scalar(&content)?);
            s.pos += 1;
        }
    }
    Ok(Value::Array(items))
}

fn mapping(s: &mut Lines, indent: usize) -> Result<Value, String> {
    let mut map = Map::new();
    while let Some((i, text)) = s.lines.get(s.pos).cloned() {
        if i != indent || text.starts_with("- ") {
            break;
        }
        let (key, rest) = split_key(&text)?;
        s.pos += 1;
        let value = if rest.is_empty() {
            let child = s.lines.get(s.pos).map(|l| l.0).unwrap_or(0);
            if child <= indent {
                return Err(format!("missing block for {key:?}"));
            }
            block(s, child)?
        } else {
            scalar(rest.strip_prefix(' ').ok_or("missing space after colon")?)?
        };
        if map.insert(key.clone(), value).is_some() {
            return Err(format!("duplicate key {key:?}"));
        }
    }
    Ok(Value::Object(map))
}

/// `key: rest` with a plain or double-quoted key.
fn split_key(text: &str) -> Result<(String, &str), String> {
    if text.starts_with('"') {
        let end = quoted_end(text).ok_or("unterminated key")?;
        let key: String = serde_json::from_str(&text[..end]).map_err(|e| e.to_string())?;
        let rest = text[end..].strip_prefix(':').ok_or("missing colon")?;
        return Ok((key, rest));
    }
    let colon = text.find(':').ok_or("no colon")?;
    let key = &text[..colon];
    if key.is_empty() || key.contains(' ') || key.starts_with('-') {
        return Err(format!("not a mapping entry: {text:?}"));
    }
    Ok((key.to_owned(), &text[colon + 1..]))
}

/// Byte index just past the closing quote of a leading quoted string.
fn quoted_end(text: &str) -> Option<usize> {
    let mut escaped = false;
    for (i, c) in text.char_indices().skip(1) {
        match c {
            _ if escaped => escaped = false,
            '\\' => escaped = true,
            '"' => return Some(i + 1),
            _ => {}
        }
    }
    None
}

fn scalar(text: &str) -> Result<Value, String> {
    match text {
        "null" => Ok(Value::Null),
        "true" => Ok(Value::Bool(true)),
        "false" => Ok(Value::Bool(false)),
        "[]" => Ok(Value::Array(Vec::new())),
        "{}" => Ok(Value::Object(Map::new())),
        _ if text.starts_with('"') => {
            if quoted_end(text) != Some(text.len()) {
                return Err(format!("text after string: {text:?}"));
            }
            serde_json::from_str(text).map_err(|e| e.to_string())
        }
        _ => text
            .parse::<serde_json::Number>()
            .map(Value::Number)
            .map_err(|_| format!("bare text is never emitted: {text:?}")),
    }
}
