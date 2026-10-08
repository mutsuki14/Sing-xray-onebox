//! Small helpers for building `serde_json::Value` documents without
//! `IndexMut` (which panics on non-objects) and for the output encodings
//! v2 used.
//!
//! Object keys always serialize sorted (serde_json without
//! `preserve_order`), which is what makes outputs byte-identical to v2.

use crate::error::Result;
use serde_json::Value;

pub(crate) trait ObjectExt {
    /// Insert or replace `key` when `self` is an object (always the case for
    /// the `json!({...})` literals this is used on).
    fn set(&mut self, key: &str, value: impl Into<Value>);
    /// Insert every member of the object `other`.
    fn merge(&mut self, other: Value);
    fn remove_key(&mut self, key: &str);
}

impl ObjectExt for Value {
    fn set(&mut self, key: &str, value: impl Into<Value>) {
        if let Value::Object(map) = self {
            map.insert(key.to_owned(), value.into());
        }
    }

    fn merge(&mut self, other: Value) {
        if let (Value::Object(map), Value::Object(extra)) = (self, other) {
            map.extend(extra);
        }
    }

    fn remove_key(&mut self, key: &str) {
        if let Value::Object(map) = self {
            map.remove(key);
        }
    }
}

/// Pretty JSON (2-space indent, raw UTF-8), no trailing newline: the format
/// of server configuration files and `probe.json`.
pub fn pretty(value: &Value) -> Result<String> {
    Ok(serde_json::to_string_pretty(value)?)
}

/// Pretty JSON plus one `"\n"`: the format of client exports.
pub fn pretty_line(value: &Value) -> Result<String> {
    let mut text = pretty(value)?;
    text.push('\n');
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn object_helpers_never_touch_non_objects() {
        let mut v = json!({"b": 1});
        v.set("a", "x");
        v.merge(json!({"c": [1], "b": 2}));
        v.remove_key("c");
        assert_eq!(v, json!({"a": "x", "b": 2}));
        let mut list = json!([1]);
        list.set("a", 1);
        list.merge(json!({"a": 1}));
        list.remove_key("a");
        assert_eq!(list, json!([1]));
    }

    #[test]
    fn pretty_output_sorts_keys_and_keeps_utf8() {
        let v = json!({"z": "中文", "a": {"y": 1, "b": [true]}});
        assert_eq!(
            pretty(&v).unwrap(),
            "{\n  \"a\": {\n    \"b\": [\n      true\n    ],\n    \"y\": 1\n  },\n  \"z\": \"中文\"\n}"
        );
        assert!(pretty_line(&v).unwrap().ends_with("}\n"));
    }
}
