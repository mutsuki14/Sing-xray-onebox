use super::reader::parse;
use super::*;
use serde_json::json;

fn roundtrip(value: &Value) {
    let text = to_yaml(value);
    assert!(text.ends_with('\n') && !text.ends_with("\n\n"), "{text}");
    assert_eq!(&parse(&text).unwrap(), value, "{text}");
}

#[test]
fn scalars_are_quoted_and_typed() {
    let value = json!({"port": 7890, "ratio": -1.5, "on": true, "off": false, "none": null,
        "s": "7890", "t": "true", "n": "null", "e": ""});
    let text = to_yaml(&value);
    assert!(text.contains("port: 7890\n"), "{text}");
    assert!(text.contains("s: \"7890\"\n"), "{text}");
    assert!(text.contains("t: \"true\"\n"), "{text}");
    assert!(text.contains("e: \"\"\n"), "{text}");
    assert!(text.contains("\"on\": true\n"), "{text}");
    assert!(text.contains("none: null\n"), "{text}");
    roundtrip(&value);
}

#[test]
fn escapes_quotes_backslashes_newlines_and_separators() {
    let tricky = "a\"b\\c\nd\re\tf\u{0}g\u{7f}h\u{85}i\u{2028}j\u{feff}k: #&*!|>%@`'";
    let text = to_yaml(&json!({ "k": tricky }));
    assert_eq!(
        text,
        "k: \"a\\\"b\\\\c\\nd\\re\\tf\\u0000g\\u007fh\\u0085i\\u2028j\\ufeffk: #&*!|>%@`'\"\n"
    );
    roundtrip(&json!({ "k": tricky }));
}

#[test]
fn unicode_stays_raw() {
    let value = json!({"name": "香港 #1-节点选择 🚀", "节点": ["自动选择"]});
    let text = to_yaml(&value);
    assert!(text.contains("name: \"香港 #1-节点选择 🚀\"\n"), "{text}");
    assert!(text.contains("\"节点\":\n  - \"自动选择\"\n"), "{text}");
    roundtrip(&value);
}

#[test]
fn keys_are_plain_only_when_unambiguous() {
    let cases = [
        ("mixed-port", "mixed-port"),
        ("HTTP", "HTTP"),
        ("site.example.com", "site.example.com"),
        ("_x", "_x"),
        ("geosite:cn", "\"geosite:cn\""),
        ("geosite:geolocation-!cn", "\"geosite:geolocation-!cn\""),
        ("8080", "\"8080\""),
        ("Yes", "\"Yes\""),
        ("y", "\"y\""),
        ("", "\"\""),
        ("-a", "\"-a\""),
        ("a b", "\"a b\""),
    ];
    for (key, shown) in cases {
        assert_eq!(key_text(key), shown, "{key}");
        roundtrip(&json!({ key: 1 }));
    }
}

#[test]
fn nested_lists_of_maps_use_dash_lines() {
    let value = json!({"proxies": [
        {"name": "a", "reality-opts": {"public-key": "k", "short-id": "s"}, "alpn": ["h2", "http/1.1"]},
        {"name": "b", "ws-opts": {"headers": {"Host": "x"}}, "empty": [], "obj": {}},
    ]});
    let text = to_yaml(&value);
    let expected = "proxies:\n  - alpn:\n      - \"h2\"\n      - \"http/1.1\"\n    name: \"a\"\n    reality-opts:\n      public-key: \"k\"\n      short-id: \"s\"\n  - empty: []\n    name: \"b\"\n    obj: {}\n    ws-opts:\n      headers:\n        Host: \"x\"\n";
    assert_eq!(text, expected);
    roundtrip(&value);
}

#[test]
fn sequences_of_sequences_and_mixed_items() {
    let value = json!([[1, [2, "x"]], {"a": [{"b": []}]}, "s", [], {}, null]);
    let text = to_yaml(&value);
    assert!(text.starts_with("- - 1\n  - - 2\n    - \"x\"\n- a:\n"), "{text}");
    roundtrip(&value);
}

#[test]
fn top_level_scalars_and_empty_collections() {
    for value in [json!("x"), json!(1), json!([]), json!({}), json!(null), json!(true)] {
        roundtrip(&value);
    }
    assert_eq!(to_yaml(&json!({})), "{}\n");
}

#[test]
fn quote_matches_json_for_ordinary_strings() {
    for s in ["plain", "with space", "中文", "a\"b", "c\\d", "e\nf"] {
        assert_eq!(quote(s), serde_json::to_string(s).unwrap(), "{s}");
    }
}
