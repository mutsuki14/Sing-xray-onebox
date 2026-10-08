//! Shared test helpers of the link tools: bundle fixtures, scripted curl
//! output and the real-tool lookup contract of CI.

use crate::domain::protocol::{Core, Transport};
use crate::render::probe::{ProbeBundle, ProbeEntry, RealityProbe};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// A minimal valid entry (one outbound tagged `proxy`).
pub fn entry(id: &str, core: Core, transport: Transport) -> ProbeEntry {
    let outbound = match core {
        Core::Singbox => json!({"type": "vless", "tag": "proxy"}),
        Core::Xray => json!({"protocol": "vless", "tag": "proxy"}),
    };
    ProbeEntry {
        id: id.into(),
        core,
        transport,
        tag: "proxy".into(),
        outbounds: vec![outbound],
        reality: None,
        extra: BTreeMap::new(),
    }
}

/// `entry` with REALITY metadata and a short id in the core's place.
pub fn reality_entry(id: &str, core: Core, reference: (&str, u16)) -> ProbeEntry {
    let mut e = entry(id, core, Transport::Tcp);
    e.outbounds[0] = match core {
        Core::Singbox => json!({"type": "vless", "tag": "proxy",
            "tls": {"reality": {"short_id": "0123abcd"}}}),
        Core::Xray => json!({"protocol": "vless", "tag": "proxy",
            "streamSettings": {"realitySettings": {"shortId": "0123abcd"}}}),
    };
    e.reality = Some(RealityProbe {
        host: "203.0.113.10".into(),
        port: 443,
        sni: "www.example.com".into(),
        reference_host: reference.0.into(),
        reference_port: reference.1,
    });
    e
}

pub fn bundle(entries: Vec<ProbeEntry>) -> ProbeBundle {
    ProbeBundle { schema: 1, entries }
}

/// curl's `--write-out` record as it appears on stderr.
pub fn curl_stats(status: u16, setup: f64, ttfb: f64, duration: f64, sent: u64) -> String {
    format!(
        "\nONEBOX_STATS:{{\"status\":{status},\"setup\":{setup},\"ttfb\":{ttfb},\"duration\":{duration},\"sent\":{sent}}}\n"
    )
}

/// The value of `flag` in a recorded command line.
pub fn arg_after<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

/// A real tool from `var`. Unset: skip (returns `None`) unless CI's
/// `ONEBOX_TEST_REQUIRE_FULL=1` contract turns the skip into a failure.
pub fn tool(var: &str) -> Option<PathBuf> {
    match std::env::var_os(var).filter(|v| !v.is_empty()) {
        Some(path) => Some(PathBuf::from(path)),
        None => {
            assert!(
                std::env::var("ONEBOX_TEST_REQUIRE_FULL").as_deref() != Ok("1"),
                "{var} 未设置，但 ONEBOX_TEST_REQUIRE_FULL=1"
            );
            eprintln!("跳过：未设置 {var}");
            None
        }
    }
}

/// Whether a program is on PATH (tests that need curl/openssl skip without).
pub fn have(program: &str) -> bool {
    let found = std::process::Command::new(program)
        .arg(if program == "openssl" {
            "version"
        } else {
            "--version"
        })
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok();
    if !found {
        assert!(
            std::env::var("ONEBOX_TEST_REQUIRE_FULL").as_deref() != Ok("1"),
            "{program} 不可用，但 ONEBOX_TEST_REQUIRE_FULL=1"
        );
        eprintln!("跳过：未找到 {program}");
    }
    found
}

/// The JSON object of a serializable report part.
pub fn to_value<T: serde::Serialize>(value: &T) -> Value {
    serde_json::to_value(value).unwrap()
}
