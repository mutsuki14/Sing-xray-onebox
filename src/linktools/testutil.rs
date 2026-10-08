//! Shared test helpers of the link tools: bundle fixtures, fake proxies,
//! scripted curl output and the real-tool lookup contract of CI.

use super::cancel::CancelToken;
use super::core_client::{Launcher, Proxy, Resources};
use super::socks::SocksEndpoint;
use crate::domain::protocol::{Core, Transport};
use crate::error::{Error, Result};
use crate::render::probe::{ProbeBundle, ProbeEntry, RealityProbe};
use crate::sys::exec::{Cmd, Output};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering};
use std::sync::Mutex;

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

/// A scripted curl run: `status`, setup = ttfb / 2, total = ttfb × 2 (s).
pub fn curl_ok(status: u16, ttfb: f64, sent: u64) -> Output {
    Output {
        code: 0,
        stdout: String::new(),
        stderr: curl_stats(status, ttfb / 2.0, ttfb, ttfb * 2.0, sent),
    }
}

/// The value of `flag` in a recorded command line.
pub fn arg_after<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

/// The SOCKS port a curl command goes through (`None` = direct).
pub fn proxy_port(cmd: &Cmd) -> Option<u16> {
    arg_after(&cmd.args, "--proxy")?
        .strip_prefix("socks5h://127.0.0.1:")?
        .parse()
        .ok()
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

/// Whether a program runs (tests that need curl/openssl skip without it,
/// except under `ONEBOX_TEST_REQUIRE_FULL=1`).
pub fn have(program: &str) -> bool {
    let probe = if program == "openssl" {
        "version"
    } else {
        "--version"
    };
    let found = std::process::Command::new(program)
        .arg(probe)
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

/// The JSON value of a serializable report part.
pub fn to_value<T: serde::Serialize>(value: &T) -> Value {
    serde_json::to_value(value).unwrap()
}

/// A launcher of fake proxies: ports are handed out from `base` in launch
/// order (scripted curl rules match on them); ids in `fail` fail.
pub struct FakeLauncher {
    next_port: AtomicU16,
    pub fail: Vec<String>,
    launched: Mutex<Vec<(String, u16)>>,
    /// Cancel this token when launching (Ctrl+C during startup).
    pub cancel_on_launch: Option<CancelToken>,
}

impl FakeLauncher {
    pub fn new(base: u16) -> FakeLauncher {
        FakeLauncher {
            next_port: AtomicU16::new(base),
            fail: Vec::new(),
            launched: Mutex::new(Vec::new()),
            cancel_on_launch: None,
        }
    }

    /// `(entry id, port)` per launch, in order.
    pub fn launched(&self) -> Vec<(String, u16)> {
        self.launched.lock().unwrap().clone()
    }
}

impl Launcher for FakeLauncher {
    fn launch(&self, entry: &ProbeEntry) -> Result<Box<dyn Proxy>> {
        if let Some(token) = &self.cancel_on_launch {
            token.cancel();
        }
        if self.fail.contains(&entry.id) {
            return Err(Error::msg("缺少客户端内核: xray"));
        }
        let port = self.next_port.fetch_add(1, Ordering::SeqCst);
        self.launched.lock().unwrap().push((entry.id.clone(), port));
        Ok(Box::new(FakeProxy::new(port)))
    }
}

/// A proxy that runs until terminated; CPU grows 0.25 s per reading.
pub struct FakeProxy {
    endpoint: SocksEndpoint,
    readings: AtomicU32,
    terminated: AtomicBool,
}

impl FakeProxy {
    pub fn new(port: u16) -> FakeProxy {
        FakeProxy {
            endpoint: SocksEndpoint {
                port,
                token: "0".repeat(48),
            },
            readings: AtomicU32::new(0),
            terminated: AtomicBool::new(false),
        }
    }
}

impl Proxy for FakeProxy {
    fn endpoint(&self) -> &SocksEndpoint {
        &self.endpoint
    }

    fn resources(&self) -> Resources {
        let n = self.readings.fetch_add(1, Ordering::SeqCst);
        Resources {
            cpu_seconds: Some(1.0 + 0.25 * f64::from(n)),
            rss_bytes: Some(1_000_000 + u64::from(n)),
        }
    }

    fn exited(&self) -> Option<i32> {
        self.terminated.load(Ordering::SeqCst).then_some(143)
    }

    fn terminate(&self) {
        self.terminated.store(true, Ordering::SeqCst);
    }
}
