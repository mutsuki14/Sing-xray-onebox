use super::*;
use crate::linktools::options::{Common, Scope};
use crate::linktools::report::REALITY_WARNINGS;
use crate::linktools::testutil::{
    arg_after, curl_ok, entry, have, proxy_port, reality_entry, tls_server, to_value, FakeLauncher,
};
use crate::render::fixtures::cert_pair;
use crate::sys::exec::{Cmd, FakeExec, Output, SystemExec};
use crate::sys::fs::TempDir;
use crate::sys::rand::SeqRandom;
use serde_json::json;
use std::io::Write;
use std::sync::Arc;

const NODE: &str = "203.0.113.10:443";
const REFERENCE: &str = "ref.example:443";

fn pem(name: &str) -> String {
    std::fs::read_to_string(cert_pair(name).0).unwrap()
}

fn s_client(cert: &str, alpn: Option<&str>) -> Output {
    let alpn = alpn.map_or("No ALPN negotiated".to_owned(), |a| {
        format!("ALPN protocol: {a}")
    });
    Output::success(format!(
        "CONNECTED(00000003)\n{cert}---\nNew, TLSv1.3, Cipher is TLS_AES_128_GCM_SHA256\n{alpn}\n"
    ))
}

/// Write `body` into the sink curl was given (our own pipe), as curl would.
fn write_body(cmd: &Cmd, body: &[u8]) {
    let path = arg_after(&cmd.args, "--output").unwrap();
    if path != "/dev/null" {
        let mut sink = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        sink.write_all(body).unwrap();
    }
}

/// How the scripted node and reference behave.
#[derive(Clone)]
struct World {
    node_cert: String,
    reference_cert: String,
    node_alpn: Option<&'static str>,
    reference_alpn: Option<&'static str>,
    node_body: &'static [u8],
    reference_body: &'static [u8],
    /// The proxy port of the wrong-short-ID core still gets through.
    wrong_accepted: bool,
}

impl Default for World {
    fn default() -> World {
        World {
            node_cert: pem("selfsigned"),
            reference_cert: pem("selfsigned"),
            node_alpn: Some("h2"),
            reference_alpn: Some("h2"),
            node_body: b"<html>same</html>",
            reference_body: b"<html>same</html>",
            wrong_accepted: false,
        }
    }
}

const BASE_PORT: u16 = 46000;

fn script(exec: &FakeExec, world: World) {
    let w = world.clone();
    exec.on(
        "openssl",
        &["s_client", "-connect", NODE],
        s_client(&w.node_cert, w.node_alpn),
    )
    .on(
        "openssl",
        &["s_client", "-connect", REFERENCE],
        s_client(&w.reference_cert, w.reference_alpn),
    );
    exec.on_fn(
        |cmd| cmd.program == "curl",
        move |cmd| {
            let connect_to = arg_after(&cmd.args, "--connect-to").unwrap_or("");
            if connect_to.ends_with(":203.0.113.10:443") {
                write_body(cmd, world.node_body);
                return Ok(curl_ok(200, 0.1, 0));
            }
            if connect_to.ends_with(":ref.example:443") {
                write_body(cmd, world.reference_body);
                return Ok(curl_ok(200, 0.1, 0));
            }
            let wrong = proxy_port(cmd) == Some(BASE_PORT + 1);
            Ok(if wrong && !world.wrong_accepted {
                Output::failure(97, "\nONEBOX_STATS:{\"status\":000,\"setup\":0,\"ttfb\":0,\"duration\":0.1,\"sent\":0}\n")
            } else {
                curl_ok(204, 0.1, 0)
            })
        },
    );
}

fn check(
    world: World,
    entries: &[&ProbeEntry],
) -> (Result<(Report<RealityRow>, Outcome)>, Arc<FakeExec>) {
    let dir = TempDir::new("linktools-test").unwrap();
    let (ctx, exec, _) = Ctx::test(dir.path());
    script(&exec, world);
    let launcher = FakeLauncher::new(BASE_PORT);
    let opts = RealityOptions {
        common: Common {
            bundle: Some("probe.json".into()),
            ..Common::default()
        },
        ..RealityOptions::default()
    };
    let cancel = CancelToken::manual();
    let checker = Checker {
        ctx: &ctx,
        launcher: &launcher,
        opts: &opts,
        cancel: &cancel,
    };
    let result = checker.check_all(entries, &mut SeqRandom(7));
    (result, exec)
}

fn referenced() -> ProbeEntry {
    reality_entry("vless-reality", Core::Singbox, ("ref.example", 443))
}

#[test]
fn a_consistent_node_passes_every_check() {
    let e = referenced();
    let (result, exec) = check(World::default(), &[&e]);
    let (report, outcome) = result.unwrap();
    assert_eq!(outcome, Outcome::default());
    assert_eq!(
        to_value(&report),
        json!({"cancelled": false, "note": REALITY_NOTE, "schema": 1,
            "scope": "current-machine-to-server",
            "entries": [{"id": "vless-reality", "warnings": [], "checks": {
                "ordinary_tls13_valid_certificate": true, "ordinary_h2": true,
                "same_certificate": true, "same_alpn": true, "same_http_status": true,
                "same_redirect": true, "authenticated_proxy": true,
                "wrong_short_id_rejected": true}}]})
    );
    // The wrong-short-ID core got a different short ID than the valid one.
    let fetches: Vec<String> = exec
        .calls()
        .iter()
        .filter_map(|c| arg_after(&c.args, "--connect-to").map(str::to_owned))
        .collect();
    assert_eq!(
        fetches,
        [
            "www.example.com:443:203.0.113.10:443",
            "www.example.com:443:ref.example:443"
        ]
    );
    assert_eq!(conclude(Tool::Reality, outcome, Ok(())).ok(), Some(()));
}

#[test]
fn differences_without_failures_are_warnings() {
    let world = World {
        node_alpn: None,
        reference_alpn: None,
        node_body: b"node",
        reference_body: b"reference",
        ..World::default()
    };
    let e = referenced();
    let (report, outcome) = check(world, &[&e]).0.unwrap();
    let row = &report.entries[0];
    assert!(!row.checks[H2]);
    assert!(!row.failed(), "h2 alone does not fail");
    assert_eq!(row.warnings, [BODY_DIFFERS, NO_H2]);
    let exit = conclude(Tool::Reality, outcome, Ok(())).unwrap_err();
    assert_eq!(
        (exit.exit_code(), exit.to_string()),
        (2, REALITY_WARNINGS.to_string())
    );
}

#[test]
fn mismatches_and_accepted_wrong_ids_fail() {
    let world = World {
        reference_cert: pem("chain"),
        reference_alpn: Some("http/1.1"),
        wrong_accepted: true,
        ..World::default()
    };
    let e = referenced();
    let (report, outcome) = check(world, &[&e]).0.unwrap();
    let checks = &report.entries[0].checks;
    assert_eq!(
        (
            checks[SAME_CERTIFICATE],
            checks[SAME_ALPN],
            checks[WRONG_REJECTED]
        ),
        (false, false, false)
    );
    assert!(checks[AUTHENTICATED]);
    assert!(outcome.failed);
    let exit = conclude(Tool::Reality, outcome, Ok(())).unwrap_err();
    assert_eq!(
        (exit.exit_code(), exit.to_string()),
        (1, "REALITY 检查失败，详见 JSON 报告".to_string())
    );
}

#[test]
fn a_site_without_public_https_has_nothing_to_compare() {
    let e = reality_entry("anytls-reality", Core::Singbox, ("", 0));
    let (report, outcome) = check(World::default(), &[&e]).0.unwrap();
    let row = &report.entries[0];
    assert_eq!(row.warnings, [NO_REFERENCE]);
    assert_eq!(
        row.checks.keys().copied().collect::<Vec<_>>(),
        [AUTHENTICATED, H2, TLS13_VALID, WRONG_REJECTED]
    );
    assert!(!outcome.failed && outcome.warned);
}

#[test]
fn block_errors_are_recorded_with_their_causes() {
    let dir = TempDir::new("linktools-test").unwrap();
    let (ctx, exec, _) = Ctx::test(dir.path());
    exec.on(
        "openssl",
        &["s_client"],
        Output::failure(1, "connect:errno=111\n"),
    );
    let mut launcher = FakeLauncher::new(BASE_PORT);
    launcher.fail = vec!["vless-reality".into()];
    let opts = RealityOptions::default();
    let cancel = CancelToken::manual();
    let checker = Checker {
        ctx: &ctx,
        launcher: &launcher,
        opts: &opts,
        cancel: &cancel,
    };
    let e = referenced();
    let (report, outcome) = checker.check_all(&[&e], &mut SeqRandom(1)).unwrap();
    assert_eq!(
        to_value(&report.entries[0]),
        json!({"id": "vless-reality",
            "checks": {"ordinary_or_reference_probe": false, "authentication_test_completed": false},
            "warnings": [PROBE_FAILED],
            "errors": ["普通 TLS 或参考站点探测: TLS 探测失败: connect:errno=111",
                       "认证测试: 缺少客户端内核: xray"]})
    );
    assert!(outcome.failed);
}

#[test]
fn only_reality_entries_are_checked_and_cancellation_wins() {
    let plain = entry(
        "trojan",
        Core::Xray,
        crate::domain::protocol::Transport::Tcp,
    );
    let err = check(World::default(), &[&plain]).0.unwrap_err();
    assert_eq!(err.to_string(), "配置中没有 REALITY 入口");

    let dir = TempDir::new("linktools-test").unwrap();
    let (ctx, _, _) = Ctx::test(dir.path());
    let opts = RealityOptions {
        scope: Scope::ServerLocal,
        ..RealityOptions::default()
    };
    let cancel = CancelToken::manual();
    cancel.cancel();
    let launcher = FakeLauncher::new(BASE_PORT);
    let checker = Checker {
        ctx: &ctx,
        launcher: &launcher,
        opts: &opts,
        cancel: &cancel,
    };
    let e = referenced();
    let (report, outcome) = checker.check_all(&[&e], &mut SeqRandom(1)).unwrap();
    assert!(report.entries.is_empty() && report.cancelled && outcome.cancelled);
    assert_eq!(report.scope, "server-local");
    let exit = conclude(Tool::Reality, outcome, Ok(())).unwrap_err();
    assert_eq!(
        (exit.exit_code(), exit.to_string()),
        (130, "REALITY 检查已取消".to_string())
    );
}

#[test]
fn wrong_short_ids_change_only_the_copy() {
    let original = reality_entry("anytls-reality", Core::Singbox, ("", 0));
    let changed = wrong_short_id(&original, &mut SeqRandom(1)).unwrap();
    assert_eq!(
        original.outbounds[0]["tls"]["reality"]["short_id"],
        "0123abcd"
    );
    let new = changed.outbounds[0]["tls"]["reality"]["short_id"]
        .as_str()
        .unwrap();
    assert_ne!(new, "0123abcd");
    assert_eq!(new.len(), 16);

    let xray = reality_entry("vless-reality", Core::Xray, ("", 0));
    let changed = wrong_short_id(&xray, &mut SeqRandom(1)).unwrap();
    assert_eq!(
        changed.outbounds[0]["streamSettings"]["realitySettings"]["shortId"],
        "0102030405060708"
    );
    // A random value equal to the original is drawn again.
    let mut same = xray.clone();
    same.outbounds[0]["streamSettings"]["realitySettings"]["shortId"] = json!("0102030405060708");
    let changed = wrong_short_id(&same, &mut SeqRandom(1)).unwrap();
    assert_eq!(
        changed.outbounds[0]["streamSettings"]["realitySettings"]["shortId"],
        "090a0b0c0d0e0f10"
    );

    let mut missing = original.clone();
    missing.outbounds[0] = json!({"type": "vless", "tag": "proxy"});
    let err = wrong_short_id(&missing, &mut SeqRandom(1)).unwrap_err();
    assert_eq!(err.to_string(), "REALITY 出站缺少 short ID");
    let mut typed = original;
    typed.outbounds[0]["tls"]["reality"]["short_id"] = json!(1234);
    let err = wrong_short_id(&typed, &mut SeqRandom(1)).unwrap_err();
    assert_eq!(err.to_string(), "REALITY short ID 类型无效");
}

// ---- real openssl (skipped without it) ----

#[test]
fn real_openssl_probe_validates_the_certificate() {
    if !have("openssl") {
        return;
    }
    let server = tls_server();
    let dir = TempDir::new("linktools-test").unwrap();
    let mut ctx = Ctx::test(dir.path()).0;
    ctx.exec = Arc::new(SystemExec);
    let cancel = CancelToken::manual();
    let t = Duration::from_secs(5);
    let ok = tls::probe(
        &ctx,
        ("127.0.0.1", server.port, "localhost"),
        Some(&server.cert),
        t,
        &cancel,
    )
    .unwrap();
    assert_eq!(ok.protocol.as_deref(), Some("TLSv1.3"));
    assert_eq!(ok.alpn.as_deref(), Some("h2"));
    let expected = crate::render::TlsMaterial::load(&server.cert).unwrap();
    assert_eq!(ok.certificate_sha256, expected.pin());
    let wrong_name = tls::probe(
        &ctx,
        ("127.0.0.1", server.port, "wrong.localhost"),
        Some(&server.cert),
        t,
        &cancel,
    );
    assert!(wrong_name
        .unwrap_err()
        .to_string()
        .starts_with("TLS 探测失败"));
    let untrusted = tls::probe(
        &ctx,
        ("127.0.0.1", server.port, "localhost"),
        None,
        t,
        &cancel,
    );
    assert!(untrusted.is_err());
}
