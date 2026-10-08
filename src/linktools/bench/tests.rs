use super::*;
use crate::domain::protocol::{Core, Transport};
use crate::linktools::testutil::{arg_after, curl_ok, entry, proxy_port, to_value, FakeLauncher};
use crate::sys::exec::{Cmd, FakeExec, Output};
use crate::sys::fs::TempDir;
use serde_json::json;
use std::sync::Arc;

fn ctx() -> (TempDir, Ctx, Arc<FakeExec>) {
    let dir = TempDir::new("linktools-test").unwrap();
    let (ctx, exec, _) = Ctx::test(dir.path());
    (dir, ctx, exec)
}

fn is_curl(cmd: &Cmd) -> bool {
    cmd.program == "curl"
}

fn opts() -> BenchOptions {
    BenchOptions {
        samples: 2,
        ..BenchOptions::default()
    }
}

#[test]
fn rows_carry_v2_keys_and_real_causes() {
    let (_dir, ctx, exec) = ctx();
    exec.on_fn(is_curl, |_| Ok(curl_ok(204, 0.2, 0)));
    let a = entry("vless-reality", Core::Singbox, Transport::Tcp);
    let b = entry("trojan", Core::Xray, Transport::Tcp);
    let mut launcher = FakeLauncher::new(41000);
    launcher.fail = vec!["trojan".into()];
    let (report, outcome) = bench(&ctx, &launcher, &[&a, &b], &opts(), &CancelToken::manual());
    assert_eq!(
        outcome,
        Outcome {
            cancelled: false,
            failed: true,
            warned: false
        }
    );
    let value = to_value(&report);
    assert_eq!(
        value,
        json!({"cancelled": false, "note": BENCH_NOTE, "schema": 1,
            "scope": "current-machine-to-proxy-to-origin",
            "entries": [
                {"id": "vless-reality", "request_failure_rate": 0.0,
                 "ttfb_ms": {"median": 200.0, "p95": 200.0},
                 "samples": [
                    {"ok": true, "setup_ms": 100.0, "status": 204, "ttfb_ms": 200.0},
                    {"ok": true, "setup_ms": 100.0, "status": 204, "ttfb_ms": 200.0}],
                 "transfers": {}, "loaded_ttfb_ms": null,
                 "client_rss_bytes_at_end": 1000001, "client_cpu_seconds": 0.25},
                {"id": "trojan", "error": CLIENT_TEST_FAILED,
                 "error_detail": "缺少客户端内核: xray"}]})
    );
    // Every health request went through the entry's proxy, never direct.
    let calls = exec.calls();
    assert_eq!(calls.len(), 2);
    assert!(calls.iter().all(|c| proxy_port(c) == Some(41000)));
    assert!(calls
        .iter()
        .all(|c| c.args.last().unwrap() == "https://www.gstatic.com/generate_204"));
}

#[test]
fn failures_are_counted_per_sample() {
    let (_dir, ctx, exec) = ctx();
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = count.clone();
    exec.on_fn(is_curl, move |_| {
        let n = seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(match n % 3 {
            0 => curl_ok(204, 0.1 * (n + 1) as f64, 0),
            1 => curl_ok(503, 0.05, 0),
            _ => Output::failure(7, "\nONEBOX_STATS:{\"status\":000,\"setup\":0,\"ttfb\":0,\"duration\":0.001,\"sent\":0}\n"),
        })
    });
    let e = entry("hysteria2", Core::Singbox, Transport::Udp);
    let opts = BenchOptions {
        samples: 5,
        ..BenchOptions::default()
    };
    let (report, outcome) = bench(&ctx, &FakeLauncher::new(42000), &[&e], &opts, &CancelToken::manual());
    assert!(outcome.failed);
    let row = &report.entries[0];
    assert_eq!(row.request_failure_rate, Some(0.6));
    // ok samples: n = 0 (100 ms) and n = 3 (400 ms).
    assert_eq!(
        row.ttfb_ms,
        Some(Some(Distribution {
            median: 250.0,
            p95: 400.0
        }))
    );
    let samples = to_value(row.samples.as_ref().unwrap());
    assert_eq!(samples[1], json!({"ok": false, "setup_ms": 25.0, "status": 503, "ttfb_ms": 50.0}));
    assert_eq!(
        samples[2],
        json!({"error": "request_failed", "ok": false,
            "error_detail": "HTTP 请求失败（连接、TLS 或超时，curl 退出码 7）"})
    );
}

#[test]
fn transfers_sample_latency_under_load_each() {
    let (_dir, ctx, exec) = ctx();
    exec.on_fn(
        |cmd| is_curl(cmd) && arg_after(&cmd.args, "--range").is_some(),
        |cmd| {
            assert_eq!(arg_after(&cmd.args, "--range"), Some("0-1048575"));
            std::thread::sleep(Duration::from_millis(500));
            Ok(curl_ok(206, 0.3, 0))
        },
    )
    .on_fn(
        |cmd| is_curl(cmd) && cmd.args.iter().any(|a| a == "--data-binary"),
        |_| {
            std::thread::sleep(Duration::from_millis(500));
            Ok(Output::failure(28, "\nONEBOX_STATS:{\"status\":000,\"setup\":0,\"ttfb\":0,\"duration\":8,\"sent\":10}\n"))
        },
    )
    .on_fn(is_curl, |_| Ok(curl_ok(204, 0.1, 0)));
    let opts = BenchOptions {
        samples: 1,
        bytes: 1_048_576,
        download: Some(TestUrl::parse("https://d.example/file").unwrap()),
        upload: Some(TestUrl::parse("https://u.example/sink").unwrap()),
        ..BenchOptions::default()
    };
    let e = entry("anytls", Core::Singbox, Transport::Tcp);
    let (report, outcome) = bench(&ctx, &FakeLauncher::new(43000), &[&e], &opts, &CancelToken::manual());
    assert!(outcome.failed, "the upload failed");
    let row = to_value(&report.entries[0]);
    let loaded = json!({"median": 100.0, "p95": 100.0});
    assert_eq!(
        row["transfers"],
        json!({
            "download": {"download_mbps": 0.0, "ok": true, "received_bytes": 0, "sent_bytes": 0,
                "setup_ms": 150.0, "status": 206, "total_ms": 600.0, "ttfb_ms": 300.0,
                "upload_mbps": 0.0, "loaded_ttfb_ms": loaded},
            "upload": {"error": "request_failed", "ok": false, "loaded_ttfb_ms": loaded,
                "error_detail": "HTTP 请求失败（连接、TLS 或超时，curl 退出码 28）"}})
    );
    assert_eq!(row["loaded_ttfb_ms"], loaded, "both transfers' samples");
    // One health sample, then two loaded samples per transfer (budget 2).
    let health = exec
        .calls()
        .iter()
        .filter(|c| c.args.last().unwrap().contains("gstatic"))
        .count();
    assert_eq!(health, 1 + 2 + 2);
}

#[test]
fn cancellation_stops_between_entries_and_reports_it() {
    let (_dir, ctx, exec) = ctx();
    exec.on_fn(is_curl, |_| Ok(curl_ok(204, 0.1, 0)));
    let cancel = CancelToken::manual();
    let mut launcher = FakeLauncher::new(44000);
    launcher.cancel_on_launch = Some(cancel.clone());
    let a = entry("a", Core::Singbox, Transport::Tcp);
    let b = entry("b", Core::Singbox, Transport::Tcp);
    let (report, outcome) = bench(&ctx, &launcher, &[&a, &b], &opts(), &cancel);
    assert!(outcome.cancelled && report.cancelled);
    assert_eq!(report.entries.len(), 1, "b never started");
    assert_eq!(report.entries[0].error_detail.as_deref(), Some("测试已停止"));
    assert_eq!(launcher.launched().len(), 1);
    let exit = conclude(Tool::Bench, outcome, Ok(())).unwrap_err();
    assert_eq!((exit.exit_code(), exit.to_string()), (130, "测试已取消".to_string()));

    let cancel = CancelToken::manual();
    cancel.cancel();
    let (report, outcome) = bench(&ctx, &FakeLauncher::new(44100), &[&a], &opts(), &cancel);
    assert!(report.entries.is_empty() && outcome.cancelled);
}

#[test]
fn the_cli_entry_point_validates_before_starting() {
    let (_dir, ctx, _) = ctx();
    let err = run(&ctx, &BenchOptions::default()).unwrap_err();
    assert_eq!(err.to_string(), "onebox bench 需要 probe.json 配置文件");
    let dir = TempDir::new("linktools-test").unwrap();
    let path = dir.join("probe.json");
    let b = crate::linktools::testutil::bundle(vec![entry("a", Core::Singbox, Transport::Tcp)]);
    crate::linktools::bundle::write_bundle(&path, &b).unwrap();
    let opts = BenchOptions {
        common: crate::linktools::options::Common {
            bundle: Some(path),
            entries: Some(vec!["zz".into()]),
            ..Default::default()
        },
        ..BenchOptions::default()
    };
    let err = run(&ctx, &opts).unwrap_err();
    assert_eq!(err.to_string(), "--entries 包含未知 ID（先执行 probe list）");
}
