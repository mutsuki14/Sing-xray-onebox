//! `bench`: for each entry, a temporary client core and real requests
//! through it — health samples, optional download/upload transfers with
//! latency under load, and the core's CPU/RSS (spec D §2.4).
//!
//! Report keys and strings are v2's (`schema` 1, scope
//! `current-machine-to-proxy-to-origin`); a failed sample is
//! `{"error":"request_failed","ok":false}`.
//!
//! Changes from v2:
//! - a failed entry keeps v2's `error` text and adds `error_detail` with
//!   the real cause (missing core, check failure, timeout…, D-8.1#8);
//!   failed samples carry `error_detail` too;
//! - latency under load is sampled per transfer (each up to `samples × 2`;
//!   v2 shared one budget, so the upload could get none, D-8.1#6): every
//!   transfer reports its own `loaded_ttfb_ms`, the row-level
//!   `loaded_ttfb_ms` keeps v2's meaning (all loaded samples);
//! - the loaded-latency pause honours cancellation.

use super::bundle::{self, Selection};
use super::cancel::{CancelToken, SignalCancel};
use super::core_client::{CoreLauncher, Launcher, Proxy, Resources, Timing};
use super::http_probe::{
    safe_measure, HttpRequest, HttpResult, Measurement, Route, REQUEST_FAILED,
};
use super::options::BenchOptions;
use super::report::{conclude, publish, Outcome, Report, Tool, BENCH_NOTE, BENCH_SCOPE};
use super::socks::SocksEndpoint;
use super::stats::{distribution, round3, Distribution};
use super::url::TestUrl;
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::render::probe::ProbeEntry;
use serde::Serialize;
use std::collections::BTreeMap;
use std::time::Duration;

/// v2 row error (kept verbatim; the cause is in `error_detail`).
pub const CLIENT_TEST_FAILED: &str = "client_test_failed: 检查该入口所需内核、版本及配置";
/// Pause between latency samples while a transfer runs (v2).
const LOADED_PAUSE: Duration = Duration::from_millis(100);

/// A failed request in a report.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Failure {
    pub error: &'static str,
    pub error_detail: String,
    pub ok: bool,
}

impl Failure {
    fn new(detail: &str) -> Failure {
        Failure {
            error: REQUEST_FAILED,
            error_detail: detail.to_owned(),
            ok: false,
        }
    }
}

/// A health sample: v2's projection `ok,status,setup_ms,ttfb_ms,error`.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Sample {
    Done {
        ok: bool,
        setup_ms: f64,
        status: u16,
        ttfb_ms: f64,
    },
    Failed(Failure),
}

impl From<&Measurement> for Sample {
    fn from(m: &Measurement) -> Sample {
        match m {
            Measurement::Done(r) => Sample::Done {
                ok: r.ok,
                setup_ms: r.setup_ms,
                status: r.status,
                ttfb_ms: r.ttfb_ms,
            },
            Measurement::Failed(detail) => Sample::Failed(Failure::new(detail)),
        }
    }
}

/// A transfer result without `body_sha256` and `location` (v2).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct TransferStats {
    pub download_mbps: f64,
    pub ok: bool,
    pub received_bytes: u64,
    pub sent_bytes: u64,
    pub setup_ms: f64,
    pub status: u16,
    pub total_ms: f64,
    pub ttfb_ms: f64,
    pub upload_mbps: f64,
}

impl From<&HttpResult> for TransferStats {
    fn from(r: &HttpResult) -> TransferStats {
        TransferStats {
            download_mbps: r.download_mbps,
            ok: r.ok,
            received_bytes: r.received_bytes,
            sent_bytes: r.sent_bytes,
            setup_ms: r.setup_ms,
            status: r.status,
            total_ms: r.total_ms,
            ttfb_ms: r.ttfb_ms,
            upload_mbps: r.upload_mbps,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(untagged)]
pub enum TransferResult {
    Done(TransferStats),
    Failed(Failure),
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Transfer {
    #[serde(flatten)]
    pub result: TransferResult,
    /// Health latency measured while this transfer ran.
    pub loaded_ttfb_ms: Option<Distribution>,
}

impl Transfer {
    fn ok(&self) -> bool {
        matches!(&self.result, TransferResult::Done(s) if s.ok)
    }
}

/// One entry's row. Keys are filled in v2's order; a key whose step was
/// not reached is absent (`Some(None)` serializes as `null`).
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct BenchRow {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_failure_rate: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttfb_ms: Option<Option<Distribution>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub samples: Option<Vec<Sample>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transfers: Option<BTreeMap<&'static str, Transfer>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loaded_ttfb_ms: Option<Option<Distribution>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_rss_bytes_at_end: Option<Option<u64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_cpu_seconds: Option<Option<f64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_detail: Option<String>,
}

/// `onebox bench`.
pub fn run(ctx: &Ctx, opts: &BenchOptions) -> Result<()> {
    let path = opts
        .common
        .bundle
        .as_deref()
        .ok_or_else(|| Error::msg("onebox bench 需要 probe.json 配置文件"))?;
    let bundle = bundle::load(path)?;
    let entries = bundle::select(&bundle, opts.common.entries.as_deref(), Selection::All)?;
    let signals = SignalCancel::install()?;
    let cancel = signals.token();
    let launcher = CoreLauncher {
        ctx,
        binaries: &opts.common.binaries,
        cancel,
        timing: Timing::default(),
    };
    let (report, outcome) = bench(ctx, &launcher, &entries, opts, cancel);
    let published = report
        .text()
        .and_then(|t| publish(&t, opts.output.as_deref()));
    conclude(Tool::Bench, outcome, published)
}

/// Measure `entries` in order; stops before the next entry once cancelled.
pub fn bench(
    ctx: &Ctx,
    launcher: &dyn Launcher,
    entries: &[&ProbeEntry],
    opts: &BenchOptions,
    cancel: &CancelToken,
) -> (Report<BenchRow>, Outcome) {
    let probe = Prober { ctx, opts, cancel };
    let mut rows = Vec::new();
    let mut failed = false;
    for entry in entries {
        if cancel.is_cancelled() {
            break;
        }
        let mut row = BenchRow {
            id: entry.id.clone(),
            ..BenchRow::default()
        };
        match bench_entry(&probe, launcher, entry, &mut row) {
            Ok(all_ok) => failed |= !all_ok,
            Err(e) => {
                row.error = Some(CLIENT_TEST_FAILED);
                row.error_detail = Some(e.to_string());
                failed = true;
            }
        }
        rows.push(row);
    }
    let cancelled = cancel.is_cancelled();
    let outcome = Outcome {
        cancelled,
        failed,
        warned: false,
    };
    (
        Report::new(BENCH_SCOPE, BENCH_NOTE, rows, cancelled),
        outcome,
    )
}

/// The measurements of one run, bound to its options.
struct Prober<'a> {
    ctx: &'a Ctx,
    opts: &'a BenchOptions,
    cancel: &'a CancelToken,
}

impl Prober<'_> {
    fn request(&self, via: &SocksEndpoint, url: &TestUrl, range: u64, upload: u64) -> Measurement {
        let req = HttpRequest {
            url,
            route: Route::Proxy(via),
            timeout_secs: self.opts.common.timeout,
            ca: self.opts.common.ca.as_deref(),
            range,
            upload,
        };
        safe_measure(self.ctx, &req, self.cancel)
    }

    fn health(&self, via: &SocksEndpoint) -> Measurement {
        self.request(via, &self.opts.common.url, 0, 0)
    }
}

/// Fill `row` for one entry; `Ok(false)` when a sample or transfer failed.
fn bench_entry(
    probe: &Prober,
    launcher: &dyn Launcher,
    entry: &ProbeEntry,
    row: &mut BenchRow,
) -> Result<bool> {
    let core = launcher.launch(entry)?;
    let before = core.resources();
    let samples = health_samples(probe, core.endpoint());
    ensure!(!samples.is_empty(), "测试已停止");
    let failures = samples.iter().filter(|s| !s.ok()).count();
    let ttfb: Vec<f64> = samples.iter().filter_map(Measurement::ok_ttfb).collect();
    row.request_failure_rate = Some(failures as f64 / samples.len() as f64);
    row.ttfb_ms = Some(distribution(&ttfb));
    row.samples = Some(samples.iter().map(Sample::from).collect());
    let (transfers, loaded) = transfers(probe, core.as_ref())?;
    let transfers_ok = transfers.values().all(Transfer::ok);
    row.transfers = Some(transfers);
    row.loaded_ttfb_ms = Some(distribution(&loaded));
    let after = core.resources();
    row.client_rss_bytes_at_end = Some(after.rss_bytes);
    row.client_cpu_seconds = Some(cpu_delta(before, after));
    Ok(failures == 0 && transfers_ok)
}

fn cpu_delta(before: Resources, after: Resources) -> Option<f64> {
    let (start, end) = before.cpu_seconds.zip(after.cpu_seconds)?;
    Some(round3((end - start).max(0.0)))
}

fn health_samples(probe: &Prober, via: &SocksEndpoint) -> Vec<Measurement> {
    let mut samples = Vec::new();
    for _ in 0..probe.opts.samples {
        if probe.cancel.is_cancelled() {
            break;
        }
        samples.push(probe.health(via));
    }
    samples
}

/// Download then upload (each only when its URL was given), with health
/// latency sampled meanwhile; returns the transfers and all loaded samples.
fn transfers(
    probe: &Prober,
    core: &dyn Proxy,
) -> Result<(BTreeMap<&'static str, Transfer>, Vec<f64>)> {
    let opts = probe.opts;
    let plan = [
        ("download", opts.download.as_ref(), opts.bytes, 0),
        ("upload", opts.upload.as_ref(), 0, opts.bytes),
    ];
    let mut done = BTreeMap::new();
    let mut all_loaded = Vec::new();
    for (name, url, range, upload) in plan {
        if probe.cancel.is_cancelled() {
            break;
        }
        let Some(url) = url else {
            continue;
        };
        let (measurement, loaded) = under_load(probe, core.endpoint(), url, range, upload)?;
        let result = match &measurement {
            Measurement::Done(r) => TransferResult::Done(r.into()),
            Measurement::Failed(detail) => TransferResult::Failed(Failure::new(detail)),
        };
        done.insert(
            name,
            Transfer {
                result,
                loaded_ttfb_ms: distribution(&loaded),
            },
        );
        all_loaded.extend(loaded);
    }
    Ok((done, all_loaded))
}

/// Run one transfer on a helper thread while sampling health latency
/// (at most `samples × 2` samples, 100 ms apart). A helper the OS refuses
/// (pids limit) fails this transfer with the cause instead of panicking.
fn under_load(
    probe: &Prober,
    via: &SocksEndpoint,
    url: &TestUrl,
    range: u64,
    upload: u64,
) -> Result<(Measurement, Vec<f64>)> {
    let budget = probe.opts.samples * 2;
    std::thread::scope(|scope| {
        let spawned = std::thread::Builder::new()
            .name("onebox-bench-transfer".into())
            .spawn_scoped(scope, || probe.request(via, url, range, upload));
        let task = match spawned {
            Ok(task) => task,
            Err(e) => {
                let detail = format!("无法创建吞吐测试线程: {e}");
                return Ok((Measurement::Failed(detail), Vec::new()));
            }
        };
        let mut loaded = Vec::new();
        while !task.is_finished() && loaded.len() < budget && !probe.cancel.is_cancelled() {
            if let Some(ttfb) = probe.health(via).ok_ttfb() {
                loaded.push(ttfb);
            }
            probe.cancel.sleep(LOADED_PAUSE);
        }
        let measurement = task.join().map_err(|_| Error::msg("吞吐测试失败"))?;
        Ok((measurement, loaded))
    })
}

#[cfg(test)]
mod tests;
