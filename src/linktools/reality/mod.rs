//! `reality-check`: for every REALITY entry, (A) an ordinary TLS 1.3
//! probe of the node compared with the reference site (certificate, ALPN,
//! HTTP status, redirect, first 64 KiB of `/`), and (B) an authenticated
//! proxy request plus the same request with a wrong short ID, which must
//! be rejected — counted only when the valid credential reached the same
//! origin (spec D §2.6). Without a bundle the node is checked from the
//! server itself (`server-local`: loopback address, handshake target as
//! the reference, the node's own cores in `/opt/onebox/bin` first).
//!
//! Check keys, warnings, note and exit codes (0 pass, 1 fail or no REALITY
//! entry, 2 warnings only, 130 cancelled) are v2's.
//!
//! Changes from v2:
//! - `ordinary_h2 = false` is a warning, not a failure: a reference site
//!   without h2 made every check fail although node and reference agreed;
//!   `same_alpn` still fails a mismatch (D-8.1#18);
//! - the real causes of a failed block are listed in a new `errors` key
//!   (absent when empty, D-8.1#8);
//! - Ctrl+C before the first REALITY entry exits 130 (D-8.1#17); the scope
//!   rules are in `options` (D-8.1#14/#15).

pub mod tls;

use super::bundle::{self, Selection};
use super::cancel::{CancelToken, SignalCancel};
use super::core_client::{CoreLauncher, Launcher, Timing};
use super::http_probe::{measure, safe_measure, HttpRequest, HttpResult, Route};
use super::options::RealityOptions;
use super::report::{conclude, publish, Outcome, Report, Tool, REALITY_NOTE};
use super::url::TestUrl;
use crate::ctx::Ctx;
use crate::domain::protocol::Core;
use crate::error::{Error, Result};
use crate::render::probe::{ProbeEntry, RealityProbe};
use crate::sys::rand::{OsRandom, Random};
use crate::ui::out;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::time::Duration;

/// Body bytes compared between node and reference (v2).
const COMPARED_BYTES: u64 = 65_536;
pub const TLS13_VALID: &str = "ordinary_tls13_valid_certificate";
pub const H2: &str = "ordinary_h2";
pub const SAME_CERTIFICATE: &str = "same_certificate";
pub const SAME_ALPN: &str = "same_alpn";
pub const SAME_STATUS: &str = "same_http_status";
pub const SAME_REDIRECT: &str = "same_redirect";
pub const PROBE_COMPLETED: &str = "ordinary_or_reference_probe";
pub const AUTHENTICATED: &str = "authenticated_proxy";
pub const WRONG_REJECTED: &str = "wrong_short_id_rejected";
pub const AUTH_COMPLETED: &str = "authentication_test_completed";

pub const PROBE_FAILED: &str = "TLS 或参考站点探测失败；检查地址、CA 和可达性";
pub const BODY_DIFFERS: &str = "前 64 KiB 内容不同；动态页面可能正常，需核对有无特有错误页";
pub const NO_REFERENCE: &str = "自建站未开放可比较的 HTTPS 入口；可在服务器执行本地检查";
pub const NO_H2: &str = "普通 TLS 未协商 h2；参考站点同样不支持时可忽略";
pub const LOCAL_NOTICE: &str = "本机回环检查；完整公网路径请在客户端使用 probe export 的配置。";

/// One entry's result.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct RealityRow {
    pub checks: BTreeMap<&'static str, bool>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
    pub id: String,
    pub warnings: Vec<String>,
}

impl RealityRow {
    /// Any check false, except the informational `ordinary_h2`.
    pub fn failed(&self) -> bool {
        self.checks.iter().any(|(key, ok)| !ok && *key != H2)
    }
}

/// `onebox reality-check`.
pub fn run(ctx: &Ctx, opts: &RealityOptions) -> Result<()> {
    let bundle = match opts.common.bundle.as_deref() {
        Some(path) => bundle::load(path)?,
        None => {
            out::info(LOCAL_NOTICE);
            bundle::from_node(ctx, true)?
        }
    };
    let entries = bundle::select(&bundle, opts.common.entries.as_deref(), Selection::All)?;
    let signals = SignalCancel::install()?;
    let cancel = signals.token();
    let launcher = CoreLauncher {
        ctx,
        binaries: &opts.common.binaries,
        cancel,
        timing: Timing::default(),
    };
    let checker = Checker {
        ctx,
        launcher: &launcher,
        opts,
        cancel,
    };
    let (report, outcome) = checker.check_all(&entries, &mut OsRandom)?;
    let published = report
        .text()
        .and_then(|t| publish(&t, opts.output.as_deref()));
    conclude(Tool::Reality, outcome, published)
}

/// A copy of `entry` whose REALITY short ID is replaced by 16 random hex
/// characters guaranteed to differ from the original.
pub fn wrong_short_id(entry: &ProbeEntry, rng: &mut dyn Random) -> Result<ProbeEntry> {
    let mut wrong = entry.clone();
    let pointer = match entry.core {
        Core::Singbox => "/tls/reality/short_id",
        Core::Xray => "/streamSettings/realitySettings/shortId",
    };
    let target = wrong
        .outbounds
        .first_mut()
        .and_then(|o| o.pointer_mut(pointer))
        .ok_or_else(|| Error::msg("REALITY 出站缺少 short ID"))?;
    let old = target
        .as_str()
        .ok_or_else(|| Error::msg("REALITY short ID 类型无效"))?
        .to_owned();
    let mut next = rng.hex(8)?;
    while next == old {
        next = rng.hex(8)?;
    }
    *target = Value::String(next);
    Ok(wrong)
}

/// Everything one run needs.
pub struct Checker<'a> {
    pub ctx: &'a Ctx,
    pub launcher: &'a dyn Launcher,
    pub opts: &'a RealityOptions,
    pub cancel: &'a CancelToken,
}

impl Checker<'_> {
    /// Check every REALITY entry in order (others are skipped).
    pub fn check_all(
        &self,
        entries: &[&ProbeEntry],
        rng: &mut dyn Random,
    ) -> Result<(Report<RealityRow>, Outcome)> {
        let mut rows = Vec::new();
        for entry in entries {
            if self.cancel.is_cancelled() {
                break;
            }
            if let Some(meta) = &entry.reality {
                rows.push(self.check(entry, meta, rng));
            }
        }
        let cancelled = self.cancel.is_cancelled();
        ensure!(cancelled || !rows.is_empty(), "配置中没有 REALITY 入口");
        let outcome = Outcome {
            cancelled,
            failed: rows.iter().any(RealityRow::failed),
            warned: rows.iter().any(|r| !r.warnings.is_empty()),
        };
        let scope = self.opts.scope.id();
        Ok((Report::new(scope, REALITY_NOTE, rows, cancelled), outcome))
    }

    fn check(&self, entry: &ProbeEntry, meta: &RealityProbe, rng: &mut dyn Random) -> RealityRow {
        let mut row = RealityRow {
            id: entry.id.clone(),
            ..RealityRow::default()
        };
        if let Err(e) = self.ordinary(meta, &mut row) {
            row.checks.insert(PROBE_COMPLETED, false);
            row.warnings.push(PROBE_FAILED.to_owned());
            row.errors.push(format!("普通 TLS 或参考站点探测: {e}"));
        }
        if row.checks.get(H2) == Some(&false) {
            row.warnings.push(NO_H2.to_owned());
        }
        if let Err(e) = self.authentication(entry, rng, &mut row) {
            row.checks.insert(AUTH_COMPLETED, false);
            row.errors.push(format!("认证测试: {e}"));
        }
        row
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(self.opts.common.timeout)
    }

    /// Block A: the node and the reference as an ordinary TLS client sees
    /// them. Checks inserted before an error stay.
    fn ordinary(&self, meta: &RealityProbe, row: &mut RealityRow) -> Result<()> {
        let ca = self.opts.common.ca.as_deref();
        let node_target = (meta.host.as_str(), meta.port, meta.sni.as_str());
        let node = tls::probe(self.ctx, node_target, ca, self.timeout(), self.cancel)?;
        row.checks.insert(TLS13_VALID, true);
        row.checks.insert(H2, node.alpn.as_deref() == Some("h2"));
        if meta.reference_host.is_empty() {
            row.warnings.push(NO_REFERENCE.to_owned());
            return Ok(());
        }
        ensure!(meta.reference_port != 0, "REALITY 参考端口无效");
        let reference_target = (
            meta.reference_host.as_str(),
            meta.reference_port,
            meta.sni.as_str(),
        );
        let reference = tls::probe(self.ctx, reference_target, ca, self.timeout(), self.cancel)?;
        row.checks.insert(
            SAME_CERTIFICATE,
            node.certificate_sha256 == reference.certificate_sha256,
        );
        row.checks.insert(SAME_ALPN, node.alpn == reference.alpn);
        let url = TestUrl::parse(&format!("https://{}/", meta.sni))?;
        let node_page = self.fetch(&url, &meta.host, meta.port)?;
        let reference_page = self.fetch(&url, &meta.reference_host, meta.reference_port)?;
        row.checks
            .insert(SAME_STATUS, node_page.status == reference_page.status);
        row.checks
            .insert(SAME_REDIRECT, node_page.location == reference_page.location);
        if node_page.body_sha256 != reference_page.body_sha256 {
            row.warnings.push(BODY_DIFFERS.to_owned());
        }
        Ok(())
    }

    /// `GET url` straight to `host:port` (first 64 KiB).
    fn fetch(&self, url: &TestUrl, host: &str, port: u16) -> Result<HttpResult> {
        let req = HttpRequest {
            url,
            route: Route::Direct {
                connect_to: Some((host, port)),
            },
            timeout_secs: self.opts.common.timeout,
            ca: self.opts.common.ca.as_deref(),
            limit: COMPARED_BYTES,
            upload: 0,
        };
        measure(self.ctx, &req, self.cancel)
    }

    /// One health request through a fresh core for `entry`.
    fn proxied_ok(&self, entry: &ProbeEntry) -> Result<bool> {
        let core = self.launcher.launch(entry)?;
        let req = HttpRequest {
            url: &self.opts.common.url,
            route: Route::Proxy(core.endpoint()),
            timeout_secs: self.opts.common.timeout,
            ca: self.opts.common.ca.as_deref(),
            limit: 0,
            upload: 0,
        };
        Ok(safe_measure(self.ctx, &req, self.cancel).ok())
    }

    /// Block B: the valid credential must work and a wrong short ID must
    /// not, against the same origin.
    fn authentication(
        &self,
        entry: &ProbeEntry,
        rng: &mut dyn Random,
        row: &mut RealityRow,
    ) -> Result<()> {
        let positive = self.proxied_ok(entry)?;
        row.checks.insert(AUTHENTICATED, positive);
        let wrong = wrong_short_id(entry, rng)?;
        let rejected = !self.proxied_ok(&wrong)?;
        row.checks.insert(WRONG_REJECTED, positive && rejected);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
