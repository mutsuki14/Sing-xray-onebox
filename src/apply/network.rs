//! The node's network rules: the `proxy` firewall owner (public ports of
//! the configuration), the temporary `acme` owner (TCP 80 while
//! certificates are prepared) and the Hysteria2 hop redirects.
//!
//! [`apply_rules`] is what apply-network, rollback and boot share (rules
//! only: units and persistence are the stages' business). [`clear_owner`]
//! and [`clear_hops`] are rollback-stop's half: they remove everything they
//! can and return what they could not, so the caller can surface it and
//! [`carry_over`] the leftovers into the ledgers the snapshot restores (a
//! rule nobody records would stay open forever on ufw/firewalld, whose
//! rules persist; a redirect nobody records could shadow the restored hop
//! until the next reboot).
//!
//! Changes from v2: a rule that cannot be removed (stopped firewalld,
//! disabled ufw, broken nft) no longer aborts a rollback — the node is
//! brought back and the leftover is reported, kept recorded and retired by
//! the next reconcile or hop change (which fails rather than let a leftover
//! redirect shadow the hop it installs); only ledger and lock problems are
//! errors, and each owner and the hops are cleared independently.

use crate::ctx::Ctx;
use crate::domain::config::{SubscriptionMode, WebCert};
use crate::domain::defaults::HTTP_PORT;
use crate::domain::ports::{proxy_http01_responder, PortPlan};
use crate::domain::protocol::{Protocol, Transport};
use crate::domain::NodeConfig;
use crate::error::Result;
use crate::host::firewall::{self, ledger_path, lock_waiting, Entry, Ledger};
use crate::host::hop::{self, Hop};
use crate::sys::fs::atomic_write;
use std::time::Duration;

/// Firewall owner of the node's public ports (`firewall-v2.json`).
pub const PROXY_OWNER: &str = "proxy";
/// Temporary owner of TCP 80 during certificate preparation.
pub const ACME_OWNER: &str = "acme";

/// Firewall rules and hops for `cfg`. Rules that could not be removed are
/// already printed as warnings by the firewall layer and retried next time.
pub fn apply_rules(ctx: &Ctx, cfg: &NodeConfig) -> Result<()> {
    let ports = PortPlan::of(cfg, &[]).firewall_ports();
    firewall::reconcile_owner(ctx, PROXY_OWNER, &ports)?;
    apply_hops(ctx, cfg)
}

/// Install the configured hop range, or remove recorded hops when there is
/// none.
fn apply_hops(ctx: &Ctx, cfg: &NodeConfig) -> Result<()> {
    let target = cfg.inbound(Protocol::Hysteria2).map(|i| i.port);
    match (cfg.hy2.hop, target) {
        (Some(range), Some(port)) => hop::apply(ctx, range, port),
        _ => hop::clear(ctx).map(drop),
    }
}

/// Whether `cfg` makes Onebox answer HTTP-01 challenges on TCP 80 (proxy
/// certificate over HTTP-01, the site's HTTP-01 certificate, or the
/// standalone subscription's port-80 server): the temporary `acme` owner
/// opens it while certificates are prepared (v2 `acme_http`).
pub fn needs_http01_port80(cfg: &NodeConfig) -> bool {
    let site = cfg.site_active().is_some_and(|s| s.cert == WebCert::Http01);
    let subscription = cfg.subscription.as_ref().is_some_and(|s| {
        matches!(
            s.mode,
            SubscriptionMode::Standalone {
                http01_port80: true,
                ..
            }
        )
    });
    site || subscription || proxy_http01_responder(cfg).is_some()
}

/// Open TCP 80 for the `acme` owner.
pub fn open_acme_port(ctx: &Ctx) -> Result<()> {
    let wanted = [(HTTP_PORT, HTTP_PORT, Transport::Tcp)];
    firewall::reconcile_owner(ctx, ACME_OWNER, &wanted).map(drop)
}

/// Remove the `acme` owner's rules; what could not be removed is returned
/// (and was printed as a warning).
pub fn clear_acme(ctx: &Ctx) -> Result<Vec<String>> {
    Ok(firewall::clear_owner(ctx, ACME_OWNER)?.failed)
}

/// What rollback-stop could not remove.
#[derive(Debug, Default)]
pub struct Leftovers {
    /// Recorded rules per owner that are still live (ledger entries).
    pub firewall: Vec<(&'static str, Vec<Entry>)>,
    /// Hop redirects that are still live (hop ledger records).
    pub hops: Vec<Hop>,
    /// Human-readable descriptions of everything left (warnings).
    pub messages: Vec<String>,
}

impl Leftovers {
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }
}

/// Remove every rule of `owner` (`acme` or `proxy`); rules that could not
/// be removed are added to `left`. Errors are ledger and lock problems.
pub fn clear_owner(ctx: &Ctx, owner: &'static str, left: &mut Leftovers) -> Result<()> {
    let report = firewall::clear_owner(ctx, owner)?;
    if report.failed.is_empty() {
        return Ok(());
    }
    let ledger = Ledger::load(&ledger_path(&ctx.paths, owner), owner)?;
    left.firewall.push((owner, ledger.entries));
    left.messages.extend(report.failed);
    Ok(())
}

/// Remove every hop redirect; the ones that could not be removed (what the
/// hop ledger still records afterwards) are added to `left`.
pub fn clear_hops(ctx: &Ctx, left: &mut Leftovers) -> Result<()> {
    let report = hop::clear(ctx)?;
    if report.failed.is_empty() {
        return Ok(());
    }
    left.hops.extend(hop::recorded(ctx)?);
    left.messages.extend(report.failed);
    Ok(())
}

/// After the snapshot put the old ledgers back: record the rules and hops
/// that could not be removed in them again, so the next reconcile, hop
/// change or clear retries (or refuses to install a hop they would shadow)
/// instead of forgetting a live rule.
pub fn carry_over(ctx: &Ctx, left: &Leftovers) -> Result<()> {
    for (owner, entries) in &left.firewall {
        let mut ledger = Ledger::load(&ledger_path(&ctx.paths, owner), owner)?;
        let fresh: Vec<Entry> = entries
            .iter()
            .filter(|e| !ledger.entries.iter().any(|k| k.rule.token == e.rule.token))
            .cloned()
            .collect();
        if fresh.is_empty() {
            continue;
        }
        ledger.entries.extend(fresh);
        ledger.save()?;
    }
    carry_over_hops(ctx, &left.hops)
}

/// Contention message of the hop ledger lock (`host::hop`'s own text).
const HOP_LOCK_BUSY: &str = "另一个端口跳跃操作正在进行；稍后重试";
const HOP_LOCK_WAIT: Duration = Duration::from_secs(30);

/// Append the `hops` the restored hop ledger does not record yet:
/// `hop::apply` retires every record present before it runs (failing when
/// one it cannot remove would shadow the new hop), `hop::clear` attempts
/// them all. Written like `host::hop` writes it (compact JSON array of
/// [`Hop`], 0600, under `hop-v2.lock`).
fn carry_over_hops(ctx: &Ctx, hops: &[Hop]) -> Result<()> {
    if hops.is_empty() {
        return Ok(());
    }
    let path = hop::ledger_path(ctx);
    let _lock = lock_waiting(&path.with_extension("lock"), HOP_LOCK_BUSY, HOP_LOCK_WAIT)?;
    let mut all = hop::recorded(ctx)?;
    let fresh: Vec<Hop> = hops
        .iter()
        .filter(|h| !all.iter().any(|r| r.token == h.token))
        .cloned()
        .collect();
    if fresh.is_empty() {
        return Ok(());
    }
    all.extend(fresh);
    atomic_write(&path, &serde_json::to_vec(&all)?, 0o600)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::config::{AcmeMethod, ProxyCertMode, ProxyTls};
    use crate::domain::fixtures::{self, standalone_subscription, with_site};
    use crate::domain::protocol::Core;

    fn base() -> NodeConfig {
        fixtures::config(&[(Protocol::VlessReality, 443, Core::Singbox)])
    }

    #[test]
    fn http01_port80_follows_every_http01_user() {
        assert!(!needs_http01_port80(&base()));
        let site = with_site(base(), "example.com", false);
        assert!(needs_http01_port80(&site));
        let mut cf_site = site.clone();
        if let Some(s) = cf_site.site.as_mut() {
            s.cert = WebCert::Cloudflare;
        }
        assert!(!needs_http01_port80(&cf_site));
        let mut sub = base();
        sub.subscription = Some(standalone_subscription(
            "sub.example.com",
            8448,
            WebCert::Http01,
        ));
        assert!(needs_http01_port80(&sub));
        sub.subscription = Some(standalone_subscription(
            "sub.example.com",
            8448,
            WebCert::Cloudflare,
        ));
        assert!(!needs_http01_port80(&sub));
        let mut proxy = fixtures::config(&[(Protocol::Trojan, 8443, Core::Singbox)]);
        proxy.tls = Some(ProxyTls {
            mode: ProxyCertMode::Acme {
                domain: "proxy.example.com".into(),
                method: AcmeMethod::Http01,
            },
            pinned: false,
        });
        assert!(needs_http01_port80(&proxy));
        if let Some(tls) = proxy.tls.as_mut() {
            tls.mode = ProxyCertMode::Acme {
                domain: "proxy.example.com".into(),
                method: AcmeMethod::Cloudflare,
            };
        }
        assert!(!needs_http01_port80(&proxy));
    }
}
