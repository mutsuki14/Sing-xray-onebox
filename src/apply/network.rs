//! The node's network rules: the `proxy` firewall owner (public ports of
//! the configuration), the temporary `acme` owner (TCP 80 while
//! certificates are prepared) and the Hysteria2 hop redirects.
//!
//! [`apply_rules`] is what apply-network, rollback and boot share (rules
//! only: units and persistence are the stages' business). [`clear_rules`]
//! is rollback-stop's half: it removes everything it can and returns what
//! it could not, so the caller can surface it and carry unremovable
//! firewall rules over into the restored ledgers (a rule nobody records
//! would stay open forever on ufw/firewalld, whose rules persist).
//!
//! Changes from v2: a rule that cannot be removed (stopped firewalld,
//! disabled ufw, broken nft) no longer aborts a rollback — the node is
//! brought back and the leftover is reported and retried later; only ledger
//! and lock problems are errors.

use crate::ctx::Ctx;
use crate::domain::defaults::HTTP_PORT;
use crate::domain::ports::{proxy_http01_responder, PortPlan};
use crate::domain::protocol::{Protocol, Transport};
use crate::domain::config::{SubscriptionMode, WebCert};
use crate::domain::NodeConfig;
use crate::error::Result;
use crate::host::firewall::{self, ledger_path, Entry, Ledger};
use crate::host::hop;

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
    let site = cfg
        .site_active()
        .is_some_and(|s| s.cert == WebCert::Http01);
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

/// What [`clear_rules`] could not remove.
#[derive(Debug, Default)]
pub struct Leftovers {
    /// Recorded rules per owner that are still live (ledger entries).
    pub firewall: Vec<(&'static str, Vec<Entry>)>,
    /// Human-readable descriptions of everything left (warnings).
    pub messages: Vec<String>,
}

impl Leftovers {
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }
}

/// rollback-stop: remove the `acme` and `proxy` rules and every hop. Each
/// part is attempted; unremovable rules are returned, ledger or lock
/// problems are errors.
pub fn clear_rules(ctx: &Ctx) -> Result<Leftovers> {
    let mut left = Leftovers::default();
    for owner in [ACME_OWNER, PROXY_OWNER] {
        let report = firewall::clear_owner(ctx, owner)?;
        if report.failed.is_empty() {
            continue;
        }
        let ledger = Ledger::load(&ledger_path(&ctx.paths, owner), owner)?;
        left.firewall.push((owner, ledger.entries));
        left.messages.extend(report.failed);
    }
    left.messages.extend(hop::clear(ctx)?.failed);
    Ok(left)
}

/// After the snapshot put the old ledgers back: record the rules that could
/// not be removed in them again, so the next reconcile or clear retries
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
    Ok(())
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
        sub.subscription = Some(standalone_subscription("sub.example.com", 8448, WebCert::Http01));
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
