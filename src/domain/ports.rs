//! `PortPlan`: the single authority for port reservation, conflicts and
//! allocation.
//!
//! Every listener a configuration implies (proxy inbounds, website, REALITY
//! guard, subscription endpoint, HTTP-01 challenges, Hysteria2 hop range) plus
//! FRP reservations is one [`Listener`]. Conflict checks, auto-allocation and
//! the firewall's public port list are all derived from that one inventory.
//!
//! Changes from v2 (which had four divergent implementations: `cli`
//! `port_available`, the guard search, `workflow::validate_ports` and
//! `network::desired_ports`, spec B §9.1 #1/#2/#5):
//! - one set of defaults (site internal port and subscription port come from
//!   the config, never from per-module fallbacks);
//! - auto-allocation avoids every reserved listener, including the hop range,
//!   ACME port 80, the guard, the site, the subscription and FRP;
//! - HTTP-01 for the proxy certificate always reserves and opens TCP 80
//!   (v2 opened it only for the literal method `standalone`, E-8.1 #4);
//! - port 80 may be shared by HTTP-01 challenge servers (the site's or the
//!   standalone subscription's nginx serves proxy challenges too).

use super::config::{AcmeMethod, NodeConfig, ProxyCertMode, SubscriptionMode};
use super::defaults;
use super::protocol::{Core, Protocol, Transport};
use crate::error::Result;
use serde::{Deserialize, Serialize};

/// Who holds a listener.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Owner {
    Inbound(Protocol),
    SiteHttp80,
    /// nginx HTTPS front-end on 443 (absent when a REALITY inbound holds 443).
    SiteHttps443,
    /// Loopback HTTPS listener the REALITY inbounds forward browsers to.
    SiteInternal,
    RealityGuard,
    /// IP-mode worker or standalone HTTPS endpoint.
    SubscriptionPort,
    SubscriptionHttp80,
    /// HTTP-01 challenges for the proxy certificate.
    AcmeHttp80,
    Hy2Hop,
    Frp(String),
}

impl Owner {
    /// Chinese label for messages.
    pub fn label(&self) -> String {
        match self {
            Owner::Inbound(p) => p.title().to_owned(),
            Owner::SiteHttp80 => "网站 HTTP".into(),
            Owner::SiteHttps443 => "网站 HTTPS 入口".into(),
            Owner::SiteInternal => "网站内部 HTTPS".into(),
            Owner::RealityGuard => "REALITY guard".into(),
            Owner::SubscriptionPort => "远程订阅".into(),
            Owner::SubscriptionHttp80 => "订阅 HTTP-01 验证".into(),
            Owner::AcmeHttp80 => "代理证书 HTTP-01 验证".into(),
            Owner::Hy2Hop => "Hysteria2 端口跳跃".into(),
            Owner::Frp(label) => format!("FRP {label}"),
        }
    }

    /// Reachable from the internet, so the firewall must open it.
    fn is_public(&self) -> bool {
        !matches!(
            self,
            Owner::SiteInternal | Owner::RealityGuard | Owner::Frp(_)
        )
    }

    /// A process of the node binds this listener while the node runs. The
    /// hop range is a netfilter REDIRECT and the proxy's HTTP-01 responder
    /// only runs during issuance, so a live socket inside either belongs to
    /// someone else. FRP sockets belong to the independent FRP server.
    fn holds_socket(&self) -> bool {
        !matches!(self, Owner::Hy2Hop | Owner::AcmeHttp80 | Owner::Frp(_))
    }

    /// The apply engine stops this listener's process (cores, site nginx,
    /// subscription nginx) before the new generation starts, so its socket is
    /// not foreign. The subscription port is excluded: the IP-mode worker
    /// keeps running.
    fn released_by_apply(&self) -> bool {
        self.holds_socket() && *self != Owner::SubscriptionPort
    }
}

/// An inclusive port range held by one owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listener {
    pub owner: Owner,
    pub transport: Transport,
    pub start: u16,
    pub end: u16,
}

impl Listener {
    fn single(owner: Owner, transport: Transport, port: u16) -> Self {
        Listener {
            owner,
            transport,
            start: port,
            end: port,
        }
    }

    fn covers(&self, port: u16, transport: Transport) -> bool {
        (self.start..=self.end).contains(&port) && self.transport.overlaps(transport)
    }

    /// First shared port and whether the clash is on UDP (TCP preferred).
    fn overlap(&self, other: &Listener) -> Option<(u16, bool)> {
        if self.start > other.end || other.start > self.end {
            return None;
        }
        let port = self.start.max(other.start);
        if self.transport.tcp() && other.transport.tcp() {
            Some((port, false))
        } else if self.transport.udp() && other.transport.udp() {
            Some((port, true))
        } else {
            None
        }
    }
}

/// A port range reserved by the independent FRP server.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reservation {
    pub start: u16,
    pub end: u16,
    pub transport: Transport,
    pub label: String,
}

/// Live socket inventory (e.g. `/proc/net/*`).
pub trait PortProbe {
    /// Whether a foreign or old socket holds `port`. Called with
    /// `Transport::Tcp` or `Transport::Udp` only.
    fn in_use(&self, port: u16, transport: Transport) -> bool;
}

/// Nothing is in use (tests, dry runs, pure migration).
pub struct NoProbe;

impl PortProbe for NoProbe {
    fn in_use(&self, _port: u16, _transport: Transport) -> bool {
        false
    }
}

/// Adapter for closures `Fn(port, transport) -> bool`.
pub struct FnProbe<F>(pub F);

impl<F: Fn(u16, Transport) -> bool> PortProbe for FnProbe<F> {
    fn in_use(&self, port: u16, transport: Transport) -> bool {
        (self.0)(port, transport)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PortPlan {
    listeners: Vec<Listener>,
    /// Cores of the configured inbounds (the shared-port exception needs them).
    cores: Vec<(Protocol, Core)>,
    /// Xray hosts REALITY but no guard port is configured.
    guard_missing: bool,
    /// Hysteria2 hop range below 1024 or not increasing.
    hop_invalid: bool,
}

impl PortPlan {
    /// Every listener `cfg` implies plus the FRP reservations. Inbounds with
    /// port 0 (not yet allocated by a planner) are skipped.
    pub fn of(cfg: &NodeConfig, frp: &[Reservation]) -> PortPlan {
        let mut plan = PortPlan::default();
        for inbound in cfg.inbounds.iter().filter(|i| i.port != 0) {
            let owner = Owner::Inbound(inbound.protocol);
            plan.push(owner, inbound.protocol.transport(), inbound.port);
        }
        plan.cores = cfg.inbounds.iter().map(|i| (i.protocol, i.core)).collect();
        plan.add_hop(cfg);
        plan.add_site(cfg);
        if cfg.uses_guard() {
            match cfg.reality.guard_port {
                0 => plan.guard_missing = true,
                port => plan.push(Owner::RealityGuard, Transport::Tcp, port),
            }
        }
        plan.add_subscription(cfg);
        if acme_http01(cfg) {
            plan.push(Owner::AcmeHttp80, Transport::Tcp, defaults::HTTP_PORT);
        }
        for r in frp.iter().filter(|r| r.start != 0 && r.start <= r.end) {
            plan.listeners.push(Listener {
                owner: Owner::Frp(r.label.clone()),
                transport: r.transport,
                start: r.start,
                end: r.end,
            });
        }
        plan
    }

    fn push(&mut self, owner: Owner, transport: Transport, port: u16) {
        self.listeners
            .push(Listener::single(owner, transport, port));
    }

    fn add_hop(&mut self, cfg: &NodeConfig) {
        let Some(hop) = cfg.hy2.hop.filter(|_| cfg.has(Protocol::Hysteria2)) else {
            return;
        };
        if hop.start < defaults::HOP_MIN_START || hop.start >= hop.end {
            self.hop_invalid = true;
            return;
        }
        self.listeners.push(Listener {
            owner: Owner::Hy2Hop,
            transport: Transport::Udp,
            start: hop.start,
            end: hop.end,
        });
    }

    fn add_site(&mut self, cfg: &NodeConfig) {
        let Some(site) = cfg.site_active() else {
            return;
        };
        self.push(Owner::SiteHttp80, Transport::Tcp, defaults::HTTP_PORT);
        if site.https_entry && !cfg.reality_on_443() {
            self.push(Owner::SiteHttps443, Transport::Tcp, defaults::HTTPS_PORT);
        }
        self.push(Owner::SiteInternal, Transport::Tcp, site.internal_port);
    }

    fn add_subscription(&mut self, cfg: &NodeConfig) {
        let Some(sub) = cfg.subscription.as_ref().filter(|s| s.port != 0) else {
            return;
        };
        match &sub.mode {
            SubscriptionMode::Site => {}
            SubscriptionMode::Ip { .. } => {
                self.push(Owner::SubscriptionPort, Transport::Tcp, sub.port);
            }
            SubscriptionMode::Standalone { http01_port80, .. } => {
                self.push(Owner::SubscriptionPort, Transport::Tcp, sub.port);
                if *http01_port80 {
                    let port = defaults::HTTP_PORT;
                    self.push(Owner::SubscriptionHttp80, Transport::Tcp, port);
                }
            }
        }
    }

    pub fn listeners(&self) -> &[Listener] {
        &self.listeners
    }

    fn core_for(&self, owner: &Owner) -> Option<Core> {
        match owner {
            Owner::Inbound(p) => self.cores.iter().find(|(x, _)| x == p).map(|(_, c)| *c),
            _ => None,
        }
    }

    /// All hard conflicts, with v2 messages (spec B §4.3, F §4.7, G §5.1.2).
    pub fn validate(&self) -> Result<()> {
        ensure!(!self.hop_invalid, "跳跃端口范围无效");
        ensure!(!self.guard_missing, "REALITY guard 端口缺失或与代理冲突");
        for (i, a) in self.listeners.iter().enumerate() {
            for b in &self.listeners[i + 1..] {
                let Some((port, udp)) = a.overlap(b) else {
                    continue;
                };
                let (ca, cb) = (self.core_for(&a.owner), self.core_for(&b.owner));
                if !compatible(&a.owner, ca, &b.owner, cb) {
                    return Err(conflict_message(&a.owner, &b.owner, port, udp).into());
                }
            }
        }
        Ok(())
    }

    /// Whether `for_owner` may bind `port` on `transport`: no other listener of
    /// this plan holds it (allowed sharing aside) and the probe reports no
    /// socket, except sockets the previous generation held that the apply
    /// releases (same owner, or cores/site/subscription nginx).
    pub fn is_free(
        &self,
        port: u16,
        transport: Transport,
        for_owner: &Owner,
        probe: &dyn PortProbe,
        previous: Option<&PortPlan>,
    ) -> bool {
        let core = self.core_for(for_owner);
        self.free_for(port, transport, for_owner, core, probe, previous)
    }

    fn free_for(
        &self,
        port: u16,
        transport: Transport,
        owner: &Owner,
        core: Option<Core>,
        probe: &dyn PortProbe,
        previous: Option<&PortPlan>,
    ) -> bool {
        if port == 0 {
            return false;
        }
        let candidate = Listener::single(owner.clone(), transport, port);
        let reserved = self.listeners.iter().any(|l| {
            l.owner != *owner
                && l.overlap(&candidate).is_some()
                && !compatible(&l.owner, self.core_for(&l.owner), owner, core)
        });
        !reserved && !probed_in_use(port, transport, owner, probe, previous)
    }

    /// First free port for a new inbound: the protocol's candidates, then
    /// 20000–20999 (`未找到空闲端口`).
    pub fn allocate(
        &self,
        protocol: Protocol,
        core: Core,
        probe: &dyn PortProbe,
        previous: Option<&PortPlan>,
    ) -> Result<u16> {
        let owner = Owner::Inbound(protocol);
        defaults::port_candidates(protocol)
            .iter()
            .copied()
            .chain(defaults::FALLBACK_PORTS)
            .find(|p| {
                self.free_for(
                    *p,
                    protocol.transport(),
                    &owner,
                    Some(core),
                    probe,
                    previous,
                )
            })
            .ok_or_else(|| "未找到空闲端口".into())
    }

    /// First free TCP port in 18000–19999 for the Xray REALITY guard.
    pub fn allocate_guard(
        &self,
        probe: &dyn PortProbe,
        previous: Option<&PortPlan>,
    ) -> Result<u16> {
        let owner = Owner::RealityGuard;
        let mut ports = defaults::GUARD_PORTS;
        ports
            .find(|p| self.free_for(*p, Transport::Tcp, &owner, None, probe, previous))
            .ok_or_else(|| "没有空闲的 REALITY guard 端口".into())
    }

    /// Public ports to open, per transport (`Tcp`/`Udp`), contiguous and
    /// overlapping ranges merged, TCP first, each list ascending.
    pub fn firewall_ports(&self) -> Vec<(u16, u16, Transport)> {
        let mut tcp = Vec::new();
        let mut udp = Vec::new();
        for l in self.listeners.iter().filter(|l| l.owner.is_public()) {
            if l.transport.tcp() {
                tcp.push((l.start, l.end));
            }
            if l.transport.udp() {
                udp.push((l.start, l.end));
            }
        }
        let tag = |t| move |(s, e)| (s, e, t);
        merge(tcp)
            .into_iter()
            .map(tag(Transport::Tcp))
            .chain(merge(udp).into_iter().map(tag(Transport::Udp)))
            .collect()
    }
}

/// The proxy certificate is issued over HTTP-01 and therefore needs TCP 80.
fn acme_http01(cfg: &NodeConfig) -> bool {
    cfg.needs_cert()
        && matches!(
            cfg.tls.as_ref().map(|t| &t.mode),
            Some(ProxyCertMode::Acme {
                method: AcmeMethod::Http01,
                ..
            })
        )
}

fn probed_in_use(
    port: u16,
    transport: Transport,
    owner: &Owner,
    probe: &dyn PortProbe,
    previous: Option<&PortPlan>,
) -> bool {
    [Transport::Tcp, Transport::Udp]
        .into_iter()
        .filter(|t| transport.overlaps(*t))
        .any(|t| probe.in_use(port, t) && !held_by_previous(previous, owner, port, t))
}

/// A live socket on `port` is ours when the previous generation had a
/// socket-holding listener there that is either the same owner or stopped by
/// the apply. Listeners without a socket (hop range, HTTP-01 responder) never
/// excuse a probed socket.
fn held_by_previous(previous: Option<&PortPlan>, owner: &Owner, port: u16, t: Transport) -> bool {
    previous.is_some_and(|prev| {
        prev.listeners.iter().any(|l| {
            l.covers(port, t)
                && l.owner.holds_socket()
                && (l.owner == *owner || l.owner.released_by_apply())
        })
    })
}

/// Pairs that may legitimately share a port.
fn compatible(a: &Owner, a_core: Option<Core>, b: &Owner, b_core: Option<Core>) -> bool {
    use Owner::*;
    match (a, b) {
        (Frp(_), Frp(_)) => true,
        // Xray serves Vision and XHTTP on one TCP port (XHTTP via fallback).
        (Inbound(x), Inbound(y)) => {
            matches!(
                (x, y),
                (Protocol::VlessReality, Protocol::VlessXhttp)
                    | (Protocol::VlessXhttp, Protocol::VlessReality)
            ) && a_core == Some(Core::Xray)
                && b_core == Some(Core::Xray)
        }
        // A REALITY inbound on 443 replaces the nginx HTTPS front-end.
        (Inbound(p), SiteHttps443) | (SiteHttps443, Inbound(p)) => p.reality(),
        // The hop range redirects to the Hysteria2 port itself.
        (Inbound(Protocol::Hysteria2), Hy2Hop) | (Hy2Hop, Inbound(Protocol::Hysteria2)) => true,
        // HTTP-01 challenge servers share 80 (one nginx serves both webroots).
        (AcmeHttp80, SiteHttp80 | SubscriptionHttp80)
        | (SiteHttp80 | SubscriptionHttp80, AcmeHttp80) => true,
        _ => false,
    }
}

fn conflict_message(a: &Owner, b: &Owner, port: u16, udp: bool) -> String {
    let t = if udp { "udp" } else { "tcp" };
    directed_message(a, b, port, t)
        .or_else(|| directed_message(b, a, port, t))
        .unwrap_or_else(|| format!("端口 {port}/{t} 冲突: {} 与 {}", a.label(), b.label()))
}

fn directed_message(x: &Owner, y: &Owner, port: u16, t: &str) -> Option<String> {
    use Owner::*;
    let text = match (x, y) {
        (Frp(_), _) => format!("端口 {port}/{t} 已保留给 FRP"),
        (Inbound(_), Inbound(_)) => format!("协议重复使用 {port}/{t}"),
        (Hy2Hop, Inbound(p)) => format!("Hysteria2 跳跃范围与 {p} UDP 端口冲突"),
        (RealityGuard, Inbound(_)) => "REALITY guard 端口缺失或与代理冲突".into(),
        (RealityGuard, SiteHttp80 | SiteHttps443 | SiteInternal) => {
            "REALITY guard 端口与网站监听冲突".into()
        }
        (RealityGuard, SubscriptionPort | SubscriptionHttp80) => {
            "REALITY guard 端口与订阅监听冲突".into()
        }
        (RealityGuard, AcmeHttp80) => "REALITY guard 端口与 HTTP-01 验证端口冲突".into(),
        (AcmeHttp80 | SubscriptionHttp80, Inbound(_)) => {
            "HTTP-01 验证需要保留 TCP 80，不能同时用于代理入站".into()
        }
        (SiteHttps443, Inbound(_)) => "TCP 443 被非 REALITY 协议占用".into(),
        (SiteHttp80 | SiteInternal, Inbound(_)) => "网站端口与代理协议冲突".into(),
        (SubscriptionPort, Inbound(_)) => "订阅或验证端口与代理端口冲突".into(),
        (SubscriptionPort | SubscriptionHttp80, SiteHttp80 | SiteHttps443 | SiteInternal) => {
            "订阅端口与自建站冲突：请复用网站，或为独立站选择其他端口和 DNS 验证".into()
        }
        (SubscriptionPort, SubscriptionHttp80 | AcmeHttp80) => {
            "HTTPS 订阅端口不能与 HTTP-01 验证端口 80 相同".into()
        }
        _ => return None,
    };
    Some(text)
}

/// Sort and merge overlapping or adjacent inclusive ranges.
fn merge(mut ranges: Vec<(u16, u16)>) -> Vec<(u16, u16)> {
    ranges.sort_unstable();
    let mut out: Vec<(u16, u16)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match out.last_mut() {
            Some(last) if start <= last.1.saturating_add(1) => last.1 = last.1.max(end),
            _ => out.push((start, end)),
        }
    }
    out
}

#[cfg(test)]
mod tests;
