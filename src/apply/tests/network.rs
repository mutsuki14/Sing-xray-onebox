//! Network rules through applies and rollbacks: Hysteria2 hop ranges with
//! a certificate protocol end to end, the temporary `acme` owner for a
//! proxy ACME certificate, and hops or rules a rollback cannot remove.

use super::*;
use crate::apply::harness::{Fault, World};
use crate::domain::config::{AcmeMethod, PortRange, ProxyCertMode, ProxyTls};
use crate::domain::fixtures;
use crate::domain::ports::{proxy_http01_responder, Http01Responder};
use crate::domain::protocol::{Core, Protocol};
use crate::domain::NodeConfig;
use crate::host::cron::testing::lines;
use crate::host::hop;
use std::fs;

/// REALITY plus Hysteria2 (self-signed certificate) on `port`, hopping
/// from `range` when given.
fn hy2(port: u16, range: Option<(u16, u16)>) -> NodeConfig {
    let mut cfg = fixtures::config(&[
        (Protocol::VlessReality, 443, Core::Singbox),
        (Protocol::Hysteria2, port, Core::Singbox),
    ]);
    cfg.hy2.hop = range.map(|(start, end)| PortRange { start, end });
    cfg
}

/// The recorded hops as `(start, end, target)`.
fn recorded(host: &Host) -> Vec<(u16, u16, u16)> {
    hop::recorded(&host.ctx)
        .unwrap()
        .iter()
        .map(|h| (h.start, h.end, h.target))
        .collect()
}

/// The live nat redirects of the fake iptables.
fn redirects(host: &Host) -> Vec<String> {
    let rules = host.world().iptables;
    rules
        .into_iter()
        .filter(|r| r.starts_with("nat "))
        .collect()
}

/// The one live redirect, checked against the hop ledger's record.
fn only_redirect(host: &Host, range: &str, target: u16) {
    let live = redirects(host);
    let ledger = hop::recorded(&host.ctx).unwrap();
    assert_eq!(live.len(), 1, "{live:?}");
    assert_eq!(ledger.len(), 1, "{ledger:?}");
    let rule = &live[0];
    assert!(
        rule.contains(&format!("--dport {range} "))
            && rule.ends_with(&format!("--to-ports {target}"))
            && rule.contains(&format!("--comment {} ", ledger[0].token)),
        "{rule}"
    );
}

fn udp_open(host: &Host, span: &str) -> bool {
    let needle = format!("filter INPUT -p udp --dport {span} ");
    host.world().iptables.iter().any(|r| r.contains(&needle))
}

#[test]
fn hop_ranges_are_installed_changed_and_removed_with_the_node() {
    let host = Host::new();
    host.install(hy2(8443, Some((20000, 30000))));
    let paths = host.paths();
    // The certificate protocol rendered and checked with TLS material.
    assert!(paths.tls().join("cert.pem").is_file());
    let config = fs::read_to_string(paths.core_config(Core::Singbox)).unwrap();
    assert!(config.contains("cert.pem"), "{config}");
    assert_eq!(recorded(&host), [(20000, 30000, 8443)]);
    only_redirect(&host, "20000:30000", 8443);
    assert!(udp_open(&host, "20000:30000") && udp_open(&host, "8443"));

    host.apply(host.change(hy2(8443, Some((40000, 50000))), "修改跳跃"))
        .unwrap();
    assert_eq!(recorded(&host), [(40000, 50000, 8443)]);
    only_redirect(&host, "40000:50000", 8443);
    assert!(udp_open(&host, "40000:50000") && !udp_open(&host, "20000:30000"));

    host.apply(host.change(hy2(8443, None), "关闭跳跃"))
        .unwrap();
    assert_eq!(recorded(&host), []);
    assert_eq!(
        fs::read_to_string(hop::ledger_path(&host.ctx)).unwrap(),
        "[]"
    );
    assert_eq!(redirects(&host), Vec::<String>::new());
    assert!(!udp_open(&host, "40000:50000") && udp_open(&host, "8443"));
    assert_no_journal(&host);
    assert_invariants(&host);
}

/// `world` with hop tokens (random per installation) masked.
fn masked(world: World) -> World {
    let mask = |text: &str| -> String {
        let mut out = String::new();
        let mut rest = text;
        while let Some(i) = rest.find("onebox-hop-") {
            let end = i + "onebox-hop-".len();
            out.push_str(&rest[..end]);
            out.push('*');
            rest = rest[end..].trim_start_matches(|c: char| c.is_ascii_hexdigit());
        }
        out.push_str(rest);
        out
    };
    let mut world = world;
    world.iptables = world.iptables.iter().map(|r| mask(r)).collect();
    for (path, (_, content)) in world.files.iter_mut() {
        if path.ends_with("hop-v2.json") {
            if let Some(bytes) = content.as_mut() {
                *bytes = mask(&String::from_utf8_lossy(bytes)).into_bytes();
            }
        }
    }
    world
}

/// A fault after apply-network rolls the hop back to the old range. The
/// old range is installed again, so its record carries a new token
/// (`host::hop` always installs before it retires); everything else is
/// byte-identical.
#[test]
fn a_fault_after_apply_network_rolls_the_hops_back() {
    for point in [
        Phase::ApplyNetwork,
        Phase::StartCores,
        Phase::PublishClients,
    ] {
        let host = Host::new();
        host.install(hy2(8443, Some((20000, 30000))));
        let before = host.world();
        host.features
            .inject(Fault::Fail(Checkpoint::Stage(point.clone())));
        let req = host.change(hy2(9443, Some((40000, 50000))), "修改跳跃");
        let text = err_text(&host.apply(req).unwrap_err());
        assert!(text.starts_with("配置未应用，已恢复原状态"), "{text}");
        assert_eq!(recorded(&host), [(20000, 30000, 8443)], "{point:?}");
        only_redirect(&host, "20000:30000", 8443);
        assert_eq!(
            masked(before.clone()).diff(&masked(host.world())),
            Vec::<String>::new(),
            "{point:?}"
        );
        assert_no_journal(&host);
        assert_invariants(&host);
    }
}

/// A redirect the rollback cannot remove is recorded again in the restored
/// hop ledger: re-applying the old hop retires it, and while it cannot be
/// removed and would shadow the restored hop, re-applying fails loudly
/// (a warning; the rollback still finishes) instead of forgetting it.
#[test]
fn a_hop_the_rollback_cannot_remove_is_recorded_and_retired_later() {
    let host = Host::new();
    host.install(hy2(8443, Some((20000, 30000))));
    let before = host.world();
    host.features
        .inject(Fault::Fail(Checkpoint::Stage(Phase::StartCores)));
    // An overlapping range to another target: a leftover of the new
    // redirect would shadow part of the restored one.
    host.fail_always("iptables -w 5 -t nat -D PREROUTING -p udp --dport 25000:35000 ");
    let req = host.change(hy2(9443, Some((25000, 35000))), "修改端口");
    let text = err_text(&host.apply(req).unwrap_err());
    assert!(text.starts_with("配置未应用，已恢复原状态"), "{text}");
    assert_no_journal(&host);
    let ledger = hop::recorded(&host.ctx).unwrap();
    let targets: Vec<u16> = ledger.iter().map(|h| h.target).collect();
    assert_eq!(targets, [9443, 8443], "the leftover stays recorded first");
    assert_eq!(redirects(&host).len(), 2);
    // The services came back regardless.
    assert!(host.unit(crate::host::service::SING_BOX).active);
    // Once the redirect can be removed, net-apply retires it.
    host.clear_faults();
    crate::apply::boot::boot_locked(&host.ctx, &host.lock, &host.features).unwrap();
    assert_eq!(recorded(&host), [(20000, 30000, 8443)]);
    only_redirect(&host, "20000:30000", 8443);
    assert_eq!(
        masked(before).diff(&masked(host.world())),
        Vec::<String>::new()
    );
}

/// The proxy certificate over HTTP-01 without an Onebox nginx on TCP 80:
/// the built-in responder needs the port, so the old holder stops and the
/// `acme` owner opens it while certificates are prepared; finalize clears
/// it and installs the renewal line.
#[test]
fn a_proxy_acme_http01_certificate_borrows_port80_and_schedules_renewals() {
    let host = Host::new();
    host.install(fixtures::config(&[
        (Protocol::VlessReality, 443, Core::Singbox),
        (Protocol::VmessWs, 80, Core::Xray),
    ]));
    assert_eq!(host.crontab(), "");
    let mut cfg = fixtures::config(&[
        (Protocol::VlessReality, 443, Core::Singbox),
        (Protocol::Trojan, 8443, Core::Singbox),
    ]);
    cfg.tls = Some(ProxyTls {
        mode: ProxyCertMode::Acme {
            domain: "proxy.example.com".into(),
            method: AcmeMethod::Http01,
        },
        pinned: true,
    });
    assert_eq!(proxy_http01_responder(&cfg), Some(Http01Responder::Builtin));
    host.exec.clear_history();
    host.features.clear();
    host.apply(host.change(cfg, "签发证书")).unwrap();
    let history = host.history();
    let at = |needle: &str| {
        history
            .iter()
            .position(|h| h.contains(needle))
            .unwrap_or_else(|| panic!("{needle}: {history:?}"))
    };
    assert!(at("systemctl stop onebox-xray") < at("--comment onebox-acme-"));
    assert!(at("--comment onebox-acme-") < at("sing-box check"));
    assert!(host
        .features
        .calls()
        .iter()
        .any(|c| c == "proxy_certificate force=false"));
    // The temporary owner is gone; the proxy owner keeps TCP 80 open for
    // the renewals' responder, next to the proxy's own ports.
    let rules = host.world().iptables;
    let proxy = |port: &str| {
        let needle = format!("--dport {port} ");
        rules
            .iter()
            .any(|r| r.contains(&needle) && r.contains("onebox-proxy-"))
    };
    assert!(
        !rules.iter().any(|r| r.contains("onebox-acme-")),
        "{rules:?}"
    );
    assert!(proxy("80") && proxy("8443"), "{rules:?}");
    assert_eq!(
        fs::read_to_string(host.paths().root.join("firewall-acme.json")).unwrap(),
        "{\n  \"rules\": []\n}"
    );
    // An ACME certificate requires the renewal line (RenewNeed::Required).
    assert_eq!(
        host.crontab(),
        format!("{}\n", lines::renew_for(host.paths()))
    );
    let saved = host.installed();
    assert!(!saved.tls.unwrap().pinned, "publicly trusted: not pinned");
    assert!(!host.unit(crate::host::service::XRAY).active);
    assert_no_journal(&host);
    assert_invariants(&host);
}
