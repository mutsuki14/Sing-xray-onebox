//! Stage policies: TCP 80 for HTTP-01 (G21), the crontab (G17/G18/G40),
//! intents reaching the feature hooks, subscription devices (G23/G30).

use super::*;
use crate::apply::harness::{two_cores, Fault};
use crate::cert::CertScopes;
use crate::domain::config::{Device, WebCert};
use crate::domain::fixtures::{self, with_site};
use crate::domain::protocol::{Core, Protocol};
use crate::host::cron::testing::lines;
use crate::host::service as svc;
use crate::site::SiteContent;

fn site_node() -> crate::domain::NodeConfig {
    with_site(
        fixtures::config(&[(Protocol::VlessReality, 443, Core::Singbox)]),
        "example.com",
        false,
    )
}

fn position(history: &[String], needle: &str) -> usize {
    history
        .iter()
        .position(|h| h.contains(needle))
        .unwrap_or_else(|| panic!("{needle} not run: {history:?}"))
}

#[test]
fn http01_stops_old_port80_holders_and_opens_port80_only_meanwhile() {
    let host = Host::new();
    host.install(fixtures::config(&[
        (Protocol::VlessReality, 443, Core::Singbox),
        (Protocol::VmessWs, 80, Core::Xray),
    ]));
    host.exec.clear_history();
    host.apply(host.change(site_node(), "启用网站")).unwrap();
    let history = host.history();
    // Xray held TCP 80; it stops before the certificate stage needs it,
    // i.e. before configurations are even checked.
    let stopped = position(&history, "systemctl stop onebox-xray");
    let opened = position(&history, "--comment onebox-acme-");
    assert!(stopped < opened, "{history:?}");
    assert!(opened < position(&history, "sing-box check"));
    // The temporary owner is gone; the site's own TCP 80 rule stays.
    let rules = host.world().iptables;
    assert!(
        !rules.iter().any(|r| r.contains("onebox-acme-")),
        "{rules:?}"
    );
    assert!(
        rules
            .iter()
            .any(|r| r.contains("--dport 80 ") && r.contains("onebox-proxy-")),
        "{rules:?}"
    );
    assert_eq!(
        std::fs::read_to_string(host.paths().root.join("firewall-acme.json")).unwrap(),
        "{\n  \"rules\": []\n}"
    );
    let calls = host.features.calls();
    assert!(calls.iter().any(|c| c == "site_apply"), "{calls:?}");
    assert_invariants(&host);
}

#[test]
fn a_rollback_restarts_the_port80_holders_it_stopped() {
    let host = Host::new();
    host.install(fixtures::config(&[
        (Protocol::VlessReality, 443, Core::Singbox),
        (Protocol::VmessWs, 80, Core::Xray),
    ]));
    let before = host.world();
    host.features
        .inject(Fault::Fail(Checkpoint::Stage(Phase::PrepareCertificates)));
    host.apply(host.change(site_node(), "启用网站"))
        .unwrap_err();
    assert_eq!(before.diff(&host.world()), Vec::<String>::new());
    assert!(host.unit(svc::XRAY).active);
}

#[test]
fn the_renewal_line_follows_the_certificates_and_retires_older_forms() {
    let host = Host::new();
    let paths = host.paths().clone();
    let exe = paths.executable.display().to_string();
    let v1 = format!("@reboot {exe} net-apply >/dev/null 2>&1; {exe} start >/dev/null 2>&1");
    let v2_cert = lines::v2_cert("site").replace(lines::EXE, &exe);
    let v2_boot = lines::v2_boot(svc::XRAY);
    host.set_crontab(&format!(
        "MAILTO=root\n{v2_cert}\n0 5 * * * /usr/bin/foreign\n{v1}\n{v2_boot}\n"
    ));
    let mut cfg = site_node();
    if let Some(site) = cfg.site.as_mut() {
        site.cert = WebCert::Cloudflare;
    }
    host.install(cfg);
    // One `renew` line where v2's certificate line was; the v1 boot line
    // and (under systemd) per-service boot lines are gone; foreign lines
    // keep their place.
    assert_eq!(
        host.crontab(),
        format!(
            "MAILTO=root\n{}\n0 5 * * * /usr/bin/foreign\n",
            lines::renew_for(&paths)
        )
    );
    // Without an ACME or custom certificate the line goes away.
    host.apply(host.change(two_cores(), "关闭网站")).unwrap();
    assert_eq!(host.crontab(), "MAILTO=root\n0 5 * * * /usr/bin/foreign\n");
}

#[test]
fn acme_renewals_without_a_running_cron_are_refused_before_anything_changes() {
    let host = Host::new();
    host.install(two_cores());
    host.set_unit("cron", Unit::default());
    let mut cfg = site_node();
    if let Some(site) = cfg.site.as_mut() {
        site.cert = WebCert::Cloudflare;
    }
    let before = host.world();
    let err = host.apply(host.change(cfg, "启用网站")).unwrap_err();
    assert_eq!(err.to_string(), crate::host::cron::NOT_RUNNING);
    assert_eq!(before.diff(&host.world()), Vec::<String>::new());
    assert_no_journal(&host);
}

#[test]
fn intents_reach_the_feature_hooks() {
    let host = Host::new();
    host.install(site_node());
    host.features.clear();
    let mut req = host.change(site_node(), "续期证书");
    req.intents.renew = CertScopes {
        proxy: true,
        site: true,
        subscription: false,
    };
    req.intents.site_content = Some(SiteContent::Template);
    host.apply(req).unwrap();
    let calls = host.features.calls();
    for expected in [
        "install_self",
        "prepare_subscription migrated=0 clear=false",
        "subscription_certificates force=false",
        "site_prepare content=Some(Template) force=true",
        "proxy_certificate force=true",
        "site_check",
        "subscription_services",
        "site_apply",
        "publish_subscription",
    ] {
        assert!(calls.iter().any(|c| c == expected), "{expected}: {calls:?}");
    }
    // Nothing turned the website off on the way.
    assert!(!calls.iter().any(|c| c == "site_disable"), "{calls:?}");
    assert_invariants(&host);
}

fn device() -> Device {
    Device {
        id: "0123456789abcdef".into(),
        name: "phone".into(),
        hash: "a".repeat(64),
        created: 1_700_000_000,
    }
}

#[test]
fn migrated_devices_are_written_inside_the_transaction() {
    let host = Host::new();
    host.install(two_cores());
    let devices = host.paths().devices();
    let before = host.world();
    let mut failing = host.change(two_cores(), "迁移");
    failing.intents.migrated_devices = Some(vec![device()]);
    host.features
        .inject(Fault::Fail(Checkpoint::Stage(Phase::PublishClients)));
    host.apply(failing).unwrap_err();
    assert!(!exists(&devices), "rolled back with the transaction");
    assert_eq!(before.diff(&host.world()), Vec::<String>::new());
    host.features.clear();
    let mut req = host.change(two_cores(), "迁移");
    req.intents.migrated_devices = Some(vec![device()]);
    host.apply(req).unwrap();
    assert!(exists(&devices));
    // A reinstall clears them (G30).
    let mut reinstall = host.change(two_cores(), "重装");
    reinstall.intents.clear_devices = true;
    host.apply(reinstall).unwrap();
    assert!(!exists(&devices));
}

/// G12: apply, rollback, recovery, boot and backups never ask anything. The
/// test prompter is interactive with no answers, so any question would fail
/// the operation with "input ended" and be recorded.
#[test]
fn nothing_reachable_from_apply_recover_boot_or_backups_asks_a_question() {
    let host = Host::new();
    host.install(site_node());
    host.features
        .inject(Fault::Fail(Checkpoint::Stage(Phase::StartCores)));
    host.apply(host.change(two_cores(), "修改")).unwrap_err();
    host.features
        .inject(Fault::Crash(Checkpoint::Stage(Phase::ApplyWebsite)));
    let req = host.change(two_cores(), "修改");
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| host.apply(req))).is_err());
    host.features.clear();
    recover_all(&host.ctx, &host.lock).unwrap();
    host.set_ips(crate::apply::harness::NEW_IPS);
    crate::apply::boot::boot_locked(&host.ctx, &host.lock, &host.features).unwrap();
    let id = crate::backup::create_locked(&host.ctx, &host.lock, "g12").unwrap();
    host.apply(host.change(two_cores(), "修改")).unwrap();
    crate::backup::restore_with(&host.ctx, &host.lock, &id, &host.features).unwrap();
    assert_eq!(host.installed().inbounds, site_node().inbounds);
    assert!(host.ui.prompts().is_empty(), "{:?}", host.ui.prompts());
    assert!(host.ui.errors().is_empty(), "{:?}", host.ui.errors());
    assert_invariants(&host);
}

/// `atomic_write` leftovers of crashed runs are swept from every owned
/// directory before the journal snapshot, so a rollback does not bring
/// them back; recent ones (possibly a concurrent writer's) stay.
#[test]
fn stale_temp_files_are_swept_before_the_journal_snapshot() {
    use crate::sys::fs::TEMP_PREFIX;
    use std::time::{Duration, SystemTime};
    let host = Host::new();
    host.install(two_cores());
    let paths = host.paths().clone();
    let dirs = [
        paths.root.clone(),
        paths.clients(),
        paths.tls().join("acme"),
        paths.site_root.clone(),
        paths.subscription_acme(),
        paths.bin.clone(),
        paths.systemd.clone(),
        paths.initd.clone(),
        paths.executable.parent().unwrap().to_path_buf(),
    ];
    let hour_ago = SystemTime::now() - Duration::from_secs(3600);
    let stale: Vec<_> = dirs
        .iter()
        .map(|dir| dir.join(format!("{TEMP_PREFIX}state.json-1234")))
        .collect();
    for path in &stale {
        crate::apply::testing::file(path, 0o600, b"partial");
        let file = std::fs::File::options().write(true).open(path).unwrap();
        file.set_modified(hour_ago).unwrap();
    }
    let fresh = paths.tls().join(format!("{TEMP_PREFIX}cert.pem-5678"));
    crate::apply::testing::file(&fresh, 0o600, b"being written");
    host.features
        .inject(Fault::Fail(Checkpoint::Stage(Phase::PrepareState)));
    host.apply(host.change(two_cores(), "修改")).unwrap_err();
    for path in &stale {
        assert!(!exists(path), "{}", path.display());
    }
    assert!(exists(&fresh));
    assert_no_journal(&host);
}
