use super::*;
use crate::cert::hooks::prepare_proxy_with;
use crate::cert::testing::{
    acme_calls, engine, fake_acme, have_openssl, self_signed, serve_release, AcmeScript, Fixture,
};
use crate::domain::config::{AcmeMethod, ProxyTls, WebCert};
use crate::domain::fixtures::{config, standalone_subscription, with_site};
use crate::domain::protocol::{Core, Protocol};
use crate::host::init::InitSystem;
use crate::sys::exec::Output;
use crate::sys::lock::BUSY_MESSAGE;

fn lock(ctx: &Ctx) -> FileLock {
    FileLock::acquire(&ctx.paths.lock(), BUSY_MESSAGE).unwrap()
}

fn opts(targets: CertScopes, scheduled: bool, force: bool) -> RenewOptions {
    RenewOptions {
        targets,
        scheduled,
        force,
    }
}

fn restarts(f: &Fixture) -> Vec<String> {
    f.fake
        .history()
        .into_iter()
        .filter(|c| c.starts_with("systemctl restart"))
        .collect()
}

#[test]
fn renewal_requires_the_node_lock() {
    let dir = crate::sys::fs::TempDir::new("renew-lock").unwrap();
    let (ctx, _, _) = Ctx::test(dir.path());
    let engine = engine(&ctx, InitSystem::None);
    let other = FileLock::acquire(&dir.join("other.lock"), BUSY_MESSAGE).unwrap();
    let cfg = config(&[(Protocol::Trojan, 443, Core::Singbox)]);
    let o = opts(CertScopes::ALL, true, false);
    assert!(renew_all_with(&engine, &other, &cfg, &o).is_err());
    let report = renew_all_with(&engine, &lock(&ctx), &config(&[]), &o).unwrap();
    assert_eq!(report, RenewReport::default());
}

#[test]
fn self_signed_renewal_changes_the_pinned_identity() {
    if !have_openssl() {
        return;
    }
    let f = Fixture::new("renew-self");
    f.fake
        .on("systemctl", &["is-active"], Output::success(""))
        .on("systemctl", &["restart"], Output::success(""));
    let engine = engine(&f.ctx, InitSystem::Systemd);
    let mut cfg = config(&[(Protocol::Trojan, 443, Core::Singbox)]);
    prepare_proxy_with(&engine, &mut cfg, false, None).unwrap();
    let held = lock(&f.ctx);

    // Fresh: nothing due, nothing restarted, also when not scheduled.
    let report =
        renew_all_with(&engine, &held, &cfg, &opts(CertScopes::ALL, false, false)).unwrap();
    assert_eq!(report.unchanged, [CertScope::Proxy]);
    assert!(report.renewed.is_empty() && !report.proxy_identity_changed);
    assert!(restarts(&f).is_empty());

    // Expiring within 30 days: regenerated; clients pin it, so the caller
    // must apply (and the cores are left to that apply).
    let tls = CertDir::proxy(&f.ctx.paths);
    let (cert, key) = self_signed(&f.dir.join("short"), &["www.bing.com"], 10);
    std::fs::copy(cert, tls.cert()).unwrap();
    std::fs::copy(key, tls.key()).unwrap();
    let report = renew_all_with(&engine, &held, &cfg, &opts(CertScopes::ALL, true, false)).unwrap();
    assert_eq!(report.renewed, [CertScope::Proxy]);
    assert!(report.proxy_identity_changed);
    assert!(restarts(&f).is_empty());
}

#[test]
fn acme_renewal_restarts_only_running_cores() {
    if !have_openssl() {
        return;
    }
    let f = Fixture::new("renew-acme");
    serve_release(&f.fake);
    f.fake
        .on(
            "systemctl",
            &["is-active", "--quiet", "onebox-sing-box"],
            Output::success(""),
        )
        .on("systemctl", &["is-active"], Output::failure(3, ""))
        .on("systemctl", &["restart"], Output::success(""));
    let engine = engine(&f.ctx, InitSystem::Systemd);
    let (chain, key) =
        f.ca.leaf(&f.dir.join("first"), &["proxy.example.com"], 90, false);
    let script = fake_acme(
        &f.fake,
        AcmeScript {
            issue: Some((chain, key)),
            fetch_port: Some(engine.http01_port),
            ..AcmeScript::default()
        },
    );
    let mut cfg = config(&[
        (Protocol::Trojan, 443, Core::Singbox),
        (Protocol::VlessReality, 8443, Core::Xray),
    ]);
    cfg.tls = Some(ProxyTls {
        mode: crate::domain::config::ProxyCertMode::Acme {
            domain: "proxy.example.com".into(),
            method: AcmeMethod::Http01,
        },
        pinned: false,
    });
    assert!(prepare_proxy_with(&engine, &mut cfg, false, None).unwrap());
    assert!(!cfg.tls.as_ref().unwrap().pinned);

    let renewed =
        f.ca.leaf(&f.dir.join("second"), &["proxy.example.com"], 90, false);
    script.lock().unwrap().issue = Some(renewed);
    let held = lock(&f.ctx);
    let report = renew_all_with(
        &engine,
        &held,
        &cfg,
        &opts(CertScopes::only(CertScope::Proxy), false, true),
    )
    .unwrap();
    assert_eq!(report.renewed, [CertScope::Proxy]);
    assert!(report.failed.is_empty(), "{:?}", report.failed);
    assert!(
        !report.proxy_identity_changed,
        "public leaf changes need no apply"
    );
    assert_eq!(restarts(&f), ["systemctl restart onebox-sing-box"]);
    let call = acme_calls(&f.fake).pop().unwrap();
    assert!(call.args.contains(&"--force".into()));
    // The temporary firewall owner is gone again.
    let ledger = f.ctx.paths.root.join("firewall-acme.json");
    let text = std::fs::read_to_string(ledger).unwrap_or_default();
    assert!(!text.contains("onebox-acme-"), "{text}");
}

#[test]
fn web_targets_renew_independently_and_report_failures() {
    if !have_openssl() {
        return;
    }
    let f = Fixture::new("renew-web");
    serve_release(&f.fake);
    f.fake
        .on(
            "systemctl",
            &["is-active", "--quiet", "onebox-site"],
            Output::success(""),
        )
        .on("systemctl", &["is-active"], Output::failure(3, ""))
        .on("systemctl", &["restart"], Output::success(""));
    let engine = engine(&f.ctx, InitSystem::Systemd);
    let reality = config(&[(Protocol::VlessReality, 443, Core::Xray)]);
    let mut cfg = with_site(reality, "www.example.com", false);
    cfg.subscription = Some(standalone_subscription(
        "sub.example.com",
        8448,
        WebCert::Http01,
    ));
    let (site_chain, site_key) =
        f.ca.leaf(&f.dir.join("site"), &["www.example.com"], 10, false);
    let site_dir = CertDir::site(&f.ctx.paths);
    crate::cert::store::install_pair(
        &f.ctx,
        &site_dir,
        &site_chain,
        &site_key,
        &["www.example.com".into()],
        Trust::Public,
    )
    .unwrap();
    let fresh =
        f.ca.leaf(&f.dir.join("site2"), &["www.example.com"], 90, false);
    fake_acme(
        &f.fake,
        AcmeScript {
            issue: Some(fresh),
            fail_for: Some("sub.example.com".into()),
            ..AcmeScript::default()
        },
    );
    let held = lock(&f.ctx);
    // The site is due (10 days) and served by its running nginx; the
    // subscription has no certificate yet and its acme.sh run fails.
    let report = renew_all_with(&engine, &held, &cfg, &opts(CertScopes::ALL, true, false)).unwrap();
    assert_eq!(report.renewed, [CertScope::Site]);
    assert_eq!(report.failed.len(), 1, "{:?}", report.failed);
    assert_eq!(report.failed[0].0, CertScope::Subscription);
    assert!(
        report.failed[0].1.contains("退出码"),
        "{}",
        report.failed[0].1
    );
    assert_eq!(restarts(&f), ["systemctl restart onebox-site"]);
    let site_call = acme_calls(&f.fake)
        .into_iter()
        .find(|c| {
            c.args
                .contains(&f.ctx.paths.site_root.display().to_string())
        })
        .unwrap();
    assert!(site_call.args.contains(&"--webroot".into()));

    // A site-mode subscription renews the site certificate.
    cfg.subscription = Some(crate::domain::config::SubscriptionConfig {
        mode: SubscriptionMode::Site,
        port: 0,
    });
    let report = renew_all_with(
        &engine,
        &held,
        &cfg,
        &opts(CertScopes::only(CertScope::Subscription), false, false),
    )
    .unwrap();
    assert_eq!(report.unchanged, [CertScope::Site]);
}

#[test]
fn identity_change_rules() {
    let self_cfg = config(&[(Protocol::Trojan, 443, Core::Singbox)]);
    let mut acme_cfg = self_cfg.clone();
    acme_cfg.tls = Some(ProxyTls {
        mode: crate::domain::config::ProxyCertMode::Acme {
            domain: "p.example.com".into(),
            method: AcmeMethod::Cloudflare,
        },
        pinned: false,
    });
    let id = |pin: &str, trusted| Identity {
        pin: Some(pin.into()),
        trusted,
    };
    let cases = [
        (&self_cfg, id("a", false), id("b", false), true),
        (&self_cfg, id("a", false), id("a", false), false),
        (&acme_cfg, id("a", true), id("b", true), false),
        (&acme_cfg, id("a", true), id("b", false), true),
        (&acme_cfg, id("a", false), id("b", false), true),
        (&acme_cfg, id("a", false), id("a", true), true),
    ];
    for (cfg, before, after, changed) in cases {
        assert_eq!(
            identity_changed(cfg, &before, &after),
            changed,
            "{before:?} → {after:?}"
        );
    }
}
