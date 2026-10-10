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
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::Arc;

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
    assert!(renew_all_with(&engine, &other, &cfg, &o, None).is_err());
    let report = renew_all_with(&engine, &lock(&ctx), &config(&[]), &o, None).unwrap();
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
    let report = renew_all_with(
        &engine,
        &held,
        &cfg,
        &opts(CertScopes::ALL, false, false),
        None,
    )
    .unwrap();
    assert_eq!(report.unchanged, [CertScope::Proxy]);
    assert!(report.renewed.is_empty() && !report.proxy_identity_changed);
    assert!(restarts(&f).is_empty());

    // Expiring within 30 days: regenerated; clients pin it, so the caller
    // must apply (and the cores are left to that apply).
    let tls = CertDir::proxy(&f.ctx.paths);
    let (cert, key) = self_signed(&f.dir.join("short"), &["www.bing.com"], 10);
    std::fs::copy(cert, tls.cert()).unwrap();
    std::fs::copy(key, tls.key()).unwrap();
    let report = renew_all_with(
        &engine,
        &held,
        &cfg,
        &opts(CertScopes::ALL, true, false),
        None,
    )
    .unwrap();
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
        None,
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
    let report = renew_all_with(
        &engine,
        &held,
        &cfg,
        &opts(CertScopes::ALL, true, false),
        None,
    )
    .unwrap();
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
        None,
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
    let custom = |pinned| {
        let mut cfg = self_cfg.clone();
        cfg.tls = Some(ProxyTls {
            mode: crate::domain::config::ProxyCertMode::Custom {
                domain: "p.example.com".into(),
                cert: "/c.pem".into(),
                key: "/k.pem".into(),
            },
            pinned,
        });
        cfg
    };
    let (custom_pinned, custom_public) = (custom(true), custom(false));
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
        // Clients were rendered unpinned and the pair is trusted again.
        (&acme_cfg, id("a", false), id("a", true), false),
        // Clients pin a custom leaf whose CA the system store now trusts:
        // the trust measured before the renewal already says "trusted",
        // but the stored configuration still pins (full apply needed).
        (&custom_pinned, id("a", true), id("b", true), true),
        (&custom_pinned, id("a", false), id("b", false), true),
        (&custom_pinned, id("a", false), id("a", false), false),
        (&custom_pinned, id("a", true), id("a", true), true),
        (&custom_public, id("a", true), id("b", true), false),
        (&custom_public, id("a", true), id("b", false), true),
    ];
    for (cfg, before, after, changed) in cases {
        assert_eq!(
            identity_changed(cfg, &before, &after),
            changed,
            "{before:?} → {after:?}"
        );
    }
}

/// A node with an ACME Cloudflare proxy certificate and a Cloudflare site.
fn dns_node() -> NodeConfig {
    let base = config(&[
        (Protocol::Trojan, 443, Core::Singbox),
        (Protocol::VlessReality, 8443, Core::Xray),
    ]);
    let mut cfg = with_site(base, "www.example.com", false);
    cfg.tls = Some(ProxyTls {
        mode: crate::domain::config::ProxyCertMode::Acme {
            domain: "proxy.example.com".into(),
            method: AcmeMethod::Cloudflare,
        },
        pinned: false,
    });
    if let Some(site) = cfg.site.as_mut() {
        site.cert = WebCert::Cloudflare;
    }
    cfg
}

fn token_of(cmd: &crate::sys::exec::Cmd) -> Option<String> {
    cmd.env
        .iter()
        .find(|(k, _)| k == "CF_Token")
        .map(|(_, v)| v.clone())
}

#[test]
fn given_credentials_serve_only_targets_without_their_own() {
    if !have_openssl() {
        return;
    }
    let f = Fixture::new("renew-cf");
    serve_release(&f.fake);
    f.fake
        .on("systemctl", &["is-active"], Output::failure(3, ""))
        .on("systemctl", &["restart"], Output::success(""));
    let engine = engine(&f.ctx, InitSystem::Systemd);
    let pair = f.ca.leaf(
        &f.dir.join("issued"),
        &["proxy.example.com", "www.example.com"],
        90,
        false,
    );
    fake_acme(
        &f.fake,
        AcmeScript {
            issue: Some(pair),
            ..AcmeScript::default()
        },
    );
    let cfg = dns_node();
    let proxy = CertDir::proxy(&f.ctx.paths);
    let site = CertDir::site(&f.ctx.paths);
    let stored = CfCredentials::token("stored-token", None).unwrap();
    crate::cert::cloudflare::persist(proxy.path(), &stored).unwrap();
    let forced = opts(CertScopes::ALL, false, true);
    assert_eq!(
        credentials_needed_with(&engine, &cfg, &forced),
        [CertScope::Site]
    );
    // Without credentials the site fails, the proxy renews with its own.
    let held = lock(&f.ctx);
    let report = renew_all_with(&engine, &held, &cfg, &forced, None).unwrap();
    assert_eq!(report.renewed, [CertScope::Proxy]);
    assert_eq!(report.failed.len(), 1, "{:?}", report.failed);
    assert_eq!(report.failed[0].1, crate::cert::cloudflare::MISSING);

    // Credentials the CLI resolved (prompted) serve the site only.
    let given = CfCredentials::token("given-token", None).unwrap();
    let before = acme_calls(&f.fake).len();
    let report = renew_all_with(&engine, &held, &cfg, &forced, Some(&given)).unwrap();
    assert!(report.failed.is_empty(), "{:?}", report.failed);
    let calls = acme_calls(&f.fake)[before..].to_vec();
    let tokens: Vec<_> = calls.iter().map(token_of).collect();
    assert_eq!(
        tokens,
        [Some("stored-token".into()), Some("given-token".into())]
    );
    // …and are stored for the next scheduled run.
    let saved = crate::cert::cloudflare::lookup_with(&f.ctx, site.path(), &|_| None)
        .unwrap()
        .unwrap();
    assert_eq!(saved.get("CF_Token"), Some("given-token"));
    assert!(credentials_needed_with(&engine, &cfg, &forced).is_empty());
    // Targets that are not due need nothing.
    let mut bare = cfg.clone();
    bare.site = None;
    std::fs::remove_file(crate::cert::cloudflare::store_path(proxy.path())).unwrap();
    let scheduled = opts(CertScopes::ALL, true, false);
    assert!(credentials_needed_with(&engine, &bare, &scheduled).is_empty());
    assert_eq!(
        credentials_needed_with(&engine, &bare, &forced),
        [CertScope::Proxy]
    );
}

#[test]
fn deferred_renewals_are_reported_unchanged() {
    if !have_openssl() {
        return;
    }
    let f = Fixture::new("renew-deferred");
    serve_release(&f.fake);
    f.fake
        .on("systemctl", &["is-active"], Output::success(""))
        .on("systemctl", &["restart"], Output::success(""));
    let engine = engine(&f.ctx, InitSystem::Systemd);
    let short =
        f.ca.leaf(&f.dir.join("short"), &["www.example.com"], 10, false);
    let script = fake_acme(
        &f.fake,
        AcmeScript {
            issue: Some(short),
            ..AcmeScript::default()
        },
    );
    let mut cfg = dns_node();
    cfg.tls = None;
    cfg.inbounds
        .retain(|i| i.protocol == Protocol::VlessReality);
    let site = CertDir::site(&f.ctx.paths);
    let creds = CfCredentials::token("tok", None).unwrap();
    let target = crate::cert::WebCertTarget {
        dir: site.path().to_path_buf(),
        domains: vec!["www.example.com".into()],
        cert: &WebCert::Cloudflare,
        webroot: None,
    };
    // The first issuance deploys the short pair (acme.sh holds the same).
    crate::cert::hooks::prepare_web_with(&engine, target, false, Some(&creds)).unwrap();
    script.lock().unwrap().code = 2;
    let held = lock(&f.ctx);
    let report = renew_all_with(
        &engine,
        &held,
        &cfg,
        &opts(CertScopes::ALL, true, false),
        None,
    )
    .unwrap();
    assert_eq!(report.unchanged, [CertScope::Site]);
    assert!(report.renewed.is_empty() && report.failed.is_empty());
    assert!(restarts(&f).is_empty());
    let m = site.metadata().unwrap().unwrap();
    assert_eq!(
        m.last_error.as_deref(),
        Some(crate::cert::engine::RENEW_DEFERRED)
    );
}

/// The site pair is renewed, but `onebox-site` does not come back with it
/// (restart = stop + start, so it may now be stopped): the old pair and
/// metadata go back and the site is restarted again, so the target stays
/// due and the next scheduled run deploys the pair acme.sh holds and
/// restarts the site (v2 rolled back the whole apply).
#[test]
fn a_failed_restart_puts_the_previous_pair_back() {
    if !have_openssl() {
        return;
    }
    let cases = [
        (1, "已恢复续期前的证书（下次续期时重试）"),
        (
            2,
            "已恢复续期前的证书，但再次重启失败: 重启 onebox-site 失败",
        ),
    ];
    for (failing, want) in cases {
        let f = Fixture::new("renew-restart");
        serve_release(&f.fake);
        let left = Arc::new(AtomicUsize::new(failing));
        f.fake
            .on_fn(
                |c| {
                    c.program_name() == "systemctl"
                        && c.args.first().is_some_and(|a| a == "restart")
                },
                move |_| {
                    let fail = left
                        .try_update(SeqCst, SeqCst, |n| n.checked_sub(1))
                        .is_ok();
                    Ok(match fail {
                        true => Output::failure(1, "Job for onebox-site.service failed"),
                        false => Output::success(""),
                    })
                },
            )
            .on("systemctl", &["is-active"], Output::success(""));
        let engine = engine(&f.ctx, InitSystem::Systemd);
        let cfg = with_site(
            config(&[(Protocol::VlessReality, 443, Core::Xray)]),
            "www.example.com",
            false,
        );
        let site_dir = CertDir::site(&f.ctx.paths);
        let (old_chain, old_key) =
            f.ca.leaf(&f.dir.join("old"), &["www.example.com"], 10, false);
        let names = ["www.example.com".to_owned()];
        crate::cert::store::install_pair(
            &f.ctx,
            &site_dir,
            &old_chain,
            &old_key,
            &names,
            Trust::Public,
        )
        .unwrap();
        let deployed = || {
            let read = |p: std::path::PathBuf| std::fs::read(p).ok();
            (
                read(site_dir.cert()),
                read(site_dir.key()),
                read(site_dir.metadata_file()),
            )
        };
        let before = deployed();
        let fresh =
            f.ca.leaf(&f.dir.join("new"), &["www.example.com"], 90, false);
        let script = fake_acme(
            &f.fake,
            AcmeScript {
                issue: Some(fresh),
                ..AcmeScript::default()
            },
        );
        let held = lock(&f.ctx);
        let scheduled = opts(CertScopes::ALL, true, false);
        let report = renew_all_with(&engine, &held, &cfg, &scheduled, None).unwrap();
        assert_eq!(report.renewed, [CertScope::Site], "{failing}");
        assert_eq!(report.failed.len(), 1, "{:?}", report.failed);
        let (scope, message) = &report.failed[0];
        assert_eq!(*scope, CertScope::Site);
        let prefix = "网站证书已续期，但重启 onebox-site 失败: ";
        assert!(message.starts_with(prefix), "{message}");
        assert!(message.contains(want), "{message}");
        assert_eq!(restarts(&f), ["systemctl restart onebox-site"; 2]);
        assert_eq!(deployed(), before, "pair and metadata put back");

        // The next run: acme.sh finds nothing due and holds the new pair,
        // which is deployed now that the target is due again.
        script.lock().unwrap().code = 2;
        f.fake.clear_history();
        let retry = renew_all_with(&engine, &held, &cfg, &scheduled, None).unwrap();
        assert_eq!(retry.renewed, [CertScope::Site]);
        assert!(retry.failed.is_empty(), "{:?}", retry.failed);
        assert_eq!(restarts(&f), ["systemctl restart onebox-site"]);
        assert_ne!(deployed().0, before.0);
    }
}
