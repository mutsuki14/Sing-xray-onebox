use super::*;
use crate::cert::testing::{
    acme_calls, engine, fake_acme, have_openssl, self_signed, serve_release, AcmeScript, Fixture,
};
use crate::domain::config::{ProxyTls, SubscriptionConfig};
use crate::domain::fixtures::{config, standalone_subscription, with_site};
use crate::domain::protocol::{Core, Protocol};
use crate::host::init::InitSystem;
use crate::sys::exec::{FakeExec, Output};

fn trojan(mode: ProxyCertMode) -> NodeConfig {
    let mut cfg = config(&[(Protocol::Trojan, 443, Core::Singbox)]);
    cfg.tls = Some(ProxyTls { mode, pinned: true });
    cfg
}

fn acme(method: AcmeMethod) -> ProxyCertMode {
    ProxyCertMode::Acme {
        domain: "proxy.example.com".into(),
        method,
    }
}

/// `systemctl is-active --quiet NAME` answers for the given services.
fn running(exec: &FakeExec, services: &[&'static str]) {
    for name in services {
        exec.on(
            "systemctl",
            &["is-active", "--quiet", name],
            Output::success(""),
        );
    }
    exec.on("systemctl", &["is-active"], Output::failure(3, ""));
}

#[test]
fn renew_need_follows_every_certificate() {
    use RenewNeed::*;
    let plain = config(&[(Protocol::VlessReality, 443, Core::Xray)]);
    let custom = || ProxyCertMode::Custom {
        domain: "proxy.example.com".into(),
        cert: "/c.pem".into(),
        key: "/k.pem".into(),
    };
    let self_signed_cfg = config(&[(Protocol::Trojan, 443, Core::Singbox)]);
    let site = with_site(plain.clone(), "www.example.com", true);
    let mut site_custom = site.clone();
    if let Some(s) = site_custom.site.as_mut() {
        s.cert = WebCert::Custom {
            cert: "/c".into(),
            key: "/k".into(),
        };
    }
    let mut sub = self_signed_cfg.clone();
    sub.subscription = Some(standalone_subscription(
        "sub.example.com",
        8448,
        WebCert::Cloudflare,
    ));
    let cases = [
        (plain.clone(), None),
        (self_signed_cfg.clone(), None),
        (trojan(acme(AcmeMethod::Http01)), Required),
        (trojan(acme(AcmeMethod::Cloudflare)), Required),
        (trojan(custom()), Recommended),
        (site, Required),
        (site_custom, Recommended),
        (sub, Required),
    ];
    for (cfg, expected) in cases {
        assert_eq!(renew_needed(&cfg), expected, "{:?}", cfg.tls);
    }
    // A dormant site (no REALITY inbound) needs nothing.
    let mut dormant = with_site(plain, "www.example.com", true);
    dormant.inbounds = self_signed_cfg.inbounds.clone();
    dormant.tls = self_signed_cfg.tls.clone();
    assert_eq!(renew_needed(&dormant), None);
}

#[test]
fn proxy_http01_challenge_follows_the_port_80_owner() {
    let dir = crate::sys::fs::TempDir::new("hooks-challenge").unwrap();
    let (ctx, exec, _) = Ctx::test(dir.path());
    let engine = engine(&ctx, InitSystem::Systemd);
    let tls = CertDir::proxy(&ctx.paths);
    let challenge = |cfg: &NodeConfig| proxy_spec(&engine, cfg, &tls).unwrap().source;
    let builtin = trojan(acme(AcmeMethod::Http01));
    assert_eq!(
        challenge(&builtin),
        Source::Acme(Challenge::Responder(tls.responder_webroot()))
    );
    let mut site = with_site(builtin.clone(), "www.example.com", false);
    site.inbounds.push(crate::domain::config::Inbound {
        protocol: Protocol::VlessReality,
        port: 8443,
        core: Core::Xray,
    });
    site.creds.reality = config(&[(Protocol::VlessReality, 8443, Core::Xray)])
        .creds
        .reality;
    let site_root = ctx.paths.site_root.clone();
    running(&exec, &[]);
    // A site root Onebox has not created yet is never written to.
    assert_eq!(
        challenge(&site),
        Source::Acme(Challenge::Responder(tls.responder_webroot()))
    );
    std::fs::create_dir_all(&site_root).unwrap();
    std::fs::write(site_root.join(".onebox-site-owned"), "onebox\n").unwrap();
    assert_eq!(
        challenge(&site),
        Source::Acme(Challenge::Responder(site_root.clone()))
    );
    let exec2 = FakeExec::new();
    running(&exec2, &[SITE]);
    let ctx2 = Ctx {
        exec: std::sync::Arc::new(exec2),
        ..ctx.clone()
    };
    let engine2 = crate::cert::testing::engine(&ctx2, InitSystem::Systemd);
    let spec = proxy_spec(&engine2, &site, &tls).unwrap();
    assert_eq!(spec.source, Source::Acme(Challenge::Webroot(site_root)));
    assert_eq!(
        (spec.primary(), spec.trust),
        ("proxy.example.com", Trust::Public)
    );

    let mut sub = builtin;
    sub.subscription = Some(SubscriptionConfig {
        ..standalone_subscription("sub.example.com", 8448, WebCert::Http01)
    });
    assert_eq!(
        challenge(&sub),
        Source::Acme(Challenge::Responder(tls.responder_webroot()))
    );
    let sub_root = subscription_acme_root(&ctx.paths);
    std::fs::create_dir_all(&sub_root).unwrap();
    std::fs::write(sub_root.join(".onebox-owned"), "onebox\n").unwrap();
    assert_eq!(
        challenge(&sub),
        Source::Acme(Challenge::Responder(sub_root))
    );
    assert_eq!(
        challenge(&trojan(acme(AcmeMethod::Cloudflare))),
        Source::Acme(Challenge::Cloudflare)
    );
    let self_spec = proxy_spec(
        &engine,
        &config(&[(Protocol::Trojan, 443, Core::Singbox)]),
        &tls,
    );
    assert_eq!(self_spec.unwrap().trust, Trust::Pinned);
    assert_eq!(
        proxy_spec(
            &engine,
            &config(&[(Protocol::VlessReality, 443, Core::Xray)]),
            &tls
        ),
        Option::None
    );
}

#[test]
fn metadata_describes_its_own_renewal() {
    let dir = CertDir::new("/etc/onebox-frp/web-tls");
    let m = |method, webroot: Option<&str>| Metadata {
        domains: vec!["a.example.com".into()],
        method,
        webroot: webroot.map(PathBuf::from),
        source_cert: Some("/src/c.pem".into()),
        source_key: Some("/src/k.pem".into()),
        last_attempt: 0,
        last_success: 0,
        last_error: Option::None,
    };
    let source = |meta: Metadata| spec_from_metadata(&dir, &meta).map(|s| (s.source, s.trust));
    assert_eq!(
        source(m(MethodId::Http, Some("/var/lib/onebox-frp/www"))).unwrap(),
        (
            Source::Acme(Challenge::Webroot("/var/lib/onebox-frp/www".into())),
            Trust::Public
        )
    );
    assert_eq!(
        source(m(MethodId::Http, Option::None))
            .unwrap_err()
            .to_string(),
        "HTTP 验证缺少网站目录"
    );
    assert_eq!(
        source(m(MethodId::Standalone, Option::None)).unwrap().0,
        Source::Acme(Challenge::Responder(dir.responder_webroot()))
    );
    // v2 recorded the site root for standalone certificates: tokens go
    // there only while Onebox owns it, else into the directory's own root.
    let tmp = crate::sys::fs::TempDir::new("hooks-standalone").unwrap();
    let local = CertDir::new(tmp.join("tls"));
    let site_root = tmp.join("onebox-site");
    std::fs::create_dir_all(&site_root).unwrap();
    let standalone = |webroot: &Path| {
        let meta = Metadata {
            webroot: Some(webroot.to_path_buf()),
            ..m(MethodId::Standalone, Option::None)
        };
        spec_from_metadata(&local, &meta).unwrap().source
    };
    assert_eq!(
        standalone(&site_root),
        Source::Acme(Challenge::Responder(local.responder_webroot()))
    );
    std::fs::write(site_root.join(".onebox-site-owned"), "onebox\n").unwrap();
    assert_eq!(
        standalone(&site_root),
        Source::Acme(Challenge::Responder(site_root.clone()))
    );
    let inside = local.path().join("acme/http01");
    assert_eq!(
        standalone(&inside),
        Source::Acme(Challenge::Responder(inside.clone()))
    );
    assert_eq!(
        source(m(MethodId::Cloudflare, Option::None)).unwrap().0,
        Source::Acme(Challenge::Cloudflare)
    );
    assert_eq!(
        source(m(MethodId::SelfSigned, Option::None)).unwrap().1,
        Trust::Pinned
    );
    let custom = source(m(MethodId::Custom, Option::None)).unwrap();
    assert_eq!(
        custom,
        (
            Source::Custom {
                cert: "/src/c.pem".into(),
                key: "/src/k.pem".into()
            },
            Trust::Pinned
        )
    );
    let mut no_source = m(MethodId::Custom, Option::None);
    no_source.source_key = Option::None;
    assert_eq!(
        source(no_source).unwrap_err().to_string(),
        "未记录外部私钥路径"
    );
}

#[test]
fn prepare_proxy_records_trust() {
    if !have_openssl() {
        return;
    }
    let f = Fixture::new("hooks-proxy");
    let engine = engine(&f.ctx, InitSystem::None);
    let mut cfg = config(&[(Protocol::Trojan, 443, Core::Singbox)]);
    assert!(prepare_proxy_with(&engine, &mut cfg, false, Option::None).unwrap());
    assert!(cfg.tls.as_ref().unwrap().pinned);
    assert!(!prepare_proxy_with(&engine, &mut cfg, false, Option::None).unwrap());

    // A custom certificate from a trusted CA is not pinned; from an
    // untrusted CA it is.
    let (chain, key) =
        f.ca.leaf(&f.dir.join("custom"), &["proxy.example.com"], 90, true);
    let mut custom = trojan(ProxyCertMode::Custom {
        domain: "proxy.example.com".into(),
        cert: chain,
        key,
    });
    assert!(prepare_proxy_with(&engine, &mut custom, false, Option::None).unwrap());
    assert!(!custom.tls.as_ref().unwrap().pinned);
    let untrusting = f.untrusting_ctx();
    let private = crate::cert::testing::engine(&untrusting, InitSystem::None);
    assert!(!prepare_proxy_with(&private, &mut custom, false, Option::None).unwrap());
    assert!(custom.tls.as_ref().unwrap().pinned);
    // The deployed leaf comes first, so the pin is the leaf's.
    let pin = crate::render::tls::TlsMaterial::deployed(&f.ctx.paths).unwrap();
    assert!(crate::cert::openssl::validate_pair(
        &f.ctx,
        &CertDir::proxy(&f.ctx.paths).cert(),
        &CertDir::proxy(&f.ctx.paths).key(),
        "proxy.example.com",
        Trust::Public
    )
    .is_ok());
    assert_eq!(pin.pems().len(), 2);

    let mut nothing = config(&[(Protocol::VlessReality, 443, Core::Xray)]);
    assert!(!prepare_proxy_with(&engine, &mut nothing, true, Option::None).unwrap());
}

#[test]
fn web_certificates_must_be_publicly_trusted() {
    if !have_openssl() {
        return;
    }
    let f = Fixture::new("hooks-web");
    let engine = engine(&f.ctx, InitSystem::None);
    let (cert, key) = self_signed(&f.dir.join("self"), &["www.example.com"], 90);
    let web = WebCert::Custom { cert, key };
    let target = WebCertTarget {
        dir: f.ctx.paths.site(),
        domains: vec!["www.example.com".into()],
        cert: &web,
        webroot: Some(f.ctx.paths.site_root.clone()),
    };
    assert!(
        !web_needs_acme_with(&engine, &target, true),
        "custom certificates never run acme.sh"
    );
    let err = prepare_web_with(&engine, target.clone(), false, Option::None).unwrap_err();
    assert!(err.to_string().starts_with(PUBLIC_REQUIRED), "{err}");
    // FRP accepts a private certificate (v2 parity).
    let frp = CertDir::frp_web(&f.ctx.paths);
    let domains = vec!["www.example.com".to_owned()];
    assert!(issue_domains(
        &f.ctx,
        frp.path(),
        &domains,
        &web,
        Option::None,
        Option::None
    )
    .unwrap());
    assert!(!renew_dir(&f.ctx, frp.path(), false, Option::None).unwrap());

    let (chain, key) =
        f.ca.leaf(&f.dir.join("public"), &["www.example.com"], 90, false);
    let public = WebCert::Custom { cert: chain, key };
    let target = WebCertTarget {
        cert: &public,
        ..target
    };
    assert!(prepare_web_with(&engine, target.clone(), false, Option::None).unwrap());
    // Publicly valid, but recorded as custom: an HTTP-01 target is issued
    // anew, so acme.sh runs (and the site must answer on port 80).
    let http = WebCertTarget {
        cert: &WebCert::Http01,
        ..target.clone()
    };
    assert!(web_needs_acme_with(&engine, &http, false));
    let status = status(&f.ctx, &f.ctx.paths.site()).unwrap().unwrap();
    assert_eq!(status.metadata.unwrap().method, MethodId::Custom);
    assert_eq!(
        super::status(&f.ctx, &f.dir.join("none")).unwrap(),
        Option::None
    );
}

#[test]
fn http01_web_targets_use_the_given_webroot_or_the_responder() {
    if !have_openssl() {
        return;
    }
    let f = Fixture::new("hooks-web-acme");
    serve_release(&f.fake);
    let engine = engine(&f.ctx, InitSystem::None);
    let (chain, key) =
        f.ca.leaf(&f.dir.join("issued"), &["sub.example.com"], 90, false);
    fake_acme(
        &f.fake,
        AcmeScript {
            issue: Some((chain, key)),
            fetch_port: Some(engine.http01_port),
            ..AcmeScript::default()
        },
    );
    let target = WebCertTarget {
        dir: CertDir::subscription(&f.ctx.paths).path().to_path_buf(),
        domains: vec!["sub.example.com".into()],
        cert: &WebCert::Http01,
        webroot: Option::None,
    };
    assert!(prepare_web_with(&engine, target, false, Option::None).unwrap());
    let call = acme_calls(&f.fake).pop().unwrap();
    let webroot = CertDir::subscription(&f.ctx.paths).responder_webroot();
    assert!(call
        .args
        .ends_with(&["--webroot".into(), webroot.display().to_string()]));
    let m = CertDir::subscription(&f.ctx.paths)
        .metadata()
        .unwrap()
        .unwrap();
    assert_eq!(m.method, MethodId::Standalone);
}
