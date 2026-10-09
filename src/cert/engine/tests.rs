use super::*;
use crate::cert::method::MethodId;
use crate::cert::testing::{
    acme_calls, engine, fake_acme, have_openssl, serve_release, AcmeScript, Fixture,
};
use crate::render::tls::TlsMaterial;
use std::path::PathBuf;

fn spec(names: &[&str], source: Source, trust: Trust) -> CertSpec {
    CertSpec {
        domains: names.iter().map(|s| s.to_string()).collect(),
        source,
        trust,
    }
}

fn pin(dir: &CertDir) -> String {
    TlsMaterial::load(&dir.cert()).unwrap().pin().to_owned()
}

#[test]
fn self_signed_pairs_are_kept_until_renamed_or_invalid() {
    if !have_openssl() {
        return;
    }
    let f = Fixture::new("engine-self");
    let engine = engine(&f.ctx, InitSystem::None);
    let dir = CertDir::proxy(&f.ctx.paths);
    let bing = spec(&["www.bing.com"], Source::SelfSigned, Trust::Pinned);
    assert!(engine.ensure(&dir, &bing, false, None).unwrap());
    let first = pin(&dir);
    assert!(
        !engine.ensure(&dir, &bing, true, None).unwrap(),
        "force keeps a valid pair"
    );
    assert!(!engine.due(&dir, &bing).unwrap());
    let m = dir.metadata().unwrap().unwrap();
    assert_eq!((m.method, m.last_error), (MethodId::SelfSigned, None));
    assert!(m.last_success > 0);

    let renamed = spec(&["www.example.com"], Source::SelfSigned, Trust::Pinned);
    assert!(engine.due(&dir, &renamed).unwrap());
    assert!(engine.ensure(&dir, &renamed, false, None).unwrap());
    assert_ne!(pin(&dir), first);
    // A pair without metadata (migrated from v2) is kept while valid.
    std::fs::remove_file(dir.metadata_file()).unwrap();
    let kept = pin(&dir);
    assert!(!engine.ensure(&dir, &renamed, false, None).unwrap());
    assert_eq!(pin(&dir), kept);
}

#[test]
fn acme_pairs_issue_renew_when_due_or_forced() {
    if !have_openssl() {
        return;
    }
    let f = Fixture::new("engine-acme");
    serve_release(&f.fake);
    let engine = engine(&f.ctx, InitSystem::None);
    let (chain, key) =
        f.ca.leaf(&f.dir.join("issued"), &["a.example.com"], 90, false);
    let script = fake_acme(
        &f.fake,
        AcmeScript {
            issue: Some((chain, key)),
            ..AcmeScript::default()
        },
    );
    let dir = CertDir::site(&f.ctx.paths);
    let webroot = f.ctx.paths.site_root.clone();
    let http = spec(
        &["a.example.com"],
        Source::Acme(Challenge::Webroot(webroot.clone())),
        Trust::Public,
    );
    assert!(engine.ensure(&dir, &http, false, None).unwrap());
    let m = dir.metadata().unwrap().unwrap();
    assert_eq!(m.method, MethodId::Http);
    assert_eq!(m.webroot.as_deref(), Some(webroot.as_path()));
    assert_eq!(acme_calls(&f.fake).len(), 1);

    // Valid for 90 days: nothing to do, not due; forced renewal re-runs acme.sh.
    assert!(!engine.ensure(&dir, &http, false, None).unwrap());
    assert!(!engine.due(&dir, &http).unwrap());
    assert_eq!(acme_calls(&f.fake).len(), 1);
    assert!(
        !engine.ensure(&dir, &http, true, None).unwrap(),
        "same pair redeployed"
    );
    let forced = acme_calls(&f.fake).pop().unwrap();
    assert!(forced.args.contains(&"--renew".into()) && forced.args.contains(&"--force".into()));

    // The responder instead of the nginx webroot keeps the pair.
    let responder = spec(
        &["a.example.com"],
        Source::Acme(Challenge::Responder(webroot.clone())),
        Trust::Public,
    );
    assert!(!engine.ensure(&dir, &responder, false, None).unwrap());
    assert_eq!(acme_calls(&f.fake).len(), 2);

    // A pair inside the 30-day window is renewed without --force.
    let (short, short_key) =
        f.ca.leaf(&f.dir.join("short"), &["a.example.com"], 10, false);
    std::fs::copy(&short, dir.cert()).unwrap();
    std::fs::copy(&short_key, dir.key()).unwrap();
    assert!(engine.due(&dir, &http).unwrap());
    assert!(engine.ensure(&dir, &http, false, None).unwrap());
    let renewal = acme_calls(&f.fake).pop().unwrap();
    assert!(renewal.args.contains(&"--renew".into()) && !renewal.args.contains(&"--force".into()));

    // A failed issuance records the fixed text and keeps the pair.
    let before = std::fs::read(dir.cert()).unwrap();
    script.lock().unwrap().code = 1;
    let renamed = spec(
        &["b.example.com"],
        Source::Acme(Challenge::Webroot(webroot)),
        Trust::Public,
    );
    assert!(engine.ensure(&dir, &renamed, false, None).is_err());
    assert_eq!(std::fs::read(dir.cert()).unwrap(), before);
    let m = dir.metadata().unwrap().unwrap();
    assert_eq!(m.last_error.as_deref(), Some(ISSUE_FAILED));
    assert_eq!(m.domains, ["b.example.com"]);
    assert!(engine
        .renew(&dir, &renamed, RenewKind::Forced, None)
        .is_err());
    let m = dir.metadata().unwrap().unwrap();
    assert_eq!(m.last_error.as_deref(), Some(RENEW_FAILED));
}

#[test]
fn issued_pairs_must_be_publicly_trusted() {
    if !have_openssl() {
        return;
    }
    let f = Fixture::new("engine-untrusted");
    serve_release(&f.fake);
    let ctx = f.untrusting_ctx();
    let engine = engine(&ctx, InitSystem::None);
    let (chain, key) =
        f.ca.leaf(&f.dir.join("issued"), &["a.example.com"], 90, false);
    fake_acme(
        &f.fake,
        AcmeScript {
            issue: Some((chain, key)),
            ..AcmeScript::default()
        },
    );
    let dir = CertDir::site(&ctx.paths);
    let http = spec(
        &["a.example.com"],
        Source::Acme(Challenge::Webroot(ctx.paths.site_root.clone())),
        Trust::Public,
    );
    let err = engine
        .ensure(&dir, &http, false, None)
        .unwrap_err()
        .to_string();
    assert!(err.starts_with("证书未通过公共 CA 验证"), "{err}");
    assert!(!dir.has_pair());
}

#[test]
fn custom_pairs_follow_their_sources() {
    if !have_openssl() {
        return;
    }
    let f = Fixture::new("engine-custom");
    let engine = engine(&f.ctx, InitSystem::None);
    let src = f.dir.join("src");
    let (chain, key) = f.ca.leaf(&src, &["a.example.com"], 90, true);
    let dir = CertDir::proxy(&f.ctx.paths);
    let custom = spec(
        &["a.example.com"],
        Source::Custom {
            cert: chain.clone(),
            key: key.clone(),
        },
        Trust::Pinned,
    );
    assert!(engine.due(&dir, &custom).unwrap(), "nothing deployed yet");
    assert!(engine.ensure(&dir, &custom, false, None).unwrap());
    assert!(
        !engine.due(&dir, &custom).unwrap(),
        "a CA-first source matches its leaf-first copy"
    );
    assert!(!engine.ensure(&dir, &custom, false, None).unwrap());
    let m = dir.metadata().unwrap().unwrap();
    assert_eq!(m.source_cert.as_deref(), Some(chain.as_path()));

    // Refreshed sources are due and redeployed by a renewal.
    f.ca.leaf(&src, &["a.example.com"], 90, false);
    assert!(engine.due(&dir, &custom).unwrap());
    let renewed = engine.renew(&dir, &custom, RenewKind::Scheduled, None);
    assert_eq!(renewed.unwrap(), Renewal::Changed);
    assert!(!engine.due(&dir, &custom).unwrap());
    // A vanished source is not due (no nightly failure), but an apply
    // that needs it fails.
    let gone = spec(
        &["a.example.com"],
        Source::Custom {
            cert: PathBuf::from("/nonexistent/cert.pem"),
            key,
        },
        Trust::Pinned,
    );
    assert!(!engine.due(&dir, &gone).unwrap());
    let err = engine.ensure(&dir, &gone, false, None).unwrap_err();
    assert_eq!(
        err.to_string(),
        "证书或私钥文件不存在: /nonexistent/cert.pem"
    );
}

#[test]
fn deleted_custom_sources_keep_the_deployed_pair() {
    if !have_openssl() {
        return;
    }
    let f = Fixture::new("engine-custom-gone");
    let engine = engine(&f.ctx, InitSystem::None);
    let src = f.dir.join("src");
    let (chain, key) = f.ca.leaf(&src, &["a.example.com"], 90, false);
    let dir = CertDir::proxy(&f.ctx.paths);
    let custom = spec(
        &["a.example.com"],
        Source::Custom {
            cert: chain.clone(),
            key: key.clone(),
        },
        Trust::Pinned,
    );
    assert!(engine.ensure(&dir, &custom, false, None).unwrap());
    let deployed = pin(&dir);
    // The user removes the source once Onebox holds a copy: applies (and
    // forced renewals) keep the deployed pair.
    std::fs::remove_file(&chain).unwrap();
    assert!(!engine.ensure(&dir, &custom, false, None).unwrap());
    let m = dir.metadata().unwrap().unwrap();
    assert_eq!(m.last_error, None);
    assert_eq!(
        engine
            .renew(&dir, &custom, RenewKind::Forced, None)
            .unwrap(),
        Renewal::Unchanged
    );
    assert_eq!(pin(&dir), deployed);
    // Other names, or a deployed pair that no longer validates, fail and
    // name the missing file.
    let renamed = spec(
        &["b.example.com"],
        Source::Custom {
            cert: chain.clone(),
            key: key.clone(),
        },
        Trust::Pinned,
    );
    let err = engine.ensure(&dir, &renamed, false, None).unwrap_err();
    assert_eq!(
        err.to_string(),
        format!("证书或私钥文件不存在: {}", chain.display())
    );
    std::fs::write(dir.cert(), "broken").unwrap();
    let err = engine.ensure(&dir, &custom, false, None).unwrap_err();
    assert_eq!(
        err.to_string(),
        format!("证书或私钥文件不存在: {}", chain.display())
    );
    // A missing key is named too; other recorded sources are not "the same".
    let (chain2, key2) =
        f.ca.leaf(&f.dir.join("src2"), &["a.example.com"], 90, false);
    let fresh = spec(
        &["a.example.com"],
        Source::Custom {
            cert: chain2,
            key: key2.clone(),
        },
        Trust::Pinned,
    );
    assert!(engine.ensure(&dir, &fresh, false, None).unwrap());
    std::fs::remove_file(&key2).unwrap();
    let moved = spec(
        &["a.example.com"],
        Source::Custom {
            cert: f.dir.join("src2/chain.pem"),
            key: f.dir.join("elsewhere/key.pem"),
        },
        Trust::Pinned,
    );
    let err = engine.ensure(&dir, &moved, false, None).unwrap_err();
    assert_eq!(
        err.to_string(),
        format!(
            "证书或私钥文件不存在: {}",
            f.dir.join("elsewhere/key.pem").display()
        )
    );
}

/// Put `(chain, key)` where acme.sh keeps the pair of `primary`.
fn hold(dir: &CertDir, primary: &str, pair: &(PathBuf, PathBuf)) {
    let (cert, key) = acme::issued_pair(dir, primary);
    std::fs::copy(&pair.0, cert).unwrap();
    std::fs::copy(&pair.1, key).unwrap();
}

fn deploy(dir: &CertDir, pair: &(PathBuf, PathBuf)) {
    std::fs::copy(&pair.0, dir.cert()).unwrap();
    std::fs::copy(&pair.1, dir.key()).unwrap();
}

#[test]
fn not_due_renewals_deploy_what_acme_sh_holds() {
    if !have_openssl() {
        return;
    }
    let f = Fixture::new("engine-not-due");
    serve_release(&f.fake);
    let engine = engine(&f.ctx, InitSystem::None);
    let names = ["a.example.com"];
    let first = f.ca.leaf(&f.dir.join("first"), &names, 90, false);
    let script = fake_acme(
        &f.fake,
        AcmeScript {
            issue: Some(first),
            ..AcmeScript::default()
        },
    );
    let dir = CertDir::site(&f.ctx.paths);
    let http = spec(
        &names,
        Source::Acme(Challenge::Webroot(f.ctx.paths.site_root.clone())),
        Trust::Public,
    );
    assert!(engine.ensure(&dir, &http, false, None).unwrap());

    // acme.sh renewed (exit 0) but the deployment failed afterwards: the
    // deployed pair is due, acme.sh holds a newer one and now says "not
    // due" (exit 2). The newer pair is deployed.
    let short = f.ca.leaf(&f.dir.join("short"), &names, 10, false);
    let newer = f.ca.leaf(&f.dir.join("newer"), &names, 90, false);
    deploy(&dir, &short);
    hold(&dir, "a.example.com", &newer);
    {
        let mut s = script.lock().unwrap();
        s.code = 2;
        s.issue = None;
    }
    assert!(engine.due(&dir, &http).unwrap());
    let outcome = engine.renew(&dir, &http, RenewKind::Scheduled, None);
    assert_eq!(outcome.unwrap(), Renewal::Changed);
    assert_eq!(pin(&dir), TlsMaterial::load(&newer.0).unwrap().pin());
    let call = acme_calls(&f.fake).pop().unwrap();
    assert!(call.args.contains(&"--renew".into()) && !call.args.contains(&"--force".into()));
    // The same through an apply (1–30 days left).
    deploy(&dir, &short);
    assert!(engine.ensure(&dir, &http, false, None).unwrap());
    assert_eq!(pin(&dir), TlsMaterial::load(&newer.0).unwrap().pin());
    let succeeded = dir.metadata().unwrap().unwrap().last_success;
    assert!(succeeded > 0);
    // Nothing newer held while the deployed pair is still due: deferred,
    // not a success (the success time stays, the deferral is recorded).
    deploy(&dir, &short);
    hold(&dir, "a.example.com", &short);
    let mut m = dir.metadata().unwrap().unwrap();
    m.last_success = 1;
    dir.save_metadata(&m).unwrap();
    let outcome = engine.renew(&dir, &http, RenewKind::Scheduled, None);
    assert_eq!(outcome.unwrap(), Renewal::Deferred);
    let m = dir.metadata().unwrap().unwrap();
    assert_eq!(m.last_success, 1);
    assert_eq!(m.last_error.as_deref(), Some(RENEW_DEFERRED));
    assert!(!engine.ensure(&dir, &http, false, None).unwrap());
    assert_eq!(dir.metadata().unwrap().unwrap().last_success, 1);
    // A pair acme.sh holds that no longer validates is a failure, not
    // "unchanged".
    std::fs::write(acme::issued_pair(&dir, "a.example.com").0, "garbage").unwrap();
    assert!(engine
        .renew(&dir, &http, RenewKind::Scheduled, None)
        .is_err());
    // Forced renewals never accept exit 2.
    assert!(engine.renew(&dir, &http, RenewKind::Forced, None).is_err());
}

#[test]
fn will_contact_acme_follows_the_ensure_rules() {
    if !have_openssl() {
        return;
    }
    let f = Fixture::new("engine-will-contact");
    let engine = engine(&f.ctx, InitSystem::None);
    let names = ["a.example.com"];
    let dir = CertDir::site(&f.ctx.paths);
    let webroot = f.ctx.paths.site_root.clone();
    let http = spec(
        &names,
        Source::Acme(Challenge::Webroot(webroot.clone())),
        Trust::Public,
    );
    let dns = spec(&names, Source::Acme(Challenge::Cloudflare), Trust::Public);
    assert!(
        engine.will_contact_acme(&dir, &http, false),
        "nothing deployed"
    );
    dir.ensure().unwrap();
    deploy(&dir, &f.ca.leaf(&f.dir.join("valid"), &names, 90, false));
    assert!(
        !engine.will_contact_acme(&dir, &http, false),
        "valid, no metadata"
    );
    assert!(engine.will_contact_acme(&dir, &http, true), "forced");
    // Metadata of another method: the engine issues anew.
    let mut cf_meta = Metadata::attempt(&dns, None, 1);
    cf_meta.last_success = 1;
    dir.save_metadata(&cf_meta).unwrap();
    assert!(engine.will_contact_acme(&dir, &http, false));
    assert!(!engine.will_contact_acme(&dir, &dns, false));
    // Due within 30 days: a renewal.
    deploy(&dir, &f.ca.leaf(&f.dir.join("short"), &names, 10, false));
    assert!(engine.will_contact_acme(&dir, &dns, false));
    // Self-signed and custom certificates never contact acme.sh.
    let own = spec(&names, Source::SelfSigned, Trust::Pinned);
    assert!(!engine.will_contact_acme(&dir, &own, true));
}

#[test]
fn cloudflare_needs_credentials_and_persists_them() {
    if !have_openssl() {
        return;
    }
    let f = Fixture::new("engine-cf");
    serve_release(&f.fake);
    let engine = engine(&f.ctx, InitSystem::None);
    let (chain, key) = f.ca.leaf(
        &f.dir.join("issued"),
        &["a.example.com", "*.a.example.com"],
        90,
        false,
    );
    fake_acme(
        &f.fake,
        AcmeScript {
            issue: Some((chain, key)),
            ..AcmeScript::default()
        },
    );
    let dir = CertDir::frp_web(&f.ctx.paths);
    let dns = spec(
        &["a.example.com", "*.a.example.com"],
        Source::Acme(Challenge::Cloudflare),
        Trust::Public,
    );
    let err = engine.ensure(&dir, &dns, false, None).unwrap_err();
    assert_eq!(err.to_string(), cloudflare::MISSING);
    assert!(
        acme_calls(&f.fake).is_empty(),
        "nothing ran without credentials"
    );
    let creds = CfCredentials::token("cf-token", None).unwrap();
    assert!(engine.ensure(&dir, &dns, false, Some(&creds)).unwrap());
    let call = acme_calls(&f.fake).pop().unwrap();
    assert!(call.env.contains(&("CF_Token".into(), "cf-token".into())));
    // A later forced renewal (cron, FRP) finds the stored credentials.
    let renewed = engine.renew(&dir, &dns, RenewKind::Forced, None).unwrap();
    assert_eq!(renewed, Renewal::Unchanged);
    let stored = std::fs::read_to_string(cloudflare::store_path(dir.path())).unwrap();
    assert_eq!(stored, r#"{"CF_Token":"cf-token"}"#);
    let metadata = std::fs::read_to_string(dir.metadata_file()).unwrap();
    assert!(!metadata.contains("cf-token"));
}
