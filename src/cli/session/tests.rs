use super::testing::{Bench, Call};
use super::*;
use crate::domain::config::{AcmeMethod, ProxyCertMode, ProxyTls};
use crate::domain::fixtures::config;
use crate::domain::protocol::{Core, Protocol};
use crate::state::StateHash;

fn trojan_cf() -> NodeConfig {
    let mut cfg = config(&[(Protocol::Trojan, 443, Core::Singbox)]);
    cfg.tls = Some(ProxyTls {
        mode: ProxyCertMode::Acme {
            domain: "proxy.example.com".into(),
            method: AcmeMethod::Cloudflare,
        },
        pinned: false,
    });
    cfg
}

#[test]
fn load_requires_an_installed_node() {
    let bench = Bench::new();
    let err = bench.session().load().unwrap_err();
    assert_eq!(err.to_string(), "尚未安装 Onebox，请先执行 onebox install");
    assert!(bench.session().load_optional().unwrap().is_none());
    assert!(!bench.session().installed());
}

/// A state file that cannot be looked at (EACCES for a non-root user in
/// the 0700 ROOT) counts as installed, so previews ask for root instead
/// of planning against no node.
#[test]
fn unreadable_state_counts_as_installed() {
    use std::io::{Error as IoError, ErrorKind};
    let bench = Bench::new();
    let paths = &bench.ctx.paths;
    assert!(!installed_with(paths, &|_| Err(IoError::from(
        ErrorKind::NotFound
    ))));
    assert!(installed_with(paths, &|_| Err(IoError::from(
        ErrorKind::PermissionDenied
    ))));
    let state = paths.state();
    assert!(installed_with(paths, &|p| if p == state {
        Ok(())
    } else {
        Err(IoError::from(ErrorKind::NotFound))
    }));
    let v1 = paths.legacy_v1_state();
    std::fs::create_dir_all(v1.parent().unwrap()).unwrap();
    std::fs::write(&v1, "").unwrap();
    assert!(bench.session().installed(), "a v1 config is a node too");
}

#[test]
fn permission_errors_explain_root() {
    let io = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
    let err = explain_permission(Error::io("/etc/onebox/state.json", io));
    assert_eq!(err.to_string(), ROOT_REQUIRED);
    let other = explain_permission(Error::msg("坏了"));
    assert_eq!(other.to_string(), "坏了");
}

#[test]
fn v2_state_is_migrated_in_memory_and_carries_devices() {
    let bench = Bench::new();
    crate::apply::testing::file(
        &bench.ctx.paths.state(),
        0o600,
        crate::apply::testing::V2_STATE,
    );
    let loaded = bench.session().load().unwrap();
    assert!(matches!(loaded.origin, Origin::V2 { .. }));
    let req = request(&loaded, loaded.config.clone(), "重新生成配置");
    assert_eq!(req.expected, loaded.hash);
    assert_eq!(req.reason, "重新生成配置");
    // Loading never writes: the v2 file is untouched and no copy exists.
    assert_eq!(
        std::fs::read(bench.ctx.paths.state()).unwrap(),
        crate::apply::testing::V2_STATE
    );
    assert!(!bench.ctx.paths.state_v2_backup().exists());
}

#[test]
fn cloudflare_credentials_are_resolved_before_apply() {
    let bench = Bench::installed(&trojan_cf());
    let session = bench.session();
    let loaded = session.load().unwrap();
    // Unattended: the v2 "missing credentials" error, nothing applied.
    bench.unattended();
    let req = request(&loaded, loaded.config.clone(), "测试");
    if std::env::var_os("CF_Token").is_none() {
        let err = session.apply(req).unwrap_err();
        assert_eq!(err.to_string(), cloudflare::MISSING);
        assert!(bench.engine.calls().is_empty());
    }
}

/// Interactive: the token is asked for before the engine runs, and the
/// renewals the request forces count too.
#[test]
fn apply_carries_prompted_cloudflare_credentials() {
    if std::env::var_os("CF_Token").is_some() {
        return;
    }
    let bench = Bench::installed(&trojan_cf());
    let session = bench.session();
    let loaded = session.load().unwrap();
    bench.answers(&["fake-token-0123", ""]);
    let mut req = request(&loaded, loaded.config.clone(), "测试");
    req.intents.renew = crate::cert::CertScopes::ALL;
    session.apply(req).unwrap();
    let creds = bench.engine.single().intents.cloudflare.unwrap();
    assert_eq!(creds.get("CF_Token"), Some("fake-token-0123"));
    // Credentials already in the request are not asked for again.
    let mut req = request(&loaded, loaded.config.clone(), "测试");
    req.intents.cloudflare = Some(creds);
    session.apply(req).unwrap();
    assert_eq!(bench.ui.remaining(), 0);
    assert_eq!(bench.engine.requests().len(), 2);
}

#[test]
fn apply_passes_the_request_to_the_engine() {
    let bench = Bench::installed(&config(&[(Protocol::VlessReality, 443, Core::Xray)]));
    let session = bench.session();
    let loaded = session.load().unwrap();
    session
        .apply(request(&loaded, loaded.config.clone(), "重新生成配置"))
        .unwrap();
    assert_eq!(bench.engine.calls(), [Call::Apply]);
    let req = bench.engine.single();
    assert_ne!(req.expected, StateHash::absent());
    assert!(req.intents.cloudflare.is_none());
}

#[test]
fn facts_and_probe_follow_the_host() {
    let bench = Bench::new();
    bench.live.occupy(8443, Transport::Udp);
    let session = bench.session();
    let probe = LiveProbe(session.live);
    assert!(probe.in_use(8443, Transport::Udp));
    assert!(!probe.in_use(8443, Transport::Tcp));
    let facts = session.facts().unwrap();
    assert!(facts.ipv6);
    let env = facts.env(&probe, None);
    assert_eq!(env.now, 1_700_000_000);
    assert!(session.require_root().is_ok());
    let session = Session::new(&bench.ctx, &bench.engine, &bench.live, false);
    assert_eq!(
        session.require_root().unwrap_err().to_string(),
        ROOT_REQUIRED
    );
}
