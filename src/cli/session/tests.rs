use super::testing::{Bench, Call};
use super::*;
use crate::domain::config::{AcmeMethod, ProxyCertMode, ProxyTls, WebCert};
use crate::domain::fixtures::{config, with_site};
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

#[test]
fn credential_decisions() {
    let bench = Bench::new();
    assert!(resolve_cloudflare(bench.ui.as_ref(), &[])
        .unwrap()
        .is_none());
    bench.answers(&["fake-token-0123", ""]);
    let creds = resolve_cloudflare(bench.ui.as_ref(), &[CertScope::Site])
        .unwrap()
        .unwrap();
    assert_eq!(creds.get("CF_Token"), Some("fake-token-0123"));
    assert_eq!(
        bench.ui.prompts(),
        [
            "Cloudflare API Token",
            "Cloudflare Account ID（可留空自动查询）"
        ]
    );
    bench.unattended();
    let err = resolve_cloudflare(bench.ui.as_ref(), &[CertScope::Proxy]).unwrap_err();
    assert_eq!(err.to_string(), cloudflare::MISSING);
}

#[test]
fn cloudflare_targets_list_certificates_without_credentials() {
    if std::env::var_os("CF_Token").is_some() {
        return;
    }
    let bench = Bench::new();
    let mut site = with_site(
        config(&[(Protocol::VlessReality, 443, Core::Singbox)]),
        "www.example.com",
        true,
    );
    assert!(cloudflare_targets(&bench.ctx, &site, CertScopes::NONE).is_empty());
    if let Some(s) = site.site.as_mut() {
        s.cert = WebCert::Cloudflare;
    }
    assert_eq!(
        cloudflare_targets(&bench.ctx, &site, CertScopes::NONE),
        [CertScope::Site]
    );
    assert_eq!(
        cloudflare_targets(&bench.ctx, &trojan_cf(), CertScopes::NONE),
        [CertScope::Proxy]
    );
    // Stored credentials satisfy the lookup.
    let creds = CfCredentials::token("fake-token-0123", None).unwrap();
    cloudflare::persist(&bench.ctx.paths.tls(), &creds).unwrap();
    assert!(cloudflare_targets(&bench.ctx, &trojan_cf(), CertScopes::NONE).is_empty());
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
