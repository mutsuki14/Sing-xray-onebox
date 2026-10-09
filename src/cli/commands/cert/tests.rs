use super::*;
use crate::cert::CertScope;
use crate::cli::args::{parse, Globals};
use crate::cli::session::testing::{Bench, Call};
use crate::domain::config::{AcmeMethod, ProxyCertMode};
use crate::domain::fixtures::config;
use crate::domain::protocol::Core::{Singbox as SB, Xray as XR};
use crate::domain::protocol::Protocol::*;
use std::sync::Mutex;

fn invocation(line: &str) -> (bool, Matches) {
    let argv: Vec<String> = line.split_whitespace().map(String::from).collect();
    let inv = parse(&[CERT, CERT_RENEW, RENEW], &argv, Globals::default())
        .unwrap_or_else(|e| panic!("{line}: {e}"));
    (inv.spec.root.required(&inv.matches), inv.matches)
}

#[test]
fn command_forms_and_root() {
    let (root, m) = invocation("cert");
    assert!(!root && m.path == ["cert"]);
    let (root, m) = invocation("cert status");
    assert!(!root && m.path == ["cert", "info"]);
    let (root, m) = invocation("cert renew proxy --cron");
    assert!(root && m.flag("cron"));
    assert_eq!(targets(&m).unwrap(), CertScopes::only(CertScope::Proxy));
    let (_, m) = invocation("cert --cron renew site");
    assert!(m.flag("cron") && m.path == ["cert", "renew"]);
    let (root, m) = invocation("cert-renew subscription --cron");
    assert!(root);
    assert_eq!(
        targets(&m).unwrap(),
        CertScopes::only(CertScope::Subscription)
    );
    let (_, m) = invocation("cert renew");
    assert_eq!(targets(&m).unwrap(), CertScopes::ALL);
    let (_, m) = invocation("cert renew bogus");
    assert_eq!(
        targets(&m).unwrap_err().to_string(),
        "续期目标应为 proxy/site/subscription/all"
    );
    let (root, _) = invocation("renew --cron");
    assert!(root);
    let (root, _) = invocation("cert set --tls self");
    assert!(root);
}

#[test]
fn info_lists_certificate_directories() {
    let bench = Bench::installed(&config(&[(VlessReality, 443, XR)]));
    info(&bench.session()).unwrap();
    assert_eq!(
        bench.output(),
        "代理证书\n  未配置证书\n网站证书\n  未配置证书"
    );
    let mut cfg = config(&[(VlessReality, 443, XR)]);
    cfg.subscription = Some(crate::domain::fixtures::standalone_subscription(
        "sub.example.com",
        8448,
        crate::domain::config::WebCert::Cloudflare,
    ));
    let bench = Bench::installed(&cfg);
    info(&bench.session()).unwrap();
    assert!(bench.output().ends_with("订阅证书\n  未配置证书"));
}

fn trojan() -> NodeConfig {
    config(&[(Trojan, 443, SB)])
}

#[test]
fn set_asks_interactively_or_needs_tls() {
    let bench = Bench::installed(&trojan());
    bench.answers(&["2", "proxy.example.com"]);
    set(&bench.session(), None).unwrap();
    let req = bench.engine.single();
    assert_eq!(req.reason, "更换代理证书");
    assert_eq!(
        req.config.tls.unwrap().mode,
        ProxyCertMode::Acme {
            domain: "proxy.example.com".into(),
            method: AcmeMethod::Http01
        }
    );
    assert_eq!(bench.ui.prompts()[0], "选择代理证书方式");
    bench.unattended();
    let err = set(&bench.session(), None).unwrap_err();
    assert_eq!(err.to_string(), SET_NEEDS_TLS);
}

#[test]
fn set_with_options() {
    let bench = Bench::installed(&trojan());
    bench.unattended();
    let args = opt::CertArgs {
        choice: Some(plan::ProxyCertChoice::SelfSigned),
        vmess_host: None,
    };
    set(&bench.session(), Some(args)).unwrap();
    assert_eq!(bench.engine.single().reason, "更换代理证书");
    let reality = Bench::installed(&config(&[(VlessReality, 443, XR)]));
    let args = opt::CertArgs {
        choice: Some(plan::ProxyCertChoice::SelfSigned),
        vmess_host: None,
    };
    let err = set(&reality.session(), Some(args)).unwrap_err();
    assert_eq!(
        err.to_string(),
        "当前协议无需代理 TLS 证书，自建站证书请使用 site 管理"
    );
}

#[test]
fn set_with_cloudflare_needs_credentials_first() {
    if std::env::var_os("CF_Token").is_some() {
        return;
    }
    let bench = Bench::installed(&trojan());
    bench.unattended();
    let args = opt::CertArgs {
        choice: Some(plan::ProxyCertChoice::Acme {
            domain: "proxy.example.com".into(),
            method: AcmeMethod::Cloudflare,
        }),
        vmess_host: None,
    };
    let err = set(&bench.session(), Some(args.clone())).unwrap_err();
    assert_eq!(err.to_string(), crate::cert::cloudflare::MISSING);
    assert!(bench.engine.calls().is_empty(), "nothing applied");
    let bench = Bench::installed(&trojan());
    bench.answers(&["fake-token-0123", ""]);
    set(&bench.session(), Some(args)).unwrap();
    let creds = bench.engine.single().intents.cloudflare.unwrap();
    assert_eq!(creds.get("CF_Token"), Some("fake-token-0123"));
}

static REPORT: Mutex<Option<RenewReport>> = Mutex::new(None);

fn scripted(
    _ctx: &Ctx,
    lock: &FileLock,
    _cfg: &NodeConfig,
    opts: &RenewOptions,
    _cf: Option<&CfCredentials>,
) -> Result<RenewReport> {
    assert!(lock.path().ends_with(".apply.lock"));
    assert_eq!(opts.force, !opts.scheduled, "manual renewals force");
    Ok(REPORT.lock().unwrap().clone().unwrap_or_default())
}

#[test]
fn renewal_outcomes() {
    let _guard = serial();
    let bench = Bench::installed(&config(&[(VlessReality, 443, XR)]));
    *REPORT.lock().unwrap() = None;
    renew_with(&bench.session(), CertScopes::ALL, false, scripted).unwrap();
    assert_eq!(bench.notes(), ["[提示] 没有需要续期的证书"]);
    assert_eq!(bench.engine.calls(), [Call::RecoverLocked]);
    renew_with(&bench.session(), CertScopes::ALL, true, scripted).unwrap();
    assert_eq!(bench.notes().len(), 1, "silent under --cron");
    *REPORT.lock().unwrap() = Some(RenewReport {
        renewed: vec![CertScope::Proxy],
        proxy_identity_changed: true,
        ..RenewReport::default()
    });
    renew_with(&bench.session(), CertScopes::ALL, true, scripted).unwrap();
    let calls = bench.engine.calls();
    assert_eq!(calls.last(), Some(&Call::ApplyLocked));
    let req = bench.engine.single();
    assert_eq!(req.reason, "证书续期");
    assert_eq!(req.config, bench.state(), "unchanged configuration");
    *REPORT.lock().unwrap() = Some(RenewReport {
        failed: vec![
            (CertScope::Site, "boom".into()),
            (CertScope::Proxy, "x".into()),
        ],
        ..RenewReport::default()
    });
    let err = renew_with(&bench.session(), CertScopes::ALL, false, scripted).unwrap_err();
    assert_eq!(err.to_string(), "证书续期失败: 网站证书、代理证书");
    *REPORT.lock().unwrap() = None;
}

#[test]
fn renewal_needs_root_and_a_free_lock() {
    let _guard = serial();
    let mut bench = Bench::installed(&config(&[(VlessReality, 443, XR)]));
    bench.is_root = false;
    let err = renew_with(&bench.session(), CertScopes::ALL, false, scripted).unwrap_err();
    assert_eq!(err.to_string(), "此操作需要 root 权限");
    bench.is_root = true;
    let _held = FileLock::acquire(&bench.ctx.paths.lock(), BUSY_MESSAGE).unwrap();
    let err = renew_with(&bench.session(), CertScopes::ALL, false, scripted).unwrap_err();
    assert_eq!(err.to_string(), BUSY_MESSAGE);
    assert!(bench.engine.calls().is_empty());
}

/// The scripted report is shared: renewal tests run one at a time.
pub(super) fn serial() -> std::sync::MutexGuard<'static, ()> {
    static SERIAL: Mutex<()> = Mutex::new(());
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
