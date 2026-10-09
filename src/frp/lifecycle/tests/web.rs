//! Web mode on the fake host with the real openssl and a fake acme.sh:
//! HTTP-01 through the bootstrap nginx, Cloudflare DNS credentials
//! persisted by the transaction, and renewals whose website part fails.

use super::{change, mode_of};
use crate::cert::cloudflare::{CfCredentials, STORE_FILE};
use crate::cert::testing::{acme_calls, fake_acme, AcmeScript, Script};
use crate::frp::ca::ControlFiles;
use crate::frp::journal;
use crate::frp::lifecycle::{apply, renew, Change};
use crate::frp::model::{self, WebTls};
use crate::frp::testing::{tcp_state, web_state, FakeHost};
use crate::host::service::{FRPS, FRP_WEB};
use std::fs;

/// A fake acme.sh issuing a test-CA pair for `app.example.com`.
fn acme(h: &FakeHost, label: &str) -> Script {
    let pair = h.public_pair(label, &["app.example.com"]);
    fake_acme(
        &h.exec,
        AcmeScript {
            issue: Some(pair),
            ..AcmeScript::default()
        },
    )
}

/// The steps of a web deployment worth ordering: nginx tests, service
/// changes and acme.sh runs (`acme.sh issue|renew`).
fn web_steps(h: &FakeHost) -> Vec<String> {
    h.timeline()
        .into_iter()
        .filter_map(|c| {
            if c.contains("/acme.sh ") {
                let kind = if c.contains(" --issue ") {
                    "issue"
                } else {
                    "renew"
                };
                return Some(format!("acme.sh {kind}"));
            }
            let keep = c.starts_with("nginx -t")
                || ["start", "stop", "restart", "enable"]
                    .iter()
                    .any(|a| c.starts_with(&format!("systemctl {a} onebox-")));
            keep.then_some(c)
        })
        .collect()
}

fn install_http01(h: &FakeHost) -> Script {
    let script = acme(h, "issued");
    let mut state = web_state(WebTls::Http01);
    state.token.clear();
    apply(&h.runtime(), state, change("安装")).unwrap();
    script
}

#[test]
fn http01_issues_through_the_bootstrap_nginx_then_starts_the_full_one() {
    let Some(h) = FakeHost::with_real_openssl() else {
        return;
    };
    install_http01(&h);
    assert_eq!(
        web_steps(&h),
        [
            "systemctl stop onebox-frp-web",
            "systemctl stop onebox-frps",
            "nginx -t bootstrap",
            "systemctl start onebox-frp-web",
            "acme.sh issue",
            "systemctl stop onebox-frp-web",
            "nginx -t full",
            "systemctl start onebox-frp-web",
            "systemctl enable onebox-frp-web",
            "systemctl start onebox-frps",
            "systemctl enable onebox-frps",
        ]
    );
    let paths = &h.ctx.paths;
    let issue = &acme_calls(&h.exec)[0];
    let webroot = paths.frp_web.join("www").to_string_lossy().into_owned();
    let at = issue.args.iter().position(|a| a == "--webroot").unwrap();
    assert_eq!(issue.args[at + 1], webroot);
    assert!(issue.env.iter().all(|(k, _)| !k.starts_with("CF_")));
    let conf = fs::read_to_string(paths.frp_root.join("nginx.conf")).unwrap();
    assert!(conf.contains("ssl_certificate"), "{conf}");
    assert!(paths.frp_root.join("web-tls/cert.pem").is_file());
    assert!(h.running(FRP_WEB) && h.enabled(FRP_WEB));
    assert!(h.running(FRPS) && h.enabled(FRPS));
    assert!(!journal::exists(paths));
}

fn cloudflare() -> Change {
    Change {
        cloudflare: Some(CfCredentials::token("fake-token-0123", None).unwrap()),
        ..change("安装")
    }
}

#[test]
fn cloudflare_credentials_are_persisted_inside_the_transaction() {
    let Some(h) = FakeHost::with_real_openssl() else {
        return;
    };
    acme(&h, "issued");
    let mut state = web_state(WebTls::Cloudflare);
    state.token.clear();
    apply(&h.runtime(), state, cloudflare()).unwrap();
    let paths = &h.ctx.paths;
    let store = paths.frp_root.join("web-tls").join(STORE_FILE);
    assert_eq!(mode_of(&store), 0o600);
    assert_eq!(
        fs::read_to_string(&store).unwrap(),
        r#"{"CF_Token":"fake-token-0123"}"#
    );
    // Only acme.sh got the token, through its own environment; DNS-01
    // needs no bootstrap nginx.
    let issue = &acme_calls(&h.exec)[0];
    assert!(issue.args.windows(2).any(|w| w == ["--dns", "dns_cf"]));
    let token = ("CF_Token".to_owned(), "fake-token-0123".to_owned());
    assert!(issue.env.contains(&token));
    assert_eq!(
        h.exec
            .calls()
            .iter()
            .filter(|c| c.env.contains(&token))
            .count(),
        1
    );
    assert!(!web_steps(&h).contains(&"nginx -t bootstrap".to_owned()));
    assert!(h.running(FRP_WEB));
}

#[test]
fn a_rolled_back_cloudflare_install_leaves_no_credentials() {
    let Some(h) = FakeHost::with_real_openssl() else {
        return;
    };
    acme(&h, "issued");
    let paths = &h.ctx.paths;
    let store = paths.frp_root.join("web-tls").join(STORE_FILE);
    // A fresh install whose health check fails: no FRP tree is left.
    h.set_healthy(false);
    let mut state = web_state(WebTls::Cloudflare);
    state.token.clear();
    apply(&h.runtime(), state, cloudflare()).unwrap_err();
    assert!(!paths.frp_root.exists());
    // A tcp installation switched to Cloudflare web mode: rolled back to
    // tcp, without the stored credentials.
    h.set_healthy(true);
    let mut tcp = tcp_state();
    tcp.token.clear();
    apply(&h.runtime(), tcp, change("安装")).unwrap();
    let installed = model::load(paths).unwrap().unwrap();
    let mut web = web_state(WebTls::Cloudflare);
    web.token.clone_from(&installed.token);
    h.set_healthy(false);
    apply(&h.runtime(), web, cloudflare()).unwrap_err();
    assert_eq!(model::load(paths).unwrap().unwrap(), installed);
    assert!(!store.exists(), "{}", store.display());
    assert!(!h.running(FRP_WEB));
    assert!(!journal::exists(paths));
}

#[test]
fn a_failed_website_renewal_commits_the_control_certificate() {
    let Some(h) = FakeHost::with_real_openssl() else {
        return;
    };
    let script = install_http01(&h);
    let paths = &h.ctx.paths;
    let rt = h.runtime();
    let lock = rt.lock().unwrap();
    let control = ControlFiles::new(&paths.frp_root);
    let deployed = fs::read(paths.frp_root.join("web-tls/cert.pem")).unwrap();
    // The control certificate must be replaced; acme.sh fails.
    fs::remove_file(control.cert()).unwrap();
    script.lock().unwrap().code = 1;
    h.clear_history();
    let err = renew(&rt, &lock, false).unwrap_err().to_string();
    assert!(err.starts_with("FRP 网站证书续期失败: "), "{err}");
    assert!(control.cert().is_file(), "the control change committed");
    assert!(!journal::exists(paths));
    assert_eq!(
        fs::read(paths.frp_root.join("web-tls/cert.pem")).unwrap(),
        deployed
    );
    assert_eq!(
        web_steps(&h),
        ["acme.sh renew", "systemctl restart onebox-frps"]
    );
    // A website renewal that deploys a new pair restarts only nginx.
    let renewed = h.public_pair("renewed", &["app.example.com"]);
    {
        let mut s = script.lock().unwrap();
        s.code = 0;
        s.issue = Some(renewed);
    }
    h.clear_history();
    renew(&rt, &lock, false).unwrap();
    assert_eq!(
        web_steps(&h),
        [
            "acme.sh renew",
            "nginx -t full",
            "systemctl restart onebox-frp-web"
        ]
    );
    assert_ne!(
        fs::read(paths.frp_root.join("web-tls/cert.pem")).unwrap(),
        deployed
    );
}

#[test]
fn a_renewed_pair_nginx_cannot_load_rolls_the_renewal_back() {
    let Some(h) = FakeHost::with_real_openssl() else {
        return;
    };
    let script = install_http01(&h);
    let paths = &h.ctx.paths;
    let rt = h.runtime();
    let lock = rt.lock().unwrap();
    let cert = paths.frp_root.join("web-tls/cert.pem");
    let deployed = fs::read(&cert).unwrap();
    let metadata = fs::read(paths.frp_root.join("web-tls/certificate.json")).unwrap();
    script.lock().unwrap().issue = Some(h.public_pair("renewed", &["app.example.com"]));
    // acme.sh deploys a new pair, then nginx does not restart.
    h.break_unit(FRP_WEB, true);
    let err = renew(&rt, &lock, false).unwrap_err().to_string();
    assert!(
        err.starts_with("FRP 网站证书已续期，但网站服务未能加载新证书: "),
        "{err}"
    );
    // The old pair (and its metadata) is back: committed, the next
    // scheduled run would find the new pair not due while nginx served
    // the old one from memory.
    assert_eq!(fs::read(&cert).unwrap(), deployed);
    assert_eq!(
        fs::read(paths.frp_root.join("web-tls/certificate.json")).unwrap(),
        metadata
    );
    assert!(!journal::exists(paths));
    // Once nginx works again the renewal is simply retried.
    h.break_unit(FRP_WEB, false);
    rt.services().start(FRP_WEB).unwrap();
    h.clear_history();
    assert!(renew(&rt, &lock, false).unwrap());
    assert_eq!(
        web_steps(&h),
        [
            "acme.sh renew",
            "nginx -t full",
            "systemctl restart onebox-frp-web"
        ]
    );
    assert_ne!(fs::read(&cert).unwrap(), deployed);
}
