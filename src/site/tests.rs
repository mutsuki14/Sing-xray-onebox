use super::*;
use crate::cert::testing::{
    acme_calls, engine, fake_acme, have_openssl, serve_release, AcmeScript, Fixture,
};
use crate::domain::config::Inbound;
use crate::domain::fixtures::{config, with_site};
use crate::domain::protocol::{Core, Protocol};
use crate::host::init::InitSystem;
use crate::sys::exec::{FakeExec, Output};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const SUB: &str =
    "location ^~ /sub/ { proxy_pass \"http://unix:/run/onebox/subscription.sock:\"; }";

/// A REALITY node with the own-domain site (no HTTPS entrance).
fn site_cfg(cert: WebCert, https_entry: bool, reality_port: u16) -> NodeConfig {
    let mut cfg = with_site(
        config(&[(Protocol::VlessReality, reality_port, Core::Xray)]),
        "www.example.com",
        https_entry,
    );
    if let Some(site) = cfg.site.as_mut() {
        site.cert = cert;
    }
    cfg
}

fn facts() -> NginxFacts {
    NginxFacts {
        worker: Worker {
            user: "www-data".into(),
            group: "www-data".into(),
        },
        http2_directive: false,
        ipv6: false,
    }
}

/// nginx, the worker account and systemd scripted on `fake`; `onebox-site`
/// reports active once it has been restarted.
fn host(fake: &FakeExec, paths: &Paths) -> Arc<AtomicBool> {
    let started = Arc::new(AtomicBool::new(false));
    let flag = started.clone();
    fake.provide("nginx")
        .on("id", &["-u", "www-data"], Output::success("33\n"))
        .on("id", &["-gn", "www-data"], Output::success("www-data\n"))
        .on("nginx", &["-T"], Output::failure(1, ""))
        .on("nginx", &["-t"], Output::success(""))
        .on_fn(
            |c| c.program_name() == "nginx" && c.args == ["-v"],
            |_| Ok(Output::failure(0, "nginx version: nginx/1.24.0 (Ubuntu)\n")),
        )
        .on_fn(
            |c| c.program == "systemctl" && c.args.first().is_some_and(|a| a == "restart"),
            move |_| {
                flag.store(true, Ordering::SeqCst);
                Ok(Output::success(""))
            },
        );
    let seen = started.clone();
    fake.on_fn(
        |c| c.program == "systemctl" && c.args.starts_with(&["is-active".into()]),
        move |_| {
            Ok(if seen.load(Ordering::SeqCst) {
                Output::success("")
            } else {
                Output::failure(3, "")
            })
        },
    )
    .on("systemctl", &[], Output::success(""));
    // TCP 80 is free: an empty /proc/net/tcp under the system root.
    let net = paths.system("/proc/net");
    std::fs::create_dir_all(&net).unwrap();
    std::fs::write(net.join("tcp"), "  sl  local_address rem_address   st\n").unwrap();
    started
}

#[test]
fn ca_bundle_prefers_ssl_cert_file_then_distro_paths() {
    let dir = crate::sys::fs::TempDir::new("site-ca").unwrap();
    let paths = Paths::isolated(dir.path());
    let none = |_: &str| None;
    assert_eq!(
        ca_bundle_with(&paths, &none).unwrap_err().to_string(),
        "缺少系统 CA 证书包"
    );
    let pki = paths.system("/etc/pki/tls/certs/ca-bundle.crt");
    std::fs::create_dir_all(pki.parent().unwrap()).unwrap();
    std::fs::write(&pki, "x").unwrap();
    assert_eq!(
        ca_bundle_with(&paths, &none).unwrap(),
        PathBuf::from("/etc/pki/tls/certs/ca-bundle.crt")
    );
    let own = dir.join("my-ca.pem");
    std::fs::write(&own, "x").unwrap();
    let own_s = own.display().to_string();
    let env = move |k: &str| (k == "SSL_CERT_FILE").then(|| own_s.clone());
    assert_eq!(ca_bundle_with(&paths, &env).unwrap(), own);
    let missing = |k: &str| (k == "SSL_CERT_FILE").then(|| "/nonexistent".to_owned());
    assert_eq!(
        ca_bundle_with(&paths, &missing).unwrap(),
        PathBuf::from("/etc/pki/tls/certs/ca-bundle.crt")
    );
}

#[test]
fn frontend_only_without_reality_on_443() {
    let paths = Paths::isolated(Path::new("/x"));
    let ca = PathBuf::from("/etc/ssl/certs/ca-certificates.crt");
    let render = |cfg: &NodeConfig, phase, sub: Option<&SiteSubscription>| {
        render_conf_with(&paths, cfg, sub, phase, &facts(), Some(&ca)).unwrap()
    };
    let entry = site_cfg(WebCert::Http01, true, 8443);
    assert!(uses_frontend(&entry));
    assert!(render(&entry, SitePhase::Full, None).contains("listen 443 ssl http2;"));
    assert!(!render(&entry, SitePhase::Deferred, None).contains("listen 443"));
    let reality_443 = site_cfg(WebCert::Http01, true, 443);
    assert!(!uses_frontend(&reality_443));
    assert!(!render(&reality_443, SitePhase::Full, None).contains("listen 443"));
    let no_entry = site_cfg(WebCert::Http01, false, 8443);
    let text = render(&no_entry, SitePhase::Full, None);
    assert!(!text.contains("listen 443"));
    assert!(text.contains("return 301 https://www.example.com:8443$request_uri;"));
    let sub = SiteSubscription {
        location_block: SUB.into(),
    };
    let text = render(&entry, SitePhase::Full, Some(&sub));
    assert_eq!(text.matches(SUB).count(), 2);
    assert!(text.contains("error_log /dev/null crit;"));
    // The site is only effective with a REALITY inbound.
    let mut dormant = entry.clone();
    dormant.inbounds = vec![Inbound {
        protocol: Protocol::Trojan,
        port: 443,
        core: Core::Singbox,
    }];
    let err = render_conf_with(&paths, &dormant, None, SitePhase::Full, &facts(), None);
    assert_eq!(err.unwrap_err().to_string(), "网站未启用");
}

#[test]
fn prepare_with_a_custom_certificate_needs_no_bootstrap() {
    if !have_openssl() {
        return;
    }
    let f = Fixture::new("site-custom");
    host(&f.fake, &f.ctx.paths);
    let engine = engine(&f.ctx, InitSystem::Systemd);
    let (chain, key) =
        f.ca.leaf(&f.dir.join("src"), &["www.example.com"], 90, false);
    let mut cfg = site_cfg(WebCert::Custom { cert: chain, key }, true, 8443);
    let done = prepare_with(&engine, &mut cfg, None, false, None).unwrap();
    assert_eq!(
        done,
        SitePrepared {
            cert_changed: true,
            content_backup: None,
            bootstrapped: false
        }
    );
    let store = ContentStore::new(&f.ctx.paths);
    assert!(store.is_generated().unwrap());
    let html = std::fs::read_to_string(store.index()).unwrap();
    assert_eq!(html, templates::homepage(cfg.site.as_ref().unwrap()));
    assert!(f.ctx.paths.systemd.join("onebox-site.service").is_file());
    assert!(
        !conf_file(&f.ctx.paths).exists(),
        "no config before check/apply"
    );
    assert!(CertDir::site(&f.ctx.paths).has_pair());

    // A template publish records the replaced content's backup.
    let done = prepare_with(&engine, &mut cfg, Some(&SiteContent::Template), false, None).unwrap();
    let id = done.content_backup.unwrap();
    assert_eq!(
        cfg.site.as_ref().unwrap().last_content_backup.as_deref(),
        Some(id.as_str())
    );
    assert!(!done.cert_changed);
    // Nothing happens for an inactive site.
    let mut off = config(&[(Protocol::Trojan, 443, Core::Singbox)]);
    assert_eq!(
        prepare_with(&engine, &mut off, Some(&SiteContent::Template), true, None).unwrap(),
        SitePrepared::default()
    );
}

#[test]
fn http01_without_a_running_site_starts_a_bootstrap_nginx() {
    if !have_openssl() {
        return;
    }
    let f = Fixture::new("site-bootstrap");
    serve_release(&f.fake);
    let started = host(&f.fake, &f.ctx.paths);
    let engine = engine(&f.ctx, InitSystem::Systemd);
    let issued =
        f.ca.leaf(&f.dir.join("issued"), &["www.example.com"], 90, false);
    fake_acme(
        &f.fake,
        AcmeScript {
            issue: Some(issued),
            ..AcmeScript::default()
        },
    );
    let mut cfg = site_cfg(WebCert::Http01, true, 8443);
    let done = prepare_with(&engine, &mut cfg, None, false, None).unwrap();
    assert!(done.bootstrapped && done.cert_changed);
    assert!(started.load(Ordering::SeqCst));
    let conf = std::fs::read_to_string(conf_file(&f.ctx.paths)).unwrap();
    assert!(
        conf.contains("location / { return 404; }") && !conf.contains("ssl"),
        "{conf}"
    );
    assert!(!staged_conf(&f.ctx.paths).exists(), "staged file consumed");
    let call = acme_calls(&f.fake).pop().unwrap();
    let webroot = f.ctx.paths.site_root.display().to_string();
    assert!(
        call.args.ends_with(&["--webroot".into(), webroot]),
        "{:?}",
        call.args
    );
    // Running site with a valid certificate: no bootstrap, no acme.sh.
    let calls = f.fake.history().len();
    let done = prepare_with(&engine, &mut cfg, None, false, None).unwrap();
    assert!(!done.bootstrapped && !done.cert_changed);
    let new_calls: Vec<String> = f.fake.history()[calls..].to_vec();
    assert!(
        new_calls
            .iter()
            .all(|c| !c.contains("acme.sh") && !c.contains("restart")),
        "{new_calls:?}"
    );
}

#[test]
fn check_then_apply_installs_the_tested_file() {
    if !have_openssl() {
        return;
    }
    let f = Fixture::new("site-apply");
    host(&f.fake, &f.ctx.paths);
    let ca = f.ctx.paths.system("/etc/ssl/certs/ca-certificates.crt");
    std::fs::create_dir_all(ca.parent().unwrap()).unwrap();
    std::fs::write(&ca, "x").unwrap();
    let engine = engine(&f.ctx, InitSystem::Systemd);
    let (chain, key) =
        f.ca.leaf(&f.dir.join("src"), &["www.example.com"], 90, false);
    let mut cfg = site_cfg(WebCert::Custom { cert: chain, key }, true, 8443);
    prepare_with(&engine, &mut cfg, None, false, None).unwrap();
    let sub = SiteSubscription {
        location_block: SUB.into(),
    };
    let staged = check_with(&engine, &cfg, Some(&sub)).unwrap().unwrap();
    assert_eq!(staged, staged_conf(&f.ctx.paths));
    let tests_before = f
        .fake
        .history()
        .iter()
        .filter(|c| c.contains(" -t "))
        .count();
    apply_with(&engine, &cfg, Some(&sub)).unwrap();
    let tests_after = f
        .fake
        .history()
        .iter()
        .filter(|c| c.contains(" -t "))
        .count();
    assert_eq!(
        tests_before, tests_after,
        "the tested file is installed as is"
    );
    let conf = std::fs::read_to_string(conf_file(&f.ctx.paths)).unwrap();
    assert!(conf.contains("listen 443 ssl http2;") && conf.contains(SUB));
    assert!(conf.contains("proxy_ssl_trusted_certificate \"/etc/ssl/certs/ca-certificates.crt\";"));
    assert!(!staged.exists());
    let history = f.fake.history();
    assert!(history.contains(&"systemctl restart onebox-site".to_owned()));
    assert!(history.contains(&"systemctl enable onebox-site".to_owned()));
    // Without a check (or with a stale one) apply tests first.
    apply_with(&engine, &cfg, None).unwrap();
    assert_eq!(
        f.fake
            .history()
            .iter()
            .filter(|c| c.contains(" -t "))
            .count(),
        tests_after + 1
    );
    // A failing test leaves the installed config alone.
    let installed = std::fs::read_to_string(conf_file(&f.ctx.paths)).unwrap();
    let broken = FakeExec::new();
    broken
        .provide("nginx")
        .on("nginx", &["-t"], Output::failure(1, "nginx: [emerg] bad\n"));
    let ctx = Ctx {
        exec: Arc::new(broken),
        ..f.ctx.clone()
    };
    let err = test_conf(&ctx, "garbage").unwrap_err().to_string();
    assert!(err.starts_with("nginx 配置测试失败"), "{err}");
    assert!(!staged_conf(&f.ctx.paths).exists());
    assert_eq!(
        std::fs::read_to_string(conf_file(&f.ctx.paths)).unwrap(),
        installed
    );

    // Turning the site off removes the service but keeps everything else.
    let off = config(&[(Protocol::Trojan, 443, Core::Singbox)]);
    apply_with(&engine, &off, None).unwrap();
    assert!(!f.ctx.paths.systemd.join("onebox-site.service").exists());
    assert!(conf_file(&f.ctx.paths).exists() && CertDir::site(&f.ctx.paths).has_pair());
    assert!(ContentStore::new(&f.ctx.paths).index().exists());
    assert_eq!(check_with(&engine, &off, None).unwrap(), None);
}

#[test]
fn info_describes_the_site() {
    if !have_openssl() {
        return;
    }
    let f = Fixture::new("site-info");
    host(&f.fake, &f.ctx.paths);
    let engine = engine(&f.ctx, InitSystem::Systemd);
    let (chain, key) =
        f.ca.leaf(&f.dir.join("src"), &["www.example.com"], 90, false);
    let mut cfg = site_cfg(WebCert::Custom { cert: chain, key }, false, 8443);
    prepare_with(&engine, &mut cfg, None, false, None).unwrap();
    let info = info_with(&engine, &cfg).unwrap();
    assert!(info.enabled && !info.running && info.generated && !info.frontend);
    assert_eq!(info.url.as_deref(), Some("https://www.example.com:8443/"));
    let lines = info.lines();
    assert_eq!(
        lines[0],
        "网站: 开启；域名: www.example.com；内部端口: 10443；公网端口: 8443"
    );
    assert!(
        lines.contains(&"HTTPS 443 入口: 关闭".to_owned()),
        "{lines:?}"
    );
    assert!(
        lines.iter().any(|l| l.starts_with("证书 主题: ")),
        "{lines:?}"
    );
    let off = info_with(&engine, &config(&[(Protocol::Trojan, 443, Core::Singbox)])).unwrap();
    assert_eq!(off.lines()[0], "网站: 关闭");
    assert_eq!(off.url, None);
}

/// Real nginx (`ONEBOX_NGINX_BIN=…/usr/sbin/nginx cargo test -- --ignored`):
/// every phase of the rendered config passes `nginx -t`.
#[test]
#[ignore = "needs a real nginx binary in ONEBOX_NGINX_BIN and openssl"]
fn real_nginx_accepts_every_phase() {
    let f = Fixture::new("site-real-nginx");
    let ctx = Ctx {
        exec: Arc::new(crate::sys::exec::SystemExec),
        ..f.ctx.clone()
    };
    let paths = &ctx.paths;
    let (chain, key) =
        f.ca.leaf(&f.dir.join("src"), &["www.example.com"], 90, false);
    let site_dir = CertDir::site(paths);
    std::fs::create_dir_all(site_dir.path()).unwrap();
    std::fs::copy(chain, site_dir.cert()).unwrap();
    std::fs::copy(key, site_dir.key()).unwrap();
    std::fs::create_dir_all(&paths.site_root).unwrap();
    let worker = nginx::worker(&ctx).unwrap();
    let version = nginx::version(&ctx).unwrap();
    let cfg = site_cfg(WebCert::Http01, true, 8443);
    let sub = SiteSubscription {
        location_block: SUB.into(),
    };
    for http2_directive in [false, version.supports_http2_directive()] {
        let facts = NginxFacts {
            worker: worker.clone(),
            http2_directive,
            ipv6: crate::sys::net::ipv6_available(Path::new("/")),
        };
        for phase in [SitePhase::Bootstrap, SitePhase::Deferred, SitePhase::Full] {
            for sub in [None, Some(&sub)] {
                let text =
                    render_conf_with(paths, &cfg, sub, phase, &facts, Some(&f.ca.cert)).unwrap();
                test_conf(&ctx, &text).unwrap_or_else(|e| panic!("{phase:?}: {e}\n{text}"));
            }
        }
    }
    assert!(
        site_dir.path().join("client_body_temp").is_dir(),
        "temp paths under ROOT/site"
    );
}
