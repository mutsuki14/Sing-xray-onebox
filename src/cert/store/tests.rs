use super::*;
use crate::cert::method::{Challenge, Source};
use crate::cert::testing::{have_openssl, Fixture};
use crate::sys::fs::TempDir;
use std::os::unix::fs::PermissionsExt;

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn directories_keep_the_v2_layout() {
    let paths = Paths::isolated(Path::new("/x"));
    assert_eq!(CertDir::proxy(&paths).path(), Path::new("/x/etc/tls"));
    assert_eq!(CertDir::site(&paths).path(), Path::new("/x/etc/site"));
    assert_eq!(
        CertDir::subscription(&paths).path(),
        Path::new("/x/etc/subscription/tls")
    );
    let frp = CertDir::frp_web(&paths);
    assert_eq!(frp.path(), Path::new("/x/frp/etc/web-tls"));
    assert_eq!(frp.cert(), Path::new("/x/frp/etc/web-tls/cert.pem"));
    assert_eq!(frp.key(), Path::new("/x/frp/etc/web-tls/key.pem"));
    assert_eq!(frp.acme_home(), Path::new("/x/frp/etc/web-tls/acme"));
    assert_eq!(
        frp.metadata_file(),
        Path::new("/x/frp/etc/web-tls/certificate.json")
    );
}

#[test]
fn metadata_reads_v2_and_writes_the_same_shape() {
    let v2 = r#"{
  "domains": [
    "www.example.com"
  ],
  "method": "http",
  "webroot": "/var/lib/onebox-site",
  "source_cert": null,
  "source_key": null,
  "last_attempt": 1760000000,
  "last_success": 1760000000,
  "last_error": null
}"#;
    let dir = TempDir::new("cert-meta").unwrap();
    let cert_dir = CertDir::new(dir.join("tls"));
    assert_eq!(cert_dir.metadata().unwrap(), None);
    std::fs::create_dir(cert_dir.path()).unwrap();
    std::fs::write(cert_dir.metadata_file(), v2).unwrap();
    let m = cert_dir.metadata().unwrap().unwrap();
    assert_eq!(m.method, MethodId::Http);
    assert_eq!(
        m.webroot.as_deref(),
        Some(Path::new("/var/lib/onebox-site"))
    );
    cert_dir.save_metadata(&m).unwrap();
    assert_eq!(
        std::fs::read_to_string(cert_dir.metadata_file()).unwrap(),
        v2
    );
    assert_eq!(mode(&cert_dir.metadata_file()), 0o600);
    // Older files without the counters still load.
    std::fs::write(
        cert_dir.metadata_file(),
        r#"{"domains":["a.example.com"],"method":"cf","webroot":null,"source_cert":null,"source_key":null}"#,
    )
    .unwrap();
    let old = cert_dir.metadata().unwrap().unwrap();
    assert_eq!((old.last_success, old.last_error), (0, None));
    std::fs::write(cert_dir.metadata_file(), "{").unwrap();
    assert!(cert_dir
        .metadata()
        .unwrap_err()
        .to_string()
        .starts_with("证书元数据无效"));
}

#[test]
fn metadata_records_the_attempt_without_secrets() {
    let spec = CertSpec {
        domains: vec!["a.example.com".into()],
        source: Source::Custom {
            cert: "/src/c.pem".into(),
            key: "/src/k.pem".into(),
        },
        trust: Trust::Pinned,
    };
    let previous = Metadata {
        last_success: 7,
        ..Metadata::attempt(&spec, None, 1)
    };
    let m = Metadata::attempt(&spec, Some(&previous), 9);
    assert_eq!((m.last_attempt, m.last_success), (9, 7));
    assert_eq!(m.source_cert.as_deref(), Some(Path::new("/src/c.pem")));
    assert!(m.matches(&spec));
    let dns = CertSpec {
        source: Source::Acme(Challenge::Cloudflare),
        trust: Trust::Public,
        ..spec.clone()
    };
    let m = Metadata::attempt(&dns, None, 1);
    assert_eq!((m.method, m.webroot.clone()), (MethodId::Cloudflare, None));
    assert!(!serde_json::to_string(&m).unwrap().contains("CF_"));
    assert!(!m.matches(&spec));
    let http = CertSpec {
        source: Source::Acme(Challenge::Webroot("/w".into())),
        ..dns.clone()
    };
    let responder = CertSpec {
        source: Source::Acme(Challenge::Responder("/r".into())),
        ..dns
    };
    let m = Metadata::attempt(&http, None, 1);
    assert_eq!(m.webroot.as_deref(), Some(Path::new("/w")));
    assert!(
        m.matches(&responder),
        "the responder does not force a reissue"
    );
    let renamed = CertSpec {
        domains: vec!["b.example.com".into()],
        ..http
    };
    assert!(!m.matches(&renamed));
}

#[test]
fn deploy_writes_key_first_and_restores_on_failure() {
    let dir = TempDir::new("cert-deploy").unwrap();
    let cert_dir = CertDir::new(dir.join("tls"));
    assert!(cert_dir.deploy(b"CERT1", b"KEY1").unwrap());
    assert_eq!(mode(cert_dir.path()), 0o700);
    assert_eq!(mode(&cert_dir.cert()), 0o600);
    assert_eq!(mode(&cert_dir.key()), 0o600);
    assert!(cert_dir.has_pair());
    assert!(!cert_dir.deploy(b"CERT1", b"KEY1").unwrap(), "unchanged");
    // A directory where cert.pem should go makes the second write fail:
    // the key written first is restored.
    std::fs::remove_file(cert_dir.cert()).unwrap();
    std::fs::create_dir(cert_dir.cert()).unwrap();
    assert!(cert_dir.deploy(b"CERT2", b"KEY2").is_err());
    assert_eq!(std::fs::read(cert_dir.key()).unwrap(), b"KEY1");
    // Without a previous pair the new key is removed again.
    let fresh = CertDir::new(dir.join("fresh"));
    std::fs::create_dir_all(fresh.cert()).unwrap();
    assert!(fresh.deploy(b"C", b"K").is_err());
    assert!(!fresh.key().exists());
    // A symlinked directory is refused.
    std::os::unix::fs::symlink(dir.join("tls"), dir.join("link")).unwrap();
    assert!(CertDir::new(dir.join("link")).deploy(b"C", b"K").is_err());
}

#[test]
fn days_and_warnings() {
    assert_eq!(days_until(86_400 * 3, 0), 3);
    assert_eq!(days_until(86_400 * 3 - 1, 0), 2);
    assert_eq!(days_until(0, 1), -1);
    let status = |days| CertStatus {
        dir: "/d".into(),
        x509: X509Info::default(),
        days_left: days,
        metadata: None,
    };
    assert_eq!(status(Some(-1)).warning(7).unwrap(), "证书已过期");
    assert_eq!(status(Some(0)).warning(7).unwrap(), "证书将在 0 天内到期");
    assert_eq!(status(Some(6)).warning(7).unwrap(), "证书将在 6 天内到期");
    // Seven whole days left is 7 × 86400 s or more: outside the window,
    // as for `openssl x509 -checkend 604800` and doctor.
    assert_eq!(status(Some(7)).warning(7), None);
    assert_eq!(status(Some(8)).warning(7), None);
    assert!(status(None).warning(7).is_some());
}

#[test]
fn expiry_predicate_boundaries() {
    const DAY: u64 = 86_400;
    let now = 1_800_000_000;
    let cases = [
        (now - 1, Expiry::Expired),
        (now, Expiry::Expiring),
        (now + 7 * DAY - 1, Expiry::Expiring),
        (now + 7 * DAY, Expiry::Valid),
        (now + 8 * DAY - 1, Expiry::Valid),
    ];
    for (at, want) in cases {
        assert_eq!(Expiry::at(at, now, 7), want, "{at}");
        assert_eq!(Expiry::of_days(days_until(at, now), 7), want, "{at}");
    }
}

#[test]
fn status_lines_are_chinese_and_readable() {
    let status = CertStatus {
        dir: "/d".into(),
        x509: X509Info {
            subject: "CN = a.example.com".into(),
            issuer: "CN = R11".into(),
            not_before: String::new(),
            not_after: "Jan  6 18:19:13 2027 GMT".into(),
            expires_at: Some(1_799_259_553),
        },
        days_left: Some(89),
        metadata: Some(Metadata {
            domains: vec!["a.example.com".into()],
            method: MethodId::Http,
            webroot: None,
            source_cert: None,
            source_key: None,
            last_attempt: 1,
            last_success: 1_791_483_553,
            last_error: None,
        }),
    };
    assert_eq!(
        status.lines(),
        [
            "主题: CN = a.example.com",
            "签发者: CN = R11",
            "到期: 2027-01-06 18:19:13 UTC（剩余 89 天）",
            "域名: a.example.com",
            "方式: ACME HTTP-01；上次成功: 2026-10-08 18:19:13 UTC；结果: 成功",
        ]
    );
}

#[test]
fn installs_custom_chains_leaf_first() {
    if !have_openssl() {
        return;
    }
    let f = Fixture::new("cert-install");
    let (chain, key) = f.ca.leaf(&f.dir.join("src"), &["a.example.com"], 90, true);
    let dir = CertDir::proxy(&f.ctx.paths);
    let names = vec!["a.example.com".to_owned()];
    assert!(install_pair(&f.ctx, &dir, &chain, &key, &names, Trust::Public).unwrap());
    let deployed = TlsMaterial::deployed(&f.ctx.paths).unwrap();
    let given = TlsMaterial::load(&chain).unwrap();
    assert_eq!(
        deployed.pems(),
        [given.pems()[1].clone(), given.pems()[0].clone()]
    );
    assert_eq!(
        std::fs::read(dir.key()).unwrap(),
        std::fs::read(&key).unwrap()
    );
    assert!(valid_for(&f.ctx, &dir, &names, Trust::Public, 30 * 86_400));
    assert!(!valid_for(
        &f.ctx,
        &dir,
        &names,
        Trust::Public,
        100 * 86_400
    ));
    // Re-installing the same source changes nothing; installing the
    // deployed files onto themselves is a validated no-op.
    assert!(!install_pair(&f.ctx, &dir, &chain, &key, &names, Trust::Public).unwrap());
    assert!(!install_pair(&f.ctx, &dir, &dir.cert(), &dir.key(), &names, Trust::Public).unwrap());
    assert!(std::fs::read_dir(dir.path()).unwrap().all(|e| !e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".stage-")));

    // A pair for another name is refused and the deployed one stays.
    let (other, other_key) =
        f.ca.leaf(&f.dir.join("other"), &["b.example.com"], 90, false);
    let before = std::fs::read(dir.cert()).unwrap();
    assert!(install_pair(&f.ctx, &dir, &other, &other_key, &names, Trust::Public).is_err());
    assert_eq!(std::fs::read(dir.cert()).unwrap(), before);
    let missing = install_pair(
        &f.ctx,
        &dir,
        &f.dir.join("nope"),
        &key,
        &names,
        Trust::Public,
    );
    assert_eq!(
        missing.unwrap_err().to_string(),
        format!("证书或私钥文件不存在: {}", f.dir.join("nope").display())
    );

    let status = status(&f.ctx, &dir).unwrap().unwrap();
    assert!(status.x509.subject.contains("a.example.com"));
    assert!((88..=90).contains(&status.days_left.unwrap()));
    assert!((88..=90).contains(&days_left(&f.ctx, &dir).unwrap()));
    let empty = CertDir::new(f.dir.join("empty"));
    assert_eq!(super::status(&f.ctx, &empty).unwrap(), None);
}
