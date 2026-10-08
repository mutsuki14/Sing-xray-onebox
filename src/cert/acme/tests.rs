use super::*;
use crate::cert::testing::{
    acme_calls, engine, fake_acme, serve_release, test_release, AcmeScript, FAKE_ACME, FAKE_DNS_CF,
};
use crate::ctx::Ctx;
use crate::host::init::InitSystem;
use crate::sys::fs::TempDir;

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

#[test]
fn pinned_release_is_acme_sh_3_1_6_from_raw_github() {
    let r = AcmeRelease::pinned();
    assert_eq!(
        r.script.url,
        "https://raw.githubusercontent.com/acmesh-official/acme.sh/3.1.6/acme.sh"
    );
    assert_eq!(
        r.dns_cf.url,
        "https://raw.githubusercontent.com/acmesh-official/acme.sh/3.1.6/dnsapi/dns_cf.sh"
    );
    assert_eq!(
        r.script.sha256,
        "c7d68b021cfd6380ea83a82962abde5b484779fee0b97d38681dfa1396bbc8d7"
    );
    assert_eq!(
        r.dns_cf.sha256,
        "9628ee8238cb3f9cfa1b1a985c0e9593436a3e4f8a9d65a6f775b981be9e76c8"
    );
    assert!(r.script.max_bytes >= 294_737 && r.dns_cf.max_bytes >= 7331);
}

#[test]
fn arguments_follow_f_4_6_3() {
    let home = Path::new("/etc/onebox/tls/acme");
    let base = "--home /etc/onebox/tls/acme --config-home /etc/onebox/tls/acme \
                --cert-home /etc/onebox/tls/acme/certs --server letsencrypt";
    let webroot = Challenge::Webroot("/var/lib/onebox-site".into());
    let two = names(&["a.example.com", "b.example.com"]);
    let cases = [
        (
            Request::Issue,
            &webroot,
            format!("{base} --issue -d a.example.com -d b.example.com --keylength ec-256 --force --webroot /var/lib/onebox-site"),
        ),
        (
            Request::Issue,
            &Challenge::Cloudflare,
            format!("{base} --issue -d a.example.com -d b.example.com --keylength ec-256 --force --dns dns_cf"),
        ),
        (
            Request::Renew { force: false },
            &webroot,
            format!("{base} --renew -d a.example.com -d b.example.com --ecc"),
        ),
        (
            Request::Renew { force: true },
            &Challenge::Cloudflare,
            format!("{base} --renew -d a.example.com -d b.example.com --ecc --force"),
        ),
    ];
    for (request, challenge, expected) in cases {
        assert_eq!(args(home, &two, challenge, request).join(" "), expected);
    }
    let responder = Challenge::Responder("/etc/onebox/tls/acme/http01".into());
    let issue = args(home, &two[..1], &responder, Request::Issue).join(" ");
    assert!(
        issue.ends_with("--force --webroot /etc/onebox/tls/acme/http01"),
        "{issue}"
    );
}

#[test]
fn recorded_challenge_reads_le_webroot_as_data() {
    let dir = TempDir::new("acme-conf").unwrap();
    let cert_dir = CertDir::new(dir.join("tls"));
    assert_eq!(recorded_challenge(&cert_dir, "a.example.com"), None);
    let issued = issued_dir(&cert_dir, "a.example.com");
    std::fs::create_dir_all(&issued).unwrap();
    std::fs::write(
        issued.join("a.example.com.conf"),
        "Le_Domain='a.example.com'\nLe_Webroot='no'\nLe_API='x'\n",
    )
    .unwrap();
    assert_eq!(
        recorded_challenge(&cert_dir, "a.example.com").as_deref(),
        Some("no")
    );
    let (cert, key) = issued_pair(&cert_dir, "a.example.com");
    assert!(cert.ends_with("a.example.com_ecc/fullchain.cer"));
    assert!(key.ends_with("a.example.com_ecc/a.example.com.key"));
}

#[test]
fn failure_output_is_redacted() {
    let secret = "fake-cf-token-not-a-real-secret-0123".to_owned();
    let mut lines: Vec<String> = (0..10).map(|i| format!("[Thu] step {i}")).collect();
    lines.push(format!("\x1b[31mError\x1b[0m: token {secret} rejected"));
    lines.push("export CF_Token='mytoken' CF_Email:a@b.c".into());
    lines.push("Authorization=Bearer abcdefghijklmnopqrstuvwxyz0123".into());
    lines.push("id 0123456789abcdef0123456789abcdef done".into());
    let out = Output {
        code: 1,
        stdout: lines.join("\n"),
        stderr: "Please check https://acme-v02.api.letsencrypt.org/directory\n".into(),
    };
    let tail = redacted_tail(&out, &[secret.clone(), "mytoken".into()]);
    assert_eq!(tail.len(), 8);
    let text = tail.join("\n");
    assert!(
        !text.contains(&secret) && !text.contains("mytoken"),
        "{text}"
    );
    assert!(
        !text.contains("a@b.c") && !text.contains("abcdefghijklmnopqrstuvwxyz0123"),
        "{text}"
    );
    assert!(!text.contains("0123456789abcdef0123456789abcdef"), "{text}");
    assert!(!text.contains('\x1b'), "{text}");
    assert!(text.contains("Error: token *** rejected"), "{text}");
    assert!(text.contains("CF_Token=***"), "{text}");
    assert!(
        text.contains("https://acme-v02.api.letsencrypt.org/directory"),
        "{text}"
    );
    let message = failure(1, &out, None).to_string();
    assert!(message.starts_with(
        "ACME 验证或签发失败，退出码 1；请检查 DNS、端口及账户配置\nacme.sh 输出（已隐去凭据）:\n  "
    ));
    assert_eq!(
        failure(7, &Output::failure(7, ""), None).to_string(),
        "ACME 验证或签发失败，退出码 7；请检查 DNS、端口及账户配置"
    );
}

#[test]
fn install_verifies_pins_and_replaces_tampered_copies() {
    let dir = TempDir::new("acme-install").unwrap();
    let (ctx, exec, _) = Ctx::test(dir.path());
    serve_release(&exec);
    let engine = engine(&ctx, InitSystem::None);
    let home = dir.join("tls/acme");
    let script = install(&engine, &home).unwrap();
    assert_eq!(std::fs::read(&script).unwrap(), FAKE_ACME);
    assert_eq!(
        std::fs::read(home.join("dnsapi/dns_cf.sh")).unwrap(),
        FAKE_DNS_CF
    );
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!((mode(&script), mode(&home)), (0o700, 0o700));
    let fetched: Vec<String> = exec
        .calls()
        .iter()
        .map(|c| c.args.last().unwrap().clone())
        .collect();
    assert_eq!(
        fetched,
        [test_release().script.url, test_release().dns_cf.url]
    );
    // Verified copies are kept; a tampered one is fetched again.
    exec.clear_history();
    install(&engine, &home).unwrap();
    assert!(exec.history().is_empty());
    std::fs::write(&script, "#!/bin/sh\nrm -rf /\n").unwrap();
    install(&engine, &home).unwrap();
    assert_eq!(std::fs::read(&script).unwrap(), FAKE_ACME);
    assert_eq!(exec.history().len(), 1);
    // A download with the wrong content is refused and not installed.
    let mut wrong = engine;
    wrong.release.dns_cf.sha256 = "0".repeat(64);
    std::fs::remove_file(home.join("dnsapi/dns_cf.sh")).unwrap();
    let err = install(&wrong, &home).unwrap_err().to_string();
    assert!(
        err.starts_with("下载 acme.sh 失败") && err.contains("SHA256"),
        "{err}"
    );
    assert!(!home.join("dnsapi/dns_cf.sh").exists());
}

#[test]
fn obtain_serves_responder_challenges_and_cleans_up() {
    let dir = TempDir::new("acme-obtain").unwrap();
    let (ctx, exec, _) = Ctx::test(dir.path());
    serve_release(&exec);
    let engine = engine(&ctx, InitSystem::None);
    let script = fake_acme(
        &exec,
        AcmeScript {
            fetch_port: Some(engine.http01_port),
            ..AcmeScript::default()
        },
    );
    let cert_dir = CertDir::proxy(&ctx.paths);
    let domains = names(&["a.example.com"]);
    let challenge = Challenge::Responder(cert_dir.responder_webroot());
    assert!(obtain(
        &engine,
        &cert_dir,
        &domains,
        &challenge,
        Request::Issue,
        None
    )
    .unwrap());
    assert!(!cert_dir.responder_webroot().join(".well-known").exists());
    let call = acme_calls(&exec).pop().unwrap();
    assert!(call.clear_env);
    assert_eq!(call.env, [("PATH".to_owned(), SAFE_PATH.to_owned())]);

    // A failing validation surfaces the redacted acme.sh output.
    script.lock().unwrap().fetch_port = Some(crate::cert::testing::free_port());
    let err = obtain(
        &engine,
        &cert_dir,
        &domains,
        &challenge,
        Request::Issue,
        None,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("退出码 1") && err.contains("Invalid response"),
        "{err}"
    );
}

#[test]
fn renewals_fall_back_to_issue_and_honor_not_due() {
    let dir = TempDir::new("acme-renew").unwrap();
    let (ctx, exec, _) = Ctx::test(dir.path());
    serve_release(&exec);
    let engine = engine(&ctx, InitSystem::None);
    let script = fake_acme(&exec, AcmeScript::default());
    let cert_dir = CertDir::site(&ctx.paths);
    let domains = names(&["a.example.com"]);
    let webroot = Challenge::Webroot(ctx.paths.site_root.clone());
    let issued = issued_dir(&cert_dir, "a.example.com");
    std::fs::create_dir_all(&issued).unwrap();
    let conf = issued.join("a.example.com.conf");
    let renew = Request::Renew { force: false };

    // v2's standalone record cannot be renewed with a webroot: reissue.
    std::fs::write(&conf, "Le_Webroot='no'\n").unwrap();
    assert!(obtain(&engine, &cert_dir, &domains, &webroot, renew, None).unwrap());
    assert!(acme_calls(&exec)
        .pop()
        .unwrap()
        .args
        .contains(&"--issue".to_owned()));

    std::fs::write(
        &conf,
        format!("Le_Webroot='{}'\n", ctx.paths.site_root.display()),
    )
    .unwrap();
    script.lock().unwrap().code = 2;
    assert!(!obtain(&engine, &cert_dir, &domains, &webroot, renew, None).unwrap());
    let call = acme_calls(&exec).pop().unwrap();
    assert!(
        call.args.contains(&"--renew".to_owned()) && !call.args.contains(&"--force".to_owned())
    );
    // Exit 2 is a failure for forced renewals and issuance.
    let forced = Request::Renew { force: true };
    let err = obtain(&engine, &cert_dir, &domains, &webroot, forced, None).unwrap_err();
    assert!(err.to_string().contains("退出码 2"), "{err}");
    assert!(acme_calls(&exec)
        .pop()
        .unwrap()
        .args
        .contains(&"--force".to_owned()));
    assert!(obtain(&engine, &cert_dir, &domains, &webroot, Request::Issue, None).is_err());
}

#[test]
fn dns_credentials_reach_only_the_acme_command() {
    let dir = TempDir::new("acme-dns").unwrap();
    let (ctx, exec, _) = Ctx::test(dir.path());
    serve_release(&exec);
    let mut engine = engine(&ctx, InitSystem::None);
    let forwarded = |key: &str| match key {
        "HOME" => Some("/root".to_owned()),
        "CF_Token" => Some("from-shell".to_owned()),
        "LE_WORKING_DIR" => Some("/tmp/evil".to_owned()),
        _ => None,
    };
    engine.env = &forwarded;
    let script = fake_acme(&exec, AcmeScript::default());
    let cert_dir = CertDir::proxy(&ctx.paths);
    let creds = CfCredentials::token("cf-secret-token", None).unwrap();
    let domains = names(&["a.example.com", "*.example.com"]);
    obtain(
        &engine,
        &cert_dir,
        &domains,
        &Challenge::Cloudflare,
        Request::Issue,
        Some(&creds),
    )
    .unwrap();
    let call = acme_calls(&exec).pop().unwrap();
    assert_eq!(
        call.env,
        [
            ("PATH".to_owned(), SAFE_PATH.to_owned()),
            ("HOME".to_owned(), "/root".to_owned()),
            ("CF_Token".to_owned(), "cf-secret-token".to_owned()),
        ]
    );
    assert!(!call.display().contains("cf-secret-token"));
    // The token never shows in a failure message.
    {
        let mut s = script.lock().unwrap();
        s.code = 1;
        s.output = "Error: cf-secret-token is invalid".into();
    }
    let err = obtain(
        &engine,
        &cert_dir,
        &domains,
        &Challenge::Cloudflare,
        Request::Issue,
        Some(&creds),
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("Error: *** is invalid") && !err.contains("cf-secret-token"),
        "{err}"
    );
    // Webroot validation never gets Cloudflare variables.
    script.lock().unwrap().code = 0;
    let webroot = Challenge::Webroot(ctx.paths.site_root.clone());
    obtain(
        &engine,
        &cert_dir,
        &domains[..1],
        &webroot,
        Request::Issue,
        Some(&creds),
    )
    .unwrap();
    let call = acme_calls(&exec).pop().unwrap();
    assert!(
        call.env.iter().all(|(k, _)| !k.starts_with("CF_")),
        "{:?}",
        call.env
    );
}
