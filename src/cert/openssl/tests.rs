use super::*;
use crate::cert::testing::{have_openssl, self_signed, Fixture};
use crate::sys::exec::FakeExec;

#[test]
fn parses_openssl_dates() {
    let cases = [
        ("Jan  1 00:00:00 1970 GMT", Some(0)),
        ("Oct  8 18:19:13 2026 GMT", Some(1_791_483_553)),
        ("Feb 29 00:00:00 2000 GMT", Some(951_782_400)),
        ("Sep 14 18:19:13 2126 GMT", Some(4_945_083_553)),
        ("Dec 31 23:59:59 1969 GMT", None),
        ("Oct  8 18:19:13 2026 UTC", None),
        ("Foo  8 18:19:13 2026 GMT", None),
        ("Oct 32 18:19:13 2026 GMT", None),
        ("Oct  8 24:00:00 2026 GMT", None),
        ("Oct  8 18:19 2026 GMT", None),
        ("", None),
    ];
    for (text, expected) in cases {
        assert_eq!(parse_date(text), expected, "{text:?}");
    }
    for (secs, text) in [(0u64, "1970-01-01"), (951_782_400, "2000-02-29")] {
        let (y, m, d) = crate::sys::time::civil_from_days((secs / 86_400) as i64);
        assert_eq!(days_from_civil(y, m, d), (secs / 86_400) as i64, "{text}");
    }
}

#[test]
fn parses_x509_status_lines() {
    let info = parse_x509_info(
        "subject=CN = proxy.example.com\nissuer=C = US, O = Let's Encrypt, CN = R11\n\
         notBefore=Oct  8 18:19:13 2026 GMT\nnotAfter=Jan  6 18:19:13 2027 GMT\n",
    );
    assert_eq!(info.subject, "CN = proxy.example.com");
    assert_eq!(info.issuer, "C = US, O = Let's Encrypt, CN = R11");
    assert_eq!(info.not_before, "Oct  8 18:19:13 2026 GMT");
    assert_eq!(info.expires_at, Some(1_791_483_553 + 90 * 86_400));
    assert_eq!(parse_x509_info("garbage").expires_at, None);
}

#[test]
fn verify_failures_name_the_check() {
    let out = Output::failure(
        2,
        "CN = a.example.com\nerror 62 at 0 depth lookup: hostname mismatch\nerror /x/cert.pem: verification failed\n",
    );
    assert_eq!(detail(&out), "hostname mismatch");
    assert_eq!(detail(&Output::failure(1, "  last line \n\n")), "last line");
    assert_eq!(detail(&Output::failure(3, "")), "退出码 3");
}

#[test]
fn rejects_bad_names_and_missing_files_before_running_openssl() {
    let dir = crate::sys::fs::TempDir::new("cert-validate").unwrap();
    let (ctx, exec, _) = Ctx::test(dir.path());
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    let err = validate_pair(&ctx, &cert, &key, "bad name", Trust::Public).unwrap_err();
    assert_eq!(err.to_string(), "证书域名无效");
    let err = validate_pair(&ctx, &cert, &key, "a.example.com", Trust::Public).unwrap_err();
    assert_eq!(err.to_string(), "证书或私钥文件不存在");
    assert!(exec.history().is_empty());
}

#[test]
fn verify_arguments_match_v2() {
    let dir = crate::sys::fs::TempDir::new("cert-verify-args").unwrap();
    let (ctx, exec, _) = Ctx::test(dir.path());
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    std::fs::write(&cert, "c").unwrap();
    std::fs::write(&key, "k").unwrap();
    exec_all_ok(&exec);
    validate_pair(&ctx, &cert, &key, "*.example.com", Trust::Pinned).unwrap_err();
    validate_pair(&ctx, &cert, &key, "203.0.113.5", Trust::Public).unwrap();
    let c = cert.display();
    let k = key.display();
    let history = exec.history();
    let expected = [
        format!("openssl x509 -in {c} -noout -checkend 0"),
        format!("openssl x509 -in {c} -pubkey -noout"),
        format!("openssl pkey -in {k} -pubout"),
        format!(
            "openssl verify -purpose sslserver -verify_hostname onebox-cert-check.example.com \
             -partial_chain -trusted {c} {c}"
        ),
        format!("openssl x509 -in {c} -noout -text"),
        format!("openssl x509 -in {c} -noout -checkend 0"),
        format!("openssl x509 -in {c} -pubkey -noout"),
        format!("openssl pkey -in {k} -pubout"),
        format!("openssl verify -purpose sslserver -verify_ip 203.0.113.5 -untrusted {c} {c}"),
    ];
    assert_eq!(history, expected);
}

/// Every openssl call succeeds with the same public key; `-text` lacks the
/// wildcard SAN.
fn exec_all_ok(exec: &FakeExec) {
    exec.on("openssl", &["x509", "-in"], Output::success("PUBKEY"))
        .on("openssl", &["pkey"], Output::success("PUBKEY\n"))
        .on("openssl", &["verify"], Output::success("OK"));
}

#[test]
fn real_pairs_validate_like_v2() {
    if !have_openssl() {
        return;
    }
    let f = Fixture::new("cert-openssl");
    let (chain, key) = f.ca.leaf(&f.dir.join("leaf"), &["a.example.com", "*.example.com"], 90, false);
    let ctx = &f.ctx;
    validate_pair(ctx, &chain, &key, "a.example.com", Trust::Public).unwrap();
    validate_pair(ctx, &chain, &key, "*.example.com", Trust::Public).unwrap();
    validate_pair(ctx, &chain, &key, "a.example.com", Trust::Pinned).unwrap();
    assert!(publicly_trusted(ctx, &chain, &key, "a.example.com"));
    let err = validate_pair(ctx, &chain, &key, "b.other.com", Trust::Public).unwrap_err();
    assert!(err.to_string().contains("b.other.com"), "{err}");

    // Without the test CA in the store the chain is only good when pinned.
    let untrusting = f.untrusting_ctx();
    assert!(!publicly_trusted(&untrusting, &chain, &key, "a.example.com"));
    validate_pair(&untrusting, &chain, &key, "a.example.com", Trust::Pinned).unwrap();

    // A foreign key, a CA-first chain (first block is the CA) and a
    // self-signed certificate checked publicly are refused.
    let (other, other_key) = self_signed(&f.dir.join("self"), &["a.example.com"], 30);
    let err = validate_pair(ctx, &chain, &other_key, "a.example.com", Trust::Pinned).unwrap_err();
    assert_eq!(err.to_string(), "证书与私钥不匹配");
    validate_pair(&untrusting, &other, &other_key, "a.example.com", Trust::Pinned).unwrap();
    assert!(!publicly_trusted(&untrusting, &other, &other_key, "a.example.com"));
    let (ca_first, ca_first_key) =
        f.ca.leaf(&f.dir.join("cafirst"), &["a.example.com"], 90, true);
    let err = validate_pair(ctx, &ca_first, &ca_first_key, "a.example.com", Trust::Public);
    assert_eq!(err.unwrap_err().to_string(), "证书与私钥不匹配");

    // A wildcard needs the literal SAN, the apex alone does not cover it.
    let (apex, apex_key) = f.ca.leaf(&f.dir.join("apex"), &["example.com"], 90, false);
    assert!(validate_pair(ctx, &apex, &apex_key, "*.example.com", Trust::Public).is_err());
}

#[test]
fn real_expiry_and_facts() {
    if !have_openssl() {
        return;
    }
    let f = Fixture::new("cert-expiry");
    let (chain, key) = f.ca.leaf(&f.dir.join("short"), &["a.example.com"], 10, false);
    assert!(expires_within(&f.ctx, &chain, 30 * 86_400));
    assert!(!expires_within(&f.ctx, &chain, 86_400));
    assert!(expires_within(&f.ctx, &f.dir.join("missing.pem"), 1));
    let info = x509_info(&f.ctx, &chain).unwrap();
    assert!(info.subject.contains("a.example.com"), "{info:?}");
    assert!(info.issuer.contains("Onebox Test CA"), "{info:?}");
    let left = info.expires_at.unwrap() as i64 - crate::sys::time::now() as i64;
    assert!((9 * 86_400..=10 * 86_400 + 60).contains(&left), "{left}");

    // The leaf of a CA-first chain is found by its public key.
    let (ca_first, ca_first_key) = f.ca.leaf(&f.dir.join("cf"), &["a.example.com"], 90, true);
    let material = TlsMaterial::load(&ca_first).unwrap();
    assert_eq!(leaf_index(&f.ctx, &material, &ca_first_key).unwrap(), 1);
    let plain = TlsMaterial::load(&chain).unwrap();
    assert_eq!(leaf_index(&f.ctx, &plain, &key).unwrap(), 0);
    let err = leaf_index(&f.ctx, &plain, &ca_first_key).unwrap_err();
    assert_eq!(err.to_string(), "证书与私钥不匹配");
}
