use super::*;
use crate::sys::fs::TempDir;
use crate::ui::ScriptedPrompter;
use std::os::unix::fs::PermissionsExt;

fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let owned: Vec<(String, String)> = pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    move |key| owned.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
}

fn no_env(_: &str) -> Option<String> {
    None
}

#[test]
fn saved_cloudflare_credentials_are_data_not_shell() {
    let parsed = parse_account_conf(
        "SAVED_CF_Token='valid-token_123'\nCF_Account_ID=0123456789abcdef0123456789abcdef\n\
         CF_Key=$(touch /tmp/forbidden)\nCF_Email='admin@example.test'; run_something\n\
         OTHER=1\n  SAVED_CF_Zone_ID=\"abcdef\"  \nCF_Email\n",
    );
    assert_eq!(
        parsed.get("CF_Token").map(String::as_str),
        Some("valid-token_123")
    );
    assert!(parsed.contains_key("CF_Account_ID"));
    assert_eq!(parsed.get("CF_Zone_ID").map(String::as_str), Some("abcdef"));
    assert!(!parsed.contains_key("CF_Key"));
    assert!(!parsed.contains_key("CF_Email"));
    assert!(!parsed.contains_key("OTHER"));
}

#[test]
fn lookup_merges_sources_in_v2_order() {
    let dir = TempDir::new("cf-lookup").unwrap();
    let (ctx, _, _) = Ctx::test(dir.path());
    let tls = ctx.paths.tls();
    std::fs::create_dir_all(tls.join("acme")).unwrap();
    std::fs::create_dir_all(ctx.paths.root.join("acme")).unwrap();
    let legacy = dir.join("legacy-acme");
    std::fs::create_dir_all(&legacy).unwrap();
    std::fs::write(
        legacy.join("account.conf"),
        "SAVED_CF_Key='legacykey'\nSAVED_CF_Email='a@b.c'\nSAVED_CF_Zone_ID='z1'\n",
    )
    .unwrap();
    std::fs::write(
        ctx.paths.root.join("acme/account.conf"),
        "SAVED_CF_Zone_ID='z2'\n",
    )
    .unwrap();
    std::fs::write(tls.join("acme/account.conf"), "SAVED_CF_Zone_ID='z3'\n").unwrap();
    let legacy_s = legacy.display().to_string();
    let env = env_of(&[("ACME_HOME", &legacy_s)]);
    let found = lookup_with(&ctx, &tls, &env).unwrap().unwrap();
    assert_eq!(found.get("CF_Key"), Some("legacykey"));
    assert_eq!(found.get("CF_Zone_ID"), Some("z3"));
    // The legacy acme home only counts for the proxy directory.
    assert_eq!(lookup_with(&ctx, &ctx.paths.site(), &env).unwrap(), None);

    // The stored file beats account.conf, the environment beats both.
    std::fs::write(
        store_path(&tls),
        r#"{"CF_Token":"stored","CF_Zone_ID":"z4","Junk":"x","CF_Email":""}"#,
    )
    .unwrap();
    let found = lookup_with(&ctx, &tls, &env).unwrap().unwrap();
    assert_eq!(
        (found.get("CF_Token"), found.get("CF_Zone_ID")),
        (Some("stored"), Some("z4"))
    );
    assert_eq!(found.get("CF_Email"), Some("a@b.c"));
    assert_eq!(found.get("Junk"), None);
    let env = env_of(&[("CF_Token", "from-env"), ("CF_Account_ID", "bad\nid")]);
    let found = lookup_with(&ctx, &tls, &env).unwrap().unwrap();
    assert_eq!(found.get("CF_Token"), Some("from-env"));
    assert_eq!(found.get("CF_Account_ID"), None);
    std::fs::write(store_path(&tls), "not json").unwrap();
    assert!(lookup_with(&ctx, &tls, &no_env).is_err());
}

#[test]
fn incomplete_credentials_are_not_returned() {
    let dir = TempDir::new("cf-incomplete").unwrap();
    let (ctx, _, _) = Ctx::test(dir.path());
    let site = ctx.paths.site();
    assert_eq!(lookup_with(&ctx, &site, &no_env).unwrap(), None);
    let key_only = env_of(&[("CF_Key", "k")]);
    assert_eq!(lookup_with(&ctx, &site, &key_only).unwrap(), None);
    let pair = env_of(&[("CF_Key", "k"), ("CF_Email", "a@b.c")]);
    assert!(lookup_with(&ctx, &site, &pair)
        .unwrap()
        .unwrap()
        .is_complete());
    assert_eq!(
        resolve(&ctx, &site, None, &no_env).unwrap_err().to_string(),
        MISSING
    );
}

#[test]
fn persist_writes_sorted_compact_json_privately() {
    let dir = TempDir::new("cf-persist").unwrap();
    let cert_dir = dir.join("site");
    let creds = CfCredentials::token("tok", Some("0123456789abcdef0123456789abcdef")).unwrap();
    persist(&cert_dir, &creds).unwrap();
    let text = std::fs::read_to_string(store_path(&cert_dir)).unwrap();
    assert_eq!(
        text,
        r#"{"CF_Account_ID":"0123456789abcdef0123456789abcdef","CF_Token":"tok"}"#
    );
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&store_path(&cert_dir)), 0o600);
    assert_eq!(mode(&cert_dir.join("acme")), 0o700);
    assert_eq!(
        creds.env(),
        [
            (
                "CF_Account_ID".to_owned(),
                "0123456789abcdef0123456789abcdef".to_owned()
            ),
            ("CF_Token".to_owned(), "tok".to_owned())
        ]
    );
    let debug = format!("{creds:?}");
    assert!(
        !debug.contains("tok\"") && debug.contains("CF_Token"),
        "{debug}"
    );
}

#[test]
fn resolve_prefers_given_credentials_and_persists_them() {
    let dir = TempDir::new("cf-resolve").unwrap();
    let (ctx, _, _) = Ctx::test(dir.path());
    let site = ctx.paths.site();
    let given = CfCredentials::token("given", None).unwrap();
    let used = resolve(&ctx, &site, Some(&given), &no_env).unwrap();
    assert_eq!(used, given);
    // The stored copy now serves a later run without the CLI.
    assert_eq!(resolve(&ctx, &site, None, &no_env).unwrap(), given);
}

#[test]
fn resolve_lays_given_credentials_over_the_stored_ones() {
    let dir = TempDir::new("cf-merge").unwrap();
    let (ctx, _, _) = Ctx::test(dir.path());
    let site = ctx.paths.site();
    std::fs::create_dir_all(site.join("acme")).unwrap();
    std::fs::write(
        store_path(&site),
        r#"{"CF_Account_ID":"0123456789abcdef0123456789abcdef","CF_Token":"old","CF_Zone_ID":"zone1"}"#,
    )
    .unwrap();
    std::fs::write(site.join("acme/account.conf"), "SAVED_CF_Email='a@b.c'\n").unwrap();
    let given = CfCredentials::token("new", None).unwrap();
    let used = resolve(&ctx, &site, Some(&given), &no_env).unwrap();
    assert_eq!(used.get("CF_Token"), Some("new"));
    assert_eq!(used.get("CF_Zone_ID"), Some("zone1"));
    assert_eq!(
        used.get("CF_Account_ID"),
        Some("0123456789abcdef0123456789abcdef")
    );
    assert_eq!(used.get("CF_Email"), Some("a@b.c"));
    let stored = std::fs::read_to_string(store_path(&site)).unwrap();
    assert_eq!(
        stored,
        r#"{"CF_Account_ID":"0123456789abcdef0123456789abcdef","CF_Email":"a@b.c","CF_Token":"new","CF_Zone_ID":"zone1"}"#
    );
    // A given account ID replaces the stored one; incomplete given values
    // are ignored in favour of what is stored.
    let other = CfCredentials::token("new", Some("ffffffffffffffffffffffffffffffff")).unwrap();
    let used = resolve(&ctx, &site, Some(&other), &no_env).unwrap();
    assert_eq!(
        used.get("CF_Account_ID"),
        Some("ffffffffffffffffffffffffffffffff")
    );
    let incomplete = CfCredentials::default();
    let used = resolve(&ctx, &site, Some(&incomplete), &no_env).unwrap();
    assert_eq!(used.get("CF_Token"), Some("new"));
}

#[test]
fn prompt_asks_for_a_secret_token_and_an_optional_account() {
    let ui = ScriptedPrompter::new(["", "tok", "nothex", ""]);
    let creds = prompt(&ui).unwrap();
    assert_eq!(creds.get("CF_Token"), Some("tok"));
    assert_eq!(creds.get("CF_Account_ID"), None);
    assert_eq!(
        ui.prompts(),
        [TOKEN_PROMPT, TOKEN_PROMPT, ACCOUNT_PROMPT, ACCOUNT_PROMPT]
    );
    let ui = ScriptedPrompter::new(["tok", "0123456789ABCDEF0123456789abcdef"]);
    let creds = prompt(&ui).unwrap();
    assert_eq!(
        creds.get("CF_Account_ID"),
        Some("0123456789ABCDEF0123456789abcdef")
    );
    let ui = ScriptedPrompter::new(["", "", ""]);
    assert_eq!(prompt(&ui).unwrap_err().to_string(), BAD_TOKEN);
    let unattended = ScriptedPrompter::unattended();
    assert_eq!(
        prompt(&unattended).unwrap_err().to_string(),
        crate::ui::UNATTENDED_SECRET
    );
    assert_eq!(
        CfCredentials::token("t", Some("short"))
            .unwrap_err()
            .to_string(),
        BAD_ACCOUNT
    );
}
