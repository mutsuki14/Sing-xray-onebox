//! Golden texts: `golden/*.service|*.openrc` were produced by v2.0.1's
//! `write_service_for_init` templates (copied verbatim into a generator)
//! for the default layout, then the documented fixes were applied: no
//! trailing space after the targets / in `depend()`, and
//! `rc_ulimit='-n 1048576'`.

use super::*;
use crate::domain::protocol::Core;
use crate::host::init::InitSystem;
use crate::host::service::{service_env, Identity, ServiceDef};
use crate::paths::Paths;
use std::path::Path;

fn paths() -> Paths {
    Paths::from_lookup(|_| None).unwrap()
}

fn defs() -> Vec<ServiceDef> {
    let p = paths();
    let nginx = Path::new("/usr/sbin/nginx");
    vec![
        ServiceDef::core(&p, Core::Singbox, true),
        ServiceDef::core(&p, Core::Xray, false),
        ServiceDef::site(&p, nginx),
        ServiceDef::network(&p),
        ServiceDef::subscription(&p),
        ServiceDef::subscription_web(&p, nginx),
        ServiceDef::frps(&p),
        ServiceDef::frp_web(&p, nginx),
    ]
}

fn golden(file: &str) -> &'static str {
    match file {
        "onebox-sing-box.service" => include_str!("../golden/onebox-sing-box.service"),
        "onebox-sing-box.openrc" => include_str!("../golden/onebox-sing-box.openrc"),
        "onebox-xray.service" => include_str!("../golden/onebox-xray.service"),
        "onebox-xray.openrc" => include_str!("../golden/onebox-xray.openrc"),
        "onebox-site.service" => include_str!("../golden/onebox-site.service"),
        "onebox-site.openrc" => include_str!("../golden/onebox-site.openrc"),
        "onebox-network.service" => include_str!("../golden/onebox-network.service"),
        "onebox-network.openrc" => include_str!("../golden/onebox-network.openrc"),
        "onebox-subscription.service" => include_str!("../golden/onebox-subscription.service"),
        "onebox-subscription.openrc" => include_str!("../golden/onebox-subscription.openrc"),
        "onebox-subscription-web.service" => {
            include_str!("../golden/onebox-subscription-web.service")
        }
        "onebox-subscription-web.openrc" => {
            include_str!("../golden/onebox-subscription-web.openrc")
        }
        "onebox-frps.service" => include_str!("../golden/onebox-frps.service"),
        "onebox-frps.openrc" => include_str!("../golden/onebox-frps.openrc"),
        "onebox-frp-web.service" => include_str!("../golden/onebox-frp-web.service"),
        "onebox-frp-web.openrc" => include_str!("../golden/onebox-frp-web.openrc"),
        other => panic!("no golden file {other}"),
    }
}

#[test]
fn systemd_units_match_v2_goldens() {
    let env = service_env(&paths(), InitSystem::Systemd);
    for def in defs() {
        let unit = render_systemd(&def, &env).unwrap();
        assert_eq!(
            unit,
            golden(&format!("{}.service", def.name)),
            "{}",
            def.name
        );
    }
}

#[test]
fn openrc_scripts_match_v2_goldens() {
    let env = service_env(&paths(), InitSystem::Openrc);
    for def in defs() {
        let script = render_openrc(&def, &env).unwrap();
        assert_eq!(
            script,
            golden(&format!("{}.openrc", def.name)),
            "{}",
            def.name
        );
    }
}

#[test]
fn every_word_is_escaped_for_its_format() {
    let p = paths();
    let mut def = ServiceDef::new(
        &p,
        "onebox-test",
        "/opt/my dir/$x",
        vec!["100% a".into(), "it's \"q\" \\".into()],
        vec!["onebox-site".into(), "nss-lookup.target".into()],
    );
    def.pre_start = Some(vec![
        "/bin/pre".into(),
        "plain".into(),
        "needs quote".into(),
    ]);
    def.identity = Identity::default();
    let mut env = service_env(&p, InitSystem::Systemd);
    env[0].1 = "/etc/one%box\"".into();
    let unit = render_systemd(&def, &env).unwrap();
    assert!(
        unit.contains("Environment=\"ONEBOX_DIR=/etc/one%%box\\\"\"\n"),
        "{unit}"
    );
    assert!(unit.contains("ExecStart=\"/opt/my dir/$$x\" \"100%% a\" \"it's \\\"q\\\" \\\\\"\n"));
    assert!(unit.contains("ExecStartPre=\"/bin/pre\" plain \"needs quote\"\n"));
    assert!(unit.contains(
        "After=network-online.target nss-lookup.target onebox-site.service nss-lookup.target\n"
    ));
    assert!(unit.contains("Wants=network-online.target onebox-site.service nss-lookup.target\n"));

    let env = service_env(&p, InitSystem::Openrc);
    let script = render_openrc(&def, &env).unwrap();
    assert!(script.contains("command='/opt/my dir/$x'\n"), "{script}");
    assert!(script.contains(r#"command_args=''\''100% a'\'' '\''it'\''\'\'''\''s "q" \'\'''"#));
    assert!(script.contains("depend() { want net; after net firewall dns onebox-site; }\n"));
    assert!(script.ends_with("start_pre() { '/bin/pre' plain 'needs quote'; }\n"));
}

#[test]
fn line_breaks_and_foreign_environment_are_refused() {
    let p = paths();
    let env = service_env(&p, InitSystem::Systemd);
    let mut def = ServiceDef::network(&p);
    def.args = vec!["net-apply\nExecStart=/bin/evil".into()];
    assert!(render_systemd(&def, &env).is_err());
    assert!(render_openrc(&def, &env).is_err());

    let def = ServiceDef::network(&p);
    let mut bad = env.clone();
    bad.push(("CF_Token".into(), "secret".into()));
    assert!(render_systemd(&def, &bad).is_err());
    let mut bad = env;
    bad[0].1 = "/etc/onebox\n[Service]".into();
    assert!(render_openrc(&def, &bad).is_err());
}

#[test]
fn oneshot_without_banner_uses_description_and_quotes_args() {
    let p = paths();
    let mut def = ServiceDef::network(&p);
    def.banner = None;
    def.args = vec!["net apply".into()];
    let script = render_openrc(&def, &service_env(&p, InitSystem::Openrc)).unwrap();
    assert!(script.contains("  ebegin 'Onebox network rule restoration'\n"));
    assert!(script.contains("  '/usr/local/bin/onebox' 'net apply'\n"));
}
