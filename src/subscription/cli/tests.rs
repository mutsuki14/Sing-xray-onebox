use super::*;
use crate::cli::args::{parse, Globals};
use crate::domain::config::SubscriptionMode;
use crate::subscription::request::EnableRequest;
use crate::subscription::testing::{ip, reality, site, standalone, Node};

const COMMANDS: &[CommandSpec] = &[SUBSCRIPTION];

fn words(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

fn resolve(list: &[&str]) -> Result<(Vec<&'static str>, bool, bool)> {
    let invocation = parse(COMMANDS, &words(list), Globals::default())?;
    let root = invocation.spec.root.required(&invocation.matches);
    Ok((invocation.matches.path, root, invocation.help))
}

#[test]
fn names_aliases_and_root_policy() {
    let cases: [(&[&str], &[&str], bool); 14] = [
        (&["subscription"], &["subscription"], false),
        (&["sub"], &["subscription"], false),
        (&["subscribe", "info"], &["subscription", "info"], false),
        (&["sub", "status"], &["subscription", "info"], false),
        (&["sub", "list"], &["subscription", "info"], false),
        (
            &["sub", "enable", "--mode", "ip"],
            &["subscription", "enable"],
            true,
        ),
        (&["sub", "disable"], &["subscription", "disable"], true),
        (&["sub", "add", "phone"], &["subscription", "add"], true),
        (&["sub", "revoke", "x"], &["subscription", "revoke"], true),
        (&["sub", "remove", "x"], &["subscription", "revoke"], true),
        (&["sub", "reset", "x"], &["subscription", "reset"], true),
        (&["sub", "refresh"], &["subscription", "publish"], true),
        (
            &["sub", "renew", "--cron"],
            &["subscription", "renew"],
            true,
        ),
        (&["sub", "serve"], &["subscription", "serve"], true),
    ];
    for (argv, path, root) in cases {
        let (got, needs_root, help) = resolve(argv).unwrap();
        assert_eq!(
            (got.as_slice(), needs_root, help),
            (path, root, false),
            "{argv:?}"
        );
    }
    assert!(
        resolve(&["sub", "help"]).unwrap().2,
        "help shows the group help"
    );
    let serve = SUBSCRIPTION.subcommand("serve").unwrap();
    assert!(serve.hidden);
}

#[test]
fn options_are_per_subcommand() {
    let unknown = resolve(&["sub", "enable", "--adress", "1.2.3.4"]).unwrap_err();
    assert!(unknown
        .to_string()
        .starts_with("subscription enable 不支持选项 --adress"));
    assert!(resolve(&["sub", "add", "--cron"]).is_err());
    assert!(resolve(&["sub", "bogus"])
        .unwrap_err()
        .to_string()
        .starts_with("未知子命令: bogus"));
    assert_eq!(
        resolve(&["sub", "enable", "--port"])
            .unwrap_err()
            .to_string(),
        "--port 需要参数"
    );
    assert_eq!(
        resolve(&["sub", "enable", "--port", "1", "--port", "2"])
            .unwrap_err()
            .to_string(),
        "重复选项: --port"
    );
    let invocation = parse(
        COMMANDS,
        &words(&["sub", "enable", "--ip", "192.0.2.1", "--name", "手机"]),
        Globals::default(),
    )
    .unwrap();
    let request = EnableRequest::from_matches(&invocation.matches).unwrap();
    assert_eq!(request.address.as_deref(), Some("192.0.2.1"));
    assert_eq!(request.name.as_deref(), Some("手机"));
}

#[test]
fn missing_device_arguments_keep_v2_usage_texts() {
    let node = Node::new("sub-cli-usage");
    let m = Matches::default();
    assert_eq!(
        add_command(&node.ctx, &m).unwrap_err().to_string(),
        ADD_USAGE
    );
    assert_eq!(
        revoke_command(&node.ctx, &m).unwrap_err().to_string(),
        REVOKE_USAGE
    );
    assert_eq!(
        reset_command(&node.ctx, &m).unwrap_err().to_string(),
        RESET_USAGE
    );
}

#[test]
fn device_commands_work_on_the_store() {
    let node = Node::new("sub-cli-devices");
    let ctx = &node.ctx;
    node.save(&reality());
    assert_eq!(
        add_device(ctx, "phone").unwrap_err().to_string(),
        devices::NOT_ENABLED
    );
    node.save(&ip(8448));
    add_device(ctx, "phone").unwrap();
    let list = devices::list(&ctx.paths).unwrap();
    assert_eq!(list.len(), 1);
    reset_device(ctx, &list[0].id).unwrap();
    assert_ne!(devices::list(&ctx.paths).unwrap()[0].hash, list[0].hash);
    assert_eq!(
        revoke_device(ctx, "ffffffffffffffff")
            .unwrap_err()
            .to_string(),
        devices::UNKNOWN_ID
    );
    revoke_device(ctx, &list[0].id).unwrap();
    assert!(devices::list(&ctx.paths).unwrap().is_empty());
    print_info(ctx).unwrap();
    let held = node.lock();
    assert_eq!(
        add_device(ctx, "tablet").unwrap_err().to_string(),
        BUSY_MESSAGE,
        "the node lock is taken without waiting"
    );
    drop(held);
}

#[test]
fn info_works_without_a_node() {
    let node = Node::new("sub-cli-info");
    print_info(&node.ctx).unwrap();
    node.save(&ip(8448));
    let info = info(&node.ctx, &ip(8448)).unwrap();
    assert_eq!(info.mode, Some("ip"));
}

#[test]
fn enable_plans_with_live_facts() {
    let node = Node::new("sub-cli-plan");
    let ctx = &node.ctx;
    node.listening(&[]);
    let request = |options: &[(&str, &str)]| EnableRequest {
        mode: options
            .iter()
            .find(|(k, _)| *k == "mode")
            .map(|(_, v)| v.to_string()),
        address: options
            .iter()
            .find(|(k, _)| *k == "address")
            .map(|(_, v)| v.to_string()),
        port: options
            .iter()
            .find(|(k, _)| *k == "port")
            .map(|(_, v)| v.to_string()),
        domain: options
            .iter()
            .find(|(k, _)| *k == "domain")
            .map(|(_, v)| v.to_string()),
        ..EnableRequest::default()
    };
    let next = plan_request(ctx, &reality(), &request(&[])).unwrap();
    let sub = next.subscription.unwrap();
    assert_eq!(sub.port, 8448);
    assert!(
        matches!(sub.mode, SubscriptionMode::Ip { .. }),
        "ip by default"
    );

    node.listening(&[9000]);
    assert_eq!(
        plan_request(ctx, &reality(), &request(&[("port", "9000")]))
            .unwrap_err()
            .to_string(),
        "订阅端口 9000 已被占用"
    );
    let on_site = plan_request(ctx, &site(), &request(&[])).unwrap();
    assert_eq!(on_site.subscription.unwrap().mode, SubscriptionMode::Site);
    let standalone_cfg =
        plan_request(ctx, &reality(), &request(&[("domain", "sub.example.com")])).unwrap();
    assert!(matches!(
        standalone_cfg.subscription.unwrap().mode,
        SubscriptionMode::Standalone { .. }
    ));
    let conflict = plan_request(ctx, &reality(), &request(&[("port", "443")])).unwrap_err();
    assert_eq!(conflict.to_string(), "订阅或验证端口与代理端口冲突");
}

#[test]
fn after_enable_creates_the_first_device_once() {
    let node = Node::new("sub-cli-after");
    let ctx = &node.ctx;
    let cfg = ip(8448);
    node.save(&cfg);
    let lock = node.lock();
    after_enable(ctx, &lock, None, &cfg, "default").unwrap();
    let first = devices::list(&ctx.paths).unwrap();
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].name, "default");
    after_enable(
        ctx,
        &lock,
        Some("http://203.0.113.10:8448"),
        &cfg,
        "default",
    )
    .unwrap();
    assert_eq!(
        devices::list(&ctx.paths).unwrap(),
        first,
        "existing devices kept"
    );
}

#[test]
fn cloudflare_credentials_are_resolved_before_the_apply() {
    let node = Node::new("sub-cli-cf");
    let ctx = &node.ctx;
    assert!(cloudflare_for(ctx, &ip(8448), false).unwrap().is_none());
    assert!(
        cloudflare_for(ctx, &standalone(WebCert::Http01, 8448), false)
            .unwrap()
            .is_none()
    );
    let cfg = standalone(WebCert::Cloudflare, 8448);
    node.ui.set_interactive(false);
    assert_eq!(
        cloudflare_for(ctx, &cfg, false).unwrap_err().to_string(),
        cloudflare::MISSING
    );
    node.ui.set_interactive(true);
    node.ui.extend(["fake-token-0123", ""]);
    let given = cloudflare_for(ctx, &cfg, false).unwrap().unwrap();
    assert_eq!(given.get("CF_Token"), Some("fake-token-0123"));

    let dir = CertDir::subscription(&ctx.paths);
    cloudflare::persist(dir.path(), &given).unwrap();
    assert!(
        cloudflare_for(ctx, &cfg, false).unwrap().is_none(),
        "stored credentials are used as they are"
    );
}
