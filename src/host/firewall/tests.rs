//! Backend argv golden tests, detection and span normalization.

use super::*;
use crate::sys::exec::{FakeExec, Output};
use crate::sys::fs::TempDir;
use std::sync::Arc;

fn rule(proto: Proto, start: u16, end: u16) -> Rule {
    Rule {
        owner: "proxy".into(),
        proto,
        start,
        end,
        token: "onebox-proxy-0123456789abcdef".into(),
    }
}

fn setup() -> (TempDir, Ctx, Arc<FakeExec>) {
    let dir = TempDir::new("firewall").unwrap();
    let (ctx, exec, _) = Ctx::test(dir.path());
    (dir, ctx, exec)
}

/// Enable IPv6 in the fixture system root.
fn enable_ipv6(ctx: &Ctx) {
    let inet6 = ctx.paths.system("/proc/net/if_inet6");
    std::fs::create_dir_all(inet6.parent().unwrap()).unwrap();
    std::fs::write(inet6, "").unwrap();
}

#[test]
fn spans_merge_per_protocol_without_mixing() {
    let desired = [
        (80, 80, Transport::Tcp),
        (81, 81, Transport::Tcp),
        (82, 82, Transport::Udp),
        (83, 83, Transport::Udp),
        (85, 85, Transport::Udp),
        (443, 443, Transport::Both),
        (20000, 30000, Transport::Udp),
        (25000, 40000, Transport::Udp),
        (65535, 65535, Transport::Tcp),
    ];
    let span = |start, end, proto| PortSpan { start, end, proto };
    assert_eq!(
        spans(&desired).unwrap(),
        [
            span(80, 81, Proto::Tcp),
            span(443, 443, Proto::Tcp),
            span(65535, 65535, Proto::Tcp),
            span(82, 83, Proto::Udp),
            span(85, 85, Proto::Udp),
            span(443, 443, Proto::Udp),
            span(20000, 40000, Proto::Udp),
        ]
    );
    assert!(spans(&[]).unwrap().is_empty());
    for (bad, message) in [
        ((0, 0, Transport::Tcp), "防火墙端口不能为0"),
        ((10, 9, Transport::Udp), "防火墙端口范围无效: 10-9"),
    ] {
        assert_eq!(spans(&[bad]).unwrap_err().to_string(), message);
    }
}

#[test]
fn owners_and_tokens() {
    for good in ["proxy", "acme", "frp", "a-1"] {
        validate_owner(good).unwrap();
    }
    for bad in ["", "../frp", "a b", "x_y", &"a".repeat(32)] {
        assert_eq!(
            validate_owner(bad).unwrap_err().to_string(),
            "防火墙所有者名称无效"
        );
    }
    let token = new_token("acme").unwrap();
    let hex = token.strip_prefix("onebox-acme-").unwrap();
    assert_eq!(hex.len(), 16);
    assert!(hex.bytes().all(|b| b.is_ascii_hexdigit()));
    assert!(safe_word(&token) && !safe_word("a;b") && !safe_word(""));
}

#[test]
fn rule_spans_use_backend_separators() {
    assert_eq!(rule(Proto::Tcp, 443, 443).span(":"), "443");
    assert_eq!(rule(Proto::Udp, 20000, 40000).span(":"), "20000:40000");
    assert_eq!(rule(Proto::Udp, 20000, 40000).span("-"), "20000-40000");
}

#[test]
fn iptables_argv_golden() {
    let (_dir, ctx, exec) = setup();
    exec.on("iptables", &["-w", "5", "-C"], Output::failure(1, ""))
        .on("iptables", &["-w", "5", "-I"], Output::success(""))
        .on("ip6tables", &["-w", "5", "-C"], Output::success(""))
        .on("ip6tables", &["-w", "5", "-D"], Output::success(""));
    let v4 = Iptables { v6: false };
    let v6 = Iptables { v6: true };
    let r = rule(Proto::Udp, 20000, 40000);
    assert!(v4.create(&ctx, &r).unwrap());
    assert!(!v4.exists(&ctx, &r).unwrap());
    v4.remove(&ctx, &r).unwrap();
    assert!(v6.exists(&ctx, &r).unwrap());
    v6.remove(&ctx, &rule(Proto::Tcp, 443, 443)).unwrap();
    let tail = "-m comment --comment onebox-proxy-0123456789abcdef -j ACCEPT";
    assert_eq!(
        exec.history(),
        [
            format!("iptables -w 5 -I INPUT 1 -p udp --dport 20000:40000 {tail}"),
            format!("iptables -w 5 -C INPUT -p udp --dport 20000:40000 {tail}"),
            format!("iptables -w 5 -C INPUT -p udp --dport 20000:40000 {tail}"),
            format!("ip6tables -w 5 -C INPUT -p udp --dport 20000:40000 {tail}"),
            format!("ip6tables -w 5 -C INPUT -p tcp --dport 443 {tail}"),
            format!("ip6tables -w 5 -D INPUT -p tcp --dport 443 {tail}"),
        ]
    );
    assert_eq!(
        (v4.name(), v6.name(), v6.program()),
        ("iptables", "ip6tables", "ip6tables")
    );
}

#[test]
fn iptables_probe_errors_are_not_absence() {
    let (_dir, ctx, exec) = setup();
    exec.on("iptables", &[], Output::failure(2, "chain INPUT gone"));
    let r = rule(Proto::Tcp, 443, 443);
    let v4 = Iptables { v6: false };
    assert_eq!(
        v4.exists(&ctx, &r).unwrap_err().to_string(),
        "无法检查 iptables 规则: chain INPUT gone"
    );
    assert_eq!(
        v4.remove(&ctx, &r).unwrap_err().to_string(),
        "无法检查已有 iptables 规则: chain INPUT gone"
    );
    assert!(
        exec.history().iter().all(|c| !c.contains(" -D ")),
        "never deletes blindly"
    );
}

#[test]
fn firewalld_argv_golden() {
    let (_dir, ctx, exec) = setup();
    exec.on(
        "firewall-cmd",
        &["--zone=public", "--query-port=443/tcp"],
        Output::failure(1, "no"),
    )
    .on(
        "firewall-cmd",
        &["--zone=public", "--query-port=20000-40000/udp"],
        Output::success("yes"),
    )
    .on("firewall-cmd", &[], Output::success("success"));
    let runtime = Firewalld {
        zone: "public".into(),
        permanent: false,
    };
    let permanent = Firewalld {
        zone: "public".into(),
        permanent: true,
    };
    let tcp = rule(Proto::Tcp, 443, 443);
    let udp = rule(Proto::Udp, 20000, 40000);
    assert!(runtime.create(&ctx, &tcp).unwrap());
    assert!(permanent.create(&ctx, &tcp).unwrap());
    assert!(
        !runtime.create(&ctx, &udp).unwrap(),
        "admin rule is not adopted"
    );
    assert!(runtime.exists(&ctx, &udp).unwrap());
    runtime.remove(&ctx, &udp).unwrap();
    runtime.remove(&ctx, &tcp).unwrap();
    assert_eq!(
        exec.history(),
        [
            "firewall-cmd --zone=public --query-port=443/tcp",
            "firewall-cmd --zone=public --add-port=443/tcp",
            "firewall-cmd --zone=public --query-port=443/tcp --permanent",
            "firewall-cmd --zone=public --add-port=443/tcp --permanent",
            "firewall-cmd --zone=public --query-port=20000-40000/udp",
            "firewall-cmd --zone=public --query-port=20000-40000/udp",
            "firewall-cmd --zone=public --query-port=20000-40000/udp",
            "firewall-cmd --zone=public --remove-port=20000-40000/udp",
            "firewall-cmd --zone=public --query-port=443/tcp",
        ]
    );
}

#[test]
fn firewalld_query_failures_change_nothing() {
    let (_dir, ctx, exec) = setup();
    exec.on(
        "firewall-cmd",
        &[],
        Output::failure(252, "FirewallD is not running"),
    );
    let zone = Firewalld {
        zone: "public".into(),
        permanent: false,
    };
    let r = rule(Proto::Tcp, 443, 443);
    let create = zone.create(&ctx, &r).unwrap_err().to_string();
    assert_eq!(
        create,
        "firewalld 查询失败，未变更规则: FirewallD is not running"
    );
    assert!(zone.exists(&ctx, &r).is_err());
    assert!(zone.remove(&ctx, &r).is_err());
    assert!(exec.history().iter().all(|c| c.contains("--query-port")));
}

#[test]
fn active_zone_parsing() {
    let text = "public (default)\n  interfaces: eth0\ndocker\n  interfaces: docker0\n\npublic\n";
    assert_eq!(firewalld::parse_active_zones(text), ["public", "docker"]);
    assert!(firewalld::parse_active_zones("").is_empty());
}

#[test]
fn ufw_argv_golden() {
    let (_dir, ctx, exec) = setup();
    let status = "Status: active\n\n     To                         Action      From\n     --                         ------      ----\n\
[ 1] 22/tcp                     ALLOW IN    Anywhere\n\
[ 2] 443/tcp                    ALLOW IN    Anywhere                   # onebox-proxy-0123456789abcdef\n\
[ 3] 8443/tcp                   ALLOW IN    Anywhere                   # onebox-proxy-0123456789abcdef0\n\
[10] 443/tcp (v6)               ALLOW IN    Anywhere (v6)              # onebox-proxy-0123456789abcdef\n";
    exec.on("ufw", &["status", "numbered"], Output::success(status))
        .on("ufw", &[], Output::success(""));
    let r = rule(Proto::Udp, 20000, 40000);
    assert!(Ufw.create(&ctx, &r).unwrap());
    assert!(Ufw.exists(&ctx, &r).unwrap());
    Ufw.remove(&ctx, &r).unwrap();
    assert_eq!(
        exec.history(),
        [
            "ufw status numbered",
            "ufw allow 20000:40000/udp comment onebox-proxy-0123456789abcdef",
            "ufw status numbered",
            "ufw status numbered",
            "ufw --force delete 10",
            "ufw --force delete 2",
        ]
    );
    assert_eq!(
        ufw::numbered_matches(status, "onebox-proxy-other"),
        Vec::<u32>::new()
    );
}

#[test]
fn ufw_status_lines_are_parsed() {
    let line =
        "[10] 443/tcp (v6)               ALLOW IN    Anywhere (v6)              # onebox-proxy-01";
    assert_eq!(
        ufw::parse_line(line),
        Some(ufw::Listed {
            number: 10,
            to: "443/tcp",
            action: "ALLOW",
            from: "Anywhere",
            comment: Some("onebox-proxy-01"),
        })
    );
    let limited =
        ufw::parse_line("[ 3] 22/tcp                     LIMIT IN    203.0.113.0/24").unwrap();
    assert_eq!(
        (limited.action, limited.from, limited.comment),
        ("LIMIT", "203.0.113.0/24", None)
    );
    for junk in [
        "Status: active",
        "",
        "     To   Action   From",
        "[x] 1/tcp ALLOW IN Anywhere",
    ] {
        assert_eq!(ufw::parse_line(junk), None, "{junk:?}");
    }
}

#[test]
fn ufw_never_rewrites_administrator_rules() {
    let (_dir, ctx, exec) = setup();
    let status = "Status: active\n\
[ 1] 443/tcp                    ALLOW IN    Anywhere\n\
[ 2] 8443/tcp                   DENY IN     Anywhere\n\
[ 3] 80/tcp                     ALLOW IN    Anywhere                   # onebox-acme-1111111111111111\n\
[ 4] 9443/tcp                   ALLOW IN    198.51.100.7\n";
    exec.on("ufw", &["status", "numbered"], Output::success(status))
        .on("ufw", &["allow"], Output::success("Rule added\n"));
    assert!(
        !Ufw.create(&ctx, &rule(Proto::Tcp, 443, 443)).unwrap(),
        "admin allow"
    );
    assert!(
        !Ufw.create(&ctx, &rule(Proto::Tcp, 8443, 8443)).unwrap(),
        "admin deny kept"
    );
    assert!(
        Ufw.create(&ctx, &rule(Proto::Tcp, 80, 80)).unwrap(),
        "another owner's rule"
    );
    assert!(
        Ufw.create(&ctx, &rule(Proto::Tcp, 9443, 9443)).unwrap(),
        "source-limited admin rule differs"
    );
    let allows: Vec<String> = exec
        .history()
        .into_iter()
        .filter(|c| c.contains("allow"))
        .collect();
    assert_eq!(
        allows,
        [
            "ufw allow 80/tcp comment onebox-proxy-0123456789abcdef",
            "ufw allow 9443/tcp comment onebox-proxy-0123456789abcdef",
        ]
    );
}

#[test]
fn inactive_ufw_cannot_confirm_removal() {
    let (_dir, ctx, exec) = setup();
    exec.on(
        "ufw",
        &["status", "numbered"],
        Output::success("Status: inactive\n"),
    );
    let err = Ufw.remove(&ctx, &rule(Proto::Tcp, 443, 443)).unwrap_err();
    assert!(err.to_string().starts_with("ufw 未启用"));
    assert_eq!(exec.history(), ["ufw status numbered"]);
}

#[test]
fn nft_argv_golden() {
    let (_dir, ctx, exec) = setup();
    let listing = r#"{"nftables":[{"metainfo":{}},
        {"chain":{"family":"inet","table":"filter","name":"input","handle":1}},
        {"rule":{"family":"inet","table":"filter","chain":"input","handle":7,"comment":"onebox-proxy-0123456789abcdef","expr":[]}},
        {"rule":{"family":"inet","table":"filter","chain":"input","handle":8,"comment":"admin","expr":[]}},
        {"rule":{"family":"inet","table":"filter","chain":"input","handle":9,"expr":[]}}]}"#;
    exec.on("nft", &["-j"], Output::success(listing))
        .on("nft", &[], Output::success(""));
    let chain = Nft {
        family: "inet".into(),
        table: "filter".into(),
        chain: "input".into(),
    };
    let r = rule(Proto::Udp, 20000, 40000);
    assert!(chain.create(&ctx, &r).unwrap());
    assert!(chain.exists(&ctx, &r).unwrap());
    chain.remove(&ctx, &r).unwrap();
    let mut other = r.clone();
    other.token = "onebox-proxy-ffffffffffffffff".into();
    assert!(!chain.exists(&ctx, &other).unwrap());
    let calls = exec.calls();
    assert_eq!(
        calls[0].args,
        [
            "insert",
            "rule",
            "inet",
            "filter",
            "input",
            "udp",
            "dport",
            "20000-40000",
            "accept",
            "comment",
            "\"onebox-proxy-0123456789abcdef\""
        ]
    );
    assert_eq!(
        exec.history()[1..4],
        [
            "nft -j list chain inet filter input",
            "nft -j -a list chain inet filter input",
            "nft delete rule inet filter input handle 7",
        ]
    );
}

#[test]
fn nft_chain_that_vanished_means_rule_gone() {
    let (_dir, ctx, exec) = setup();
    exec.on(
        "nft",
        &[],
        Output::failure(
            1,
            "Error: No such file or directory\nlist chain inet filter input",
        ),
    );
    let chain = Nft {
        family: "inet".into(),
        table: "filter".into(),
        chain: "input".into(),
    };
    let r = rule(Proto::Tcp, 443, 443);
    assert!(!chain.exists(&ctx, &r).unwrap());
    chain.remove(&ctx, &r).unwrap();
    let (_dir, ctx, exec) = setup();
    exec.on(
        "nft",
        &[],
        Output::failure(1, "Error: Operation not permitted"),
    );
    assert!(chain.remove(&ctx, &r).is_err());
}

/// A filter base chain with `policy drop` (one that can block a port).
fn chain_json(family: &str, table: &str, name: &str, hook: &str) -> String {
    policy_chain(family, table, name, hook, "drop")
}

fn policy_chain(family: &str, table: &str, name: &str, hook: &str, policy: &str) -> String {
    format!(
        r#"{{"chain":{{"family":"{family}","table":"{table}","name":"{name}","handle":1,"type":"filter","hook":"{hook}","prio":0,"policy":"{policy}"}}}}"#
    )
}

fn rule_json(family: &str, table: &str, chain: &str, expr: &str) -> String {
    format!(
        r#"{{"rule":{{"family":"{family}","table":"{table}","chain":"{chain}","handle":9,"expr":{expr}}}}}"#
    )
}

fn nft_chain(family: &str, table: &str, chain: &str) -> Nft {
    Nft {
        family: family.into(),
        table: table.into(),
        chain: chain.into(),
    }
}

fn ruleset(chains: &[String]) -> String {
    let mut items = vec![r#"{"metainfo":{"version":"1.0.9"}}"#.to_string()];
    items.extend(chains.iter().cloned());
    format!(r#"{{"nftables":[{}]}}"#, items.join(","))
}

#[test]
fn ruleset_classification_keeps_iptables_nft_tables_out_of_nft() {
    let nat_input = r#"{"chain":{"family":"inet","table":"natty","name":"input","handle":2,"type":"nat","hook":"input","prio":100,"policy":"accept"}}"#;
    let doc: serde_json::Value = serde_json::from_str(&ruleset(&[
        chain_json("ip", "filter", "INPUT", "input"),
        chain_json("ip6", "filter", "INPUT", "input"),
        chain_json("inet", "filter", "input", "input"),
        chain_json("inet", "filter", "input", "input"),
        chain_json("ip", "filter", "FORWARD", "forward"),
        chain_json("bridge", "filter", "input", "input"),
        chain_json("ip", "mangle", "INPUT", "input"),
        chain_json("ip", "security", "INPUT", "input"),
        chain_json("ip", "nat", "INPUT", "input"),
        chain_json("ip", "myfilter", "INPUT", "input"),
        nat_input.to_string(),
    ]))
    .unwrap();
    let scan = nft::parse_ruleset(&doc).unwrap();
    assert!(scan.compat_v4 && scan.compat_v6);
    assert_eq!(
        scan.native,
        [
            Nft {
                family: "inet".into(),
                table: "filter".into(),
                chain: "input".into()
            },
            Nft {
                family: "ip".into(),
                table: "myfilter".into(),
                chain: "INPUT".into()
            },
        ],
        "iptables-nft tables and non-filter chains are never edited"
    );
    let mangle_only: serde_json::Value =
        serde_json::from_str(&ruleset(&[chain_json("ip", "mangle", "INPUT", "input")])).unwrap();
    let scan = nft::parse_ruleset(&mangle_only).unwrap();
    assert!(!scan.compat_v4 && scan.native.is_empty());
    assert!(nft::parse_ruleset(&serde_json::json!({})).is_err());
}

#[test]
fn only_chains_that_can_block_get_rules() {
    const SET_DROP: &str = r#"[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"@crowdsec-blacklists"}},{"drop":null}]"#;
    let doc: serde_json::Value = serde_json::from_str(&ruleset(&[
        // crowdsec-firewall-bouncer: accept policy, only set-matched drops.
        policy_chain("ip", "crowdsec", "crowdsec-chain", "input", "accept"),
        rule_json("ip", "crowdsec", "crowdsec-chain", SET_DROP),
        // fail2ban: a rate-limited drop is conditional too.
        policy_chain("inet", "f2b-table", "f2b-chain", "input", "accept"),
        rule_json(
            "inet",
            "f2b-table",
            "f2b-chain",
            r#"[{"limit":{"rate":10,"per":"second"}},{"drop":null}]"#,
        ),
        // The admin's filter: policy drop.
        chain_json("inet", "filter", "input", "input"),
        // Accept policy ending in an unconditional `counter reject`.
        policy_chain("inet", "guard", "input", "input", "accept"),
        rule_json(
            "inet",
            "guard",
            "input",
            r#"[{"counter":{"packets":0,"bytes":0}},{"reject":{"type":"icmpx","expr":"admin-prohibited"}}]"#,
        ),
        // Accept policy whose only rule accepts.
        policy_chain("inet", "open", "input", "input", "accept"),
        rule_json("inet", "open", "input", r#"[{"accept":null}]"#),
    ]))
    .unwrap();
    let scan = nft::parse_ruleset(&doc).unwrap();
    assert_eq!(
        scan.native,
        [
            nft_chain("inet", "filter", "input"),
            nft_chain("inet", "guard", "input")
        ],
        "an accept in crowdsec/f2b chains would only bypass their drops"
    );
    assert!(scan.skipped.is_empty());
}

#[test]
fn hosts_with_only_non_blocking_nft_chains_use_iptables() {
    let (_dir, ctx, exec) = setup();
    exec.provide("nft").provide("iptables");
    exec.on(
        "nft",
        &["-j", "list", "ruleset"],
        Output::success(ruleset(&[policy_chain(
            "ip",
            "crowdsec",
            "crowdsec-chain",
            "input",
            "accept",
        )])),
    )
    .on("iptables", &["-w", "5", "-S", "INPUT"], Output::success(""));
    assert_eq!(
        detect(&ctx).unwrap(),
        [Location::Iptables(Iptables { v6: false })],
        "an accept in a separate table never bypasses crowdsec's drops"
    );
}

#[test]
fn unsafe_chain_names_are_skipped_not_fatal() {
    let (_dir, ctx, exec) = setup();
    exec.provide("nft");
    exec.on(
        "nft",
        &["-j", "list", "ruleset"],
        Output::success(ruleset(&[
            // LXD / Incus (nftables driver).
            policy_chain("inet", "lxd", "in.lxdbr0", "input", "accept"),
            rule_json(
                "inet",
                "lxd",
                "in.lxdbr0",
                r#"[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"lxdbr0"}},{"accept":null}]"#,
            ),
            chain_json("inet", "filter", "input", "input"),
            chain_json("inet", "my table", "in.put", "input"),
        ])),
    );
    assert_eq!(
        detect(&ctx).unwrap(),
        [Location::Nft(nft_chain("inet", "filter", "input"))]
    );
    let listed = ruleset(&[
        policy_chain("inet", "lxd", "in.lxdbr0", "input", "drop"),
        chain_json("inet", "filter", "input", "input"),
    ]);
    let scan = nft::parse_ruleset(&serde_json::from_str(&listed).unwrap()).unwrap();
    assert_eq!(scan.native, [nft_chain("inet", "filter", "input")]);
    assert_eq!(scan.skipped, [nft_chain("inet", "lxd", "in.lxdbr0")]);
    assert_eq!(
        nft::skipped_notice(&scan.skipped[0]),
        "nft 链 inet lxd in.lxdbr0 名称无法安全管理，已跳过；该链会拦截未放行的流量，Onebox 端口可能无法访问，请手动放行"
    );
}

#[test]
fn detection_prefers_active_ufw() {
    let (_dir, ctx, exec) = setup();
    exec.provide("ufw").provide("firewall-cmd").provide("nft");
    exec.on("ufw", &["status"], Output::success("Status: active\n"));
    assert_eq!(detect(&ctx).unwrap(), [Location::Ufw(Ufw)]);
    assert_eq!(exec.history(), ["ufw status"]);
}

#[test]
fn detection_uses_every_active_firewalld_zone() {
    let (_dir, ctx, exec) = setup();
    exec.provide("ufw").provide("firewall-cmd");
    exec.on("ufw", &["status"], Output::success("Status: inactive\n"))
        .on("firewall-cmd", &["--state"], Output::success("running\n"))
        .on(
            "firewall-cmd",
            &["--get-active-zones"],
            Output::success(
                "public (default)\n  interfaces: eth0\ntrusted\n  sources: 10.0.0.0/8\n",
            ),
        );
    let zone = |zone: &str, permanent| {
        Location::Firewalld(Firewalld {
            zone: zone.into(),
            permanent,
        })
    };
    assert_eq!(
        detect(&ctx).unwrap(),
        [
            zone("public", false),
            zone("public", true),
            zone("trusted", false),
            zone("trusted", true)
        ]
    );
}

#[test]
fn firewalld_without_active_zones_uses_the_default_zone() {
    let (_dir, ctx, exec) = setup();
    exec.provide("firewall-cmd");
    exec.on("firewall-cmd", &["--state"], Output::success("running\n"))
        .on("firewall-cmd", &["--get-active-zones"], Output::success(""))
        .on(
            "firewall-cmd",
            &["--get-default-zone"],
            Output::success("drop\n"),
        );
    assert_eq!(detect(&ctx).unwrap().len(), 2);
    let (_dir, ctx, exec) = setup();
    exec.provide("firewall-cmd");
    exec.on("firewall-cmd", &["--state"], Output::success("running\n"))
        .on(
            "firewall-cmd",
            &["--get-active-zones"],
            Output::success("bad;zone\n"),
        );
    assert_eq!(detect(&ctx).unwrap_err().to_string(), "firewalld zone 无效");
}

#[test]
fn stopped_firewalld_falls_through() {
    let (_dir, ctx, exec) = setup();
    exec.provide("firewall-cmd").provide("iptables");
    exec.on(
        "firewall-cmd",
        &["--state"],
        Output::failure(252, "not running"),
    )
    .on(
        "iptables",
        &["-w", "5", "-S", "INPUT"],
        Output::success("-P INPUT ACCEPT\n"),
    );
    assert_eq!(
        detect(&ctx).unwrap(),
        [Location::Iptables(Iptables { v6: false })]
    );
}

#[test]
fn native_nft_chains_with_iptables_nft_compat_tables() {
    let (_dir, ctx, exec) = setup();
    enable_ipv6(&ctx);
    exec.provide("nft").provide("iptables").provide("ip6tables");
    exec.on(
        "nft",
        &["-j", "list", "ruleset"],
        Output::success(ruleset(&[
            chain_json("inet", "filter", "input", "input"),
            chain_json("ip", "filter", "INPUT", "input"),
        ])),
    )
    .on(
        "iptables",
        &["-w", "5", "-S", "INPUT"],
        Output::success("-P INPUT ACCEPT\n"),
    );
    assert_eq!(
        detect(&ctx).unwrap(),
        [
            Location::Nft(Nft {
                family: "inet".into(),
                table: "filter".into(),
                chain: "input".into()
            }),
            Location::Iptables(Iptables { v6: false }),
        ],
        "ip6 has no compat chain, so ip6tables is not involved"
    );
}

#[test]
fn compat_only_hosts_use_iptables_and_ipv6_needs_proc_support() {
    let (_dir, ctx, exec) = setup();
    exec.provide("nft").provide("iptables").provide("ip6tables");
    exec.on(
        "nft",
        &["-j", "list", "ruleset"],
        Output::success(ruleset(&[
            chain_json("ip", "filter", "INPUT", "input"),
            chain_json("ip6", "filter", "INPUT", "input"),
        ])),
    )
    .on("iptables", &["-w", "5", "-S"], Output::success(""))
    .on("ip6tables", &["-w", "5", "-S"], Output::success(""));
    assert_eq!(
        detect(&ctx).unwrap(),
        [Location::Iptables(Iptables { v6: false })],
        "IPv6 disabled in the fixture"
    );
    enable_ipv6(&ctx);
    assert_eq!(detect(&ctx).unwrap().len(), 2);
    let disable = ctx.paths.system("/proc/sys/net/ipv6/conf/all/disable_ipv6");
    std::fs::create_dir_all(disable.parent().unwrap()).unwrap();
    std::fs::write(&disable, "1\n").unwrap();
    assert!(!crate::sys::net::ipv6_available(&ctx.paths.system_root));
}

#[test]
fn unusable_nft_falls_back_to_iptables_and_probe_failures_are_errors() {
    let (_dir, ctx, exec) = setup();
    exec.provide("nft").provide("iptables");
    exec.on("nft", &[], Output::failure(1, "Operation not supported"))
        .on(
            "iptables",
            &["-w", "5", "-S"],
            Output::failure(4, "can't initialize"),
        );
    let err = detect(&ctx).unwrap_err().to_string();
    assert_eq!(err, "iptables 执行失败 (4): can't initialize");
    let (_dir, ctx, _exec) = setup();
    assert!(detect(&ctx).unwrap().is_empty(), "no firewall at all");
}

#[test]
fn location_descriptions() {
    let zone = Location::Firewalld(Firewalld {
        zone: "public".into(),
        permanent: true,
    });
    assert_eq!(zone.describe(), "firewalld public（永久）");
    assert_eq!(zone.backend().program(), "firewall-cmd");
    let runtime = Location::Firewalld(Firewalld {
        zone: "public".into(),
        permanent: false,
    });
    assert_eq!(runtime.describe(), "firewalld public（运行时）");
    assert_eq!(
        Location::Iptables(Iptables { v6: true }).describe(),
        "ip6tables"
    );
    assert_eq!(Location::Ufw(Ufw).describe(), "ufw");
}
