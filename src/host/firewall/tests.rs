//! Backend argv golden tests, status and listing parsers, span arithmetic.

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
    .on(
        "firewall-cmd",
        &["--zone=public", "--list-ports"],
        Output::success("80/tcp 20000-40000/udp\n"),
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
            "firewall-cmd --zone=public --list-ports",
            "firewall-cmd --zone=public --remove-port=20000-40000/udp",
            "firewall-cmd --zone=public --list-ports",
        ],
        "443/tcp is not listed: nothing to remove"
    );
}

#[test]
fn firewalld_port_lists_are_parsed() {
    let span = |start, end, proto| PortSpan { start, end, proto };
    assert_eq!(
        firewalld::parse_ports("80/tcp 443/udp 20000-40000/udp http/tcp 9-1/tcp 1/sctp\n"),
        [
            span(80, 80, Proto::Tcp),
            span(443, 443, Proto::Udp),
            span(20000, 40000, Proto::Udp)
        ]
    );
    assert!(firewalld::parse_ports("\n").is_empty());
}

#[test]
fn port_span_set_arithmetic() {
    let span = |start, end| PortSpan {
        start,
        end,
        proto: Proto::Tcp,
    };
    let udp = PortSpan {
        start: 80,
        end: 90,
        proto: Proto::Udp,
    };
    assert!(span(80, 90).contains(&span(85, 90)) && !span(80, 90).contains(&span(85, 91)));
    assert!(span(80, 90).overlaps(&span(90, 95)) && !span(80, 90).overlaps(&span(91, 95)));
    assert!(!span(80, 90).overlaps(&udp) && !span(80, 90).contains(&udp));
    assert_eq!(
        span(80, 90).uncovered(&[span(82, 83), span(70, 80), span(83, 85), udp]),
        [span(81, 81), span(86, 90)]
    );
    assert!(span(80, 81).uncovered(&[span(1, 65535)]).is_empty());
    assert_eq!(
        span(65534, 65535).uncovered(&[span(65534, 65534)]),
        [span(65535, 65535)]
    );
    assert_eq!(span(1, 3).uncovered(&[]), [span(1, 3)]);
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
    assert_eq!(
        zone.remove(&ctx, &r).unwrap_err().to_string(),
        "无法读取 firewalld 端口: FirewallD is not running"
    );
    assert!(exec
        .history()
        .iter()
        .all(|c| c.contains("--query-port") || c.contains("--list-ports")));
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
            to: "443/tcp".into(),
            to_interface: None,
            action: "ALLOW",
            direction: Some("IN"),
            from: "Anywhere".into(),
            from_interface: None,
            attributes: vec![],
            comment: Some("onebox-proxy-01"),
        })
    );
    let limited =
        ufw::parse_line("[ 3] 22/tcp                     LIMIT IN    203.0.113.0/24").unwrap();
    assert_eq!(
        (limited.action, limited.from.as_str(), limited.comment),
        ("LIMIT", "203.0.113.0/24", None)
    );
    let old_ufw = ufw::parse_line("[ 1] 443/tcp                    ALLOW       Anywhere").unwrap();
    assert_eq!((old_ufw.action, old_ufw.direction), ("ALLOW", None));
    assert!(old_ufw.plain_inbound("443/tcp"));
    for junk in [
        "Status: active",
        "",
        "     To   Action   From",
        "[x] 1/tcp ALLOW IN Anywhere",
        "[ 1] 443/tcp",
    ] {
        assert_eq!(ufw::parse_line(junk), None, "{junk:?}");
    }
}

#[test]
fn ufw_direction_interface_and_attribute_columns() {
    let route = ufw::parse_line("[ 1] 443/tcp                    ALLOW FWD   Anywhere").unwrap();
    assert_eq!((route.action, route.direction), ("ALLOW", Some("FWD")));
    let scoped = ufw::parse_line("[ 2] 443/tcp on eth0            ALLOW IN    Anywhere").unwrap();
    assert_eq!(
        (scoped.to.as_str(), scoped.to_interface, scoped.action),
        ("443/tcp", Some("eth0"), "ALLOW")
    );
    let scoped6 =
        ufw::parse_line("[ 3] 443/tcp (v6) on eth0       ALLOW IN    Anywhere (v6)").unwrap();
    assert_eq!(scoped6.to_interface, Some("eth0"));
    let out = ufw::parse_line(
        "[ 4] 443/tcp                    ALLOW OUT   Anywhere                   (out)",
    )
    .unwrap();
    assert_eq!(
        (out.direction, out.from.as_str(), out.attributes.clone()),
        (Some("OUT"), "Anywhere", vec!["out"])
    );
    let routed = ufw::parse_line(
        "[ 5] 443/tcp on eth1            ALLOW FWD   Anywhere on eth0           (out, log)",
    )
    .unwrap();
    assert_eq!(
        (routed.from_interface, routed.attributes.clone()),
        (Some("eth0"), vec!["out", "log"])
    );
    let host = ufw::parse_line("[ 6] 10.0.0.1 443/tcp           ALLOW IN    Anywhere").unwrap();
    assert_eq!(host.to, "10.0.0.1 443/tcp");
    let logged = ufw::parse_line(
        "[ 7] 443/tcp                    ALLOW IN    Anywhere                   (log)",
    )
    .unwrap();
    for (listed, plain) in [
        (&route, false),
        (&scoped, false),
        (&scoped6, false),
        (&out, false),
        (&routed, false),
        (&host, false),
        (&logged, true),
    ] {
        assert_eq!(listed.plain_inbound("443/tcp"), plain, "{listed:?}");
    }
}

#[test]
fn ufw_route_out_and_interface_rules_do_not_hold_our_port() {
    let (_dir, ctx, exec) = setup();
    let status = "Status: active\n\
[ 1] 443/tcp                    ALLOW FWD   Anywhere\n\
[ 2] 8443/tcp on eth0           ALLOW IN    Anywhere\n\
[ 3] 9443/tcp                   ALLOW OUT   Anywhere                   (out)\n\
[ 4] 2053/tcp                   DENY IN     Anywhere                   (log)\n";
    exec.on("ufw", &["status", "numbered"], Output::success(status))
        .on("ufw", &["allow"], Output::success("Rule added\n"));
    for port in [443, 8443, 9443] {
        assert!(
            Ufw.create(&ctx, &rule(Proto::Tcp, port, port)).unwrap(),
            "{port}: a distinct rule for ufw"
        );
    }
    assert!(
        !Ufw.create(&ctx, &rule(Proto::Tcp, 2053, 2053)).unwrap(),
        "a logged admin deny is the same rule"
    );
    let allows = exec
        .history()
        .into_iter()
        .filter(|c| c.contains("allow"))
        .count();
    assert_eq!(allows, 3);
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

mod detect;
