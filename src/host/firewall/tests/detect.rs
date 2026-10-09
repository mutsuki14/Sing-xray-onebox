//! Backend detection: nft ruleset classification, firewalld zones, ufw
//! state and the iptables fallback.

use super::*;

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
    assert_eq!(
        scan.filter_input,
        [
            nft::FilterInput {
                chain: nft_chain("ip", "filter", "INPUT"),
                blocks: true
            },
            nft::FilterInput {
                chain: nft_chain("ip6", "filter", "INPUT"),
                blocks: true
            },
        ],
        "iptables decides who owns `filter INPUT` (see detect)"
    );
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
    assert!(scan.filter_input.is_empty() && scan.native.is_empty());
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
    .on("iptables", &["-V"], Output::success(IPTABLES_NFT))
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
    .on("iptables", &["-V"], Output::success(IPTABLES_NFT))
    .on(
        "ip6tables",
        &["-V"],
        Output::success("ip6tables v1.8.10 (nf_tables)\n"),
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

const IPTABLES_NFT: &str = "iptables v1.8.10 (nf_tables)\n";
const IPTABLES_LEGACY: &str = "iptables v1.8.10 (legacy)\n";
/// What iptables-nft 1.8.10 prints for a chain holding native nft
/// expressions (exit 1).
const INCOMPATIBLE: &str =
    "iptables v1.8.10 (nf_tables): chain `INPUT' in table `filter' is incompatible, use 'nft' tool.";

/// `nft -j list ruleset` after `nft -f` of what `iptables-restore-translate`
/// (iptables 1.8.10) makes of a policy-DROP rules.v4: `ct state` is a
/// native expression iptables-nft cannot list.
const TRANSLATED: &str = r#"{"nftables": [{"metainfo": {"version": "1.0.9", "release_name": "Old Doc Yak #3", "json_schema_version": 1}}, {"table": {"family": "ip", "name": "filter", "handle": 1}}, {"chain": {"family": "ip", "table": "filter", "name": "INPUT", "handle": 1, "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}}, {"chain": {"family": "ip", "table": "filter", "name": "FORWARD", "handle": 2, "type": "filter", "hook": "forward", "prio": 0, "policy": "accept"}}, {"chain": {"family": "ip", "table": "filter", "name": "OUTPUT", "handle": 3, "type": "filter", "hook": "output", "prio": 0, "policy": "accept"}}, {"rule": {"family": "ip", "table": "filter", "chain": "INPUT", "handle": 4, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "lo"}}, {"counter": {"packets": 0, "bytes": 0}}, {"accept": null}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "INPUT", "handle": 5, "expr": [{"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": ["established", "related"]}}, {"counter": {"packets": 0, "bytes": 0}}, {"accept": null}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "INPUT", "handle": 6, "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 22}}, {"counter": {"packets": 0, "bytes": 0}}, {"accept": null}]}}]}"#;

#[test]
fn filter_input_belongs_to_iptables_only_when_iptables_nft_lists_it() {
    let translated_accept = ruleset(&[
        policy_chain("ip", "filter", "INPUT", "input", "accept"),
        rule_json(
            "ip",
            "filter",
            "INPUT",
            r#"[{"match":{"op":"in","left":{"ct":{"key":"state"}},"right":"invalid"}},{"drop":null}]"#,
        ),
    ]);
    let with_inet = ruleset(&[
        chain_json("inet", "filter", "input", "input"),
        chain_json("ip", "filter", "INPUT", "input"),
    ]);
    let native = || Location::Nft(nft_chain("ip", "filter", "INPUT"));
    let v4 = || Location::Iptables(Iptables { v6: false });
    // (case, ruleset, `iptables -V` (None: no binary), `-S INPUT` result, locations)
    type Case<'a> = (&'a str, &'a str, Option<&'a str>, Output, Vec<Location>);
    let cases: [Case; 7] = [
        (
            "translated policy drop, iptables-nft refuses it",
            TRANSLATED,
            Some(IPTABLES_NFT),
            Output::failure(1, INCOMPATIBLE),
            vec![native()],
        ),
        (
            "translated policy drop beside iptables-legacy",
            TRANSLATED,
            Some(IPTABLES_LEGACY),
            Output::success("-P INPUT ACCEPT\n"),
            vec![native()],
        ),
        (
            "translated policy drop without iptables",
            TRANSLATED,
            None,
            Output::failure(127, "unused"),
            vec![native()],
        ),
        (
            "iptables-nft's own chain",
            &ruleset(&[chain_json("ip", "filter", "INPUT", "input")]),
            Some(IPTABLES_NFT),
            Output::success("-P INPUT DROP\n"),
            vec![v4()],
        ),
        (
            "native accept-policy chain iptables-nft refuses: nothing to open",
            &translated_accept,
            Some(IPTABLES_NFT),
            Output::failure(1, INCOMPATIBLE),
            vec![],
        ),
        (
            "native accept-policy chain beside iptables-legacy keeps the legacy rules",
            &translated_accept,
            Some(IPTABLES_LEGACY),
            Output::success("-P INPUT DROP\n"),
            vec![v4()],
        ),
        (
            "both native chains get nft rules",
            &with_inet,
            Some(IPTABLES_NFT),
            Output::failure(1, INCOMPATIBLE),
            vec![
                Location::Nft(nft_chain("inet", "filter", "input")),
                native(),
            ],
        ),
    ];
    for (case, listed, version, list, expected) in cases {
        let (_dir, ctx, exec) = setup();
        exec.provide("nft");
        exec.on("nft", &["-j", "list", "ruleset"], Output::success(listed));
        if let Some(version) = version {
            exec.provide("iptables");
            exec.on("iptables", &["-V"], Output::success(version)).on(
                "iptables",
                &["-w", "5", "-S", "INPUT"],
                list,
            );
        }
        assert_eq!(detect(&ctx).unwrap(), expected, "{case}");
    }
}

#[test]
fn translated_ruleset_is_managed_with_nft_rules() {
    let (_dir, ctx, exec) = setup();
    exec.provide("nft").provide("iptables");
    exec.on(
        "nft",
        &["-j", "list", "ruleset"],
        Output::success(TRANSLATED),
    )
    .on("iptables", &["-V"], Output::success(IPTABLES_NFT))
    .on(
        "iptables",
        &["-w", "5", "-S", "INPUT"],
        Output::failure(1, INCOMPATIBLE),
    )
    .on("nft", &["-j", "list", "chain"], Output::success(TRANSLATED))
    .on("nft", &["insert", "rule"], Output::success(""));
    let report = reconcile_owner(&ctx, "proxy", &[(443, 443, Transport::Tcp)]).unwrap();
    assert_eq!(report.created, ["nft ip filter INPUT 443/tcp"]);
    let inserted = exec
        .history()
        .into_iter()
        .filter(|line| line.starts_with("nft insert rule"))
        .collect::<Vec<_>>();
    assert_eq!(inserted.len(), 1);
    assert!(
        inserted[0].starts_with("nft insert rule ip filter INPUT tcp dport 443 accept comment"),
        "{inserted:?}"
    );
    assert!(
        !exec.history().iter().any(|line| line.contains("-I INPUT")),
        "iptables-nft cannot edit the translated chain"
    );
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
