use super::*;
use crate::sys::exec::{FakeExec, Output};
use crate::sys::fs::TempDir;
use std::sync::{Arc, Mutex};

fn range(start: u16, end: u16) -> PortRange {
    PortRange { start, end }
}

fn setup() -> (TempDir, Ctx, Arc<FakeExec>) {
    let dir = TempDir::new("hop").unwrap();
    let (ctx, exec, _) = Ctx::test(dir.path());
    std::fs::create_dir_all(&ctx.paths.root).unwrap();
    (dir, ctx, exec)
}

fn enable_ipv6(ctx: &Ctx) {
    let inet6 = ctx.paths.system("/proc/net/if_inet6");
    std::fs::create_dir_all(inet6.parent().unwrap()).unwrap();
    std::fs::write(inet6, "").unwrap();
}

/// Capture the scripts handed to `nft -f` (read while the file exists).
fn capture_nft(exec: &FakeExec, code: i32) -> Arc<Mutex<Vec<String>>> {
    let scripts = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&scripts);
    exec.on_fn(
        |c| c.program == "nft" && c.args.first().is_some_and(|a| a == "-f"),
        move |c| {
            let text = std::fs::read_to_string(&c.args[1]).unwrap();
            seen.lock().unwrap().push(text);
            Ok(if code == 0 {
                Output::success("")
            } else {
                Output::failure(
                    code,
                    "Error: Could not process rule: No such file or directory",
                )
            })
        },
    );
    scripts
}

fn tables_json(token: &str, families: &[&str]) -> String {
    let rows: Vec<String> = families
        .iter()
        .map(|f| format!(r#"{{"table":{{"family":"{f}","name":"{token}","handle":3}}}}"#))
        .collect();
    format!(
        r#"{{"nftables":[{{"metainfo":{{}}}},{{"table":{{"family":"inet","name":"filter","handle":1}}}},{}]}}"#,
        rows.join(",")
    )
}

#[test]
fn ranges_must_be_ascending_and_unprivileged() {
    let (_dir, ctx, exec) = setup();
    for (r, target) in [
        (range(1023, 2000), 443),
        (range(20000, 20000), 443),
        (range(30000, 20000), 443),
        (range(20000, 30000), 0),
    ] {
        assert_eq!(
            apply(&ctx, r, target).unwrap_err().to_string(),
            "跳跃范围必须为1024以上递增端口"
        );
    }
    assert!(exec.history().is_empty());
}

#[test]
fn nft_script_is_valid_multi_line_syntax() {
    assert_eq!(
        nft_script(&["ip", "ip6"], "onebox_hop_0011223344556677", range(20000, 40000), 443),
        "table ip onebox_hop_0011223344556677 {\n\tchain prerouting {\n\t\ttype nat hook prerouting priority -100; policy accept;\n\t\tfib daddr type local udp dport 20000-40000 redirect to :443\n\t}\n}\n\
table ip6 onebox_hop_0011223344556677 {\n\tchain prerouting {\n\t\ttype nat hook prerouting priority -100; policy accept;\n\t\tfib daddr type local udp dport 20000-40000 redirect to :443\n\t}\n}\n"
    );
}

#[test]
fn nft_tables_are_installed_and_recorded() {
    let (_dir, ctx, exec) = setup();
    enable_ipv6(&ctx);
    exec.provide("nft");
    let scripts = capture_nft(&exec, 0);
    apply(&ctx, range(20000, 40000), 8443).unwrap();
    let hops = recorded(&ctx).unwrap();
    assert_eq!(hops.len(), 1);
    let hop = &hops[0];
    assert_eq!(
        (hop.backend.as_str(), hop.start, hop.end, hop.target),
        ("nft", 20000, 40000, 8443)
    );
    let hex = hop.token.strip_prefix("onebox_hop_").unwrap();
    assert_eq!(hex.len(), 16);
    let scripts = scripts.lock().unwrap();
    assert_eq!(
        scripts[0],
        nft_script(&["ip", "ip6"], &hop.token, range(20000, 40000), 8443)
    );
    let ledger = std::fs::read_to_string(ledger_path(&ctx)).unwrap();
    assert_eq!(
        ledger,
        format!(
            r#"[{{"backend":"nft","start":20000,"end":40000,"target":8443,"token":"{}"}}]"#,
            hop.token
        )
    );
    let leftovers: Vec<_> = std::fs::read_dir(&ctx.paths.root)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.starts_with(crate::sys::fs::TEMP_PREFIX))
        .collect();
    assert!(leftovers.is_empty(), "script file removed: {leftovers:?}");
}

#[test]
fn applying_again_replaces_the_previous_tables() {
    let (_dir, ctx, exec) = setup();
    exec.provide("nft");
    capture_nft(&exec, 0);
    std::fs::write(
        ledger_path(&ctx),
        r#"[{"backend":"nft","start":20000,"end":30000,"target":443,"token":"onebox_hop_aaaaaaaaaaaaaaaa"}]"#,
    )
    .unwrap();
    exec.on(
        "nft",
        &["-j", "list", "tables"],
        Output::success(tables_json("onebox_hop_aaaaaaaaaaaaaaaa", &["ip", "ip6"])),
    )
    .on("nft", &["delete", "table"], Output::success(""));
    apply(&ctx, range(30000, 31000), 443).unwrap();
    let history = exec.history();
    assert!(history[0].starts_with("nft -f "), "new table first");
    assert_eq!(
        history[1..],
        [
            "nft -j list tables",
            "nft delete table ip onebox_hop_aaaaaaaaaaaaaaaa",
            "nft delete table ip6 onebox_hop_aaaaaaaaaaaaaaaa",
        ]
    );
    let hops = recorded(&ctx).unwrap();
    assert_eq!(hops.len(), 1);
    assert_eq!(hops[0].start, 30000);
}

#[test]
fn a_failed_change_keeps_the_working_hopping() {
    let (_dir, ctx, exec) = setup();
    exec.provide("nft");
    capture_nft(&exec, 1);
    let previous = r#"[{"backend":"nft","start":20000,"end":30000,"target":443,"token":"onebox_hop_aaaaaaaaaaaaaaaa"}]"#;
    std::fs::write(ledger_path(&ctx), previous).unwrap();
    assert!(apply(&ctx, range(30000, 31000), 443).is_err());
    assert_eq!(
        std::fs::read_to_string(ledger_path(&ctx)).unwrap(),
        previous
    );
    assert!(exec.history().iter().all(|c| !c.contains("delete")));
}

#[test]
fn a_partial_iptables_install_is_undone() {
    let (_dir, ctx, exec) = setup();
    enable_ipv6(&ctx);
    exec.provide("iptables").provide("ip6tables");
    exec.on("iptables", &[], Output::success("")).on(
        "ip6tables",
        &[],
        Output::failure(3, "can't initialize ip6tables table `nat'"),
    );
    let err = apply(&ctx, range(20000, 21000), 443)
        .unwrap_err()
        .to_string();
    assert!(err.starts_with("ip6tables 执行失败 (3)"), "{err}");
    let history = exec.history();
    assert!(
        history[2].starts_with("iptables -w 5 -t nat -C PREROUTING"),
        "{history:?}"
    );
    assert!(
        history[3].starts_with("iptables -w 5 -t nat -D PREROUTING"),
        "{history:?}"
    );
    assert!(recorded(&ctx).unwrap().is_empty());
}

#[test]
fn old_rules_that_cannot_be_retired_stay_recorded() {
    let (_dir, ctx, exec) = setup();
    exec.provide("iptables");
    let old = r#"[{"backend":"iptables","start":20000,"end":30000,"target":443,"token":"onebox-hop-1111111111111111"}]"#;
    std::fs::write(ledger_path(&ctx), old).unwrap();
    exec.on(
        "iptables",
        &["-w", "5", "-t", "nat", "-A"],
        Output::success(""),
    )
    .on("iptables", &[], Output::failure(4, "resource problem"));
    apply(&ctx, range(30001, 31000), 443).unwrap();
    let hops = recorded(&ctx).unwrap();
    assert_eq!(hops.len(), 2, "old and new both recorded");
    assert_eq!(hops[0].token, "onebox-hop-1111111111111111");
    assert_eq!(hops[1].start, 30001);
    // The next change retries the leftover (and replaces the current hop).
    exec.clear_history();
    apply(&ctx, range(30001, 31000), 443).unwrap();
    let retried = exec
        .history()
        .iter()
        .filter(|c| c.contains(" -C ") && c.contains("onebox-hop-1111111111111111"))
        .count();
    assert_eq!(retried, 1);
    assert_eq!(recorded(&ctx).unwrap().len(), 3);
}

#[test]
fn a_leftover_that_redirects_new_ports_elsewhere_fails_the_change() {
    let (_dir, ctx, exec) = setup();
    exec.provide("iptables");
    let old = r#"[{"backend":"iptables","start":20000,"end":30000,"target":8443,"token":"onebox-hop-1111111111111111"}]"#;
    std::fs::write(ledger_path(&ctx), old).unwrap();
    exec.on(
        "iptables",
        &["-w", "5", "-t", "nat", "-A"],
        Output::success(""),
    )
    .on("iptables", &[], Output::failure(4, "resource problem"));
    let err = apply(&ctx, range(25000, 31000), 443)
        .unwrap_err()
        .to_string();
    assert!(
        err.starts_with("新的端口跳跃规则已生效，但与其冲突的旧规则清理失败（已保留记录）: iptables 20000-30000/udp → 8443: 无法读取跳跃规则: resource problem"),
        "{err}"
    );
    assert_eq!(recorded(&ctx).unwrap().len(), 2, "both kept for recover");
}

#[test]
fn a_broken_nft_does_not_block_changes_or_clearing() {
    let (_dir, ctx, exec) = setup();
    exec.provide("nft").provide("iptables");
    // nf_tables is gone from the running kernel: nft cannot list or load.
    exec.on(
        "nft",
        &[],
        Output::failure(1, "Error: Could not process rule: Operation not supported"),
    )
    .on("iptables", &[], Output::success(""));
    let old = r#"[{"backend":"nft","start":20000,"end":30000,"target":443,"token":"onebox_hop_aaaaaaaaaaaaaaaa"}]"#;
    std::fs::write(ledger_path(&ctx), old).unwrap();
    apply(&ctx, range(20000, 30000), 443).unwrap();
    let hops = recorded(&ctx).unwrap();
    assert_eq!(
        hops.iter().map(|h| h.backend.as_str()).collect::<Vec<_>>(),
        ["nft", "iptables"],
        "the leftover redirects to the same port: kept and retried later"
    );
    let report = clear(&ctx).unwrap();
    assert_eq!(report.removed, ["iptables 20000-30000/udp → 443"]);
    assert_eq!(report.failed.len(), 1);
    assert!(
        report.failed[0].starts_with("nft 20000-30000/udp → 443: nft 执行失败 (1)"),
        "{report:?}"
    );
    let left = recorded(&ctx).unwrap();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].backend, "nft");
}

#[test]
fn iptables_redirects_per_binary_when_nft_is_missing() {
    let (_dir, ctx, exec) = setup();
    enable_ipv6(&ctx);
    exec.provide("iptables").provide("ip6tables");
    exec.on("iptables", &[], Output::success(""))
        .on("ip6tables", &[], Output::success(""));
    apply(&ctx, range(20000, 40000), 443).unwrap();
    let hops = recorded(&ctx).unwrap();
    assert_eq!(hops.len(), 2);
    assert_ne!(hops[0].token, hops[1].token, "one token per binary");
    let rule = |bin: &str, op: &str, token: &str| {
        format!("{bin} -w 5 -t nat {op} PREROUTING -p udp --dport 20000:40000 -m addrtype --dst-type LOCAL -m comment --comment {token} -j REDIRECT --to-ports 443")
    };
    assert_eq!(
        exec.history(),
        [
            rule("iptables", "-A", &hops[0].token),
            rule("ip6tables", "-A", &hops[1].token)
        ]
    );
    assert!(hops.iter().all(|h| h.token.starts_with("onebox-hop-")));
    exec.clear_history();
    clear(&ctx).unwrap();
    assert_eq!(
        exec.history(),
        [
            rule("iptables", "-C", &hops[0].token),
            rule("iptables", "-D", &hops[0].token),
            rule("ip6tables", "-C", &hops[1].token),
            rule("ip6tables", "-D", &hops[1].token),
        ]
    );
    assert_eq!(std::fs::read_to_string(ledger_path(&ctx)).unwrap(), "[]");
}

#[test]
fn unusable_nft_falls_back_to_iptables() {
    let (_dir, ctx, exec) = setup();
    exec.provide("nft").provide("iptables");
    capture_nft(&exec, 1);
    exec.on("iptables", &[], Output::success(""));
    apply(&ctx, range(20000, 21000), 443).unwrap();
    let hops = recorded(&ctx).unwrap();
    assert_eq!(hops.len(), 1);
    assert_eq!(hops[0].backend, "iptables");

    let (_dir, ctx, exec) = setup();
    exec.provide("nft");
    capture_nft(&exec, 1);
    let err = apply(&ctx, range(20000, 21000), 443)
        .unwrap_err()
        .to_string();
    assert!(err.starts_with("nft 执行失败 (1)"), "{err}");
    assert!(recorded(&ctx).unwrap().is_empty());
}

#[test]
fn an_unrecordable_nft_table_is_removed_and_not_retried_with_iptables() {
    let (_dir, ctx, exec) = setup();
    exec.provide("nft").provide("iptables");
    let ledger = ledger_path(&ctx);
    let token = Arc::new(Mutex::new(String::new()));
    let seen = Arc::clone(&token);
    exec.on_fn(
        |c| c.program == "nft" && c.args.first().is_some_and(|a| a == "-f"),
        move |c| {
            let script = std::fs::read_to_string(&c.args[1]).unwrap();
            let name = script.split_whitespace().nth(2).unwrap().to_string();
            *seen.lock().unwrap() = name;
            // The ledger cannot be written any more.
            std::fs::create_dir_all(&ledger).unwrap();
            Ok(Output::success(""))
        },
    );
    let listing = Arc::clone(&token);
    exec.on_fn(
        |c| c.program == "nft" && c.args.starts_with(&["-j".into(), "list".into()]),
        move |_| {
            Ok(Output::success(tables_json(
                &listing.lock().unwrap(),
                &["ip"],
            )))
        },
    )
    .on("nft", &["delete", "table"], Output::success(""));
    assert!(apply(&ctx, range(20000, 21000), 443).is_err());
    let history = exec.history();
    assert_eq!(
        history.last().unwrap(),
        &format!("nft delete table ip {}", token.lock().unwrap())
    );
    assert!(history.iter().all(|c| !c.starts_with("iptables")));
}

#[test]
fn hopping_needs_some_backend() {
    let (_dir, ctx, _exec) = setup();
    assert_eq!(
        apply(&ctx, range(20000, 21000), 443)
            .unwrap_err()
            .to_string(),
        "端口跳跃需要 nft 或 iptables/ip6tables"
    );
}

#[test]
fn clear_attempts_every_hop_and_keeps_only_failures() {
    let (_dir, ctx, exec) = setup();
    exec.provide("iptables").provide("ip6tables");
    let v2 = r#"[{"backend":"iptables","start":20000,"end":40000,"target":443,"token":"onebox-hop-1111111111111111"},{"backend":"ip6tables","start":20000,"end":40000,"target":443,"token":"onebox-hop-2222222222222222"}]"#;
    std::fs::write(ledger_path(&ctx), v2).unwrap();
    exec.on("iptables", &[], Output::failure(3, "table nat missing"))
        .on("ip6tables", &[], Output::success(""));
    let report = clear(&ctx).unwrap();
    assert_eq!(report.removed, ["ip6tables 20000-40000/udp → 443"]);
    assert_eq!(
        report.failed,
        ["iptables 20000-40000/udp → 443: 无法读取跳跃规则: table nat missing"]
    );
    assert_eq!(
        std::fs::read_to_string(ledger_path(&ctx)).unwrap(),
        r#"[{"backend":"iptables","start":20000,"end":40000,"target":443,"token":"onebox-hop-1111111111111111"}]"#
    );
}

#[test]
fn absent_rules_and_vanished_programs_count_as_removed() {
    let (_dir, ctx, exec) = setup();
    exec.provide("iptables");
    std::fs::write(
        ledger_path(&ctx),
        r#"[{"backend":"iptables","start":20000,"end":40000,"target":443,"token":"onebox-hop-1111111111111111"},{"backend":"ip6tables","start":20000,"end":40000,"target":443,"token":"onebox-hop-2222222222222222"},{"backend":"nft","start":20000,"end":40000,"target":443,"token":"onebox_hop_3333333333333333"}]"#,
    )
    .unwrap();
    exec.on("iptables", &[], Output::failure(1, "Bad rule"));
    clear(&ctx).unwrap();
    assert_eq!(exec.history().len(), 1, "only the iptables check ran");
    assert!(recorded(&ctx).unwrap().is_empty());
    clear(&ctx).unwrap();
    std::fs::remove_file(ledger_path(&ctx)).unwrap();
    clear(&ctx).unwrap();
}

#[test]
fn unsafe_records_are_refused() {
    let (_dir, ctx, exec) = setup();
    exec.provide("nft");
    std::fs::write(
        ledger_path(&ctx),
        r#"[{"backend":"nft","start":20000,"end":40000,"target":443,"token":"x; flush ruleset"}]"#,
    )
    .unwrap();
    let err = clear(&ctx).unwrap_err().to_string();
    assert!(err.starts_with("端口跳跃记录无效: "), "{err}");
    assert!(err.ends_with("hop-v2.json: 跳跃表名称无效"), "{err}");
    assert!(
        apply(&ctx, range(20000, 21000), 443).is_err(),
        "refused before installing"
    );
    std::fs::write(
        ledger_path(&ctx),
        r#"[{"backend":"pf","start":20000,"end":40000,"target":443,"token":"t"}]"#,
    )
    .unwrap();
    let err = clear(&ctx).unwrap_err().to_string();
    assert!(err.ends_with(": 未知端口跳跃记录类型"), "{err}");
    assert!(exec.history().is_empty());
}

/// Checks the generated script with the real nft parser (`nft -c`, no
/// changes are made). Needs nft and CAP_NET_ADMIN; run with `--ignored`.
#[test]
#[ignore]
fn real_nft_accepts_the_hop_script() {
    let dir = TempDir::new("hop-real").unwrap();
    let file = dir.join("hop.nft");
    let script = nft_script(
        &["ip", "ip6"],
        "onebox_hop_0011223344556677",
        range(20000, 40000),
        443,
    );
    std::fs::write(&file, script).unwrap();
    let out = std::process::Command::new("nft")
        .arg("-c")
        .arg("-f")
        .arg(&file)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
