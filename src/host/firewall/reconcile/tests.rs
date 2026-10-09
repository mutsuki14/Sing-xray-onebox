//! Reconcile scenarios against a simulated iptables (FakeExec).

use super::*;
use crate::host::firewall::{Iptables, Proto, Ufw};
use crate::sys::exec::{Cmd, FakeExec, Output};
use crate::sys::fs::TempDir;
use std::sync::{Arc, Mutex, MutexGuard};

/// A tiny iptables/ip6tables model: rule specs per binary, in chain order.
#[derive(Default)]
struct Sim {
    v4: Vec<String>,
    v6: Vec<String>,
    /// `-D` of a spec containing this text fails with code 7.
    fail_delete: Option<String>,
    /// Ledger path replaced by a directory when a rule is inserted, so the
    /// following ledger save fails.
    sabotage_ledger: Option<std::path::PathBuf>,
}

struct Fixture {
    _dir: TempDir,
    ctx: Ctx,
    exec: Arc<FakeExec>,
    sim: Arc<Mutex<Sim>>,
}

impl Fixture {
    fn new() -> Fixture {
        let dir = TempDir::new("reconcile").unwrap();
        let (ctx, exec, _) = Ctx::test(dir.path());
        let sim = Arc::new(Mutex::new(Sim::default()));
        exec.provide("iptables");
        let model = Arc::clone(&sim);
        exec.on_fn(
            |c| matches!(c.program.as_str(), "iptables" | "ip6tables"),
            move |c| Ok(simulate(&mut model.lock().unwrap(), c)),
        );
        Fixture {
            _dir: dir,
            ctx,
            exec,
            sim,
        }
    }

    fn sim(&self) -> MutexGuard<'_, Sim> {
        self.sim.lock().unwrap()
    }

    fn ledger(&self) -> Ledger {
        Ledger::load(&ledger_path(&self.ctx.paths, "proxy"), "proxy").unwrap()
    }

    fn reconcile(&self, desired: &[(u16, u16, Transport)]) -> Result<Report> {
        reconcile_owner(&self.ctx, "proxy", desired)
    }

    fn commands(&self, op: &str) -> Vec<String> {
        self.exec
            .history()
            .into_iter()
            .filter(|c| c.contains(&format!(" {op} ")))
            .collect()
    }
}

fn simulate(sim: &mut Sim, c: &Cmd) -> Output {
    let args = &c.args;
    let op = args.get(2).map(String::as_str).unwrap_or_default();
    if op == "-S" {
        return Output::success("-P INPUT ACCEPT\n");
    }
    let skip = if op == "-I" { 5 } else { 4 };
    let spec = args[skip..].join(" ");
    let fail_delete = sim.fail_delete.clone();
    let sabotage = sim.sabotage_ledger.take();
    let rules = if c.program == "iptables" {
        &mut sim.v4
    } else {
        &mut sim.v6
    };
    match op {
        "-I" => {
            rules.insert(0, spec);
            if let Some(path) = sabotage {
                let _ = std::fs::remove_file(&path);
                std::fs::create_dir_all(path).unwrap();
            }
            Output::success("")
        }
        "-C" if rules.contains(&spec) => Output::success(""),
        "-C" => Output::failure(1, "Bad rule"),
        "-D" if fail_delete.is_some_and(|f| spec.contains(&f)) => Output::failure(7, "busy"),
        "-D" => match rules.iter().position(|r| *r == spec) {
            Some(i) => {
                rules.remove(i);
                Output::success("")
            }
            None => Output::failure(1, "Bad rule"),
        },
        _ => Output::failure(2, "unsupported"),
    }
}

fn spec(proto: &str, port: &str, token: &str) -> String {
    format!("-p {proto} --dport {port} -m comment --comment {token} -j ACCEPT")
}

const TCP: Transport = Transport::Tcp;
const UDP: Transport = Transport::Udp;

#[test]
fn creates_merged_rules_and_records_each() {
    let f = Fixture::new();
    let report = f
        .reconcile(&[
            (443, 443, TCP),
            (80, 80, TCP),
            (81, 81, TCP),
            (443, 443, UDP),
        ])
        .unwrap();
    assert_eq!(
        report.created,
        ["iptables 80-81/tcp", "iptables 443/tcp", "iptables 443/udp"]
    );
    let ledger = f.ledger();
    let spans: Vec<(u16, u16, Proto)> = ledger
        .entries
        .iter()
        .map(|e| (e.rule.start, e.rule.end, e.rule.proto))
        .collect();
    assert_eq!(
        spans,
        [
            (80, 81, Proto::Tcp),
            (443, 443, Proto::Tcp),
            (443, 443, Proto::Udp)
        ]
    );
    let tokens: Vec<&str> = ledger
        .entries
        .iter()
        .map(|e| e.rule.token.as_str())
        .collect();
    assert!(tokens.iter().all(|t| t.starts_with("onebox-proxy-")));
    assert_eq!(
        f.sim().v4,
        [
            spec("udp", "443", tokens[2]),
            spec("tcp", "443", tokens[1]),
            spec("tcp", "80:81", tokens[0]),
        ],
        "each inserted at position 1"
    );
    assert!(f.sim().v6.is_empty(), "ip6tables absent");
}

#[test]
fn second_run_only_queries_and_recreates_vanished_rules_with_their_token() {
    let f = Fixture::new();
    let desired = [(443, 443, TCP), (8443, 8443, TCP)];
    f.reconcile(&desired).unwrap();
    let before = f.ledger().entries;
    f.exec.clear_history();
    let report = f.reconcile(&desired).unwrap();
    assert_eq!(report, Report::default());
    assert!(f.commands("-I").is_empty() && f.commands("-D").is_empty());
    // An admin flush removes our rules: they come back with the same tokens.
    f.sim().v4.clear();
    let report = f.reconcile(&desired).unwrap();
    assert_eq!(report.created.len(), 2);
    assert_eq!(
        f.ledger().entries,
        before,
        "same tokens, nothing re-recorded"
    );
    assert_eq!(f.sim().v4.len(), 2);
}

#[test]
fn stale_rules_are_removed_by_token_and_admin_rules_stay() {
    let f = Fixture::new();
    f.sim().v4.push("-p tcp --dport 443 -j ACCEPT".into());
    f.sim()
        .v4
        .push(spec("tcp", "443", "onebox-proxy-ffffffffffffffff"));
    f.reconcile(&[(443, 443, TCP), (20000, 20010, UDP)])
        .unwrap();
    let report = f.reconcile(&[(8443, 8443, TCP)]).unwrap();
    assert_eq!(report.created, ["iptables 8443/tcp"]);
    assert_eq!(
        report.removed,
        ["iptables 443/tcp", "iptables 20000-20010/udp"]
    );
    let ledger = f.ledger();
    assert_eq!(ledger.entries.len(), 1);
    let token = &ledger.entries[0].rule.token;
    assert_eq!(
        f.sim().v4,
        [
            spec("tcp", "8443", token),
            "-p tcp --dport 443 -j ACCEPT".to_string(),
            spec("tcp", "443", "onebox-proxy-ffffffffffffffff"),
        ],
        "foreign rules (no or unknown token) are untouched"
    );
}

#[test]
fn rules_of_a_vanished_backend_are_dropped_without_running_it() {
    let f = Fixture::new();
    let path = ledger_path(&f.ctx.paths, "proxy");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
        &path,
        r#"{"rules":[{"backend":"ufw","port":443,"end":443,"udp":false,"token":"onebox-proxy-1111111111111111"},
                     {"backend":"ip6tables","port":443,"end":443,"udp":false,"token":"onebox-proxy-2222222222222222"}]}"#,
    )
    .unwrap();
    let report = f.reconcile(&[(443, 443, TCP)]).unwrap();
    assert_eq!(report.removed, ["ufw 443/tcp", "ip6tables 443/tcp"]);
    assert!(report.failed.is_empty());
    assert!(f
        .exec
        .history()
        .iter()
        .all(|c| !c.starts_with("ufw") && !c.starts_with("ip6tables")));
    let ledger = f.ledger();
    assert_eq!(ledger.entries.len(), 1);
    assert_eq!(
        ledger.entries[0].location,
        Location::Iptables(Iptables { v6: false })
    );
}

#[test]
fn switching_backends_moves_the_rules() {
    let f = Fixture::new();
    f.reconcile(&[(443, 443, TCP)]).unwrap();
    // ufw gets enabled: the port moves to ufw, the iptables rule is removed.
    f.exec.provide("ufw");
    f.exec
        .on(
            "ufw",
            &["status", "numbered"],
            Output::success("Status: active\n"),
        )
        .on("ufw", &["status"], Output::success("Status: active\n"))
        .on("ufw", &["allow"], Output::success("Rule added\n"));
    let report = f.reconcile(&[(443, 443, TCP)]).unwrap();
    assert_eq!(report.created, ["ufw 443/tcp"]);
    assert_eq!(report.removed, ["iptables 443/tcp"]);
    assert!(f.sim().v4.is_empty());
    assert_eq!(f.ledger().entries[0].location, Location::Ufw(Ufw));
}

#[test]
fn failed_stale_removal_warns_keeps_the_record_and_retries() {
    let f = Fixture::new();
    f.reconcile(&[(443, 443, TCP), (8443, 8443, TCP)]).unwrap();
    f.sim().fail_delete = Some("--dport 443 ".into());
    let report = f.reconcile(&[]).unwrap();
    assert_eq!(report.removed, ["iptables 8443/tcp"]);
    assert_eq!(report.failed.len(), 1);
    assert!(report.failed[0].starts_with("iptables 443/tcp: iptables 执行失败 (7)"));
    assert_eq!(
        f.ledger().entries.len(),
        1,
        "only the failed rule stays recorded"
    );
    f.sim().fail_delete = None;
    let report = f.reconcile(&[]).unwrap();
    assert_eq!(report.removed, ["iptables 443/tcp"]);
    assert!(f.ledger().entries.is_empty() && f.sim().v4.is_empty());
}

#[test]
fn a_rule_that_cannot_be_recorded_is_removed_again() {
    let f = Fixture::new();
    f.reconcile(&[]).unwrap();
    f.sim().sabotage_ledger = Some(ledger_path(&f.ctx.paths, "proxy"));
    let err = f.reconcile(&[(443, 443, TCP)]).unwrap_err().to_string();
    assert!(err.contains("firewall-v2.json"), "{err}");
    assert!(f.sim().v4.is_empty(), "the unrecorded rule was taken out");
    assert_eq!(f.commands("-D").len(), 1);
}

#[test]
fn ipv6_hosts_get_ip6tables_rules() {
    let f = Fixture::new();
    let inet6 = f.ctx.paths.system("/proc/net/if_inet6");
    std::fs::create_dir_all(inet6.parent().unwrap()).unwrap();
    std::fs::write(inet6, "").unwrap();
    f.exec.provide("ip6tables");
    let report = f.reconcile(&[(443, 443, Transport::Both)]).unwrap();
    assert_eq!(
        report.created,
        [
            "iptables 443/tcp",
            "ip6tables 443/tcp",
            "iptables 443/udp",
            "ip6tables 443/udp"
        ]
    );
    let sim = f.sim();
    assert_eq!((sim.v4.len(), sim.v6.len()), (2, 2));
}

#[test]
fn no_firewall_means_nothing_to_do_but_old_rules_still_go() {
    let dir = TempDir::new("reconcile").unwrap();
    let (ctx, exec, _) = Ctx::test(dir.path());
    let report = reconcile_owner(&ctx, "acme", &[(80, 80, TCP)]).unwrap();
    assert_eq!(report, Report::default());
    assert!(exec.history().is_empty());
    let saved = std::fs::read_to_string(ledger_path(&ctx.paths, "acme")).unwrap();
    assert_eq!(saved, "{\n  \"rules\": []\n}");
}

#[test]
fn clear_owner_retains_only_failed_rules() {
    let f = Fixture::new();
    f.reconcile(&[(443, 443, TCP), (8443, 8443, TCP)]).unwrap();
    f.sim().fail_delete = Some("--dport 443 ".into());
    let report = clear_owner(&f.ctx, "proxy").unwrap();
    assert_eq!(report.removed, ["iptables 8443/tcp"]);
    assert_eq!(report.failed.len(), 1);
    assert!(
        report.failed[0].starts_with("iptables 443/tcp: iptables 执行失败 (7)"),
        "{report:?}"
    );
    let ledger = f.ledger();
    assert_eq!(ledger.entries.len(), 1);
    assert_eq!(ledger.entries[0].rule.start, 443);
    for call in f
        .exec
        .calls()
        .iter()
        .filter(|c| c.args.get(2).is_some_and(|a| a != "-S"))
    {
        assert!(
            call.args.iter().any(|a| a.starts_with("onebox-proxy-")),
            "{}",
            call.display()
        );
    }
    f.sim().fail_delete = None;
    let report = clear_owner(&f.ctx, "proxy").unwrap();
    assert_eq!(report.removed, ["iptables 443/tcp"]);
    assert!(f.ledger().entries.is_empty() && f.sim().v4.is_empty());
}

#[test]
fn clearing_rules_of_a_disabled_ufw_keeps_them_recorded_without_failing() {
    let dir = TempDir::new("reconcile").unwrap();
    let (ctx, exec, _) = Ctx::test(dir.path());
    let path = ledger_path(&ctx.paths, "proxy");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let ledger = r#"{"rules":[{"backend":"ufw","port":443,"end":443,"udp":false,"token":"onebox-proxy-1111111111111111"}]}"#;
    std::fs::write(&path, ledger).unwrap();
    exec.provide("ufw");
    exec.on(
        "ufw",
        &["status", "numbered"],
        Output::success("Status: inactive\n"),
    );
    let report = clear_owner(&ctx, "proxy").unwrap();
    assert!(report.removed.is_empty());
    assert_eq!(report.failed.len(), 1);
    assert!(
        report.failed[0].starts_with("ufw 443/tcp: ufw 未启用"),
        "{report:?}"
    );
    assert_eq!(
        Ledger::load(&path, "proxy").unwrap().entries.len(),
        1,
        "kept for the next attempt"
    );
    assert_eq!(exec.history(), ["ufw status numbered"]);
}

#[test]
fn owners_have_separate_ledgers() {
    let f = Fixture::new();
    f.reconcile(&[(443, 443, TCP)]).unwrap();
    reconcile_owner(&f.ctx, "acme", &[(80, 80, TCP)]).unwrap();
    clear_owner(&f.ctx, "acme").unwrap();
    assert_eq!(f.ledger().entries.len(), 1, "proxy rules survive");
    assert_eq!(f.sim().v4.len(), 1);
    assert!(clear_owner(&f.ctx, "../x").is_err());
    assert!(reconcile_owner(&f.ctx, "proxy", &[(0, 0, TCP)]).is_err());
}

#[test]
fn explicit_ledger_paths_are_honoured() {
    let f = Fixture::new();
    let path = f.ctx.paths.frp_root.join("firewall-v2.json");
    reconcile(&f.ctx, &path, "frp", &[(7000, 7000, TCP)]).unwrap();
    let ledger = Ledger::load(&path, "frp").unwrap();
    assert!(ledger.entries[0].rule.token.starts_with("onebox-frp-"));
    clear(&f.ctx, &path, "frp").unwrap();
    assert!(f.sim().v4.is_empty());
}

/// End-to-end against the real iptables-nft / nft of the host. Destructive
/// for the current network namespace, so it only runs when
/// `ONEBOX_TEST_NETNS=1` says the test binary was started in a private one
/// (`unshare -n <test-binary> real_firewall --ignored`).
#[test]
#[ignore]
fn real_firewall_in_private_netns() {
    if std::env::var("ONEBOX_TEST_NETNS").as_deref() != Ok("1") {
        return;
    }
    use crate::domain::config::PortRange;
    use crate::sys::exec::SystemExec;
    let dir = TempDir::new("real-fw").unwrap();
    let ctx = Ctx {
        paths: crate::paths::Paths::isolated(dir.path()),
        exec: Arc::new(SystemExec),
        ui: Arc::new(crate::ui::ScriptedPrompter::new(Vec::<String>::new())),
    };
    let run = |cmd: &[&str]| {
        ctx.check(&Cmd::new(cmd[0]).args(cmd[1..].iter().copied()))
            .unwrap()
    };
    let desired = [(443, 443, TCP), (20000, 20010, UDP)];
    // iptables (through iptables-nft): no native nft chain exists yet.
    let report = reconcile_owner(&ctx, "proxy", &desired).unwrap();
    assert_eq!(
        report.created,
        ["iptables 443/tcp", "iptables 20000-20010/udp"]
    );
    let rules = run(&["iptables", "-w", "5", "-S", "INPUT"]);
    assert!(
        rules.contains("--dport 443 ") && rules.contains("20000:20010"),
        "{rules}"
    );
    assert_eq!(
        reconcile_owner(&ctx, "proxy", &desired).unwrap(),
        Report::default()
    );
    // A native nft input chain appears: it gets nft rules, while the
    // iptables-nft chain keeps being managed through iptables.
    run(&["nft", "add", "table", "inet", "filter"]);
    run(&[
        "nft",
        "add",
        "chain",
        "inet",
        "filter",
        "input",
        "{ type filter hook input priority 0; policy drop; }",
    ]);
    // Chains that must not get rules: LXD's (a name nft argv cannot carry
    // safely) and a crowdsec-like chain whose only drop is conditional.
    run(&["nft", "add", "table", "inet", "lxd"]);
    run(&[
        "nft",
        "add",
        "chain",
        "inet",
        "lxd",
        "in.lxdbr0",
        "{ type filter hook input priority 0; policy accept; }",
    ]);
    run(&["nft", "add", "table", "ip", "crowdsec"]);
    run(&[
        "nft",
        "add",
        "set",
        "ip",
        "crowdsec",
        "crowdsec-blacklists",
        "{ type ipv4_addr; }",
    ]);
    run(&[
        "nft",
        "add",
        "chain",
        "ip",
        "crowdsec",
        "crowdsec-chain",
        "{ type filter hook input priority -10; policy accept; }",
    ]);
    run(&[
        "nft",
        "add",
        "rule",
        "ip",
        "crowdsec",
        "crowdsec-chain",
        "ip saddr @crowdsec-blacklists drop",
    ]);
    let report = reconcile_owner(&ctx, "proxy", &desired).unwrap();
    assert_eq!(
        report.created,
        [
            "nft inet filter input 443/tcp",
            "nft inet filter input 20000-20010/udp"
        ]
    );
    let chain = run(&["nft", "list", "chain", "inet", "filter", "input"]);
    assert!(
        chain.contains("tcp dport 443 accept comment \"onebox-proxy-"),
        "{chain}"
    );
    for table in [["inet", "lxd"], ["ip", "crowdsec"]] {
        let listed = run(&["nft", "list", "table", table[0], table[1]]);
        assert!(!listed.contains("onebox-proxy-"), "{listed}");
    }
    let compat = run(&["nft", "-j", "list", "table", "ip", "filter"]);
    assert!(
        !compat.contains("\"comment\": \"onebox-proxy-"),
        "no raw nft rule in the iptables-nft table: {compat}"
    );
    clear_owner(&ctx, "proxy").unwrap();
    assert!(!run(&["nft", "list", "ruleset"]).contains("onebox-proxy-"));
    // Port hopping through a real nft table.
    std::fs::create_dir_all(&ctx.paths.root).unwrap();
    let range = PortRange {
        start: 30000,
        end: 30010,
    };
    crate::host::hop::apply(&ctx, range, 443).unwrap();
    assert!(run(&["nft", "list", "tables"]).contains("onebox_hop_"));
    crate::host::hop::clear(&ctx).unwrap();
    assert!(!run(&["nft", "list", "tables"]).contains("onebox_hop_"));
    // What `iptables-restore-translate` makes of a policy-DROP rules.v4:
    // `ip filter INPUT` is a native chain iptables-nft refuses to list, so
    // it gets nft rules instead of failing every apply.
    run(&["nft", "flush", "ruleset"]);
    ctx.check(&Cmd::new("nft").args(["-f", "-"]).stdin_bytes(
        "add table ip filter\n\
         add chain ip filter INPUT { type filter hook input priority 0; policy drop; }\n\
         add rule ip filter INPUT iifname \"lo\" counter accept\n\
         add rule ip filter INPUT ct state related,established counter accept\n\
         add rule ip filter INPUT tcp dport 22 counter accept\n",
    ))
    .unwrap();
    let report = reconcile_owner(&ctx, "proxy", &desired).unwrap();
    assert_eq!(
        report.created,
        [
            "nft ip filter INPUT 443/tcp",
            "nft ip filter INPUT 20000-20010/udp"
        ]
    );
    let chain = run(&["nft", "list", "chain", "ip", "filter", "INPUT"]);
    assert!(
        chain.contains("tcp dport 443 accept comment \"onebox-proxy-"),
        "{chain}"
    );
    assert_eq!(
        reconcile_owner(&ctx, "proxy", &desired).unwrap(),
        Report::default()
    );
    clear_owner(&ctx, "proxy").unwrap();
    assert!(!run(&["nft", "list", "ruleset"]).contains("onebox-proxy-"));
}
