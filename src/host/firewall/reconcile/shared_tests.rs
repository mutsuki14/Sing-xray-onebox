//! Ports that are one shared object (firewalld, ufw): several Onebox owners
//! and administrator rules on the same port.

use super::*;
use crate::sys::exec::{Cmd, FakeExec, Output};
use crate::sys::fs::TempDir;
use std::sync::{Arc, Mutex};

const TCP: Transport = Transport::Tcp;

/// firewalld with one active zone `public`: the runtime and permanent
/// port entries `(start, end, proto)`. `merging` models firewalld ≥ 0.9
/// (overlapping ranges become one entry, queries match inside entries,
/// removals split entries); otherwise every added range is its own entry
/// and matching is exact (older versions).
#[derive(Default)]
struct Zone {
    merging: bool,
    runtime: Vec<(u16, u16, String)>,
    permanent: Vec<(u16, u16, String)>,
}

impl Zone {
    /// Whether `port`/tcp is open in both configurations.
    fn open(&self, port: u16) -> bool {
        let has = |entries: &[(u16, u16, String)]| {
            entries
                .iter()
                .any(|(s, e, p)| *s <= port && port <= *e && p == "tcp")
        };
        has(&self.runtime) && has(&self.permanent)
    }

    /// The runtime entries as `--list-ports` prints them.
    fn listed(&self) -> String {
        listing(&self.runtime)
    }
}

fn listing(entries: &[(u16, u16, String)]) -> String {
    let mut words: Vec<String> = entries
        .iter()
        .map(|(s, e, p)| {
            if s == e {
                format!("{s}/{p}")
            } else {
                format!("{s}-{e}/{p}")
            }
        })
        .collect();
    words.sort();
    words.join(" ")
}

fn firewalld(exec: &FakeExec) -> Arc<Mutex<Zone>> {
    let zone = Arc::new(Mutex::new(Zone::default()));
    let model = Arc::clone(&zone);
    exec.provide("firewall-cmd");
    exec.on_fn(
        |c| c.program == "firewall-cmd",
        move |c| Ok(answer_firewalld(&mut model.lock().unwrap(), c)),
    );
    zone
}

fn parse_port(text: &str) -> (u16, u16, String) {
    let (ports, proto) = text.split_once('/').unwrap();
    let (start, end) = ports.split_once('-').unwrap_or((ports, ports));
    (
        start.parse().unwrap(),
        end.parse().unwrap(),
        proto.to_string(),
    )
}

fn answer_firewalld(zone: &mut Zone, c: &Cmd) -> Output {
    match c.args.first().map(String::as_str) {
        Some("--state") => return Output::success("running\n"),
        Some("--get-active-zones") => return Output::success("public\n  interfaces: eth0\n"),
        _ => {}
    }
    let merging = zone.merging;
    let entries = if c.args.iter().any(|a| a == "--permanent") {
        &mut zone.permanent
    } else {
        &mut zone.runtime
    };
    let action = c.args[1].trim_start_matches("--");
    if action == "list-ports" {
        return Output::success(format!("{}\n", listing(entries)));
    }
    let (verb, port) = action.split_once("-port=").unwrap();
    let (start, end, proto) = parse_port(port);
    let inside = |e: &(u16, u16, String)| e.2 == proto && e.0 <= start && end <= e.1;
    let exact = |e: &(u16, u16, String)| e.2 == proto && e.0 == start && e.1 == end;
    let present = if merging {
        entries.iter().position(inside)
    } else {
        entries.iter().position(exact)
    };
    match verb {
        "query" if present.is_some() => Output::success("yes\n"),
        "query" => Output::failure(1, "no\n"),
        "add" if present.is_some() => Output::success("Warning: ALREADY_ENABLED\n"),
        "add" if merging => {
            let (mut lo, mut hi) = (start, end);
            entries.retain(|e| {
                let overlaps = e.2 == proto && e.0 <= hi && lo <= e.1;
                if overlaps {
                    (lo, hi) = (lo.min(e.0), hi.max(e.1));
                }
                !overlaps
            });
            entries.push((lo, hi, proto));
            Output::success("success\n")
        }
        "add" => {
            entries.push((start, end, proto));
            Output::success("success\n")
        }
        "remove" => {
            let Some(index) = present else {
                return Output::success("Warning: NOT_ENABLED\n");
            };
            let (lo, hi, p) = entries.remove(index);
            if lo < start {
                entries.push((lo, start - 1, p.clone()));
            }
            if end < hi {
                entries.push((end + 1, hi, p));
            }
            Output::success("success\n")
        }
        _ => Output::failure(2, "unsupported"),
    }
}

/// `(spec, comment)` per rule, one rule per spec.
type UfwRules = Arc<Mutex<Vec<(String, Option<String>)>>>;

/// An active ufw.
fn ufw(exec: &FakeExec) -> UfwRules {
    let rules = Arc::new(Mutex::new(Vec::new()));
    let model = Arc::clone(&rules);
    exec.provide("ufw");
    exec.on_fn(
        |c| c.program == "ufw",
        move |c| Ok(answer_ufw(&mut model.lock().unwrap(), c)),
    );
    rules
}

fn answer_ufw(rules: &mut Vec<(String, Option<String>)>, c: &Cmd) -> Output {
    let args: Vec<&str> = c.args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["status"] => Output::success("Status: active\n"),
        ["status", "numbered"] => {
            let mut text = String::from("Status: active\n\n");
            for (i, (spec, comment)) in rules.iter().enumerate() {
                let tail = comment
                    .as_ref()
                    .map(|c| format!(" # {c}"))
                    .unwrap_or_default();
                text.push_str(&format!(
                    "[{:>2}] {spec:<26} ALLOW IN    Anywhere{tail}\n",
                    i + 1
                ));
            }
            Output::success(text)
        }
        ["allow", spec, "comment", comment] => {
            match rules.iter_mut().find(|(s, _)| s == spec) {
                Some(rule) => rule.1 = Some(comment.to_string()),
                None => rules.push((spec.to_string(), Some(comment.to_string()))),
            }
            Output::success("Rule added\n")
        }
        ["--force", "delete", n] => {
            let index: usize = n.parse().unwrap();
            rules.remove(index - 1);
            Output::success("Rule deleted\n")
        }
        _ => Output::failure(2, "unsupported"),
    }
}

fn setup() -> (TempDir, Ctx, Arc<FakeExec>) {
    let dir = TempDir::new("shared").unwrap();
    let (ctx, exec, _) = Ctx::test(dir.path());
    (dir, ctx, exec)
}

fn recorded(ctx: &Ctx, owner: &str) -> usize {
    Ledger::load(&ledger_path(&ctx.paths, owner), owner)
        .unwrap()
        .entries
        .len()
}

#[test]
fn firewalld_port_stays_open_while_another_owner_wants_it() {
    for merging in [false, true] {
        for acme_first in [true, false] {
            let (_dir, ctx, exec) = setup();
            let zone = firewalld(&exec);
            zone.lock().unwrap().merging = merging;
            let (first, second) = if acme_first {
                ("acme", "proxy")
            } else {
                ("proxy", "acme")
            };
            reconcile_owner(&ctx, first, &[(80, 80, TCP)]).unwrap();
            let report = reconcile_owner(&ctx, second, &[(80, 80, TCP)]).unwrap();
            assert!(report.created.is_empty(), "already open");
            assert_eq!(
                recorded(&ctx, second),
                2,
                "shared runtime + permanent recorded"
            );
            clear_owner(&ctx, "acme").unwrap();
            assert!(
                zone.lock().unwrap().open(80),
                "proxy still needs 80 (acme first: {acme_first}, merging: {merging})"
            );
            reconcile_owner(&ctx, "proxy", &[]).unwrap();
            let zone = zone.lock().unwrap();
            assert!(
                zone.runtime.is_empty() && zone.permanent.is_empty(),
                "nobody wants 80 any more"
            );
        }
    }
}

#[test]
fn firewalld_admin_ports_are_never_recorded_or_removed() {
    let (_dir, ctx, exec) = setup();
    let zone = firewalld(&exec);
    zone.lock().unwrap().runtime.push((443, 443, "tcp".into()));
    reconcile_owner(&ctx, "proxy", &[(443, 443, TCP)]).unwrap();
    assert_eq!(
        recorded(&ctx, "proxy"),
        1,
        "only the permanent copy is ours"
    );
    clear_owner(&ctx, "proxy").unwrap();
    assert_eq!(zone.lock().unwrap().listed(), "443/tcp");
    assert!(zone.lock().unwrap().permanent.is_empty());
}

#[test]
fn a_merged_firewalld_entry_keeps_the_ports_other_owners_need() {
    for merging in [false, true] {
        // acme opens 80; proxy's site (80) + an inbound on 81 open 80-81,
        // which a merging firewalld folds acme's entry into.
        let (_dir, ctx, exec) = setup();
        let zone = firewalld(&exec);
        zone.lock().unwrap().merging = merging;
        reconcile_owner(&ctx, "acme", &[(80, 80, TCP)]).unwrap();
        reconcile_owner(&ctx, "proxy", &[(80, 81, TCP)]).unwrap();
        let expected = if merging {
            "80-81/tcp"
        } else {
            "80-81/tcp 80/tcp"
        };
        assert_eq!(zone.lock().unwrap().listed(), expected);
        let report = clear_owner(&ctx, "acme").unwrap();
        assert!(report.failed.is_empty(), "{report:?}");
        assert_eq!(
            zone.lock().unwrap().listed(),
            "80-81/tcp",
            "port 80 stays open for the site (merging: {merging})"
        );
        reconcile_owner(&ctx, "proxy", &[]).unwrap();
        assert_eq!(zone.lock().unwrap().listed(), "");
        assert!(zone.lock().unwrap().permanent.is_empty());

        // The other order: proxy holds 80-81, acme shares 80, proxy stops
        // wanting 80-81 while acme still needs 80.
        let (_dir, ctx, exec) = setup();
        let zone = firewalld(&exec);
        zone.lock().unwrap().merging = merging;
        reconcile_owner(&ctx, "proxy", &[(80, 81, TCP)]).unwrap();
        reconcile_owner(&ctx, "acme", &[(80, 80, TCP)]).unwrap();
        reconcile_owner(&ctx, "proxy", &[]).unwrap();
        assert_eq!(
            zone.lock().unwrap().listed(),
            "80/tcp",
            "81 closed, 80 kept for acme (merging: {merging})"
        );
        clear_owner(&ctx, "acme").unwrap();
        assert_eq!(zone.lock().unwrap().listed(), "", "nothing leaks");
        assert!(zone.lock().unwrap().permanent.is_empty());
    }
}

#[test]
fn an_admin_range_that_absorbed_our_port_is_never_cut() {
    let (_dir, ctx, exec) = setup();
    let zone = firewalld(&exec);
    zone.lock().unwrap().merging = true;
    reconcile_owner(&ctx, "proxy", &[(8443, 8443, TCP)]).unwrap();
    // The administrator opens 8000-9000; firewalld merges our entry into it.
    let admin = Cmd::new("firewall-cmd").args(["--zone=public", "--add-port=8000-9000/tcp"]);
    answer_firewalld(&mut zone.lock().unwrap(), &admin);
    reconcile_owner(&ctx, "proxy", &[]).unwrap();
    assert_eq!(zone.lock().unwrap().listed(), "8000-9000/tcp");
    assert!(zone.lock().unwrap().permanent.is_empty(), "ours, unmerged");
    assert_eq!(recorded(&ctx, "proxy"), 0, "forgotten, not removed");
}

#[test]
fn shrinking_a_range_keeps_the_ports_still_wanted() {
    for merging in [false, true] {
        let (_dir, ctx, exec) = setup();
        let zone = firewalld(&exec);
        zone.lock().unwrap().merging = merging;
        reconcile_owner(&ctx, "proxy", &[(443, 445, TCP)]).unwrap();
        reconcile_owner(&ctx, "proxy", &[(444, 444, TCP)]).unwrap();
        assert_eq!(
            zone.lock().unwrap().listed(),
            "444/tcp",
            "merging: {merging}"
        );
        assert!(zone.lock().unwrap().open(444));
        assert_eq!(recorded(&ctx, "proxy"), 2);
        reconcile_owner(&ctx, "proxy", &[]).unwrap();
        assert_eq!(zone.lock().unwrap().listed(), "");
    }
}

#[test]
fn ufw_comment_is_handed_back_instead_of_deleting_a_shared_rule() {
    let (_dir, ctx, exec) = setup();
    let rules = ufw(&exec);
    reconcile_owner(&ctx, "proxy", &[(80, 80, TCP)]).unwrap();
    let proxy_token = Ledger::load(&ledger_path(&ctx.paths, "proxy"), "proxy")
        .unwrap()
        .entries[0]
        .rule
        .token
        .clone();
    reconcile_owner(&ctx, "acme", &[(80, 80, TCP)]).unwrap();
    let comment = rules.lock().unwrap()[0].1.clone().unwrap();
    assert!(
        comment.starts_with("onebox-acme-"),
        "acme took the rule over"
    );
    clear_owner(&ctx, "acme").unwrap();
    assert_eq!(
        *rules.lock().unwrap(),
        [("80/tcp".to_string(), Some(proxy_token))],
        "rule kept and handed back to proxy"
    );
    assert_eq!(
        reconcile_owner(&ctx, "proxy", &[(80, 80, TCP)]).unwrap(),
        Report::default(),
        "proxy finds its rule again"
    );
}

#[test]
fn a_recorded_port_replaced_by_an_admin_rule_is_forgotten() {
    let (_dir, ctx, exec) = setup();
    let rules = ufw(&exec);
    reconcile_owner(&ctx, "proxy", &[(8443, 8443, TCP)]).unwrap();
    // The admin deleted our rule and added the same spec themselves.
    *rules.lock().unwrap() = vec![("8443/tcp".into(), None)];
    reconcile_owner(&ctx, "proxy", &[(8443, 8443, TCP)]).unwrap();
    assert_eq!(recorded(&ctx, "proxy"), 0);
    reconcile_owner(&ctx, "proxy", &[]).unwrap();
    assert_eq!(*rules.lock().unwrap(), [("8443/tcp".to_string(), None)]);
}

#[test]
fn the_v2_owner_name_is_reserved_for_the_proxy_ledger() {
    let (_dir, ctx, _exec) = setup();
    assert_eq!(
        reconcile_owner(&ctx, "v2", &[]).unwrap_err().to_string(),
        "防火墙所有者名称无效"
    );
    assert!(clear_owner(&ctx, "v2").is_err());
}
