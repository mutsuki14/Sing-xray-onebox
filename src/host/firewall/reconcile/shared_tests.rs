//! Ports that are one shared object (firewalld, ufw): several Onebox owners
//! and administrator rules on the same port.

use super::*;
use crate::sys::exec::{Cmd, FakeExec, Output};
use crate::sys::fs::TempDir;
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

const TCP: Transport = Transport::Tcp;

/// firewalld with one active zone `public`: runtime and permanent ports.
#[derive(Default)]
struct Zone {
    runtime: BTreeSet<String>,
    permanent: BTreeSet<String>,
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

fn answer_firewalld(zone: &mut Zone, c: &Cmd) -> Output {
    match c.args.first().map(String::as_str) {
        Some("--state") => return Output::success("running\n"),
        Some("--get-active-zones") => return Output::success("public\n  interfaces: eth0\n"),
        _ => {}
    }
    let ports = if c.args.iter().any(|a| a == "--permanent") {
        &mut zone.permanent
    } else {
        &mut zone.runtime
    };
    let action = &c.args[1];
    let (verb, port) = action
        .trim_start_matches("--")
        .split_once("-port=")
        .unwrap();
    let port = port.to_string();
    match verb {
        "query" if ports.contains(&port) => Output::success("yes\n"),
        "query" => Output::failure(1, "no\n"),
        "add" => {
            ports.insert(port);
            Output::success("success\n")
        }
        "remove" => {
            ports.remove(&port);
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
    for acme_first in [true, false] {
        let (_dir, ctx, exec) = setup();
        let zone = firewalld(&exec);
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
        let open = zone.lock().unwrap().runtime.contains("80/tcp");
        assert!(open, "proxy still needs 80 (acme first: {acme_first})");
        assert!(zone.lock().unwrap().permanent.contains("80/tcp"));
        reconcile_owner(&ctx, "proxy", &[]).unwrap();
        assert!(
            zone.lock().unwrap().runtime.is_empty(),
            "nobody wants 80 any more"
        );
        assert!(zone.lock().unwrap().permanent.is_empty());
    }
}

#[test]
fn firewalld_admin_ports_are_never_recorded_or_removed() {
    let (_dir, ctx, exec) = setup();
    let zone = firewalld(&exec);
    zone.lock().unwrap().runtime.insert("443/tcp".into());
    reconcile_owner(&ctx, "proxy", &[(443, 443, TCP)]).unwrap();
    assert_eq!(
        recorded(&ctx, "proxy"),
        1,
        "only the permanent copy is ours"
    );
    clear_owner(&ctx, "proxy").unwrap();
    assert!(zone.lock().unwrap().runtime.contains("443/tcp"));
    assert!(zone.lock().unwrap().permanent.is_empty());
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
