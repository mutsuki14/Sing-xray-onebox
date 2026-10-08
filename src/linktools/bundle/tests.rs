use super::*;
use crate::domain::fixtures::config;
use crate::domain::protocol::{Core, Protocol};
use crate::linktools::testutil::{bundle, entry};
use crate::sys::fs::TempDir;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use Transport::{Both, Tcp, Udp};

fn ids(selected: &[&ProbeEntry]) -> Vec<String> {
    selected.iter().map(|e| e.id.clone()).collect()
}

fn strings(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

#[test]
fn v2_select_order_and_default_tcp_quic_pair() {
    let b = bundle(vec![
        entry("quic", Core::Singbox, Udp),
        entry("tcp", Core::Singbox, Tcp),
        entry("more", Core::Singbox, Tcp),
    ]);
    assert_eq!(ids(&select(&b, None, Selection::Pair).unwrap()), ["tcp", "quic"]);
    assert_eq!(
        ids(&select(&b, Some(&strings(&["more", "tcp"])), Selection::All).unwrap()),
        ["more", "tcp"]
    );
    for (invalid, message) in [
        ("tcp,tcp", "--entries 包含重复的 ID"),
        ("missing", "--entries 包含未知 ID（先执行 probe list）"),
        ("", "--entries 包含未知 ID（先执行 probe list）"),
        ("tcp,", "--entries 包含未知 ID（先执行 probe list）"),
    ] {
        let err = select(&b, Some(&split_ids(invalid)), Selection::All).unwrap_err();
        assert_eq!(err.to_string(), message, "{invalid:?}");
    }
}

#[test]
fn explicit_ids_are_trimmed() {
    let b = bundle(vec![
        entry("a", Core::Singbox, Tcp),
        entry("b", Core::Xray, Tcp),
    ]);
    let picked = select(&b, Some(&split_ids(" b , a")), Selection::Pair).unwrap();
    assert_eq!(ids(&picked), ["b", "a"]);
    let err = select(&b, Some(&split_ids("a, a")), Selection::All).unwrap_err();
    assert_eq!(err.to_string(), "--entries 包含重复的 ID");
}

#[test]
fn default_selections() {
    let all_tcp = bundle(vec![
        entry("a", Core::Singbox, Tcp),
        entry("b", Core::Singbox, Tcp),
    ]);
    // An all-TCP bundle yields one entry (failover then needs --entries).
    assert_eq!(ids(&select(&all_tcp, None, Selection::Pair).unwrap()), ["a"]);
    assert_eq!(ids(&select(&all_tcp, None, Selection::All).unwrap()), ["a", "b"]);
    let both = bundle(vec![
        entry("ss", Core::Singbox, Both),
        entry("hy", Core::Singbox, Udp),
    ]);
    assert_eq!(ids(&select(&both, None, Selection::Pair).unwrap()), ["ss", "hy"]);
    let udp_only = bundle(vec![
        entry("hy", Core::Singbox, Udp),
        entry("tuic", Core::Singbox, Udp),
    ]);
    assert_eq!(ids(&select(&udp_only, None, Selection::Pair).unwrap()), ["hy"]);
}

#[test]
fn merge_prefixes_by_input_position() {
    let first = bundle(vec![
        entry("vless-reality", Core::Singbox, Tcp),
        entry("hysteria2", Core::Singbox, Udp),
    ]);
    let second = bundle(vec![entry("vless-reality", Core::Xray, Tcp)]);
    let merged = merge(&[first, second]).unwrap();
    assert_eq!(
        merged.entries.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(),
        ["n1-vless-reality", "n1-hysteria2", "n2-vless-reality"]
    );
    assert_eq!(merged.entries[2].core, Core::Xray);
    assert_eq!(
        list_lines(&merged),
        [
            "n1-vless-reality\ttcp\tsingbox",
            "n1-hysteria2\tudp\tsingbox",
            "n2-vless-reality\ttcp\txray"
        ]
    );
}

#[test]
fn merge_limits_have_clear_messages() {
    let one = bundle(vec![entry("a", Core::Singbox, Tcp)]);
    let err = merge(std::slice::from_ref(&one)).unwrap_err();
    assert_eq!(err.to_string(), "probe merge 至少需要两份探测配置");

    let long = bundle(vec![entry(&"x".repeat(78), Core::Singbox, Tcp)]);
    let err = merge(&[one.clone(), long]).unwrap_err();
    assert_eq!(
        err.to_string(),
        format!("合并后的入口 ID 超过 80 个字符: n2-{}", "x".repeat(78))
    );

    let many: Vec<ProbeEntry> = (0..17)
        .map(|i| entry(&format!("e{i}"), Core::Singbox, Tcp))
        .collect();
    let err = merge(&[bundle(many.clone()), bundle(many)]).unwrap_err();
    assert_eq!(err.to_string(), "配置需要 1 至 32 个入口");
}

#[test]
fn private_outputs_never_overwrite_or_follow_symlinks() {
    let dir = TempDir::new("linktools-test").unwrap();
    let path = dir.join("probe.json");
    let b = bundle(vec![entry("a", Core::Singbox, Tcp)]);
    write_bundle(&path, &b).unwrap();
    let meta = fs::metadata(&path).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.starts_with("{\n  \"entries\": [") && text.ends_with("}\n"));
    assert_eq!(load(&path).unwrap(), b, "round trip");

    let err = write_bundle(&path, &b).unwrap_err();
    assert!(err.to_string().starts_with("目标已存在"), "{err}");
    let link = dir.join("link.json");
    std::os::unix::fs::symlink(dir.join("absent.json"), &link).unwrap();
    assert!(write_private(&link, "{}").is_err(), "dangling symlink refused");
    assert!(!dir.join("absent.json").exists());
}

#[test]
fn export_reads_the_installed_node() {
    let dir = TempDir::new("linktools-test").unwrap();
    let (ctx, _, _) = Ctx::test(dir.path());
    let err = from_node(&ctx, false).unwrap_err();
    assert_eq!(err.to_string(), "尚未安装 Onebox，请先执行 onebox install");

    let cfg = config(&[
        (Protocol::VlessReality, 443, Core::Singbox),
        (Protocol::Shadowsocks, 8388, Core::Singbox),
    ]);
    StateStore::save_to(&ctx.paths, &cfg).unwrap();
    let public = from_node(&ctx, false).unwrap();
    assert_eq!(
        list_lines(&public),
        ["vless-reality\ttcp\tsingbox", "shadowsocks\tboth\tsingbox"]
    );
    let meta = public.entries[0].reality.clone().unwrap();
    assert_eq!(meta.host, "203.0.113.10");
    let local = from_node(&ctx, true).unwrap();
    assert_eq!(local.entries[0].reality.clone().unwrap().host, "127.0.0.1");
    let text = json_text(&public.to_value().unwrap()).unwrap();
    let private = cfg.creds.reality.as_ref().unwrap().private_key.clone();
    assert!(!text.contains(&private), "server private key never exported");
}
