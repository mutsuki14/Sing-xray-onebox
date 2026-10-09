use super::*;
use crate::domain::config::PortRange;
use crate::domain::fixtures::config;
use crate::domain::protocol::{Core, Protocol};
use crate::frp::model::{AppDomain, BindAddr, Mode, WebSettings, WebTls};
use crate::sys::exec::Output;
use crate::sys::fs::TempDir;
use std::fs;

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn tcp(domain: &str, range: PortRange) -> FrpState {
    FrpState::new(
        domain.into(),
        TOKEN.into(),
        BindAddr::AnyV4,
        Mode::Tcp { range },
    )
}

fn web(app: AppDomain) -> FrpState {
    FrpState::new(
        "control.example.com".into(),
        TOKEN.into(),
        BindAddr::AnyV6,
        Mode::Web(WebSettings::new(app, WebTls::Cloudflare)),
    )
}

#[test]
fn isolated_layout_is_accepted_and_overlaps_are_refused() {
    let root = Path::new("/tmp/onebox-frp-path-test");
    check_paths(&Paths::isolated(root)).unwrap();
    let mut nested = Paths::isolated(root);
    nested.frp_web = nested.frp_root.join("www");
    assert_eq!(
        check_paths(&nested).unwrap_err().to_string(),
        "FRP 数据目录不能相同或互相包含"
    );
    let mut same = Paths::isolated(root);
    same.frp_log = same.frp_run.clone();
    assert!(check_paths(&same).is_err());
    let mut node = Paths::isolated(root);
    node.frp_bin = node.bin.join("frp");
    assert_eq!(
        check_paths(&node).unwrap_err().to_string(),
        "FRP 路径不能与代理、网站或服务目录重叠"
    );
    for bad in ["/etc", "/var/lib", "/opt/my frp", "/opt/frp$x", "/"] {
        let mut p = Paths::isolated(root);
        p.frp_root = bad.into();
        let err = check_paths(&p).unwrap_err().to_string();
        assert_eq!(
            err,
            format!("FRP 路径必须为专用绝对目录且不能含空格: {bad}")
        );
    }
    let mut exe = Paths::isolated(root);
    exe.executable = "/usr/local/bin/one box".into();
    assert!(check_paths(&exe).is_err());
}

/// DNS fixture: the host owns 192.0.2.1; `stale` adds a foreign AAAA.
fn dns_ctx(dir: &TempDir, stale: bool) -> Ctx {
    let (ctx, exec, _) = Ctx::test(dir.path());
    exec.on(
        "ip",
        &["-j", "address", "show"],
        Output::success(r#"[{"addr_info":[{"local":"192.0.2.1"},{"local":"fe80::1"}]}]"#),
    );
    exec.on(
        "getent",
        &["ahosts"],
        Output::success("192.0.2.1 STREAM control.example.com\n"),
    );
    let v6 = if stale {
        "2001:db8::99 STREAM control.example.com\n"
    } else {
        "::ffff:192.0.2.1 STREAM control.example.com\n"
    };
    exec.on("getent", &["ahostsv6"], Output::success(v6));
    exec.on("getent", &["hosts"], Output::failure(2, ""));
    ctx
}

#[test]
fn dns_checks_stale_aaaa_and_normalizes_mapped_ipv4() {
    let dir = TempDir::new("frp-dns").unwrap();
    let state = tcp(
        "control.example.com",
        PortRange {
            start: 20000,
            end: 20100,
        },
    );
    check_dns(&dns_ctx(&dir, false), &state).unwrap();
    let err = check_dns(&dns_ctx(&dir, true), &state).unwrap_err();
    assert_eq!(
        err.to_string(),
        "FRP 域名 control.example.com 的 2001:db8::99 不属于本机；检查全部 A/AAAA 并关闭 CDN 代理"
    );
}

#[test]
fn dns_requires_records_and_probes_wildcards() {
    let dir = TempDir::new("frp-dns-missing").unwrap();
    let state = web(AppDomain::Wildcard {
        root: "apps.example.com".into(),
    });
    let (ctx, exec, _) = Ctx::test(dir.path());
    exec.on("ip", &[], Output::failure(1, ""));
    exec.on("getent", &[], Output::failure(2, ""));
    let err = check_dns(&ctx, &state).unwrap_err();
    assert_eq!(
        err.to_string(),
        "无法解析 control.example.com，请先添加 DNS 记录"
    );
    // Every name resolves to the public IPv4 address ipify reports.
    let (ctx, exec, _) = Ctx::test(dir.path());
    exec.on("ip", &[], Output::failure(1, ""));
    exec.on("curl", &["-fsS", "-4"], Output::success("198.51.100.7\n"));
    exec.on("getent", &[], Output::success("198.51.100.7 x\n"));
    check_dns(&ctx, &state).unwrap();
    let probes: Vec<String> = exec
        .history()
        .into_iter()
        .filter(|c| c.starts_with("getent ahosts onebox-"))
        .collect();
    assert_eq!(probes.len(), 1, "{probes:?}");
    assert!(probes[0].ends_with(".apps.example.com"));
    let curls = exec
        .history()
        .iter()
        .filter(|c| c.starts_with("curl"))
        .count();
    assert_eq!(curls, 2, "public addresses are detected once");
}

#[test]
fn node_ports_conflict_with_reservations() {
    let dir = TempDir::new("frp-node-ports").unwrap();
    let (ctx, _, _) = Ctx::test(dir.path());
    let state = tcp(
        "control.example.com",
        PortRange {
            start: 20000,
            end: 20100,
        },
    );
    check_node_ports(&ctx, &state).unwrap();
    let node = config(&[(Protocol::Hysteria2, 20050, Core::Singbox)]);
    StateStore::save(&ctx, &node).unwrap();
    let err = check_node_ports(&ctx, &state).unwrap_err();
    assert_eq!(
        err.to_string(),
        "FRP 20000-20100/both 与已有代理或网站 20050-20050/udp 冲突"
    );
    // A TCP-only reservation does not collide with a UDP inbound.
    let mut web_state = web(AppDomain::Single {
        domain: "app.example.com".into(),
    });
    if let Mode::Web(w) = &mut web_state.mode {
        w.https_port = 20050;
    }
    check_node_ports(&ctx, &web_state).unwrap();
    // So does the web bind port (TCP only, as in v2): the node's UDP
    // inbound on it keeps working after `configure`.
    web_state.bind_port = 20050;
    if let Mode::Web(w) = &mut web_state.mode {
        w.https_port = 443;
    }
    check_node_ports(&ctx, &web_state).unwrap();
}

/// `/proc/net/{tcp,udp}` with one listener (TCP LISTEN = `0A`).
fn proc_net(dir: &TempDir, tcp: &[u16], udp: &[u16]) -> std::path::PathBuf {
    let root = dir.join("system");
    fs::create_dir_all(root.join("proc/net")).unwrap();
    let header = "  sl  local_address rem_address   st tx_queue rx_queue\n";
    let line = |port: &u16, st: &str| format!("   0: 00000000:{port:04X} 00000000:0000 {st} 0\n");
    let tcp: String = tcp.iter().map(|p| line(p, "0A")).collect();
    let udp: String = udp.iter().map(|p| line(p, "07")).collect();
    fs::write(root.join("proc/net/tcp"), format!("{header}{tcp}")).unwrap();
    fs::write(root.join("proc/net/udp"), format!("{header}{udp}")).unwrap();
    root
}

#[test]
fn live_sockets_in_reserved_ports_are_refused() {
    let dir = TempDir::new("frp-live").unwrap();
    let state = tcp(
        "control.example.com",
        PortRange {
            start: 20000,
            end: 20010,
        },
    );
    let root = proc_net(&dir, &[22, 443], &[53]);
    check_live_ports(&root, &state).unwrap();
    let root = proc_net(&dir, &[20005], &[]);
    assert_eq!(
        check_live_ports(&root, &state).unwrap_err().to_string(),
        "FRP 端口 20005/tcp 已被其他进程占用"
    );
    let root = proc_net(&dir, &[], &[7000]);
    // The tcp-mode bind port is TCP only; UDP 7000 is someone else's.
    check_live_ports(&root, &state).unwrap();
    let root = proc_net(&dir, &[], &[20010]);
    assert_eq!(
        check_live_ports(&root, &state).unwrap_err().to_string(),
        "FRP 端口 20010/udp 已被其他进程占用"
    );
}

#[test]
fn connected_udp_client_sockets_do_not_block_the_range() {
    let dir = TempDir::new("frp-live-udp").unwrap();
    let state = tcp(
        "control.example.com",
        PortRange {
            start: 40000,
            end: 40010,
        },
    );
    let root = proc_net(&dir, &[], &[]);
    let header = "  sl  local_address rem_address   st tx_queue rx_queue\n";
    // A resolver query from ephemeral port 40005 to 8.8.8.8:53 (state 01,
    // connected) and a TCP connection in TIME_WAIT on 40006.
    let udp = format!("{header}   0: 0100007F:9C45 08080808:0035 01 0\n");
    let tcp_rows = format!("{header}   0: 0100007F:9C46 08080808:01BB 06 0\n");
    fs::write(root.join("proc/net/udp"), &udp).unwrap();
    fs::write(root.join("proc/net/tcp"), &tcp_rows).unwrap();
    check_live_ports(&root, &state).unwrap();
    // The same port unconnected (a server socket) is busy, IPv6 too.
    let udp6 = format!(
        "{header}   0: 00000000000000000000000000000000:9C45 00000000000000000000000000000000:0000 07 0\n"
    );
    fs::write(root.join("proc/net/udp6"), udp6).unwrap();
    assert_eq!(
        check_live_ports(&root, &state).unwrap_err().to_string(),
        "FRP 端口 40005/udp 已被其他进程占用"
    );
}
