use super::*;
use crate::cert::testing::engine;
use crate::domain::config::{SubscriptionConfig, SubscriptionMode, WebCert};
use crate::host::init::InitSystem;
use crate::render::fixtures::spec;
use crate::subscription::testing::{
    device, ip, reality, standalone, with_subscription, Node, TOKEN,
};
use crate::subscription::{devices, snapshot};

const PID: u32 = 777;

fn by_name<'a>(checks: &'a [Check], name: &str) -> &'a Check {
    checks.iter().find(|c| c.name == name).unwrap()
}

#[test]
fn nothing_to_check_when_off() {
    let node = Node::new("sub-checks-off");
    assert!(checks_with(&engine(&node.ctx, InitSystem::Systemd), &reality()).is_empty());
}

#[test]
fn ip_mode_checks_worker_snapshot_devices_and_address() {
    let node = Node::new("sub-checks-ip");
    let systemd = node.systemd(PID);
    node.install_exe();
    node.proc_exe(PID, &node.ctx.paths.executable);
    let engine = engine(&node.ctx, InitSystem::Systemd);
    let cfg = ip(8448);
    let all = checks_with(&engine, &cfg);
    let names: Vec<&str> = all.iter().map(|c| c.name.as_str()).collect();
    // A stopped worker is the built-in service check's line.
    assert_eq!(names, [ADDRESS, SNAPSHOT, DEVICES]);
    assert_eq!(by_name(&all, ADDRESS).detail, "http://203.0.113.10:8448");
    assert_eq!(by_name(&all, SNAPSHOT).status, CheckStatus::Fail);
    assert_eq!(by_name(&all, DEVICES).status, CheckStatus::Warn);

    systemd.activate(SERVICE);
    snapshot::write(&node.ctx.paths, &snapshot::render(&spec(&cfg)).unwrap()).unwrap();
    devices::DeviceStore::write(&node.ctx.paths, &[device("00000000000000aa", "a", TOKEN)])
        .unwrap();
    let all = checks_with(&engine, &cfg);
    assert!(all.iter().all(|c| c.status == CheckStatus::Pass), "{all:?}");
    assert_eq!(by_name(&all, WORKER).detail, "运行当前安装的程序");
    assert_eq!(
        by_name(&all, SNAPSHOT).detail,
        "base64 / mihomo / provider / singbox / singbox-notun / xray"
    );
    assert_eq!(by_name(&all, DEVICES).detail, "1 个设备");

    let old = node.dir.join("old");
    std::fs::write(&old, "old").unwrap();
    node.proc_exe(PID, &old);
    let stale = checks_with(&engine, &cfg);
    assert_eq!(by_name(&stale, WORKER).status, CheckStatus::Warn);

    let anytls = with_subscription(
        crate::domain::fixtures::config(&[(
            crate::domain::protocol::Protocol::AnytlsReality,
            443,
            crate::domain::protocol::Core::Singbox,
        )]),
        crate::domain::fixtures::ip_subscription(8448),
    );
    assert_eq!(
        by_name(&checks_with(&engine, &anytls), SNAPSHOT).status,
        CheckStatus::Warn,
        "published formats no longer match the protocols"
    );
    std::fs::write(node.ctx.paths.devices(), "{").unwrap();
    assert_eq!(
        by_name(&checks_with(&engine, &cfg), DEVICES).status,
        CheckStatus::Fail
    );
}

#[test]
fn ipv6_address_without_ipv6_fails() {
    let node = Node::new("sub-checks-v6");
    node.systemd(PID);
    let cfg = with_subscription(
        reality(),
        SubscriptionConfig {
            mode: SubscriptionMode::Ip {
                address: "2001:db8::7".parse().unwrap(),
            },
            port: 8448,
        },
    );
    let all = checks_with(&engine(&node.ctx, InitSystem::Systemd), &cfg);
    assert_eq!(by_name(&all, ADDRESS).status, CheckStatus::Fail);
}

#[test]
fn standalone_service_and_certificate_are_left_to_the_built_in_checks() {
    let node = Node::new("sub-checks-standalone");
    let systemd = node.systemd(PID);
    systemd.activate(crate::subscription::WEB_SERVICE);
    let all = checks_with(
        &engine(&node.ctx, InitSystem::Systemd),
        &standalone(WebCert::Cloudflare, 8448),
    );
    let names: Vec<&str> = all.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, [ADDRESS, SNAPSHOT, DEVICES]);
}
