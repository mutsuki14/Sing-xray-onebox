use super::*;
use crate::diag::fixture::{check, two_core_config, Node, NOW};
use crate::diag::redact::contains_ip;
use crate::diag::CheckStatus;
use crate::domain::config::ProxyTls;
use crate::domain::fixtures;
use crate::sys::exec::Output;
use crate::sys::fs::TempDir;
use crate::sys::rand::SeqRandom;
use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt;

fn report_of(node: &Node, extra: &[CheckFn]) -> SupportReport {
    let doctor = node.doctor();
    let diagnosis = doctor.diagnose(extra, &mut |_| {}).unwrap();
    SupportReport::build(&doctor, &diagnosis)
}

#[test]
fn healthy_report_contents() {
    let node = Node::healthy();
    let report = report_of(&node, &[]);
    assert_eq!(report.schema, SUPPORT_SCHEMA);
    assert_eq!(report.program_version, crate::VERSION);
    assert_eq!(report.generated_at, NOW);
    assert_eq!(report.state, "v3");
    assert_eq!(report.note, SUPPORT_NOTE);
    assert!(!report.pending_recovery);
    assert!(!report.operation_running);
    assert_eq!(
        report.protocols,
        [
            ProtocolRow {
                core: "singbox",
                network: "tcp",
                port: 443,
                protocol: "vless-reality"
            },
            ProtocolRow {
                core: "singbox",
                network: "udp",
                port: 8443,
                protocol: "hysteria2"
            },
            ProtocolRow {
                core: "xray",
                network: "tcp",
                port: 2053,
                protocol: "vless-xhttp"
            },
        ]
    );
    assert_eq!(
        report.cores,
        [
            CoreRow {
                core: "singbox",
                pinned: false,
                running: true,
                version: Some("1.14.2".into())
            },
            CoreRow {
                core: "xray",
                pinned: false,
                running: true,
                version: Some("26.3.27".into())
            },
        ]
    );
    assert_eq!(
        report.certificates,
        CertModes {
            proxy: Some("self-signed"),
            site: None,
            subscription: None
        }
    );
    assert_eq!(report.features, Features::default());
    assert_eq!(report.host.arch.as_deref(), Some("x86_64"));
    assert_eq!(report.host.kernel.as_deref(), Some("6.1.0-18-amd64"));
    assert_eq!(report.host.init, "systemd");
    assert!(report.checks.iter().all(|c| c.status == CheckStatus::Pass));
    assert_eq!(report.checks.len(), node.diagnose().checks.len());
}

#[test]
fn json_has_sorted_keys_and_a_trailing_newline() {
    let report = report_of(&Node::healthy(), &[]);
    let text = report.to_json().unwrap();
    assert!(text.ends_with("}\n") && !text.ends_with("\n\n"));
    let doc: Value = serde_json::from_str(&text).unwrap();
    let top: Vec<&String> = doc.as_object().unwrap().keys().collect();
    assert_eq!(
        top,
        [
            "certificates",
            "checks",
            "cores",
            "features",
            "generated_at",
            "host",
            "note",
            "operation_running",
            "pending_recovery",
            "program_version",
            "protocols",
            "schema",
            "state"
        ]
    );
    // Keys appear in sorted order in the text itself, not only in the parse.
    let host = text.find("\"host\"").unwrap();
    assert!(text[host..].find("\"arch\"").unwrap() < text[host..].find("\"init\"").unwrap());
    assert_eq!(doc["checks"][0]["status"], "pass");
    assert_eq!(doc["checks"][0]["name"], "节点配置");
}

#[test]
fn reports_are_private_exclusive_and_collision_free() {
    let dir = TempDir::new("diag-support").unwrap();
    let root = dir.join("etc");
    let mut rng = SeqRandom(0);
    let first = write_report(&root, 1_700_000_000, "{}\n", &mut rng).unwrap();
    assert_eq!(
        first.file_name().unwrap().to_str().unwrap(),
        "support-1700000000-000102030405.json"
    );
    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&first), 0o600);
    assert_eq!(mode(&root), 0o700, "a missing root is created private");
    assert_eq!(fs::read_to_string(&first).unwrap(), "{}\n");

    // The same second and the same random suffix: the next name is used,
    // the existing file is untouched.
    let mut replay = SeqRandom(0);
    let second = write_report(&root, 1_700_000_000, "{\"b\":1}\n", &mut replay).unwrap();
    assert_ne!(first, second);
    assert_eq!(
        second.file_name().unwrap().to_str().unwrap(),
        "support-1700000000-060708090a0b.json"
    );
    assert_eq!(fs::read_to_string(&first).unwrap(), "{}\n");
    assert_eq!(report_name(5, "ab"), "support-5-ab.json");
}

#[test]
fn write_support_creates_the_report_under_root() {
    let node = Node::healthy();
    let path = write_support(&node.doctor(), &[]).unwrap();
    assert_eq!(path.parent(), Some(node.ctx.paths.root.as_path()));
    let name = path.file_name().unwrap().to_str().unwrap();
    assert!(name.starts_with(&format!("support-{NOW}-")) && name.ends_with(".json"));
    let doc: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(doc["state"], "v3");
}

fn leaky_provider(_: &Doctor, cfg: Option<&NodeConfig>) -> Vec<Check> {
    let Some(cfg) = cfg else {
        return vec![];
    };
    vec![Check::fail(
        "订阅 sub.example.org",
        format!(
            "token {} for https://sub.example.org/ from 192.0.2.99 and [2001:db8::99]",
            cfg.creds.uuid
        ),
    )]
}

#[test]
fn reports_never_contain_credentials_addresses_or_domains() {
    let mut cfg = fixtures::with_site(two_core_config(), "blog.example.org", false);
    cfg.server.addr = "node.example.net".parse().unwrap();
    cfg.routing.own_cidrs = vec!["198.51.100.20/32".into()];
    cfg.tls = Some(ProxyTls {
        mode: crate::domain::config::ProxyCertMode::Acme {
            domain: "proxy.example.net".into(),
            method: crate::domain::config::AcmeMethod::Cloudflare,
        },
        pinned: false,
    });
    let node = Node::new(cfg.clone());
    node.fake.on(
        "sing-box",
        &["check"],
        Output::failure(
            1,
            "FATAL[0000] start inbound: listen tcp 203.0.113.10:443: bind: address already in use; dest blog.example.org:443 node.example.net",
        ),
    );
    let node = node.finish();
    let report = report_of(&node, &[leaky_provider]);
    let text = report.to_json().unwrap();
    let keys = cfg.creds.reality.clone().unwrap();
    for secret in [
        cfg.creds.uuid.as_str(),
        cfg.creds.password.as_str(),
        cfg.creds.hy2_obfs_password.as_str(),
        cfg.creds.clash_secret.as_str(),
        keys.private_key.as_str(),
        keys.short_id.as_str(),
        "node.example.net",
        "blog.example.org",
        "proxy.example.net",
        "sub.example.org",
        "example",
    ] {
        assert!(!text.contains(secret), "{secret} leaked:\n{text}");
    }
    assert!(!contains_ip(&text), "{text}");
    let core = report
        .checks
        .iter()
        .find(|c| c.name == "sing-box 配置")
        .unwrap();
    assert_eq!(core.status, CheckStatus::Fail);
    assert!(
        core.detail
            .contains("listen tcp <ip>:443: bind: address already in use"),
        "{core:?}"
    );
    let extra = report.checks.last().unwrap();
    assert_eq!(extra.name, "订阅 <domain>");
    assert_eq!(
        extra.detail,
        "token <secret> for https://<domain>/ from <ip> and [<ip>]"
    );
    assert_eq!(report.certificates.proxy, Some("acme-cloudflare"));
    assert_eq!(report.certificates.site, Some("acme-http01"));
    assert!(report.features.site);
}

#[test]
fn long_details_are_capped() {
    let check = Check::warn("x", "长".repeat(DETAIL_MAX + 10));
    let redacted = redact_check(&Redactor::new(), &check);
    assert_eq!(redacted.detail.chars().count(), DETAIL_MAX + 1);
    assert!(redacted.detail.ends_with('…'));
    let short = Check::pass("x", "短");
    assert_eq!(redact_check(&Redactor::new(), &short), short);
}

#[test]
fn a_corrupt_journal_marks_recovery_pending() {
    let node = Node::healthy();
    let dir = node.ctx.paths.transaction();
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("journal.json"), "[").unwrap();
    assert!(report_of(&node, &[]).pending_recovery);
}

#[test]
fn failing_host_probes_leave_fields_empty() {
    let node = Node::new(two_core_config());
    node.fake
        .on("uname", &[], Output::failure(1, "uname: boom"));
    let node = node.finish();
    let doc = node.ctx.paths.system("/etc/os-release");
    fs::create_dir_all(doc.parent().unwrap()).unwrap();
    fs::write(&doc, "ID=debian\nVERSION_ID=\"12\"\n").unwrap();
    let host = HostInfo::detect(&node.doctor());
    assert_eq!(
        host,
        HostInfo {
            arch: None,
            container: None,
            init: "systemd",
            kernel: None,
            os: Some("debian".into()),
            version: Some("12".into()),
            virtualization: None,
            wsl: false,
        }
    );
}

#[test]
fn feature_flags_and_certificate_methods() {
    let mut cfg = fixtures::config(&[(
        crate::domain::Protocol::Tuic,
        443,
        crate::domain::Core::Singbox,
    )]);
    assert_eq!(
        Features::of(Some(&cfg), true),
        Features {
            frp: true,
            ..Features::default()
        }
    );
    cfg.subscription = Some(fixtures::ip_subscription(8448));
    let ip = Features::of(Some(&cfg), false);
    assert!(ip.subscription && !ip.site);
    assert_eq!(ip.subscription_mode, Some("ip"));
    cfg.subscription = Some(fixtures::standalone_subscription(
        "sub.example.org",
        8448,
        crate::domain::config::WebCert::Custom {
            cert: "/c.pem".into(),
            key: "/k.pem".into(),
        },
    ));
    assert_eq!(
        Features::of(Some(&cfg), false).subscription_mode,
        Some("standalone")
    );
    assert_eq!(
        CertModes::of(&cfg),
        CertModes {
            proxy: Some("self-signed"),
            site: None,
            subscription: Some("custom"),
        }
    );
    assert_eq!(Features::of(None, false), Features::default());
}

/// The report of `node` with its `state.json` edited by `edit`.
fn report_with_state(edit: impl FnOnce(&mut Value)) -> (SupportReport, String) {
    let node = Node::healthy();
    let path = node.ctx.paths.state();
    let mut doc: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    edit(&mut doc);
    fs::write(&path, serde_json::to_string(&doc).unwrap()).unwrap();
    let report = report_of(&node, &[]);
    let text = report.to_json().unwrap();
    (report, text)
}

fn state_line(report: &SupportReport) -> &Check {
    report.checks.iter().find(|c| c.name == "节点配置").unwrap()
}

#[test]
fn an_invalid_state_never_leaks_the_values_its_error_echoes() {
    let (report, text) = report_with_state(|doc| {
        doc["creds"]["ws_path"] = Value::from("/s3cret path");
    });
    assert_eq!(report.state, "invalid");
    let line = state_line(&report);
    assert_eq!(line.status, CheckStatus::Fail);
    assert_eq!(line.detail, "state.json 校验失败: WS 路径无效: <secret>");
    assert!(!text.contains("s3cret"), "{text}");

    let (report, text) = report_with_state(|doc| {
        doc["creds"]["password"] = Value::from(12_345_678);
    });
    let line = state_line(&report);
    assert!(line.detail.contains("integer `<secret>`"), "{line:?}");
    assert!(!text.contains("12345678"), "{text}");
}

#[test]
fn an_unparseable_state_shows_no_error_text() {
    let node = Node::healthy();
    fs::write(node.ctx.paths.state(), "uuid 0b5c6a1e s3cret\n").unwrap();
    let report = report_of(&node, &[]);
    assert_eq!(state_line(&report), &Check::fail("节点配置", UNREADABLE));
    // doctor itself still prints the real error.
    let printed = check(&node.diagnose().checks, "节点配置").clone();
    assert!(printed.detail.starts_with("state.json 无效"), "{printed:?}");
}

#[test]
fn a_v1_only_install_keeps_its_upgrade_message() {
    let node = Node::healthy();
    fs::remove_file(node.ctx.paths.state()).unwrap();
    fs::write(node.ctx.paths.legacy_v1_state(), "X=1\n").unwrap();
    let report = report_of(&node, &[]);
    assert!(
        state_line(&report)
            .detail
            .starts_with("检测到 Onebox 1.x 配置"),
        "{report:?}"
    );
}

#[test]
fn an_invalid_frp_state_never_leaks_its_values() {
    let node = Node::healthy();
    let root = &node.ctx.paths.frp_root;
    fs::create_dir_all(root).unwrap();
    fs::write(root.join(".managed"), "").unwrap();
    fs::write(
        root.join("state.json"),
        r#"{"schema": 2, "domain": "frp.example.org", "token": 87654321}"#,
    )
    .unwrap();
    let text = report_of(&node, &[]).to_json().unwrap();
    assert!(
        !text.contains("87654321") && !text.contains("example"),
        "{text}"
    );

    fs::remove_file(root.join("state.json")).unwrap();
    fs::write(
        root.join("state.conf"),
        "FRPS_TOKEN='tok-s3cret-1'\nFRPS_PORT=x\n",
    )
    .unwrap();
    let report = report_of(&node, &[]);
    let frp = report
        .checks
        .iter()
        .find(|c| c.name == "FRP 服务端")
        .unwrap();
    assert_eq!(frp.status, CheckStatus::Fail);
    assert!(
        !report.to_json().unwrap().contains("tok-s3cret-1"),
        "{frp:?}"
    );
}
