use super::*;
use crate::domain::fixtures::config;
use crate::domain::ports::PortPlan;
use crate::domain::protocol::{Core, Protocol};
use crate::paths::Paths;
use crate::sys::fs::TempDir;
use serde_json::Value;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// The spec H §3.3 example (v2 shape, web mode, single domain).
fn v2_web_json() -> String {
    format!(
        r#"{{
  "mode": "web",
  "domain": "frp.example.com",
  "bind_addr": "::",
  "bind_port": 7000,
  "http_port": 7080,
  "https_port": 443,
  "redirect_port": 80,
  "web_domain": "app.example.com",
  "subdomain_host": "",
  "range_start": 20000,
  "range_end": 20100,
  "token": "{TOKEN}",
  "tls_method": "http",
  "cert_input": "",
  "key_input": "",
  "version": "0.71.0"
}}"#
    )
}

fn v2_web() -> V2Config {
    serde_json::from_str(&v2_web_json()).unwrap()
}

/// v2 tcp mode keeps (and ignores) its web defaults.
fn v2_tcp() -> V2Config {
    V2Config {
        mode: "tcp".into(),
        web_domain: String::new(),
        bind_addr: "0.0.0.0".into(),
        ..v2_web()
    }
}

/// What v1 `_frps_save` wrote (`printf '%s=%s\n'` for every key).
fn v1_state_conf() -> String {
    format!(
        "FRPS_MODE=tcp\nFRPS_DOMAIN=frp.example.com\nFRPS_BIND_ADDR=::\nFRPS_BIND_PORT=7000\n\
         FRPS_HTTP_PORT=7080\nFRPS_HTTPS_PORT=443\nFRPS_REDIRECT_PORT=80\nFRPS_WEB_DOMAIN=\n\
         FRPS_SUBDOMAIN_HOST=\nFRPS_RANGE_START=20000\nFRPS_RANGE_END=20100\nFRPS_TOKEN={TOKEN}\n\
         FRPS_TLS_METHOD=http\nFRPS_CERT_INPUT=\nFRPS_KEY_INPUT=\nFRPS_VERSION=0.71.0\n"
    )
}

fn web_state() -> FrpState {
    v2_web().into_state().unwrap()
}

struct Layout {
    _dir: TempDir,
    paths: Paths,
}

fn layout() -> Layout {
    let dir = TempDir::new("frp-model").unwrap();
    let paths = Paths::isolated(dir.path());
    fs::create_dir_all(&paths.frp_root).unwrap();
    Layout { _dir: dir, paths }
}

fn write(path: &Path, content: &str) {
    fs::write(path, content).unwrap();
}

fn managed(paths: &Paths) {
    write(&managed_path(paths), "Managed by Onebox FRP\n");
}

#[test]
fn reads_the_v2_shape() {
    let state = parse_state_json(v2_web_json().as_bytes()).unwrap();
    assert_eq!(state.schema, SCHEMA);
    assert_eq!(state.domain, "frp.example.com");
    assert_eq!(state.bind_addr, BindAddr::AnyV6);
    assert_eq!(state.bind_port, 7000);
    assert_eq!(state.range(), None, "web mode has no forwarding range");
    assert_eq!(state.token, TOKEN);
    assert_eq!(state.version, "0.71.0");
    assert_eq!(
        state.mode,
        Mode::Web(WebSettings::new(
            AppDomain::Single {
                domain: "app.example.com".into()
            },
            WebTls::Http01
        ))
    );
    let tcp = v2_tcp().into_state().unwrap();
    assert_eq!(tcp.mode, Mode::tcp());
    assert_eq!(tcp.range(), Some(DEFAULT_RANGE));
    assert_eq!(tcp.bind_addr, BindAddr::AnyV4);
}

#[test]
fn the_v2_shape_requires_exactly_its_16_fields() {
    let mut doc: Value = serde_json::from_str(&v2_web_json()).unwrap();
    doc["extra"] = 1.into();
    assert!(parse_state_json(&serde_json::to_vec(&doc).unwrap()).is_err());
    let mut doc: Value = serde_json::from_str(&v2_web_json()).unwrap();
    doc.as_object_mut().unwrap().remove("key_input");
    assert!(parse_state_json(&serde_json::to_vec(&doc).unwrap()).is_err());
    let mut doc: Value = serde_json::from_str(&v2_web_json()).unwrap();
    doc["bind_port"] = 70000.into();
    assert!(parse_state_json(&serde_json::to_vec(&doc).unwrap()).is_err());
}

#[test]
fn v2_conversions_round_trip() {
    let wildcard = V2Config {
        web_domain: String::new(),
        subdomain_host: "apps.example.com".into(),
        tls_method: "cf".into(),
        redirect_port: 0,
        ..v2_web()
    };
    let custom = V2Config {
        tls_method: "custom".into(),
        cert_input: "/root/cert.pem".into(),
        key_input: "/root/key.pem".into(),
        https_port: 8443,
        ..v2_web()
    };
    for v2 in [v2_web(), v2_tcp(), wildcard, custom] {
        let state = v2.clone().into_state().unwrap();
        assert_eq!(V2Config::from_state(&state), v2);
    }
    // Domains are lower-cased (DNS is case-insensitive; v3 checks lower case).
    let upper = V2Config {
        domain: "FRP.Example.COM".into(),
        web_domain: "App.Example.com".into(),
        ..v2_web()
    };
    let state = upper.into_state().unwrap();
    assert_eq!(state.domain, "frp.example.com");
    assert_eq!(state.web().unwrap().app.cert_domains(), ["app.example.com"]);
    // A web-mode range means nothing: it is dropped, and v2's shape gets
    // v2's default back.
    let custom_range = V2Config {
        range_start: 30000,
        range_end: 30100,
        ..v2_web()
    };
    let state = custom_range.into_state().unwrap();
    assert_eq!(state.range(), None);
    assert_eq!(V2Config::from_state(&state), v2_web());
    // A tcp range is kept.
    let tcp = V2Config {
        range_start: 30000,
        range_end: 30999,
        ..v2_tcp()
    };
    let state = tcp.clone().into_state().unwrap();
    assert_eq!(
        state.mode,
        Mode::Tcp {
            range: PortRange {
                start: 30000,
                end: 30999
            }
        }
    );
    assert_eq!(V2Config::from_state(&state), tcp);
}

#[test]
fn v2_validation_messages() {
    let ports = "FRP 端口无效，转发范围必须为 1 至 1000 个端口";
    let overlap = "FRP 监听端口重复或落在转发范围内";
    let http01 = "HTTP-01 要求 TCP 80 且不支持泛域名；泛域名请选择 cf 或 custom";
    type Edit = fn(&mut V2Config);
    let cases: [(Edit, &str); 19] = [
        (
            |c| c.web_domain = "app\u{1b}.com".into(),
            "FRP 参数不能含控制字符",
        ),
        (|c| c.cert_input = "/x\n".into(), "FRP 参数不能含控制字符"),
        (|c| c.mode = "udp".into(), "FRP 模式应为 web 或 tcp"),
        (|c| c.bind_addr = "1.2.3.4".into(), "FRP 监听地址无效"),
        (
            |c| c.domain = "localhost".into(),
            "请设置有效的 FRP 控制域名",
        ),
        (
            |c| c.version = "0.70.9".into(),
            "FRP 版本须为 0.71.0 或更新的稳定版本",
        ),
        (
            |c| c.version = "v0.71.0".into(),
            "FRP 版本须为 0.71.0 或更新的稳定版本",
        ),
        (
            |c| c.token = TOKEN.to_uppercase(),
            "FRP token 必须为 64 位小写十六进制值",
        ),
        (
            |c| c.token = String::new(),
            "FRP token 必须为 64 位小写十六进制值",
        ),
        (|c| c.bind_port = 0, ports),
        (|c| c.https_port = 0, ports),
        (|c| c.http_port = 443, overlap),
        (|c| c.redirect_port = 7000, overlap),
        (|c| c.web_domain = "app".into(), "请设置有效应用域名"),
        (
            |c| c.subdomain_host = "apps.example.com".into(),
            "应用域名与泛域名根不能并用",
        ),
        (
            |c| c.tls_method = "dns".into(),
            "网站证书方式应为 http、cf 或 custom",
        ),
        (|c| c.redirect_port = 8080, http01),
        (
            |c| {
                c.web_domain.clear();
                c.subdomain_host = "apps.example.com".into();
            },
            http01,
        ),
        (
            |c| c.tls_method = "custom".into(),
            "自备证书需要 --cert 与 --key",
        ),
    ];
    for (edit, expected) in cases {
        let mut v2 = v2_web();
        edit(&mut v2);
        let err = v2.into_state().unwrap_err().to_string();
        assert_eq!(err, expected);
    }
    // An overlong wildcard root has its own message.
    let long_root = format!("{}.example.com", vec!["a".repeat(60); 4].join("."));
    let v2 = V2Config {
        web_domain: String::new(),
        subdomain_host: long_root,
        tls_method: "cf".into(),
        ..v2_web()
    };
    assert_eq!(
        v2.into_state().unwrap_err().to_string(),
        "请设置有效的泛域名根（不超过 238 个字符）"
    );
    // The forwarding range is checked in tcp mode only.
    let range_cases: [(Edit, &str); 4] = [
        (|c| c.range_end = 19999, ports),
        (|c| c.range_end = 21000, ports),
        (|c| c.range_start = 0, ports),
        (|c| c.bind_port = 20050, overlap),
    ];
    for (edit, expected) in range_cases {
        let mut tcp = v2_tcp();
        edit(&mut tcp);
        assert_eq!(tcp.into_state().unwrap_err().to_string(), expected);
        let mut web = v2_web();
        edit(&mut web);
        web.into_state().unwrap();
    }
    // Tcp mode ignores the web fields (and accepts `latest`).
    let tcp = V2Config {
        tls_method: "garbage".into(),
        http_port: 20050,
        version: "latest".into(),
        ..v2_tcp()
    };
    tcp.into_state().unwrap();
}

#[test]
fn schema_2_round_trip_and_format() {
    let l = layout();
    let state = web_state();
    save(&l.paths, &state).unwrap();
    let text = fs::read_to_string(state_path(&l.paths)).unwrap();
    assert!(text.ends_with("}\n"));
    let mode = fs::metadata(state_path(&l.paths))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    let doc: Value = serde_json::from_str(&text).unwrap();
    let expected = serde_json::json!({
        "schema": 2,
        "domain": "frp.example.com",
        "bind_addr": "::",
        "bind_port": 7000,
        "token": TOKEN,
        "version": "0.71.0",
        "mode": {
            "type": "web",
            "http_port": 7080,
            "https_port": 443,
            "redirect_port": 80,
            "app": {"type": "single", "domain": "app.example.com"},
            "tls": {"type": "http01"}
        }
    });
    assert_eq!(doc, expected);
    managed(&l.paths);
    assert_eq!(load(&l.paths).unwrap(), Some(state));
    for (tls, json) in [
        (
            WebTls::Cloudflare,
            serde_json::json!({"type": "cloudflare"}),
        ),
        (
            WebTls::Custom {
                cert: "/c".into(),
                key: "/k".into(),
            },
            serde_json::json!({"type": "custom", "cert": "/c", "key": "/k"}),
        ),
    ] {
        assert_eq!(serde_json::to_value(&tls).unwrap(), json);
    }
    let tcp = FrpState::new(
        "frp.example.com".into(),
        TOKEN.into(),
        BindAddr::AnyV4,
        Mode::tcp(),
    );
    save(&l.paths, &tcp).unwrap();
    let doc: Value = serde_json::from_slice(&fs::read(state_path(&l.paths)).unwrap()).unwrap();
    assert_eq!(
        doc["mode"],
        serde_json::json!({"type": "tcp", "range": "20000-20100"})
    );
    assert_eq!(doc.get("range"), None);
    assert_eq!(load(&l.paths).unwrap(), Some(tcp));
}

#[test]
fn schema_numbers_are_checked() {
    let mut doc = serde_json::to_value(web_state()).unwrap();
    doc["schema"] = 3.into();
    let err = parse_state_json(&serde_json::to_vec(&doc).unwrap()).unwrap_err();
    assert_eq!(
        err.to_string(),
        "FRP 配置由更新版本的 Onebox 写入（schema 3），请先更新程序"
    );
    for bad in [Value::from(1), Value::from("2"), Value::Null] {
        doc["schema"] = bad;
        let err = parse_state_json(&serde_json::to_vec(&doc).unwrap()).unwrap_err();
        assert_eq!(err.to_string(), "FRP 状态 schema 无效");
    }
    // A schema-2 document is validated like any other.
    doc["schema"] = 2.into();
    doc["token"] = "short".into();
    assert!(parse_state_json(&serde_json::to_vec(&doc).unwrap()).is_err());
    // `save` refuses an invalid state.
    let l = layout();
    let mut state = web_state();
    state.bind_port = 0;
    assert!(save(&l.paths, &state).is_err());
    assert!(!state_path(&l.paths).exists());
}

#[test]
fn reads_the_v1_state_conf() {
    let state = parse_state_conf(&v1_state_conf()).unwrap();
    assert_eq!(state.mode, Mode::tcp());
    assert_eq!(state.token, TOKEN, "the token is preserved");
    assert_eq!(state.bind_addr, BindAddr::AnyV6);
    assert_eq!(state.range(), Some(DEFAULT_RANGE));
    // Web mode, wildcard with Cloudflare, CRLF line ends, blank lines.
    let web = v1_state_conf()
        .replace("FRPS_MODE=tcp", "FRPS_MODE=web")
        .replace(
            "FRPS_SUBDOMAIN_HOST=\n",
            "FRPS_SUBDOMAIN_HOST=apps.example.com\n\n",
        )
        .replace("FRPS_TLS_METHOD=http", "FRPS_TLS_METHOD=cf")
        .replace('\n', "\r\n");
    let state = parse_state_conf(&web).unwrap();
    assert_eq!(
        state.web().unwrap().app,
        AppDomain::Wildcard {
            root: "apps.example.com".into()
        }
    );
    assert_eq!(state.web().unwrap().tls, WebTls::Cloudflare);
}

#[test]
fn hostile_state_conf_is_refused_as_data() {
    let base = v1_state_conf();
    let cases = [
        // Shell syntax is never interpreted.
        (
            base.replace("FRPS_DOMAIN=frp.example.com", "FRPS_DOMAIN=$(reboot)"),
            "请设置有效的 FRP 控制域名",
        ),
        (
            base.replace("FRPS_MODE=tcp", "FRPS_MODE='tcp'"),
            "FRP 模式应为 web 或 tcp",
        ),
        (
            base.replace("FRPS_MODE=tcp", "export FRPS_MODE=tcp"),
            "旧 FRP 状态含未知键",
        ),
        (format!("# comment\n{base}"), "旧 FRP 状态格式无效"),
        (format!("{base}FRPS_EVIL=1\n"), "旧 FRP 状态含未知键"),
        (
            base.replace("FRPS_MODE=tcp", "FRPS_MODE =tcp"),
            "旧 FRP 状态含未知键",
        ),
        (
            format!("{base}FRPS_MODE=web\n"),
            "旧 FRP 状态含重复键 FRPS_MODE",
        ),
        (
            base.replace(
                "FRPS_DOMAIN=frp.example.com",
                "FRPS_DOMAIN=frp.example.com\u{1b}[2J",
            ),
            "旧 FRP 状态 FRPS_DOMAIN 含控制字符",
        ),
        (
            base.replace("FRPS_TOKEN=", "FRPS_TOKEN=\r"),
            "旧 FRP 状态 FRPS_TOKEN 含控制字符",
        ),
        (
            base.replace("FRPS_VERSION=0.71.0\n", ""),
            "旧 FRP 状态缺少 FRPS_VERSION",
        ),
        (
            base.replace("FRPS_BIND_PORT=7000", "FRPS_BIND_PORT=seven"),
            "旧 FRP 状态 FRPS_BIND_PORT 不是有效端口",
        ),
        (
            base.replace("FRPS_RANGE_END=20100", "FRPS_RANGE_END=70000"),
            "旧 FRP 状态 FRPS_RANGE_END 不是有效端口",
        ),
        (
            base.replace("FRPS_DOMAIN=frp.example.com", "FRPS_DOMAIN=a=b.com"),
            "请设置有效的 FRP 控制域名",
        ),
        (
            base.replace(&format!("FRPS_TOKEN={TOKEN}"), "FRPS_TOKEN="),
            "FRP token 必须为 64 位小写十六进制值",
        ),
        (String::new(), "旧 FRP 状态缺少 FRPS_MODE"),
    ];
    for (text, expected) in cases {
        let err = parse_state_conf(&text).unwrap_err().to_string();
        assert_eq!(err, expected, "{text:?}");
    }
}

#[test]
fn installed_needs_the_marker_and_a_state_file() {
    let l = layout();
    let paths = &l.paths;
    assert!(!installed(paths));
    write(&state_path(paths), &v2_web_json());
    assert!(!installed(paths), "state without .managed");
    managed(paths);
    assert!(installed(paths));
    fs::remove_file(state_path(paths)).unwrap();
    assert!(!installed(paths), ".managed without state");
    write(&legacy_state_path(paths), &v1_state_conf());
    assert!(installed(paths), "v1 state.conf counts");
    fs::remove_file(managed_path(paths)).unwrap();
    symlink(legacy_state_path(paths), managed_path(paths)).unwrap();
    assert!(!installed(paths), "a symlinked marker does not count");
    fs::remove_file(managed_path(paths)).unwrap();
    fs::create_dir(managed_path(paths)).unwrap();
    assert!(!installed(paths), "a marker directory does not count");
}

#[test]
fn load_prefers_state_json_and_names_the_broken_file() {
    let l = layout();
    let paths = &l.paths;
    assert_eq!(load(paths).unwrap(), None);
    managed(paths);
    write(&legacy_state_path(paths), &v1_state_conf());
    assert_eq!(load(paths).unwrap().unwrap().mode, Mode::tcp());
    write(&state_path(paths), &v2_web_json());
    assert!(load(paths).unwrap().unwrap().is_web(), "state.json wins");
    write(&state_path(paths), "{");
    let err = load(paths).unwrap_err().to_string();
    let prefix = format!("FRP 状态 {} 无效", state_path(paths).display());
    assert!(err.starts_with(&prefix), "{err}");
    fs::File::create(state_path(paths))
        .unwrap()
        .set_len(MAX_STATE_BYTES + 1)
        .unwrap();
    assert_eq!(
        load(paths).unwrap_err().to_string(),
        format!("{prefix}: FRP 状态文件异常大")
    );
    fs::remove_file(state_path(paths)).unwrap();
    symlink(legacy_state_path(paths), state_path(paths)).unwrap();
    let err = load(paths).unwrap_err().to_string();
    assert!(err.contains("不允许符号链接"), "{err}");
    fs::remove_file(state_path(paths)).unwrap();
    fs::write(legacy_state_path(paths), [0xff, 0xfe]).unwrap();
    assert!(load(paths)
        .unwrap_err()
        .to_string()
        .ends_with("旧 FRP 状态不是 UTF-8"));
}

fn spans(reservations: &[Reservation]) -> Vec<(u16, u16, Transport)> {
    reservations
        .iter()
        .map(|r| (r.start, r.end, r.transport))
        .collect()
}

#[test]
fn reservations_per_mode() {
    let web = web_state();
    assert_eq!(
        spans(&web.reservations()),
        [
            (7000, 7000, Transport::Tcp),
            (7080, 7080, Transport::Tcp),
            (443, 443, Transport::Tcp),
            (80, 80, Transport::Tcp)
        ],
        "no forwarding range in web mode"
    );
    assert_eq!(web.reservations()[0].label, "控制端口");
    let mut no_redirect = web.clone();
    if let Mode::Web(w) = &mut no_redirect.mode {
        w.redirect_port = 0;
        w.tls = WebTls::Cloudflare;
    }
    assert_eq!(no_redirect.reservations().len(), 3);
    let tcp = v2_tcp().into_state().unwrap();
    assert_eq!(
        spans(&tcp.reservations()),
        [
            (7000, 7000, Transport::Tcp),
            (20000, 20100, Transport::Both)
        ]
    );
    assert_eq!(tcp.reservations()[1].label, "转发端口");
    assert_eq!(
        tcp.firewall_ports(),
        [
            (7000, 7000, Transport::Tcp),
            (20000, 20100, Transport::Both)
        ]
    );
    assert_eq!(
        web.firewall_ports(),
        [
            (7000, 7000, Transport::Tcp),
            (443, 443, Transport::Tcp),
            (80, 80, Transport::Tcp)
        ]
    );
}

#[test]
fn reservations_from_disk() {
    let l = layout();
    let paths = &l.paths;
    assert!(reservations(paths).unwrap().is_empty(), "not installed");
    write(&state_path(paths), "garbage");
    assert!(
        reservations(paths).unwrap().is_empty(),
        "no .managed: not installed"
    );
    managed(paths);
    let err = reservations(paths).unwrap_err().to_string();
    assert!(
        err.starts_with("FRP 状态"),
        "a corrupt state names FRP: {err}"
    );
    write(&legacy_state_path(paths), &v1_state_conf());
    fs::remove_file(state_path(paths)).unwrap();
    assert_eq!(reservations(paths).unwrap().len(), 2);
}

#[test]
fn node_ports_inside_an_unused_web_range_are_allowed() {
    // H-8.1#8: a web-mode FRP no longer blocks 20000–20100 for the node.
    let cfg = config(&[(Protocol::Hysteria2, 20050, Core::Singbox)]);
    PortPlan::of(&cfg, &web_state().reservations())
        .validate()
        .unwrap();
    let tcp = v2_tcp().into_state().unwrap();
    let err = PortPlan::of(&cfg, &tcp.reservations())
        .validate()
        .unwrap_err();
    assert_eq!(err.to_string(), "端口 20050/udp 已保留给 FRP");
}

#[test]
fn versions_and_bind_addresses() {
    for (version, ok) in [
        ("latest", true),
        ("0.71.0", true),
        ("0.71.10", true),
        ("0.100.0", true),
        ("0.70.99", false),
        ("1.0.0", false),
        ("0.71", false),
        ("0.71.0.1", false),
        ("0.71.x", false),
        ("", false),
        ("0.71.0-rc1", false),
    ] {
        assert_eq!(check_version(version).is_ok(), ok, "{version}");
    }
    for addr in BindAddr::ALL {
        assert_eq!(BindAddr::parse(addr.as_str()), Some(addr));
        assert_eq!(serde_json::to_value(addr).unwrap(), addr.to_string());
    }
    assert_eq!(BindAddr::parse("[::]"), None);
    assert_eq!(BindAddr::default_for(true), BindAddr::AnyV6);
    assert_eq!(BindAddr::default_for(false), BindAddr::AnyV4);
    assert!(serde_json::from_str::<BindAddr>("\"1.1.1.1\"").is_err());
}

#[test]
fn drafts_may_lack_the_token() {
    let mut draft = web_state();
    draft.token.clear();
    draft.validate_draft().unwrap();
    assert!(draft.validate().is_err());
    draft.token = "zz".into();
    assert!(draft.validate_draft().is_err());
}

fn installed_with(paths: &Paths, file: &Path, content: &str) {
    managed(paths);
    write(file, content);
}

#[test]
fn ip_literal_domains_v2_accepted_stay_readable() {
    // v2's `valid_domain` accepted IP literals: such hosts must keep working
    // (ARCH §10), with a notice, and node port planning must not break.
    let l = layout();
    let paths = &l.paths;
    let ip_v2 = v2_web_json().replace("frp.example.com", "203.0.113.5");
    installed_with(paths, &state_path(paths), &ip_v2);
    let state = load(paths).unwrap().unwrap();
    assert_eq!(state.domain, "203.0.113.5");
    assert_eq!(
        state.warnings(),
        ["FRP 控制域名 203.0.113.5 不是有效域名（v2 曾允许 IP 地址），frpc 无法校验服务端证书；请通过 onebox frps 重新配置为域名"]
    );
    assert_eq!(
        spans(&reservations(paths).unwrap()),
        [
            (7000, 7000, Transport::Tcp),
            (7080, 7080, Transport::Tcp),
            (443, 443, Transport::Tcp),
            (80, 80, Transport::Tcp)
        ]
    );
    // Saving it unchanged (the lazy schema-2 migration) keeps it readable.
    save(paths, &state).unwrap();
    let saved = load(paths).unwrap().unwrap();
    assert_eq!(saved, state);
    assert!(fs::read_to_string(state_path(paths))
        .unwrap()
        .contains("\"schema\": 2"));
    // A changed domain must be a DNS name.
    let mut other_ip = state.clone();
    other_ip.domain = "198.51.100.7".into();
    assert_eq!(
        save(paths, &other_ip).unwrap_err().to_string(),
        "FRP 控制域名必须是域名，不能是 IP 地址: 198.51.100.7"
    );
    assert_eq!(load(paths).unwrap().unwrap(), state, "nothing written");
    let mut fixed = state.clone();
    fixed.domain = "frp.example.com".into();
    save(paths, &fixed).unwrap();
    assert!(load(paths).unwrap().unwrap().warnings().is_empty());
    // New input never accepts an IP literal.
    assert!(state.validate_change(None).is_err());
    let mut draft = state.clone();
    draft.token.clear();
    assert_eq!(
        draft.validate_draft().unwrap_err().to_string(),
        "FRP 控制域名必须是域名，不能是 IP 地址: 203.0.113.5"
    );
    // v1 state.conf with an IP control domain.
    fs::remove_file(state_path(paths)).unwrap();
    let conf = v1_state_conf().replace("FRPS_DOMAIN=frp.example.com", "FRPS_DOMAIN=203.0.113.5");
    write(&legacy_state_path(paths), &conf);
    assert_eq!(load(paths).unwrap().unwrap().domain, "203.0.113.5");
    assert_eq!(reservations(paths).unwrap().len(), 2);
}

#[test]
fn ip_literal_application_names_are_kept_only_while_unchanged() {
    let single = V2Config {
        web_domain: "203.0.113.9".into(),
        ..v2_web()
    };
    let state = single.into_state().unwrap();
    assert_eq!(state.warnings().len(), 1);
    assert!(state.warnings()[0].starts_with("FRP 应用域名 203.0.113.9 不是有效域名"));
    state.validate_change(Some(&state)).unwrap();
    assert_eq!(
        state.validate_change(None).unwrap_err().to_string(),
        "FRP 应用域名必须是域名，不能是 IP 地址: 203.0.113.9"
    );
    // The same value in another field is a change.
    let mut moved = state.clone();
    moved.domain = "203.0.113.9".into();
    if let Mode::Web(web) = &mut moved.mode {
        web.app = AppDomain::Single {
            domain: "app.example.com".into(),
        };
    }
    assert_eq!(
        moved.validate_change(Some(&state)).unwrap_err().to_string(),
        "FRP 控制域名必须是域名，不能是 IP 地址: 203.0.113.9"
    );
    let wildcard = V2Config {
        web_domain: String::new(),
        subdomain_host: "apps.123".into(),
        tls_method: "cf".into(),
        ..v2_web()
    };
    let state = wildcard.into_state().unwrap();
    assert!(state.warnings()[0].starts_with("FRP 泛域名根 apps.123"));
    assert!(state.validate_change(None).is_err());
    // v2 never accepted these, and neither does v3.
    for bad in ["localhost", "1.2.3.", "-a.com", "a..b"] {
        let v2 = V2Config {
            domain: bad.into(),
            ..v2_web()
        };
        assert_eq!(
            v2.into_state().unwrap_err().to_string(),
            "请设置有效的 FRP 控制域名",
            "{bad}"
        );
    }
}

#[test]
fn reservations_need_only_the_port_fields() {
    let l = layout();
    let paths = &l.paths;
    let web4 = 4;
    // A v2 state with problems outside its ports: load refuses it, port
    // planning still gets FRP's ports.
    let broken = v2_web_json()
        .replace(TOKEN, "short")
        .replace("\"version\": \"0.71.0\"", "\"version\": \"garbage\"")
        .replace("\"tls_method\": \"http\"", "\"tls_method\": \"dns\"");
    installed_with(paths, &state_path(paths), &broken);
    assert!(load(paths).is_err());
    assert_eq!(reservations(paths).unwrap().len(), web4);
    // Schema 2 likewise (unknown members, bad bind address, no token).
    let mut doc = serde_json::to_value(web_state()).unwrap();
    doc["bind_addr"] = "1.1.1.1".into();
    doc.as_object_mut().unwrap().remove("token");
    doc["future"] = true.into();
    write(&state_path(paths), &doc.to_string());
    assert!(load(paths).is_err());
    assert_eq!(reservations(paths).unwrap().len(), web4);
    // v1 state.conf with a bad token.
    fs::remove_file(state_path(paths)).unwrap();
    let conf = v1_state_conf().replace(&format!("FRPS_TOKEN={TOKEN}"), "FRPS_TOKEN=x");
    write(&legacy_state_path(paths), &conf);
    assert!(load(paths).is_err());
    assert_eq!(
        spans(&reservations(paths).unwrap()),
        [
            (7000, 7000, Transport::Tcp),
            (20000, 20100, Transport::Both)
        ]
    );
    fs::remove_file(legacy_state_path(paths)).unwrap();
    // Broken port fields are errors naming the FRP state file.
    let prefix = format!("FRP 状态 {} 无效: ", state_path(paths).display());
    let cases = [
        (
            v2_web_json().replace("\"bind_port\": 7000", "\"bind_port\": 0"),
            "FRP 端口无效，转发范围必须为 1 至 1000 个端口",
        ),
        (
            v2_web_json().replace("\"https_port\": 443", "\"https_port\": 7000"),
            "FRP 监听端口重复或落在转发范围内",
        ),
        (
            v2_web_json().replace("\"mode\": \"web\"", "\"mode\": \"udp\""),
            "FRP 模式应为 web 或 tcp",
        ),
        (
            serde_json::json!({"schema": 3}).to_string(),
            "FRP 配置由更新版本的 Onebox 写入（schema 3），请先更新程序",
        ),
    ];
    for (text, detail) in cases {
        write(&state_path(paths), &text);
        let err = reservations(paths).unwrap_err().to_string();
        assert_eq!(err, format!("{prefix}{detail}"));
    }
    let mut doc = serde_json::to_value(FrpState::new(
        "frp.example.com".into(),
        TOKEN.into(),
        BindAddr::AnyV4,
        Mode::tcp(),
    ))
    .unwrap();
    doc["mode"].as_object_mut().unwrap().remove("range");
    write(&state_path(paths), &doc.to_string());
    let err = reservations(paths).unwrap_err().to_string();
    assert!(err.starts_with(&prefix), "{err}");
}
