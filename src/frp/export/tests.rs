use super::*;
use crate::domain::config::PortRange;
use crate::frp::model::{AppDomain, BindAddr, Mode, WebSettings, WebTls};
use crate::sys::fs::TempDir;
use crate::ui::ScriptedPrompter;
use std::os::unix::fs::PermissionsExt;

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

struct Fixture {
    dir: TempDir,
    paths: Paths,
}

fn fixture() -> Fixture {
    let dir = TempDir::new("frp-export").unwrap();
    let paths = Paths::isolated(dir.path());
    fs::create_dir_all(&paths.frp_root).unwrap();
    fs::write(paths.frp_root.join("ca.pem"), "PUBLIC CA").unwrap();
    fs::write(paths.frp_root.join("ca-key.pem"), "PRIVATE CA KEY").unwrap();
    fs::write(paths.frp_root.join("server-key.pem"), "SERVER KEY").unwrap();
    Fixture { dir, paths }
}

fn web(app: AppDomain) -> FrpState {
    FrpState::new(
        "control.example.com".into(),
        TOKEN.into(),
        BindAddr::AnyV6,
        Mode::Web(WebSettings::new(app, WebTls::Http01)),
    )
}

fn single() -> FrpState {
    web(AppDomain::Single {
        domain: "app.example.com".into(),
    })
}

fn tcp() -> FrpState {
    FrpState::new(
        "control.example.com".into(),
        TOKEN.into(),
        BindAddr::AnyV4,
        Mode::Tcp {
            range: PortRange {
                start: 20000,
                end: 20010,
            },
        },
    )
}

fn request(output: &Path) -> ExportRequest {
    ExportRequest {
        output: Some(output.to_string_lossy().into_owned()),
        ..ExportRequest::default()
    }
}

#[test]
fn exports_pin_the_private_ca_and_never_overwrite() {
    let f = fixture();
    let ui = ScriptedPrompter::unattended();
    let output = f.dir.join("export");
    let req = ExportRequest {
        local_port: Some(8081),
        ..request(&output)
    };
    let written = export(&ui, &f.paths, &single(), &req, f.dir.path()).unwrap();
    assert_eq!(written, output);
    let text = fs::read_to_string(output.join("frpc.toml")).unwrap();
    assert!(text.contains("transport.tls.trustedCaFile = \"./ca.pem\""));
    assert!(text.contains("transport.tls.serverName = \"control.example.com\""));
    assert!(text.contains("localPort = 8081"));
    assert_eq!(
        fs::read_to_string(output.join("ca.pem")).unwrap(),
        "PUBLIC CA"
    );
    let names: Vec<String> = fs::read_dir(&output)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names.len(), 3, "{names:?}");
    for name in ["frpc.toml", "ca.pem", "README.txt"] {
        let mode = fs::metadata(output.join(name))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "{name}");
    }
    let dir_mode = fs::metadata(&output).unwrap().permissions().mode();
    assert_eq!(dir_mode & 0o777, 0o700);
    let readme = fs::read_to_string(output.join("README.txt")).unwrap();
    assert!(readme.contains("访问：https://app.example.com:443/"));
    // A second export to the same directory changes nothing.
    let err = export(&ui, &f.paths, &single(), &req, f.dir.path()).unwrap_err();
    assert_eq!(err.to_string(), "导出目录已存在，请选择新的目录");
    assert_eq!(fs::read_to_string(output.join("frpc.toml")).unwrap(), text);
}

#[test]
fn relative_outputs_follow_the_working_directory() {
    let f = fixture();
    let ui = ScriptedPrompter::unattended();
    let req = ExportRequest {
        output: Some("bundle".into()),
        kind: Some("udp".into()),
        remote_port: Some(20005),
        ..ExportRequest::default()
    };
    let written = export(&ui, &f.paths, &tcp(), &req, f.dir.path()).unwrap();
    assert_eq!(written, f.dir.join("bundle"));
    let text = fs::read_to_string(written.join("frpc.toml")).unwrap();
    assert!(text.contains("type = \"udp\"\n"));
    assert!(text.ends_with("remotePort = 20005\n"));
}

#[test]
fn v2_validation_messages() {
    let f = fixture();
    let ui = ScriptedPrompter::unattended();
    let out = f.dir.join("x");
    for (state, req, message) in [
        (
            single(),
            ExportRequest {
                kind: Some("tcp".into()),
                ..request(&out)
            },
            "FRP 导出协议或本地端口无效",
        ),
        (
            tcp(),
            ExportRequest {
                kind: Some("http".into()),
                ..request(&out)
            },
            "FRP 导出协议或本地端口无效",
        ),
        (
            single(),
            ExportRequest {
                local_port: Some(0),
                ..request(&out)
            },
            "FRP 导出协议或本地端口无效",
        ),
        (
            tcp(),
            ExportRequest {
                remote_port: Some(19999),
                ..request(&out)
            },
            "公网转发端口不在允许范围内",
        ),
        (
            single(),
            ExportRequest {
                subdomain: Some("Home".into()),
                ..request(&out)
            },
            "子域标签无效",
        ),
        (
            single(),
            ExportRequest {
                output: Some("../escape".into()),
                ..ExportRequest::default()
            },
            "导出目录不能包含 ..",
        ),
    ] {
        let err = export(&ui, &f.paths, &state, &req, f.dir.path()).unwrap_err();
        assert!(err.to_string().starts_with(message), "{err} vs {message}");
        assert!(!out.exists());
    }
}

#[test]
fn usage_without_an_output_directory() {
    let f = fixture();
    let ui = ScriptedPrompter::unattended();
    let options_only = ExportRequest {
        kind: Some("http".into()),
        ..ExportRequest::default()
    };
    for req in [ExportRequest::default(), options_only] {
        let err = export(&ui, &f.paths, &single(), &req, f.dir.path()).unwrap_err();
        assert_eq!(err.to_string(), USAGE);
    }
}

#[test]
fn a_missing_ca_creates_nothing() {
    let f = fixture();
    fs::remove_file(f.paths.frp_root.join("ca.pem")).unwrap();
    let ui = ScriptedPrompter::unattended();
    let out = f.dir.join("bundle");
    assert!(export(&ui, &f.paths, &single(), &request(&out), f.dir.path()).is_err());
    assert!(!out.exists());
}

#[test]
fn interactive_tcp_export() {
    let f = fixture();
    fs::create_dir(f.dir.join("taken")).unwrap();
    // UDP, local 9000, a port outside the range first, then 20003; the
    // taken directory is refused before a new one is accepted.
    let ui = ScriptedPrompter::new(["2", "9000", "30000", "20003", "taken", "fresh"]);
    let written = export(
        &ui,
        &f.paths,
        &tcp(),
        &ExportRequest::default(),
        f.dir.path(),
    )
    .unwrap();
    assert_eq!(written, f.dir.join("fresh"));
    let text = fs::read_to_string(written.join("frpc.toml")).unwrap();
    assert!(text.contains("name = \"onebox-udp-20003\"\n"));
    assert!(text.contains("localPort = 9000\n"));
    assert_eq!(
        ui.prompts(),
        [
            "转发协议：1 TCP，2 UDP",
            "内网服务端口",
            "公网转发端口",
            "公网转发端口",
            "导出到新的目录",
            "导出到新的目录",
        ]
    );
}

#[test]
fn interactive_wildcard_export_asks_the_label() {
    let f = fixture();
    let state = web(AppDomain::Wildcard {
        root: "apps.example.com".into(),
    });
    let ui = ScriptedPrompter::new(["", "-bad", "b", "", "home", ""]);
    let written = export(
        &ui,
        &f.paths,
        &state,
        &ExportRequest::default(),
        f.dir.path(),
    )
    .unwrap();
    assert_eq!(written, f.dir.join("frpc-client"));
    let text = fs::read_to_string(written.join("frpc.toml")).unwrap();
    assert!(text.contains("subdomain = \"home\"\n"));
    assert_eq!(ui.remaining(), 0);
}

#[test]
fn interactive_export_can_be_cancelled() {
    let f = fixture();
    let ui = ScriptedPrompter::new(["", "q"]);
    let err = export(
        &ui,
        &f.paths,
        &single(),
        &ExportRequest::default(),
        f.dir.path(),
    )
    .unwrap_err();
    assert!(err.is_cancelled());
    assert!(!f.dir.join("frpc-client").exists());
}
