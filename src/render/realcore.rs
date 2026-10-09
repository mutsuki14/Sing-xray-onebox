//! Real-core validation (`#[ignore]`): every server and client document of
//! every golden case is checked by the core that consumes it.
//!
//! Run with the tested binaries:
//! `ONEBOX_TEST_SINGBOX=/path/sing-box ONEBOX_TEST_XRAY=/path/xray
//! ONEBOX_TEST_MIHOMO=/path/mihomo cargo test -- --ignored realcore`.
//! A test whose variable is unset reports the skip and passes, except under
//! CI's `ONEBOX_TEST_REQUIRE_FULL=1` (`sys::testenv`), where it fails.
//!
//! Geodata: Xray client documents reference `geosite:`/`geoip:` lists, so
//! their check needs `geosite.dat` and `geoip.dat` in
//! `ONEBOX_TEST_XRAY_ASSETS` (default: next to the xray binary, Xray's own
//! default); without them only the client document check is skipped (the
//! same contract).
//! mihomo downloads its geodata into a cache directory under the system temp
//! dir on the first run (network needed once).

use super::golden::{cases, Case};
use super::json::pretty;
use super::spec::NodeSpec;
use super::{client, mihomo, probe, server, yaml};
use crate::domain::protocol::{ClientFormat, Core};
use crate::paths::Paths;
use crate::sys::exec::{Cmd, Exec, SystemExec};
use crate::sys::fs::TempDir;
use crate::sys::testenv;
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(120);

/// The tested core named by `var` (the shared real-tool contract).
fn tool(var: &str) -> Option<String> {
    testenv::tool(var).map(|p| p.to_string_lossy().into_owned())
}

/// The case rendered under a real temporary root holding its certificate
/// pair, so the cores can load the files the server configs name.
fn deploy(case: &Case, dir: &TempDir) -> NodeSpec {
    let mut paths = Paths::isolated(dir.path());
    paths.root = dir.join("etc");
    if let Some(pair) = &case.cert_pair {
        let (cert, key) = super::fixtures::cert_pair(pair);
        fs::create_dir_all(paths.tls()).unwrap();
        fs::copy(cert, paths.tls().join("cert.pem")).unwrap();
        fs::copy(key, paths.tls().join("key.pem")).unwrap();
    }
    NodeSpec::new(&case.config, &paths, case.material.as_ref()).unwrap()
}

fn run(label: &str, program: &str, args: &[&str]) {
    run_cmd(label, Cmd::new(program).args(args.iter().copied()));
}

fn run_cmd(label: &str, cmd: Cmd) {
    let cmd = cmd.timeout(TIMEOUT);
    let out = SystemExec.run(&cmd).unwrap();
    assert!(
        out.ok(),
        "{label}: {} failed ({}):\n{}\n{}",
        cmd.display(),
        out.code,
        out.stdout,
        out.stderr
    );
}

fn write(dir: &Path, name: &str, text: &str) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, text).unwrap();
    path
}

fn check_singbox(bin: &str, label: &str, dir: &Path, name: &str, doc: &Value) {
    let path = write(dir, name, &pretty(doc).unwrap());
    run(label, bin, &["check", "-c", path.to_str().unwrap()]);
}

fn check_xray(bin: &str, assets: &Path, label: &str, dir: &Path, name: &str, doc: &Value) {
    let path = write(dir, name, &pretty(doc).unwrap());
    let cmd = Cmd::new(bin)
        .args(["run", "-test", "-c", path.to_str().unwrap()])
        .env("XRAY_LOCATION_ASSET", assets.to_str().unwrap());
    run_cmd(label, cmd);
}

/// Directory with Xray's `geosite.dat` / `geoip.dat`, if available.
fn xray_assets(bin: &str) -> Option<PathBuf> {
    let dir = match std::env::var_os("ONEBOX_TEST_XRAY_ASSETS") {
        Some(dir) => PathBuf::from(dir),
        None => Path::new(bin).parent()?.to_owned(),
    };
    let complete = ["geosite.dat", "geoip.dat"]
        .iter()
        .all(|f| dir.join(f).is_file());
    if !complete {
        testenv::skip(&format!(
            "Xray 客户端配置检查：{} 中缺少 geosite.dat / geoip.dat",
            dir.display()
        ));
    }
    complete.then_some(dir)
}

/// A minimal client around one probe entry, as the link tools build it.
fn probe_client(entry: &probe::ProbeEntry) -> Value {
    match entry.core {
        Core::Singbox => json!({"log": {"level": "warn"},
            "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": 1080}],
            "outbounds": entry.outbounds, "route": {"final": entry.tag}}),
        Core::Xray => json!({"log": {"loglevel": "warning"},
            "inbounds": [{"listen": "127.0.0.1", "port": 1080, "protocol": "socks",
                "settings": {"udp": true}}],
            "outbounds": entry.outbounds}),
    }
}

fn probe_entries(spec: &NodeSpec, core: Core) -> Vec<(String, probe::ProbeEntry)> {
    let mut entries = Vec::new();
    for local in [false, true] {
        for entry in probe::bundle(spec, local).unwrap().entries {
            if entry.core == core {
                entries.push((format!("probe-{}-{local}.json", entry.id), entry));
            }
        }
    }
    entries
}

#[test]
#[ignore = "needs ONEBOX_TEST_SINGBOX"]
fn realcore_singbox_accepts_every_document() {
    let Some(bin) = tool("ONEBOX_TEST_SINGBOX") else {
        return;
    };
    for case in cases() {
        let dir = TempDir::new("realcore-sb").unwrap();
        let spec = deploy(&case, &dir);
        let label = case.name.as_str();
        if spec.on_core(Core::Singbox).next().is_some() {
            let doc = server(&spec, Core::Singbox).unwrap();
            check_singbox(&bin, label, dir.path(), "server.json", &doc);
        }
        for (format, name) in [
            (ClientFormat::Singbox, "client-tun.json"),
            (ClientFormat::SingboxNoTun, "client.json"),
        ] {
            if spec.formats().contains(&format) {
                let text = client(&spec, format).unwrap();
                let doc: Value = serde_json::from_str(&text).unwrap();
                check_singbox(&bin, label, dir.path(), name, &doc);
            }
        }
        for (name, entry) in probe_entries(&spec, Core::Singbox) {
            check_singbox(&bin, label, dir.path(), &name, &probe_client(&entry));
        }
    }
}

#[test]
#[ignore = "needs ONEBOX_TEST_XRAY"]
fn realcore_xray_accepts_every_document() {
    let Some(bin) = tool("ONEBOX_TEST_XRAY") else {
        return;
    };
    let assets = xray_assets(&bin);
    let no_assets = PathBuf::from("/nonexistent");
    for case in cases() {
        let dir = TempDir::new("realcore-xr").unwrap();
        let spec = deploy(&case, &dir);
        let label = case.name.as_str();
        if spec.on_core(Core::Xray).next().is_some() {
            let doc = server(&spec, Core::Xray).unwrap();
            check_xray(&bin, &no_assets, label, dir.path(), "server.json", &doc);
        }
        let with_client = spec.formats().contains(&ClientFormat::Xray);
        if let Some(assets) = assets.as_ref().filter(|_| with_client) {
            let text = client(&spec, ClientFormat::Xray).unwrap();
            let doc: Value = serde_json::from_str(&text).unwrap();
            check_xray(&bin, assets, label, dir.path(), "client.json", &doc);
        }
        for (name, entry) in probe_entries(&spec, Core::Xray) {
            let doc = probe_client(&entry);
            check_xray(&bin, &no_assets, label, dir.path(), &name, &doc);
        }
    }
}

#[test]
#[ignore = "needs ONEBOX_TEST_MIHOMO (and network once for geodata)"]
fn realcore_mihomo_accepts_full_config_and_provider() {
    let Some(bin) = tool("ONEBOX_TEST_MIHOMO") else {
        return;
    };
    // Geodata survives between runs so only the first run downloads it.
    let home = std::env::temp_dir().join("onebox-test-mihomo-home");
    fs::create_dir_all(&home).unwrap();
    for case in cases() {
        let spec = case.spec.clone();
        if !spec.formats().contains(&ClientFormat::Mihomo) {
            continue;
        }
        let dir = TempDir::new("realcore-mh").unwrap();
        let label = case.name.as_str();
        let full = write(
            dir.path(),
            "mihomo.yaml",
            &client(&spec, ClientFormat::Mihomo).unwrap(),
        );
        let home_arg = home.to_str().unwrap();
        run(
            label,
            &bin,
            &["-t", "-d", home_arg, "-f", full.to_str().unwrap()],
        );
        // The provider's proxies inside a minimal configuration.
        let mut minimal = mihomo::provider(&spec).unwrap();
        crate::render::json::ObjectExt::merge(
            &mut minimal,
            json!({"mode": "rule", "rules": ["MATCH,DIRECT"]}),
        );
        let provider = write(dir.path(), "provider.yaml", &yaml::to_yaml(&minimal));
        run(
            label,
            &bin,
            &["-t", "-d", home_arg, "-f", provider.to_str().unwrap()],
        );
    }
}
