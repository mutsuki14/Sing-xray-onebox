//! Parity with v2.0.1: every golden case (`tests/golden/cases/*`) is a v2
//! `state.json` (+ subscription settings, + certificate) together with the
//! outputs the v2 binary produced for it (`tests/golden/generate.sh`).
//! Each case goes through the real v2 migration (`state::v2::migrate`) and
//! `NodeSpec::new`; every v3 output must equal the v2 output:
//! - JSON documents as `serde_json::Value` *and* as text;
//! - links and Base64 subscriptions byte for byte;
//! - mihomo documents by structure (v3 writes YAML, v2 wrote JSON), with the
//!   emitted YAML parsed back by the test reader;
//! - a v2 failure (`.err`) must be a v3 failure.
//!
//! The only accepted differences are the transformations in [`ALLOWED`],
//! each documented in `tests/golden/ALLOWED_DIFFS.md`; the test fails if a
//! listed difference no longer occurs or occurs anywhere else.

use super::fixtures::golden_dir;
use super::spec::NodeSpec;
use super::tls::TlsMaterial;
use super::yaml::reader;
use super::{client, inbound, mihomo, outbound, pretty, probe, server};
use crate::domain::config::NodeConfig;
use crate::domain::protocol::{ClientFormat, Core, Protocol};
use crate::paths::Paths;
use crate::state::v2::{migrate, v2_values_from_json, DeployedCerts};
use crate::sys::rand::SeqRandom;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Root the generator deployed each case under (paths inside server configs).
const DEPLOY_BASE: &str = "/tmp/onebox-golden";

/// Accepted differences: `(id, case, expected file)`; see ALLOWED_DIFFS.md.
const ALLOWED: &[(&str, &str, &str)] = &[
    (
        XRAY_HY2_MASQUERADE,
        "c06-custom-pinned-ipv6",
        "render-server-xray.json",
    ),
    (
        XRAY_HY2_MASQUERADE,
        "c06-custom-pinned-ipv6",
        "render-inbound-hysteria2.json",
    ),
];

/// C-8.1 #3: an Xray Hysteria2 server with Salamander obfuscation no longer
/// also sets a masquerade site.
const XRAY_HY2_MASQUERADE: &str = "D1-xray-hy2-obfs-masquerade";

pub(crate) struct Case {
    pub name: String,
    pub dir: PathBuf,
    /// The migrated configuration and its resolved view.
    pub config: NodeConfig,
    pub spec: NodeSpec,
    /// Certificate pair deployed with the case (`certs/<pair>`).
    pub cert_pair: Option<String>,
    pub material: Option<TlsMaterial>,
}

/// Every golden case, migrated and resolved.
pub(crate) fn cases() -> Vec<Case> {
    let mut dirs: Vec<PathBuf> = fs::read_dir(golden_dir().join("cases"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    dirs.sort();
    dirs.into_iter().map(|dir| load_case(&dir)).collect()
}

fn load_case(dir: &Path) -> Case {
    let name = dir.file_name().unwrap().to_str().unwrap().to_owned();
    let values = v2_values_from_json(&fs::read(dir.join("state.json")).unwrap()).unwrap();
    let settings: Option<Value> = fs::read(dir.join("settings.json"))
        .ok()
        .map(|b| serde_json::from_slice(&b).unwrap());
    let root = Path::new(DEPLOY_BASE).join(&name);
    let mut paths = Paths::isolated(&root);
    paths.root = root;
    let migrated = migrate(
        &values,
        settings.as_ref(),
        &DeployedCerts::of(&paths),
        &mut SeqRandom(0),
    )
    .unwrap_or_else(|e| panic!("{name}: migration failed: {e}"));
    assert!(
        migrated.warnings.is_empty(),
        "{name}: migration warnings {:?}",
        migrated.warnings
    );
    let cert_pair = fs::read_to_string(dir.join("cert"))
        .ok()
        .map(|s| s.trim().to_owned());
    let material = cert_pair.as_ref().map(|pair| {
        TlsMaterial::load(&golden_dir().join("certs").join(pair).join("cert.pem")).unwrap()
    });
    let spec = NodeSpec::new(&migrated.config, &paths, material.as_ref())
        .unwrap_or_else(|e| panic!("{name}: {e}"));
    Case {
        name,
        dir: dir.to_owned(),
        config: migrated.config,
        spec,
        cert_pair,
        material,
    }
}

/// What a file of `expected/` describes.
enum Target {
    Server(Core),
    Inbound(Protocol),
    Outbound(Protocol, Core),
    Probe,
    Client(ClientFormat),
}

fn target(stem: &str) -> Target {
    if let Some(core) = stem.strip_prefix("render-server-") {
        return Target::Server(core.parse().unwrap());
    }
    if let Some(p) = stem.strip_prefix("render-inbound-") {
        return Target::Inbound(p.parse().unwrap());
    }
    if let Some(rest) = stem.strip_prefix("render-outbound-") {
        let (p, core) = rest.rsplit_once('-').unwrap();
        return Target::Outbound(p.parse().unwrap(), core.parse().unwrap());
    }
    if stem == "render-probe" {
        return Target::Probe;
    }
    let format = stem.strip_prefix("client-").unwrap();
    Target::Client(ClientFormat::parse(format).unwrap())
}

/// v3 result for a target: a JSON value or export text.
enum Actual {
    Json(Value),
    Text(String),
}

fn render(spec: &NodeSpec, target: &Target) -> crate::error::Result<Actual> {
    Ok(match target {
        Target::Server(core) => Actual::Json(server(spec, *core)?),
        Target::Inbound(p) => Actual::Json(inbound(spec, *p)?),
        Target::Outbound(p, core) => Actual::Json(outbound(spec, *p, *core)?),
        Target::Probe => Actual::Json(probe::bundle(spec, false)?.to_value()?),
        Target::Client(format) => Actual::Text(client(spec, *format)?),
    })
}

/// Apply every allowed difference to a v2 value; returns the ids applied.
fn allow_diffs(expected: &mut Value) -> Vec<&'static str> {
    let mut applied = Vec::new();
    if drop_obfs_masquerade(expected) {
        applied.push(XRAY_HY2_MASQUERADE);
    }
    applied
}

/// Remove `hysteriaSettings.masquerade` from Xray Hysteria2 inbounds that
/// also carry a Salamander `finalmask` (the v2 combination v3 fixed).
fn drop_obfs_masquerade(value: &mut Value) -> bool {
    match value {
        Value::Object(map) => {
            let mut changed = false;
            if map.get("protocol") == Some(&Value::from("hysteria")) && map.contains_key("port") {
                if let Some(stream) = map.get_mut("streamSettings") {
                    if stream.get("finalmask").is_some() {
                        if let Some(Value::Object(s)) = stream.get_mut("hysteriaSettings") {
                            changed |= s.remove("masquerade").is_some();
                        }
                    }
                }
            }
            for v in map.values_mut() {
                changed |= drop_obfs_masquerade(v);
            }
            changed
        }
        Value::Array(items) => items
            .iter_mut()
            .fold(false, |c, v| drop_obfs_masquerade(v) | c),
        _ => false,
    }
}

/// Compare one expected file; returns the allowed differences it needed.
fn check_file(case: &Case, file: &Path) -> Vec<&'static str> {
    let name = file.file_name().unwrap().to_str().unwrap();
    let (stem, ext) = name.rsplit_once('.').unwrap();
    let target = target(stem);
    let label = format!("{}/{name}", case.name);
    let actual = render(&case.spec, &target);
    if ext == "err" {
        assert!(actual.is_err(), "{label}: v2 failed but v3 rendered");
        return Vec::new();
    }
    let actual = actual.unwrap_or_else(|e| panic!("{label}: {e}"));
    let text = fs::read_to_string(file).unwrap();
    match (&target, actual) {
        (Target::Client(ClientFormat::Mihomo | ClientFormat::Provider), Actual::Text(yaml)) => {
            let format = match target {
                Target::Client(f) => f,
                _ => unreachable!(),
            };
            let expected: Value = serde_json::from_str(&text).unwrap();
            let structure = if format == ClientFormat::Mihomo {
                mihomo::config(&case.spec).unwrap()
            } else {
                mihomo::provider(&case.spec).unwrap()
            };
            assert_eq!(structure, expected, "{label}: structure");
            let parsed = reader::parse(&yaml).unwrap_or_else(|e| panic!("{label}: {e}"));
            assert_eq!(parsed, expected, "{label}: emitted YAML");
            Vec::new()
        }
        (Target::Client(format), Actual::Text(out)) => {
            // v2 printed client() with println!, adding one newline.
            assert_eq!(format!("{out}\n"), text, "{label}: text");
            if !matches!(format, ClientFormat::Links | ClientFormat::Base64) {
                let expected: Value = serde_json::from_str(&text).unwrap();
                assert_eq!(serde_json::from_str::<Value>(&out).unwrap(), expected);
            }
            Vec::new()
        }
        (_, Actual::Json(value)) => {
            let mut expected: Value = serde_json::from_str(&text).unwrap();
            let applied = allow_diffs(&mut expected);
            assert_eq!(value, expected, "{label}");
            if applied.is_empty() {
                assert_eq!(
                    format!("{}\n", pretty(&value).unwrap()),
                    text,
                    "{label}: text"
                );
            }
            applied
        }
        (_, Actual::Text(_)) => panic!("{label}: unexpected text output"),
    }
}

#[test]
fn v3_renders_exactly_what_v2_rendered() {
    let cases = cases();
    assert!(cases.len() >= 8);
    let mut applied = BTreeSet::new();
    let mut checked = 0;
    for case in &cases {
        let mut files: Vec<PathBuf> = fs::read_dir(case.dir.join("expected"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        files.sort();
        assert!(!files.is_empty(), "{}: no expected outputs", case.name);
        for file in files {
            let name = file.file_name().unwrap().to_str().unwrap().to_owned();
            for id in check_file(case, &file) {
                applied.insert((id, case.name.clone(), name.clone()));
            }
            checked += 1;
        }
    }
    let allowed: BTreeSet<(&str, String, String)> = ALLOWED
        .iter()
        .map(|(id, case, file)| (*id, case.to_string(), file.to_string()))
        .collect();
    assert_eq!(applied, allowed, "allowed differences changed");
    assert!(checked > 200, "only {checked} files compared");
}

#[test]
fn every_allowed_difference_is_documented() {
    let doc = fs::read_to_string(golden_dir().join("ALLOWED_DIFFS.md")).unwrap();
    for (id, case, file) in ALLOWED {
        assert!(doc.contains(id), "{id} missing from ALLOWED_DIFFS.md");
        assert!(
            doc.contains(&format!("{case}/{file}")),
            "{case}/{file} not documented"
        );
    }
}

#[test]
fn cases_cover_the_parity_matrix() {
    let cases = cases();
    let all: Vec<&NodeSpec> = cases.iter().map(|c| &c.spec).collect();
    for p in Protocol::ALL {
        assert!(all.iter().any(|s| s.inbound(p).is_some()), "{p} uncovered");
    }
    for core in Core::ALL {
        assert!(all.iter().any(|s| s.on_core(core).next().is_some()));
    }
    let any = |f: &dyn Fn(&NodeSpec) -> bool| all.iter().any(|s| f(s));
    assert!(any(&|s| s.xhttp_shared()));
    assert!(any(&|s| s.site.as_ref().is_some_and(|x| x.https_entry)));
    assert!(any(&|s| s.site.as_ref().is_some_and(|x| !x.https_entry)));
    assert!(any(&|s| s.tls.as_ref().is_some_and(|t| t.pinned())));
    assert!(any(&|s| s.tls.as_ref().is_some_and(|t| !t.pinned())));
    assert!(any(
        &|s| s.hy2.obfs_password.is_some() && s.hy2.hop.is_some()
    ));
    assert!(any(
        &|s| s.hy2.bandwidth.is_some() && s.hy2.windows.is_some()
    ));
    assert!(
        any(&|s| s.vmess.tls) && any(&|s| s.inbound(Protocol::VmessWs).is_some() && !s.vmess.tls)
    );
    assert!(any(&|s| s.server.ip().is_some_and(|ip| ip.is_ipv6())));
    assert!(any(&|s| !s.routing.block_private) && any(&|s| !s.routing.block_bt));
    assert!(any(&|s| !s.direct.domains.is_empty()) && any(&|s| !s.direct.cidrs.is_empty()));
    assert!(cases
        .iter()
        .any(|c| c.cert_pair.as_deref() == Some("chain")));
}
