//! Shared fixtures of the FRP unit tests: sample states, a fake frp
//! release (API document and package served through the fake curl) and a
//! tar.gz builder.

use super::model::{AppDomain, BindAddr, FrpState, Mode, WebSettings, WebTls};
use crate::domain::config::PortRange;
use crate::host::fetch::testing::Reply;
use crate::host::fetch::Asset;
use crate::sys::fs::sha256_hex;
use serde_json::json;
use std::path::Path;

pub const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
pub const API: &str = "https://api.github.com/repos/fatedier/frp/releases";

pub fn no_env(_: &str) -> Option<String> {
    None
}

pub fn tcp_state() -> FrpState {
    FrpState::new(
        "frp.example.com".into(),
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

pub fn web_state(tls: WebTls) -> FrpState {
    FrpState::new(
        "frp.example.com".into(),
        TOKEN.into(),
        BindAddr::AnyV4,
        Mode::Web(WebSettings::new(
            AppDomain::Single {
                domain: "app.example.com".into(),
            },
            tls,
        )),
    )
}

/// A gzip tar with the given `(path, bytes)` regular files (mode 0755).
pub fn tar_gz(members: &[(&str, &[u8])]) -> Vec<u8> {
    let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    let mut builder = tar::Builder::new(gz);
    for (name, data) in members {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o755);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder.append_data(&mut header, name, *data).unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap()
}

/// The official package name for amd64.
pub fn package_name(version: &str) -> String {
    format!("frp_{version}_linux_amd64.tar.gz")
}

/// The package of `version` holding a fake `frps`.
pub fn package(version: &str) -> Vec<u8> {
    let dir = format!("frp_{version}_linux_amd64");
    tar_gz(&[
        (&format!("{dir}/LICENSE"), b"license"),
        (&format!("{dir}/frps"), b"\x7fELF fake frps"),
        (&format!("{dir}/frpc"), b"\x7fELF fake frpc"),
    ])
}

/// The API document of release `v{version}` with the given assets.
pub fn release_json(version: &str, assets: Vec<serde_json::Value>) -> serde_json::Value {
    json!({
        "tag_name": format!("v{version}"),
        "draft": false,
        "prerelease": false,
        "body": "",
        "assets": assets,
    })
}

/// One asset entry; `digest` adds the API SHA-256.
pub fn asset_json(version: &str, name: &str, bytes: &[u8], digest: bool) -> serde_json::Value {
    let tag = format!("v{version}");
    let mut asset = json!({
        "name": name,
        "size": bytes.len(),
        "browser_download_url": Asset::expected_url("fatedier/frp", &tag, name),
    });
    if digest {
        asset["digest"] = json!(format!("sha256:{}", sha256_hex(bytes)));
    }
    asset
}

/// Routes serving release `version` (by tag, and as `latest` when
/// `latest`) with its package and an API digest.
pub fn release_routes(version: &str, latest: bool) -> Vec<(String, Reply)> {
    let bytes = package(version);
    let name = package_name(version);
    let doc = release_json(version, vec![asset_json(version, &name, &bytes, true)]).to_string();
    let mut routes = vec![
        (format!("{API}/tags/v{version}"), Reply::body(doc.clone())),
        (
            Asset::expected_url("fatedier/frp", &format!("v{version}"), &name),
            Reply::body(bytes),
        ),
    ];
    if latest {
        routes.push((format!("{API}/latest"), Reply::body(doc)));
    }
    routes
}

/// `{binary} -v` answers: binaries below `stage` report `staged`, the
/// installed one (`installed`) reports `current` (`None` = it fails).
pub fn frps_versions(
    exec: &crate::sys::exec::FakeExec,
    installed: &Path,
    current: Option<&str>,
    staged: &str,
) {
    let installed = installed.to_path_buf();
    let current = current.map(str::to_owned);
    let staged = staged.to_owned();
    exec.on_fn(
        |cmd| cmd.program.ends_with("/frps") && cmd.args == ["-v"],
        move |cmd| {
            use crate::sys::exec::Output;
            if Path::new(&cmd.program) == installed {
                return Ok(match &current {
                    Some(v) => Output::success(format!("{v}\n")),
                    None => Output::failure(126, "exec format error"),
                });
            }
            Ok(Output::success(format!("{staged}\n")))
        },
    );
}
