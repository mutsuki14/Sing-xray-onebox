//! `frps client`: export a ready-to-run client bundle (spec H §2.7, §3.6)
//! — `frpc.toml`, the public `ca.pem` and `README.txt` — into a new
//! directory, asked interactively or given on the command line.
//!
//! Invariants: the bundle never contains a private key (only `ca.pem` is
//! copied from the FRP root), never overwrites anything (the directory is
//! created without `-p` and must not exist; files are created exclusively,
//! 0600, inside the new 0700 directory) and is removed again when writing
//! fails half-way.
//!
//! Changes from v2: the interactive form runs on the shared step engine;
//! option values are parsed with Chinese messages; options without an
//! output directory are a usage error instead of treating the first
//! option as the directory name; a symlink in a parent directory of the
//! output (the user's own tree) is accepted, the new directory itself and
//! its files never follow one.

use super::model::FrpState;
use super::render::{client_readme, client_toml, ProxyKind, ProxySpec, DEFAULT_SUBDOMAIN};
use super::steps::{self, ask, ask_port, choose, value, Answer, Form};
use crate::cli::args::Matches;
use crate::error::{Error, Result};
use crate::paths::Paths;
use crate::sys::fs::{read_bounded, write_new_exclusive};
use crate::sys::text::valid_label;
use crate::ui::{out, Prompter};
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Component, Path, PathBuf};

pub const USAGE: &str =
    "用法: onebox frps client 新目录 [--type http|tcp|udp --local-port N --remote-port N --subdomain 标签]";
const DEFAULT_LOCAL_PORT: u16 = 8080;
const DEFAULT_OUTPUT: &str = "./frpc-client";
const CA_MAX_BYTES: u64 = 1024 * 1024;

/// What the user asked for; `None` = the default.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExportRequest {
    pub output: Option<String>,
    pub kind: Option<String>,
    pub local_port: Option<u16>,
    pub remote_port: Option<u16>,
    pub subdomain: Option<String>,
}

impl ExportRequest {
    pub fn from_matches(m: &Matches) -> Result<ExportRequest> {
        Ok(ExportRequest {
            output: m.positional(0).map(str::to_owned),
            kind: m.value("type").map(str::to_owned),
            local_port: m.parse("local-port")?,
            remote_port: m.parse("remote-port")?,
            subdomain: m.value("subdomain").map(str::to_owned),
        })
    }

    fn has_options(&self) -> bool {
        self.kind.is_some()
            || self.local_port.is_some()
            || self.remote_port.is_some()
            || self.subdomain.is_some()
    }
}

/// The bundle's settings while they are being chosen.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Choice {
    kind: String,
    local_port: u16,
    remote_port: u16,
    subdomain: String,
    output: String,
}

impl Choice {
    fn defaults(state: &FrpState) -> Choice {
        Choice {
            kind: if state.is_web() { "http" } else { "tcp" }.to_owned(),
            local_port: DEFAULT_LOCAL_PORT,
            remote_port: state.range().map_or(0, |r| r.start),
            subdomain: DEFAULT_SUBDOMAIN.to_owned(),
            output: String::new(),
        }
    }

    fn with(mut self, req: &ExportRequest) -> Choice {
        if let Some(kind) = &req.kind {
            self.kind.clone_from(kind);
        }
        if let Some(port) = req.local_port {
            self.local_port = port;
        }
        if let Some(port) = req.remote_port {
            self.remote_port = port;
        }
        if let Some(label) = &req.subdomain {
            self.subdomain.clone_from(label);
        }
        if let Some(output) = &req.output {
            self.output.clone_from(output);
        }
        self
    }
}

/// Export the bundle for `state` and return the directory written.
/// Without an output directory the settings are asked interactively.
pub fn export(
    ui: &dyn Prompter,
    paths: &Paths,
    state: &FrpState,
    req: &ExportRequest,
    cwd: &Path,
) -> Result<PathBuf> {
    let mut choice = Choice::defaults(state).with(req);
    if req.output.is_none() {
        ensure!(!req.has_options() && ui.interactive(), "{USAGE}");
        let mut form = ExportForm {
            state,
            choice,
            cwd: cwd.to_path_buf(),
        };
        steps::run(ui, &mut form)?;
        choice = form.choice;
    }
    let spec = validate(state, &choice)?;
    let output = resolve_output(&choice.output, cwd)?;
    write_bundle(paths, state, &spec, &output)?;
    out::ok(format!(
        "已导出 {}；将整个目录复制到内网机器后运行 frpc",
        output.display()
    ));
    Ok(output)
}

/// The proxy of a choice (v2 checks and messages, in v2 order).
fn validate(state: &FrpState, choice: &Choice) -> Result<ProxySpec> {
    let kind = ProxyKind::parse(&choice.kind)
        .filter(|k| (*k == ProxyKind::Http) == state.is_web())
        .filter(|_| choice.local_port != 0)
        .ok_or_else(|| Error::msg("FRP 导出协议或本地端口无效"))?;
    if kind != ProxyKind::Http {
        let inside = state
            .range()
            .is_some_and(|r| r.contains(choice.remote_port));
        ensure!(inside, "公网转发端口不在允许范围内");
    }
    ensure!(valid_label(&choice.subdomain), "子域标签无效");
    Ok(ProxySpec {
        kind,
        local_port: choice.local_port,
        remote_port: choice.remote_port,
        subdomain: choice.subdomain.clone(),
    })
}

/// `output` made absolute against `cwd`; it must be new and free of `..`.
fn resolve_output(output: &str, cwd: &Path) -> Result<PathBuf> {
    ensure!(!output.is_empty(), "{USAGE}");
    let path = Path::new(output);
    let path: PathBuf = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    }
    .components()
    .filter(|c| *c != Component::CurDir)
    .collect();
    ensure!(
        !path.components().any(|c| c == Component::ParentDir),
        "导出目录不能包含 ..: {}",
        path.display()
    );
    ensure!(
        fs::symlink_metadata(&path).is_err(),
        "导出目录已存在，请选择新的目录"
    );
    Ok(path)
}

/// Create `output` (0700, parent must exist) with the three files; remove
/// it again if anything fails after it was created.
fn write_bundle(paths: &Paths, state: &FrpState, spec: &ProxySpec, output: &Path) -> Result<()> {
    let ca = read_bounded(&paths.frp_root.join("ca.pem"), CA_MAX_BYTES)?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(output)
        .map_err(|e| match e.kind() {
            ErrorKind::AlreadyExists => Error::msg("导出目录已存在，请选择新的目录"),
            _ => Error::io(output, e),
        })?;
    let files: [(&str, Vec<u8>); 3] = [
        ("frpc.toml", client_toml(state, spec).into_bytes()),
        ("ca.pem", ca),
        ("README.txt", client_readme(state, spec).into_bytes()),
    ];
    let written = files
        .iter()
        .try_for_each(|(name, bytes)| write_new_exclusive(&output.join(name), bytes, 0o600));
    if written.is_err() {
        let _ = fs::remove_dir_all(output);
    }
    written
}

/// The interactive export (v2 steps 0–3).
struct ExportForm<'a> {
    state: &'a FrpState,
    choice: Choice,
    cwd: PathBuf,
}

impl Form for ExportForm<'_> {
    fn steps(&self) -> usize {
        4
    }

    fn step(&mut self, ui: &dyn Prompter, index: usize) -> Result<Answer<()>> {
        let state = self.state;
        let c = &mut self.choice;
        match index {
            0 if !state.is_web() => {
                let default = if c.kind == "udp" { 2 } else { 1 };
                let picked = value!(choose(ui, "转发协议：1 TCP，2 UDP", default, 1, 2)?);
                c.kind = if picked == 1 { "tcp" } else { "udp" }.to_owned();
            }
            1 => c.local_port = value!(ask_port(ui, "内网服务端口", c.local_port, false)?),
            2 if !state.is_web() => {
                let port = value!(ask_port(ui, "公网转发端口", c.remote_port, false)?);
                let inside = state.range().is_some_and(|r| r.contains(port));
                ensure!(inside, "端口不在允许转发范围内");
                c.remote_port = port;
            }
            2 if state.web().is_some_and(|w| w.app.is_wildcard()) => {
                let label = value!(ask(ui, "子域标签", &c.subdomain)?);
                ensure!(valid_label(&label), "子域标签无效");
                c.subdomain = label;
            }
            3 => {
                let default = if c.output.is_empty() {
                    DEFAULT_OUTPUT
                } else {
                    c.output.as_str()
                };
                let picked = value!(ask(ui, "导出到新的目录", default)?);
                let exists = fs::symlink_metadata(self.cwd.join(&picked)).is_ok();
                ensure!(!exists, "导出目录已存在，请选择新目录");
                c.output = picked;
            }
            _ => {}
        }
        Ok(Answer::Value(()))
    }
}

#[cfg(test)]
mod tests;
