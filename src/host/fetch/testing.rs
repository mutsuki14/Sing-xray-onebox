//! Test double for curl: canned replies by URL, written to the `--output`
//! path the way the real curl does. Shared by the fetch and cores tests.

use crate::sys::exec::{Cmd, FakeExec, Output};
use std::path::PathBuf;

/// What the fake network answers for one URL.
#[derive(Clone, Debug)]
pub enum Reply {
    Body(Vec<u8>),
    /// curl exit code and stderr.
    Fail(i32, String),
}

impl Reply {
    pub fn body(bytes: impl Into<Vec<u8>>) -> Reply {
        Reply::Body(bytes.into())
    }
    pub fn http(status: u16) -> Reply {
        Reply::Fail(
            22,
            format!("curl: (22) The requested URL returned error: {status}"),
        )
    }
}

/// The `--output` argument of a curl command.
pub fn output_arg(cmd: &Cmd) -> Option<PathBuf> {
    let at = cmd.args.iter().position(|a| a == "--output")?;
    cmd.args.get(at + 1).map(PathBuf::from)
}

/// The URL curl fetches (the last argument).
pub fn url_arg(cmd: &Cmd) -> &str {
    cmd.args.last().map(String::as_str).unwrap_or("")
}

/// Make `curl` available and answer it from `routes` (exact URL match);
/// unknown URLs fail like an HTTP 404.
pub fn serve(exec: &FakeExec, routes: Vec<(String, Reply)>) {
    exec.provide("curl");
    exec.on_fn(
        |cmd| cmd.program == "curl",
        move |cmd| {
            let url = url_arg(cmd);
            let reply = routes
                .iter()
                .find(|(u, _)| u == url)
                .map(|(_, r)| r.clone())
                .unwrap_or_else(|| Reply::http(404));
            match reply {
                Reply::Body(bytes) => {
                    if let Some(path) = output_arg(cmd) {
                        std::fs::write(path, bytes)?;
                    }
                    Ok(Output::success(""))
                }
                Reply::Fail(code, stderr) => Ok(Output::failure(code, stderr)),
            }
        },
    );
}

/// `(url, reply)` pairs from string URLs.
pub fn routes<const N: usize>(pairs: [(&str, Reply); N]) -> Vec<(String, Reply)> {
    pairs.into_iter().map(|(u, r)| (u.to_owned(), r)).collect()
}
