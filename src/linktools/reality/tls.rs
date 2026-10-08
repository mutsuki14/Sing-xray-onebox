//! Ordinary TLS 1.3 probes with `openssl s_client` (spec D §4.1): the
//! certificate must verify for the SNI, and the probe reports the
//! negotiated ALPN and the SHA-256 of the leaf certificate's DER.
//!
//! Changes from v2:
//! - the leaf DER is decoded from the PEM in-process (render's
//!   `TlsMaterial`, the same digest the proxy pin uses) instead of a second
//!   `openssl x509 -outform DER` run;
//! - the protocol version is parsed from the output (`Protocol  : TLSv1.3`)
//!   instead of being hard-coded (D-8.1#19);
//! - a failure carries openssl's last message line, and a cancellation is
//!   `Error::Cancelled` instead of `TLS 探测失败` (D-8.1#20).

use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::linktools::cancel::CancelToken;
use crate::render::TlsMaterial;
use crate::sys::exec::{Cmd, Output};
use crate::sys::text::sanitize_input;
use std::path::Path;
use std::time::Duration;

const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
/// Largest s_client output accepted (v2: 1 MiB).
const MAX_OUTPUT: usize = 1024 * 1024;
const DETAIL_CHARS: usize = 200;
pub const TLS13: &str = "TLSv1.3";

/// What the TLS handshake showed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsProbe {
    /// e.g. `TLSv1.3` (`None` when openssl did not print it).
    pub protocol: Option<String>,
    /// The negotiated ALPN protocol, `None` without one.
    pub alpn: Option<String>,
    /// Lowercase hex SHA-256 of the leaf certificate's DER.
    pub certificate_sha256: String,
}

fn unsafe_text(s: &str) -> bool {
    s.is_empty() || s.bytes().any(|b| b <= b' ' || b == 0x7f)
}

/// `openssl s_client -connect HOST:PORT -servername SNI -verify_hostname
/// SNI -verify_return_error -tls1_3 -alpn h2,http/1.1 -showcerts
/// -no_ign_eof [-CAfile CA]`. An SNI starting with `-` is refused (option
/// injection), as are empty values and control characters.
pub fn s_client_command(host: &str, port: u16, sni: &str, ca: Option<&Path>) -> Result<Cmd> {
    ensure!(
        !unsafe_text(host) && !unsafe_text(sni) && !sni.starts_with('-'),
        "TLS 探测目标无效"
    );
    let address = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let mut cmd = Cmd::new("openssl").args([
        "s_client",
        "-connect",
        &address,
        "-servername",
        sni,
        "-verify_hostname",
        sni,
        "-verify_return_error",
        "-tls1_3",
        "-alpn",
        "h2,http/1.1",
        "-showcerts",
        "-no_ign_eof",
    ]);
    if let Some(ca) = ca {
        let ca = ca
            .to_str()
            .ok_or_else(|| Error::msg(format!("路径必须是 UTF-8: {}", ca.display())))?;
        cmd = cmd.args(["-CAfile", ca]);
    }
    Ok(cmd)
}

/// Parse a successful s_client run's stdout.
pub fn parse_s_client(stdout: &str) -> Result<TlsProbe> {
    ensure!(stdout.len() <= MAX_OUTPUT, "TLS 响应过大");
    let start = stdout
        .find(BEGIN)
        .ok_or_else(|| Error::msg("TLS 响应缺少证书"))?;
    let material =
        TlsMaterial::from_pem(&stdout[start..]).map_err(|_| Error::msg("TLS 响应证书无效"))?;
    let alpn = stdout
        .lines()
        .find_map(|line| line.trim().strip_prefix("ALPN protocol:"))
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty());
    Ok(TlsProbe {
        protocol: protocol(stdout),
        alpn,
        certificate_sha256: material.pin().to_owned(),
    })
}

/// `Protocol  : TLSv1.3` (session block; `Protocol version:` in newer
/// OpenSSL) or `New, TLSv1.3, Cipher is …`.
fn protocol(stdout: &str) -> Option<String> {
    let from_session = stdout.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        matches!(key.trim(), "Protocol" | "Protocol version").then(|| value.trim().to_owned())
    });
    from_session.or_else(|| {
        stdout.lines().find_map(|line| {
            let rest = line.trim().strip_prefix("New, ")?;
            rest.split(',').next().map(|v| v.trim().to_owned())
        })
    })
}

/// openssl's last non-empty stderr line (the verify or connect error),
/// else its last stdout line.
fn detail(output: &Output) -> String {
    let last = |text: &str| {
        text.lines()
            .rev()
            .map(str::trim)
            .find(|l| !l.is_empty() && *l != "DONE")
            .map(str::to_owned)
    };
    let line = last(&output.stderr)
        .or_else(|| last(&output.stdout))
        .unwrap_or_default();
    sanitize_input(&line).chars().take(DETAIL_CHARS).collect()
}

/// Probe `host:port` presenting `sni`, verifying against the system trust
/// store or `ca`, within `timeout`.
pub fn probe(
    ctx: &Ctx,
    target: (&str, u16, &str),
    ca: Option<&Path>,
    timeout: Duration,
    cancel: &CancelToken,
) -> Result<TlsProbe> {
    let (host, port, sni) = target;
    let cmd = s_client_command(host, port, sni, ca)?.timeout(timeout);
    let output = ctx.run(&cmd)?;
    if cancel.is_cancelled() {
        return Err(Error::Cancelled);
    }
    if !output.ok() {
        let detail = detail(&output);
        if detail.is_empty() {
            bail!("TLS 探测失败");
        }
        bail!("TLS 探测失败: {detail}");
    }
    let probe = parse_s_client(&output.stdout)?;
    if let Some(version) = probe.protocol.as_deref().filter(|v| *v != TLS13) {
        bail!("TLS 探测失败: 协商的协议为 {version}，不是 TLS 1.3");
    }
    Ok(probe)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render::fixtures::cert_pair;

    pub(crate) fn s_client_output(cert_pem: &str, alpn: Option<&str>) -> String {
        let alpn = match alpn {
            Some(a) => format!("ALPN protocol: {a}"),
            None => "No ALPN negotiated".to_owned(),
        };
        format!(
            "CONNECTED(00000003)\n---\nCertificate chain\n 0 s:CN = www.bing.com\n{cert_pem}---\n\
             New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n{alpn}\n---\n\
             Post-Handshake New Session Ticket arrived:\nSSL-Session:\n    Protocol  : TLSv1.3\n\
             DONE\n"
        )
    }

    fn cert() -> String {
        std::fs::read_to_string(cert_pair("selfsigned").0).unwrap()
    }

    #[test]
    fn command_line_is_v2s() {
        let cmd = s_client_command("203.0.113.10", 443, "www.example.com", None).unwrap();
        assert_eq!(
            cmd.display(),
            "openssl s_client -connect 203.0.113.10:443 -servername www.example.com \
             -verify_hostname www.example.com -verify_return_error -tls1_3 -alpn h2,http/1.1 \
             -showcerts -no_ign_eof"
        );
        let cmd =
            s_client_command("2001:db8::1", 8443, "a.example", Some(Path::new("/ca.pem"))).unwrap();
        assert!(cmd.display().contains("-connect [2001:db8::1]:8443 "));
        assert!(cmd.display().ends_with("-no_ign_eof -CAfile /ca.pem"));
        for (host, sni) in [
            ("", "a"),
            ("h", ""),
            ("h", "-x"),
            ("h o", "a"),
            ("h", "a\nb"),
        ] {
            let err = s_client_command(host, 1, sni, None).unwrap_err();
            assert_eq!(err.to_string(), "TLS 探测目标无效", "{host:?} {sni:?}");
        }
    }

    #[test]
    fn output_parsing() {
        let pem = cert();
        let expected = TlsMaterial::from_pem(&pem).unwrap().pin().to_owned();
        let probe = parse_s_client(&s_client_output(&pem, Some("h2"))).unwrap();
        assert_eq!(
            probe,
            TlsProbe {
                protocol: Some("TLSv1.3".into()),
                alpn: Some("h2".into()),
                certificate_sha256: expected,
            }
        );
        let plain = parse_s_client(&s_client_output(&pem, None)).unwrap();
        assert_eq!(plain.alpn, None);
        let newline_only = "New, TLSv1.2, Cipher is X\n".to_owned() + &pem;
        assert_eq!(protocol(&newline_only).as_deref(), Some("TLSv1.2"));
        assert_eq!(
            protocol("Protocol version: TLSv1.3\n").as_deref(),
            Some("TLSv1.3")
        );
        let cases = [
            ("CONNECTED\nno certificate\n".to_owned(), "TLS 响应缺少证书"),
            (
                format!("{BEGIN}\n!!!\n-----END CERTIFICATE-----\n"),
                "TLS 响应证书无效",
            ),
            (format!("{BEGIN}\nMAMCAQE=\n"), "TLS 响应证书无效"),
            ("x".repeat(MAX_OUTPUT + 1), "TLS 响应过大"),
        ];
        for (text, message) in cases {
            assert_eq!(parse_s_client(&text).unwrap_err().to_string(), message);
        }
    }

    #[test]
    fn failures_name_openssl_s_reason() {
        let output = Output {
            code: 1,
            stdout: "CONNECTED(00000003)\nDONE\n".into(),
            stderr: "depth=0 CN = x\nverify error:num=62:hostname mismatch\n".into(),
        };
        assert_eq!(detail(&output), "verify error:num=62:hostname mismatch");
        assert_eq!(detail(&Output::failure(1, "")), "");
    }

    #[test]
    fn scripted_probes() {
        let dir = crate::sys::fs::TempDir::new("linktools-test").unwrap();
        let (ctx, exec, _) = Ctx::test(dir.path());
        let pem = cert();
        let ok = s_client_output(&pem, Some("h2"));
        let old = ok.replace("TLSv1.3", "TLSv1.2");
        exec.on(
            "openssl",
            &["s_client", "-connect", "ok:443"],
            Output::success(ok),
        )
        .on(
            "openssl",
            &["s_client", "-connect", "old:443"],
            Output::success(old),
        )
        .on(
            "openssl",
            &["s_client", "-connect", "bad:443"],
            Output::failure(
                1,
                "40F7:error:0A000086:SSL routines::certificate verify failed\n",
            ),
        );
        let cancel = CancelToken::manual();
        let t = Duration::from_secs(2);
        let probe = probe_at(&ctx, "ok", t, &cancel).unwrap();
        assert_eq!(probe.alpn.as_deref(), Some("h2"));
        assert_eq!(exec.calls()[0].timeout, Some(t));
        let err = probe_at(&ctx, "old", t, &cancel).unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS 探测失败: 协商的协议为 TLSv1.2，不是 TLS 1.3"
        );
        let err = probe_at(&ctx, "bad", t, &cancel).unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS 探测失败: 40F7:error:0A000086:SSL routines::certificate verify failed"
        );
        cancel.cancel();
        assert!(probe_at(&ctx, "ok", t, &cancel).unwrap_err().is_cancelled());
    }

    fn probe_at(ctx: &Ctx, host: &str, t: Duration, cancel: &CancelToken) -> Result<TlsProbe> {
        probe(ctx, (host, 443, "www.bing.com"), None, t, cancel)
    }
}
