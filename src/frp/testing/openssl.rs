//! A fake `openssl` for the private-CA calls of [`crate::frp::ca`], so the
//! lifecycle tests fork no real programs (forks race with the lock tests
//! elsewhere in the crate and make the suite slow).
//!
//! Files are one-line text records: a key `FAKE-KEY {id}`, a request
//! `FAKE-CSR key={id} dns={domain}` and a certificate
//! `FAKE-CERT key={id} dns={domain} issuer={CA key id}`. A certificate
//! "verifies" for its domain against the CA whose key signed it and never
//! expires; public keys print as `PUB {id}`.

use crate::sys::exec::Output;
use std::collections::BTreeMap;
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_KEY: AtomicU64 = AtomicU64::new(1);

/// Answer one `openssl {args}` call.
pub fn run(args: &[String]) -> Output {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match args.first().copied() {
        Some("ecparam") => genkey(&args),
        Some("req") if args.contains(&"-x509") => self_signed(&args),
        Some("req") => request(&args),
        Some("x509") if args.contains(&"-req") => sign(&args),
        Some("x509") if args.contains(&"-pubkey") => cert_pubkey(&args),
        Some("x509") if args.contains(&"-checkend") => checkend(&args),
        Some("verify") => verify(&args),
        Some("pkey") => key_pubkey(&args),
        _ => None,
    };
    result.unwrap_or_else(|| Output::failure(1, format!("fake openssl refused {args:?}")))
}

/// The value after `flag`.
fn value<'a>(args: &[&'a str], flag: &str) -> Option<&'a str> {
    let at = args.iter().position(|a| *a == flag)?;
    args.get(at + 1).copied()
}

/// `KIND k=v k=v…` with the expected kind.
fn record(path: &str, kind: &str) -> Option<BTreeMap<String, String>> {
    let text = fs::read_to_string(path).ok()?;
    let mut words = text.split_whitespace();
    if words.next()? != kind {
        return None;
    }
    words
        .map(|w| w.split_once('=').map(|(k, v)| (k.to_owned(), v.to_owned())))
        .collect()
}

fn key_id(path: &str) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    text.strip_prefix("FAKE-KEY ")
        .map(|id| id.trim().to_owned())
}

/// The `subjectAltName=DNS:` of a request configuration (`-` without).
fn config_dns(path: &str) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    Some(
        text.lines()
            .find_map(|l| l.strip_prefix("subjectAltName=DNS:"))
            .unwrap_or("-")
            .to_owned(),
    )
}

fn write(path: &str, text: String) -> Option<Output> {
    fs::write(path, text + "\n").ok()?;
    Some(Output::success(""))
}

fn genkey(args: &[&str]) -> Option<Output> {
    let id = NEXT_KEY.fetch_add(1, Ordering::Relaxed);
    write(value(args, "-out")?, format!("FAKE-KEY k{id}"))
}

fn self_signed(args: &[&str]) -> Option<Output> {
    let key = key_id(value(args, "-key")?)?;
    let dns = config_dns(value(args, "-config")?)?;
    write(
        value(args, "-out")?,
        format!("FAKE-CERT key={key} dns={dns} issuer={key}"),
    )
}

fn request(args: &[&str]) -> Option<Output> {
    let key = key_id(value(args, "-key")?)?;
    let dns = config_dns(value(args, "-config")?)?;
    write(
        value(args, "-out")?,
        format!("FAKE-CSR key={key} dns={dns}"),
    )
}

fn sign(args: &[&str]) -> Option<Output> {
    let csr = record(value(args, "-in")?, "FAKE-CSR")?;
    let ca = record(value(args, "-CA")?, "FAKE-CERT")?;
    let ca_key = key_id(value(args, "-CAkey")?)?;
    if ca.get("key") != Some(&ca_key) {
        return Some(Output::failure(1, "CA key does not match"));
    }
    write(
        value(args, "-out")?,
        format!(
            "FAKE-CERT key={} dns={} issuer={ca_key}",
            csr.get("key")?,
            csr.get("dns")?
        ),
    )
}

fn cert_pubkey(args: &[&str]) -> Option<Output> {
    let cert = record(value(args, "-in")?, "FAKE-CERT")?;
    Some(Output::success(format!("PUB {}\n", cert.get("key")?)))
}

fn checkend(args: &[&str]) -> Option<Output> {
    record(value(args, "-in")?, "FAKE-CERT")?;
    Some(Output::success("Certificate will not expire\n"))
}

fn verify(args: &[&str]) -> Option<Output> {
    let ca = record(value(args, "-CAfile")?, "FAKE-CERT")?;
    let cert = record(args.last()?, "FAKE-CERT")?;
    let host = value(args, "-verify_hostname")?;
    let ok =
        cert.get("issuer") == ca.get("key") && cert.get("dns").map(String::as_str) == Some(host);
    Some(if ok {
        Output::success(format!("{}: OK\n", args.last()?))
    } else {
        Output::failure(2, "verification failed")
    })
}

fn key_pubkey(args: &[&str]) -> Option<Output> {
    let id = key_id(value(args, "-in")?)?;
    Some(Output::success(format!("PUB {id}\n")))
}

#[cfg(test)]
mod tests {
    use crate::frp::ca::{control_cert, ControlFiles};
    use crate::frp::testing::FakeHost;
    use std::fs;

    #[test]
    fn the_fake_follows_the_private_ca_rules() {
        let h = FakeHost::new();
        let root = &h.ctx.paths.frp_root;
        fs::create_dir_all(root).unwrap();
        assert!(control_cert(&h.ctx, root, "frp.example.com").unwrap());
        assert!(!control_cert(&h.ctx, root, "frp.example.com").unwrap());
        let files = ControlFiles::new(root);
        let ca = fs::read(files.ca()).unwrap();
        // Another control domain: a new server certificate, the same CA.
        assert!(control_cert(&h.ctx, root, "other.example.com").unwrap());
        assert_eq!(fs::read(files.ca()).unwrap(), ca);
        // A server key that no longer matches is replaced.
        fs::write(files.key(), "FAKE-KEY stranger\n").unwrap();
        assert!(control_cert(&h.ctx, root, "other.example.com").unwrap());
        // A broken CA is refused, never regenerated.
        fs::write(files.ca_key(), "FAKE-KEY stranger\n").unwrap();
        let err = control_cert(&h.ctx, root, "other.example.com").unwrap_err();
        assert_eq!(err.to_string(), crate::frp::ca::CA_INVALID);
    }
}
