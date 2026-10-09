//! Redaction of free-form text for the support report.
//!
//! Three passes, in order:
//! 1. known values — every credential, domain and address of the node
//!    configuration and the FRP state — are replaced (longest first, so a
//!    subdomain goes before its parent);
//! 2. IPv6 and IPv4 literals anywhere in the text;
//! 3. anything shaped like a domain name (`label.label…` ending in an
//!    alphabetic label), except file names with a common extension
//!    (`sing-box.json`, `nginx.conf`, `acme.sh`) so error messages stay
//!    useful. Version numbers (`1.14.2`) end in digits and are kept.
//!
//! Placeholders: `<secret>`, `<domain>`, `<ip>`.

use crate::domain::config::{Host, HostPort, NodeConfig, ProxyCertMode, SubscriptionMode, WebCert};
use crate::frp::model::{AppDomain, FrpState, WebTls};
use std::net::{Ipv4Addr, Ipv6Addr};

pub const SECRET: &str = "<secret>";
pub const DOMAIN: &str = "<domain>";
pub const IP: &str = "<ip>";
/// Shorter known values are not replaced: they would mangle ordinary words.
const MIN_KNOWN: usize = 4;
/// Final labels that make a dotted word a file name, not a domain.
const FILE_EXTENSIONS: [&str; 52] = [
    "json", "conf", "pem", "key", "crt", "csr", "cer", "der", "log", "sock", "service", "socket",
    "timer", "target", "sh", "bash", "py", "txt", "html", "htm", "css", "js", "md", "yaml", "yml",
    "toml", "ini", "cfg", "new", "old", "bak", "tmp", "temp", "lock", "pid", "gz", "tgz", "tar",
    "zip", "xz", "zst", "so", "db", "xml", "svg", "png", "ico", "list", "dgst", "sig", "asc",
    "deb",
];

/// Replaces sensitive values in text (see the module docs).
#[derive(Clone, Debug, Default)]
pub struct Redactor {
    /// (value, placeholder), longest value first.
    known: Vec<(String, &'static str)>,
}

impl Redactor {
    pub fn new() -> Redactor {
        Redactor::default()
    }

    /// Knows every credential, domain and address of `cfg` and `frp`.
    pub fn for_node(cfg: Option<&NodeConfig>, frp: Option<&FrpState>) -> Redactor {
        let mut r = Redactor::new();
        if let Some(cfg) = cfg {
            r.add_node(cfg);
        }
        if let Some(frp) = frp {
            r.add_frp(frp);
        }
        r
    }

    /// Replace `value` with `placeholder` wherever it occurs.
    pub fn add(&mut self, value: &str, placeholder: &'static str) {
        let value = value.trim();
        if value.chars().count() < MIN_KNOWN || self.known.iter().any(|(v, _)| v == value) {
            return;
        }
        self.known.push((value.to_owned(), placeholder));
        self.known.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
    }

    fn add_host(&mut self, host: &Host) {
        match host {
            Host::Ip(ip) => self.add(&ip.to_string(), IP),
            Host::Domain(domain) => self.add(domain, DOMAIN),
        }
    }

    fn add_target(&mut self, target: &HostPort) {
        self.add_host(&target.host);
    }

    fn add_web_cert(&mut self, cert: &WebCert) {
        if let WebCert::Custom { cert, key } = cert {
            self.add(&cert.to_string_lossy(), SECRET);
            self.add(&key.to_string_lossy(), SECRET);
        }
    }

    fn add_node(&mut self, cfg: &NodeConfig) {
        let c = &cfg.creds;
        for secret in [
            &c.uuid,
            &c.password,
            &c.ss_password,
            &c.hy2_obfs_password,
            &c.shadowtls_password,
            &c.shadowtls_ss_password,
            &c.clash_secret,
            &c.ws_path,
            &c.vmess_path,
            &c.xhttp_path,
            &c.grpc_service,
        ] {
            self.add(secret, SECRET);
        }
        if let Some(keys) = &c.reality {
            for secret in [&keys.private_key, &keys.public_key, &keys.short_id] {
                self.add(secret, SECRET);
            }
        }
        self.add_host(&cfg.server.addr);
        if let Some(v4) = cfg.server.ipv4 {
            self.add(&v4.to_string(), IP);
        }
        if let Some(v6) = cfg.server.ipv6 {
            self.add(&v6.to_string(), IP);
        }
        for cidr in &cfg.routing.own_cidrs {
            let ip = cidr.split('/').next().unwrap_or(cidr);
            self.add(ip, IP);
        }
        self.add(&cfg.reality.sni, DOMAIN);
        self.add_target(&cfg.reality.dest);
        self.add(&cfg.shadowtls.sni, DOMAIN);
        if let Some(dest) = &cfg.shadowtls.dest {
            self.add_target(dest);
        }
        if let Some(host) = &cfg.vmess_host {
            self.add(host, DOMAIN);
        }
        self.add_node_endpoints(cfg);
    }

    /// Certificate names and paths, the site and the subscription.
    fn add_node_endpoints(&mut self, cfg: &NodeConfig) {
        if let Some(tls) = &cfg.tls {
            self.add(tls.mode.server_name(), DOMAIN);
            if let ProxyCertMode::Custom { cert, key, .. } = &tls.mode {
                self.add(&cert.to_string_lossy(), SECRET);
                self.add(&key.to_string_lossy(), SECRET);
            }
        }
        if let Some(site) = &cfg.site {
            self.add(&site.domain, DOMAIN);
            self.add_web_cert(&site.cert);
        }
        match cfg.subscription.as_ref().map(|s| &s.mode) {
            Some(SubscriptionMode::Ip { address }) => self.add(&address.to_string(), IP),
            Some(SubscriptionMode::Standalone { domain, cert, .. }) => {
                self.add(domain, DOMAIN);
                self.add_web_cert(cert);
            }
            Some(SubscriptionMode::Site) | None => {}
        }
    }

    fn add_frp(&mut self, frp: &FrpState) {
        self.add(&frp.token, SECRET);
        self.add(&frp.domain, DOMAIN);
        if let Some(web) = frp.web() {
            match &web.app {
                AppDomain::Single { domain } => self.add(domain, DOMAIN),
                AppDomain::Wildcard { root } => self.add(root, DOMAIN),
            }
            if let WebTls::Custom { cert, key } = &web.tls {
                self.add(cert, SECRET);
                self.add(key, SECRET);
            }
        }
    }

    /// `text` with known values, IP literals and domain names replaced.
    pub fn redact(&self, text: &str) -> String {
        let mut out = text.to_owned();
        for (value, placeholder) in &self.known {
            out = out.replace(value.as_str(), placeholder);
        }
        scrub_domains(&scrub_ipv4(&scrub_ipv6(&out)))
    }
}

/// Replace every maximal run of `in_run` characters for which `replace`
/// returns a placeholder; `replace` gets the run and the characters just
/// before and after it.
fn scrub_runs(
    text: &str,
    in_run: impl Fn(char) -> bool,
    replace: impl Fn(&str, Option<char>, Option<char>) -> Option<String>,
) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    let mut before: Option<char> = None;
    while !rest.is_empty() {
        let start = rest.find(&in_run).unwrap_or(rest.len());
        out.push_str(&rest[..start]);
        if start > 0 {
            before = rest[..start].chars().next_back();
        }
        rest = &rest[start..];
        if rest.is_empty() {
            break;
        }
        let len = rest.find(|c: char| !in_run(c)).unwrap_or(rest.len());
        let (run, tail) = rest.split_at(len);
        match replace(run, before, tail.chars().next()) {
            Some(replacement) => out.push_str(&replacement),
            None => out.push_str(run),
        }
        before = run.chars().next_back();
        rest = tail;
    }
    out
}

/// A word character next to a candidate means it is part of a longer word.
fn joins(c: Option<char>) -> bool {
    c.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The length of `run` without trailing `chars` (punctuation that may end
/// a sentence after an address or a name).
fn trim_trailing(run: &str, chars: &[char]) -> usize {
    run.trim_end_matches(chars).len()
}

/// IPv6 literals (runs of hex digits, `:` and `.` with at least two colons).
fn scrub_ipv6(text: &str) -> String {
    scrub_runs(
        text,
        |c| c.is_ascii_hexdigit() || c == ':' || c == '.',
        |run, before, after| {
            if joins(before) || joins(after) || run.matches(':').count() < 2 {
                return None;
            }
            // `::1:` or `fe80::1.` at the end of a sentence.
            [run, run.trim_end_matches(['.', ':'])]
                .into_iter()
                .find(|candidate| candidate.parse::<Ipv6Addr>().is_ok())
                .map(|found| format!("{IP}{}", &run[found.len()..]))
        },
    )
}

/// IPv4 literals (runs of digits and dots).
fn scrub_ipv4(text: &str) -> String {
    scrub_runs(
        text,
        |c| c.is_ascii_digit() || c == '.',
        |run, before, after| {
            if joins(before) || joins(after) {
                return None;
            }
            let kept = trim_trailing(run, &['.']);
            let candidate = &run[..kept];
            candidate
                .parse::<Ipv4Addr>()
                .is_ok()
                .then(|| format!("{IP}{}", &run[kept..]))
        },
    )
}

fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Whether `word` (without trailing dots) is shaped like a domain name.
pub fn looks_like_domain(word: &str) -> bool {
    let labels: Vec<&str> = word.split('.').collect();
    let Some(last) = labels.last() else {
        return false;
    };
    let tld_ok = (2..=63).contains(&last.len()) && last.bytes().all(|b| b.is_ascii_alphabetic());
    labels.len() >= 2
        && tld_ok
        && labels.iter().all(|l| valid_label(l))
        && !FILE_EXTENSIONS.contains(&last.to_ascii_lowercase().as_str())
}

/// Domain-shaped words (see [`looks_like_domain`]).
fn scrub_domains(text: &str) -> String {
    scrub_runs(
        text,
        |c| c.is_ascii_alphanumeric() || c == '-' || c == '.',
        |run, before, after| {
            if joins(before) || joins(after) || before == Some('_') {
                return None;
            }
            let kept = trim_trailing(run, &['.', '-']);
            let word = &run[..kept];
            looks_like_domain(word).then(|| format!("{DOMAIN}{}", &run[kept..]))
        },
    )
}

/// Whether `text` still contains an IP literal.
#[cfg(test)]
pub(crate) fn contains_ip(text: &str) -> bool {
    text.split(|c: char| !(c.is_ascii_hexdigit() || c == ':' || c == '.'))
        .any(|word| {
            let word = word.trim_end_matches(['.', ':']);
            word.parse::<std::net::IpAddr>().is_ok() && word.contains(['.', ':'])
        })
}

#[cfg(test)]
mod tests;
