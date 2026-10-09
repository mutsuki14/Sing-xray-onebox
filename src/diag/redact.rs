//! Redaction of free-form text for the support report.
//!
//! Two passes, in order:
//! 1. known values — every credential, domain and address of the node
//!    configuration and the FRP state, or every value of a state file that
//!    could not be loaded ([`Redactor::add_raw`]) — are replaced (longest
//!    first, so a subdomain goes before its parent);
//! 2. patterns ([`scrub`]): IPv6 and IPv4 literals, then anything shaped
//!    like a domain name, also inside file names (`example.com.crt` →
//!    `<domain>.crt`). File names (`sing-box.json`, `nginx.conf.new`,
//!    `acme.sh`), versions (`1.14.2`) and JSON path segments
//!    (`inbounds[0].tls.server_name`) are kept so error messages stay
//!    useful.
//!
//! Placeholders: `<secret>`, `<domain>`, `<ip>`.

mod scrub;

use crate::domain::config::{Host, HostPort, NodeConfig, ProxyCertMode, SubscriptionMode, WebCert};
use crate::domain::{Core, Protocol};
use crate::frp::model::{AppDomain, FrpState, WebTls};
use serde_json::Value;
use std::net::IpAddr;

pub const SECRET: &str = "<secret>";
pub const DOMAIN: &str = "<domain>";
pub const IP: &str = "<ip>";
/// Shorter known values are not replaced: they would mangle ordinary words.
const MIN_KNOWN: usize = 4;
/// Keys whose numeric values are credentials (`"password": 12345678`).
const CREDENTIAL_KEYS: [&str; 11] = [
    "pass", "secret", "token", "uuid", "key", "path", "short", "service", "auth", "psk", "obfs",
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
        self.known.sort_by_key(|(v, _)| std::cmp::Reverse(v.len()));
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

    /// Treat every value of `text`, an input file that could not be loaded,
    /// as sensitive: its load error may echo any of them (`ws_path 路径无效:
    /// /x`, ``invalid type: integer `12345678` ``). JSON gives its string
    /// leaves and the numbers under credential-like keys, a `KEY=value` file
    /// (FRP's v1 `state.conf`) its values. Protocol and core ids are kept.
    /// `false` when `text` is neither format: the caller must then not show
    /// the load error at all.
    pub fn add_raw(&mut self, text: &str) -> bool {
        if let Ok(doc) = serde_json::from_str::<Value>(text) {
            self.add_json(&doc, "");
            return true;
        }
        let lines: Vec<&str> = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();
        let pairs: Option<Vec<&str>> = lines.iter().map(|l| conf_value(l)).collect();
        match pairs {
            Some(values) if !values.is_empty() => {
                values.into_iter().for_each(|v| self.add_leaf(v));
                true
            }
            _ => false,
        }
    }

    fn add_json(&mut self, value: &Value, key: &str) {
        match value {
            Value::String(s) => self.add_leaf(s),
            Value::Number(n) if credential_key(key) => self.add(&n.to_string(), SECRET),
            Value::Array(items) => items.iter().for_each(|v| self.add_json(v, key)),
            Value::Object(map) => map.iter().for_each(|(k, v)| self.add_json(v, k)),
            _ => {}
        }
    }

    /// A raw value, classified by its shape.
    fn add_leaf(&mut self, value: &str) {
        let value = value.trim();
        let vocabulary = Protocol::ALL.iter().any(|p| p.id() == value)
            || Core::ALL
                .iter()
                .any(|c| c.id() == value || c.binary() == value);
        if vocabulary {
            return;
        }
        let placeholder = if value.parse::<IpAddr>().is_ok() {
            IP
        } else if looks_like_domain(value) {
            DOMAIN
        } else {
            SECRET
        };
        self.add(value, placeholder);
    }

    /// `text` with known values, IP literals and domain names replaced.
    pub fn redact(&self, text: &str) -> String {
        let mut out = text.to_owned();
        for (value, placeholder) in &self.known {
            out = out.replace(value.as_str(), placeholder);
        }
        scrub::scrub(&out)
    }
}

/// Whether `word` (without surrounding punctuation) is shaped like a
/// domain name as a whole (`example.com`, not `example.com.crt`).
pub fn looks_like_domain(word: &str) -> bool {
    scrub::domain_len(word) == Some(word.len())
}

/// The value of a `KEY=value` line (quotes removed); `None` for any other
/// line.
fn conf_value(line: &str) -> Option<&str> {
    let (key, value) = line.split_once('=')?;
    let key_ok = !key.is_empty() && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
    key_ok.then(|| value.trim().trim_matches(['"', '\'']))
}

fn credential_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    CREDENTIAL_KEYS.iter().any(|k| key.contains(k))
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
