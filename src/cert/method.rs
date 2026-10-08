//! Certificate names, methods and the desired content of a certificate
//! directory ([`CertSpec`]).
//!
//! A spec says *what* a directory must hold (names, where the pair comes
//! from, which trust the deployed pair must satisfy); the engine decides
//! whether that needs an issuance, a renewal or nothing.
//!
//! Changes from v2: methods are typed (v2 passed the strings `self`, `http`,
//! `standalone`, `cf`, `custom` around and validated them late); the
//! metadata strings are kept so v2 and v3 read each other's
//! `certificate.json`. `standalone` now means "the built-in HTTP-01
//! responder serves the challenge" (v2: acme.sh `--standalone`, which needs
//! socat and fails while an nginx holds TCP 80, F-8.1#4/#5).

use super::openssl::Trust;
use crate::error::{Error, Result};
use crate::sys::text::valid_domain;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// At most this many names per certificate (v2 limit).
pub const MAX_NAMES: usize = 32;

/// The method recorded in `certificate.json` (v2 strings).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MethodId {
    #[serde(rename = "self")]
    SelfSigned,
    /// ACME HTTP-01 through an Onebox nginx webroot.
    #[serde(rename = "http")]
    Http,
    /// ACME HTTP-01 through the built-in responder (v2: acme.sh standalone).
    #[serde(rename = "standalone")]
    Standalone,
    /// ACME DNS-01 through Cloudflare.
    #[serde(rename = "cf")]
    Cloudflare,
    #[serde(rename = "custom")]
    Custom,
}

impl MethodId {
    pub fn id(self) -> &'static str {
        match self {
            MethodId::SelfSigned => "self",
            MethodId::Http => "http",
            MethodId::Standalone => "standalone",
            MethodId::Cloudflare => "cf",
            MethodId::Custom => "custom",
        }
    }

    /// Chinese label for status output.
    pub fn label(self) -> &'static str {
        match self {
            MethodId::SelfSigned => "自签证书",
            MethodId::Http => "ACME HTTP-01",
            MethodId::Standalone => "ACME HTTP-01（内置验证服务）",
            MethodId::Cloudflare => "ACME Cloudflare DNS",
            MethodId::Custom => "自备证书",
        }
    }

    /// HTTP-01 through nginx or the responder is one kind of certificate:
    /// switching the responder never forces a new issuance.
    pub fn same_kind(self, other: MethodId) -> bool {
        let kind = |m: MethodId| match m {
            MethodId::Standalone => MethodId::Http,
            other => other,
        };
        kind(self) == kind(other)
    }
}

/// Where acme.sh's HTTP-01 / DNS-01 challenge is answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Challenge {
    /// acme.sh writes the token below this webroot; a running Onebox nginx
    /// serves it on TCP 80.
    Webroot(PathBuf),
    /// acme.sh writes the token below this webroot; the built-in responder
    /// serves it on TCP 80 for the duration of the acme.sh call.
    Responder(PathBuf),
    /// DNS-01 through Cloudflare (`--dns dns_cf`).
    Cloudflare,
}

impl Challenge {
    /// The webroot acme.sh writes tokens to, if any.
    pub fn webroot(&self) -> Option<&Path> {
        match self {
            Challenge::Webroot(p) | Challenge::Responder(p) => Some(p),
            Challenge::Cloudflare => None,
        }
    }
}

/// Where the certificate pair comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    SelfSigned,
    Acme(Challenge),
    /// A pair the user supplied; copied (chain re-ordered leaf first) into
    /// the directory.
    Custom { cert: PathBuf, key: PathBuf },
}

/// What a certificate directory must hold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertSpec {
    /// The first name is the primary one (CN, acme.sh directory name).
    pub domains: Vec<String>,
    pub source: Source,
    /// The trust every name of the deployed pair must verify with.
    pub trust: Trust,
}

impl CertSpec {
    pub fn method(&self) -> MethodId {
        match &self.source {
            Source::SelfSigned => MethodId::SelfSigned,
            Source::Acme(Challenge::Webroot(_)) => MethodId::Http,
            Source::Acme(Challenge::Responder(_)) => MethodId::Standalone,
            Source::Acme(Challenge::Cloudflare) => MethodId::Cloudflare,
            Source::Custom { .. } => MethodId::Custom,
        }
    }

    pub fn primary(&self) -> &str {
        self.domains.first().map(String::as_str).unwrap_or("")
    }

    pub fn challenge(&self) -> Option<&Challenge> {
        match &self.source {
            Source::Acme(challenge) => Some(challenge),
            _ => None,
        }
    }

    /// The built-in responder will bind TCP 80 for this certificate.
    pub fn uses_responder(&self) -> bool {
        matches!(self.challenge(), Some(Challenge::Responder(_)))
    }

    /// v2 `check_domains` for this spec's method.
    pub fn check(&self) -> Result<()> {
        check_domains(&self.domains, self.method())
    }
}

/// A certificate name: an IP literal, a lower-case DNS name, or `*.` plus a
/// DNS name (v2 `domain_valid`).
pub fn valid_name(name: &str) -> bool {
    name.parse::<IpAddr>().is_ok() || valid_domain(name.strip_prefix("*.").unwrap_or(name))
}

/// v2 rules: 1–32 valid names; IP names only for self-signed and custom
/// certificates; wildcards need DNS validation or a supplied certificate.
pub fn check_domains(domains: &[String], method: MethodId) -> Result<()> {
    if domains.is_empty() || domains.len() > MAX_NAMES {
        return Err(Error::msg("证书域名数量无效"));
    }
    let ip_ok = matches!(method, MethodId::SelfSigned | MethodId::Custom);
    let wildcard_ok = matches!(
        method,
        MethodId::Cloudflare | MethodId::Custom | MethodId::SelfSigned
    );
    for name in domains {
        if !valid_name(name) || (name.parse::<IpAddr>().is_ok() && !ip_ok) {
            return Err(Error::msg("证书域名无效"));
        }
        if name.starts_with("*.") && !wildcard_ok {
            return Err(Error::msg("泛域名需要 DNS 验证或自备证书"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn names_follow_v2_rules() {
        for good in ["example.com", "*.example.com", "203.0.113.1", "2001:db8::1"] {
            assert!(valid_name(good), "{good}");
        }
        for bad in [
            "example.com\nfoo",
            "-a.example.com",
            "*.bad",
            "example.com/path",
            "Example.com",
            "*.*.example.com",
            "",
        ] {
            assert!(!valid_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn method_rules_for_wildcards_and_ips() {
        use MethodId::*;
        let cases: &[(&[&str], MethodId, Option<&str>)] = &[
            (&["*.example.com"], Http, Some("泛域名需要 DNS 验证或自备证书")),
            (&["*.example.com"], Standalone, Some("泛域名需要 DNS 验证或自备证书")),
            (&["example.com", "*.example.com"], Cloudflare, None),
            (&["*.example.com"], Custom, None),
            (&["*.example.com"], SelfSigned, None),
            (&["203.0.113.1"], SelfSigned, None),
            (&["203.0.113.1"], Custom, None),
            (&["203.0.113.1"], Http, Some("证书域名无效")),
            (&["203.0.113.1"], Cloudflare, Some("证书域名无效")),
            (&[], Http, Some("证书域名数量无效")),
            (&["bad name"], Custom, Some("证书域名无效")),
        ];
        for (list, method, error) in cases {
            let result = check_domains(&names(list), *method);
            match error {
                None => assert!(result.is_ok(), "{list:?} {method:?}"),
                Some(e) => assert_eq!(result.unwrap_err().to_string(), *e, "{list:?}"),
            }
        }
        let many: Vec<String> = (0..33).map(|i| format!("n{i}.example.com")).collect();
        assert!(check_domains(&many[..32], Http).is_ok());
        assert_eq!(
            check_domains(&many, Http).unwrap_err().to_string(),
            "证书域名数量无效"
        );
    }

    #[test]
    fn method_ids_keep_v2_strings() {
        use MethodId::*;
        for (m, id) in [
            (SelfSigned, "self"),
            (Http, "http"),
            (Standalone, "standalone"),
            (Cloudflare, "cf"),
            (Custom, "custom"),
        ] {
            assert_eq!(m.id(), id);
            assert_eq!(serde_json::to_value(m).unwrap(), serde_json::json!(id));
            let back: MethodId = serde_json::from_value(serde_json::json!(id)).unwrap();
            assert_eq!(back, m);
        }
        assert!(serde_json::from_value::<MethodId>(serde_json::json!("acme")).is_err());
        assert!(Http.same_kind(Standalone) && Standalone.same_kind(Http));
        assert!(!Http.same_kind(Cloudflare) && !SelfSigned.same_kind(Custom));
    }

    #[test]
    fn spec_methods_follow_the_source() {
        let spec = |source| CertSpec {
            domains: names(&["example.com"]),
            source,
            trust: Trust::Public,
        };
        let webroot = PathBuf::from("/var/lib/onebox-site");
        assert_eq!(
            spec(Source::Acme(Challenge::Webroot(webroot.clone()))).method(),
            MethodId::Http
        );
        let responder = spec(Source::Acme(Challenge::Responder(webroot.clone())));
        assert_eq!(responder.method(), MethodId::Standalone);
        assert!(responder.uses_responder());
        assert_eq!(responder.challenge().unwrap().webroot(), Some(&*webroot));
        let dns = spec(Source::Acme(Challenge::Cloudflare));
        assert_eq!(dns.method(), MethodId::Cloudflare);
        assert_eq!(dns.challenge().unwrap().webroot(), None);
        assert_eq!(spec(Source::SelfSigned).method(), MethodId::SelfSigned);
        assert_eq!(spec(Source::SelfSigned).primary(), "example.com");
    }
}
