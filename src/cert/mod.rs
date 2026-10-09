//! Certificates for the proxy, the own-domain website, the standalone
//! subscription endpoint and FRP's web mode: self-signed (openssl), ACME
//! (acme.sh 3.1.6, Let's Encrypt; HTTP-01 through an Onebox nginx webroot
//! or the built-in responder, DNS-01 through Cloudflare) and custom pairs.
//!
//! Structure:
//! - [`method`]: names, methods, [`CertSpec`] (what a directory must hold);
//! - [`store`]: certificate directories, metadata, deployment, status;
//! - [`openssl`]: validation (v2's exact checks), leaf detection, dates;
//! - [`selfsigned`], [`acme`], [`cloudflare`], [`http01`]: the sources;
//! - [`engine`]: issue / renew / due decisions for one directory;
//! - [`hooks`]: what the apply engine and FRP call (never prompting);
//! - [`renew`]: `onebox renew --cron`, `cert renew …` without an apply.
//!
//! Changes from v2 (details in each module):
//! - acme.sh and dns_cf.sh are pinned by SHA-256 (F-8.1#12);
//! - manual renewals force acme.sh (`--force`, F-8.1#3);
//! - HTTP-01 never needs socat: a running Onebox nginx serves the webroot,
//!   otherwise the built-in responder binds TCP 80 (F-8.1#4/#5);
//! - Cloudflare credentials go only to acme.sh's environment and are
//!   resolved by the CLI before an apply; applies never prompt (F-8.1#11);
//! - renewals restart only the affected service and never run a full apply
//!   (G-8.1#4); the caller applies only when the proxy identity changed;
//! - custom chains are deployed leaf-first; the proxy pin is the leaf's;
//! - self-signed-only nodes need no renewal cron (F-8.1#6); custom
//!   certificates get it so refreshed sources are redeployed (G17);
//! - acme.sh's "not due" still deploys the pair it holds, and a renewal
//!   acme.sh defers while the deployed pair expires within 30 days is
//!   reported, not recorded as a success.

pub mod acme;
pub mod cloudflare;
pub mod engine;
pub mod hooks;
pub mod http01;
pub mod method;
pub mod openssl;
pub mod renew;
pub mod selfsigned;
pub mod store;
#[cfg(test)]
pub(crate) mod testing;

pub use cloudflare::CfCredentials;
pub use engine::{Engine, RenewKind, Renewal};
pub use hooks::{
    issue_domains, prepare_proxy, prepare_web, renew_dir, renew_needed, renewal_due, status,
    web_needs_acme, RenewNeed, WebCertTarget,
};
pub use method::{CertSpec, Challenge, MethodId, Source};
pub use openssl::{publicly_trusted, validate_pair, Trust};
pub use renew::{credentials_needed, renew_all, RenewOptions, RenewReport};
pub use store::{CertDir, CertStatus, Expiry, Metadata};

use crate::error::{Error, Result};
use std::fmt;
use std::str::FromStr;

/// Error for a public endpoint whose certificate is not publicly trusted.
pub const PUBLIC_REQUIRED: &str = "公网网站及订阅需要正式证书，不能使用自签证书";

/// One renewable certificate of the node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CertScope {
    Proxy,
    Site,
    Subscription,
}

impl CertScope {
    pub const ALL: [CertScope; 3] = [CertScope::Proxy, CertScope::Site, CertScope::Subscription];

    /// Command-line id (`cert renew proxy|site|subscription`).
    pub fn id(self) -> &'static str {
        match self {
            CertScope::Proxy => "proxy",
            CertScope::Site => "site",
            CertScope::Subscription => "subscription",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            CertScope::Proxy => "代理证书",
            CertScope::Site => "网站证书",
            CertScope::Subscription => "订阅证书",
        }
    }
}

impl fmt::Display for CertScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

/// A set of [`CertScope`]s (renewal targets, forced renewals of an apply).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CertScopes {
    pub proxy: bool,
    pub site: bool,
    pub subscription: bool,
}

impl CertScopes {
    pub const NONE: CertScopes = CertScopes {
        proxy: false,
        site: false,
        subscription: false,
    };
    pub const ALL: CertScopes = CertScopes {
        proxy: true,
        site: true,
        subscription: true,
    };

    pub fn only(scope: CertScope) -> CertScopes {
        let mut set = CertScopes::NONE;
        set.insert(scope);
        set
    }

    pub fn insert(&mut self, scope: CertScope) {
        *self.slot(scope) = true;
    }

    pub fn contains(&self, scope: CertScope) -> bool {
        match scope {
            CertScope::Proxy => self.proxy,
            CertScope::Site => self.site,
            CertScope::Subscription => self.subscription,
        }
    }

    pub fn is_empty(&self) -> bool {
        *self == CertScopes::NONE
    }

    /// Members in the fixed order proxy, site, subscription.
    pub fn iter(self) -> impl Iterator<Item = CertScope> {
        CertScope::ALL
            .into_iter()
            .filter(move |s| self.contains(*s))
    }

    fn slot(&mut self, scope: CertScope) -> &mut bool {
        match scope {
            CertScope::Proxy => &mut self.proxy,
            CertScope::Site => &mut self.site,
            CertScope::Subscription => &mut self.subscription,
        }
    }
}

impl FromStr for CertScopes {
    type Err = Error;
    /// `proxy` / `site` / `subscription` / `all` (`cert renew` targets).
    fn from_str(s: &str) -> Result<CertScopes> {
        match s {
            "all" => Ok(CertScopes::ALL),
            _ => CertScope::ALL
                .into_iter()
                .find(|scope| scope.id() == s)
                .map(CertScopes::only)
                .ok_or_else(|| Error::msg("续期目标应为 proxy/site/subscription/all")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_parse_and_iterate_in_order() {
        assert_eq!("all".parse::<CertScopes>().unwrap(), CertScopes::ALL);
        let site: CertScopes = "site".parse().unwrap();
        assert_eq!(site.iter().collect::<Vec<_>>(), [CertScope::Site]);
        assert!(site.contains(CertScope::Site) && !site.contains(CertScope::Proxy));
        assert_eq!(
            "bogus".parse::<CertScopes>().unwrap_err().to_string(),
            "续期目标应为 proxy/site/subscription/all"
        );
        let mut set = CertScopes::NONE;
        assert!(set.is_empty());
        set.insert(CertScope::Subscription);
        set.insert(CertScope::Proxy);
        assert_eq!(
            set.iter().collect::<Vec<_>>(),
            [CertScope::Proxy, CertScope::Subscription]
        );
        assert_eq!(CertScope::Site.to_string(), "site");
        assert_eq!(CertScope::Proxy.label(), "代理证书");
    }
}
