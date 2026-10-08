//! Derived predicates on `NodeConfig` and keyword parsing for the small
//! configuration enums (used by planners, the v2 migration and the CLI).

use super::*;
use crate::domain::defaults::HTTPS_PORT;

impl NodeConfig {
    pub fn core_of(&self, protocol: Protocol) -> Option<Core> {
        self.inbound(protocol).map(|i| i.core)
    }
    pub fn inbound_mut(&mut self, protocol: Protocol) -> Option<&mut Inbound> {
        self.inbounds.iter_mut().find(|i| i.protocol == protocol)
    }
    /// Xray needs the local REALITY guard inbound when it hosts any REALITY protocol.
    pub fn uses_guard(&self) -> bool {
        self.inbounds
            .iter()
            .any(|i| i.protocol.reality() && i.core == Core::Xray)
    }
    /// Some REALITY inbound listens on TCP 443 and therefore also serves as the
    /// website's HTTPS entrance (no separate nginx 443 front-end is needed).
    pub fn reality_on_443(&self) -> bool {
        self.inbounds
            .iter()
            .any(|i| i.protocol.reality() && i.port == HTTPS_PORT)
    }
    /// Public HTTPS port of the website (v2 `site::public_port`): 443 with the
    /// HTTPS entrance, otherwise the lowest REALITY port (REALITY forwards
    /// browsers to the site), 443 when there is none.
    pub fn site_public_port(&self) -> u16 {
        if self.site.as_ref().is_some_and(|s| s.https_entry) {
            return HTTPS_PORT;
        }
        self.inbounds
            .iter()
            .filter(|i| i.protocol.reality())
            .map(|i| i.port)
            .min()
            .unwrap_or(HTTPS_PORT)
    }
}

/// Implements `ALL`, `id()`, `FromStr` and `Display` for a kebab-case keyword enum.
macro_rules! keyword_enum {
    ($ty:ident, $error:literal, [$($variant:ident => $id:literal),+ $(,)?]) => {
        impl $ty {
            pub const ALL: &'static [$ty] = &[$($ty::$variant),+];
            pub fn id(self) -> &'static str {
                match self {
                    $($ty::$variant => $id),+
                }
            }
        }

        impl FromStr for $ty {
            type Err = Error;
            fn from_str(s: &str) -> Result<Self> {
                match s {
                    $($id => Ok($ty::$variant),)+
                    _ => Err(Error::Msg($error.to_owned())),
                }
            }
        }

        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.id())
            }
        }
    };
}

keyword_enum!(SiteTemplate, "模板应为 minimal/profile/docs", [
    Minimal => "minimal",
    Profile => "profile",
    Docs => "docs",
]);
keyword_enum!(SiteTheme, "主题应为 forest/ocean/slate", [
    Forest => "forest",
    Ocean => "ocean",
    Slate => "slate",
]);
keyword_enum!(Hy2Profile, "Hy2 档位无效", [
    Auto => "auto",
    Conservative => "conservative",
    Measured => "measured",
]);
keyword_enum!(ResourceProfile, "资源档位无效", [
    Balanced => "balanced",
    LowMemory => "low-memory",
    Throughput => "throughput",
]);

impl WebCert {
    /// Method name as used on the command line (`http` / `cf` / `custom`).
    pub fn method(&self) -> &'static str {
        match self {
            WebCert::Http01 => "http",
            WebCert::Cloudflare => "cf",
            WebCert::Custom { .. } => "custom",
        }
    }
}

impl ProxyCertMode {
    /// A certificate for a real domain (ACME or user supplied), as opposed to
    /// the self-signed default. VMess-WS uses TLS by default only then.
    pub fn is_domain_cert(&self) -> bool {
        !matches!(self, ProxyCertMode::SelfSigned { .. })
    }
}

impl SubscriptionMode {
    pub fn id(&self) -> &'static str {
        match self {
            SubscriptionMode::Ip { .. } => "ip",
            SubscriptionMode::Site => "site",
            SubscriptionMode::Standalone { .. } => "standalone",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyword_enums_roundtrip_with_serde() {
        for t in SiteTemplate::ALL {
            assert_eq!(t.id().parse::<SiteTemplate>().unwrap(), *t);
            assert_eq!(serde_json::to_value(t).unwrap(), serde_json::json!(t.id()));
        }
        for t in SiteTheme::ALL {
            assert_eq!(t.id().parse::<SiteTheme>().unwrap(), *t);
            assert_eq!(serde_json::to_value(t).unwrap(), serde_json::json!(t.id()));
        }
        for p in Hy2Profile::ALL {
            assert_eq!(p.id().parse::<Hy2Profile>().unwrap(), *p);
            assert_eq!(serde_json::to_value(p).unwrap(), serde_json::json!(p.id()));
        }
        for p in ResourceProfile::ALL {
            assert_eq!(p.id().parse::<ResourceProfile>().unwrap(), *p);
            assert_eq!(serde_json::to_value(p).unwrap(), serde_json::json!(p.id()));
        }
        assert_eq!(
            "huge".parse::<ResourceProfile>().unwrap_err().to_string(),
            "资源档位无效"
        );
        assert!("Docs".parse::<SiteTemplate>().is_err());
        assert_eq!(WebCert::Cloudflare.method(), "cf");
        assert_eq!(SubscriptionMode::Site.id(), "site");
    }

    #[test]
    fn derived_ports_and_cores() {
        use crate::domain::fixtures::{config, with_site};
        use Core::{Singbox as SB, Xray as XR};
        use Protocol::*;
        let cfg = config(&[(VlessReality, 8443, XR), (Anytls, 443, SB)]);
        assert!(cfg.uses_guard());
        assert!(!cfg.reality_on_443());
        assert_eq!(cfg.core_of(Anytls), Some(SB));
        assert_eq!(cfg.core_of(Tuic), None);
        let mut site = with_site(cfg, "www.example.com", false);
        assert_eq!(site.site_public_port(), 8443);
        if let Some(s) = site.site.as_mut() {
            s.https_entry = true;
        }
        assert_eq!(site.site_public_port(), 443);
    }
}
