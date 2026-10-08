//! Semantic-version precedence (semver 2.0.0 §11) for program versions:
//! `MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]`, an optional leading `v`.
//!
//! Changes from v2: v2 only compared versions for equality, so it could
//! not tell an upgrade from a downgrade; the self-install (and later the
//! update checks) order versions with this type.

use std::cmp::Ordering;

/// A parsed version; ordering follows semver precedence (build metadata
/// is ignored, so `1.0.0+a` and `1.0.0+b` compare equal).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Semver {
    core: [u64; 3],
    pre: Vec<Ident>,
}

/// A pre-release identifier. The variant order is the semver rule:
/// numeric identifiers sort before alphanumeric ones.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Ident {
    Num(u64),
    Alpha(String),
}

impl Semver {
    /// `None` unless `text` (trimmed) is a valid semantic version.
    pub fn parse(text: &str) -> Option<Semver> {
        let text = text.trim();
        let text = text.strip_prefix('v').unwrap_or(text);
        let (rest, build) = match text.split_once('+') {
            Some((rest, build)) => (rest, Some(build)),
            None => (text, None),
        };
        if build.is_some_and(|b| !b.split('.').all(valid_ident)) {
            return None;
        }
        let (core, pre) = match rest.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (rest, None),
        };
        let core = parse_core(core)?;
        let pre = match pre {
            Some(pre) => pre.split('.').map(parse_pre).collect::<Option<Vec<_>>>()?,
            None => Vec::new(),
        };
        Some(Semver { core, pre })
    }
}

impl Ord for Semver {
    fn cmp(&self, other: &Self) -> Ordering {
        self.core.cmp(&other.core).then_with(|| {
            // A release outranks its pre-releases; identifiers compare
            // left to right and a longer list wins a tie (derived Vec order).
            match (self.pre.is_empty(), other.pre.is_empty()) {
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => self.pre.cmp(&other.pre),
            }
        })
    }
}

impl PartialOrd for Semver {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn parse_core(core: &str) -> Option<[u64; 3]> {
    let mut parts = core.split('.').map(parse_number);
    let version = [parts.next()??, parts.next()??, parts.next()??];
    parts.next().is_none().then_some(version)
}

/// A numeric identifier: digits without a leading zero (except `0`).
fn parse_number(s: &str) -> Option<u64> {
    let digits = !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    let canonical = s == "0" || !s.starts_with('0');
    (digits && canonical).then(|| s.parse().ok()).flatten()
}

fn parse_pre(s: &str) -> Option<Ident> {
    if !valid_ident(s) {
        return None;
    }
    if s.bytes().all(|b| b.is_ascii_digit()) {
        return parse_number(s).map(Ident::Num);
    }
    Some(Ident::Alpha(s.to_owned()))
}

fn valid_ident(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(text: &str) -> Semver {
        Semver::parse(text).unwrap_or_else(|| panic!("{text} should parse"))
    }

    #[test]
    fn parses_valid_versions_only() {
        for good in [
            "3.0.0",
            "v3.0.1",
            " 3.0.0\n",
            "1.0.0-rc.1",
            "1.0.0-0.3.7",
            "1.0.0-x-y.z",
            "1.0.0+build.5",
            "1.0.0-beta+exp.sha.5114f85",
        ] {
            assert!(Semver::parse(good).is_some(), "{good}");
        }
        for bad in [
            "",
            "3",
            "3.0",
            "3.0.0.0",
            "03.0.0",
            "3.0.x",
            "3.0.0-",
            "3.0.0-01",
            "3.0.0-a..b",
            "3.0.0+",
            "3.0.0-α",
            "Onebox 3.0.0",
            "-1.0.0",
        ] {
            assert!(Semver::parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn precedence_follows_the_semver_spec() {
        // The example chain of semver §11, strictly increasing.
        let chain = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
            "1.0.1",
            "1.1.0",
            "2.0.0",
            "10.0.0",
        ];
        for pair in chain.windows(2) {
            assert!(v(pair[0]) < v(pair[1]), "{} < {}", pair[0], pair[1]);
        }
        assert_eq!(v("1.0.0+a").cmp(&v("v1.0.0+b")), Ordering::Equal);
        assert!(v("3.0.1") > v("3.0.0"));
        assert!(v("3.0.0-rc.1") < v("3.0.0"));
    }
}
