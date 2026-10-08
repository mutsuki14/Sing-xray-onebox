//! Text helpers: validation, quoting and sanitizing.

/// DNS name check: ≤ 253 chars, at least two labels, labels 1–63 chars of
/// `[a-z0-9-]` not starting/ending with `-`, alphabetic TLD. Unlike v2, IP
/// literals (all-numeric TLD) are rejected. Callers lower-case first.
pub fn valid_domain(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 || s.ends_with('.') || !s.contains('.') {
        return false;
    }
    let labels: Vec<&str> = s.split('.').collect();
    let label_ok = |l: &&str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    let tld_alpha = labels
        .last()
        .is_some_and(|t| t.bytes().any(|b| b.is_ascii_lowercase()));
    labels.iter().all(label_ok) && tld_alpha
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains() {
        assert!(valid_domain("www.example.com"));
        assert!(valid_domain("xn--fiqs8s.cn"));
        assert!(!valid_domain("1.2.3.4"));
        assert!(!valid_domain("example"));
        assert!(!valid_domain("example.com."));
        assert!(!valid_domain("-a.example.com"));
        assert!(!valid_domain("Example.com"));
    }
}
