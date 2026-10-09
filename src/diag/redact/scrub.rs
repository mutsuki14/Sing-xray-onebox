//! The pattern passes of the redactor: IP literals, then domain-shaped
//! words. They catch what the known values miss (addresses in core or nginx
//! output, values of a state that could not be loaded), so they lean
//! towards over-redaction: a word is kept only when it clearly is not an
//! address or a domain name (a version, a file name, a JSON path segment).
//!
//! Word boundaries: `_` separates (`_acme-challenge.example.com`,
//! `example.com_ecc`, `host_192.0.2.1`), and so does a change between CJK
//! and other letters (`域名example.net无效`).

use super::{DOMAIN, IP};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Final labels that make a dotted word a file name. None of them is a
/// delegated top-level domain: `.sh`, `.zip`, `.md`, `.py`, `.so`, `.new`
/// and `.target` are, so `node.example.sh` is a domain name.
const FILE_EXTENSIONS: [&str; 46] = [
    "json", "conf", "pem", "key", "crt", "csr", "cer", "der", "log", "sock", "service", "socket",
    "timer", "bash", "txt", "html", "htm", "css", "js", "yaml", "yml", "toml", "ini", "cfg", "old",
    "bak", "orig", "tmp", "temp", "lock", "pid", "gz", "tgz", "tar", "xz", "zst", "db", "xml",
    "svg", "png", "ico", "list", "dgst", "sig", "asc", "deb",
];
/// File and unit names whose final label is also a top-level domain.
const KNOWN_NAMES: [&str; 9] = [
    "acme.sh",
    "cf.sh",
    "onebox.sh",
    "onebox-v2.sh",
    "install.sh",
    "network.target",
    "network-online.target",
    "multi-user.target",
    "nss-lookup.target",
];
/// A backup suffix after a file extension (`nginx.conf.new`).
const BACKUP_SUFFIX: &str = "new";

/// IP literals, then domain names.
pub fn scrub(text: &str) -> String {
    scrub_domains(&scrub_ipv4(&scrub_ipv6(text)))
}

/// Replace every maximal run of `in_run` characters for which `replace`
/// returns a replacement; `replace` gets the run and the characters just
/// before and after it.
fn scrub_runs(
    text: &str,
    in_run: impl Fn(char) -> bool,
    replace: impl Fn(&str, Option<char>, Option<char>) -> Option<String>,
) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    let mut before: Option<char> = None;
    while let Some(start) = rest.find(&in_run) {
        out.push_str(&rest[..start]);
        if start > 0 {
            before = rest[..start].chars().next_back();
        }
        rest = &rest[start..];
        let len = rest.find(|c: char| !in_run(c)).unwrap_or(rest.len());
        let (run, tail) = rest.split_at(len);
        match replace(run, before, tail.chars().next()) {
            Some(replacement) => out.push_str(&replacement),
            None => out.push_str(run),
        }
        before = run.chars().next_back();
        rest = tail;
    }
    out.push_str(rest);
    out
}

/// An ASCII letter or digit next to a candidate makes it part of a longer
/// word (`v1.2.3.4`, `crate::diag`); `_` does not.
fn joins(c: Option<char>) -> bool {
    c.is_some_and(|c| c.is_ascii_alphanumeric())
}

/// IPv6 literals: runs of hex digits, `:` and `.` with at least two colons.
fn scrub_ipv6(text: &str) -> String {
    scrub_runs(
        text,
        |c| c.is_ascii_hexdigit() || c == ':' || c == '.',
        ipv6_run,
    )
}

fn ipv6_run(run: &str, before: Option<char>, after: Option<char>) -> Option<String> {
    // `addr:2001:db8::1`: the colon after a word separates it.
    let (lead, body) = if joins(before) {
        (":", run.strip_prefix(':')?)
    } else {
        ("", run)
    };
    if joins(after) || body.matches(':').count() < 2 {
        return None;
    }
    // `::1:` or `fe80::1.` at the end of a sentence.
    [body, body.trim_end_matches(['.', ':'])]
        .into_iter()
        .find(|candidate| candidate.parse::<Ipv6Addr>().is_ok())
        .map(|found| format!("{lead}{IP}{}", &body[found.len()..]))
}

/// IPv4 literals: runs of digits and dots.
fn scrub_ipv4(text: &str) -> String {
    scrub_runs(
        text,
        |c| c.is_ascii_digit() || c == '.',
        |run, before, after| {
            if joins(before) || joins(after) {
                return None;
            }
            let start = run.len() - run.trim_start_matches('.').len();
            let end = run.trim_end_matches('.').len();
            (start < end && run[start..end].parse::<Ipv4Addr>().is_ok())
                .then(|| format!("{}{IP}{}", &run[..start], &run[end..]))
        },
    )
}

fn word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '-' || c == '.'
}

/// CJK scripts, which Chinese text writes next to Latin words without a
/// space.
fn is_wide(c: char) -> bool {
    matches!(c,
        '\u{2E80}'..='\u{9FFF}'
        | '\u{AC00}'..='\u{D7AF}'
        | '\u{F900}'..='\u{FAFF}'
        | '\u{FF00}'..='\u{FFEF}'
        | '\u{20000}'..='\u{3FFFF}')
}

/// Byte length of the word at the start of `text`: word characters of one
/// script class (`.` and `-` belong to either).
fn word_len(text: &str) -> usize {
    let mut wide: Option<bool> = None;
    for (i, c) in text.char_indices() {
        if !word_char(c) {
            return i;
        }
        if c.is_alphanumeric() {
            match wide {
                None => wide = Some(is_wide(c)),
                Some(w) if w != is_wide(c) => return i,
                Some(_) => {}
            }
        }
    }
    text.len()
}

/// Domain-shaped words (see [`domain_len`]).
fn scrub_domains(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    let mut before: Option<char> = None;
    while let Some(start) = rest.find(word_char) {
        out.push_str(&rest[..start]);
        if start > 0 {
            before = rest[..start].chars().next_back();
        }
        rest = &rest[start..];
        let (word, tail) = rest.split_at(word_len(rest));
        match redact_word(word, before) {
            Some(replacement) => out.push_str(&replacement),
            None => out.push_str(word),
        }
        before = word.chars().next_back();
        rest = tail;
    }
    out.push_str(rest);
    out
}

fn redact_word(word: &str, before: Option<char>) -> Option<String> {
    // A segment of a configuration path: `inbounds[0].tls.server_name`.
    if before == Some(']') && word.starts_with('.') {
        return None;
    }
    let start = word.len() - word.trim_start_matches(['.', '-']).len();
    let end = word.trim_end_matches(['.', '-']).len();
    if start >= end {
        return None;
    }
    let len = domain_len(&word[start..end])?;
    Some(format!(
        "{}{DOMAIN}{}",
        &word[..start],
        &word[start + len..]
    ))
}

fn is_extension(label: &str) -> bool {
    FILE_EXTENSIONS.contains(&label.to_ascii_lowercase().as_str())
}

/// The byte length of the domain name `word` consists of, followed only by
/// file extensions (`example.com.crt` → 11); `None` when it is no domain
/// name (`sing-box.json`, `nginx.conf.new`, `acme.sh`, `1.14.2`).
pub fn domain_len(word: &str) -> Option<usize> {
    if KNOWN_NAMES
        .iter()
        .any(|name| name.eq_ignore_ascii_case(word))
    {
        return None;
    }
    let labels: Vec<&str> = word.split('.').collect();
    let mut n = labels.len();
    loop {
        if n >= 1 && is_extension(labels[n - 1]) {
            n -= 1;
        } else if n >= 2
            && labels[n - 1].eq_ignore_ascii_case(BACKUP_SUFFIX)
            && is_extension(labels[n - 2])
        {
            n -= 2;
        } else {
            break;
        }
    }
    let stem = &labels[..n];
    is_domain(stem).then(|| stem.iter().map(|label| label.len()).sum::<usize>() + n - 1)
}

/// At least two valid labels ending in a top-level label.
fn is_domain(labels: &[&str]) -> bool {
    let [.., last] = labels else {
        return false;
    };
    labels.len() >= 2 && labels.iter().all(|label| valid_label(label)) && valid_tld(last)
}

fn valid_label(label: &str) -> bool {
    (1..=63).contains(&label.chars().count())
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label.chars().all(|c| c.is_alphanumeric() || c == '-')
}

/// Letters (at least two when ASCII; any script, `中国`) or an IDNA
/// A-label (`xn--p1ai`).
fn valid_tld(label: &str) -> bool {
    let lower = label.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix("xn--") {
        return !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    }
    label.chars().all(char::is_alphabetic) && (!label.is_ascii() || label.len() >= 2)
}
