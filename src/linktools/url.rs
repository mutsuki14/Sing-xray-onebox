//! Strict HTTP(S) test URLs: what `--url`, `--download-url` and
//! `--upload-url` accept, validated before any work starts (v2
//! `url_parts`). The text is handed to curl unchanged; host and port are
//! kept for `--connect-to`.
//!
//! Changes from v2: the port must be decimal digits (v2 accepted
//! `https://x:+80/` and passed it to curl as written, D-8.1#13) and its
//! range error names the URL port instead of a bare `参数必须在 …`.

use crate::error::{Error, Result};
use std::fmt;
use std::net::Ipv6Addr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    fn default_port(self) -> u16 {
        match self {
            Scheme::Http => 80,
            Scheme::Https => 443,
        }
    }
}

/// A validated test URL. Invariant: `text` contains no whitespace,
/// control characters, `#` or `\`, the scheme is exactly `http`/`https`,
/// there is no userinfo, and `host` is an IPv6 literal (unbracketed) or
/// matches `[A-Za-z0-9._-]+`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TestUrl {
    text: String,
    scheme: Scheme,
    host: String,
    port: u16,
}

/// Default health URL of every tool (v2): an HTTPS endpoint answering 204.
pub const DEFAULT_HEALTH_URL: &str = "https://www.gstatic.com/generate_204";

impl TestUrl {
    /// [`DEFAULT_HEALTH_URL`], already validated.
    pub fn default_health() -> TestUrl {
        TestUrl {
            text: DEFAULT_HEALTH_URL.to_owned(),
            scheme: Scheme::Https,
            host: "www.gstatic.com".to_owned(),
            port: 443,
        }
    }

    pub fn parse(url: &str) -> Result<TestUrl> {
        ensure!(
            !url.bytes().any(|b| b <= b' ' || b == 0x7f || b == b'#' || b == b'\\'),
            "测试 URL 包含空白、片段或控制字符"
        );
        let (scheme, rest) = url
            .split_once("://")
            .ok_or_else(|| Error::msg("测试 URL 必须为 HTTP(S)"))?;
        let scheme = match scheme {
            "http" => Scheme::Http,
            "https" => Scheme::Https,
            _ => bail!("测试 URL 必须为 HTTP(S)"),
        };
        let authority = rest.split(['/', '?']).next().unwrap_or("");
        ensure!(
            !authority.is_empty() && !authority.contains('@'),
            "测试 URL 不得包含账号，且必须有主机名"
        );
        let (host, port) = split_authority(authority, scheme.default_port())?;
        Ok(TestUrl {
            text: url.to_owned(),
            scheme,
            host,
            port,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// Host without IPv6 brackets.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The explicit port, else 443 (https) / 80 (http).
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl fmt::Display for TestUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

fn split_authority(authority: &str, default_port: u16) -> Result<(String, u16)> {
    if let Some(bracketed) = authority.strip_prefix('[') {
        let (host, tail) = bracketed
            .split_once(']')
            .ok_or_else(|| Error::msg("IPv6 URL 地址无效"))?;
        // Zone ids (`fe80::1%eth0`) do not parse and are rejected.
        host.parse::<Ipv6Addr>()
            .map_err(|_| Error::msg("IPv6 URL 地址无效"))?;
        let port = match tail {
            "" => default_port,
            _ => parse_port(
                tail.strip_prefix(':')
                    .ok_or_else(|| Error::msg("URL 端口无效"))?,
            )?,
        };
        return Ok((host.to_owned(), port));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, parse_port(port)?),
        None => (authority, default_port),
    };
    ensure!(valid_host(host), "URL 主机名无效（国际域名请使用 Punycode）");
    Ok((host.to_owned(), port))
}

fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b))
}

/// Decimal digits only, 1..=65535.
fn parse_port(text: &str) -> Result<u16> {
    ensure!(
        !text.is_empty() && text.len() <= 5 && text.bytes().all(|b| b.is_ascii_digit()),
        "URL 端口无效"
    );
    match text.parse::<u32>() {
        Ok(port @ 1..=65535) => Ok(port as u16),
        _ => bail!("URL 端口必须在 1..65535 之间"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_what_v2_rejected_with_its_messages() {
        let cases = [
            ("file:///etc/passwd", "测试 URL 必须为 HTTP(S)"),
            ("HTTPS://x/", "测试 URL 必须为 HTTP(S)"),
            ("example.org/x", "测试 URL 必须为 HTTP(S)"),
            ("https://a:b@example.org", "测试 URL 不得包含账号，且必须有主机名"),
            ("https:///path", "测试 URL 不得包含账号，且必须有主机名"),
            ("https://x/#frag", "测试 URL 包含空白、片段或控制字符"),
            (
                "https://x/\r\nInjected:yes",
                "测试 URL 包含空白、片段或控制字符",
            ),
            ("https://x y/", "测试 URL 包含空白、片段或控制字符"),
            ("https://x\\@elsewhere", "测试 URL 包含空白、片段或控制字符"),
            ("https://[::1]:0/", "URL 端口必须在 1..65535 之间"),
            ("https://x:65536/", "URL 端口必须在 1..65535 之间"),
            ("https://x:+80/", "URL 端口无效"),
            ("https://x:/", "URL 端口无效"),
            ("https://[::1]x/", "URL 端口无效"),
            ("https://[::1/", "IPv6 URL 地址无效"),
            ("https://[fe80::1%25eth0]/", "IPv6 URL 地址无效"),
            ("https://[nope]/", "IPv6 URL 地址无效"),
            ("https://::1/", "URL 主机名无效（国际域名请使用 Punycode）"),
            ("https://例子.cn/", "URL 主机名无效（国际域名请使用 Punycode）"),
            ("https://a*b/", "URL 主机名无效（国际域名请使用 Punycode）"),
        ];
        for (url, message) in cases {
            let err = TestUrl::parse(url).unwrap_err();
            assert_eq!(err.to_string(), message, "{url}");
        }
    }

    #[test]
    fn extracts_host_and_port() {
        let cases = [
            ("https://[::1]:8443/path?q=1", Scheme::Https, "::1", 8443),
            ("http://localhost/", Scheme::Http, "localhost", 80),
            ("https://www.gstatic.com/generate_204", Scheme::Https, "www.gstatic.com", 443),
            ("https://[2001:db8::1]", Scheme::Https, "2001:db8::1", 443),
            ("http://127.0.0.1:8080?x=1", Scheme::Http, "127.0.0.1", 8080),
            ("https://a_b.example:443/", Scheme::Https, "a_b.example", 443),
        ];
        for (text, scheme, host, port) in cases {
            let url = TestUrl::parse(text).unwrap();
            assert_eq!(
                (url.scheme(), url.host(), url.port(), url.as_str()),
                (scheme, host, port, text),
                "{text}"
            );
            assert_eq!(url.to_string(), text);
        }
        assert_eq!(
            TestUrl::default_health(),
            TestUrl::parse(DEFAULT_HEALTH_URL).unwrap()
        );
    }
}
