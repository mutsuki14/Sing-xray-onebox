//! SOCKS5 as the link tools speak it, as pure codecs over `Read + Write`:
//! the username/password client used against the temporary client cores
//! (RFC 1928 + RFC 1929) and the CONNECT-only, no-auth server of
//! `failover`. Reply bytes are exactly v2's (spec D §2.5, §4.4).
//!
//! Changes from v2: a refused request is a typed outcome instead of an
//! early `Ok` from deep inside the handler; the credential length is
//! checked instead of silently truncated to one byte; [`SocksEndpoint`]
//! never prints its token in `Debug` output.

use crate::error::{Error, Result};
use std::fmt;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::time::Duration;

/// Fixed SOCKS username of the temporary client cores (v2).
pub const USERNAME: &str = "onebox-";

const VERSION: u8 = 5;
const AUTH_VERSION: u8 = 1;
const METHOD_NO_AUTH: u8 = 0;
const METHOD_PASSWORD: u8 = 2;
const METHOD_NONE_ACCEPTABLE: u8 = 0xff;
const CMD_CONNECT: u8 = 1;
const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_IPV6: u8 = 4;

/// `05 FF`: none of the offered authentication methods is acceptable.
pub const NO_ACCEPTABLE_METHODS: [u8; 2] = [VERSION, METHOD_NONE_ACCEPTABLE];
/// `05 00`: no authentication.
pub const METHOD_SELECTED: [u8; 2] = [VERSION, METHOD_NO_AUTH];
/// Reply `succeeded`, BND = 0.0.0.0:0.
pub const REPLY_SUCCEEDED: [u8; 10] = reply(0);
/// Reply `host unreachable` (no healthy entry, upstream refused).
pub const REPLY_HOST_UNREACHABLE: [u8; 10] = reply(4);
/// Reply `command not supported` (anything but CONNECT).
pub const REPLY_COMMAND_NOT_SUPPORTED: [u8; 10] = reply(7);

const fn reply(code: u8) -> [u8; 10] {
    [VERSION, code, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0]
}

/// The loopback SOCKS inbound of a temporary client core.
#[derive(Clone, PartialEq, Eq)]
pub struct SocksEndpoint {
    pub port: u16,
    /// Password of [`USERNAME`]; 48 lowercase hex characters.
    pub token: String,
}

impl SocksEndpoint {
    pub fn address(&self) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, self.port))
    }

    /// The proxy URL curl uses (remote DNS: domains reach the core as is).
    pub fn proxy_url(&self) -> String {
        format!("socks5h://127.0.0.1:{}", self.port)
    }
}

impl fmt::Debug for SocksEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SocksEndpoint")
            .field("port", &self.port)
            .field("token", &"<redacted>")
            .finish()
    }
}

/// A CONNECT destination. Domains stay unresolved (socks5h semantics).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
}

fn read_array<const N: usize>(stream: &mut impl Read) -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn read_vec(stream: &mut impl Read, len: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0u8; len];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}

/// Client: offer username/password only and log in as [`USERNAME`].
pub fn login<S: Read + Write>(stream: &mut S, token: &str) -> Result<()> {
    let password = u8::try_from(token.len()).map_err(|_| Error::msg("SOCKS 认证信息过长"))?;
    stream.write_all(&[VERSION, 1, METHOD_PASSWORD])?;
    ensure!(
        read_array::<2>(stream)? == [VERSION, METHOD_PASSWORD],
        "SOCKS 认证方式不匹配"
    );
    let mut auth = vec![AUTH_VERSION, USERNAME.len() as u8];
    auth.extend_from_slice(USERNAME.as_bytes());
    auth.push(password);
    auth.extend_from_slice(token.as_bytes());
    stream.write_all(&auth)?;
    ensure!(
        read_array::<2>(stream)? == [AUTH_VERSION, 0],
        "SOCKS 认证失败"
    );
    Ok(())
}

/// ATYP + address + big-endian port. IP literals are sent as addresses,
/// anything else as a domain (1..=255 printable ASCII bytes).
pub fn encode_address(host: &str, port: u16) -> Result<Vec<u8>> {
    let mut out = match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => [&[ATYP_IPV4][..], &ip.octets()].concat(),
        Ok(IpAddr::V6(ip)) => [&[ATYP_IPV6][..], &ip.octets()].concat(),
        Err(_) => {
            let printable = host.bytes().all(|b| b > b' ' && b < 0x7f);
            ensure!(
                !host.is_empty() && host.len() <= 255 && printable,
                "SOCKS 域名无效"
            );
            [&[ATYP_DOMAIN, host.len() as u8][..], host.as_bytes()].concat()
        }
    };
    out.extend_from_slice(&port.to_be_bytes());
    Ok(out)
}

/// Read an address of type `atyp` (without the port).
pub fn read_address(stream: &mut impl Read, atyp: u8) -> Result<String> {
    match atyp {
        ATYP_IPV4 => Ok(Ipv4Addr::from(read_array::<4>(stream)?).to_string()),
        ATYP_IPV6 => Ok(Ipv6Addr::from(read_array::<16>(stream)?).to_string()),
        ATYP_DOMAIN => {
            let [len] = read_array::<1>(stream)?;
            ensure!(len > 0, "SOCKS 域名为空");
            String::from_utf8(read_vec(stream, usize::from(len))?)
                .map_err(|_| Error::msg("SOCKS 域名无效"))
        }
        _ => bail!("SOCKS 地址类型无效"),
    }
}

/// Client: CONNECT to `host:port` on a logged-in stream and consume the
/// reply (including the bound address).
pub fn request_connect<S: Read + Write>(stream: &mut S, host: &str, port: u16) -> Result<()> {
    let mut request = vec![VERSION, CMD_CONNECT, 0];
    request.extend(encode_address(host, port)?);
    stream.write_all(&request)?;
    let head = read_array::<4>(stream)?;
    ensure!(head[..3] == [VERSION, 0, 0], "代理拒绝连接");
    read_address(stream, head[3])?;
    read_array::<2>(stream)?;
    Ok(())
}

/// Connect to `endpoint` and log in; `timeout` bounds the connect and
/// every read/write on the returned stream.
pub fn dial(endpoint: &SocksEndpoint, timeout: Duration) -> Result<TcpStream> {
    let mut stream = TcpStream::connect_timeout(&endpoint.address(), timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    login(&mut stream, &endpoint.token)?;
    Ok(stream)
}

/// [`dial`] then CONNECT; the returned stream carries the tunnel.
pub fn connect(endpoint: &SocksEndpoint, target: &Target, timeout: Duration) -> Result<TcpStream> {
    let mut stream = dial(endpoint, timeout)?;
    request_connect(&mut stream, &target.host, target.port)?;
    Ok(stream)
}

/// What the server side of a handshake decided.
#[derive(Debug, PartialEq, Eq)]
pub enum Handshake {
    /// A CONNECT request: the caller replies and relays.
    Connect(Target),
    /// Already answered with a refusal (no acceptable method, or a command
    /// other than CONNECT); the caller just closes.
    Refused,
}

/// Server: accept only "no authentication" and CONNECT. Malformed input
/// is an error without a reply (v2).
pub fn accept_handshake<S: Read + Write>(stream: &mut S) -> Result<Handshake> {
    let [version, count] = read_array::<2>(stream)?;
    ensure!(version == VERSION && count > 0, "SOCKS 请求无效");
    let methods = read_vec(stream, usize::from(count))?;
    if !methods.contains(&METHOD_NO_AUTH) {
        stream.write_all(&NO_ACCEPTABLE_METHODS)?;
        return Ok(Handshake::Refused);
    }
    stream.write_all(&METHOD_SELECTED)?;
    let head = read_array::<4>(stream)?;
    if head[..3] != [VERSION, CMD_CONNECT, 0] {
        stream.write_all(&REPLY_COMMAND_NOT_SUPPORTED)?;
        return Ok(Handshake::Refused);
    }
    let host = read_address(stream, head[3])?;
    let port = u16::from_be_bytes(read_array::<2>(stream)?);
    Ok(Handshake::Connect(Target { host, port }))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::{self, Cursor};

    /// In-memory duplex stream: reads from `input`, records writes.
    pub(crate) struct Duplex {
        pub input: Cursor<Vec<u8>>,
        pub output: Vec<u8>,
    }

    impl Duplex {
        pub fn new(input: &[u8]) -> Duplex {
            Duplex {
                input: Cursor::new(input.to_vec()),
                output: Vec::new(),
            }
        }
    }

    impl Read for Duplex {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.input.read(buf)
        }
    }

    impl Write for Duplex {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.output.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn login_sends_the_exact_rfc1929_bytes() {
        let mut stream = Duplex::new(&[5, 2, 1, 0]);
        login(&mut stream, "abc").unwrap();
        assert_eq!(
            stream.output,
            [&[5u8, 1, 2, 1, 7][..], b"onebox-", &[3], b"abc"].concat()
        );
        for (reply, message) in [
            (&[5u8, 0][..], "SOCKS 认证方式不匹配"),
            (&[5, 2, 1, 1], "SOCKS 认证失败"),
        ] {
            let err = login(&mut Duplex::new(reply), "abc").unwrap_err();
            assert_eq!(err.to_string(), message);
        }
        assert!(login(&mut Duplex::new(&[5]), "abc").is_err(), "short reply");
        let long = "x".repeat(256);
        let err = login(&mut Duplex::new(&[5, 2, 1, 0]), &long).unwrap_err();
        assert_eq!(err.to_string(), "SOCKS 认证信息过长");
    }

    #[test]
    fn addresses_encode_by_kind() {
        let cases: [(&str, u16, &[u8]); 3] = [
            ("1.2.3.4", 443, &[1, 1, 2, 3, 4, 1, 187]),
            ("example.org", 80, b"\x03\x0bexample.org\x00\x50"),
            (
                "::1",
                8080,
                &[
                    4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x1f, 0x90,
                ],
            ),
        ];
        for (host, port, bytes) in cases {
            assert_eq!(encode_address(host, port).unwrap(), bytes, "{host}");
        }
        for bad in ["", "a b", "tab\t", "é.example", &"a".repeat(256)] {
            let err = encode_address(bad, 1).unwrap_err();
            assert_eq!(err.to_string(), "SOCKS 域名无效", "{bad:?}");
        }
        assert!(encode_address(&"a".repeat(255), 1).is_ok());
    }

    #[test]
    fn connect_consumes_every_reply_shape() {
        let replies: [&[u8]; 3] = [
            &[5, 0, 0, 1, 0, 0, 0, 0, 0, 0],
            &[5, 0, 0, 3, 1, b'x', 0, 1],
            &[
                5, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1,
            ],
        ];
        for reply in replies {
            let mut stream = Duplex::new(reply);
            request_connect(&mut stream, "example.org", 443).unwrap();
            assert_eq!(stream.output, b"\x05\x01\x00\x03\x0bexample.org\x01\xbb");
            assert_eq!(stream.input.position() as usize, reply.len(), "{reply:?}");
        }
        let err = request_connect(&mut Duplex::new(&REPLY_HOST_UNREACHABLE), "x", 1);
        assert_eq!(err.unwrap_err().to_string(), "代理拒绝连接");
        let err = request_connect(&mut Duplex::new(&[5, 0, 0, 9]), "x", 1);
        assert_eq!(err.unwrap_err().to_string(), "SOCKS 地址类型无效");
    }

    #[test]
    fn server_accepts_connect_without_auth() {
        let cases: [(&[u8], Target); 3] = [
            (
                b"\x05\x02\x02\x00\x05\x01\x00\x03\x0bexample.org\x01\xbb",
                Target {
                    host: "example.org".into(),
                    port: 443,
                },
            ),
            (
                &[5, 1, 0, 5, 1, 0, 1, 10, 0, 0, 1, 0, 80],
                Target {
                    host: "10.0.0.1".into(),
                    port: 80,
                },
            ),
            (
                &[
                    5, 1, 0, 5, 1, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 22,
                ],
                Target {
                    host: "::1".into(),
                    port: 22,
                },
            ),
        ];
        for (input, target) in cases {
            let mut stream = Duplex::new(input);
            assert_eq!(
                accept_handshake(&mut stream).unwrap(),
                Handshake::Connect(target)
            );
            assert_eq!(stream.output, METHOD_SELECTED);
        }
    }

    #[test]
    fn server_refusals_use_v2_reply_bytes() {
        let mut stream = Duplex::new(&[5, 1, 2]);
        assert_eq!(accept_handshake(&mut stream).unwrap(), Handshake::Refused);
        assert_eq!(stream.output, [5, 0xff]);

        for request in [[5u8, 2, 0, 1], [5, 3, 0, 1], [4, 1, 0, 1], [5, 1, 1, 1]] {
            let mut input = vec![5, 1, 0];
            input.extend_from_slice(&request);
            let mut stream = Duplex::new(&input);
            assert_eq!(accept_handshake(&mut stream).unwrap(), Handshake::Refused);
            assert_eq!(
                stream.output,
                [&METHOD_SELECTED[..], &[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]].concat()
            );
        }
        assert_eq!(REPLY_SUCCEEDED, [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(REPLY_HOST_UNREACHABLE, [5, 4, 0, 1, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn malformed_server_input_is_an_error_without_reply() {
        let cases: [(&[u8], &str); 4] = [
            (&[4, 1, 0], "SOCKS 请求无效"),
            (&[5, 0], "SOCKS 请求无效"),
            (&[5, 1, 0, 5, 1, 0, 3, 0], "SOCKS 域名为空"),
            (&[5, 1, 0, 5, 1, 0, 9], "SOCKS 地址类型无效"),
        ];
        for (input, message) in cases {
            let mut stream = Duplex::new(input);
            let err = accept_handshake(&mut stream).unwrap_err();
            assert_eq!(err.to_string(), message, "{input:?}");
        }
        let mut invalid_utf8 = Duplex::new(&[5, 1, 0, 5, 1, 0, 3, 1, 0xff, 0, 80]);
        assert!(accept_handshake(&mut invalid_utf8).is_err());
    }

    #[test]
    fn endpoint_debug_hides_the_token() {
        let endpoint = SocksEndpoint {
            port: 1080,
            token: "secret-token".into(),
        };
        let text = format!("{endpoint:?}");
        assert!(text.contains("1080") && !text.contains("secret-token"));
        assert_eq!(endpoint.proxy_url(), "socks5h://127.0.0.1:1080");
    }
}
