//! Golden tests: expected texts are v2's output (spec H §3.5–3.7, §5.11,
//! and `onebox-v2 frps plan` for the summaries) with the deliberate
//! changes of the module docs.

use super::*;
use crate::domain::config::PortRange;
use crate::frp::model::{BindAddr, FrpState, Mode, WebSettings, DEFAULT_RANGE};

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const ROOT: &str = "/etc/onebox-frp";
const WEB: &str = "/var/lib/onebox-frp";

fn web(app: AppDomain, tls: WebTls) -> FrpState {
    FrpState::new(
        "frp.example.com".into(),
        TOKEN.into(),
        BindAddr::AnyV6,
        Mode::Web(WebSettings::new(app, tls)),
    )
}

fn single() -> FrpState {
    web(
        AppDomain::Single {
            domain: "app.example.com".into(),
        },
        WebTls::Http01,
    )
}

fn wildcard() -> FrpState {
    web(
        AppDomain::Wildcard {
            root: "apps.example.com".into(),
        },
        WebTls::Cloudflare,
    )
}

fn tcp() -> FrpState {
    FrpState::new(
        "frp.example.com".into(),
        TOKEN.into(),
        BindAddr::AnyV4,
        Mode::Tcp {
            range: DEFAULT_RANGE,
        },
    )
}

fn web_settings(state: &FrpState) -> WebSettings {
    state.web().unwrap().clone()
}

fn layout(ipv6: bool) -> NginxLayout<'static> {
    NginxLayout {
        frp_root: Path::new(ROOT),
        frp_web: Path::new(WEB),
        worker: "nginx nginx",
        ipv6,
    }
}

#[test]
fn quoting_matches_json() {
    for s in ["::", "a\"b", "c\\d", "x\ny", "\u{1}", "中文"] {
        assert_eq!(quote(s), serde_json::to_string(s).unwrap(), "{s:?}");
    }
}

#[test]
fn server_toml_web_mode() {
    let expected = format!(
        "bindAddr = \"::\"\nbindPort = 7000\nproxyBindAddr = \"127.0.0.1\"\nauth.method = \"token\"\n\
auth.token = \"{TOKEN}\"\nauth.additionalScopes = [\"HeartBeats\", \"NewWorkConns\"]\n\
transport.tls.force = true\ntransport.tls.certFile = \"/etc/onebox-frp/server-cert.pem\"\n\
transport.tls.keyFile = \"/etc/onebox-frp/server-key.pem\"\nallowPorts = [{{ start = 7000, end = 7000 }}]\n\
maxPortsPerClient = 10\nlog.to = \"console\"\nlog.level = \"info\"\nlog.disablePrintColor = true\n\
vhostHTTPPort = 7080\n"
    );
    let text = server_toml(&single(), Path::new(ROOT));
    assert_eq!(text, expected);
    assert!(!text.contains("webServer"));
    let wild = server_toml(&wildcard(), Path::new(ROOT));
    assert!(wild.ends_with("vhostHTTPPort = 7080\nsubDomainHost = \"apps.example.com\"\n"));
}

#[test]
fn server_toml_tcp_mode_binds_proxies_like_the_control_port() {
    let text = server_toml(&tcp(), Path::new(ROOT));
    assert!(
        text.starts_with("bindAddr = \"0.0.0.0\"\nbindPort = 7000\nproxyBindAddr = \"0.0.0.0\"\n")
    );
    assert!(text.contains("\nallowPorts = [{ start = 20000, end = 20100 }]\n"));
    assert!(text.ends_with("log.disablePrintColor = true\n"));
    assert!(!text.contains("vhostHTTPPort"));
}

const NGINX_FULL: &str = r#"# Managed by Onebox FRP
user nginx nginx;
worker_processes 1;
pid "/etc/onebox-frp/nginx.pid";
error_log "/etc/onebox-frp/nginx-error.log" warn;
events { worker_connections 1024; }
http {
 access_log off; server_tokens off; default_type text/plain;
 map $http_upgrade $onebox_frp_connection { default upgrade; '' close; }
 client_body_temp_path "/var/lib/onebox-frp/tmp/client_body";
 proxy_temp_path "/var/lib/onebox-frp/tmp/proxy";
 fastcgi_temp_path "/var/lib/onebox-frp/tmp/fastcgi";
 uwsgi_temp_path "/var/lib/onebox-frp/tmp/uwsgi";
 scgi_temp_path "/var/lib/onebox-frp/tmp/scgi";
 server { listen 80; listen [::]:80; server_name app.example.com;
 location ^~ /.well-known/acme-challenge/ { root "/var/lib/onebox-frp/www"; try_files $uri =404; }
 location / { return 301 https://$host$request_uri; }
 }
 server { listen 80 default_server; listen [::]:80 default_server; server_name _; return 404; }
 server { listen 443 ssl; listen [::]:443 ssl; server_name app.example.com; ssl_certificate "/etc/onebox-frp/web-tls/cert.pem"; ssl_certificate_key "/etc/onebox-frp/web-tls/key.pem"; ssl_protocols TLSv1.2 TLSv1.3;
 ssl_session_cache shared:onebox_frp:1m; ssl_session_timeout 10m; client_max_body_size 0;
 location / { proxy_pass http://127.0.0.1:7080; proxy_http_version 1.1;
 proxy_set_header Host $host; proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection $onebox_frp_connection;
 proxy_set_header X-Real-IP $remote_addr; proxy_set_header X-Forwarded-For $remote_addr;
 proxy_set_header X-Forwarded-Proto https; proxy_set_header X-Forwarded-Host $host; proxy_set_header X-Forwarded-Port 443; proxy_set_header Forwarded "";
 proxy_buffering off; proxy_request_buffering off; proxy_read_timeout 3600s; proxy_send_timeout 3600s;
 } }
 server { listen 443 ssl default_server; listen [::]:443 ssl default_server; server_name _; ssl_certificate "/etc/onebox-frp/web-tls/cert.pem"; ssl_certificate_key "/etc/onebox-frp/web-tls/key.pem"; ssl_protocols TLSv1.2 TLSv1.3; return 404; }
}
"#;

#[test]
fn nginx_full_config_is_v2_text() {
    let text = nginx_conf(&web_settings(&single()), &layout(true), NginxPhase::Full);
    assert_eq!(text, NGINX_FULL);
}

#[test]
fn nginx_variants() {
    // Without IPv6 each listener is followed by one space.
    let v4 = nginx_conf(&web_settings(&single()), &layout(false), NginxPhase::Full);
    assert!(v4.contains(" server { listen 80;  server_name app.example.com;\n"));
    assert!(v4.contains(" server { listen 80 default_server;  server_name _; return 404; }\n"));
    assert!(v4.contains(" server { listen 443 ssl;  server_name app.example.com; "));
    assert!(!v4.contains("[::]"));

    // Bootstrap: challenges only, no TLS servers.
    let boot = nginx_conf(
        &web_settings(&single()),
        &layout(true),
        NginxPhase::Bootstrap,
    );
    assert!(boot.contains("\n location / { return 404; }\n"));
    assert!(!boot.contains("ssl"));
    assert!(boot.ends_with(" server { listen 80 default_server; listen [::]:80 default_server; server_name _; return 404; }\n}\n"));

    // Wildcard, HTTPS on 8443, no redirect port.
    let mut settings = web_settings(&wildcard());
    settings.https_port = 8443;
    settings.redirect_port = 0;
    let text = nginx_conf(&settings, &layout(true), NginxPhase::Full);
    assert!(!text.contains("listen 80"));
    assert!(text.contains("server_name *.apps.example.com;"));
    assert!(text.contains("proxy_set_header X-Forwarded-Port 8443;"));
    // A redirect port with HTTPS ≠ 443 names the port.
    settings.redirect_port = 8080;
    let text = nginx_conf(&settings, &layout(true), NginxPhase::Full);
    assert!(text.contains("location / { return 301 https://$host:8443$request_uri; }"));
}

fn spec(kind: ProxyKind) -> ProxySpec {
    ProxySpec {
        kind,
        local_port: 8080,
        remote_port: 20000,
        subdomain: DEFAULT_SUBDOMAIN.into(),
    }
}

#[test]
fn client_bundle_single_domain() {
    let state = single();
    let expected = format!(
        "serverAddr = \"frp.example.com\"\nserverPort = 7000\nauth.method = \"token\"\n\
auth.token = \"{TOKEN}\"\nauth.additionalScopes = [\"HeartBeats\", \"NewWorkConns\"]\n\
transport.tls.enable = true\ntransport.tls.serverName = \"frp.example.com\"\n\
transport.tls.trustedCaFile = \"./ca.pem\"\nlog.to = \"console\"\nlog.disablePrintColor = true\n\n\
[[proxies]]\nname = \"onebox-http-app.example.com\"\ntype = \"http\"\nlocalIP = \"127.0.0.1\"\n\
localPort = 8080\ncustomDomains = [\"app.example.com\"]\n\
requestHeaders.set.\"X-Forwarded-Proto\" = \"https\"\n"
    );
    assert_eq!(client_toml(&state, &spec(ProxyKind::Http)), expected);
    assert_eq!(
        client_readme(&state, &spec(ProxyKind::Http)),
        "本目录含 FRP token，请私密保存。不要复制服务端 CA 私钥。\n\
在内网机器安装 frpc 0.71.0，复制整个目录并进入该目录：\nfrpc verify -c frpc.toml\n\
frpc -c frpc.toml\n内网服务：127.0.0.1:8080\n访问：https://app.example.com:443/\n\
必须保留 trustedCaFile 与 serverName 校验。\n"
    );
}

#[test]
fn client_bundle_wildcard_and_tcp() {
    let mut wild_spec = spec(ProxyKind::Http);
    wild_spec.subdomain = "home".into();
    let text = client_toml(&wildcard(), &wild_spec);
    assert!(text.contains("name = \"onebox-http-home.apps.example.com\"\n"));
    assert!(text.ends_with(
        "localPort = 8080\nsubdomain = \"home\"\nrequestHeaders.set.\"X-Forwarded-Proto\" = \"https\"\n"
    ));
    assert_eq!(
        endpoint(&wildcard(), &wild_spec),
        "https://home.apps.example.com:443/"
    );
    for kind in [ProxyKind::Tcp, ProxyKind::Udp] {
        let text = client_toml(&tcp(), &spec(kind));
        assert!(text.contains(&format!(
            "name = \"onebox-{}-20000\"\ntype = \"{}\"\n",
            kind.id(),
            kind.id()
        )));
        assert!(text.ends_with("localPort = 8080\nremotePort = 20000\n"));
        assert_eq!(
            endpoint(&tcp(), &spec(kind)),
            format!("frp.example.com:20000 ({})", kind.id())
        );
    }
    assert_eq!(ProxyKind::parse("udp"), Some(ProxyKind::Udp));
    assert_eq!(ProxyKind::parse("quic"), None);
}

#[test]
fn summaries() {
    assert_eq!(
        summary(&single()),
        "FRP web / v0.71.0\n控制入口: frp.example.com:7000（TLS + 私有 CA + token）\n\
控制域名 A / AAAA 应直接指向 VPS，关闭 CDN 代理。凭据不在此处显示。\n\
应用入口: https://app.example.com/\n内部转发: 127.0.0.1:7080；证书方式: http\n\
HTTP-01 申请和自动续期需要持续开放公网 TCP 80。\n保留端口: 7000-7000/tcp\n\
保留端口: 7080-7080/tcp\n保留端口: 443-443/tcp\n保留端口: 80-80/tcp"
    );
    let mut state = wildcard();
    if let Mode::Web(w) = &mut state.mode {
        w.https_port = 8443;
        w.redirect_port = 0;
    }
    assert_eq!(
        summary(&state),
        "FRP web / v0.71.0\n控制入口: frp.example.com:7000（TLS + 私有 CA + token）\n\
控制域名 A / AAAA 应直接指向 VPS，关闭 CDN 代理。凭据不在此处显示。\n\
应用入口: https://www.apps.example.com:8443/\n内部转发: 127.0.0.1:7080；证书方式: cf\n\
添加泛域名解析 *.apps.example.com，客户端 subdomain = www\n保留端口: 7000-7000/tcp\n\
保留端口: 7080-7080/tcp\n保留端口: 8443-8443/tcp"
    );
    let mut tcp = tcp();
    tcp.mode = Mode::Tcp {
        range: PortRange {
            start: 30000,
            end: 30010,
        },
    };
    assert_eq!(
        summary(&tcp),
        "FRP tcp / v0.71.0\n控制入口: frp.example.com:7000（TLS + 私有 CA + token）\n\
控制域名 A / AAAA 应直接指向 VPS，关闭 CDN 代理。凭据不在此处显示。\n\
公网 TCP / UDP 转发范围: 30000-30010\n保留端口: 7000-7000/tcp\n保留端口: 30000-30010/both"
    );
    assert!(!summary(&tcp).contains(TOKEN));
}
