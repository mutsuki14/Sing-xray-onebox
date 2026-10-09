//! Pure renderers: `frps.toml` (spec H §3.5), the web-mode `nginx.conf`
//! (H §3.7), the exported client bundle (H §3.6) and the summary text
//! (H §5.11). Byte-for-byte v2 output except the changes listed here.
//!
//! Changes from v2:
//! - `allowPorts` comes from [`FrpState::allow_ports`]: in web mode it is
//!   the bind port alone (v2 allowed TCP/UDP proxies on 20000–20100 there,
//!   H-8.1#8);
//! - the wildcard summary shows the label the export uses by default
//!   (`www`, [`DEFAULT_SUBDOMAIN`]) instead of `app` (H-8.1#4);
//! - the nginx worker account comes from `host::nginx::worker` (the distro
//!   `user` directive first) and IPv6 listeners follow the one
//!   `ipv6_available` answer.

use super::model::{AppDomain, BindAddr, FrpState, Mode, WebSettings, WebTls};
use std::fmt::Write as _;
use std::path::Path;

/// The application label of a wildcard deployment unless the user picks
/// another one at export time.
pub const DEFAULT_SUBDOMAIN: &str = "www";

/// A TOML basic string (JSON-compatible escaping, as v2 produced it with
/// `serde_json::to_string`).
pub fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn path(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

/// `frps.toml` (exact keys and order of v2). `frp_root` holds the control
/// certificate pair.
pub fn server_toml(state: &FrpState, frp_root: &Path) -> String {
    let proxy_bind = if state.is_web() {
        BindAddr::LoopbackV4
    } else {
        state.bind_addr
    };
    let allow = state
        .allow_ports()
        .iter()
        .map(|(start, end)| format!("{{ start = {start}, end = {end} }}"))
        .collect::<Vec<_>>()
        .join(", ");
    let mut out = format!(
        "bindAddr = {}\nbindPort = {}\nproxyBindAddr = {}\nauth.method = \"token\"\n\
         auth.token = {}\nauth.additionalScopes = [\"HeartBeats\", \"NewWorkConns\"]\n\
         transport.tls.force = true\ntransport.tls.certFile = {}\ntransport.tls.keyFile = {}\n\
         allowPorts = [{allow}]\nmaxPortsPerClient = 10\nlog.to = \"console\"\n\
         log.level = \"info\"\nlog.disablePrintColor = true\n",
        quote(state.bind_addr.as_str()),
        state.bind_port,
        quote(proxy_bind.as_str()),
        quote(&state.token),
        quote(&path(&frp_root.join("server-cert.pem"))),
        quote(&path(&frp_root.join("server-key.pem"))),
    );
    if let Some(web) = state.web() {
        let _ = writeln!(out, "vhostHTTPPort = {}", web.http_port);
        if let AppDomain::Wildcard { root } = &web.app {
            let _ = writeln!(out, "subDomainHost = {}", quote(root));
        }
    }
    out
}

/// Which `nginx.conf` to render.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NginxPhase {
    /// Port 80 only, serving HTTP-01 challenges before a certificate exists.
    Bootstrap,
    /// Redirect server plus the TLS reverse proxy.
    Full,
}

/// Where the web nginx keeps its files and how it runs.
#[derive(Clone, Copy, Debug)]
pub struct NginxLayout<'a> {
    /// Prefix: `nginx.pid`, `nginx-error.log`, `web-tls/`.
    pub frp_root: &'a Path,
    /// `www/` (ACME webroot) and `tmp/` (temp paths).
    pub frp_web: &'a Path,
    /// The `user` directive operand (`www-data www-data`).
    pub worker: &'a str,
    pub ipv6: bool,
}

/// `listen {port}{suffix};` plus the IPv6 twin, or a single trailing space
/// without IPv6 (v2 whitespace).
fn listen(layout: &NginxLayout, port: u16, suffix: &str) -> String {
    let v6 = if layout.ipv6 {
        format!("listen [::]:{port}{suffix};")
    } else {
        String::new()
    };
    format!("listen {port}{suffix}; {v6}")
}

/// The web-mode `nginx.conf` (v2 text, whitespace included).
pub fn nginx_conf(web: &WebSettings, layout: &NginxLayout, phase: NginxPhase) -> String {
    let root = path(layout.frp_root);
    let www = path(&layout.frp_web.join("www"));
    let mut s = format!(
        "# Managed by Onebox FRP\nuser {};\nworker_processes 1;\npid \"{root}/nginx.pid\";\n\
         error_log \"{root}/nginx-error.log\" warn;\nevents {{ worker_connections 1024; }}\n\
         http {{\n access_log off; server_tokens off; default_type text/plain;\n \
         map $http_upgrade $onebox_frp_connection {{ default upgrade; '' close; }}\n",
        layout.worker
    );
    for kind in ["client_body", "proxy", "fastcgi", "uwsgi", "scgi"] {
        let _ = writeln!(
            s,
            " {kind}_temp_path \"{}/tmp/{kind}\";",
            path(layout.frp_web)
        );
    }
    let names = match &web.app {
        AppDomain::Single { domain } => domain.clone(),
        AppDomain::Wildcard { root } => format!("*.{root}"),
    };
    if web.redirect_port > 0 {
        let target = match phase {
            NginxPhase::Bootstrap => "return 404;".to_owned(),
            NginxPhase::Full => format!(
                "return 301 https://$host{}$request_uri;",
                port_suffix(web.https_port)
            ),
        };
        let _ = write!(
            s,
            " server {{ {} server_name {names};\n location ^~ /.well-known/acme-challenge/ \
             {{ root \"{www}\"; try_files $uri =404; }}\n location / {{ {target} }}\n }}\n \
             server {{ {} server_name _; return 404; }}\n",
            listen(layout, web.redirect_port, ""),
            listen(layout, web.redirect_port, " default_server"),
        );
    }
    if phase == NginxPhase::Full {
        s.push_str(&tls_servers(web, layout, &names));
    }
    s.push_str("}\n");
    s
}

/// `:{port}` unless it is 443.
fn port_suffix(https_port: u16) -> String {
    if https_port == 443 {
        String::new()
    } else {
        format!(":{https_port}")
    }
}

fn tls_servers(web: &WebSettings, layout: &NginxLayout, names: &str) -> String {
    let cert = path(&layout.frp_root.join("web-tls/cert.pem"));
    let key = path(&layout.frp_root.join("web-tls/key.pem"));
    let tls = format!(
        "ssl_certificate \"{cert}\"; ssl_certificate_key \"{key}\"; ssl_protocols TLSv1.2 TLSv1.3;"
    );
    format!(
        " server {{ {} server_name {names}; {tls}\n ssl_session_cache shared:onebox_frp:1m; \
         ssl_session_timeout 10m; client_max_body_size 0;\n location / {{ proxy_pass \
         http://127.0.0.1:{}; proxy_http_version 1.1;\n proxy_set_header Host $host; \
         proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection \
         $onebox_frp_connection;\n proxy_set_header X-Real-IP $remote_addr; proxy_set_header \
         X-Forwarded-For $remote_addr;\n proxy_set_header X-Forwarded-Proto https; \
         proxy_set_header X-Forwarded-Host $host; proxy_set_header X-Forwarded-Port {}; \
         proxy_set_header Forwarded \"\";\n proxy_buffering off; proxy_request_buffering off; \
         proxy_read_timeout 3600s; proxy_send_timeout 3600s;\n }} }}\n server {{ {} server_name \
         _; {tls} return 404; }}\n",
        listen(layout, web.https_port, " ssl"),
        web.http_port,
        web.https_port,
        listen(layout, web.https_port, " ssl default_server"),
    )
}

/// The proxy kind of an exported client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyKind {
    Http,
    Tcp,
    Udp,
}

impl ProxyKind {
    pub fn id(self) -> &'static str {
        match self {
            ProxyKind::Http => "http",
            ProxyKind::Tcp => "tcp",
            ProxyKind::Udp => "udp",
        }
    }

    pub fn parse(value: &str) -> Option<ProxyKind> {
        [ProxyKind::Http, ProxyKind::Tcp, ProxyKind::Udp]
            .into_iter()
            .find(|k| k.id() == value)
    }
}

/// One validated client proxy (see `export`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxySpec {
    pub kind: ProxyKind,
    pub local_port: u16,
    /// Public port (tcp/udp only).
    pub remote_port: u16,
    /// Wildcard label (http with a wildcard root only).
    pub subdomain: String,
}

/// The application domain of an http proxy: the single domain, or
/// `{label}.{root}`.
pub fn app_domain(state: &FrpState, spec: &ProxySpec) -> String {
    match state.web().map(|w| &w.app) {
        Some(AppDomain::Single { domain }) => domain.clone(),
        Some(AppDomain::Wildcard { root }) => format!("{}.{root}", spec.subdomain),
        None => String::new(),
    }
}

/// The exported `frpc.toml` (v2 text).
pub fn client_toml(state: &FrpState, spec: &ProxySpec) -> String {
    let domain = app_domain(state, spec);
    let name = match spec.kind {
        ProxyKind::Http => format!("onebox-http-{domain}"),
        kind => format!("onebox-{}-{}", kind.id(), spec.remote_port),
    };
    let mut text = format!(
        "serverAddr = {}\nserverPort = {}\nauth.method = \"token\"\nauth.token = {}\n\
         auth.additionalScopes = [\"HeartBeats\", \"NewWorkConns\"]\ntransport.tls.enable = true\n\
         transport.tls.serverName = {}\ntransport.tls.trustedCaFile = \"./ca.pem\"\n\
         log.to = \"console\"\nlog.disablePrintColor = true\n\n[[proxies]]\nname = {}\ntype = {}\n\
         localIP = \"127.0.0.1\"\nlocalPort = {}\n",
        quote(&state.domain),
        state.bind_port,
        quote(&state.token),
        quote(&state.domain),
        quote(&name),
        quote(spec.kind.id()),
        spec.local_port,
    );
    if spec.kind == ProxyKind::Http {
        match state.web().map(|w| &w.app) {
            Some(AppDomain::Wildcard { .. }) => {
                let _ = writeln!(text, "subdomain = {}", quote(&spec.subdomain));
            }
            _ => {
                let _ = writeln!(text, "customDomains = [{}]", quote(&domain));
            }
        }
        text.push_str("requestHeaders.set.\"X-Forwarded-Proto\" = \"https\"\n");
    } else {
        let _ = writeln!(text, "remotePort = {}", spec.remote_port);
    }
    text
}

/// Where the exported service is reachable.
pub fn endpoint(state: &FrpState, spec: &ProxySpec) -> String {
    match (spec.kind, state.web()) {
        (ProxyKind::Http, Some(web)) => {
            format!("https://{}:{}/", app_domain(state, spec), web.https_port)
        }
        (kind, _) => format!("{}:{} ({})", state.domain, spec.remote_port, kind.id()),
    }
}

/// The exported `README.txt` (v2 text).
pub fn client_readme(state: &FrpState, spec: &ProxySpec) -> String {
    format!(
        "本目录含 FRP token，请私密保存。不要复制服务端 CA 私钥。\n\
         在内网机器安装 frpc {}，复制整个目录并进入该目录：\nfrpc verify -c frpc.toml\n\
         frpc -c frpc.toml\n内网服务：127.0.0.1:{}\n访问：{}\n\
         必须保留 trustedCaFile 与 serverName 校验。\n",
        state.version,
        spec.local_port,
        endpoint(state, spec)
    )
}

/// The configuration summary (H §5.11), one line per entry, without the
/// trailing newline. The token is never shown.
pub fn summary(state: &FrpState) -> String {
    let mode = if state.is_web() { "web" } else { "tcp" };
    let mut lines = vec![
        format!("FRP {mode} / v{}", state.version),
        format!(
            "控制入口: {}:{}（TLS + 私有 CA + token）",
            state.domain, state.bind_port
        ),
        "控制域名 A / AAAA 应直接指向 VPS，关闭 CDN 代理。凭据不在此处显示。".to_owned(),
    ];
    match &state.mode {
        Mode::Web(web) => lines.extend(web_summary(web)),
        Mode::Tcp { range } => lines.push(format!("公网 TCP / UDP 转发范围: {range}")),
    }
    for r in state.reservations() {
        lines.push(format!(
            "保留端口: {}-{}/{}",
            r.start,
            r.end,
            r.transport.id()
        ));
    }
    lines.join("\n")
}

fn web_summary(web: &WebSettings) -> Vec<String> {
    let host = match &web.app {
        AppDomain::Single { domain } => domain.clone(),
        AppDomain::Wildcard { root } => format!("{DEFAULT_SUBDOMAIN}.{root}"),
    };
    let mut lines = vec![
        format!("应用入口: https://{host}{}/", port_suffix(web.https_port)),
        format!(
            "内部转发: 127.0.0.1:{}；证书方式: {}",
            web.http_port,
            web.tls.v2_id()
        ),
    ];
    if let AppDomain::Wildcard { root } = &web.app {
        lines.push(format!(
            "添加泛域名解析 *.{root}，客户端 subdomain = {DEFAULT_SUBDOMAIN}"
        ));
    }
    if web.tls == WebTls::Http01 {
        lines.push("HTTP-01 申请和自动续期需要持续开放公网 TCP 80。".to_owned());
    }
    lines
}

#[cfg(test)]
mod tests;
