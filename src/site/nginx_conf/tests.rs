use super::*;
use std::path::PathBuf;

/// v2's `site::config` string builder (site.rs:204-244), kept verbatim as
/// the golden oracle; only its inputs are parameters.
#[allow(clippy::too_many_arguments)]
fn v2_config(
    user: &str,
    local: u16,
    public: u16,
    domain: &str,
    ipv6: bool,
    temporary: &str,
    dir: &Path,
    site_root: &Path,
    sub: &str,
    ca: Option<&Path>,
    bootstrap: bool,
    defer: bool,
    frontend: bool,
) -> String {
    let suffix = if public == 443 {
        String::new()
    } else {
        format!(":{public}")
    };
    let listen6 = if ipv6 { "listen [::]:80;" } else { "" };
    let https6 = if ipv6 {
        "listen [::]:443 ssl http2;"
    } else {
        ""
    };
    let root = quote_path(site_root).unwrap();
    let cert = quote_path(&dir.join("cert.pem")).unwrap();
    let key = quote_path(&dir.join("key.pem")).unwrap();
    let error_log = if !sub.is_empty() {
        "/dev/null crit".to_string()
    } else {
        format!("{} warn", quote_path(&dir.join("error.log")).unwrap())
    };
    let mut c=format!("user {user};\nworker_processes 1;\npid {};\nerror_log {error_log};\nevents {{ worker_connections 512; }}\nhttp {{\n{temporary}\naccess_log off; server_tokens off; charset utf-8; default_type application/octet-stream;\ntypes {{ text/html html htm; text/css css; application/javascript js; image/png png; image/jpeg jpg jpeg; image/svg+xml svg; text/plain txt; }}\nsendfile on; keepalive_timeout 20; client_max_body_size 1m;\nserver {{ listen 80; {listen6} server_name {domain};\nlocation ^~ /.well-known/acme-challenge/ {{ root {root}; default_type text/plain; try_files $uri =404; }}\nlocation / {{ {} }}\n}}\n",quote_path(&dir.join("nginx.pid")).unwrap(),if bootstrap{"return 404;".into()}else{format!("return 301 https://{domain}{suffix}$request_uri;")});
    if !bootstrap {
        c.push_str(&format!("server {{ listen 127.0.0.1:{local} ssl http2; server_name {domain};\nssl_certificate {cert}; ssl_certificate_key {key}; ssl_protocols TLSv1.3; ssl_ecdh_curve X25519:prime256v1;\nabsolute_redirect off; root {root}; index index.html;\nadd_header X-Content-Type-Options nosniff always; add_header Referrer-Policy no-referrer always;\n{sub}\nlocation ~ /\\. {{ deny all; }}\nlocation / {{ try_files $uri $uri/ =404; }}\n}}\n"));
        if !defer && frontend {
            c.push_str(&format!("server {{ listen 443 ssl http2; {https6} server_name {domain};\nssl_certificate {cert}; ssl_certificate_key {key}; ssl_protocols TLSv1.2 TLSv1.3;\n{sub}\nlocation / {{ proxy_pass https://127.0.0.1:{local}; proxy_ssl_server_name on; proxy_ssl_name {domain}; proxy_ssl_verify on; proxy_ssl_trusted_certificate {}; proxy_ssl_verify_depth 5; proxy_set_header Host {domain}; proxy_set_header Connection \"\"; proxy_http_version 1.1; proxy_buffering off; proxy_request_buffering off; }}\n}}\n",quote_path(ca.unwrap()).unwrap()));
        }
    }
    c.push_str("}\n");
    c
}

/// v2's subscription `location` block (subscription.rs:308-319).
const SUB: &str = r#"location ^~ /sub/ {
        access_log off; error_log /dev/null crit;
        limit_except GET { deny all; }
        proxy_pass "http://unix:/run/onebox/subscription.sock:";
        proxy_http_version 1.1; proxy_set_header Connection "";
        proxy_buffering off; proxy_request_buffering off; proxy_cache off;
        proxy_connect_timeout 3s; proxy_read_timeout 10s;
        add_header Cache-Control "private, no-store" always;
        add_header Referrer-Policy "no-referrer" always;
        add_header X-Content-Type-Options "nosniff" always;
    }"#;

struct Case {
    phase: SitePhase,
    ipv6: bool,
    public: u16,
    frontend: bool,
    sub: bool,
}

fn worker() -> Worker {
    Worker {
        user: "www-data".into(),
        group: "www-data".into(),
    }
}

fn site_dir() -> PathBuf {
    PathBuf::from("/etc/onebox/site")
}

fn site_root() -> PathBuf {
    PathBuf::from("/var/lib/onebox-site")
}

fn ca() -> PathBuf {
    PathBuf::from("/etc/ssl/certs/ca-certificates.crt")
}

fn ours(case: &Case, http2_directive: bool) -> String {
    let (w, dir, root, ca) = (worker(), site_dir(), site_root(), ca());
    render(&SiteConf {
        worker: &w,
        domain: "www.example.com",
        internal_port: 10443,
        public_port: case.public,
        ipv6: case.ipv6,
        http2_directive,
        site_dir: &dir,
        site_root: &root,
        phase: case.phase,
        frontend_ca: case.frontend.then_some(ca.as_path()),
        subscription: case.sub.then_some(SUB),
    })
    .unwrap()
}

fn oracle(case: &Case) -> String {
    let temporary = temp_paths(&site_dir()).unwrap();
    v2_config(
        "www-data www-data",
        10443,
        case.public,
        "www.example.com",
        case.ipv6,
        &temporary,
        &site_dir(),
        &site_root(),
        if case.sub { SUB } else { "" },
        Some(&ca()),
        case.phase == SitePhase::Bootstrap,
        case.phase != SitePhase::Full,
        case.frontend,
    )
}

#[test]
fn every_variant_matches_v2_with_persistent_temp_paths() {
    let mut count = 0;
    for phase in [SitePhase::Bootstrap, SitePhase::Deferred, SitePhase::Full] {
        for ipv6 in [false, true] {
            for (public, frontend) in [(443, true), (443, false), (8443, false)] {
                for sub in [false, true] {
                    let case = Case {
                        phase,
                        ipv6,
                        public,
                        frontend,
                        sub,
                    };
                    assert_eq!(
                        ours(&case, false),
                        oracle(&case),
                        "{phase:?} v6={ipv6} {public} fe={frontend} sub={sub}"
                    );
                    count += 1;
                }
            }
        }
    }
    assert_eq!(count, 36);
}

#[test]
fn full_example_from_the_spec() {
    let text = ours(
        &Case {
            phase: SitePhase::Full,
            ipv6: true,
            public: 443,
            frontend: true,
            sub: false,
        },
        false,
    );
    let expected = "user www-data www-data;
worker_processes 1;
pid \"/etc/onebox/site/nginx.pid\";
error_log \"/etc/onebox/site/error.log\" warn;
events { worker_connections 512; }
http {
client_body_temp_path \"/etc/onebox/site/client_body_temp\";
proxy_temp_path \"/etc/onebox/site/proxy_temp\";
fastcgi_temp_path \"/etc/onebox/site/fastcgi_temp\";
uwsgi_temp_path \"/etc/onebox/site/uwsgi_temp\";
scgi_temp_path \"/etc/onebox/site/scgi_temp\";

access_log off; server_tokens off; charset utf-8; default_type application/octet-stream;
types { text/html html htm; text/css css; application/javascript js; image/png png; image/jpeg jpg jpeg; image/svg+xml svg; text/plain txt; }
sendfile on; keepalive_timeout 20; client_max_body_size 1m;
server { listen 80; listen [::]:80; server_name www.example.com;
location ^~ /.well-known/acme-challenge/ { root \"/var/lib/onebox-site\"; default_type text/plain; try_files $uri =404; }
location / { return 301 https://www.example.com$request_uri; }
}
server { listen 127.0.0.1:10443 ssl http2; server_name www.example.com;
ssl_certificate \"/etc/onebox/site/cert.pem\"; ssl_certificate_key \"/etc/onebox/site/key.pem\"; ssl_protocols TLSv1.3; ssl_ecdh_curve X25519:prime256v1;
absolute_redirect off; root \"/var/lib/onebox-site\"; index index.html;
add_header X-Content-Type-Options nosniff always; add_header Referrer-Policy no-referrer always;

location ~ /\\. { deny all; }
location / { try_files $uri $uri/ =404; }
}
server { listen 443 ssl http2; listen [::]:443 ssl http2; server_name www.example.com;
ssl_certificate \"/etc/onebox/site/cert.pem\"; ssl_certificate_key \"/etc/onebox/site/key.pem\"; ssl_protocols TLSv1.2 TLSv1.3;

location / { proxy_pass https://127.0.0.1:10443; proxy_ssl_server_name on; proxy_ssl_name www.example.com; proxy_ssl_verify on; proxy_ssl_trusted_certificate \"/etc/ssl/certs/ca-certificates.crt\"; proxy_ssl_verify_depth 5; proxy_set_header Host www.example.com; proxy_set_header Connection \"\"; proxy_http_version 1.1; proxy_buffering off; proxy_request_buffering off; }
}
}
";
    assert_eq!(text, expected);
}

#[test]
fn new_nginx_uses_the_http2_directive() {
    let case = Case {
        phase: SitePhase::Full,
        ipv6: true,
        public: 443,
        frontend: true,
        sub: true,
    };
    let text = ours(&case, true);
    assert!(!text.contains("ssl http2"), "{text}");
    assert!(text
        .contains("server { listen 127.0.0.1:10443 ssl; http2 on; server_name www.example.com;"));
    assert!(text.contains(
        "server { listen 443 ssl; listen [::]:443 ssl; http2 on; server_name www.example.com;"
    ));
    // Apart from the listen syntax both styles are the same text.
    let legacy = ours(&case, false)
        .replace(" ssl http2;", " ssl;")
        .replace("ssl; server_name", "ssl; http2 on; server_name");
    assert_eq!(text, legacy);
}

#[test]
fn subscription_location_goes_into_both_tls_servers_and_silences_logs() {
    let case = Case {
        phase: SitePhase::Full,
        ipv6: false,
        public: 443,
        frontend: true,
        sub: true,
    };
    let text = ours(&case, false);
    assert_eq!(text.matches("location ^~ /sub/ {").count(), 2);
    assert!(text.contains("error_log /dev/null crit;\nevents"));
    assert!(!text.contains("error.log"));
    // Without IPv6 v2's double space stays.
    assert!(text.contains("server { listen 80;  server_name www.example.com;"));
    assert!(text.contains("server { listen 443 ssl http2;  server_name www.example.com;"));
    let deferred = ours(
        &Case {
            phase: SitePhase::Deferred,
            ..case
        },
        false,
    );
    assert_eq!(deferred.matches("location ^~ /sub/ {").count(), 1);
    assert!(!deferred.contains("listen 443"));
}

#[test]
fn redirect_carries_a_non_standard_public_port() {
    let text = ours(
        &Case {
            phase: SitePhase::Full,
            ipv6: false,
            public: 8443,
            frontend: false,
            sub: false,
        },
        false,
    );
    assert!(text.contains("location / { return 301 https://www.example.com:8443$request_uri; }"));
    let bootstrap = ours(
        &Case {
            phase: SitePhase::Bootstrap,
            ipv6: false,
            public: 8443,
            frontend: true,
            sub: true,
        },
        false,
    );
    assert!(bootstrap.contains("location / { return 404; }"));
    assert!(!bootstrap.contains("ssl"));
}

#[test]
fn quoting_and_validation() {
    assert_eq!(
        quote_path(Path::new("/tmp/a\"b")).unwrap(),
        "\"/tmp/a\\\"b\""
    );
    assert_eq!(
        quote_path(Path::new("/tmp/$x\\y")).unwrap(),
        "\"/tmp/\\$x\\\\y\""
    );
    assert_eq!(
        quote_path(Path::new("/tmp/foo\nbar"))
            .unwrap_err()
            .to_string(),
        "路径含控制字符"
    );
    let (w, dir, root) = (worker(), site_dir(), site_root());
    let bad = SiteConf {
        worker: &w,
        domain: "bad domain; include /etc/passwd",
        internal_port: 10443,
        public_port: 443,
        ipv6: false,
        http2_directive: false,
        site_dir: &dir,
        site_root: &root,
        phase: SitePhase::Full,
        frontend_ca: None,
        subscription: None,
    };
    assert_eq!(render(&bad).unwrap_err().to_string(), "网站域名无效");
}
