use super::*;
use crate::subscription::testing::{ip, reality, site, standalone, Node};
use crate::sys::exec::Output;

fn default_paths() -> Paths {
    Paths::from_lookup(|_| None).unwrap()
}

fn facts(http2_directive: bool, ipv6: bool) -> NginxFacts {
    NginxFacts {
        worker: Worker {
            user: "www-data".into(),
            group: "www-data".into(),
        },
        http2_directive,
        ipv6,
    }
}

#[test]
fn location_block_is_v2_text_with_hidden_backend_headers() {
    assert_eq!(
        location_block(&default_paths()).unwrap(),
        r#"location ^~ /sub/ {
        access_log off; error_log /dev/null crit;
        limit_except GET { deny all; }
        proxy_pass "http://unix:/run/onebox/subscription.sock:";
        proxy_http_version 1.1; proxy_set_header Connection "";
        proxy_buffering off; proxy_request_buffering off; proxy_cache off;
        proxy_hide_header Cache-Control; proxy_hide_header Referrer-Policy; proxy_hide_header X-Content-Type-Options;
        proxy_connect_timeout 3s; proxy_read_timeout 10s;
        add_header Cache-Control "private, no-store" always;
        add_header Referrer-Policy "no-referrer" always;
        add_header X-Content-Type-Options "nosniff" always;
    }"#
    );
}

#[test]
fn socket_paths_nginx_or_the_kernel_cannot_take_are_refused() {
    for run in ["/run/a\"b", "/run/$x", "/run/a\\b"] {
        let paths = Paths::from_lookup(|k| (k == "ONEBOX_RUN_DIR").then(|| run.into())).unwrap();
        assert_eq!(
            location_block(&paths).unwrap_err().to_string(),
            "订阅 socket 路径含不支持的字符",
            "{run}"
        );
        assert!(check_socket_path(&paths).is_err());
    }
    let long = format!("/{}", "r".repeat(90));
    let paths =
        Paths::from_lookup(|k| (k == "ONEBOX_RUN_DIR").then(|| long.clone().into())).unwrap();
    assert_eq!(
        check_socket_path(&paths).unwrap_err().to_string(),
        "订阅 Unix socket 路径过长"
    );
    assert!(check_socket_path(&default_paths()).is_ok());
}

#[test]
fn site_location_only_in_site_mode() {
    let paths = default_paths();
    let block = site_location(&paths, &site()).unwrap().location_block;
    assert_eq!(block, location_block(&paths).unwrap());
    for cfg in [ip(8448), standalone(WebCert::Http01, 8448), reality()] {
        assert_eq!(site_location(&paths, &cfg), None);
    }
    let mut inactive = site();
    inactive.site = None;
    assert_eq!(site_location(&paths, &inactive), None);
}

#[test]
fn standalone_config_full_and_bootstrap() {
    let paths = default_paths();
    let location = location_block(&paths).unwrap();
    let cfg = standalone(WebCert::Http01, 8448);
    let full = render_for(&paths, &cfg, &facts(false, true), WebPhase::Full)
        .unwrap()
        .unwrap();
    let header = "user www-data www-data;\nworker_processes 1;\n\
        pid \"/etc/onebox/subscription/nginx.pid\";\nerror_log /dev/null crit;\n\
        events { worker_connections 256; }\n\
        http { client_body_temp_path \"/etc/onebox/subscription/client_body_temp\";\n\
        proxy_temp_path \"/etc/onebox/subscription/proxy_temp\";\n\
        fastcgi_temp_path \"/etc/onebox/subscription/fastcgi_temp\";\n\
        uwsgi_temp_path \"/etc/onebox/subscription/uwsgi_temp\";\n\
        scgi_temp_path \"/etc/onebox/subscription/scgi_temp\";\n\n\
        access_log off; server_tokens off; default_type text/plain; client_max_body_size 1k; keepalive_timeout 10;\n";
    let acme = "server { listen 80; listen [::]:80; server_name _;\n\
        location ^~ /.well-known/acme-challenge/ { root \"/var/lib/onebox-subscription-acme\"; try_files $uri =404; }\n\
        location / { return 404; }\n}\n";
    let tls = format!(
        "server {{ listen 8448 ssl http2; listen [::]:8448 ssl http2; server_name sub.example.com;\n\
         ssl_certificate \"/etc/onebox/subscription/tls/cert.pem\"; ssl_certificate_key \"/etc/onebox/subscription/tls/key.pem\"; ssl_protocols TLSv1.2 TLSv1.3;\n\
         {location}\nlocation / {{ return 404; }}\n}}\n"
    );
    assert_eq!(full, format!("{header}{acme}{tls}}}\n"));
    let bootstrap = render_for(&paths, &cfg, &facts(false, true), WebPhase::Bootstrap)
        .unwrap()
        .unwrap();
    assert_eq!(bootstrap, format!("{header}{acme}}}\n"));
    assert!(!full.contains("/run/onebox/nginx-subscription"), "G19");
}

#[test]
fn standalone_config_variants() {
    let paths = default_paths();
    let render = |cfg: &NodeConfig, facts: &NginxFacts| {
        render_for(&paths, cfg, facts, WebPhase::Full)
            .unwrap()
            .unwrap()
    };
    let cf = standalone(WebCert::Cloudflare, 443);
    let v4_only = render(&cf, &facts(false, false));
    assert!(v4_only.contains("server { listen 443 ssl http2;  server_name sub.example.com;\n"));
    assert!(
        !v4_only.contains("listen 80;"),
        "no port-80 server without HTTP-01"
    );
    let modern = render(&cf, &facts(true, true));
    assert!(modern.contains(
        "server { listen 443 ssl; listen [::]:443 ssl; http2 on; server_name sub.example.com;\n"
    ));
    for cfg in [ip(8448), site(), reality()] {
        assert_eq!(
            render_for(&paths, &cfg, &facts(false, true), WebPhase::Full).unwrap(),
            None
        );
    }
    assert_eq!(v4_only.matches("server {").count(), 1);
    let worker = facts(false, false).worker;
    let conf = |domain, port| WebConf {
        worker: &worker,
        http2_directive: false,
        ipv6: false,
        sub_dir: Path::new("/s"),
        acme_root: Path::new("/a"),
        domain,
        port,
        http01: false,
        location: "",
        phase: WebPhase::Full,
    };
    assert_eq!(
        super::render(&conf("not a domain", 443))
            .unwrap_err()
            .to_string(),
        "订阅域名无效"
    );
    assert_eq!(
        super::render(&conf("sub.example.com", 0))
            .unwrap_err()
            .to_string(),
        "订阅端口无效"
    );
}

#[test]
fn bootstrap_configs_are_tested_before_install() {
    let node = Node::new("sub-front-stage");
    let ctx = &node.ctx;
    node.fake
        .provide("nginx")
        .on("nginx", &["-t"], Output::success(""));
    assert!(!conf_installed(&ctx.paths));
    let staged = test_conf(ctx, "events {}\n").unwrap();
    assert_eq!(staged, staged_conf(&ctx.paths));
    let call = node.fake.history().pop().unwrap();
    assert!(
        call.contains("-t -q -p") && call.contains("nginx.conf.new"),
        "{call}"
    );
    install_web_conf(ctx, &staged).unwrap();
    assert!(!staged.exists(), "the bootstrap's staged file is consumed");
    assert_eq!(
        std::fs::read_to_string(conf_file(&ctx.paths)).unwrap(),
        "events {}\n"
    );
    assert!(conf_installed(&ctx.paths));

    // The engine's staged copy (in its journal directory) is only copied.
    node.fake.clear_history();
    let engine_staged = ctx.paths.transaction().join("subscription-web.conf.new");
    std::fs::create_dir_all(ctx.paths.transaction()).unwrap();
    std::fs::write(&engine_staged, "http {}\n").unwrap();
    install_web_conf(ctx, &engine_staged).unwrap();
    assert!(engine_staged.exists(), "not ours to remove");
    assert_eq!(
        std::fs::read_to_string(conf_file(&ctx.paths)).unwrap(),
        "http {}\n"
    );
    assert!(node.fake.history().is_empty(), "installing tests nothing");

    remove_conf(&ctx.paths).unwrap();
    assert!(!conf_file(&ctx.paths).exists() && !conf_installed(&ctx.paths));
    std::fs::create_dir_all(ctx.paths.subscription()).unwrap();
    std::os::unix::fs::symlink(&engine_staged, conf_file(&ctx.paths)).unwrap();
    assert!(
        !conf_installed(&ctx.paths),
        "a link is not an installed config"
    );
}

#[test]
fn a_failing_test_leaves_the_installed_config() {
    let node = Node::new("sub-front-fail");
    let ctx = &node.ctx;
    std::fs::create_dir_all(ctx.paths.subscription()).unwrap();
    std::fs::write(conf_file(&ctx.paths), "old\n").unwrap();
    node.fake.provide("nginx").on(
        "nginx",
        &["-t"],
        Output::failure(1, "nginx: [emerg] unknown directive \"bogus\"\n"),
    );
    let err = test_conf(ctx, "bogus;\n").unwrap_err().to_string();
    assert!(
        err.starts_with("nginx 配置测试失败") && err.contains("bogus"),
        "{err}"
    );
    assert!(!staged_conf(&ctx.paths).exists());
    assert_eq!(
        std::fs::read_to_string(conf_file(&ctx.paths)).unwrap(),
        "old\n"
    );
}

#[test]
fn installed_acme_server_is_detected() {
    let node = Node::new("sub-front-acme");
    let paths = &node.ctx.paths;
    assert!(!installed_serves_acme(paths));
    let cfg = standalone(WebCert::Http01, 8448);
    let full = render_for(paths, &cfg, &facts(false, false), WebPhase::Full)
        .unwrap()
        .unwrap();
    std::fs::create_dir_all(paths.subscription()).unwrap();
    std::fs::write(conf_file(paths), &full).unwrap();
    assert!(installed_serves_acme(paths));
    let cf = render_for(
        paths,
        &standalone(WebCert::Cloudflare, 8448),
        &facts(false, false),
        WebPhase::Full,
    )
    .unwrap()
    .unwrap();
    std::fs::write(conf_file(paths), cf).unwrap();
    assert!(!installed_serves_acme(paths));
}
