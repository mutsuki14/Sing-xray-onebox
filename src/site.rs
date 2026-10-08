//! Managed website and HTTPS front end, independent from distro nginx config.
use crate::{cert, context::Context, model::State, platform, util, Result};
use std::{
    env, fs,
    net::TcpListener,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

pub const SERVICE: &str = "onebox-site";
pub fn nginx(ctx: &Context) -> Result<PathBuf> {
    if let Some(path) = env::var_os("ONEBOX_NGINX_BIN") {
        let path = PathBuf::from(path);
        if !path.is_file() {
            return Err("ONEBOX_NGINX_BIN 不存在".into());
        }
        return Ok(path);
    }
    if !platform::has("nginx") {
        if Path::new("/etc/nginx").exists() {
            return Err("检测到现有 nginx 配置但找不到程序，请先修复 nginx".into());
        }
        platform::ensure_package(ctx, "nginx", "nginx")?;
        // A newly installed distro service may have claimed 80; it has no user
        // configuration because /etc/nginx did not exist before installation.
        match platform::init_system() {
            "systemd" => {
                ctx.run("systemctl", &["disable", "--now", "nginx"])?;
            }
            "openrc" => {
                let _ = ctx.output("rc-service", &["nginx", "stop"]);
                let _ = ctx.output("rc-update", &["del", "nginx", "default"]);
            }
            _ => {}
        }
    }
    env::split_paths(&env::var_os("PATH").unwrap_or_default())
        .map(|p| p.join("nginx"))
        .find(|p| p.is_file())
        .ok_or_else(|| "找不到 nginx".into())
}
pub fn worker_user(ctx: &Context) -> Result<String> {
    for name in ["nginx", "www-data", "nobody"] {
        if ctx
            .output("id", &["-u", name])
            .map(|o| o.success())
            .unwrap_or(false)
        {
            return Ok(name.into());
        }
    }
    Err("缺少 nginx 非 root 工作账号".into())
}
pub fn worker_identity(ctx: &Context) -> Result<String> {
    let user = worker_user(ctx)?;
    let group = ctx.run("id", &["-gn", &user])?.trim().to_owned();
    if group.is_empty()
        || !group
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
    {
        return Err("nginx 工作账号的组名无效".into());
    }
    Ok(format!("{user} {group}"))
}
/// Keep nginx's writable temporary files independent from distro defaults and
/// outside the private certificate/configuration tree. nginx assigns each leaf
/// directory to its configured worker at startup.
pub fn nginx_runtime(ctx: &Context, scope: &str) -> Result<String> {
    if !matches!(scope, "site" | "subscription" | "frp") {
        return Err("无效 nginx 运行目录".into());
    }
    util::safe_path(&ctx.paths.run)?;
    fs::create_dir_all(&ctx.paths.run)?;
    fs::set_permissions(&ctx.paths.run, fs::Permissions::from_mode(0o755))?;
    let root = ctx.paths.run.join(format!("nginx-{scope}"));
    util::safe_path(&root)?;
    fs::create_dir_all(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755))?;
    let mut config = String::new();
    for kind in ["client_body", "proxy", "fastcgi", "uwsgi", "scgi"] {
        let path = root.join(kind);
        util::safe_path(&path)?;
        config.push_str(&format!("{kind}_temp_path {};\n", quote_path(&path)?));
    }
    Ok(config)
}
pub fn quote_path(p: &Path) -> Result<String> {
    let s = util::path_str(p)?;
    if s.chars().any(|c| c.is_control()) {
        return Err("路径含控制字符".into());
    }
    Ok(format!(
        "\"{}\"",
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('$', "\\$")
    ))
}
fn html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
pub fn template(name: &str, title: &str, description: &str, theme: &str) -> Result<String> {
    let color = match theme {
        "forest" => "#234e3c",
        "ocean" => "#164e72",
        "slate" => "#364152",
        _ => return Err("主题应为 forest/ocean/slate".into()),
    };
    let content=match name {
        "minimal"=>"<section><h2>慢慢记录</h2><p>记录值得停留的瞬间，也整理尚未成形的想法。</p></section>",
        "profile"=>"<section><h2>关于我</h2><p>保持好奇，专注创造，在日常中发现新的可能。</p></section><section><h2>作品与日常</h2><p>这里收藏学习、创作和生活中的片段。</p></section>",
        "docs"=>"<section><h2>从这里开始</h2><p>这是一份持续整理的知识笔记。</p></section><section><h2>阅读目录</h2><ol><li>想法与方法</li><li>实践中的记录</li><li>值得收藏的参考</li></ol></section>",
        _=>return Err("模板应为 minimal/profile/docs".into()),
    };
    Ok(format!(
        r#"<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="description" content="{}"><title>{}</title><style>:root{{color-scheme:light;--ink:{color}}}*{{box-sizing:border-box}}body{{margin:0;background:#f7f6f1;color:var(--ink);font:17px/1.8 system-ui,sans-serif}}main,header,footer{{width:min(850px,calc(100% - 48px));margin:auto}}header{{padding:32px 0;border-bottom:1px solid #cfd6cf}}h1{{font-size:clamp(34px,7vw,64px);line-height:1.25;font-weight:500}}.hero{{padding:70px 0 50px}}section{{border-top:1px solid #cfd6cf;padding:28px 0}}footer{{padding:32px 0;font-size:13px}}a{{color:inherit}}</style></head><body><header>{}</header><main><div class="hero"><h1>{}</h1><p>{}</p></div>{content}</main><footer>保持好奇，慢慢记录。</footer></body></html>"#,
        html(description),
        html(title),
        html(title),
        html(title),
        html(description)
    ))
}
fn paths_safe(ctx: &Context) -> Result<()> {
    let root = &ctx.paths.site_root;
    util::safe_path(root)?;
    util::safe_path(&ctx.paths.site())?;
    if root.parent().is_none()
        || [
            "/", "/etc", "/var", "/var/lib", "/usr", "/home", "/root", "/tmp",
        ]
        .iter()
        .any(|p| root == Path::new(p))
        || root.starts_with(&ctx.paths.root)
        || ctx.paths.root.starts_with(root)
    {
        return Err("网站目录必须独立于私密配置和系统目录".into());
    }
    Ok(())
}
pub(crate) fn reserve_validate(ctx: &Context, s: &State) -> Result<()> {
    if !util::valid_domain(s.get("REALITY_SITE_DOMAIN")) {
        return Err("网站域名无效".into());
    }
    let port = s.number("REALITY_SITE_PORT", 8443);
    if port < 1024 {
        return Err("网站内部 TLS 端口必须大于等于 1024".into());
    }
    for p in s.protocols() {
        if p.network() != "udp" && (s.port(p) == port || s.port(p) == 80) {
            return Err("网站端口与代理协议冲突".into());
        }
    }
    if s.number("REALITY_GUARD_PORT", 0) == port {
        return Err("网站端口与 REALITY 防偷跑端口冲突".into());
    }
    for p in s.protocols() {
        if p.network() != "udp" && s.port(p) == 443 && s.flag("REALITY_SITE_HTTPS") && !p.reality()
        {
            return Err("TCP 443 被非 REALITY 协议占用".into());
        }
    }
    let mut wanted = vec![80, port];
    if s.flag("REALITY_SITE_HTTPS") {
        wanted.push(443);
    }
    for (start, end, network) in crate::frp::reserved_ports(ctx)? {
        if network != "udp" && wanted.iter().any(|p| (start..=end).contains(p)) {
            return Err("网站端口已保留给 FRP".into());
        }
    }
    Ok(())
}
fn uses_frontend(s: &State) -> bool {
    s.flag("REALITY_SITE_HTTPS")
        && !s
            .protocols()
            .iter()
            .any(|p| p.reality() && s.port(*p) == 443)
}
pub fn public_port(s: &State) -> u16 {
    if s.flag("REALITY_SITE_HTTPS") {
        443
    } else {
        s.protocols()
            .iter()
            .filter(|p| p.reality())
            .map(|p| s.port(*p))
            .min()
            .unwrap_or(443)
    }
}
pub fn ipv6_available() -> bool {
    std::net::TcpListener::bind((std::net::Ipv6Addr::LOCALHOST, 0)).is_ok()
}
fn can_bind(port: u16) -> bool {
    TcpListener::bind(("0.0.0.0", port)).is_ok()
}
pub(crate) fn config(ctx: &Context, s: &State, bootstrap: bool, defer: bool) -> Result<String> {
    let dir = ctx.paths.site();
    let domain = s.get("REALITY_SITE_DOMAIN");
    let user = worker_identity(ctx)?;
    let local = s.number("REALITY_SITE_PORT", 8443);
    let public = public_port(s);
    let suffix = if public == 443 {
        String::new()
    } else {
        format!(":{public}")
    };
    let listen6 = if ipv6_available() {
        "listen [::]:80;"
    } else {
        ""
    };
    let https6 = if ipv6_available() {
        "listen [::]:443 ssl http2;"
    } else {
        ""
    };
    let root = quote_path(&ctx.paths.site_root)?;
    let cert = quote_path(&dir.join("cert.pem"))?;
    let key = quote_path(&dir.join("key.pem"))?;
    let temporary = nginx_runtime(ctx, "site")?;
    let error_log = if crate::subscription::uses_site(ctx)? {
        "/dev/null crit".to_string()
    } else {
        format!("{} warn", quote_path(&dir.join("error.log"))?)
    };
    let mut c=format!("user {user};\nworker_processes 1;\npid {};\nerror_log {error_log};\nevents {{ worker_connections 512; }}\nhttp {{\n{temporary}\naccess_log off; server_tokens off; charset utf-8; default_type application/octet-stream;\ntypes {{ text/html html htm; text/css css; application/javascript js; image/png png; image/jpeg jpg jpeg; image/svg+xml svg; text/plain txt; }}\nsendfile on; keepalive_timeout 20; client_max_body_size 1m;\nserver {{ listen 80; {listen6} server_name {domain};\nlocation ^~ /.well-known/acme-challenge/ {{ root {root}; default_type text/plain; try_files $uri =404; }}\nlocation / {{ {} }}\n}}\n",quote_path(&dir.join("nginx.pid"))?,if bootstrap{"return 404;".into()}else{format!("return 301 https://{domain}{suffix}$request_uri;")});
    if !bootstrap {
        let sub = crate::subscription::nginx_location(ctx)?;
        c.push_str(&format!("server {{ listen 127.0.0.1:{local} ssl http2; server_name {domain};\nssl_certificate {cert}; ssl_certificate_key {key}; ssl_protocols TLSv1.3; ssl_ecdh_curve X25519:prime256v1;\nabsolute_redirect off; root {root}; index index.html;\nadd_header X-Content-Type-Options nosniff always; add_header Referrer-Policy no-referrer always;\n{sub}\nlocation ~ /\\. {{ deny all; }}\nlocation / {{ try_files $uri $uri/ =404; }}\n}}\n"));
        if !defer && uses_frontend(s) {
            c.push_str(&format!("server {{ listen 443 ssl http2; {https6} server_name {domain};\nssl_certificate {cert}; ssl_certificate_key {key}; ssl_protocols TLSv1.2 TLSv1.3;\n{sub}\nlocation / {{ proxy_pass https://127.0.0.1:{local}; proxy_ssl_server_name on; proxy_ssl_name {domain}; proxy_ssl_verify on; proxy_ssl_trusted_certificate {}; proxy_ssl_verify_depth 5; proxy_set_header Host {domain}; proxy_set_header Connection \"\"; proxy_http_version 1.1; proxy_buffering off; proxy_request_buffering off; }}\n}}\n",quote_path(&ca_bundle()?)?));
        }
    }
    c.push_str("}\n");
    Ok(c)
}
pub fn ca_bundle() -> Result<PathBuf> {
    if let Some(path) = env::var_os("SSL_CERT_FILE") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Ok(path);
        }
    }
    [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
        "/etc/ssl/cert.pem",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|p| p.is_file())
    .ok_or_else(|| "缺少系统 CA 证书包".into())
}
fn write_config(ctx: &Context, s: &State, bootstrap: bool, defer: bool) -> Result<()> {
    let dest = ctx.paths.site().join("nginx.conf");
    let old = fs::read(&dest).ok();
    let bin = nginx(ctx)?;
    util::atomic_write(&dest, config(ctx, s, bootstrap, defer)?.as_bytes(), 0o600)?;
    if let Err(e) = ctx.run(
        util::path_str(&bin)?,
        &[
            "-t",
            "-p",
            util::path_str(&ctx.paths.site())?,
            "-c",
            util::path_str(&dest)?,
        ],
    ) {
        if let Some(old) = old {
            let _ = util::atomic_write(&dest, &old, 0o600);
        } else {
            let _ = fs::remove_file(dest);
        }
        return Err(e);
    }
    Ok(())
}
fn stop_legacy(ctx: &Context, bin: &Path) -> Result<()> {
    if platform::service_spec_path(ctx, SERVICE).exists() {
        return Ok(());
    }
    let dir = ctx.paths.site();
    let Some(pid) = fs::read_to_string(dir.join("nginx.pid"))
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .filter(|p| *p > 1)
    else {
        return Ok(());
    };
    let cmd = fs::read_to_string(format!("/proc/{pid}/cmdline")).unwrap_or_default();
    if cmd.is_empty() && !Path::new(&format!("/proc/{pid}")).exists() {
        let _ = fs::remove_file(dir.join("nginx.pid"));
        return Ok(());
    }
    if !cmd.contains(util::path_str(&dir.join("nginx.conf"))?) || !cmd.contains("nginx") {
        return Err("历史网站 PID 无法确认为 onebox nginx，请先检查旧服务".into());
    }
    ctx.run(
        util::path_str(bin)?,
        &[
            "-p",
            util::path_str(&dir)?,
            "-c",
            util::path_str(&dir.join("nginx.conf"))?,
            "-s",
            "quit",
        ],
    )?;
    for _ in 0..30 {
        if !Path::new(&format!("/proc/{pid}")).exists() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Err("历史 nginx 未退出，请稍后重试".into())
}
pub fn prepare(ctx: &Context, s: &mut State) -> Result<()> {
    if !s.site_enabled() {
        s.values.remove("CERT_RENEW_SITE");
        return Ok(());
    }
    paths_safe(ctx)?;
    if s.get("REALITY_SITE_PORT").is_empty() {
        s.set("REALITY_SITE_PORT", 8443);
    }
    if s.get("REALITY_SITE_HTTPS").is_empty() {
        s.set("REALITY_SITE_HTTPS", 1);
    }
    reserve_validate(ctx, s)?;
    s.set("REALITY_SNI", s.get("REALITY_SITE_DOMAIN").to_string());
    s.set(
        "REALITY_DEST",
        format!("127.0.0.1:{}", s.number("REALITY_SITE_PORT", 8443)),
    );
    let dir = ctx.paths.site();
    fs::create_dir_all(&dir)?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    let root = &ctx.paths.site_root;
    if root.exists()
        && !root.join(".onebox-site-owned").exists()
        && fs::read_dir(root)?.next().is_some()
    {
        return Err("网站目录含未托管内容，请改用 site import".into());
    }
    fs::create_dir_all(root.join(".well-known/acme-challenge"))?;
    fs::set_permissions(root, fs::Permissions::from_mode(0o755))?;
    for d in [
        root.join(".well-known"),
        root.join(".well-known/acme-challenge"),
    ] {
        fs::set_permissions(d, fs::Permissions::from_mode(0o755))?;
    }
    util::atomic_write(&root.join(".onebox-site-owned"), b"onebox\n", 0o600)?;
    util::atomic_write(&dir.join(".onebox-site-owned"), b"onebox\n", 0o600)?;
    prepare_content(ctx, s)?;
    if !root.join("index.html").exists() {
        let text = template(
            s.get_or("SITE_TEMPLATE", "minimal"),
            s.get_or("REALITY_SITE_TITLE", "山间手记"),
            s.get_or("SITE_DESCRIPTION", "给思考一点空间，给日常一些留白。"),
            s.get_or("SITE_THEME", "forest"),
        )?;
        util::atomic_write(&root.join("index.html"), text.as_bytes(), 0o644)?;
        util::atomic_write(
            &dir.join("index.sha256"),
            util::sha256(text.as_bytes()).as_bytes(),
            0o600,
        )?;
    }
    let bin = nginx(ctx)?;
    stop_legacy(ctx, &bin)?;
    platform::write_service(
        ctx,
        SERVICE,
        &bin,
        &[
            "-p".into(),
            dir.display().to_string(),
            "-c".into(),
            dir.join("nginx.conf").display().to_string(),
            "-g".into(),
            "daemon off;".into(),
        ],
        &[],
    )?;
    let valid = cert::validate_pair(
        ctx,
        &dir.join("cert.pem"),
        &dir.join("key.pem"),
        s.get("REALITY_SITE_DOMAIN"),
        true,
    )
    .is_ok();
    if !valid && s.get_or("SITE_ACME_METHOD", "http") == "http" {
        if !platform::running(ctx, SERVICE) && !can_bind(80) {
            return Err("HTTP-01 需要 TCP 80；请选择 DNS 验证或释放端口".into());
        }
        write_config(ctx, s, true, true)?;
        platform::service(ctx, SERVICE, "restart")?;
        platform::wait_running(ctx, SERVICE)?;
    }
    if s.flag("CERT_RENEW_SITE") {
        if dir.join("certificate.json").is_file() {
            cert::renew(ctx, &dir)?;
        }
        s.values.remove("CERT_RENEW_SITE");
    }
    cert::prepare_site(ctx, s)?;
    write_config(ctx, s, false, true)?;
    Ok(())
}
pub fn apply(ctx: &Context, s: &State) -> Result<()> {
    if !s.site_enabled() {
        if ctx.paths.site().join(".onebox-site-owned").exists() {
            platform::service(ctx, SERVICE, "stop")?;
            platform::service(ctx, SERVICE, "disable")?;
        }
        return Ok(());
    }
    write_config(ctx, s, false, false)?;
    platform::service(ctx, SERVICE, "restart")?;
    platform::service(ctx, SERVICE, "enable")?;
    platform::wait_running(ctx, SERVICE)?;
    cron(ctx, "site", true)?;
    Ok(())
}
fn scheduler_ready(ctx: &Context) -> Result<()> {
    match platform::init_system() {
        "systemd" => {
            for name in ["cron", "crond", "cronie"] {
                if ctx
                    .output("systemctl", &["is-active", "--quiet", name])
                    .map(|o| o.success())
                    .unwrap_or(false)
                {
                    return Ok(());
                }
            }
            for name in ["cron", "crond", "cronie"] {
                if ctx
                    .output("systemctl", &["enable", "--now", name])
                    .map(|o| o.success())
                    .unwrap_or(false)
                {
                    return Ok(());
                }
            }
        }
        "openrc" => {
            for name in ["crond", "cronie", "dcron", "cron"] {
                if ctx
                    .output("rc-service", &[name, "start"])
                    .map(|o| o.success())
                    .unwrap_or(false)
                {
                    ctx.run("rc-update", &["add", name, "default"])?;
                    return Ok(());
                }
            }
        }
        _ => {
            if let Ok(entries) = fs::read_dir("/proc") {
                for e in entries.flatten() {
                    if let Ok(name) = fs::read_to_string(e.path().join("comm")) {
                        if matches!(name.trim(), "cron" | "crond" | "cronie" | "dcron") {
                            return Ok(());
                        }
                    }
                }
            }
        }
    }
    Err("cron 未运行，无法启用证书自动续期；请启动系统 cron 服务".into())
}
pub fn cron(ctx: &Context, target: &str, enabled: bool) -> Result<()> {
    if !matches!(target, "site" | "proxy" | "subscription") {
        return Err("无效续期任务".into());
    }
    if !enabled && !platform::has("crontab") {
        return Ok(());
    }
    platform::ensure_package(ctx, "crontab", "cron")?;
    if enabled {
        scheduler_ready(ctx)?;
    }
    let old = ctx.output("crontab", &["-l"])?;
    if !old.success()
        && !(old.code == 1
            && old.stdout.is_empty()
            && (old.stderr.contains("no crontab for ")
                || old.stderr.contains("No such file or directory")))
    {
        return Err("无法读取 crontab，原任务保持不变".into());
    }
    let marker = format!("# onebox-native-cert-{target}");
    let legacy_acme = if target == "site" {
        ctx.paths.site().join("acme/acme.sh")
    } else {
        ctx.paths.tls().join("acme/acme.sh")
    };
    let executable = ctx.paths.executable.to_string_lossy();
    let mut text = old
        .stdout
        .lines()
        .filter(|l| {
            !l.ends_with(&marker)
                && !(l.contains(legacy_acme.to_string_lossy().as_ref())
                    && l.split_whitespace().any(|v| v == "--cron"))
                && !(l.contains(executable.as_ref())
                    && l.contains(&format!("cert-renew {target} --cron")))
        })
        .map(|s| format!("{s}\n"))
        .collect::<String>();
    if enabled {
        let exe = util::path_str(&ctx.paths.executable)?;
        if !exe
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
        {
            return Err("续期命令路径含不支持字符".into());
        }
        let command = if target == "subscription" {
            "subscription renew --cron".into()
        } else {
            format!("cert renew {target} --cron")
        };
        text.push_str(&format!(
            "17 4 * * * {exe} {command} >/dev/null 2>&1 {marker}\n"
        ));
    }
    let path = ctx
        .paths
        .run
        .join(format!(".cron-{}", util::random_hex(8)?));
    util::atomic_write(&path, text.as_bytes(), 0o600)?;
    let result = ctx.run("crontab", &[util::path_str(&path)?]);
    let _ = fs::remove_file(path);
    result?;
    Ok(())
}
fn copy_tree(source: &Path, dest: &Path, total: &mut u64) -> Result<()> {
    let m = fs::symlink_metadata(source)?;
    if m.file_type().is_symlink() {
        return Err("网站内容不能包含符号链接".into());
    }
    if m.is_dir() {
        fs::create_dir_all(dest)?;
        fs::set_permissions(dest, fs::Permissions::from_mode(0o755))?;
        for e in fs::read_dir(source)? {
            let e = e?;
            if e.file_name() == ".well-known" || e.file_name() == ".onebox-site-owned" {
                continue;
            }
            copy_tree(&e.path(), &dest.join(e.file_name()), total)?;
        }
    } else if m.is_file() {
        *total += m.len();
        if *total > 256 * 1024 * 1024 {
            return Err("网站内容超过 256 MiB".into());
        }
        util::atomic_write(dest, &fs::read(source)?, 0o644)?;
    } else {
        return Err("网站内容包含特殊文件".into());
    }
    Ok(())
}
fn publish_content(ctx: &Context, source: &Path, generated: bool) -> Result<String> {
    paths_safe(ctx)?;
    if !source.join("index.html").is_file() {
        return Err("网站需要 index.html".into());
    }
    let canonical = fs::canonicalize(source)?;
    let root = &ctx.paths.site_root;
    if canonical == *root
        || root.starts_with(&canonical)
        || canonical.starts_with(root)
        || ["/", "/etc", "/usr", "/var", "/root", "/home"]
            .iter()
            .any(|p| canonical == Path::new(p))
    {
        return Err("不允许递归导入或导入系统目录".into());
    }
    let dir = ctx.paths.site();
    let id = format!("{}-{}", util::now(), util::random_hex(4)?);
    let stage = root.with_file_name(format!(".onebox-site-{id}"));
    let result = (|| -> Result<String> {
        copy_tree(source, &stage, &mut 0)?;
        if root.join(".well-known").exists() {
            copy_tree(
                &root.join(".well-known"),
                &stage.join(".well-known"),
                &mut 0,
            )?;
        }
        util::atomic_write(&stage.join(".onebox-site-owned"), b"onebox\n", 0o600)?;
        let backups = dir.join("content-backups");
        fs::create_dir_all(&backups)?;
        fs::set_permissions(&backups, fs::Permissions::from_mode(0o700))?;
        let backup = backups.join(&id);
        if root.exists() {
            copy_tree(root, &backup, &mut 0)?;
        }
        let old = root.with_file_name(format!(".onebox-old-{id}"));
        if root.exists() {
            fs::rename(root, &old)?;
        }
        if let Err(e) = fs::rename(&stage, root) {
            if old.exists() {
                let _ = fs::rename(&old, root);
            }
            return Err(e.into());
        }
        let _ = fs::remove_dir_all(old);
        if generated {
            util::atomic_write(
                &dir.join("index.sha256"),
                util::sha256(&fs::read(root.join("index.html"))?).as_bytes(),
                0o600,
            )?;
        } else {
            let _ = fs::remove_file(dir.join("index.sha256"));
        }
        Ok(id)
    })();
    let _ = fs::remove_dir_all(stage);
    result
}
fn option(args: &[String], key: &str) -> Option<String> {
    args.windows(2).find(|a| a[0] == key).map(|a| a[1].clone())
}
/// Apply content only inside the workflow snapshot, together with its title
/// and generated-file hash. A process interruption is recovered with the rest
/// of the website rather than preserving half of a template change.
fn prepare_content(ctx: &Context, state: &mut State) -> Result<()> {
    let source = state.get("SITE_CONTENT_PENDING_PATH").to_owned();
    let text = state.get("SITE_CONTENT_PENDING_TEXT").to_owned();
    if source.is_empty() && text.is_empty() {
        return Ok(());
    }
    if !source.is_empty() && !text.is_empty() {
        return Err("网站内容任务存在冲突".into());
    }
    let temporary = ctx
        .paths
        .site()
        .join(format!(".content-{}", util::random_hex(8)?));
    let id = if source.is_empty() {
        util::atomic_write(&temporary.join("index.html"), text.as_bytes(), 0o644)?;
        let result = publish_content(ctx, &temporary, true);
        let _ = fs::remove_dir_all(&temporary);
        result?
    } else {
        publish_content(ctx, Path::new(&source), false)?
    };
    state.values.remove("SITE_CONTENT_PENDING_PATH");
    state.values.remove("SITE_CONTENT_PENDING_TEXT");
    state.set("SITE_LAST_CONTENT_BACKUP", id);
    Ok(())
}
pub fn command(ctx: &Context, args: &[String]) -> Result<()> {
    let action = args.first().map(String::as_str).unwrap_or("info");
    let mut s = crate::state::load(ctx)?;
    match action {
        "info"|"status"=>{println!("网站: {}；域名: {}；内部端口: {}；公网端口: {}\n内容: {}",if s.site_enabled(){"开启"}else{"关闭"},s.get("REALITY_SITE_DOMAIN"),s.number("REALITY_SITE_PORT",8443),public_port(&s),ctx.paths.site_root.display());if ctx.paths.site().join("cert.pem").is_file(){cert::status(ctx,&ctx.paths.site())?;}Ok(())},
        "enable"=>{let domain=args.get(1).ok_or("用法: site enable 域名 [--tls http|cf|custom --cert 文件 --key 文件]")?;if !s.any_reality(){return Err("自建 REALITY 网站需要先开启 REALITY 协议；独立订阅请用 subscription enable".into());}s.set("REALITY_SITE_DOMAIN",domain);s.set("REALITY_SITE_ENABLED",1);s.set("REALITY_SITE_HTTPS",1);s.set("SITE_ACME_METHOD",option(args,"--tls").unwrap_or_else(||"http".into()));if let Some(c)=option(args,"--cert"){s.set("SITE_CUSTOM_CERT",c);}
            if let Some(k)=option(args,"--key"){s.set("SITE_CUSTOM_KEY",k);}crate::workflow::apply(ctx,&s)},
        "disable"=>{if crate::subscription::uses_site(ctx)?{return Err("请先关闭订阅或将订阅切换为独立 HTTPS 站点".into());}s.set("REALITY_SITE_ENABLED",0);s.set("REALITY_SNI","www.microsoft.com");s.set("REALITY_DEST","www.microsoft.com:443");crate::workflow::apply(ctx,&s)},
        "https"=>{let v=match args.get(1).map(String::as_str){Some("on")=>1,Some("off")=>0,_=>return Err("用法: site https on|off".into())};s.set("REALITY_SITE_HTTPS",v);crate::workflow::apply(ctx,&s)},
        "renew"=>{s.set("CERT_RENEW_SITE",1);crate::workflow::apply(ctx,&s)},
        "import"=>{if !s.site_enabled(){return Err("请先启用网站".into());}let source=Path::new(args.get(1).ok_or("用法: site import 目录")?);util::safe_path(&fs::canonicalize(source)?)?;s.set("SITE_CONTENT_PENDING_PATH",util::path_str(source)?);crate::workflow::apply(ctx,&s)?;println!("网站已发布，原内容保存在网站备份目录");Ok(())},
        "restore"=>{if !s.site_enabled(){return Err("请先启用网站".into());}let key=args.get(1).map(String::as_str).unwrap_or("latest");let dir=ctx.paths.site().join("content-backups");let id=if key=="latest"{let mut names=fs::read_dir(&dir)?.filter_map(|e|e.ok()).filter(|e|e.file_type().map(|t|t.is_dir()).unwrap_or(false)).map(|e|e.file_name().to_string_lossy().to_string()).collect::<Vec<_>>();names.sort();names.pop().ok_or("没有网站备份")?}else{if !key.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-'){return Err("无效备份 ID".into());}key.into()};s.set("SITE_CONTENT_PENDING_PATH",util::path_str(&dir.join(id))?);crate::workflow::apply(ctx,&s)?;println!("网站已恢复");Ok(())},
        "template"|"preview"|"title"=>{
            let name=if action=="title"{s.get_or("SITE_TEMPLATE","minimal").into()}else{args.get(1).cloned().unwrap_or_else(||"minimal".into())};
            let title=if action=="title"{args.get(1).cloned().ok_or("用法: site title 标题")?}else{option(args,"--title").unwrap_or_else(||s.get_or("REALITY_SITE_TITLE","山间手记").into())};
            let description=option(args,"--description").unwrap_or_else(||s.get_or("SITE_DESCRIPTION","给思考一点空间，给日常一些留白。").into());let theme=option(args,"--theme").unwrap_or_else(||s.get_or("SITE_THEME","forest").into());
            let text=template(&name,&title,&description,&theme)?;
            if action=="preview"{let p=ctx.paths.site().join("preview.html");util::atomic_write(&p,text.as_bytes(),0o600)?;println!("{}",p.display());return Ok(());}
            if action=="title"{let saved=fs::read_to_string(ctx.paths.site().join("index.sha256")).unwrap_or_default();if saved!=util::sha256(&fs::read(ctx.paths.site_root.join("index.html"))?){return Err("网站已被手动修改或导入，请编辑原网页后重新导入".into());}}
            if !s.site_enabled(){return Err("请先启用网站".into());}
            s.set("SITE_CONTENT_PENDING_TEXT",text);s.set("REALITY_SITE_TITLE",title);s.set("SITE_DESCRIPTION",description);s.set("SITE_TEMPLATE",name);s.set("SITE_THEME",theme);crate::workflow::apply(ctx,&s)?;println!("网站已发布，原内容保存在网站备份目录");Ok(())
        },
        _=>Err("用法: site [info|enable 域名|disable|https on/off|renew|template|preview|title|import|restore]".into()),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn templates_escape_text() {
        let t = template("profile", "<script>alert(1)</script>", "a\"b", "ocean").unwrap();
        assert!(!t.contains("<script>"));
        assert!(t.contains("&lt;script&gt;"));
        assert!(template("bad", "x", "x", "forest").is_err());
    }
    #[test]
    fn quote_paths_reject_newline() {
        assert!(quote_path(Path::new("/tmp/foo\nbar")).is_err());
        assert_eq!(
            quote_path(Path::new("/tmp/a\"b")).unwrap(),
            "\"/tmp/a\\\"b\""
        );
    }
    #[test]
    fn reality_443_is_not_a_second_nginx_listener() {
        let mut s = State::default();
        s.set("PROTOCOLS", "anytls-reality");
        s.set_port(crate::model::Protocol::AnytlsReality, 443);
        s.set("REALITY_SITE_HTTPS", 1);
        assert!(!uses_frontend(&s));
        assert_eq!(public_port(&s), 443);
        s.set_port(crate::model::Protocol::AnytlsReality, 9443);
        assert!(uses_frontend(&s));
    }
    #[test]
    fn content_publish_preserves_challenge_and_refuses_symlink() {
        let root =
            std::env::temp_dir().join(format!("onebox-site-test-{}", util::random_hex(8).unwrap()));
        let ctx = Context {
            paths: crate::context::Paths::isolated(&root),
            ..Context::default()
        };
        let upload = root.join("upload");
        fs::create_dir_all(&upload).unwrap();
        fs::write(upload.join("index.html"), "new").unwrap();
        fs::create_dir_all(ctx.paths.site_root.join(".well-known/acme-challenge")).unwrap();
        fs::write(
            ctx.paths.site_root.join(".well-known/acme-challenge/token"),
            "challenge",
        )
        .unwrap();
        fs::write(ctx.paths.site_root.join("index.html"), "old").unwrap();
        let id = publish_content(&ctx, &upload, false).unwrap();
        assert_eq!(
            fs::read_to_string(ctx.paths.site_root.join("index.html")).unwrap(),
            "new"
        );
        assert_eq!(
            fs::read_to_string(ctx.paths.site_root.join(".well-known/acme-challenge/token"))
                .unwrap(),
            "challenge"
        );
        assert_eq!(
            fs::read_to_string(
                ctx.paths
                    .site()
                    .join("content-backups")
                    .join(id)
                    .join("index.html")
            )
            .unwrap(),
            "old"
        );
        std::os::unix::fs::symlink("/etc/passwd", upload.join("secret")).unwrap();
        assert!(publish_content(&ctx, &upload, false).is_err());
        assert_eq!(
            fs::read_to_string(ctx.paths.site_root.join("index.html")).unwrap(),
            "new"
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn pending_content_updates_hash_and_can_be_restored_with_transaction() {
        let root = std::env::temp_dir().join(format!(
            "onebox-content-txn-{}",
            util::random_hex(8).unwrap()
        ));
        let ctx = Context {
            paths: crate::context::Paths::isolated(&root),
            ..Context::default()
        };
        fs::create_dir_all(&ctx.paths.site_root).unwrap();
        fs::create_dir_all(ctx.paths.site()).unwrap();
        fs::write(ctx.paths.site_root.join("index.html"), b"old").unwrap();
        fs::write(ctx.paths.site().join("index.sha256"), util::sha256(b"old")).unwrap();
        let journal = crate::transaction::begin(&ctx, None, vec![], vec![], vec![], false).unwrap();
        let mut state = State::default();
        state.set("SITE_CONTENT_PENDING_TEXT", "new");
        prepare_content(&ctx, &mut state).unwrap();
        assert!(state.get("SITE_CONTENT_PENDING_TEXT").is_empty());
        assert_eq!(
            fs::read_to_string(ctx.paths.site().join("index.sha256")).unwrap(),
            util::sha256(b"new")
        );
        assert_eq!(
            fs::read(ctx.paths.site_root.join("index.html")).unwrap(),
            b"new"
        );
        journal.restore_files(&ctx).unwrap();
        assert_eq!(
            fs::read(ctx.paths.site_root.join("index.html")).unwrap(),
            b"old"
        );
        assert_eq!(
            fs::read_to_string(ctx.paths.site().join("index.sha256")).unwrap(),
            util::sha256(b"old")
        );
        journal.finish(&ctx).unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
