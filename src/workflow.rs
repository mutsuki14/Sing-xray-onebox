//! Transactional configuration application. Only a fully verified generation
//! is made durable; failures retain a recovery journal until rollback succeeds.
use crate::{
    cert,
    context::Context,
    model::{Core, Protocol, State},
    network, platform, render, site, state, subscription,
    transaction::{self, Journal, LEGACY_NETWORK_SERVICES, SERVICES},
    util, Result,
};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::IpAddr,
    sync::atomic::{AtomicI32, Ordering},
};

static CANCELLED: AtomicI32 = AtomicI32::new(0);
#[cfg(not(test))]
extern "C" fn interrupt(signal: i32) {
    CANCELLED.store(signal, Ordering::Relaxed);
}
struct Signals(Vec<(i32, libc::sigaction)>);
impl Signals {
    fn new() -> Result<Self> {
        CANCELLED.store(0, Ordering::Relaxed);
        #[allow(unused_mut)]
        let mut signals = Self(Vec::new());
        #[cfg(not(test))]
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = interrupt as *const () as usize;
            unsafe {
                libc::sigemptyset(&mut action.sa_mask);
            }
            if unsafe { libc::sigaction(signal, &action, &mut old) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            signals.0.push((signal, old));
        }
        Ok(signals)
    }
}
impl Drop for Signals {
    fn drop(&mut self) {
        for (signal, old) in &self.0 {
            unsafe {
                libc::sigaction(*signal, old, std::ptr::null_mut());
            }
        }
    }
}
fn cancelled() -> Result<()> {
    let signal = CANCELLED.load(Ordering::Relaxed);
    if signal != 0 {
        Err(format!("操作被信号 {signal} 中断").into())
    } else {
        Ok(())
    }
}

fn service_exists(ctx: &Context, name: &str) -> bool {
    platform::exists(ctx, name)
}
fn owned_cron(ctx: &Context, line: &str) -> bool {
    line.rsplit_once("# onebox-rust:")
        .map(|(_, name)| SERVICES.contains(&name.trim()))
        .unwrap_or(false)
        || [
            "# onebox-native-cert-site",
            "# onebox-native-cert-proxy",
            "# onebox-native-cert-subscription",
        ]
        .iter()
        .any(|m| line.trim_end().ends_with(m))
        || platform::boot::legacy_cron(ctx, line)
}
fn cron_snapshot(ctx: &Context) -> Result<(Vec<String>, bool)> {
    if !platform::has("crontab") {
        return Ok((vec![], false));
    }
    let out = ctx.output("crontab", &["-l"])?;
    if out.code != 0 && out.code != 1 {
        return Err("无法读取当前 crontab，事务尚未开始".into());
    }
    Ok((
        out.stdout
            .lines()
            .filter(|l| owned_cron(ctx, l))
            .map(str::to_owned)
            .collect(),
        true,
    ))
}
fn enabled(ctx: &Context, name: &str, cron: &[String]) -> Result<bool> {
    if !service_exists(ctx, name) {
        return Ok(false);
    }
    match platform::init_system() {
        "systemd" => {
            let out = ctx.output("systemctl", &["is-enabled", name])?;
            if out.code > 4 {
                return Err(format!("无法读取 {name} 自启状态").into());
            }
            Ok(out.success())
        }
        "openrc" => {
            let out = ctx.run("rc-update", &["show", "default"])?;
            Ok(out
                .lines()
                .any(|l| l.split_whitespace().next() == Some(name)))
        }
        _ => Ok(cron
            .iter()
            .any(|l| l.trim_end().ends_with(&format!("# onebox-rust:{name}")))),
    }
}
fn restore_cron(ctx: &Context, j: &Journal) -> Result<()> {
    if !platform::has("crontab") {
        return if j.cron_available && !j.cron_lines.is_empty() {
            Err("恢复续期任务需要 crontab".into())
        } else {
            Ok(())
        };
    }
    let out = ctx.output("crontab", &["-l"])?;
    if out.code != 0 && out.code != 1 {
        return Err("无法读取 crontab 以恢复托管任务".into());
    }
    let mut lines = out
        .stdout
        .lines()
        .filter(|l| !owned_cron(ctx, l))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    lines.extend(j.cron_lines.clone());
    let file = transaction::directory(ctx).join("restore-crontab");
    util::atomic_write(&file, format!("{}\n", lines.join("\n")).as_bytes(), 0o600)?;
    ctx.run("crontab", &[util::path_str(&file)?])?;
    Ok(())
}
type RuntimeSnapshot = (Vec<String>, Vec<String>, Vec<String>, bool);
fn snapshot_running(ctx: &Context) -> Result<RuntimeSnapshot> {
    let (cron, available) = cron_snapshot(ctx)?;
    let mut active = Vec::new();
    let mut auto = Vec::new();
    for name in SERVICES.iter().chain(LEGACY_NETWORK_SERVICES) {
        if platform::running(ctx, name) {
            active.push((*name).into());
        }
        if enabled(ctx, name, &cron)? {
            auto.push((*name).into());
        }
    }
    Ok((active, auto, cron, available))
}
fn stop_current(ctx: &Context, disable: bool) -> Result<()> {
    let mut errors = Vec::new();
    // Close public entrances before their backends. The network unit is a
    // oneshot that may be running this recovery; stopping it would kill us.
    for name in [
        "onebox-sing-box",
        "onebox-xray",
        "onebox-subscription-web",
        "onebox-site",
        "onebox-subscription",
    ] {
        if service_exists(ctx, name) {
            if let Err(e) = platform::service(ctx, name, "stop") {
                errors.push(format!("停止 {name}: {e}"));
            }
            if disable {
                if let Err(e) = platform::service(ctx, name, "disable") {
                    errors.push(format!("停用 {name}: {e}"));
                }
            }
        }
    }
    // Disabling an enabled unit only removes its future boot hook. Do not
    // stop this oneshot: it may be the process performing this rollback.
    if disable && service_exists(ctx, "onebox-network") {
        if let Err(e) = platform::service(ctx, "onebox-network", "disable") {
            errors.push(format!("停用 onebox-network: {e}"));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; ").into())
    }
}

/// Restore the snapshot while its current firewall ledgers are still available.
/// If removal fails, do not overwrite those ledgers or the binaries of running
/// processes; leave the journal for a later, repeatable recovery attempt.
fn rollback(ctx: &Context, j: &mut Journal) -> Result<()> {
    // A corrupt snapshot must not take healthy running services offline.
    j.validate_files(ctx)?;
    j.set_phase(ctx, "rollback-stop")?;
    let mut errors = Vec::new();
    if let Err(e) = stop_current(ctx, true) {
        errors.push(e.to_string());
    }
    if let Err(e) = network::clear_owner(ctx, "acme") {
        errors.push(format!("清理 ACME 防火墙: {e}"));
    }
    if let Err(e) = network::clear_rules(ctx) {
        errors.push(format!("清理当前网络: {e}"));
    }
    if !errors.is_empty() {
        return Err(errors.join("; ").into());
    }
    j.set_phase(ctx, "rollback-files")?;
    j.restore_files(ctx)?;
    if platform::init_system() == "systemd" {
        ctx.run("systemctl", &["daemon-reload"])?;
    }
    j.set_phase(ctx, "rollback-services")?;
    if let Some(old) = &j.old_state {
        // Rebuild rules only. Reinstalling persistence here would immediately
        // retire the legacy hooks that the file snapshot just restored.
        network::apply_rules(ctx, old)?;
    }
    for name in SERVICES.iter().chain(LEGACY_NETWORK_SERVICES) {
        if service_exists(ctx, name) {
            platform::service(
                ctx,
                name,
                if j.enabled_services.iter().any(|n| n == name) {
                    "enable"
                } else {
                    "disable"
                },
            )?;
        }
    }
    restore_cron(ctx, j)?;
    for name in [
        "onebox-subscription",
        "onebox-site",
        "onebox-subscription-web",
        "onebox-sing-box",
        "onebox-xray",
    ] {
        if j.active_services.iter().any(|n| n == name) {
            platform::service(ctx, name, "start")?;
            platform::wait_running(ctx, name)?;
        }
    }
    j.set_phase(ctx, "rolled-back")?;
    j.finish(ctx)
}
pub fn recover_locked(ctx: &Context, lock: &transaction::Lock) -> Result<()> {
    lock.verify(ctx)?;
    if let Some(mut journal) = transaction::load(ctx)? {
        if matches!(journal.phase.as_str(), "committed" | "rolled-back") {
            journal.finish(ctx)?;
        } else {
            rollback(ctx, &mut journal).map_err(|e| {
                format!(
                    "未完成事务恢复失败；日志保留于 {}: {e}",
                    transaction::directory(ctx).display()
                )
            })?;
        }
    }
    crate::update::recover_locked(ctx, lock)
}
pub fn recover(ctx: &Context) -> Result<()> {
    let lock = transaction::acquire(ctx)?;
    recover_locked(ctx, &lock)
}
/// Reestablish network rules at boot and refresh the self-address denylist
/// when global interface addresses changed since the saved generation.
pub fn restore_network(ctx: &Context) -> Result<()> {
    let lock = transaction::acquire(ctx)?;
    recover_locked(ctx, &lock)?;
    let mut current = state::load(ctx)?;
    if current.get_or("BLOCK_PRIVATE", "1") == "1" {
        let previous = current.get("OWN_IP_CIDRS").to_owned();
        refresh_own_ips(ctx, &mut current)?;
        if current.get("OWN_IP_CIDRS") != previous {
            return apply_locked(ctx, &current, &lock);
        }
    }
    // This path has no configuration journal. Leave persistence untouched;
    // hook migration belongs to a full apply transaction.
    network::apply_rules(ctx, &current)
}

/// Inventory is captured before rendering, including secondary global
/// addresses not used as the advertised endpoint. Never infer ownership from
/// a DNS name alone; render adds the explicit advertised IPs as well.
fn refresh_own_ips(ctx: &Context, s: &mut State) -> Result<()> {
    let out = ctx.run("ip", &["-j", "address", "show", "scope", "global"])?;
    let interfaces: Value = serde_json::from_str(&out)?;
    let rows = interfaces.as_array().ok_or("ip 地址清单不是 JSON 数组")?;
    let mut values = BTreeSet::new();
    for row in rows {
        if let Some(addresses) = row["addr_info"].as_array() {
            for addr in addresses {
                if let Some(raw) = addr["local"].as_str() {
                    let ip: IpAddr = raw.parse().map_err(|_| "ip 地址清单包含无效 IP")?;
                    values.insert(format!("{ip}/{}", if ip.is_ipv4() { 32 } else { 128 }));
                }
            }
        }
    }
    s.set("OWN_IP_CIDRS", serde_json::to_string(&values)?);
    Ok(())
}
fn acme_http(s: &State) -> bool {
    s.site_enabled() && s.get_or("SITE_ACME_METHOD", "http") == "http"
        || s.needs_cert()
            && s.get("TLS_MODE") == "acme"
            && matches!(s.get_or("ACME_METHOD", "standalone"), "standalone" | "http")
        || s.flag("SUBSCRIPTION_ENABLED")
            && s.get("SUBSCRIPTION_MODE") == "standalone"
            && s.flag("SUBSCRIPTION_HTTP")
}
fn validate_ports(ctx: &Context, s: &State) -> Result<()> {
    let mut seen = BTreeMap::new();
    for p in s.protocols() {
        for udp in [false, true] {
            if (udp && p.network() == "tcp") || (!udp && p.network() == "udp") {
                continue;
            }
            let port = s.port(p);
            if let Some(previous) = seen.insert((port, udp), p) {
                let shared =
                    !udp && matches!(
                        (previous, p),
                        (Protocol::VlessReality, Protocol::VlessXhttp)
                            | (Protocol::VlessXhttp, Protocol::VlessReality)
                    ) && s.core(Protocol::VlessReality) == Core::Xray
                        && s.core(Protocol::VlessXhttp) == Core::Xray
                        && s.port(Protocol::VlessReality) == s.port(Protocol::VlessXhttp);
                if !shared {
                    return Err(
                        format!("协议重复使用 {port}/{}", if udp { "udp" } else { "tcp" }).into(),
                    );
                }
            }
        }
    }
    if acme_http(s) && seen.contains_key(&(80, false)) {
        return Err("HTTP-01 验证需要保留 TCP 80，不能同时用于代理入站".into());
    }
    if s.enabled(Protocol::Hysteria2) && !s.get("HY2_HOP").is_empty() {
        let (start, end) = s.get("HY2_HOP").split_once('-').ok_or("跳跃端口范围无效")?;
        let (start, end) = (start.parse::<u16>()?, end.parse::<u16>()?);
        if start < 1024 || start >= end {
            return Err("跳跃端口范围无效".into());
        }
        for p in s.protocols() {
            if p != Protocol::Hysteria2
                && p.network() != "tcp"
                && (start..=end).contains(&s.port(p))
            {
                return Err(format!("Hysteria2 跳跃范围与 {p} UDP 端口冲突").into());
            }
        }
    }
    let uses_guard = s
        .protocols()
        .iter()
        .any(|p| p.reality() && s.core(*p) == Core::Xray);
    if uses_guard {
        let guard = s.number("REALITY_GUARD_PORT", 0);
        if guard == 0 || seen.contains_key(&(guard, false)) {
            return Err("REALITY guard 端口缺失或与代理冲突".into());
        }
        if s.site_enabled()
            && (guard == 80
                || guard == s.number("REALITY_SITE_PORT", 8443)
                || (guard == 443 && s.get_or("REALITY_SITE_HTTPS", "1") == "1"))
        {
            return Err("REALITY guard 端口与网站监听冲突".into());
        }
        if s.flag("SUBSCRIPTION_ENABLED")
            && s.get("SUBSCRIPTION_MODE") == "standalone"
            && (guard == s.number("SUBSCRIPTION_PORT", 443)
                || (guard == 80 && s.flag("SUBSCRIPTION_HTTP")))
        {
            return Err("REALITY guard 端口与订阅监听冲突".into());
        }
    }
    // FRP reserves inactive listeners and TCP/UDP allow ranges too.
    let mut desired = network::desired_ports(s)?;
    if s.site_enabled() {
        desired.push((s.number("REALITY_SITE_PORT", 8443), false));
    }
    if uses_guard {
        desired.push((s.number("REALITY_GUARD_PORT", 0), false));
    }
    for (start, end, transport) in crate::frp::reserved_ports(ctx)? {
        for (port, udp) in &desired {
            if *port >= start
                && *port <= end
                && (transport == "both" || transport == if *udp { "udp" } else { "tcp" })
            {
                return Err(format!(
                    "端口 {port}/{} 已保留给 FRP",
                    if *udp { "udp" } else { "tcp" }
                )
                .into());
            }
        }
    }
    Ok(())
}
fn configure_defaults(s: &mut State) -> Result<()> {
    if s.get("BLOCK_PRIVATE").is_empty() {
        s.set("BLOCK_PRIVATE", 1);
    }
    if s.get("BLOCK_BT").is_empty() {
        s.set("BLOCK_BT", 1);
    }
    if s.get("INSTALLED_AT").is_empty() {
        s.set("INSTALLED_AT", util::now());
    }
    if s.get("CLASH_SECRET").is_empty() {
        s.set("CLASH_SECRET", util::random_hex(24)?);
    }
    s.validate()
}
fn stage(ctx: &Context, j: &mut Journal, name: &str) -> Result<()> {
    cancelled()?;
    j.set_phase(ctx, name)
}
fn apply_generation(
    ctx: &Context,
    s: &mut State,
    j: &mut Journal,
    replacements: &[(Core, std::path::PathBuf)],
) -> Result<()> {
    stage(ctx, j, "prepare-state")?;
    platform::install_self(ctx)?;
    cert::disable_legacy_deployments(ctx)?;
    crate::backup::prepare_restore(ctx, s)?;
    subscription::prepare(ctx, s)?;
    if !replacements.is_empty() {
        stage(ctx, j, "replace-cores")?;
        let mut changed = BTreeSet::new();
        for (core, candidate) in replacements {
            if !s.uses(*core) || !changed.insert(*core) {
                return Err("待更新内核不在配置中或重复".into());
            }
            util::safe_path(candidate)?;
            let metadata = fs::metadata(candidate)?;
            if !metadata.is_file() || metadata.len() > 512 * 1024 * 1024 {
                return Err("待更新内核文件无效".into());
            }
            util::atomic_write(&ctx.paths.core_bin(*core), &fs::read(candidate)?, 0o755)?;
        }
    }
    stage(ctx, j, "prepare-cores")?;
    platform::ensure_cores(ctx, s)?;
    refresh_own_ips(ctx, s)?;
    validate_ports(ctx, s)?;
    stage(ctx, j, "prepare-certificates")?;
    if acme_http(s) {
        network::apply_ports(ctx, "acme", &[(80, false)])?;
    }
    subscription::prepare_certificates(ctx, s)?;
    // Standalone HTTP-01 must be able to acquire port 80 when an old website
    // or proxy listener is being removed by this same transaction.
    if s.needs_cert()
        && s.get("TLS_MODE") == "acme"
        && s.get_or("ACME_METHOD", "standalone") == "standalone"
        && !s.site_enabled()
    {
        if service_exists(ctx, "onebox-site") {
            platform::service(ctx, "onebox-site", "stop")?;
        }
        if let Some(old) = &j.old_state {
            for core in [Core::Singbox, Core::Xray] {
                if old
                    .protocols()
                    .iter()
                    .any(|p| old.core(*p) == core && old.port(*p) == 80 && p.network() != "udp")
                {
                    platform::service(ctx, core.service(), "stop")?;
                }
            }
        }
    }
    site::prepare(ctx, s)?;
    cancelled()?;
    cert::prepare(ctx, s)?;
    stage(ctx, j, "check-configurations")?;
    for core in [Core::Singbox, Core::Xray] {
        if s.uses(core) {
            let path = transaction::directory(ctx).join(format!("{}.new.json", core.binary()));
            util::atomic_write(
                &path,
                &serde_json::to_vec_pretty(&render::server(ctx, s, core)?)?,
                0o600,
            )?;
            platform::core_check(ctx, core, &path)?;
        }
    }
    stage(ctx, j, "stop-old-services")?;
    for name in [
        "onebox-sing-box",
        "onebox-xray",
        "onebox-subscription-web",
        "onebox-site",
    ] {
        if service_exists(ctx, name) {
            platform::service(ctx, name, "stop")?;
        }
    }
    stage(ctx, j, "commit-configurations")?;
    for core in [Core::Singbox, Core::Xray] {
        let target = ctx.paths.core_config(core);
        if s.uses(core) {
            let source = transaction::directory(ctx).join(format!("{}.new.json", core.binary()));
            util::atomic_write(&target, &fs::read(source)?, 0o600)?;
        } else if target.exists() {
            fs::remove_file(target)?;
        }
    }
    stage(ctx, j, "configure-services")?;
    platform::configure_services(ctx, s)?;
    stage(ctx, j, "apply-website")?;
    site::apply(ctx, s)?;
    stage(ctx, j, "apply-network")?;
    network::apply(ctx, s)?;
    stage(ctx, j, "start-cores")?;
    for core in [Core::Singbox, Core::Xray] {
        if s.uses(core) {
            platform::service(ctx, core.service(), "start")?;
            platform::wait_running(ctx, core.service())?;
        }
    }
    stage(ctx, j, "publish-clients")?;
    render::write_clients(ctx, s)?;
    stage(ctx, j, "publish-subscription")?;
    subscription::publish(ctx, s)?;
    stage(ctx, j, "finalize")?;
    network::clear_owner(ctx, "acme")?;
    // Recheck after publishing: a failed/racing service must not be blessed by
    // a successful state write just because its first startup check passed.
    for core in [Core::Singbox, Core::Xray] {
        if s.uses(core) && !platform::running(ctx, core.service()) {
            return Err(format!("{} 在提交前退出", core.service()).into());
        }
    }
    cancelled()?;
    state::save(ctx, s)?;
    j.set_phase(ctx, "committed")?;
    j.finish(ctx)
}
pub fn apply(ctx: &Context, new_state: &State) -> Result<()> {
    let lock = transaction::acquire(ctx)?;
    apply_locked(ctx, new_state, &lock)
}
pub fn apply_locked(ctx: &Context, new_state: &State, lock: &transaction::Lock) -> Result<()> {
    apply_with_cores_locked(ctx, new_state, lock, &[])
}
/// Update candidates are copied only after the old binaries are captured by
/// the same journal as their configs, so rollback never combines generations.
pub fn apply_with_cores_locked(
    ctx: &Context,
    new_state: &State,
    lock: &transaction::Lock,
    replacements: &[(Core, std::path::PathBuf)],
) -> Result<()> {
    recover_locked(ctx, lock)?;
    if !new_state.get("__EXPECTED_STATE_HASH").is_empty()
        && new_state.get("__EXPECTED_STATE_HASH") != state::expected_hash(ctx)?
    {
        return Err("配置已被其他操作修改，请重新读取后重试".into());
    }
    let _signals = Signals::new()?;
    let mut proposed = new_state.clone();
    proposed.values.remove("__EXPECTED_STATE_HASH");
    configure_defaults(&mut proposed)?;
    validate_ports(ctx, &proposed)?;
    let old = if state::installed(ctx) {
        Some(state::load(ctx)?)
    } else {
        None
    };
    let (active, enabled, cron, cron_available) = snapshot_running(ctx)?;
    let mut journal = transaction::begin(ctx, old, active, enabled, cron, cron_available)?;
    if let Err(error) = apply_generation(ctx, &mut proposed, &mut journal, replacements) {
        // If journal cleanup alone failed after a durable commit, recovery
        // only needs to clean up that committed journal, not revert a success.
        if journal.phase == "committed" {
            return Err(format!("配置已提交，但事务清理失败: {error}；请执行 recover 清理").into());
        }
        return match rollback(ctx, &mut journal) {
            Ok(()) => Err(format!("配置未应用，已恢复原状态: {error}").into()),
            Err(recovery) => Err(format!(
                "配置失败: {error}；恢复未完成: {recovery}；事务日志保留于 {}，请执行 recover",
                transaction::directory(ctx).display()
            )
            .into()),
        };
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{CommandOutput, Paths, Runner};
    use std::sync::{Arc, Mutex};
    struct Fake {
        commands: Mutex<Vec<String>>,
        fail: &'static str,
    }
    impl Runner for Fake {
        fn output(&self, p: &str, a: &[String]) -> Result<CommandOutput> {
            let cmd = format!("{p} {}", a.join(" "));
            self.commands.lock().unwrap().push(cmd.clone());
            if cmd.contains(self.fail) && !self.fail.is_empty() {
                return Ok(CommandOutput {
                    code: 1,
                    stderr: "injected failure".into(),
                    ..Default::default()
                });
            }
            let stdout = if p == "ip" {
                r#"[{"addr_info":[{"local":"8.8.4.4"},{"local":"9.9.9.9"},{"local":"2001:4860:4860::8888"}]}]"#.into()
            } else {
                String::new()
            };
            Ok(CommandOutput {
                stdout,
                ..Default::default()
            })
        }
    }
    fn fixture(fail: &'static str) -> (Context, std::path::PathBuf) {
        let root =
            std::env::temp_dir().join(format!("onebox-workflow-{}", util::random_hex(8).unwrap()));
        let ctx = Context {
            paths: Paths::isolated(&root),
            runner: Arc::new(Fake {
                commands: Mutex::new(vec![]),
                fail,
            }),
            yes: true,
        };
        (ctx, root)
    }
    #[test]
    fn all_global_addresses_are_recorded_for_self_access_protection() {
        let (ctx, _) = fixture("");
        let mut s = State::default();
        refresh_own_ips(&ctx, &mut s).unwrap();
        let addresses: Vec<String> = serde_json::from_str(s.get("OWN_IP_CIDRS")).unwrap();
        assert!(addresses.contains(&"9.9.9.9/32".into()));
        assert!(addresses.contains(&"2001:4860:4860::8888/128".into()));
    }
    #[test]
    fn ip_inventory_failure_does_not_silently_weaken_policy() {
        let (ctx, _) = fixture("ip ");
        assert!(refresh_own_ips(&ctx, &mut State::default()).is_err());
    }
    #[test]
    fn stage_journal_is_durable_before_action_and_repeatable() {
        let (ctx, root) = fixture("");
        let _lock = transaction::acquire(&ctx).unwrap();
        let mut j = transaction::begin(&ctx, None, vec![], vec![], vec![], false).unwrap();
        for name in [
            "prepare-cores",
            "prepare-certificates",
            "commit-configurations",
            "apply-network",
            "start-cores",
            "publish-clients",
            "publish-subscription",
        ] {
            stage(&ctx, &mut j, name).unwrap();
            assert_eq!(transaction::load(&ctx).unwrap().unwrap().phase, name);
        }
        j.finish(&ctx).unwrap();
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn unrelated_cron_jobs_are_not_owned() {
        let (ctx, _) = fixture("");
        assert!(owned_cron(
            &ctx,
            "17 4 * * * onebox cert renew site # onebox-native-cert-site"
        ));
        assert!(owned_cron(
            &ctx,
            "@reboot onebox service onebox-xray start # onebox-rust:onebox-xray"
        ));
        assert!(!owned_cron(&ctx, "* * * * * admin-command # other"));
        assert!(!owned_cron(
            &ctx,
            "@reboot onebox frps start # onebox-rust:onebox-frps"
        ));
        let legacy = format!(
            "@reboot {} net-apply >/dev/null 2>&1; {} start >/dev/null 2>&1",
            ctx.paths.executable.display(),
            ctx.paths.executable.display()
        );
        assert!(owned_cron(&ctx, &legacy));
        assert!(!owned_cron(&ctx, &format!("{legacy}; admin-command")));
        assert!(!owned_cron(
            &ctx,
            "@reboot /opt/unrelated/onebox net-apply >/dev/null 2>&1; /opt/unrelated/onebox start >/dev/null 2>&1"
        ));
    }
    #[test]
    fn hop_ranges_and_guard_ports_cannot_steal_other_listeners() {
        let (ctx, _) = fixture("");
        let mut s = State::default();
        s.set("PROTOCOLS", "hysteria2 tuic");
        s.set_port(Protocol::Hysteria2, 24000);
        s.set_port(Protocol::Tuic, 25050);
        s.set("HY2_HOP", "25000-25100");
        assert!(validate_ports(&ctx, &s)
            .unwrap_err()
            .to_string()
            .contains("跳跃范围"));
        s.set_port(Protocol::Tuic, 25200);
        assert!(validate_ports(&ctx, &s).is_ok());
        s.set("PROTOCOLS", "vless-reality");
        s.set_core(Protocol::VlessReality, Core::Xray);
        s.set_port(Protocol::VlessReality, 443);
        s.set("REALITY_GUARD_PORT", 8443);
        s.set("REALITY_SITE_ENABLED", 1);
        assert!(validate_ports(&ctx, &s)
            .unwrap_err()
            .to_string()
            .contains("网站"));
        s.set("REALITY_SITE_ENABLED", 0);
        s.set("SUBSCRIPTION_ENABLED", 1);
        s.set("SUBSCRIPTION_MODE", "standalone");
        s.set("SUBSCRIPTION_PORT", 8443);
        assert!(validate_ports(&ctx, &s)
            .unwrap_err()
            .to_string()
            .contains("订阅"));
        s.set("SUBSCRIPTION_PORT", 9443);
        assert!(validate_ports(&ctx, &s).is_ok());
    }

    struct RuntimeState {
        active: BTreeSet<String>,
        enabled: BTreeSet<String>,
        cron: String,
        commands: Vec<String>,
        fault: String,
        fired: bool,
        block_rollback: bool,
    }
    struct Runtime {
        paths: Paths,
        state: Mutex<RuntimeState>,
    }
    impl Runner for Runtime {
        fn output(&self, p: &str, a: &[String]) -> Result<CommandOutput> {
            let mut runtime = self.state.lock().unwrap();
            let phase = fs::read(self.paths.root.join(".transaction/journal.json"))
                .ok()
                .and_then(|b| serde_json::from_slice::<Journal>(&b).ok())
                .map(|j| j.phase)
                .unwrap_or_default();
            runtime
                .commands
                .push(format!("{phase}: {p} {}", a.join(" ")));
            let command = a.first().map(String::as_str).unwrap_or("");
            if runtime.block_rollback && phase == "rollback-stop" && command == "stop" {
                return Ok(CommandOutput {
                    code: 1,
                    stderr: "injected persistent stop failure".into(),
                    ..Default::default()
                });
            }
            if !runtime.fired {
                let fault = runtime.fault.clone();
                if fault == "legacy-second-disable"
                    && p == "systemctl"
                    && a == ["disable", "onebox-hop"]
                {
                    runtime.fired = true;
                    return Ok(CommandOutput {
                        code: 1,
                        stderr: "injected partial legacy retirement".into(),
                        ..Default::default()
                    });
                }
                if !fault.is_empty() && fault == phase {
                    runtime.fired = true;
                    return Ok(CommandOutput {
                        code: 1,
                        stderr: format!("injected {phase}"),
                        ..Default::default()
                    });
                }
                // Filesystem commit errors are introduced at the preceding
                // Runner boundary; production code contains no test hooks.
                if fault == "commit-configurations"
                    && phase == "stop-old-services"
                    && command == "stop"
                {
                    let target = self.paths.core_config(Core::Singbox);
                    fs::remove_file(&target)?;
                    fs::create_dir(target)?;
                    runtime.fired = true;
                } else if matches!(fault.as_str(), "publish-clients" | "publish-subscription")
                    && phase == "start-cores"
                    && command == "is-active"
                {
                    if fault == "publish-clients" {
                        fs::remove_dir_all(self.paths.clients())?;
                        fs::write(self.paths.clients(), b"not a directory")?;
                    } else {
                        let dir = self.paths.root.join("subscription");
                        fs::create_dir_all(&dir)?;
                        fs::write(dir.join("settings.json"), b"invalid JSON")?;
                    }
                    runtime.fired = true;
                } else if fault == "final-state" && phase == "finalize" && command == "is-active" {
                    fs::remove_file(self.paths.state())?;
                    fs::create_dir(self.paths.state())?;
                    runtime.fired = true;
                }
            }
            if p == "ip" {
                return Ok(CommandOutput{stdout:r#"[{"addr_info":[{"local":"8.8.4.4"},{"local":"9.9.9.9"},{"local":"2001:4860:4860::8888"}]}]"#.into(),..Default::default()});
            }
            if command == "version" {
                return Ok(CommandOutput {
                    stdout: "sing-box version 1.14.2\n".into(),
                    ..Default::default()
                });
            }
            if p == "crontab" {
                if command == "-l" {
                    return Ok(CommandOutput {
                        stdout: runtime.cron.clone(),
                        ..Default::default()
                    });
                }
                runtime.cron = fs::read_to_string(command)?;
                return Ok(CommandOutput::default());
            }
            if p == "systemctl" {
                let name = a.last().cloned().unwrap_or_default();
                let success = match command {
                    "is-active" => runtime.active.contains(&name),
                    "is-enabled" => runtime.enabled.contains(&name),
                    "start" | "restart" => {
                        runtime.active.insert(name);
                        true
                    }
                    "stop" => {
                        runtime.active.remove(&name);
                        true
                    }
                    "enable" => {
                        runtime.enabled.insert(name);
                        true
                    }
                    "disable" => {
                        runtime.enabled.remove(&name);
                        true
                    }
                    _ => true,
                };
                return Ok(CommandOutput {
                    code: if success { 0 } else { 3 },
                    ..Default::default()
                });
            }
            Ok(CommandOutput::default())
        }
    }
    fn runtime_fixture() -> (Context, State, Arc<Runtime>, std::path::PathBuf) {
        let root =
            std::env::temp_dir().join(format!("onebox-runtime-{}", util::random_hex(8).unwrap()));
        let paths = Paths::isolated(&root);
        let runner = Arc::new(Runtime {
            paths: paths.clone(),
            state: Mutex::new(RuntimeState {
                active: BTreeSet::new(),
                enabled: BTreeSet::new(),
                cron: String::new(),
                commands: vec![],
                fault: String::new(),
                fired: false,
                block_rollback: false,
            }),
        });
        let ctx = Context {
            paths,
            runner: runner.clone(),
            yes: true,
        };
        fs::create_dir_all(&ctx.paths.bin).unwrap();
        util::atomic_write(&ctx.paths.core_bin(Core::Singbox), b"old-core", 0o755).unwrap();
        util::atomic_write(&ctx.paths.executable, b"old-manager", 0o755).unwrap();
        let mut old = State::default();
        for (k, v) in [
            ("PROTOCOLS", "anytls-reality"),
            ("PASSWORD", "old-secret"),
            ("SERVER_ADDR", "8.8.4.4"),
            ("REALITY_PRIVATE_KEY", "private"),
            ("REALITY_PUBLIC_KEY", "public"),
            ("REALITY_SHORT_ID", "0123456789abcdef"),
            ("REALITY_SNI", "www.example.com"),
            ("REALITY_DEST", "www.example.com:443"),
        ] {
            old.set(k, v);
        }
        old.set_port(Protocol::AnytlsReality, 24443);
        state::save(&ctx, &old).unwrap();
        util::atomic_write(&ctx.paths.core_config(Core::Singbox), b"old-config", 0o600).unwrap();
        util::atomic_write(
            &ctx.paths.clients().join("old-client"),
            b"old-client",
            0o600,
        )
        .unwrap();
        util::atomic_write(
            &ctx.paths.site().join(".onebox-site-owned"),
            b"owned",
            0o600,
        )
        .unwrap();
        util::atomic_write(&ctx.paths.site_root.join("index.html"), b"old-site", 0o644).unwrap();
        platform::configure_services(&ctx, &old).unwrap();
        platform::write_service(&ctx, "onebox-site", &ctx.paths.executable, &[], &[]).unwrap();
        for service in ["onebox-sing-box", "onebox-site"] {
            platform::service(&ctx, service, "enable").unwrap();
            platform::service(&ctx, service, "start").unwrap();
        }
        (ctx, old, runner, root)
    }
    fn assert_old_generation(ctx: &Context, old: &State, runner: &Runtime) {
        let mut restored = state::load(ctx).unwrap();
        restored.values.remove("__EXPECTED_STATE_HASH");
        let mut expected = old.clone();
        expected.values.remove("__EXPECTED_STATE_HASH");
        assert_eq!(restored, expected);
        assert_eq!(
            fs::read(ctx.paths.core_config(Core::Singbox)).unwrap(),
            b"old-config"
        );
        assert_eq!(
            fs::read(ctx.paths.core_bin(Core::Singbox)).unwrap(),
            b"old-core"
        );
        assert_eq!(fs::read(&ctx.paths.executable).unwrap(), b"old-manager");
        assert_eq!(
            fs::read(ctx.paths.clients().join("old-client")).unwrap(),
            b"old-client"
        );
        assert_eq!(
            fs::read(ctx.paths.site_root.join("index.html")).unwrap(),
            b"old-site"
        );
        let runtime = runner.state.lock().unwrap();
        for service in ["onebox-sing-box", "onebox-site"] {
            assert!(runtime.active.contains(service), "{service} not running");
            assert!(runtime.enabled.contains(service), "{service} not enabled");
        }
        assert!(!transaction::directory(ctx).exists());
    }
    #[test]
    fn legacy_boot_retirement_rolls_back_files_cron_and_enabled_units() {
        const CHILD: &str = "ONEBOX_WORKFLOW_LEGACY_BOOT_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let path = std::env::temp_dir().join(format!(
                "onebox-boot-test-path-{}",
                util::random_hex(8).unwrap()
            ));
            fs::create_dir(&path).unwrap();
            // Presence is used for capability detection; commands are handled
            // by the Runner, never by a host crontab.
            util::atomic_write(&path.join("crontab"), b"fixture", 0o755).unwrap();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "workflow::tests::legacy_boot_retirement_rolls_back_files_cron_and_enabled_units", "--nocapture"])
                .env(CHILD, "1").env("ONEBOX_INIT", "systemd").env("PATH", &path).output().unwrap();
            fs::remove_dir_all(path).unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        // One failure interrupts retirement halfway through; the other occurs
        // after all old hooks were removed and the replacement was enabled.
        for fault in ["legacy-second-disable", "start-cores"] {
            let (ctx, old, runner, root) = runtime_fixture();
            let hooks = platform::boot::legacy_paths(&ctx).unwrap();
            for path in &hooks {
                util::atomic_write(path, b"old-owned-boot-hook\n", 0o755).unwrap();
            }
            let unrelated = root.join("local.d/admin.start");
            util::atomic_write(&unrelated, b"unrelated-local-hook\n", 0o755).unwrap();
            let legacy = format!(
                "@reboot {} net-apply >/dev/null 2>&1; {} start >/dev/null 2>&1",
                ctx.paths.executable.display(),
                ctx.paths.executable.display()
            );
            let original_cron = format!("17 4 * * * admin-backup\n{legacy}\n");
            {
                let mut runtime = runner.state.lock().unwrap();
                runtime.cron = original_cron.clone();
                runtime
                    .enabled
                    .extend(LEGACY_NETWORK_SERVICES.iter().map(|name| (*name).into()));
                runtime.fault = fault.into();
                runtime.commands.clear();
            }
            let error = apply(&ctx, &old).unwrap_err().to_string();
            assert!(error.contains("已恢复原状态"), "{fault}: {error}");
            assert_old_generation(&ctx, &old, &runner);
            for path in &hooks {
                assert_eq!(fs::read(path).unwrap(), b"old-owned-boot-hook\n");
            }
            assert_eq!(fs::read(&unrelated).unwrap(), b"unrelated-local-hook\n");
            let runtime = runner.state.lock().unwrap();
            assert!(runtime.fired, "{fault} was not reached");
            assert_eq!(runtime.cron, original_cron);
            for name in LEGACY_NETWORK_SERVICES {
                assert!(runtime.enabled.contains(*name));
            }
            assert!(!runtime.enabled.contains("onebox-network"));
            assert!(!ctx.paths.systemd.join("onebox-network.service").exists());
            assert!(!runtime
                .commands
                .iter()
                .any(|command| command.contains("stop onebox-net")
                    || command.contains("stop onebox-hop")
                    || command.contains("start onebox-net")
                    || command.contains("start onebox-hop")));
            drop(runtime);
            fs::remove_dir_all(root).unwrap();
        }
    }
    #[test]
    fn runner_failures_restore_each_commit_stage_and_recovery_is_repeatable() {
        // Environment-dependent init/PATH discovery is isolated in a child
        // test process, so parallel unit tests never see this mock setup.
        const CHILD: &str = "ONEBOX_WORKFLOW_FAILURE_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let empty = std::env::temp_dir().join(format!(
                "onebox-empty-path-{}",
                util::random_hex(8).unwrap()
            ));
            fs::create_dir(&empty).unwrap();
            let output=std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact","workflow::tests::runner_failures_restore_each_commit_stage_and_recovery_is_repeatable","--nocapture"])
                .env(CHILD,"1").env("ONEBOX_INIT","systemd").env("PATH",&empty).output().unwrap();
            fs::remove_dir(empty).unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        for fault in [
            "prepare-cores",
            "prepare-certificates",
            "check-configurations",
            "stop-old-services",
            "commit-configurations",
            "configure-services",
            "apply-website",
            "apply-network",
            "start-cores",
            "publish-clients",
            "publish-subscription",
            "finalize",
            "final-state",
        ] {
            let (ctx, old, runner, root) = runtime_fixture();
            let mut proposed = old.clone();
            proposed.set("PASSWORD", "new-secret");
            if fault == "prepare-certificates" {
                proposed.set("PROTOCOLS", "trojan");
                proposed.set_port(Protocol::Trojan, 24444);
                proposed.set("TLS_MODE", "self");
            }
            runner.state.lock().unwrap().fault = fault.into();
            let error = apply(&ctx, &proposed).unwrap_err().to_string();
            assert!(
                runner.state.lock().unwrap().fired,
                "fault never reached: {fault}: {error}"
            );
            assert!(error.contains("已恢复原状态"), "{fault}: {error}");
            assert_old_generation(&ctx, &old, &runner);
            recover(&ctx).unwrap();
            fs::remove_dir_all(root).unwrap();
        }
        // Pending subscription settings are part of the same rollback scope,
        // including cases where rendering fails after they were prepared.
        let (ctx, old, runner, root) = runtime_fixture();
        let mut proposed = old.clone();
        proposed.set("SUBSCRIPTION_SETTINGS_PENDING",r#"{"enabled":false,"mode":"site","domain":"","port":443,"method":"cf","custom_cert":null,"custom_key":null,"devices":[]}"#);
        proposed.set("SUBSCRIPTION_SETTINGS_EXPECTED", "absent");
        runner.state.lock().unwrap().fault = "check-configurations".into();
        assert!(apply(&ctx, &proposed)
            .unwrap_err()
            .to_string()
            .contains("已恢复原状态"));
        assert!(!ctx.paths.root.join("subscription/settings.json").exists());
        assert_old_generation(&ctx, &old, &runner);
        fs::remove_dir_all(root).unwrap();
        // Recovery failures must stay visible and retain the original snapshot
        // until a later retry can stop the affected service successfully.
        let (ctx, old, runner, root) = runtime_fixture();
        {
            let mut runtime = runner.state.lock().unwrap();
            runtime.fault = "start-cores".into();
            runtime.block_rollback = true;
        }
        let error = apply(&ctx, &old).unwrap_err().to_string();
        assert!(error.contains("恢复未完成"));
        assert!(transaction::directory(&ctx).exists());
        runner.state.lock().unwrap().block_rollback = false;
        recover(&ctx).unwrap();
        assert_old_generation(&ctx, &old, &runner);
        fs::remove_dir_all(root).unwrap();

        // A persisted crash journal is sufficient; recovery does not depend on
        // in-process rollback state or on a particular last completed stage.
        for phase in [
            "commit-configurations",
            "configure-services",
            "apply-website",
            "apply-network",
            "start-cores",
            "publish-clients",
            "publish-subscription",
            "finalize",
        ] {
            let (ctx, old, runner, root) = runtime_fixture();
            let mut j = transaction::begin(
                &ctx,
                Some(old.clone()),
                vec!["onebox-sing-box".into(), "onebox-site".into()],
                vec!["onebox-sing-box".into(), "onebox-site".into()],
                vec![],
                false,
            )
            .unwrap();
            j.set_phase(&ctx, phase).unwrap();
            fs::write(ctx.paths.core_config(Core::Singbox), b"crashed-generation").unwrap();
            fs::write(ctx.paths.site_root.join("index.html"), b"crashed-site").unwrap();
            runner.state.lock().unwrap().active.clear();
            recover(&ctx).unwrap();
            assert_old_generation(&ctx, &old, &runner);
            fs::remove_dir_all(root).unwrap();
        }
        // Snapshot corruption is detected before any stop/disable/firewall
        // command, leaving the live generation and journal available.
        let (ctx, old, runner, root) = runtime_fixture();
        let j = transaction::begin(&ctx, Some(old), vec![], vec![], vec![], false).unwrap();
        let entry = j
            .snapshot
            .entries
            .iter()
            .find(|e| e.target == ctx.paths.state())
            .unwrap();
        fs::write(
            transaction::directory(&ctx).join("files").join(&entry.slot),
            b"corrupt",
        )
        .unwrap();
        runner.state.lock().unwrap().commands.clear();
        assert!(recover(&ctx).is_err());
        assert!(runner.state.lock().unwrap().commands.is_empty());
        assert!(transaction::directory(&ctx).exists());
        fs::remove_dir_all(root).unwrap();

        // Optimistic concurrency must fail before any service action or
        // journal creation, retaining the separately committed generation.
        let (ctx, old, runner, root) = runtime_fixture();
        let stale = state::load(&ctx).unwrap();
        let mut concurrent = old.clone();
        concurrent.set("PASSWORD", "concurrently-changed");
        state::save(&ctx, &concurrent).unwrap();
        runner.state.lock().unwrap().commands.clear();
        assert!(apply(&ctx, &stale)
            .unwrap_err()
            .to_string()
            .contains("其他操作"));
        assert_eq!(
            state::load(&ctx).unwrap().get("PASSWORD"),
            "concurrently-changed"
        );
        assert!(runner.state.lock().unwrap().commands.is_empty());
        assert!(!transaction::directory(&ctx).exists());
        fs::remove_dir_all(root).unwrap();

        // Core replacements are captured and rolled back by the same journal
        // even when the candidate is incompatible at configuration checking.
        let (ctx, old, runner, root) = runtime_fixture();
        let candidate = root.join("candidate");
        fs::write(&candidate, b"new-core").unwrap();
        runner.state.lock().unwrap().fault = "check-configurations".into();
        let lock = transaction::acquire(&ctx).unwrap();
        assert!(
            apply_with_cores_locked(&ctx, &old, &lock, &[(Core::Singbox, candidate)])
                .unwrap_err()
                .to_string()
                .contains("已恢复原状态")
        );
        assert_old_generation(&ctx, &old, &runner);
        drop(lock);
        fs::remove_dir_all(root).unwrap();

        // Boot network recovery leaves an unchanged generation untouched.
        let (ctx, mut old, runner, root) = runtime_fixture();
        refresh_own_ips(&ctx, &mut old).unwrap();
        state::save(&ctx, &old).unwrap();
        let original = fs::read(ctx.paths.state()).unwrap();
        runner.state.lock().unwrap().commands.clear();
        restore_network(&ctx).unwrap();
        assert_eq!(fs::read(ctx.paths.state()).unwrap(), original);
        assert_eq!(
            fs::read(ctx.paths.core_config(Core::Singbox)).unwrap(),
            b"old-config"
        );
        assert!(!runner
            .state
            .lock()
            .unwrap()
            .commands
            .iter()
            .any(|c| c.starts_with("prepare-cores:")));
        fs::remove_dir_all(root).unwrap();

        // Address changes regenerate the server's denylist before restoring
        // firewall rules, instead of retaining stale public self-addresses.
        let (ctx, _, runner, root) = runtime_fixture();
        restore_network(&ctx).unwrap();
        assert!(state::load(&ctx)
            .unwrap()
            .get("OWN_IP_CIDRS")
            .contains("9.9.9.9/32"));
        let config = fs::read_to_string(ctx.paths.core_config(Core::Singbox)).unwrap();
        assert!(config.contains("9.9.9.9/32"));
        assert!(runner
            .state
            .lock()
            .unwrap()
            .commands
            .iter()
            .any(|c| c.starts_with("prepare-cores:")));
        fs::remove_dir_all(root).unwrap();

        // A failed boot regeneration must not stop/remove the oneshot network
        // unit currently executing the recovery and lose its rollback process.
        let (ctx, old, runner, root) = runtime_fixture();
        network::apply(&ctx, &old).unwrap();
        platform::service(&ctx, "onebox-network", "start").unwrap();
        {
            let mut r = runner.state.lock().unwrap();
            r.commands.clear();
            r.fault = "check-configurations".into();
        }
        assert!(restore_network(&ctx)
            .unwrap_err()
            .to_string()
            .contains("已恢复原状态"));
        assert_old_generation(&ctx, &old, &runner);
        assert!(!runner
            .state
            .lock()
            .unwrap()
            .commands
            .iter()
            .any(|c| c.contains("systemctl stop onebox-network")));
        fs::remove_dir_all(root).unwrap();

        // A successful generation publishes new state and all supported client
        // artifacts, including the interface inventory, then removes journal.
        let (ctx, old, runner, root) = runtime_fixture();
        let mut proposed = old.clone();
        proposed.set("PASSWORD", "new-secret");
        apply(&ctx, &proposed).unwrap();
        let saved = state::load(&ctx).unwrap();
        assert_eq!(saved.get("PASSWORD"), "new-secret");
        assert!(saved.get("OWN_IP_CIDRS").contains("9.9.9.9/32"));
        assert!(ctx.paths.clients().join("sing-box.json").is_file());
        assert!(!ctx.paths.clients().join("old-client").exists());
        assert!(!transaction::directory(&ctx).exists());
        assert!(runner
            .state
            .lock()
            .unwrap()
            .active
            .contains("onebox-sing-box"));
        fs::remove_dir_all(root).unwrap();
    }
}
