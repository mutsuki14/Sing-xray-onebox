//! `subscription` / `subscribe` / `sub`: command specs and handlers (the
//! CLI registry lists [`SUBSCRIPTION`]).
//!
//! Subcommands (bare = `info`): `enable`, `disable`, `info|status|list`,
//! `add NAME`, `revoke|remove ID`, `reset ID`, `publish|refresh`,
//! `renew [--cron]`, hidden `serve`. Only `info` runs without root; when
//! the root-only devices or configuration cannot be read it says that
//! root is needed ([`NEEDS_ROOT`]) instead of showing an I/O error.
//!
//! Locking and credentials (G8): `enable` plans and resolves Cloudflare
//! credentials (prompting only on a terminal) before it takes the node
//! lock, so an unanswered prompt never blocks other node commands or a
//! scheduled renewal; it then takes the lock, recovers a leftover journal
//! and applies with that lock — the request's state hash makes the apply
//! refuse (`配置已被其他操作修改…`) if `state.json` changed meanwhile — and
//! creates the first device under the same lock (G31). `publish` resolves
//! credentials the same way before the engine takes the lock. `disable`
//! records the endpoint the devices' URLs carry in `devices.json`, so a
//! later `enable` with the same endpoint says the URLs still work. Device changes take the lock,
//! load the configuration before changing anything (a reset never replaces
//! a token it then cannot print, G-8.1#1), refuse a pending journal, and
//! restart a running worker that is not the installed program (a v2
//! worker reads only `settings.json`; G23). `renew --cron` waits up to 10
//! minutes for the lock.
//!
//! Output: URLs, tokens, device lists and results on stdout; the
//! plaintext warning on stderr.
//!
//! Changes from v2: see [`super::request`] (option rules) and
//! [`super::endpoint`] (URL block); `disable` of a disabled subscription
//! applies nothing; `publish` is a transaction with the stored
//! configuration as before; `renew` never runs an apply.

use super::devices::{self, DeviceStore, NewDevice};
use super::endpoint::{self, SubscriptionInfo, DISABLED, REVOKED};
use super::request::{EnableRequest, Mode};
use super::{lifecycle, renew, server, snapshot};
use crate::apply::{self, ApplyRequest};
use crate::cert::{self, cloudflare, CertScopes, CfCredentials, Engine};
use crate::cli::args::{ArgSpec, CommandSpec, Group, Matches, OptSpec, Root};
use crate::ctx::Ctx;
use crate::domain::plan::{self, PlanEnv};
use crate::domain::ports::FnProbe;
use crate::domain::protocol::Transport;
use crate::domain::NodeConfig;
use crate::error::{Error, Result};
use crate::state::StateStore;
use crate::sys::lock::{FileLock, BUSY_MESSAGE};
use crate::ui::out;
use std::time::Duration;

const ADD_USAGE: &str = "用法: subscription add 设备名称";
const REVOKE_USAGE: &str = "用法: subscription revoke 设备ID";
const RESET_USAGE: &str = "用法: subscription reset 设备ID";
const NO_SNAPSHOT: &str = "订阅快照尚未发布，链接暂时无法访问；请执行 onebox subscription publish";
/// `subscription info` as a user who cannot read the root-only files.
pub const NEEDS_ROOT: &str = "查看订阅需要 root 权限：订阅设备与节点配置仅 root 可读";
/// A device change saved while a worker of another program keeps running.
pub const STALE_WORKER: &str = "订阅服务仍在运行旧版程序，且未能重启";
const WORKER_RESTARTED: &str = "订阅服务运行的是旧版程序，已重启以应用设备变更";
/// `renew --cron` waits this long for the node lock.
const CRON_LOCK_WAIT: Duration = Duration::from_secs(600);
const CRON_LOCK_POLL: Duration = Duration::from_secs(5);

const ENABLE: CommandSpec = CommandSpec::new("enable", Group::Feature, "启用或重新配置远程订阅")
    .usage(&[
        "subscription enable [--mode ip|site|standalone] [选项]",
        "subscription enable --mode ip --address IP [--port 8448]（HTTP，无需域名）",
        "subscription enable --mode site",
        "subscription enable --mode standalone --domain 域名 [--port 8448] [--tls cf|http|custom [--cert 证书 --key 私钥]]",
    ])
    .options(&[
        OptSpec::value("mode", "模式", "ip（HTTP 直连）| site（复用自有网站）| standalone（独立域名 HTTPS）；已启用时省略则保持当前模式，其他省略的选项沿用当前值"),
        OptSpec::value("address", "IP", "ip 模式的订阅地址（IPv4 或 IPv6，不加方括号；默认节点 IP）"),
        OptSpec::value("ip", "IP", "同 --address"),
        OptSpec::value("domain", "域名", "standalone 模式的订阅域名（需已解析到本机）"),
        OptSpec::value("port", "端口", "ip / standalone 模式的端口（默认 8448，已启用时沿用当前端口）"),
        OptSpec::value("tls", "方式", "standalone 证书：cf（默认）| http | custom"),
        OptSpec::value("cert", "路径", "--tls custom 的完整证书链"),
        OptSpec::value("key", "路径", "--tls custom 的私钥"),
        OptSpec::value("name", "名称", "首个设备的名称（默认 default）"),
    ])
    .handler(enable_command);

const DISABLE: CommandSpec =
    CommandSpec::new("disable", Group::Feature, "关闭远程订阅（设备保留）")
        .handler(disable_command);

const INFO: CommandSpec = CommandSpec::new("info", Group::Feature, "查看订阅入口与设备")
    .aliases(&["status", "list"])
    .root(Root::NotRequired)
    .handler(info_command);

const ADD: CommandSpec = CommandSpec::new("add", Group::Feature, "新建设备并显示其订阅链接")
    .args(&[ArgSpec::optional("设备名称", "1–80 字节，不能重复")])
    .handler(add_command);

const REVOKE: CommandSpec = CommandSpec::new("revoke", Group::Feature, "撤销设备（立即生效）")
    .aliases(&["remove"])
    .args(&[ArgSpec::optional("设备ID", "见 subscription info")])
    .handler(revoke_command);

const RESET: CommandSpec =
    CommandSpec::new("reset", Group::Feature, "更换设备令牌（旧链接立即失效）")
        .args(&[ArgSpec::optional("设备ID", "见 subscription info")])
        .handler(reset_command);

const PUBLISH: CommandSpec =
    CommandSpec::new("publish", Group::Feature, "立即重新生成并发布订阅内容")
        .aliases(&["refresh"])
        .handler(publish_command);

const RENEW: CommandSpec = CommandSpec::new(
    "renew",
    Group::Feature,
    "续期 HTTPS 订阅证书（site 模式即网站证书；ip 模式无需）",
)
.options(&[OptSpec::flag(
    "cron",
    "计划任务模式：仅在到期时续期，无事可做时不输出",
)])
.handler(renew_command);

const SERVE: CommandSpec =
    CommandSpec::new("serve", Group::Hidden, "订阅服务进程（由服务管理器启动）")
        .hidden()
        .handler(serve_command);

/// The `subscription` command tree.
pub const SUBSCRIPTION: CommandSpec = CommandSpec::new(
    "subscription",
    Group::Feature,
    "远程订阅：按设备授权的客户端配置 URL",
)
.aliases(&["subscribe", "sub"])
.usage(&[
    "subscription [info]",
    "subscription enable|info|add 名称|revoke ID|reset ID|disable",
    "subscription enable --mode ip --address IP [--port 8448]（HTTP，无需域名）",
    "subscription publish | renew [--cron]",
])
.subcommands(&[
    ENABLE, DISABLE, INFO, ADD, REVOKE, RESET, PUBLISH, RENEW, SERVE,
])
.root(Root::NotRequired)
.handler(info_command);

fn info_command(ctx: &Ctx, _m: &Matches) -> Result<()> {
    print_info(ctx)
}

fn enable_command(ctx: &Ctx, m: &Matches) -> Result<()> {
    enable(ctx, &EnableRequest::from_matches(m)?)
}

fn disable_command(ctx: &Ctx, _m: &Matches) -> Result<()> {
    disable(ctx)
}

fn add_command(ctx: &Ctx, m: &Matches) -> Result<()> {
    add_device(ctx, m.positional(0).ok_or(ADD_USAGE)?)
}

fn revoke_command(ctx: &Ctx, m: &Matches) -> Result<()> {
    revoke_device(ctx, m.positional(0).ok_or(REVOKE_USAGE)?)
}

fn reset_command(ctx: &Ctx, m: &Matches) -> Result<()> {
    reset_device(ctx, m.positional(0).ok_or(RESET_USAGE)?)
}

fn publish_command(ctx: &Ctx, _m: &Matches) -> Result<()> {
    publish_now(ctx)
}

fn renew_command(ctx: &Ctx, m: &Matches) -> Result<()> {
    renew_now(ctx, m.flag("cron"))
}

fn serve_command(ctx: &Ctx, _m: &Matches) -> Result<()> {
    server::serve(ctx)
}

/// `subscription info` (also for a node without subscription or state).
pub fn print_info(ctx: &Ctx) -> Result<()> {
    let devices = readable(devices::list(&ctx.paths))?;
    let info = match readable(StateStore::load(ctx))? {
        Some(loaded) => SubscriptionInfo::of(&loaded.config, devices),
        None => SubscriptionInfo {
            mode: None,
            endpoint: None,
            devices,
            formats: Vec::new(),
            plaintext: false,
        },
    };
    let lines = info.lines();
    if info.plaintext {
        out::warn(endpoint::PLAINTEXT_WARNING);
    }
    print(&lines)
}

/// `subscription info` for a loaded configuration.
pub fn info(ctx: &Ctx, cfg: &NodeConfig) -> Result<SubscriptionInfo> {
    Ok(SubscriptionInfo::of(
        cfg,
        readable(devices::list(&ctx.paths))?,
    ))
}

/// A permission error on the root-only subscription files means "run as
/// root" (`subscription info` itself needs no root; v2 failed with a raw
/// I/O error, G-8.1#16).
fn readable<T>(result: Result<T>) -> Result<T> {
    result.map_err(|e| {
        if permission_denied(&e) {
            Error::msg(NEEDS_ROOT)
        } else {
            e
        }
    })
}

fn permission_denied(e: &Error) -> bool {
    match e {
        Error::Io { source, .. } => source.kind() == std::io::ErrorKind::PermissionDenied,
        Error::Context { source, .. } => permission_denied(source),
        _ => false,
    }
}

/// The node lock, without waiting.
pub fn node_lock(ctx: &Ctx) -> Result<FileLock> {
    FileLock::acquire(&ctx.paths.lock(), BUSY_MESSAGE)
}

/// `subscription enable` (module docs): plan and resolve credentials
/// without the lock, then apply and create the first device with it.
pub fn enable(ctx: &Ctx, request: &EnableRequest) -> Result<()> {
    let name = request.name.as_deref().unwrap_or("default");
    ensure!(devices::valid_name(name.trim()), "{}", devices::BAD_NAME);
    let loaded = StateStore::load_required(ctx)?;
    let next = plan_request(ctx, &loaded.config, request)?;
    let cloudflare = cloudflare_for(ctx, &next)?;
    let lock = node_lock(ctx)?;
    // A journal left behind is finished first; if that (or anything
    // else) changed state.json since it was loaded, the apply refuses.
    apply::recover_locked(ctx, &lock)?;
    let old_endpoint = published_endpoint(ctx, &loaded.config);
    let mut req = ApplyRequest::from_loaded(&loaded, next.clone(), "启用订阅");
    req.intents.cloudflare = cloudflare;
    apply::apply_locked(ctx, &lock, req)?;
    after_enable(ctx, &lock, old_endpoint.as_deref(), &next, name)
}

/// The endpoint existing device URLs carry: the enabled one, else the one
/// recorded when the subscription was disabled (`None` when unknown, which
/// the enable reports as a changed entry).
fn published_endpoint(ctx: &Ctx, cfg: &NodeConfig) -> Option<String> {
    endpoint::endpoint(cfg).or_else(|| {
        DeviceStore::load(&ctx.paths)
            .ok()
            .and_then(|store| store.endpoint().map(str::to_owned))
    })
}

/// The configuration an enable request asks for (options checked, ignored
/// site-mode options named, live facts consulted).
pub fn plan_request(ctx: &Ctx, cfg: &NodeConfig, request: &EnableRequest) -> Result<NodeConfig> {
    let (choice, port) = request.choice(cfg)?;
    if request.mode(cfg)? == Mode::Site {
        let ignored = request.ignored_in_site_mode();
        if !ignored.is_empty() {
            out::info(format!(
                "site 模式复用网站的域名、证书和端口，已忽略 {}",
                ignored.join(" ")
            ));
        }
    }
    plan_enable(ctx, cfg, &choice, port)
}

/// After the enable committed `cfg` (still under `lock`): the first device
/// when there is none, else whether existing URLs changed (G31).
pub fn after_enable(
    ctx: &Ctx,
    lock: &FileLock,
    old_endpoint: Option<&str>,
    cfg: &NodeConfig,
    name: &str,
) -> Result<()> {
    if DeviceStore::load(&ctx.paths)?.is_empty() {
        let device = devices::add(ctx, lock, cfg, name)?;
        return print_device(ctx, cfg, &device, true);
    }
    print(&[endpoint::enabled_message(old_endpoint, cfg)])?;
    print_warnings(cfg);
    Ok(())
}

/// Plan the enable with the live facts (IPv6, sockets, FRP reservations).
fn plan_enable(
    ctx: &Ctx,
    cfg: &NodeConfig,
    choice: &plan::SubscriptionChoice,
    port: Option<u16>,
) -> Result<NodeConfig> {
    let system_root = ctx.paths.system_root.clone();
    let probe = FnProbe(move |port, transport: Transport| {
        crate::sys::net::listening(&system_root, port, transport == Transport::Tcp)
    });
    let frp = crate::frp::model::reservations(&ctx.paths)?;
    let env = PlanEnv {
        ipv6: crate::sys::net::ipv6_available(&ctx.paths.system_root),
        probe: &probe,
        frp: &frp,
        previous: Some(cfg),
        now: crate::sys::time::now(),
    };
    plan::enable_subscription(cfg, choice, port, &env)
}

/// Cloudflare credentials an apply of `cfg` needs and lacks (stored and
/// environment ones are used as they are), prompted for on a terminal
/// before the node lock is taken — the rule of every apply caller (G8).
pub fn cloudflare_for(ctx: &Ctx, cfg: &NodeConfig) -> Result<Option<CfCredentials>> {
    cloudflare::resolve_for_apply(ctx, ctx.ui.as_ref(), cfg, CertScopes::NONE)
}

/// `subscription disable`: planned and credentials resolved without the
/// lock, like `enable` (the apply refuses if state.json changed since).
pub fn disable(ctx: &Ctx) -> Result<()> {
    disable_with(ctx, &apply::apply_locked)
}

/// [`disable`] with the apply under the lock injected.
fn disable_with(
    ctx: &Ctx,
    apply_locked: &dyn Fn(&Ctx, &FileLock, ApplyRequest) -> Result<()>,
) -> Result<()> {
    let loaded = StateStore::load_required(ctx)?;
    if loaded.config.subscription.is_none() {
        // Still finish a journal left behind, as every command does.
        let lock = node_lock(ctx)?;
        apply::recover_locked(ctx, &lock)?;
        return print(&[DISABLED.to_owned()]);
    }
    let next = plan::disable_subscription(&loaded.config)?;
    let mut req = ApplyRequest::from_loaded(&loaded, next, "关闭订阅");
    req.intents.cloudflare = cloudflare_for(ctx, &req.config)?;
    let lock = node_lock(ctx)?;
    apply::recover_locked(ctx, &lock)?;
    apply_locked(ctx, &lock, req)?;
    if let Some(old) = endpoint::endpoint(&loaded.config) {
        // Best effort: without it the next enable only reports the entry
        // as changed (the subscription is disabled either way).
        let _ = devices::record_endpoint(ctx, &lock, &old);
    }
    print(&[DISABLED.to_owned()])
}

/// `subscription add NAME`.
pub fn add_device(ctx: &Ctx, name: &str) -> Result<()> {
    let lock = node_lock(ctx)?;
    let cfg = StateStore::load_required(ctx)?.config;
    let device = devices::add(ctx, &lock, &cfg, name)?;
    let refreshed = refresh_worker(ctx);
    print_device(ctx, &cfg, &device, true)?;
    refreshed.map_err(|e| stale_after_new_token(e, "新链接可能无法访问"))
}

/// `subscription revoke ID`.
pub fn revoke_device(ctx: &Ctx, id: &str) -> Result<()> {
    let lock = node_lock(ctx)?;
    devices::revoke(ctx, &lock, id)?;
    refresh_worker(ctx).map_err(|e| {
        Error::msg(format!(
            "设备已从列表移除，但{STALE_WORKER}: {e}；执行 onebox regen 之前旧链接可能仍可访问"
        ))
    })?;
    print(&[REVOKED.to_owned()])
}

/// `subscription reset ID`. The configuration (needed for the URLs) is
/// loaded before the old token is replaced: if it cannot be loaded,
/// nothing changes (G-8.1#1).
pub fn reset_device(ctx: &Ctx, id: &str) -> Result<()> {
    let lock = node_lock(ctx)?;
    let cfg = StateStore::load_required(ctx)?.config;
    let device = devices::reset(ctx, &lock, id)?;
    let refreshed = refresh_worker(ctx);
    print_device(ctx, &cfg, &device, false)?;
    refreshed.map_err(|e| stale_after_new_token(e, "新链接可能无法访问，旧链接可能仍然有效"))
}

/// After a device change (node lock held): restart a running worker that
/// is not the installed program, so the change takes effect now.
fn refresh_worker(ctx: &Ctx) -> Result<()> {
    if lifecycle::refresh_stale_worker(&Engine::system(ctx))? {
        out::info(WORKER_RESTARTED);
    }
    Ok(())
}

/// The token was printed already; say why its URLs may not work yet.
fn stale_after_new_token(e: Error, effect: &str) -> Error {
    Error::msg(format!(
        "{STALE_WORKER}: {e}；执行 onebox regen 之前{effect}"
    ))
}

/// `subscription publish`: a transaction with the stored configuration.
pub fn publish_now(ctx: &Ctx) -> Result<()> {
    apply::apply(ctx, publish_request(ctx)?)
}

/// The apply `subscription publish` runs, with Cloudflare credentials
/// resolved (prompted for on a terminal) before the engine takes the node
/// lock (G8).
pub fn publish_request(ctx: &Ctx) -> Result<ApplyRequest> {
    let loaded = StateStore::load_required(ctx)?;
    let mut req = ApplyRequest::from_loaded(&loaded, loaded.config.clone(), "发布订阅");
    req.intents.cloudflare = cloudflare_for(ctx, &loaded.config)?;
    Ok(req)
}

/// `subscription renew [--cron]` (see [`super::renew`]).
pub fn renew_now(ctx: &Ctx, scheduled: bool) -> Result<()> {
    let Some(loaded) = StateStore::load(ctx)? else {
        return Ok(());
    };
    let cf = renew_credentials(ctx, &loaded.config, scheduled)?;
    let lock = if scheduled {
        FileLock::acquire_waiting(
            &ctx.paths.lock(),
            BUSY_MESSAGE,
            CRON_LOCK_WAIT,
            CRON_LOCK_POLL,
        )?
    } else {
        node_lock(ctx)?
    };
    apply::recover_locked(ctx, &lock)?;
    let cfg = StateStore::load_required(ctx)?.config;
    renew::renew(ctx, &lock, &cfg, scheduled, cf.as_ref())
}

/// Credentials a manual renewal needs and lacks (prompted on a terminal);
/// scheduled renewals use what is stored.
fn renew_credentials(
    ctx: &Ctx,
    cfg: &NodeConfig,
    scheduled: bool,
) -> Result<Option<CfCredentials>> {
    if scheduled {
        return Ok(None);
    }
    let needed = cert::credentials_needed(ctx, cfg, &renew::options(false));
    cloudflare::resolve_needed(ctx.ui.as_ref(), &needed)
}

/// Print a created or reset device (stdout) and the warnings (stderr).
fn print_device(ctx: &Ctx, cfg: &NodeConfig, device: &NewDevice, with_id: bool) -> Result<()> {
    print(&endpoint::url_block(cfg, device, with_id))?;
    print_warnings(cfg);
    if cfg.subscription.is_some() && !matches!(snapshot::load(&ctx.paths), Ok(Some(_))) {
        out::warn(NO_SNAPSHOT);
    }
    Ok(())
}

fn print_warnings(cfg: &NodeConfig) {
    for warning in endpoint::warnings(cfg) {
        out::warn(warning);
    }
}

fn print(lines: &[String]) -> Result<()> {
    out::data(&lines.join("\n"))
}

#[cfg(test)]
mod tests;
