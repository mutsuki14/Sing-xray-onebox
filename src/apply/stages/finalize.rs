//! publish-clients, publish-subscription and finalize (the commit point).

use super::Run;
use crate::apply::features::Checkpoint;
use crate::apply::journal::Phase;
use crate::apply::network;
use crate::cert::{self, RenewNeed};
use crate::ctx::Ctx;
use crate::domain::defaults::NODE_RENEW_CRON;
use crate::domain::NodeConfig;
use crate::error::Result;
use crate::host::cron::{self, Crontab, Scope, Tag};
use crate::host::init::InitSystem;
use crate::host::service::prepare_dir;
use crate::render;
use crate::state::StateStore;
use crate::sys::signal;
use crate::ui::out;

/// No crontab while a custom certificate would like scheduled redeploys.
pub const NO_CRON_CUSTOM: &str =
    "未找到 crontab：外部证书不会自动重新部署，更新证书文件后请执行 onebox renew";

pub fn publish_clients(run: &mut Run) -> Result<()> {
    let published = render::write_clients(&run.ctx.paths, run.spec()?)?;
    for warning in published.warnings {
        out::warn(warning);
    }
    Ok(())
}

/// The tested standalone web config first, then the snapshot and worker.
pub fn publish_subscription(run: &mut Run) -> Result<()> {
    if let Some(staged) = run.web_conf.clone() {
        run.features.install_web_conf(run.ctx, &staged)?;
    }
    run.features
        .publish_subscription(run.ctx, &run.cfg, run.spec()?)
}

/// finalize: the temporary `acme` owner is cleared, the cores must still
/// run (a crashing core must not be blessed by its first successful
/// check), the crontab gets its policy, then `state.json` is written and
/// the journal says `committed` — the commit point (spec B §6.5).
pub fn finalize(run: &mut Run) -> Result<()> {
    let ctx = run.ctx;
    network::clear_acme(ctx)?;
    for core in run.cfg.cores() {
        ensure!(
            run.services.running(core.service()),
            "{} 在提交前退出",
            core.service()
        );
    }
    signal::check()?;
    apply_cron(ctx, &run.cfg, run.services.init())?;
    StateStore::save(ctx, &run.cfg)?;
    run.features.checkpoint(&Checkpoint::Saved)?;
    run.journal.set_phase(&ctx.paths, Phase::Committed)
}

/// The node's crontab policy, in one edit (G17, G18, G40): the single
/// `renew` line iff an ACME or custom certificate exists (replacing v2's
/// three `onebox-native-cert-*` lines), the v1 boot line removed, and
/// under systemd/OpenRC no per-service `@reboot` lines (units are enabled
/// instead; without init `Services::enable` maintains them).
pub fn apply_cron(ctx: &Ctx, cfg: &NodeConfig, init: InitSystem) -> Result<()> {
    let need = cert::renew_needed(cfg);
    if !cron::available(ctx) {
        // ACME was refused before the transaction began; see `precheck`.
        if need == RenewNeed::Recommended {
            out::warn(NO_CRON_CUSTOM);
        }
        return Ok(());
    }
    let renew = match need {
        RenewNeed::None => None,
        RenewNeed::Recommended | RenewNeed::Required => Some(renew_line(ctx, init)?),
    };
    Crontab::edit(ctx, |tab| {
        match &renew {
            Some(line) => tab.replace(&Tag::renew(), std::slice::from_ref(line)).map(drop)?,
            None => drop(tab.remove(&Tag::renew())),
        }
        tab.remove(&Tag::legacy_boot());
        if init != InitSystem::None {
            for tag in node_boot_tags(tab) {
                tab.remove(&tag);
            }
        }
        Ok(())
    })
}

/// `17 4 * * * … 'EXE' renew --cron >>'LOG/renew.log' 2>&1 # onebox:renew`.
fn renew_line(ctx: &Ctx, init: InitSystem) -> Result<String> {
    let paths = &ctx.paths;
    prepare_dir(&paths.log)?;
    cron::line(
        NODE_RENEW_CRON,
        paths,
        init,
        &["renew", "--cron"],
        &paths.log.join("renew.log"),
        &Tag::renew(),
    )
}

/// The `boot:onebox-*` tags of node services present in `tab`.
fn node_boot_tags(tab: &Crontab) -> Vec<Tag> {
    let mut tags: Vec<Tag> = tab
        .owned()
        .map(|(tag, _)| tag.clone())
        .filter(|tag| tag.as_str().starts_with("boot:") && Scope::Node.covers(tag))
        .collect();
    tags.sort();
    tags.dedup();
    tags
}

/// Before the transaction (G17): an ACME certificate needs a working cron
/// (installing `crontab` and starting the daemon when possible); a custom
/// one only warns.
pub fn precheck(ctx: &Ctx, cfg: &NodeConfig, init: InitSystem) -> Result<()> {
    match cert::renew_needed(cfg) {
        RenewNeed::None => Ok(()),
        RenewNeed::Required => cron::ensure_scheduler(ctx, init),
        RenewNeed::Recommended => {
            if let Err(e) = cron::ensure_scheduler(ctx, init) {
                out::warn(format!("{e}；外部证书不会自动重新部署"));
            }
            Ok(())
        }
    }
}
