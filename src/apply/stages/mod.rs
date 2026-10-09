//! The ordered stages of one apply (ARCH §4 table). Each stage first checks
//! for a cancellation signal, then durably records its phase in the journal
//! (so a crash at any point is rolled back from the journal alone), prints
//! its progress line, and only then acts.
//!
//! | phase | work |
//! |---|---|
//! | prepare-state | install the manager, restore a backup's files, subscription devices |
//! | replace-cores | swap in verified core binaries (`onebox update` only) |
//! | prepare-cores | make sure used cores exist, record versions, refresh own IPs, re-check ports |
//! | prepare-certificates | stop old TCP-80 holders and open TCP 80 when HTTP-01 needs it; subscription, site and proxy certificates |
//! | check-configurations | render + check core configs, `nginx -t` the site and subscription configs (staged) |
//! | stop-old-services | stop cores, subscription nginx, site |
//! | commit-configurations | move core configs into place, remove unused ones |
//! | configure-services | core units (enabled), unused cores removed, subscription units |
//! | apply-website | site nginx up (tested config), or the site removed |
//! | apply-network | firewall `proxy` owner, hops, `onebox-network` unit written + enabled (never started) |
//! | start-cores | start + wait until running |
//! | publish-clients | every client format, atomic directory swap |
//! | publish-subscription | tested web config installed, snapshot published, worker state |
//! | finalize | `acme` owner cleared, running re-check, crontab policy, state.json, `committed` |
//!
//! Changes from v2:
//! - crash leftovers are swept just before the journal snapshot instead of
//!   in prepare-state, so a rollback never restores them;
//! - stages read typed intents instead of magic state keys, and feature
//!   modules never rewrite the configuration behind the engine's back
//!   (only the recorded facts listed on [`Run::cfg`]);
//! - old TCP-80 holders are stopped whenever any HTTP-01 challenge needs the
//!   port, not only for the proxy's standalone method (G21);
//! - nginx configs are tested in check-configurations, before any service
//!   stops (K7);
//! - finalize writes one `renew` crontab line (or none) and retires the v2
//!   and v1 lines in the same edit (G17, G18, G40);
//! - legacy boot hooks are no longer retired here (v1 is unsupported).

mod commit;
mod finalize;
mod prepare;

pub(super) use finalize::precheck as cron_precheck;
pub(super) use prepare::{check_replacements, sweep_leftovers};

use super::features::{Checkpoint, Features};
use super::journal::{Journal, Phase};
use super::request::Intents;
use crate::ctx::Ctx;
use crate::domain::NodeConfig;
use crate::error::{Error, Result};
use crate::host::service::Services;
use crate::render::NodeSpec;
use crate::site::SiteSubscription;
use crate::sys::signal;
use crate::ui::out;
use std::path::PathBuf;

/// Everything the stages share during one apply.
pub(super) struct Run<'a> {
    pub ctx: &'a Ctx,
    pub features: &'a dyn Features,
    pub services: Services<'a>,
    pub journal: Journal,
    /// The configuration being applied; prepare stages record installed
    /// core versions, own addresses, certificate trust and content backups.
    pub cfg: NodeConfig,
    /// The running generation's configuration (`None` for a first install).
    pub old: Option<NodeConfig>,
    pub intents: Intents,
    /// Resolved view of `cfg` for rendering (from check-configurations on).
    pub spec: Option<NodeSpec>,
    /// The site's subscription location (from check-configurations on).
    pub site_sub: Option<SiteSubscription>,
    /// The standalone subscription nginx config that passed `nginx -t`.
    pub web_conf: Option<PathBuf>,
    done: usize,
    total: usize,
}

impl<'a> Run<'a> {
    pub fn new(
        ctx: &'a Ctx,
        features: &'a dyn Features,
        services: Services<'a>,
        journal: Journal,
        cfg: NodeConfig,
        old: Option<NodeConfig>,
        intents: Intents,
    ) -> Run<'a> {
        let total = phases(&intents).len();
        Run {
            ctx,
            features,
            services,
            journal,
            cfg,
            old,
            intents,
            spec: None,
            site_sub: None,
            web_conf: None,
            done: 0,
            total,
        }
    }

    /// The rendering view; set by check-configurations.
    pub fn spec(&self) -> Result<&NodeSpec> {
        self.spec
            .as_ref()
            .ok_or_else(|| Error::msg("内部错误：配置尚未校验"))
    }

    /// Cancellation check, durable phase, progress line.
    fn enter(&mut self, phase: &Phase) -> Result<()> {
        signal::check()?;
        self.journal.set_phase(&self.ctx.paths, phase.clone())?;
        self.done += 1;
        out::step(self.done, self.total, phase.label());
        Ok(())
    }
}

/// The stages to run, in order.
pub(super) fn phases(intents: &Intents) -> Vec<Phase> {
    Phase::STAGES
        .into_iter()
        .filter(|p| *p != Phase::ReplaceCores || !intents.replace_cores.is_empty())
        .collect()
}

/// Run every stage; the first error stops the apply (the caller rolls
/// back unless the journal already says `committed`).
pub(super) fn run_all(run: &mut Run) -> Result<()> {
    for phase in phases(&run.intents) {
        run.enter(&phase)?;
        execute(run, &phase)?;
        run.features.checkpoint(&Checkpoint::Stage(phase))?;
    }
    Ok(())
}

fn execute(run: &mut Run, phase: &Phase) -> Result<()> {
    match phase {
        Phase::PrepareState => prepare::prepare_state(run),
        Phase::ReplaceCores => prepare::replace_cores(run),
        Phase::PrepareCores => prepare::prepare_cores(run),
        Phase::PrepareCertificates => prepare::prepare_certificates(run),
        Phase::CheckConfigurations => commit::check_configurations(run),
        Phase::StopOldServices => commit::stop_old_services(run),
        Phase::CommitConfigurations => commit::commit_configurations(run),
        Phase::ConfigureServices => commit::configure_services(run),
        Phase::ApplyWebsite => commit::apply_website(run),
        Phase::ApplyNetwork => commit::apply_network(run),
        Phase::StartCores => commit::start_cores(run),
        Phase::PublishClients => finalize::publish_clients(run),
        Phase::PublishSubscription => finalize::publish_subscription(run),
        Phase::Finalize => finalize::finalize(run),
        other => Err(Error::msg(format!("内部错误：{} 不是应用阶段", other.id()))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::protocol::Core;
    use std::path::PathBuf;

    #[test]
    fn replace_cores_runs_only_with_replacements() {
        let mut intents = Intents::default();
        let plain = phases(&intents);
        assert_eq!(plain.len(), 13);
        assert!(!plain.contains(&Phase::ReplaceCores));
        assert_eq!(plain.first(), Some(&Phase::PrepareState));
        assert_eq!(plain.last(), Some(&Phase::Finalize));
        intents
            .replace_cores
            .push((Core::Xray, PathBuf::from("/tmp/xray")));
        let all = phases(&intents);
        assert_eq!(all, Phase::STAGES.to_vec());
        assert_eq!(all[1], Phase::ReplaceCores);
    }
}
