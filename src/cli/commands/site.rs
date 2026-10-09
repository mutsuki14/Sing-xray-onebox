//! `site …`: the own-domain REALITY website (spec F §2.1).
//!
//! Every change that alters the homepage (template, theme, title,
//! description) asks the transaction to publish the rendered page
//! (`Intents.site_content = Template`); `import` and `restore` publish a
//! directory or a content backup; the replaced content is always backed up
//! by the site module. `title`, `theme` and `description` edit the
//! generated page and are refused once the content was imported or edited
//! by hand; `template` replaces the page deliberately.
//!
//! Changes from v2: `site template --title X` no longer reads `--title` as
//! the template name; `theme` and `description` are commands of their own;
//! `restore` checks the backup exists before anything runs, and `latest`
//! is the newest by creation time (v2: by name); `https` without a site is
//! refused; `site renew` renews without a full apply (G9); `preview` does
//! not need an enabled site (it renders the default title and description
//! then, as v2 did); page edits without a site say `请先启用网站`.

use crate::cert::{CertScope, CertScopes};
use crate::cli::args::{ArgSpec, CommandSpec, Group, Matches, OptSpec, Root};
use crate::cli::commands::cert::renew;
use crate::cli::options as opt;
use crate::cli::session::{request, with_system, LiveProbe, Session};
use crate::ctx::Ctx;
use crate::domain::config::{NodeConfig, SiteTemplate, SiteTheme, WebCert};
use crate::domain::{defaults, plan};
use crate::error::{Error, Result};
use crate::site::{ContentStore, SiteContent};
use std::path::Path;

pub const PUBLISHED: &str = "网站已发布，原内容保存在网站备份目录";
const RESTORED: &str = "网站已恢复";
const EDITED: &str = "网站已被手动修改或导入，请编辑原网页后重新导入";
const ENABLE_USAGE: &str = "用法: site enable 域名 [--tls http|cf|custom --cert 文件 --key 文件]";

const TITLE: OptSpec = OptSpec::value("title", "标题", "主页标题");
const DESCRIPTION: OptSpec = OptSpec::value("description", "文字", "主页描述");
const THEME: OptSpec = OptSpec::value("theme", "forest|ocean|slate", "配色主题");

const fn sub(name: &'static str, summary: &'static str) -> CommandSpec {
    CommandSpec::new(name, Group::Feature, summary).handler(site_command)
}

pub const SITE: CommandSpec = CommandSpec::new("site", Group::Feature, "自有域名 REALITY 网站")
    .usage(&[
        "site [info]",
        "site enable 域名 [--tls http|cf|custom --cert 文件 --key 文件]",
        "site disable | https on|off | renew",
        "site template [minimal|profile|docs] [--title 标题] [--description 文字] [--theme 主题]",
        "site theme forest|ocean|slate | title 标题 | description 文字",
        "site import 目录 | restore [ID|latest] | preview [模板]",
    ])
    .subcommands(&[
        sub("info", "查看网站状态")
            .aliases(&["status"])
            .root(Root::NotRequired),
        sub("enable", "启用网站作为 REALITY 目标")
            .args(&[ArgSpec::optional("域名", "已解析到本机的域名")])
            .options(&[opt::WEB_TLS, opt::CERT, opt::KEY]),
        sub("disable", "关闭网站（REALITY 改回默认目标）"),
        sub("https", "开启或关闭 HTTPS 443 入口").args(&[ArgSpec::optional("开关", "on / off")]),
        sub("template", "更换主页模板并重新发布")
            .args(&[ArgSpec::optional("模板", "minimal（默认）/ profile / docs")])
            .options(&[TITLE, DESCRIPTION, THEME]),
        sub("theme", "更换主页配色").args(&[ArgSpec::optional("主题", "forest / ocean / slate")]),
        sub("title", "修改主页标题").args(&[ArgSpec::optional("标题", "新标题")]),
        sub("description", "修改主页描述").args(&[ArgSpec::optional("描述", "新描述")]),
        sub("import", "导入本地网站目录（需含 index.html）")
            .args(&[ArgSpec::optional("目录", "本地网站目录")]),
        sub("restore", "恢复网站内容备份")
            .args(&[ArgSpec::optional("备份", "备份 ID 或 latest（默认）")]),
        sub("preview", "预览主页（写入 preview.html，不发布）")
            .args(&[ArgSpec::optional("模板", "minimal（默认）/ profile / docs")])
            .options(&[TITLE, DESCRIPTION, THEME]),
        sub("renew", "续期网站证书"),
    ])
    .root(Root::NotRequired)
    .handler(site_command);

/// One `site` operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SiteAction {
    Info,
    Enable { domain: String, cert: WebCert },
    Disable,
    Https(bool),
    Template(PageEdit),
    Theme(SiteTheme),
    Title(String),
    Description(String),
    Import(String),
    Restore(String),
    Preview(PageEdit),
    Renew,
}

/// A homepage rendering request (`template`, `preview`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PageEdit {
    pub template: Option<SiteTemplate>,
    pub title: Option<String>,
    pub description: Option<String>,
    pub theme: Option<SiteTheme>,
}

/// Parse a `site …` command line (v2 usage messages).
pub fn parse(m: &Matches) -> Result<SiteAction> {
    let arg = |usage: &str| -> Result<String> {
        m.positional(0)
            .map(str::to_owned)
            .ok_or_else(|| Error::msg(usage.to_owned()))
    };
    Ok(match m.path.get(1).copied() {
        None | Some("info") => SiteAction::Info,
        Some("enable") => SiteAction::Enable {
            domain: arg(ENABLE_USAGE)?,
            cert: opt::web_cert(m)?,
        },
        Some("disable") => SiteAction::Disable,
        Some("https") => SiteAction::Https(
            opt::on_off(&arg("用法: site https on|off")?, "site https")
                .map_err(|_| Error::msg("用法: site https on|off"))?,
        ),
        Some("template") => SiteAction::Template(page_edit(m)?),
        Some("preview") => SiteAction::Preview(page_edit(m)?),
        Some("theme") => SiteAction::Theme(arg("用法: site theme forest|ocean|slate")?.parse()?),
        Some("title") => SiteAction::Title(arg("用法: site title 标题")?),
        Some("description") => SiteAction::Description(arg("用法: site description 描述")?),
        Some("import") => SiteAction::Import(arg("用法: site import 目录")?),
        Some("restore") => SiteAction::Restore(m.positional(0).unwrap_or("latest").to_owned()),
        Some("renew") => SiteAction::Renew,
        Some(other) => bail!("未知网站操作: {other}"),
    })
}

fn page_edit(m: &Matches) -> Result<PageEdit> {
    Ok(PageEdit {
        template: m.positional(0).map(str::parse).transpose()?,
        title: m.value("title").map(str::to_owned),
        description: m.value("description").map(str::to_owned),
        theme: m.value("theme").map(str::parse).transpose()?,
    })
}

fn site_command(ctx: &Ctx, m: &Matches) -> Result<()> {
    let action = parse(m)?;
    with_system(ctx, |s| run(s, action))
}

/// Run one `site` operation.
pub fn run(session: &Session, action: SiteAction) -> Result<()> {
    match action {
        SiteAction::Info => info(session),
        SiteAction::Renew => renew(session, CertScopes::only(CertScope::Site), false),
        SiteAction::Preview(edit) => preview(session, &edit),
        change => {
            session.require_root()?;
            let Some((req, message)) = plan_change(session, change)? else {
                return Ok(());
            };
            session.apply(req)?;
            match message {
                Some(message) => session.data(message),
                None => Ok(()),
            }
        }
    }
}

/// `site info`.
pub fn info(session: &Session) -> Result<()> {
    let loaded = session.load()?;
    let info = crate::site::info(session.ctx, &loaded.config)?;
    session.data(&info.lines().join("\n"))
}

/// A planned site change.
struct Change {
    next: NodeConfig,
    reason: &'static str,
    content: Option<SiteContent>,
    message: Option<&'static str>,
}

impl Change {
    fn config(next: NodeConfig, reason: &'static str) -> Change {
        Change {
            next,
            reason,
            content: None,
            message: None,
        }
    }

    /// A change that republishes the generated homepage.
    fn page(next: NodeConfig, reason: &'static str) -> Change {
        Change {
            next,
            reason,
            content: Some(SiteContent::Template),
            message: Some(PUBLISHED),
        }
    }

    /// A change that publishes other content.
    fn content(
        cfg: &NodeConfig,
        reason: &'static str,
        content: SiteContent,
        message: &'static str,
    ) -> Change {
        Change {
            next: cfg.clone(),
            reason,
            content: Some(content),
            message: Some(message),
        }
    }
}

/// The request of a site change and the message printed after it.
pub fn plan_change(
    session: &Session,
    action: SiteAction,
) -> Result<Option<(crate::apply::ApplyRequest, Option<&'static str>)>> {
    let loaded = session.load()?;
    let Some(change) = change(session, &loaded.config, action)? else {
        return Ok(None);
    };
    let mut req = request(&loaded, change.next, change.reason);
    req.intents.site_content = change.content;
    Ok(Some((req, change.message)))
}

fn change(session: &Session, cfg: &NodeConfig, action: SiteAction) -> Result<Option<Change>> {
    let store = ContentStore::new(&session.ctx.paths);
    let edits_page = matches!(
        action,
        SiteAction::Theme(_) | SiteAction::Title(_) | SiteAction::Description(_)
    );
    if edits_page {
        // Without a site there is no page: say so before looking at it.
        require_site(cfg)?;
        require_generated(&store)?;
    }
    Ok(Some(match action {
        SiteAction::Enable { domain, cert } => {
            let facts = session.facts()?;
            let probe = LiveProbe(session.live);
            let env = facts.env(&probe, Some(cfg));
            Change::config(plan::enable_site(cfg, &domain, cert, &env)?, "启用网站")
        }
        SiteAction::Disable => Change::config(plan::disable_site(cfg)?, "关闭网站"),
        SiteAction::Https(on) => Change::config(plan::site_https(cfg, on)?, "修改网站入口"),
        SiteAction::Template(edit) => Change::page(edit_page(cfg, &edit)?, "更换网站模板"),
        SiteAction::Theme(theme) => Change::page(plan::site_theme(cfg, theme)?, "更换网站主题"),
        SiteAction::Title(title) => Change::page(plan::site_title(cfg, &title)?, "修改网站标题"),
        SiteAction::Description(text) => {
            Change::page(plan::site_description(cfg, &text)?, "修改网站描述")
        }
        SiteAction::Import(dir) => {
            require_site(cfg)?;
            let source = store.check_import(Path::new(&dir))?;
            Change::content(cfg, "导入网站", SiteContent::Import(source), PUBLISHED)
        }
        SiteAction::Restore(id) => {
            require_site(cfg)?;
            check_backup(&store, &id)?;
            Change::content(cfg, "恢复网站内容", SiteContent::Restore(id), RESTORED)
        }
        SiteAction::Info | SiteAction::Preview(_) | SiteAction::Renew => return Ok(None),
    }))
}

/// `template`: the template (default minimal) plus optional edits.
fn edit_page(cfg: &NodeConfig, edit: &PageEdit) -> Result<NodeConfig> {
    let template = edit.template.unwrap_or(defaults::SITE_TEMPLATE);
    let mut next = plan::site_template(cfg, template)?;
    if let Some(title) = &edit.title {
        next = plan::site_title(&next, title)?;
    }
    if let Some(text) = &edit.description {
        next = plan::site_description(&next, text)?;
    }
    if let Some(theme) = edit.theme {
        next = plan::site_theme(&next, theme)?;
    }
    Ok(next)
}

fn require_site(cfg: &NodeConfig) -> Result<()> {
    ensure!(cfg.site_active().is_some(), "请先启用网站");
    Ok(())
}

/// Edits of the generated page refuse imported or hand-edited content.
fn require_generated(store: &ContentStore) -> Result<()> {
    ensure!(store.is_generated()?, "{EDITED}");
    Ok(())
}

/// `latest` or an existing backup id (v2 id rule).
fn check_backup(store: &ContentStore, id: &str) -> Result<()> {
    let backups = store.backups()?;
    if id == "latest" {
        ensure!(!backups.is_empty(), "没有网站备份");
        return Ok(());
    }
    ensure!(
        !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        "无效备份 ID"
    );
    ensure!(backups.iter().any(|b| b.id == id), "网站备份不存在: {id}");
    Ok(())
}

/// `preview`: render the page to `ROOT/site/preview.html` and print its path.
pub fn preview(session: &Session, edit: &PageEdit) -> Result<()> {
    session.require_root()?;
    let loaded = session.load()?;
    let site = loaded.config.site.as_ref();
    let html = crate::site::templates::render(
        edit.template
            .or(site.map(|s| s.template))
            .unwrap_or(defaults::SITE_TEMPLATE),
        edit.theme
            .or(site.map(|s| s.theme))
            .unwrap_or(defaults::SITE_THEME),
        edit.title
            .as_deref()
            .or(site.map(|s| s.title.as_str()))
            .unwrap_or(defaults::SITE_TITLE),
        edit.description
            .as_deref()
            .or(site.map(|s| s.description.as_str()))
            .unwrap_or(defaults::SITE_DESCRIPTION),
    );
    let path = ContentStore::new(&session.ctx.paths).preview(&html)?;
    session.data(&path.to_string_lossy())
}

#[cfg(test)]
mod tests;
