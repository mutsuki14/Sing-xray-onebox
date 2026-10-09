//! Performance and diagnostics: tuning with a preview and confirmation,
//! doctor, probe bundles (export, list, merge), bench, failover, REALITY
//! check and BBR (v2 menu 21 and its prompts, spec D §2.9). File answers
//! are dispatched after `--`.

use super::Menu;
use crate::cli::commands::tune::{self, Tune};
use crate::cli::session::request;
use crate::domain::config::{Hy2Profile, NodeConfig, ResourceProfile};
use crate::domain::defaults::HY2_MBPS;
use crate::domain::protocol::Protocol;
use crate::error::{Error, Result};
use crate::ui::menu::Entry;
use crate::ui::Prompter;
use std::ops::RangeInclusive;

const HEALTH_URL: &str = "https://www.gstatic.com/generate_204";
const FAILOVER_NOTE: &str = "仅监听本机 SOCKS5 TCP；连续检测失败才切换，Ctrl+C 结束。";

impl Menu<'_> {
    pub(super) fn performance_menu(&self) -> Result<()> {
        let heading = || match self.session.load() {
            Ok(loaded) => format!("性能与诊断\n{}", tuning_state(&loaded.config)),
            Err(e) => format!("性能与诊断\n[错误] {}", e.report_text()),
        };
        let items: Vec<Entry> = [
            "Hysteria2 调优：自动（BBR）",
            "Hysteria2 调优：保守",
            "Hysteria2 调优：指定带宽",
            "Hysteria2 混淆与端口跳跃",
            "资源档位",
            "重置调优",
            "体检（doctor）",
            "探测配置（导出 / 查看 / 合并）",
            "测速（bench）",
            "故障切换演练（failover）",
            "REALITY 检查",
            "BBR",
        ]
        .iter()
        .map(|l| Entry::new(*l))
        .collect();
        self.submenu(&heading, &items, &|i| match i {
            0 => self.tune(hy2(Hy2Profile::Auto)),
            1 => self.tune(hy2(Hy2Profile::Conservative)),
            2 => self.tune(self.measured()?),
            3 => self.tune(self.hy2_transport()?),
            4 => match self.resource()? {
                Some(profile) => self.tune(Tune::Resource(profile)),
                None => Ok(()),
            },
            5 => self.tune(Tune::Reset),
            6 => self.dispatch(&["doctor"]),
            7 => self.probe_menu(),
            8 => self.bench(),
            9 => self.failover(),
            10 => self.dispatch(&["reality-check"]),
            _ => self.dispatch(&["bbr"]),
        })
    }

    /// Preview a tuning change, apply it when confirmed (root, which the
    /// preview needs too: the node state is root-only).
    fn tune(&self, change: Tune) -> Result<()> {
        self.session.require_root()?;
        let loaded = self.loaded()?;
        let next = tune::plan_live(self.session, &loaded.config, change)?;
        self.session.data(&tune::preview_text(&next, change))?;
        if !self.session.ui().confirm("应用此调优配置？", true)? {
            return Ok(());
        }
        let reimport = tune::needs_reimport(&loaded.config, &next);
        self.session.apply(request(&loaded, next, "调优"))?;
        if reimport {
            self.session.info(tune::REIMPORT);
        }
        Ok(())
    }

    fn measured(&self) -> Result<Tune> {
        let hy2 = self.loaded()?.config.hy2;
        let ui = self.session.ui();
        let default = |v: Option<u32>| v.unwrap_or(100).to_string();
        let up = ask_number(ui, "上传 Mbps", &default(hy2.up_mbps), HY2_MBPS)?;
        let down = ask_number(ui, "下载 Mbps", &default(hy2.down_mbps), HY2_MBPS)?;
        Ok(Tune::hy2(Hy2Profile::Measured, Some(up), Some(down)))
    }

    /// Salamander obfuscation and the hopping range, defaulting to the
    /// current settings.
    fn hy2_transport(&self) -> Result<Tune> {
        let hy2 = self.loaded()?.config.hy2;
        let ui = self.session.ui();
        let obfs = ui.confirm("启用 Salamander 混淆?", hy2.obfs)?;
        let current = hy2.hop.map_or_else(|| "off".to_owned(), |r| r.to_string());
        let check = |answer: &str| tune::hop(answer).map(|_| answer.trim().to_owned());
        let answer = ui.input_with("UDP 端口跳跃范围（起-止，off 关闭）", &current, &check)?;
        Ok(Tune::hy2_transport(Some(obfs), Some(tune::hop(&answer)?)))
    }

    fn resource(&self) -> Result<Option<ResourceProfile>> {
        let current = self.loaded()?.config.resource_profile;
        let all = ResourceProfile::ALL;
        let items: Vec<String> = all.iter().map(|p| p.id().to_owned()).collect();
        let default = all.iter().position(|p| *p == current).unwrap_or(0);
        let choice = self
            .session
            .ui()
            .select("资源档位", &items, default, true)?;
        Ok(choice.and_then(|i| all.get(i).copied()))
    }

    /// v2's probe submenu: export this node's bundle, list a bundle's
    /// entries, merge bundles of several servers.
    fn probe_menu(&self) -> Result<()> {
        let local = self.local_probe();
        let heading = || {
            let state = if local.is_file() {
                local.to_string_lossy().into_owned()
            } else {
                "尚未生成".to_owned()
            };
            format!("探测配置\n  本机探测配置 {state}")
        };
        let items: Vec<Entry> = ["导出本机探测配置", "查看配置入口", "合并多份配置"]
            .iter()
            .map(|l| Entry::new(*l))
            .collect();
        self.submenu(&heading, &items, &|i| match i {
            0 => self.probe_export(),
            1 => self.probe_list(),
            _ => self.probe_merge(),
        })
    }

    fn probe_export(&self) -> Result<()> {
        let path = self.session.ui().input_with(
            "导出到新文件（不可已存在）",
            "probe-export.json",
            &new_file,
        )?;
        self.run_tool(&["probe", "export"], Vec::new(), &[path])
    }

    fn probe_list(&self) -> Result<()> {
        let default = self.default_probe();
        let file = self
            .session
            .ui()
            .input_with("探测配置文件", &default, &existing_file)?;
        self.run_tool(&["probe", "list"], Vec::new(), &[file])
    }

    /// `probe merge NEW F1..Fn` with 2–8 inputs (v2 prompts and defaults).
    fn probe_merge(&self) -> Result<()> {
        let ui = self.session.ui();
        let target = ui.input_with("合并到新文件（不可已存在）", "combined.json", &new_file)?;
        let count = ask_number(ui, "要合并的文件数", "2", 2..=8)?;
        let mut files = vec![target];
        for i in 1..=count {
            let prompt = format!("第 {i} 份探测配置文件");
            let default = format!("server-{i}.json");
            files.push(ui.input_with(&prompt, &default, &existing_file)?);
        }
        self.run_tool(&["probe", "merge"], Vec::new(), &files)
    }

    /// The node's own bundle, written with the client configurations.
    fn local_probe(&self) -> std::path::PathBuf {
        self.session.ctx.paths.clients().join("probe.json")
    }

    /// The node's own bundle when it exists, else v2's `probe.json`.
    fn default_probe(&self) -> String {
        let local = self.local_probe();
        if local.is_file() {
            local.to_string_lossy().into_owned()
        } else {
            "probe.json".to_owned()
        }
    }

    /// The probe file, then the health URL and entries options shared by
    /// bench/failover.
    fn link_test_base(&self) -> Result<(String, Vec<String>)> {
        let ui = self.session.ui();
        let file = ui.input_with("探测配置文件", &self.default_probe(), &existing_file)?;
        let url = ui.input_with("HTTPS 健康检测地址（应返回 2xx）", HEALTH_URL, &https_url)?;
        let entries = ui.input_with("入口 ID（逗号分隔，留空自动选择）", "", &entry_ids)?;
        let mut options = vec!["--url".to_owned(), url];
        if !entries.is_empty() {
            options.extend(["--entries".into(), entries]);
        }
        Ok((file, options))
    }

    fn bench(&self) -> Result<()> {
        let ui = self.session.ui();
        let (file, mut argv) = self.link_test_base()?;
        let samples = ask_number(ui, "健康检测次数", "5", 1..=20)?;
        argv.extend(["--samples".into(), samples.to_string()]);
        for (flag, prompt, check) in [
            (
                "--download-url",
                "下载测速 HTTPS 地址（留空跳过）",
                optional_url as Check,
            ),
            (
                "--upload-url",
                "已授权上传测速的 HTTPS 地址（留空跳过）",
                optional_url,
            ),
            (
                "--output",
                "报告保存到新文件（留空打印到终端）",
                optional_new_file,
            ),
        ] {
            let value = ui.input_with(prompt, "", &check)?;
            if !value.is_empty() {
                argv.extend([flag.to_owned(), value]);
            }
        }
        self.run_tool(&["bench"], argv, &[file])
    }

    fn failover(&self) -> Result<()> {
        let ui = self.session.ui();
        let (file, mut argv) = self.link_test_base()?;
        self.session.info(FAILOVER_NOTE);
        for (flag, prompt, default, range) in [
            ("--port", "本机 SOCKS5 端口", "2080", 1024..=65535),
            ("--interval", "健康检测间隔（秒）", "15", 1..=3600),
            ("--failures", "切换前连续失败次数", "3", 1..=20),
            ("--recoveries", "恢复前连续成功次数", "3", 1..=20),
            ("--cooldown", "恢复冷却期（秒）", "60", 0..=3600),
        ] {
            let value = ask_number(ui, prompt, default, range)?;
            argv.extend([flag.to_owned(), value.to_string()]);
        }
        self.run_tool(&["failover"], argv, &[file])
    }

    /// `words OPTIONS -- FILES`: typed file names are data, never options.
    fn run_tool(&self, words: &[&str], options: Vec<String>, files: &[String]) -> Result<()> {
        let mut argv: Vec<&str> = words.to_vec();
        argv.extend(options.iter().map(String::as_str));
        argv.push("--");
        argv.extend(files.iter().map(String::as_str));
        self.dispatch(&argv)
    }
}

type Check = fn(&str) -> Result<String>;

fn hy2(profile: Hy2Profile) -> Tune {
    Tune::hy2(profile, None, None)
}

fn tuning_state(cfg: &NodeConfig) -> String {
    let mut parts = Vec::new();
    if cfg.has(Protocol::Hysteria2) {
        let profile = match cfg.hy2.profile {
            None => "未设置".to_owned(),
            Some(Hy2Profile::Measured) => format!(
                "measured（上传 {} / 下载 {} Mbps）",
                cfg.hy2.up_mbps.unwrap_or(0),
                cfg.hy2.down_mbps.unwrap_or(0)
            ),
            Some(p) => p.id().to_owned(),
        };
        parts.push(format!("Hysteria2 调优 {profile}"));
        parts.push(format!(
            "混淆 {}",
            if cfg.hy2.obfs { "开启" } else { "关闭" }
        ));
        let hop = cfg
            .hy2
            .hop
            .map_or_else(|| "关闭".to_owned(), |r| r.to_string());
        parts.push(format!("端口跳跃 {hop}"));
    }
    parts.push(format!("资源档位 {}", cfg.resource_profile));
    format!("  {}", parts.join(" · "))
}

/// An integer in `range` (re-asked otherwise).
fn ask_number(
    ui: &dyn Prompter,
    prompt: &str,
    default: &str,
    range: RangeInclusive<u32>,
) -> Result<u32> {
    let (low, high) = (*range.start(), *range.end());
    let answer = ui.input_with(
        prompt,
        default,
        &|text: &str| match text.trim().parse::<u32>() {
            Ok(n) if range.contains(&n) => Ok(n.to_string()),
            _ => Err(Error::msg(format!("请输入 {low}–{high} 的整数"))),
        },
    )?;
    answer
        .parse()
        .map_err(|_| Error::msg(format!("请输入 {low}–{high} 的整数")))
}

fn existing_file(path: &str) -> Result<String> {
    if std::path::Path::new(path).is_file() {
        Ok(path.to_owned())
    } else {
        Err(Error::msg(format!("文件不存在: {path}")))
    }
}

fn new_file(path: &str) -> Result<String> {
    if path.is_empty() {
        return Err(Error::msg("请输入文件路径"));
    }
    if std::fs::symlink_metadata(path).is_ok() {
        return Err(Error::msg(format!("目标已存在: {path}")));
    }
    Ok(path.to_owned())
}

fn optional_new_file(path: &str) -> Result<String> {
    if path.is_empty() {
        Ok(String::new())
    } else {
        new_file(path)
    }
}

fn https_url(url: &str) -> Result<String> {
    let ok = url.starts_with("https://")
        && url.len() > "https://".len()
        && !url.chars().any(|c| c.is_whitespace() || c.is_control());
    if ok {
        Ok(url.to_owned())
    } else {
        Err(Error::msg("请输入 https:// 开头的地址"))
    }
}

fn optional_url(url: &str) -> Result<String> {
    if url.is_empty() {
        Ok(String::new())
    } else {
        https_url(url)
    }
}

fn entry_ids(text: &str) -> Result<String> {
    let ok = text
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b',' | b'-' | b'_' | b'.'));
    if ok {
        Ok(text.to_owned())
    } else {
        Err(Error::msg("入口 ID 只能包含字母、数字、-、_、. 和逗号"))
    }
}
