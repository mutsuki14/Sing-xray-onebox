//! The interactive configuration wizard of `frps install|configure`
//! (spec H §2.5): v2's steps, prompts and defaults on the [`Draft`], run by
//! the shared step engine.
//!
//! Steps: 0 mode · 1 control domain · 2 control port · 3 application
//! domain (web) or forwarding range (tcp) · 4 certificate method (web) ·
//! 5 web ports · 6 custom certificate paths · 7 validation of the whole
//! configuration (a failure is printed and the wizard resumes at step 2).
//!
//! Changes from v2: certificate paths are made absolute against the
//! current directory; new names must be DNS domains (IP literals are
//! refused, H-8.1#15).

use super::draft::{absolute_path, finish, Draft, ModeKind, TlsKind};
use super::model::FrpState;
use super::steps::{self, ask, ask_domain, ask_port, ask_range, choose, value, Answer, Form};
use crate::error::Result;
use crate::ui::{out, Prompter};
use std::path::{Path, PathBuf};

pub const INTRO: &str = "FRP 配置向导：回车保留默认值；b 返回上一步；q 取消。确认后才修改系统。";
const CF_HINT: &str =
    "Cloudflare DNS 使用 CF_Token 与 CF_Account_ID 环境变量；已有账户配置可继续复用。";
const STEPS: usize = 8;
/// The final step validates; on failure the wizard resumes here.
const RESUME_AT: usize = 2;

/// Ask every step for `draft` and return the validated state (see
/// [`finish`] for the rules against `previous`).
pub fn run(
    ui: &dyn Prompter,
    draft: Draft,
    previous: Option<&FrpState>,
    cwd: &Path,
) -> Result<FrpState> {
    out::line(INTRO);
    let mut wizard = Wizard {
        draft,
        previous,
        cwd: cwd.to_path_buf(),
        result: None,
    };
    steps::run(ui, &mut wizard)?;
    wizard
        .result
        .ok_or_else(|| crate::error::Error::msg("FRP 配置向导未完成"))
}

struct Wizard<'a> {
    draft: Draft,
    previous: Option<&'a FrpState>,
    cwd: PathBuf,
    result: Option<FrpState>,
}

impl Form for Wizard<'_> {
    fn steps(&self) -> usize {
        STEPS
    }

    fn step(&mut self, ui: &dyn Prompter, index: usize) -> Result<Answer<()>> {
        let web = self.draft.is_web();
        match index {
            0 => self.mode(ui),
            1 => {
                self.draft.domain = value!(ask_domain(ui, "控制域名", &self.draft.domain)?);
                Ok(Answer::Value(()))
            }
            2 => {
                self.draft.bind_port =
                    value!(ask_port(ui, "控制端口", self.draft.bind_port, false)?);
                Ok(Answer::Value(()))
            }
            3 if web => self.app_domain(ui),
            3 => {
                self.draft.range = value!(ask_range(ui, "允许转发端口范围", self.draft.range)?);
                Ok(Answer::Value(()))
            }
            4 if web => self.tls(ui),
            5 if web => self.web_ports(ui),
            6 if web && self.draft.tls == TlsKind::Custom => self.custom_paths(ui),
            7 => {
                self.result = Some(finish(&self.draft, self.previous)?);
                Ok(Answer::Value(()))
            }
            _ => Ok(Answer::Value(())),
        }
    }

    fn retry_at(&self, index: usize) -> usize {
        if index + 1 >= STEPS {
            RESUME_AT
        } else {
            index
        }
    }
}

impl Wizard<'_> {
    fn mode(&mut self, ui: &dyn Prompter) -> Result<Answer<()>> {
        let default = if self.draft.is_web() { 1 } else { 2 };
        let picked = value!(choose(
            ui,
            "模式：1 HTTPS 网站，2 TCP / UDP 转发",
            default,
            1,
            2
        )?);
        self.draft.mode = if picked == 1 {
            ModeKind::Web
        } else {
            ModeKind::Tcp
        };
        Ok(Answer::Value(()))
    }

    fn app_domain(&mut self, ui: &dyn Prompter) -> Result<Answer<()>> {
        let d = &mut self.draft;
        let default = if d.wildcard() { 2 } else { 1 };
        let kind = value!(choose(ui, "应用域名：1 单域名，2 泛域名", default, 1, 2)?);
        if kind == 1 {
            d.web_domain = value!(ask_domain(ui, "应用域名", &d.web_domain)?);
            d.subdomain_host.clear();
        } else {
            d.subdomain_host = value!(ask_domain(ui, "泛域名根（不带 *.）", &d.subdomain_host)?);
            d.web_domain.clear();
        }
        Ok(Answer::Value(()))
    }

    fn tls(&mut self, ui: &dyn Prompter) -> Result<Answer<()>> {
        let d = &mut self.draft;
        let default = match d.tls {
            TlsKind::Cloudflare => 2,
            TlsKind::Custom => 3,
            TlsKind::Http01 if d.wildcard() => 2,
            TlsKind::Http01 => 1,
        };
        let picked = value!(choose(
            ui,
            "证书：1 HTTP-01，2 Cloudflare DNS，3 自备证书",
            default,
            1,
            3
        )?);
        d.tls = match picked {
            1 => TlsKind::Http01,
            2 => TlsKind::Cloudflare,
            _ => TlsKind::Custom,
        };
        ensure!(
            !(d.tls == TlsKind::Http01 && d.wildcard()),
            "泛域名需要 Cloudflare DNS 或自备证书"
        );
        if d.tls == TlsKind::Cloudflare {
            out::line(CF_HINT);
        }
        Ok(Answer::Value(()))
    }

    fn web_ports(&mut self, ui: &dyn Prompter) -> Result<Answer<()>> {
        let d = &mut self.draft;
        d.http_port = value!(ask_port(ui, "frps 内部 HTTP 端口", d.http_port, false)?);
        d.https_port = value!(ask_port(ui, "公开 HTTPS 端口", d.https_port, false)?);
        d.redirect_port = if d.tls == TlsKind::Http01 {
            80
        } else {
            value!(ask_port(
                ui,
                "HTTP 跳转端口（0 关闭）",
                d.redirect_port,
                true
            )?)
        };
        Ok(Answer::Value(()))
    }

    fn custom_paths(&mut self, ui: &dyn Prompter) -> Result<Answer<()>> {
        let cert = value!(ask(ui, "证书完整链路径", &self.draft.cert)?);
        let key = value!(ask(ui, "未加密私钥路径", &self.draft.key)?);
        self.draft.cert = absolute_path(&cert, &self.cwd)?;
        self.draft.key = absolute_path(&key, &self.cwd)?;
        Ok(Answer::Value(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frp::model::{AppDomain, BindAddr, WebTls};
    use crate::ui::ScriptedPrompter;

    fn wizard(answers: &[&str], draft: Draft) -> (Result<FrpState>, ScriptedPrompter) {
        let ui = ScriptedPrompter::new(answers.iter().copied());
        let result = run(&ui, draft, None, Path::new("/srv"));
        (result, ui)
    }

    #[test]
    fn web_single_domain_with_defaults() {
        let answers = ["", "frp.example.com", "", "", "app.example.com", "", "", ""];
        let (state, ui) = wizard(&answers, Draft::fresh(true));
        let state = state.unwrap();
        let web = state.web().unwrap();
        assert_eq!(state.domain, "frp.example.com");
        assert_eq!(state.bind_addr, BindAddr::AnyV6);
        assert_eq!(
            web.app,
            AppDomain::Single {
                domain: "app.example.com".into()
            }
        );
        assert_eq!(web.tls, WebTls::Http01);
        assert_eq!(
            (web.http_port, web.https_port, web.redirect_port),
            (7080, 443, 80)
        );
        assert_eq!(
            ui.prompts(),
            [
                "模式：1 HTTPS 网站，2 TCP / UDP 转发",
                "控制域名",
                "控制端口",
                "应用域名：1 单域名，2 泛域名",
                "应用域名",
                "证书：1 HTTP-01，2 Cloudflare DNS，3 自备证书",
                "frps 内部 HTTP 端口",
                "公开 HTTPS 端口",
            ]
        );
        assert_eq!(ui.remaining(), 0);
    }

    #[test]
    fn tcp_mode_asks_for_the_range() {
        let answers = ["2", "frp.example.com", "7100", "30000-30009"];
        let (state, _) = wizard(&answers, Draft::fresh(false));
        let state = state.unwrap();
        assert_eq!(state.bind_port, 7100);
        assert_eq!(
            state.range().map(|r| (r.start, r.end)),
            Some((30000, 30009))
        );
    }

    #[test]
    fn wildcard_needs_dns_or_custom_and_back_works() {
        // Wildcard with the HTTP-01 default is refused (step 4 re-asks);
        // custom paths are made absolute; `b` at the first web port goes
        // back to the certificate step.
        let answers = [
            "",
            "frp.example.com",
            "",
            "2",
            "Apps.Example.com",
            "1",
            "3",
            "b",
            "3",
            "",
            "8443",
            "0",
            "chain.pem",
            "/etc/key.pem",
        ];
        let (state, ui) = wizard(&answers, Draft::fresh(true));
        let state = state.unwrap();
        let web = state.web().unwrap();
        assert_eq!(
            web.app,
            AppDomain::Wildcard {
                root: "apps.example.com".into()
            }
        );
        assert_eq!(
            web.tls,
            WebTls::Custom {
                cert: "/srv/chain.pem".into(),
                key: "/etc/key.pem".into()
            }
        );
        assert_eq!((web.https_port, web.redirect_port), (8443, 0));
        assert_eq!(ui.remaining(), 0);
    }

    #[test]
    fn a_failed_validation_resumes_at_the_control_port() {
        // The HTTP port equals the control port: step 7 fails, the wizard
        // asks the control port again.
        let answers = [
            "",
            "frp.example.com",
            "7080",
            "",
            "app.example.com",
            "",
            "",
            "",
            "7000",
            "",
            "app.example.com",
            "",
            "",
            "",
        ];
        let (state, ui) = wizard(&answers, Draft::fresh(true));
        assert_eq!(state.unwrap().bind_port, 7000);
        assert_eq!(ui.prompts()[8], "控制端口");
    }

    #[test]
    fn cancel_and_eof_abort() {
        let (result, _) = wizard(&["", "q"], Draft::fresh(true));
        assert!(result.unwrap_err().is_cancelled());
        let (result, _) = wizard(&[""], Draft::fresh(true));
        assert!(result.unwrap_err().is_cancelled());
    }

    #[test]
    fn cloudflare_keeps_an_explicit_redirect_port() {
        let answers = [
            "",
            "frp.example.com",
            "",
            "",
            "app.example.com",
            "2",
            "",
            "",
            "8080",
        ];
        let (state, _) = wizard(&answers, Draft::fresh(true));
        let state = state.unwrap();
        let web = state.web().unwrap();
        assert_eq!(
            (web.tls.clone(), web.redirect_port),
            (WebTls::Cloudflare, 8080)
        );
    }
}
