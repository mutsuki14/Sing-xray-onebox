//! Homepage templates (`minimal`, `profile`, `docs`) × themes (`forest`,
//! `ocean`, `slate`): one line of HTML, byte-identical to v2
//! (`site::template`, F §3.8; the goldens in `golden/` were produced by the
//! v2.0.1 binary's `site preview`).
//!
//! Title and description are HTML-escaped (`&`, `<`, `>`, `"`, `'`, in that
//! order); an empty title or description falls back to the defaults
//! (`山间手记`, `给思考一点空间，给日常一些留白。`), as v2's `get_or` did.

use crate::domain::config::{SiteConfig, SiteTemplate, SiteTheme};
use crate::domain::defaults::{SITE_DESCRIPTION, SITE_TITLE};

/// The `--ink` colour of a theme.
pub fn ink(theme: SiteTheme) -> &'static str {
    match theme {
        SiteTheme::Forest => "#234e3c",
        SiteTheme::Ocean => "#164e72",
        SiteTheme::Slate => "#364152",
    }
}

/// The template's `<section>` blocks.
pub fn sections(template: SiteTemplate) -> &'static str {
    match template {
        SiteTemplate::Minimal => {
            "<section><h2>慢慢记录</h2><p>记录值得停留的瞬间，也整理尚未成形的想法。</p></section>"
        }
        SiteTemplate::Profile => {
            "<section><h2>关于我</h2><p>保持好奇，专注创造，在日常中发现新的可能。</p></section>\
             <section><h2>作品与日常</h2><p>这里收藏学习、创作和生活中的片段。</p></section>"
        }
        SiteTemplate::Docs => {
            "<section><h2>从这里开始</h2><p>这是一份持续整理的知识笔记。</p></section>\
             <section><h2>阅读目录</h2><ol><li>想法与方法</li><li>实践中的记录</li>\
             <li>值得收藏的参考</li></ol></section>"
        }
    }
}

/// v2 `html()`.
pub fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// The homepage for the given choices.
pub fn render(template: SiteTemplate, theme: SiteTheme, title: &str, description: &str) -> String {
    let title = escape(if title.is_empty() { SITE_TITLE } else { title });
    let description = escape(if description.is_empty() {
        SITE_DESCRIPTION
    } else {
        description
    });
    let color = ink(theme);
    let content = sections(template);
    format!(
        "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" \
         content=\"width=device-width,initial-scale=1\"><meta name=\"description\" \
         content=\"{description}\"><title>{title}</title><style>:root{{color-scheme:light;\
         --ink:{color}}}*{{box-sizing:border-box}}body{{margin:0;background:#f7f6f1;\
         color:var(--ink);font:17px/1.8 system-ui,sans-serif}}main,header,footer{{\
         width:min(850px,calc(100% - 48px));margin:auto}}header{{padding:32px 0;\
         border-bottom:1px solid #cfd6cf}}h1{{font-size:clamp(34px,7vw,64px);line-height:1.25;\
         font-weight:500}}.hero{{padding:70px 0 50px}}section{{border-top:1px solid #cfd6cf;\
         padding:28px 0}}footer{{padding:32px 0;font-size:13px}}a{{color:inherit}}</style>\
         </head><body><header>{title}</header><main><div class=\"hero\"><h1>{title}</h1>\
         <p>{description}</p></div>{content}</main><footer>保持好奇，慢慢记录。</footer>\
         </body></html>"
    )
}

/// The homepage of a configured site.
pub fn homepage(site: &SiteConfig) -> String {
    render(site.template, site.theme, &site.title, &site.description)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn golden(name: &str) -> &'static str {
        match name {
            "minimal-forest" => include_str!("golden/minimal-forest.html"),
            "minimal-ocean" => include_str!("golden/minimal-ocean.html"),
            "minimal-slate" => include_str!("golden/minimal-slate.html"),
            "profile-forest" => include_str!("golden/profile-forest.html"),
            "profile-ocean" => include_str!("golden/profile-ocean.html"),
            "profile-slate" => include_str!("golden/profile-slate.html"),
            "docs-forest" => include_str!("golden/docs-forest.html"),
            "docs-ocean" => include_str!("golden/docs-ocean.html"),
            "docs-slate" => include_str!("golden/docs-slate.html"),
            _ => include_str!("golden/escaped.html"),
        }
    }

    #[test]
    fn every_template_and_theme_matches_v2_bytes() {
        for template in SiteTemplate::ALL {
            for theme in SiteTheme::ALL {
                let name = format!("{template}-{theme}");
                assert_eq!(render(*template, *theme, "", ""), golden(&name), "{name}");
                assert_eq!(
                    render(*template, *theme, SITE_TITLE, SITE_DESCRIPTION),
                    golden(&name)
                );
            }
        }
    }

    #[test]
    fn text_is_escaped_like_v2() {
        let html = render(
            SiteTemplate::Docs,
            SiteTheme::Slate,
            "A<b>\"&'x",
            "<i>d&\"</i>",
        );
        assert_eq!(html, golden("escaped"));
        assert!(!html.contains("<b>") && !html.contains("<i>"));
        assert_eq!(escape("&lt;"), "&amp;lt;");
    }

    #[test]
    fn homepage_uses_the_site_settings() {
        let site = SiteConfig {
            domain: "www.example.com".into(),
            internal_port: 10443,
            https_entry: true,
            title: SITE_TITLE.into(),
            template: SiteTemplate::Profile,
            theme: SiteTheme::Ocean,
            description: String::new(),
            cert: crate::domain::config::WebCert::Http01,
            last_content_backup: None,
        };
        assert_eq!(homepage(&site), golden("profile-ocean"));
    }
}
