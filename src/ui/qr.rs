//! In-process QR code rendering (qrcode crate) as Unicode half-block text.
//!
//! Changes from v2: no `qrencode` dependency (B-9.1#18). Two module rows
//! share one text line (`▀` upper, `▄` lower, `█` both, space neither).
//! Light modules — including the 2-module quiet zone — are drawn as blocks.
//! On a terminal every line is wrapped in explicit colors (white blocks on
//! a black background, as v2's `qrencode -t ANSIUTF8`), so the code is
//! dark-on-light — the polarity phone scanners expect — whatever the
//! terminal theme; plain text (a file, a pipe, `NO_COLOR`) is only right
//! on a dark background.

use crate::error::{Error, Result};
use qrcode::{Color, EcLevel, QrCode};

/// Quiet-zone width in modules on each side.
pub const QUIET_ZONE: usize = 2;
/// SGR opening each colored line: black background, bright white blocks.
pub const LINE_COLORS: &str = "\x1b[40;97m";
/// SGR closing each colored line.
pub const LINE_RESET: &str = "\x1b[0m";

/// Render `text` as a QR code (error correction level M); `color` wraps
/// each line in [`LINE_COLORS`] … [`LINE_RESET`].
pub fn render(text: &str, color: bool) -> Result<String> {
    let code = QrCode::with_error_correction_level(text.as_bytes(), EcLevel::M)
        .map_err(|_| Error::msg("内容过长，无法生成二维码"))?;
    let width = code.width();
    let colors = code.to_colors();
    let size = width + 2 * QUIET_ZONE;
    // `lit(x, y)` over the padded grid: true where a block is drawn. Rows
    // past the bottom edge (odd height) are background, i.e. not lit.
    let lit = |x: usize, y: usize| -> bool {
        if y >= size {
            return false;
        }
        let inside = |v: usize| (QUIET_ZONE..QUIET_ZONE + width).contains(&v);
        if !inside(x) || !inside(y) {
            return true;
        }
        colors[(y - QUIET_ZONE) * width + (x - QUIET_ZONE)] == Color::Light
    };
    let line_extra = if color {
        LINE_COLORS.len() + LINE_RESET.len()
    } else {
        0
    };
    let mut out = String::with_capacity(size.div_ceil(2) * (size * 3 + line_extra + 1));
    for y in (0..size).step_by(2) {
        if color {
            out.push_str(LINE_COLORS);
        }
        for x in 0..size {
            out.push(match (lit(x, y), lit(x, y + 1)) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        if color {
            out.push_str(LINE_RESET);
        }
        out.push('\n');
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dimensions_and_determinism() {
        let text = render("hello", false).unwrap();
        // Version 1 is 21 modules; plus the quiet zone on both sides.
        let size = 21 + 2 * QUIET_ZONE;
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), size.div_ceil(2));
        assert!(lines.iter().all(|l| l.chars().count() == size));
        assert_eq!(render("hello", false).unwrap(), text);
        assert_ne!(render("hellp", false).unwrap(), text);
    }

    /// Light-background terminals: every line (quiet zone included) carries
    /// explicit white-on-black colors, so the polarity never depends on the
    /// theme; the glyphs are the plain rendering's.
    #[test]
    fn colored_lines_force_white_on_black() {
        let plain = render("vless://example", false).unwrap();
        let colored = render("vless://example", true).unwrap();
        assert_eq!(LINE_COLORS, "\x1b[40;97m");
        assert_eq!(colored.lines().count(), plain.lines().count());
        for (c, p) in colored.lines().zip(plain.lines()) {
            let inner = c
                .strip_prefix(LINE_COLORS)
                .and_then(|l| l.strip_suffix(LINE_RESET));
            assert_eq!(inner, Some(p), "{c:?}");
        }
        assert!(!plain.contains('\x1b'));
    }

    #[test]
    fn quiet_zone_and_finder_pattern() {
        let text = render("vless://example", false).unwrap();
        let lines: Vec<Vec<char>> = text.lines().map(|l| l.chars().collect()).collect();
        // The first line covers quiet-zone rows 0 and 1: all light → full blocks.
        assert!(lines[0].iter().all(|&c| c == '█'));
        // Line 1 covers grid rows 2–3, the finder pattern's dark outer ring,
        // so its first column inside the code is not lit.
        assert_eq!(lines[1][QUIET_ZONE], ' ');
        assert_eq!(lines[1][0], '█', "quiet zone column");
        // The last line pairs the bottom quiet row with background.
        assert!(lines.last().unwrap().iter().all(|&c| c == '▀'));
    }

    #[test]
    fn share_links_fit() {
        let link = format!(
            "vless://{}@203.0.113.10:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk={}&sid=0123456789abcdef&type=tcp#onebox-VLESS-REALITY",
            "0b2d4f6a-1c3e-4a5b-8c7d-9e0f1a2b3c4d",
            "A".repeat(43)
        );
        assert!(render(&link, true).is_ok());
        assert!(render(&"x".repeat(5000), false).is_err());
    }
}
