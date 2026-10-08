//! Terminal prompter. One buffered reader serves the whole session, so
//! pasted multi-line input is never lost between questions (v2 created a
//! new reader per question on /dev/tty). Prompts are written to the stream
//! paired with the reader: stderr when answering from a stdin TTY, the tty
//! itself otherwise.

use super::{
    confirm_prompt, format_menu, input_prompt, parse_confirm, parse_select, parse_select_many,
    select_hint, select_many_prompt, select_prompt, Prompter,
};
use crate::error::{Error, Result};
use crate::sys::text::sanitize_input;
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, IsTerminal, Write};
use std::sync::{Mutex, MutexGuard, PoisonError};

/// Longest accepted answer line; longer input is refused, not truncated.
const MAX_LINE: usize = 64 * 1024;

struct Terminal {
    reader: Box<dyn BufRead + Send>,
    writer: Box<dyn Write + Send>,
}

pub struct TtyPrompter {
    terminal: Mutex<Terminal>,
}

impl TtyPrompter {
    /// stdin when it is a terminal (prompts on stderr), else `/dev/tty`;
    /// `None` when neither is available.
    pub fn open() -> Option<TtyPrompter> {
        if io::stdin().is_terminal() {
            return Some(Self::from_streams(
                BufReader::new(io::stdin()),
                io::stderr(),
            ));
        }
        let tty = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .ok()?;
        let reader = tty.try_clone().ok()?;
        Some(Self::from_streams(BufReader::new(reader), tty))
    }

    /// A prompter over arbitrary streams (tests, alternative terminals).
    pub fn from_streams(
        reader: impl BufRead + Send + 'static,
        writer: impl Write + Send + 'static,
    ) -> TtyPrompter {
        TtyPrompter {
            terminal: Mutex::new(Terminal {
                reader: Box::new(reader),
                writer: Box::new(writer),
            }),
        }
    }

    /// Holding the guard for a whole question keeps concurrent prompts from
    /// interleaving.
    fn terminal(&self) -> MutexGuard<'_, Terminal> {
        self.terminal.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Terminal {
    fn say(&mut self, text: &str) -> Result<()> {
        writeln!(self.writer, "{text}")?;
        self.writer.flush()?;
        Ok(())
    }

    /// Show `prompt`, read one line and return it sanitized. EOF → Cancelled.
    fn ask(&mut self, prompt: &str) -> Result<String> {
        write!(self.writer, "{prompt}")?;
        self.writer.flush()?;
        match read_line(self.reader.as_mut())? {
            Some(line) => Ok(sanitize_input(&line)),
            None => {
                // Finish the prompt line so the error message starts cleanly.
                let _ = writeln!(self.writer);
                Err(Error::Cancelled)
            }
        }
    }

    /// Ask until `parse` accepts the answer, printing `hint` after each miss.
    fn ask_until<T>(
        &mut self,
        prompt: &str,
        hint: &str,
        parse: impl Fn(&str) -> Option<T>,
    ) -> Result<T> {
        loop {
            let answer = self.ask(prompt)?;
            if let Some(value) = parse(&answer) {
                return Ok(value);
            }
            self.say(hint)?;
        }
    }
}

/// Read one line (without the newline). `None` on EOF before any byte. A
/// read interrupted by a cancellation signal (handlers installed by
/// `sys::signal::SignalScope`) cancels the prompt.
fn read_line(reader: &mut dyn BufRead) -> Result<Option<String>> {
    let mut line = Vec::new();
    loop {
        let (used, done) = {
            let buf = match reader.fill_buf() {
                Ok(buf) => buf,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                    crate::sys::signal::check()?;
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            if buf.is_empty() {
                return Ok((!line.is_empty()).then(|| String::from_utf8_lossy(&line).into_owned()));
            }
            match buf.iter().position(|&b| b == b'\n') {
                Some(i) => {
                    line.extend_from_slice(&buf[..i]);
                    (i + 1, true)
                }
                None => {
                    line.extend_from_slice(buf);
                    (buf.len(), false)
                }
            }
        };
        reader.consume(used);
        if line.len() > MAX_LINE {
            return Err(Error::msg("输入过长"));
        }
        if done {
            return Ok(Some(String::from_utf8_lossy(&line).into_owned()));
        }
    }
}

impl Prompter for TtyPrompter {
    fn interactive(&self) -> bool {
        true
    }

    fn assume_yes(&self) -> bool {
        false
    }

    fn input(&self, prompt: &str, default: &str) -> Result<String> {
        let answer = self.terminal().ask(&input_prompt(prompt, default))?;
        Ok(if answer.is_empty() {
            default.to_string()
        } else {
            answer
        })
    }

    fn input_with(
        &self,
        prompt: &str,
        default: &str,
        check: &dyn Fn(&str) -> Result<String>,
    ) -> Result<String> {
        loop {
            let value = self.input(prompt, default)?;
            match check(&value) {
                Ok(valid) => return Ok(valid),
                Err(e) if e.is_cancelled() => return Err(e),
                Err(e) => self.terminal().say(&format!("[错误] {e}"))?,
            }
        }
    }

    fn confirm(&self, prompt: &str, default: bool) -> Result<bool> {
        self.terminal()
            .ask_until(&confirm_prompt(prompt, default), "请输入 y 或 n", |a| {
                parse_confirm(a, default)
            })
    }

    fn select(
        &self,
        title: &str,
        items: &[String],
        default: usize,
        back: bool,
    ) -> Result<Option<usize>> {
        if items.is_empty() && !back {
            return Err(Error::msg("没有可选择的项目"));
        }
        let mut terminal = self.terminal();
        terminal.say(&format_menu(title, items, back))?;
        let hint = select_hint(items.len(), back);
        terminal.ask_until(&select_prompt(items.len(), default), &hint, |a| {
            parse_select(a, items.len(), default, back)
        })
    }

    fn select_many(&self, title: &str, items: &[String], default: &[usize]) -> Result<Vec<usize>> {
        let mut terminal = self.terminal();
        terminal.say(&format_menu(title, items, false))?;
        terminal.ask_until(&select_many_prompt(default), "编号无效", |a| {
            parse_select_many(a, items.len(), default)
        })
    }

    fn secret(&self, prompt: &str) -> Result<String> {
        super::secret::read_secret(prompt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::Arc;

    /// A writer whose bytes the test can inspect afterwards.
    #[derive(Clone, Default)]
    struct Shared(Arc<Mutex<Vec<u8>>>);

    impl Write for Shared {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Shared {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    fn prompter(input: &str) -> (TtyPrompter, Shared) {
        let out = Shared::default();
        let ui = TtyPrompter::from_streams(Cursor::new(input.as_bytes().to_vec()), out.clone());
        (ui, out)
    }

    fn items(n: usize) -> Vec<String> {
        (1..=n).map(|i| format!("选项{i}")).collect()
    }

    #[test]
    fn input_uses_default_and_sanitizes() {
        let (ui, out) = prompter("\n  my\x1b[Anode \r\n");
        assert_eq!(ui.input("节点名称", "onebox").unwrap(), "onebox");
        assert_eq!(ui.input("域名", "").unwrap(), "mynode");
        assert_eq!(out.text(), "节点名称 [默认: onebox]: 域名: ");
    }

    #[test]
    fn one_reader_keeps_pasted_lines() {
        let (ui, _) = prompter("first\nsecond\nthird");
        assert_eq!(ui.input("a", "").unwrap(), "first");
        assert_eq!(ui.input("b", "").unwrap(), "second");
        assert_eq!(
            ui.input("c", "").unwrap(),
            "third",
            "last line without newline"
        );
        let err = ui.input("d", "x").unwrap_err();
        assert!(err.is_cancelled(), "EOF cancels");
    }

    #[test]
    fn input_with_prints_errors_and_re_asks() {
        let (ui, out) = prompter("abc\n8443\n");
        let port = |s: &str| -> Result<String> {
            s.parse::<u16>()
                .map(|p| p.to_string())
                .map_err(|_| Error::msg(format!("端口无效: {s}")))
        };
        assert_eq!(ui.input_with("端口", "443", &port).unwrap(), "8443");
        assert_eq!(
            out.text(),
            "端口 [默认: 443]: [错误] 端口无效: abc\n端口 [默认: 443]: "
        );
    }

    #[test]
    fn confirm_loop() {
        let (ui, out) = prompter("what\n是\n\n");
        assert!(ui.confirm("继续？", false).unwrap());
        assert!(ui.confirm("继续？", true).unwrap());
        assert_eq!(
            out.text(),
            "继续？ [y/N]: 请输入 y 或 n\n继续？ [y/N]: 继续？ [Y/n]: "
        );
    }

    #[test]
    fn select_shows_menu_and_validates() {
        let (ui, out) = prompter("5\n2\n");
        assert_eq!(
            ui.select("REALITY 目标", &items(3), 0, true).unwrap(),
            Some(1)
        );
        assert_eq!(
            out.text(),
            "REALITY 目标\n  1) 选项1\n  2) 选项2\n  3) 选项3\n  0) 返回\n\
             请选择 [默认: 1]: 请输入 0–3\n请选择 [默认: 1]: "
        );
        let (ui, _) = prompter("\n0\n");
        assert_eq!(ui.select("", &items(2), 1, false).unwrap(), Some(1));
        let (ui, _) = prompter("0\n");
        assert_eq!(ui.select("", &items(2), 0, true).unwrap(), None);
        let (ui, _) = prompter("");
        assert!(ui.select("", &[], 0, false).is_err());
    }

    #[test]
    fn select_many_re_asks_on_invalid_numbers() {
        let (ui, out) = prompter("1 9\n3,1\n");
        assert_eq!(ui.select_many("协议", &items(3), &[0]).unwrap(), [0, 2]);
        assert!(out.text().ends_with(
            "选择编号，以空格或逗号分隔 [默认: 1]: 编号无效\n选择编号，以空格或逗号分隔 [默认: 1]: "
        ));
    }

    #[test]
    fn overlong_lines_are_refused() {
        let long = "x".repeat(MAX_LINE + 10) + "\n";
        let (ui, _) = prompter(&long);
        assert_eq!(ui.input("a", "").unwrap_err().to_string(), "输入过长");
    }

    #[test]
    fn flags() {
        let (ui, _) = prompter("");
        assert!(ui.interactive());
        assert!(!ui.assume_yes());
    }
}
