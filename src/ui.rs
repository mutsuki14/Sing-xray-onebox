use crate::{context::Context, Result};
use std::{
    fs::OpenOptions,
    io::{self, BufRead, IsTerminal, Write},
};
#[derive(Debug)]
pub struct Cancelled;
impl std::fmt::Display for Cancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "输入结束，操作已取消")
    }
}
impl std::error::Error for Cancelled {}
pub fn interactive(ctx: &Context) -> bool {
    !ctx.yes
        && (io::stdin().is_terminal()
            || OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/tty")
                .is_ok())
}
pub fn ask(ctx: &Context, prompt: &str, default: &str) -> Result<String> {
    if ctx.yes {
        return Ok(default.into());
    }
    let mut line = String::new();
    let count = if io::stdin().is_terminal() {
        eprint!("{prompt} [默认: {default}]: ");
        io::stderr().flush()?;
        io::stdin().read_line(&mut line)?
    } else if let Ok(mut tty) = OpenOptions::new().read(true).write(true).open("/dev/tty") {
        write!(tty, "{prompt} [默认: {default}]: ")?;
        tty.flush()?;
        io::BufReader::new(tty).read_line(&mut line)?
    } else {
        return Err("当前没有交互终端，请通过参数提供配置并使用 -y".into());
    };
    if count == 0 {
        return Err(Box::new(Cancelled));
    }
    let clean = sanitize(line.trim());
    Ok(if clean.is_empty() {
        default.to_string()
    } else {
        clean
    })
}
pub fn sanitize(input: &str) -> String {
    let mut out = String::new();
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if matches!(chars.peek(), Some('[') | Some('O')) {
                chars.next();
                for x in chars.by_ref() {
                    if x.is_ascii_alphabetic() || x == '~' {
                        break;
                    }
                }
            }
        } else if !c.is_control() {
            out.push(c)
        }
    }
    out.trim().to_string()
}
pub fn confirm(ctx: &Context, prompt: &str, default: bool) -> Result<bool> {
    if ctx.yes {
        return Ok(true);
    }
    loop {
        let value = ask(ctx, prompt, if default { "y" } else { "n" })?;
        match value.to_ascii_lowercase().as_str() {
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => eprintln!("请输入 y 或 n"),
        }
    }
}
pub fn choose(ctx: &Context, prompt: &str, default: u32, min: u32, max: u32) -> Result<u32> {
    loop {
        let value = ask(ctx, prompt, &default.to_string())?;
        if let Ok(n) = value.parse::<u32>() {
            if n >= min && n <= max {
                return Ok(n);
            }
        }
        if ctx.yes {
            return Err("默认选项无效".into());
        }
        eprintln!("请输入 {min}–{max}")
    }
}
/// Read a secret from the controlling terminal without displaying its value.
/// Ctrl+C and Ctrl+D are handled as input so terminal settings are restored
/// before cancellation, including while no process-wide signal handler exists.
pub fn secret(ctx: &Context, prompt: &str) -> Result<String> {
    use std::{io::Read, os::fd::AsRawFd};
    if ctx.yes {
        return Err("无人值守模式请通过环境变量提供凭据".into());
    }
    let mut tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| "无法读取控制终端，请通过环境变量提供凭据")?;
    let fd = tty.as_raw_fd();
    let mut old = unsafe { std::mem::zeroed::<libc::termios>() };
    if unsafe { libc::tcgetattr(fd, &mut old) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    struct Restore {
        fd: i32,
        old: libc::termios,
    }
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe {
                libc::tcsetattr(self.fd, libc::TCSANOW, &self.old);
            }
        }
    }
    let mut hidden = old;
    hidden.c_lflag &= !(libc::ECHO | libc::ECHONL | libc::ICANON | libc::ISIG);
    hidden.c_cc[libc::VMIN] = 1;
    hidden.c_cc[libc::VTIME] = 0;
    write!(tty, "{prompt}（输入不回显，Ctrl+C 取消）: ")?;
    tty.flush()?;
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &hidden) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let _restore = Restore { fd, old };
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0u8];
        if tty.read(&mut byte)? == 0 {
            writeln!(tty)?;
            return Err(Box::new(Cancelled));
        }
        match byte[0] {
            3 | 4 => {
                writeln!(tty)?;
                return Err(Box::new(Cancelled));
            }
            b'\r' | b'\n' => {
                writeln!(tty)?;
                return Ok(String::from_utf8(bytes)?);
            }
            8 | 127 => {
                bytes.pop();
                while !bytes.is_empty() && std::str::from_utf8(&bytes).is_err() {
                    bytes.pop();
                }
            }
            b if b >= 32 => {
                if bytes.len() >= 4096 {
                    writeln!(tty)?;
                    return Err("凭据过长".into());
                }
                bytes.push(b);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strips_terminal_sequences() {
        assert_eq!(sanitize(" name\x1b[A\x1b[31m\r\t"), "name");
        assert_eq!(sanitize("中文"), "中文")
    }
}
