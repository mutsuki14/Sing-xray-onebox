//! Crate-wide error type with Chinese messages and process exit codes.
//!
//! Exit codes: 0 success, 1 error, 2 warnings-only result, 75 self-update
//! recovery finished in a stale process, 130 cancelled. Cancellation keeps
//! code 130 even when wrapped in context (v2 turned it into 1 inside applies).
//!
//! What [`report`] prints (stderr unless noted): `Exit{0}` → its message on
//! stdout; a bare `Cancelled` (EOF at a prompt) → `[错误] 输入结束，操作已取消`;
//! a wrapped cancellation → `[错误] {context}` without the generic
//! `: 操作已取消` tail (e.g. `[错误] 测试已取消`); `Exit{2}` (a warnings-only
//! result such as `reality-check`'s) → `[警告] {message}`; anything else →
//! `[错误] {error}`.

use std::fmt;
use std::io;
use std::path::PathBuf;

pub type Result<T, E = Error> = std::result::Result<T, E>;

pub const EXIT_ERROR: i32 = 1;
pub const EXIT_WARNINGS: i32 = 2;
pub const EXIT_STALE_PROCESS: i32 = 75;
pub const EXIT_CANCELLED: i32 = 130;

#[derive(Debug)]
pub enum Error {
    /// The user cancelled (EOF on a prompt, Ctrl+C in a secret prompt, signal).
    Cancelled,
    /// An explicit exit code; code 0 prints `message` to stdout without a prefix.
    Exit {
        code: i32,
        message: String,
    },
    /// A user-facing message.
    Msg(String),
    /// A message wrapping a lower-level cause.
    Context {
        message: String,
        source: Box<Error>,
    },
    NotInstalled,
    /// A lock is held by another operation.
    Busy(String),
    /// Optimistic concurrency check failed.
    Conflict,
    Io {
        path: Option<PathBuf>,
        source: io::Error,
    },
    Command {
        program: String,
        code: i32,
        detail: String,
    },
}

impl Error {
    pub fn msg(message: impl Into<String>) -> Self {
        Error::Msg(message.into())
    }

    pub fn io(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Error::Io {
            path: Some(path.into()),
            source,
        }
    }

    pub fn exit(code: i32, message: impl Into<String>) -> Self {
        Error::Exit {
            code,
            message: message.into(),
        }
    }

    pub fn is_cancelled(&self) -> bool {
        match self {
            Error::Cancelled => true,
            Error::Context { source, .. } => source.is_cancelled(),
            _ => false,
        }
    }

    pub fn exit_code(&self) -> i32 {
        match self {
            Error::Exit { code, .. } => *code,
            Error::Context { source, .. } => source.exit_code(),
            Error::Cancelled => EXIT_CANCELLED,
            _ => EXIT_ERROR,
        }
    }

    /// The text `main` prints after its `[错误]` prefix: the `Display` text,
    /// except that a wrapped cancellation ends with its innermost context
    /// instead of the generic `操作已取消` (`测试已取消`, not
    /// `测试已取消: 操作已取消`).
    pub fn report_text(&self) -> String {
        match self {
            Error::Context { message, source } if source.is_cancelled() => match **source {
                Error::Cancelled => message.clone(),
                _ => format!("{message}: {}", source.report_text()),
            },
            other => other.to_string(),
        }
    }

    /// Wrap with a context message, keeping `Cancelled` and `Exit` intact so
    /// they still control the exit code.
    pub fn wrap(self, message: impl Into<String>) -> Self {
        match self {
            Error::Exit { .. } => self,
            other => Error::Context {
                message: message.into(),
                source: Box::new(other),
            },
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Cancelled => f.write_str("操作已取消"),
            Error::Exit { message, .. } | Error::Msg(message) | Error::Busy(message) => {
                f.write_str(message)
            }
            Error::Context { message, source } => write!(f, "{message}: {source}"),
            Error::NotInstalled => f.write_str("尚未安装 Onebox，请先执行 onebox install"),
            Error::Conflict => f.write_str("配置已被其他操作修改，请重新读取后重试"),
            Error::Io {
                path: Some(path),
                source,
            } => {
                write!(f, "{}: {}", path.display(), io_text(source))
            }
            Error::Io { path: None, source } => f.write_str(&io_text(source)),
            Error::Command {
                program,
                code,
                detail,
            } => {
                let detail = detail.trim();
                if detail.is_empty() {
                    write!(f, "{program} 执行失败 ({code})")
                } else {
                    write!(f, "{program} 执行失败 ({code}): {detail}")
                }
            }
        }
    }
}

impl std::error::Error for Error {}

/// Chinese text for common I/O failures; falls back to the OS message.
fn io_text(error: &io::Error) -> String {
    use io::ErrorKind::*;
    match error.kind() {
        NotFound => "文件或目录不存在".into(),
        PermissionDenied => "权限不足".into(),
        AlreadyExists => "目标已存在".into(),
        _ => error.to_string(),
    }
}

impl From<io::Error> for Error {
    fn from(source: io::Error) -> Self {
        Error::Io { path: None, source }
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Error::Msg(format!("JSON 无效: {error}"))
    }
}

impl From<String> for Error {
    fn from(message: String) -> Self {
        Error::Msg(message)
    }
}

impl From<&str> for Error {
    fn from(message: &str) -> Self {
        Error::Msg(message.to_owned())
    }
}

/// Attach context to fallible results.
pub trait Context<T> {
    fn context(self, message: impl Into<String>) -> Result<T>;
    fn with_context<F: FnOnce() -> String>(self, f: F) -> Result<T>;
}

impl<T, E: Into<Error>> Context<T> for std::result::Result<T, E> {
    fn context(self, message: impl Into<String>) -> Result<T> {
        self.map_err(|e| e.into().wrap(message))
    }

    fn with_context<F: FnOnce() -> String>(self, f: F) -> Result<T> {
        self.map_err(|e| e.into().wrap(f()))
    }
}

impl<T> Context<T> for Option<T> {
    fn context(self, message: impl Into<String>) -> Result<T> {
        self.ok_or_else(|| Error::Msg(message.into()))
    }

    fn with_context<F: FnOnce() -> String>(self, f: F) -> Result<T> {
        self.ok_or_else(|| Error::Msg(f()))
    }
}

/// Return early with a formatted user-facing message.
#[macro_export]
macro_rules! bail {
    ($($arg:tt)*) => {
        return Err($crate::error::Error::Msg(format!($($arg)*)))
    };
}

/// Return early with a formatted message unless the condition holds.
#[macro_export]
macro_rules! ensure {
    ($cond:expr, $($arg:tt)*) => {
        if !$cond {
            $crate::bail!($($arg)*);
        }
    };
}

/// Print an error the way `main` does and return its exit code.
///
/// Printing is best effort, like `ui::out`'s diagnostics: a closed pipe
/// (`onebox update-script | head -n 3`) or a hung-up terminal never turns
/// the result into a panic (`println!` would abort with status 134); the
/// exit code comes from the error alone.
pub fn report(error: &Error) -> i32 {
    report_to(error, &mut io::stdout().lock(), &mut io::stderr().lock())
}

/// [`report`] with explicit streams: `Exit{0}`'s message goes to `stdout`,
/// everything else to `stderr`. Write failures are ignored.
fn report_to(error: &Error, stdout: &mut dyn io::Write, stderr: &mut dyn io::Write) -> i32 {
    let (stream, text): (&mut dyn io::Write, String) = match error {
        Error::Exit { code: 0, message } if message.is_empty() => return 0,
        Error::Exit { code: 0, message } => (stdout, message.clone()),
        Error::Cancelled => (stderr, "[错误] 输入结束，操作已取消".to_owned()),
        // A warnings-only result (reality-check) is not an error (D-8.1#3).
        Error::Exit {
            code: EXIT_WARNINGS,
            message,
        } => (stderr, format!("[警告] {message}")),
        _ => (stderr, format!("[错误] {}", error.report_text())),
    };
    let _ = writeln!(stream, "{text}").and_then(|()| stream.flush());
    error.exit_code()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_survives_context() {
        let e = Error::Cancelled.wrap("配置未应用").wrap("外层");
        assert!(e.is_cancelled());
        assert_eq!(e.exit_code(), EXIT_CANCELLED);
    }

    #[test]
    fn exit_errors_are_not_wrapped() {
        let e = Error::exit(75, "stale").wrap("ctx");
        assert_eq!(e.exit_code(), 75);
        assert_eq!(e.to_string(), "stale");
    }

    #[test]
    fn context_formats_chain() {
        let r: Result<()> = Err(Error::msg("内层")).context("外层");
        assert_eq!(r.unwrap_err().to_string(), "外层: 内层");
    }

    #[test]
    fn wrapped_cancellations_report_their_context() {
        let e = Error::Cancelled.wrap("测试已取消");
        assert!(e.is_cancelled());
        assert_eq!(e.exit_code(), EXIT_CANCELLED);
        assert_eq!(e.to_string(), "测试已取消: 操作已取消");
        assert_eq!(e.report_text(), "测试已取消");
        let nested = Error::Cancelled
            .wrap("操作被信号 2 中断")
            .wrap("配置未应用，已恢复原状态");
        assert_eq!(
            nested.report_text(),
            "配置未应用，已恢复原状态: 操作被信号 2 中断"
        );
        assert_eq!(Error::Cancelled.report_text(), "操作已取消");
        let plain = Error::msg("内层").wrap("外层");
        assert_eq!(plain.report_text(), "外层: 内层");
        assert_eq!(report(&e), EXIT_CANCELLED);
    }

    #[test]
    fn report_returns_the_exit_code() {
        assert_eq!(report(&Error::exit(EXIT_WARNINGS, "检查完成，有警告")), 2);
        assert_eq!(report(&Error::exit(EXIT_CANCELLED, "测试已取消")), 130);
        assert_eq!(report(&Error::msg("失败")), 1);
    }

    /// A stream whose every write fails, like a pipe whose reader exited
    /// or a terminal that hung up.
    struct Dead(io::ErrorKind);

    impl io::Write for Dead {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(self.0))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::from(self.0))
        }
    }

    #[test]
    fn report_routes_each_kind_to_its_stream() {
        let cases: [(Error, i32, &str, &str); 6] = [
            (Error::exit(0, "程序已更新到 3.0.1"), 0, "程序已更新到 3.0.1\n", ""),
            (Error::exit(0, ""), 0, "", ""),
            (Error::Cancelled, 130, "", "[错误] 输入结束，操作已取消\n"),
            (
                Error::exit(EXIT_WARNINGS, "检查完成，有警告"),
                2,
                "",
                "[警告] 检查完成，有警告\n",
            ),
            (
                Error::Cancelled.wrap("测试已取消"),
                130,
                "",
                "[错误] 测试已取消\n",
            ),
            (Error::msg("未知命令: nope"), 1, "", "[错误] 未知命令: nope\n"),
        ];
        for (error, code, out, err) in cases {
            let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
            assert_eq!(report_to(&error, &mut stdout, &mut stderr), code, "{error}");
            assert_eq!(String::from_utf8_lossy(&stdout), out, "{error}");
            assert_eq!(String::from_utf8_lossy(&stderr), err, "{error}");
        }
    }

    #[test]
    fn report_survives_dead_streams() {
        // `onebox update-script | head -n 3`: the update finished, so the
        // closed stdout must neither panic nor change the exit code.
        for kind in [io::ErrorKind::BrokenPipe, io::ErrorKind::Other] {
            let cases = [
                (Error::exit(0, "程序已更新到 3.0.1"), 0),
                (Error::exit(EXIT_STALE_PROCESS, "旧进程"), EXIT_STALE_PROCESS),
                (Error::exit(EXIT_WARNINGS, "检查完成，有警告"), EXIT_WARNINGS),
                (Error::Cancelled, EXIT_CANCELLED),
                (Error::msg("未知命令: nope"), EXIT_ERROR),
            ];
            for (error, code) in cases {
                let code_seen = report_to(&error, &mut Dead(kind), &mut Dead(kind));
                assert_eq!(code_seen, code, "{error} ({kind:?})");
            }
        }
    }

    #[test]
    fn command_error_text() {
        let e = Error::Command {
            program: "nginx".into(),
            code: 1,
            detail: " bad \n".into(),
        };
        assert_eq!(e.to_string(), "nginx 执行失败 (1): bad");
    }
}
