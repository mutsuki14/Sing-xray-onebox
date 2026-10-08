//! Crate-wide error type with Chinese messages and process exit codes.
//!
//! Exit codes: 0 success, 1 error, 2 warnings-only result, 75 self-update
//! recovery finished in a stale process, 130 cancelled. Cancellation keeps
//! code 130 even when wrapped in context (v2 turned it into 1 inside applies).

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
            Error::Context { source, .. } if source.is_cancelled() => EXIT_CANCELLED,
            Error::Cancelled => EXIT_CANCELLED,
            _ => EXIT_ERROR,
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
pub fn report(error: &Error) -> i32 {
    let code = error.exit_code();
    match error {
        Error::Exit { code: 0, message } => {
            if !message.is_empty() {
                println!("{message}");
            }
        }
        Error::Cancelled => eprintln!("[错误] 输入结束，操作已取消"),
        _ => eprintln!("[错误] {error}"),
    }
    code
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
    fn command_error_text() {
        let e = Error::Command {
            program: "nginx".into(),
            code: 1,
            detail: " bad \n".into(),
        };
        assert_eq!(e.to_string(), "nginx 执行失败 (1): bad");
    }
}
