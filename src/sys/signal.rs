//! Signal handling: a process-wide cancellation flag set by scoped handlers
//! for SIGINT/SIGTERM/SIGHUP, and a guard that blocks those signals during
//! critical sections (binary swaps, sysctl changes).
//!
//! The flag is the only global mutable state in the crate. Handlers only
//! store the signal number (async-signal-safe); long operations poll
//! [`check`] at safe points (between apply stages) and unwind with
//! `Error::Cancelled`, so rollback runs instead of dying mid-write.
//! Handlers are installed without `SA_RESTART`, so a blocking prompt read
//! returns `EINTR` and the prompter can cancel promptly.

use crate::error::{Error, Result};
use std::io;
use std::sync::atomic::{AtomicI32, Ordering};

/// The signals Onebox treats as "cancel the current operation".
pub const CANCEL_SIGNALS: [libc::c_int; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];

/// Last cancellation signal received while a [`SignalScope`] was active (0 = none).
static PENDING: AtomicI32 = AtomicI32::new(0);

extern "C" fn record(sig: libc::c_int) {
    PENDING.store(sig, Ordering::SeqCst);
}

/// Address of [`record`] in the form `sigaction` expects.
fn record_address() -> libc::sighandler_t {
    record as *const () as libc::sighandler_t
}

/// Restore the default SIGINT disposition (a bootstrap shell may have left it
/// ignored for background children).
pub fn reset_interrupt_disposition() {
    // SAFETY: setting a standard disposition for a valid signal number.
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_DFL);
    }
}

/// The signal received while a scope was active, if any.
pub fn pending() -> Option<i32> {
    match PENDING.load(Ordering::SeqCst) {
        0 => None,
        n => Some(n),
    }
}

/// Forget a recorded signal (after it has been handled).
pub fn clear() {
    PENDING.store(0, Ordering::SeqCst);
}

/// `Err(Cancelled)` (exit 130) when a cancellation signal is pending.
pub fn check() -> Result<()> {
    match pending() {
        None => Ok(()),
        Some(n) => Err(Error::Cancelled.wrap(format!("操作被信号 {n} 中断"))),
    }
}

/// Installs recording handlers for INT/TERM/HUP; the previous dispositions
/// are restored on drop. Scopes nest (inner drop restores the outer
/// handler). Installing does not clear an already pending signal, so an
/// outer operation's cancellation is not lost.
pub struct SignalScope {
    previous: Vec<(libc::c_int, libc::sigaction)>,
}

impl SignalScope {
    pub fn install() -> Result<SignalScope> {
        let mut scope = SignalScope {
            previous: Vec::with_capacity(CANCEL_SIGNALS.len()),
        };
        for sig in CANCEL_SIGNALS {
            // On failure `scope` drops and restores what was installed so far.
            let old = set_handler(sig, record_address(), 0)
                .map_err(|e| Error::msg(format!("无法安装信号处理器: {e}")))?;
            scope.previous.push((sig, old));
        }
        Ok(scope)
    }
}

impl Drop for SignalScope {
    fn drop(&mut self) {
        for (sig, old) in self.previous.drain(..).rev() {
            // SAFETY: restoring a sigaction previously returned by the kernel.
            unsafe {
                libc::sigaction(sig, &old, std::ptr::null_mut());
            }
        }
    }
}

/// Install `handler` (a function address or SIG_DFL/SIG_IGN) for `sig` with
/// an empty handler mask; returns the previous action.
fn set_handler(
    sig: libc::c_int,
    handler: libc::sighandler_t,
    flags: libc::c_int,
) -> io::Result<libc::sigaction> {
    // SAFETY: sigaction structs are plain data, zero-initialised then filled;
    // `record` only performs an atomic store, which is async-signal-safe.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = handler;
        action.sa_flags = flags;
        libc::sigemptyset(&mut action.sa_mask);
        let mut old: libc::sigaction = std::mem::zeroed();
        if libc::sigaction(sig, &action, &mut old) != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(old)
    }
}

fn cancel_set() -> libc::sigset_t {
    // SAFETY: sigset_t is plain data initialised by sigemptyset.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for sig in CANCEL_SIGNALS {
            libc::sigaddset(&mut set, sig);
        }
        set
    }
}

/// Blocks INT/TERM/HUP for the calling thread until dropped, for sections
/// that must not be interrupted half-way (binary replacement). Signals that
/// arrive meanwhile are delivered when the guard drops. Children are not
/// affected: `sys::exec` resets the mask before exec.
pub struct BlockSignals {
    previous: libc::sigset_t,
}

impl BlockSignals {
    pub fn new() -> Result<BlockSignals> {
        let set = cancel_set();
        // SAFETY: valid sigset pointers; pthread_sigmask affects this thread only.
        unsafe {
            let mut previous: libc::sigset_t = std::mem::zeroed();
            let rc = libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut previous);
            if rc != 0 {
                return Err(Error::msg(format!(
                    "无法屏蔽信号: {}",
                    io::Error::from_raw_os_error(rc)
                )));
            }
            Ok(BlockSignals { previous })
        }
    }
}

impl Drop for BlockSignals {
    fn drop(&mut self) {
        // SAFETY: restores the mask captured in `new`.
        unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &self.previous, std::ptr::null_mut());
        }
    }
}

/// Serializes tests that change process-wide signal state or depend on it
/// (exec timeouts forward pending signals).
#[cfg(test)]
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    fn guard() -> std::sync::MutexGuard<'static, ()> {
        TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn current_handler(sig: libc::c_int) -> libc::sighandler_t {
        unsafe {
            let mut old: libc::sigaction = std::mem::zeroed();
            libc::sigaction(sig, std::ptr::null(), &mut old);
            old.sa_sigaction
        }
    }

    #[test]
    fn scope_records_and_restores() {
        let _g = guard();
        clear();
        let before = current_handler(libc::SIGHUP);
        {
            let _scope = SignalScope::install().unwrap();
            assert_eq!(current_handler(libc::SIGHUP), record_address());
            assert!(check().is_ok());
            unsafe {
                libc::raise(libc::SIGHUP);
            }
            assert_eq!(pending(), Some(libc::SIGHUP));
            let err = check().unwrap_err();
            assert!(err.is_cancelled());
            assert_eq!(err.exit_code(), 130);
            assert!(err.to_string().starts_with("操作被信号 1 中断"));
            clear();
            assert_eq!(pending(), None);
        }
        assert_eq!(current_handler(libc::SIGHUP), before);
    }

    #[test]
    fn nested_scopes_restore_outer_handler() {
        let _g = guard();
        let _outer = SignalScope::install().unwrap();
        {
            let _inner = SignalScope::install().unwrap();
        }
        assert_eq!(current_handler(libc::SIGTERM), record_address());
    }

    #[test]
    fn blocked_signals_are_delivered_on_release() {
        let _g = guard();
        clear();
        let _scope = SignalScope::install().unwrap();
        {
            let _block = BlockSignals::new().unwrap();
            unsafe {
                libc::raise(libc::SIGINT);
            }
            assert_eq!(pending(), None, "blocked while the guard lives");
        }
        assert_eq!(pending(), Some(libc::SIGINT));
        clear();
    }
}
