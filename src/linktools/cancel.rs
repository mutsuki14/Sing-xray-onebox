//! Cancellation for one link-tool run: a [`CancelToken`] passed explicitly
//! to every loop, child wait and relay, cancelled either by the user's
//! INT/TERM/HUP (through [`SignalCancel`], which owns a `sys::signal` scope)
//! or programmatically (failover stops on a fatal listener error).
//!
//! Changes from v2: no process-global `STOP` static (D-8.1#24): two runs
//! in one process (the menu) or parallel tests cannot see each other's
//! stop; a signal received before the run started is ignored (v2 reset the
//! flag on install); SIGHUP cancels too (terminal hang-up), like every
//! other long operation of Onebox; the handled signal is cleared when the
//! run ends, so a menu that continues after `failover` (Ctrl+C = normal
//! stop) does not cancel its next operation.

use crate::error::Result;
use crate::sys::signal::{self, SignalScope};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Granularity of [`CancelToken::sleep`]: how late a cancellation may be
/// noticed by a sleeping loop.
const SLEEP_TICK: Duration = Duration::from_millis(50);

#[derive(Debug)]
struct Inner {
    cancelled: AtomicBool,
    /// Receive count of `sys::signal` when the run started; a different
    /// count means the user sent a cancellation signal since. `None` for
    /// tokens that only cancel programmatically.
    baseline: Option<u16>,
}

/// Shared cancellation flag of one run; clones observe the same state.
#[derive(Clone, Debug)]
pub struct CancelToken {
    inner: Arc<Inner>,
}

impl CancelToken {
    /// A token that only [`CancelToken::cancel`] trips (tests, embedding).
    pub fn manual() -> CancelToken {
        CancelToken::with_baseline(None)
    }

    fn with_baseline(baseline: Option<u16>) -> CancelToken {
        CancelToken {
            inner: Arc::new(Inner {
                cancelled: AtomicBool::new(false),
                baseline,
            }),
        }
    }

    pub fn cancel(&self) {
        self.inner.cancelled.store(true, Ordering::SeqCst);
    }

    /// True once cancelled. A signal latches the flag, so later readings
    /// never depend on the signal counter again.
    pub fn is_cancelled(&self) -> bool {
        if self.inner.cancelled.load(Ordering::SeqCst) {
            return true;
        }
        if self.signalled() {
            self.cancel();
            return true;
        }
        false
    }

    fn signalled(&self) -> bool {
        self.inner
            .baseline
            .is_some_and(|start| signal::received().count != start)
    }

    /// Sleep for `duration` unless cancelled first; returns false when the
    /// sleep was cut short by a cancellation.
    pub fn sleep(&self, duration: Duration) -> bool {
        let until = Instant::now() + duration;
        loop {
            if self.is_cancelled() {
                return false;
            }
            let now = Instant::now();
            if now >= until {
                return true;
            }
            std::thread::sleep(SLEEP_TICK.min(until - now));
        }
    }
}

/// Recording INT/TERM/HUP handlers for the duration of a run, wired to a
/// fresh [`CancelToken`]. Dropping it restores the previous handlers and
/// forgets a signal this run handled.
pub struct SignalCancel {
    token: CancelToken,
    _scope: SignalScope,
}

impl SignalCancel {
    pub fn install() -> Result<SignalCancel> {
        // Handlers first, then the baseline: a signal in between is counted.
        let scope = SignalScope::install()?;
        let token = CancelToken::with_baseline(Some(signal::received().count));
        Ok(SignalCancel {
            token,
            _scope: scope,
        })
    }

    pub fn token(&self) -> &CancelToken {
        &self.token
    }
}

impl Drop for SignalCancel {
    fn drop(&mut self) {
        if self.token.signalled() {
            signal::clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::signal::TEST_LOCK;

    #[test]
    fn manual_tokens_are_shared_between_clones() {
        let token = CancelToken::manual();
        let clone = token.clone();
        assert!(!clone.is_cancelled());
        token.cancel();
        assert!(clone.is_cancelled());
        assert!(!clone.sleep(Duration::from_secs(5)), "cut short at once");
    }

    #[test]
    fn sleep_runs_to_completion_without_cancellation() {
        let token = CancelToken::manual();
        let started = Instant::now();
        assert!(token.sleep(Duration::from_millis(60)));
        assert!(started.elapsed() >= Duration::from_millis(60));
    }

    #[test]
    fn a_cancel_from_another_thread_wakes_a_sleeper() {
        let token = CancelToken::manual();
        let remote = token.clone();
        let started = Instant::now();
        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(80));
            remote.cancel();
        });
        assert!(!token.sleep(Duration::from_secs(10)));
        assert!(started.elapsed() < Duration::from_secs(5));
        handle.join().unwrap();
    }

    #[test]
    fn signals_cancel_only_the_run_that_saw_them() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        {
            // A signal recorded by an earlier scope is not this run's.
            let _earlier = SignalScope::install().unwrap();
            unsafe {
                libc::raise(libc::SIGTERM);
            }
        }
        let run = SignalCancel::install().unwrap();
        let token = run.token().clone();
        assert!(!token.is_cancelled(), "old signal ignored");
        unsafe {
            libc::raise(libc::SIGINT);
        }
        assert!(token.is_cancelled());
        assert_eq!(signal::pending(), Some(libc::SIGINT));
        drop(run);
        assert_eq!(signal::pending(), None, "handled signal is cleared");
        assert!(token.is_cancelled(), "the latch survives the scope");
        assert!(!CancelToken::manual().is_cancelled());
    }
}
