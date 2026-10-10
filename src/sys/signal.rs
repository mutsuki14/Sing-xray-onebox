//! Signal handling: a process-wide cancellation flag set by scoped handlers
//! for SIGINT/SIGTERM/SIGHUP, and a guard that blocks those signals during
//! critical sections (binary swaps, sysctl changes).
//!
//! The flag (plus the reference count of who needs the handlers) is the only
//! global mutable state in the crate. Handlers only update the atomic flag
//! (async-signal-safe); long operations poll [`check`] at safe points
//! (between apply stages) and unwind with `Error::Cancelled`, so rollback
//! runs instead of dying mid-write. Handlers are installed without
//! `SA_RESTART`, so a blocking prompt read returns `EINTR` and the prompter
//! can cancel promptly. `sys::exec` holds a [`WaitScope`] while waiting for
//! children in their own process group and forwards new signals to them.
//!
//! Changes from v2: one flag and one scope type shared by apply, update and
//! BBR (v2 had per-module guards); cancellation surfaces as
//! `Error::Cancelled`, so it keeps exit code 130 through rollback wrappers
//! (B-9.1#16); handler installation is reference-counted, so scopes held by
//! different threads may end in any order; a signal the parent left ignored
//! (`nohup` ignores SIGHUP) stays ignored instead of being turned into a
//! cancellation, so `nohup onebox … &` survives closing the terminal.

use crate::error::{Error, Result};
use std::io;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

/// The signals Onebox treats as "cancel the current operation".
pub const CANCEL_SIGNALS: [libc::c_int; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];

/// The signal flag, packed into one atomic so the handler stays a single
/// lock-free update:
/// - bits 0..8: the pending signal (0 = none), reset by [`clear`];
/// - bits 8..16: the last signal received (never reset);
/// - bits 16..32: how many signals were received (wrapping), so a waiter can
///   tell a new signal from one recorded before it started.
static STATE: AtomicU32 = AtomicU32::new(0);
const PENDING_MASK: u32 = 0xff;
const LAST_SHIFT: u32 = 8;
const COUNT_SHIFT: u32 = 16;

extern "C" fn record(sig: libc::c_int) {
    let sig = (sig as u32) & PENDING_MASK;
    let mut current = STATE.load(Ordering::SeqCst);
    loop {
        let count = (current >> COUNT_SHIFT).wrapping_add(1);
        let next = (count << COUNT_SHIFT) | (sig << LAST_SHIFT) | sig;
        match STATE.compare_exchange_weak(current, next, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return,
            Err(actual) => current = actual,
        }
    }
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

/// The signal received while handlers were installed, if not yet cleared.
pub fn pending() -> Option<i32> {
    match STATE.load(Ordering::SeqCst) & PENDING_MASK {
        0 => None,
        n => Some(n as i32),
    }
}

/// Forget a recorded signal (after it has been handled). The receive
/// counter is kept, so waiters still notice that a signal arrived.
pub fn clear() {
    STATE.fetch_and(!PENDING_MASK, Ordering::SeqCst);
}

/// A reading of the receive counter; compare two readings to detect a
/// signal that arrived in between, even if it was cleared meanwhile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Received {
    pub count: u16,
    /// The last signal received (0 = none yet).
    pub last: i32,
}

pub fn received() -> Received {
    let state = STATE.load(Ordering::SeqCst);
    Received {
        count: (state >> COUNT_SHIFT) as u16,
        last: ((state >> LAST_SHIFT) & PENDING_MASK) as i32,
    }
}

/// `Err(Cancelled)` (exit 130) when a cancellation signal is pending.
pub fn check() -> Result<()> {
    match pending() {
        None => Ok(()),
        Some(n) => Err(Error::Cancelled.wrap(format!("操作被信号 {n} 中断"))),
    }
}

/// Who currently needs the recording handlers. They are installed when the
/// first holder appears and the previous dispositions are restored when the
/// last one leaves, so holders on different threads may come and go in any
/// order. (This bookkeeping and [`STATE`] are the crate's only global state.)
struct Installed {
    owners: usize,
    waiters: usize,
    previous: Vec<(libc::c_int, libc::sigaction)>,
}

static INSTALLED: Mutex<Installed> = Mutex::new(Installed {
    owners: 0,
    waiters: 0,
    previous: Vec::new(),
});

fn installed() -> MutexGuard<'static, Installed> {
    INSTALLED.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Installed {
    fn holders(&self) -> usize {
        self.owners + self.waiters
    }

    /// Install the handlers unless a holder already did. A signal whose
    /// inherited disposition is `SIG_IGN` is left alone: whoever started us
    /// asked the process to survive it (`nohup` for SIGHUP; `main` resets
    /// SIGINT on purpose, see [`reset_interrupt_disposition`]).
    fn install(&mut self) -> Result<()> {
        if self.holders() > 0 {
            return Ok(());
        }
        for sig in CANCEL_SIGNALS {
            match disposition(sig) {
                Ok(current) if current == libc::SIG_IGN => continue,
                Ok(_) => {}
                Err(e) => {
                    self.restore();
                    return Err(Error::msg(format!("无法读取信号处理方式: {e}")));
                }
            }
            match set_handler(sig, record_address(), 0) {
                Ok(old) => self.previous.push((sig, old)),
                Err(e) => {
                    self.restore();
                    return Err(Error::msg(format!("无法安装信号处理器: {e}")));
                }
            }
        }
        Ok(())
    }

    /// Restore the saved dispositions once nobody holds the handlers.
    fn release(&mut self) {
        if self.holders() == 0 {
            self.restore();
        }
    }

    fn restore(&mut self) {
        for (sig, old) in self.previous.drain(..).rev() {
            // SAFETY: restoring a sigaction previously returned by the kernel.
            unsafe {
                libc::sigaction(sig, &old, std::ptr::null_mut());
            }
        }
    }
}

/// Installs recording handlers for INT/TERM/HUP for an operation that polls
/// [`check`] at safe points (the scope's *owner*); the previous dispositions
/// are restored when the last holder drops. Scopes nest. Installing does not
/// clear an already pending signal, so an outer operation's cancellation is
/// not lost. Signals inherited as ignored stay ignored (see the module docs).
pub struct SignalScope {
    _private: (),
}

impl SignalScope {
    pub fn install() -> Result<SignalScope> {
        let mut state = installed();
        state.install()?;
        state.owners += 1;
        Ok(SignalScope { _private: () })
    }
}

impl Drop for SignalScope {
    fn drop(&mut self) {
        let mut state = installed();
        state.owners -= 1;
        state.release();
    }
}

/// Recording handlers held while waiting for a child that cannot see the
/// terminal's signals (it runs in its own process group): the waiter
/// forwards new signals to the child. [`WaitScope::owned`] tells whether a
/// [`SignalScope`] owner was active — then that owner turns the signal into
/// a cancellation; otherwise the waiter must do so itself.
pub struct WaitScope {
    owned: bool,
}

impl WaitScope {
    pub fn acquire() -> Result<WaitScope> {
        let mut state = installed();
        let owned = state.owners > 0;
        state.install()?;
        state.waiters += 1;
        Ok(WaitScope { owned })
    }

    pub fn owned(&self) -> bool {
        self.owned
    }
}

impl Drop for WaitScope {
    fn drop(&mut self) {
        let mut state = installed();
        state.waiters -= 1;
        state.release();
    }
}

/// The current disposition of `sig` (a handler address, SIG_DFL or SIG_IGN).
fn disposition(sig: libc::c_int) -> io::Result<libc::sighandler_t> {
    // SAFETY: a null new action only reads the current one into `old`,
    // a zero-initialised plain-data struct.
    unsafe {
        let mut old: libc::sigaction = std::mem::zeroed();
        if libc::sigaction(sig, std::ptr::null(), &mut old) != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(old.sa_sigaction)
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
    // `record` only performs atomic operations, which are async-signal-safe.
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
/// arrive meanwhile are delivered when the guard drops. Children do not
/// inherit the mask (`sys::exec` resets it before exec), but untimed ones
/// started meanwhile get their own process group ([`cancel_blocked`]), so
/// the terminal's Ctrl+C or hang-up does not reach them either.
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

/// Whether INT, TERM and HUP are all blocked in the calling thread (a
/// [`BlockSignals`] section): `sys::exec` then keeps untimed children out
/// of the terminal's process group as well.
pub fn cancel_blocked() -> bool {
    // SAFETY: a null new set only reads this thread's mask into `current`,
    // a zero-initialised plain-data struct.
    unsafe {
        let mut current: libc::sigset_t = std::mem::zeroed();
        if libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut current) != 0 {
            return false;
        }
        CANCEL_SIGNALS
            .iter()
            .all(|sig| libc::sigismember(&current, *sig) == 1)
    }
}

/// Serializes tests that change process-wide signal state or depend on it
/// (exec timeouts forward pending signals).
#[cfg(test)]
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Tests: `sig` ignored (as `nohup` leaves SIGHUP) until dropped, then the
/// previous action is back. Hold [`TEST_LOCK`] meanwhile.
#[cfg(test)]
pub(crate) struct IgnoredForTest {
    sig: libc::c_int,
    previous: libc::sigaction,
}

#[cfg(test)]
impl IgnoredForTest {
    pub(crate) fn new(sig: libc::c_int) -> IgnoredForTest {
        let previous = set_handler(sig, libc::SIG_IGN, 0).expect("sigaction");
        IgnoredForTest { sig, previous }
    }
}

#[cfg(test)]
impl Drop for IgnoredForTest {
    fn drop(&mut self) {
        // SAFETY: restoring a sigaction previously returned by the kernel.
        unsafe {
            libc::sigaction(self.sig, &self.previous, std::ptr::null_mut());
        }
    }
}

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
        let before = current_handler(libc::SIGTERM);
        {
            let _outer = SignalScope::install().unwrap();
            {
                let _inner = SignalScope::install().unwrap();
            }
            assert_eq!(current_handler(libc::SIGTERM), record_address());
        }
        assert_eq!(current_handler(libc::SIGTERM), before);
    }

    #[test]
    fn holders_may_drop_in_any_order() {
        let _g = guard();
        let before = current_handler(libc::SIGINT);
        let waiter = WaitScope::acquire().unwrap();
        assert!(!waiter.owned(), "no owner yet");
        let owner = SignalScope::install().unwrap();
        assert!(WaitScope::acquire().unwrap().owned());
        drop(waiter);
        assert_eq!(
            current_handler(libc::SIGINT),
            record_address(),
            "the owner still needs the handler"
        );
        drop(owner);
        assert_eq!(current_handler(libc::SIGINT), before);
    }

    #[test]
    fn receive_counter_survives_clear() {
        let _g = guard();
        let _scope = SignalScope::install().unwrap();
        let start = received();
        unsafe {
            libc::raise(libc::SIGTERM);
        }
        clear();
        let now = received();
        assert_eq!(pending(), None);
        assert_ne!(now.count, start.count, "a waiter still sees the signal");
        assert_eq!(now.last, libc::SIGTERM);
        unsafe {
            libc::raise(libc::SIGTERM);
        }
        assert_ne!(received().count, now.count, "repeated signals are new");
        clear();
    }

    #[test]
    fn inherited_ignored_signals_stay_ignored() {
        let _g = guard();
        clear();
        let ignored = IgnoredForTest::new(libc::SIGHUP);
        let term_before = current_handler(libc::SIGTERM);
        {
            let _scope = SignalScope::install().unwrap();
            assert_eq!(current_handler(libc::SIGHUP), libc::SIG_IGN, "nohup kept");
            assert_eq!(current_handler(libc::SIGTERM), record_address());
            let start = received();
            unsafe {
                libc::raise(libc::SIGHUP);
            }
            assert_eq!(pending(), None);
            assert_eq!(received(), start, "an ignored hang-up is not counted");
            let _waiter = WaitScope::acquire().unwrap();
            assert_eq!(current_handler(libc::SIGHUP), libc::SIG_IGN);
        }
        assert_eq!(current_handler(libc::SIGHUP), libc::SIG_IGN);
        assert_eq!(current_handler(libc::SIGTERM), term_before);
        drop(ignored);
        assert_ne!(current_handler(libc::SIGHUP), libc::SIG_IGN);
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
