//! Signal handling: a process-wide cancellation flag set by scoped handlers
//! for SIGINT/SIGTERM/SIGHUP, and a guard that blocks those signals during
//! critical sections (binary swaps, sysctl changes).

/// Restore the default SIGINT disposition (a bootstrap shell may have left it
/// ignored for background children).
pub fn reset_interrupt_disposition() {
    // SAFETY: setting a standard disposition for a valid signal number.
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_DFL);
    }
}
