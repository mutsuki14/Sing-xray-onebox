//! Facts about the current process: effective user.

/// Effective user id of this process.
pub fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// True when running with root privileges.
pub fn is_root() -> bool {
    effective_uid() == 0
}

/// Send `signal` to the single process `pid`. Returns `Ok(false)` when no
/// such process exists (ESRCH). Pids below 2 are refused: `kill(0)` and
/// `kill(-1)` would signal whole groups, and pid 1 is init.
pub fn send_signal(pid: u32, signal: i32) -> std::io::Result<bool> {
    let target = libc::pid_t::try_from(pid)
        .ok()
        .filter(|p| *p >= 2)
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    // SAFETY: kill on a positive pid touches no memory; errors come via errno.
    if unsafe { libc::kill(target, signal) } == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ESRCH) => Ok(false),
        _ => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_matches_uid() {
        assert_eq!(is_root(), effective_uid() == 0);
    }

    #[test]
    fn signals_single_processes_only() {
        for pid in [0, 1, u32::MAX] {
            assert!(send_signal(pid, 0).is_err(), "pid {pid}");
        }
        assert!(send_signal(std::process::id(), 0).unwrap());
    }
}
