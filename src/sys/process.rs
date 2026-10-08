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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_matches_uid() {
        assert_eq!(is_root(), effective_uid() == 0);
    }
}
