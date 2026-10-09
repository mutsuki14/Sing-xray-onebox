//! Helper threads of the failover service. The OS may refuse a new thread
//! (EAGAIN under a pids cgroup limit or RLIMIT_NPROC); `Scope::spawn` and
//! `thread::spawn` panic then, which would end the whole service (exit 101,
//! the cores and every relay gone) because of one client. Every helper is
//! therefore started through a [`Spawner`], and each caller handles a
//! refusal where it occurs: a client is refused with `05 FF`, a relay
//! closes its connection, a health check runs on the round's own thread.

use std::io;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{Scope, ScopedJoinHandle};

/// A helper's work.
pub type Task<'scope> = Box<dyn FnOnce() + Send + 'scope>;

/// Starts scoped helper threads (real: [`OsThreads`]; tests inject
/// refusals).
pub trait Spawner: Sync {
    fn spawn<'scope, 'env>(
        &self,
        scope: &'scope Scope<'scope, 'env>,
        name: &'static str,
        task: Task<'scope>,
    ) -> io::Result<ScopedJoinHandle<'scope, ()>>;
}

/// `std::thread::Builder`, which reports a refused thread as an error
/// instead of panicking.
pub struct OsThreads;

impl Spawner for OsThreads {
    fn spawn<'scope, 'env>(
        &self,
        scope: &'scope Scope<'scope, 'env>,
        name: &'static str,
        task: Task<'scope>,
    ) -> io::Result<ScopedJoinHandle<'scope, ()>> {
        std::thread::Builder::new()
            .name(name.to_owned())
            .spawn_scoped(scope, task)
    }
}

/// Run `work(item)` on a helper thread. When the thread is refused the
/// task never ran, and `item` comes back with the error so the caller can
/// still use it (answer the client).
pub fn spawn_with<'scope, 'env, T: Send + 'scope>(
    spawner: &dyn Spawner,
    scope: &'scope Scope<'scope, 'env>,
    name: &'static str,
    item: T,
    work: impl FnOnce(T) + Send + 'scope,
) -> Result<(), (io::Error, T)> {
    let cell = Arc::new(Mutex::new(Some(item)));
    let theirs = Arc::clone(&cell);
    let task: Task<'scope> = Box::new(move || {
        if let Some(item) = take(&theirs) {
            work(item);
        }
    });
    match spawner.spawn(scope, name, task) {
        Ok(_) => Ok(()),
        Err(e) => match take(&cell) {
            Some(item) => Err((e, item)),
            // The spawner ran the task after all: the work is done.
            None => Ok(()),
        },
    }
}

fn take<T>(cell: &Mutex<Option<T>>) -> Option<T> {
    cell.lock().unwrap_or_else(PoisonError::into_inner).take()
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Refuses the next `count` spawns of threads named `name` (EAGAIN, as
    /// under a pids limit); everything else starts normally.
    pub struct Refusing {
        pub name: &'static str,
        left: AtomicUsize,
        refused: AtomicUsize,
    }

    impl Refusing {
        pub fn new(name: &'static str, count: usize) -> Refusing {
            Refusing {
                name,
                left: AtomicUsize::new(count),
                refused: AtomicUsize::new(0),
            }
        }

        /// How many spawns were refused so far.
        pub fn refused(&self) -> usize {
            self.refused.load(Ordering::SeqCst)
        }
    }

    impl Spawner for Refusing {
        fn spawn<'scope, 'env>(
            &self,
            scope: &'scope Scope<'scope, 'env>,
            name: &'static str,
            task: Task<'scope>,
        ) -> io::Result<ScopedJoinHandle<'scope, ()>> {
            let refuse = name == self.name
                && self
                    .left
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                    .is_ok();
            if refuse {
                self.refused.fetch_add(1, Ordering::SeqCst);
                return Err(io::Error::from_raw_os_error(libc::EAGAIN));
            }
            OsThreads.spawn(scope, name, task)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::Refusing;
    use super::*;

    #[test]
    fn refused_threads_hand_the_item_back() {
        let refusing = Refusing::new("x", 1);
        let ran = Mutex::new(Vec::new());
        std::thread::scope(|scope| {
            let first = spawn_with(&refusing, scope, "x", 1, |n| ran.lock().unwrap().push(n));
            let (err, item) = first.unwrap_err();
            assert_eq!((err.raw_os_error(), item), (Some(libc::EAGAIN), 1));
            spawn_with(&refusing, scope, "x", 2, |n| ran.lock().unwrap().push(n)).unwrap();
            spawn_with(&OsThreads, scope, "y", 3, |n| ran.lock().unwrap().push(n)).unwrap();
        });
        let mut ran = ran.into_inner().unwrap();
        ran.sort_unstable();
        assert_eq!(ran, [2, 3], "the refused task never ran");
        assert_eq!(refusing.refused(), 1);
    }
}
