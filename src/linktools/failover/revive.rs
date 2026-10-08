//! Restarting client cores that die while failover runs (D-8.1#26; v2
//! left a crashed core unhealthy forever). After each health round the
//! monitor restarts dead cores: at once, then — after failed attempts —
//! with an exponential backoff of 2, 4 … 32 health rounds. A restarted core gets a
//! new port and credential; running relays never hold a proxy (only the
//! endpoint they connected to), so replacing it is safe. The policy is not
//! reset: the entry regains availability through its normal recovery
//! streak.

use crate::error::Result;
use crate::linktools::cancel::CancelToken;
use crate::linktools::core_client::Proxy;
use crate::ui::out;
use std::sync::{Arc, PoisonError, RwLock};

/// Longest wait between restart attempts, in health rounds.
pub const MAX_BACKOFF_ROUNDS: u64 = 32;

/// The current proxy of one entry, replaceable after a restart.
pub struct ProxySlot {
    current: RwLock<Arc<dyn Proxy>>,
}

impl ProxySlot {
    pub fn new(proxy: Box<dyn Proxy>) -> ProxySlot {
        ProxySlot {
            current: RwLock::new(Arc::from(proxy)),
        }
    }

    pub fn get(&self) -> Arc<dyn Proxy> {
        self.current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Install `proxy`; the old one is dropped (stopped) once unused.
    pub fn replace(&self, proxy: Box<dyn Proxy>) {
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = Arc::from(proxy);
    }
}

/// Restart bookkeeping of one entry.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Backoff {
    failures: u32,
    next_round: u64,
    announced: bool,
}

impl Backoff {
    pub fn due(&self, round: u64) -> bool {
        round >= self.next_round
    }

    /// A failed attempt in `round`: wait 2^failures rounds (capped).
    pub fn failed(&mut self, round: u64) {
        self.failures = self.failures.saturating_add(1);
        let wait = 1u64 << self.failures.min(MAX_BACKOFF_ROUNDS.trailing_zeros());
        self.next_round = round + wait;
    }

    pub fn succeeded(&mut self) {
        *self = Backoff::default();
    }
}

/// Restart every dead core whose backoff is due (stops early when
/// cancelled). `restart(i)` starts a fresh proxy for entry `i`.
pub fn revive(
    ids: &[String],
    slots: &[ProxySlot],
    backoff: &mut [Backoff],
    round: u64,
    restart: &dyn Fn(usize) -> Result<Box<dyn Proxy>>,
    cancel: &CancelToken,
) {
    for (i, (slot, state)) in slots.iter().zip(backoff.iter_mut()).enumerate() {
        if cancel.is_cancelled() {
            return;
        }
        let Some(code) = slot.get().exited() else {
            continue;
        };
        let id = ids.get(i).map_or("?", String::as_str);
        if !state.announced {
            state.announced = true;
            out::warn(format!(
                "入口 {id} 的客户端内核已退出（退出码 {code}），将自动重新启动"
            ));
        }
        if !state.due(round) {
            continue;
        }
        match restart(i) {
            Ok(proxy) => {
                slot.replace(proxy);
                state.succeeded();
                out::info(format!("入口 {id} 的客户端内核已重新启动"));
            }
            Err(e) => {
                state.failed(round);
                out::warn(format!("入口 {id} 的客户端内核重新启动失败: {e}"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use crate::linktools::testutil::FakeProxy;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn backoff_doubles_up_to_the_cap() {
        let mut b = Backoff::default();
        assert!(b.due(0));
        let mut waits = Vec::new();
        let mut round = 0;
        for _ in 0..8 {
            b.failed(round);
            waits.push(b.next_round - round);
            round = b.next_round;
        }
        assert_eq!(waits, [2, 4, 8, 16, 32, 32, 32, 32]);
        assert!(!b.due(round - 1) && b.due(round));
        b.succeeded();
        assert_eq!(b, Backoff::default());
    }

    #[test]
    fn dead_cores_are_replaced_when_due() {
        let ids = vec!["a".to_string(), "b".to_string()];
        let slots = vec![
            ProxySlot::new(Box::new(FakeProxy::new(1))),
            ProxySlot::new(Box::new(FakeProxy::new(2))),
        ];
        slots[0].get().terminate();
        let calls = AtomicUsize::new(0);
        let fail = std::sync::atomic::AtomicBool::new(true);
        let restart = |i: usize| -> Result<Box<dyn Proxy>> {
            calls.fetch_add(1, Ordering::SeqCst);
            if fail.load(Ordering::SeqCst) {
                return Err(Error::msg("客户端内核启动超时"));
            }
            Ok(Box::new(FakeProxy::new(100 + i as u16)))
        };
        let mut backoff = vec![Backoff::default(); 2];
        let cancel = CancelToken::manual();
        revive(&ids, &slots, &mut backoff, 0, &restart, &cancel);
        assert_eq!(calls.load(Ordering::SeqCst), 1, "only the dead core");
        revive(&ids, &slots, &mut backoff, 1, &restart, &cancel);
        assert_eq!(calls.load(Ordering::SeqCst), 1, "backing off until round 2");
        fail.store(false, Ordering::SeqCst);
        revive(&ids, &slots, &mut backoff, 2, &restart, &cancel);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(slots[0].get().endpoint().port, 100);
        assert_eq!(slots[0].get().exited(), None);
        assert_eq!(slots[1].get().endpoint().port, 2, "healthy core untouched");
        assert_eq!(backoff[0], Backoff::default());

        cancel.cancel();
        slots[1].get().terminate();
        revive(&ids, &slots, &mut backoff, 3, &restart, &cancel);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "no restarts once cancelled"
        );
    }
}
