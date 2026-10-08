//! The failover state machine (spec D §2.5), reproduced bit for bit from
//! v2: consecutive-failure and consecutive-recovery streaks, a cooldown
//! before switching back to a higher-priority entry, an emergency switch
//! that ignores the cooldown, and no direct fallback (`None` refuses).
//!
//! Before the first switch every healthy entry is available at once; the
//! initial `None → Some` selection counts as a switch, so afterwards an
//! entry needs `recoveries` consecutive successes to (re)gain
//! availability. The cooldown runs from the last switch of any kind.

/// Pure policy over one health result per entry and round.
#[derive(Clone, Debug, PartialEq)]
pub struct FailoverPolicy {
    failures: u32,
    recoveries: u32,
    cooldown: f64,
    bad: Vec<u32>,
    good: Vec<u32>,
    available: Vec<bool>,
    active: Option<usize>,
    last_switch: Option<f64>,
}

impl FailoverPolicy {
    /// `count` entries in priority order; `cooldown` in seconds.
    pub fn new(count: usize, failures: u32, recoveries: u32, cooldown: u64) -> FailoverPolicy {
        FailoverPolicy {
            failures,
            recoveries,
            cooldown: cooldown as f64,
            bad: vec![0; count],
            good: vec![0; count],
            available: vec![false; count],
            active: None,
            last_switch: None,
        }
    }

    pub fn active(&self) -> Option<usize> {
        self.active
    }

    /// Apply one round of `results` (one per entry, in priority order)
    /// observed at `now` seconds; returns the active entry. Like v2, only
    /// entries with a result are updated or considered (extra results are
    /// ignored instead of panicking).
    pub fn update(&mut self, results: &[bool], now: f64) -> Option<usize> {
        let results = &results[..results.len().min(self.good.len())];
        for (i, &ok) in results.iter().enumerate() {
            self.good[i] = if ok { self.good[i].saturating_add(1) } else { 0 };
            self.bad[i] = if ok { 0 } else { self.bad[i].saturating_add(1) };
            if ok && (self.last_switch.is_none() || self.good[i] >= self.recoveries) {
                self.available[i] = true;
            }
            if self.bad[i] >= self.failures {
                self.available[i] = false;
            }
        }
        let candidate = results
            .iter()
            .enumerate()
            .find_map(|(i, &ok)| (ok && self.available[i]).then_some(i));
        let old = self.active;
        match old {
            None => self.active = candidate,
            Some(active) if !self.available[active] => self.active = candidate,
            Some(active) => {
                if let Some(next) = candidate {
                    let since = now - self.last_switch.unwrap_or(f64::NEG_INFINITY);
                    if next < active && since >= self.cooldown && self.good[next] >= self.recoveries
                    {
                        self.active = Some(next);
                    }
                }
            }
        }
        if old != self.active {
            self.last_switch = Some(now);
        }
        self.active
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- v2's three tests, verbatim (golden) ----

    #[test]
    fn failure_streak_not_cumulative() {
        let mut p = FailoverPolicy::new(2, 3, 2, 60);
        assert_eq!(p.update(&[true, true], 0.0), Some(0));
        for (t, ok) in [(1.0, false), (2.0, true), (3.0, false), (4.0, false)] {
            assert_eq!(p.update(&[ok, true], t), Some(0));
        }
        assert_eq!(p.update(&[false, true], 5.0), Some(1));
    }

    #[test]
    fn recovery_needs_streak_and_cooldown() {
        let mut p = FailoverPolicy::new(2, 2, 3, 60);
        p.update(&[true, true], 0.0);
        p.update(&[false, true], 1.0);
        assert_eq!(p.update(&[false, true], 2.0), Some(1));
        for t in [3.0, 4.0, 5.0, 61.0] {
            assert_eq!(p.update(&[true, true], t), Some(1));
        }
        assert_eq!(p.update(&[true, true], 62.0), Some(0));
    }

    #[test]
    fn dead_active_bypasses_cooldown_no_direct() {
        let mut p = FailoverPolicy::new(2, 1, 1, 60);
        assert_eq!(p.update(&[true, true], 0.0), Some(0));
        assert_eq!(p.update(&[false, true], 1.0), Some(1));
        assert_eq!(p.update(&[false, false], 2.0), None);
        assert_eq!(p.update(&[true, false], 3.0), Some(0));
        let mut p = FailoverPolicy::new(3, 1, 2, 0);
        p.update(&[true, false, true], 0.0);
        assert_eq!(p.update(&[false, true, true], 1.0), Some(2));
        assert_eq!(p.update(&[false, true, true], 2.0), Some(1));
    }

    // ---- further consequences of the same rules ----

    #[test]
    fn nothing_healthy_means_no_route() {
        let mut p = FailoverPolicy::new(2, 3, 3, 60);
        assert_eq!(p.update(&[false, false], 0.0), None);
        assert_eq!(p.active(), None);
        // The first healthy round selects without a recovery streak.
        assert_eq!(p.update(&[false, true], 1.0), Some(1));
    }

    #[test]
    fn a_failing_active_stays_until_its_streak_completes() {
        let mut p = FailoverPolicy::new(2, 3, 1, 0);
        assert_eq!(p.update(&[true, true], 0.0), Some(0));
        assert_eq!(p.update(&[false, true], 1.0), Some(0));
        assert_eq!(p.update(&[false, true], 2.0), Some(0));
        assert_eq!(p.update(&[false, true], 3.0), Some(1));
        // Recovered with cooldown 0 and a streak of 1: switch back at once.
        assert_eq!(p.update(&[true, true], 4.0), Some(0));
    }

    #[test]
    fn cooldown_counts_from_the_emergency_switch() {
        let mut p = FailoverPolicy::new(2, 1, 1, 10);
        assert_eq!(p.update(&[true, true], 0.0), Some(0));
        assert_eq!(p.update(&[false, true], 5.0), Some(1), "emergency at t=5");
        assert_eq!(p.update(&[true, true], 14.0), Some(1), "9 s < cooldown");
        assert_eq!(p.update(&[true, true], 15.0), Some(0));
    }

    #[test]
    fn short_result_lists_leave_other_entries_alone() {
        let mut p = FailoverPolicy::new(3, 1, 1, 0);
        assert_eq!(p.update(&[true], 0.0), Some(0));
        assert_eq!(p.update(&[false, true], 1.0), Some(1));
        assert_eq!(p.update(&[], 2.0), Some(1), "no evidence, no change");
        assert_eq!(p.update(&[true, true, true, true], 3.0), Some(0), "extra ignored");
    }
}
