//! Per-failed-op exponential backoff schedule.
//!
//! ADR-0054 §6 specifies "failed netlink ops retry with exponential
//! backoff from 100 ms to a 5 second cap, with jitter". The schedule
//! is per-op-key rather than per-actor so a single stuck operation
//! doesn't gate unrelated successful ones.
//!
//! Keys are `(EvpnInstanceId, MacAddress)`, the same shape used
//! throughout the diff pass. The schedule advances each time the
//! actor records a failure for the key and resets each time a
//! reconcile pass succeeds for it.
//!
//! ## Determinism in tests
//!
//! Jitter uses a small linear congruential generator seeded
//! deterministically (default seed `0xa55a`). Tests that need exact
//! timings can construct [`RetrySchedule`] with a fixed seed and
//! disable jitter via [`RetrySchedule::with_jitter`]. The actor
//! constructs its own schedule with the default seed at startup —
//! good enough to spread retries across actors without needing a
//! cryptographic RNG dependency.

use std::collections::BTreeMap;
use std::time::Duration;

use rustbgpd_evpn::{EvpnInstanceId, MacAddress};

/// Initial backoff after the first failure, in milliseconds.
pub const BACKOFF_INITIAL_MS: u64 = 100;
/// Cap on backoff in milliseconds regardless of how many consecutive
/// failures occurred.
pub const BACKOFF_CAP_MS: u64 = 5_000;
/// Initial backoff after the first failure.
pub const BACKOFF_INITIAL: Duration = Duration::from_millis(BACKOFF_INITIAL_MS);
/// Cap on backoff regardless of how many consecutive failures occurred.
pub const BACKOFF_CAP: Duration = Duration::from_millis(BACKOFF_CAP_MS);
/// Geometric multiplier on each consecutive failure.
pub const BACKOFF_FACTOR: u32 = 2;

/// Per-op retry tracker.
///
/// Entries appear when [`Self::record_failure`] is called for a key
/// that wasn't tracked, and disappear when [`Self::record_success`]
/// runs against a tracked key. The actor consults
/// [`Self::earliest_due`] at each reconcile pass to decide when
/// previously-failed ops are next ready to re-attempt.
#[derive(Debug)]
pub struct RetrySchedule {
    entries: BTreeMap<(EvpnInstanceId, MacAddress), RetryState>,
    rng_state: u64,
    jitter_enabled: bool,
}

#[derive(Debug, Clone, Copy)]
struct RetryState {
    /// Number of consecutive failures recorded for this key.
    consecutive_failures: u32,
    /// When the next retry is due, in milliseconds since the actor
    /// epoch (provided by the caller via [`RetrySchedule::record_failure`]).
    next_due_ms: u64,
}

impl RetrySchedule {
    /// New schedule with default deterministic jitter seed.
    #[must_use]
    pub fn new() -> Self {
        Self::with_seed(0x_a55a)
    }

    /// Construct with an explicit RNG seed (for reproducible tests).
    #[must_use]
    pub fn with_seed(seed: u64) -> Self {
        Self {
            entries: BTreeMap::new(),
            rng_state: seed,
            jitter_enabled: true,
        }
    }

    /// Enable / disable jitter. Disabled in some unit tests so the
    /// asserted backoff window is exact.
    #[must_use]
    pub fn with_jitter(mut self, enabled: bool) -> Self {
        self.jitter_enabled = enabled;
        self
    }

    /// Record a failure for `(vni, mac)` at `now_ms`. Returns the
    /// scheduled next-attempt timestamp (also stored internally).
    pub fn record_failure(&mut self, vni: EvpnInstanceId, mac: MacAddress, now_ms: u64) -> u64 {
        let consecutive = self
            .entries
            .get(&(vni, mac))
            .map_or(1, |s| s.consecutive_failures.saturating_add(1));
        let backoff_ms = self.compute_backoff_ms(consecutive);
        let next_due_ms = now_ms.saturating_add(backoff_ms);
        self.entries.insert(
            (vni, mac),
            RetryState {
                consecutive_failures: consecutive,
                next_due_ms,
            },
        );
        next_due_ms
    }

    /// Drop the retry tracking for `(vni, mac)` — called after a
    /// successful apply.
    pub fn record_success(&mut self, vni: EvpnInstanceId, mac: MacAddress) {
        self.entries.remove(&(vni, mac));
    }

    /// Earliest `next_due_ms` across all tracked keys, or `None` if no
    /// retries are pending. The actor uses this to set its retry
    /// timer.
    #[must_use]
    pub fn earliest_due(&self) -> Option<u64> {
        self.entries.values().map(|s| s.next_due_ms).min()
    }

    /// `Some(next_due_ms)` if `(vni, mac)` is currently in the retry
    /// schedule, `None` otherwise. The reconcile actor reads this in
    /// the apply path to skip ops whose backoff hasn't elapsed; the
    /// outer `tokio::select!` re-fires on the retry timer when the
    /// deadline arrives.
    #[must_use]
    pub fn next_due_for(&self, vni: EvpnInstanceId, mac: MacAddress) -> Option<u64> {
        self.entries.get(&(vni, mac)).map(|s| s.next_due_ms)
    }

    /// Keys whose retry is due at or before `now_ms`.
    #[must_use]
    pub fn keys_due(&self, now_ms: u64) -> Vec<(EvpnInstanceId, MacAddress)> {
        self.entries
            .iter()
            .filter_map(|(&k, s)| (s.next_due_ms <= now_ms).then_some(k))
            .collect()
    }

    /// Number of tracked failed keys (for metrics / diagnostics).
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.entries.len()
    }

    /// `true` if no failures are tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Compute the backoff for `consecutive` failures (>= 1) in
    /// milliseconds. Pure function so unit tests can assert windows.
    fn compute_backoff_ms(&mut self, consecutive: u32) -> u64 {
        // Geometric growth: initial * factor^(consecutive-1), capped.
        // 2^20 ms ≈ 17 min, far past the cap, so clamp the exponent.
        let exp = consecutive.saturating_sub(1).min(20);
        let raw_ms =
            BACKOFF_INITIAL_MS.saturating_mul(u64::from(BACKOFF_FACTOR.saturating_pow(exp)));
        let capped_ms = raw_ms.min(BACKOFF_CAP_MS);

        if !self.jitter_enabled {
            return capped_ms;
        }

        // Apply ±25% jitter via a small LCG so tests are deterministic
        // when seeded. Stays in u64 throughout: pct in 0..=50, so
        // delta = capped * pct / 100 fits, and we add or subtract
        // depending on whether pct > 25.
        self.rng_state = self
            .rng_state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let jitter_pct = (self.rng_state >> 48) % 51; // 0..=50
        if jitter_pct >= 25 {
            let bonus_pct = jitter_pct - 25;
            capped_ms.saturating_add(capped_ms.saturating_mul(bonus_pct) / 100)
        } else {
            let penalty_pct = 25 - jitter_pct;
            let delta = capped_ms.saturating_mul(penalty_pct) / 100;
            capped_ms.saturating_sub(delta).max(1)
        }
    }
}

impl Default for RetrySchedule {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vni(n: u32) -> EvpnInstanceId {
        EvpnInstanceId::new(n).unwrap()
    }
    fn mac(b: u8) -> MacAddress {
        MacAddress::new([b; 6])
    }

    #[test]
    fn first_failure_uses_initial_backoff_no_jitter() {
        let mut s = RetrySchedule::new().with_jitter(false);
        let due = s.record_failure(vni(100), mac(1), 0);
        assert_eq!(due, BACKOFF_INITIAL_MS);
    }

    #[test]
    fn consecutive_failures_double_until_cap() {
        let mut s = RetrySchedule::new().with_jitter(false);
        let d1 = s.record_failure(vni(100), mac(1), 0);
        let d2 = s.record_failure(vni(100), mac(1), 0);
        let d3 = s.record_failure(vni(100), mac(1), 0);
        assert_eq!(d1, 100);
        assert_eq!(d2, 200);
        assert_eq!(d3, 400);
    }

    #[test]
    fn backoff_caps_at_5s() {
        let mut s = RetrySchedule::new().with_jitter(false);
        // 2^7 * 100ms = 12_800ms, well past the 5s cap.
        for _ in 0..15 {
            s.record_failure(vni(100), mac(1), 0);
        }
        let earliest = s.earliest_due().unwrap();
        assert_eq!(earliest, BACKOFF_CAP_MS);
    }

    #[test]
    fn record_success_clears_tracking() {
        let mut s = RetrySchedule::new();
        s.record_failure(vni(100), mac(1), 0);
        assert_eq!(s.pending_count(), 1);
        s.record_success(vni(100), mac(1));
        assert!(s.is_empty());
    }

    #[test]
    fn jitter_stays_within_25_percent_band() {
        let mut s = RetrySchedule::with_seed(42);
        for _ in 0..100 {
            let due = s.record_failure(vni(100), mac(1), 0);
            // First failure uses 100ms base ± 25% → [75, 125].
            // After ten record_failure calls the cap dominates so we
            // reset by clearing the schedule between samples.
            assert!((75..=125).contains(&due), "due = {due}");
            s.record_success(vni(100), mac(1));
        }
    }

    #[test]
    fn keys_due_filters_by_now_ms() {
        let mut s = RetrySchedule::new().with_jitter(false);
        s.record_failure(vni(100), mac(1), 0); // due at 100
        s.record_failure(vni(200), mac(2), 0); // due at 100
        // At now_ms=50, neither is due.
        assert!(s.keys_due(50).is_empty());
        // At now_ms=100, both are due.
        assert_eq!(s.keys_due(100).len(), 2);
    }

    #[test]
    fn earliest_due_returns_min_across_tracked_keys() {
        let mut s = RetrySchedule::new().with_jitter(false);
        s.record_failure(vni(100), mac(1), 1000); // due at 1100
        s.record_failure(vni(200), mac(2), 0); // due at 100
        assert_eq!(s.earliest_due(), Some(100));
    }
}
