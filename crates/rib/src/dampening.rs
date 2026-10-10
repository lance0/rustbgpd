//! Pure RFC 2439 penalty accounting, without received-route or actor hooks.
//!
//! One owner represents one source peer. Its caller supplies elapsed monotonic
//! time, classifies real path changes, and owns any held routes. Nothing here
//! selects, withdraws, or announces a route.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::ops::RangeBounds;
use std::time::Duration;

use rustbgpd_wire::Prefix;

const TICK_SECONDS: u64 = 10;

/// Validated penalty parameters. The default suppress threshold follows RFC
/// 7196 and RIPE-580; the ceiling still follows RFC 2439's maximum hold time.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DampeningParameters {
    half_life: u32,
    reuse: u32,
    suppress: u32,
    max_suppress_time: u32,
    ceiling: f64,
}

/// A rejected parameter, with a field name suitable for configuration errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DampeningParameterError {
    /// Parameter name.
    pub field: &'static str,
    /// Why the parameter is invalid.
    pub reason: String,
}

impl fmt::Display for DampeningParameterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.field, self.reason)
    }
}

impl std::error::Error for DampeningParameterError {}

impl Default for DampeningParameters {
    fn default() -> Self {
        Self {
            half_life: 900,
            reuse: 750,
            suppress: 6000,
            max_suppress_time: 3600,
            ceiling: 12_000.0,
        }
    }
}

impl DampeningParameters {
    /// Validate the timer and threshold relationships.
    ///
    /// # Errors
    ///
    /// Returns the invalid field and its constraint.
    pub fn new(
        half_life: u32,
        reuse: u32,
        suppress: u32,
        max_suppress_time: u32,
    ) -> Result<Self, DampeningParameterError> {
        let invalid = |field, reason: String| DampeningParameterError { field, reason };
        if !(60..=2700).contains(&half_life) {
            return Err(invalid("half_life", "must be 60..=2700 seconds".into()));
        }
        if !(1..=49_999).contains(&reuse) {
            return Err(invalid("reuse", "must be 1..=49999".into()));
        }
        if suppress <= reuse || suppress > 50_000 {
            return Err(invalid(
                "suppress",
                "must exceed reuse and be at most 50000".into(),
            ));
        }
        if max_suppress_time < half_life || max_suppress_time > 14_400 {
            return Err(invalid(
                "max_suppress_time",
                "must be at least half_life and at most 14400 seconds".into(),
            ));
        }
        let ceiling =
            f64::from(reuse) * (f64::from(max_suppress_time) / f64::from(half_life)).exp2();
        if ceiling > 1_000_000.0 {
            return Err(invalid(
                "max_suppress_time",
                "computed penalty ceiling must be at most 1000000".into(),
            ));
        }
        if f64::from(suppress) > ceiling {
            let minimum =
                (f64::from(half_life) * (f64::from(suppress) / f64::from(reuse)).log2()).ceil();
            return Err(invalid(
                "suppress",
                format!(
                    "exceeds penalty ceiling {ceiling:.0}; max_suppress_time must be at least {minimum:.0} seconds"
                ),
            ));
        }
        Ok(Self {
            half_life,
            reuse,
            suppress,
            max_suppress_time,
            ceiling,
        })
    }

    /// Maximum accumulated penalty for these timers.
    #[must_use]
    pub const fn ceiling(self) -> f64 {
        self.ceiling
    }
}

/// Received path identity within one source peer, including Add-Path ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DampeningKey {
    /// Received unicast prefix.
    pub prefix: Prefix,
    /// Received Add-Path ID, or zero without Add-Path.
    pub path_id: u32,
}

/// Caller-classified input. Unknown withdrawals and refresh/stale replays must
/// be classified by the received-route owner before calling this engine.
#[derive(Clone, Copy, Debug)]
pub enum DampeningEvent {
    /// Withdrawal of a known path: 1000 penalty units.
    Withdrawal,
    /// Replacement of a fresh path with changed attributes: 500 units.
    AttributeChange,
    /// First/identical announcement or an exempt replay: no added penalty.
    Announcement,
}

impl DampeningEvent {
    const fn penalty(self) -> u32 {
        match self {
            Self::Withdrawal => 1000,
            Self::AttributeChange => 500,
            Self::Announcement => 0,
        }
    }
}

/// Current penalty state. Penalties retain fractional precision across touches.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DampeningState {
    /// Decayed, unrounded penalty.
    pub penalty: f64,
    /// Hysteresis state: suppress at the cutoff, reuse strictly below reuse.
    pub suppressed: bool,
    /// Number of charged events since this history entry was created.
    pub flap_count: u64,
    /// Monotonic time of the entry's first charged event.
    pub first_flap: Duration,
}

/// A read-only view at a caller-supplied observation time.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DampeningInspection {
    /// Penalty is decayed for the observation; suppression remains the stored
    /// eligibility state until a mutating operation processes the transition.
    pub state: DampeningState,
    /// Last input write, comparable only within this engine instance.
    pub revision: u64,
    /// Existing scheduled deadline; inspecting does not reschedule it.
    pub due: Duration,
}

struct History {
    state: DampeningState,
    revision: u64,
    updated: Duration,
    due: Duration,
}

/// Result of one bounded due-work call; reuse never carries a saved route.
#[derive(Debug, Default)]
pub struct DampeningDue {
    /// Number of history entries examined, including reclaim-only entries.
    pub processed: usize,
    /// Keys that changed from suppressed to reusable.
    pub reused: Vec<DampeningKey>,
    /// Keys whose history was reclaimed below reuse / 2.
    pub reclaimed: Vec<DampeningKey>,
}

/// Per-source history and removable schedule. Repeated flaps replace their
/// existing deadline, so schedule memory is proportional to history entries.
pub struct DampeningEngine {
    parameters: DampeningParameters,
    history: BTreeMap<DampeningKey, History>,
    schedule: BTreeSet<(Duration, DampeningKey)>,
    now: Duration,
    revision: u64,
}

impl DampeningEngine {
    /// Create an empty owner; stable paths allocate no history.
    #[must_use]
    pub fn new(parameters: DampeningParameters) -> Self {
        Self {
            parameters,
            history: BTreeMap::new(),
            schedule: BTreeSet::new(),
            now: Duration::ZERO,
            revision: 0,
        }
    }

    /// Number of paths with retained history.
    #[must_use]
    pub fn len(&self) -> usize {
        self.history.len()
    }

    /// Whether there is no history or scheduled work.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.history.is_empty()
    }

    /// Earliest due tick, without scanning history.
    #[must_use]
    pub fn next_due(&self) -> Option<Duration> {
        self.schedule.first().map(|(due, _)| *due)
    }

    /// Latest input write. Timer decay preserves each entry's input revision.
    /// A clear cursor can retain this cutoff and skip later input writes.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Inspect one entry without changing eligibility, scheduling, or time.
    ///
    /// # Panics
    ///
    /// Panics if the observation predates the engine's last mutation time.
    #[must_use]
    pub fn inspect(&self, key: DampeningKey, now: Duration) -> Option<DampeningInspection> {
        assert!(now >= self.now, "dampening observation must be monotonic");
        self.history
            .get(&key)
            .map(|history| self.inspection(history, now))
    }

    /// Lazily inspect a key range. Callers bound examined entries with `take`
    /// and retain the last examined key when continuing a scoped operation.
    ///
    /// # Panics
    ///
    /// Panics for invalid range bounds or an observation before the last mutation.
    pub fn inspect_range(
        &self,
        range: impl RangeBounds<DampeningKey>,
        now: Duration,
    ) -> impl DoubleEndedIterator<Item = (DampeningKey, DampeningInspection)> + '_ {
        assert!(now >= self.now, "dampening observation must be monotonic");
        self.history
            .range(range)
            .map(move |(key, history)| (*key, self.inspection(history, now)))
    }

    fn inspection(&self, history: &History, now: Duration) -> DampeningInspection {
        let mut state = history.state;
        state.penalty *= self.decay_factor(history.updated, now);
        DampeningInspection {
            state,
            revision: history.revision,
            due: history.due,
        }
    }

    /// Remove exactly one history entry and its deadline. This never announces
    /// a route; the caller must resolve any current held value separately.
    pub fn remove(&mut self, key: DampeningKey) -> bool {
        let Some(history) = self.history.remove(&key) else {
            return false;
        };
        self.schedule.remove(&(history.due, key));
        true
    }

    /// Retire at most `budget` entries in key order, including their deadlines.
    /// Returned keys contain no saved routes and need current-owner validation
    /// before any caller releases a held value.
    pub fn retire(&mut self, budget: usize) -> Vec<DampeningKey> {
        let mut removed = Vec::new();
        while removed.len() < budget {
            let Some((key, history)) = self.history.pop_first() else {
                break;
            };
            self.schedule.remove(&(history.due, key));
            removed.push(key);
        }
        removed
    }

    fn advance(&mut self, now: Duration) {
        assert!(now >= self.now, "dampening time must be monotonic");
        let horizon = Duration::from_secs(
            u64::from(self.parameters.max_suppress_time)
                + u64::from(self.parameters.half_life)
                + TICK_SECONDS,
        );
        assert!(
            now <= Duration::MAX
                .checked_sub(horizon)
                .expect("bounded dampening horizon"),
            "dampening time exceeds scheduling range"
        );
        self.now = now;
    }

    fn decay(&self, history: &mut History, now: Duration) {
        history.state.penalty *= self.decay_factor(history.updated, now);
        history.updated = now;
    }

    fn decay_factor(&self, updated: Duration, now: Duration) -> f64 {
        let elapsed = now
            .checked_sub(updated)
            .expect("monotonic time checked before decay");
        (-elapsed.as_secs_f64() / f64::from(self.parameters.half_life)).exp2()
    }

    fn due(&self, state: DampeningState, now: Duration) -> Duration {
        let threshold = f64::from(self.parameters.reuse) / if state.suppressed { 1.0 } else { 2.0 };
        let seconds = f64::from(self.parameters.half_life) * (state.penalty / threshold).log2();
        let crossing = now + Duration::from_secs_f64(seconds.max(0.0));
        // Both reuse and reclaim are strict comparisons. The first tick
        // strictly AFTER equality avoids rescheduling at the same due time.
        Duration::from_secs((crossing.as_secs() / TICK_SECONDS + 1) * TICK_SECONDS)
    }

    /// Apply a classified event at elapsed monotonic time.
    ///
    /// Returns no state for a stable announcement or history reclaimed below
    /// reuse / 2. The caller owns route presence; this engine never retains it.
    ///
    /// # Panics
    ///
    /// Panics if the caller moves its monotonic clock backwards or supplies a
    /// time too close to `Duration::MAX` to represent the scheduling horizon,
    /// or exhausts the engine's input revision counter.
    pub fn record(
        &mut self,
        key: DampeningKey,
        event: DampeningEvent,
        now: Duration,
    ) -> Option<DampeningState> {
        // Check exhaustion before removing retained history or its schedule.
        let revision = self
            .revision
            .checked_add(1)
            .expect("dampening input revision exhausted");
        self.advance(now);
        let mut history = if let Some(mut history) = self.history.remove(&key) {
            self.schedule.remove(&(history.due, key));
            self.decay(&mut history, now);
            history
        } else {
            if event.penalty() == 0 {
                return None;
            }
            History {
                state: DampeningState {
                    penalty: 0.0,
                    suppressed: false,
                    flap_count: 0,
                    first_flap: now,
                },
                revision,
                updated: now,
                due: now,
            }
        };
        self.revision = revision;
        history.revision = revision;
        history.state.penalty =
            (history.state.penalty + f64::from(event.penalty())).min(self.parameters.ceiling);
        if event.penalty() != 0 {
            history.state.flap_count = history.state.flap_count.saturating_add(1);
        }
        history.state.suppressed = history.state.penalty
            >= f64::from(if history.state.suppressed {
                self.parameters.reuse
            } else {
                self.parameters.suppress
            });
        // A charged value can start below the reclaim floor for a valid high
        // reuse threshold. Re-announcements must not erase it before its due
        // tick, or real withdrawal/re-announcement flaps never accumulate.
        if event.penalty() == 0
            && now >= history.due
            && history.state.penalty < f64::from(self.parameters.reuse) / 2.0
        {
            return None;
        }
        history.due = self.due(history.state, now);
        let state = history.state;
        self.schedule.insert((history.due, key));
        self.history.insert(key, history);
        Some(state)
    }

    /// Process at most `budget` due entries. A late call may both reuse and
    /// reclaim the same key. Returned keys refer to current caller-owned state.
    ///
    /// # Panics
    ///
    /// Panics if the caller moves its monotonic clock backwards or supplies a
    /// time too close to `Duration::MAX` to represent the scheduling horizon.
    pub fn process_due(&mut self, now: Duration, budget: usize) -> DampeningDue {
        self.advance(now);
        let mut result = DampeningDue::default();
        while result.processed < budget {
            let Some(&(due, key)) = self.schedule.first() else {
                break;
            };
            if due > now {
                break;
            }
            self.schedule.pop_first();
            let mut history = self
                .history
                .remove(&key)
                .expect("scheduled dampening history exists");
            result.processed += 1;
            self.decay(&mut history, now);
            if history.state.suppressed && history.state.penalty < f64::from(self.parameters.reuse)
            {
                history.state.suppressed = false;
                result.reused.push(key);
            }
            if history.state.penalty < f64::from(self.parameters.reuse) / 2.0 {
                result.reclaimed.push(key);
            } else {
                history.due = self.due(history.state, now);
                self.schedule.insert((history.due, key));
                self.history.insert(key, history);
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustbgpd_wire::Ipv4Prefix;

    fn key(path_id: u32) -> DampeningKey {
        DampeningKey {
            prefix: Prefix::V4(Ipv4Prefix::new("192.0.2.0".parse().unwrap(), 24)),
            path_id,
        }
    }

    #[test]
    fn inspection_decays_without_reuse_reclaim_or_clock_mutation() {
        let mut engine = DampeningEngine::new(DampeningParameters::default());
        for _ in 0..6 {
            engine.record(key(0), DampeningEvent::Withdrawal, Duration::ZERO);
        }
        let before = engine.inspect(key(0), Duration::ZERO).unwrap();
        let view = engine.inspect(key(0), Duration::from_secs(10_000)).unwrap();
        assert!(view.state.penalty < 375.0);
        assert!(
            view.state.suppressed,
            "inspection cannot release a held path"
        );
        assert_eq!(view.revision, before.revision);
        assert_eq!(view.due, before.due);
        assert_eq!(engine.len(), 1);
        assert_eq!(engine.schedule.len(), 1);
        assert_eq!(engine.inspect(key(0), Duration::ZERO), Some(before));
        let due = engine.process_due(Duration::from_secs(10_000), 1);
        assert_eq!(due.reused, [key(0)]);
        assert_eq!(due.reclaimed, [key(0)]);
    }

    #[test]
    fn scoped_revision_cutoff_preserves_new_input_and_timer_keeps_old_revision() {
        let mut engine = DampeningEngine::new(DampeningParameters::default());
        for id in 0..3 {
            for _ in 0..6 {
                engine.record(key(id), DampeningEvent::Withdrawal, Duration::ZERO);
            }
        }
        let cutoff = engine.revision();
        let upper = engine
            .inspect_range(.., Duration::ZERO)
            .next_back()
            .unwrap()
            .0;
        assert_eq!(upper, key(2));
        assert_eq!(
            engine.process_due(Duration::from_secs(2710), 1).reused,
            [key(0)]
        );
        assert!(
            engine
                .inspect(key(0), Duration::from_secs(2710))
                .unwrap()
                .revision
                <= cutoff
        );
        engine.record(
            key(1),
            DampeningEvent::AttributeChange,
            Duration::from_secs(2710),
        );
        engine.record(
            key(3),
            DampeningEvent::Withdrawal,
            Duration::from_secs(2710),
        );
        let candidates: Vec<_> = engine
            .inspect_range(key(0)..=upper, Duration::from_secs(2710))
            .take(3)
            .map(|(key, view)| (key, view.revision))
            .collect();
        for (key, revision) in candidates {
            if revision <= cutoff {
                assert!(engine.remove(key));
            }
        }
        assert_eq!(
            engine
                .inspect_range(.., Duration::from_secs(2710))
                .map(|(key, _)| key)
                .collect::<Vec<_>>(),
            [key(1), key(3)]
        );
        assert_eq!(engine.len(), engine.schedule.len());
        assert!(!engine.remove(key(0)));
        assert_eq!(engine.retire(0), [] as [DampeningKey; 0]);
        assert_eq!(engine.retire(1), [key(1)]);
        assert_eq!(engine.len(), engine.schedule.len());
        assert_eq!(engine.retire(usize::MAX), [key(3)]);
        assert!(engine.is_empty());
        assert!(engine.next_due().is_none());
    }

    #[test]
    fn revision_exhaustion_preserves_retained_history_and_schedule() {
        let mut engine = DampeningEngine::new(DampeningParameters::default());
        engine.record(key(0), DampeningEvent::Withdrawal, Duration::ZERO);
        let before = engine.inspect(key(0), Duration::ZERO);
        engine.revision = u64::MAX;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            engine.record(key(0), DampeningEvent::Withdrawal, Duration::from_secs(1));
        }));
        assert!(result.is_err());
        assert_eq!(engine.inspect(key(0), Duration::ZERO), before);
        assert_eq!(engine.schedule.len(), 1);
    }

    #[test]
    fn penalty_decay_hysteresis_reuse_and_reclaim() {
        let mut engine = DampeningEngine::new(DampeningParameters::default());
        assert!(
            engine
                .record(key(0), DampeningEvent::Announcement, Duration::ZERO)
                .is_none()
        );
        assert!(engine.is_empty());
        for _ in 0..6 {
            engine.record(key(0), DampeningEvent::Withdrawal, Duration::ZERO);
        }
        let state = engine
            .record(key(0), DampeningEvent::Announcement, Duration::ZERO)
            .unwrap();
        assert!(state.suppressed);
        assert_eq!(state.flap_count, 6);
        assert!((state.penalty - 6000.0).abs() < 1e-9);
        let half = engine
            .record(
                key(0),
                DampeningEvent::Announcement,
                Duration::from_mins(15),
            )
            .unwrap();
        assert!((half.penalty - 3000.0).abs() < 1e-9);
        assert!(half.suppressed, "reuse hysteresis persists below suppress");
        assert_eq!(engine.next_due(), Some(Duration::from_secs(2710)));
        assert_eq!(engine.process_due(Duration::from_mins(45), 10).processed, 0);
        let reused = engine.process_due(Duration::from_secs(2710), 10);
        assert_eq!(reused.reused, [key(0)]);
        assert_eq!(reused.reclaimed, []);
        let reclaim = engine.next_due().unwrap();
        assert_eq!(engine.process_due(reclaim, 10).reclaimed, [key(0)]);
        assert!(engine.is_empty());
        assert!(engine.next_due().is_none());
    }

    #[test]
    fn ceiling_reuses_within_one_tick_of_maximum_hold() {
        let mut engine = DampeningEngine::new(DampeningParameters::default());
        for _ in 0..100 {
            engine.record(key(0), DampeningEvent::Withdrawal, Duration::ZERO);
        }
        let state = engine
            .record(key(0), DampeningEvent::Announcement, Duration::ZERO)
            .unwrap();
        assert!((state.penalty - 12_000.0).abs() < 1e-9);
        assert_eq!(engine.next_due(), Some(Duration::from_secs(3610)));
        assert_eq!(engine.process_due(Duration::from_secs(3600), 1).reused, []);
        assert_eq!(
            engine.process_due(Duration::from_secs(3610), 1).reused,
            [key(0)]
        );
    }

    #[test]
    fn delayed_tick_does_not_clear_suppression_before_new_penalty() {
        let mut engine = DampeningEngine::new(DampeningParameters::default());
        for _ in 0..6 {
            engine.record(key(0), DampeningEvent::Withdrawal, Duration::ZERO);
        }
        let state = engine
            .record(
                key(0),
                DampeningEvent::AttributeChange,
                Duration::from_secs(2800),
            )
            .unwrap();
        assert!(state.penalty > 750.0 && state.penalty < 6000.0);
        assert!(
            state.suppressed,
            "the post-event penalty remains above reuse"
        );
        assert_eq!(engine.process_due(Duration::from_secs(2800), 1).reused, []);
        let due = engine.next_due().unwrap();
        assert_eq!(engine.process_due(due, 1).reused, [key(0)]);
    }

    #[test]
    fn charged_events_below_reclaim_floor_still_accumulate() {
        let mut engine =
            DampeningEngine::new(DampeningParameters::new(900, 3000, 6000, 3600).unwrap());
        let first = engine
            .record(key(0), DampeningEvent::AttributeChange, Duration::ZERO)
            .unwrap();
        assert!((first.penalty - 500.0).abs() < 1e-9);
        for now in [Duration::ZERO, Duration::from_secs(9)] {
            assert!(
                engine
                    .record(key(0), DampeningEvent::Announcement, now)
                    .is_some()
            );
            assert_eq!(engine.next_due(), Some(Duration::from_secs(10)));
        }
        assert_eq!(
            engine.process_due(Duration::from_secs(10), 1).reclaimed,
            [key(0)]
        );
        for _ in 0..6 {
            engine.record(key(1), DampeningEvent::Withdrawal, Duration::from_secs(10));
            assert!(
                engine
                    .record(
                        key(1),
                        DampeningEvent::Announcement,
                        Duration::from_secs(10)
                    )
                    .is_some(),
                "re-announcement keeps recent charged history"
            );
        }
        assert!(
            engine
                .record(
                    key(1),
                    DampeningEvent::Announcement,
                    Duration::from_secs(10)
                )
                .unwrap()
                .suppressed
        );
    }

    #[test]
    fn rapid_flaps_replace_the_deadline_and_due_work_is_bounded() {
        let mut engine = DampeningEngine::new(DampeningParameters::default());
        engine.record(key(0), DampeningEvent::Withdrawal, Duration::ZERO);
        let old_due = engine.next_due().unwrap();
        for i in 1..10_000 {
            engine.record(key(0), DampeningEvent::Withdrawal, Duration::from_millis(i));
            assert_eq!(engine.schedule.len(), engine.len());
        }
        assert_eq!(
            engine.process_due(old_due, 10).processed,
            0,
            "old deadline was removed"
        );
        let now = Duration::from_secs(10_000);
        for path_id in 1..10 {
            engine.record(key(path_id), DampeningEvent::AttributeChange, now);
        }
        let result = engine.process_due(Duration::from_secs(20_000), 3);
        assert_eq!(result.processed, 3);
        assert_eq!(result.reclaimed.len(), 3);
        assert_eq!(engine.schedule.len(), engine.len());
        assert!(engine.next_due().unwrap() < Duration::from_secs(20_000));
        assert_eq!(
            engine.process_due(Duration::from_secs(20_000), 0).processed,
            0
        );
        assert_eq!(
            engine
                .process_due(Duration::from_secs(20_000), 20)
                .processed,
            7
        );
        assert!(engine.is_empty());
    }

    #[test]
    fn attribute_changes_cost_half_a_withdrawal_and_replays_keep_precision() {
        let mut engine = DampeningEngine::new(DampeningParameters::default());
        engine.record(key(0), DampeningEvent::AttributeChange, Duration::ZERO);
        let mut state = None;
        for i in 1..=900 {
            state = engine.record(
                key(0),
                DampeningEvent::Announcement,
                Duration::from_millis(i),
            );
        }
        let expected = 500.0 * (-0.9_f64 / 900.0).exp2();
        assert!((state.unwrap().penalty - expected).abs() < 1e-8);
        assert_eq!(state.unwrap().flap_count, 1);
        assert!(
            engine
                .record(
                    key(0),
                    DampeningEvent::Announcement,
                    Duration::from_secs(100_000)
                )
                .is_none()
        );
        assert!(engine.is_empty());
    }

    #[test]
    fn parameters_validate_ceiling_and_support_rfc7196_maximum() {
        assert!((DampeningParameters::default().ceiling() - 12_000.0).abs() < 1e-9);
        let high = DampeningParameters::new(900, 750, 50_000, 6300).unwrap();
        assert!(high.ceiling() >= 50_000.0);
        assert!(DampeningParameters::new(900, 750, 12_000, 3600).is_ok());
        for (values, field) in [
            ((59, 750, 6000, 3600), "half_life"),
            ((2701, 750, 6000, 3600), "half_life"),
            ((900, 0, 6000, 3600), "reuse"),
            ((900, 50_000, 50_000, 3600), "reuse"),
            ((900, 750, 750, 3600), "suppress"),
            ((900, 750, 50_001, 6300), "suppress"),
            ((900, 750, 6000, 899), "max_suppress_time"),
            ((2700, 750, 6000, 14_401), "max_suppress_time"),
            ((60, 750, 6000, 14_400), "max_suppress_time"),
            ((900, 750, 12_001, 3600), "suppress"),
        ] {
            assert_eq!(
                DampeningParameters::new(values.0, values.1, values.2, values.3)
                    .unwrap_err()
                    .field,
                field
            );
        }
        assert!(
            DampeningParameters::new(900, 750, 12_001, 3600)
                .unwrap_err()
                .reason
                .contains("3601 seconds")
        );
    }

    #[test]
    #[should_panic(expected = "dampening time must be monotonic")]
    fn backward_clock_is_rejected() {
        let mut engine = DampeningEngine::new(DampeningParameters::default());
        engine.process_due(Duration::from_secs(1), 0);
        engine.record(key(0), DampeningEvent::Withdrawal, Duration::ZERO);
    }

    #[test]
    #[should_panic(expected = "dampening time exceeds scheduling range")]
    fn unrepresentable_deadline_is_rejected_before_history_changes() {
        let mut engine = DampeningEngine::new(DampeningParameters::default());
        engine.record(key(0), DampeningEvent::Withdrawal, Duration::MAX);
    }
}
