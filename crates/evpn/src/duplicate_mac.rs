//! Duplicate-MAC detection window for RFC 7432 §15.1.
//!
//! The detector is intentionally pure: callers provide `Instant`s and
//! decide what to do with threshold crossings. That keeps telemetry,
//! config, and daemon-side route withdrawal policy out of the domain
//! state while still pinning the RFC M/N sliding-window behavior in
//! focused unit tests.

use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

use rustbgpd_wire::MacAddress;
use thiserror::Error;

use crate::EvpnInstanceId;

/// RFC 7432 §15.1 default duplicate-MAC detection window (`M`).
pub const DEFAULT_DUPLICATE_MAC_WINDOW: Duration = Duration::from_mins(3);
/// RFC 7432 §15.1 default duplicate-MAC move threshold (`N`).
pub const DEFAULT_DUPLICATE_MAC_THRESHOLD: u32 = 5;
/// Default local suppression hold time. Three windows mirrors the
/// conservative loop-protection retry guidance in the bis draft while
/// keeping the first rustbgpd action slice self-recovering.
pub const DEFAULT_DUPLICATE_MAC_RECOVERY: Duration = Duration::from_mins(9);

/// Operator-selected action when a `(VNI, MAC)` exceeds the M/N window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DuplicateMacAction {
    /// Record threshold crossings but do not suppress originations.
    DetectOnly,
    /// Suppress locally-originated Type 2 routes for the `(VNI, MAC)`.
    SuppressLocal,
}

/// Per-instance duplicate-MAC detection policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DuplicateMacConfig {
    pub action: DuplicateMacAction,
    pub window: Duration,
    pub threshold: u32,
    pub recovery: Duration,
}

impl Default for DuplicateMacConfig {
    fn default() -> Self {
        Self {
            action: DuplicateMacAction::DetectOnly,
            window: DEFAULT_DUPLICATE_MAC_WINDOW,
            threshold: DEFAULT_DUPLICATE_MAC_THRESHOLD,
            recovery: DEFAULT_DUPLICATE_MAC_RECOVERY,
        }
    }
}

impl DuplicateMacConfig {
    /// Build a validated policy.
    ///
    /// # Errors
    /// Returns [`DuplicateMacConfigError`] when a duration or threshold
    /// is zero.
    pub fn new(
        action: DuplicateMacAction,
        window: Duration,
        threshold: u32,
        recovery: Duration,
    ) -> Result<Self, DuplicateMacConfigError> {
        if window.is_zero() {
            return Err(DuplicateMacConfigError::ZeroWindow);
        }
        if threshold == 0 {
            return Err(DuplicateMacConfigError::ZeroThreshold);
        }
        if recovery.is_zero() {
            return Err(DuplicateMacConfigError::ZeroRecovery);
        }
        Ok(Self {
            action,
            window,
            threshold,
            recovery,
        })
    }
}

/// Invalid duplicate-MAC detection policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DuplicateMacConfigError {
    #[error("duplicate_mac_detection.window_seconds must be greater than 0")]
    ZeroWindow,
    #[error("duplicate_mac_detection.threshold must be greater than 0")]
    ZeroThreshold,
    #[error("duplicate_mac_detection.recovery_seconds must be greater than 0")]
    ZeroRecovery,
}

/// Stable key for duplicate-MAC detection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DuplicateMacKey {
    pub vni: EvpnInstanceId,
    pub mac: MacAddress,
}

impl DuplicateMacKey {
    #[must_use]
    pub const fn new(vni: EvpnInstanceId, mac: MacAddress) -> Self {
        Self { vni, mac }
    }
}

/// Result of recording one mobility-contention event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DuplicateMacDecision {
    /// Event recorded but the threshold has not been reached.
    Recorded { window_count: u32 },
    /// Threshold reached in detect-only mode.
    ThresholdExceeded { window_count: u32 },
    /// Threshold reached and local suppression is now active.
    Quarantined { window_count: u32, until: Instant },
    /// Suppression was already active; no new window accounting happened.
    AlreadyQuarantined { until: Instant },
}

#[derive(Debug, Clone, Default)]
struct DuplicateMacWindow {
    moves: VecDeque<Instant>,
    quarantined_until: Option<Instant>,
}

/// Sliding-window detector keyed by `(VNI, MAC)`.
#[derive(Debug, Clone, Default)]
pub struct DuplicateMacDetector {
    windows: BTreeMap<DuplicateMacKey, DuplicateMacWindow>,
}

impl DuplicateMacDetector {
    /// Record one RFC 7432 mobility-contention event.
    pub fn record_move(
        &mut self,
        key: DuplicateMacKey,
        now: Instant,
        config: DuplicateMacConfig,
    ) -> DuplicateMacDecision {
        let _ = self.expire_key(key, now);
        let window = self.windows.entry(key).or_default();
        if let Some(until) = active_until(window, now) {
            return DuplicateMacDecision::AlreadyQuarantined { until };
        }

        prune_old_moves(&mut window.moves, now, config.window);
        window.moves.push_back(now);
        let window_count = u32::try_from(window.moves.len()).unwrap_or(u32::MAX);
        if window_count < config.threshold {
            return DuplicateMacDecision::Recorded { window_count };
        }

        window.moves.clear();
        match config.action {
            DuplicateMacAction::DetectOnly => {
                DuplicateMacDecision::ThresholdExceeded { window_count }
            }
            DuplicateMacAction::SuppressLocal => {
                let until = now + config.recovery;
                window.quarantined_until = Some(until);
                DuplicateMacDecision::Quarantined {
                    window_count,
                    until,
                }
            }
        }
    }

    /// Return true while the key is actively suppressed.
    ///
    /// This read-only check intentionally leaves expired suppressions in
    /// place. Callers with side effects should use [`Self::expire`] or
    /// [`Self::expire_key`] so metrics/replay code observes the recovery.
    pub fn is_quarantined(&mut self, key: DuplicateMacKey, now: Instant) -> bool {
        let Some(window) = self.windows.get_mut(&key) else {
            return false;
        };
        active_until(window, now).is_some()
    }

    /// Expire all elapsed suppressions and return the keys that became
    /// eligible for re-origination.
    pub fn expire(&mut self, now: Instant) -> Vec<DuplicateMacKey> {
        let mut expired = Vec::new();
        for (key, window) in &mut self.windows {
            if expire_window(window, now) {
                expired.push(*key);
            }
        }
        expired
    }

    /// Expire one elapsed suppression. Returns true when the key
    /// transitioned from active/pending recovery to reusable.
    pub fn expire_key(&mut self, key: DuplicateMacKey, now: Instant) -> bool {
        self.windows
            .get_mut(&key)
            .is_some_and(|window| expire_window(window, now))
    }
}

fn active_until(window: &mut DuplicateMacWindow, now: Instant) -> Option<Instant> {
    let until = window.quarantined_until?;
    if now < until { Some(until) } else { None }
}

fn expire_window(window: &mut DuplicateMacWindow, now: Instant) -> bool {
    if window.quarantined_until.is_some_and(|until| now >= until) {
        window.quarantined_until = None;
        window.moves.clear();
        true
    } else {
        false
    }
}

fn prune_old_moves(moves: &mut VecDeque<Instant>, now: Instant, window: Duration) {
    while moves
        .front()
        .is_some_and(|first| now.duration_since(*first) > window)
    {
        moves.pop_front();
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

    fn key() -> DuplicateMacKey {
        DuplicateMacKey::new(vni(100), mac(0xaa))
    }

    fn config(action: DuplicateMacAction) -> DuplicateMacConfig {
        DuplicateMacConfig::new(action, Duration::from_secs(10), 3, Duration::from_secs(30))
            .unwrap()
    }

    #[test]
    fn defaults_match_rfc_window_and_threshold() {
        let cfg = DuplicateMacConfig::default();
        assert_eq!(cfg.action, DuplicateMacAction::DetectOnly);
        assert_eq!(cfg.window, Duration::from_mins(3));
        assert_eq!(cfg.threshold, 5);
        assert_eq!(cfg.recovery, Duration::from_mins(9));
    }

    #[test]
    fn detect_only_fires_on_threshold_without_quarantine() {
        let mut detector = DuplicateMacDetector::default();
        let now = Instant::now();
        let cfg = config(DuplicateMacAction::DetectOnly);
        assert_eq!(
            detector.record_move(key(), now, cfg),
            DuplicateMacDecision::Recorded { window_count: 1 }
        );
        assert_eq!(
            detector.record_move(key(), now + Duration::from_secs(1), cfg),
            DuplicateMacDecision::Recorded { window_count: 2 }
        );
        assert_eq!(
            detector.record_move(key(), now + Duration::from_secs(2), cfg),
            DuplicateMacDecision::ThresholdExceeded { window_count: 3 }
        );
        assert!(!detector.is_quarantined(key(), now + Duration::from_secs(3)));
    }

    #[test]
    fn old_moves_outside_window_do_not_count() {
        let mut detector = DuplicateMacDetector::default();
        let now = Instant::now();
        let cfg = config(DuplicateMacAction::SuppressLocal);
        assert_eq!(
            detector.record_move(key(), now, cfg),
            DuplicateMacDecision::Recorded { window_count: 1 }
        );
        assert_eq!(
            detector.record_move(key(), now + Duration::from_secs(11), cfg),
            DuplicateMacDecision::Recorded { window_count: 1 }
        );
    }

    #[test]
    fn suppress_local_quarantines_and_expires() {
        let mut detector = DuplicateMacDetector::default();
        let now = Instant::now();
        let cfg = config(DuplicateMacAction::SuppressLocal);
        assert!(matches!(
            detector.record_move(key(), now, cfg),
            DuplicateMacDecision::Recorded { .. }
        ));
        assert!(matches!(
            detector.record_move(key(), now + Duration::from_secs(1), cfg),
            DuplicateMacDecision::Recorded { .. }
        ));
        let decision = detector.record_move(key(), now + Duration::from_secs(2), cfg);
        let DuplicateMacDecision::Quarantined { until, .. } = decision else {
            panic!("expected quarantine, got {decision:?}");
        };
        assert_eq!(until, now + Duration::from_secs(32));
        assert!(detector.is_quarantined(key(), now + Duration::from_secs(31)));
        assert_eq!(
            detector.record_move(key(), now + Duration::from_secs(31), cfg),
            DuplicateMacDecision::AlreadyQuarantined { until }
        );
        assert!(!detector.is_quarantined(key(), now + Duration::from_secs(32)));
        assert_eq!(detector.expire(now + Duration::from_secs(32)), vec![key()]);
        assert!(!detector.is_quarantined(key(), now + Duration::from_secs(32)));
    }

    #[test]
    fn config_rejects_zero_values() {
        assert_eq!(
            DuplicateMacConfig::new(
                DuplicateMacAction::DetectOnly,
                Duration::ZERO,
                1,
                Duration::from_secs(1)
            ),
            Err(DuplicateMacConfigError::ZeroWindow)
        );
        assert_eq!(
            DuplicateMacConfig::new(
                DuplicateMacAction::DetectOnly,
                Duration::from_secs(1),
                0,
                Duration::from_secs(1)
            ),
            Err(DuplicateMacConfigError::ZeroThreshold)
        );
        assert_eq!(
            DuplicateMacConfig::new(
                DuplicateMacAction::DetectOnly,
                Duration::from_secs(1),
                1,
                Duration::ZERO
            ),
            Err(DuplicateMacConfigError::ZeroRecovery)
        );
    }
}
