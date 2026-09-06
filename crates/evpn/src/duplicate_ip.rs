//! Detect-only duplicate-IP M/N accounting (RFC 9721 §8.2 / RFC 9161 §3.7).

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use thiserror::Error;

use crate::{
    DEFAULT_DUPLICATE_MAC_THRESHOLD, DEFAULT_DUPLICATE_MAC_WINDOW, DuplicateMacAction,
    DuplicateMacConfig, DuplicateMacDecision, EvpnInstanceId,
};

/// Per-instance duplicate-IP diagnostics. No suppression action is supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DuplicateIpConfig {
    pub enabled: bool,
    pub window: Duration,
    pub threshold: u32,
}

impl Default for DuplicateIpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            window: DEFAULT_DUPLICATE_MAC_WINDOW,
            threshold: DEFAULT_DUPLICATE_MAC_THRESHOLD,
        }
    }
}

impl DuplicateIpConfig {
    /// Build a validated diagnostic policy, including when disabled.
    ///
    /// # Errors
    /// Returns an error for a zero window or threshold.
    pub fn new(
        enabled: bool,
        window: Duration,
        threshold: u32,
    ) -> Result<Self, DuplicateIpConfigError> {
        if window.is_zero() {
            return Err(DuplicateIpConfigError::ZeroWindow);
        }
        if threshold == 0 {
            return Err(DuplicateIpConfigError::ZeroThreshold);
        }
        Ok(Self {
            enabled,
            window,
            threshold,
        })
    }
}

/// Invalid duplicate-IP diagnostic policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DuplicateIpConfigError {
    #[error("duplicate_ip_detection.window_seconds must be greater than 0")]
    ZeroWindow,
    #[error("duplicate_ip_detection.threshold must be greater than 0")]
    ZeroThreshold,
}

/// IP ownership is scoped to an EVI, independently of the MAC address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DuplicateIpKey {
    pub vni: EvpnInstanceId,
    pub ip: IpAddr,
}

use crate::duplicate_mac::DuplicateMacWindow;

/// Reuses the MAC detector's sliding window with suppression inaccessible.
#[derive(Debug, Clone, Default)]
pub struct DuplicateIpDetector {
    windows: BTreeMap<DuplicateIpKey, DuplicateMacWindow>,
}

impl DuplicateIpDetector {
    /// Record one conflict. Returns true on each threshold crossing.
    /// Disabled policies do not allocate state.
    pub fn record_move(
        &mut self,
        key: DuplicateIpKey,
        now: Instant,
        config: DuplicateIpConfig,
    ) -> bool {
        config.enabled
            && matches!(
                self.windows.entry(key).or_default().record(
                    now,
                    DuplicateMacConfig {
                        action: DuplicateMacAction::DetectOnly,
                        window: config.window,
                        threshold: config.threshold,
                        ..DuplicateMacConfig::default()
                    }
                ),
                DuplicateMacDecision::ThresholdExceeded { .. }
            )
    }

    /// Expire idle windows. This never causes route recovery or withdrawal.
    pub fn expire(&mut self, now: Instant) {
        self.windows.retain(|_, window| window.retain_moves(now));
    }

    /// Forget all move history for a removed or redefined VNI.
    pub fn clear_vni(&mut self, vni: EvpnInstanceId) {
        self.windows.retain(|key, _| key.vni != vni);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_ip_window_is_detect_only_and_isolated_by_vni_and_family() {
        let now = Instant::now();
        let config = DuplicateIpConfig::new(true, Duration::from_secs(10), 2).unwrap();
        let key = DuplicateIpKey {
            vni: EvpnInstanceId::new(100).unwrap(),
            ip: "192.0.2.1".parse().unwrap(),
        };
        let other_vni = DuplicateIpKey {
            vni: EvpnInstanceId::new(200).unwrap(),
            ..key
        };
        let other_ip = DuplicateIpKey {
            ip: "2001:db8::1".parse().unwrap(),
            ..key
        };
        let mut detector = DuplicateIpDetector::default();
        assert!(!detector.record_move(key, now, DuplicateIpConfig::default()));
        assert!(detector.windows.is_empty());
        assert!(!detector.record_move(key, now, config));
        assert!(!detector.record_move(other_vni, now, config));
        assert!(!detector.record_move(other_ip, now, config));
        assert!(
            detector.record_move(key, now + config.window, config),
            "window boundary is inclusive"
        );
        assert!(
            !detector.record_move(key, now + config.window, config),
            "threshold resets the window, without quarantine"
        );
        detector.clear_vni(key.vni);
        assert_eq!(detector.windows.len(), 1);
        assert!(detector.record_move(other_vni, now + config.window, config));
        detector.expire(now + config.window + Duration::from_nanos(1));
        assert!(detector.windows.is_empty());
        assert!(!detector.record_move(key, now, config));
        assert!(
            !detector.record_move(key, now + config.window + Duration::from_nanos(1), config),
            "old moves expire strictly past M"
        );
    }

    #[test]
    fn duplicate_ip_config_rejects_zero_even_when_disabled() {
        assert_eq!(
            DuplicateIpConfig::new(false, Duration::ZERO, 5),
            Err(DuplicateIpConfigError::ZeroWindow)
        );
        assert_eq!(
            DuplicateIpConfig::new(false, Duration::from_secs(1), 0),
            Err(DuplicateIpConfigError::ZeroThreshold)
        );
    }
}
