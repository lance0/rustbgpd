//! Per-source inbound accept-rate limiting (ADR-0120).
//!
//! A token bucket per aggregated source address, held in a
//! fixed-capacity LRU table owned by the `PeerManager` actor. The
//! accept path consults it for dynamic-range-matched sources only;
//! statically configured neighbors are exempt by admission path (they
//! never reach the dynamic arm). All state is single-task-owned — no
//! locks anywhere near the accept path.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroUsize;

use lru::LruCache;
use tokio::time::Instant;

use crate::config::InboundAdmissionConfig;

/// Minimum spacing between rate-limit warn lines, so the log stream
/// cannot be flooded by the flood it reports.
const LOG_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// Mask `addr` down to its configured aggregation prefix, producing the
/// bucket key for that source.
fn aggregate(addr: IpAddr, v4_len: u8, v6_len: u8) -> IpAddr {
    match addr {
        IpAddr::V4(v4) => {
            let mask = u32::MAX << (32 - u32::from(v4_len));
            IpAddr::V4(Ipv4Addr::from(u32::from(v4) & mask))
        }
        IpAddr::V6(v6) => {
            let mask = if v6_len == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(v6_len))
            };
            IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask))
        }
    }
}

struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

pub(super) struct InboundAdmission {
    rate_per_second: f64,
    burst: f64,
    v4_len: u8,
    v6_len: u8,
    buckets: LruCache<IpAddr, TokenBucket>,
    last_log: Option<Instant>,
    suppressed_since_last_log: u64,
}

impl InboundAdmission {
    /// Build the limiter from config; `None` when disabled. Bounds are
    /// enforced by config validation before this is reached.
    pub(super) fn from_config(cfg: &InboundAdmissionConfig) -> Option<Self> {
        if !cfg.enabled {
            return None;
        }
        Some(Self {
            rate_per_second: f64::from(cfg.rate_per_minute) / 60.0,
            burst: f64::from(cfg.burst),
            v4_len: cfg.v4_aggregation_len,
            v6_len: cfg.v6_aggregation_len,
            buckets: LruCache::new(
                NonZeroUsize::new(cfg.table_capacity.max(1)).expect("capacity is non-zero"),
            ),
            last_log: None,
            suppressed_since_last_log: 0,
        })
    }

    /// Take one token for an accept attempt from `source`. Returns
    /// `true` when the accept is admitted. A source not yet tracked
    /// starts with a full burst allowance; inserting it may evict the
    /// least-recently-used aggregate, keeping the table at its fixed
    /// capacity.
    pub(super) fn admit(&mut self, source: IpAddr) -> bool {
        let key = aggregate(source, self.v4_len, self.v6_len);
        let now = Instant::now();
        if let Some(bucket) = self.buckets.get_mut(&key) {
            let elapsed = now.saturating_duration_since(bucket.last_refill);
            bucket.tokens =
                (bucket.tokens + elapsed.as_secs_f64() * self.rate_per_second).min(self.burst);
            bucket.last_refill = now;
            if bucket.tokens >= 1.0 {
                bucket.tokens -= 1.0;
                true
            } else {
                false
            }
        } else {
            self.buckets.push(
                key,
                TokenBucket {
                    tokens: self.burst - 1.0,
                    last_refill: now,
                },
            );
            true
        }
    }

    /// Whether a rate-limit drop may emit its warn line now. At most
    /// one line per [`LOG_INTERVAL`]; returns the number of drops
    /// suppressed since the last emitted line.
    pub(super) fn should_log(&mut self) -> Option<u64> {
        let now = Instant::now();
        if self
            .last_log
            .is_none_or(|last| now.saturating_duration_since(last) >= LOG_INTERVAL)
        {
            self.last_log = Some(now);
            Some(std::mem::take(&mut self.suppressed_since_last_log))
        } else {
            self.suppressed_since_last_log += 1;
            None
        }
    }

    /// Tracked source aggregates, for capacity-bound assertions.
    #[cfg(test)]
    pub(super) fn tracked(&self) -> usize {
        self.buckets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(rate_per_minute: u32, burst: u32, capacity: usize) -> InboundAdmissionConfig {
        InboundAdmissionConfig {
            enabled: true,
            rate_per_minute,
            burst,
            table_capacity: capacity,
            ..InboundAdmissionConfig::default()
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn disabled_config_builds_no_limiter() {
        assert!(InboundAdmission::from_config(&InboundAdmissionConfig::default()).is_none());
    }

    #[test]
    fn aggregation_masks_host_bits() {
        assert_eq!(aggregate(ip("192.0.2.77"), 32, 64), ip("192.0.2.77"));
        assert_eq!(aggregate(ip("192.0.2.77"), 24, 64), ip("192.0.2.0"));
        assert_eq!(
            aggregate(ip("2001:db8:1:2:3:4:5:6"), 32, 64),
            ip("2001:db8:1:2::")
        );
        assert_eq!(
            aggregate(ip("2001:db8:1:2:3:4:5:6"), 32, 48),
            ip("2001:db8:1::")
        );
        assert_eq!(
            aggregate(ip("2001:db8:1:2:3:4:5:6"), 32, 128),
            ip("2001:db8:1:2:3:4:5:6")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn burst_exhausts_then_refills_at_rate() {
        let mut admission = InboundAdmission::from_config(&config(60, 2, 64)).unwrap();
        assert!(admission.admit(ip("192.0.2.1")));
        assert!(admission.admit(ip("192.0.2.1")));
        assert!(!admission.admit(ip("192.0.2.1")));
        // 60/min = 1 token per second.
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        assert!(admission.admit(ip("192.0.2.1")));
        assert!(!admission.admit(ip("192.0.2.1")));
    }

    #[tokio::test(start_paused = true)]
    async fn v6_sources_in_one_slash64_share_a_bucket() {
        let mut admission = InboundAdmission::from_config(&config(60, 1, 64)).unwrap();
        assert!(admission.admit(ip("2001:db8::1")));
        assert!(
            !admission.admit(ip("2001:db8::2")),
            "a rotated interface identifier inside the same /64 must not refill the burst"
        );
        assert!(
            admission.admit(ip("2001:db8:0:1::1")),
            "a different /64 is a distinct aggregate"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn refill_never_exceeds_burst() {
        let mut admission = InboundAdmission::from_config(&config(60, 2, 64)).unwrap();
        assert!(admission.admit(ip("192.0.2.1")));
        tokio::time::advance(std::time::Duration::from_secs(90)).await;
        assert!(admission.admit(ip("192.0.2.1")));
        assert!(admission.admit(ip("192.0.2.1")));
        assert!(!admission.admit(ip("192.0.2.1")));
    }

    #[tokio::test(start_paused = true)]
    async fn table_never_exceeds_capacity_and_evicts_lru() {
        let capacity: usize = 64;
        let mut admission = InboundAdmission::from_config(&config(60, 1, capacity)).unwrap();
        for i in 0u32..256 {
            admission.admit(IpAddr::V4(Ipv4Addr::from(0xc000_0200 + i)));
            assert!(admission.tracked() <= capacity);
        }
        assert_eq!(admission.tracked(), capacity);
        // The earliest source was evicted, so it re-enters with a fresh
        // burst rather than remembering its spent allowance.
        assert!(admission.admit(ip("192.0.2.0")));
    }

    #[tokio::test(start_paused = true)]
    async fn rate_limit_log_is_throttled() {
        let mut admission = InboundAdmission::from_config(&config(60, 1, 64)).unwrap();
        assert_eq!(admission.should_log(), Some(0));
        assert_eq!(admission.should_log(), None);
        assert_eq!(admission.should_log(), None);
        tokio::time::advance(LOG_INTERVAL).await;
        assert_eq!(admission.should_log(), Some(2));
    }
}
