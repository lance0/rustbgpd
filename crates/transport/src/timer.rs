//! BGP session timers (connect-retry, hold, keepalive).

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use rustbgpd_fsm::TimerType;
use tokio::time::Sleep;

/// Manages the three BGP session timers (connect-retry, hold, keepalive).
///
/// Each timer is an `Option<Pin<Box<Sleep>>>` — `None` means the timer is
/// stopped, `Some` means it is running.
#[derive(Debug, Default)]
pub struct Timers {
    /// Connect-retry timer (RFC 4271 §8.2.2).
    pub connect_retry: Option<Pin<Box<Sleep>>>,
    /// Hold timer — session tears down if no KEEPALIVE/UPDATE within this window.
    pub hold: Option<Pin<Box<Sleep>>>,
    /// Keepalive timer slot. Unused since ADR-0078 moved the KEEPALIVE
    /// cadence into the per-connection writer task; kept so
    /// `TimerType::Keepalive` still maps to a slot.
    pub keepalive: Option<Pin<Box<Sleep>>>,
    /// Interval of the most recent hold-timer start, so an expiry that
    /// coincides with pending unprocessed input can re-arm at the
    /// negotiated duration (ADR-0078).
    pub last_hold_secs: Option<u32>,
}

impl Timers {
    /// Start (or restart) a timer with the given duration in seconds.
    pub fn start(&mut self, timer_type: TimerType, secs: u32) {
        if timer_type == TimerType::Hold {
            self.last_hold_secs = Some(secs);
        }
        let duration = Duration::from_secs(u64::from(secs));
        let duration = if timer_type == TimerType::ConnectRetry {
            jittered(duration)
        } else {
            duration
        };
        if let Some(slot) = self.slot_mut(timer_type) {
            *slot = Some(Box::pin(tokio::time::sleep(duration)));
        }
    }

    /// Stop a running timer.
    pub fn stop(&mut self, timer_type: TimerType) {
        if let Some(slot) = self.slot_mut(timer_type) {
            *slot = None;
        }
    }

    /// Stop all timers.
    pub fn stop_all(&mut self) {
        self.connect_retry = None;
        self.hold = None;
        self.keepalive = None;
    }

    /// `None` for a timer kind this build does not run (`TimerType` is
    /// non-exhaustive): the request is ignored — no slot, no expiry.
    fn slot_mut(&mut self, timer_type: TimerType) -> Option<&mut Option<Pin<Box<Sleep>>>> {
        match timer_type {
            TimerType::ConnectRetry => Some(&mut self.connect_retry),
            TimerType::Hold => Some(&mut self.hold),
            TimerType::Keepalive => Some(&mut self.keepalive),
            _ => None,
        }
    }
}

/// Jitter a retry wait (the `ConnectRetry` timer and the Idle reconnect
/// wait) by a factor in RFC 4271 §10's default range of 0.75 to 1.0, so a
/// jittered wait never exceeds its unjittered value or the backoff cap.
pub(crate) fn jittered(base: Duration) -> Duration {
    // RFC 4271 §10: "To minimize the likelihood that the distribution of BGP
    // messages by a given BGP speaker will contain peaks, jitter SHOULD be
    // applied to the timers associated with MinASOriginationIntervalTimer,
    // KeepaliveTimer, MinRouteAdvertisementIntervalTimer, and
    // ConnectRetryTimer. [...] The suggested default amount of jitter SHALL
    // be determined by multiplying the base value of the appropriate timer by
    // a random factor, which is uniformly distributed in the range from 0.75
    // to 1.0. A new random value SHOULD be picked each time the timer is
    // set."
    jittered_by(base, jitter_sample())
}

fn random_sample() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    // Each `RandomState` has fresh SipHash keys; this needs spread, not
    // unpredictability.
    std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish()
}

#[cfg(not(test))]
fn jitter_sample() -> u64 {
    random_sample()
}

#[cfg(test)]
thread_local! {
    /// Unit tests see unjittered waits unless they opt in on their thread.
    pub(crate) static TEST_RANDOM_JITTER: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn jitter_sample() -> u64 {
    if TEST_RANDOM_JITTER.get() {
        random_sample()
    } else {
        0
    }
}

/// `base` scaled by `1 - sample / 2^64 / 4`, a factor in (0.75, 1.0].
fn jittered_by(base: Duration, sample: u64) -> Duration {
    // `base` comes from u32 seconds, so the product stays below 2^124.
    let cut = ((base.as_nanos() / 4) * u128::from(sample)) >> 64;
    base.saturating_sub(Duration::from_nanos(u64::try_from(cut).unwrap_or(u64::MAX)))
}

/// A future that resolves when the timer fires, or pends forever if `None`.
///
/// This is a freestanding function (not a method) so it can be used in
/// `tokio::select!` without conflicting with other `&mut self` borrows.
pub fn poll_timer(timer: &mut Option<Pin<Box<Sleep>>>) -> PollTimer<'_> {
    PollTimer { timer }
}

/// Future returned by [`poll_timer`].
pub struct PollTimer<'a> {
    timer: &'a mut Option<Pin<Box<Sleep>>>,
}

impl Future for PollTimer<'_> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        match this.timer.as_mut() {
            Some(sleep) => sleep.as_mut().poll(cx),
            None => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn start_and_stop_timer() {
        let mut timers = Timers::default();
        assert!(timers.connect_retry.is_none());

        timers.start(TimerType::ConnectRetry, 30);
        assert!(timers.connect_retry.is_some());

        timers.stop(TimerType::ConnectRetry);
        assert!(timers.connect_retry.is_none());
    }

    #[tokio::test]
    async fn stop_all_clears_everything() {
        let mut timers = Timers::default();
        timers.start(TimerType::ConnectRetry, 10);
        timers.start(TimerType::Hold, 90);
        timers.start(TimerType::Keepalive, 30);

        timers.stop_all();
        assert!(timers.connect_retry.is_none());
        assert!(timers.hold.is_none());
        assert!(timers.keepalive.is_none());
    }

    /// Jitter stays in the RFC 4271 §10 range at both sample extremes, and
    /// live samples vary.
    #[test]
    fn retry_jitter_stays_within_bounds_and_varies() {
        TEST_RANDOM_JITTER.set(true);
        let base = Duration::from_secs(300);
        assert_eq!(jittered_by(base, 0), base);
        let low = jittered_by(base, u64::MAX);
        assert!(low >= base.mul_f64(0.75) && low < base, "{low:?}");
        let live: std::collections::BTreeSet<_> = (0..64).map(|_| jittered(base)).collect();
        assert!(
            live.iter()
                .all(|wait| *wait >= base.mul_f64(0.75) && *wait <= base),
            "{live:?}"
        );
        assert!(live.len() > 32, "jitter is near constant: {live:?}");
    }

    /// The `ConnectRetry` timer is jittered; the hold timer is not.
    #[tokio::test(start_paused = true)]
    async fn connect_retry_timer_is_jittered() {
        TEST_RANDOM_JITTER.set(true);
        let start = tokio::time::Instant::now();
        let base = Duration::from_secs(300);
        let mut deadlines = std::collections::BTreeSet::new();
        let mut timers = Timers::default();
        for _ in 0..16 {
            timers.start(TimerType::ConnectRetry, 300);
            let wait = timers.connect_retry.as_ref().unwrap().deadline() - start;
            assert!(wait >= base.mul_f64(0.75) && wait <= base, "{wait:?}");
            deadlines.insert(wait);
        }
        assert!(deadlines.len() > 1, "ConnectRetry is not jittered");
        timers.start(TimerType::Hold, 90);
        assert_eq!(
            timers.hold.as_ref().unwrap().deadline() - start,
            Duration::from_secs(90)
        );
    }

    #[tokio::test]
    async fn poll_timer_fires() {
        let mut timer: Option<Pin<Box<Sleep>>> =
            Some(Box::pin(tokio::time::sleep(Duration::from_millis(1))));
        poll_timer(&mut timer).await;
        // Completed without hanging
    }

    #[tokio::test]
    async fn poll_timer_none_pends() {
        let mut timer: Option<Pin<Box<Sleep>>> = None;
        // Should pend forever — use select to prove it doesn't fire
        tokio::select! {
            () = poll_timer(&mut timer) => {
                unreachable!("poll_timer(None) should not resolve");
            }
            () = tokio::time::sleep(Duration::from_millis(10)) => {
                // Expected: the sleep won, poll_timer pended
            }
        }
    }
}
