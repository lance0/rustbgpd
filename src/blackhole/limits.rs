use std::time::Duration;

use rustbgpd_wire::Prefix;
use tokio::time::Instant;

#[derive(Debug)]
pub(super) struct InstallLimits {
    max_active: Option<u32>,
    bucket: Option<TokenBucket>,
    cursor: Option<Prefix>,
    pub(super) next_wake: Option<Instant>,
}

impl InstallLimits {
    pub(super) fn new(max_active: Option<u32>, rate: Option<u32>, burst: Option<u32>) -> Self {
        Self {
            max_active,
            bucket: rate
                .zip(burst)
                .map(|(rate, burst)| TokenBucket::new(rate, burst)),
            cursor: None,
            next_wake: None,
        }
    }

    pub(super) fn order<T, F>(&self, values: &mut [T], prefix: F)
    where
        F: Fn(&T) -> Prefix,
    {
        if self.max_active.is_none() && self.bucket.is_none() {
            return;
        }
        values.sort_by_key(&prefix);
        let Some(cursor) = self.cursor else { return };
        let split = values.partition_point(|value| prefix(value) <= cursor);
        values.rotate_left(split);
    }

    pub(super) fn admit(&mut self, active: usize, now: Instant) -> Result<(), &'static str> {
        if self
            .max_active
            .is_some_and(|limit| active >= limit as usize)
        {
            return Err("active_limit_exceeded");
        }
        let Some(bucket) = &mut self.bucket else {
            return Ok(());
        };
        match bucket.take(now) {
            Ok(()) => Ok(()),
            Err(wake) => {
                self.next_wake = Some(self.next_wake.map_or(wake, |old| old.min(wake)));
                Err("install_rate_limited")
            }
        }
    }

    pub(super) fn attempted(&mut self, prefix: Prefix) {
        self.cursor = Some(prefix);
    }

    pub(super) fn begin_pass(&mut self) {
        self.next_wake = None;
    }
}

#[derive(Debug)]
struct TokenBucket {
    rate_per_minute: f64,
    burst: f64,
    tokens: f64,
    updated: Instant,
}

impl TokenBucket {
    fn new(rate: u32, burst: u32) -> Self {
        Self {
            rate_per_minute: f64::from(rate),
            burst: f64::from(burst),
            tokens: f64::from(burst),
            updated: Instant::now(),
        }
    }

    fn take(&mut self, now: Instant) -> Result<(), Instant> {
        let elapsed = now.duration_since(self.updated).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate_per_minute / 60.0).min(self.burst);
        self.updated = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            return Ok(());
        }
        let nanos = wait_nanos((1.0 - self.tokens) * 60.0 / self.rate_per_minute);
        Err(now + Duration::from_nanos(nanos))
    }
}

#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "ceil and clamp produce a finite 1..=60_000_000_000 nanosecond wait"
)]
fn wait_nanos(seconds: f64) -> u64 {
    (seconds * 1_000_000_000.0)
        .ceil()
        .clamp(1.0, 60_000_000_000.0) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blackhole::tests::{FakeFib, rib_with_events, route};
    use crate::blackhole::{BlackholeConfig, BlackholeState, OwnershipState, run_loop};
    use prometheus::Registry;
    use rustbgpd_rib::{RibUpdate, RouteOrigin};
    use rustbgpd_telemetry::BgpMetrics;
    use rustbgpd_wire::{Ipv4Prefix, Ipv6Prefix};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::sync::{broadcast, mpsc, watch};
    use tokio_util::sync::CancellationToken;

    fn v4(addr: [u8; 4]) -> Prefix {
        Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(addr), 32))
    }

    fn host(last: u8) -> Prefix {
        v4([203, 0, 113, last])
    }

    fn spawn_actor(
        rib: mpsc::Sender<RibUpdate>,
        fib: FakeFib,
    ) -> (
        CancellationToken,
        watch::Receiver<Vec<crate::blackhole::BlackholeStatus>>,
        tokio::task::JoinHandle<()>,
    ) {
        let (status_tx, status_rx) = watch::channel(Vec::new());
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(run_loop(
            BlackholeConfig {
                enabled: true,
                install_rate_per_minute: Some(4),
                install_burst: Some(1),
                ..BlackholeConfig::default()
            },
            rib,
            fib,
            BgpMetrics::with_registry(Registry::new()),
            status_tx,
            shutdown.clone(),
            OwnershipState::ephemeral([]),
        ));
        (shutdown, status_rx, task)
    }

    async fn yield_actor() {
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
    }

    fn tagged(last: u8) -> rustbgpd_rib::Route {
        route(
            host(last),
            RouteOrigin::Ebgp,
            vec![rustbgpd_wire::COMMUNITY_BLACKHOLE],
        )
    }

    #[tokio::test(start_paused = true)]
    async fn refill_exposes_exact_wake_and_releases_a_token() {
        let mut limits = InstallLimits::new(None, Some(2), Some(1));
        let now = Instant::now();
        assert_eq!(limits.admit(0, now), Ok(()));
        assert_eq!(limits.admit(0, now), Err("install_rate_limited"));
        assert_eq!(limits.next_wake, Some(now + Duration::from_secs(30)));
        tokio::time::advance(Duration::from_secs(30)).await;
        assert_eq!(limits.admit(0, Instant::now()), Ok(()));
    }

    #[tokio::test(start_paused = true)]
    async fn extreme_rate_fractional_deficit_still_wakes_in_the_future() {
        let mut bucket = TokenBucket::new(u32::MAX, 1);
        let now = Instant::now();
        assert_eq!(bucket.take(now), Ok(()));
        tokio::time::advance(Duration::from_nanos(13)).await;
        let almost_full = Instant::now();
        let wake = bucket
            .take(almost_full)
            .expect_err("fractional deficit must wait");
        assert_eq!(wake - almost_full, Duration::from_nanos(1));
        tokio::time::advance(wake - almost_full).await;
        assert_eq!(bucket.take(Instant::now()), Ok(()));
    }

    #[test]
    fn disabled_limits_preserve_input_order() {
        let limits = InstallLimits::new(None, None, None);
        let mut values = vec![v4([192, 0, 2, 2]), v4([192, 0, 2, 1])];
        let original = values.clone();
        limits.order(&mut values, |prefix| *prefix);
        assert_eq!(values, original);
    }

    #[test]
    fn cap_and_cyclic_canonical_fairness() {
        let mut limits = InstallLimits::new(Some(1), None, None);
        assert_eq!(
            limits.admit(1, Instant::now()),
            Err("active_limit_exceeded")
        );
        let v6 = Prefix::V6(Ipv6Prefix::new(Ipv6Addr::LOCALHOST, 128));
        let first = v4([192, 0, 2, 1]);
        let second = v4([192, 0, 2, 2]);
        let mut values = vec![v6, second, first];
        limits.attempted(first);
        limits.order(&mut values, |prefix| *prefix);
        assert_eq!(values, vec![second, v6, first]);
    }

    #[tokio::test(start_paused = true)]
    async fn failed_attempt_advances_cursor_and_timer_installs_before_periodic() {
        let (rib, _, _) = rib_with_events(vec![tagged(66), tagged(68)]);
        let installs = Arc::new(AtomicUsize::new(0));
        let log = Arc::new(Mutex::new(Vec::new()));
        let fib = FakeFib::rate_test(installs.clone(), log.clone(), host(66));
        let (shutdown, status, task) = spawn_actor(rib, fib);
        yield_actor().await;
        assert_eq!(installs.load(Ordering::SeqCst), 1);
        assert!(
            status
                .borrow()
                .iter()
                .any(|s| s.prefix == host(68) && s.reason == "install_rate_limited")
        );
        tokio::time::advance(Duration::from_secs(15)).await;
        yield_actor().await;
        assert_eq!(*log.lock().unwrap(), vec![host(66), host(68)]);
        assert!(
            status
                .borrow()
                .iter()
                .any(|s| s.prefix == host(68) && s.state == BlackholeState::Installed)
        );
        shutdown.cancel();
        task.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn failed_query_at_expired_wake_does_not_spin() {
        let (rib, mut rx) = mpsc::channel(8);
        let queries = Arc::new(AtomicUsize::new(0));
        let seen = queries.clone();
        tokio::spawn(async move {
            let (events, _) = broadcast::channel(1);
            while let Some(update) = rx.recv().await {
                match update {
                    RibUpdate::SubscribeRouteEvents { reply } => {
                        let _ = reply.send(events.subscribe());
                    }
                    RibUpdate::QueryBestRoutes { reply, .. }
                        if seen.fetch_add(1, Ordering::SeqCst) == 0 =>
                    {
                        let _ = reply.send(vec![tagged(66), tagged(68)]);
                    }
                    _ => {}
                }
            }
        });
        let (shutdown, _, task) = spawn_actor(rib, FakeFib::default());
        yield_actor().await;
        assert_eq!(queries.load(Ordering::SeqCst), 1);
        tokio::time::advance(Duration::from_secs(15)).await;
        yield_actor().await;
        assert_eq!(queries.load(Ordering::SeqCst), 2);
        yield_actor().await;
        assert_eq!(queries.load(Ordering::SeqCst), 2);
        shutdown.cancel();
        task.await.unwrap();
    }
}
