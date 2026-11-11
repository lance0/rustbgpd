//! systemd service-manager notifications (the `sd_notify(3)` datagram
//! protocol) without a libsystemd dependency.
//!
//! The daemon sends `READY=1` once the configured peer roster is installed,
//! `STOPPING=1` when coordinated shutdown begins, and `WATCHDOG=1` after each
//! liveness sample in which the `PeerManager` and RIB actors both answered.
//! Liveness is not readiness: a RIB that answers "stalled" from inside a long
//! unit of work fails `/readyz` and is still pinged. Without `NOTIFY_SOCKET`
//! every call is a silent no-op, so the daemon behaves identically outside
//! systemd.

use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::sync::Arc;
use std::time::Duration;

use rustbgpd_api::health_probe::CoreReadinessProbe;
use rustbgpd_telemetry::BgpMetrics;
use tracing::{debug, warn};

/// Floor for the watchdog ping interval so a degenerate `WATCHDOG_USEC`
/// cannot turn the ping loop into a busy loop.
const MIN_PING_INTERVAL: Duration = Duration::from_millis(100);
/// Retry cadence after a failed liveness sample, bounded by the sample
/// period, so one transient miss delays the next ping by about a second.
const PROBE_RETRY: Duration = Duration::from_secs(1);
/// Longest gap between liveness samples. The last ping before the actors go
/// silent is at most this old, so the service manager's deadline runs from
/// within this much of the moment they stopped answering.
const MAX_SAMPLE_PERIOD: Duration = Duration::from_secs(10);
/// Longest wait for one liveness sample: seconds, not the 200 ms readiness
/// deadline, because a slow answer is still an answer.
const MAX_SAMPLE_DEADLINE: Duration = Duration::from_secs(5);

/// Sample period and per-sample deadline for a ping interval (half
/// `WATCHDOG_USEC`): a quarter and an eighth of the watchdog timeout, capped
/// at 10 s and 5 s. A live daemon therefore pings at least every 3/8 of the
/// timeout, and one missed sample (period, deadline, retry, deadline) still
/// fits inside it.
fn sample_timing(interval: Duration) -> (Duration, Duration) {
    let period = (interval / 2).min(MAX_SAMPLE_PERIOD);
    (period, (period / 2).min(MAX_SAMPLE_DEADLINE))
}

/// One watchdog liveness sample of the core actors. A sample that got no
/// answer is logged and counted; the caller withholds the ping.
pub async fn core_actors_live(
    probe: &CoreReadinessProbe,
    metrics: &BgpMetrics,
    deadline: Duration,
) -> bool {
    match probe.check_liveness(deadline).await {
        Ok(()) => true,
        Err(error) => {
            metrics.record_systemd_watchdog_ping_skipped();
            warn!(
                ?error,
                deadline_ms = deadline.as_millis(),
                "core control-plane liveness sample got no answer; systemd watchdog ping skipped"
            );
            false
        }
    }
}

/// Notification endpoint resolved from the service-manager environment.
#[derive(Clone, Debug)]
pub struct SdNotify {
    target: Option<Arc<(UnixDatagram, SocketAddr)>>,
    watchdog_interval: Option<Duration>,
}

impl SdNotify {
    /// Resolve `NOTIFY_SOCKET`, `WATCHDOG_USEC`, and `WATCHDOG_PID` from the
    /// process environment.
    pub fn from_env() -> Self {
        let var = |name: &str| std::env::var(name).ok();
        let interval = watchdog_interval(
            var("WATCHDOG_USEC").as_deref(),
            var("WATCHDOG_PID").as_deref(),
            std::process::id(),
        );
        Self::new(var("NOTIFY_SOCKET").as_deref(), interval)
    }

    /// Build a notifier for an explicit socket (`@name` selects the abstract
    /// namespace) and ping interval. `None` for the socket disables every
    /// notification; the interval is floored at 100 ms.
    pub fn new(socket: Option<&str>, watchdog_interval: Option<Duration>) -> Self {
        let target = socket.and_then(|raw| match socket_addr(raw).and_then(|addr| {
            UnixDatagram::unbound().map(|datagram| Arc::new((datagram, addr)))
        }) {
            Ok(target) => Some(target),
            Err(error) => {
                warn!(%error, socket = raw, "systemd notification socket unusable; notifications disabled");
                None
            }
        });
        Self {
            target,
            watchdog_interval: watchdog_interval.map(|interval| interval.max(MIN_PING_INTERVAL)),
        }
    }

    /// Whether a notification socket is configured.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.target.is_some()
    }

    /// Announce that startup completed.
    pub fn ready(&self) {
        self.send("READY=1");
    }

    /// Announce that coordinated shutdown began.
    pub fn stopping(&self) {
        self.send("STOPPING=1");
    }

    /// Sample `live` every [`sample_timing`] period, passing it the sample
    /// deadline, and send `WATCHDOG=1` after every sample that reports the
    /// core actors responsive. A failed sample skips the ping and retries
    /// after one second; a control plane that stays unresponsive therefore
    /// lets the service manager's watchdog expire, one full timeout after a
    /// ping at most one sample period old. Returns immediately when either
    /// the socket or the watchdog is not configured.
    pub async fn run_watchdog<Fut>(&self, live: impl Fn(Duration) -> Fut)
    where
        Fut: Future<Output = bool>,
    {
        let (Some(interval), true) = (self.watchdog_interval, self.is_enabled()) else {
            return;
        };
        let (period, deadline) = sample_timing(interval);
        let retry = PROBE_RETRY.min(period);
        debug!(
            ?interval,
            ?period,
            ?deadline,
            "systemd watchdog pings enabled"
        );
        loop {
            if live(deadline).await {
                self.send("WATCHDOG=1");
                tokio::time::sleep(period).await;
            } else {
                tokio::time::sleep(retry).await;
            }
        }
    }

    fn send(&self, state: &str) {
        let Some(target) = &self.target else {
            return;
        };
        let (datagram, addr) = target.as_ref();
        match datagram.send_to_addr(state.as_bytes(), addr) {
            Ok(_) => debug!(state, "sent systemd notification"),
            Err(error) => warn!(%error, state, "systemd notification failed"),
        }
    }
}

fn socket_addr(raw: &str) -> std::io::Result<SocketAddr> {
    match raw.strip_prefix('@') {
        Some(name) => SocketAddr::from_abstract_name(name),
        None => SocketAddr::from_pathname(raw),
    }
}

/// Derive the ping interval from `WATCHDOG_USEC`/`WATCHDOG_PID`: half the
/// configured timeout, or `None` when the watchdog is unset, zero, malformed,
/// or addressed to another process.
fn watchdog_interval(usec: Option<&str>, pid: Option<&str>, own_pid: u32) -> Option<Duration> {
    let usec = usec?.parse::<u64>().ok().filter(|usec| *usec > 0)?;
    if let Some(pid) = pid
        && pid.parse::<u32>().ok() != Some(own_pid)
    {
        return None;
    }
    Some(Duration::from_micros(usec / 2).max(MIN_PING_INTERVAL))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use super::*;

    const RECV_TIMEOUT: Duration = Duration::from_secs(2);

    fn abstract_socket() -> (UnixDatagram, String) {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let name = format!(
            "rustbgpd-sd-notify-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let addr = SocketAddr::from_abstract_name(&name).unwrap();
        let socket = UnixDatagram::bind_addr(&addr).unwrap();
        socket.set_read_timeout(Some(RECV_TIMEOUT)).unwrap();
        (socket, format!("@{name}"))
    }

    fn recv(socket: &UnixDatagram) -> Option<String> {
        let mut buf = [0u8; 64];
        match socket.recv(&mut buf) {
            Ok(len) => Some(String::from_utf8_lossy(&buf[..len]).into_owned()),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                None
            }
            Err(error) => panic!("recv failed: {error}"),
        }
    }

    fn drain(socket: &UnixDatagram) {
        socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        while recv(socket).is_some() {}
        socket.set_read_timeout(Some(RECV_TIMEOUT)).unwrap();
    }

    #[test]
    fn ready_then_stopping_arrive_once_each_in_order() {
        let (socket, name) = abstract_socket();
        let notify = SdNotify::new(Some(&name), None);
        assert!(notify.is_enabled());

        notify.ready();
        notify.stopping();

        assert_eq!(recv(&socket).as_deref(), Some("READY=1"));
        assert_eq!(recv(&socket).as_deref(), Some("STOPPING=1"));
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        assert_eq!(
            recv(&socket),
            None,
            "no duplicate lifecycle notification is sent; watchdog pings may continue during drain"
        );
    }

    #[test]
    fn pathname_socket_receives_notifications() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notify");
        let socket = UnixDatagram::bind(&path).unwrap();
        socket.set_read_timeout(Some(RECV_TIMEOUT)).unwrap();

        let notify = SdNotify::new(path.to_str(), None);
        notify.ready();

        assert_eq!(recv(&socket).as_deref(), Some("READY=1"));
    }

    #[tokio::test]
    async fn no_socket_is_a_silent_no_op() {
        let notify = SdNotify::new(None, Some(Duration::from_millis(100)));
        assert!(!notify.is_enabled());
        notify.ready();
        notify.stopping();
        // Must return instead of looping when nothing can receive the ping.
        notify.run_watchdog(|_| async { true }).await;
    }

    #[tokio::test]
    async fn watchdog_without_interval_returns_immediately() {
        let (_socket, name) = abstract_socket();
        let notify = SdNotify::new(Some(&name), None);
        notify.run_watchdog(|_| async { true }).await;
    }

    fn pings(socket: &UnixDatagram) -> usize {
        let mut count = 0;
        let mut buf = [0u8; 64];
        loop {
            match socket.recv(&mut buf) {
                Ok(len) => {
                    assert_eq!(&buf[..len], b"WATCHDOG=1");
                    count += 1;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return count,
                Err(error) => panic!("recv failed: {error}"),
            }
        }
    }

    /// The shipped `WatchdogSec=5min` on a paused clock. The documented
    /// tolerance depends on this cadence: a ping after every live sample, ten
    /// seconds apart, so the last ping before silence is under ten seconds
    /// old and the abort follows 290 to 300 s after the actors stop.
    #[tokio::test(start_paused = true)]
    async fn shipped_timeout_pings_every_ten_seconds_and_retries_a_miss_each_second() {
        let (socket, name) = abstract_socket();
        socket.set_nonblocking(true).unwrap();
        let interval = watchdog_interval(Some("300000000"), None, std::process::id());
        let notify = SdNotify::new(Some(&name), interval);
        let live = Arc::new(AtomicBool::new(true));
        let samples = Arc::new(AtomicUsize::new(0));
        let (probe_live, probe_samples) = (live.clone(), samples.clone());
        let task = tokio::spawn(async move {
            notify
                .run_watchdog(|deadline| {
                    assert_eq!(deadline, Duration::from_secs(5));
                    probe_samples.fetch_add(1, Ordering::Relaxed);
                    let live = probe_live.load(Ordering::Relaxed);
                    async move { live }
                })
                .await;
        });
        let wait = |secs_f64: f64| tokio::time::sleep(Duration::from_secs_f64(secs_f64));

        // t = 0.5 s: the first sample pinged at once.
        wait(0.5).await;
        assert_eq!(pings(&socket), 1);
        // t = 9.5 s: nothing between samples. t = 10.5 s: the next ping.
        wait(9.0).await;
        assert_eq!(pings(&socket), 0);
        wait(1.0).await;
        assert_eq!(pings(&socket), 1);
        // t = 300.5 s: one ping per ten seconds across a whole timeout.
        wait(290.0).await;
        assert_eq!(pings(&socket), 29);

        // Silence: no ping however long it lasts, one retry per second.
        live.store(false, Ordering::Relaxed);
        let before = samples.load(Ordering::Relaxed);
        wait(300.0).await;
        assert_eq!(pings(&socket), 0, "a silent control plane is never pinged");
        // The first failed sample is the one already due at t = 310 s.
        assert_eq!(samples.load(Ordering::Relaxed) - before, 291);

        // Recovery pings on the next one-second retry.
        live.store(true, Ordering::Relaxed);
        wait(1.0).await;
        assert_eq!(pings(&socket), 1);
        task.abort();
    }

    #[test]
    fn sample_timing_scales_with_the_timeout_and_caps_at_ten_and_five_seconds() {
        let secs = Duration::from_secs;
        // Interval is half WATCHDOG_USEC: 5 min, 1 min, 8 s.
        assert_eq!(sample_timing(secs(150)), (secs(10), secs(5)));
        assert_eq!(sample_timing(secs(30)), (secs(10), secs(5)));
        assert_eq!(sample_timing(secs(4)), (secs(2), secs(1)));
        for interval in [MIN_PING_INTERVAL, secs(4), secs(30), secs(150)] {
            let (period, deadline) = sample_timing(interval);
            let timeout = interval * 2;
            assert!(
                period + deadline + PROBE_RETRY.min(period) + deadline < timeout,
                "one missed sample must fit inside a {timeout:?} watchdog"
            );
        }
    }

    fn core_probe() -> (
        CoreReadinessProbe,
        tokio::sync::mpsc::Receiver<rustbgpd_api::peer_types::PeerManagerCommand>,
        tokio::sync::mpsc::Receiver<rustbgpd_rib::RibReadinessQuery>,
    ) {
        let (peer_tx, peer_rx) = tokio::sync::mpsc::channel(1);
        let (rib_query_tx, _) = tokio::sync::mpsc::channel(1);
        let (rib_readiness_tx, rib_readiness_rx) = tokio::sync::mpsc::channel(1);
        let probe =
            CoreReadinessProbe::new(peer_tx, rib_query_tx).with_rib_readiness(rib_readiness_tx);
        (probe, peer_rx, rib_readiness_rx)
    }

    async fn answer(
        peer_rx: &mut tokio::sync::mpsc::Receiver<rustbgpd_api::peer_types::PeerManagerCommand>,
        rib_rx: &mut tokio::sync::mpsc::Receiver<rustbgpd_rib::RibReadinessQuery>,
        rib_answer: Result<usize, rustbgpd_rib::RibReadinessError>,
    ) {
        let Some(rustbgpd_api::peer_types::PeerManagerCommand::Ping { reply }) =
            peer_rx.recv().await
        else {
            panic!("liveness must ping the peer manager");
        };
        reply.send(()).unwrap();
        let rustbgpd_rib::RibReadinessQuery::LocRibCount { reply, .. } =
            rib_rx.recv().await.unwrap();
        reply.send(rib_answer).unwrap();
    }

    /// The function the daemon hands to `run_watchdog`: a stalled RIB answer
    /// keeps the ping and counts nothing; silence withholds it and counts.
    #[tokio::test(start_paused = true)]
    async fn core_actors_live_keeps_the_ping_on_stalled_and_counts_only_silence() {
        use rustbgpd_rib::RibReadinessError as Stalled;
        let deadline = Duration::from_secs(5);
        let metrics = BgpMetrics::new();
        let skipped = || {
            let families = metrics.registry().gather();
            let family = families
                .iter()
                .find(|family| family.name() == "bgp_systemd_watchdog_pings_skipped_total")
                .expect("skip counter is registered");
            family.get_metric()[0].get_counter().get_value()
        };
        let (probe, mut peer_rx, mut rib_rx) = core_probe();

        for rib_answer in [
            Ok(0),
            Err(Stalled::PolicyTransitionStalled),
            Err(Stalled::SelectionReleaseStalled),
            Err(Stalled::PeerTeardownStalled),
        ] {
            let (live, ()) = tokio::join!(
                core_actors_live(&probe, &metrics, deadline),
                answer(&mut peer_rx, &mut rib_rx, rib_answer)
            );
            assert!(live, "{rib_answer:?} is an answer from a running RIB actor");
        }
        assert!(skipped().abs() < f64::EPSILON);

        // Nobody answers: the sample runs out its deadline.
        assert!(!core_actors_live(&probe, &metrics, deadline).await);
        assert!((skipped() - 1.0).abs() < f64::EPSILON);

        // Actors gone: lanes closed.
        drop((peer_rx, rib_rx));
        assert!(!core_actors_live(&probe, &metrics, deadline).await);
        assert!((skipped() - 2.0).abs() < f64::EPSILON);
    }

    // The receiver blocks on a std socket, so the ping task needs its own worker.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn watchdog_pings_while_live_and_stops_when_stalled() {
        let (socket, name) = abstract_socket();
        let notify = SdNotify::new(Some(&name), Some(Duration::from_millis(100)));
        let live = Arc::new(AtomicBool::new(true));
        let probe_live = live.clone();
        let task = tokio::spawn(async move {
            notify
                .run_watchdog(|_| async { probe_live.load(Ordering::Relaxed) })
                .await;
        });

        assert_eq!(recv(&socket).as_deref(), Some("WATCHDOG=1"));
        assert_eq!(recv(&socket).as_deref(), Some("WATCHDOG=1"));

        live.store(false, Ordering::Relaxed);
        drain(&socket);
        socket
            .set_read_timeout(Some(Duration::from_millis(400)))
            .unwrap();
        assert_eq!(
            recv(&socket),
            None,
            "a stalled control plane must not be pinged as live"
        );

        live.store(true, Ordering::Relaxed);
        socket.set_read_timeout(Some(RECV_TIMEOUT)).unwrap();
        assert_eq!(
            recv(&socket).as_deref(),
            Some("WATCHDOG=1"),
            "pings resume once the probe recovers"
        );
        task.abort();
    }

    #[test]
    fn watchdog_usec_boundaries() {
        let own = std::process::id();
        assert_eq!(watchdog_interval(None, None, own), None);
        assert_eq!(watchdog_interval(Some(""), None, own), None);
        assert_eq!(watchdog_interval(Some("0"), None, own), None);
        assert_eq!(watchdog_interval(Some("-1"), None, own), None);
        assert_eq!(watchdog_interval(Some("5s"), None, own), None);
        assert_eq!(
            watchdog_interval(Some("1"), None, own),
            Some(MIN_PING_INTERVAL),
            "a degenerate timeout floors at the minimum ping interval"
        );
        assert_eq!(
            watchdog_interval(Some("300000000"), None, own),
            Some(Duration::from_secs(150))
        );
        assert_eq!(
            watchdog_interval(Some(&u64::MAX.to_string()), None, own),
            Some(Duration::from_micros(u64::MAX / 2))
        );
        assert_eq!(
            watchdog_interval(Some("300000000"), Some(&own.to_string()), own),
            Some(Duration::from_secs(150))
        );
        assert_eq!(
            watchdog_interval(
                Some("300000000"),
                Some(&(own.wrapping_add(1)).to_string()),
                own
            ),
            None,
            "a watchdog addressed to another process is not ours"
        );
        assert_eq!(watchdog_interval(Some("300000000"), Some("pid"), own), None);
    }

    #[test]
    fn socket_addr_distinguishes_abstract_from_pathname() {
        assert_eq!(
            socket_addr("@notify").unwrap().as_abstract_name(),
            Some(&b"notify"[..])
        );
        assert_eq!(
            socket_addr("/run/systemd/notify").unwrap().as_pathname(),
            Some(std::path::Path::new("/run/systemd/notify"))
        );
    }

    #[test]
    fn unusable_socket_disables_notifications() {
        let too_long = "/".repeat(200);
        let notify = SdNotify::new(Some(&too_long), Some(Duration::from_secs(1)));
        assert!(!notify.is_enabled());
        notify.ready();
    }
}
