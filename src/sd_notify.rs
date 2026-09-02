//! systemd service-manager notifications (the `sd_notify(3)` datagram
//! protocol) without a libsystemd dependency.
//!
//! The daemon sends `READY=1` once the configured peer roster is installed,
//! `STOPPING=1` when coordinated shutdown begins, and `WATCHDOG=1` at half the
//! `WATCHDOG_USEC` interval for as long as the `PeerManager` and RIB actors keep
//! answering the same bounded core-actor probe `/readyz` uses. Without
//! `NOTIFY_SOCKET` every call is a silent no-op, so the daemon behaves
//! identically outside systemd.

use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, warn};

/// Floor for the watchdog ping interval so a degenerate `WATCHDOG_USEC`
/// cannot turn the ping loop into a busy loop.
const MIN_PING_INTERVAL: Duration = Duration::from_millis(100);
/// Retry cadence after a failed liveness probe, bounded by the ping interval,
/// so one transient miss delays the next ping by about a second instead of a
/// full interval.
const PROBE_RETRY: Duration = Duration::from_secs(1);

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
            let datagram = UnixDatagram::unbound()?;
            datagram.set_nonblocking(true)?;
            Ok(Arc::new((datagram, addr)))
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

    /// Send `WATCHDOG=1` every half `WATCHDOG_USEC` while `live` reports the
    /// core actors responsive. A failed probe skips the ping and retries after
    /// one second; a control plane that stays unresponsive therefore lets the
    /// service manager's watchdog expire. Returns immediately when either the
    /// socket or the watchdog is not configured.
    pub async fn run_watchdog<Fut>(&self, live: impl Fn() -> Fut)
    where
        Fut: Future<Output = bool>,
    {
        let (Some(interval), true) = (self.watchdog_interval, self.is_enabled()) else {
            return;
        };
        let retry = PROBE_RETRY.min(interval);
        debug!(?interval, "systemd watchdog pings enabled");
        loop {
            if live().await {
                self.send("WATCHDOG=1");
                tokio::time::sleep(interval).await;
            } else {
                warn!("core control-plane liveness probe failed; systemd watchdog ping skipped");
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
        notify.run_watchdog(|| async { true }).await;
    }

    #[tokio::test]
    async fn watchdog_without_interval_returns_immediately() {
        let (_socket, name) = abstract_socket();
        let notify = SdNotify::new(Some(&name), None);
        notify.run_watchdog(|| async { true }).await;
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
                .run_watchdog(|| async { probe_live.load(Ordering::Relaxed) })
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

    #[test]
    #[allow(
        unsafe_code,
        reason = "test inspects descriptor flags directly to prove O_NONBLOCK is set"
    )]
    fn notifier_socket_is_nonblocking_and_send_does_not_block() {
        use std::os::unix::io::AsRawFd;

        let (receiver, name) = abstract_socket();
        let notify = SdNotify::new(Some(&name), None);
        assert!(notify.is_enabled());

        let target = notify
            .target
            .as_ref()
            .expect("notification target initialized");
        let (datagram, _) = target.as_ref();

        assert!(matches!(datagram.take_error(), Ok(None)));

        let fd = datagram.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        assert_ne!(flags, -1, "fcntl F_GETFL failed");
        assert_ne!(
            flags & libc::O_NONBLOCK,
            0,
            "systemd notification socket must have O_NONBLOCK set"
        );

        // Minimise receiver buffer to reliably saturate the queue.
        let rcvbuf: libc::c_int = 1024;
        let ret = unsafe {
            libc::setsockopt(
                receiver.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                std::ptr::addr_of!(rcvbuf).cast(),
                libc::socklen_t::try_from(std::mem::size_of_val(&rcvbuf)).unwrap(),
            )
        };
        assert_eq!(ret, 0, "setsockopt SO_RCVBUF failed");

        // Flooding unread notifications must not block or hang when the socket buffer fills.
        for _ in 0..5000 {
            notify.ready();
        }

        // Datagrams were delivered up to socket capacity.
        assert_eq!(recv(&receiver).as_deref(), Some("READY=1"));
    }
}
