//! Linux socket runtime: one raw `ICMPv6` socket per started interface, a
//! reader task per socket, and one actor that owns the [`Engine`].

use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::io::{self, IoSliceMut};
use std::net::{Ipv6Addr, SocketAddrV6};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use nix::sys::socket::{ControlMessageOwned, MsgFlags, SockaddrIn6, recvmsg};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tokio_util::task::AbortOnDropHandle;
use tracing::{debug, info, warn};

use super::engine::{DiscoveryConfig, DiscoveryEvent, Engine, LinkEvent, Transmit};
use super::packet::{self, DropReason, NdMessage};

const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
const ALL_ROUTERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);
/// Received packets queued from reader tasks to the actor. A full queue
/// back-pressures the readers, and the kernel socket buffer drops the excess.
const RECEIVE_QUEUE: usize = 256;
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
/// How long an interface's address list is reused for the own-address check,
/// which now runs on every RA: a flood of RAs from known sources must not
/// become one `getifaddrs` netlink dump per packet.
const LOCAL_ADDRESS_TTL: Duration = Duration::from_secs(1);
/// Socket-open retry backoff: 1 s, doubling, capped at 60 s. Independent of
/// the RA timer, so discovery recovers even with sending off and no
/// candidates to expire.
const OPEN_RETRY_INITIAL: Duration = Duration::from_secs(1);
const OPEN_RETRY_MAX: Duration = Duration::from_secs(60);

#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    #[error("interface-only neighbor discovery needs CAP_NET_RAW to open a raw ICMPv6 socket: {0}")]
    MissingCapNetRaw(#[source] io::Error),
    #[error("cannot open a raw ICMPv6 socket: {0}")]
    Socket(#[source] io::Error),
}

/// What a queued [`DiscoveryEvent`] is coalesced under.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum EventKey {
    Binding(String),
    Conflict(String),
}

/// Events waiting for the neighbor owner: per key the latest event and how
/// many times to deliver it, served round-robin so a key with many
/// deliveries cannot hold back the others.
#[derive(Default)]
struct PendingEvents {
    order: VecDeque<EventKey>,
    events: HashMap<EventKey, (DiscoveryEvent, u64)>,
}

/// Create the discovery → neighbor owner event queue.
///
/// Its RA input is untrusted link traffic, and the owner can be busy, so the
/// queue coalesces instead of growing per event. It holds at most one entry
/// per interface for each kind:
/// - the latest binding change, which replaces a pending one: the owner's
///   reconcile is level-triggered on `current`, so a binding discovery has
///   already dropped is never applied;
/// - the latest conflict, with the number of conflicts it stands for, each
///   delivered, so engine conflicts are counted exactly. The deliveries
///   carry the latest `bound` and `other`.
///
/// Discovery raises every conflict itself, including a foreign router's
/// first binding beside an Established peer the owner learned from an
/// inbound connection (the owner reports that peer's address with
/// `session_established`), so the counts stay exact however far the owner
/// falls behind.
///
/// Keys are served round-robin, so a conflict can be delivered ahead of a
/// binding change queued between two conflicts. Learned and expired
/// candidates are only logged; the actor logs them itself and never queues
/// them.
pub(crate) fn event_channel() -> (EventSender, DiscoveryEvents) {
    let pending = Arc::new(Mutex::new(PendingEvents::default()));
    // One wake token covers every pending entry: the receiver drains the map
    // before it waits again.
    let (wake_tx, wake_rx) = mpsc::channel(1);
    (
        EventSender {
            pending: Arc::clone(&pending),
            wake: wake_tx,
        },
        DiscoveryEvents {
            pending,
            wake: wake_rx,
        },
    )
}

/// Sending half of [`event_channel`]. Never blocks.
pub(crate) struct EventSender {
    pending: Arc<Mutex<PendingEvents>>,
    wake: mpsc::Sender<()>,
}

impl EventSender {
    pub(crate) fn send(&self, event: DiscoveryEvent) {
        let key = match &event {
            DiscoveryEvent::BindingChanged { interface, .. } => {
                EventKey::Binding(interface.clone())
            }
            DiscoveryEvent::Conflict { interface, .. } => EventKey::Conflict(interface.clone()),
            DiscoveryEvent::CandidateLearned { .. } | DiscoveryEvent::CandidateExpired { .. } => {
                return;
            }
        };
        {
            let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
            let pending = &mut *pending;
            match pending.events.entry(key) {
                Entry::Occupied(mut slot) => {
                    let (latest, count) = slot.get_mut();
                    if matches!(event, DiscoveryEvent::Conflict { .. }) {
                        *count += 1;
                    }
                    *latest = event;
                }
                Entry::Vacant(slot) => {
                    pending.order.push_back(slot.key().clone());
                    slot.insert((event, 1));
                }
            }
        }
        // Full means a token is already queued, and the receiver drains the
        // map after taking it; closed means the owner is gone.
        let _ = self.wake.try_send(());
    }

    /// Entries waiting for the owner.
    #[cfg(test)]
    fn pending(&self) -> usize {
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .order
            .len()
    }
}

/// Receiving half of [`event_channel`], held by the neighbor owner.
pub struct DiscoveryEvents {
    pending: Arc<Mutex<PendingEvents>>,
    wake: mpsc::Receiver<()>,
}

impl DiscoveryEvents {
    /// The next event, or `None` once the actor has exited and every queued
    /// event was received.
    pub async fn recv(&mut self) -> Option<DiscoveryEvent> {
        loop {
            // A counted backlog never waits on the wake channel, so spend the
            // task's cooperative budget here, before anything is taken: the
            // owner yields to other tasks, and a recv cancelled at this
            // await loses nothing.
            tokio::task::consume_budget().await;
            if let Some(event) = self.pop() {
                return Some(event);
            }
            self.wake.recv().await?;
        }
    }

    /// Deliver from the front entry, then move it to the back if it has more.
    fn pop(&self) -> Option<DiscoveryEvent> {
        let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        let pending = &mut *pending;
        let key = pending.order.pop_front()?;
        let Some((latest, count)) = pending.events.get_mut(&key) else {
            debug_assert!(false, "a queued key has no pending event");
            return None;
        };
        *count -= 1;
        let event = latest.clone();
        if *count > 0 {
            pending.order.push_back(key);
        } else {
            pending.events.remove(&key);
        }
        Some(event)
    }
}

/// Handle to the discovery actor. Every input is a non-blocking send; events
/// arrive on the receiver returned by [`RaDiscovery::spawn`].
pub struct RaDiscovery {
    commands: mpsc::UnboundedSender<Command>,
    counters: Arc<Counters>,
    task: tokio::task::JoinHandle<()>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Command {
    Start(String),
    Stop(String),
    Link(LinkEvent),
    SessionEstablished(String, Ipv6Addr),
    SessionFailed(String),
}

/// Bounded errno classes for failed RA and RS sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SendFailure {
    AddressUnavailable,
    NetworkUnavailable,
    PermissionDenied,
    WouldBlock,
    Other,
}

impl SendFailure {
    const ALL: [Self; 5] = [
        Self::AddressUnavailable,
        Self::NetworkUnavailable,
        Self::PermissionDenied,
        Self::WouldBlock,
        Self::Other,
    ];

    fn as_str(self) -> &'static str {
        match self {
            Self::AddressUnavailable => "address_unavailable",
            Self::NetworkUnavailable => "network_unavailable",
            Self::PermissionDenied => "permission_denied",
            Self::WouldBlock => "would_block",
            Self::Other => "other",
        }
    }

    fn classify(error: &io::Error) -> Self {
        match error.raw_os_error() {
            Some(libc::EADDRNOTAVAIL) => Self::AddressUnavailable,
            Some(libc::ENETDOWN | libc::ENETUNREACH | libc::EHOSTUNREACH | libc::ENODEV) => {
                Self::NetworkUnavailable
            }
            Some(libc::EACCES | libc::EPERM) => Self::PermissionDenied,
            Some(libc::EAGAIN) => Self::WouldBlock,
            _ => Self::Other,
        }
    }
}

#[derive(Default)]
struct Counters {
    drops: [AtomicU64; DropReason::ALL.len()],
    socket_open_failures: AtomicU64,
    send_failures: [AtomicU64; SendFailure::ALL.len()],
    /// Exports the drop and socket-open counts; absent in unit tests.
    metrics: Option<rustbgpd_telemetry::BgpMetrics>,
}

impl Counters {
    fn bump(&self, reason: DropReason) {
        self.drops[reason as usize].fetch_add(1, Ordering::Relaxed);
        if let Some(metrics) = &self.metrics {
            metrics.record_unnumbered_ra_drop(reason.as_str());
        }
    }

    fn socket_open_failed(&self) {
        self.socket_open_failures.fetch_add(1, Ordering::Relaxed);
        if let Some(metrics) = &self.metrics {
            metrics.record_unnumbered_ra_socket_open_failure();
        }
    }
}

/// Opens the per-interface socket; replaced by a fake in tests.
type Opener = Box<dyn FnMut(&str, u32) -> io::Result<Socket> + Send>;
/// Sends one datagram; replaced by a fake in tests.
type Sender = Box<dyn FnMut(&Socket, &[u8], &socket2::SockAddr) -> io::Result<usize> + Send>;

impl RaDiscovery {
    /// Open-probe a raw `ICMPv6` socket, then spawn the actor on the current
    /// Tokio runtime. A missing `CAP_NET_RAW` is a typed error.
    pub fn spawn(
        config: DiscoveryConfig,
        metrics: rustbgpd_telemetry::BgpMetrics,
    ) -> Result<(Self, DiscoveryEvents), DiscoveryError> {
        drop(raw_socket()?);
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() ^ u64::from(d.subsec_nanos()))
            ^ u64::from(std::process::id());
        // Unbounded by design, bounded by its one producer: only the peer
        // manager sends, one command per configured interface added or
        // removed, per change of an interface's state in its link snapshot,
        // per bound session's state transition, and per reconcile that
        // confirms or releases a bound session (`session_established` /
        // `session_failed`); its sends never wait. The actor applies each command without waiting on another
        // task, so the queue holds only what the peer manager produced
        // since the actor last ran. A bounded send would make the peer
        // manager wait on (or drop) a link or session input that discovery
        // must not lose.
        let (commands, command_rx) = mpsc::unbounded_channel();
        let (mut actor, event_rx, received_rx) =
            Actor::new(config, seed, Box::new(interface_socket));
        actor.counters = Arc::new(Counters {
            metrics: Some(metrics),
            ..Counters::default()
        });
        let counters = Arc::clone(&actor.counters);
        let task = tokio::spawn(actor.run(command_rx, received_rx));
        Ok((
            Self {
                commands,
                counters,
                task,
            },
            event_rx,
        ))
    }

    /// A handle whose inputs are recorded instead of driving an actor, for
    /// tests of the neighbor owner.
    #[cfg(test)]
    pub(crate) fn recording() -> (Self, mpsc::UnboundedReceiver<Command>) {
        let (commands, command_rx) = mpsc::unbounded_channel();
        let handle = Self {
            commands,
            counters: Arc::default(),
            task: tokio::spawn(async {}),
        };
        (handle, command_rx)
    }

    pub fn start(&self, interface: &str) {
        let _ = self.commands.send(Command::Start(interface.to_owned()));
    }

    pub fn stop(&self, interface: &str) {
        let _ = self.commands.send(Command::Stop(interface.to_owned()));
    }

    pub fn link_event(&self, event: LinkEvent) {
        let _ = self.commands.send(Command::Link(event));
    }

    /// The interface's session with `peer` reached Established; discovery
    /// stops moving its binding and reports any other new source as a
    /// conflict. Interface-only peers are link-local IPv6; an IPv4 `peer`
    /// is mapped and so never matches an RA source.
    pub fn session_established(&self, interface: &str, peer: std::net::IpAddr) {
        let peer = match peer {
            std::net::IpAddr::V6(address) => address,
            std::net::IpAddr::V4(address) => address.to_ipv6_mapped(),
        };
        let _ = self
            .commands
            .send(Command::SessionEstablished(interface.to_owned(), peer));
    }

    /// The interface's session failed; the binding may move again.
    pub fn session_failed(&self, interface: &str) {
        let _ = self
            .commands
            .send(Command::SessionFailed(interface.to_owned()));
    }

    pub fn dropped(&self, reason: DropReason) -> u64 {
        self.counters.drops[reason as usize].load(Ordering::Relaxed)
    }

    /// Failed per-interface socket opens (each is retried with backoff).
    pub fn socket_open_failures(&self) -> u64 {
        self.counters.socket_open_failures.load(Ordering::Relaxed)
    }

    /// Failed RA/RS sends, including retries, grouped by errno class.
    pub fn send_failures(&self) -> [(&'static str, u64); 5] {
        SendFailure::ALL.map(|reason| {
            (
                reason.as_str(),
                self.counters.send_failures[reason as usize].load(Ordering::Relaxed),
            )
        })
    }

    /// Send final lifetime-0 RAs where advertising, close the sockets and
    /// stop the actor.
    pub async fn shutdown(self) {
        drop(self.commands);
        match tokio::time::timeout(SHUTDOWN_TIMEOUT, self.task).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => warn!(%error, "RA discovery actor panicked"),
            Err(_) => warn!("RA discovery actor shutdown timed out"),
        }
    }
}

/// Open and close a raw `ICMPv6` socket: `--check` and startup refuse an
/// interface-only configuration with [`DiscoveryError::MissingCapNetRaw`].
pub fn probe_raw_socket() -> Result<(), DiscoveryError> {
    raw_socket().map(drop)
}

fn raw_socket() -> Result<Socket, DiscoveryError> {
    Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6)).map_err(|error| {
        match error.raw_os_error() {
            Some(libc::EPERM | libc::EACCES) => DiscoveryError::MissingCapNetRaw(error),
            _ => DiscoveryError::Socket(error),
        }
    })
}

/// The per-interface socket: bound to the device, `ICMPv6` filtered to RS and
/// RA, Hop Limit reported on receive, sent at Hop Limit 255, multicast
/// loopback off so our own RAs never come back, and joined to all-routers so
/// solicitations arrive.
fn interface_socket(name: &str, ifindex: u32) -> io::Result<Socket> {
    let socket = raw_socket().map_err(|e| match e {
        DiscoveryError::MissingCapNetRaw(e) | DiscoveryError::Socket(e) => e,
    })?;
    socket.bind_device(Some(name.as_bytes()))?;
    // Bound by name: refuse if the name already belongs to a newer interface;
    // its own link event will reopen the socket.
    if nix::net::if_::if_nametoindex(name).map_err(io::Error::from)? != ifindex {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "interface was recreated with another ifindex",
        ));
    }
    socket.set_multicast_loop_v6(false)?;
    socket.set_multicast_hops_v6(u32::from(packet::ND_HOP_LIMIT))?;
    socket.set_unicast_hops_v6(u32::from(packet::ND_HOP_LIMIT))?;
    socket.set_multicast_if_v6(ifindex)?;
    socket.set_recv_hoplimit_v6(true)?;
    socket.join_multicast_v6(&ALL_ROUTERS, ifindex)?;
    set_icmp6_filter(&socket)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

/// `ICMP6_FILTER`: pass only Router Solicitation and Router Advertisement.
/// Linux semantics: a set bit blocks that type.
#[allow(
    unsafe_code,
    reason = "ICMP6_FILTER has no safe wrapper in socket2, nix or libc"
)]
fn set_icmp6_filter(socket: &Socket) -> io::Result<()> {
    const ICMP6_FILTER: libc::c_int = 1;
    let mut filter = [u32::MAX; 8];
    for kind in [packet::ND_ROUTER_SOLICIT, packet::ND_ROUTER_ADVERT] {
        filter[usize::from(kind >> 5)] &= !(1u32 << (kind & 31));
    }
    let len = libc::socklen_t::try_from(std::mem::size_of_val(&filter))
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: the fd is a live socket we own; `filter` is a live
    // `struct icmp6_filter` (eight u32 words) of the declared length.
    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_ICMPV6,
            ICMP6_FILTER,
            filter.as_ptr().cast(),
            len,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Register an opened socket with the reactor.
#[allow(
    unsafe_code,
    reason = "tokio exposes AsyncFd registration only as an unsafe I/O-safety contract"
)]
fn register(socket: Socket) -> io::Result<AsyncFd<Socket>> {
    // SAFETY: `Socket` owns its fd, so `as_raw_fd` returns the same open
    // descriptor until the socket is dropped, and `AsyncFd` drops it only
    // after deregistering. The `AsyncFd` is held only behind an `Arc`, so
    // no `get_mut`/`into_inner` can close or replace the socket, and the
    // fd is never duplicated or closed through a raw handle elsewhere.
    unsafe { AsyncFd::register(socket) }.map_err(io::Error::from)
}

struct Received {
    ifindex: u32,
    /// The engine's link generation the socket was opened under.
    generation: u64,
    source: Ipv6Addr,
    hop_limit: Option<u8>,
    payload: Vec<u8>,
}

fn recv_one(socket: &Socket, buf: &mut [u8]) -> io::Result<(Ipv6Addr, Option<u8>, usize)> {
    let mut cmsg = nix::cmsg_space!(libc::c_int);
    let mut iov = [IoSliceMut::new(buf)];
    let msg = recvmsg::<SockaddrIn6>(
        socket.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg),
        MsgFlags::MSG_DONTWAIT,
    )
    .map_err(io::Error::from)?;
    let hop_limit = msg.cmsgs().map_err(io::Error::from)?.find_map(|c| match c {
        ControlMessageOwned::Ipv6HopLimit(h) => u8::try_from(h).ok(),
        _ => None,
    });
    let source = msg.address.map_or(Ipv6Addr::UNSPECIFIED, |a| a.ip());
    Ok((source, hop_limit, msg.bytes))
}

async fn reader(
    socket: Arc<AsyncFd<Socket>>,
    ifindex: u32,
    generation: u64,
    tx: mpsc::Sender<Received>,
) {
    // An RA is at most one MTU; this also holds any non-jumbogram whole.
    let mut buf = vec![0u8; 65_535];
    loop {
        let Ok(mut guard) = socket.readable().await else {
            return;
        };
        match guard.try_io(|s| recv_one(s.get_ref(), &mut buf)) {
            Ok(Ok((source, hop_limit, len))) => {
                let received = Received {
                    ifindex,
                    generation,
                    source,
                    hop_limit,
                    payload: buf[..len].to_vec(),
                };
                if tx.send(received).await.is_err() {
                    return;
                }
            }
            Ok(Err(error)) => debug!(ifindex, %error, "RA socket receive failed"),
            Err(_would_block) => {}
        }
    }
}

struct InterfaceSocket {
    name: String,
    ifindex: u32,
    generation: u64,
    socket: Arc<AsyncFd<Socket>>,
    _reader: AbortOnDropHandle<()>,
    send_warned: bool,
}

struct Actor {
    engine: Engine,
    sockets: HashMap<String, InterfaceSocket>,
    events: EventSender,
    counters: Arc<Counters>,
    received_tx: mpsc::Sender<Received>,
    local_addresses: HashMap<String, (Instant, Vec<Ipv6Addr>)>,
    opener: Opener,
    open_retries: HashMap<String, OpenRetry>,
    sender: Sender,
    /// A link-up RS not yet sent (no socket, or the send failed), keyed by
    /// interface name. Retried until it is sent; dropped on stop or a
    /// generation change.
    pending_rs: HashMap<String, PendingRs>,
}

struct PendingRs {
    ifindex: u32,
    generation: u64,
    failures: u32,
    /// After a send failure, not before this (same backoff as socket opens).
    at: Instant,
}

enum Input {
    Command(Command),
    Packet(Received),
    Wake,
}

/// A failed open for one (ifindex, generation) and when to try again.
struct OpenRetry {
    ifindex: u32,
    generation: u64,
    failures: u32,
    at: Instant,
}

fn open_backoff(failures: u32) -> Duration {
    OPEN_RETRY_INITIAL
        .saturating_mul(1 << failures.saturating_sub(1).min(16))
        .min(OPEN_RETRY_MAX)
}

impl Actor {
    fn new(
        config: DiscoveryConfig,
        seed: u64,
        opener: Opener,
    ) -> (Self, DiscoveryEvents, mpsc::Receiver<Received>) {
        let (events, event_rx) = event_channel();
        let (received_tx, received_rx) = mpsc::channel(RECEIVE_QUEUE);
        let actor = Self {
            engine: Engine::new(config, seed),
            sockets: HashMap::new(),
            events,
            counters: Arc::default(),
            received_tx,
            local_addresses: HashMap::new(),
            opener,
            open_retries: HashMap::new(),
            sender: Box::new(Socket::send_to),
            pending_rs: HashMap::new(),
        };
        (actor, event_rx, received_rx)
    }

    /// The next engine deadline, socket-open retry or RS resend. An RS that
    /// is waiting for its socket wakes nothing: the open retry does.
    fn next_wake(&self) -> Option<Instant> {
        let rs = self
            .pending_rs
            .iter()
            .filter(|(name, p)| self.has_socket(name, p.ifindex, p.generation))
            .map(|(_, p)| p.at);
        let retry = self.open_retries.values().map(|r| r.at).chain(rs).min();
        match (self.engine.next_deadline(), retry) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    async fn run(
        mut self,
        mut commands: mpsc::UnboundedReceiver<Command>,
        mut received: mpsc::Receiver<Received>,
    ) {
        loop {
            let deadline = self.next_wake();
            let sleep = async {
                match deadline {
                    Some(at) => tokio::time::sleep_until(at.into()).await,
                    None => std::future::pending().await,
                }
            };
            let input = tokio::select! {
                command = commands.recv() => {
                    let Some(command) = command else {
                        self.engine.stop_all();
                        self.flush(Instant::now());
                        return;
                    };
                    Input::Command(command)
                }
                Some(packet) = received.recv() => Input::Packet(packet),
                () = sleep => Input::Wake,
            };
            self.handle(input, Instant::now());
        }
    }

    /// Apply one input. Socket reconciliation runs only for control inputs
    /// and timer wakes, which are the only inputs that change which sockets
    /// are wanted or retry a failed open; a received packet never does, so
    /// a flood on one port does not re-inventory every other port.
    fn handle(&mut self, input: Input, now: Instant) {
        let reconcile = match input {
            Input::Packet(packet) => {
                self.received(&packet, now);
                false
            }
            Input::Command(command) => {
                self.command(command, now);
                true
            }
            Input::Wake => {
                self.engine.poll(now);
                true
            }
        };
        if reconcile {
            self.open_sockets(now);
        }
        self.flush(now);
        if reconcile {
            self.close_stale_sockets();
            self.send_pending_rs(now);
        }
    }

    fn has_socket(&self, name: &str, ifindex: u32, generation: u64) -> bool {
        self.sockets
            .get(name)
            .is_some_and(|s| (s.ifindex, s.generation) == (ifindex, generation))
    }

    /// Send every pending RS whose socket is open and whose backoff is over.
    fn send_pending_rs(&mut self, now: Instant) {
        let due: Vec<String> = self
            .pending_rs
            .iter()
            .filter(|(name, p)| p.at <= now && self.has_socket(name, p.ifindex, p.generation))
            .map(|(name, _)| name.clone())
            .collect();
        for name in due {
            let ifindex = self.pending_rs[&name].ifindex;
            if self.transmit(Transmit::RouterSolicitation { ifindex }) {
                self.pending_rs.remove(&name);
            } else if let Some(p) = self.pending_rs.get_mut(&name) {
                p.failures += 1;
                p.at = now + open_backoff(p.failures);
            }
        }
    }

    fn command(&mut self, command: Command, now: Instant) {
        match command {
            Command::Start(name) => self.engine.start(&name),
            Command::Stop(name) => self.engine.stop(&name),
            Command::Link(event) => self.engine.on_link(&event, now),
            Command::SessionEstablished(name, peer) => {
                self.engine.session_established(&name, peer);
            }
            Command::SessionFailed(name) => self.engine.session_failed(&name, now),
        }
    }

    fn received(&mut self, packet: &Received, now: Instant) {
        let local = &mut self.local_addresses;
        let result = match packet::parse(&packet.payload, packet.source, packet.hop_limit) {
            Ok(NdMessage::RouterAdvertisement {
                router_lifetime_secs,
            }) => self.engine.on_router_advertisement(
                packet.ifindex,
                packet.generation,
                packet.source,
                router_lifetime_secs,
                now,
                |name, source| is_local_address(local, name, source, now, interface_addresses),
            ),
            Ok(NdMessage::RouterSolicitation) => {
                self.engine
                    .on_router_solicitation(packet.ifindex, packet.generation, now);
                Ok(())
            }
            Err(reason) => Err(reason),
        };
        if let Err(reason) = result {
            self.counters.bump(reason);
            debug!(
                ifindex = packet.ifindex,
                source = %packet.source,
                reason = reason.as_str(),
                "router discovery packet dropped"
            );
        }
    }

    /// Open a socket for every bound interface that lacks one for its
    /// current (ifindex, generation). A new generation gets a new socket, so
    /// anything the kernel buffered for the old link is discarded with it.
    fn open_sockets(&mut self, now: Instant) {
        let wanted: Vec<(String, u32, u64)> = self
            .engine
            .bound_interfaces()
            .filter(|(name, ifindex, generation)| {
                self.sockets
                    .get(*name)
                    .is_none_or(|s| (s.ifindex, s.generation) != (*ifindex, *generation))
            })
            .map(|(name, ifindex, generation)| (name.to_owned(), ifindex, generation))
            .collect();
        for (name, ifindex, generation) in wanted {
            let previous = self
                .open_retries
                .get(&name)
                .filter(|r| (r.ifindex, r.generation) == (ifindex, generation));
            if previous.is_some_and(|r| r.at > now) {
                continue;
            }
            let failures = previous.map_or(0, |r| r.failures);
            match (self.opener)(&name, ifindex).and_then(register) {
                Ok(socket) => {
                    self.open_retries.remove(&name);
                    let socket = Arc::new(socket);
                    let reader = AbortOnDropHandle::new(tokio::spawn(reader(
                        Arc::clone(&socket),
                        ifindex,
                        generation,
                        self.received_tx.clone(),
                    )));
                    debug!(interface = %name, ifindex, "RA socket open");
                    self.sockets.insert(
                        name.clone(),
                        InterfaceSocket {
                            name: name.clone(),
                            ifindex,
                            generation,
                            socket,
                            _reader: reader,
                            send_warned: false,
                        },
                    );
                }
                Err(error) => {
                    let failures = failures + 1;
                    let retry_in = open_backoff(failures);
                    self.counters.socket_open_failed();
                    warn!(interface = %name, ifindex, %error, ?retry_in, "cannot open RA socket");
                    self.open_retries.insert(
                        name,
                        OpenRetry {
                            ifindex,
                            generation,
                            failures,
                            at: now + retry_in,
                        },
                    );
                }
            }
        }
    }

    fn close_stale_sockets(&mut self) {
        let live: HashMap<&str, (u32, u64)> = self
            .engine
            .bound_interfaces()
            .map(|(name, ifindex, generation)| (name, (ifindex, generation)))
            .collect();
        self.sockets
            .retain(|name, s| live.get(name.as_str()) == Some(&(s.ifindex, s.generation)));
        self.open_retries
            .retain(|name, r| live.get(name.as_str()) == Some(&(r.ifindex, r.generation)));
        self.pending_rs
            .retain(|name, p| live.get(name.as_str()) == Some(&(p.ifindex, p.generation)));
    }

    fn flush(&mut self, now: Instant) {
        for event in self.engine.events.drain(..) {
            debug!(?event, "router discovery event");
            match &event {
                DiscoveryEvent::CandidateLearned { interface, address } => {
                    info!(%interface, %address, "unnumbered: peer address learned");
                }
                DiscoveryEvent::CandidateExpired { interface, address } => {
                    info!(%interface, %address, "unnumbered: peer address expired");
                }
                DiscoveryEvent::BindingChanged { .. } | DiscoveryEvent::Conflict { .. } => {
                    self.events.send(event);
                }
            }
        }
        for transmit in std::mem::take(&mut self.engine.transmits) {
            if self.transmit(transmit) {
                continue;
            }
            // Not sent: no socket yet, or the send failed. A missed RA is
            // covered by the next scheduled one; the link-up RS is not, so
            // keep it. Without a socket it goes as soon as one opens; after
            // a send failure it backs off like a socket open.
            if let Transmit::RouterSolicitation { ifindex } = transmit
                && let Some((name, _, generation)) = self
                    .engine
                    .bound_interfaces()
                    .find(|(_, i, _)| *i == ifindex)
            {
                let at = if self.has_socket(name, ifindex, generation) {
                    now + open_backoff(1)
                } else {
                    now
                };
                let pending = PendingRs {
                    ifindex,
                    generation,
                    failures: u32::from(at != now),
                    at,
                };
                self.pending_rs.insert(name.to_owned(), pending);
            }
        }
    }

    /// Send on the interface's socket. False when it has no socket or the
    /// send failed.
    fn transmit(&mut self, transmit: Transmit) -> bool {
        let (ifindex, destination) = match transmit {
            Transmit::RouterAdvertisement { ifindex, .. } => (ifindex, ALL_NODES),
            Transmit::RouterSolicitation { ifindex } => (ifindex, ALL_ROUTERS),
        };
        let Some(socket) = self.sockets.values_mut().find(|s| s.ifindex == ifindex) else {
            return false;
        };
        let lladdr = link_layer_address(&socket.name);
        let bytes = match transmit {
            Transmit::RouterAdvertisement {
                router_lifetime_secs,
                ..
            } => packet::encode_router_advertisement(router_lifetime_secs, lladdr),
            Transmit::RouterSolicitation { .. } => packet::encode_router_solicitation(lladdr),
        };
        let to = SocketAddrV6::new(destination, 0, 0, ifindex);
        match (self.sender)(socket.socket.get_ref(), &bytes, &to.into()) {
            Ok(_) => true,
            Err(error) => {
                let reason = SendFailure::classify(&error);
                self.counters.send_failures[reason as usize].fetch_add(1, Ordering::Relaxed);
                if !socket.send_warned {
                    warn!(interface = %socket.name, ifindex, generation = socket.generation,
                        errno_class = reason.as_str(), %error, "router discovery send failed");
                    socket.send_warned = true;
                }
                false
            }
        }
    }
}

/// Whether `address` is assigned to `interface` (own-advertisement check),
/// from an address list at most [`LOCAL_ADDRESS_TTL`] old. `None` when the
/// list cannot be read: a failed read is never cached and never stands in
/// for an empty list.
fn is_local_address(
    cache: &mut HashMap<String, (Instant, Vec<Ipv6Addr>)>,
    interface: &str,
    address: Ipv6Addr,
    now: Instant,
    inventory: impl FnOnce(&str) -> io::Result<Vec<Ipv6Addr>>,
) -> Option<bool> {
    let fresh = cache
        .get(interface)
        .is_some_and(|(at, _)| now.duration_since(*at) < LOCAL_ADDRESS_TTL);
    if !fresh {
        match inventory(interface) {
            Ok(addresses) => {
                cache.insert(interface.to_owned(), (now, addresses));
            }
            Err(error) => {
                cache.remove(interface);
                debug!(interface, %error, "cannot read interface addresses");
                return None;
            }
        }
    }
    Some(cache[interface].1.contains(&address))
}

fn interface_addresses(interface: &str) -> io::Result<Vec<Ipv6Addr>> {
    let addrs = nix::ifaddrs::getifaddrs().map_err(io::Error::from)?;
    Ok(addrs
        .filter(|a| a.interface_name == interface)
        .filter_map(|a| Some(a.address?.as_sockaddr_in6()?.ip()))
        .collect())
}

/// The interface's Ethernet address for the Source Link-Layer Address option.
fn link_layer_address(interface: &str) -> Option<[u8; 6]> {
    nix::ifaddrs::getifaddrs().ok()?.find_map(|a| {
        if a.interface_name != interface {
            return None;
        }
        a.address.as_ref()?.as_link_addr()?.addr()
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::Ipv6Addr;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use socket2::{Domain, Socket, Type};

    use super::{Actor, Command, Input, Received, is_local_address, open_backoff};
    use crate::ra_discovery::{DiscoveryConfig, LinkEvent, LinkState};

    /// `ICMPv6` types the fake sender was asked to send, in order.
    type Sent = Arc<Mutex<Vec<u8>>>;

    /// Record each send; the first `failures` sends fail.
    fn fake_sender(actor: &mut Actor, failures: u32) -> Sent {
        let sent = Sent::default();
        let log = Arc::clone(&sent);
        let mut calls = 0;
        actor.sender = Box::new(move |_, bytes, _| {
            calls += 1;
            if calls <= failures {
                return Err(std::io::Error::other("send failed"));
            }
            log.lock().unwrap().push(bytes[0]);
            Ok(bytes.len())
        });
        sent
    }

    /// An actor whose socket opener fails `failures` times, then succeeds
    /// with an ordinary socket standing in for the raw one.
    fn flaky_actor(failures: u32, send: bool) -> (Actor, Arc<AtomicU32>) {
        let attempts = Arc::new(AtomicU32::new(0));
        let counter = Arc::clone(&attempts);
        let opener = move |_: &str, _: u32| {
            if counter.fetch_add(1, Ordering::Relaxed) < failures {
                Err(std::io::Error::other("transient"))
            } else {
                Socket::new(Domain::IPV6, Type::DGRAM, None)
            }
        };
        let config = DiscoveryConfig {
            send,
            ..DiscoveryConfig::default()
        };
        let (actor, _, _) = Actor::new(config, 1, Box::new(opener));
        (actor, attempts)
    }

    fn link(state: LinkState) -> Input {
        Input::Command(Command::Link(LinkEvent {
            ifindex: 9,
            name: "x".into(),
            state,
        }))
    }

    #[tokio::test]
    async fn received_packets_do_not_reconcile_sockets() {
        let (mut actor, attempts) = flaky_actor(u32::MAX, false);
        let t0 = Instant::now();
        actor.handle(Input::Command(Command::Start("x".into())), t0);
        actor.handle(link(LinkState::Unknown), t0);
        assert_eq!(attempts.load(Ordering::Relaxed), 1);
        // The retry is overdue at t0+5s, but a packet must not run it.
        let t5 = t0 + Duration::from_secs(5);
        for _ in 0..100 {
            let packet = Received {
                ifindex: 9,
                generation: 1,
                source: "fe80::1".parse().unwrap(),
                hop_limit: Some(255),
                payload: Vec::new(),
            };
            actor.handle(Input::Packet(packet), t5);
        }
        assert_eq!(attempts.load(Ordering::Relaxed), 1);
        // A timer wake does.
        actor.handle(Input::Wake, t5);
        assert_eq!(attempts.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn link_up_rs_waits_for_the_socket() {
        let (mut actor, attempts) = flaky_actor(2, true);
        let sent = fake_sender(&mut actor, 0);
        let t0 = Instant::now();
        actor.handle(Input::Command(Command::Start("x".into())), t0);
        actor.handle(link(LinkState::Up), t0);
        actor.handle(Input::Wake, t0 + Duration::from_secs(1));
        assert_eq!(attempts.load(Ordering::Relaxed), 2);
        assert_eq!(*sent.lock().unwrap(), Vec::<u8>::new(), "no socket yet");
        actor.handle(Input::Wake, t0 + Duration::from_secs(3));
        assert_eq!(attempts.load(Ordering::Relaxed), 3);
        assert_eq!(*sent.lock().unwrap(), vec![133], "the held RS");
        assert!(actor.pending_rs.is_empty());
    }

    #[tokio::test]
    async fn failed_rs_send_stays_pending_until_a_later_tick_sends_it() {
        let (mut actor, _) = flaky_actor(0, true);
        let sent = fake_sender(&mut actor, 1);
        let t0 = Instant::now();
        actor.handle(Input::Command(Command::Start("x".into())), t0);
        actor.handle(link(LinkState::Up), t0);
        // The link-up RS send failed: still pending, with a 1 s retry wake.
        assert_eq!(*sent.lock().unwrap(), Vec::<u8>::new());
        assert!(actor.pending_rs.contains_key("x"));
        assert!(actor.next_wake().unwrap() <= t0 + Duration::from_secs(1));
        actor.handle(Input::Wake, t0 + Duration::from_secs(1));
        // The tick also sends the first unsolicited RA (134).
        assert_eq!(*sent.lock().unwrap(), vec![134, 133], "RS resent");
        assert!(actor.pending_rs.is_empty());
    }

    /// Reach the "router discovery send failed" callsite once.
    fn fail_link_up_send() {
        let (mut actor, _) = flaky_actor(0, true);
        fake_sender(&mut actor, u32::MAX);
        actor.handle(Input::Command(Command::Start("x".into())), Instant::now());
        actor.handle(link(LinkState::Up), Instant::now());
    }

    #[tokio::test]
    async fn send_failures_count_every_attempt_and_warn_once_per_generation() {
        use std::io::{Read, Seek, SeekFrom};

        let mut log = tempfile::tempfile().unwrap();
        let writer = log.try_clone().unwrap();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(move || writer.try_clone().unwrap())
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        // A sibling test reaching the warning with no subscriber, after this
        // install, caches its process-wide interest as never. Force that
        // ordering, then warm the callsite here, rebuild the cache and read
        // only what follows.
        tokio::task::spawn_blocking(fail_link_up_send)
            .await
            .unwrap();
        fail_link_up_send();
        tracing::callsite::rebuild_interest_cache();
        let start = log.stream_position().unwrap();
        let (mut actor, _) = flaky_actor(0, true);
        actor.sender =
            Box::new(|_, _, _| Err(std::io::Error::from_raw_os_error(libc::EADDRNOTAVAIL)));
        let now = Instant::now();
        actor.handle(Input::Command(Command::Start("x".into())), now);
        actor.handle(link(LinkState::Up), now);
        let first_generation = actor.sockets["x"].generation;
        assert_eq!(
            actor.counters.send_failures[super::SendFailure::AddressUnavailable as usize]
                .load(Ordering::Relaxed),
            1
        );
        actor.handle(Input::Wake, now + Duration::from_secs(1));
        assert_eq!(
            actor.counters.send_failures[super::SendFailure::AddressUnavailable as usize]
                .load(Ordering::Relaxed),
            3
        );
        actor.handle(link(LinkState::Down), now + Duration::from_secs(2));
        actor.handle(link(LinkState::Up), now + Duration::from_secs(3));
        let second_generation = actor.sockets["x"].generation;
        assert_ne!(first_generation, second_generation);
        log.seek(SeekFrom::Start(start)).unwrap();
        let mut text = String::new();
        log.read_to_string(&mut text).unwrap();
        let rows: Vec<serde_json::Value> = text
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .filter(|row| row["fields"]["message"] == "router discovery send failed")
            .collect();
        assert_eq!(
            rows.len(),
            2,
            "one actual warning per link generation: {text}"
        );
        for (row, generation) in rows.iter().zip([first_generation, second_generation]) {
            assert_eq!(row["level"], "WARN");
            assert_eq!(row["fields"]["interface"], "x");
            assert_eq!(row["fields"]["ifindex"], 9);
            assert_eq!(row["fields"]["generation"], generation);
            assert_eq!(row["fields"]["errno_class"], "address_unavailable");
        }
    }

    #[test]
    fn send_errno_classes_are_bounded() {
        use super::SendFailure as S;
        for (errno, expected) in [
            (libc::EADDRNOTAVAIL, S::AddressUnavailable),
            (libc::ENETDOWN, S::NetworkUnavailable),
            (libc::ENETUNREACH, S::NetworkUnavailable),
            (libc::ENODEV, S::NetworkUnavailable),
            (libc::EPERM, S::PermissionDenied),
            (libc::EACCES, S::PermissionDenied),
            (libc::EAGAIN, S::WouldBlock),
            (libc::EINVAL, S::Other),
        ] {
            assert_eq!(
                S::classify(&std::io::Error::from_raw_os_error(errno)),
                expected
            );
        }
    }

    #[test]
    fn unreadable_inventory_is_never_cached_or_read_as_empty() {
        let mut cache = HashMap::new();
        let local: Ipv6Addr = "fe80::1".parse().unwrap();
        let t0 = Instant::now();
        let fail = |_: &str| Err(std::io::Error::other("netlink dump failed"));
        assert_eq!(is_local_address(&mut cache, "x", local, t0, fail), None);
        assert!(cache.is_empty(), "the failure is not cached");
        let ok = |_: &str| Ok(vec![local]);
        assert_eq!(is_local_address(&mut cache, "x", local, t0, ok), Some(true));
        // A later failure drops the stale list rather than serving it.
        let later = t0 + Duration::from_secs(2);
        assert_eq!(is_local_address(&mut cache, "x", local, later, fail), None);
        assert!(cache.is_empty());
    }

    #[tokio::test]
    async fn pending_link_up_rs_is_dropped_on_stop_and_new_generation() {
        // Stop: the interface is gone, nothing is sent later.
        let (mut actor, _) = flaky_actor(1, true);
        let t0 = Instant::now();
        actor.handle(Input::Command(Command::Start("x".into())), t0);
        actor.handle(link(LinkState::Up), t0);
        assert_eq!(actor.pending_rs.len(), 1);
        actor.handle(Input::Command(Command::Stop("x".into())), t0);
        assert!(actor.pending_rs.is_empty());
        // Down drops the old generation's RS; the next Up queues its own.
        let (mut actor, _) = flaky_actor(u32::MAX, true);
        actor.handle(Input::Command(Command::Start("x".into())), t0);
        actor.handle(link(LinkState::Up), t0);
        let first = actor.pending_rs["x"].generation;
        actor.handle(link(LinkState::Down), t0);
        assert!(actor.pending_rs.is_empty());
        actor.handle(link(LinkState::Up), t0);
        assert_ne!(actor.pending_rs["x"].generation, first);
    }

    #[test]
    fn open_backoff_doubles_to_a_one_minute_cap() {
        let secs: Vec<u64> = (1..=8).map(|n| open_backoff(n).as_secs()).collect();
        assert_eq!(secs, [1, 2, 4, 8, 16, 32, 60, 60]);
        assert_eq!(open_backoff(u32::MAX), Duration::from_secs(60));
    }

    #[tokio::test]
    async fn socket_open_is_retried_with_backoff_until_it_succeeds() {
        let attempts = Arc::new(AtomicU32::new(0));
        let counter = Arc::clone(&attempts);
        let opener = move |_: &str, _: u32| {
            if counter.fetch_add(1, Ordering::Relaxed) < 3 {
                Err(std::io::Error::other("transient"))
            } else {
                // Any socket stands in for the raw ICMPv6 one.
                Socket::new(Domain::IPV6, Type::DGRAM, None)
            }
        };
        // Sending off and no candidates: nothing but the retry can wake us.
        let (mut actor, _events, _received) =
            Actor::new(DiscoveryConfig::default(), 1, Box::new(opener));
        let t0 = Instant::now();
        actor.engine.start("x");
        actor.engine.on_link(
            &LinkEvent {
                ifindex: 9,
                name: "x".into(),
                state: LinkState::Unknown,
            },
            t0,
        );
        assert_eq!(actor.engine.next_deadline(), None);
        let secs = Duration::from_secs;
        for (at, tries, wake) in [
            (t0, 1, Some(t0 + secs(1))),
            (t0 + Duration::from_millis(999), 1, Some(t0 + secs(1))),
            (t0 + secs(1), 2, Some(t0 + secs(3))),
            (t0 + secs(3), 3, Some(t0 + secs(7))),
            (t0 + secs(7), 4, None),
        ] {
            actor.open_sockets(at);
            assert_eq!(attempts.load(Ordering::Relaxed), tries);
            assert_eq!(actor.next_wake(), wake);
        }
        assert!(actor.sockets.contains_key("x"));
        assert_eq!(
            actor.counters.socket_open_failures.load(Ordering::Relaxed),
            3
        );
    }

    /// An opened socket is registered with the reactor: a datagram arriving
    /// on it wakes the reader task, which queues it for the actor tagged
    /// with the link it was opened under.
    #[tokio::test]
    async fn opened_socket_delivers_datagrams_to_the_actor() {
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, None).expect("socket");
        socket
            .bind(&"[::1]:0".parse::<std::net::SocketAddr>().unwrap().into())
            .expect("bind");
        socket.set_nonblocking(true).expect("nonblocking");
        let dst = socket.local_addr().unwrap().as_socket().unwrap();
        let mut socket = Some(socket);
        let opener = move |_: &str, _: u32| Ok(socket.take().expect("opened once"));
        let (mut actor, _events, mut received) =
            Actor::new(DiscoveryConfig::default(), 1, Box::new(opener));
        let now = Instant::now();
        actor.engine.start("x");
        actor.engine.on_link(
            &LinkEvent {
                ifindex: 9,
                name: "x".into(),
                state: LinkState::Unknown,
            },
            now,
        );
        actor.open_sockets(now);
        assert!(actor.sockets.contains_key("x"));

        let tx = std::net::UdpSocket::bind("[::1]:0").expect("bind tx");
        tx.send_to(b"ra", dst).expect("send");
        let packet = tokio::time::timeout(Duration::from_secs(5), received.recv())
            .await
            .expect("reader woke on the datagram")
            .expect("reader alive");
        assert_eq!(packet.ifindex, 9);
        assert_eq!(packet.generation, actor.sockets["x"].generation);
        assert_eq!(packet.source, Ipv6Addr::LOCALHOST);
        assert_eq!(packet.payload, b"ra");
    }

    /// RAs that keep moving the binding or raising conflicts, while the
    /// neighbor owner is not reading, leave at most one binding change and
    /// one conflict queued for the interface. The owner then receives the
    /// final binding and every conflict.
    #[tokio::test]
    async fn discovery_events_stay_bounded_while_the_owner_stalls() {
        use crate::ra_discovery::{DiscoveryEvent, Endpoint};

        let opener = |_: &str, _: u32| Err(std::io::Error::other("unused"));
        let (mut actor, mut events, _received) =
            Actor::new(DiscoveryConfig::default(), 1, Box::new(opener));
        let t0 = Instant::now();
        actor.engine.start("x");
        actor.engine.on_link(
            &LinkEvent {
                ifindex: 9,
                name: "x".into(),
                state: LinkState::Up,
            },
            t0,
        );
        let generation = actor.engine.bound_interfaces().next().unwrap().2;
        let mut at = t0;
        let mut advertise = |actor: &mut Actor, source: Ipv6Addr, lifetime: u16| {
            // Each RA lands after the previous 1 s candidate expired.
            at += Duration::from_secs(2);
            actor
                .engine
                .on_router_advertisement(9, generation, source, lifetime, at, |_, _| Some(false))
                .unwrap();
            actor.flush(at);
            assert!(actor.events.pending() <= 2, "{}", actor.events.pending());
        };
        // Every RA expires the bound source and binds the new one: four
        // engine events each, which the old queue held all of.
        for i in 0..500 {
            advertise(&mut actor, Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 2, i), 1);
        }
        // A long-lived source holds the binding while others conflict.
        let bound: Ipv6Addr = "fe80::1".parse().unwrap();
        advertise(&mut actor, bound, 9000);
        let conflicts = 500;
        for i in 0..conflicts {
            advertise(&mut actor, Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 3, i), 1);
        }
        let last_other = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 3, conflicts - 1);

        drop(actor);
        let mut delivered = Vec::new();
        while let Some(event) = events.recv().await {
            delivered.push(event);
        }
        let endpoint = |address| Endpoint {
            address,
            ifindex: 9,
        };
        // Only the final binding: the churned ones were dropped by discovery
        // before the owner read them, so applying them would only churn.
        let bindings: Vec<_> = delivered
            .iter()
            .filter(|event| matches!(event, DiscoveryEvent::BindingChanged { .. }))
            .collect();
        assert_eq!(
            bindings,
            [&DiscoveryEvent::BindingChanged {
                interface: "x".into(),
                previous: None,
                current: Some(endpoint(bound)),
            }]
        );
        let conflict = DiscoveryEvent::Conflict {
            interface: "x".into(),
            bound,
            other: last_other,
        };
        assert_eq!(
            delivered.iter().filter(|event| **event == conflict).count(),
            usize::from(conflicts)
        );
        assert_eq!(delivered.len(), 1 + usize::from(conflicts));
    }

    /// Draining a large counted backlog yields to other tasks on the same
    /// thread: receiving never waits on the wake channel, so without the
    /// cooperative budget the owner would replay it all in one poll.
    #[tokio::test]
    async fn receiving_a_counted_backlog_lets_other_tasks_run() {
        use crate::ra_discovery::DiscoveryEvent;
        use std::sync::atomic::AtomicBool;

        let (sender, mut events) = super::event_channel();
        let backlog = 10_000;
        for _ in 0..backlog {
            sender.send(DiscoveryEvent::Conflict {
                interface: "a".into(),
                bound: "fe80::1".parse().unwrap(),
                other: "fe80::2".parse().unwrap(),
            });
        }
        let ran = Arc::new(AtomicBool::new(false));
        let other = Arc::clone(&ran);
        let _other = tokio::spawn(async move { other.store(true, Ordering::Relaxed) });
        let mut received = 0;
        while !ran.load(Ordering::Relaxed) {
            assert!(
                received < backlog,
                "the whole backlog was received before another task ran"
            );
            events.recv().await.unwrap();
            received += 1;
        }
    }

    /// A conflict storm on one interface cannot hold back another
    /// interface's binding change: slots are served round-robin.
    #[tokio::test]
    async fn a_conflict_storm_does_not_starve_other_interfaces() {
        use crate::ra_discovery::{DiscoveryEvent, Endpoint};

        let (sender, mut events) = super::event_channel();
        let conflict = |other: u16| DiscoveryEvent::Conflict {
            interface: "a".into(),
            bound: "fe80::1".parse().unwrap(),
            other: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 2, other),
        };
        for other in 0..1000 {
            sender.send(conflict(other));
        }
        let binding = DiscoveryEvent::BindingChanged {
            interface: "b".into(),
            previous: None,
            current: Some(Endpoint {
                address: "fe80::b".parse().unwrap(),
                ifindex: 2,
            }),
        };
        sender.send(binding.clone());
        let mut receives = 0;
        loop {
            // The storm continues while the owner reads.
            sender.send(conflict(1000 + receives));
            receives += 1;
            if events.recv().await == Some(binding.clone()) {
                break;
            }
            assert!(receives < 3, "binding change held back by the storm");
        }
    }

    /// An event queued while the owner waits wakes it; one queued before
    /// the owner waits needs no second wake.
    #[tokio::test]
    async fn discovery_event_wakes_a_waiting_owner() {
        use crate::ra_discovery::DiscoveryEvent;

        let (sender, mut events) = super::event_channel();
        let conflict = |other: &str| DiscoveryEvent::Conflict {
            interface: "x".into(),
            bound: "fe80::1".parse().unwrap(),
            other: other.parse().unwrap(),
        };
        let waiting = tokio::spawn(async move {
            let first = events.recv().await;
            (first, events)
        });
        tokio::task::yield_now().await;
        assert!(
            !waiting.is_finished(),
            "the owner is waiting before the send"
        );
        sender.send(conflict("fe80::2"));
        let (first, mut events) = tokio::time::timeout(Duration::from_secs(5), waiting)
            .await
            .expect("the send wakes the waiting owner")
            .unwrap();
        assert_eq!(first, Some(conflict("fe80::2")));
        sender.send(conflict("fe80::3"));
        sender.send(conflict("fe80::4"));
        let mut recv = async || {
            tokio::time::timeout(Duration::from_secs(5), events.recv())
                .await
                .expect("a queued event needs no further wake")
        };
        assert_eq!(recv().await, Some(conflict("fe80::4")));
        assert_eq!(recv().await, Some(conflict("fe80::4")));
        drop(sender);
        assert_eq!(recv().await, None);
    }
}
