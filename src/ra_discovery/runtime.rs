//! Linux socket runtime: one raw `ICMPv6` socket per started interface, a
//! reader task per socket, and one actor that owns the [`Engine`].

use std::collections::HashMap;
use std::io::{self, IoSliceMut};
use std::net::{Ipv6Addr, SocketAddrV6};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use nix::sys::socket::{ControlMessageOwned, MsgFlags, SockaddrIn6, recvmsg};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tokio_util::task::AbortOnDropHandle;
use tracing::{debug, warn};

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

/// Handle to the discovery actor. Every input is a non-blocking send; events
/// arrive on the receiver returned by [`RaDiscovery::spawn`].
pub struct RaDiscovery {
    commands: mpsc::UnboundedSender<Command>,
    counters: Arc<Counters>,
    task: tokio::task::JoinHandle<()>,
}

enum Command {
    Start(String),
    Stop(String),
    Link(LinkEvent),
    SessionEstablished(String),
    SessionFailed(String),
}

#[derive(Default)]
struct Counters {
    drops: [AtomicU64; DropReason::ALL.len()],
    socket_open_failures: AtomicU64,
}

impl Counters {
    fn bump(&self, reason: DropReason) {
        self.drops[reason as usize].fetch_add(1, Ordering::Relaxed);
    }
}

/// Opens the per-interface socket; replaced by a fake in tests.
type Opener = Box<dyn FnMut(&str, u32) -> io::Result<Socket> + Send>;

impl RaDiscovery {
    /// Open-probe a raw `ICMPv6` socket, then spawn the actor on the current
    /// Tokio runtime. A missing `CAP_NET_RAW` is a typed error.
    pub fn spawn(
        config: DiscoveryConfig,
    ) -> Result<(Self, mpsc::UnboundedReceiver<DiscoveryEvent>), DiscoveryError> {
        drop(raw_socket()?);
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() ^ u64::from(d.subsec_nanos()))
            ^ u64::from(std::process::id());
        let (commands, command_rx) = mpsc::unbounded_channel();
        let (actor, event_rx, received_rx) = Actor::new(config, seed, Box::new(interface_socket));
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

    pub fn start(&self, interface: &str) {
        let _ = self.commands.send(Command::Start(interface.to_owned()));
    }

    pub fn stop(&self, interface: &str) {
        let _ = self.commands.send(Command::Stop(interface.to_owned()));
    }

    pub fn link_event(&self, event: LinkEvent) {
        let _ = self.commands.send(Command::Link(event));
    }

    /// The interface's session reached Established; discovery stops moving
    /// its binding.
    pub fn session_established(&self, interface: &str) {
        let _ = self
            .commands
            .send(Command::SessionEstablished(interface.to_owned()));
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
}

struct Actor {
    engine: Engine,
    sockets: HashMap<String, InterfaceSocket>,
    events: mpsc::UnboundedSender<DiscoveryEvent>,
    counters: Arc<Counters>,
    received_tx: mpsc::Sender<Received>,
    local_addresses: HashMap<String, (Instant, Vec<Ipv6Addr>)>,
    opener: Opener,
    open_retries: HashMap<String, OpenRetry>,
    /// A link-up RS whose interface had no socket yet, keyed by interface
    /// name with the (ifindex, generation) it belongs to. Sent when that
    /// socket opens; dropped on stop or a generation change.
    pending_rs: HashMap<String, (u32, u64)>,
    #[cfg(test)]
    sent: Vec<Transmit>,
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
    ) -> (
        Self,
        mpsc::UnboundedReceiver<DiscoveryEvent>,
        mpsc::Receiver<Received>,
    ) {
        let (events, event_rx) = mpsc::unbounded_channel();
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
            pending_rs: HashMap::new(),
            #[cfg(test)]
            sent: Vec::new(),
        };
        (actor, event_rx, received_rx)
    }

    /// The next engine deadline or socket-open retry.
    fn next_wake(&self) -> Option<Instant> {
        let retry = self.open_retries.values().map(|r| r.at).min();
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
                        self.flush();
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
        self.flush();
        if reconcile {
            self.close_stale_sockets();
        }
    }

    fn command(&mut self, command: Command, now: Instant) {
        match command {
            Command::Start(name) => self.engine.start(&name),
            Command::Stop(name) => self.engine.stop(&name),
            Command::Link(event) => self.engine.on_link(&event, now),
            Command::SessionEstablished(name) => self.engine.session_established(&name),
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
                |name, source| is_local_address(local, name, source, now),
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
            match (self.opener)(&name, ifindex).and_then(AsyncFd::new) {
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
                    let pending_rs = self.pending_rs.get(&name) == Some(&(ifindex, generation));
                    self.sockets.insert(
                        name.clone(),
                        InterfaceSocket {
                            name: name.clone(),
                            ifindex,
                            generation,
                            socket,
                            _reader: reader,
                        },
                    );
                    if pending_rs {
                        self.pending_rs.remove(&name);
                        self.transmit(Transmit::RouterSolicitation { ifindex });
                    }
                }
                Err(error) => {
                    let failures = failures + 1;
                    let retry_in = open_backoff(failures);
                    self.counters
                        .socket_open_failures
                        .fetch_add(1, Ordering::Relaxed);
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
            .retain(|name, link| live.get(name.as_str()) == Some(link));
    }

    fn flush(&mut self) {
        for event in self.engine.events.drain(..) {
            debug!(?event, "router discovery event");
            let _ = self.events.send(event);
        }
        for transmit in std::mem::take(&mut self.engine.transmits) {
            if self.transmit(transmit) {
                continue;
            }
            // No socket yet. A missed RA is covered by the next scheduled
            // one; the link-up RS is not, so keep it for the socket.
            if let Transmit::RouterSolicitation { ifindex } = transmit
                && let Some((name, _, generation)) = self
                    .engine
                    .bound_interfaces()
                    .find(|(_, i, _)| *i == ifindex)
            {
                self.pending_rs
                    .insert(name.to_owned(), (ifindex, generation));
            }
        }
    }

    /// Send on the interface's socket. False when it has no socket.
    fn transmit(&mut self, transmit: Transmit) -> bool {
        let (ifindex, destination) = match transmit {
            Transmit::RouterAdvertisement { ifindex, .. } => (ifindex, ALL_NODES),
            Transmit::RouterSolicitation { ifindex } => (ifindex, ALL_ROUTERS),
        };
        let Some(socket) = self.sockets.values().find(|s| s.ifindex == ifindex) else {
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
        if let Err(error) = socket.socket.get_ref().send_to(&bytes, &to.into()) {
            debug!(interface = %socket.name, %error, "router discovery send failed");
        }
        #[cfg(test)]
        self.sent.push(transmit);
        true
    }
}

/// Whether `address` is assigned to `interface` (own-advertisement check),
/// from an address list at most [`LOCAL_ADDRESS_TTL`] old.
fn is_local_address(
    cache: &mut HashMap<String, (Instant, Vec<Ipv6Addr>)>,
    interface: &str,
    address: Ipv6Addr,
    now: Instant,
) -> bool {
    let entry = cache
        .entry(interface.to_owned())
        .or_insert_with(|| (now, interface_addresses(interface)));
    if now.duration_since(entry.0) >= LOCAL_ADDRESS_TTL {
        *entry = (now, interface_addresses(interface));
    }
    entry.1.contains(&address)
}

fn interface_addresses(interface: &str) -> Vec<Ipv6Addr> {
    nix::ifaddrs::getifaddrs().map_or_else(
        |_| Vec::new(),
        |addrs| {
            addrs
                .filter(|a| a.interface_name == interface)
                .filter_map(|a| Some(a.address?.as_sockaddr_in6()?.ip()))
                .collect()
        },
    )
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
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{Duration, Instant};

    use socket2::{Domain, Socket, Type};

    use super::{Actor, Command, Input, Received, open_backoff};
    use crate::ra_discovery::engine::Transmit;
    use crate::ra_discovery::{DiscoveryConfig, LinkEvent, LinkState};

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
        let t0 = Instant::now();
        actor.handle(Input::Command(Command::Start("x".into())), t0);
        actor.handle(link(LinkState::Up), t0);
        actor.handle(Input::Wake, t0 + Duration::from_secs(1));
        assert_eq!(attempts.load(Ordering::Relaxed), 2);
        assert_eq!(actor.sent, vec![], "no socket yet");
        actor.handle(Input::Wake, t0 + Duration::from_secs(3));
        assert_eq!(attempts.load(Ordering::Relaxed), 3);
        assert_eq!(
            actor.sent,
            vec![Transmit::RouterSolicitation { ifindex: 9 }]
        );
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
        let first = actor.pending_rs["x"];
        actor.handle(link(LinkState::Down), t0);
        assert!(actor.pending_rs.is_empty());
        actor.handle(link(LinkState::Up), t0);
        assert_ne!(actor.pending_rs["x"], first);
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
}
