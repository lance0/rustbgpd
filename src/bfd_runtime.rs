//! Asynchronous BFD actor (ADR-0067): single-hop (RFC 5881) and multihop
//! (RFC 5883) sessions.
//!
//! Owns the UDP sockets, the real per-session timers, and transmit jitter, and
//! drives the pure [`rustbgpd_bfd::Session`] state machine. It is a **pure
//! session-runner**: it reconciles a desired session set owned and published by
//! `PeerManager` (a `watch` channel) and never derives lifecycle from BGP
//! itself. It publishes status via a `watch` channel + Prometheus metrics, a
//! lossy [`BfdRuntimeEvent`] broadcast for the operator event stream, and a
//! per-peer coalescing [`BfdStateChange`] channel (bounded by the session
//! count; latest state wins, a real transition is never masked by an ack) that
//! `PeerManager` consumes for RFC 5882 BGP coupling.
//!
//! Design: a single actor task `select!`s over the shared per-AF receive
//! sockets (UDP/3784 single-hop, UDP/4784 multihop — each opened only when a
//! session of that mode and family exists) and a min-deadline timer heap
//! covering every session's transmit and detection timers. The receive path
//! validates the RFC 5881 TTL/Hop-Limit-255 requirement via `recvmsg`
//! ancillary data (single-hop only — RFC 5883 packets have transited routers)
//! and the source-port range (49152..=65535, RFC 5881 §4 / RFC 5883 §5),
//! decodes, demultiplexes to the session by Your Discriminator (RFC 5880
//! §6.8.6; source address only for the zero-discriminator bootstrap), refuses a
//! packet whose encapsulation mode differs from the session's, and executes
//! the resulting [`rustbgpd_bfd::Action`]s. Both modes transmit with TTL /
//! Hop Limit 255; multihop can bind the configured per-family active source.

use std::net::{IpAddr, SocketAddr, SocketAddrV6};

use crate::config::{BfdConfig, Config};

/// Resolved parameters for one BFD session (one per BFD-enabled neighbor).
///
/// This is one entry of the **desired session set** that `PeerManager` owns and
/// publishes to the actor once BGP coupling is active (ADR-0067 step 4). The
/// actor is a pure session-runner: it reconciles this set onto its sockets and
/// timers and never derives lifecycle from BGP itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BfdSessionParams {
    /// Peer IP address (the BGP neighbor).
    pub peer: IpAddr,
    /// Linux interface index for an IPv6 link-local peer. Global IPv4/IPv6
    /// sessions are deliberately unscoped (`None`). This stays inside the
    /// daemon runtime and is not part of the public BFD status identity.
    pub(crate) scope_id: Option<u32>,
    /// Concrete control-packet destination derived together with `scope_id`.
    /// Keeping this in the startup-pinned runtime value makes a missing scope
    /// impossible to discover as a best-effort transmit failure later.
    pub(crate) destination: SocketAddr,
    /// Desired minimum transmit interval (microseconds).
    pub desired_min_tx_us: u32,
    /// Required minimum receive interval (microseconds).
    pub required_min_rx_us: u32,
    /// Detection multiplier.
    pub detect_mult: u8,
    /// RFC 5882 strict mode (consumed by the BGP-coupling slice; carried here so
    /// the surface can report it).
    pub strict: bool,
    /// Whether the session should actively run. `false` (e.g. a disabled
    /// neighbor) is reconciled the same as an absent entry — the actor drains
    /// the session to `AdminDown` and drops it.
    pub enabled: bool,
    /// RFC 5883 multihop encapsulation (UDP/4784, no receive TTL check).
    pub multihop: bool,
    /// Configured per-family active-open source for multihop transmit.
    pub source: Option<IpAddr>,
}

/// The desired BFD session set the actor reconciles toward. Owned and published
/// by `PeerManager` (level-triggered via a `watch` channel once coupling is
/// active); at startup it is derived from config via [`BfdRuntimeConfig::from_config`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BfdRuntimeConfig {
    /// One entry per BFD-enabled neighbor.
    pub sessions: Vec<BfdSessionParams>,
}

/// Checked BFD startup derivation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BfdRuntimeConfigError(String);

impl std::fmt::Display for BfdRuntimeConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for BfdRuntimeConfigError {}

/// A BFD session state change delivered to `PeerManager` (ADR-0067 step 4) over
/// the per-peer coalescing channel from [`state_change_channel`] — distinct
/// from the lossy [`BfdRuntimeEvent`] broadcast that feeds the operator event
/// stream, because a missed Down would leave BGP up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BfdStateChange {
    /// Peer IP address.
    pub peer: IpAddr,
    /// New session state.
    pub state: rustbgpd_bfd::SessionState,
    /// Local diagnostic accompanying the transition.
    pub diagnostic: rustbgpd_bfd::Diagnostic,
    /// Whether this Down was caused by the remote signaling `AdminDown` (RFC
    /// 5882 §4.1/§4.2). The BGP coupling uses it to keep BGP up (and release a
    /// withheld strict session) when the peer merely disabled BFD
    /// administratively, rather than tearing BGP down.
    pub remote_admin_down: bool,
    /// `true` for a **level re-report** (an "ack") emitted on reconcile rather
    /// than a real state *transition*. The coupling treats an ack as
    /// release-only — it may release a withheld session when BFD now permits BGP
    /// but never tears BGP down. This re-confirms a session's current state to
    /// `PeerManager` across a coalesced disable→re-enable (where the session may
    /// stay Up with no new transition), so the strict withhold can be released
    /// without ever trusting a possibly-stale cached state — and without a
    /// deadlock when no fresh edge is coming. (A single-task actor + a
    /// per-peer coalescing channel that always delivers the latest state make
    /// a monotonic generation unnecessary.)
    pub resync: bool,
}

/// Create the BFD → `PeerManager` state-change channel.
///
/// The channel coalesces per peer: at most one pending [`BfdStateChange`] per
/// peer, latest state wins. So a burst (e.g. a session flapped by a packet
/// flood faster than `PeerManager` drains) is bounded by the session count
/// instead of growing without limit — and the coupling only ever needs the
/// *current* per-peer level, not the intermediate flaps (a flap that resolved
/// before the consumer looked is one BGP flap avoided). One rule keeps the
/// merge lossless where it matters: a pending real transition
/// (`resync = false`) is never masked by a later reconcile ack — the merged
/// change keeps `resync = false`, so a genuine Down still tears BGP down.
#[must_use]
pub fn state_change_channel() -> (BfdStateChangeSender, BfdStateChangeReceiver) {
    let pending = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    let (wake_tx, wake_rx) = tokio::sync::mpsc::unbounded_channel();
    (
        BfdStateChangeSender {
            pending: std::sync::Arc::clone(&pending),
            wake: wake_tx,
        },
        BfdStateChangeReceiver {
            pending,
            wake: wake_rx,
        },
    )
}

/// Sending half of [`state_change_channel`].
#[derive(Clone)]
pub struct BfdStateChangeSender {
    /// At most one pending change per peer (latest wins, see the merge rule).
    pending: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<IpAddr, BfdStateChange>>>,
    /// One wake token per peer with a pending entry — so this queue is bounded
    /// by the session count, never by the burst rate.
    wake: tokio::sync::mpsc::UnboundedSender<IpAddr>,
}

impl BfdStateChangeSender {
    /// Enqueue a state change, coalescing with any pending change for the same
    /// peer (latest state/diagnostic/`remote_admin_down`; `resync` stays
    /// `false` if either side was a real transition).
    pub fn send(&self, change: BfdStateChange) {
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match pending.entry(change.peer) {
            std::collections::hash_map::Entry::Occupied(mut slot) => {
                let resync = slot.get().resync && change.resync;
                let mut merged = change;
                merged.resync = resync;
                slot.insert(merged);
                // No new wake token: one is already queued for this peer.
            }
            std::collections::hash_map::Entry::Vacant(slot) => {
                let peer = change.peer;
                slot.insert(change);
                // Receiver gone (daemon shutting down): drop silently, like the
                // old mpsc send.
                let _ = self.wake.send(peer);
            }
        }
    }
}

/// Receiving half of [`state_change_channel`].
pub struct BfdStateChangeReceiver {
    pending: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<IpAddr, BfdStateChange>>>,
    wake: tokio::sync::mpsc::UnboundedReceiver<IpAddr>,
}

impl BfdStateChangeReceiver {
    /// Receive the next (coalesced) state change, or `None` once every sender
    /// is dropped and the queue is drained — the same close semantics as
    /// `mpsc::UnboundedReceiver::recv`.
    pub async fn recv(&mut self) -> Option<BfdStateChange> {
        loop {
            let peer = self.wake.recv().await?;
            let change = self
                .pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&peer);
            // The entry always exists (one wake token per pending entry), but
            // loop rather than unwrap so an imbalance degrades to a skipped
            // token instead of a panic.
            if change.is_some() {
                return change;
            }
        }
    }
}

impl BfdRuntimeConfig {
    /// Whether the actor should run at all.
    #[must_use]
    pub fn enabled(&self) -> bool {
        !self.sessions.is_empty()
    }

    /// Whether any configured single-hop session targets an IPv4 peer.
    /// Sockets are opened only for (mode, family) pairs with at least one
    /// session, so a family that is absent on the host (e.g.
    /// `ipv6.disable=1`) cannot fail startup unless a session actually needs
    /// it, and a multihop-only daemon never binds the single-hop port.
    #[must_use]
    pub fn needs_ipv4(&self) -> bool {
        self.sessions
            .iter()
            .any(|s| s.peer.is_ipv4() && !s.multihop)
    }

    /// Whether any configured single-hop session targets an IPv6 peer. See
    /// [`Self::needs_ipv4`].
    #[must_use]
    pub fn needs_ipv6(&self) -> bool {
        self.sessions
            .iter()
            .any(|s| s.peer.is_ipv6() && !s.multihop)
    }

    /// Whether any configured multihop (RFC 5883) session targets an IPv4
    /// peer. See [`Self::needs_ipv4`].
    #[must_use]
    pub fn needs_multihop_ipv4(&self) -> bool {
        self.sessions.iter().any(|s| s.peer.is_ipv4() && s.multihop)
    }

    /// Whether any configured multihop (RFC 5883) session targets an IPv6
    /// peer. See [`Self::needs_ipv4`].
    #[must_use]
    pub fn needs_multihop_ipv6(&self) -> bool {
        self.sessions.iter().any(|s| s.peer.is_ipv6() && s.multihop)
    }

    fn multihop_source(&self, v6: bool) -> Option<IpAddr> {
        self.sessions
            .iter()
            .find(|session| session.multihop && session.peer.is_ipv6() == v6)
            .and_then(|session| session.source)
    }

    fn validate_destinations(&self) -> Result<(), BfdRuntimeConfigError> {
        for session in &self.sessions {
            let expected = bfd_destination(session.peer, session.scope_id, session.multihop)?;
            if session.destination != expected {
                return Err(BfdRuntimeConfigError(format!(
                    "BFD peer {} has inconsistent runtime destination {} (expected {expected})",
                    session.peer, session.destination
                )));
            }
        }
        Ok(())
    }

    /// Resolve the BFD session set from the daemon config: every static
    /// neighbor whose own `bfd` (or inherited peer-group `bfd`) names a defined
    /// profile. Config validation has already checked the profile references.
    pub fn from_config(config: &Config) -> Result<BfdRuntimeConfig, BfdRuntimeConfigError> {
        let mut sessions = Vec::new();
        for neighbor in &config.neighbors {
            let Some(bfd) = resolve_bfd(
                neighbor.bfd.as_ref(),
                neighbor.peer_group.as_deref(),
                config,
            ) else {
                continue;
            };
            // A `bfd = { enabled = false }` block (often a neighbor overriding
            // an inherited peer-group block) runs no session.
            if !bfd.enabled {
                continue;
            }
            let peer = neighbor.address.parse::<IpAddr>().map_err(|error| {
                BfdRuntimeConfigError(format!(
                    "neighbor {:?}: failed to derive configured BFD session address: {error}",
                    neighbor.address
                ))
            })?;
            let profile = config
                .bfd_profiles
                .iter()
                .find(|p| p.name == bfd.profile)
                .ok_or_else(|| {
                    BfdRuntimeConfigError(format!(
                        "neighbor {:?}: configured BFD profile {:?} is missing",
                        neighbor.address, bfd.profile
                    ))
                })?;
            let scope_id = if is_ipv6_link_local(peer) {
                let interface = neighbor.interface.as_deref().ok_or_else(|| {
                    BfdRuntimeConfigError(format!(
                        "neighbor {:?}: IPv6 link-local BFD requires a configured interface",
                        neighbor.address
                    ))
                })?;
                Some(nix::net::if_::if_nametoindex(interface).map_err(|error| {
                    BfdRuntimeConfigError(format!(
                        "neighbor {:?} interface {:?}: failed to resolve IPv6 link-local BFD scope: {error}",
                        neighbor.address, interface
                    ))
                })?)
            } else {
                None
            };
            let destination = bfd_destination(peer, scope_id, bfd.multihop)?;
            sessions.push(BfdSessionParams {
                peer,
                scope_id,
                destination,
                desired_min_tx_us: profile.min_tx_interval.saturating_mul(1000),
                required_min_rx_us: profile.min_rx_interval.saturating_mul(1000),
                // Validation rejects multiplier > 255 / interval > u32::MAX/1000,
                // so these conversions are exact (the fallbacks never fire).
                detect_mult: u8::try_from(profile.multiplier).unwrap_or(u8::MAX),
                strict: bfd.strict,
                enabled: true,
                multihop: bfd.multihop,
                source: bfd
                    .multihop
                    .then(|| config.active_source_for(peer))
                    .flatten(),
            });
        }
        Ok(BfdRuntimeConfig { sessions })
    }
}

fn is_ipv6_link_local(peer: IpAddr) -> bool {
    matches!(peer, IpAddr::V6(v6) if {
        let octets = v6.octets();
        octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80
    })
}

/// UDP destination port: 3784 single-hop (RFC 5881 §4), 4784 multihop (RFC
/// 5883 §5).
fn bfd_control_port(multihop: bool) -> u16 {
    if multihop { 4784 } else { 3784 }
}

pub(crate) fn bfd_destination(
    peer: IpAddr,
    scope_id: Option<u32>,
    multihop: bool,
) -> Result<SocketAddr, BfdRuntimeConfigError> {
    if multihop && is_ipv6_link_local(peer) {
        return Err(BfdRuntimeConfigError(format!(
            "BFD peer {peer} is IPv6 link-local; multihop BFD (RFC 5883) needs a global peer address"
        )));
    }
    let port = bfd_control_port(multihop);
    match (peer, scope_id) {
        (IpAddr::V6(v6), Some(scope_id)) if is_ipv6_link_local(peer) && scope_id != 0 => {
            Ok(SocketAddr::V6(SocketAddrV6::new(v6, port, 0, scope_id)))
        }
        (IpAddr::V6(_), None) if is_ipv6_link_local(peer) => Err(BfdRuntimeConfigError(format!(
            "BFD peer {peer} is IPv6 link-local but has no interface scope"
        ))),
        (IpAddr::V6(_), Some(0)) if is_ipv6_link_local(peer) => Err(BfdRuntimeConfigError(
            format!("BFD peer {peer} has invalid zero interface scope"),
        )),
        (_, Some(scope_id)) => Err(BfdRuntimeConfigError(format!(
            "global BFD peer {peer} unexpectedly carries interface scope {scope_id}"
        ))),
        (_, None) => Ok(SocketAddr::new(peer, port)),
    }
}

/// A neighbor's effective BFD config: its own, else its peer-group's.
fn resolve_bfd<'a>(
    neighbor_bfd: Option<&'a BfdConfig>,
    peer_group: Option<&str>,
    config: &'a Config,
) -> Option<&'a BfdConfig> {
    if let Some(bfd) = neighbor_bfd {
        return Some(bfd);
    }
    config.peer_groups.get(peer_group?)?.bfd.as_ref()
}

/// Operator-visible state for one BFD session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BfdStatus {
    /// Peer IP address.
    pub peer: IpAddr,
    /// Current session state.
    pub state: rustbgpd_bfd::SessionState,
    /// Local diagnostic for the last state change.
    pub diagnostic: rustbgpd_bfd::Diagnostic,
    /// Whether the session is configured strict (RFC 5882).
    pub strict: bool,
    /// Whether the peer's most recently received control packet signaled
    /// `AdminDown`. The local state remains [`rustbgpd_bfd::SessionState::Down`]
    /// in that case, so this cause bit is required to explain why RFC 5882
    /// permits BGP while BFD is locally Down.
    pub remote_admin_down: bool,
    /// Whether the session uses RFC 5883 multihop encapsulation.
    pub multihop: bool,
}

/// A BFD session state transition, broadcast for the operator event stream
/// (ADR-0067 step 3b). The daemon bridges this into the unified
/// `EventService.WatchEvents` stream; the actor itself stays decoupled from the
/// gRPC proto (mirrors `fib_runtime`'s `FibRuntimeEvent`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BfdRuntimeEvent {
    /// Peer IP address.
    pub peer: IpAddr,
    /// State before the transition.
    pub old_state: rustbgpd_bfd::SessionState,
    /// State after the transition.
    pub new_state: rustbgpd_bfd::SessionState,
    /// Local diagnostic accompanying the transition.
    pub diagnostic: rustbgpd_bfd::Diagnostic,
}

#[cfg(target_os = "linux")]
// These are crate-internal daemon wiring types; their names are not all
// referenced directly in this binary crate, hence the allow.
#[allow(unused_imports)]
pub use linux::{BfdRuntimeHandle, PreparedRuntime, prepare_runtime, spawn_prepared};

/// RFC 5880 §6.8.6 demultiplexing decision (pure, testable): pick the session a
/// received packet belongs to. A non-zero Your Discriminator selects the session
/// by *our* local discriminator (which the peer echoes back in that field); a
/// zero Your Discriminator falls back to the source address, valid only for the
/// initial bootstrap packet before the peer has learned our discriminator (RFC
/// 5881 §5 warns against identifying an established single-hop session by source
/// address). Returns the peer key, or `None` if no session matches.
///
/// Note: Once a candidate session is selected by discriminator, RFC 5883 §5
/// mandates verifying that the packet's source IP matches the session's peer
/// for multihop sessions. Single-hop (RFC 5881 §5) deliberately does NOT
/// verify source IP — it relies on GTSM (TTL=255) instead. The source IP
/// check is enforced on packet reception in `on_packet`, gated on multihop.
///
/// Gated to Linux (where the actor runs) plus test builds.
#[cfg(any(test, target_os = "linux"))]
fn demux_target(
    by_discriminator: &std::collections::HashMap<u32, std::net::IpAddr>,
    src: std::net::IpAddr,
    your_discriminator: u32,
    have_session_for_src: bool,
) -> Option<std::net::IpAddr> {
    if your_discriminator != 0 {
        by_discriminator.get(&your_discriminator).copied()
    } else if have_session_for_src {
        Some(src)
    } else {
        None
    }
}

/// Whether a received packet changed the operator-visible BFD snapshot.
///
/// Remote `AdminDown` assertion and clear can both be cause-only Down→Down
/// changes, so comparing the local RFC 5880 state alone would leave the status
/// watch stale even though the BGP coupling observed the new cause.
#[cfg(any(test, target_os = "linux"))]
fn operator_status_changed(
    before_state: rustbgpd_bfd::SessionState,
    before_remote_admin_down: bool,
    after_state: rustbgpd_bfd::SessionState,
    after_remote_admin_down: bool,
) -> bool {
    before_state != after_state || before_remote_admin_down != after_remote_admin_down
}

#[cfg(target_os = "linux")]
mod linux {
    use std::cmp::Reverse;
    use std::collections::{BTreeMap, BinaryHeap, HashMap};
    use std::io::IoSliceMut;
    use std::net::{IpAddr, SocketAddr};
    use std::os::fd::AsRawFd;
    use std::time::Duration;

    use nix::sys::socket::{ControlMessageOwned, MsgFlags, recvmsg};
    use rustbgpd_bfd::{
        Action, ControlPacket, Diagnostic, DiscriminatorAllocator, Event, Session, SessionConfig,
        SessionState, TimerKind,
    };
    use rustbgpd_telemetry::BgpMetrics;
    use socket2::{Domain, Protocol, Socket, Type};
    use tokio::io::unix::AsyncFd;
    use tokio::net::UdpSocket;
    use tokio::sync::{broadcast, watch};
    use tokio::time::Instant;
    use tokio_util::sync::CancellationToken;
    use tracing::{debug, info, warn};

    use super::{
        BfdRuntimeConfig, BfdRuntimeEvent, BfdSessionParams, BfdStateChange, BfdStateChangeSender,
        BfdStatus, demux_target, operator_status_changed,
    };

    /// BFD single-hop control port (RFC 5881 §4).
    const BFD_CONTROL_PORT: u16 = 3784;
    /// BFD multihop control port (RFC 5883 §5).
    const BFD_MULTIHOP_CONTROL_PORT: u16 = 4784;
    const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
    /// Max datagrams pulled off one receive socket per actor turn. Bounds the
    /// work a packet flood can pin the actor to before the `select!` loop gets
    /// back to the shutdown / desired-set / timer arms; leftover datagrams keep
    /// the socket ready, so the next turn resumes reading immediately.
    const RECV_BUDGET: usize = 64;

    /// Join handle for daemon shutdown.
    pub struct BfdRuntimeHandle {
        shutdown: CancellationToken,
        task: tokio::task::JoinHandle<()>,
    }

    impl BfdRuntimeHandle {
        /// Signal the actor to drain (emit `AdminDown`) and stop.
        pub async fn shutdown(self) {
            self.shutdown.cancel();
            match tokio::time::timeout(SHUTDOWN_TIMEOUT, self.task).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => warn!(error = %e, "BFD actor task panicked on shutdown"),
                Err(_) => warn!("BFD actor shutdown timed out"),
            }
        }
    }

    /// The receive + transmit socket pair for one address family and one
    /// encapsulation mode. Opening them before spawning the task makes socket
    /// acquisition part of daemon startup instead of an eventually logged
    /// background failure.
    struct FamilySockets {
        rx: AsyncFd<std::net::UdpSocket>,
        tx: UdpSocket,
    }

    impl FamilySockets {
        /// Single-hop pair: receive on UDP/3784 (RFC 5881 §4).
        fn open(v6: bool) -> std::io::Result<Self> {
            Self::open_on(v6, BFD_CONTROL_PORT, None)
        }

        /// Multihop pair: receive on UDP/4784 (RFC 5883 §5). The transmit
        /// socket transmits at TTL 255 like the single-hop one.
        fn open_multihop(v6: bool, source: Option<IpAddr>) -> std::io::Result<Self> {
            Self::open_on(v6, BFD_MULTIHOP_CONTROL_PORT, source)
        }

        fn open_on(v6: bool, port: u16, source: Option<IpAddr>) -> std::io::Result<Self> {
            Ok(Self {
                rx: AsyncFd::new(rx_socket(v6, port)?)?,
                tx: UdpSocket::from_std(tx_socket(v6, source)?)?,
            })
        }
    }

    /// Sockets owned by one BFD actor, per address family. A family with no
    /// configured session is never opened (`None`), so a host without that
    /// family (e.g. `ipv6.disable=1`) cannot fail startup unless a session
    /// actually needs it.
    struct RuntimeSockets {
        v4: Option<FamilySockets>,
        v6: Option<FamilySockets>,
    }

    /// BFD sockets acquired during fail-fast startup and retained, inactive,
    /// until the daemon reaches the existing BFD activation point. Each
    /// encapsulation mode has its own per-family set; a mode with no
    /// configured session opens nothing.
    pub struct PreparedRuntime {
        single_hop: Option<RuntimeSockets>,
        multihop: Option<RuntimeSockets>,
    }

    /// Open sockets for exactly the families that have configured sessions.
    /// A family that has sessions and cannot open its sockets fails startup
    /// with the family named; a family with zero sessions is skipped entirely.
    fn prepare_runtime_sockets(
        needs_v4: bool,
        needs_v6: bool,
        opener: impl Fn(bool) -> std::io::Result<FamilySockets>,
    ) -> std::io::Result<Option<RuntimeSockets>> {
        if !needs_v4 && !needs_v6 {
            return Ok(None);
        }
        let open = |v6: bool| {
            let family = if v6 { "IPv6" } else { "IPv4" };
            opener(v6).map_err(|error| {
                std::io::Error::new(
                    error.kind(),
                    format!("BFD {family} socket startup failed: {error}"),
                )
            })
        };
        Ok(Some(RuntimeSockets {
            v4: needs_v4.then(|| open(false)).transpose()?,
            v6: needs_v6.then(|| open(true)).transpose()?,
        }))
    }

    /// Open the required family sockets without spawning the BFD actor.
    pub fn prepare_runtime(config: &BfdRuntimeConfig) -> std::io::Result<Option<PreparedRuntime>> {
        config.validate_destinations().map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid BFD runtime configuration: {error}"),
            )
        })?;
        let single_hop = prepare_runtime_sockets(
            config.needs_ipv4(),
            config.needs_ipv6(),
            FamilySockets::open,
        )?;
        let multihop = prepare_runtime_sockets(
            config.needs_multihop_ipv4(),
            config.needs_multihop_ipv6(),
            |v6| FamilySockets::open_multihop(v6, config.multihop_source(v6)),
        )
        .map_err(|error| std::io::Error::new(error.kind(), format!("multihop {error}")))?;
        if single_hop.is_none() && multihop.is_none() {
            return Ok(None);
        }
        Ok(Some(PreparedRuntime {
            single_hop,
            multihop,
        }))
    }

    /// Activate an already prepared BFD runtime. Socket acquisition cannot
    /// fail here; `None` means no BFD family was configured at startup.
    pub fn spawn_prepared(
        prepared: Option<PreparedRuntime>,
        desired_rx: watch::Receiver<BfdRuntimeConfig>,
        metrics: BgpMetrics,
        status_tx: watch::Sender<Vec<BfdStatus>>,
        event_tx: broadcast::Sender<BfdRuntimeEvent>,
        state_change_tx: BfdStateChangeSender,
        shutdown: CancellationToken,
    ) -> Option<BfdRuntimeHandle> {
        let prepared = prepared?;
        let task_shutdown = shutdown.clone();
        let task = tokio::spawn(async move {
            run(
                prepared,
                desired_rx,
                &metrics,
                &status_tx,
                &event_tx,
                &state_change_tx,
                &task_shutdown,
            )
            .await;
        });
        Some(BfdRuntimeHandle { shutdown, task })
    }

    /// One running session plus its provenance.
    struct Entry {
        session: Session,
        peer: IpAddr,
        /// Required receive/transmit interface for an IPv6 link-local peer.
        /// Global IPv4/IPv6 sessions remain unscoped.
        scope_id: Option<u32>,
        /// Prevalidated concrete destination; link-local addresses include the
        /// required interface scope.
        destination: SocketAddr,
        strict: bool,
        /// RFC 5883 multihop encapsulation: selects the UDP/4784 socket pair
        /// and rejects packets that arrive through the other mode's socket.
        multihop: bool,
        /// Our local discriminator for this session (RFC 5880 §6.8.1) — held so
        /// it can be released back to the allocator and removed from the
        /// `by_discriminator` demux index when the session is torn down.
        local_discriminator: u32,
        /// Local diagnostic from the most recent state change — surfaced in
        /// `BfdStatus` so the operator surface (PR3) shows *why* a session is
        /// in its current state (detection timeout, `AdminDown`, ...).
        last_diagnostic: Diagnostic,
        /// Per-timer epoch; bumped on (re)arm/stop so stale heap entries are
        /// recognized and skipped when they pop.
        epochs: HashMap<TimerKind, u64>,
    }

    /// A scheduled timer firing.
    #[derive(Debug, PartialEq, Eq)]
    struct Deadline {
        at: Instant,
        peer: IpAddr,
        kind: TimerKind,
        epoch: u64,
    }
    impl PartialOrd for Deadline {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }
    impl Ord for Deadline {
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            // The heap only cares about `at`; the remaining fields are
            // deterministic tie-breakers so the total order is consistent with
            // the derived `Eq` (Ord contract: `cmp == Equal` ⇔ `eq`), which
            // matters when several deadlines share the same `Instant`.
            self.at
                .cmp(&other.at)
                .then_with(|| self.epoch.cmp(&other.epoch))
                .then_with(|| self.peer.cmp(&other.peer))
                .then_with(|| kind_key(self.kind).cmp(&kind_key(other.kind)))
        }
    }

    /// Stable ordering key for `TimerKind` (which has no `Ord`), used only as a
    /// `Deadline` tie-breaker.
    fn kind_key(kind: TimerKind) -> u8 {
        match kind {
            TimerKind::Tx => 0,
            TimerKind::Detect => 1,
        }
    }

    struct Actor {
        sessions: BTreeMap<IpAddr, Entry>,
        /// Allocates unique non-zero local discriminators (RFC 5880 §6.8.1).
        /// Replaces an address hash, which could collide across peers.
        discriminators: DiscriminatorAllocator,
        /// Reverse index: our local discriminator → peer, for RFC 5880 §6.8.6
        /// demultiplexing (a packet's non-zero Your Discriminator selects the
        /// session, not the source address).
        by_discriminator: HashMap<u32, IpAddr>,
        timers: BinaryHeap<Reverse<Deadline>>,
        /// Transmit socket per family; `None` when the family had no
        /// configured session at startup (the session set is restart-required,
        /// so a session can never appear in an unopened family).
        tx_v4: Option<UdpSocket>,
        tx_v6: Option<UdpSocket>,
        /// Multihop transmit socket per family, same opening rule.
        multihop_tx_v4: Option<UdpSocket>,
        multihop_tx_v6: Option<UdpSocket>,
        /// Broadcast sink for session state transitions (ADR-0067 step 3b) —
        /// lossy, feeds the operator event stream.
        event_tx: broadcast::Sender<BfdRuntimeEvent>,
        /// Per-peer coalescing sink for session state changes consumed by
        /// `PeerManager` (ADR-0067 step 4 — BGP coupling).
        state_change_tx: BfdStateChangeSender,
        /// Simple deterministic PRNG for transmit jitter (RFC 5880 §6.8.7).
        jitter_state: u64,
    }

    /// The receive and transmit halves of one family's socket pair (`None`
    /// for an unopened family).
    type FamilyHalves = (Option<AsyncFd<std::net::UdpSocket>>, Option<UdpSocket>);

    /// Split one mode's per-family socket pairs into `(IPv4, IPv6)` halves.
    fn split_sockets(sockets: Option<RuntimeSockets>) -> (FamilyHalves, FamilyHalves) {
        let split = |family: Option<FamilySockets>| match family {
            Some(f) => (Some(f.rx), Some(f.tx)),
            None => (None, None),
        };
        match sockets {
            Some(RuntimeSockets { v4, v6 }) => (split(v4), split(v6)),
            None => ((None, None), (None, None)),
        }
    }

    /// Service one readable receive socket: read up to `RECV_BUDGET`
    /// datagrams, clear readiness only when the socket is fully drained, and
    /// feed each packet to the actor. `multihop` selects the RFC 5883
    /// receive rules (no TTL-255 requirement) and tags the packets so demux
    /// can refuse a session reached through the other mode's socket.
    async fn service_rx(
        actor: &mut Actor,
        guard: std::io::Result<tokio::io::unix::AsyncFdReadyGuard<'_, std::net::UdpSocket>>,
        multihop: bool,
        metrics: &BgpMetrics,
        status_tx: &watch::Sender<Vec<BfdStatus>>,
    ) {
        let Ok(mut g) = guard else {
            return;
        };
        let (pkts, drained) = drain_socket(g.get_inner().as_raw_fd(), RECV_BUDGET, multihop);
        if drained {
            g.clear_ready();
        }
        for packet in pkts {
            actor.on_packet(packet, metrics, status_tx).await;
        }
    }

    async fn run(
        prepared: PreparedRuntime,
        mut desired_rx: watch::Receiver<BfdRuntimeConfig>,
        metrics: &BgpMetrics,
        status_tx: &watch::Sender<Vec<BfdStatus>>,
        event_tx: &broadcast::Sender<BfdRuntimeEvent>,
        state_change_tx: &BfdStateChangeSender,
        shutdown: &CancellationToken,
    ) {
        let PreparedRuntime {
            single_hop,
            multihop,
        } = prepared;
        let ((rx_v4, tx_v4), (rx_v6, tx_v6)) = split_sockets(single_hop);
        let ((rx_mh_v4, tx_mh_v4), (rx_mh_v6, tx_mh_v6)) = split_sockets(multihop);
        let mut actor = Actor {
            sessions: BTreeMap::new(),
            discriminators: DiscriminatorAllocator::new(),
            by_discriminator: HashMap::new(),
            timers: BinaryHeap::new(),
            tx_v4,
            tx_v6,
            multihop_tx_v4: tx_mh_v4,
            multihop_tx_v6: tx_mh_v6,
            event_tx: event_tx.clone(),
            state_change_tx: state_change_tx.clone(),
            jitter_state: 0x9E37_79B9_7F4A_7C15,
        };

        // Reconcile the initial desired set, then on every change. Bind the
        // clone before awaiting so the watch `Ref` guard isn't held across the
        // await point (it is not `Send`).
        let initial = desired_rx.borrow_and_update().clone();
        actor.reconcile(&initial, metrics, status_tx).await;
        info!(sessions = actor.sessions.len(), "BFD actor started");

        // `biased` + this arm order is the actor's starvation defense: shutdown
        // and desired-set changes always win, due timers beat pending packets
        // (a garbage flood must not delay detection timeouts), and each receive
        // arm reads at most `RECV_BUDGET` datagrams before the loop re-selects
        // (`clear_ready` is skipped when the budget ran out, so a still-loaded
        // socket is picked up again on the very next turn).
        // ponytail: a sustained flood on an earlier rx arm can delay the later
        // ones (biased arm order: single-hop v4, v6, then multihop v4, v6);
        // rotate the rx arms per turn if that ever matters.
        loop {
            let sleep = next_timer_sleep(&actor.timers);
            tokio::select! {
                biased;
                () = shutdown.cancelled() => {
                    actor.drain(metrics, status_tx).await;
                    return;
                }
                changed = desired_rx.changed() => {
                    if changed.is_err() {
                        // The desired-set sender is gone (daemon shutting down).
                        actor.drain(metrics, status_tx).await;
                        return;
                    }
                    let desired = desired_rx.borrow_and_update().clone();
                    actor.reconcile(&desired, metrics, status_tx).await;
                }
                () = sleep => {
                    actor.fire_due_timers(metrics, status_tx).await;
                }
                guard = readable_or_pending(rx_v4.as_ref()) => {
                    service_rx(&mut actor, guard, false, metrics, status_tx).await;
                }
                guard = readable_or_pending(rx_v6.as_ref()) => {
                    service_rx(&mut actor, guard, false, metrics, status_tx).await;
                }
                guard = readable_or_pending(rx_mh_v4.as_ref()) => {
                    service_rx(&mut actor, guard, true, metrics, status_tx).await;
                }
                guard = readable_or_pending(rx_mh_v6.as_ref()) => {
                    service_rx(&mut actor, guard, true, metrics, status_tx).await;
                }
            }
        }
    }

    /// Await readability of a receive socket, or pend forever when the family
    /// was not opened (no configured session) — so an absent family simply
    /// never fires its `select!` arm.
    async fn readable_or_pending(
        rx: Option<&AsyncFd<std::net::UdpSocket>>,
    ) -> std::io::Result<tokio::io::unix::AsyncFdReadyGuard<'_, std::net::UdpSocket>> {
        match rx {
            Some(fd) => fd.readable().await,
            None => std::future::pending().await,
        }
    }

    impl Actor {
        async fn start_session(&mut self, params: &BfdSessionParams, metrics: &BgpMetrics) {
            // A unique non-zero local discriminator (RFC 5880 §6.8.1) from the
            // allocator — guaranteed distinct across peers, unlike an address
            // hash which can collide.
            let discr = match self.discriminators.allocate() {
                Ok(discr) => discr,
                Err(error) => {
                    warn!(
                        peer = %params.peer,
                        error = %error,
                        "skipping BFD session: local discriminator allocation failed"
                    );
                    return;
                }
            };
            let (session, actions) = match Session::new(SessionConfig {
                local_discriminator: discr,
                desired_min_tx_interval_us: params.desired_min_tx_us,
                required_min_rx_interval_us: params.required_min_rx_us,
                detect_mult: params.detect_mult,
            }) {
                Ok(pair) => pair,
                Err(e) => {
                    warn!(peer = %params.peer, error = %e, "skipping invalid BFD session");
                    self.discriminators.release(discr);
                    return;
                }
            };
            let entry = Entry {
                session,
                peer: params.peer,
                scope_id: params.scope_id,
                destination: params.destination,
                strict: params.strict,
                multihop: params.multihop,
                local_discriminator: discr,
                last_diagnostic: Diagnostic::None,
                epochs: HashMap::new(),
            };
            self.by_discriminator.insert(discr, params.peer);
            self.sessions.insert(params.peer, entry);
            // Seed the up gauge at 0 so a session that never comes Up (peer
            // absent, TTL-blocked, misconfigured) still has an observable
            // `bfd_session_up{peer}=0` series, not a missing one.
            metrics.record_bfd_state(&params.peer.to_string(), false, false);
            // Apply the session's initial actions (arms the slow tx timer).
            self.apply(params.peer, actions, metrics).await;
        }

        /// Reconcile running sessions toward the desired set (level-triggered):
        /// start missing enabled sessions, drain (`AdminDown` + remove) sessions
        /// no longer desired or now disabled, and refresh mutable metadata
        /// (`strict`) on the rest. Interval/multiplier changes are
        /// restart-required and intentionally ignored here.
        async fn reconcile(
            &mut self,
            desired: &BfdRuntimeConfig,
            metrics: &BgpMetrics,
            status_tx: &watch::Sender<Vec<BfdStatus>>,
        ) {
            let wanted: BTreeMap<IpAddr, &BfdSessionParams> = desired
                .sessions
                .iter()
                .filter(|s| s.enabled)
                .map(|s| (s.peer, s))
                .collect();

            // Drain sessions no longer desired (absent or disabled).
            let stale: Vec<IpAddr> = self
                .sessions
                .keys()
                .copied()
                .filter(|peer| !wanted.contains_key(peer))
                .collect();
            for peer in stale {
                self.admin_down_and_remove(peer, metrics).await;
            }

            // Start missing sessions; refresh metadata on existing ones.
            for (peer, params) in wanted {
                if let Some(entry) = self.sessions.get_mut(&peer) {
                    entry.strict = params.strict;
                } else {
                    self.start_session(params, metrics).await;
                }
            }
            self.publish_status(status_tx);

            // Re-confirm each running session's current state to PeerManager as
            // an "ack" (resync=true), on the coupling channel only (not
            // the operator broadcast). This is what lets the strict BGP coupling
            // release a withhold across a coalesced disable→re-enable — where the
            // session may stay Up with no fresh transition — without ever
            // trusting a stale cached state, and without deadlocking. The
            // consumer treats an ack as release-only, so re-confirming a Down
            // (e.g. a freshly (re)started session) never tears BGP down.
            let acks: Vec<BfdStateChange> = self
                .sessions
                .values()
                .map(|e| BfdStateChange {
                    peer: e.peer,
                    state: e.session.state(),
                    diagnostic: e.last_diagnostic,
                    remote_admin_down: e.session.remote_admin_down(),
                    resync: true,
                })
                .collect();
            for ack in acks {
                self.state_change_tx.send(ack);
            }
        }

        /// Drain one session to `AdminDown` (RFC 5880 §6.8.16 — emit the final
        /// `AdminDown` packet so the peer goes Down promptly) and drop it.
        async fn admin_down_and_remove(&mut self, peer: IpAddr, metrics: &BgpMetrics) {
            let actions = self
                .sessions
                .get_mut(&peer)
                .map(|e| e.session.administratively_down())
                .unwrap_or_default();
            self.apply(peer, actions, metrics).await;
            if let Some(entry) = self.sessions.remove(&peer) {
                // Free the discriminator and drop the demux index entry.
                self.by_discriminator.remove(&entry.local_discriminator);
                self.discriminators.release(entry.local_discriminator);
            }
        }

        async fn on_packet(
            &mut self,
            packet: ReceivedPacket,
            metrics: &BgpMetrics,
            status_tx: &watch::Sender<Vec<BfdStatus>>,
        ) {
            let ReceivedPacket {
                src,
                ifindex,
                multihop,
                packet: pkt,
                ..
            } = packet;
            let Some(peer) = scoped_demux_target(
                &self.by_discriminator,
                src,
                pkt.your_discriminator,
                ifindex,
                |candidate| self.sessions.get(&candidate).map(|entry| entry.scope_id),
            ) else {
                debug!(
                    peer = %src,
                    received_scope = ?ifindex,
                    your_discriminator = pkt.your_discriminator,
                    "BFD packet not matched to a session and interface scope; ignoring"
                );
                return;
            };
            let Some(entry) = self.sessions.get_mut(&peer) else {
                return;
            };
            // A session is single-hop or multihop, never both: a packet that
            // reached it through the other mode's socket (and therefore the
            // other mode's receive rules) is not this session's traffic.
            if entry.multihop != multihop {
                debug!(
                    %peer,
                    session_multihop = entry.multihop,
                    packet_multihop = multihop,
                    "BFD packet arrived through the other encapsulation mode's socket; ignoring"
                );
                return;
            }
            // RFC 5883 §5: for multihop sessions, if the source address does
            // not match the session's peer, the packet MUST be discarded.
            // Single-hop (RFC 5881 §5) deliberately does NOT verify source IP;
            // it relies on GTSM (TTL=255) for spoofing protection instead.
            if entry.multihop && src != peer {
                debug!(
                    %peer,
                    packet_src = %src,
                    your_discriminator = pkt.your_discriminator,
                    multihop,
                    "BFD packet source address does not match multihop session peer; ignoring"
                );
                return;
            }
            let before_state = entry.session.state();
            let before_remote_admin_down = entry.session.remote_admin_down();
            let actions = entry.session.handle(Event::PacketReceived(pkt));
            let changed = operator_status_changed(
                before_state,
                before_remote_admin_down,
                entry.session.state(),
                entry.session.remote_admin_down(),
            );
            self.apply(peer, actions, metrics).await;
            if changed {
                self.publish_status(status_tx);
            }
        }

        async fn fire_due_timers(
            &mut self,
            metrics: &BgpMetrics,
            status_tx: &watch::Sender<Vec<BfdStatus>>,
        ) {
            let now = Instant::now();
            let mut any_change = false;
            while let Some(Reverse(d)) = self.timers.peek() {
                if d.at > now {
                    break;
                }
                let Some(Reverse(d)) = self.timers.pop() else {
                    break;
                };
                // Skip stale (cancelled or superseded) timers.
                let Some(entry) = self.sessions.get_mut(&d.peer) else {
                    continue;
                };
                if entry.epochs.get(&d.kind).copied() != Some(d.epoch) {
                    continue;
                }
                let before = entry.session.state();
                let event = match d.kind {
                    TimerKind::Tx => Event::TxTimerExpires,
                    TimerKind::Detect => Event::DetectTimerExpires,
                };
                let actions = entry.session.handle(event);
                if entry.session.state() != before {
                    any_change = true;
                }
                self.apply(d.peer, actions, metrics).await;
            }
            if any_change {
                self.publish_status(status_tx);
            }
        }

        /// Apply a session's actions: schedule timers + update metrics under
        /// `&mut self`, then flush the collected packet sends under `&self`.
        async fn apply(&mut self, peer: IpAddr, actions: Vec<Action>, metrics: &BgpMetrics) {
            let sends = self.execute(peer, actions, metrics);
            for (dst, pkt) in sends {
                self.send(dst, &pkt).await;
            }
        }

        /// Schedule/cancel timers and record metrics for a session's actions;
        /// return the packets to transmit (sent by [`Actor::apply`]).
        fn execute(
            &mut self,
            peer: IpAddr,
            actions: Vec<Action>,
            metrics: &BgpMetrics,
        ) -> Vec<(IpAddr, ControlPacket)> {
            let mut sends = Vec::new();
            for action in actions {
                match action {
                    Action::SendPacket(pkt) => sends.push((peer, pkt)),
                    Action::StartTimer { kind, interval_us } => {
                        if let Some(entry) = self.sessions.get_mut(&peer) {
                            let epoch = entry.epochs.entry(kind).or_insert(0);
                            *epoch += 1;
                            let epoch = *epoch;
                            let interval = self.timer_interval(kind, interval_us);
                            self.timers.push(Reverse(Deadline {
                                at: Instant::now() + interval,
                                peer,
                                kind,
                                epoch,
                            }));
                        }
                    }
                    Action::StopTimer { kind } => {
                        if let Some(entry) = self.sessions.get_mut(&peer) {
                            *entry.epochs.entry(kind).or_insert(0) += 1;
                        }
                    }
                    Action::StateChanged {
                        old,
                        new,
                        diagnostic,
                    } => {
                        let mut remote_admin_down = false;
                        if let Some(entry) = self.sessions.get_mut(&peer) {
                            entry.last_diagnostic = diagnostic;
                            remote_admin_down = entry.session.remote_admin_down();
                        }
                        // `old == new` is a coupling-level re-report (the remote
                        // flipped into/out of AdminDown while the local state
                        // stayed put, RFC 5882 §4.1/§4.2): it goes only to the
                        // coupling channel — the operator event stream and the
                        // up/down metrics describe real transitions.
                        if old == new {
                            info!(peer = %peer, state = ?new, remote_admin_down,
                                "BFD remote AdminDown flip without local transition");
                        } else {
                            info!(peer = %peer, ?old, ?new, ?diagnostic, "BFD state change");
                            metrics.record_bfd_state(
                                &peer.to_string(),
                                new == SessionState::Up,
                                old == SessionState::Up,
                            );
                            // Broadcast for the unified event stream (ADR-0067
                            // step 3b). `send` errors only when there are no
                            // subscribers — expected and ignorable.
                            let _ = self.event_tx.send(BfdRuntimeEvent {
                                peer,
                                old_state: old,
                                new_state: new,
                                diagnostic,
                            });
                        }
                        // Notify PeerManager for BGP coupling (step 4), on the
                        // per-peer coalescing channel. A real change
                        // (resync=false): the consumer may tear BGP down on a
                        // genuine Down, not just release.
                        self.state_change_tx.send(BfdStateChange {
                            peer,
                            state: new,
                            diagnostic,
                            remote_admin_down,
                            resync: false,
                        });
                    }
                }
            }
            sends
        }

        /// Apply jitter to transmit timers (RFC 5880 §6.8.7: 0–25% reduction).
        fn timer_interval(&mut self, kind: TimerKind, interval_us: u32) -> Duration {
            let micros = match kind {
                TimerKind::Detect => u64::from(interval_us),
                TimerKind::Tx => {
                    // xorshift then reduce by 0..25%.
                    self.jitter_state ^= self.jitter_state << 13;
                    self.jitter_state ^= self.jitter_state >> 7;
                    self.jitter_state ^= self.jitter_state << 17;
                    let reduction = self.jitter_state % 26; // 0..=25
                    u64::from(interval_us) * (100 - reduction) / 100
                }
            };
            Duration::from_micros(micros.max(1))
        }

        async fn send(&mut self, peer: IpAddr, pkt: &ControlPacket) {
            let bytes = pkt.encode();
            let Some((dst, multihop)) = self
                .sessions
                .get(&peer)
                .map(|entry| (entry.destination, entry.multihop))
            else {
                return;
            };
            let sent = if multihop {
                let sock = if peer.is_ipv4() {
                    self.multihop_tx_v4.as_mut()
                } else {
                    self.multihop_tx_v6.as_mut()
                };
                let Some(sock) = sock else {
                    // Unreachable while the restart-required session set holds
                    // (a session's mode and family always had their sockets
                    // opened at startup); degrade to a logged non-send rather
                    // than a panic.
                    warn!(peer = %peer, "BFD transmit skipped: no multihop socket for the peer's address family");
                    return;
                };
                sock.send_to(&bytes, dst).await.map(|_| ())
            } else {
                let sock = if peer.is_ipv4() {
                    self.tx_v4.as_ref()
                } else {
                    self.tx_v6.as_ref()
                };
                let Some(sock) = sock else {
                    warn!(peer = %peer, "BFD transmit skipped: no socket for the peer's address family");
                    return;
                };
                sock.send_to(&bytes, dst).await.map(|_| ())
            };
            if let Err(e) = sent {
                debug!(peer = %peer, error = %e, "BFD transmit failed");
            }
        }

        async fn drain(&mut self, metrics: &BgpMetrics, status_tx: &watch::Sender<Vec<BfdStatus>>) {
            let peers: Vec<IpAddr> = self.sessions.keys().copied().collect();
            for peer in peers {
                let actions = self
                    .sessions
                    .get_mut(&peer)
                    .map(|e| e.session.administratively_down())
                    .unwrap_or_default();
                self.apply(peer, actions, metrics).await;
            }
            // Clear status — the actor is gone.
            let _ = status_tx.send(Vec::new());
            info!("BFD actor drained");
        }

        fn publish_status(&self, status_tx: &watch::Sender<Vec<BfdStatus>>) {
            let statuses: Vec<BfdStatus> = self
                .sessions
                .values()
                .map(|e| BfdStatus {
                    peer: e.peer,
                    state: e.session.state(),
                    diagnostic: e.last_diagnostic,
                    strict: e.strict,
                    remote_admin_down: e.session.remote_admin_down(),
                    multihop: e.multihop,
                })
                .collect();
            let _ = status_tx.send(statuses);
        }
    }

    /// Enforce receive-interface identity for any packet involving a
    /// link-local address. This gate runs after selecting the candidate session
    /// but before the packet reaches its FSM, so neither zero-discriminator
    /// bootstrap nor non-zero discriminator demux can bypass scope.
    fn receive_scope_matches(
        src: IpAddr,
        peer: IpAddr,
        expected_scope: Option<u32>,
        received_scope: Option<u32>,
    ) -> bool {
        if super::is_ipv6_link_local(src) || super::is_ipv6_link_local(peer) {
            expected_scope.is_some() && expected_scope == received_scope
        } else {
            true
        }
    }

    fn scoped_demux_target(
        by_discriminator: &HashMap<u32, IpAddr>,
        src: IpAddr,
        your_discriminator: u32,
        received_scope: Option<u32>,
        session_scope: impl Fn(IpAddr) -> Option<Option<u32>>,
    ) -> Option<IpAddr> {
        let source_exists = session_scope(src).is_some();
        let peer = demux_target(by_discriminator, src, your_discriminator, source_exists)?;
        let expected_scope = session_scope(peer)?;
        receive_scope_matches(src, peer, expected_scope, received_scope).then_some(peer)
    }

    fn next_timer_sleep(timers: &BinaryHeap<Reverse<Deadline>>) -> tokio::time::Sleep {
        match timers.peek() {
            Some(Reverse(d)) => tokio::time::sleep_until(d.at),
            // No timer pending: park on a long sleep until a packet or
            // shutdown wakes the select! loop and rebuilds the timer set.
            None => tokio::time::sleep(Duration::from_hours(1)),
        }
    }

    /// Outcome of one `recvmsg`.
    pub(super) enum Recv {
        /// A valid control packet from `(source IP)`.
        Packet(ReceivedPacket),
        /// A datagram was received but dropped (bad TTL, address, or decode).
        Discard,
        /// Nothing more to read (would-block or error).
        Done,
    }

    pub(super) struct ReceivedPacket {
        pub(super) src: IpAddr,
        pub(super) ifindex: Option<u32>,
        /// Which socket (mode) delivered the datagram.
        pub(super) multihop: bool,
        /// Received TTL / Hop Limit from ancillary data, when reported. The
        /// actor only gates on it (above); the netns tests read it to prove
        /// multihop transmit TTL 255 reaches the wire.
        #[cfg(test)]
        pub(super) ttl: Option<i32>,
        pub(super) packet: ControlPacket,
    }

    /// Read up to `budget` datagrams from a non-blocking RX socket, validating
    /// the TTL/Hop-Limit-255 requirement (RFC 5881; skipped for a `multihop`
    /// socket per RFC 5883) via ancillary data and decoding each into a
    /// `(source IP, ControlPacket)`. Every `recvmsg` (including discarded
    /// datagrams) counts against the budget, so a garbage flood is bounded
    /// exactly like a valid one. Returns the packets and whether the socket
    /// was fully drained (`false` = budget exhausted with data possibly still
    /// queued — the caller must keep the socket marked ready and come back).
    fn drain_socket(fd: i32, budget: usize, multihop: bool) -> (Vec<ReceivedPacket>, bool) {
        let mut out = Vec::new();
        for _ in 0..budget {
            match recv_one(fd, multihop) {
                Recv::Packet(packet) => out.push(packet),
                Recv::Discard => {}
                Recv::Done => return (out, true),
            }
        }
        (out, false)
    }

    pub(super) fn recv_one(fd: i32, multihop: bool) -> Recv {
        let mut buf = [0u8; 256];
        let mut iov = [IoSliceMut::new(&mut buf)];
        let mut cmsg = nix::cmsg_space!([u8; 256]);
        // Any recv error (incl. EWOULDBLOCK/EAGAIN) means stop reading.
        let Ok(msg) = recvmsg::<nix::sys::socket::SockaddrStorage>(
            fd,
            &mut iov,
            Some(&mut cmsg),
            MsgFlags::empty(),
        ) else {
            return Recv::Done;
        };
        let mut ttl: Option<i32> = None;
        let mut ifindex: Option<u32> = None;
        if let Ok(cmsgs) = msg.cmsgs() {
            for c in cmsgs {
                match c {
                    ControlMessageOwned::Ipv4Ttl(t) | ControlMessageOwned::Ipv6HopLimit(t) => {
                        ttl = Some(t);
                    }
                    ControlMessageOwned::Ipv6PacketInfo(info) => {
                        ifindex = Some(info.ipi6_ifindex);
                    }
                    _ => {}
                }
            }
        }
        // RFC 5881 §5: single-hop control packets must arrive with TTL/Hop
        // Limit 255, else be discarded. RFC 5883 packets have crossed routers,
        // so the multihop socket applies no TTL requirement (§5 leaves any
        // GTSM-style bound to the operator; none is configured here).
        if !multihop && ttl != Some(255) {
            return Recv::Discard;
        }
        let Some((src, src_port)) = msg.address.and_then(socket_ip_port) else {
            return Recv::Discard;
        };
        // RFC 5881 §4 / RFC 5883 §5: the source port MUST be in
        // 49152..=65535. The range's upper bound is the u16 ceiling, so only
        // the lower bound needs checking. Defense-in-depth alongside the
        // exact-TTL check and discriminator demux.
        if src_port < BFD_SRC_PORT_MIN {
            tracing::debug!(
                %src,
                src_port,
                "discarding BFD control packet with out-of-range source port (RFC 5881 §4)"
            );
            return Recv::Discard;
        }
        let n = msg.bytes;
        match ControlPacket::decode(&buf[..n]) {
            Ok(packet) => Recv::Packet(ReceivedPacket {
                src,
                ifindex,
                multihop,
                #[cfg(test)]
                ttl,
                packet,
            }),
            Err(_) => Recv::Discard,
        }
    }

    fn socket_ip_port(addr: nix::sys::socket::SockaddrStorage) -> Option<(IpAddr, u16)> {
        if let Some(v4) = addr.as_sockaddr_in() {
            return Some((IpAddr::V4(v4.ip()), v4.port()));
        }
        if let Some(v6) = addr.as_sockaddr_in6() {
            return Some((IpAddr::V6(v6.ip()), v6.port()));
        }
        None
    }

    fn rx_socket(v6: bool, port: u16) -> std::io::Result<std::net::UdpSocket> {
        rx_socket_with(v6, port, enable_recv_ttl)
    }

    fn rx_socket_with(
        v6: bool,
        port: u16,
        recv_ttl_enabler: impl FnOnce(i32, bool) -> std::io::Result<()>,
    ) -> std::io::Result<std::net::UdpSocket> {
        let domain = if v6 { Domain::IPV6 } else { Domain::IPV4 };
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_reuse_address(true)?;
        let bind: SocketAddr = if v6 {
            SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), port)
        } else {
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), port)
        };
        if v6 {
            socket.set_only_v6(true)?;
        }
        socket.bind(&bind.into()).map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("failed to bind BFD receive socket {bind}: {error}"),
            )
        })?;
        socket.set_nonblocking(true)?;
        let (family, option) = if v6 {
            ("IPv6", "IPV6_RECVHOPLIMIT")
        } else {
            ("IPv4", "IP_RECVTTL")
        };
        recv_ttl_enabler(socket.as_raw_fd(), v6).map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("failed to enable {option} on {family} BFD receive socket {bind}: {error}"),
            )
        })?;
        if v6 {
            nix::sys::socket::setsockopt(
                &socket,
                nix::sys::socket::sockopt::Ipv6RecvPacketInfo,
                &true,
            )
            .map_err(|error| {
                std::io::Error::new(
                    std::io::Error::from(error).kind(),
                    format!(
                        "failed to enable IPV6_RECVPKTINFO on IPv6 BFD receive socket {bind}: {error}"
                    ),
                )
            })?;
        }
        Ok(socket.into())
    }

    /// RFC 5881 §4: single-hop BFD control packets MUST use a source port in
    /// 49152..=65535.
    const BFD_SRC_PORT_MIN: u16 = 49152;
    const BFD_SRC_PORT_MAX: u16 = 65535;

    pub(super) fn tx_socket(
        v6: bool,
        source: Option<IpAddr>,
    ) -> std::io::Result<std::net::UdpSocket> {
        let domain = if v6 { Domain::IPV6 } else { Domain::IPV4 };
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        if v6 {
            socket.set_only_v6(true)?;
            socket.set_unicast_hops_v6(255)?;
        } else {
            socket.set_ttl_v4(255)?;
        }
        bind_source_port(&socket, v6, source)?;
        socket.set_nonblocking(true)?;
        Ok(socket.into())
    }

    /// Bind the transmit socket to a free port inside the RFC 5881 §4 source
    /// range. `bind(port 0)` would let the OS pick from the ephemeral range
    /// (Linux: ≥ 32768), which can fall below 49152 and break strict interop;
    /// scan the range from a per-process pseudo-random offset and bind the
    /// first free port instead.
    fn bind_source_port(socket: &Socket, v6: bool, source: Option<IpAddr>) -> std::io::Result<()> {
        let span = BFD_SRC_PORT_MAX - BFD_SRC_PORT_MIN; // 16383
        // Pseudo-random start within the range, derived from the PID.
        let start = u16::try_from(std::process::id() % u32::from(span + 1)).unwrap_or(0);
        let bind_address = source.unwrap_or({
            if v6 {
                IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
            } else {
                IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
            }
        });
        let mut first_error = None;
        for i in 0..=span {
            let port = BFD_SRC_PORT_MIN + (start + i) % (span + 1);
            match socket.bind(&SocketAddr::new(bind_address, port).into()) {
                Ok(()) => return Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {}
                Err(error) => {
                    first_error.get_or_insert(error);
                    break;
                }
            }
        }
        if let Some(error) = first_error {
            return Err(std::io::Error::new(
                error.kind(),
                format!("failed to bind BFD transmit source {bind_address}: {error}"),
            ));
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            "no free BFD source port in 49152..=65535",
        ))
    }

    // Raw setsockopt: socket2 / the safe wrappers don't expose IP_RECVTTL /
    // IPV6_RECVHOPLIMIT. The call is a textbook c_int option set on an owned fd.
    #[allow(
        unsafe_code,
        reason = "BFD receive TTL requires the raw Linux socket-option ABI"
    )]
    pub(super) fn enable_recv_ttl(fd: i32, v6: bool) -> std::io::Result<()> {
        let on: libc::c_int = 1;
        let (level, opt) = if v6 {
            (libc::IPPROTO_IPV6, libc::IPV6_RECVHOPLIMIT)
        } else {
            (libc::IPPROTO_IP, libc::IP_RECVTTL)
        };
        let optlen =
            libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>()).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "c_int size does not fit socklen_t",
                )
            })?;
        // SAFETY: `fd` is a valid socket fd we own; `&on` points to a live
        // c_int of the declared length for the option's lifetime.
        let ret =
            unsafe { libc::setsockopt(fd, level, opt, std::ptr::addr_of!(on).cast(), optlen) };
        if ret == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    #[cfg(test)]
    mod unit {
        use super::{
            BFD_SRC_PORT_MIN, Deadline, FamilySockets, enable_recv_ttl, kind_key,
            prepare_runtime_sockets, rx_socket_with, scoped_demux_target, tx_socket,
        };
        use rustbgpd_bfd::{ControlPacket, Diagnostic, SessionState, TimerKind};
        use std::collections::HashMap;
        use std::net::{IpAddr, SocketAddr, SocketAddrV6};
        use std::os::fd::AsRawFd;
        use tokio::io::unix::AsyncFd;
        use tokio::time::Instant;

        /// Open a real loopback socket pair for one family on ephemeral ports
        /// (never the BFD control port — these tests must not collide with a
        /// running daemon or each other).
        fn loopback_family_sockets(v6: bool) -> std::io::Result<FamilySockets> {
            let addr = if v6 { "[::1]:0" } else { "127.0.0.1:0" };
            let rx = std::net::UdpSocket::bind(addr)?;
            rx.set_nonblocking(true)?;
            let tx = std::net::UdpSocket::bind(addr)?;
            tx.set_nonblocking(true)?;
            Ok(FamilySockets {
                rx: AsyncFd::new(rx)?,
                tx: tokio::net::UdpSocket::from_std(tx)?,
            })
        }

        /// Current-thread runtime whose reactor backs `AsyncFd`/`UdpSocket`
        /// registration in the tests that open real sockets.
        fn io_runtime() -> tokio::runtime::Runtime {
            tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .build()
                .expect("build runtime")
        }

        fn deadline(at: Instant, peer: &str, kind: TimerKind, epoch: u64) -> Deadline {
            Deadline {
                at,
                peer: peer.parse::<IpAddr>().unwrap(),
                kind,
                epoch,
            }
        }

        #[test]
        fn deadline_ord_is_consistent_with_eq() {
            let now = Instant::now();
            let later = now + std::time::Duration::from_millis(1);
            let a = deadline(now, "10.0.0.1", TimerKind::Tx, 0);
            // Same `at`, different fields: Ord must NOT report Equal (that would
            // violate the Ord/Eq contract for the BinaryHeap).
            let same_at = deadline(now, "10.0.0.2", TimerKind::Detect, 1);
            assert_ne!(a, same_at);
            assert_ne!(a.cmp(&same_at), std::cmp::Ordering::Equal);
            // Identical fields compare Equal and are Eq.
            let clone = deadline(now, "10.0.0.1", TimerKind::Tx, 0);
            assert_eq!(a, clone);
            assert_eq!(a.cmp(&clone), std::cmp::Ordering::Equal);
            // `at` is still the primary key.
            assert!(a < deadline(later, "10.0.0.0", TimerKind::Tx, 0));
        }

        #[test]
        fn kind_key_is_injective() {
            assert_ne!(kind_key(TimerKind::Tx), kind_key(TimerKind::Detect));
        }

        #[test]
        fn transmit_destination_scopes_only_link_local_ipv6() {
            use super::super::{BfdRuntimeConfigError, bfd_destination};

            let link_local: IpAddr = "fe80::2".parse().unwrap();
            assert_eq!(
                bfd_destination(link_local, Some(17), false),
                Ok(SocketAddr::V6(SocketAddrV6::new(
                    "fe80::2".parse().unwrap(),
                    3784,
                    0,
                    17
                )))
            );
            assert_eq!(
                bfd_destination(link_local, None, false),
                Err(BfdRuntimeConfigError(
                    "BFD peer fe80::2 is IPv6 link-local but has no interface scope".to_string()
                )),
                "link-local transmit must fail closed without a scope"
            );
            assert_eq!(
                bfd_destination(link_local, Some(0), false),
                Err(BfdRuntimeConfigError(
                    "BFD peer fe80::2 has invalid zero interface scope".to_string()
                )),
                "link-local transmit must fail closed with an invalid scope"
            );

            let global_v6: IpAddr = "2001:db8::2".parse().unwrap();
            assert_eq!(
                bfd_destination(global_v6, None, false),
                Ok("[2001:db8::2]:3784".parse().unwrap())
            );
            let global_v4: IpAddr = "192.0.2.2".parse().unwrap();
            assert_eq!(
                bfd_destination(global_v4, None, false),
                Ok("192.0.2.2:3784".parse().unwrap())
            );
        }

        #[test]
        fn transmit_destination_uses_multihop_port_and_rejects_link_local() {
            use super::super::bfd_destination;

            // RFC 5883 §5: multihop control packets go to UDP/4784.
            assert_eq!(
                bfd_destination("192.0.2.2".parse().unwrap(), None, true),
                Ok("192.0.2.2:4784".parse().unwrap())
            );
            assert_eq!(
                bfd_destination("2001:db8::2".parse().unwrap(), None, true),
                Ok("[2001:db8::2]:4784".parse().unwrap())
            );
            // Single-hop stays on 3784 — the port is the only difference.
            assert_eq!(
                bfd_destination("192.0.2.2".parse().unwrap(), None, false),
                Ok("192.0.2.2:3784".parse().unwrap())
            );
            // A link-local peer is adjacent by definition: fail closed even
            // when a scope is supplied.
            let link_local: IpAddr = "fe80::2".parse().unwrap();
            for scope in [None, Some(17)] {
                let error = bfd_destination(link_local, scope, true)
                    .expect_err("link-local multihop must fail closed");
                assert!(
                    error.to_string().contains("multihop") && error.to_string().contains("fe80::2"),
                    "actionable error: {error}"
                );
            }
        }

        #[test]
        fn multihop_receive_admits_transit_ttl_while_single_hop_requires_255() {
            // One real RX socket with IP_RECVTTL; the same TTL-7 datagram is
            // read once under each mode's rules. Load-bearing proof: dropping
            // the `!multihop` guard makes the single-hop assertion red, and
            // re-adding an unconditional TTL check makes the multihop one red.
            let rx = rx_socket_with(false, 0, enable_recv_ttl).expect("rx socket");
            let dst = ("127.0.0.1", rx.local_addr().expect("addr").port());
            let sender = sender_in(BFD_SRC_PORT_MIN..=BFD_SRC_PORT_MIN + 200);
            sender.set_ttl(7).expect("ttl");

            sender
                .send_to(&control_packet(0x5111).encode(), dst)
                .expect("send");
            let (pkts, drained) = super::drain_socket(rx.as_raw_fd(), 8, false);
            assert!(drained);
            assert!(
                pkts.is_empty(),
                "RFC 5881 §5: a single-hop socket discards TTL≠255"
            );

            sender
                .send_to(&control_packet(0x5883).encode(), dst)
                .expect("send");
            let (pkts, drained) = super::drain_socket(rx.as_raw_fd(), 8, true);
            assert!(drained);
            assert_eq!(pkts.len(), 1, "RFC 5883 packets have transited routers");
            assert_eq!(pkts[0].packet.my_discriminator, 0x5883);
            assert!(
                pkts[0].multihop,
                "packets are tagged with the receiving mode"
            );
            assert_eq!(pkts[0].ttl, Some(7), "the received TTL is still reported");
        }

        #[test]
        fn link_local_scope_gates_zero_and_nonzero_discriminator_demux() {
            let peer: IpAddr = "fe80::2".parse().unwrap();
            let by_discriminator = HashMap::from([(41_u32, peer)]);
            let session_scope = |candidate| (candidate == peer).then_some(Some(17));

            for discriminator in [0, 41] {
                assert_eq!(
                    scoped_demux_target(
                        &by_discriminator,
                        peer,
                        discriminator,
                        Some(17),
                        session_scope,
                    ),
                    Some(peer),
                    "matching receive scope must admit discriminator {discriminator}"
                );
                assert_eq!(
                    scoped_demux_target(
                        &by_discriminator,
                        peer,
                        discriminator,
                        None,
                        session_scope,
                    ),
                    None,
                    "missing pktinfo must drop discriminator {discriminator}"
                );
                assert_eq!(
                    scoped_demux_target(
                        &by_discriminator,
                        peer,
                        discriminator,
                        Some(18),
                        session_scope,
                    ),
                    None,
                    "wrong interface must drop discriminator {discriminator}"
                );
            }

            let global: IpAddr = "2001:db8::2".parse().unwrap();
            let global_disc = HashMap::from([(42_u32, global)]);
            let global_scope = |candidate| (candidate == global).then_some(None);
            assert_eq!(
                scoped_demux_target(&global_disc, global, 42, None, global_scope),
                Some(global),
                "global IPv6 behavior remains unscoped"
            );
        }

        #[test]
        fn ipv6_receive_socket_enables_packet_info() {
            let socket = rx_socket_with(true, 0, enable_recv_ttl).expect("IPv6 receive socket");
            let enabled = nix::sys::socket::getsockopt(
                &socket,
                nix::sys::socket::sockopt::Ipv6RecvPacketInfo,
            )
            .expect("read IPV6_RECVPKTINFO");
            assert!(enabled);
        }

        #[test]
        fn transmit_socket_binds_configured_source_and_preserves_bind_error() {
            let socket = tx_socket(false, Some("127.0.0.1".parse().unwrap()))
                .expect("bind configured loopback source");
            let local = socket.local_addr().expect("local address");
            assert_eq!(local.ip(), "127.0.0.1".parse::<IpAddr>().unwrap());
            assert!((BFD_SRC_PORT_MIN..=u16::MAX).contains(&local.port()));

            let error = tx_socket(false, Some("192.0.2.1".parse().unwrap()))
                .expect_err("unavailable source must fail");
            assert_eq!(error.kind(), std::io::ErrorKind::AddrNotAvailable);
            assert!(error.to_string().contains("192.0.2.1"));
        }

        #[test]
        fn configured_startup_propagates_socket_open_failure() {
            // Load-bearing proof: changing `prepare_runtime_sockets` back to
            // the old log-and-continue behavior (`Err(_) => Ok(None)`) makes
            // this assertion red.
            let result = prepare_runtime_sockets(true, false, |_v6| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    "injected UDP/3784 collision",
                ))
            });
            let Err(error) = result else {
                panic!("configured BFD startup accepted a socket-open failure");
            };
            assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
            assert_eq!(
                error.to_string(),
                "BFD IPv4 socket startup failed: injected UDP/3784 collision"
            );
        }

        #[test]
        fn missing_link_local_scope_fails_before_socket_preparation() {
            use super::super::{BfdRuntimeConfig, BfdSessionParams};

            let config = BfdRuntimeConfig {
                sessions: vec![BfdSessionParams {
                    peer: "fe80::2".parse().unwrap(),
                    scope_id: None,
                    destination: "[fe80::2]:3784".parse().unwrap(),
                    desired_min_tx_us: 300_000,
                    required_min_rx_us: 300_000,
                    detect_mult: 3,
                    strict: false,
                    enabled: true,
                    multihop: false,
                    source: None,
                }],
            };
            let Err(error) = super::prepare_runtime(&config) else {
                panic!("missing scope must fail at startup preflight");
            };
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
            assert!(
                error.to_string().contains("fe80::2")
                    && error.to_string().contains("no interface scope"),
                "actionable startup error: {error}"
            );
        }

        #[test]
        fn disabled_startup_does_not_open_sockets() {
            // Load-bearing proof: removing the no-family early return makes
            // the injected opener panic and this test red.
            let result = prepare_runtime_sockets(false, false, |_v6| {
                panic!("disabled BFD startup attempted to open sockets")
            });
            assert!(matches!(result, Ok(None)));
        }

        #[test]
        fn ipv4_only_startup_skips_the_ipv6_family() {
            // Load-bearing proof: family-blind socket opening (open both
            // families whenever any session exists) hits the EAFNOSUPPORT arm
            // and turns an IPv4-only startup into a boot failure — exactly the
            // ipv6.disable=1 regression this test pins.
            let rt = io_runtime();
            let _guard = rt.enter();
            let result = prepare_runtime_sockets(true, false, |v6| {
                if v6 {
                    Err(std::io::Error::from_raw_os_error(libc::EAFNOSUPPORT))
                } else {
                    loopback_family_sockets(false)
                }
            });
            let sockets = result
                .expect("IPv4-only startup must not require IPv6")
                .expect("a configured family opens sockets");
            assert!(sockets.v4.is_some(), "the configured family is opened");
            assert!(
                sockets.v6.is_none(),
                "a family with no sessions stays closed"
            );
        }

        #[test]
        fn ipv6_session_startup_failure_is_fatal_and_names_the_family() {
            // A family that HAS sessions still fails closed, and the error
            // names the family so the operator knows which one to fix.
            let result = prepare_runtime_sockets(false, true, |v6| {
                assert!(v6, "IPv6-only startup must not open IPv4 sockets");
                Err(std::io::Error::from_raw_os_error(libc::EAFNOSUPPORT))
            });
            let Err(error) = result else {
                panic!("a family with sessions must fail closed");
            };
            assert!(
                error
                    .to_string()
                    .starts_with("BFD IPv6 socket startup failed:"),
                "error must name the failing family: {error}"
            );
        }

        #[test]
        fn mixed_config_opens_both_families() {
            // Real sockets on loopback ephemeral ports; skip (not fail) when
            // the host has no usable IPv6, mirroring the busy-UDP-port
            // anticipation in the flood test.
            if std::net::UdpSocket::bind("[::1]:0").is_err() {
                eprintln!("skipping: host has no usable IPv6 loopback");
                return;
            }
            let rt = io_runtime();
            let _guard = rt.enter();
            let sockets = prepare_runtime_sockets(true, true, loopback_family_sockets)
                .expect("both families open")
                .expect("configured families open sockets");
            assert!(sockets.v4.is_some());
            assert!(sockets.v6.is_some());
        }

        #[test]
        fn receive_ttl_enable_failure_propagates_with_socket_context() {
            // Load-bearing proof: ignoring the enabler result makes this
            // return `Ok`, while dropping the context makes the message
            // assertion red.
            let result = rx_socket_with(false, 0, |_fd, v6| {
                assert!(!v6);
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "injected option denial",
                ))
            });
            let error = result.expect_err("receive-TTL option failure must fail startup");
            assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
            assert_eq!(
                error.to_string(),
                "failed to enable IP_RECVTTL on IPv4 BFD receive socket 0.0.0.0:0: injected option denial"
            );
        }

        #[test]
        fn receive_ttl_setsockopt_preserves_errno() {
            // Load-bearing proof: restoring the old log-and-continue path or
            // replacing `last_os_error` with a generic error makes this red.
            let error = enable_recv_ttl(-1, false).expect_err("invalid fd must fail setsockopt");
            assert_eq!(error.raw_os_error(), Some(libc::EBADF));
        }

        #[test]
        fn drain_socket_budget_bounds_receive_work() {
            use std::os::fd::AsRawFd;
            let rx = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind rx");
            rx.set_nonblocking(true).expect("nonblocking");
            let tx = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind tx");
            let dst = rx.local_addr().expect("addr");
            // Queue 10 garbage datagrams (loopback delivery is synchronous).
            // Discards (no TTL-255 ancillary data here) must count against the
            // budget too — a garbage flood costs the same receive work.
            for _ in 0..10 {
                tx.send_to(&[0u8; 24], dst).expect("send");
            }
            let (pkts, drained) = super::drain_socket(rx.as_raw_fd(), 4, false);
            assert!(pkts.is_empty(), "garbage never decodes into packets");
            assert!(!drained, "budget exhausted with datagrams still queued");
            let (pkts, drained) = super::drain_socket(rx.as_raw_fd(), 64, false);
            assert!(pkts.is_empty());
            assert!(drained, "second turn drains the remainder");
        }

        fn control_packet(my_discriminator: u32) -> ControlPacket {
            ControlPacket {
                diagnostic: Diagnostic::None,
                state: SessionState::Down,
                poll: false,
                final_bit: false,
                control_plane_independent: false,
                auth_present: false,
                demand: false,
                multipoint: false,
                detect_mult: 3,
                my_discriminator,
                your_discriminator: 0,
                desired_min_tx_interval: 1_000_000,
                required_min_rx_interval: 1_000_000,
                required_min_echo_rx_interval: 0,
            }
        }

        /// Bind a loopback UDP sender on the first free port in `range`.
        fn sender_in(range: std::ops::RangeInclusive<u16>) -> std::net::UdpSocket {
            for port in range.clone() {
                if let Ok(s) = std::net::UdpSocket::bind(("127.0.0.1", port)) {
                    return s;
                }
            }
            panic!("no free sender port in {range:?}");
        }

        #[test]
        fn out_of_range_source_port_is_discarded() {
            // Real RX socket with IP_RECVTTL so the TTL-255 gate passes and
            // the source-port gate is the discriminating check.
            let rx = rx_socket_with(false, 0, enable_recv_ttl).expect("rx socket");
            let rx_port = rx.local_addr().expect("addr").port();
            let dst = ("127.0.0.1", rx_port);

            // Identical valid packets, distinguished by discriminator; both
            // senders emit TTL 255. Loopback delivery is synchronous.
            let bad = sender_in(20000..=20200);
            assert!(bad.local_addr().expect("addr").port() < BFD_SRC_PORT_MIN);
            bad.set_ttl(255).expect("ttl");
            bad.send_to(&control_packet(0xBAD).encode(), dst)
                .expect("send");

            let good = sender_in(BFD_SRC_PORT_MIN..=BFD_SRC_PORT_MIN + 200);
            good.set_ttl(255).expect("ttl");
            good.send_to(&control_packet(0x600D).encode(), dst)
                .expect("send");

            let (pkts, drained) = super::drain_socket(rx.as_raw_fd(), 8, false);
            assert!(drained, "both datagrams fit the budget");
            let discs: Vec<u32> = pkts
                .iter()
                .map(|received| received.packet.my_discriminator)
                .collect();
            assert_eq!(
                discs,
                vec![0x600D],
                "RFC 5881 §4: only the in-range source port passes"
            );
        }

        fn test_actor() -> (
            super::Actor,
            rustbgpd_telemetry::BgpMetrics,
            tokio::sync::watch::Sender<Vec<super::super::BfdStatus>>,
        ) {
            use super::super::state_change_channel;
            use super::{Actor, DiscriminatorAllocator};
            use prometheus::Registry;
            use rustbgpd_telemetry::BgpMetrics;
            use std::collections::{BTreeMap, BinaryHeap, HashMap};
            use tokio::sync::{broadcast, watch};

            let (event_tx, _event_rx) = broadcast::channel(64);
            let (state_change_tx, _state_change_rx) = state_change_channel();
            let (status_tx, _status_rx) = watch::channel(Vec::new());
            let metrics = BgpMetrics::with_registry(Registry::new());

            let actor = Actor {
                sessions: BTreeMap::new(),
                discriminators: DiscriminatorAllocator::new(),
                by_discriminator: HashMap::new(),
                timers: BinaryHeap::new(),
                tx_v4: None,
                tx_v6: None,
                multihop_tx_v4: None,
                multihop_tx_v6: None,
                event_tx,
                state_change_tx,
                jitter_state: 0x9E37_79B9_7F4A_7C15,
            };
            (actor, metrics, status_tx)
        }

        fn init_packet(my_discriminator: u32, your_discriminator: u32) -> ControlPacket {
            ControlPacket {
                diagnostic: Diagnostic::None,
                state: SessionState::Init,
                poll: false,
                final_bit: false,
                control_plane_independent: false,
                auth_present: false,
                demand: false,
                multipoint: false,
                detect_mult: 3,
                my_discriminator,
                your_discriminator,
                desired_min_tx_interval: 1_000_000,
                required_min_rx_interval: 1_000_000,
                required_min_echo_rx_interval: 0,
            }
        }

        #[tokio::test]
        async fn multihop_packet_with_mismatched_source_ip_is_discarded() {
            use super::super::BfdSessionParams;
            use super::ReceivedPacket;

            let (mut actor, metrics, status_tx) = test_actor();
            let peer: IpAddr = "192.0.2.1".parse().unwrap();
            let params = BfdSessionParams {
                peer,
                scope_id: None,
                destination: SocketAddr::new(peer, 4784),
                desired_min_tx_us: 1_000_000,
                required_min_rx_us: 1_000_000,
                detect_mult: 3,
                strict: false,
                enabled: true,
                multihop: true,
                source: None,
            };
            actor.start_session(&params, &metrics).await;

            let local_discr = actor
                .sessions
                .get(&peer)
                .expect("session exists")
                .local_discriminator;
            assert_eq!(
                actor.sessions.get(&peer).unwrap().session.state(),
                SessionState::Down
            );

            // RFC 5883 §5: packet with valid your_discriminator but mismatched source IP
            // MUST be discarded and MUST NOT affect session state.
            let mismatched_src: IpAddr = "198.51.100.99".parse().unwrap();
            let bad_packet = ReceivedPacket {
                src: mismatched_src,
                ifindex: None,
                multihop: true,
                #[cfg(test)]
                ttl: Some(254),
                packet: init_packet(9001, local_discr),
            };
            actor.on_packet(bad_packet, &metrics, &status_tx).await;
            assert_eq!(
                actor.sessions.get(&peer).unwrap().session.state(),
                SessionState::Down,
                "mismatched multihop source IP must be discarded and session must remain Down"
            );

            // A packet from the matching peer IP with state=Init transitions session to Up.
            let good_packet = ReceivedPacket {
                src: peer,
                ifindex: None,
                multihop: true,
                #[cfg(test)]
                ttl: Some(254),
                packet: init_packet(9001, local_discr),
            };
            actor.on_packet(good_packet, &metrics, &status_tx).await;
            assert_eq!(
                actor.sessions.get(&peer).unwrap().session.state(),
                SessionState::Up,
                "packet from matching multihop source IP transitions session to Up"
            );
        }

        #[tokio::test]
        async fn link_local_single_hop_source_ip_not_verified_but_scope_is() {
            use super::super::BfdSessionParams;
            use super::ReceivedPacket;

            let (mut actor, metrics, status_tx) = test_actor();
            let peer: IpAddr = "fe80::1".parse().unwrap();
            let scope_id = 10;
            let params = BfdSessionParams {
                peer,
                scope_id: Some(scope_id),
                destination: SocketAddr::V6(SocketAddrV6::new(
                    "fe80::1".parse().unwrap(),
                    3784,
                    0,
                    scope_id,
                )),
                desired_min_tx_us: 1_000_000,
                required_min_rx_us: 1_000_000,
                detect_mult: 3,
                strict: false,
                enabled: true,
                multihop: false,
                source: None,
            };
            actor.start_session(&params, &metrics).await;

            let local_discr = actor
                .sessions
                .get(&peer)
                .expect("session exists")
                .local_discriminator;
            assert_eq!(
                actor.sessions.get(&peer).unwrap().session.state(),
                SessionState::Down
            );

            // Correct source IP on wrong interface -> discarded by
            // scoped_demux_target's receive_scope_matches; session stays Down.
            let wrong_scope_packet = ReceivedPacket {
                src: peer,
                ifindex: Some(20),
                multihop: false,
                #[cfg(test)]
                ttl: Some(255),
                packet: init_packet(9002, local_discr),
            };
            actor
                .on_packet(wrong_scope_packet, &metrics, &status_tx)
                .await;
            assert_eq!(
                actor.sessions.get(&peer).unwrap().session.state(),
                SessionState::Down,
                "link-local packet on wrong interface must be discarded"
            );

            // Single-hop link-local does NOT verify source IP (RFC 5881 §5
            // relies on GTSM, not source matching). Mismatched source IP on
            // the correct interface is accepted and transitions to Up.
            let mismatched_src_packet = ReceivedPacket {
                src: "fe80::2".parse().unwrap(),
                ifindex: Some(scope_id),
                multihop: false,
                #[cfg(test)]
                ttl: Some(255),
                packet: init_packet(9002, local_discr),
            };
            actor
                .on_packet(mismatched_src_packet, &metrics, &status_tx)
                .await;
            assert_eq!(
                actor.sessions.get(&peer).unwrap().session.state(),
                SessionState::Up,
                "mismatched link-local source IP is accepted by GTSM (TTL=255), not discarded"
            );
        }

        #[tokio::test]
        async fn single_hop_packet_with_mismatched_source_ip_is_accepted_by_gtsm() {
            use super::super::BfdSessionParams;
            use super::ReceivedPacket;

            let (mut actor, metrics, status_tx) = test_actor();
            let peer: IpAddr = "10.0.0.1".parse().unwrap();
            let params = BfdSessionParams {
                peer,
                scope_id: None,
                destination: SocketAddr::new(peer, 3784),
                desired_min_tx_us: 1_000_000,
                required_min_rx_us: 1_000_000,
                detect_mult: 3,
                strict: false,
                enabled: true,
                multihop: false,
                source: None,
            };
            actor.start_session(&params, &metrics).await;

            let local_discr = actor
                .sessions
                .get(&peer)
                .expect("session exists")
                .local_discriminator;
            assert_eq!(
                actor.sessions.get(&peer).unwrap().session.state(),
                SessionState::Down
            );

            // Single-hop (RFC 5881 §5) does NOT verify source IP — it relies
            // on GTSM (TTL=255) for spoofing protection. A packet with a
            // mismatched source IP but valid your_discriminator and correct
            // TTL=255 is accepted and transitions the session to Up.
            let packet = ReceivedPacket {
                src: "10.0.0.2".parse().unwrap(),
                ifindex: None,
                multihop: false,
                #[cfg(test)]
                ttl: Some(255),
                packet: init_packet(9003, local_discr),
            };
            actor.on_packet(packet, &metrics, &status_tx).await;
            assert_eq!(
                actor.sessions.get(&peer).unwrap().session.state(),
                SessionState::Up,
                "single-hop with mismatched source IP is accepted by GTSM (TTL=255), not discarded"
            );
        }
    }

    /// LAN-285: the receive budget + biased `select!` must keep the shutdown
    /// command serviceable under a sustained packet flood (binds the real BFD
    /// port; the flood is garbage, so every datagram is receive work that is
    /// discarded before demux).
    #[cfg(test)]
    mod flood {
        use super::super::state_change_channel;
        use super::{BfdRuntimeConfig, BfdSessionParams, prepare_runtime, spawn_prepared};
        use prometheus::Registry;
        use rustbgpd_telemetry::BgpMetrics;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::Duration;
        use tokio::sync::{broadcast, watch};
        use tokio_util::sync::CancellationToken;

        async fn wait_status(
            rx: &mut watch::Receiver<Vec<super::super::BfdStatus>>,
            want_empty: bool,
            timeout: Duration,
        ) -> bool {
            tokio::time::timeout(timeout, async {
                loop {
                    if rx.borrow().is_empty() == want_empty {
                        return;
                    }
                    if rx.changed().await.is_err() {
                        return;
                    }
                }
            })
            .await
            .is_ok()
        }

        #[tokio::test]
        async fn shutdown_is_serviced_under_packet_flood() {
            let config = BfdRuntimeConfig {
                sessions: vec![BfdSessionParams {
                    peer: "127.0.0.9".parse().expect("ip"),
                    scope_id: None,
                    destination: "127.0.0.9:3784".parse().expect("socket address"),
                    desired_min_tx_us: 100_000,
                    required_min_rx_us: 100_000,
                    detect_mult: 3,
                    strict: false,
                    enabled: true,
                    multihop: false,
                    source: None,
                }],
            };
            let prepared = prepare_runtime(&config).expect("actor sockets open");
            let (status_tx, mut status_rx) = watch::channel(Vec::new());
            let (event_tx, _event_rx) = broadcast::channel(64);
            let (_desired_tx, desired_rx) = watch::channel(config);
            let (state_change_tx, _state_change_rx) = state_change_channel();
            let shutdown = CancellationToken::new();
            let metrics = BgpMetrics::with_registry(Registry::new());
            let handle = spawn_prepared(
                prepared,
                desired_rx,
                metrics,
                status_tx,
                event_tx,
                state_change_tx,
                shutdown.clone(),
            )
            .expect("actor spawns with one session");
            // The actor is up once it has published its session status.
            assert!(
                wait_status(&mut status_rx, false, Duration::from_secs(5)).await,
                "actor never published its session status (is UDP 3784 usable?)"
            );

            // Blast garbage datagrams at the BFD port from blocking threads
            // for the whole shutdown window.
            let stop = Arc::new(AtomicBool::new(false));
            let flooders: Vec<_> = (0..2)
                .map(|_| {
                    let stop = Arc::clone(&stop);
                    std::thread::spawn(move || {
                        let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind flooder");
                        let buf = [0u8; 24];
                        while !stop.load(Ordering::Relaxed) {
                            let _ = s.send_to(&buf, "127.0.0.1:3784");
                        }
                    })
                })
                .collect();
            tokio::time::sleep(Duration::from_millis(200)).await;

            // Demand shutdown mid-flood: the drain (which clears the status)
            // must complete while packets are still pouring in.
            shutdown.cancel();
            let drained = wait_status(&mut status_rx, true, Duration::from_secs(3)).await;
            stop.store(true, Ordering::Relaxed);
            for f in flooders {
                let _ = f.join();
            }
            assert!(
                drained,
                "BFD actor failed to service shutdown under a packet flood"
            );
            handle.shutdown().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::BfdRuntimeConfig;
    use crate::config::Config;

    fn config_with(extra: &str) -> Config {
        let toml = format!(
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"
{extra}
"#
        );
        toml::from_str(&toml).expect("parse config")
    }

    use crate::test_support::ip;

    #[test]
    fn from_config_collects_bfd_enabled_neighbor() {
        let config = config_with(
            r#"
[[bfd_profiles]]
name = "fast"
min_tx_interval = 250
min_rx_interval = 200
multiplier = 4

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
bfd = { profile = "fast", strict = true }
"#,
        );
        let rc = BfdRuntimeConfig::from_config(&config).expect("derive BFD runtime");
        assert!(rc.enabled());
        assert_eq!(rc.sessions.len(), 1);
        let s = &rc.sessions[0];
        assert_eq!(s.peer, ip("10.0.0.2"));
        assert_eq!(s.scope_id, None, "global IPv4 remains unscoped");
        // Profile ms intervals become microseconds for the FSM.
        assert_eq!(s.desired_min_tx_us, 250_000);
        assert_eq!(s.required_min_rx_us, 200_000);
        assert_eq!(s.detect_mult, 4);
        assert!(s.strict);
    }

    #[test]
    fn from_config_collects_multihop_mode() {
        let config = config_with(
            r#"
[[bfd_profiles]]
name = "fast"

[[neighbors]]
address = "10.0.2.2"
remote_asn = 65002
bfd = { profile = "fast", multihop = true }

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
bfd = { profile = "fast" }
"#,
        );
        let rc = BfdRuntimeConfig::from_config(&config).expect("derive BFD runtime");
        let multihop = rc
            .sessions
            .iter()
            .find(|s| s.peer == ip("10.0.2.2"))
            .expect("multihop session");
        assert!(multihop.multihop);
        assert_eq!(multihop.source, None);
        assert_eq!(multihop.destination, "10.0.2.2:4784".parse().unwrap());
        let single_hop = rc
            .sessions
            .iter()
            .find(|s| s.peer == ip("10.0.0.2"))
            .expect("single-hop session");
        assert!(!single_hop.multihop);
        assert_eq!(single_hop.source, None);
        assert_eq!(single_hop.destination, "10.0.0.2:3784".parse().unwrap());
        // Sockets open per (mode, family): a mixed config needs both IPv4
        // sets and neither IPv6 set.
        assert!(rc.needs_ipv4() && rc.needs_multihop_ipv4());
        assert!(!rc.needs_ipv6() && !rc.needs_multihop_ipv6());
    }

    #[test]
    fn from_config_carries_active_source_only_for_multihop() {
        let mut config = config_with(
            r#"
[[bfd_profiles]]
name = "fast"

[[neighbors]]
address = "127.0.0.2"
remote_asn = 65001
bfd = { profile = "fast", multihop = true }

[[neighbors]]
address = "127.0.0.3"
remote_asn = 65001
bfd = { profile = "fast" }
"#,
        );
        config.global.listen_addresses = Some(vec![ip("127.0.0.1")]);
        let runtime = BfdRuntimeConfig::from_config(&config).expect("derive runtime");
        assert_eq!(runtime.sessions[0].source, Some(ip("127.0.0.1")));
        assert_eq!(runtime.sessions[1].source, None);
    }

    #[test]
    fn multihop_only_config_never_needs_the_single_hop_sockets() {
        let config = config_with(
            r#"
[[bfd_profiles]]
name = "fast"

[[neighbors]]
address = "2001:db8::2"
remote_asn = 65002
bfd = { profile = "fast", multihop = true }
"#,
        );
        let rc = BfdRuntimeConfig::from_config(&config).expect("derive BFD runtime");
        assert!(rc.needs_multihop_ipv6());
        assert!(
            !rc.needs_ipv4() && !rc.needs_ipv6() && !rc.needs_multihop_ipv4(),
            "a multihop-only daemon must not bind UDP/3784"
        );
    }

    #[test]
    fn from_config_inherits_multihop_from_peer_group() {
        let config = config_with(
            r#"
[[bfd_profiles]]
name = "fast"

[peer_groups.rr-clients]
bfd = { profile = "fast", multihop = true }

[[neighbors]]
address = "10.0.2.2"
remote_asn = 65001
peer_group = "rr-clients"
"#,
        );
        let rc = BfdRuntimeConfig::from_config(&config).expect("derive BFD runtime");
        assert_eq!(rc.sessions.len(), 1);
        assert!(rc.sessions[0].multihop);
        assert_eq!(rc.sessions[0].destination, "10.0.2.2:4784".parse().unwrap());
    }

    #[test]
    fn from_config_rejects_multihop_on_link_local_neighbor() {
        // Config validation refuses this earlier; the runtime derivation must
        // fail closed on its own too (it is what the actor trusts).
        let config = config_with(
            r#"
[[bfd_profiles]]
name = "fast"

[[neighbors]]
address = "fe80::2"
interface = "lo"
remote_asn = 65002
bfd = { profile = "fast", multihop = true }
"#,
        );
        let error = BfdRuntimeConfig::from_config(&config)
            .expect_err("link-local multihop must not derive a session");
        assert!(
            error.to_string().contains("fe80::2") && error.to_string().contains("multihop"),
            "actionable error: {error}"
        );
    }

    #[test]
    fn from_config_resolves_link_local_interface_scope() {
        let config = config_with(
            r#"
[[bfd_profiles]]
name = "p"

[[neighbors]]
address = "fe80::2"
interface = "lo"
remote_asn = 65002
bfd = { profile = "p" }
"#,
        );
        let rc = BfdRuntimeConfig::from_config(&config).expect("resolve link-local scope");
        assert_eq!(rc.sessions.len(), 1);
        assert_eq!(rc.sessions[0].peer, ip("fe80::2"));
        assert_eq!(
            rc.sessions[0].scope_id,
            Some(nix::net::if_::if_nametoindex("lo").expect("loopback interface"))
        );
    }

    #[test]
    fn from_config_resolves_inherited_link_local_interface_scope() {
        let config = config_with(
            r#"
[[bfd_profiles]]
name = "p"

[peer_groups.fabric]
bfd = { profile = "p" }

[[neighbors]]
address = "fe80::3"
interface = "lo"
remote_asn = 65003
peer_group = "fabric"
"#,
        );
        let rc = BfdRuntimeConfig::from_config(&config).expect("resolve inherited scope");
        assert_eq!(rc.sessions.len(), 1);
        assert_eq!(rc.sessions[0].peer, ip("fe80::3"));
        assert_eq!(
            rc.sessions[0].scope_id,
            Some(nix::net::if_::if_nametoindex("lo").expect("loopback interface"))
        );
    }

    #[test]
    fn link_local_disabled_override_runs_no_session() {
        let config = config_with(
            r#"
[[bfd_profiles]]
name = "p"

[peer_groups.fabric]
bfd = { profile = "p" }

[[neighbors]]
address = "fe80::4"
interface = "lo"
remote_asn = 65004
peer_group = "fabric"
bfd = { profile = "p", enabled = false }
"#,
        );
        let rc = BfdRuntimeConfig::from_config(&config).expect("disabled BFD needs no scope");
        assert!(rc.sessions.is_empty());
    }

    #[test]
    fn nonexistent_link_local_interface_fails_checked_derivation() {
        let config = config_with(
            r#"
[[bfd_profiles]]
name = "p"

[[neighbors]]
address = "fe80::5"
interface = "rustbgpd-no-such-interface"
remote_asn = 65005
bfd = { profile = "p" }
"#,
        );
        let error = BfdRuntimeConfig::from_config(&config)
            .expect_err("missing interface must fail before socket preparation");
        let message = error.to_string();
        assert!(message.contains("fe80::5"), "neighbor context: {message}");
        assert!(
            message.contains("rustbgpd-no-such-interface"),
            "interface context: {message}"
        );
        assert!(message.contains("failed to resolve"), "reason: {message}");
    }

    #[test]
    fn from_config_inherits_peer_group_bfd() {
        let config = config_with(
            r#"
[[bfd_profiles]]
name = "p"
min_tx_interval = 300
min_rx_interval = 300
multiplier = 3

[peer_groups.rrc]
bfd = { profile = "p" }

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "rrc"
"#,
        );
        let rc = BfdRuntimeConfig::from_config(&config).expect("derive BFD runtime");
        assert_eq!(rc.sessions.len(), 1);
        assert_eq!(rc.sessions[0].peer, ip("10.0.0.2"));
        assert_eq!(rc.sessions[0].scope_id, None);
        assert!(!rc.sessions[0].strict);
    }

    #[test]
    fn neighbor_can_disable_inherited_peer_group_bfd() {
        let config = config_with(
            r#"
[[bfd_profiles]]
name = "p"

[peer_groups.rrc]
bfd = { profile = "p" }

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "rrc"

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
peer_group = "rrc"
bfd = { profile = "p", enabled = false }
"#,
        );
        let rc = BfdRuntimeConfig::from_config(&config).expect("derive BFD runtime");
        // Only the inheriting neighbor runs a session; the override disables it.
        assert_eq!(rc.sessions.len(), 1);
        assert_eq!(rc.sessions[0].peer, ip("10.0.0.2"));
    }

    #[test]
    fn neighbor_bfd_overrides_peer_group_bfd() {
        let config = config_with(
            r#"
[[bfd_profiles]]
name = "group"
min_tx_interval = 300
min_rx_interval = 300
multiplier = 3

[[bfd_profiles]]
name = "own"
min_tx_interval = 150
min_rx_interval = 150
multiplier = 5

[peer_groups.rrc]
bfd = { profile = "group" }

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "rrc"
bfd = { profile = "own", strict = true }
"#,
        );
        let rc = BfdRuntimeConfig::from_config(&config).expect("derive BFD runtime");
        assert_eq!(rc.sessions.len(), 1);
        let s = &rc.sessions[0];
        assert_eq!(s.desired_min_tx_us, 150_000);
        assert_eq!(s.detect_mult, 5);
        assert!(s.strict, "neighbor's own bfd wins over the peer-group's");
    }

    #[test]
    fn from_config_skips_neighbor_without_bfd() {
        let config = config_with(
            r#"
[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
"#,
        );
        let rc = BfdRuntimeConfig::from_config(&config).expect("derive BFD runtime");
        assert!(rc.sessions.is_empty());
        assert!(!rc.enabled());
    }

    #[test]
    fn reload_cannot_introduce_a_session_in_an_unopened_family() {
        // The actor opens sockets only for address families that have
        // configured sessions at startup. That is sound because BFD config is
        // restart-required: `pin_bfd_startup_only_runtime` (applied on every
        // reload) pins the effective session set to the live snapshot, so the
        // `desired_rx` watch can never introduce a session whose family had no
        // socket opened. This test pins that seam: a reload adding the first
        // IPv6 session to an IPv4-only runtime must not widen the family set.
        let profiles = r#"
[[bfd_profiles]]
name = "p"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
bfd = { profile = "p" }
"#;
        let live = config_with(profiles);
        let mut candidate = config_with(&format!(
            r#"{profiles}
[[neighbors]]
address = "2001:db8::2"
remote_asn = 65003
bfd = {{ profile = "p" }}
"#
        ));
        let candidate_families =
            BfdRuntimeConfig::from_config(&candidate).expect("derive candidate BFD runtime");
        assert!(
            candidate_families.needs_ipv6(),
            "candidate must genuinely ask for a new family"
        );
        assert!(
            crate::config::pin_bfd_startup_only_runtime(&mut candidate, &live),
            "a BFD-attachment change must be classified restart-required"
        );
        let rc = BfdRuntimeConfig::from_config(&candidate).expect("derive pinned BFD runtime");
        assert!(rc.needs_ipv4());
        assert!(
            !rc.needs_ipv6(),
            "pinned reload must not add a session in a family with no socket"
        );
    }

    mod state_change_channel {
        use super::super::{BfdStateChange, state_change_channel};
        use crate::test_support::ip;
        use rustbgpd_bfd::{Diagnostic, SessionState};

        fn change(state: SessionState, resync: bool) -> BfdStateChange {
            BfdStateChange {
                peer: ip("10.0.0.2"),
                state,
                diagnostic: Diagnostic::None,
                remote_admin_down: false,
                resync,
            }
        }

        #[tokio::test]
        async fn burst_for_one_peer_coalesces_to_latest() {
            let (tx, mut rx) = state_change_channel();
            // A large burst for one peer must not grow the channel: it
            // coalesces to a single pending change carrying the latest state.
            for _ in 0..1000 {
                tx.send(change(SessionState::Down, false));
                tx.send(change(SessionState::Up, false));
            }
            let got = rx.recv().await.expect("one coalesced change");
            assert_eq!(got.state, SessionState::Up, "latest state wins");
            assert!(!got.resync);
            // Exactly one delivery: with the senders dropped, the channel
            // closes rather than yielding queued leftovers.
            drop(tx);
            assert!(rx.recv().await.is_none());
        }

        #[tokio::test]
        async fn ack_does_not_mask_pending_real_transition() {
            let (tx, mut rx) = state_change_channel();
            // A real Down transition, then a reconcile ack for the same peer
            // before the consumer drains: the merge must keep resync=false so
            // the consumer still tears BGP down (an ack is release-only).
            tx.send(change(SessionState::Down, false));
            tx.send(change(SessionState::Down, true));
            let got = rx.recv().await.expect("merged change");
            assert_eq!(got.state, SessionState::Down);
            assert!(!got.resync, "ack must not mask a pending real transition");
        }

        #[tokio::test]
        async fn distinct_peers_are_not_coalesced_together() {
            let (tx, mut rx) = state_change_channel();
            let mut a = change(SessionState::Down, false);
            let mut b = change(SessionState::Up, false);
            a.peer = ip("10.0.0.2");
            b.peer = ip("10.0.0.3");
            tx.send(a);
            tx.send(b);
            let first = rx.recv().await.expect("first peer");
            let second = rx.recv().await.expect("second peer");
            assert_eq!(first.peer, ip("10.0.0.2"));
            assert_eq!(second.peer, ip("10.0.0.3"));
        }
    }

    #[test]
    fn demux_prefers_your_discriminator_then_source() {
        use super::demux_target;
        use std::collections::HashMap;

        let peer_a = ip("10.0.0.2");
        let peer_b = ip("10.0.0.3");
        let by_disc = HashMap::from([(7u32, peer_a), (8u32, peer_b)]);

        // RFC 5880 §6.8.6: a non-zero Your Discriminator selects the session by
        // discriminator, independent of the packet's source address.
        assert_eq!(
            demux_target(&by_disc, ip("203.0.113.9"), 7, false),
            Some(peer_a),
            "your_discriminator routes to its session regardless of source"
        );
        assert_eq!(demux_target(&by_disc, peer_b, 8, true), Some(peer_b));

        // A non-zero Your Discriminator with no matching session is dropped even
        // when a session exists for the source address — the discriminator, not
        // the source, is authoritative once set.
        assert_eq!(demux_target(&by_disc, peer_a, 999, true), None);

        // A zero Your Discriminator (initial bootstrap) falls back to the source
        // address, and only matches when a session for that source exists.
        assert_eq!(demux_target(&by_disc, peer_a, 0, true), Some(peer_a));
        assert_eq!(demux_target(&by_disc, ip("198.51.100.1"), 0, false), None);
    }

    /// Load-bearing proof: removing the remote-cause comparison from
    /// `operator_status_changed` makes both cause-only assertions red, while a
    /// repeated unchanged cause stays quiet.
    #[test]
    fn cause_only_remote_admin_down_assert_and_clear_publish_status() {
        use rustbgpd_bfd::SessionState;

        assert!(super::operator_status_changed(
            SessionState::Down,
            false,
            SessionState::Down,
            true,
        ));
        assert!(super::operator_status_changed(
            SessionState::Down,
            true,
            SessionState::Down,
            false,
        ));
        assert!(!super::operator_status_changed(
            SessionState::Down,
            true,
            SessionState::Down,
            true,
        ));
    }

    // --- Privileged netns integration test (Linux, gated) ---------------
    //
    // Runs the real BFD actor on real UDP sockets inside a network
    // namespace and drives it from a hand-rolled BFD peer (the test
    // itself), proving the full receive path: TTL/Hop-Limit-255 discard
    // (RFC 5881), decode, Your-Discriminator demux, the session FSM reaching Up,
    // and detection-timer expiry when the peer goes silent.
    //
    // Gated by EVPN_LINUX_NETNS=1 (set by the Docker netns harness); the
    // outer invocation re-execs the test binary inside a fresh netns,
    // mirroring `fib_runtime`'s pattern.
    #[cfg(target_os = "linux")]
    mod netns {
        use super::super::linux::{Recv, enable_recv_ttl, recv_one};
        use super::super::{
            BfdRuntimeConfig, BfdSessionParams, BfdStatus, prepare_runtime, spawn_prepared,
        };
        use prometheus::Registry;
        use rustbgpd_bfd::{ControlPacket, Diagnostic, SessionState};
        use rustbgpd_telemetry::BgpMetrics;
        use socket2::{Domain, Protocol, Socket, Type};
        use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};
        use std::os::fd::AsRawFd;
        use std::process::Command;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU16, Ordering};
        use std::time::Duration;
        use tokio::sync::{broadcast, watch};
        use tokio_util::sync::CancellationToken;

        const PEER_DISC: u32 = 0x0A0B_0C0D;
        const ACTOR_ADDR: &str = "127.0.0.1";
        const PEER_ADDR: &str = "127.0.0.2";
        const LL_ACTOR_ADDR: &str = "fe80::51";
        const LL_PEER_ADDR: &str = "fe80::52";
        const LL_WRONG_ACTOR_ADDR: &str = "fe80::53";
        const LL_ACTOR_IF: &str = "bfda";
        const LL_PEER_IF: &str = "bfdp";
        const LL_WRONG_ACTOR_IF: &str = "bfdwa";
        const LL_WRONG_PEER_IF: &str = "bfdwp";
        const PORT: u16 = 3784;
        const MULTIHOP_PORT: u16 = 4784;
        /// A never-answered single-hop peer that keeps the UDP/3784 sockets
        /// open beside the multihop ones, so the mode-isolation phase has a
        /// single-hop socket to misdeliver through.
        const SINGLE_HOP_BYSTANDER_ADDR: &str = "127.0.0.3";

        // Multihop responder mode, shared via a watch channel.
        const MH_MODE_TRANSIT: u8 = 0; // reply on 4784 with TTL=1 (transited; must be accepted)
        const MH_MODE_WRONG_SOCKET: u8 = 1; // reply on 3784 with TTL=255 (must be ignored)
        const MH_MODE_SILENT: u8 = 2; // stop replying

        // Peer responder mode, shared via a watch channel.
        const MODE_TTL_BAD: u8 = 0; // reply with TTL=1 (must be discarded)
        const MODE_TTL_GOOD: u8 = 1; // reply with TTL=255 (valid)
        const MODE_SILENT: u8 = 2; // stop replying

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum LinkLocalResponderMode {
            WrongInterface,
            IntendedInterface,
            Silent,
        }

        fn netns_gate() -> bool {
            std::env::var("EVPN_LINUX_NETNS").as_deref() == Ok("1")
        }

        fn is_inner() -> bool {
            std::env::var("RUSTBGPD_BFD_NETNS_INNER").is_ok()
        }

        fn run(cmd: &str, args: &[&str]) {
            let out = Command::new(cmd).args(args).output().expect("spawn");
            assert!(
                out.status.success(),
                "{cmd} {args:?} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }

        fn try_run(cmd: &str, args: &[&str]) {
            let _ = Command::new(cmd).args(args).output();
        }

        struct Netns {
            name: String,
        }

        impl Netns {
            fn create(suffix: &str) -> Self {
                let name = format!("rustbgpd-bfd-{suffix}-{}", std::process::id());
                try_run("ip", &["netns", "delete", &name]);
                run("ip", &["netns", "add", &name]);
                // Bring up loopback and assign 127.0.0.1/8 so both the actor
                // (127.0.0.1) and the hand-rolled peer (127.0.0.2) are bindable.
                run(
                    "ip",
                    &["-n", &name, "addr", "add", "127.0.0.1/8", "dev", "lo"],
                );
                run("ip", &["-n", &name, "link", "set", "lo", "up"]);
                Self { name }
            }

            fn create_link_local() -> Self {
                let ns = Self::create("ll");
                for (actor_if, peer_if) in [
                    (LL_ACTOR_IF, LL_PEER_IF),
                    (LL_WRONG_ACTOR_IF, LL_WRONG_PEER_IF),
                ] {
                    run(
                        "ip",
                        &[
                            "-n", &ns.name, "link", "add", actor_if, "type", "veth", "peer",
                            "name", peer_if,
                        ],
                    );
                    run("ip", &["-n", &ns.name, "link", "set", actor_if, "up"]);
                    run("ip", &["-n", &ns.name, "link", "set", peer_if, "up"]);
                }
                for (address, interface) in [
                    (LL_ACTOR_ADDR, LL_ACTOR_IF),
                    (LL_PEER_ADDR, LL_PEER_IF),
                    (LL_WRONG_ACTOR_ADDR, LL_WRONG_ACTOR_IF),
                    (LL_PEER_ADDR, LL_WRONG_PEER_IF),
                ] {
                    run(
                        "ip",
                        &[
                            "-n",
                            &ns.name,
                            "-6",
                            "addr",
                            "add",
                            &format!("{address}/64"),
                            "dev",
                            interface,
                            "nodad",
                        ],
                    );
                }
                ns
            }
        }

        impl Drop for Netns {
            fn drop(&mut self) {
                try_run("ip", &["netns", "delete", &self.name]);
            }
        }

        fn reexec_inner(ns: &Netns, test_name: &str) {
            let exe = std::env::current_exe().expect("self-exe");
            let status = Command::new("ip")
                .args(["netns", "exec", &ns.name])
                .arg(&exe)
                .args(["--exact", "--nocapture", test_name])
                .env("RUSTBGPD_BFD_NETNS_INNER", "1")
                .env("EVPN_LINUX_NETNS", "1")
                .status()
                .expect("spawn inner");
            assert!(status.success(), "inner netns test failed");
        }

        fn peer_socket() -> tokio::net::UdpSocket {
            let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
            s.set_reuse_address(true).unwrap();
            let addr: SocketAddr = format!("{PEER_ADDR}:{PORT}").parse().unwrap();
            s.bind(&addr.into()).unwrap();
            s.set_nonblocking(true).unwrap();
            tokio::net::UdpSocket::from_std(s.into()).unwrap()
        }

        /// Transmit socket for the hand-rolled peer, bound to the peer
        /// address on a port inside the RFC 5881 §4 source-port range —
        /// the actor's receive path discards control packets from
        /// out-of-range source ports.
        fn peer_tx_socket() -> tokio::net::UdpSocket {
            let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
            let bound = (49152u16..=65535).any(|port| {
                let addr: SocketAddr = format!("{PEER_ADDR}:{port}").parse().unwrap();
                s.bind(&addr.into()).is_ok()
            });
            assert!(bound, "no free peer source port in 49152..=65535");
            s.set_nonblocking(true).unwrap();
            tokio::net::UdpSocket::from_std(s.into()).unwrap()
        }

        /// Multihop peer receive socket on UDP/4784 with `IP_RECVTTL`, so the
        /// responder can read the actor's transmit TTL through `recv_one`.
        fn multihop_peer_rx() -> std::net::UdpSocket {
            let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
            s.set_reuse_address(true).unwrap();
            let addr: SocketAddr = format!("{PEER_ADDR}:{MULTIHOP_PORT}").parse().unwrap();
            s.bind(&addr.into()).unwrap();
            enable_recv_ttl(s.as_raw_fd(), false).unwrap();
            s.set_nonblocking(true).unwrap();
            s.into()
        }

        /// Hand-rolled multihop peer: answers the actor's UDP/4784 packets
        /// with a transited-looking TTL, or misdelivers the same reply through
        /// the single-hop port, or stays silent.
        async fn multihop_peer_responder(
            rx: std::net::UdpSocket,
            tx_sock: tokio::net::UdpSocket,
            mode_rx: watch::Receiver<u8>,
            observed_ttl: Arc<AtomicI32>,
            stop: CancellationToken,
        ) {
            let multihop_actor: SocketAddr =
                format!("{ACTOR_ADDR}:{MULTIHOP_PORT}").parse().unwrap();
            let single_hop_actor: SocketAddr = format!("{ACTOR_ADDR}:{PORT}").parse().unwrap();
            let mut cur_ttl = 0u32;
            loop {
                tokio::select! {
                    biased;
                    () = stop.cancelled() => return,
                    () = tokio::time::sleep(Duration::from_millis(10)) => {
                        let Recv::Packet(received) = recv_one(rx.as_raw_fd(), true) else {
                            continue;
                        };
                        observed_ttl.store(received.ttl.unwrap_or(-1), Ordering::Relaxed);
                        let actor_disc = received.packet.my_discriminator;
                        if actor_disc == 0 {
                            continue;
                        }
                        let (ttl, dst) = match *mode_rx.borrow() {
                            MH_MODE_TRANSIT => (1, multihop_actor),
                            MH_MODE_WRONG_SOCKET => (255, single_hop_actor),
                            _ => continue,
                        };
                        if ttl != cur_ttl {
                            tx_sock.set_ttl(ttl).unwrap();
                            cur_ttl = ttl;
                        }
                        let _ = tx_sock.send_to(&peer_init(actor_disc), dst).await;
                    }
                }
            }
        }

        fn link_local_peer_rx(scope_id: u32) -> std::net::UdpSocket {
            let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).unwrap();
            socket.set_reuse_address(true).unwrap();
            socket.set_only_v6(true).unwrap();
            let peer: Ipv6Addr = LL_PEER_ADDR.parse().unwrap();
            socket
                .bind(&SocketAddrV6::new(peer, PORT, 0, scope_id).into())
                .unwrap();
            enable_recv_ttl(socket.as_raw_fd(), true).unwrap();
            nix::sys::socket::setsockopt(
                &socket,
                nix::sys::socket::sockopt::Ipv6RecvPacketInfo,
                &true,
            )
            .unwrap();
            socket.set_nonblocking(true).unwrap();
            socket.into()
        }

        fn link_local_peer_tx(source_scope: u32) -> tokio::net::UdpSocket {
            let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).unwrap();
            socket.set_only_v6(true).unwrap();
            socket.set_unicast_hops_v6(255).unwrap();
            let source: Ipv6Addr = LL_PEER_ADDR.parse().unwrap();
            let bound = (49152_u16..=65535).any(|port| {
                socket
                    .bind(&SocketAddrV6::new(source, port, 0, source_scope).into())
                    .is_ok()
            });
            assert!(bound, "no free scoped IPv6 BFD source port");
            socket.set_nonblocking(true).unwrap();
            tokio::net::UdpSocket::from_std(socket.into()).unwrap()
        }

        // A control packet from the hand-rolled peer that drives a Down actor
        // to Up: State=Init with a non-zero my/your discriminator pair.
        fn peer_init(your_disc: u32) -> Vec<u8> {
            ControlPacket {
                diagnostic: Diagnostic::None,
                state: SessionState::Init,
                poll: false,
                final_bit: false,
                control_plane_independent: false,
                auth_present: false,
                demand: false,
                multipoint: false,
                detect_mult: 3,
                my_discriminator: PEER_DISC,
                your_discriminator: your_disc,
                desired_min_tx_interval: 100_000,
                required_min_rx_interval: 100_000,
                required_min_echo_rx_interval: 0,
            }
            .encode()
            .to_vec()
        }

        async fn peer_responder(
            sock: tokio::net::UdpSocket,
            tx_sock: tokio::net::UdpSocket,
            mode_rx: watch::Receiver<u8>,
            observed_src_port: Arc<AtomicU16>,
            stop: CancellationToken,
        ) {
            let actor: SocketAddr = format!("{ACTOR_ADDR}:{PORT}").parse().unwrap();
            let mut buf = [0u8; 256];
            let mut actor_disc = 0u32;
            let mut cur_ttl = 0u32;
            loop {
                tokio::select! {
                    biased;
                    () = stop.cancelled() => return,
                    r = sock.recv_from(&mut buf) => {
                        let Ok((n, src)) = r else { continue; };
                        // RFC 5881 §4: record the actor's transmit source port
                        // so the test can assert it is in 49152..=65535.
                        observed_src_port.store(src.port(), Ordering::Relaxed);
                        if let Ok(pkt) = ControlPacket::decode(&buf[..n])
                            && pkt.my_discriminator != 0
                        {
                            actor_disc = pkt.my_discriminator;
                        }
                        let mode = *mode_rx.borrow();
                        if mode == MODE_SILENT || actor_disc == 0 {
                            continue;
                        }
                        let ttl = if mode == MODE_TTL_BAD { 1 } else { 255 };
                        if ttl != cur_ttl {
                            tx_sock.set_ttl(ttl).unwrap();
                            cur_ttl = ttl;
                        }
                        let _ = tx_sock.send_to(&peer_init(actor_disc), actor).await;
                    }
                }
            }
        }

        #[expect(
            clippy::too_many_arguments,
            reason = "netns responder carries both intended and adversarial interface scopes"
        )]
        async fn link_local_peer_responder(
            rx: std::net::UdpSocket,
            good_tx: tokio::net::UdpSocket,
            wrong_tx: tokio::net::UdpSocket,
            peer_scope: u32,
            wrong_peer_scope: u32,
            mode_rx: watch::Receiver<LinkLocalResponderMode>,
            observed_source: Arc<AtomicBool>,
            observed_interface: Arc<AtomicBool>,
            wrong_send_succeeded: Arc<AtomicBool>,
            stop: CancellationToken,
        ) -> Result<(), String> {
            let good_actor = SocketAddr::V6(SocketAddrV6::new(
                LL_ACTOR_ADDR.parse().unwrap(),
                PORT,
                0,
                peer_scope,
            ));
            let wrong_actor = SocketAddr::V6(SocketAddrV6::new(
                LL_WRONG_ACTOR_ADDR.parse().unwrap(),
                PORT,
                0,
                wrong_peer_scope,
            ));
            let expected_source: IpAddr = LL_ACTOR_ADDR.parse().unwrap();
            loop {
                tokio::select! {
                    biased;
                    () = stop.cancelled() => return Ok(()),
                    () = tokio::time::sleep(Duration::from_millis(10)) => {
                        let Recv::Packet(received) = recv_one(rx.as_raw_fd(), false) else {
                            continue;
                        };
                        // `recv_one` admits only Hop-Limit 255 and an RFC 5881
                        // source port. Its pktinfo also proves which veth
                        // received the actor's shared-socket transmit.
                        observed_source.store(received.src == expected_source, Ordering::Relaxed);
                        observed_interface.store(
                            received.ifindex == Some(peer_scope),
                            Ordering::Relaxed,
                        );
                        let actor_disc = received.packet.my_discriminator;
                        if actor_disc == 0
                            || *mode_rx.borrow() == LinkLocalResponderMode::Silent
                        {
                            continue;
                        }
                        let response = peer_init(actor_disc);
                        if *mode_rx.borrow() == LinkLocalResponderMode::WrongInterface {
                            wrong_tx
                                .send_to(&response, wrong_actor)
                                .await
                                .map_err(|error| format!("wrong-interface BFD send failed: {error}"))?;
                            wrong_send_succeeded.store(true, Ordering::Relaxed);
                        } else {
                            good_tx
                                .send_to(&response, good_actor)
                                .await
                                .map_err(|error| format!("intended-interface BFD send failed: {error}"))?;
                        }
                    }
                }
            }
        }

        fn state_of(statuses: &[BfdStatus], peer: IpAddr) -> Option<SessionState> {
            statuses.iter().find(|s| s.peer == peer).map(|s| s.state)
        }

        /// Read the `bfd_session_up{peer}` gauge value from the registry by
        /// encoding to the Prometheus text format (version-stable), or `None`
        /// if the series does not exist yet.
        fn bfd_up_gauge(registry: &Registry, peer: &str) -> Option<i64> {
            use prometheus::Encoder;
            let mut buf = Vec::new();
            prometheus::TextEncoder::new()
                .encode(&registry.gather(), &mut buf)
                .ok()?;
            let text = String::from_utf8(buf).ok()?;
            let needle = format!("bfd_session_up{{peer=\"{peer}\"}}");
            text.lines()
                .find_map(|line| line.strip_prefix(&needle))
                .and_then(|rest| rest.trim().parse::<i64>().ok())
        }

        async fn wait_for(
            rx: &watch::Receiver<Vec<BfdStatus>>,
            peer: IpAddr,
            want: SessionState,
            timeout: Duration,
        ) -> bool {
            let deadline = tokio::time::Instant::now() + timeout;
            loop {
                if state_of(&rx.borrow(), peer) == Some(want) {
                    return true;
                }
                if tokio::time::Instant::now() >= deadline {
                    return false;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }

        /// Poll until `bfd_session_up{peer}` reaches `want`, or the timeout
        /// elapses. The actor runs on its own task, so the gauge appears (and
        /// changes) asynchronously after spawn / state transitions.
        async fn wait_for_gauge(
            registry: &Registry,
            peer: &str,
            want: i64,
            timeout: Duration,
        ) -> bool {
            let deadline = tokio::time::Instant::now() + timeout;
            loop {
                if bfd_up_gauge(registry, peer) == Some(want) {
                    return true;
                }
                if tokio::time::Instant::now() >= deadline {
                    return false;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }

        #[tokio::test]
        #[expect(clippy::too_many_lines, reason = "end-to-end netns scenario")]
        async fn session_reaches_up_and_detects_down() {
            if !netns_gate() {
                eprintln!("skipping: set EVPN_LINUX_NETNS=1 to run the privileged BFD netns test");
                return;
            }
            if !is_inner() {
                let ns = Netns::create("v4");
                reexec_inner(
                    &ns,
                    "bfd_runtime::tests::netns::session_reaches_up_and_detects_down",
                );
                return;
            }

            let peer_ip: IpAddr = PEER_ADDR.parse().unwrap();
            let config = BfdRuntimeConfig {
                sessions: vec![BfdSessionParams {
                    peer: peer_ip,
                    scope_id: None,
                    destination: "127.0.0.2:3784".parse().unwrap(),
                    desired_min_tx_us: 100_000,
                    required_min_rx_us: 100_000,
                    detect_mult: 3,
                    strict: false,
                    enabled: true,
                    multihop: false,
                    source: None,
                }],
            };
            let prepared = prepare_runtime(&config).expect("actor sockets open");
            let registry = Registry::new();
            let metrics = BgpMetrics::with_registry(registry.clone());
            let (status_tx, status_rx) = watch::channel(Vec::new());
            let (event_tx, mut event_rx) = broadcast::channel(64);
            let (_desired_tx, desired_rx) = watch::channel(config);
            let (state_change_tx, mut state_change_rx) = super::super::state_change_channel();
            let shutdown = CancellationToken::new();
            let handle = spawn_prepared(
                prepared,
                desired_rx,
                metrics,
                status_tx,
                event_tx,
                state_change_tx,
                shutdown.clone(),
            )
            .expect("actor should start with one session");

            // The up gauge is seeded to 0 at session creation, before any
            // packet exchange — a never-up session must still be observable.
            assert!(
                wait_for_gauge(&registry, PEER_ADDR, 0, Duration::from_secs(2)).await,
                "bfd_session_up should be seeded to 0 for a Down session"
            );

            let (mode_tx, mode_rx) = watch::channel(MODE_TTL_BAD);
            let peer_stop = CancellationToken::new();
            let observed_src_port = Arc::new(AtomicU16::new(0));
            let peer_task = tokio::spawn(peer_responder(
                peer_socket(),
                peer_tx_socket(),
                mode_rx,
                Arc::clone(&observed_src_port),
                peer_stop.clone(),
            ));

            // Phase A — TTL=1 replies must be discarded (RFC 5881 §5): the
            // session must NOT come Up no matter how many we send.
            let came_up = wait_for(
                &status_rx,
                peer_ip,
                SessionState::Up,
                Duration::from_millis(1500),
            )
            .await;
            assert!(
                !came_up,
                "session came Up on TTL≠255 packets — single-hop guard not enforced"
            );

            // Phase B — switch to TTL=255: the session must reach Up.
            mode_tx.send(MODE_TTL_GOOD).unwrap();
            assert!(
                wait_for(
                    &status_rx,
                    peer_ip,
                    SessionState::Up,
                    Duration::from_secs(5)
                )
                .await,
                "session did not reach Up on valid TTL=255 packets"
            );
            assert!(
                wait_for_gauge(&registry, PEER_ADDR, 1, Duration::from_secs(2)).await,
                "bfd_session_up should be 1 once the session is Up"
            );

            // The actor must broadcast a state-change event reaching Up (the
            // signal the unified WatchEvents stream is bridged from).
            let up_event = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    match event_rx.recv().await {
                        Ok(ev) if ev.new_state == SessionState::Up => return ev,
                        Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                        Err(broadcast::error::RecvError::Closed) => {
                            panic!("BFD event channel closed before Up")
                        }
                    }
                }
            })
            .await
            .expect("actor should broadcast a BFD Up event");
            assert_eq!(up_event.peer, peer_ip);

            // The actor must also deliver a state change to PeerManager
            // (the BGP-coupling channel, ADR-0067 step 4).
            let up_change = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    match state_change_rx.recv().await {
                        Some(change) if change.state == SessionState::Up => return change,
                        Some(_) => {}
                        None => panic!("BFD state-change channel closed before Up"),
                    }
                }
            })
            .await
            .expect("actor should deliver a BFD Up state change");
            assert_eq!(up_change.peer, peer_ip);

            // RFC 5881 §4: the actor's transmit source port must be in
            // 49152..=65535. By now the peer has observed several packets.
            let src_port = observed_src_port.load(Ordering::Relaxed);
            assert!(
                (49152u16..=65535).contains(&src_port),
                "actor transmit source port {src_port} outside RFC 5881 range 49152..=65535"
            );

            // Phase C — peer goes silent: detection timer must drive Down.
            mode_tx.send(MODE_SILENT).unwrap();
            assert!(
                wait_for(
                    &status_rx,
                    peer_ip,
                    SessionState::Down,
                    Duration::from_secs(5)
                )
                .await,
                "session did not detect Down after the peer went silent"
            );

            peer_stop.cancel();
            let _ = peer_task.await;
            handle.shutdown().await;
        }

        /// RFC 5883 multihop session end to end: UDP/4784 both ways, the
        /// transmit TTL 255 on the wire, transited (TTL≠255) replies
        /// accepted, encapsulation-mode isolation, and detection of loss.
        #[tokio::test]
        #[expect(clippy::too_many_lines, reason = "end-to-end netns scenario")]
        async fn multihop_session_accepts_transit_ttl_on_udp_4784_and_detects_down() {
            if !netns_gate() {
                eprintln!("skipping: set EVPN_LINUX_NETNS=1 to run the privileged BFD netns test");
                return;
            }
            if !is_inner() {
                let ns = Netns::create("mh");
                reexec_inner(
                    &ns,
                    "bfd_runtime::tests::netns::multihop_session_accepts_transit_ttl_on_udp_4784_and_detects_down",
                );
                return;
            }

            let peer_ip: IpAddr = PEER_ADDR.parse().unwrap();
            let bystander_ip: IpAddr = SINGLE_HOP_BYSTANDER_ADDR.parse().unwrap();
            let config = BfdRuntimeConfig {
                sessions: vec![
                    BfdSessionParams {
                        peer: peer_ip,
                        scope_id: None,
                        destination: format!("{PEER_ADDR}:{MULTIHOP_PORT}").parse().unwrap(),
                        desired_min_tx_us: 100_000,
                        required_min_rx_us: 100_000,
                        detect_mult: 3,
                        strict: false,
                        enabled: true,
                        multihop: true,
                        source: Some(ACTOR_ADDR.parse().unwrap()),
                    },
                    BfdSessionParams {
                        peer: bystander_ip,
                        scope_id: None,
                        destination: format!("{SINGLE_HOP_BYSTANDER_ADDR}:{PORT}")
                            .parse()
                            .unwrap(),
                        desired_min_tx_us: 100_000,
                        required_min_rx_us: 100_000,
                        detect_mult: 3,
                        strict: false,
                        enabled: true,
                        multihop: false,
                        source: None,
                    },
                ],
            };
            let prepared = prepare_runtime(&config).expect("actor sockets open");
            let registry = Registry::new();
            let metrics = BgpMetrics::with_registry(registry.clone());
            let (status_tx, status_rx) = watch::channel(Vec::new());
            let (event_tx, _event_rx) = broadcast::channel(64);
            let (_desired_tx, desired_rx) = watch::channel(config);
            let (state_change_tx, _state_change_rx) = super::super::state_change_channel();
            let shutdown = CancellationToken::new();
            let handle = spawn_prepared(
                prepared,
                desired_rx,
                metrics,
                status_tx,
                event_tx,
                state_change_tx,
                shutdown.clone(),
            )
            .expect("actor should start with two sessions");

            let (mode_tx, mode_rx) = watch::channel(MH_MODE_TRANSIT);
            let peer_stop = CancellationToken::new();
            let observed_ttl = Arc::new(AtomicI32::new(0));
            let peer_task = tokio::spawn(multihop_peer_responder(
                multihop_peer_rx(),
                peer_tx_socket(),
                mode_rx,
                Arc::clone(&observed_ttl),
                peer_stop.clone(),
            ));

            // Phase A — transited replies (TTL=1) on UDP/4784 bring the
            // session Up: no TTL-255 requirement on the multihop socket.
            assert!(
                wait_for(
                    &status_rx,
                    peer_ip,
                    SessionState::Up,
                    Duration::from_secs(5)
                )
                .await,
                "multihop session did not reach Up on TTL=1 replies over UDP/4784"
            );
            assert!(
                wait_for_gauge(&registry, PEER_ADDR, 1, Duration::from_secs(2)).await,
                "bfd_session_up should be 1 once the multihop session is Up"
            );
            assert_eq!(
                observed_ttl.load(Ordering::Relaxed),
                255,
                "multihop transmit TTL must be 255"
            );
            {
                let statuses = status_rx.borrow();
                let multihop = statuses.iter().find(|s| s.peer == peer_ip).expect("status");
                assert!(multihop.multihop, "operator snapshot reports the mode");
                let bystander = statuses
                    .iter()
                    .find(|s| s.peer == bystander_ip)
                    .expect("bystander status");
                assert!(!bystander.multihop);
                assert_eq!(
                    bystander.state,
                    SessionState::Down,
                    "the never-answered single-hop session stays Down"
                );
            }

            // Phase B — peer goes silent: detection drives Down.
            mode_tx.send(MH_MODE_SILENT).unwrap();
            assert!(
                wait_for(
                    &status_rx,
                    peer_ip,
                    SessionState::Down,
                    Duration::from_secs(5)
                )
                .await,
                "multihop session did not detect Down after the peer went silent"
            );

            // Phase C — the same valid reply (TTL=255, our discriminator)
            // delivered through the single-hop socket must not revive a
            // multihop session: encapsulation modes never cross.
            mode_tx.send(MH_MODE_WRONG_SOCKET).unwrap();
            let revived = wait_for(
                &status_rx,
                peer_ip,
                SessionState::Up,
                Duration::from_millis(1500),
            )
            .await;
            assert!(
                !revived,
                "multihop session came Up from packets on the single-hop socket"
            );

            // Phase D — back on UDP/4784 the session recovers.
            mode_tx.send(MH_MODE_TRANSIT).unwrap();
            assert!(
                wait_for(
                    &status_rx,
                    peer_ip,
                    SessionState::Up,
                    Duration::from_secs(5)
                )
                .await,
                "multihop session did not recover on UDP/4784"
            );

            peer_stop.cancel();
            let _ = peer_task.await;
            handle.shutdown().await;
        }

        #[tokio::test]
        #[expect(clippy::too_many_lines, reason = "scoped IPv6 netns scenario")]
        async fn link_local_session_enforces_interface_scope_and_detects_down() {
            if !netns_gate() {
                eprintln!("skipping: set EVPN_LINUX_NETNS=1 to run the privileged BFD netns test");
                return;
            }
            if !is_inner() {
                let ns = Netns::create_link_local();
                reexec_inner(
                    &ns,
                    "bfd_runtime::tests::netns::link_local_session_enforces_interface_scope_and_detects_down",
                );
                return;
            }

            let actor_scope = nix::net::if_::if_nametoindex(LL_ACTOR_IF).unwrap();
            let peer_scope = nix::net::if_::if_nametoindex(LL_PEER_IF).unwrap();
            let wrong_peer_scope = nix::net::if_::if_nametoindex(LL_WRONG_PEER_IF).unwrap();
            let peer_ip: IpAddr = LL_PEER_ADDR.parse().unwrap();

            // Bind the hand-rolled peer specifically to its intended veth.
            // The actor itself still uses one shared wildcard IPv6 socket.
            let peer_rx = link_local_peer_rx(peer_scope);
            let good_tx = link_local_peer_tx(peer_scope);
            let wrong_tx = link_local_peer_tx(wrong_peer_scope);
            let config = BfdRuntimeConfig {
                sessions: vec![BfdSessionParams {
                    peer: peer_ip,
                    scope_id: Some(actor_scope),
                    destination: SocketAddr::V6(SocketAddrV6::new(
                        LL_PEER_ADDR.parse().unwrap(),
                        PORT,
                        0,
                        actor_scope,
                    )),
                    desired_min_tx_us: 100_000,
                    required_min_rx_us: 100_000,
                    detect_mult: 3,
                    strict: false,
                    enabled: true,
                    multihop: false,
                    source: None,
                }],
            };
            let prepared = prepare_runtime(&config).expect("scoped actor sockets open");
            let metrics = BgpMetrics::with_registry(Registry::new());
            let (status_tx, status_rx) = watch::channel(Vec::new());
            let (event_tx, _event_rx) = broadcast::channel(64);
            let (_desired_tx, desired_rx) = watch::channel(config);
            let (state_change_tx, _state_change_rx) = super::super::state_change_channel();
            let shutdown = CancellationToken::new();
            let handle = spawn_prepared(
                prepared,
                desired_rx,
                metrics,
                status_tx,
                event_tx,
                state_change_tx,
                shutdown.clone(),
            )
            .expect("scoped actor starts");

            let (mode_tx, mode_rx) = watch::channel(LinkLocalResponderMode::WrongInterface);
            let peer_stop = CancellationToken::new();
            let observed_source = Arc::new(AtomicBool::new(false));
            let observed_interface = Arc::new(AtomicBool::new(false));
            let wrong_send_succeeded = Arc::new(AtomicBool::new(false));
            let peer_task = tokio::spawn(link_local_peer_responder(
                peer_rx,
                good_tx,
                wrong_tx,
                peer_scope,
                wrong_peer_scope,
                mode_rx,
                Arc::clone(&observed_source),
                Arc::clone(&observed_interface),
                Arc::clone(&wrong_send_succeeded),
                peer_stop.clone(),
            ));

            // Replies use the correct link-local source but arrive through the
            // adversarial veth. Non-zero discriminator knowledge must not let
            // them bypass the configured-interface gate.
            assert!(
                !wait_for(
                    &status_rx,
                    peer_ip,
                    SessionState::Up,
                    Duration::from_millis(1500),
                )
                .await,
                "link-local BFD came Up from the wrong receive interface"
            );
            assert!(
                observed_source.load(Ordering::Relaxed),
                "actor transmit did not use the intended link-local source"
            );
            assert!(
                observed_interface.load(Ordering::Relaxed),
                "actor transmit did not arrive on the intended peer interface with Hop-Limit 255"
            );
            assert!(
                wrong_send_succeeded.load(Ordering::Relaxed),
                "adversarial peer packet was never successfully sent through the wrong interface"
            );

            // Switch only the peer's output interface. The same peer address
            // and packet now arrive with matching IPV6_PKTINFO and reach Up.
            mode_tx
                .send(LinkLocalResponderMode::IntendedInterface)
                .unwrap();
            assert!(
                wait_for(
                    &status_rx,
                    peer_ip,
                    SessionState::Up,
                    Duration::from_secs(5),
                )
                .await,
                "link-local BFD did not reach Up on the configured interface"
            );

            mode_tx.send(LinkLocalResponderMode::Silent).unwrap();
            assert!(
                wait_for(
                    &status_rx,
                    peer_ip,
                    SessionState::Down,
                    Duration::from_secs(5),
                )
                .await,
                "link-local BFD did not detect loss"
            );

            peer_stop.cancel();
            peer_task
                .await
                .expect("link-local responder task join")
                .expect("link-local responder completed without send failures");
            handle.shutdown().await;
        }
    }
}
