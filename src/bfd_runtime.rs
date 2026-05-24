//! Single-hop asynchronous BFD actor (ADR-0067).
//!
//! Owns the UDP sockets, the real per-session timers, and transmit jitter, and
//! drives the pure [`rustbgpd_bfd::Session`] state machine. It is a **pure
//! session-runner**: it reconciles a desired session set owned and published by
//! `PeerManager` (a `watch` channel) and never derives lifecycle from BGP
//! itself. It publishes status via a `watch` channel + Prometheus metrics, a
//! lossy [`BfdRuntimeEvent`] broadcast for the operator event stream, and a
//! lossless [`BfdStateChange`] channel that `PeerManager` consumes for RFC 5882
//! BGP coupling (non-strict teardown shipped; strict withholding lands next).
//!
//! Design: a single actor task `select!`s over the shared per-AF receive
//! sockets and a min-deadline timer heap covering every session's transmit and
//! detection timers. The receive path validates the RFC 5881 TTL/Hop-Limit-255
//! requirement via `recvmsg` ancillary data, decodes, demultiplexes to the
//! session by Your Discriminator (RFC 5880 §6.8.6; source address only for the
//! zero-discriminator bootstrap), and executes the resulting
//! [`rustbgpd_bfd::Action`]s.

use std::net::IpAddr;

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
}

/// The desired BFD session set the actor reconciles toward. Owned and published
/// by `PeerManager` (level-triggered via a `watch` channel once coupling is
/// active); at startup it is derived from config via [`BfdRuntimeConfig::from_config`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BfdRuntimeConfig {
    /// One entry per BFD-enabled neighbor.
    pub sessions: Vec<BfdSessionParams>,
}

/// A BFD session state change delivered to `PeerManager` (ADR-0067 step 4) over
/// a lossless `mpsc` channel — distinct from the lossy [`BfdRuntimeEvent`]
/// broadcast that feeds the operator event stream, because a missed Down would
/// leave BGP up.
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
    /// deadlock when no fresh edge is coming. (A single-task actor + FIFO
    /// channel guarantee ordering, so a monotonic generation is unnecessary.)
    pub resync: bool,
}

impl BfdRuntimeConfig {
    /// Whether the actor should run at all.
    #[must_use]
    pub fn enabled(&self) -> bool {
        !self.sessions.is_empty()
    }

    /// Resolve the BFD session set from the daemon config: every static
    /// neighbor whose own `bfd` (or inherited peer-group `bfd`) names a defined
    /// profile. Config validation has already checked the profile references.
    #[must_use]
    pub fn from_config(config: &Config) -> BfdRuntimeConfig {
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
            let Ok(peer) = neighbor.address.parse::<IpAddr>() else {
                continue;
            };
            let Some(profile) = config.bfd_profiles.iter().find(|p| p.name == bfd.profile) else {
                continue;
            };
            sessions.push(BfdSessionParams {
                peer,
                desired_min_tx_us: profile.min_tx_interval.saturating_mul(1000),
                required_min_rx_us: profile.min_rx_interval.saturating_mul(1000),
                // Validation rejects multiplier > 255 / interval > u32::MAX/1000,
                // so these conversions are exact (the fallbacks never fire).
                detect_mult: u8::try_from(profile.multiplier).unwrap_or(u8::MAX),
                strict: bfd.strict,
                enabled: true,
            });
        }
        BfdRuntimeConfig { sessions }
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
// `BfdRuntimeHandle` is the public return type of `spawn`; the name isn't
// referenced directly in this binary crate, hence the allow.
#[allow(unused_imports)]
pub use linux::{BfdRuntimeHandle, spawn};

#[cfg(not(target_os = "linux"))]
pub use stub::{BfdRuntimeHandle, spawn};

#[cfg(not(target_os = "linux"))]
mod stub {
    use super::{BfdRuntimeConfig, BfdRuntimeEvent, BfdStateChange, BfdStatus};
    use rustbgpd_telemetry::BgpMetrics;
    use tokio::sync::{broadcast, mpsc, watch};
    use tokio_util::sync::CancellationToken;

    /// Non-Linux placeholder handle (BFD sockets are Linux-only).
    pub struct BfdRuntimeHandle;

    impl BfdRuntimeHandle {
        /// No-op shutdown.
        pub async fn shutdown(self) {}
    }

    /// BFD is unsupported off Linux; the actor never starts.
    #[must_use]
    pub fn spawn(
        _desired_rx: watch::Receiver<BfdRuntimeConfig>,
        _metrics: BgpMetrics,
        _status_tx: watch::Sender<Vec<BfdStatus>>,
        _event_tx: broadcast::Sender<BfdRuntimeEvent>,
        _state_change_tx: mpsc::UnboundedSender<BfdStateChange>,
        _shutdown: CancellationToken,
    ) -> Option<BfdRuntimeHandle> {
        None
    }
}

/// RFC 5880 §6.8.6 demultiplexing decision (pure, testable): pick the session a
/// received packet belongs to. A non-zero Your Discriminator selects the session
/// by *our* local discriminator (which the peer echoes back in that field); a
/// zero Your Discriminator falls back to the source address, valid only for the
/// initial bootstrap packet before the peer has learned our discriminator (RFC
/// 5881 §5 warns against identifying an established single-hop session by source
/// address). Returns the peer key, or `None` if no session matches.
///
/// Gated to Linux (where the actor runs) plus test builds; the non-Linux stub
/// has no receive path, so without this gate it would be dead code there.
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
    use tokio::sync::{broadcast, mpsc, watch};
    use tokio::time::Instant;
    use tokio_util::sync::CancellationToken;
    use tracing::{debug, info, warn};

    use super::{
        BfdRuntimeConfig, BfdRuntimeEvent, BfdSessionParams, BfdStateChange, BfdStatus,
        demux_target,
    };

    /// BFD single-hop control port (RFC 5881 §4).
    const BFD_CONTROL_PORT: u16 = 3784;
    const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);

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

    /// Spawn the BFD actor. Returns `None` when the initial desired set is
    /// empty (no BFD-configured neighbors at startup) — BFD config is
    /// restart-required, so the actor's existence is fixed at startup; the
    /// `desired_rx` watch then drives enable/disable/strict among that set.
    #[must_use]
    pub fn spawn(
        desired_rx: watch::Receiver<BfdRuntimeConfig>,
        metrics: BgpMetrics,
        status_tx: watch::Sender<Vec<BfdStatus>>,
        event_tx: broadcast::Sender<BfdRuntimeEvent>,
        state_change_tx: mpsc::UnboundedSender<BfdStateChange>,
        shutdown: CancellationToken,
    ) -> Option<BfdRuntimeHandle> {
        if !desired_rx.borrow().enabled() {
            return None;
        }
        let task_shutdown = shutdown.clone();
        let task = tokio::spawn(async move {
            if let Err(e) = run(
                desired_rx,
                &metrics,
                &status_tx,
                &event_tx,
                &state_change_tx,
                &task_shutdown,
            )
            .await
            {
                warn!(error = %e, "BFD actor exited with error");
            }
        });
        Some(BfdRuntimeHandle { shutdown, task })
    }

    /// One running session plus its provenance.
    struct Entry {
        session: Session,
        peer: IpAddr,
        strict: bool,
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
        tx_v4: UdpSocket,
        tx_v6: UdpSocket,
        /// Broadcast sink for session state transitions (ADR-0067 step 3b) —
        /// lossy, feeds the operator event stream.
        event_tx: broadcast::Sender<BfdRuntimeEvent>,
        /// Lossless sink for session state changes consumed by `PeerManager`
        /// (ADR-0067 step 4 — BGP coupling).
        state_change_tx: mpsc::UnboundedSender<BfdStateChange>,
        /// Simple deterministic PRNG for transmit jitter (RFC 5880 §6.8.7).
        jitter_state: u64,
    }

    async fn run(
        mut desired_rx: watch::Receiver<BfdRuntimeConfig>,
        metrics: &BgpMetrics,
        status_tx: &watch::Sender<Vec<BfdStatus>>,
        event_tx: &broadcast::Sender<BfdRuntimeEvent>,
        state_change_tx: &mpsc::UnboundedSender<BfdStateChange>,
        shutdown: &CancellationToken,
    ) -> std::io::Result<()> {
        let rx_v4 = AsyncFd::new(rx_socket(false)?)?;
        let rx_v6 = AsyncFd::new(rx_socket(true)?)?;
        let mut actor = Actor {
            sessions: BTreeMap::new(),
            discriminators: DiscriminatorAllocator::new(),
            by_discriminator: HashMap::new(),
            timers: BinaryHeap::new(),
            tx_v4: UdpSocket::from_std(tx_socket(false)?)?,
            tx_v6: UdpSocket::from_std(tx_socket(true)?)?,
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

        loop {
            let sleep = next_timer_sleep(&actor.timers);
            tokio::select! {
                biased;
                () = shutdown.cancelled() => {
                    actor.drain(metrics, status_tx).await;
                    return Ok(());
                }
                changed = desired_rx.changed() => {
                    if changed.is_err() {
                        // The desired-set sender is gone (daemon shutting down).
                        actor.drain(metrics, status_tx).await;
                        return Ok(());
                    }
                    let desired = desired_rx.borrow_and_update().clone();
                    actor.reconcile(&desired, metrics, status_tx).await;
                }
                guard = rx_v4.readable() => {
                    if let Ok(mut g) = guard {
                        let pkts = drain_socket(g.get_inner().as_raw_fd());
                        g.clear_ready();
                        for (src, pkt) in pkts {
                            actor.on_packet(src, &pkt, metrics, status_tx).await;
                        }
                    }
                }
                guard = rx_v6.readable() => {
                    if let Ok(mut g) = guard {
                        let pkts = drain_socket(g.get_inner().as_raw_fd());
                        g.clear_ready();
                        for (src, pkt) in pkts {
                            actor.on_packet(src, &pkt, metrics, status_tx).await;
                        }
                    }
                }
                () = sleep => {
                    actor.fire_due_timers(metrics, status_tx).await;
                }
            }
        }
    }

    impl Actor {
        async fn start_session(&mut self, params: &BfdSessionParams, metrics: &BgpMetrics) {
            // A unique non-zero local discriminator (RFC 5880 §6.8.1) from the
            // allocator — guaranteed distinct across peers, unlike an address
            // hash which can collide.
            let discr = self.discriminators.allocate();
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
                strict: params.strict,
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
            // an "ack" (resync=true), on the lossless coupling channel only (not
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
                let _ = self.state_change_tx.send(ack);
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
            src: IpAddr,
            pkt: &ControlPacket,
            metrics: &BgpMetrics,
            status_tx: &watch::Sender<Vec<BfdStatus>>,
        ) {
            let Some(peer) = demux_target(
                &self.by_discriminator,
                src,
                pkt.your_discriminator,
                self.sessions.contains_key(&src),
            ) else {
                debug!(
                    peer = %src,
                    your_discriminator = pkt.your_discriminator,
                    "BFD packet not matched to a session; ignoring"
                );
                return;
            };
            let Some(entry) = self.sessions.get_mut(&peer) else {
                return;
            };
            let before = entry.session.state();
            let actions = entry.session.handle(Event::PacketReceived(pkt.clone()));
            let changed = entry.session.state() != before;
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
                let Reverse(d) = self.timers.pop().expect("peeked");
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
                        info!(peer = %peer, ?old, ?new, ?diagnostic, "BFD state change");
                        let mut remote_admin_down = false;
                        if let Some(entry) = self.sessions.get_mut(&peer) {
                            entry.last_diagnostic = diagnostic;
                            remote_admin_down = entry.session.remote_admin_down();
                        }
                        metrics.record_bfd_state(
                            &peer.to_string(),
                            new == SessionState::Up,
                            old == SessionState::Up,
                        );
                        // Broadcast for the unified event stream (ADR-0067 step
                        // 3b). `send` errors only when there are no subscribers
                        // — expected and ignorable.
                        let _ = self.event_tx.send(BfdRuntimeEvent {
                            peer,
                            old_state: old,
                            new_state: new,
                            diagnostic,
                        });
                        // Lossless notify for PeerManager BGP coupling (step 4).
                        // A real transition (resync=false): the consumer may tear
                        // BGP down on a genuine Down, not just release.
                        let _ = self.state_change_tx.send(BfdStateChange {
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

        async fn send(&self, peer: IpAddr, pkt: &ControlPacket) {
            let bytes = pkt.encode();
            let dst = SocketAddr::new(peer, BFD_CONTROL_PORT);
            let sock = if peer.is_ipv4() {
                &self.tx_v4
            } else {
                &self.tx_v6
            };
            if let Err(e) = sock.send_to(&bytes, dst).await {
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
                })
                .collect();
            let _ = status_tx.send(statuses);
        }
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
    enum Recv {
        /// A valid control packet from `(source IP)`.
        Packet(IpAddr, ControlPacket),
        /// A datagram was received but dropped (bad TTL, address, or decode).
        Discard,
        /// Nothing more to read (would-block or error).
        Done,
    }

    /// Read all currently-available datagrams from a non-blocking RX socket,
    /// validating the TTL/Hop-Limit-255 requirement (RFC 5881) via ancillary
    /// data and decoding each into a `(source IP, ControlPacket)`.
    fn drain_socket(fd: i32) -> Vec<(IpAddr, ControlPacket)> {
        let mut out = Vec::new();
        loop {
            match recv_one(fd) {
                Recv::Packet(src, pkt) => out.push((src, pkt)),
                Recv::Discard => {}
                Recv::Done => break,
            }
        }
        out
    }

    fn recv_one(fd: i32) -> Recv {
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
        if let Ok(cmsgs) = msg.cmsgs() {
            for c in cmsgs {
                match c {
                    ControlMessageOwned::Ipv4Ttl(t) | ControlMessageOwned::Ipv6HopLimit(t) => {
                        ttl = Some(t);
                    }
                    _ => {}
                }
            }
        }
        // RFC 5881 §5: single-hop control packets must arrive with TTL/Hop
        // Limit 255, else be discarded.
        if ttl != Some(255) {
            return Recv::Discard;
        }
        let Some(src) = msg.address.and_then(socket_ip) else {
            return Recv::Discard;
        };
        let n = msg.bytes;
        match ControlPacket::decode(&buf[..n]) {
            Ok(pkt) => Recv::Packet(src, pkt),
            Err(_) => Recv::Discard,
        }
    }

    fn socket_ip(addr: nix::sys::socket::SockaddrStorage) -> Option<IpAddr> {
        if let Some(v4) = addr.as_sockaddr_in() {
            return Some(IpAddr::V4(v4.ip()));
        }
        if let Some(v6) = addr.as_sockaddr_in6() {
            return Some(IpAddr::V6(v6.ip()));
        }
        None
    }

    fn rx_socket(v6: bool) -> std::io::Result<std::net::UdpSocket> {
        let domain = if v6 { Domain::IPV6 } else { Domain::IPV4 };
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_reuse_address(true)?;
        let bind: SocketAddr = if v6 {
            SocketAddr::new(
                IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                BFD_CONTROL_PORT,
            )
        } else {
            SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                BFD_CONTROL_PORT,
            )
        };
        if v6 {
            socket.set_only_v6(true)?;
        }
        socket.bind(&bind.into())?;
        socket.set_nonblocking(true)?;
        enable_recv_ttl(socket.as_raw_fd(), v6);
        Ok(socket.into())
    }

    /// RFC 5881 §4: single-hop BFD control packets MUST use a source port in
    /// 49152..=65535.
    const BFD_SRC_PORT_MIN: u16 = 49152;
    const BFD_SRC_PORT_MAX: u16 = 65535;

    fn tx_socket(v6: bool) -> std::io::Result<std::net::UdpSocket> {
        let domain = if v6 { Domain::IPV6 } else { Domain::IPV4 };
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        if v6 {
            socket.set_only_v6(true)?;
            socket.set_unicast_hops_v6(255)?;
        } else {
            socket.set_ttl_v4(255)?;
        }
        bind_source_port(&socket, v6)?;
        socket.set_nonblocking(true)?;
        Ok(socket.into())
    }

    /// Bind the transmit socket to a free port inside the RFC 5881 §4 source
    /// range. `bind(port 0)` would let the OS pick from the ephemeral range
    /// (Linux: ≥ 32768), which can fall below 49152 and break strict interop;
    /// scan the range from a per-process pseudo-random offset and bind the
    /// first free port instead.
    fn bind_source_port(socket: &Socket, v6: bool) -> std::io::Result<()> {
        let span = BFD_SRC_PORT_MAX - BFD_SRC_PORT_MIN; // 16383
        // Pseudo-random start within the range, derived from the PID.
        let start = u16::try_from(std::process::id() % u32::from(span + 1)).unwrap_or(0);
        let unspec: IpAddr = if v6 {
            IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
        };
        for i in 0..=span {
            let port = BFD_SRC_PORT_MIN + (start + i) % (span + 1);
            if socket.bind(&SocketAddr::new(unspec, port).into()).is_ok() {
                return Ok(());
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            "no free BFD source port in 49152..=65535",
        ))
    }

    // Raw setsockopt: socket2 / the safe wrappers don't expose IP_RECVTTL /
    // IPV6_RECVHOPLIMIT. The call is a textbook c_int option set on an owned fd.
    #[allow(unsafe_code)]
    fn enable_recv_ttl(fd: i32, v6: bool) {
        let on: libc::c_int = 1;
        let (level, opt) = if v6 {
            (libc::IPPROTO_IPV6, libc::IPV6_RECVHOPLIMIT)
        } else {
            (libc::IPPROTO_IP, libc::IP_RECVTTL)
        };
        let optlen = libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>())
            .expect("c_int size fits socklen_t");
        // SAFETY: `fd` is a valid socket fd we own; `&on` points to a live
        // c_int of the declared length for the option's lifetime.
        let ret =
            unsafe { libc::setsockopt(fd, level, opt, std::ptr::addr_of!(on).cast(), optlen) };
        if ret != 0 {
            warn!(error = %std::io::Error::last_os_error(), "failed to enable BFD recv TTL");
        }
    }

    #[cfg(test)]
    mod unit {
        use super::{Deadline, kind_key};
        use rustbgpd_bfd::TimerKind;
        use std::net::IpAddr;
        use tokio::time::Instant;

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
    }
}

#[cfg(test)]
mod tests {
    use super::BfdRuntimeConfig;
    use crate::config::Config;
    use std::net::IpAddr;

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

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

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
        let rc = BfdRuntimeConfig::from_config(&config);
        assert!(rc.enabled());
        assert_eq!(rc.sessions.len(), 1);
        let s = &rc.sessions[0];
        assert_eq!(s.peer, ip("10.0.0.2"));
        // Profile ms intervals become microseconds for the FSM.
        assert_eq!(s.desired_min_tx_us, 250_000);
        assert_eq!(s.required_min_rx_us, 200_000);
        assert_eq!(s.detect_mult, 4);
        assert!(s.strict);
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
        let rc = BfdRuntimeConfig::from_config(&config);
        assert_eq!(rc.sessions.len(), 1);
        assert_eq!(rc.sessions[0].peer, ip("10.0.0.2"));
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
        let rc = BfdRuntimeConfig::from_config(&config);
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
        let rc = BfdRuntimeConfig::from_config(&config);
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
        let rc = BfdRuntimeConfig::from_config(&config);
        assert!(rc.sessions.is_empty());
        assert!(!rc.enabled());
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
        use super::super::{BfdRuntimeConfig, BfdSessionParams, BfdStatus, spawn};
        use prometheus::Registry;
        use rustbgpd_bfd::{ControlPacket, Diagnostic, SessionState};
        use rustbgpd_telemetry::BgpMetrics;
        use socket2::{Domain, Protocol, Socket, Type};
        use std::net::{IpAddr, SocketAddr};
        use std::process::Command;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU16, Ordering};
        use std::time::Duration;
        use tokio::sync::{broadcast, mpsc, watch};
        use tokio_util::sync::CancellationToken;

        const PEER_DISC: u32 = 0x0A0B_0C0D;
        const ACTOR_ADDR: &str = "127.0.0.1";
        const PEER_ADDR: &str = "127.0.0.2";
        const PORT: u16 = 3784;

        // Peer responder mode, shared via a watch channel.
        const MODE_TTL_BAD: u8 = 0; // reply with TTL=1 (must be discarded)
        const MODE_TTL_GOOD: u8 = 1; // reply with TTL=255 (valid)
        const MODE_SILENT: u8 = 2; // stop replying

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
            fn create() -> Self {
                let name = format!("rustbgpd-bfd-{}", std::process::id());
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
        }

        impl Drop for Netns {
            fn drop(&mut self) {
                try_run("ip", &["netns", "delete", &self.name]);
            }
        }

        fn reexec_inner(ns: &Netns) {
            let exe = std::env::current_exe().expect("self-exe");
            let status = Command::new("ip")
                .args(["netns", "exec", &ns.name])
                .arg(&exe)
                .args([
                    "--exact",
                    "--nocapture",
                    "bfd_runtime::tests::netns::session_reaches_up_and_detects_down",
                ])
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
                            sock.set_ttl(ttl).unwrap();
                            cur_ttl = ttl;
                        }
                        let _ = sock.send_to(&peer_init(actor_disc), actor).await;
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
                let ns = Netns::create();
                reexec_inner(&ns);
                return;
            }

            let peer_ip: IpAddr = PEER_ADDR.parse().unwrap();
            let config = BfdRuntimeConfig {
                sessions: vec![BfdSessionParams {
                    peer: peer_ip,
                    desired_min_tx_us: 100_000,
                    required_min_rx_us: 100_000,
                    detect_mult: 3,
                    strict: false,
                    enabled: true,
                }],
            };
            let registry = Registry::new();
            let metrics = BgpMetrics::with_registry(registry.clone());
            let (status_tx, status_rx) = watch::channel(Vec::new());
            let (event_tx, mut event_rx) = broadcast::channel(64);
            let (_desired_tx, desired_rx) = watch::channel(config);
            let (state_change_tx, mut state_change_rx) = mpsc::unbounded_channel();
            let shutdown = CancellationToken::new();
            let handle = spawn(
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

            // The actor must also deliver a lossless state change to PeerManager
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
    }
}
