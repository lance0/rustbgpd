//! Interface-only unnumbered neighbors (ADR-0142): wire Router Advertisement
//! discovery to the peer table.
//!
//! Discovery ([`crate::ra_discovery`]) owns the candidate table and the
//! binding rules. This module owns the session side:
//!
//! - Link state comes from the fast-external-failover monitor's snapshot,
//!   level-triggered: each published snapshot is evaluated as it stands now
//!   and only a changed per-interface state is passed on. An invalid
//!   snapshot is unknown and passes nothing on, so it never reads as down.
//! - A binding becomes an ordinary scoped link-local peer, resolved from the
//!   interface-only neighbor as if it had been configured with the learned
//!   address. The stored configuration is never edited.
//! - Reconciliation compares the binding with the peer table. Confirmed
//!   carrier loss or removal deletes the peer, which purges its routes. A new
//!   address replaces the peer, under the same neighbor, only while its
//!   session is not Established. A lost binding with the link up keeps an
//!   Established peer (session liveness belongs to the hold timer), and keeps
//!   a peer that is down only while the RIB retains its GR or LLGR stale
//!   routes. Once that retention ends the peer is removed, which ends its
//!   redial and releases the address it reserved.
//! - The port set follows `current_config`: a configured interface gains a
//!   port (and discovery starts when it is the first), a removed one loses
//!   its peer, RIB identity and port (and discovery stops with the last), and
//!   a neighbor whose bind-time settings changed is rebound under them. This
//!   runs on the owner loop after the mutating command, never under a staged
//!   transaction snapshot.
//! - Neighbors on different interfaces may share a learned address: the
//!   RIB keys each by its own identity. While BMP collectors are configured,
//!   admission refuses an address another neighbor holds
//!   (`bmp_identity_conflict`), because a collector cannot tell the two
//!   sessions apart; a feature keyed by the bare address refuses it too
//!   (`shared_address_feature`). The check and the insertion run in this
//!   single owner without an intervening input, so two links discovering one
//!   address cannot both be admitted.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv6Addr};

use futures::StreamExt as _;
use rustbgpd_api::peer_types::{PeerKey, PeerLifecycleError};
use rustbgpd_fsm::SessionState;
use rustbgpd_transport::{PeerCommandError, PeerHandle, StateQueryOutcome};
use tracing::{debug, error, info, warn};

use crate::config::BindTimeProjection;
use crate::ra_discovery::{
    DiscoveryConfig, DiscoveryEvent, DiscoveryEvents, Endpoint, LinkEvent, LinkState, RaDiscovery,
};

use super::PeerManager;
use super::conditional::ConditionalReplyWait;

/// Tell discovery that `key`'s session on `name` is Established. An
/// interface-only peer's key is always built from a link-local IPv6 address.
fn report_established(discovery: &RaDiscovery, name: &str, key: &PeerKey) {
    if let IpAddr::V6(address) = key.address {
        discovery.session_established(name, address);
    }
}

/// How long reconciliation waits for a bound session, or the RIB, to answer.
const BOUND_STATE_QUERY_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);
/// How soon a reconcile is retried after a bound session did not answer.
const RECONCILE_RETRY: std::time::Duration = std::time::Duration::from_secs(1);
/// How soon retained routes with no RIB timer armed are checked again.
const RETENTION_RECHECK: std::time::Duration = std::time::Duration::from_secs(30);

/// Session replies retained only while one port completes this reconcile round.
#[derive(Default)]
#[expect(
    clippy::option_option,
    reason = "outer None means unasked; an answered inner None records unavailable retention and retries without querying twice"
)]
struct PortSessionChecks {
    /// One window for all of this port's session phases, opened when its
    /// first wait starts.
    deadline_at: Option<tokio::time::Instant>,
    /// The round's inline time this window has already been extended by.
    inline_credited: std::time::Duration,
    /// The port's `observations` when this round's first query started.
    observed: Option<u64>,
    /// A retirement this round issued ended the session, or found it gone.
    /// That is terminal: no later notification about the session undoes it.
    session_ended: bool,
    state: Option<StateQueryOutcome>,
    retirement: Option<Result<bool, PeerCommandError>>,
    retention_before: Option<Option<rustbgpd_rib::PeerRetention>>,
    retention_after: Option<Option<rustbgpd_rib::PeerRetention>>,
}

enum PortSessionRequest {
    State,
    Retire { spare_handshake: bool },
    Retention { after_shutdown: bool },
    Delete { reason: &'static str },
}

struct BoundPeerRetirement {
    had_latch: bool,
    graceful_shutdown: bool,
    held: HeldState,
}

enum PortRoundCompletion {
    Check {
        name: String,
        key: PeerKey,
        id: Option<u64>,
        checks: Box<PortSessionChecks>,
    },
    Deleted {
        name: String,
        key: PeerKey,
        stopped: Option<Box<super::lifecycle::StoppedPeerDelete>>,
        retirement: BoundPeerRetirement,
    },
}

impl PortSessionChecks {
    /// The deadline for this port's next wait. What the actor has awaited
    /// inline since the port's previous wait started (`inline`, the round's
    /// running total) is no session's time: an open window is extended by
    /// it, so the next phase is not timed out unsent. A session whose wait
    /// was in flight meanwhile had that time too, so a port's phases can
    /// take up to the window plus the round's inline time.
    fn open_window(&mut self, inline: std::time::Duration) -> tokio::time::Instant {
        if let Some(deadline_at) = &mut self.deadline_at {
            *deadline_at += inline.saturating_sub(self.inline_credited);
        }
        self.inline_credited = inline;
        *self
            .deadline_at
            .get_or_insert_with(|| tokio::time::Instant::now() + BOUND_STATE_QUERY_TIMEOUT)
    }

    fn state(&self) -> Result<&StateQueryOutcome, PortSessionRequest> {
        self.state.as_ref().ok_or(PortSessionRequest::State)
    }

    async fn wait(
        mut self,
        request: PortSessionRequest,
        commands: Option<tokio::sync::mpsc::Sender<rustbgpd_transport::PeerCommand>>,
        deadline_at: tokio::time::Instant,
        rib_tx: tokio::sync::mpsc::Sender<rustbgpd_rib::RibUpdate>,
        rib_peer: rustbgpd_rib::PeerId,
    ) -> Self {
        match request {
            PortSessionRequest::State => {
                self.state = Some(
                    PeerHandle::query_state_outcome_until(
                        commands.expect("state request has a captured actor"),
                        deadline_at,
                    )
                    .await,
                );
            }
            PortSessionRequest::Retire { spare_handshake } => {
                self.retirement = Some(if spare_handshake {
                    PeerHandle::shutdown_unless_connected_until(
                        commands.expect("retirement has a captured actor"),
                        deadline_at,
                    )
                    .await
                } else {
                    PeerHandle::shutdown_unless_established_until(
                        commands.expect("retirement has a captured actor"),
                        deadline_at,
                    )
                    .await
                });
            }
            PortSessionRequest::Retention { after_shutdown } => {
                let retention = query_peer_retention_until(rib_tx, rib_peer, deadline_at).await;
                if after_shutdown {
                    self.retention_after = Some(retention);
                } else {
                    self.retention_before = Some(retention);
                }
            }
            PortSessionRequest::Delete { .. } => {
                unreachable!("deletion owns a detached peer, not a command sender")
            }
        }
        self
    }
}

pub(super) async fn query_peer_retention_until(
    rib_tx: tokio::sync::mpsc::Sender<rustbgpd_rib::RibUpdate>,
    peer: rustbgpd_rib::PeerId,
    deadline_at: tokio::time::Instant,
) -> Option<rustbgpd_rib::PeerRetention> {
    if deadline_at <= tokio::time::Instant::now() {
        return None;
    }
    let (reply, response) = tokio::sync::oneshot::channel();
    rib_tx
        .try_send(rustbgpd_rib::RibUpdate::QueryPeerRetention { peer, reply })
        .ok()?;
    tokio::time::timeout_at(deadline_at, response)
        .await
        .ok()?
        .ok()
}

/// The discovery actor, its events, and one entry per interface-only
/// neighbor, by interface name.
pub(crate) struct Unnumbered {
    discovery: RaDiscovery,
    events: Option<DiscoveryEvents>,
    ports: BTreeMap<String, Port>,
    reconcile_due: bool,
    /// A bound session did not answer its state query: reconcile again then.
    retry_at: Option<tokio::time::Instant>,
}

/// One GTSM change at the BGP listener for interface-only neighbors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ListenerGtsmRequest {
    /// Install, replace or (`None`) remove the learned-endpoint selector of
    /// the neighbor on `interface`, enforced from accept.
    Selector {
        interface: String,
        selector: Option<rustbgpd_transport::LearnedTtlSecuritySelector>,
    },
    /// Raise the IPv6 listener's outbound Hop Limit to 255; never lowered.
    RaiseOutboundV6,
}

/// Sends a [`ListenerGtsmRequest`] to the BGP listener.
pub(crate) type LearnedGtsmUpdate = std::sync::Arc<
    dyn Fn(
            ListenerGtsmRequest,
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = LearnedGtsmOutcome> + Send>>
        + Send
        + Sync,
>;

/// How the listener answered a [`LearnedGtsmUpdate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LearnedGtsmOutcome {
    Applied,
    /// Definitely not applied.
    Failed(String),
    /// Accepted, with no answer: it may have been applied.
    Unconfirmed,
}

/// The owner's view of configured interface-only neighbors: whether the port
/// set needs reconciling with `current_config`, and how Router Advertisement
/// discovery opens when the first one arrives after startup. Tests replace
/// `probe` and `spawn`.
pub(crate) struct UnnumberedRuntime {
    /// `current_config` was replaced since the port set last followed it.
    pub(crate) config_due: bool,
    /// The discovery actor could not be started, or a listener GTSM change
    /// failed: try again then.
    spawn_retry_at: Option<tokio::time::Instant>,
    /// GTSM at the BGP listener. Kept here, not on [`Unnumbered`], so
    /// discovery started by a reload or transaction has it too.
    gtsm: Option<LearnedGtsmUpdate>,
    /// The listener confirmed its IPv6 outbound Hop Limit is 255.
    gtsm_outbound_raised: bool,
    /// Interfaces whose GTSM selector the listener holds, or may: an
    /// unanswered update counts as installed until a later one is answered.
    /// Kept apart from the port, so a deleted neighbor's entry outlives it
    /// until the removal is confirmed.
    gtsm_selectors: BTreeSet<String>,
    /// Where the running interface-only set is published after each port
    /// reconcile (the host IPv6 prerequisite monitor reads it).
    running: Option<tokio::sync::watch::Sender<std::sync::Arc<Vec<crate::config::Neighbor>>>>,
    /// The `CAP_NET_RAW` check, run before a change that would need it.
    pub(crate) probe: fn() -> Result<(), String>,
    /// A reload generation passed its preflight and has not applied yet.
    generation_hold: Option<GenerationHold>,
    /// Spawn the actor.
    #[expect(
        clippy::type_complexity,
        reason = "one boxed constructor matching RaDiscovery::spawn"
    )]
    pub(crate) spawn: Box<
        dyn FnMut(
                DiscoveryConfig,
                rustbgpd_telemetry::BgpMetrics,
            ) -> Result<(RaDiscovery, DiscoveryEvents), String>
            + Send
            + Sync,
    >,
}

impl Default for UnnumberedRuntime {
    fn default() -> Self {
        Self {
            config_due: false,
            spawn_retry_at: None,
            gtsm: None,
            gtsm_outbound_raised: false,
            gtsm_selectors: BTreeSet::new(),
            running: None,
            probe: || crate::ra_discovery::probe_raw_socket().map_err(|error| error.to_string()),
            generation_hold: None,
            spawn: Box::new(|config, metrics| {
                RaDiscovery::spawn(config, metrics).map_err(|error| error.to_string())
            }),
        }
    }
}

/// The static link-local addresses of a reload candidate whose preflight
/// passed, closed to learned endpoints until its generation applies: the
/// reload route makes effects outside the peer manager between the two, so
/// the generation's own check must not fail on a binding made meanwhile.
/// The route owns the strong reference; when it returns without
/// dispatching, the hold lapses with it.
struct GenerationHold {
    route: std::sync::Weak<()>,
    addresses: Vec<(Ipv6Addr, String)>,
}

#[derive(Debug, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "link, retirement, retained-route and BFD cleanup states are independent per-port latches"
)]
struct Port {
    /// Discovery's current binding.
    desired: Option<Endpoint>,
    /// The link state last passed to discovery.
    link: Option<(u32, LinkState)>,
    /// The peer created for the binding.
    bound: Option<PeerKey>,
    /// The bound peer's session is Established.
    established: bool,
    /// Counts the session notifications that set `established`. A round's
    /// cached session answers are older than any notification handled after
    /// its first query started, and are dropped when this has moved.
    observations: u64,
    /// The address last refused, so the refusal is logged once.
    refused: Option<Ipv6Addr>,
    /// Why the current binding is refused (`<reason>: <detail>`), reported
    /// as the unbound neighbor's last error.
    refusal: Option<String>,
    /// Operator and safety state carried from a retired endpoint to the next.
    held: Option<HeldState>,
    /// An operator's RFC 8326 graceful-shutdown advertisement for the next
    /// peer while unbound, replayed on it as a static neighbor's reconfigure
    /// does. Written by a retired endpoint or an all-peers toggle, so a
    /// neighbor that never bound takes the toggle too; taken by the bind.
    graceful_shutdown: bool,
    /// A BFD removal changed local membership but its actor acknowledgement
    /// is still uncertain. The port owns retries until the current set is confirmed.
    bfd_removal_unsettled: bool,
    /// The neighbor's RIB identity, allocated at its first binding and kept
    /// across every later endpoint: an address change is a session down and
    /// up under the same `PeerId`. Released when configuration deletes the
    /// neighbor.
    rib_peer: Option<rustbgpd_rib::PeerId>,
    /// The bind-time settings the bound peer was created with; a change
    /// rebinds it.
    settings: Option<BindTimeProjection>,
    /// A successfully stopped peer keeps its address while the RIB retains
    /// its routes. A reconnect clears this mark after its state is read.
    stopped_retained: bool,
    /// The address the neighbor was last bound to, so a binding to another
    /// one counts as an address change.
    last_address: Option<Ipv6Addr>,
    /// Why the neighbor's endpoint is being removed or added, for the
    /// presence event of the change in progress.
    presence_reason: Option<&'static str>,
}

/// State of an interface-only neighbor that belongs to the neighbor, not to
/// one learned endpoint: operator state, max-prefix shutdown and lifetime
/// counters survive carrier loss, interface recreation and address changes.
#[derive(Debug)]
struct HeldState {
    enabled: bool,
    /// The configured `admin_down` the retired peer ran under. A rebind
    /// keeps the operator's toggle only while this is unchanged, as
    /// `lifecycle::config_admin_enable` does for a static neighbor.
    config_admin_down: bool,
    max_prefix_restart_seconds: Option<u32>,
    latch: Option<super::MaxPrefixLatch>,
    counters: rustbgpd_transport::NeighborCounters,
}

impl Unnumbered {
    /// Set the graceful-shutdown intent every unbound neighbor, bound
    /// before or not, holds for its next peer. A port kept only for a
    /// deleted neighbor's cleanup is skipped, so a neighbor re-added there
    /// does not inherit a toggle that ran while it was not configured.
    pub(super) fn set_held_graceful_shutdown(
        &mut self,
        enabled: bool,
        configured: impl Fn(&str) -> bool,
    ) {
        for (_, port) in self
            .ports
            .iter_mut()
            .filter(|(name, port)| port.bound.is_none() && configured(name))
        {
            port.graceful_shutdown = enabled;
        }
    }

    /// Take ownership of a spawned discovery actor.
    pub(crate) fn new(discovery: RaDiscovery, events: DiscoveryEvents) -> Self {
        Self {
            discovery,
            events: Some(events),
            ports: BTreeMap::new(),
            reconcile_due: false,
            retry_at: None,
        }
    }

    pub(super) async fn shutdown(self) {
        self.discovery.shutdown().await;
    }
}

impl PeerManager {
    /// Enforce interface-only neighbors' `ttl_security` at `listener`, for
    /// neighbors configured at startup and those a reload or transaction adds.
    #[must_use]
    pub(crate) fn with_listener_gtsm(
        self,
        listener: Option<rustbgpd_transport::TcpAoListenerHandle>,
    ) -> Self {
        let Some(listener) = listener else {
            return self;
        };
        self.with_gtsm_update(std::sync::Arc::new(move |request| {
            let listener = listener.clone();
            Box::pin(async move {
                use rustbgpd_transport::listener::ReloadDispatch;
                let dispatch = match request {
                    ListenerGtsmRequest::Selector {
                        interface,
                        selector,
                    } => listener.set_learned_ttl_security(interface, selector).await,
                    ListenerGtsmRequest::RaiseOutboundV6 => listener.raise_gtsm_outbound_v6().await,
                };
                match dispatch {
                    ReloadDispatch::Replied(Ok(())) => LearnedGtsmOutcome::Applied,
                    ReloadDispatch::Replied(Err(error)) | ReloadDispatch::NotAccepted(error) => {
                        LearnedGtsmOutcome::Failed(error.to_string())
                    }
                    ReloadDispatch::AcknowledgementLost => LearnedGtsmOutcome::Unconfirmed,
                }
            })
        }))
    }

    #[must_use]
    pub(crate) fn with_gtsm_update(mut self, update: LearnedGtsmUpdate) -> Self {
        self.unnumbered_runtime.gtsm = Some(update);
        self
    }

    /// Publish the running interface-only set to `running` after every
    /// port reconcile.
    #[must_use]
    pub(crate) fn with_running_interface_only(
        mut self,
        running: tokio::sync::watch::Sender<std::sync::Arc<Vec<crate::config::Neighbor>>>,
    ) -> Self {
        self.unnumbered_runtime.running = Some(running);
        self
    }

    /// Start discovery on every interface-only neighbor's interface and feed
    /// it the current link snapshot.
    #[must_use]
    pub(crate) fn with_unnumbered(mut self, mut unnumbered: Unnumbered) -> Self {
        for neighbor in self.current_config.neighbors.interface_only() {
            if let Some(interface) = neighbor.interface.clone() {
                unnumbered.discovery.start(&interface);
                unnumbered.ports.insert(interface, Port::default());
            }
        }
        self.unnumbered = Some(Box::new(unnumbered));
        self.feed_unnumbered_links();
        self
    }

    /// Next discovery event; pending forever without discovery, and once its
    /// actor has exited.
    pub(super) async fn receive_discovery_event(
        unnumbered: &mut Option<Box<Unnumbered>>,
    ) -> Option<DiscoveryEvent> {
        let Some(events) = unnumbered.as_mut().and_then(|u| u.events.as_mut()) else {
            return std::future::pending().await;
        };
        let event = events.recv().await;
        if event.is_none() {
            error!("interface-only neighbor discovery stopped; no new binding will be learned");
            if let Some(unnumbered) = unnumbered.as_mut() {
                unnumbered.events = None;
            }
        }
        event
    }

    pub(super) fn unnumbered_reconcile_due(&self) -> bool {
        self.unnumbered_runtime.config_due
            || self.unnumbered.as_ref().is_some_and(|u| u.reconcile_due)
    }

    /// Pass each interface's state in the current link snapshot to discovery
    /// when it differs from what discovery last saw. Level-triggered, and an
    /// invalid snapshot passes nothing: unknown is never down.
    pub(super) fn feed_unnumbered_links(&mut self) {
        let Some(unnumbered) = self.unnumbered.as_mut() else {
            return;
        };
        let Some(state) = self.link_check.state.as_ref() else {
            return;
        };
        let snapshot = std::sync::Arc::clone(&state.borrow());
        if !snapshot.valid {
            return;
        }
        for (name, port) in &mut unnumbered.ports {
            let current = match snapshot.ifindex_of(name) {
                Some(ifindex) => {
                    let link = &snapshot.links[&ifindex];
                    let up = link.admin_up && link.lower_up;
                    (ifindex, if up { LinkState::Up } else { LinkState::Down })
                }
                // Never seen: the interface is missing, there is nothing to clear.
                None => match port.link {
                    Some((ifindex, _)) => (ifindex, LinkState::Removed),
                    None => continue,
                },
            };
            if port.link == Some(current) {
                continue;
            }
            let previous = port.link.replace(current);
            debug!(interface = %name, ifindex = current.0, state = ?current.1, "unnumbered: link state");
            unnumbered.discovery.link_event(LinkEvent {
                ifindex: current.0,
                name: name.clone(),
                state: current.1,
            });
            // Down, removal, or an Up on a new index (a recreation the
            // monitor reported without a Down in between).
            if current.1 != LinkState::Up
                || previous.is_some_and(|(ifindex, _)| ifindex != current.0)
            {
                unnumbered.reconcile_due = true;
            }
        }
    }

    pub(super) fn handle_discovery_event(&mut self, event: DiscoveryEvent) {
        let Some(unnumbered) = self.unnumbered.as_mut() else {
            return;
        };
        match event {
            DiscoveryEvent::BindingChanged {
                interface,
                previous,
                current,
            } => {
                info!(%interface, ?previous, ?current, "unnumbered: binding changed");
                if let Some(port) = unnumbered.ports.get_mut(&interface) {
                    // A second router beside an Established peer is counted
                    // from discovery's `Conflict`, even when that peer was
                    // learned from an inbound connection: its address goes
                    // to discovery with `session_established`.
                    port.desired = current;
                    unnumbered.reconcile_due = true;
                }
            }
            // Logged by the discovery actor, which never queues them.
            DiscoveryEvent::CandidateLearned { .. } | DiscoveryEvent::CandidateExpired { .. } => {}
            DiscoveryEvent::Conflict {
                interface,
                bound,
                other,
                count,
            } => {
                // Queued before the neighbor was deleted: counting it would
                // recreate the series its removal reaped.
                if !unnumbered.ports.contains_key(&interface) {
                    debug!(%interface, "unnumbered: conflict for a removed neighbor, ignored");
                    return;
                }
                // One record stands for `count` conflicts: logged once and
                // counted in one increment, however large its backlog.
                warn!(
                    %interface, %bound, %other, conflicts = count,
                    reason = "multiple_routers_on_link",
                    "unnumbered: a second router advertises on an interface-only link"
                );
                self.metrics.record_unnumbered_ra_conflicts(
                    &rustbgpd_telemetry::interface_peer_label(&interface),
                    count,
                );
            }
        }
    }

    /// Session state for a bound interface-only peer: Established freezes the
    /// binding in discovery, and leaving Established releases it.
    pub(super) fn note_unnumbered_session_state(
        &mut self,
        peer: &PeerKey,
        old: SessionState,
        new: SessionState,
    ) {
        let Some(unnumbered) = self.unnumbered.as_mut() else {
            return;
        };
        let Some((name, port)) = unnumbered
            .ports
            .iter_mut()
            .find(|(_, port)| port.bound.as_ref() == Some(peer))
        else {
            return;
        };
        if new == SessionState::Established {
            port.established = true;
            port.observations += 1;
            report_established(&unnumbered.discovery, name, peer);
        } else if old == SessionState::Established {
            port.established = false;
            port.observations += 1;
            unnumbered.discovery.session_failed(name);
            unnumbered.reconcile_due = true;
        }
    }

    /// The bound peer's primary session fell back to Idle. This arrives on
    /// the lossless session-notification channel, so discovery is released
    /// even when the lossy `StateChanged` transition was dropped.
    pub(super) fn note_unnumbered_session_idle(&mut self, peer: &PeerKey) {
        let Some(unnumbered) = self.unnumbered.as_mut() else {
            return;
        };
        let Some((name, port)) = unnumbered
            .ports
            .iter_mut()
            .find(|(_, port)| port.bound.as_ref() == Some(peer))
        else {
            return;
        };
        port.established = false;
        port.observations += 1;
        unnumbered.discovery.session_failed(name);
        unnumbered.reconcile_due = true;
    }

    /// A binding resolves its peer from `current_config`, which is
    /// provisional while a transaction snapshot is staged: a rollback would
    /// not undo the bound peer's installed policies. Defer it; the commit or
    /// rollback that clears the stage wakes the loop, which reconciles again.
    fn defer_unnumbered_while_staged(&mut self) -> bool {
        if !self.config_snapshot_staged {
            return false;
        }
        if let Some(unnumbered) = self.unnumbered.as_mut() {
            unnumbered.reconcile_due = true;
        }
        true
    }

    /// Shut the bound session down unless it is Established, atomically in
    /// the session. `true` once it can no longer establish (or is already
    /// gone). An Established session is kept and reported to discovery. An
    /// unanswered command withdraws its ticket, keeps the binding and retries.
    /// `spare_handshake` also keeps an `OpenSent` or `OpenConfirm` session,
    /// decided in the same session turn; its outcome reports itself.
    async fn shut_down_unless_established(
        &mut self,
        name: &str,
        key: &PeerKey,
        spare_handshake: bool,
    ) -> bool {
        let Some(managed) = self.peers.get(key) else {
            return true;
        };
        // A pending inbound connection from the bound address is that router,
        // live. The retirement's notification drains would promote it once
        // the primary is gone, and it could establish before the deletion.
        // Only the accept path creates candidates, and it cannot run during
        // this retirement, so checking here fences promotion for its length.
        if managed.pending_inbound.is_some() {
            info!(interface = %name, peer = %key, "unnumbered: a connection from the bound address is pending; keeping it");
            self.arm_unnumbered_retry();
            return false;
        }
        let commands = managed.handle().commands_sender();
        let deadline_at = tokio::time::Instant::now() + BOUND_STATE_QUERY_TIMEOUT;
        let operation = async move {
            if spare_handshake {
                PeerHandle::shutdown_unless_connected_until(commands, deadline_at).await
            } else {
                PeerHandle::shutdown_unless_established_until(commands, deadline_at).await
            }
        };
        let outcome = self.await_session_sweep(operation).await;
        self.apply_unnumbered_retirement(name, key, spare_handshake, outcome)
    }

    fn apply_unnumbered_retirement(
        &mut self,
        name: &str,
        key: &PeerKey,
        spare_handshake: bool,
        outcome: Result<bool, PeerCommandError>,
    ) -> bool {
        match outcome {
            Ok(true)
            | Err(
                rustbgpd_transport::PeerCommandError::SessionExited
                | rustbgpd_transport::PeerCommandError::ReplyDropped,
            ) => true,
            Ok(false) if spare_handshake => {
                info!(interface = %name, peer = %key, "unnumbered: bound session is connected; keeping it");
                // A handshake that fails in OpenSent falls back to Active,
                // which reports nothing: check it again.
                self.arm_unnumbered_retry();
                false
            }
            Ok(false) => {
                info!(interface = %name, peer = %key, "unnumbered: bound session became Established; keeping it");
                if let Some(unnumbered) = self.unnumbered.as_mut() {
                    report_established(&unnumbered.discovery, name, key);
                }
                self.port_mut(name).established = true;
                false
            }
            Err(rustbgpd_transport::PeerCommandError::CommandFailed(reason)) => {
                // The session answered: it would retire, but holds messages
                // for a full RIB mailbox and stays owned until they are
                // admitted. Nothing is wrong with it; ask again.
                debug!(interface = %name, peer = %key, %reason, "unnumbered: bound session is waiting on the RIB mailbox; retrying its retirement");
                self.arm_unnumbered_retry();
                false
            }
            Err(error) => {
                warn!(interface = %name, peer = %key, %error, "unnumbered: bound session did not answer the retirement check; retrying");
                self.arm_unnumbered_retry();
                false
            }
        }
    }

    fn checked_unnumbered_retirement(
        &mut self,
        name: &str,
        key: &PeerKey,
        spare_handshake: bool,
        checks: &mut PortSessionChecks,
    ) -> Result<bool, PortSessionRequest> {
        let Some(managed) = self.peers.get(key) else {
            return Ok(true);
        };
        if managed.pending_inbound.is_some() {
            self.arm_unnumbered_retry();
            return Ok(false);
        }
        let outcome = checks
            .retirement
            .take()
            .ok_or(PortSessionRequest::Retire { spare_handshake })?;
        Ok(self.apply_unnumbered_retirement(name, key, spare_handshake, outcome))
    }

    /// When an unanswered state query is due to be asked again.
    pub(super) fn unnumbered_retry_at(&self) -> Option<tokio::time::Instant> {
        let actor = self
            .unnumbered
            .as_ref()
            .and_then(|unnumbered| unnumbered.retry_at);
        [actor, self.unnumbered_runtime.spawn_retry_at]
            .into_iter()
            .flatten()
            .min()
    }

    /// Reconcile again after [`RECONCILE_RETRY`]; an earlier armed deadline
    /// is kept, which bounds the retry rate.
    fn arm_unnumbered_retry(&mut self) {
        self.arm_unnumbered_retry_at(tokio::time::Instant::now() + RECONCILE_RETRY);
    }

    /// Reconcile again by `at`, or at the earlier deadline already armed.
    fn arm_unnumbered_retry_at(&mut self, at: tokio::time::Instant) {
        if let Some(unnumbered) = self.unnumbered.as_mut() {
            unnumbered.retry_at = Some(unnumbered.retry_at.map_or(at, |armed| armed.min(at)));
        }
    }

    /// The retry deadline passed: reconcile again.
    pub(super) fn unnumbered_retry_due(&mut self) {
        self.unnumbered_runtime.config_due = true;
        self.unnumbered_runtime.spawn_retry_at = None;
        if let Some(unnumbered) = self.unnumbered.as_mut() {
            unnumbered.retry_at = None;
            unnumbered.reconcile_due = true;
        }
    }

    /// A peer left the table, or the configuration changed what may share
    /// an address: a refused binding may now be admissible, and nothing else
    /// re-raises it (refreshed RAs emit no binding change).
    pub(super) fn recheck_refused_bindings(&mut self) {
        if let Some(unnumbered) = self.unnumbered.as_mut()
            && unnumbered.ports.values().any(|port| port.refused.is_some())
        {
            unnumbered.reconcile_due = true;
        }
    }

    /// Every live binding's learned address and interface.
    pub(super) fn unnumbered_binding_endpoints(&self) -> Vec<(IpAddr, String)> {
        self.unnumbered
            .iter()
            .flat_map(|unnumbered| unnumbered.ports.iter())
            .filter_map(|(name, port)| Some((port.bound.as_ref()?.address, name.clone())))
            .collect()
    }

    /// Whether `peer` is an interface-only neighbor's stopped peer, whose
    /// session task has exited while its address waits on retention.
    pub(super) fn unnumbered_stopped(&self, peer: &PeerKey) -> bool {
        self.unnumbered.as_ref().is_some_and(|unnumbered| {
            unnumbered
                .ports
                .values()
                .any(|port| port.stopped_retained && port.bound.as_ref() == Some(peer))
        })
    }

    /// Every live binding: its interface, learned address and the index its
    /// peer is scoped to.
    pub(super) fn unnumbered_bindings(&self) -> Vec<(String, Ipv6Addr, u32)> {
        self.unnumbered
            .iter()
            .flat_map(|unnumbered| unnumbered.ports.iter())
            .filter_map(|(name, port)| {
                let key = port.bound.as_ref()?;
                let IpAddr::V6(address) = key.address else {
                    return None;
                };
                let ifindex = self.peers.get(key)?.transport_config.peer_scope_id?;
                Some((name.clone(), address, ifindex))
            })
            .collect()
    }

    /// The addresses interface-only neighbors are bound to now.
    pub(super) fn unnumbered_bound_addresses(&self) -> std::collections::HashSet<IpAddr> {
        self.unnumbered
            .iter()
            .flat_map(|unnumbered| unnumbered.ports.values())
            .filter_map(|port| port.bound.as_ref().map(|key| key.address))
            .collect()
    }

    /// The interface whose interface-only neighbor owns `peer`.
    /// Whether an interface-only neighbor keeps `peer` as its RIB identity.
    pub(super) fn unnumbered_holds(&self, peer: rustbgpd_rib::PeerId) -> bool {
        self.unnumbered.as_ref().is_some_and(|unnumbered| {
            unnumbered
                .ports
                .values()
                .any(|port| port.rib_peer == Some(peer))
        })
    }

    /// The peer bound for the interface-only neighbor on `interface`.
    pub(super) fn unnumbered_bound_peer(&self, interface: &str) -> Option<PeerKey> {
        self.unnumbered
            .as_ref()?
            .ports
            .get(interface)?
            .bound
            .clone()
    }

    /// One row per interface-only neighbor with no bound peer, for neighbor
    /// listings: its configured settings and where discovery stands. A bound
    /// neighbor is listed through its peer.
    pub(super) fn unbound_interface_only_infos(&self) -> Vec<rustbgpd_api::peer_types::PeerInfo> {
        use rustbgpd_api::peer_types::{InterfaceOnlyState, NeighborDiscoveryState};
        let Some(unnumbered) = self.unnumbered.as_ref() else {
            return Vec::new();
        };
        let ebgp_requires_policy = self.current_config.rfc8212_posture().policy_effective;
        unnumbered
            .ports
            .iter()
            .filter(|(_, port)| port.bound.is_none())
            .filter_map(|(name, port)| {
                let neighbor = self.current_config.neighbors.interface_only_on(name)?;
                let resolved = self
                    .current_config
                    .resolve_unbound_interface_neighbor(neighbor)
                    .ok()?;
                let policy_present = self
                    .current_config
                    .explicit_policy_presence(neighbor)
                    .ok()?;
                let discovery = match port.link {
                    None | Some((_, LinkState::Removed)) => {
                        NeighborDiscoveryState::InterfaceMissing
                    }
                    Some((_, LinkState::Down)) => NeighborDiscoveryState::LinkDown,
                    Some((_, LinkState::Up | LinkState::Unknown)) => {
                        NeighborDiscoveryState::AwaitingDiscovery
                    }
                };
                let enabled = resolved.admin_down.is_none()
                    && port.held.as_ref().is_none_or(|held| held.enabled);
                let mut info = super::snapshot::unbound_interface_only_info(
                    name,
                    &resolved,
                    policy_present,
                    enabled,
                    ebgp_requires_policy,
                    InterfaceOnlyState {
                        discovery,
                        learned_address: None,
                    },
                );
                // A refused binding is where discovery stands: an address
                // was learned and admission turned it away.
                if discovery == NeighborDiscoveryState::AwaitingDiscovery
                    && let Some(refusal) = &port.refusal
                {
                    refusal.clone_into(&mut info.last_error);
                }
                info.remote_asn_mode = match neighbor.remote_asn {
                    crate::config::RemoteAsn::External => {
                        rustbgpd_api::peer_types::RemoteAsnMode::External
                    }
                    crate::config::RemoteAsn::Internal => {
                        rustbgpd_api::peer_types::RemoteAsnMode::Internal
                    }
                    crate::config::RemoteAsn::Asn(_) => {
                        rustbgpd_api::peer_types::RemoteAsnMode::Numeric
                    }
                };
                // A max-prefix shutdown held across the endpoint is still
                // the neighbor's state: its reason and restart countdown.
                if let Some(held) = &port.held {
                    let totals = &held.counters;
                    info.updates_received = totals.updates_received();
                    info.updates_sent = totals.updates_sent();
                    info.notifications_received = totals.notifications_received();
                    info.notifications_sent = totals.notifications_sent();
                    info.otc_routes_blocked = totals.otc_routes_blocked();
                    info.import_policy_routes_permitted = totals.import_policy_routes_permitted();
                    info.import_policy_routes_denied = totals.import_policy_routes_denied();
                    let export = totals.export_policy().snapshot();
                    info.export_policy_routes_permitted = export.export_policy_routes_permitted;
                    info.export_policy_routes_denied = export.export_policy_routes_denied;
                    info.flap_count = totals.flaps();
                    (info.messages_received, info.messages_sent) = self
                        .metrics
                        .peer_message_totals(&rustbgpd_telemetry::interface_peer_label(name));
                    if let Some(latch) = &held.latch {
                        super::snapshot::apply_max_prefix_latch(
                            &mut info,
                            &latch.error,
                            latch.deadline,
                        );
                    }
                }
                Some(info)
            })
            .collect()
    }

    pub(super) fn unnumbered_owner_of(&self, peer: &PeerKey) -> Option<&str> {
        self.unnumbered
            .as_ref()?
            .ports
            .iter()
            .find_map(|(name, port)| (port.bound.as_ref() == Some(peer)).then_some(name.as_str()))
    }

    /// While a BMP collector refuses identity conflicts, any neighbor
    /// already holding `address`: a peer in the table (bound interface-only,
    /// static, or retained) or a configured static neighbor. Without BMP,
    /// neighbors on different interfaces may share an address; when every
    /// collector excludes, admission excludes the newcomer from BMP instead.
    fn bmp_identity_holder(&self, address: Ipv6Addr) -> Option<String> {
        if self.bmp_identity_conflict() != Some(crate::config::BmpIdentityConflict::Refuse) {
            return None;
        }
        let address = IpAddr::V6(address);
        self.peers
            .keys()
            .find(|key| key.address == address)
            .map(PeerKey::label)
            .or_else(|| {
                self.current_config
                    .neighbors
                    .iter()
                    .find(|neighbor| neighbor.address.parse() == Ok(address))
                    .map(crate::config::Neighbor::label)
            })
    }

    /// The pending generation's static neighbor holding `address`, while the
    /// reload route that obtained the hold is still running.
    fn generation_held(&self, address: Ipv6Addr) -> Option<&str> {
        let hold = self.unnumbered_runtime.generation_hold.as_ref()?;
        if hold.route.strong_count() == 0 {
            return None;
        }
        hold.addresses
            .iter()
            .find_map(|(held, label)| (*held == address).then_some(label.as_str()))
    }

    /// The reload route's preflight, before its first effect outside the
    /// peer manager. On acceptance the candidate's static link-local
    /// addresses are held closed to learned endpoints until the generation
    /// applies or `route` is dropped, so the generation's own preflight
    /// cannot then fail on a binding made in between.
    pub(super) fn preflight_reload_generation(
        &mut self,
        candidate: &crate::config::Config,
        route: std::sync::Weak<()>,
    ) -> Result<(), String> {
        self.unnumbered_preflight(candidate)?;
        let addresses = candidate
            .neighbors
            .iter()
            .filter_map(|neighbor| match neighbor.address.parse() {
                Ok(IpAddr::V6(address)) if address.is_unicast_link_local() => {
                    Some((address, neighbor.label()))
                }
                _ => None,
            })
            .collect();
        self.unnumbered_runtime.generation_hold = Some(GenerationHold { route, addresses });
        Ok(())
    }

    /// The neighbor RPC's add of an interface-only neighbor: checked, then
    /// installed in `current_config` in this owner turn. The port reconcile
    /// on the next loop pass starts discovery, as for a reload. A refusal,
    /// including the [`Self::unnumbered_preflight`] one, changes nothing.
    pub(super) fn add_interface_only_neighbor(
        &mut self,
        spec: Box<rustbgpd_api::peer_types::PresenceAwareNeighborCreate>,
    ) -> Result<(), PeerLifecycleError> {
        let Some(interface) = spec.interface.clone() else {
            return Err(PeerLifecycleError::Invalid(
                "an interface-only neighbor needs an interface".to_string(),
            ));
        };
        if self
            .current_config
            .neighbors
            .interface_only_on(&interface)
            .is_some()
        {
            return Err(PeerLifecycleError::InterfaceOnlyExists(interface));
        }
        let mut next = self.current_config.clone();
        crate::policy_admin::apply_config_event(
            &mut next,
            &rustbgpd_api::peer_types::ConfigEvent::PresenceAwareNeighborAdded { spec, ack: None },
        )
        .map_err(|error| PeerLifecycleError::Invalid(error.to_string()))?;
        let neighbor = next
            .neighbors
            .interface_only_on(&interface)
            .ok_or_else(|| {
                PeerLifecycleError::internal(format!(
                    "interface-only neighbor on {interface} missing after the config update"
                ))
            })?;
        let resolved = next
            .resolve_unbound_interface_neighbor(neighbor)
            .map_err(|error| PeerLifecycleError::Invalid(error.to_string()))?;
        // As for a static RPC add: the listener takes these only at startup
        // or SIGHUP, and the clamp only at startup.
        let transport = &resolved.transport_config;
        if transport.md5_password.is_some()
            || transport.ttl_security_hops.is_some()
            || transport.tcp_mss.is_some()
        {
            return Err(PeerLifecycleError::RestartRequired(format!(
                "the interface-only neighbor on {interface} resolves md5_password, \
                 ttl_security, or tcp_mss; runtime peer CRUD cannot change inbound listener \
                 enforcement — use the config file and SIGHUP for md5_password/ttl_security, \
                 or restart for tcp_mss"
            )));
        }
        self.unnumbered_preflight(&next)
            .map_err(PeerLifecycleError::Precondition)?;
        self.replace_current_config(next);
        Ok(())
    }

    /// The neighbor RPC's delete of the interface-only neighbor on
    /// `interface`, bound or not: removed from `current_config` in this owner
    /// turn. The port reconcile then ends its session, purges its routes and
    /// releases its RIB identity and learned address, as for a reload.
    pub(super) fn delete_interface_only_neighbor(
        &mut self,
        interface: &str,
    ) -> Result<(), PeerLifecycleError> {
        if self
            .current_config
            .neighbors
            .interface_only_on(interface)
            .is_none()
        {
            return Err(PeerLifecycleError::InterfaceOnlyNotFound(
                interface.to_owned(),
            ));
        }
        let mut next = self.current_config.clone();
        next.neighbors.set_interface_only(interface, None);
        self.replace_current_config(next);
        Ok(())
    }

    /// A runtime catalog edit to `next` moves some interface-only neighbors'
    /// policy chains without changing their bind-time settings (a member
    /// that overrides the edited session knob): no rebind will give the
    /// bound peer its new chains, so they apply live here. Returns the
    /// captured priors for [`Self::restore_interface_only_policies`]. The
    /// failure keeps its settlement classification: a failed apply whose own
    /// restore also failed is ambiguous, not compensated.
    pub(super) async fn apply_interface_only_policy_deltas(
        &mut self,
        next: &crate::config::Config,
    ) -> Result<
        Vec<rustbgpd_api::peer_types::ResolvedPeerPolicy>,
        super::policy::PolicySnapshotFailure,
    > {
        let targets: Vec<_> = next
            .neighbors
            .interface_only()
            .iter()
            .filter_map(|neighbor| {
                let interface = neighbor.interface.as_deref()?;
                let prior = self.current_config.neighbors.interface_only_on(interface)?;
                let bound = self.unnumbered_bound_peer(interface)?;
                let chains = next.interface_only_policy_chains(neighbor)?;
                (self.current_config.interface_only_policy_chains(prior)? != chains
                    && self.current_config.bind_time_settings(prior)
                        == next.bind_time_settings(neighbor))
                .then(|| rustbgpd_api::peer_types::ResolvedPeerPolicy {
                    address: bound.address,
                    interface: Some(interface.to_owned()),
                    import_policy: chains.0,
                    export_policy: chains.1,
                })
            })
            .collect();
        if targets.is_empty() {
            return Ok(Vec::new());
        }
        self.apply_resolved_policy_snapshot_with_prestage_reads(
            targets,
            true,
            super::OperatorReadAdmission::Served,
        )
        .await
    }

    /// Put back the chains [`Self::apply_interface_only_policy_deltas`]
    /// replaced; `false` when that failed and runtime state is uncertain.
    pub(super) async fn restore_interface_only_policies(
        &mut self,
        priors: Vec<rustbgpd_api::peer_types::ResolvedPeerPolicy>,
    ) -> bool {
        if priors.is_empty() {
            return true;
        }
        let Err(error) = self
            .apply_resolved_policy_snapshot_with_prestage_reads(
                priors,
                true,
                super::OperatorReadAdmission::Served,
            )
            .await
        else {
            return true;
        };
        warn!(
            error = %error.message,
            "interface-only policy chains could not be restored after the peer-group change failed"
        );
        false
    }

    /// The held generation applied or was refused: admission sees only the
    /// peer table and `current_config` again, and a binding the hold refused
    /// is reconsidered.
    pub(super) fn release_generation_hold(&mut self) {
        if self.unnumbered_runtime.generation_hold.take().is_some() {
            self.recheck_refused_bindings();
        }
    }

    /// Check a candidate configuration before it takes effect anywhere:
    /// the first interface-only neighbor needs the link monitor and
    /// `CAP_NET_RAW` (ADR-0142 "Privilege"), a static link-local neighbor
    /// must not take the key of a learned endpoint, bound or reserved, and
    /// neighbors that would share a link-local address must be able to
    /// ("Same-address neighbors"). The error names the cause.
    pub(super) fn unnumbered_preflight(
        &self,
        candidate: &crate::config::Config,
    ) -> Result<(), String> {
        for neighbor in &candidate.neighbors {
            let Ok(IpAddr::V6(address)) = neighbor.address.parse::<IpAddr>() else {
                continue;
            };
            let key = PeerKey::new(IpAddr::V6(address), neighbor.interface.clone());
            // A static neighbor replacing an interface-only stanza at its
            // learned address on the same interface would meet the
            // still-bound peer, whose key it shares, after the effects.
            if let Some(holder) = self.unnumbered_owner_of(&key) {
                return Err(format!(
                    "duplicate_link_local_address: neighbor {key} is the endpoint the \
                     interface-only neighbor on {holder} holds; remove that neighbor first"
                ));
            }
        }
        self.validate_live_shared_addresses(candidate)?;
        if self.current_config.neighbors.interface_only().is_empty()
            && !candidate.neighbors.interface_only().is_empty()
        {
            if self.link_check.state.is_none() {
                return Err(
                    "interface-only neighbors need the netlink link monitor, which is not running"
                        .to_string(),
                );
            }
            (self.unnumbered_runtime.probe)()?;
        }
        Ok(())
    }

    /// Bring the port set in line with the configured interface-only
    /// neighbors, then every neighbor's peer in line with its binding.
    #[expect(
        clippy::too_many_lines,
        reason = "one finite pump retains identity checks and continuation ordering across owned session phases"
    )]
    pub(super) async fn reconcile_unnumbered(&mut self) {
        // Keep the finite continuation pump off every caller future's stack.
        Box::pin(async {
        if self.unnumbered_runtime.config_due && !self.config_snapshot_staged {
            self.unnumbered_runtime.config_due = false;
            self.sync_unnumbered_ports().await;
        }
        let Some(unnumbered) = self.unnumbered.as_mut() else {
            return;
        };
        unnumbered.reconcile_due = false;
        let names: Vec<String> = unnumbered.ports.keys().cloned().collect();
        let mut ready: std::collections::VecDeque<_> = names
            .into_iter()
            .map(|name| (name, PortSessionChecks::default()))
            .collect();
        let mut pending = futures::stream::FuturesUnordered::<
            futures::future::BoxFuture<'static, PortRoundCompletion>,
        >::new();
        let mut completed = std::collections::VecDeque::new();
        // Time the actor spent awaiting inline in this round: preparing or
        // settling one port while other ports' windows are open.
        let mut inline = std::time::Duration::ZERO;
        loop {
            while let Some((name, mut checks)) = ready.pop_front() {
                checks.session_ended |= matches!(
                    checks.retirement,
                    Some(
                        Ok(true)
                            | Err(PeerCommandError::SessionExited
                                | PeerCommandError::ReplyDropped)
                    )
                );
                // A notification about this port's session was handled (by
                // another port's preparation or settlement drain) after the
                // answers were asked for: it is newer than they are.
                if checks
                    .observed
                    .is_some_and(|observed| observed != self.port_mut(&name).observations)
                {
                    if checks.session_ended {
                        // Reads can be outdated; the end of the session is
                        // not. Dropping it would leave an exited handle
                        // bound, so the round goes on to remove the peer.
                        self.port_mut(&name).established = false;
                    } else {
                        debug!(interface = %name, "unnumbered: session state changed during the round; dropping its cached answers and retrying");
                        self.arm_unnumbered_retry();
                        continue;
                    }
                }
                let from = tokio::time::Instant::now();
                let reconciled = self.reconcile_port(&name, &mut checks).await;
                inline += from.elapsed();
                if let Err(request) = reconciled {
                    let Some(key) = self.port_mut(&name).bound.clone() else {
                        continue;
                    };
                    if let PortSessionRequest::Delete { reason } = request {
                        let from = tokio::time::Instant::now();
                        let prepared = self
                            .prepare_bound_peer_retirement(&name, &key, reason)
                            .await;
                        inline += from.elapsed();
                        let deadline_at = checks.open_window(inline);
                        match prepared {
                            Ok((detached, retirement)) => {
                                super::notifications::start_round_wait(
                                    async move {
                                        let stopped = match detached {
                                            Some(detached) => Some(Box::new(
                                                detached.stop_until(deadline_at).await,
                                            )),
                                            None => None,
                                        };
                                        PortRoundCompletion::Deleted {
                                            name,
                                            key,
                                            stopped,
                                            retirement,
                                        }
                                    },
                                    &mut pending,
                                    &mut completed,
                                );
                            }
                            Err(error) => {
                                self.port_mut(&name).presence_reason = None;
                                warn!(interface = %name, peer = %key, %error, "unnumbered: could not remove the bound peer");
                                self.arm_unnumbered_retry();
                            }
                        }
                        continue;
                    }
                    let deadline_at = checks.open_window(inline);
                    let observations = self.port_mut(&name).observations;
                    checks.observed.get_or_insert(observations);
                    let managed = self.peers.get(&key);
                    let id = managed.map(super::ManagedPeer::session_id);
                    let commands = managed.map(|managed| managed.handle().commands_sender());
                    let rib_tx = self.rib_tx.clone();
                    let rib_peer = self.rib_peer_of(&key);
                    super::notifications::start_round_wait(
                        async move {
                            let checks = checks
                                .wait(request, commands, deadline_at, rib_tx, rib_peer)
                                .await;
                            PortRoundCompletion::Check {
                                name,
                                key,
                                id,
                                checks: Box::new(checks),
                            }
                        },
                        &mut pending,
                        &mut completed,
                    );
                }
            }
            let completion = if let Some(completion) = completed.pop_front() {
                completion
            } else if let Some(completion) = self.await_session_sweep(pending.next()).await {
                completion
            } else {
                break;
            };
            match completion {
                PortRoundCompletion::Check {
                    name,
                    key,
                    id,
                    checks,
                } => {
                    if self
                        .unnumbered
                        .as_ref()
                        .and_then(|u| u.ports.get(&name))
                        .is_some_and(|port| port.bound.as_ref() == Some(&key))
                        && self.peers.get(&key).map(super::ManagedPeer::session_id) == id
                    {
                        ready.push_back((name, *checks));
                    } else {
                        self.arm_unnumbered_retry();
                    }
                }
                PortRoundCompletion::Deleted {
                    name,
                    key,
                    stopped,
                    retirement,
                } => {
                    let from = tokio::time::Instant::now();
                    if let Some(stopped) = stopped {
                        self.finish_stopped_peer_delete(*stopped).await;
                    }
                    if self
                        .unnumbered
                        .as_ref()
                        .and_then(|u| u.ports.get(&name))
                        .is_some_and(|port| port.bound.as_ref() == Some(&key))
                    {
                        self.finish_bound_peer_retirement(&name, key, retirement)
                            .await;
                        ready.push_back((name, PortSessionChecks::default()));
                    } else {
                        // Nothing in a round rebinds a port whose delete is
                        // in flight; if it happens, the held operator and
                        // latch state is lost with this retirement.
                        debug_assert!(false, "port {name} was rebound during its delete");
                        warn!(interface = %name, peer = %key, "unnumbered: port binding changed while its peer was being removed; held neighbor state dropped, retrying");
                        self.arm_unnumbered_retry();
                    }
                    inline += from.elapsed();
                }
            }
        }
        })
        .await;
    }

    /// Add, remove and rebind ports against `current_config`.
    async fn sync_unnumbered_ports(&mut self) {
        // A GTSM peer that sends no RAs is learned from its inbound
        // connection, which completes only once the listener's SYN-ACKs
        // carry Hop Limit 255: raise it before any added or reconfigured
        // neighbor can bind. A neighbor learned from its RA installs a
        // selector, which raises it too.
        if crate::interface_only_gtsm(&self.current_config) {
            self.raise_gtsm_outbound_v6().await;
        }
        let configured: BTreeMap<String, Option<BindTimeProjection>> = self
            .current_config
            .neighbors
            .interface_only()
            .iter()
            .filter_map(|neighbor| {
                Some((
                    neighbor.interface.clone()?,
                    self.current_config.bind_time_settings(neighbor),
                ))
            })
            .collect();
        let existing: Vec<String> = self
            .unnumbered
            .as_ref()
            .map(|unnumbered| unnumbered.ports.keys().cloned().collect())
            .unwrap_or_default();
        for name in &existing {
            if configured.contains_key(name)
                && self.port_mut(name).bfd_removal_unsettled
                && !self.settle_port_bfd_removal(name).await
            {
                continue;
            }
            match configured.get(name) {
                None => self.remove_port(name).await,
                Some(settings) => {
                    if let Some(settings) = settings {
                        self.sync_interface_restart_policy(name, settings.2);
                    }
                    self.rebind_reconfigured_port(name, settings.as_ref()).await;
                }
            }
        }
        self.remove_stale_gtsm_selectors().await;
        let added: Vec<&String> = configured
            .keys()
            .filter(|name| !existing.contains(name))
            .collect();
        if !added.is_empty() && self.unnumbered.is_none() {
            let config = crate::unnumbered_discovery_config(&self.current_config);
            match (self.unnumbered_runtime.spawn)(config, self.metrics.clone()) {
                Ok((discovery, events)) => {
                    info!("unnumbered: starting Router Advertisement discovery");
                    self.unnumbered = Some(Box::new(Unnumbered::new(discovery, events)));
                }
                Err(error) => {
                    error!(%error, "unnumbered: could not start discovery for an added interface-only neighbor; retrying");
                    // Retried until it starts or the neighbors are removed.
                    self.unnumbered_runtime
                        .spawn_retry_at
                        .get_or_insert_with(|| tokio::time::Instant::now() + RECONCILE_RETRY);
                    return;
                }
            }
        }
        if let Some(unnumbered) = self.unnumbered.as_mut() {
            for name in added {
                info!(interface = %name, "unnumbered: interface-only neighbor added");
                unnumbered.discovery.start(name);
                unnumbered.ports.insert(name.clone(), Port::default());
            }
            unnumbered.reconcile_due = true;
        }
        self.feed_unnumbered_links();
        self.publish_running_interface_only();
        if self
            .unnumbered
            .as_ref()
            .is_some_and(|unnumbered| unnumbered.ports.is_empty())
            && let Some(unnumbered) = self.unnumbered.take()
        {
            info!("unnumbered: no interface-only neighbor left; stopping discovery");
            unnumbered.shutdown().await;
        }
    }

    /// Duration edits take effect when configuration is adopted, even when
    /// the next binding arrives much later.
    fn sync_interface_restart_policy(&mut self, name: &str, restart_seconds: Option<u32>) {
        let bound = self.port_mut(name).bound.clone();
        if let Some(key) = bound {
            if self
                .peers
                .get(&key)
                .is_some_and(|peer| peer.max_prefix_restart_seconds != restart_seconds)
            {
                self.rearm_max_prefix_restart(&key, restart_seconds);
                if let Some(peer) = self.peers.get_mut(&key) {
                    peer.max_prefix_restart_seconds = restart_seconds;
                }
            }
        } else if let Some(mut held) = self.port_mut(name).held.take() {
            if held.max_prefix_restart_seconds != restart_seconds {
                if let Some(latch) = &mut held.latch {
                    let generation = self.allocate_max_prefix_latch_generation();
                    latch.reschedule(generation, restart_seconds);
                }
                held.max_prefix_restart_seconds = restart_seconds;
            }
            self.port_mut(name).held = Some(held);
        }
    }

    /// A bound peer whose bind-time settings changed is rebound under them,
    /// on the endpoint it ran on (even one learned from an inbound
    /// connection or whose RA has expired; link loss or a recreated
    /// interface still invalidates it in `reconcile_port`).
    async fn rebind_reconfigured_port(
        &mut self,
        name: &str,
        settings: Option<&BindTimeProjection>,
    ) {
        let port = self.port_mut(name);
        let Some(key) = port
            .bound
            .clone()
            .filter(|_| port.settings.as_ref() != settings)
        else {
            return;
        };
        let scope = self
            .peers
            .get(&key)
            .and_then(|managed| managed.transport_config.peer_scope_id);
        let endpoint = match (key.address, scope) {
            (IpAddr::V6(address), Some(ifindex)) => Some(Endpoint { address, ifindex }),
            _ => None,
        };
        if self
            // The operator changed the settings: retire unconditionally,
            // which also settles any unanswered conditional retirement.
            .retire_bound_peer(name, key, "neighbor_reconfigured", false)
            .await
        {
            let port = self.port_mut(name);
            port.settings = None;
            // The working address, even when discovery has meanwhile seen
            // another router's RA: a settings edit never moves the peer.
            if let Some(endpoint) = endpoint {
                port.desired = Some(endpoint);
            }
        } else {
            // The peer keeps its old settings; try again.
            self.arm_unnumbered_retry();
        }
    }

    /// Publish the running interface-only set (the host IPv6 prerequisite
    /// monitor reads it).
    fn publish_running_interface_only(&self) {
        if let Some(running) = &self.unnumbered_runtime.running {
            let configured = self.current_config.neighbors.interface_only();
            running.send_if_modified(|published| {
                let changed = published.as_slice() != configured;
                if changed {
                    *published = std::sync::Arc::new(configured.to_vec());
                }
                changed
            });
        }
    }

    /// Configuration deleted the neighbor on `name`: end its session, purge
    /// what it learned, release its RIB identity (and with it any address
    /// reservation) and stop discovery there. A peer that cannot be removed
    /// keeps its port, and the removal is retried.
    async fn remove_port(&mut self, name: &str) {
        let Some(bound) = self
            .unnumbered
            .as_ref()
            .and_then(|unnumbered| unnumbered.ports.get(name))
            .map(|port| port.bound.clone())
        else {
            return;
        };
        info!(interface = %name, "unnumbered: interface-only neighbor removed");
        if let Some(key) = bound {
            self.drain_ready_session_notifications(Some(&key)).await;
            // Deleted while the port still owns it, so the deletion reaps
            // the series labelled by the interface (the stanza has left
            // `current_config`) in the session and, after its teardown, in
            // the RIB. The port keeps the RIB identity until released below.
            match self.delete_peer(key.clone(), false).await {
                Ok(_) | Err(PeerLifecycleError::NotFound(_)) => {}
                Err(error) => {
                    warn!(interface = %name, peer = %key, %error, "unnumbered: could not remove the deleted neighbor's peer; retrying");
                    self.arm_unnumbered_retry();
                    return;
                }
            }
            if self.max_prefix_latches.contains_key(&key) {
                self.remove_max_prefix_latch(&key);
            }
        }
        // Only cleanup ownership survives deletion, not the old neighbor's
        // operator state, safety latch, lifetime counters or planned-restart
        // membership.
        let port = self.port_mut(name);
        port.held = None;
        port.graceful_shutdown = false;
        self.planned_restart_interfaces.remove(name);
        let label = rustbgpd_telemetry::interface_peer_label(name);
        // BGP teardown is settled; a pending BFD cleanup must not let a
        // deleted and re-added neighbor inherit the old startup window. Like
        // the deletion above it, this never waits for mailbox room, and a
        // re-added neighbor's session under the label starts behind it.
        // A BFD cleanup retry repeats this step; one queued retirement for
        // the interface covers them all.
        if !self.deferred_rib.retires_eor_grace(name) {
            let _ = self.defer_rib_update(
                Some(label.clone()),
                rustbgpd_rib::RibUpdate::RetireEorGraceInterface {
                    interface: name.into(),
                },
            );
        }
        if !self.settle_port_bfd_removal(name).await {
            // The peer is already gone; only the port's cleanup ownership remains.
            let port = self.port_mut(name);
            port.bound = None;
            port.established = false;
            return;
        }
        let Some(port) = self
            .unnumbered
            .as_mut()
            .and_then(|unnumbered| unnumbered.ports.remove(name))
        else {
            return;
        };
        if let Some(rib_peer) = port.rib_peer {
            // A binding lost earlier was deleted from the RIB keeping its
            // series; this final deletion, queued behind it, ends them under
            // the interface label after anything that one still emits.
            if port.bound.is_none() {
                let _ = self.defer_rib_update(
                    Some(label.clone()),
                    rustbgpd_rib::RibUpdate::PeerDeleted {
                        peer: rib_peer,
                        label: Some(label.as_str().into()),
                        keep_series: false,
                    },
                );
            }
            self.release_unused_rib_peer(rib_peer);
        }
        if let Some(unnumbered) = self.unnumbered.as_mut() {
            unnumbered.discovery.stop(name);
        }
        // An unbound neighbor has no peer to delete: its identity series
        // (kept across endpoints) and discovery counters end here.
        self.metrics.reap_peer_identity_series(&label, name);
        self.metrics.reap_peer_series(&label);
    }

    /// Keep cleanup ownership after a failed acknowledgement, even when the
    /// local membership has already dropped the registration.
    async fn settle_port_bfd_removal(&mut self, name: &str) -> bool {
        let result = if let Some(address) = self.bound_bfd_registration_on(name) {
            self.port_mut(name).bfd_removal_unsettled = true;
            self.set_bound_bfd_session(address, None).await
        } else if self.port_mut(name).bfd_removal_unsettled {
            self.confirm_bound_bfd_removal().await
        } else {
            return true;
        };
        match result {
            Ok(()) => {
                self.port_mut(name).bfd_removal_unsettled = false;
                true
            }
            Err(error) => {
                warn!(interface = %name, %error, "unnumbered: could not confirm removal of the binding's BFD session; retrying");
                self.arm_unnumbered_retry();
                false
            }
        }
    }

    /// Remove the selectors of deleted neighbors, whose peers are gone; a
    /// failure is retried on the reconcile timer.
    async fn remove_stale_gtsm_selectors(&mut self) {
        let Some(update) = self.unnumbered_runtime.gtsm.clone() else {
            return;
        };
        let stale: Vec<String> = self
            .unnumbered_runtime
            .gtsm_selectors
            .iter()
            .filter(|name| {
                self.unnumbered
                    .as_ref()
                    .is_none_or(|unnumbered| !unnumbered.ports.contains_key(*name))
            })
            .cloned()
            .collect();
        for name in stale {
            let outcome = update(ListenerGtsmRequest::Selector {
                interface: name.clone(),
                selector: None,
            })
            .await;
            if outcome == LearnedGtsmOutcome::Applied {
                self.unnumbered_runtime.gtsm_selectors.remove(&name);
            } else {
                warn!(interface = %name, ?outcome, "unnumbered: could not remove a deleted neighbor's GTSM selector; retrying");
                self.unnumbered_runtime
                    .spawn_retry_at
                    .get_or_insert_with(|| tokio::time::Instant::now() + RECONCILE_RETRY);
            }
        }
    }

    fn port_mut(&mut self, name: &str) -> &mut Port {
        self.unnumbered
            .as_mut()
            .and_then(|unnumbered| unnumbered.ports.get_mut(name))
            .expect("reconciled port exists")
    }

    async fn reconcile_port(
        &mut self,
        name: &str,
        checks: &mut PortSessionChecks,
    ) -> Result<(), PortSessionRequest> {
        let port = self.port_mut(name);
        if port.bfd_removal_unsettled {
            return Ok(());
        }
        let link = port.link;
        let link_down = matches!(link, Some((_, LinkState::Down | LinkState::Removed)));
        let current_ifindex = port.link.map(|(ifindex, _)| ifindex);
        let (bound, established) = (port.bound.clone(), port.established);
        // A binding learned on an older index of a recreated interface is
        // stale: the link monitor may report the recreation as Up then Up.
        let desired = port
            .desired
            .filter(|endpoint| current_ifindex.is_none_or(|i| i == endpoint.ifindex));

        if let Some(key) = bound {
            let bound_scope = self
                .peers
                .get(&key)
                .and_then(|managed| managed.transport_config.peer_scope_id);
            // Level-triggered: the bound peer's scope against the interface's
            // index now. A mismatch means the interface it ran on is gone.
            let recreated = current_ifindex.is_some_and(|ifindex| bound_scope != Some(ifindex));
            let lost = link_down || recreated;
            if !lost && !self.confirm_still_stopped(name, &key, checks)? {
                return Ok(());
            }
            let same_endpoint = desired.is_some_and(|endpoint| {
                key.address == IpAddr::V6(endpoint.address) && bound_scope == Some(endpoint.ifindex)
            });
            // A stopped peer is no session to keep at a returning binding.
            let stopped = self.port_mut(name).stopped_retained && desired.is_some();
            // Its replacement binds from `current_config`, so a staged
            // transaction defers it: keep the stopped peer, and the retention
            // its replacement would purge, until the stage clears. A binding
            // that expires meanwhile leaves it to the retention.
            if stopped && !lost && self.defer_unnumbered_while_staged() {
                return Ok(());
            }
            // A lost binding keeps the peer; a new one never displaces an
            // Established session; confirmed carrier loss or interface
            // recreation always ends it.
            let gone = lost || stopped;
            let keep = !gone && (desired.is_none() || same_endpoint || established);
            if keep {
                if desired.is_none() && !established {
                    self.release_unless_retained(name, &key, checks)?;
                }
                return Ok(());
            }
            // Replacing the endpoint binds from `current_config`; wait out a
            // staged transaction. Teardown on a lost link reads no config.
            if !gone && self.defer_unnumbered_while_staged() {
                return Ok(());
            }
            // Level-triggered check of what the edge events claimed.
            if !gone && !self.bound_session_down(name, &key, checks)? {
                return Ok(());
            }
            if !gone && !self.checked_unnumbered_retirement(name, &key, false, checks)? {
                return Ok(());
            }
            return Err(PortSessionRequest::Delete {
                reason: retire_reason(link, recreated, stopped),
            });
        }
        if link_down {
            return Ok(());
        }
        let Some(endpoint) = desired else {
            // A refusal with no binding behind it, such as an inbound
            // connection from a router that sends no RAs, stands while its
            // conflict does: a recheck or configuration change re-reads it.
            let refusal = self.port_mut(name).refused.and_then(|address| {
                self.learned_address_refusal(name, address)
                    .map(|(reason, detail)| refusal_text(reason, address, &detail))
            });
            let port = self.port_mut(name);
            if refusal.is_none() {
                port.refused = None;
            }
            port.refusal = refusal;
            return Ok(());
        };
        if self.defer_unnumbered_while_staged() {
            return Ok(());
        }
        if let Some((reason, detail)) = self.learned_address_refusal(name, endpoint.address) {
            self.refuse_learned_address(name, endpoint.address, reason, &detail);
            return Ok(());
        }
        if self.bind_would_wait(name) {
            self.defer_bind_behind_rib(name, endpoint.address);
            return Ok(());
        }
        let port = self.port_mut(name);
        port.refused = None;
        port.refusal = None;
        match self.bind_port(name, endpoint).await {
            Ok(true) => {}
            Ok(false) => self.defer_bind_behind_rib(name, endpoint.address),
            Err(error) => {
                // Nothing else re-raises this binding (refreshed RAs and an
                // unchanged link emit no event), so retry on the timer.
                warn!(interface = %name, address = %endpoint.address, %error, "unnumbered: could not add the bound peer; retrying");
                self.arm_unnumbered_retry();
            }
        }
        Ok(())
    }

    /// Refuse a learned address for `reason`, logging it and counting a BMP
    /// identity conflict once per address.
    fn refuse_learned_address(
        &mut self,
        name: &str,
        address: Ipv6Addr,
        reason: &'static str,
        detail: &str,
    ) {
        // A reload route that ends without dispatching its generation drops
        // the hold silently; ask again.
        if reason == "reload_pending" {
            self.arm_unnumbered_retry();
        }
        let port = self.port_mut(name);
        port.refusal = Some(refusal_text(reason, address, detail));
        if port.refused == Some(address) {
            return;
        }
        port.refused = Some(address);
        if reason == "bmp_identity_conflict" {
            self.metrics.record_bmp_identity_conflict(false);
        }
        warn!(
            interface = %name, %address, %detail, reason,
            "unnumbered: refusing a learned address another neighbor holds"
        );
    }

    /// Why the interface-only neighbor on `name` may not bind `address`:
    /// a BMP-monitored holder while a collector refuses identity conflicts
    /// (`bmp_identity_conflict`), a neighbor there using a feature keyed by
    /// the bare address (`shared_address_feature`), or a static neighbor of
    /// a reload generation that passed its preflight (`reload_pending`).
    fn learned_address_refusal(
        &self,
        name: &str,
        address: Ipv6Addr,
    ) -> Option<(&'static str, String)> {
        if let Some(holder) = self.bmp_identity_holder(address) {
            return Some(("bmp_identity_conflict", format!("held by {holder}")));
        }
        let key = PeerKey::new(IpAddr::V6(address), Some(name.to_owned()));
        self.shared_address_feature_conflict(&key, &self.current_config)
            .map(|reason| ("shared_address_feature", reason))
            .or_else(|| {
                self.generation_held(address)
                    .map(|label| ("reload_pending", format!("held by {label}, reload pending")))
            })
    }

    /// Whether the bound session is down, read from the session itself. An
    /// Established session is recorded and reported to discovery. No answer
    /// keeps it, claims nothing to discovery, and asks again shortly.
    fn bound_session_down(
        &mut self,
        name: &str,
        key: &PeerKey,
        checks: &PortSessionChecks,
    ) -> Result<bool, PortSessionRequest> {
        if !self.peers.contains_key(key) {
            return Ok(true);
        }
        Ok(match checks.state()? {
            StateQueryOutcome::State(state) if state.fsm_state == SessionState::Established => {
                if let Some(unnumbered) = self.unnumbered.as_mut() {
                    report_established(&unnumbered.discovery, name, key);
                }
                self.port_mut(name).established = true;
                false
            }
            StateQueryOutcome::TimedOut => {
                self.arm_unnumbered_retry();
                false
            }
            _ => true,
        })
    }

    /// ADR-0142: an unbound neighbor whose session is down keeps its last
    /// address reserved only while the RIB retains GR or LLGR stale routes
    /// from it. Once that retention ends, by a purge or its timers, the peer
    /// is removed: the redial ends and the address is released. Retained, it
    /// is checked again at the RIB's next timer, which sweeps the routes or
    /// promotes them to LLGR.
    fn release_unless_retained(
        &mut self,
        name: &str,
        key: &PeerKey,
        checks: &mut PortSessionChecks,
    ) -> Result<(), PortSessionRequest> {
        if !self.port_mut(name).stopped_retained {
            if checks.retirement.is_none() {
                if !self.bound_session_quiet(name, key, checks)? {
                    return Ok(());
                }
                // The session answered the read only after sending its
                // teardown's GR or PeerDown to the RIB, so this query, queued
                // behind it, sees the retention that teardown left.
                if self.retained_until_next_check(name, key, checks, false)? {
                    return Ok(());
                }
            }
            if !self.checked_unnumbered_retirement(name, key, true, checks)? {
                return Ok(());
            }
            // The session may have established and failed with GR between
            // the check and the shutdown; the second query, queued behind
            // that teardown, sees it.
            self.port_mut(name).stopped_retained = true;
        }
        if self.retained_until_next_check(name, key, checks, true)? {
            return Ok(());
        }
        Err(PortSessionRequest::Delete {
            reason: "binding_expired",
        })
    }

    /// Whether the bound session has no connection past TCP: Idle, Connect,
    /// Active or gone. An Established session is recorded and reported to
    /// discovery. An `OpenSent` or `OpenConfirm` session is a live router mid-
    /// handshake, such as an inbound connection learned without an RA; its
    /// outcome reports itself. No answer retries shortly.
    fn bound_session_quiet(
        &mut self,
        name: &str,
        key: &PeerKey,
        checks: &PortSessionChecks,
    ) -> Result<bool, PortSessionRequest> {
        let Some(_) = self.peers.get(key) else {
            return Ok(true);
        };
        Ok(match checks.state()? {
            rustbgpd_transport::StateQueryOutcome::State(state) => match state.fsm_state {
                SessionState::Established => {
                    if let Some(unnumbered) = self.unnumbered.as_mut() {
                        report_established(&unnumbered.discovery, name, key);
                    }
                    self.port_mut(name).established = true;
                    false
                }
                // A handshake that fails in OpenSent falls back to Active,
                // which reports nothing: check it again.
                SessionState::OpenSent | SessionState::OpenConfirm => {
                    self.arm_unnumbered_retry();
                    false
                }
                _ => true,
            },
            rustbgpd_transport::StateQueryOutcome::SessionGone => true,
            rustbgpd_transport::StateQueryOutcome::TimedOut => {
                self.arm_unnumbered_retry();
                false
            }
        })
    }

    /// A stopped peer stays stopped until a new session is installed for
    /// it, such as an inbound reconnect: a session that answers clears the
    /// mark, and the ordinary checks then apply to it. `false` (retry
    /// armed) when the session did not answer.
    fn confirm_still_stopped(
        &mut self,
        name: &str,
        key: &PeerKey,
        checks: &PortSessionChecks,
    ) -> Result<bool, PortSessionRequest> {
        if !self.port_mut(name).stopped_retained || checks.retention_after.is_some() {
            return Ok(true);
        }
        let Some(_) = self.peers.get(key) else {
            return Ok(true);
        };
        Ok(match checks.state()? {
            rustbgpd_transport::StateQueryOutcome::State(_) => {
                self.port_mut(name).stopped_retained = false;
                true
            }
            rustbgpd_transport::StateQueryOutcome::SessionGone => true,
            rustbgpd_transport::StateQueryOutcome::TimedOut => {
                self.arm_unnumbered_retry();
                false
            }
        })
    }

    /// Whether the RIB still retains the bound peer's GR or LLGR routes.
    /// Retained, the next check is armed at the RIB's next timer, which
    /// sweeps them or promotes them to LLGR; no answer retries shortly.
    fn retained_until_next_check(
        &mut self,
        name: &str,
        key: &PeerKey,
        checks: &PortSessionChecks,
        after_shutdown: bool,
    ) -> Result<bool, PortSessionRequest> {
        let result = if after_shutdown {
            &checks.retention_after
        } else {
            &checks.retention_before
        };
        let Some(retention) = result
            .as_ref()
            .ok_or(PortSessionRequest::Retention { after_shutdown })?
        else {
            self.arm_unnumbered_retry();
            return Ok(true);
        };
        if retention.stale_routes == 0 {
            return Ok(false);
        }
        let now = tokio::time::Instant::now();
        let at = retention
            .next_deadline
            .unwrap_or(now + RETENTION_RECHECK)
            .max(now + RECONCILE_RETRY);
        debug!(interface = %name, peer = %key, stale_routes = retention.stale_routes, "unnumbered: unbound neighbor keeps its address while its routes are retained");
        self.arm_unnumbered_retry_at(at);
        Ok(true)
    }

    /// End the bound peer's session and clear the binding, keeping the
    /// neighbor's operator and safety state for its next endpoint. `false`
    /// when the peer could not be removed; the binding is then unchanged.
    ///
    /// An address change (`unless_established`) never ends an Established
    /// session: the session itself checks and shuts down in one turn, so a
    /// KEEPALIVE landing after the caller's state read cannot be torn down.
    /// Confirmed carrier loss and interface recreation end it regardless.
    async fn retire_bound_peer(
        &mut self,
        name: &str,
        key: PeerKey,
        reason: &'static str,
        unless_established: bool,
    ) -> bool {
        if unless_established && !self.shut_down_unless_established(name, &key, false).await {
            return false;
        }
        let (detached, retirement) = match self
            .prepare_bound_peer_retirement(name, &key, reason)
            .await
        {
            Ok(retirement) => retirement,
            Err(PeerLifecycleError::NotFound(_)) => return true,
            Err(error) => {
                self.port_mut(name).presence_reason = None;
                warn!(interface = %name, peer = %key, %error, "unnumbered: could not remove the bound peer");
                return false;
            }
        };
        if let Some(detached) = detached {
            self.delete_detached_peers(vec![detached]).await;
        }
        self.finish_bound_peer_retirement(name, key, retirement)
            .await;
        true
    }

    async fn prepare_bound_peer_retirement(
        &mut self,
        name: &str,
        key: &PeerKey,
        reason: &'static str,
    ) -> Result<(Option<super::lifecycle::DetachedPeer>, BoundPeerRetirement), PeerLifecycleError>
    {
        info!(interface = %name, peer = %key, reason, "unnumbered: ending the bound session");
        self.port_mut(name).presence_reason = Some(reason);
        // Drain already-reported state before joining the retiring actor.
        self.drain_ready_session_notifications(Some(key)).await;
        // The neighbor's operator and safety state outlives the endpoint.
        let had_latch = self.max_prefix_latches.contains_key(key);
        let graceful_shutdown = self
            .peers
            .get(key)
            .is_some_and(|managed| managed.advertise_graceful_shutdown);
        let held = HeldState {
            enabled: self.peers.get(key).is_none_or(|managed| managed.enabled),
            config_admin_down: self
                .peers
                .get(key)
                .is_some_and(|managed| managed.admin_down.is_some()),
            max_prefix_restart_seconds: self
                .peers
                .get(key)
                .and_then(|managed| managed.max_prefix_restart_seconds),
            latch: None,
            counters: self.neighbor_counters_for(key),
        };
        let detached = match self
            .detach_peer_for_delete(key.clone(), false, None, false, None, None)
            .await
        {
            Ok(detached) => Some(detached),
            Err(PeerLifecycleError::NotFound(_)) => None,
            Err(error) => return Err(error),
        };
        Ok((
            detached,
            BoundPeerRetirement {
                had_latch,
                graceful_shutdown,
                held,
            },
        ))
    }

    async fn finish_bound_peer_retirement(
        &mut self,
        name: &str,
        key: PeerKey,
        retirement: BoundPeerRetirement,
    ) {
        let BoundPeerRetirement {
            had_latch,
            graceful_shutdown,
            mut held,
        } = retirement;
        held.latch = self.max_prefix_latches.remove(&key);
        if let Some(latch) = &mut held.latch {
            held.enabled = false;
            self.publish_peer_admin_enabled_metric(&key, false);
            // The retiring session has left `peers`, so its late notice could
            // not read the accepted duration when it installed this latch.
            if !had_latch && latch.deadline.is_none() {
                latch.deadline = held.max_prefix_restart_seconds.map(|seconds| {
                    tokio::time::Instant::now() + std::time::Duration::from_secs(seconds.into())
                });
            }
        }
        self.reap_deleted_peer_metric_series_for_key(&key);
        self.port_mut(name).presence_reason = None;
        if held.latch.is_some() {
            self.metrics.set_max_prefix_latched(
                &rustbgpd_telemetry::interface_peer_label(name),
                name,
                true,
            );
            self.recompute_next_max_prefix_restart_deadline();
        }
        // The retired endpoint's export gate goes with it; the run loop's
        // reconcile installs the set without it (or the next binding's
        // install does, first).
        if self
            .conditional_advertisements
            .attachments
            .contains_key(&key.rib_endpoint())
        {
            self.conditional_reconcile_pending = true;
        }
        // The endpoint's BFD session goes with it; uncertain removal keeps
        // cleanup ownership and blocks rebinding until the actor confirms it.
        if let Err(error) = self.set_bound_bfd_session(key.address, None).await {
            self.port_mut(name).bfd_removal_unsettled = true;
            self.arm_unnumbered_retry();
            warn!(interface = %name, peer = %key, %error, "unnumbered: could not remove the bound BFD session yet");
        }
        let port = self.port_mut(name);
        port.bound = None;
        port.established = false;
        port.stopped_retained = false;
        port.held = Some(held);
        port.graceful_shutdown = graceful_shutdown;
        let previous = port.last_address.map(|address| address.to_string());
        self.metrics.set_unnumbered_peer_address(
            &rustbgpd_telemetry::interface_peer_label(name),
            name,
            previous.as_deref(),
            None,
        );
        // Only once the old peer is gone: until then its endpoint keeps GTSM.
        if let Err(error) = self.set_learned_gtsm(name, None).await {
            warn!(interface = %name, %error, "unnumbered: could not remove the retired endpoint's GTSM selector; the next binding replaces it");
        }
        // The retired session's queued reports have been drained by
        // now; an Established among them must not outlive it.
        if let Some(unnumbered) = self.unnumbered.as_mut() {
            unnumbered.discovery.session_failed(name);
        }
    }

    /// The interface-only neighbor's interface whose current index is
    /// `scope_id`: an inbound link-local connection's arrival scope, resolved
    /// by interface name as for every link-local dial and inbound match.
    pub(super) fn interface_only_port_at(&self, scope_id: u32) -> Option<String> {
        let feed = self.link_state_feed(true);
        self.unnumbered
            .as_ref()?
            .ports
            .keys()
            .find(|name| feed.resolve_interface(name) == Some(scope_id))
            .cloned()
    }

    /// Refuse an inbound connection from a second router on `name`'s link,
    /// counted as a conflict and as `unconfigured`. Another address while the
    /// bound session is Established is one, with or without an RA binding.
    fn refuse_second_router(&self, name: &str) -> Option<PeerKey> {
        self.metrics
            .record_unnumbered_ra_conflicts(&rustbgpd_telemetry::interface_peer_label(name), 1);
        self.refuse_inbound()
    }

    /// Count a refused inbound learning attempt as `unconfigured`, as such a
    /// connection was before inbound learning: its source is no neighbor's
    /// configured or learned endpoint on the arrival interface.
    fn refuse_inbound(&self) -> Option<PeerKey> {
        self.metrics.record_inbound_connection_drop(
            rustbgpd_telemetry::reason_labels::InboundConnectionDropReason::Unconfigured,
        );
        None
    }

    /// Admission refuses `address` on `name`: log the refusal and count it.
    fn inbound_address_held(&mut self, name: &str, address: Ipv6Addr) -> bool {
        let Some((reason, detail)) = self.learned_address_refusal(name, address) else {
            return false;
        };
        // Reported as the neighbor's last error, as an RA refusal is, until a
        // binding is admitted or the conflict ends.
        let port = self.port_mut(name);
        port.refused = Some(address);
        port.refusal = Some(refusal_text(reason, address, &detail));
        if reason == "bmp_identity_conflict" {
            self.metrics.record_bmp_identity_conflict(false);
        }
        warn!(
            interface = %name, %address, %detail, reason,
            "unnumbered: refusing an inbound address another neighbor holds"
        );
        self.refuse_inbound();
        true
    }

    /// ADR-0142 secondary discovery: an inbound connection from `address`
    /// arrived on `name`, the interface of an interface-only neighbor, and
    /// matched no peer. Bind the neighbor to that endpoint through the same
    /// admission check as an RA binding, and return the bound peer for the
    /// ordinary inbound gates (BFD, admin state, NOTIFICATION backoff,
    /// collision). `None` refuses the connection; the reason is logged here
    /// and counted in `bgp_inbound_connections_dropped_total`.
    ///
    /// Refused while the link is confirmed down, while a live RA binding, a
    /// session past TCP establishment or a pending inbound candidate holds a
    /// different address (a second router on a link defined to have one),
    /// while the bound session is Established or held by NOTIFICATION
    /// backoff, and, while BMP collectors are configured, when another
    /// neighbor holds the address (`bmp_identity_conflict`). A bound session that has not
    /// reached `OpenSent` is retired: the peer moved address.
    #[expect(
        clippy::too_many_lines,
        reason = "every refusal of a learned inbound endpoint stays in one ordered admission check"
    )]
    pub(super) async fn learn_inbound_endpoint(
        &mut self,
        name: &str,
        address: Ipv6Addr,
        ifindex: u32,
    ) -> Option<PeerKey> {
        let Some(port) = self
            .unnumbered
            .as_ref()
            .and_then(|unnumbered| unnumbered.ports.get(name))
        else {
            return self.refuse_inbound();
        };
        if matches!(port.link, Some((_, LinkState::Down | LinkState::Removed))) {
            info!(interface = %name, %address, "unnumbered: inbound connection on a link that is down, dropping");
            return self.refuse_inbound();
        }
        if let Some(desired) = port.desired
            && desired.address != address
        {
            warn!(
                interface = %name, %address, bound = %desired.address,
                reason = "multiple_routers_on_link",
                "unnumbered: inbound connection from a second router on an interface-only link, dropping"
            );
            return self.refuse_second_router(name);
        }
        let bound = port.bound.clone();
        if let Some(key) = bound.clone()
            && key.address == IpAddr::V6(address)
        {
            return Some(key);
        }
        // Checked before the current endpoint is retired, so a refused
        // address leaves the port bound, and again just before binding.
        if self.inbound_address_held(name, address) {
            return None;
        }
        // Binding would wait for RIB mailbox room (`bind_would_wait`);
        // refuse the connection instead (the remote retries), here and again
        // after a retirement queues its cleanup.
        if self.refuse_learning_behind_rib(name, address) {
            return None;
        }
        if let Some(key) = bound {
            // An inbound candidate from the bound address is opening even
            // when the primary is not: that router is live on the link.
            if self
                .peers
                .get(&key)
                .is_some_and(|managed| managed.pending_inbound.is_some())
            {
                warn!(
                    interface = %name, %address, peer = %key,
                    reason = "multiple_routers_on_link",
                    "unnumbered: inbound connection from a second router while the bound address has a connection pending, dropping"
                );
                return self.refuse_second_router(name);
            }
            let state = match self.peers.get(&key) {
                None => None,
                Some(managed) => {
                    let commands = managed.handle().commands_sender();
                    match self
                        .await_session_sweep(PeerHandle::query_state_outcome_with(
                            commands,
                            BOUND_STATE_QUERY_TIMEOUT,
                        ))
                        .await
                    {
                        rustbgpd_transport::StateQueryOutcome::State(state) => Some(state),
                        rustbgpd_transport::StateQueryOutcome::SessionGone => None,
                        rustbgpd_transport::StateQueryOutcome::TimedOut => {
                            info!(interface = %name, %address, peer = %key, "unnumbered: bound session did not report its state; dropping the inbound connection (remote will retry)");
                            return self.refuse_inbound();
                        }
                    }
                }
            };
            if let Some(
                state @ (SessionState::OpenSent
                | SessionState::OpenConfirm
                | SessionState::Established),
            ) = state.as_ref().map(|state| state.fsm_state)
            {
                warn!(
                    interface = %name, %address, peer = %key, state = state.as_str(),
                    reason = "multiple_routers_on_link",
                    "unnumbered: inbound connection from a second router while the bound session is opening or Established, dropping"
                );
                return self.refuse_second_router(name);
            }
            if let Some(state) = state
                .as_ref()
                .filter(|state| super::inbound::notification_backoff_holds_inbound(state))
            {
                self.record_notification_backoff_drop(key.address, state, "inbound connection");
                return None; // counted as `notification_backoff`
            }
            if !self
                .retire_bound_peer(name, key, "peer_address_changed", true)
                .await
            {
                return self.refuse_inbound();
            }
        }
        // The same atomic admission step as an RA binding: no input runs
        // between this check and the insertion in `bind_port`.
        if self.inbound_address_held(name, address)
            || self.refuse_learning_behind_rib(name, address)
        {
            return None;
        }
        let endpoint = Endpoint { address, ifindex };
        match self.bind_port(name, endpoint).await {
            Ok(true) => {}
            Ok(false) => {
                self.record_rib_cleanup_pending_drop(name, address);
                return None;
            }
            Err(error) => {
                warn!(interface = %name, %address, %error, "unnumbered: could not add the peer learned from an inbound connection");
                return self.refuse_inbound();
            }
        }
        info!(interface = %name, %address, "unnumbered: peer address learned from an inbound connection");
        let port = self.port_mut(name);
        port.refused = None;
        port.refusal = None;
        port.bound.clone()
    }

    /// Raise the IPv6 listener's outbound Hop Limit to 255 once; a failure
    /// is retried on the reconcile timer.
    async fn raise_gtsm_outbound_v6(&mut self) {
        if self.unnumbered_runtime.gtsm_outbound_raised {
            return;
        }
        let Some(update) = self.unnumbered_runtime.gtsm.clone() else {
            return;
        };
        let error = match update(ListenerGtsmRequest::RaiseOutboundV6).await {
            LearnedGtsmOutcome::Applied => {
                self.unnumbered_runtime.gtsm_outbound_raised = true;
                return;
            }
            LearnedGtsmOutcome::Failed(error) => error,
            LearnedGtsmOutcome::Unconfirmed => "no answer".to_owned(),
        };
        warn!(%error, "unnumbered: could not raise the listener's IPv6 Hop Limit to 255 for GTSM; retrying");
        self.unnumbered_runtime
            .spawn_retry_at
            .get_or_insert_with(|| tokio::time::Instant::now() + RECONCILE_RETRY);
    }

    /// Install, replace or (`None`) remove the listener's GTSM selector for
    /// `name`'s interface-only neighbor. A neighbor without GTSM and no
    /// selector skips the listener entirely.
    async fn set_learned_gtsm(
        &mut self,
        name: &str,
        selector: Option<rustbgpd_transport::LearnedTtlSecuritySelector>,
    ) -> Result<(), PeerLifecycleError> {
        let Some(update) = self.unnumbered_runtime.gtsm.clone() else {
            return Ok(());
        };
        let installed = &mut self.unnumbered_runtime.gtsm_selectors;
        if selector.is_none() && !installed.contains(name) {
            return Ok(());
        }
        let outcome = update(ListenerGtsmRequest::Selector {
            interface: name.to_owned(),
            selector,
        })
        .await;
        let installed = &mut self.unnumbered_runtime.gtsm_selectors;
        match outcome {
            LearnedGtsmOutcome::Applied => {
                if selector.is_some() {
                    installed.insert(name.to_owned());
                } else {
                    installed.remove(name);
                }
                Ok(())
            }
            LearnedGtsmOutcome::Failed(error) => Err(PeerLifecycleError::Internal(format!(
                "the listener did not update the GTSM selector: {error}"
            ))),
            LearnedGtsmOutcome::Unconfirmed => {
                installed.insert(name.to_owned());
                Err(PeerLifecycleError::Internal(
                    "the listener did not confirm the GTSM selector update".into(),
                ))
            }
        }
    }

    /// Why `peer`'s endpoint is being removed or added, when it belongs to
    /// an interface-only neighbor whose binding is changing.
    pub(super) fn unnumbered_presence_reason(&self, peer: &PeerKey) -> Option<&'static str> {
        self.unnumbered
            .as_ref()?
            .ports
            .get(peer.interface.as_deref()?)?
            .presence_reason
    }

    /// `name`'s interface-only neighbor and the peer configuration it binds
    /// at `endpoint`.
    fn bound_peer_config(
        &self,
        name: &str,
        endpoint: Endpoint,
    ) -> Result<(crate::config::Neighbor, super::PeerManagerNeighborConfig), PeerLifecycleError>
    {
        let neighbor = self
            .current_config
            .neighbors
            .interface_only_on(name)
            .cloned()
            .ok_or_else(|| {
                PeerLifecycleError::Internal(format!("no interface-only neighbor on {name}"))
            })?;
        let resolved = self
            .current_config
            .resolve_bound_interface_neighbor(&neighbor, endpoint.address, endpoint.ifindex)
            .map_err(|error| PeerLifecycleError::Invalid(error.to_string()))?;
        // Restart-eligible like startup static neighbors: during a planned
        // restart's window a neighbor of that restart's roster sends R=1, so
        // helpers keep the routes they retained; after the window, or for a
        // neighbor added at runtime, it sends R=0.
        let restart_eligible = self.planned_restart_interfaces.contains(name);
        Ok((
            neighbor,
            Self::peer_manager_config_from_resolved(resolved, restart_eligible),
        ))
    }

    /// The export gate of the neighbor's conditional advertisements is keyed
    /// by endpoint: install it for `key` before the peer exists, so its first
    /// UPDATE is already gated (ADR-0137). `true` when the neighbor has one.
    async fn install_binding_gate(
        &mut self,
        neighbor: &crate::config::Neighbor,
        key: &PeerKey,
        name: &str,
    ) -> Result<bool, PeerLifecycleError> {
        if self
            .current_config
            .effective_conditional_advertisements(neighbor)
            .is_empty()
        {
            return Ok(false);
        }
        let mut bindings = self.unnumbered_binding_endpoints();
        bindings.push((key.address, name.to_owned()));
        let set = self
            .conditional_set_with_bindings(&self.current_config, &bindings)
            .map_err(|error| PeerLifecycleError::Invalid(error.to_string()))?;
        if let Err(error) = self
            .install_conditional_advertisements(set, &[], ConditionalReplyWait::Retrying)
            .await
        {
            // An install that was never sent changed nothing, so the
            // reconcile then finds nothing to change. One whose acknowledgement
            // failed may still be held by the RIB: reconcile it against the
            // live bindings, or a binding that ends before the retry leaves
            // the gate at an endpoint with no peer.
            self.conditional_reconcile_pending = true;
            return Err(PeerLifecycleError::Internal(error.to_string()));
        }
        Ok(true)
    }

    /// Whether the interface-only neighbor on `name` keeps a RIB handle
    /// across endpoints, which its next binding moves with `RebindPeer`.
    fn port_holds_rib_peer(&self, name: &str) -> bool {
        self.unnumbered
            .as_ref()
            .and_then(|unnumbered| unnumbered.ports.get(name))
            .is_some_and(|port| port.rib_peer.is_some())
    }

    /// Whether binding `name` now would wait in the actor for RIB mailbox
    /// room: its session starts only after a cleanup queued under the
    /// interface's label is admitted, and a neighbor that keeps its RIB handle
    /// sends `RebindPeer` (with `try_send`, so a mailbox that fills after this
    /// check still returns `Ok(false)`). Deferred cleanup under other labels
    /// does not hold a bind back: nothing of this neighbor's is behind it. Its
    /// callers retry or refuse instead, so no bind waits with no owner.
    fn bind_would_wait(&self, name: &str) -> bool {
        self.deferred_rib
            .reaps(&rustbgpd_telemetry::interface_peer_label(name))
            || (self.port_holds_rib_peer(name) && self.rib_tx.capacity() == 0)
    }

    /// A discovery-driven bind of `name` at `address` would wait for RIB
    /// mailbox room: retry it on the reconcile timer, and report why as the
    /// unbound neighbor's last error until then.
    fn defer_bind_behind_rib(&mut self, name: &str, address: Ipv6Addr) {
        debug!(interface = %name, %address, deferred = self.deferred_rib.queue.len(), "unnumbered: binding waits for RIB mailbox room; retrying");
        self.port_mut(name).refusal = Some(refusal_text(
            "rib_cleanup_pending",
            address,
            "the binding waits until the RIB admits the updates ahead of it",
        ));
        self.arm_unnumbered_retry();
    }

    /// Refuse an inbound connection that would learn `address` on `name`
    /// while its bind would wait for RIB mailbox room.
    fn refuse_learning_behind_rib(&self, name: &str, address: Ipv6Addr) -> bool {
        let refused = self.bind_would_wait(name);
        if refused {
            self.record_rib_cleanup_pending_drop(name, address);
        }
        refused
    }

    fn record_rib_cleanup_pending_drop(&self, name: &str, address: Ipv6Addr) {
        self.metrics.record_inbound_connection_drop(
            rustbgpd_telemetry::reason_labels::InboundConnectionDropReason::RibCleanupPending,
        );
        debug!(interface = %name, %address, "unnumbered: dropping an inbound connection whose binding waits for RIB mailbox room");
    }

    #[expect(
        clippy::too_many_lines,
        reason = "binding admission and rollback share the held neighbor state and must preserve side-effect ordering"
    )]
    /// `Ok(false)`: the RIB mailbox had no room for the neighbor's
    /// `RebindPeer`, which goes before every other step, so nothing was
    /// applied and the caller retries or refuses.
    pub(super) async fn bind_port(
        &mut self,
        name: &str,
        endpoint: Endpoint,
    ) -> Result<bool, PeerLifecycleError> {
        // Only the actor-owned term: sessions change the mailbox's free
        // capacity concurrently, and `try_send` below handles a full one.
        debug_assert!(
            !self
                .deferred_rib
                .reaps(&rustbgpd_telemetry::interface_peer_label(name)),
            "a bind of {name} would wait for the cleanup queued under its label"
        );
        if self.port_mut(name).bfd_removal_unsettled {
            self.arm_unnumbered_retry();
            return Err(PeerLifecycleError::Internal(
                "the previous binding's BFD removal is not yet confirmed".into(),
            ));
        }
        let (neighbor, config) = self.bound_peer_config(name, endpoint)?;
        let key = PeerKey::new(IpAddr::V6(endpoint.address), Some(name.to_owned()));
        let bfd = crate::bfd_runtime::bound_session_params(
            &self.current_config,
            &neighbor,
            name,
            endpoint.address,
            endpoint.ifindex,
        )
        .map_err(|error| PeerLifecycleError::Invalid(error.to_string()))?;
        // The neighbor keeps its RIB identity across endpoints. The RIB moves
        // it to the new endpoint, in order after the previous binding's
        // deletion and before the new session's first message. Always sent:
        // the table may not yet reflect a rebind still queued to the RIB,
        // whose handler skips an unchanged endpoint in its own order. Sent
        // directly, never waiting: `bind_would_wait` held no cleanup under
        // this interface's label, so the previous binding's deletion has
        // reached the RIB and only other neighbors' deferred updates, which
        // nothing here depends on, can still be queued.
        //
        // Sent before any other side effect, so a mailbox that filled after
        // `bind_would_wait` leaves nothing to roll back. The gate install
        // below reaches the RIB after it, which is safe: the moved handle has
        // no session registered until this binding's `PeerUp`, so the gate
        // still precedes the peer's first UPDATE. A later failure leaves the
        // handle at this endpoint with no session; the retry's `RebindPeer`,
        // or the next binding's, settles it.
        let rib_peer = self.port_mut(name).rib_peer;
        if let Some(rib_peer) = rib_peer {
            let next = rustbgpd_rib::PeerEndpoint::new(IpAddr::V6(endpoint.address), Some(name));
            let sent = self.rib_tx.try_send(rustbgpd_rib::RibUpdate::RebindPeer {
                peer: rib_peer,
                endpoint: next,
            });
            match sent {
                Ok(()) => {}
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => return Ok(false),
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    return Err(PeerLifecycleError::Internal(
                        "RIB channel closed while rebinding the neighbor".into(),
                    ));
                }
            }
        }
        // GTSM is in force at the listener for this endpoint before the peer
        // can be matched inbound; a neighbor without it leaves no selector.
        let selector = learned_selector(endpoint, config.ttl_security_hops);
        self.set_learned_gtsm(name, selector).await?;
        // The binding's BFD session exists before its peer, so a strict peer
        // is added withheld until BFD is Up on this endpoint (ADR-0142).
        let has_bfd = bfd.is_some();
        let gated = self.install_binding_gate(&neighbor, &key, name).await?;
        if has_bfd && let Err(error) = self.set_bound_bfd_session(key.address, bfd).await {
            // The gate installed above names an endpoint with no peer.
            self.conditional_reconcile_pending |= gated;
            return Err(PeerLifecycleError::Internal(error));
        }
        // Carry the previous endpoint's state: a disable stays, and a latch
        // keeps the new peer down until its restart deadline or an enable.
        let held = self.port_mut(name).held.take();
        let graceful_shutdown = std::mem::take(&mut self.port_mut(name).graceful_shutdown);
        // A changed configured admin state takes effect; an unchanged one
        // keeps the operator's toggle. The max-prefix latch is separate.
        let next_down = config.admin_down.is_some();
        let enabled = match &held {
            Some(held) if held.config_admin_down == next_down => held.enabled,
            _ => !next_down,
        };
        let mut carried_latch = false;
        if let Some(latch) = held.as_ref().and_then(|held| held.latch.clone()) {
            self.max_prefix_latches.insert(key.clone(), latch);
            self.publish_max_prefix_latched_metric(&key, true);
            self.recompute_next_max_prefix_restart_deadline();
            carried_latch = true;
        }
        if let Some(rib_peer) = rib_peer {
            self.rib_peers.insert(
                key.clone(),
                rustbgpd_transport::RibPeerSlot::assigned(rib_peer),
            );
        }
        self.note_binding_reason(name, endpoint.address);
        if let Some(held) = &held {
            self.neighbor_counters
                .insert(key.clone(), held.counters.clone());
        }
        let added = self.add_peer_impl(config, false, enabled, true).await;
        self.port_mut(name).presence_reason = None;
        if let Err(error) = added {
            self.neighbor_counters.remove(&key);
            if carried_latch {
                self.remove_max_prefix_latch(&key);
            }
            if rib_peer.is_some() {
                self.rib_peers.remove(&key);
            }
            let port = self.port_mut(name);
            port.held = held;
            port.graceful_shutdown = graceful_shutdown;
            // The gate installed above names an endpoint with no peer.
            self.conditional_reconcile_pending |= gated;
            if has_bfd {
                let _ = self.settle_port_bfd_removal(name).await;
            }
            return Err(error);
        }
        info!(interface = %name, peer = %key, enabled, "unnumbered: bound peer added");
        // Best-effort, like a static neighbor's reconfigure replay.
        if graceful_shutdown
            && let Err(error) = self.set_graceful_shutdown(Some(key.clone()), true).await
        {
            warn!(interface = %name, peer = %key, %error, "unnumbered: could not replay graceful shutdown on the new peer");
        }
        let rib_peer = self.rib_peer_of(&key);
        let settings = self.current_config.bind_time_settings(&neighbor);
        let port = self.port_mut(name);
        port.rib_peer = port.rib_peer.or(Some(rib_peer));
        port.bound = Some(key);
        port.settings = settings;
        self.publish_bound_address(name, endpoint.address);
        Ok(true)
    }

    /// Why `name`'s endpoint is being added, for its presence event.
    fn note_binding_reason(&mut self, name: &str, address: Ipv6Addr) {
        let port = self.port_mut(name);
        port.presence_reason = Some(if port.last_address.is_some_and(|last| last != address) {
            "peer_address_changed"
        } else {
            "peer_address_learned"
        });
    }

    /// `name` is bound to `address`: count a change of address and publish
    /// the address series.
    fn publish_bound_address(&mut self, name: &str, address: Ipv6Addr) {
        let previous = self.port_mut(name).last_address.replace(address);
        let label = rustbgpd_telemetry::interface_peer_label(name);
        if let Some(previous) = previous.filter(|previous| *previous != address) {
            info!(interface = %name, %previous, %address, "unnumbered: peer address changed");
            self.metrics.record_unnumbered_address_change(&label);
        }
        self.metrics.set_unnumbered_peer_address(
            &label,
            name,
            previous.map(|previous| previous.to_string()).as_deref(),
            Some(&address.to_string()),
        );
    }
}

/// Why a bound endpoint is retired, as logged and as its presence events
/// carry it.
fn retire_reason(link: Option<(u32, LinkState)>, recreated: bool, exited: bool) -> &'static str {
    match link {
        _ if recreated => "interface_removed",
        Some((_, LinkState::Removed)) => "interface_removed",
        Some((_, LinkState::Down)) => "link_down",
        _ if exited => "session_exited",
        _ => "peer_address_changed",
    }
}

/// The listener's GTSM selector for a neighbor bound at `endpoint`, if it
/// runs GTSM.
fn learned_selector(
    endpoint: Endpoint,
    hops: Option<std::num::NonZeroU8>,
) -> Option<rustbgpd_transport::LearnedTtlSecuritySelector> {
    hops.map(|hops| rustbgpd_transport::LearnedTtlSecuritySelector {
        address: endpoint.address,
        ifindex: endpoint.ifindex,
        hops,
    })
}

/// The last error a refused binding reports: `<reason>: <detail>`.
fn refusal_text(reason: &str, address: Ipv6Addr, detail: &str) -> String {
    format!("{reason}: learned address {address} refused, {detail}")
}
