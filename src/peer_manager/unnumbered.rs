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
//! - Admission refuses an address that another neighbor holds
//!   (`duplicate_link_local_address`) until the scoped RIB identity lands.
//!   The check and the insertion run in this single owner without an
//!   intervening input, so two links discovering one address cannot both be
//!   admitted.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv6Addr};

use rustbgpd_api::peer_types::{PeerKey, PeerLifecycleError};
use rustbgpd_fsm::SessionState;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::config::BindTimeProjection;
use crate::ra_discovery::{
    DiscoveryConfig, DiscoveryEvent, Endpoint, LinkEvent, LinkState, RaDiscovery,
};

use super::PeerManager;

/// How long reconciliation waits for a bound session, or the RIB, to answer.
const BOUND_STATE_QUERY_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);
/// How soon a reconcile is retried after a bound session did not answer.
const RECONCILE_RETRY: std::time::Duration = std::time::Duration::from_secs(1);
/// How soon retained routes with no RIB timer armed are checked again.
const RETENTION_RECHECK: std::time::Duration = std::time::Duration::from_secs(30);

/// The discovery actor, its events, and one entry per interface-only
/// neighbor, by interface name.
pub(crate) struct Unnumbered {
    discovery: RaDiscovery,
    events: Option<mpsc::UnboundedReceiver<DiscoveryEvent>>,
    ports: BTreeMap<String, Port>,
    reconcile_due: bool,
    /// A bound session did not answer its state query: reconcile again then.
    retry_at: Option<tokio::time::Instant>,
}

/// The owner's view of configured interface-only neighbors: whether the port
/// set needs reconciling with `current_config`, and how Router Advertisement
/// discovery opens when the first one arrives after startup. Tests replace
/// `probe` and `spawn`.
pub(crate) struct UnnumberedRuntime {
    /// `current_config` was replaced since the port set last followed it.
    pub(crate) config_due: bool,
    /// The discovery actor could not be started: try again then.
    spawn_retry_at: Option<tokio::time::Instant>,
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
            )
                -> Result<(RaDiscovery, mpsc::UnboundedReceiver<DiscoveryEvent>), String>
            + Send
            + Sync,
    >,
}

impl Default for UnnumberedRuntime {
    fn default() -> Self {
        Self {
            config_due: false,
            spawn_retry_at: None,
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
struct Port {
    /// Discovery's current binding.
    desired: Option<Endpoint>,
    /// The link state last passed to discovery.
    link: Option<(u32, LinkState)>,
    /// The peer created for the binding.
    bound: Option<PeerKey>,
    /// The bound peer's session is Established.
    established: bool,
    /// The address last refused, so the refusal is logged once.
    refused: Option<Ipv6Addr>,
    /// Operator and safety state carried from a retired endpoint to the next.
    held: Option<HeldState>,
    /// The neighbor's RIB identity, allocated at its first binding and kept
    /// across every later endpoint: an address change is a session down and
    /// up under the same `PeerId`. Released when configuration deletes the
    /// neighbor.
    rib_peer: Option<rustbgpd_rib::PeerId>,
    /// The bind-time settings the bound peer was created with; a change
    /// rebinds it.
    settings: Option<BindTimeProjection>,
    /// A conditional retirement of the bound session went unanswered: it may
    /// still have shut the session down, which reports nothing. Settled by
    /// reading the session before the binding is trusted again.
    retire_unsettled: bool,
    /// The bound session was shut down, to release the address or by a late
    /// conditional retirement. Either may follow a GR teardown, so the
    /// stopped peer keeps the address until the RIB retains nothing from it
    /// or a binding elsewhere is installed. A new session installed for the
    /// peer, such as an inbound reconnect, clears it.
    stopped_retained: bool,
    /// The address the neighbor was last bound to, so a binding to another
    /// one counts as an address change.
    last_address: Option<Ipv6Addr>,
    /// Why the neighbor's endpoint is being removed or added, for the
    /// presence event of the change in progress.
    presence_reason: Option<&'static str>,
}

/// State of an interface-only neighbor that belongs to the neighbor, not to
/// one learned endpoint: an operator disable and a max-prefix shutdown latch
/// (with its restart deadline) survive carrier loss, interface recreation
/// and a change of learned address.
#[derive(Debug)]
struct HeldState {
    enabled: bool,
    /// The configured `admin_down` the retired peer ran under. A rebind
    /// keeps the operator's toggle only while this is unchanged, as
    /// `lifecycle::config_admin_enable` does for a static neighbor.
    config_admin_down: bool,
    /// An operator's RFC 8326 graceful-shutdown advertisement, replayed on
    /// the next peer as a static neighbor's reconfigure does.
    graceful_shutdown: bool,
    latch: Option<super::MaxPrefixLatch>,
}

impl Unnumbered {
    /// Take ownership of a spawned discovery actor.
    pub(crate) fn new(
        discovery: RaDiscovery,
        events: mpsc::UnboundedReceiver<DiscoveryEvent>,
    ) -> Self {
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
                    // An Established peer learned from an inbound connection
                    // is unknown to discovery, which reports no conflict when
                    // a second router's RA arrives: its first binding is that
                    // router. Discovery had no binding, so this is the only
                    // count.
                    if previous.is_none()
                        && port.established
                        && let (Some(bound), Some(current)) = (&port.bound, current)
                        && bound.address != IpAddr::V6(current.address)
                    {
                        warn!(
                            %interface, bound = %bound.address, other = %current.address,
                            reason = "multiple_routers_on_link",
                            "unnumbered: a second router advertises on an interface-only link"
                        );
                        self.metrics.record_unnumbered_ra_conflict(
                            &rustbgpd_telemetry::interface_peer_label(&interface),
                        );
                    }
                    port.desired = current;
                    unnumbered.reconcile_due = true;
                }
            }
            DiscoveryEvent::CandidateLearned { interface, address } => {
                info!(%interface, %address, "unnumbered: peer address learned");
            }
            DiscoveryEvent::CandidateExpired { interface, address } => {
                info!(%interface, %address, "unnumbered: peer address expired");
            }
            DiscoveryEvent::Conflict {
                interface,
                bound,
                other,
            } => {
                warn!(
                    %interface, %bound, %other,
                    reason = "multiple_routers_on_link",
                    "unnumbered: a second router advertises on an interface-only link"
                );
                self.metrics.record_unnumbered_ra_conflict(
                    &rustbgpd_telemetry::interface_peer_label(&interface),
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
            unnumbered.discovery.session_established(name);
        } else if old == SessionState::Established {
            port.established = false;
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
        unnumbered.discovery.session_failed(name);
        unnumbered.reconcile_due = true;
    }

    /// The bound peer's session state now, read from the session itself:
    /// the decision to replace it never rests on an edge event that may have
    /// been dropped. `None` when the session did not answer in time.
    // ponytail: one bounded query per port that needs replacing, run in turn
    // on the owner loop, so N stalled sessions cost up to N x 500 ms; join
    // the queries if fabrics ever replace many ports at once.
    async fn bound_session_established(&self, peer: &PeerKey) -> Option<bool> {
        let Some(managed) = self.peers.get(peer) else {
            return Some(false);
        };
        match managed
            .handle()
            .query_state_outcome(BOUND_STATE_QUERY_TIMEOUT)
            .await
        {
            rustbgpd_transport::StateQueryOutcome::State(state) => {
                Some(state.fsm_state == SessionState::Established)
            }
            rustbgpd_transport::StateQueryOutcome::TimedOut => None,
            rustbgpd_transport::StateQueryOutcome::SessionGone => Some(false),
        }
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
    /// unanswered command keeps the binding and retries: it may still run
    /// later, and the retry's command then finds the session gone.
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
        let handle = managed.handle();
        let outcome = if spare_handshake {
            handle
                .shutdown_unless_connected_timeout(BOUND_STATE_QUERY_TIMEOUT)
                .await
        } else {
            handle
                .shutdown_unless_established_timeout(BOUND_STATE_QUERY_TIMEOUT)
                .await
        };
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
                    unnumbered.discovery.session_established(name);
                }
                self.port_mut(name).established = true;
                false
            }
            Err(error) => {
                warn!(interface = %name, peer = %key, %error, "unnumbered: bound session did not answer the retirement check; retrying");
                self.port_mut(name).retire_unsettled = true;
                self.arm_unnumbered_retry();
                false
            }
        }
    }

    /// Whether an unanswered retirement ended the bound session since: the
    /// read queues behind that command, so it settles the outcome. `false`
    /// with nothing unsettled, and on a `lost` link, which ends the session
    /// unconditionally without reading it (it may never answer). `None`
    /// (retry armed) when still unanswered.
    async fn settle_retirement(&mut self, name: &str, peer: &PeerKey, lost: bool) -> Option<bool> {
        if lost || !self.port_mut(name).retire_unsettled {
            return Some(false);
        }
        let outcome = match self.peers.get(peer) {
            None => rustbgpd_transport::StateQueryOutcome::SessionGone,
            Some(managed) => {
                managed
                    .handle()
                    .query_state_outcome(BOUND_STATE_QUERY_TIMEOUT)
                    .await
            }
        };
        let exited = match outcome {
            rustbgpd_transport::StateQueryOutcome::State(_) => false,
            rustbgpd_transport::StateQueryOutcome::SessionGone => true,
            rustbgpd_transport::StateQueryOutcome::TimedOut => {
                self.arm_unnumbered_retry();
                return None;
            }
        };
        self.port_mut(name).retire_unsettled = false;
        Some(exited)
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

    /// A peer left the table: a refused binding may now be admissible.
    pub(super) fn note_peer_removed(&mut self) {
        if let Some(unnumbered) = self.unnumbered.as_mut()
            && unnumbered.ports.values().any(|port| port.refused.is_some())
        {
            unnumbered.reconcile_due = true;
        }
    }

    /// The interface-only neighbor whose bound peer holds `address`, other
    /// than `peer` itself. Static admission refuses such an address.
    pub(super) fn unnumbered_holder_of(&self, address: IpAddr, peer: &PeerKey) -> Option<&str> {
        self.unnumbered
            .as_ref()?
            .ports
            .iter()
            .find_map(|(name, port)| {
                port.bound
                    .as_ref()
                    .is_some_and(|bound| bound.address == address && bound != peer)
                    .then_some(name.as_str())
            })
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
                if let Some(latch) = port.held.as_ref().and_then(|held| held.latch.as_ref()) {
                    super::snapshot::apply_max_prefix_latch(
                        &mut info,
                        &latch.error,
                        latch.deadline,
                    );
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

    /// Any neighbor already holding `address`: a peer in the table (bound
    /// interface-only, static, or retained), a configured static neighbor,
    /// or a static neighbor of a reload generation that passed its preflight.
    fn link_local_address_holder(&self, address: Ipv6Addr) -> Option<String> {
        let v6 = address;
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
            .or_else(|| {
                self.generation_held(v6)
                    .map(|label| format!("{label} (reload pending)"))
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

    /// The held generation applied or was refused: admission sees only the
    /// peer table and `current_config` again, and a binding the hold refused
    /// is reconsidered.
    pub(super) fn release_generation_hold(&mut self) {
        if self.unnumbered_runtime.generation_hold.take().is_some() {
            self.note_peer_removed();
        }
    }

    /// Check a candidate configuration before it takes effect anywhere:
    /// the first interface-only neighbor needs the link monitor and
    /// `CAP_NET_RAW` (ADR-0142 "Privilege"), and a static link-local neighbor
    /// it adds must not take an address a learned endpoint holds, bound or
    /// reserved ("Same-address neighbors"). The error names the cause.
    pub(super) fn unnumbered_preflight(
        &self,
        candidate: &crate::config::Config,
    ) -> Result<(), String> {
        for neighbor in &candidate.neighbors {
            let Ok(IpAddr::V6(address)) = neighbor.address.parse::<IpAddr>() else {
                continue;
            };
            if !address.is_unicast_link_local() {
                continue;
            }
            let key = PeerKey::new(IpAddr::V6(address), neighbor.interface.clone());
            // The exact key counts too: a static neighbor replacing an
            // interface-only stanza at its learned address on the same
            // interface would meet the still-bound peer after the effects.
            let holder = self.unnumbered.as_ref().and_then(|unnumbered| {
                unnumbered.ports.iter().find_map(|(name, port)| {
                    port.bound
                        .as_ref()
                        .is_some_and(|bound| bound.address == IpAddr::V6(address))
                        .then_some(name.as_str())
                })
            });
            if let Some(holder) = holder {
                return Err(format!(
                    "duplicate_link_local_address: neighbor {key} uses {address}, which the \
                     interface-only neighbor on {holder} holds; remove that neighbor first"
                ));
            }
        }
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
    pub(super) async fn reconcile_unnumbered(&mut self) {
        if self.unnumbered_runtime.config_due && !self.config_snapshot_staged {
            self.unnumbered_runtime.config_due = false;
            self.sync_unnumbered_ports().await;
        }
        let Some(unnumbered) = self.unnumbered.as_mut() else {
            return;
        };
        unnumbered.reconcile_due = false;
        let names: Vec<String> = unnumbered.ports.keys().cloned().collect();
        for name in names {
            self.reconcile_port(&name).await;
        }
    }

    /// Add, remove and rebind ports against `current_config`.
    async fn sync_unnumbered_ports(&mut self) {
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
            match configured.get(name) {
                None => self.remove_port(name).await,
                Some(settings) => {
                    self.rebind_reconfigured_port(name, settings.as_ref()).await;
                }
            }
        }
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
        let Some(port) = self
            .unnumbered
            .as_mut()
            .and_then(|unnumbered| unnumbered.ports.remove(name))
        else {
            return;
        };
        info!(interface = %name, "unnumbered: interface-only neighbor removed");
        if let Some(key) = port.bound.clone() {
            self.drain_ready_session_notifications(Some(&key)).await;
            // The port is gone, so the deletion releases the RIB identity.
            match self.delete_peer(key.clone(), false).await {
                Ok(_) | Err(PeerLifecycleError::NotFound(_)) => {}
                Err(error) => {
                    warn!(interface = %name, peer = %key, %error, "unnumbered: could not remove the deleted neighbor's peer; retrying");
                    if let Some(unnumbered) = self.unnumbered.as_mut() {
                        unnumbered.ports.insert(name.to_owned(), port);
                    }
                    self.arm_unnumbered_retry();
                    return;
                }
            }
            if self.max_prefix_latches.contains_key(&key) {
                self.remove_max_prefix_latch(&key);
            }
        } else if let Some(rib_peer) = port.rib_peer {
            self.release_unused_rib_peer(rib_peer).await;
        }
        if let Some(unnumbered) = self.unnumbered.as_mut() {
            unnumbered.discovery.stop(name);
        }
    }

    fn port_mut(&mut self, name: &str) -> &mut Port {
        self.unnumbered
            .as_mut()
            .and_then(|unnumbered| unnumbered.ports.get_mut(name))
            .expect("reconciled port exists")
    }

    async fn reconcile_port(&mut self, name: &str) {
        let port = self.port_mut(name);
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
            // A session that an unanswered retirement ended is a stopped
            // peer: it may have failed with GR before its late shutdown ran.
            // A binding elsewhere replaces it, purging that retention; with
            // none, its address waits on the retention.
            let lost = link_down || recreated;
            let Some(exited) = self.settle_retirement(name, &key, lost).await else {
                return;
            };
            if exited && !lost {
                self.port_mut(name).stopped_retained = true;
            }
            if !lost && !self.confirm_still_stopped(name, &key).await {
                return;
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
                return;
            }
            // A lost binding keeps the peer; a new one never displaces an
            // Established session; confirmed carrier loss or interface
            // recreation always ends it.
            let gone = lost || stopped;
            let keep = !gone && (desired.is_none() || same_endpoint || established);
            if keep {
                if desired.is_none() && !established {
                    self.release_unless_retained(name, key).await;
                }
                return;
            }
            // Replacing the endpoint binds from `current_config`; wait out a
            // staged transaction. Teardown on a lost link reads no config.
            if !gone && self.defer_unnumbered_while_staged() {
                return;
            }
            // Level-triggered check of what the edge events claimed.
            if !gone && !self.bound_session_down(name, &key).await {
                return;
            }
            let reason = retire_reason(link, recreated, stopped);
            if !self.retire_bound_peer(name, key, reason, !gone).await {
                return;
            }
        }
        if link_down {
            return;
        }
        let Some(endpoint) = desired else {
            return;
        };
        if self.defer_unnumbered_while_staged() {
            return;
        }
        if let Some(holder) = self.link_local_address_holder(endpoint.address) {
            let port = self.port_mut(name);
            if port.refused != Some(endpoint.address) {
                port.refused = Some(endpoint.address);
                warn!(
                    interface = %name,
                    address = %endpoint.address,
                    holder = %holder,
                    reason = "duplicate_link_local_address",
                    "unnumbered: refusing a learned address another neighbor holds"
                );
            }
            // A reload route that ends without dispatching its generation
            // drops the hold silently; ask again.
            if self.generation_held(endpoint.address).is_some() {
                self.arm_unnumbered_retry();
            }
            return;
        }
        self.port_mut(name).refused = None;
        if let Err(error) = self.bind_port(name, endpoint).await {
            // Nothing else re-raises this binding (refreshed RAs and an
            // unchanged link emit no event), so retry on the timer.
            warn!(interface = %name, address = %endpoint.address, %error, "unnumbered: could not add the bound peer; retrying");
            self.arm_unnumbered_retry();
        }
    }

    /// Whether the bound session is down, read from the session itself. An
    /// Established session is recorded and reported to discovery. No answer
    /// keeps it, claims nothing to discovery, and asks again shortly.
    async fn bound_session_down(&mut self, name: &str, key: &PeerKey) -> bool {
        match self.bound_session_established(key).await {
            Some(true) => {
                if let Some(unnumbered) = self.unnumbered.as_mut() {
                    unnumbered.discovery.session_established(name);
                }
                self.port_mut(name).established = true;
                false
            }
            None => {
                self.arm_unnumbered_retry();
                false
            }
            Some(false) => true,
        }
    }

    /// ADR-0142: an unbound neighbor whose session is down keeps its last
    /// address reserved only while the RIB retains GR or LLGR stale routes
    /// from it. Once that retention ends, by a purge or its timers, the peer
    /// is removed: the redial ends and the address is released. Retained, it
    /// is checked again at the RIB's next timer, which sweeps the routes or
    /// promotes them to LLGR.
    async fn release_unless_retained(&mut self, name: &str, key: PeerKey) {
        if !self.port_mut(name).stopped_retained {
            if !self.bound_session_quiet(name, &key).await {
                return;
            }
            // The session answered the read only after sending its
            // teardown's GR or PeerDown to the RIB, so this query, queued
            // behind it, sees the retention that teardown left.
            if self.retained_until_next_check(name, &key).await {
                return;
            }
            if !self.shut_down_unless_established(name, &key, true).await {
                return;
            }
            // The session may have established and failed with GR between
            // the check and the shutdown; the second query, queued behind
            // that teardown, sees it.
            self.port_mut(name).stopped_retained = true;
        }
        if self.retained_until_next_check(name, &key).await {
            return;
        }
        self.retire_bound_peer(name, key, "binding_expired", false)
            .await;
    }

    /// Whether the bound session has no connection past TCP: Idle, Connect,
    /// Active or gone. An Established session is recorded and reported to
    /// discovery. An `OpenSent` or `OpenConfirm` session is a live router mid-
    /// handshake, such as an inbound connection learned without an RA; its
    /// outcome reports itself. No answer retries shortly.
    async fn bound_session_quiet(&mut self, name: &str, key: &PeerKey) -> bool {
        let Some(managed) = self.peers.get(key) else {
            return true;
        };
        match managed
            .handle()
            .query_state_outcome(BOUND_STATE_QUERY_TIMEOUT)
            .await
        {
            rustbgpd_transport::StateQueryOutcome::State(state) => match state.fsm_state {
                SessionState::Established => {
                    if let Some(unnumbered) = self.unnumbered.as_mut() {
                        unnumbered.discovery.session_established(name);
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
        }
    }

    /// A stopped peer stays stopped until a new session is installed for
    /// it, such as an inbound reconnect: a session that answers clears the
    /// mark, and the ordinary checks then apply to it. `false` (retry
    /// armed) when the session did not answer.
    async fn confirm_still_stopped(&mut self, name: &str, key: &PeerKey) -> bool {
        if !self.port_mut(name).stopped_retained {
            return true;
        }
        let Some(managed) = self.peers.get(key) else {
            return true;
        };
        match managed
            .handle()
            .query_state_outcome(BOUND_STATE_QUERY_TIMEOUT)
            .await
        {
            rustbgpd_transport::StateQueryOutcome::State(_) => {
                self.port_mut(name).stopped_retained = false;
                true
            }
            rustbgpd_transport::StateQueryOutcome::SessionGone => true,
            rustbgpd_transport::StateQueryOutcome::TimedOut => {
                self.arm_unnumbered_retry();
                false
            }
        }
    }

    /// Whether the RIB still retains the bound peer's GR or LLGR routes.
    /// Retained, the next check is armed at the RIB's next timer, which
    /// sweeps them or promotes them to LLGR; no answer retries shortly.
    async fn retained_until_next_check(&mut self, name: &str, key: &PeerKey) -> bool {
        let Some(retention) = self.bound_peer_retention(key).await else {
            self.arm_unnumbered_retry();
            return true;
        };
        if retention.stale_routes == 0 {
            return false;
        }
        let now = tokio::time::Instant::now();
        let at = retention
            .next_deadline
            .unwrap_or(now + RETENTION_RECHECK)
            .max(now + RECONCILE_RETRY);
        debug!(interface = %name, peer = %key, stale_routes = retention.stale_routes, "unnumbered: unbound neighbor keeps its address while its routes are retained");
        self.arm_unnumbered_retry_at(at);
        true
    }

    /// The RIB's GR/LLGR retention for the bound peer's identity; `None`
    /// when the RIB did not answer in time.
    pub(super) async fn bound_peer_retention(
        &mut self,
        key: &PeerKey,
    ) -> Option<rustbgpd_rib::PeerRetention> {
        let (reply, response) = tokio::sync::oneshot::channel();
        let request = rustbgpd_rib::RibUpdate::QueryPeerRetention {
            peer: self.rib_peer_of(key),
            reply,
        };
        let rib_tx = self.rib_tx.clone();
        let round_trip = tokio::time::timeout(BOUND_STATE_QUERY_TIMEOUT, async move {
            rib_tx.send(request).await.ok()?;
            response.await.ok()
        });
        self.await_with_readiness(round_trip, super::OperatorReadAdmission::Served)
            .await
            .ok()
            .flatten()
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
        info!(interface = %name, peer = %key, reason, "unnumbered: ending the bound session");
        self.port_mut(name).presence_reason = Some(reason);
        // Apply what the session already reported, such as a max-prefix
        // shutdown queued as it went Idle, before capturing the state that
        // outlives it; the deletion below would otherwise apply and discard it.
        self.drain_ready_session_notifications(Some(&key)).await;
        // The neighbor's operator and safety state outlives the endpoint.
        let held = HeldState {
            enabled: self.peers.get(&key).is_none_or(|managed| managed.enabled),
            config_admin_down: self
                .peers
                .get(&key)
                .is_some_and(|managed| managed.admin_down.is_some()),
            graceful_shutdown: self
                .peers
                .get(&key)
                .is_some_and(|managed| managed.advertise_graceful_shutdown),
            latch: self.max_prefix_latches.remove(&key),
        };
        let deleted = self.delete_peer(key.clone(), false).await;
        self.port_mut(name).presence_reason = None;
        match deleted {
            // Already gone: nothing is left to clear.
            Ok(_) | Err(PeerLifecycleError::NotFound(_)) => {}
            Err(error) => {
                if let Some(latch) = held.latch {
                    self.max_prefix_latches.insert(key.clone(), latch);
                }
                warn!(interface = %name, peer = %key, %error, "unnumbered: could not remove the bound peer");
                return false;
            }
        }
        if held.latch.is_some() {
            self.publish_max_prefix_latched_metric(&key, false);
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
        // The endpoint's BFD session goes with it. Left disabled by the
        // deletion when this cannot run now; the next membership change
        // prunes it.
        if let Err(error) = self.set_bound_bfd_session(key.address, None).await {
            warn!(interface = %name, peer = %key, %error, "unnumbered: could not remove the bound BFD session yet");
        }
        let port = self.port_mut(name);
        port.bound = None;
        port.established = false;
        port.retire_unsettled = false;
        port.stopped_retained = false;
        port.held = Some(held);
        let previous = port.last_address.map(|address| address.to_string());
        self.metrics.set_unnumbered_peer_address(
            &rustbgpd_telemetry::interface_peer_label(name),
            name,
            previous.as_deref(),
            None,
        );
        // The retired session's queued reports have been drained by
        // now; an Established among them must not outlive it.
        if let Some(unnumbered) = self.unnumbered.as_mut() {
            unnumbered.discovery.session_failed(name);
        }
        true
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
            .record_unnumbered_ra_conflict(&rustbgpd_telemetry::interface_peer_label(name));
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

    /// Another neighbor holds `address`: log the refusal and count it.
    fn inbound_address_held(&self, name: &str, address: Ipv6Addr) -> bool {
        let Some(holder) = self.link_local_address_holder(address) else {
            return false;
        };
        warn!(
            interface = %name, %address, %holder,
            reason = "duplicate_link_local_address",
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
    /// backoff, and when another neighbor holds the address
    /// (`duplicate_link_local_address`). A bound session that has not
    /// reached `OpenSent` is retired: the peer moved address.
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
        if let Some(key) = port.bound.clone()
            && key.address == IpAddr::V6(address)
        {
            return Some(key);
        }
        // Checked before the current endpoint is retired, so a refused
        // address leaves the port bound, and again just before binding.
        if self.inbound_address_held(name, address) {
            return None;
        }
        if let Some(key) = port.bound.clone() {
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
                Some(managed) => match managed
                    .handle()
                    .query_state_outcome(BOUND_STATE_QUERY_TIMEOUT)
                    .await
                {
                    rustbgpd_transport::StateQueryOutcome::State(state) => Some(state),
                    rustbgpd_transport::StateQueryOutcome::SessionGone => None,
                    rustbgpd_transport::StateQueryOutcome::TimedOut => {
                        info!(interface = %name, %address, peer = %key, "unnumbered: bound session did not report its state; dropping the inbound connection (remote will retry)");
                        return self.refuse_inbound();
                    }
                },
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
        if self.inbound_address_held(name, address) {
            return None;
        }
        let endpoint = Endpoint { address, ifindex };
        if let Err(error) = self.bind_port(name, endpoint).await {
            warn!(interface = %name, %address, %error, "unnumbered: could not add the peer learned from an inbound connection");
            return self.refuse_inbound();
        }
        info!(interface = %name, %address, "unnumbered: peer address learned from an inbound connection");
        self.port_mut(name).bound.clone()
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
        // Restart-eligible like configured neighbors: during a planned
        // restart's window the OPEN carries R=1, so helpers keep the routes
        // they retained; after the window it carries R=0.
        Ok((
            neighbor,
            Self::peer_manager_config_from_resolved(resolved, true),
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
            .current_config
            .conditional_advertisement_set_with_bindings(&bindings)
            .map_err(|error| PeerLifecycleError::Invalid(error.to_string()))?;
        self.install_conditional_advertisements(set, &[])
            .await
            .map_err(PeerLifecycleError::Internal)?;
        Ok(true)
    }

    async fn bind_port(
        &mut self,
        name: &str,
        endpoint: Endpoint,
    ) -> Result<(), PeerLifecycleError> {
        let (neighbor, config) = self.bound_peer_config(name, endpoint)?;
        let key = PeerKey::new(IpAddr::V6(endpoint.address), Some(name.to_owned()));
        // The binding's BFD session exists before its peer, so a strict peer
        // is added withheld until BFD is Up on this endpoint (ADR-0142).
        let bfd = crate::bfd_runtime::bound_session_params(
            &self.current_config,
            &neighbor,
            name,
            endpoint.address,
            endpoint.ifindex,
        )
        .map_err(|error| PeerLifecycleError::Invalid(error.to_string()))?;
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
        // The neighbor keeps its RIB identity across endpoints. The RIB moves
        // it to the new endpoint, in order after the previous binding's
        // deletion and before the new session's first message. Always sent:
        // the table may not yet reflect a rebind still queued to the RIB,
        // whose handler skips an unchanged endpoint in its own order.
        let rib_peer = self.port_mut(name).rib_peer;
        if let Some(rib_peer) = rib_peer {
            self.rib_peers.insert(
                key.clone(),
                rustbgpd_transport::RibPeerSlot::assigned(rib_peer),
            );
            let next = rustbgpd_rib::PeerEndpoint::new(IpAddr::V6(endpoint.address), Some(name));
            if self
                .send_rib_update(
                    rustbgpd_rib::RibUpdate::RebindPeer {
                        peer: rib_peer,
                        endpoint: next,
                    },
                    super::OperatorReadAdmission::Fenced {
                        reason: "an interface-only neighbor is changing endpoint",
                    },
                )
                .await
                .is_err()
            {
                self.rib_peers.remove(&key);
                self.port_mut(name).held = held;
                self.conditional_reconcile_pending |= gated;
                if has_bfd {
                    let _ = self.set_bound_bfd_session(key.address, None).await;
                }
                return Err(PeerLifecycleError::Internal(
                    "RIB channel closed while rebinding the neighbor".into(),
                ));
            }
        }
        self.note_binding_reason(name, endpoint.address);
        let added = self.add_peer_impl(config, false, enabled, true).await;
        self.port_mut(name).presence_reason = None;
        if let Err(error) = added {
            if carried_latch {
                self.remove_max_prefix_latch(&key);
            }
            if rib_peer.is_some() {
                self.rib_peers.remove(&key);
            }
            self.port_mut(name).held = held;
            // The gate installed above names an endpoint with no peer.
            self.conditional_reconcile_pending |= gated;
            if has_bfd {
                let _ = self.set_bound_bfd_session(key.address, None).await;
            }
            return Err(error);
        }
        info!(interface = %name, peer = %key, enabled, "unnumbered: bound peer added");
        // Best-effort, like a static neighbor's reconfigure replay.
        if held.as_ref().is_some_and(|held| held.graceful_shutdown)
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
        Ok(())
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
