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
//!   session is not Established. A lost binding with the link up keeps the
//!   peer: session liveness belongs to the hold timer, and the peer keeps
//!   its address reserved.
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

use crate::ra_discovery::{DiscoveryEvent, Endpoint, LinkEvent, LinkState, RaDiscovery};

use super::PeerManager;

/// How long reconciliation waits for a bound session to report its state.
const BOUND_STATE_QUERY_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);
/// How soon a reconcile is retried after a bound session did not answer.
const RECONCILE_RETRY: std::time::Duration = std::time::Duration::from_secs(1);

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
        self.unnumbered.as_ref().is_some_and(|u| u.reconcile_due)
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
            port.link = Some(current);
            debug!(interface = %name, ifindex = current.0, state = ?current.1, "unnumbered: link state");
            unnumbered.discovery.link_event(LinkEvent {
                ifindex: current.0,
                name: name.clone(),
                state: current.1,
            });
            if current.1 != LinkState::Up {
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

    /// When an unanswered state query is due to be asked again.
    pub(super) fn unnumbered_retry_at(&self) -> Option<tokio::time::Instant> {
        self.unnumbered.as_ref()?.retry_at
    }

    /// The retry deadline passed: reconcile again.
    pub(super) fn unnumbered_retry_due(&mut self) {
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

    /// The interface whose interface-only neighbor owns `peer`.
    pub(super) fn unnumbered_owner_of(&self, peer: &PeerKey) -> Option<&str> {
        self.unnumbered
            .as_ref()?
            .ports
            .iter()
            .find_map(|(name, port)| (port.bound.as_ref() == Some(peer)).then_some(name.as_str()))
    }

    /// Any neighbor already holding `address`: a peer in the table (bound
    /// interface-only, static, or retained) or a configured static neighbor.
    fn link_local_address_holder(&self, address: Ipv6Addr) -> Option<String> {
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

    /// Bring every interface-only neighbor's peer in line with its binding.
    pub(super) async fn reconcile_unnumbered(&mut self) {
        let Some(unnumbered) = self.unnumbered.as_mut() else {
            return;
        };
        unnumbered.reconcile_due = false;
        let names: Vec<String> = unnumbered.ports.keys().cloned().collect();
        for name in names {
            self.reconcile_port(&name).await;
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
        let link_down = matches!(port.link, Some((_, LinkState::Down | LinkState::Removed)));
        let (desired, bound, established) = (port.desired, port.bound.clone(), port.established);

        if let Some(key) = bound {
            let same_endpoint = desired.is_some_and(|endpoint| {
                key.address == IpAddr::V6(endpoint.address)
                    && self.peers.get(&key).is_some_and(|managed| {
                        managed.transport_config.peer_scope_id == Some(endpoint.ifindex)
                    })
            });
            // A lost binding keeps the peer; a new one never displaces an
            // Established session; confirmed carrier loss always ends it.
            let keep = !link_down && (desired.is_none() || same_endpoint || established);
            if keep {
                return;
            }
            // Level-triggered check of what the edge events claimed.
            if !link_down {
                match self.bound_session_established(&key).await {
                    Some(true) => {
                        if let Some(unnumbered) = self.unnumbered.as_mut() {
                            unnumbered.discovery.session_established(name);
                        }
                        self.port_mut(name).established = true;
                        return;
                    }
                    // No answer: keep the session, claim nothing to
                    // discovery, and ask again shortly.
                    None => {
                        if let Some(unnumbered) = self.unnumbered.as_mut() {
                            unnumbered.retry_at.get_or_insert_with(|| {
                                tokio::time::Instant::now() + RECONCILE_RETRY
                            });
                        }
                        return;
                    }
                    Some(false) => {}
                }
            }
            let reason = if link_down {
                "link_down"
            } else {
                "peer_address_changed"
            };
            info!(interface = %name, peer = %key, reason, "unnumbered: ending the bound session");
            match self.delete_peer(key.clone(), false).await {
                // Already gone: nothing is left to clear.
                Ok(_) | Err(PeerLifecycleError::NotFound(_)) => {}
                Err(error) => {
                    warn!(interface = %name, peer = %key, %error, "unnumbered: could not remove the bound peer");
                    return;
                }
            }
            let port = self.port_mut(name);
            port.bound = None;
            port.established = false;
        }
        if link_down {
            return;
        }
        let Some(endpoint) = desired else {
            return;
        };
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
            return;
        }
        self.port_mut(name).refused = None;
        if let Err(error) = self.bind_port(name, endpoint).await {
            warn!(interface = %name, address = %endpoint.address, %error, "unnumbered: could not add the bound peer");
        }
    }

    async fn bind_port(
        &mut self,
        name: &str,
        endpoint: Endpoint,
    ) -> Result<(), PeerLifecycleError> {
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
        let config = Self::peer_manager_config_from_resolved(resolved, false);
        let key = PeerKey::new(IpAddr::V6(endpoint.address), Some(name.to_owned()));
        self.add_peer(config, false).await?;
        info!(interface = %name, peer = %key, "unnumbered: bound peer added");
        self.port_mut(name).bound = Some(key);
        Ok(())
    }
}
