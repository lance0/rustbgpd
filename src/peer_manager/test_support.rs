use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use rustbgpd_fsm::SessionState;
use rustbgpd_transport::handle::MaxPrefixState;
use rustbgpd_transport::{PeerCommand, PeerHandle, PeerSessionState};
use tokio::sync::{Notify, mpsc};

use super::{ManagedPeer, ManagedPeerState, PeerManager};
use crate::config::ResolvedNeighbor;

#[derive(Clone, Default)]
pub(crate) struct EstablishedPolicyPeerAcks {
    state_queries: Arc<AtomicU32>,
    import_updates: Arc<AtomicU32>,
    export_updates: Arc<AtomicU32>,
    route_refreshes: Arc<AtomicU32>,
    exited: Arc<AtomicBool>,
    exit_notify: Arc<Notify>,
    /// Report a negotiated session that has Route Refresh until the first
    /// refresh is answered, and lacks it afterwards: the peer reconnected
    /// without the capability after taking the chain.
    lose_route_refresh: bool,
    import_chains: Arc<std::sync::Mutex<Vec<Option<rustbgpd_policy::PolicyChain>>>>,
    /// For each administrative reset, how many import chains the session had
    /// installed when the reset arrived.
    resets: Arc<std::sync::Mutex<Vec<usize>>>,
    reset_notify: Arc<Notify>,
    /// The session's command queue, held weakly so the session still exits
    /// when the peer manager drops its handle.
    commands: Arc<std::sync::OnceLock<mpsc::WeakSender<PeerCommand>>>,
}

impl EstablishedPolicyPeerAcks {
    pub(crate) fn state_queries(&self) -> u32 {
        self.state_queries.load(Ordering::SeqCst)
    }

    pub(crate) fn import_updates(&self) -> u32 {
        self.import_updates.load(Ordering::SeqCst)
    }

    pub(crate) fn export_updates(&self) -> u32 {
        self.export_updates.load(Ordering::SeqCst)
    }

    pub(crate) fn import_chains(&self) -> Vec<Option<rustbgpd_policy::PolicyChain>> {
        self.import_chains.lock().unwrap().clone()
    }

    /// The resets the session has handled, once it has handled `count`. A
    /// reset is only admitted to the session's queue, so this is the
    /// handshake that orders a read after it.
    pub(crate) async fn resets_after(&self, count: usize) -> Vec<usize> {
        loop {
            let notified = self.reset_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let resets = self.resets.lock().unwrap().clone();
            if resets.len() >= count {
                return resets;
            }
            notified.await;
        }
    }

    /// The resets the session has handled, read once it has answered a state
    /// query sent behind every command already queued. A reset is only
    /// admitted to the session's queue, so this orders the read after any
    /// reset queued before the call.
    pub(crate) async fn resets_once_drained(&self) -> Vec<usize> {
        let commands = self
            .commands
            .get()
            .and_then(mpsc::WeakSender::upgrade)
            .expect("the session is running");
        PeerHandle::query_state_with(commands, std::time::Duration::from_secs(5))
            .await
            .expect("the session answers behind its queued commands");
        self.resets.lock().unwrap().clone()
    }

    pub(crate) fn route_refreshes(&self) -> u32 {
        self.route_refreshes.load(Ordering::SeqCst)
    }

    pub(crate) async fn wait_for_exit(&self) {
        loop {
            let notified = self.exit_notify.notified();
            tokio::pin!(notified);
            // Register before observing the flag so `notify_waiters` cannot
            // land between the state check and this waiter becoming visible.
            notified.as_mut().enable();
            if self.exited.load(Ordering::SeqCst) {
                return;
            }
            notified.await;
        }
    }
}

/// The negotiated session a capability-reporting test session answers with.
fn negotiated_session(route_refresh: bool) -> rustbgpd_transport::NegotiatedSessionState {
    rustbgpd_transport::NegotiatedSessionState {
        local_address: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        hold_time: 90,
        keepalive_interval: 30,
        remote_router_id: Ipv4Addr::new(192, 0, 2, 1),
        four_octet_as: true,
        families: vec![(rustbgpd_wire::Afi::Ipv4, rustbgpd_wire::Safi::Unicast)],
        add_path_receive_families: Vec::new(),
        peer_route_refresh: route_refresh,
        peer_enhanced_route_refresh: false,
        peer_extended_message: false,
        outbound_max_message_bytes: rustbgpd_wire::MAX_MESSAGE_LEN,
        graceful_restart: None,
    }
}

fn established_policy_handle(peer: IpAddr, acks: EstablishedPolicyPeerAcks) -> PeerHandle {
    let (command_tx, mut command_rx) = mpsc::channel(8);
    let _ = acks.commands.set(command_tx.downgrade());
    let task = tokio::spawn(async move {
        let mut route_refresh = true;
        let mut current_import = None;
        while let Some(command) = command_rx.recv().await {
            match command {
                PeerCommand::QueryState { reply } => {
                    acks.state_queries.fetch_add(1, Ordering::SeqCst);
                    let negotiated_session = acks
                        .lose_route_refresh
                        .then(|| negotiated_session(route_refresh));
                    let _ = reply.send(PeerSessionState {
                        fsm_state: SessionState::Established,
                        peer_ip: peer,
                        peer_asn: None,
                        prefix_count: 0,
                        rejected_routes_retained: 0,
                        policy_reject_counts: None,
                        pre_policy_route_counts: None,
                        max_prefix: MaxPrefixState::default(),
                        negotiated_hold_time: None,
                        four_octet_as: None,
                        remote_router_id: Some(Ipv4Addr::UNSPECIFIED),
                        negotiated_session,
                        local_role: None,
                        remote_role: None,
                        role_negotiated: false,
                        peer_paths_limits: Vec::new(),
                        effective_add_path_send_limits: Vec::new(),
                        updates_received: 0,
                        updates_sent: 0,
                        notifications_received: 0,
                        notifications_sent: 0,
                        messages_received: 0,
                        messages_sent: 0,
                        flap_count: 0,
                        uptime_secs: 1,
                        last_error: String::new(),
                        last_error_unix_ms: 0,
                        tcp_ao_info: None,
                        tcp_ao_protected: false,
                        otc_routes_blocked: 0,
                        import_policy_routes_permitted: 0,
                        import_policy_routes_denied: 0,
                        slow_peer: false,
                        reconnect_in_secs: 0,
                        notification_idle_failures: 0,
                    });
                }
                PeerCommand::UpdateImportPolicy {
                    policy,
                    install,
                    reply,
                } => {
                    acks.import_updates.fetch_add(1, Ordering::SeqCst);
                    let policy = policy.map(|chain| *chain);
                    let changed = current_import.as_ref() != Some(&policy);
                    if acks.lose_route_refresh && install.refused(true, route_refresh, changed) {
                        let _ = reply.send(Err(
                            rustbgpd_transport::PeerCommandError::RouteRefreshUnsupported,
                        ));
                        continue;
                    }
                    acks.import_chains.lock().unwrap().push(policy.clone());
                    current_import = Some(policy);
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::UpdateExportPolicy { reply, .. } => {
                    acks.export_updates.fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::SendRouteRefresh { reply, .. } => {
                    acks.route_refreshes.fetch_add(1, Ordering::SeqCst);
                    if !route_refresh {
                        let _ = reply.send(Err(
                            rustbgpd_transport::PeerCommandError::RouteRefreshUnsupported,
                        ));
                        continue;
                    }
                    route_refresh = !acks.lose_route_refresh;
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::AdministrativeReset { .. } => {
                    let installed = acks.import_chains.lock().unwrap().len();
                    acks.resets.lock().unwrap().push(installed);
                    acks.reset_notify.notify_waiters();
                }
                PeerCommand::Shutdown | PeerCommand::Stop { .. } | PeerCommand::CollisionDump => {
                    break;
                }
                _ => {}
            }
        }
        acks.exited.store(true, Ordering::SeqCst);
        acks.exit_notify.notify_waiters();
        Ok(())
    });
    PeerHandle::from_parts(command_tx, task)
}

impl PeerManager {
    /// Install a configured static peer backed by a deterministic Established
    /// session task. The task acknowledges the same bounded session commands
    /// used by live config-transaction policy applies; no RIB observation is
    /// fabricated here.
    pub(crate) fn install_established_policy_test_peer(
        &mut self,
        resolved: ResolvedNeighbor,
        session_id: u64,
    ) -> EstablishedPolicyPeerAcks {
        self.install_established_policy_test_peer_with(resolved, session_id, false)
    }

    /// Like [`Self::install_established_policy_test_peer`], but the session
    /// loses Route Refresh once it has answered its first refresh.
    pub(crate) fn install_established_policy_test_peer_losing_route_refresh(
        &mut self,
        resolved: ResolvedNeighbor,
        session_id: u64,
    ) -> EstablishedPolicyPeerAcks {
        self.install_established_policy_test_peer_with(resolved, session_id, true)
    }

    fn install_established_policy_test_peer_with(
        &mut self,
        resolved: ResolvedNeighbor,
        session_id: u64,
        lose_route_refresh: bool,
    ) -> EstablishedPolicyPeerAcks {
        let peer = resolved.transport_config.remote_addr.ip();
        let key = rustbgpd_api::peer_types::PeerKey::new(peer, None);
        let acks = EstablishedPolicyPeerAcks {
            lose_route_refresh,
            ..EstablishedPolicyPeerAcks::default()
        };
        let handle = established_policy_handle(peer, acks.clone());
        let remote_asn = resolved.transport_config.peer.remote_asn;
        let hold_time = resolved.transport_config.peer.hold_time;
        let max_prefixes = resolved.transport_config.max_prefixes;
        let tcp_ao_protected = resolved.transport_config.tcp_ao.is_some();
        self.peers.insert(
            key.clone(),
            ManagedPeer::new(
                handle,
                session_id,
                ManagedPeerState {
                    admin_down: None,
                    policy_known_down: false,
                    import_install_unknown: false,
                    export_install_unknown: false,
                    remote_asn,
                    description: resolved.label,
                    peer_group: resolved.peer_group,
                    enabled: true,
                    hold_time: Some(hold_time),
                    max_prefixes,
                    max_prefix_restart_seconds: resolved.max_prefix_restart_seconds,
                    transport_config: resolved.transport_config,
                    import_policy: resolved.import_policy,
                    export_policy: resolved.export_policy,
                    pending_inbound: None,
                    is_dynamic: false,
                    rfc8212_external: resolved.rfc8212_external,
                    tcp_ao_protected,
                    tcp_ao_rotation: rustbgpd_transport::TcpAoRotationStatus::default(),
                    accepted_dynamic_range: None,
                    pending_refresh: false,
                    pending_export_apply: false,
                    advertise_graceful_shutdown: false,
                },
            ),
        );
        self.register_session(session_id, &key);
        self.retain_neighbor_counters(&key);
        acks
    }
}

#[cfg(test)]
mod tests {
    use std::task::Poll;
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn exit_wait_wakes_every_registered_clone() {
        let acks = EstablishedPolicyPeerAcks::default();
        let mut first = Box::pin(acks.wait_for_exit());
        let mut second = Box::pin(acks.wait_for_exit());

        assert!(matches!(futures::poll!(first.as_mut()), Poll::Pending));
        assert!(matches!(futures::poll!(second.as_mut()), Poll::Pending));

        acks.exited.store(true, Ordering::SeqCst);
        acks.exit_notify.notify_waiters();

        tokio::time::timeout(Duration::from_secs(1), async {
            first.await;
            second.await;
        })
        .await
        .expect("every registered clone observes task exit");
    }
}
