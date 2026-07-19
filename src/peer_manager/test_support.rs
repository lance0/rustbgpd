use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use rustbgpd_fsm::SessionState;
use rustbgpd_transport::{PeerCommand, PeerHandle, PeerSessionState};
use tokio::sync::{Notify, mpsc};

use super::{ManagedPeer, PeerManager};
use crate::config::ResolvedNeighbor;

#[derive(Clone, Default)]
pub(crate) struct EstablishedPolicyPeerAcks {
    state_queries: Arc<AtomicU32>,
    import_updates: Arc<AtomicU32>,
    export_updates: Arc<AtomicU32>,
    route_refreshes: Arc<AtomicU32>,
    exited: Arc<AtomicBool>,
    exit_notify: Arc<Notify>,
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

fn established_policy_handle(peer: IpAddr, acks: EstablishedPolicyPeerAcks) -> PeerHandle {
    let (command_tx, mut command_rx) = mpsc::channel(8);
    let task = tokio::spawn(async move {
        while let Some(command) = command_rx.recv().await {
            match command {
                PeerCommand::QueryState { reply } => {
                    acks.state_queries.fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(PeerSessionState {
                        fsm_state: SessionState::Established,
                        peer_ip: peer,
                        peer_asn: None,
                        prefix_count: 0,
                        negotiated_hold_time: None,
                        four_octet_as: None,
                        remote_router_id: Some(Ipv4Addr::UNSPECIFIED),
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
                        tcp_ao_info: None,
                        tcp_ao_protected: false,
                        otc_routes_blocked: 0,
                        import_policy_routes_permitted: 0,
                        import_policy_routes_denied: 0,
                        slow_peer: false,
                    });
                }
                PeerCommand::UpdateImportPolicy { reply, .. } => {
                    acks.import_updates.fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::UpdateExportPolicy { reply, .. } => {
                    acks.export_updates.fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(Ok(()));
                }
                PeerCommand::SendRouteRefresh { reply, .. } => {
                    acks.route_refreshes.fetch_add(1, Ordering::SeqCst);
                    let _ = reply.send(Ok(()));
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
        let peer = resolved.transport_config.remote_addr.ip();
        let key = rustbgpd_api::peer_types::PeerKey::new(peer, None);
        let acks = EstablishedPolicyPeerAcks::default();
        let handle = established_policy_handle(peer, acks.clone());
        let remote_asn = resolved.transport_config.peer.remote_asn;
        let hold_time = resolved.transport_config.peer.hold_time;
        let max_prefixes = resolved.transport_config.max_prefixes;
        let tcp_ao_protected = resolved.transport_config.tcp_ao.is_some();
        self.peers.insert(
            key.clone(),
            ManagedPeer {
                handle,
                session_id,
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
                tcp_ao_protected,
                tcp_ao_rotation: rustbgpd_transport::TcpAoRotationStatus::default(),
                accepted_dynamic_range: None,
                pending_refresh: false,
                pending_export_apply: false,
                advertise_graceful_shutdown: false,
            },
        );
        self.register_session(session_id, &key);
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
