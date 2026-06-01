use std::collections::BTreeSet;
use std::net::IpAddr;

use rustbgpd_api::peer_types::{
    ConfigEvent, POLICY_EVENT_HISTORY_CAPACITY, PeerKey, PolicyEvent,
    SESSION_EVENT_HISTORY_CAPACITY, SessionEvent, SessionLifecycleEvent, SessionLifecycleEventType,
    SessionNotificationEvent, SessionNotificationEventType,
};
use rustbgpd_event_history::Category;
use rustbgpd_fsm::SessionState;
use rustbgpd_rib::event::unix_timestamp_now;
use rustbgpd_transport::{
    SessionNotificationDirection as TransportNotificationDirection,
    SessionNotificationEvent as TransportNotificationEvent,
};
use tokio::sync::oneshot;

use super::PeerManager;

impl PeerManager {
    pub(super) fn session_event_timestamp() -> String {
        unix_timestamp_now()
    }

    pub(super) fn session_role_label(role: rustbgpd_transport::SessionRole) -> &'static str {
        match role {
            rustbgpd_transport::SessionRole::Primary => "primary",
            rustbgpd_transport::SessionRole::InboundCandidate => "inbound_candidate",
        }
    }

    pub(super) fn classify_state_event(
        old: SessionState,
        new: SessionState,
    ) -> SessionLifecycleEventType {
        if new == SessionState::Established {
            SessionLifecycleEventType::Established
        } else if old == SessionState::Established {
            SessionLifecycleEventType::Lost
        } else {
            SessionLifecycleEventType::StateChanged
        }
    }

    pub(super) fn publish_session_event(&mut self, event: SessionEvent) {
        if let SessionEvent::Lifecycle(lifecycle) = &event {
            if self.session_event_history.len() >= SESSION_EVENT_HISTORY_CAPACITY {
                self.session_event_history.pop_front();
            }
            self.session_event_history.push_back(lifecycle.clone());
        }
        // ADR-0072 durable outbox enqueue. The legacy ring +
        // broadcast surfaces above are unchanged — they back the
        // existing `WatchEvents` / `ListSessionEvents` RPCs.
        // SubscribeFromEvent is the durable cursor consumer.
        if let Some(handle) = &self.event_history {
            let peer = match &event {
                SessionEvent::Lifecycle(l) => Some(l.peer),
                SessionEvent::Notification(n) => Some(n.peer),
            };
            let proto_event =
                rustbgpd_api::event_converters::session_event_to_bgp_event(event.clone());
            let envelope = rustbgpd_api::event_history_sinks::envelope_from_bgp_event(
                &proto_event,
                Category::Session,
                peer,
                None,
            );
            rustbgpd_api::event_history_sinks::try_send_envelope(handle, &self.metrics, envelope);
        }
        let _ = self.session_events_tx.send(event);
    }

    pub(super) fn publish_lifecycle_event(&mut self, event: SessionLifecycleEvent) {
        self.publish_session_event(SessionEvent::Lifecycle(event));
    }

    pub(super) fn publish_policy_event(&mut self, event: PolicyEvent) {
        if self.policy_event_history.len() >= POLICY_EVENT_HISTORY_CAPACITY {
            self.policy_event_history.pop_front();
        }
        self.policy_event_history.push_back(event.clone());
        // ADR-0072 durable outbox enqueue; legacy ring + broadcast
        // above remain authoritative for `ListPolicyEvents` /
        // `WatchEvents`.
        if let Some(handle) = &self.event_history {
            let peer = event.peer;
            let proto_event =
                rustbgpd_api::event_converters::policy_event_to_bgp_event(event.clone());
            let envelope = rustbgpd_api::event_history_sinks::envelope_from_bgp_event(
                &proto_event,
                Category::Policy,
                peer,
                None,
            );
            rustbgpd_api::event_history_sinks::try_send_envelope(handle, &self.metrics, envelope);
        }
        let _ = self.policy_events_tx.send(event);
    }

    pub(super) fn policy_event_details(
        event: &ConfigEvent,
    ) -> (&'static str, &'static str, String, Option<IpAddr>) {
        match event {
            ConfigEvent::SetPolicy { name, .. } => ("set", "policy", name.clone(), None),
            ConfigEvent::DeletePolicy { name } => ("delete", "policy", name.clone(), None),
            ConfigEvent::SetNeighborSet { name, .. } => ("set", "neighbor_set", name.clone(), None),
            ConfigEvent::DeleteNeighborSet { name } => {
                ("delete", "neighbor_set", name.clone(), None)
            }
            ConfigEvent::SetGlobalImportChain { .. } => {
                ("set", "global_import_chain", "global".to_string(), None)
            }
            ConfigEvent::SetGlobalExportChain { .. } => {
                ("set", "global_export_chain", "global".to_string(), None)
            }
            ConfigEvent::ClearGlobalImportChain => {
                ("clear", "global_import_chain", "global".to_string(), None)
            }
            ConfigEvent::ClearGlobalExportChain => {
                ("clear", "global_export_chain", "global".to_string(), None)
            }
            ConfigEvent::SetNeighborImportChain { address, .. } => (
                "set",
                "neighbor_import_chain",
                address.to_string(),
                Some(*address),
            ),
            ConfigEvent::SetNeighborExportChain { address, .. } => (
                "set",
                "neighbor_export_chain",
                address.to_string(),
                Some(*address),
            ),
            ConfigEvent::ClearNeighborImportChain { address } => (
                "clear",
                "neighbor_import_chain",
                address.to_string(),
                Some(*address),
            ),
            ConfigEvent::ClearNeighborExportChain { address } => (
                "clear",
                "neighbor_export_chain",
                address.to_string(),
                Some(*address),
            ),
            ConfigEvent::SetPeerGroup { name, .. } => ("set", "peer_group", name.clone(), None),
            ConfigEvent::DeletePeerGroup { name } => ("delete", "peer_group", name.clone(), None),
            ConfigEvent::SetNeighborPeerGroup { address, .. } => (
                "set",
                "neighbor_peer_group",
                address.to_string(),
                Some(*address),
            ),
            ConfigEvent::ClearNeighborPeerGroup { address } => (
                "clear",
                "neighbor_peer_group",
                address.to_string(),
                Some(*address),
            ),
            ConfigEvent::DynamicNeighborAdded { prefix, .. } => {
                ("add", "dynamic_neighbor", prefix.clone(), None)
            }
            ConfigEvent::DynamicNeighborDeleted { prefix, .. } => {
                ("delete", "dynamic_neighbor", prefix.clone(), None)
            }
            ConfigEvent::NeighborAdded { .. } | ConfigEvent::NeighborDeleted { .. } => {
                ("change", "neighbor", String::new(), None)
            }
            ConfigEvent::FibTablesReplaced { .. } => {
                ("replace", "fib_tables", "fib_tables".to_string(), None)
            }
        }
    }

    pub(super) fn publish_policy_config_event(
        &mut self,
        event: &ConfigEvent,
        affected_peer_count: usize,
    ) {
        let (operation, target_type, target, peer) = Self::policy_event_details(event);
        if target_type == "neighbor" {
            return;
        }
        let reason = format!("policy {operation} {target_type} {target}");
        self.publish_policy_event(PolicyEvent {
            operation,
            target_type,
            target,
            peer,
            affected_peer_count,
            timestamp: Self::session_event_timestamp(),
            reason,
        });
    }

    pub(super) fn publish_peer_lifecycle_event(
        &mut self,
        peer: &PeerKey,
        event_type: SessionLifecycleEventType,
        reason: String,
    ) {
        self.publish_lifecycle_event(SessionLifecycleEvent {
            event_type,
            peer: peer.address,
            peer_label: Some(peer.label()),
            timestamp: Self::session_event_timestamp(),
            old_state: None,
            new_state: None,
            session_role: None,
            reason,
        });
    }

    pub(super) fn publish_state_lifecycle_event(
        &mut self,
        peer: &PeerKey,
        role: rustbgpd_transport::SessionRole,
        old: SessionState,
        new: SessionState,
    ) {
        let event_type = Self::classify_state_event(old, new);
        let peer_label = peer.label();
        let reason = match event_type {
            SessionLifecycleEventType::Established => {
                format!("session established for peer {peer_label}")
            }
            SessionLifecycleEventType::Lost => {
                format!(
                    "session lost for peer {peer_label}: {} -> {}",
                    old.as_str(),
                    new.as_str()
                )
            }
            SessionLifecycleEventType::StateChanged => {
                format!(
                    "session state changed for peer {peer_label}: {} -> {}",
                    old.as_str(),
                    new.as_str()
                )
            }
            SessionLifecycleEventType::PeerEnabled | SessionLifecycleEventType::PeerDisabled => {
                unreachable!("peer lifecycle events are emitted by publish_peer_lifecycle_event")
            }
        };
        self.publish_lifecycle_event(SessionLifecycleEvent {
            event_type,
            peer: peer.address,
            peer_label: Some(peer_label),
            timestamp: Self::session_event_timestamp(),
            old_state: Some(old),
            new_state: Some(new),
            session_role: Some(Self::session_role_label(role).to_string()),
            reason,
        });
    }

    pub(super) fn publish_notification_event(&mut self, event: TransportNotificationEvent) {
        let event_type = match event.direction {
            TransportNotificationDirection::Sent => SessionNotificationEventType::Sent,
            TransportNotificationDirection::Received => SessionNotificationEventType::Received,
        };
        let direction = match event.direction {
            TransportNotificationDirection::Sent => "sent",
            TransportNotificationDirection::Received => "received",
        };
        let reason = format!(
            "BGP NOTIFICATION {direction} for peer {}: {}/{} ({})",
            event.peer_addr, event.code, event.subcode, event.description
        );
        self.publish_session_event(SessionEvent::Notification(SessionNotificationEvent {
            event_type,
            peer: event.peer_addr,
            timestamp: Self::session_event_timestamp(),
            code: event.code,
            subcode: event.subcode,
            description: event.description,
            session_role: Some(Self::session_role_label(event.role).to_string()),
            shutdown_reason: event.shutdown_reason,
            reason,
        }));
    }

    pub(super) fn handle_query_session_event_history(
        &self,
        peer: Option<IpAddr>,
        event_types: &BTreeSet<SessionLifecycleEventType>,
        limit: usize,
        reply: oneshot::Sender<Vec<SessionLifecycleEvent>>,
    ) {
        let limit = if limit == 0 {
            SESSION_EVENT_HISTORY_CAPACITY
        } else {
            limit.min(SESSION_EVENT_HISTORY_CAPACITY)
        };

        let mut events: Vec<SessionLifecycleEvent> = self
            .session_event_history
            .iter()
            .rev()
            .filter(|event| match peer {
                Some(peer) => event.peer == peer,
                None => true,
            })
            .filter(|event| event_types.is_empty() || event_types.contains(&event.event_type))
            .take(limit)
            .cloned()
            .collect();
        events.reverse();
        let _ = reply.send(events);
    }

    pub(super) fn handle_query_policy_event_history(
        &self,
        peer: Option<IpAddr>,
        limit: usize,
        reply: oneshot::Sender<Vec<PolicyEvent>>,
    ) {
        let limit = if limit == 0 {
            POLICY_EVENT_HISTORY_CAPACITY
        } else {
            limit.min(POLICY_EVENT_HISTORY_CAPACITY)
        };

        let mut events: Vec<PolicyEvent> = self
            .policy_event_history
            .iter()
            .rev()
            .filter(|event| match peer {
                Some(peer) => event.peer == Some(peer),
                None => true,
            })
            .take(limit)
            .cloned()
            .collect();
        events.reverse();
        let _ = reply.send(events);
    }
}
