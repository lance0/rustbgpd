//! gRPC BFD service — single-hop and multihop BFD session inspection (ADR-0067).
//!
//! Read-only operator surface over the BFD actor's published session status.
//! The actor owns the sessions; this service just snapshots their state.

use tonic::{Request, Response, Status};

use crate::actor_read::KnownPeerQueries;
use crate::proto;

/// Live snapshot provider for BFD session status. The daemon wires this to the
/// BFD actor's status `watch` channel; off Linux / when BFD is unconfigured it
/// is an empty-vec closure.
pub type BfdSessionSnapshotFn =
    std::sync::Arc<dyn Fn() -> Vec<proto::BfdSession> + Send + Sync + 'static>;

/// gRPC service exposing BFD session state (read-only).
pub struct BfdService {
    snapshot: BfdSessionSnapshotFn,
    /// Resolves an empty per-peer view to `NOT_FOUND` for an unknown peer.
    known_peers: Option<KnownPeerQueries>,
}

impl BfdService {
    /// Create a BFD service backed by a live session snapshot provider.
    pub fn with_snapshot(snapshot: BfdSessionSnapshotFn) -> Self {
        Self {
            snapshot,
            known_peers: None,
        }
    }

    /// Answer an empty per-peer view with `NOT_FOUND` for an unknown peer.
    #[must_use]
    pub(crate) fn with_known_peer_queries(mut self, known_peers: KnownPeerQueries) -> Self {
        self.known_peers = Some(known_peers);
        self
    }
}

impl Default for BfdService {
    /// A service with no sessions — used off Linux / when BFD is unconfigured.
    fn default() -> Self {
        Self {
            snapshot: std::sync::Arc::new(Vec::new),
            known_peers: None,
        }
    }
}

#[tonic::async_trait]
impl proto::bfd_service_server::BfdService for BfdService {
    async fn get_bfd_sessions(
        &self,
        request: Request<proto::GetBfdSessionsRequest>,
    ) -> Result<Response<proto::GetBfdSessionsResponse>, Status> {
        let filter = request.into_inner().peer_address;
        let mut sessions = (self.snapshot)();
        if !filter.is_empty() {
            // Parse to IpAddr and compare canonicalized forms so equivalent
            // textual representations (notably IPv6) match — mirrors the
            // address-filter handling in NeighborService / RibService. Snapshot
            // peer addresses are already `IpAddr::to_string()` (canonical).
            let peer = filter
                .parse::<std::net::IpAddr>()
                .map_err(|e| Status::invalid_argument(format!("invalid peer_address: {e}")))?;
            let wanted = peer.to_string();
            sessions.retain(|s| s.peer_address == wanted);
            if sessions.is_empty()
                && let Some(known_peers) = &self.known_peers
            {
                known_peers.require_known(peer).await?;
            }
        }
        Ok(Response::new(proto::GetBfdSessionsResponse { sessions }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto::bfd_service_server::BfdService as _;

    fn session(peer: &str, state: proto::BfdSessionState) -> proto::BfdSession {
        proto::BfdSession {
            peer_address: peer.to_string(),
            state: state as i32,
            diagnostic: "none".to_string(),
            strict: false,
            remote_administrative_down: None,
            multihop: false,
        }
    }

    /// Load-bearing proof: renumbering field 5 or removing proto3 presence
    /// makes this compatibility contract red before generated clients drift.
    #[test]
    fn remote_admin_down_proto_field_is_optional_and_append_only() {
        let proto_source = include_str!("../../../proto/rustbgpd.proto");
        assert!(proto_source.contains("optional bool remote_administrative_down = 5;"));
    }

    #[tokio::test]
    async fn returns_all_sessions_when_unfiltered() {
        let svc = BfdService::with_snapshot(std::sync::Arc::new(|| {
            vec![
                session("10.0.0.1", proto::BfdSessionState::Up),
                session("10.0.0.2", proto::BfdSessionState::Down),
            ]
        }));
        let resp = svc
            .get_bfd_sessions(Request::new(proto::GetBfdSessionsRequest::default()))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp.sessions.len(), 2);
    }

    #[tokio::test]
    async fn filters_by_peer_address() {
        let svc = BfdService::with_snapshot(std::sync::Arc::new(|| {
            vec![
                session("10.0.0.1", proto::BfdSessionState::Up),
                session("10.0.0.2", proto::BfdSessionState::Down),
            ]
        }));
        let resp = svc
            .get_bfd_sessions(Request::new(proto::GetBfdSessionsRequest {
                peer_address: "10.0.0.2".to_string(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp.sessions.len(), 1);
        assert_eq!(resp.sessions[0].peer_address, "10.0.0.2");
    }

    /// Load-bearing: removing the known-peer check makes the unknown row
    /// answer OK-empty; checking before the session filter fails the
    /// unmanaged address that does own a session.
    #[tokio::test]
    async fn empty_peer_view_rejects_only_unknown_peers() {
        let svc = BfdService::with_snapshot(std::sync::Arc::new(|| {
            vec![session("10.0.0.9", proto::BfdSessionState::Up)]
        }))
        .with_known_peer_queries(crate::actor_read::mock_known_peer_queries(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
        ));
        let view = |peer: &str| {
            svc.get_bfd_sessions(Request::new(proto::GetBfdSessionsRequest {
                peer_address: peer.to_string(),
            }))
        };
        assert!(
            view("10.0.0.1")
                .await
                .unwrap()
                .into_inner()
                .sessions
                .is_empty()
        );
        assert!(
            view("10.0.0.2")
                .await
                .unwrap()
                .into_inner()
                .sessions
                .is_empty()
        );
        assert_eq!(
            view("10.0.0.9").await.unwrap().into_inner().sessions.len(),
            1
        );
        let error = view("192.0.2.99").await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::NotFound);
        assert_eq!(error.message(), "neighbor 192.0.2.99 not found");
    }

    #[tokio::test]
    async fn rejects_invalid_peer_address() {
        let svc = BfdService::default();
        let err = svc
            .get_bfd_sessions(Request::new(proto::GetBfdSessionsRequest {
                peer_address: "not-an-ip".to_string(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn ipv6_filter_matches_canonical_form() {
        // Snapshot stores the canonical form; a non-canonical request still matches.
        let svc = BfdService::with_snapshot(std::sync::Arc::new(|| {
            vec![session("2001:db8::1", proto::BfdSessionState::Up)]
        }));
        let resp = svc
            .get_bfd_sessions(Request::new(proto::GetBfdSessionsRequest {
                peer_address: "2001:DB8:0:0:0:0:0:1".to_string(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp.sessions.len(), 1);
    }

    #[tokio::test]
    async fn default_service_has_no_sessions() {
        let svc = BfdService::default();
        let resp = svc
            .get_bfd_sessions(Request::new(proto::GetBfdSessionsRequest::default()))
            .await
            .unwrap()
            .into_inner();
        assert!(resp.sessions.is_empty());
    }
}
