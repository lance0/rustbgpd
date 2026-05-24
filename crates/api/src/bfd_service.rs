//! gRPC BFD service — single-hop BFD session inspection (ADR-0067).
//!
//! Read-only operator surface over the BFD actor's published session status.
//! The actor owns the sessions; this service just snapshots their state.

use tonic::{Request, Response, Status};

use crate::proto;

/// Live snapshot provider for BFD session status. The daemon wires this to the
/// BFD actor's status `watch` channel; off Linux / when BFD is unconfigured it
/// is an empty-vec closure.
pub type BfdSessionSnapshotFn =
    std::sync::Arc<dyn Fn() -> Vec<proto::BfdSession> + Send + Sync + 'static>;

/// gRPC service exposing BFD session state (read-only).
pub struct BfdService {
    snapshot: BfdSessionSnapshotFn,
}

impl BfdService {
    /// Create a BFD service backed by a live session snapshot provider.
    pub fn with_snapshot(snapshot: BfdSessionSnapshotFn) -> Self {
        Self { snapshot }
    }
}

impl Default for BfdService {
    /// A service with no sessions — used off Linux / when BFD is unconfigured.
    fn default() -> Self {
        Self {
            snapshot: std::sync::Arc::new(Vec::new),
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
            let wanted = filter
                .parse::<std::net::IpAddr>()
                .map_err(|e| Status::invalid_argument(format!("invalid peer_address: {e}")))?
                .to_string();
            sessions.retain(|s| s.peer_address == wanted);
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
        }
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
