//! Bounded RPKI route-origin validation diagnostics.

use std::net::IpAddr;
use std::sync::Arc;

use rustbgpd_rpki::{CacheQueryHandle, MAX_COVERING_VRPS, VrpTable};
use rustbgpd_wire::{Ipv4Prefix, Ipv6Prefix, Prefix, RpkiValidation};
use tonic::{Request, Response, Status};

use crate::proto::rpki_service_server::RpkiService as RpkiServiceTrait;
use crate::proto::{
    AcceptedRpkiCacheState, CoveringVrp, ListRpkiCachesRequest, ListRpkiCachesResponse,
    RouteOriginValidation, RpkiCacheState, ValidateRouteOriginRequest, ValidateRouteOriginResponse,
};

/// Synchronous daemon-owned reader for the latest authoritative VRP snapshot.
///
/// Implementations clone the current [`Arc<VrpTable>`] and release any watch
/// borrow before returning. Response construction therefore never retains a
/// borrow of the live snapshot channel.
pub type VrpSnapshotFn = Arc<dyn Fn() -> Option<Arc<VrpTable>> + Send + Sync>;

/// RPKI diagnostic service backed by the daemon's current validation snapshot.
#[derive(Clone)]
pub struct RpkiService {
    snapshot: VrpSnapshotFn,
    cache_queries: Option<CacheQueryHandle>,
}

impl RpkiService {
    /// Construct a service from the daemon's narrow synchronous snapshot read.
    #[must_use]
    pub fn new(snapshot: VrpSnapshotFn) -> Self {
        Self {
            snapshot,
            cache_queries: None,
        }
    }

    #[must_use]
    pub fn with_cache_queries(mut self, cache_queries: Option<CacheQueryHandle>) -> Self {
        self.cache_queries = cache_queries;
        self
    }
}

fn parse_prefix(request: &ValidateRouteOriginRequest) -> Result<Prefix, Status> {
    if request.prefix.contains('/') {
        return Err(Status::invalid_argument(
            "prefix must be a bare IP address; provide prefix_length separately",
        ));
    }
    let address = request
        .prefix
        .parse::<IpAddr>()
        .map_err(|_| Status::invalid_argument("prefix must be a valid IPv4 or IPv6 address"))?;
    let length = request
        .prefix_length
        .ok_or_else(|| Status::invalid_argument("prefix_length is required"))?;
    match address {
        IpAddr::V4(address) if length <= 32 => Ok(Prefix::V4(Ipv4Prefix::new(
            address,
            u8::try_from(length).expect("validated IPv4 prefix length fits u8"),
        ))),
        IpAddr::V6(address) if length <= 128 => Ok(Prefix::V6(Ipv6Prefix::new(
            address,
            u8::try_from(length).expect("validated IPv6 prefix length fits u8"),
        ))),
        IpAddr::V4(_) => Err(Status::invalid_argument(
            "prefix_length must be between 0 and 32 for IPv4",
        )),
        IpAddr::V6(_) => Err(Status::invalid_argument(
            "prefix_length must be between 0 and 128 for IPv6",
        )),
    }
}

const fn validation_to_proto(validation: RpkiValidation) -> RouteOriginValidation {
    match validation {
        RpkiValidation::Valid => RouteOriginValidation::Valid,
        RpkiValidation::Invalid => RouteOriginValidation::Invalid,
        RpkiValidation::NotFound => RouteOriginValidation::NotFound,
    }
}

#[tonic::async_trait]
impl RpkiServiceTrait for RpkiService {
    async fn list_caches(
        &self,
        _request: Request<ListRpkiCachesRequest>,
    ) -> Result<Response<ListRpkiCachesResponse>, Status> {
        let Some(queries) = self.cache_queries.clone() else {
            return Ok(Response::new(ListRpkiCachesResponse {
                caches: Vec::new(),
                complete: true,
                omitted: 0,
            }));
        };
        let list = tokio::time::timeout(std::time::Duration::from_secs(2), queries.list())
            .await
            .map_err(|_| Status::deadline_exceeded("RPKI cache inventory query timed out"))?
            .map_err(|_| Status::unavailable("RPKI cache inventory actor is unavailable"))?;
        let caches = list
            .rows
            .into_iter()
            .map(|row| RpkiCacheState {
                address: row.server.to_string(),
                connected: row.connected,
                accepted: row.accepted.map(|accepted| AcceptedRpkiCacheState {
                    protocol_version: accepted.protocol_version.map(u32::from),
                    session_id: accepted.session_id.map(u32::from),
                    serial: accepted.serial,
                    vrp_v4_count: u64::try_from(accepted.vrp_v4_count).unwrap_or(u64::MAX),
                    vrp_v6_count: u64::try_from(accepted.vrp_v6_count).unwrap_or(u64::MAX),
                    aspa_count: u64::try_from(accepted.aspa_count).unwrap_or(u64::MAX),
                    age_seconds: accepted.age_seconds,
                }),
            })
            .collect();
        Ok(Response::new(ListRpkiCachesResponse {
            caches,
            complete: list.omitted == 0,
            omitted: list.omitted,
        }))
    }

    async fn validate_route_origin(
        &self,
        request: Request<ValidateRouteOriginRequest>,
    ) -> Result<Response<ValidateRouteOriginResponse>, Status> {
        let request = request.into_inner();
        let prefix = parse_prefix(&request)?;
        if request.origin_asn == 0 {
            return Err(Status::invalid_argument("origin_asn must be nonzero"));
        }

        // This is the sole snapshot read. The daemon closure clones the Arc and
        // drops its watch borrow before any table walk or response construction.
        let table = (self.snapshot)().ok_or_else(|| {
            Status::failed_precondition("no authoritative VRP snapshot is available yet")
        })?;

        // Compute the complete-table verdict independently of the bounded
        // diagnostic rows. Truncation can never affect this value.
        let validation = table.validate(&prefix, request.origin_asn);
        let covering = table.covering_vrps(&prefix, request.origin_asn, MAX_COVERING_VRPS);
        let covering_vrps = covering
            .rows
            .into_iter()
            .map(|row| CoveringVrp {
                prefix: row.prefix.to_string(),
                prefix_length: u32::from(row.prefix_len),
                max_length: u32::from(row.max_len),
                origin_asn: row.origin_asn,
                authorizes: row.authorizes,
            })
            .collect();

        Ok(Response::new(ValidateRouteOriginResponse {
            prefix: prefix.to_string(),
            origin_asn: request.origin_asn,
            validation: validation_to_proto(validation) as i32,
            covering_vrps,
            complete: covering.omitted == 0,
            omitted: covering.omitted,
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use rustbgpd_rpki::{ValidationSnapshot, VrpEntry};
    use tonic::Code;

    use super::*;

    fn request(
        prefix: &str,
        prefix_length: Option<u32>,
        origin_asn: u32,
    ) -> Request<ValidateRouteOriginRequest> {
        Request::new(ValidateRouteOriginRequest {
            prefix: prefix.to_string(),
            prefix_length,
            origin_asn,
        })
    }

    fn table(entries: Vec<VrpEntry>) -> Arc<VrpTable> {
        Arc::new(VrpTable::new(entries))
    }

    fn v4(prefix: Ipv4Addr, prefix_len: u8, max_len: u8, origin_asn: u32) -> VrpEntry {
        VrpEntry {
            prefix: IpAddr::V4(prefix),
            prefix_len,
            max_len,
            origin_asn,
        }
    }

    #[tokio::test]
    async fn rejects_malformed_missing_overflow_cidr_and_asn_zero() {
        let service = RpkiService::new(Arc::new(|| Some(table(Vec::new()))));
        for (prefix, length, asn) in [
            ("not-an-ip", Some(24), 64496),
            ("192.0.2.1", None, 64496),
            ("192.0.2.1", Some(33), 64496),
            ("2001:db8::1", Some(129), 64496),
            ("192.0.2.0/24", Some(24), 64496),
            ("192.0.2.1", Some(24), 0),
        ] {
            let error = service
                .validate_route_origin(request(prefix, length, asn))
                .await
                .unwrap_err();
            assert_eq!(error.code(), Code::InvalidArgument, "{prefix}/{length:?}");
        }
    }

    #[tokio::test]
    async fn distinguishes_absent_and_authoritative_empty_snapshots() {
        let absent = RpkiService::new(Arc::new(|| None));
        let error = absent
            .validate_route_origin(request("192.0.2.1", Some(24), 64496))
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::FailedPrecondition);

        let empty = RpkiService::new(Arc::new(|| Some(table(Vec::new()))));
        let response = empty
            .validate_route_origin(request("192.0.2.1", Some(24), 64496))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.prefix, "192.0.2.0/24");
        assert_eq!(response.validation, RouteOriginValidation::NotFound as i32);
        assert!(response.covering_vrps.is_empty());
        assert!(response.complete);
        assert_eq!(response.omitted, 0);
    }

    #[tokio::test]
    async fn unconfigured_cache_inventory_is_empty_and_complete() {
        let service = RpkiService::new(Arc::new(|| None));
        let response = service
            .list_caches(Request::new(ListRpkiCachesRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert!(response.caches.is_empty());
        assert!(response.complete);
        assert_eq!(response.omitted, 0);
    }

    #[tokio::test]
    async fn closed_cache_inventory_actor_is_unavailable() {
        let (attachment, updates, queries) = rustbgpd_rpki::CacheInventoryAttachment::new([]);
        drop(attachment);
        drop(updates);
        let service = RpkiService::new(Arc::new(|| None)).with_cache_queries(Some(queries));
        let error = service
            .list_caches(Request::new(ListRpkiCachesRequest {}))
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::Unavailable);
    }

    #[tokio::test(start_paused = true)]
    async fn cache_inventory_whole_query_timeout_is_deadline_exceeded() {
        let (_attachment, _updates, queries) =
            rustbgpd_rpki::CacheInventoryAttachment::new(["192.0.2.1:3323".parse().unwrap()]);
        let service = RpkiService::new(Arc::new(|| None)).with_cache_queries(Some(queries));
        let error = service
            .list_caches(Request::new(ListRpkiCachesRequest {}))
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::DeadlineExceeded);
    }

    #[tokio::test]
    async fn configured_initial_cache_is_present_without_accepted_epoch() {
        let (legacy_tx, legacy_rx) = tokio::sync::mpsc::channel(1);
        let (rib_tx, _rib_rx) = tokio::sync::mpsc::channel(1);
        let (attachment, updates, queries) =
            rustbgpd_rpki::CacheInventoryAttachment::new(["192.0.2.1:3323".parse().unwrap()]);
        let manager = tokio::spawn(
            rustbgpd_rpki::VrpManager::new(legacy_rx, rib_tx)
                .with_cache_inventory(attachment)
                .run(),
        );
        let service = RpkiService::new(Arc::new(|| None)).with_cache_queries(Some(queries));
        let response = service
            .list_caches(Request::new(ListRpkiCachesRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.caches.len(), 1);
        assert_eq!(response.caches[0].address, "192.0.2.1:3323");
        assert!(!response.caches[0].connected);
        assert!(response.caches[0].accepted.is_none());
        drop(legacy_tx);
        drop(updates);
        manager.await.unwrap();
    }

    #[tokio::test]
    async fn reads_one_fresh_snapshot_and_normalizes_host_bits() {
        let (tx, rx) = tokio::sync::watch::channel(ValidationSnapshot::default());
        let calls = Arc::new(AtomicUsize::new(0));
        let service = RpkiService::new({
            let calls = Arc::clone(&calls);
            Arc::new(move || {
                calls.fetch_add(1, Ordering::SeqCst);
                // The cloned Arc is the return value, so the watch borrow ends
                // at this statement before validation begins.
                rx.borrow().vrp_table.clone()
            })
        });

        let error = service
            .validate_route_origin(request("192.0.2.129", Some(24), 64496))
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::FailedPrecondition);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        tx.send_modify(|snapshot| {
            snapshot.vrp_table = Some(table(vec![
                v4(Ipv4Addr::new(192, 0, 2, 0), 24, 24, 64496),
                v4(Ipv4Addr::new(192, 0, 2, 0), 24, 24, 0),
            ]));
        });
        let response = service
            .validate_route_origin(request("192.0.2.129", Some(24), 64496))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(response.prefix, "192.0.2.0/24");
        assert_eq!(response.validation, RouteOriginValidation::Valid as i32);
        assert_eq!(response.covering_vrps.len(), 2);
        assert!(response.covering_vrps[0].authorizes);
        assert_eq!(response.covering_vrps[1].origin_asn, 0);
        assert!(!response.covering_vrps[1].authorizes);
    }

    #[tokio::test]
    async fn verdict_is_independent_of_diagnostic_bound() {
        let entries: Vec<VrpEntry> = (1..=300)
            .map(|origin_asn| v4(Ipv4Addr::new(10, 0, 0, 0), 8, 24, origin_asn))
            .chain(std::iter::once(v4(
                Ipv4Addr::new(10, 0, 0, 0),
                8,
                24,
                65_000,
            )))
            .collect();
        let service = RpkiService::new(Arc::new(move || Some(table(entries.clone()))));
        let response = service
            .validate_route_origin(request("10.1.2.3", Some(24), 65_000))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(response.validation, RouteOriginValidation::Valid as i32);
        assert_eq!(response.covering_vrps.len(), MAX_COVERING_VRPS);
        assert!(response.covering_vrps[0].authorizes);
        assert!(!response.complete);
        assert_eq!(response.omitted, 45);
    }
}
