//! Bounded RPKI origin and ASPA path diagnostics.

use std::net::IpAddr;
use std::sync::Arc;

use rustbgpd_rpki::{CacheQueryHandle, MAX_COVERING_VRPS, ValidationSnapshot};
use rustbgpd_wire::{
    AsPath, AsPathSegment, AspaValidation, BgpRole, Ipv4Prefix, Ipv6Prefix, Prefix, RpkiValidation,
};
use tonic::{Request, Response, Status};

use crate::proto::rpki_service_server::RpkiService as RpkiServiceTrait;
use crate::proto::{
    AcceptedRpkiCacheState, AspaInvalidHop, AspaLocalRole, AspaSegmentKind, CoveringVrp,
    ListRpkiCachesRequest, ListRpkiCachesResponse, LookupAspaRequest, LookupAspaResponse,
    RouteAspaValidation, RouteOriginValidation, RpkiCacheState, ValidateRouteOriginRequest,
    ValidateRouteOriginResponse, VerifyAsPathRequest, VerifyAsPathResponse,
};

/// Synchronous daemon-owned reader for the latest authoritative validation snapshot.
///
/// Implementations clone the current [`ValidationSnapshot`] and release any watch
/// borrow before returning. Response construction therefore never retains a
/// borrow of the live snapshot channel.
pub type ValidationSnapshotFn = Arc<dyn Fn() -> ValidationSnapshot + Send + Sync>;

/// RPKI diagnostic service backed by the daemon's current validation snapshot.
#[derive(Clone)]
pub struct RpkiService {
    snapshot: ValidationSnapshotFn,
    cache_queries: Option<CacheQueryHandle>,
}

impl RpkiService {
    /// Construct a service from the daemon's narrow synchronous snapshot read.
    #[must_use]
    pub fn new(snapshot: ValidationSnapshotFn) -> Self {
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

const MAX_ASPA_PROVIDERS: usize = 256;
const MAX_ASPA_PATH_ASNS: usize = 4096;

fn parse_aspa_context(request: &VerifyAsPathRequest) -> Result<Option<BgpRole>, Status> {
    if request.neighbor_asn == 0 {
        return Err(Status::invalid_argument("neighbor_asn must be nonzero"));
    }
    match AspaLocalRole::try_from(request.local_role) {
        Ok(AspaLocalRole::None) => Ok(None),
        Ok(AspaLocalRole::Provider) => Ok(Some(BgpRole::Provider)),
        Ok(AspaLocalRole::Customer) => Ok(Some(BgpRole::Customer)),
        Ok(AspaLocalRole::Peer) => Ok(Some(BgpRole::Peer)),
        Ok(AspaLocalRole::RouteServer) => Ok(Some(BgpRole::RouteServer)),
        Ok(AspaLocalRole::RsClient) => Ok(Some(BgpRole::RouteServerClient)),
        _ => Err(Status::invalid_argument(
            "local_role must be explicitly selected",
        )),
    }
}

fn parse_aspa_path(request: &VerifyAsPathRequest) -> Result<AsPath, Status> {
    if request.segments.len() > MAX_ASPA_PATH_ASNS {
        return Err(Status::invalid_argument("AS_PATH exceeds 4096 segments"));
    }
    let mut count = 0_usize;
    let mut segments = Vec::with_capacity(request.segments.len());
    for segment in &request.segments {
        if segment.asns.len() > MAX_ASPA_PATH_ASNS - count {
            return Err(Status::invalid_argument("AS_PATH exceeds 4096 ASNs"));
        }
        if segment.asns.is_empty() || segment.asns.contains(&0) {
            return Err(Status::invalid_argument(
                "AS_PATH segments must contain nonzero ASNs",
            ));
        }
        count += segment.asns.len();
        segments.push(match AspaSegmentKind::try_from(segment.kind) {
            Ok(AspaSegmentKind::Sequence) => AsPathSegment::AsSequence(segment.asns.clone()),
            Ok(AspaSegmentKind::Set) => AsPathSegment::AsSet(segment.asns.clone()),
            _ => {
                return Err(Status::invalid_argument(
                    "AS_PATH segment kind must be SEQUENCE or SET",
                ));
            }
        });
    }
    Ok(AsPath { segments })
}

#[tonic::async_trait]
impl RpkiServiceTrait for RpkiService {
    async fn lookup_aspa(
        &self,
        request: Request<LookupAspaRequest>,
    ) -> Result<Response<LookupAspaResponse>, Status> {
        let customer_asn = request.into_inner().customer_asn;
        if customer_asn == 0 {
            return Err(Status::invalid_argument("customer_asn must be nonzero"));
        }
        let table = (self.snapshot)().aspa_table.ok_or_else(|| {
            Status::failed_precondition("no authoritative ASPA snapshot is available yet")
        })?;
        let providers = table.providers(customer_asn);
        let rows = providers.unwrap_or_default();
        let omitted = rows.len().saturating_sub(MAX_ASPA_PROVIDERS);
        Ok(Response::new(LookupAspaResponse {
            customer_asn,
            found: providers.is_some(),
            provider_asns: rows[..rows.len().min(MAX_ASPA_PROVIDERS)].to_vec(),
            complete: omitted == 0,
            omitted: u64::try_from(omitted).unwrap_or(u64::MAX),
        }))
    }

    async fn verify_as_path(
        &self,
        request: Request<VerifyAsPathRequest>,
    ) -> Result<Response<VerifyAsPathResponse>, Status> {
        let request = request.into_inner();
        let role = parse_aspa_context(&request)?;
        let path = parse_aspa_path(&request)?;
        let table = (self.snapshot)().aspa_table.ok_or_else(|| {
            Status::failed_precondition("no authoritative ASPA snapshot is available yet")
        })?;
        let context = rustbgpd_rpki::aspa_verify::validation_context(request.neighbor_asn, role);
        let result = rustbgpd_rpki::aspa_verify::verify_detailed(&path, &table, context);
        let validation = match result.state {
            AspaValidation::Valid => RouteAspaValidation::Valid,
            AspaValidation::Invalid => RouteAspaValidation::Invalid,
            AspaValidation::Unknown => RouteAspaValidation::Unknown,
            _ => RouteAspaValidation::Unspecified,
        };
        Ok(Response::new(VerifyAsPathResponse {
            validation: validation as i32,
            invalid_hop: result.invalid_hop.map(|hop| AspaInvalidHop {
                customer_asn: hop.customer_asn,
                provider_asn: hop.provider_asn,
            }),
        }))
    }

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
        let table = (self.snapshot)().vrp_table.ok_or_else(|| {
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

    use rustbgpd_rpki::{VrpEntry, VrpTable};
    use tonic::Code;

    use super::*;

    fn aspa_service(table: rustbgpd_rpki::AspaTable) -> RpkiService {
        let table = Arc::new(table);
        RpkiService::new(Arc::new(move || ValidationSnapshot {
            aspa_table: Some(Arc::clone(&table)),
            ..Default::default()
        }))
    }

    fn path_request(asns: Vec<u32>, role: AspaLocalRole) -> VerifyAsPathRequest {
        VerifyAsPathRequest {
            segments: vec![crate::proto::AspaPathSegment {
                kind: AspaSegmentKind::Sequence as i32,
                asns,
            }],
            neighbor_asn: 65_001,
            local_role: role as i32,
        }
    }

    #[tokio::test]
    async fn aspa_lookup_preserves_presence_as0_union_and_bound() {
        use rustbgpd_rpki::{AspaRecord, AspaTable};
        let absent = RpkiService::new(Arc::new(ValidationSnapshot::default));
        assert_eq!(
            absent
                .lookup_aspa(Request::new(LookupAspaRequest { customer_asn: 1 }))
                .await
                .unwrap_err()
                .code(),
            Code::FailedPrecondition
        );
        let service = aspa_service(AspaTable::new(vec![
            AspaRecord {
                customer_asn: 1,
                provider_asns: (0..300).rev().collect(),
            },
            AspaRecord {
                customer_asn: 1,
                provider_asns: vec![2, 300],
            },
            AspaRecord {
                customer_asn: 2,
                provider_asns: vec![],
            },
        ]));
        let response = service
            .lookup_aspa(Request::new(LookupAspaRequest { customer_asn: 1 }))
            .await
            .unwrap()
            .into_inner();
        assert!(response.found);
        assert_eq!(response.provider_asns, (0..256).collect::<Vec<_>>());
        assert!(!response.complete);
        assert_eq!(response.omitted, 45);
        // Provider 300 is outside the displayed slice but still authorizes.
        let mut request = path_request(vec![300, 1], AspaLocalRole::Peer);
        request.neighbor_asn = 300;
        assert_eq!(
            service
                .verify_as_path(Request::new(request))
                .await
                .unwrap()
                .into_inner()
                .validation,
            RouteAspaValidation::Valid as i32
        );

        for (customer_asn, found) in [(2, true), (3, false)] {
            let response = service
                .lookup_aspa(Request::new(LookupAspaRequest { customer_asn }))
                .await
                .unwrap()
                .into_inner();
            assert_eq!(response.found, found);
            assert!(response.provider_asns.is_empty());
            assert!(response.complete);
            assert_eq!(response.omitted, 0);
        }
        assert_eq!(
            service
                .lookup_aspa(Request::new(LookupAspaRequest { customer_asn: 0 }))
                .await
                .unwrap_err()
                .code(),
            Code::InvalidArgument
        );
        let empty = aspa_service(AspaTable::new(vec![]));
        assert!(
            !empty
                .lookup_aspa(Request::new(LookupAspaRequest { customer_asn: 1 }))
                .await
                .unwrap()
                .into_inner()
                .found
        );
    }

    #[tokio::test]
    async fn aspa_verification_matches_shared_verifier_for_every_role_and_verdict() {
        use rustbgpd_rpki::{AspaRecord, AspaTable};
        let records = vec![
            AspaRecord {
                customer_asn: 65_003,
                provider_asns: vec![65_002],
            },
            AspaRecord {
                customer_asn: 65_002,
                provider_asns: vec![65_001],
            },
        ];
        let table = AspaTable::new(records.clone());
        let service = aspa_service(AspaTable::new(records));
        for (role, wire_role) in [
            (AspaLocalRole::None, None),
            (AspaLocalRole::Provider, Some(BgpRole::Provider)),
            (AspaLocalRole::Customer, Some(BgpRole::Customer)),
            (AspaLocalRole::Peer, Some(BgpRole::Peer)),
            (AspaLocalRole::RouteServer, Some(BgpRole::RouteServer)),
            (AspaLocalRole::RsClient, Some(BgpRole::RouteServerClient)),
        ] {
            for asns in [
                vec![65_001, 65_002, 65_003],
                vec![65_001, 65_003],
                vec![65_001, 65_004],
                vec![65_001, 65_001, 65_002, 65_003],
            ] {
                let request = path_request(asns.clone(), role);
                let expected = rustbgpd_rpki::aspa_verify::verify_detailed(
                    &AsPath {
                        segments: vec![AsPathSegment::AsSequence(asns)],
                    },
                    &table,
                    rustbgpd_rpki::aspa_verify::validation_context(65_001, wire_role),
                );
                let response = service
                    .verify_as_path(Request::new(request))
                    .await
                    .unwrap()
                    .into_inner();
                let state = match expected.state {
                    AspaValidation::Valid => RouteAspaValidation::Valid,
                    AspaValidation::Invalid => RouteAspaValidation::Invalid,
                    AspaValidation::Unknown => RouteAspaValidation::Unknown,
                    _ => RouteAspaValidation::Unspecified,
                };
                assert_eq!(response.validation, state as i32, "{role:?}");
                assert_eq!(
                    response
                        .invalid_hop
                        .map(|hop| (hop.customer_asn, hop.provider_asn)),
                    expected
                        .invalid_hop
                        .map(|hop| (hop.customer_asn, hop.provider_asn))
                );
            }
        }
        for (path, state, hop) in [
            (
                vec![65_001, 65_002, 65_003],
                RouteAspaValidation::Valid,
                None,
            ),
            (
                vec![65_001, 65_003],
                RouteAspaValidation::Invalid,
                Some((65_003, 65_001)),
            ),
            (vec![65_001, 65_004], RouteAspaValidation::Unknown, None),
        ] {
            let response = service
                .verify_as_path(Request::new(path_request(path, AspaLocalRole::Peer)))
                .await
                .unwrap()
                .into_inner();
            assert_eq!(response.validation, state as i32);
            assert_eq!(
                response
                    .invalid_hop
                    .map(|hop| (hop.customer_asn, hop.provider_asn)),
                hop
            );
        }
    }

    #[tokio::test]
    async fn aspa_preconditions_and_absent_empty_data_are_distinct() {
        let absent = RpkiService::new(Arc::new(ValidationSnapshot::default));
        assert_eq!(
            absent
                .verify_as_path(Request::new(path_request(
                    vec![65_001],
                    AspaLocalRole::Peer
                )))
                .await
                .unwrap_err()
                .code(),
            Code::FailedPrecondition
        );
        let service = aspa_service(rustbgpd_rpki::AspaTable::new(vec![]));
        for role in [
            AspaLocalRole::None,
            AspaLocalRole::Provider,
            AspaLocalRole::Customer,
            AspaLocalRole::Peer,
            AspaLocalRole::RouteServer,
            AspaLocalRole::RsClient,
        ] {
            let response = service
                .verify_as_path(Request::new(path_request(vec![65_999], role)))
                .await
                .unwrap()
                .into_inner();
            assert_eq!(
                response.validation,
                if role == AspaLocalRole::RsClient {
                    RouteAspaValidation::Valid
                } else {
                    RouteAspaValidation::Invalid
                } as i32
            );
            assert!(response.invalid_hop.is_none());
        }
        let mut empty = path_request(vec![65_001], AspaLocalRole::Peer);
        empty.segments.clear();
        let mut as_set = path_request(vec![65_001], AspaLocalRole::Peer);
        as_set.segments[0].kind = AspaSegmentKind::Set as i32;
        for request in [empty, as_set] {
            let response = service
                .verify_as_path(Request::new(request))
                .await
                .unwrap()
                .into_inner();
            assert_eq!(response.validation, RouteAspaValidation::Invalid as i32);
            assert!(response.invalid_hop.is_none());
        }
        let response = service
            .verify_as_path(Request::new(path_request(
                vec![65_001, 65_002],
                AspaLocalRole::Peer,
            )))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.validation, RouteAspaValidation::Unknown as i32);
    }

    #[tokio::test]
    async fn aspa_invalid_requests_fail_before_snapshot_and_limits_are_exact() {
        let service = RpkiService::new(Arc::new(|| {
            panic!("invalid request must not read snapshot")
        }));
        let valid = path_request(vec![65_001], AspaLocalRole::Peer);
        let mut requests = Vec::new();
        for role in [0, 99] {
            let mut request = valid.clone();
            request.local_role = role;
            requests.push(request);
        }
        for kind in [0, 99] {
            let mut request = valid.clone();
            request.segments[0].kind = kind;
            requests.push(request);
        }
        for asns in [vec![], vec![0], vec![1; 4097]] {
            let mut request = valid.clone();
            request.segments[0].asns = asns;
            requests.push(request);
        }
        let mut request = valid.clone();
        request.neighbor_asn = 0;
        requests.push(request);
        let mut request = valid.clone();
        request.segments = vec![request.segments[0].clone(); 4097];
        requests.push(request);
        for request in requests {
            assert_eq!(
                service
                    .verify_as_path(Request::new(request))
                    .await
                    .unwrap_err()
                    .code(),
                Code::InvalidArgument
            );
        }
        let service = aspa_service(rustbgpd_rpki::AspaTable::new(vec![]));
        let mut request = valid.clone();
        request.segments[0].asns = vec![65_001; 4096];
        assert_eq!(
            service
                .verify_as_path(Request::new(request))
                .await
                .unwrap()
                .into_inner()
                .validation,
            RouteAspaValidation::Valid as i32
        );
        let mut request = valid;
        request.segments = vec![request.segments[0].clone(); 4096];
        assert_eq!(
            service
                .verify_as_path(Request::new(request))
                .await
                .unwrap()
                .into_inner()
                .validation,
            RouteAspaValidation::Valid as i32
        );
    }

    #[tokio::test]
    async fn aspa_queries_take_one_fresh_snapshot_per_result() {
        use rustbgpd_rpki::{AspaRecord, AspaTable};
        let (tx, rx) = tokio::sync::watch::channel(ValidationSnapshot::default());
        let calls = Arc::new(AtomicUsize::new(0));
        let service = RpkiService::new({
            let calls = Arc::clone(&calls);
            Arc::new(move || {
                calls.fetch_add(1, Ordering::SeqCst);
                rx.borrow().clone()
            })
        });
        for (providers, expected) in [
            (vec![65_001], RouteAspaValidation::Valid),
            (vec![65_003], RouteAspaValidation::Invalid),
        ] {
            tx.send_modify(|snapshot| {
                snapshot.aspa_table = Some(Arc::new(AspaTable::new(vec![AspaRecord {
                    customer_asn: 65_002,
                    provider_asns: providers.clone(),
                }])));
            });
            let before = calls.load(Ordering::SeqCst);
            let lookup = service
                .lookup_aspa(Request::new(LookupAspaRequest {
                    customer_asn: 65_002,
                }))
                .await
                .unwrap()
                .into_inner();
            assert_eq!(calls.load(Ordering::SeqCst), before + 1);
            assert_eq!(lookup.provider_asns, providers);
            let result = service
                .verify_as_path(Request::new(path_request(
                    vec![65_001, 65_002],
                    AspaLocalRole::Peer,
                )))
                .await
                .unwrap()
                .into_inner();
            assert_eq!(calls.load(Ordering::SeqCst), before + 2);
            assert_eq!(result.validation, expected as i32);
        }
    }

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
        let service = RpkiService::new(Arc::new(|| ValidationSnapshot {
            vrp_table: Some(table(Vec::new())),
            ..Default::default()
        }));
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
        let absent = RpkiService::new(Arc::new(ValidationSnapshot::default));
        let error = absent
            .validate_route_origin(request("192.0.2.1", Some(24), 64496))
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::FailedPrecondition);

        let empty = RpkiService::new(Arc::new(|| ValidationSnapshot {
            vrp_table: Some(table(Vec::new())),
            ..Default::default()
        }));
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
        let service = RpkiService::new(Arc::new(ValidationSnapshot::default));
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
        let service = RpkiService::new(Arc::new(ValidationSnapshot::default))
            .with_cache_queries(Some(queries));
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
        let service = RpkiService::new(Arc::new(ValidationSnapshot::default))
            .with_cache_queries(Some(queries));
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
        let service = RpkiService::new(Arc::new(ValidationSnapshot::default))
            .with_cache_queries(Some(queries));
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
                rx.borrow().clone()
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
        let service = RpkiService::new(Arc::new(move || ValidationSnapshot {
            vrp_table: Some(table(entries.clone())),
            ..Default::default()
        }));
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
