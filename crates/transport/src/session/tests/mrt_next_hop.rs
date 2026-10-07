//! Routes as inbound stores them must re-encode with exactly one next hop.
//!
//! Inbound keeps the received `NEXT_HOP` among an IPv4 unicast route's stored
//! attributes, while `Route::next_hop` carries the effective (post-import-
//! policy) next hop. The MRT dump, the warm checkpoint and the BMP Loc-RIB
//! synthesizer emit the next hop from `Route::next_hop` and must not also
//! emit the stored attribute.

use super::*;
use rustbgpd_mrt::warm_bundle::{
    WarmBundleDirectory, WarmBundleExpectedV1, WarmBundleFamilyV1, WarmBundleFreshnessV1,
    WarmBundleIdentityV1, WarmBundlePolicyDigestV1, WarmBundleViewKindV1, WarmBundleViewV1,
    load_warm_bundle, write_warm_bundle,
};
use rustbgpd_mrt::{SnapshotNlri, SnapshotReader};
use rustbgpd_policy::NextHopAction;
use rustbgpd_rib::{MrtPeerEntry, Route};

const RECEIVED: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

/// Feed one body IPv4 UPDATE through `process_update` and return the routes
/// exactly as the session hands them to the RIB.
async fn stored_routes(import_next_hop: Option<NextHopAction>) -> Vec<Route> {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    session.negotiated = Some(Arc::new(negotiated_session(65002, false)));
    if let Some(action) = import_next_hop {
        session.install_import_policy(Some(PolicyChain::new(vec![Policy {
            entries: vec![PolicyStatement {
                prefix: None,
                ge: None,
                le: None,
                action: PolicyAction::Permit,
                match_community: vec![],
                match_as_path: None,
                match_neighbor_set: None,
                match_route_type: None,
                match_evpn_route_type: None,
                match_rpki_validation: None,
                match_aspa_validation: None,
                match_as_path_length_ge: None,
                match_as_path_length_le: None,
                match_local_pref_ge: None,
                match_local_pref_le: None,
                match_med_ge: None,
                match_med_le: None,
                match_next_hop: None,
                modifications: RouteModifications {
                    set_next_hop: Some(action),
                    ..Default::default()
                },
            }],
            default_action: PolicyAction::Deny,
        }])));
    }
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(RECEIVED),
        PathAttribute::Communities(vec![0xFFFF_029A]),
    ];
    let announced = [Ipv4NlriEntry {
        path_id: 0,
        prefix: Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24),
    }];
    let update = UpdateMessage::build(&announced, &[], &attrs, true, false, Ipv4UnicastMode::Body);
    session.process_update(update).await;
    let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected RoutesReceived");
    };
    // The storage shape every test below depends on.
    assert_eq!(
        announced[0]
            .attributes
            .iter()
            .filter(|attr| matches!(attr, PathAttribute::NextHop(_)))
            .count(),
        1
    );
    announced
}

fn peers() -> [MrtPeerEntry; 1] {
    [MrtPeerEntry {
        peer_addr: IpAddr::V4(RECEIVED),
        peer_bgp_id: RECEIVED,
        peer_asn: 65002,
    }]
}

/// Decode a snapshot, requiring nothing was discarded, and return each
/// entry's next hop plus how many `NEXT_HOP` attributes the bytes carried.
fn decoded_next_hops(snapshot: &[u8]) -> Vec<(Option<IpAddr>, usize)> {
    let mut reader = SnapshotReader::new(snapshot).unwrap();
    let entries: Vec<_> = reader.by_ref().map(Result::unwrap).collect();
    assert_eq!(reader.discarded_path_attributes(), 0, "duplicate attribute");
    entries
        .into_iter()
        .map(|entry| {
            let count = entry
                .attributes
                .iter()
                .filter(|attr| matches!(attr, PathAttribute::NextHop(_)))
                .count();
            (entry.next_hop, count)
        })
        .collect()
}

#[tokio::test]
async fn mrt_dump_of_a_received_ipv4_route_carries_one_next_hop() {
    let routes = stored_routes(None).await;
    let snapshot = rustbgpd_mrt::codec::encode_snapshot(
        Ipv4Addr::new(10, 0, 0, 1),
        &peers(),
        &routes,
        &[],
        1_800_000_000,
    )
    .unwrap();
    assert_eq!(
        decoded_next_hops(&snapshot),
        [(Some(IpAddr::V4(RECEIVED)), 1)]
    );
}

/// Import `next-hop self` rewrites only `Route::next_hop`; the stored
/// attribute keeps the received value. The dump records the post-policy
/// next hop the RIB selected and installs with.
#[tokio::test]
async fn mrt_dump_records_the_post_policy_next_hop() {
    for (action, expected) in [
        (NextHopAction::Self_, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        (
            NextHopAction::Specific(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9))),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)),
        ),
    ] {
        let self_ = action == NextHopAction::Self_;
        let routes = stored_routes(Some(action)).await;
        assert_eq!(routes[0].next_hop, expected);
        // `next-hop self` leaves the received attribute stored.
        let stored = if self_ {
            RECEIVED
        } else {
            Ipv4Addr::new(192, 0, 2, 9)
        };
        assert!(
            routes[0]
                .attributes
                .iter()
                .any(|attr| *attr == PathAttribute::NextHop(stored))
        );
        let snapshot = rustbgpd_mrt::codec::encode_snapshot(
            Ipv4Addr::new(10, 0, 0, 1),
            &peers(),
            &routes,
            &[],
            1_800_000_000,
        )
        .unwrap();
        assert_eq!(decoded_next_hops(&snapshot), [(Some(expected), 1)]);
    }
}

#[tokio::test]
async fn warm_checkpoint_of_a_received_ipv4_route_publishes_and_recovers() {
    let routes = stored_routes(None).await;
    let generation = "a".repeat(32);
    let snapshot = rustbgpd_mrt::codec::encode_warm_snapshot(
        Ipv4Addr::new(10, 0, 0, 1),
        &generation,
        &peers(),
        &routes,
        &[],
        1_800_000_000,
        &[],
    )
    .unwrap();
    let view = WarmBundleViewV1 {
        kind: WarmBundleViewKindV1::AdjRibInPostImportPolicy,
        peer: IpAddr::V4(RECEIVED),
        peer_asn: 65002,
        peer_router_id: RECEIVED,
        family: WarmBundleFamilyV1::Ipv4Unicast,
        add_path_receive: false,
    };
    let digest = "0".repeat(64);
    let identity = WarmBundleIdentityV1 {
        checkpoint_generation: generation.clone(),
        created_at_utc_seconds: 1_800_000_000,
        snapshot_revision: 1,
        local_asn: 65001,
        local_router_id: Ipv4Addr::new(10, 0, 0, 1),
        peer_index_table_view: generation.clone(),
        config_sha256: digest.clone(),
        resolved_import_policy: WarmBundlePolicyDigestV1 {
            version: 1,
            sha256: digest.clone(),
        },
        views: vec![view.clone()],
    };
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(
        temp.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    let dir = WarmBundleDirectory::open(temp.path()).unwrap();
    let manifest = write_warm_bundle(&dir, identity, &snapshot).unwrap();
    assert_eq!(manifest.view_route_counts, [1]);
    let expected = WarmBundleExpectedV1 {
        checkpoint_generation: generation,
        local_asn: 65001,
        local_router_id: Ipv4Addr::new(10, 0, 0, 1),
        config_sha256: digest.clone(),
        resolved_import_policy: WarmBundlePolicyDigestV1 {
            version: 1,
            sha256: digest,
        },
        views: vec![view],
    };
    let freshness = WarmBundleFreshnessV1 {
        now_utc_seconds: 1_800_000_010,
        max_age_seconds: 60,
        max_future_skew_seconds: 5,
    };
    let loaded = load_warm_bundle(&dir, &expected, freshness).unwrap();
    let recovered: Vec<_> = SnapshotReader::new(&loaded.snapshot)
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].nlri, SnapshotNlri::Unicast(routes[0].prefix));
    assert_eq!(recovered[0].next_hop, Some(routes[0].next_hop));
    assert_eq!(recovered[0].attributes, routes[0].attributes.as_slice());
}

#[tokio::test]
async fn bmp_loc_rib_announce_of_a_received_ipv4_route_carries_one_next_hop() {
    for action in [None, Some(NextHopAction::Self_)] {
        let routes = stored_routes(action).await;
        let pdu = rustbgpd_rib::bmp_sync::synthesize_unicast_announce(&routes[0]).unwrap();
        // The 19-byte BGP header precedes the UPDATE body.
        let mut body = pdu.slice(19..);
        let body_len = body.len();
        let update = UpdateMessage::decode(&mut body, body_len).unwrap();
        let parsed = update.parse_revised(true, false, false, &[]).unwrap();
        let next_hops: Vec<_> = parsed
            .update
            .attributes
            .iter()
            .filter_map(|attr| match attr {
                PathAttribute::NextHop(next_hop) => Some(IpAddr::V4(*next_hop)),
                _ => None,
            })
            .collect();
        assert_eq!(next_hops, [routes[0].next_hop]);
        assert!(parsed.malformed.is_empty(), "{:?}", parsed.malformed);
    }
}

/// IPv6 unicast keeps its next hop in the MRT-reduced `MP_REACH_NLRI`,
/// including the link-local half, and never gains a `NEXT_HOP`.
#[tokio::test]
async fn mrt_dump_of_a_received_ipv6_route_keeps_mp_reach_next_hop() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv6, Safi::Unicast)];
    session.negotiated = Some(Arc::new(negotiated));
    let global: Ipv6Addr = "2001:db8::2".parse().unwrap();
    let link_local: Ipv6Addr = "fe80::2".parse().unwrap();
    let prefix = Prefix::V6(Ipv6Prefix::new("2001:db8:100::".parse().unwrap(), 48));
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::MpReachNlri(Box::new(MpReachNlri {
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
            next_hop: IpAddr::V6(global),
            link_local_next_hop: Some(link_local),
            announced: vec![NlriEntry { path_id: 0, prefix }],
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: vec![],
        })),
    ];
    let update = UpdateMessage::build(&[], &[], &attrs, true, false, Ipv4UnicastMode::Body);
    session.process_update(update).await;
    let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected RoutesReceived");
    };
    assert_eq!(announced.len(), 1);
    let snapshot = rustbgpd_mrt::codec::encode_snapshot(
        Ipv4Addr::new(10, 0, 0, 1),
        &peers(),
        &announced,
        &[],
        1_800_000_000,
    )
    .unwrap();
    let mut reader = SnapshotReader::new(&snapshot).unwrap();
    let entries: Vec<_> = reader.by_ref().map(Result::unwrap).collect();
    assert_eq!(reader.discarded_path_attributes(), 0);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].nlri, SnapshotNlri::Unicast(prefix));
    assert_eq!(entries[0].next_hop, Some(IpAddr::V6(global)));
    assert_eq!(entries[0].link_local_next_hop, Some(link_local));
    assert_eq!(entries[0].attributes, announced[0].attributes.as_slice());
}
