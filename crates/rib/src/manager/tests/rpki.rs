use super::*;
use crate::manager::helpers::AspaInvalidHopSummary;

/// Red proof: retention, eviction/admission accounting, or counts/order break exact output.
#[test]
fn aspa_invalid_hop_summary_keeps_smallest_pairs_and_exact_suppression() {
    let mut summary = AspaInvalidHopSummary::default();
    for customer_asn in 2..=9 {
        summary.observe(rustbgpd_rpki::AspaInvalidHop {
            customer_asn,
            provider_asn: customer_asn + 100,
        });
    }
    for _ in 0..2 {
        summary.observe(rustbgpd_rpki::AspaInvalidHop {
            customer_asn: 9,
            provider_asn: 109,
        });
    }
    summary.observe(rustbgpd_rpki::AspaInvalidHop {
        customer_asn: 1,
        provider_asn: 101,
    });
    for _ in 0..2 {
        summary.observe(rustbgpd_rpki::AspaInvalidHop {
            customer_asn: 10,
            provider_asn: 110,
        });
        summary.observe(rustbgpd_rpki::AspaInvalidHop {
            customer_asn: 1,
            provider_asn: 101,
        });
    }
    assert_eq!(summary.routes, 15);
    assert_eq!(summary.suppressed_routes, 5);
    let rendered = summary.render();
    assert_eq!(
        rendered,
        "1>101:3, 2>102:1, 3>103:1, 4>104:1, 5>105:1, 6>106:1, 7>107:1, 8>108:1"
    );
    assert!(rendered.len() <= 512);
}

/// Red proof: deleting/splitting the event or skipping unchanged Invalid breaks exact fields.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "single-subscriber event fixture asserts the complete bounded log contract"
)]
fn aspa_cache_update_emits_one_bounded_completion_event() {
    use std::collections::BTreeMap;
    use std::sync::{Arc as StdArc, Mutex};

    use rustbgpd_rpki::{AspaRecord, AspaTable};
    use tracing::field::{Field, Visit};
    use tracing::span::{Attributes, Id, Record};
    use tracing::{Event, Metadata, Subscriber};

    #[derive(Default)]
    struct Fields(BTreeMap<String, String>);
    impl Visit for Fields {
        fn record_u64(&mut self, field: &Field, value: u64) {
            self.0.insert(field.name().to_string(), value.to_string());
        }
        fn record_str(&mut self, field: &Field, value: &str) {
            self.0.insert(field.name().to_string(), value.to_string());
        }
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.0
                .insert(field.name().to_string(), format!("{value:?}"));
        }
    }

    struct Capture(StdArc<Mutex<Vec<Fields>>>);
    impl Subscriber for Capture {
        fn enabled(&self, _: &Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &Attributes<'_>) -> Id {
            Id::from_u64(1)
        }
        fn record(&self, _: &Id, _: &Record<'_>) {}
        fn record_follows_from(&self, _: &Id, _: &Id) {}
        fn event(&self, event: &Event<'_>) {
            let mut fields = Fields::default();
            event.record(&mut fields);
            self.0.lock().unwrap().push(fields);
        }
        fn enter(&self, _: &Id) {}
        fn exit(&self, _: &Id) {}
    }

    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 8));
    let mut first = make_route_with_as_path(
        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 1, 0), 24),
        Ipv4Addr::new(1, 0, 0, 8),
        vec![65002, 65003],
    );
    first.aspa_state = rustbgpd_wire::AspaValidation::Valid;
    let mut unchanged = make_route_with_as_path(
        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 2, 0), 24),
        Ipv4Addr::new(1, 0, 0, 8),
        vec![65004, 65005],
    );
    unchanged.aspa_state = rustbgpd_wire::AspaValidation::Invalid;
    let mut rib = crate::adj_rib_in::AdjRibIn::new(peer);
    rib.insert(first);
    rib.insert(unchanged);
    manager.ribs.insert(peer, rib);

    let captured = StdArc::new(Mutex::new(Vec::new()));
    manager.aspa_table = Some(Arc::new(AspaTable::new(vec![])));
    let table = Arc::new(AspaTable::new(vec![
        AspaRecord {
            customer_asn: 65003,
            provider_asns: vec![99],
        },
        AspaRecord {
            customer_asn: 65005,
            provider_asns: vec![99],
        },
    ]));
    tracing::subscriber::with_default(Capture(StdArc::clone(&captured)), || {
        // Sibling tests in this module drive the same completion callsite
        // through `manager.run()` on tokio workers that have no subscriber
        // installed. Whichever thread wins a callsite's one-shot registration
        // decides its cached `Interest`, and a no-subscriber thread caches
        // `Interest::never()` for it process-wide; a scoped subscriber does
        // not invalidate that cache, so the measured call below can be
        // dropped on the macro's cached-interest fast path before any
        // subscriber sees it. Warm the callsite on a throwaway manager, then
        // re-register it against this subscriber — a callsite registers once,
        // so the measured call cannot lose that race afterwards.
        let (_warm_tx, warm_rx) = mpsc::channel(1);
        let mut warm = RibManager::new(warm_rx, dummy_query_rx(), None, None, BgpMetrics::new());
        warm.handle_aspa_cache_update(Arc::clone(&table), None);
        tracing::callsite::rebuild_interest_cache();
        captured.lock().unwrap().clear();

        manager.handle_aspa_cache_update(table, Some(rustc_hash::FxHashSet::from_iter([65003])));
    });

    // Count *the* completion event, not this thread's global event volume.
    let all = captured.lock().unwrap();
    let events: Vec<&Fields> = all
        .iter()
        .filter(|fields| {
            fields
                .0
                .get("message")
                .is_some_and(|message| message == "ASPA cache update re-validation complete")
        })
        .collect();
    assert_eq!(events.len(), 1);
    let fields = &events[0].0;
    for (name, value) in [
        ("records", "2"),
        ("mode", "delta"),
        ("routes_scanned", "2"),
        ("routes_revalidated", "1"),
        ("changed_routes", "1"),
        ("affected_prefixes", "1"),
        ("invalid_hop_routes", "1"),
        ("suppressed_routes", "0"),
    ] {
        assert_eq!(fields.get(name).map(String::as_str), Some(value), "{name}");
    }
    assert_eq!(
        fields.get("invalid_hops").map(String::as_str),
        Some("65003>65002:1")
    );
    assert!(fields.contains_key("elapsed_ms"));
}

#[test]
fn aspa_delta_revalidates_only_intersecting_paths_across_segments() {
    use rustbgpd_rpki::AspaTable;
    use rustbgpd_wire::AspaValidation;

    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let paths = [
        vec![65010, 65100],
        vec![65101, 65010, 65102],
        vec![65103, 65010],
        vec![65200, 65201],
    ];
    let mut rib = crate::adj_rib_in::AdjRibIn::new(peer);
    for (octet, path) in (1_u8..).zip(paths) {
        let mut route = make_route_with_as_path(
            Ipv4Prefix::new(Ipv4Addr::new(10, 0, octet, 0), 24),
            Ipv4Addr::new(192, 0, 2, 1),
            path,
        );
        route.aspa_state = AspaValidation::Valid;
        rib.insert(route);
    }
    let mut as_set = make_route_with_as_path(
        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 5, 0), 24),
        Ipv4Addr::new(192, 0, 2, 1),
        vec![],
    );
    as_set.attributes = Arc::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSet(vec![65010, 65300])],
        }),
    ]);
    as_set.aspa_state = AspaValidation::Valid;
    rib.insert(as_set);
    manager.ribs.insert(peer, rib);
    manager.aspa_table = Some(Arc::new(AspaTable::new(vec![])));

    manager.handle_aspa_cache_update(
        Arc::new(AspaTable::new(vec![])),
        Some(rustc_hash::FxHashSet::from_iter([65010])),
    );

    let states: Vec<_> = manager.ribs[&peer]
        .iter()
        .map(|route| route.aspa_state)
        .collect();
    assert_eq!(
        states
            .iter()
            .filter(|state| **state == AspaValidation::Unknown)
            .count(),
        3
    );
    assert_eq!(
        states
            .iter()
            .filter(|state| **state == AspaValidation::Invalid)
            .count(),
        1
    );
    assert_eq!(
        states
            .iter()
            .filter(|state| **state == AspaValidation::Valid)
            .count(),
        1
    );
    assert_eq!(
        manager.ribs[&peer]
            .iter()
            .find(
                |route| route.prefix == Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 4, 0), 24))
            )
            .unwrap()
            .aspa_state,
        AspaValidation::Valid,
        "disjoint poison proves the route was scanned but not revalidated"
    );
}

#[test]
fn aspa_first_delta_forces_full_rescan() {
    use rustbgpd_rpki::AspaTable;
    use rustbgpd_wire::AspaValidation;

    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
    let mut route = make_route_with_as_path(
        Ipv4Prefix::new(Ipv4Addr::new(10, 1, 0, 0), 24),
        Ipv4Addr::new(192, 0, 2, 2),
        vec![65100, 65101],
    );
    route.aspa_state = AspaValidation::Valid;
    let mut rib = crate::adj_rib_in::AdjRibIn::new(peer);
    rib.insert(route);
    manager.ribs.insert(peer, rib);

    manager.handle_aspa_cache_update(
        Arc::new(AspaTable::new(vec![])),
        Some(rustc_hash::FxHashSet::from_iter([65010])),
    );
    assert_eq!(
        manager.ribs[&peer].iter().next().unwrap().aspa_state,
        AspaValidation::Unknown
    );
}

#[test]
fn aspa_none_forces_full_rescan() {
    use rustbgpd_rpki::AspaTable;
    use rustbgpd_wire::AspaValidation;

    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3));
    let mut route = make_route_with_as_path(
        Ipv4Prefix::new(Ipv4Addr::new(10, 2, 0, 0), 24),
        Ipv4Addr::new(192, 0, 2, 3),
        vec![65100, 65101],
    );
    route.aspa_state = AspaValidation::Valid;
    let mut rib = crate::adj_rib_in::AdjRibIn::new(peer);
    rib.insert(route);
    manager.ribs.insert(peer, rib);
    manager.aspa_table = Some(Arc::new(AspaTable::new(vec![])));

    manager.handle_aspa_cache_update(Arc::new(AspaTable::new(vec![])), None);
    assert_eq!(
        manager.ribs[&peer].iter().next().unwrap().aspa_state,
        AspaValidation::Unknown
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one differential fixture keeps the 40-step state-machine oracle auditable"
)]
fn aspa_delta_matches_full_rescan_on_deterministic_sequences() {
    use rustbgpd_rpki::{AspaRecord, AspaTable};

    fn fixture_manager() -> RibManager {
        let (_tx, rx) = mpsc::channel(1);
        let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
        for peer_octet in [10_u8, 11] {
            let peer = Ipv4Addr::new(192, 0, 2, peer_octet);
            let mut routes = vec![
                make_route_with_as_path(
                    Ipv4Prefix::new(Ipv4Addr::new(10, 3, 1, 0), 24),
                    peer,
                    vec![65001, 65002],
                ),
                make_route_with_as_path(
                    Ipv4Prefix::new(Ipv4Addr::new(10, 3, 2, 0), 24),
                    peer,
                    vec![65003, 65004, 65004],
                ),
                make_route_with_as_path(
                    Ipv4Prefix::new(Ipv4Addr::new(10, 3, 3, 0), 24),
                    peer,
                    vec![],
                ),
                make_route_with_as_path(
                    Ipv4Prefix::new(Ipv4Addr::new(10, 3, 4, 0), 24),
                    peer,
                    vec![],
                ),
                make_route_with_as_path(
                    Ipv4Prefix::new(Ipv4Addr::new(10, 3, 5, 0), 24),
                    peer,
                    vec![65006, 65007],
                ),
                make_route_with_as_path(
                    Ipv4Prefix::new(Ipv4Addr::new(10, 3, 6, 0), 24),
                    peer,
                    vec![65008, 65009, 65010],
                ),
            ];
            routes[2].attributes = Arc::new(vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![
                        AsPathSegment::AsSequence(vec![65005]),
                        AsPathSegment::AsSet(vec![65006, 65007]),
                    ],
                }),
            ]);
            routes[3].attributes = Arc::new(vec![PathAttribute::Origin(Origin::Igp)]);
            routes[4].origin_type = crate::route::RouteOrigin::Ibgp;
            manager.handle_update(RibUpdate::RoutesReceived {
                session_id: 0,
                peer: IpAddr::V4(peer),
                announced: routes,
                withdrawn: vec![],
                flowspec_announced: vec![],
                flowspec_withdrawn: vec![],
                evpn_announced: vec![],
                evpn_withdrawn: vec![],
            });
        }
        manager
    }

    fn snapshot(manager: &RibManager) -> (Vec<String>, Vec<String>) {
        let mut adj: Vec<_> = manager
            .ribs
            .iter()
            .flat_map(|(peer, rib)| {
                rib.iter().map(move |route| {
                    format!(
                        "{peer}|{}|{}|{:?}",
                        route.prefix, route.path_id, route.aspa_state
                    )
                })
            })
            .collect();
        let mut loc: Vec<_> = manager
            .loc_rib
            .iter()
            .map(|route| {
                format!(
                    "{}|{}|{}|{:?}",
                    route.prefix, route.peer, route.path_id, route.aspa_state
                )
            })
            .collect();
        adj.sort_unstable();
        loc.sort_unstable();
        (adj, loc)
    }

    fn table(records: &BTreeMap<u32, Vec<u32>>) -> Arc<AspaTable> {
        Arc::new(AspaTable::new(
            records
                .iter()
                .map(|(customer_asn, provider_asns)| AspaRecord {
                    customer_asn: *customer_asn,
                    provider_asns: provider_asns.clone(),
                })
                .collect(),
        ))
    }

    let mut delta_manager = fixture_manager();
    let mut full_manager = fixture_manager();
    let mut records = BTreeMap::new();
    records.insert(65002, vec![65001]);
    let mut current = table(&records);
    delta_manager.handle_aspa_cache_update(Arc::clone(&current), None);
    full_manager.handle_aspa_cache_update(Arc::clone(&current), None);
    assert_eq!(snapshot(&delta_manager), snapshot(&full_manager));

    let mut distributed = 0;
    let mut suppressed = 0;
    for step in 0_u32..40 {
        let customer = 65001 + (step % 10);
        match step % 5 {
            0 => {
                records.insert(customer, vec![66000 + (step % 3)]);
            }
            1 => {
                records.insert(customer, vec![66000, 66001]);
            }
            2 => {
                records.remove(&customer);
            }
            3 => {
                records.insert(customer, vec![66001, 66002]);
            }
            _ => {}
        }
        let next = table(&records);
        if *next == *current {
            suppressed += 1;
            continue;
        }
        delta_manager.handle_aspa_cache_update(
            Arc::clone(&next),
            Some(rustc_hash::FxHashSet::from_iter([customer])),
        );
        full_manager.handle_aspa_cache_update(Arc::clone(&next), None);
        current = next;
        distributed += 1;
        assert_eq!(
            snapshot(&delta_manager),
            snapshot(&full_manager),
            "diverged at deterministic step {step}"
        );
    }
    assert_eq!(distributed + suppressed, 40);
    assert!(distributed > 0);
    assert!(suppressed >= 4);
}

#[test]
fn validate_route_rpki_valid() {
    use rustbgpd_rpki::{VrpEntry, VrpTable};
    let table = VrpTable::new(vec![VrpEntry {
        prefix: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
        prefix_len: 24,
        max_len: 24,
        origin_asn: 65001,
    }]);
    let route = make_route_with_as_path(
        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24),
        Ipv4Addr::new(1, 0, 0, 1),
        vec![65001],
    );
    assert_eq!(
        super::validate_route_rpki(&route, &table),
        RpkiValidation::Valid,
    );
}

#[test]
fn validate_route_rpki_invalid() {
    use rustbgpd_rpki::{VrpEntry, VrpTable};
    let table = VrpTable::new(vec![VrpEntry {
        prefix: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
        prefix_len: 24,
        max_len: 24,
        origin_asn: 65001,
    }]);
    // Origin AS 65002 doesn't match VRP
    let route = make_route_with_as_path(
        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24),
        Ipv4Addr::new(1, 0, 0, 1),
        vec![65002],
    );
    assert_eq!(
        super::validate_route_rpki(&route, &table),
        RpkiValidation::Invalid,
    );
}

#[test]
fn validate_route_rpki_not_found() {
    use rustbgpd_rpki::{VrpEntry, VrpTable};
    let table = VrpTable::new(vec![VrpEntry {
        prefix: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
        prefix_len: 24,
        max_len: 24,
        origin_asn: 65001,
    }]);
    // Prefix 192.168.1.0/24 not covered by any VRP
    let route = make_route_with_as_path(
        Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24),
        Ipv4Addr::new(1, 0, 0, 1),
        vec![65001],
    );
    assert_eq!(
        super::validate_route_rpki(&route, &table),
        RpkiValidation::NotFound,
    );
}

#[test]
fn validate_route_rpki_no_as_path() {
    use rustbgpd_rpki::{VrpEntry, VrpTable};
    let table = VrpTable::new(vec![VrpEntry {
        prefix: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
        prefix_len: 24,
        max_len: 24,
        origin_asn: 65001,
    }]);
    // Route with no AS_PATH
    let route = make_route(
        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24),
        Ipv4Addr::new(1, 0, 0, 1),
    );
    assert_eq!(
        super::validate_route_rpki(&route, &table),
        RpkiValidation::NotFound,
    );
}

#[test]
fn validate_route_rpki_empty_as_path() {
    use rustbgpd_rpki::{VrpEntry, VrpTable};
    let table = VrpTable::new(vec![VrpEntry {
        prefix: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
        prefix_len: 24,
        max_len: 24,
        origin_asn: 65001,
    }]);
    // Route with empty AS_PATH (no segments)
    let route = Route {
        prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
        next_hop: IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
        attributes: Arc::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath { segments: vec![] }),
            PathAttribute::LocalPref(100),
        ]),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    };
    assert_eq!(
        super::validate_route_rpki(&route, &table),
        RpkiValidation::NotFound,
    );
}

#[tokio::test]
async fn routes_validated_on_insert_with_vrp_table() {
    use rustbgpd_rpki::{VrpEntry, VrpTable};
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    // Send RPKI cache update first
    let table = Arc::new(VrpTable::new(vec![VrpEntry {
        prefix: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
        prefix_len: 24,
        max_len: 24,
        origin_asn: 65001,
    }]));
    tx.send(RibUpdate::RpkiCacheUpdate { table, delta: None })
        .await
        .unwrap();

    // Now send a route with matching origin
    let peer = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
    let route = make_route_with_as_path(
        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24),
        Ipv4Addr::new(1, 0, 0, 1),
        vec![65001],
    );
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Query received routes — should have Valid validation state
    let routes = query_received_routes(&tx, peer).await;
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].validation_state, RpkiValidation::Valid);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn rpki_cache_update_revalidates_existing_routes() {
    use rustbgpd_rpki::{VrpEntry, VrpTable};
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
    let route = make_route_with_as_path(
        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24),
        Ipv4Addr::new(1, 0, 0, 1),
        vec![65001],
    );

    // Insert route (no VRP table yet → NotFound)
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Verify it's NotFound
    let routes = query_received_routes(&tx, peer).await;
    assert_eq!(routes[0].validation_state, RpkiValidation::NotFound);

    // Now send VRP table that covers the route
    let table = Arc::new(VrpTable::new(vec![VrpEntry {
        prefix: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
        prefix_len: 24,
        max_len: 24,
        origin_asn: 65001,
    }]));
    tx.send(RibUpdate::RpkiCacheUpdate { table, delta: None })
        .await
        .unwrap();

    // Query again — should be Valid now
    let routes = query_received_routes(&tx, peer).await;
    assert_eq!(routes[0].validation_state, RpkiValidation::Valid);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn rpki_cache_update_changes_best_path() {
    use rustbgpd_rpki::{VrpEntry, VrpTable};
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);

    // Both routes same LP, same AS_PATH length. peer1 has lower peer address → wins initially.
    let route1 = make_route_with_as_path(prefix, Ipv4Addr::new(1, 0, 0, 1), vec![65001]);
    let route2 = make_route_with_as_path(prefix, Ipv4Addr::new(1, 0, 0, 2), vec![65002]);

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer1,
        announced: vec![route1],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer2,
        announced: vec![route2],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Before RPKI: peer1 should be best (lower address)
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes {
        deadline: full_snapshot_query_deadline(),
        reply: reply_tx,
    })
    .await
    .unwrap();
    let best = reply_rx.await.unwrap();
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].peer, peer1);

    // Now send VRP that only validates peer2's origin
    let table = Arc::new(VrpTable::new(vec![VrpEntry {
        prefix: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
        prefix_len: 24,
        max_len: 24,
        origin_asn: 65002,
    }]));
    tx.send(RibUpdate::RpkiCacheUpdate { table, delta: None })
        .await
        .unwrap();

    // After RPKI: peer2 should be best (Valid > NotFound)
    // But peer1's route has origin 65001, not covered → still NotFound.
    // peer2's route has origin 65002, covered with matching ASN → Valid.
    // Wait a moment for processing...
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes {
        deadline: full_snapshot_query_deadline(),
        reply: reply_tx,
    })
    .await
    .unwrap();
    let best = reply_rx.await.unwrap();
    assert_eq!(best.len(), 1);
    // peer2 wins: Valid beats NotFound
    assert_eq!(best[0].peer, peer2);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn rpki_cache_update_invalid_demotes_best_path() {
    use rustbgpd_rpki::{VrpEntry, VrpTable};
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
    let peer2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);

    // peer1 has lower address → wins initially
    let route1 = make_route_with_as_path(prefix, Ipv4Addr::new(1, 0, 0, 1), vec![65001]);
    let route2 = make_route_with_as_path(prefix, Ipv4Addr::new(1, 0, 0, 2), vec![65002]);

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer1,
        announced: vec![route1],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: peer2,
        announced: vec![route2],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // VRP covers the prefix but only for AS 65002 → peer1 (65001) becomes Invalid
    let table = Arc::new(VrpTable::new(vec![VrpEntry {
        prefix: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
        prefix_len: 24,
        max_len: 24,
        origin_asn: 65002,
    }]));
    tx.send(RibUpdate::RpkiCacheUpdate { table, delta: None })
        .await
        .unwrap();

    // peer1 is now Invalid (VRP covers prefix but wrong origin), peer2 is Valid
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutes {
        deadline: full_snapshot_query_deadline(),
        reply: reply_tx,
    })
    .await
    .unwrap();
    let best = reply_rx.await.unwrap();
    assert_eq!(best.len(), 1);
    assert_eq!(best[0].peer, peer2);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn rpki_no_table_all_not_found() {
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
    let route = make_route_with_as_path(
        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24),
        Ipv4Addr::new(1, 0, 0, 1),
        vec![65001],
    );
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let routes = query_received_routes(&tx, peer).await;
    assert_eq!(routes[0].validation_state, RpkiValidation::NotFound);

    drop(tx);
    handle.await.unwrap();
}

/// Load-bearing RIB replay proof: removing the `!route.is_ebgp()` guard makes
/// insertion evaluate Valid and the cache update evaluate Invalid, so both
/// exact Unknown assertions fail.
#[tokio::test]
async fn ibgp_aspa_stays_unknown_on_insert_and_cache_revalidation() {
    use rustbgpd_rpki::{AspaRecord, AspaTable};

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());
    let peer = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 5));
    let valid_table = Arc::new(AspaTable::new(vec![AspaRecord {
        customer_asn: 65003,
        provider_asns: vec![65002],
    }]));
    tx.send(RibUpdate::AspaTableUpdate {
        table: valid_table,
        changed_customer_asns: None,
    })
    .await
    .unwrap();

    let mut route = make_route_with_as_path(
        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24),
        Ipv4Addr::new(1, 0, 0, 5),
        vec![65002, 65003],
    );
    route.origin_type = crate::route::RouteOrigin::Ibgp;
    route.aspa_context = rustbgpd_wire::AspaValidationContext {
        neighbor_asn: Some(65002),
        local_role: None,
        first_as_check_exempt: false,
    };
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let query = async |tx: &mpsc::Sender<RibUpdate>| query_received_routes(tx, peer).await;
    let inserted = query(&tx).await;
    assert_eq!(
        inserted[0].aspa_state,
        rustbgpd_wire::AspaValidation::Unknown
    );

    let invalid_table = Arc::new(AspaTable::new(vec![AspaRecord {
        customer_asn: 65003,
        provider_asns: vec![65099],
    }]));
    tx.send(RibUpdate::AspaTableUpdate {
        table: invalid_table,
        changed_customer_asns: None,
    })
    .await
    .unwrap();
    let revalidated = query(&tx).await;
    assert_eq!(
        revalidated[0].aspa_state,
        rustbgpd_wire::AspaValidation::Unknown
    );

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn aspa_cache_update_revalidates_with_stored_downstream_context() {
    use rustbgpd_rpki::{AspaRecord, AspaTable};

    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 4));
    let mut route = make_route_with_as_path(
        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24),
        Ipv4Addr::new(1, 0, 0, 4),
        vec![65004, 65003, 65002, 65001],
    );
    route.aspa_context = rustbgpd_wire::AspaValidationContext {
        neighbor_asn: Some(65004),
        local_role: Some(rustbgpd_wire::BgpRole::Customer),
        first_as_check_exempt: false,
    };

    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    let table = Arc::new(AspaTable::new(vec![
        AspaRecord {
            customer_asn: 65004,
            provider_asns: vec![65003],
        },
        AspaRecord {
            customer_asn: 65003,
            provider_asns: vec![65002],
        },
        AspaRecord {
            customer_asn: 65002,
            provider_asns: vec![65001],
        },
    ]));
    tx.send(RibUpdate::AspaTableUpdate {
        table,
        changed_customer_asns: None,
    })
    .await
    .unwrap();

    let routes = query_received_routes(&tx, peer).await;
    assert_eq!(routes[0].aspa_state, rustbgpd_wire::AspaValidation::Valid);

    drop(tx);
    handle.await.unwrap();
}

#[tokio::test]
async fn rpki_cache_update_no_change_no_redistribution() {
    use rustbgpd_rpki::{VrpEntry, VrpTable};
    let (tx, rx) = mpsc::channel(64);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let handle = tokio::spawn(manager.run());

    let peer = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
    let (out_tx, mut out_rx) = mpsc::channel(16);

    tx.send(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: out_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    })
    .await
    .unwrap();
    drain_eor(&mut out_rx).await;

    // Insert route with origin 65001
    let route = make_route_with_as_path(
        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24),
        Ipv4Addr::new(1, 0, 0, 1),
        vec![65001],
    );
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer,
        announced: vec![route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    })
    .await
    .unwrap();

    // Consume the outbound update from route insertion (split-horizon blocks it
    // since peer == route.peer, so nothing should arrive)
    // Send an unrelated VRP table that doesn't cover our prefix
    let table = Arc::new(VrpTable::new(vec![VrpEntry {
        prefix: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)),
        prefix_len: 16,
        max_len: 24,
        origin_asn: 65099,
    }]));
    tx.send(RibUpdate::RpkiCacheUpdate { table, delta: None })
        .await
        .unwrap();

    // Verify route stays NotFound — no VRP covers 10.0.0.0/24
    let routes = query_received_routes(&tx, peer).await;
    assert_eq!(routes[0].validation_state, RpkiValidation::NotFound);

    drop(tx);
    handle.await.unwrap();
}

// ---- Add-Path multi-path send tests ----

// ---- Delta-scoped revalidation (LAN-1029) ----
//
// Correctness fence: the delta arm must produce validation outcomes
// identical to a full rescan — only which routes get revisited changes.
// Several tests poison an uncovered route's stored state as a sentinel:
// the delta arm must NOT touch it (a full rescan would repair it), which
// proves both the scoping and which arm actually ran.

fn delta_vrp(addr: Ipv4Addr, prefix_len: u8, max_len: u8, asn: u32) -> rustbgpd_rpki::VrpEntry {
    rustbgpd_rpki::VrpEntry {
        prefix: IpAddr::V4(addr),
        prefix_len,
        max_len,
        origin_asn: asn,
    }
}

fn delta_table(entries: &[rustbgpd_rpki::VrpEntry]) -> Arc<rustbgpd_rpki::VrpTable> {
    Arc::new(rustbgpd_rpki::VrpTable::new(entries.to_vec()))
}

fn delta_manager() -> RibManager {
    let (_tx, rx) = mpsc::channel(1);
    RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
}

fn insert_routes(manager: &mut RibManager, peer: Ipv4Addr, routes: Vec<Route>) {
    let peer = IpAddr::V4(peer);
    let mut rib = crate::adj_rib_in::AdjRibIn::new(peer);
    for route in routes {
        rib.insert(route);
    }
    manager.ribs.insert(peer, rib);
}

fn set_state(manager: &mut RibManager, peer: IpAddr, prefix: Prefix, state: RpkiValidation) {
    manager
        .ribs
        .get_mut(&peer)
        .unwrap()
        .iter_mut()
        .find(|r| r.prefix == prefix)
        .unwrap()
        .validation_state = state;
}

fn state_of(manager: &RibManager, peer: IpAddr, prefix: Prefix) -> RpkiValidation {
    manager
        .ribs
        .get(&peer)
        .unwrap()
        .iter()
        .find(|r| r.prefix == prefix)
        .unwrap()
        .validation_state
}

fn rpki_states(manager: &RibManager) -> Vec<(IpAddr, Prefix, u32, RpkiValidation)> {
    let mut out: Vec<(IpAddr, Prefix, u32, RpkiValidation)> = manager
        .ribs
        .iter()
        .flat_map(|(peer, rib)| {
            rib.iter()
                .map(move |r| (*peer, r.prefix, r.path_id, r.validation_state))
        })
        .collect();
    out.sort_unstable_by_key(|&(peer, prefix, path_id, _)| (peer, prefix, path_id));
    out
}

#[test]
fn rpki_delta_revalidates_only_covered_routes() {
    let mut manager = delta_manager();
    let peer = Ipv4Addr::new(1, 0, 0, 1);
    let covered = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24));
    let more_specific = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 1, 0), 25));
    let outside = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 168, 0, 0), 24));
    insert_routes(
        &mut manager,
        peer,
        vec![
            make_route_with_as_path(
                Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24),
                peer,
                vec![65001],
            ),
            make_route_with_as_path(
                Ipv4Prefix::new(Ipv4Addr::new(10, 0, 1, 0), 25),
                peer,
                vec![65002],
            ),
            make_route_with_as_path(
                Ipv4Prefix::new(Ipv4Addr::new(192, 168, 0, 0), 24),
                peer,
                vec![65003],
            ),
        ],
    );
    let peer = IpAddr::V4(peer);

    // Baseline snapshot (first table always full-rescans): everything NotFound.
    manager.handle_rpki_cache_update(delta_table(&[]), None);
    assert_eq!(state_of(&manager, peer, covered), RpkiValidation::NotFound);

    // Sentinel: poison the uncovered route's stored state.
    set_state(&mut manager, peer, outside, RpkiValidation::Valid);

    // Announce 10.0.0.0/16 max_len 25 AS65001 as an incremental delta.
    let announced = delta_vrp(Ipv4Addr::new(10, 0, 0, 0), 16, 25, 65001);
    manager.handle_rpki_cache_update(
        delta_table(std::slice::from_ref(&announced)),
        Some(vec![announced]),
    );

    // The covered set includes more-specifics of the announced VRP.
    assert_eq!(state_of(&manager, peer, covered), RpkiValidation::Valid);
    // Covered, within max_len, wrong origin → Invalid.
    assert_eq!(
        state_of(&manager, peer, more_specific),
        RpkiValidation::Invalid
    );
    // Uncovered sentinel untouched — the delta path did not scan it.
    assert_eq!(state_of(&manager, peer, outside), RpkiValidation::Valid);
}

#[test]
fn rpki_delta_withdrawal_flips_states_and_respects_overlap() {
    let mut manager = delta_manager();
    let peer1 = Ipv4Addr::new(1, 0, 0, 1);
    let peer2 = Ipv4Addr::new(1, 0, 0, 2);
    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24));
    insert_routes(
        &mut manager,
        peer1,
        vec![make_route_with_as_path(
            Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24),
            peer1,
            vec![65001],
        )],
    );
    insert_routes(
        &mut manager,
        peer2,
        vec![make_route_with_as_path(
            Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24),
            peer2,
            vec![65002],
        )],
    );
    let (peer1, peer2) = (IpAddr::V4(peer1), IpAddr::V4(peer2));

    let general = delta_vrp(Ipv4Addr::new(10, 0, 0, 0), 16, 24, 65001);
    let specific = delta_vrp(Ipv4Addr::new(10, 0, 0, 0), 24, 24, 65002);
    manager.handle_rpki_cache_update(delta_table(&[general.clone(), specific.clone()]), None);
    assert_eq!(state_of(&manager, peer1, prefix), RpkiValidation::Valid);
    assert_eq!(state_of(&manager, peer2, prefix), RpkiValidation::Valid);

    // Withdraw the general VRP: the specific one still covers, so peer1's
    // route flips Valid→Invalid (covered, wrong origin) — NOT NotFound —
    // and peer2's route is revisited but stays Valid.
    manager.handle_rpki_cache_update(
        delta_table(std::slice::from_ref(&specific)),
        Some(vec![general]),
    );
    assert_eq!(state_of(&manager, peer1, prefix), RpkiValidation::Invalid);
    assert_eq!(state_of(&manager, peer2, prefix), RpkiValidation::Valid);

    // Withdraw the last covering VRP: both flip to NotFound.
    manager.handle_rpki_cache_update(delta_table(&[]), Some(vec![specific]));
    assert_eq!(state_of(&manager, peer1, prefix), RpkiValidation::NotFound);
    assert_eq!(state_of(&manager, peer2, prefix), RpkiValidation::NotFound);
}

#[test]
fn rpki_delta_max_len_gates_valid_but_not_coverage() {
    let mut manager = delta_manager();
    let peer = Ipv4Addr::new(1, 0, 0, 1);
    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24));
    insert_routes(
        &mut manager,
        peer,
        vec![make_route_with_as_path(
            Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24),
            peer,
            vec![65001],
        )],
    );
    let peer = IpAddr::V4(peer);
    manager.handle_rpki_cache_update(delta_table(&[]), None);

    // The announced VRP authorizes only up to /16, but coverage is by
    // prefix-length containment: the /24 must be revisited and flip
    // NotFound→Invalid even though it can never be Valid under this VRP.
    let tight = delta_vrp(Ipv4Addr::new(10, 0, 0, 0), 16, 16, 65001);
    manager.handle_rpki_cache_update(
        delta_table(std::slice::from_ref(&tight)),
        Some(vec![tight.clone()]),
    );
    assert_eq!(state_of(&manager, peer, prefix), RpkiValidation::Invalid);

    // A second VRP for the same network with max_len 24 makes it Valid...
    let loose = delta_vrp(Ipv4Addr::new(10, 0, 0, 0), 16, 24, 65001);
    manager.handle_rpki_cache_update(
        delta_table(&[tight.clone(), loose.clone()]),
        Some(vec![loose.clone()]),
    );
    assert_eq!(state_of(&manager, peer, prefix), RpkiValidation::Valid);

    // ...and withdrawing it flips back to Invalid under the surviving
    // tighter VRP.
    manager.handle_rpki_cache_update(delta_table(std::slice::from_ref(&tight)), Some(vec![loose]));
    assert_eq!(state_of(&manager, peer, prefix), RpkiValidation::Invalid);
}

#[test]
fn rpki_first_table_with_delta_forces_full_rescan() {
    let mut manager = delta_manager();
    let peer = Ipv4Addr::new(1, 0, 0, 1);
    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24));
    insert_routes(
        &mut manager,
        peer,
        vec![make_route_with_as_path(
            Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24),
            peer,
            vec![65001],
        )],
    );
    let peer = IpAddr::V4(peer);
    // Poison before any table exists.
    set_state(&mut manager, peer, prefix, RpkiValidation::Valid);

    // The first-ever update arrives claiming a delta that does not cover
    // the route. With no baseline to delta from, the manager must ignore
    // the delta, full-rescan, and repair the poisoned state.
    let unrelated = delta_vrp(Ipv4Addr::new(192, 168, 0, 0), 24, 24, 65099);
    manager.handle_rpki_cache_update(
        delta_table(std::slice::from_ref(&unrelated)),
        Some(vec![unrelated]),
    );
    assert_eq!(state_of(&manager, peer, prefix), RpkiValidation::NotFound);
}

#[test]
fn rpki_delta_covers_ipv6_routes() {
    fn v6_route(addr: &str, len: u8, peer: Ipv4Addr, asns: Vec<u32>) -> Route {
        let mut route =
            make_route_with_as_path(Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0), peer, asns);
        route.prefix = Prefix::V6(rustbgpd_wire::Ipv6Prefix::new(addr.parse().unwrap(), len));
        route
    }

    let mut manager = delta_manager();
    let peer = Ipv4Addr::new(1, 0, 0, 1);
    let covered = Prefix::V6(rustbgpd_wire::Ipv6Prefix::new(
        "2001:db8:1::".parse().unwrap(),
        48,
    ));
    let outside = Prefix::V6(rustbgpd_wire::Ipv6Prefix::new(
        "2001:db9::".parse().unwrap(),
        32,
    ));
    insert_routes(
        &mut manager,
        peer,
        vec![
            v6_route("2001:db8:1::", 48, peer, vec![65001]),
            v6_route("2001:db9::", 32, peer, vec![65001]),
        ],
    );
    let peer = IpAddr::V4(peer);
    manager.handle_rpki_cache_update(delta_table(&[]), None);
    set_state(&mut manager, peer, outside, RpkiValidation::Invalid);

    let announced = rustbgpd_rpki::VrpEntry {
        prefix: IpAddr::V6("2001:db8::".parse().unwrap()),
        prefix_len: 32,
        max_len: 48,
        origin_asn: 65001,
    };
    manager.handle_rpki_cache_update(
        delta_table(std::slice::from_ref(&announced)),
        Some(vec![announced]),
    );
    assert_eq!(state_of(&manager, peer, covered), RpkiValidation::Valid);
    // Same family, different network: the sentinel proves it was skipped.
    assert_eq!(state_of(&manager, peer, outside), RpkiValidation::Invalid);
}

/// Differential fence: a random announce/withdraw sequence applied through
/// the delta arm and through full rescans must land every route of every
/// peer in identical validation states at every step.
#[test]
fn rpki_delta_matches_full_rescan_on_random_sequences() {
    fn rng_next(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    // VRP candidate universe with deliberate overlap: a /8 umbrella, /16s
    // and /24s at competing origins and max lengths.
    let mut candidates = vec![delta_vrp(Ipv4Addr::new(10, 0, 0, 0), 8, 24, 65001)];
    for x in 0..4u8 {
        for &(asn, max_len) in &[(65001u32, 16u8), (65001, 24), (65002, 20)] {
            candidates.push(delta_vrp(Ipv4Addr::new(10, x, 0, 0), 16, max_len, asn));
        }
        for y in 0..2u8 {
            for &(asn, max_len) in &[(65001u32, 24u8), (65002, 32), (65003, 25)] {
                candidates.push(delta_vrp(Ipv4Addr::new(10, x, y, 0), 24, max_len, asn));
            }
        }
    }

    // Identical route sets in both managers: 4 peers × mixed lengths and
    // origins across the candidate networks, plus one never-covered route
    // per peer.
    let build = || {
        let mut manager = delta_manager();
        for p in 1..=4u8 {
            let peer = Ipv4Addr::new(1, 0, 0, p);
            let mut routes = Vec::new();
            for x in 0..4u8 {
                for &(y, len) in &[(0u8, 16u8), (0, 20), (0, 24), (0, 25), (1, 24), (1, 32)] {
                    let origin = 65001 + u32::from((x + y + p) % 4);
                    routes.push(make_route_with_as_path(
                        Ipv4Prefix::new(Ipv4Addr::new(10, x, y, 0), len),
                        peer,
                        vec![64900, origin],
                    ));
                }
            }
            routes.push(make_route_with_as_path(
                Ipv4Prefix::new(Ipv4Addr::new(172, 16, p, 0), 24),
                peer,
                vec![65001],
            ));
            insert_routes(&mut manager, peer, routes);
        }
        manager
    };
    let mut with_delta = build();
    let mut with_full = build();

    let mut rng = 0x1029_5EED_u64;
    let mut current: Vec<rustbgpd_rpki::VrpEntry> = Vec::new();
    let mut prev_table = delta_table(&[]);
    for step in 0..40 {
        // 1-3 withdrawals then 1-3 announcements of random candidates,
        // mirroring the VRP manager's withdraw-before-announce order and
        // its delta = withdrawn + announced construction.
        let mut delta = Vec::new();
        for _ in 0..=(rng_next(&mut rng) % 3) {
            let pick = usize::try_from(rng_next(&mut rng)).unwrap_or(usize::MAX);
            let entry = candidates[pick % candidates.len()].clone();
            current.retain(|c| c != &entry);
            delta.push(entry);
        }
        for _ in 0..=(rng_next(&mut rng) % 3) {
            let pick = usize::try_from(rng_next(&mut rng)).unwrap_or(usize::MAX);
            let entry = candidates[pick % candidates.len()].clone();
            if !current.contains(&entry) {
                current.push(entry.clone());
            }
            delta.push(entry);
        }
        let table = delta_table(&current);
        // Mirror the VRP manager's deep-equality suppression: an update
        // that leaves the merged table unchanged is never distributed, so
        // its delta is dropped for both arms.
        if *table == *prev_table {
            continue;
        }
        prev_table = Arc::clone(&table);
        with_delta.handle_rpki_cache_update(Arc::clone(&table), Some(delta));
        with_full.handle_rpki_cache_update(table, None);
        assert_eq!(
            rpki_states(&with_delta),
            rpki_states(&with_full),
            "delta and full rescan diverged at step {step}"
        );
    }
}

/// Timing receipt at the LAN-1029 synthetic shape: 100 peers × 10k routes,
/// 1-entry delta. Two managers with identical state take the same T1→T2
/// transition, one through each arm, so the timed sections do identical
/// recompute work and differ only in revalidation scan scope. Outcomes are
/// asserted identical; timings print to stderr (run with --nocapture).
#[test]
fn rpki_delta_timing_receipt() {
    let build = || {
        let mut manager = delta_manager();
        for p in 0..100u8 {
            let peer = Ipv4Addr::new(1, 0, p, 1);
            let mut routes = Vec::with_capacity(10_000);
            for a in 0..40u8 {
                for b in 0..250u8 {
                    // 10.0.0.0/24 carries origin 65002 so the delta below
                    // flips exactly that route on every peer.
                    let origin = if a == 0 && b == 0 { 65002 } else { 65001 };
                    routes.push(make_route_with_as_path(
                        Ipv4Prefix::new(Ipv4Addr::new(10, a, b, 0), 24),
                        peer,
                        vec![64900, origin],
                    ));
                }
            }
            insert_routes(&mut manager, peer, routes);
        }
        manager
    };

    // T1: one VRP per route prefix authorizing AS65001.
    let mut t1_entries = Vec::with_capacity(10_000);
    for a in 0..40u8 {
        for b in 0..250u8 {
            t1_entries.push(delta_vrp(Ipv4Addr::new(10, a, b, 0), 24, 24, 65001));
        }
    }
    let t1 = delta_table(&t1_entries);
    // T2 = T1 + one VRP authorizing AS65002 on 10.0.0.0/24.
    let extra = delta_vrp(Ipv4Addr::new(10, 0, 0, 0), 24, 24, 65002);
    let mut t2_entries = t1_entries.clone();
    t2_entries.push(extra.clone());
    let t2 = delta_table(&t2_entries);

    let mut with_full = build();
    let mut with_delta = build();
    with_full.handle_rpki_cache_update(Arc::clone(&t1), None);
    with_delta.handle_rpki_cache_update(Arc::clone(&t1), None);

    let target = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24));
    let probe_peer = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
    assert_eq!(
        state_of(&with_full, probe_peer, target),
        RpkiValidation::Invalid
    );
    assert_eq!(
        state_of(&with_delta, probe_peer, target),
        RpkiValidation::Invalid
    );

    let started = std::time::Instant::now();
    with_full.handle_rpki_cache_update(Arc::clone(&t2), None);
    let full_elapsed = started.elapsed();
    let started = std::time::Instant::now();
    with_delta.handle_rpki_cache_update(t2, Some(vec![extra]));
    let delta_elapsed = started.elapsed();

    // Identical outcomes on every peer: the 10.0.0.0/24 route flipped
    // Invalid→Valid through both arms.
    assert_eq!(rpki_states(&with_full), rpki_states(&with_delta));
    for p in 0..100u8 {
        let peer = IpAddr::V4(Ipv4Addr::new(1, 0, p, 1));
        assert_eq!(state_of(&with_delta, peer, target), RpkiValidation::Valid);
    }
    eprintln!(
        "rpki revalidation receipt (100 peers x 10k routes, 1-entry delta): \
         full={full_elapsed:?} delta={delta_elapsed:?}"
    );
}
