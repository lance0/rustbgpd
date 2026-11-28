//! A registered peer's metric binding (`RibManager::peer_series`): commits
//! publish through children resolved once per registration, re-resolve
//! them after any removal of their series, and scrape exactly as the unbound
//! writers did.

use std::collections::BTreeMap;

use super::outbound_prefix_limits::announce;
use super::*;
use crate::peer_id::LABELS_FORMATTED;
use crate::test_support::peer_v4;

const SOURCE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

/// The families a binding writes.
const BOUND: [&str; 6] = [
    "bgp_rib_prefixes",
    "bgp_rib_adj_out_prefixes",
    "bgp_outbound_prefix_usage",
    "bgp_outbound_prefix_blocking",
    "bgp_policy_routes_total",
    "bgp_peer_update_group",
];

fn target(index: u8) -> PeerId {
    peer_v4(Ipv4Addr::new(10, 0, 1, index))
}

fn peer_up(
    manager: &mut RibManager,
    peer: PeerId,
    session_id: u64,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (outbound_tx, outbound_rx) = mpsc::channel(64);
    manager.handle_update(RibUpdate::PeerUp {
        supersedes: None,
        per_client_best: false,
        interpret_rfc1997: true,
        session_id,
        peer,
        peer_asn: 65_002,
        peer_router_id: peer.addr().to_string().parse().unwrap(),
        outbound_tx,
        export_policy: None,
        sendable_families: ipv4_sendable(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    });
    outbound_rx
}

fn routes(octets: impl IntoIterator<Item = u8>) -> Vec<Route> {
    octets
        .into_iter()
        .map(|octet| {
            crate::test_support::make_route(
                Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, octet), 32),
                SOURCE,
            )
        })
        .collect()
}

/// Every sample of the bound families labelled `peer` (all peers when
/// `None`), keyed by family and sorted labels as the scrape renders them.
fn bound_samples(metrics: &BgpMetrics, peer: Option<&str>) -> BTreeMap<String, f64> {
    metrics
        .registry()
        .gather()
        .into_iter()
        .filter(|family| BOUND.contains(&family.name()))
        .flat_map(|family| {
            let name = family.name().to_owned();
            family
                .get_metric()
                .iter()
                .filter(|metric| {
                    peer.is_none_or(|peer| {
                        metric
                            .get_label()
                            .iter()
                            .any(|label| label.name() == "peer" && label.value() == peer)
                    })
                })
                .map(|metric| {
                    let labels: Vec<_> = metric
                        .get_label()
                        .iter()
                        .map(|label| format!("{}=\"{}\"", label.name(), label.value()))
                        .collect();
                    // A sample is a gauge or a counter; the other reads zero.
                    let value = metric.get_gauge().get_value() + metric.get_counter().get_value();
                    (format!("{name}{{{}}}", labels.join(",")), value)
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

fn adj_out_and_usage(metrics: &BgpMetrics, peer: &str) -> [Option<f64>; 2] {
    let samples = bound_samples(metrics, Some(peer));
    [
        "bgp_rib_adj_out_prefixes{family=\"ipv4_unicast\"",
        "bgp_outbound_prefix_usage{family=\"ipv4_unicast\"",
    ]
    .map(|prefix| {
        samples
            .iter()
            .find(|(key, _)| key.starts_with(prefix))
            .map(|(_, value)| *value)
    })
}

/// A registered peer's series are removed while its binding lives (the
/// peer manager reaps every family of a deleted neighbor before the RIB
/// handles its teardown), and its next commit shows them again with the
/// committed counts, as an unbound write recreates them. Its deletion then
/// reaps them, and a re-added neighbor at the address publishes fresh ones.
/// Red proof: skipping the epoch comparison in `RibPeerSeries::bound` keeps
/// the removed children, and the series stay absent after the commit.
#[test]
fn a_binding_resolves_again_after_its_series_are_removed() {
    let (_tx, rx) = mpsc::channel(1);
    let metrics = BgpMetrics::new();
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let source = peer_v4(SOURCE);
    let peer = target(2);
    let label = peer.label();

    announce(&mut manager, source, routes([1]));
    let first = peer_up(&mut manager, peer, 1);
    assert_eq!(adj_out_and_usage(&metrics, &label), [Some(1.0), Some(1.0)]);

    metrics.reap_peer_series(&label);
    assert_eq!(adj_out_and_usage(&metrics, &label), [None, None]);
    announce(&mut manager, source, routes([2]));
    assert_eq!(
        adj_out_and_usage(&metrics, &label),
        [Some(2.0), Some(2.0)],
        "the commit after the removal publishes under the label again"
    );

    drop(first);
    manager.handle_update(RibUpdate::PeerDown {
        peer,
        session_id: 1,
    });
    manager.handle_update(RibUpdate::PeerDeleted {
        peer,
        label: None,
        keep_series: false,
    });
    assert_eq!(bound_samples(&metrics, Some(&label)), BTreeMap::new());
    let _second = peer_up(&mut manager, peer, 2);
    assert_eq!(adj_out_and_usage(&metrics, &label), [Some(2.0), Some(2.0)]);
}

/// Membership churn leaves the bound families scraping exactly as before:
/// a departed member's series go and nobody else's change, and once it
/// rejoins and takes its initial table every sample equals the pre-churn
/// scrape. Red proof: keeping a binding across its registration's removal
/// together with skipping the epoch comparison leaves the rejoined
/// member's series absent.
#[test]
fn membership_churn_leaves_the_bound_families_scrape_unchanged() {
    let (_tx, rx) = mpsc::channel(1);
    let metrics = BgpMetrics::new();
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let source = peer_v4(SOURCE);
    let _receivers: Vec<_> = (2..6)
        .map(|index| peer_up(&mut manager, target(index), 1))
        .collect();
    announce(&mut manager, source, routes(1..=3));
    let before = bound_samples(&metrics, None);
    let leaver = target(3).label();
    assert!(before.keys().any(|key| key.contains(&leaver)));

    manager.handle_update(RibUpdate::PeerDown {
        peer: target(3),
        session_id: 1,
    });
    manager.handle_update(RibUpdate::PeerDeleted {
        peer: target(3),
        label: None,
        keep_series: false,
    });
    let others: BTreeMap<_, _> = before
        .iter()
        .filter(|(key, _)| !key.contains(&format!("peer=\"{leaver}\"")))
        .map(|(key, value)| (key.clone(), *value))
        .collect();
    assert_eq!(
        bound_samples(&metrics, None),
        others,
        "exact removed-series cleanup"
    );

    let _rejoined = peer_up(&mut manager, target(3), 2);
    assert_eq!(bound_samples(&metrics, None), before);
}

/// `PeerId::label` calls and metric children resolved through their vecs
/// during one route-bearing announcement to `members` registered targets.
fn work_per_announcement(members: u8) -> (usize, u64) {
    let (_tx, rx) = mpsc::channel(1);
    let metrics = BgpMetrics::new();
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let source = peer_v4(SOURCE);
    let _receivers: Vec<_> = (0..members)
        .map(|index| peer_up(&mut manager, target(10 + index), 1))
        .collect();
    announce(&mut manager, source, routes([1]));
    let labels = LABELS_FORMATTED.get();
    let resolves = metrics.rib_series_resolves();
    announce(&mut manager, source, routes([2]));
    (
        LABELS_FORMATTED.get() - labels,
        metrics.rib_series_resolves() - resolves,
    )
}

/// Work count: after registration, committing an announcement to every
/// member neither formats a member's label nor resolves a member's metric
/// child through its vec, so both counts are flat from 8 to 32 members.
/// Red proofs: bypassing the bindings grows the label count with the
/// members (it did on the parent), and resetting every binding on each
/// write grows the resolve count.
#[test]
fn commits_format_no_label_and_resolve_no_child_after_registration() {
    assert_eq!(work_per_announcement(8), work_per_announcement(32));
}

/// `PeerId::label` calls and children resolved during one round in which
/// each of `sources` registered sources sends one announce chunk, with one
/// member receiving the results.
fn work_per_ingest_round(sources: u8) -> (usize, u64) {
    let (_tx, rx) = mpsc::channel(1);
    let metrics = BgpMetrics::new();
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let mut member = peer_up(&mut manager, target(2), 1);
    let source_routes = |index: u8, round: u8| {
        let addr = Ipv4Addr::new(10, 0, 2, index);
        vec![crate::test_support::make_route(
            Ipv4Prefix::new(Ipv4Addr::new(198, 18, index, round), 32),
            addr,
        )]
    };
    // Each source keeps its session's outbound receiver, so no registration
    // drops and re-registers inside the measured round.
    let mut source_receivers: Vec<_> = (0..sources)
        .map(|index| peer_up(&mut manager, peer_v4(Ipv4Addr::new(10, 0, 2, index)), 0))
        .collect();
    for index in 0..sources {
        let addr = Ipv4Addr::new(10, 0, 2, index);
        announce(&mut manager, peer_v4(addr), source_routes(index, 1));
    }
    // Every session's queue has room for the measured round, so no commit
    // fails on a full queue (a refusal formats the label it counts under).
    for receiver in source_receivers.iter_mut().chain([&mut member]) {
        while receiver.try_recv().is_ok() {}
    }
    let labels = LABELS_FORMATTED.get();
    let resolves = metrics.rib_series_resolves();
    for index in 0..sources {
        let addr = Ipv4Addr::new(10, 0, 2, index);
        announce(&mut manager, peer_v4(addr), source_routes(index, 2));
    }
    (
        LABELS_FORMATTED.get() - labels,
        metrics.rib_series_resolves() - resolves,
    )
}

/// Work count on the ingest path: once every source is registered, an
/// announce chunk formats no label and resolves no child, whether for the
/// source's Adj-RIB-In gauges, the Loc-RIB gauges or the actor's work and
/// turn histograms, so both counts are flat from 8 to 32 sources. Red
/// proofs: bypassing the source's binding grows the label count with the
/// sources (it did on the parent), and resolving the Loc-RIB or actor
/// histogram children on every write grows the resolve count.
#[test]
fn ingest_chunks_format_no_label_and_resolve_no_child_after_registration() {
    assert_eq!(work_per_ingest_round(8), work_per_ingest_round(32));
}

fn rib_in(metrics: &BgpMetrics, peer: &str) -> Option<f64> {
    bound_samples(metrics, Some(peer))
        .into_iter()
        .find(|(key, _)| key.starts_with("bgp_rib_prefixes{family=\"ipv4_unicast\""))
        .map(|(_, value)| value)
}

/// An import-only source (its outbound registration deferred, so it has no
/// RIB-written series but its Adj-RIB-In gauges) has those gauges reaped by
/// the peer manager while the RIB still holds its binding. Its next chunk
/// publishes them again with the chunk's count through the same binding.
/// Red proof: reaping `bgp_rib_prefixes` after the epoch advance and leaving
/// it out of the bound families' removal count, as before this binding
/// existed, keeps the removed child, and the series stays absent.
#[test]
fn an_import_only_sources_binding_resolves_again_after_a_reap() {
    let (tx, rx) = mpsc::channel(8);
    let metrics = BgpMetrics::new();
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let source = peer_v4(SOURCE);
    register_deferred_test_peer(&mut manager, &tx, source, 0);
    announce(&mut manager, source, routes([1]));
    let label = source.label();
    assert!(manager.peer_metric_series.contains_key(&source));
    assert!(!manager.outbound_peers.contains_key(&source));
    assert_eq!(rib_in(&metrics, &label), Some(1.0));

    metrics.reap_peer_series(&label);
    assert_eq!(rib_in(&metrics, &label), None);
    announce(&mut manager, source, routes([2]));
    assert!(
        manager.peer_metric_series.contains_key(&source),
        "the same binding"
    );
    assert_eq!(
        rib_in(&metrics, &label),
        Some(2.0),
        "the chunk after the reap publishes under the label again"
    );
}
