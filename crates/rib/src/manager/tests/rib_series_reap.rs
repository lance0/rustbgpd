//! The RIB's label reap at a neighbor's deletion covers exactly what the RIB
//! writes: every series it emitted for the neighbor goes, and the series a
//! new neighbor's session and peer manager emit under the same label first
//! stay (`BgpMetrics::reap_rib_peer_series`).

use std::collections::BTreeSet;

use super::outbound_prefix_limits::{announce, apply, limit_config, prepare};
use super::*;
use crate::test_support::peer_v4;

const TARGET: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const SOURCE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

/// Every series labelled `peer`, as family name and label set.
fn series(metrics: &BgpMetrics, peer: &str) -> BTreeSet<String> {
    metrics
        .registry()
        .gather()
        .into_iter()
        .flat_map(|family| {
            let name = family.name().to_owned();
            family
                .get_metric()
                .iter()
                .filter(|metric| {
                    metric
                        .get_label()
                        .iter()
                        .any(|label| label.name() == "peer" && label.value() == peer)
                })
                .map(|metric| {
                    let labels: Vec<_> = metric
                        .get_label()
                        .iter()
                        .map(|label| format!("{}={}", label.name(), label.value()))
                        .collect();
                    format!("{name}[{}]", labels.join(","))
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

fn families(series: &BTreeSet<String>) -> BTreeSet<&str> {
    series
        .iter()
        .map(|series| series.split('[').next().unwrap_or_default())
        .collect()
}

fn peer_up(manager: &mut RibManager, session_id: u64) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (outbound_tx, outbound_rx) = mpsc::channel(64);
    manager.handle_update(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id,
        peer: peer_v4(TARGET),
        peer_asn: 65_002,
        peer_router_id: TARGET,
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

fn routes(source: Ipv4Addr, octets: impl IntoIterator<Item = u8>) -> Vec<Route> {
    octets
        .into_iter()
        .map(|octet| {
            crate::test_support::make_route(
                Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, octet), 32),
                source,
            )
        })
        .collect()
}

/// The target's session `session_id` sends routes, handled to completion.
fn receive_from_target(
    manager: &mut RibManager,
    session_id: u64,
    octets: impl IntoIterator<Item = u8>,
) {
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: peer_v4(TARGET),
        session_id,
        announced: routes(TARGET, octets),
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    while manager.process_next_route_chunk() {}
}

/// What a new neighbor's session and peer manager emit under its label
/// before any of its RIB messages: none of it is the RIB's to reap. (The
/// session's zero exact-export series are the RIB's too: the RIB reaps them
/// and seeds them again when it registers the session.)
fn seed_session_and_peer_manager_series(metrics: &BgpMetrics, peer: &str) {
    metrics.set_peer_admin_enabled(peer, "", true);
    metrics.set_peer_info(peer, "", 65_002, "replacement", "");
    metrics.set_peer_session_state(peer, "", "connect");
    metrics.set_peer_session_established(peer, "", false);
    metrics.set_max_prefix_latched(peer, "", false);
    metrics.record_state_transition(peer, "idle", "connect");
    metrics.record_message_sent(peer, "open");
    metrics.initialize_export_family_suppressed_series(
        peer,
        "ipv6_unicast",
        rustbgpd_telemetry::reason_labels::ExactExportReason::MissingIpv6NextHop,
    );
    metrics.initialize_update_malformed_series(peer);
    metrics.set_rfc8212_missing_policy(peer, false, false);
    metrics.record_policy_routes(peer, "inline", "import", "permit");
}

/// The census. A neighbor's RIB life writes its `peer`-labelled families:
/// received and advertised prefixes, update group, export policy counts,
/// outbound prefix capacity and a blocked prefix, route refresh, stale
/// session messages and teardowns, a replaced registration, a dropped
/// outbound update, and Graceful Restart with its timer expiry. The RIB's
/// reap removes all of them and leaves every series a new neighbor's
/// session and peer manager emit under the label. Red proofs: dropping a
/// family the RIB writes from `reap_rib_peer_series` leaves its series; a
/// session or peer-manager family in the list removes the new neighbor's.
#[test]
fn the_rib_reap_covers_exactly_what_the_rib_writes() {
    let (_tx, rx) = mpsc::channel(1);
    let metrics = BgpMetrics::new();
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let target = peer_v4(TARGET);
    let source = peer_v4(SOURCE);
    let label = TARGET.to_string();

    announce(&mut manager, source, routes(SOURCE, [1]));
    let first = peer_up(&mut manager, 1);
    receive_from_target(&mut manager, 1, [41, 42]);
    prepare(
        &mut manager,
        1,
        limit_config(&[(target, Some(1), None)], &[]),
    )
    .unwrap();
    apply(&mut manager, 1, true).unwrap();
    announce(&mut manager, source, routes(SOURCE, [2]));
    manager.handle_update(RibUpdate::BeginRouteRefresh {
        session_id: 1,
        peer: target,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    });
    // A late session's messages, then a second session replacing the first.
    receive_from_target(&mut manager, 99, [43]);
    manager.handle_update(RibUpdate::PeerDown {
        peer: target,
        session_id: 99,
    });
    drop(first);
    let second = peer_up(&mut manager, 2);
    drop(second);
    announce(&mut manager, source, routes(SOURCE, [3]));
    manager.handle_update(RibUpdate::PeerGracefulRestart {
        peer: target,
        session_id: 2,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    });
    let written = series(&metrics, &label);
    manager.sweep_gr_stale(target);
    let written: BTreeSet<_> = written.union(&series(&metrics, &label)).cloned().collect();
    let driven = BTreeSet::from([
        "bgp_rib_prefixes",
        "bgp_rib_adj_out_prefixes",
        "bgp_peer_update_group",
        "bgp_policy_routes_total",
        "bgp_outbound_prefix_usage",
        "bgp_outbound_prefix_limit",
        "bgp_outbound_prefix_headroom",
        "bgp_outbound_prefix_blocking",
        "bgp_outbound_prefix_blocked_total",
        "bgp_route_refresh_in_progress",
        "bgp_route_refresh_stale_entries",
        "bgp_rib_stale_session_message_ignored_total",
        "bgp_rib_stale_peer_down_ignored_total",
        "bgp_rib_outbound_registration_replaced_total",
        "bgp_outbound_route_drops_total",
        "bgp_gr_active_peers",
        "bgp_gr_stale_routes",
        "bgp_gr_timer_expired_total",
    ]);
    let written_families = families(&written);
    let missing: Vec<_> = driven.difference(&written_families).collect();
    assert!(
        missing.is_empty(),
        "the scenario no longer drives {missing:?}"
    );

    seed_session_and_peer_manager_series(&metrics, &label);
    let foreign: BTreeSet<_> = series(&metrics, &label)
        .difference(&written)
        .cloned()
        .collect();
    assert!(!foreign.is_empty());
    metrics.reap_rib_peer_series(&label);
    assert_eq!(
        series(&metrics, &label),
        foreign,
        "the RIB reap removes what the RIB wrote and nothing else"
    );
}

/// The `name` fields a function body reaches through `self.0.` or `inner.`.
fn fields_of(body: &str) -> BTreeSet<String> {
    let flat: String = body.split_whitespace().collect();
    let mut fields = BTreeSet::new();
    for prefix in ["self.0.", "inner."] {
        for (at, _) in flat.match_indices(prefix) {
            let field: String = flat[at + prefix.len()..]
                .chars()
                .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '_')
                .collect();
            if !field.is_empty() {
                fields.insert(field);
            }
        }
    }
    fields
}

/// Every `peer`-labelled metric vec `source` declares: a
/// `let name = ...Vec::new(` whose label list starts with `"peer"`.
fn peer_labelled_vecs(source: &str) -> BTreeSet<String> {
    source
        .split("\n        let ")
        .filter_map(|declaration| {
            let (name, rest) = declaration.split_once(" = ")?;
            let flat: String = rest.split_whitespace().collect();
            (flat.split_once('(')?.0.ends_with("Vec::new") && flat.contains("&[\"peer\""))
                .then(|| name.to_owned())
        })
        .collect()
}

/// Every `pub fn` in `source` with its body: from its signature to the
/// closing brace at the method indent.
fn pub_fns(source: &str) -> Vec<(&str, &str)> {
    source
        .match_indices("\n    pub fn ")
        .filter_map(|(at, marker)| {
            let rest = &source[at + marker.len()..];
            let name = &rest[..rest.find(['(', '<'])?];
            let body = &rest[..rest.find("\n    }\n")?];
            Some((name, body))
        })
        .collect()
}

/// The RIB's non-test sources under `dir`, concatenated.
fn rib_sources(dir: &std::path::Path, out: &mut String) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let text = path.to_string_lossy();
        if path.is_dir() {
            if !text.ends_with("/tests") {
                rib_sources(&path, out);
            }
        } else if text.ends_with(".rs")
            && !text.ends_with("tests.rs")
            && !text.contains("test_support")
            && !text.contains("bench")
        {
            out.push_str(&std::fs::read_to_string(&path).unwrap());
        }
    }
}

/// The static census. Maps every public `BgpMetrics` method to the
/// `peer`-labelled families its body writes, finds the methods the RIB's own
/// sources call, and requires the RIB reap list to be exactly those
/// families: a family the RIB writes on a path no scenario drives is still
/// listed, and no family only a session or the peer manager writes is.
/// Red proofs: dropping `outbound_eor_deferrals` from the list, or listing
/// `peer_admin_enabled`, fails it.
#[test]
fn the_rib_reap_list_is_the_families_the_rib_writes() {
    let crate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let metrics = std::fs::read_to_string(crate_dir.join("../telemetry/src/metrics.rs")).unwrap();
    let metrics = metrics
        .split("\n#[cfg(test)]\nmod tests")
        .next()
        .unwrap_or_default();
    let fns = pub_fns(metrics);
    let body_of = |wanted: &str| {
        fns.iter().find(|(name, _)| *name == wanted).map_or_else(
            || panic!("BgpMetrics::{wanted} not found"),
            |(_, body)| *body,
        )
    };
    let listed = fields_of(body_of("reap_rib_peer_series"));
    let peer_labelled = peer_labelled_vecs(metrics);
    let mut rib = String::new();
    rib_sources(&crate_dir.join("src"), &mut rib);
    let written: BTreeSet<_> = fns
        .iter()
        .filter(|(name, _)| !name.starts_with("reap") && rib.contains(&format!(".{name}(")))
        .flat_map(|(_, body)| fields_of(body))
        .filter(|field| peer_labelled.contains(field))
        .collect();
    assert_eq!(written.len(), 24, "{written:?}");
    assert_eq!(
        listed.difference(&written).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "listed in reap_rib_peer_series, but the RIB never writes them"
    );
    assert_eq!(
        written.difference(&listed).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "the RIB writes these peer-labelled families, but reap_rib_peer_series misses them"
    );
}

/// Two handles for one neighbor address, sharing its `peer` label: a
/// replaced speaker and its successor.
const SHARED: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 77);

fn shared_handle() -> PeerId {
    PeerId::allocate(crate::PeerEndpoint::new(IpAddr::V4(SHARED), None))
}

/// How a session in [`session_with_routes`] ends.
#[derive(Clone, Copy, PartialEq)]
enum End {
    /// It stays up.
    Up,
    /// Graceful Restart for IPv4 unicast.
    Restart,
    /// Graceful Restart, with Long-Lived Graceful Restart after it.
    LongLivedRestart,
}

/// `peer`'s session `session_id` comes up, sends `count` routes, and ends
/// as `end` says.
fn session_with_routes(
    manager: &mut RibManager,
    peer: PeerId,
    session_id: u64,
    first: u8,
    count: u8,
    end: End,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (outbound_tx, outbound_rx) = mpsc::channel(64);
    manager.handle_update(RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id,
        peer,
        peer_asn: 65_077,
        peer_router_id: SHARED,
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
    let announced = (first..first + count)
        .map(|octet| {
            let mut route = crate::test_support::make_route(
                Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, octet), 32),
                SHARED,
            );
            route.peer = peer;
            route
        })
        .collect();
    manager.handle_update(RibUpdate::RoutesReceived {
        peer,
        session_id,
        announced,
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    while manager.process_next_route_chunk() {}
    if end != End::Up {
        let long_lived = end == End::LongLivedRestart;
        manager.handle_update(RibUpdate::PeerGracefulRestart {
            peer,
            session_id,
            restart_time: 120,
            stale_routes_time: 360,
            gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
            peer_llgr_capable: long_lived,
            peer_llgr_families: if long_lived {
                vec![rustbgpd_wire::LlgrFamily {
                    afi: Afi::Ipv4,
                    safi: Safi::Unicast,
                    forwarding_preserved: false,
                    stale_time: 3600,
                }]
            } else {
                vec![]
            },
            llgr_stale_time: if long_lived { 3600 } else { 0 },
        });
    }
    outbound_rx
}

/// The shared label's restart flag, held-stale count and received prefixes.
fn shared_gr_gauges(metrics: &BgpMetrics) -> [Option<f64>; 3] {
    let label = SHARED.to_string();
    [
        "bgp_gr_active_peers",
        "bgp_gr_stale_routes",
        "bgp_rib_prefixes",
    ]
    .map(|family| {
        metrics
            .registry()
            .gather()
            .into_iter()
            .find(|candidate| candidate.name() == family)?
            .get_metric()
            .iter()
            .find(|metric| {
                let labels = metric.get_label();
                labels
                    .iter()
                    .any(|pair| pair.name() == "peer" && pair.value() == label)
                    && labels
                        .iter()
                        .all(|pair| pair.name() != "family" || pair.value() == "ipv4_unicast")
            })
            .map(|metric| metric.get_gauge().get_value())
    })
}

/// A replaced speaker, superseded while its deletion waits, has its restart
/// timer expire and moves its three routes to Long-Lived Graceful Restart;
/// its successor is itself restarting with five routes held. The promotion
/// writes nothing under the shared label, so the label keeps the
/// successor's counts and is not charged with the old speaker's timer
/// expiry, and the old speaker's deletion leaves the successor's restart in
/// view. Red proof: letting the sweep of a superseded handle write the label
/// shows the old speaker's three routes there and counts its expiry.
#[test]
fn a_superseded_speakers_gr_expiry_leaves_a_restarting_successors_gauges() {
    let (_tx, rx) = mpsc::channel(1);
    let metrics = BgpMetrics::new();
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let (old, new) = (shared_handle(), shared_handle());
    let _old_rx = session_with_routes(&mut manager, old, 1, 1, 3, End::LongLivedRestart);
    let _new_rx = session_with_routes(&mut manager, new, 2, 11, 5, End::Restart);
    old.supersede();
    let restarting = [Some(1.0), Some(5.0), Some(5.0)];
    assert_eq!(shared_gr_gauges(&metrics), restarting);

    manager.sweep_gr_stale(old);
    assert!(manager.llgr_peers.contains_key(&old), "promoted to LLGR");
    assert_eq!(
        shared_gr_gauges(&metrics),
        restarting,
        "the old speaker's expiry leaves the successor's gauges"
    );
    let expiries = metrics
        .registry()
        .gather()
        .into_iter()
        .find(|family| family.name() == "bgp_gr_timer_expired_total")
        .map_or(0, |family| family.get_metric().len());
    assert_eq!(expiries, 0, "the old speaker's expiry is not the label's");
    manager.handle_update(RibUpdate::PeerDeleted {
        peer: old,
        label: None,
        keep_series: true,
    });
    assert_eq!(
        shared_gr_gauges(&metrics),
        restarting,
        "the old speaker's deletion leaves the successor's restart in view"
    );
    assert!(old.release() && new.release());
}

/// The same expiry with a successor that is up, not restarting: the
/// deletion of the old speaker, which finds none of its own GR state left,
/// ends the restart gauges the old speaker published and leaves the
/// successor's prefix count. Red proof: publishing GR gauges only from the
/// old speaker's own GR state leaves the label reporting a restart.
#[test]
fn a_superseded_speakers_gr_expiry_ends_its_gauges_for_a_live_successor() {
    let (_tx, rx) = mpsc::channel(1);
    let metrics = BgpMetrics::new();
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, metrics.clone());
    let (old, new) = (shared_handle(), shared_handle());
    let _old_rx = session_with_routes(&mut manager, old, 1, 1, 3, End::Restart);
    old.supersede();
    let _new_rx = session_with_routes(&mut manager, new, 2, 11, 5, End::Up);
    assert_eq!(
        shared_gr_gauges(&metrics),
        [Some(1.0), Some(3.0), Some(5.0)]
    );

    manager.sweep_gr_stale(old);
    manager.handle_update(RibUpdate::PeerDeleted {
        peer: old,
        label: None,
        keep_series: true,
    });
    assert_eq!(
        shared_gr_gauges(&metrics),
        [Some(0.0), Some(0.0), Some(5.0)],
        "no restart under the label, and the successor's routes"
    );
    assert!(old.release() && new.release());
}
