//! Per-poll work for the first route-server member, including a single busy prefix.

use std::future::{Future, poll_fn};

use super::policy_work::{Build, snapshot};
use super::*;

const RS_ASN: u32 = 65_000;
const CLIENT_ASN: u32 = 64_512;
const PAGE: usize = crate::loc_rib::REGISTRATION_PAGE_SIZE;
const CANDIDATE_BUDGET: usize = 128;

// Construction checkpoints include per-prefix work. Count the inner candidate
// operations and storage growth in the poll where they occurred.
const WORK: &[&str] = &[
    "discovery",
    "first_group_repairs",
    "first_pcb_gathered",
    "first_pcb_source_probes",
    "first_pcb_comparisons",
    "first_pcb_rank_moves",
    "first_pcb_rank_retired",
    "first_pcb_consumed",
    "first_pcb_eval_calls",
    "first_pcb_fallback_appends",
    "pcb_fallback_projection_visits",
    "pcb_rs_index_keys",
    "pcb_rs_fallback_search",
    "pcb_committed_prefixes",
    "pcb_fallback_retired_rows",
    "group_build_checkpoints",
    "group_build_rehashed",
    "group_build_growing_slots",
    "group_source_writes",
    "group_denials_written",
];

fn seed(manager: &mut RibManager, prefix_count: u16, paths_per_prefix: u32) {
    // Every path from SOURCE beats OTHER in the Loc-RIB, and every one is
    // suppressed toward this member by a 0:CLIENT_ASN control community.
    let prefix = prefixes(0)[0];
    let mut preferred = route(prefix, SOURCE, 200);
    crate::attr_set::AttrSet::edit(&mut preferred.attributes, |attributes| {
        attributes.push(rustbgpd_wire::PathAttribute::Communities(vec![CLIENT_ASN]));
    });
    let alternate = route(prefix, OTHER, 100);
    for (template, count) in [(preferred, paths_per_prefix - 1), (alternate, 1)] {
        let mut input = Vec::new();
        for i in 0..prefix_count {
            for path_id in 0..count {
                let mut row = template.clone();
                row.prefix = prefixes(i)[0];
                row.path_id = path_id;
                input.push(row);
            }
        }
        manager.handle_update(test_routes_received(template.peer, input));
        drain_route_chunks(manager);
    }
    assert_eq!(manager.loc_rib.len(), usize::from(prefix_count));
    assert_eq!(manager.loc_rib.get(&prefix).unwrap().peer, peer_v4(SOURCE));
}

async fn cold_server(prefix_count: u16, paths_per_prefix: u32) -> Build {
    let (mut manager, tx, _) = fixture(0);
    manager.initial_member_replays.min_routes = None;
    seed(&mut manager, prefix_count, paths_per_prefix);
    let peer = receiver(1);
    manager.handle_update(RibUpdate::SetPeerRsControl {
        peer,
        session_id: 1,
        rs_control_asn: Some(RS_ASN),
    });
    let (out, mut rx) = mpsc::channel(64);
    let mut up = test_peer_up(peer, 1, out);
    let RibUpdate::PeerUp {
        peer_asn,
        per_client_best,
        ..
    } = &mut up
    else {
        unreachable!()
    };
    *peer_asn = CLIENT_ASN;
    *per_client_best = true;
    tx.try_send(up).unwrap();
    let mut tx = Some(tx);
    let mut actor = Box::pin(manager.run_actor());
    let mut build = Build::default();
    let mut seen = HashSet::new();
    let mut markers = Vec::new();
    let manager = poll_fn(|cx| {
        let before = snapshot();
        let result = actor.as_mut().poll(cx);
        build.record(&before, snapshot(), WORK);
        while let Ok(update) = rx.try_recv().map(delivered) {
            assert!(update.unicast_withdrawals().next().is_none());
            for row in update.announce.iter() {
                assert!(markers.is_empty());
                assert_eq!(
                    (row.peer, row.next_hop),
                    (peer_v4(OTHER), IpAddr::V4(OTHER))
                );
                assert!(seen.insert(row.prefix));
            }
            markers.extend(update.end_of_rib.iter().copied());
        }
        if !markers.is_empty() && tx.take().is_some() {
            cx.waker().wake_by_ref();
        }
        result
    })
    .await;
    assert!(manager.grouped_member_of(peer).is_some());
    assert_eq!(markers, [(Afi::Ipv4, Safi::Unicast)]);
    assert_eq!(seen, (0..prefix_count).map(|i| prefixes(i)[0]).collect());
    for stage in [
        "first_pcb_gathered",
        "first_pcb_consumed",
        "first_pcb_eval_calls",
    ] {
        assert_eq!(
            build.total.get(stage).copied().unwrap_or(0),
            usize::from(prefix_count) * usize::try_from(paths_per_prefix).unwrap(),
            "{stage}"
        );
    }
    assert!(build.total["first_pcb_fallback_appends"] > 0);
    assert!(build.total["pcb_rs_index_keys"] >= usize::from(prefix_count));
    build
}

async fn check_growth(small: (u16, u32), large: (u16, u32)) {
    let a = cold_server(small.0, small.1).await;
    let b = cold_server(large.0, large.1).await;
    eprintln!("prefixes × paths {small:?}: {a:?}\nprefixes × paths {large:?}: {b:?}");
    assert!(
        b.polls > a.polls,
        "{small:?}: {}, {large:?}: {}",
        a.polls,
        b.polls
    );
    for build in [a, b] {
        assert!(build.peak["work_units"] <= 16 * PAGE, "{:?}", build.peak);
        assert!(build.peak["discovery"] <= PAGE);
        for stage in [
            "first_pcb_gathered",
            "first_pcb_source_probes",
            "first_pcb_consumed",
            "first_pcb_eval_calls",
            "first_pcb_comparisons",
            "first_pcb_fallback_appends",
            "pcb_fallback_projection_visits",
            "pcb_committed_prefixes",
        ] {
            assert!(
                build.peak.get(stage).copied().unwrap_or(0) <= CANDIDATE_BUDGET,
                "{stage}: {:?}",
                build.peak
            );
        }
        // A rank move accompanies a sift comparison or installs the selected
        // root. Small unindexed fallback lists can visit the old and new slot.
        assert!(
            build.peak.get("first_pcb_rank_moves").copied().unwrap_or(0) <= 2 * CANDIDATE_BUDGET
        );
        assert!(
            build
                .peak
                .get("pcb_rs_fallback_search")
                .copied()
                .unwrap_or(0)
                <= 2 * CANDIDATE_BUDGET
        );
        assert!(build.peak["pcb_rs_index_keys"] <= PAGE, "{:?}", build.peak);
    }
}

#[tokio::test]
async fn pcb_cold_build_bounds_broad_table_work_per_poll() {
    check_growth((8_192, 2), (32_768, 2)).await;
}

#[tokio::test]
async fn pcb_cold_build_bounds_crowded_prefix_work_per_poll() {
    check_growth((1, 2_048), (1, 8_192)).await;
}
