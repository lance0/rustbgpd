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

// The member's paced replay after the build publishes.
const REPLAY: &[&str] = &[
    "initial_member_replay_visits",
    "initial_member_replay_units",
];

// Every stage that spends the poll's candidate budget, each counted at most
// once per unit charged. One poll may combine several prefixes.
const CHARGED: &[&str] = &[
    "first_pcb_gathered",
    "first_pcb_comparisons",
    "first_pcb_consumed",
    "first_pcb_rank_retired",
    "pcb_fallback_projection_visits",
    "pcb_fallback_retired_rows",
    "pcb_committed_prefixes",
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
    // Offer the paced initial replay at every size this test builds.
    manager.initial_member_replays.min_routes = Some(0);
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
    let mut charged = Build::default();
    let mut replay = Build::default();
    let mut seen = HashSet::new();
    let mut markers = Vec::new();
    let manager = poll_fn(|cx| {
        let before = snapshot();
        let result = actor.as_mut().poll(cx);
        let after = snapshot();
        charged.record(&before, after.clone(), CHARGED);
        replay.record(&before, after.clone(), REPLAY);
        build.record(&before, after, WORK);
        while let Ok(update) = rx.try_recv().map(delivered) {
            assert!(update.unicast_withdrawals().next().is_none());
            for row in update.announce.iter() {
                assert_eq!(markers.first(), None, "route after End-of-RIB");
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
    if usize::from(prefix_count) > PAGE {
        // The replay pages the table too: one page of keys per poll, and one
        // page of units counting each fallback row a key's RS view may
        // search, beyond the poll's first key.
        let paths = usize::try_from(paths_per_prefix).unwrap();
        assert!(replay.polls > 1, "{replay:?}");
        assert!(
            replay.peak["initial_member_replay_visits"] <= PAGE,
            "{replay:?}"
        );
        assert!(
            replay.peak["initial_member_replay_units"] <= PAGE + paths,
            "{replay:?}"
        );
        assert!(replay.total["initial_member_replay_units"] >= usize::from(prefix_count));
    } else {
        // A table below the paging threshold replays in one turn.
        assert_eq!(
            replay.peak.get("initial_member_replay_visits").copied(),
            Some(usize::from(prefix_count))
        );
    }
    assert!(
        charged.peak["work_units"] <= CANDIDATE_BUDGET,
        "{:?}",
        charged.peak
    );
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
    check_growth((1, 8_192), (1, 32_768)).await;
}

// Crowded prefixes resolve the member's slot through hundreds of fallback
// rows. A page of such keys must spread across polls, not search every row
// of a page in one.
#[tokio::test]
async fn pcb_replay_bounds_fallback_searches_per_poll() {
    cold_server(2_048, 32).await;
}

fn register(manager: &mut RibManager, n: u8, asn: u32) -> mpsc::Receiver<OutboundRouteUpdate> {
    let peer = receiver(n);
    manager.handle_update(RibUpdate::SetPeerRsControl {
        peer,
        session_id: 1,
        rs_control_asn: Some(RS_ASN),
    });
    let (out, rx) = mpsc::channel(1 << 16);
    let mut up = test_peer_up(peer, 1, out);
    let RibUpdate::PeerUp {
        peer_asn,
        per_client_best,
        ..
    } = &mut up
    else {
        unreachable!()
    };
    *peer_asn = asn;
    *per_client_best = true;
    manager.handle_update(up);
    rx
}

fn settle(manager: &mut RibManager) {
    for _ in 0..100_000 {
        if manager.pending_initial_registrations.is_empty() && manager.first_group_build.is_none() {
            return;
        }
        manager.advance_pending_initial_registration();
    }
    panic!("registration did not settle");
}

// A candidate-only withdrawal of a crowded prefix while its rank is partial
// must restart the rank, never dereference the withdrawn path.
#[test]
fn crowded_candidate_withdrawal_mid_rank_restarts_the_rank() {
    let (mut manager, _tx, _) = fixture(0);
    seed(&mut manager, 1, 4_096);
    let prefix = prefixes(0)[0];
    let winner = manager.loc_rib.get(&prefix).unwrap().path_id;
    let mut rx = register(&mut manager, 1, CLIENT_ASN);
    assert!(manager.first_group_build.is_some());
    for _ in 0..20 {
        manager.advance_first_group_build();
    }
    assert!(
        manager.first_group_build.is_some(),
        "rank finished too early"
    );
    // Withdraw every SOURCE path except the Loc-RIB winner: no Loc-RIB write.
    let mut received = test_routes_received(peer_v4(SOURCE), vec![]);
    let RibUpdate::RoutesReceived { withdrawn, .. } = &mut received else {
        unreachable!()
    };
    withdrawn.extend((0..4_095).filter(|&id| id != winner).map(|id| (prefix, id)));
    manager.handle_update(received);
    drain_route_chunks(&mut manager);
    assert_eq!(manager.loc_rib.get(&prefix).unwrap().path_id, winner);
    settle(&mut manager);
    assert!(manager.grouped_member_of(receiver(1)).is_some());
    let mut seen = Vec::new();
    while let Ok(update) = rx.try_recv().map(delivered) {
        for row in update.announce.iter() {
            seen.push((row.prefix, row.peer));
        }
    }
    assert_eq!(seen, [(prefix, peer_v4(OTHER))]);
}

// An Adj-RIB-In write that bypasses candidate capture leaves a dangling rank
// identity. Release builds requeue the prefix; tests must still notice.
#[test]
#[should_panic(expected = "an Adj-RIB-In write skipped candidate capture")]
fn uncaptured_candidate_removal_is_caught_in_tests() {
    let (mut manager, _tx, _) = fixture(0);
    seed(&mut manager, 1, 4_096);
    let prefix = prefixes(0)[0];
    let winner = manager.loc_rib.get(&prefix).unwrap().path_id;
    let _rx = register(&mut manager, 1, CLIENT_ASN);
    for _ in 0..20 {
        manager.advance_first_group_build();
    }
    assert!(
        manager.first_group_build.is_some(),
        "rank finished too early"
    );
    let rib = manager.ribs.get_mut(&peer_v4(SOURCE)).unwrap();
    for id in (0..4_095).filter(|&id| id != winner) {
        rib.withdraw(&prefix, id);
    }
    settle(&mut manager);
}

/// Projection visits when a fenced release prepares the crowded prefix's
/// installed fallback list for both RS members.
fn release_projection_visits(paced: bool) -> usize {
    use crate::manager::update_groups::{PerClientBestPrefixStage, ReleaseFallback};
    let (mut manager, _tx, _) = fixture(0);
    if !paced {
        manager.first_group_build_min_routes = usize::MAX;
    }
    seed(&mut manager, 1, 300);
    let prefix = prefixes(0)[0];
    let _founder = register(&mut manager, 1, CLIENT_ASN);
    assert_eq!(manager.first_group_build.is_some(), paced);
    settle(&mut manager);
    let _member = register(&mut manager, 2, CLIENT_ASN + 1);
    settle(&mut manager);
    let gid = manager.grouped_member_of(receiver(1)).unwrap();
    assert_eq!(manager.grouped_member_of(receiver(2)), Some(gid));
    let visits = || {
        crate::manager::slice_timing::group_work()
            .get("pcb_fallback_projection_visits")
            .copied()
            .unwrap_or(0)
    };
    let before = visits();
    let (mut stage, mut progress) = (
        PerClientBestPrefixStage::default(),
        ReleaseFallback::default(),
    );
    let members = [receiver(1), receiver(2)];
    while !manager.prepare_release_fallback(gid, prefix, &members, &mut stage, &mut progress) {}
    visits() - before
}

// The paced founder's commit indexes only its own control context. A later
// fenced release must prepare every member's projection, as after a
// synchronous build, instead of trusting the founder-only result.
#[test]
fn paced_founder_projection_does_not_outlive_the_build() {
    let synchronous = release_projection_visits(false);
    let paced = release_projection_visits(true);
    assert!(synchronous > 0, "the release prepared no projection");
    assert_eq!(paced, synchronous);
}

/// Ingest of one 1,024-route chunk per build poll during a cold registration:
/// (paced builds lost to repair-log overflow, polls until joined, joined).
fn ingest_rounds(pcb: bool) -> (usize, usize, bool) {
    let (mut manager, _tx, _) = fixture(0);
    seed(&mut manager, 8_192, 2);
    let peer = receiver(1);
    if pcb {
        manager.handle_update(RibUpdate::SetPeerRsControl {
            peer,
            session_id: 1,
            rs_control_asn: Some(RS_ASN),
        });
    }
    let (out, _rx) = mpsc::channel(1 << 16);
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
    *per_client_best = pcb;
    manager.handle_update(up);
    assert!(manager.first_group_build.is_some());
    let (mut overflows, mut rounds) = (0, 0);
    for round in 0..2_000_u32 {
        if manager.first_group_build.is_none() && manager.pending_initial_registrations.is_empty() {
            break;
        }
        rounds += 1;
        if round < INGEST_ROUNDS {
            // OTHER takes or yields the Loc-RIB win on 1024 distinct prefixes.
            let pref = if round % 2 == 0 { 300 } else { 100 };
            let rows = (0..1024_u32)
                .map(|k| {
                    let i = u16::try_from((round * 1024 + k) % 8_192).unwrap();
                    route(prefixes(i)[0], OTHER, pref)
                })
                .collect();
            manager.handle_update(test_routes_received(peer_v4(OTHER), rows));
            drain_route_chunks(&mut manager);
        }
        let scanning =
            manager.first_group_build.is_some() && manager.first_group_retiring_slots().is_none();
        manager.advance_pending_initial_registration();
        let joined = manager.grouped_member_of(peer).is_some();
        if scanning
            && !joined
            && (manager.first_group_build.is_none()
                || manager.first_group_retiring_slots().is_some())
        {
            overflows += 1;
        }
    }
    (overflows, rounds, manager.grouped_member_of(peer).is_some())
}

const INGEST_ROUNDS: u32 = 400;

// A route-server cold start: clients reconnect and send full tables while the
// first member builds. Overflow restarts are bounded; past the bound the
// founder takes the synchronous build while ingest continues.
#[test]
fn per_client_best_founder_joins_under_sustained_ingest() {
    use crate::manager::first_group_build::PCB_OVERFLOW_RESTARTS;
    let single = ingest_rounds(false);
    let (overflows, rounds, joined) = ingest_rounds(true);
    eprintln!("single-best (overflows, rounds, joined) = {single:?}");
    eprintln!("per-client-best = {:?}", (overflows, rounds, joined));
    let attempts = usize::from(PCB_OVERFLOW_RESTARTS) + 1;
    // An attempt overflows the 4,096-key log on its fifth 1,024-key chunk at
    // the latest; one poll retires the small partial table, one restarts.
    let bound = attempts * (4_096 / 1_024 + 1 + 2) + 1;
    assert!(joined);
    assert_eq!(overflows, attempts);
    assert!(rounds <= bound, "{rounds} polls > {bound}");
    assert!(
        rounds < INGEST_ROUNDS as usize,
        "joined only after ingest ended"
    );
}

fn delivered_rows(rx: &mut mpsc::Receiver<OutboundRouteUpdate>) -> Vec<(Prefix, PeerId)> {
    let mut seen = Vec::new();
    while let Ok(update) = rx.try_recv().map(delivered) {
        seen.extend(update.announce.iter().map(|row| (row.prefix, row.peer)));
    }
    seen
}

// A losing path of a crowded prefix that changes every poll discards each
// partial rank, and its repairs coalesce to one key, so the log never
// overflows. The founder must still join while the churn continues.
#[test]
fn crowded_prefix_losing_path_churn_still_joins() {
    use crate::manager::first_group_build::RANK_DISCARDS_BEFORE_FORCED;
    let (mut manager, _tx, _) = fixture(0);
    seed(&mut manager, 1, 4_096);
    let prefix = prefixes(0)[0];
    let mut rx = register(&mut manager, 1, CLIENT_ASN);
    assert!(manager.first_group_build.is_some());
    let mut polls = 0;
    for round in 0..2_000_u32 {
        if manager.grouped_member_of(receiver(1)).is_some() {
            break;
        }
        let losing = route(prefix, OTHER, 100 + round % 2);
        manager.handle_update(test_routes_received(peer_v4(OTHER), vec![losing]));
        drain_route_chunks(&mut manager);
        assert_eq!(manager.loc_rib.get(&prefix).unwrap().peer, peer_v4(SOURCE));
        manager.advance_pending_initial_registration();
        polls += 1;
    }
    eprintln!("joined after {polls} polls of churn");
    assert!(
        manager.grouped_member_of(receiver(1)).is_some(),
        "never joined"
    );
    // Discovery, one partial rank per allowed discard, then the forced rank
    // and publication in one poll, with one poll of slack.
    let bound = 1 + usize::from(RANK_DISCARDS_BEFORE_FORCED) + 2;
    assert!(polls <= bound, "{polls} polls > {bound}");
    assert_eq!(delivered_rows(&mut rx), [(prefix, peer_v4(OTHER))]);
}

// A founder disconnect while a crowded prefix is partly ranked retires its
// candidate rows within the same per-poll budget as the build.
#[test]
fn crowded_retirement_after_disconnect_stays_within_the_candidate_budget() {
    let (mut manager, _tx, _) = fixture(0);
    seed(&mut manager, 1, 4_096);
    let _rx = register(&mut manager, 1, CLIENT_ASN);
    for _ in 0..40 {
        manager.advance_first_group_build();
    }
    assert!(
        manager.first_group_build.is_some(),
        "rank finished too early"
    );
    manager.handle_update(RibUpdate::PeerDown {
        peer: receiver(1),
        session_id: 1,
    });
    let mut charged = Build::default();
    for _ in 0..10_000 {
        if manager.first_group_build.is_none() {
            break;
        }
        let before = snapshot();
        manager.advance_pending_initial_registration();
        charged.record(&before, snapshot(), CHARGED);
    }
    assert!(manager.first_group_build.is_none());
    assert!(
        charged.total["work_units"] > CANDIDATE_BUDGET,
        "nothing to retire: {:?}",
        charged.total
    );
    assert!(
        charged.peak["work_units"] <= CANDIDATE_BUDGET,
        "{:?}",
        charged.peak
    );
}

// The run loop under input that never drains: after the second overflow the
// founder can no longer pace, and busy turns used to retry only the paced
// build. It must complete synchronously at a route-batch boundary instead.
#[tokio::test]
async fn overflowed_founder_registers_while_input_stays_queued() {
    const CAP: usize = 2_000;
    let (mut manager, tx, _) = fixture(0);
    seed(&mut manager, 8_192, 2);
    let peer = receiver(1);
    manager.handle_update(RibUpdate::SetPeerRsControl {
        peer,
        session_id: 1,
        rs_control_asn: Some(RS_ASN),
    });
    let (out, mut rx) = mpsc::channel(1 << 16);
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
    let (mut polls, mut round, mut joined_at) = (0, 0_u32, None);
    let manager = poll_fn(|cx| {
        let result = actor.as_mut().poll(cx);
        polls += 1;
        while let Ok(update) = rx.try_recv() {
            if !update.end_of_rib.is_empty() {
                joined_at.get_or_insert(polls);
            }
        }
        if let Some(sender) = &tx {
            if joined_at.is_some() || polls >= CAP {
                tx = None;
            } else {
                // OTHER takes or yields the Loc-RIB win on 1,024 distinct prefixes.
                let pref = if round % 2 == 0 { 300 } else { 100 };
                let rows = (0..1_024_u32)
                    .map(|k| {
                        let i = u16::try_from((round * 1_024 + k) % 8_192).unwrap();
                        route(prefixes(i)[0], OTHER, pref)
                    })
                    .collect();
                if sender
                    .try_send(test_routes_received(peer_v4(OTHER), rows))
                    .is_ok()
                {
                    round += 1;
                }
            }
            cx.waker().wake_by_ref();
        }
        result
    })
    .await;
    eprintln!("joined at poll {joined_at:?} after {round} queued updates");
    assert!(manager.grouped_member_of(peer).is_some());
    let joined_at = joined_at.expect("no End-of-RIB");
    assert!(joined_at < CAP / 4, "joined only at poll {joined_at}");
}
