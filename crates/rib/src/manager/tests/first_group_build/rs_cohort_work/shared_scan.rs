//! Joiners of one group table ride one scan of the Loc-RIB. Its rows do not
//! grow with the riders, a late joiner completes one pass after it joined,
//! and a rider that falls a whole log behind reconciles on its own.
use rustbgpd_policy::datasets::{DatasetBindings, DatasetData, DatasetHandle, DatasetKind};
use rustbgpd_policy::rpol::RpolFile;
use rustbgpd_policy::sets::{PrefixSet, PrefixSetEntry, SetStore};
use rustbgpd_policy::{Policy, PolicyAction, PolicyChain};

use super::*;
use crate::manager::distribution::rs_control::rs_control_route_tagged;
use crate::manager::tests::update_groups::deny_statement;

/// Loc-RIB buckets every registration scan has visited on this thread.
fn buckets() -> usize {
    crate::loc_rib::REGISTRATION_VISITS.with(|visits| visits.get().0)
}

// Rows scanned per cohort: the Loc-RIB buckets a mass rejoin visits stay
// flat as the cohort grows. With one scan per member they grow with it.
#[tokio::test]
async fn a_join_cohort_scans_the_loc_rib_once_whatever_its_size() {
    let mut scanned = Vec::new();
    for joiners in [8, 32] {
        let before = buckets();
        Box::pin(rejoin(joiners)).await;
        scanned.push(buckets() - before);
    }
    eprintln!("Loc-RIB buckets scanned at 8 and 32 joiners: {scanned:?}");
    assert!(
        scanned[1] <= scanned[0] + REGISTRATION_PAGE_SIZE,
        "rows scanned grew with the cohort: {scanned:?}"
    );
}

/// One rider's wire state: each prefix's source as last delivered.
struct Rider {
    n: u8,
    rx: mpsc::Receiver<OutboundRouteUpdate>,
    table: HashMap<Prefix, PeerId>,
    // Every row delivered, in order.
    rows: Vec<(Prefix, PeerId)>,
    // Delivered rows that carry a control community for the RS ASN.
    control_tagged: usize,
    markers: usize,
    // Route-bearing envelopes with the cohort's encode cell, and without.
    shared: usize,
    private: usize,
}

impl Rider {
    fn join(manager: &mut RibManager, n: u8, capacity: usize) -> Self {
        Self::new(n, rs_client(manager, n, capacity))
    }

    fn new(n: u8, rx: mpsc::Receiver<OutboundRouteUpdate>) -> Self {
        Self {
            n,
            rx,
            table: HashMap::new(),
            rows: Vec::new(),
            control_tagged: 0,
            markers: 0,
            shared: 0,
            private: 0,
        }
    }

    fn read(&mut self) {
        while let Ok(update) = self.rx.try_recv() {
            assert_eq!(self.markers, 0, "rider {}: update after End-of-RIB", self.n);
            for (prefix, _) in update.unicast_withdrawals() {
                self.table.remove(prefix);
            }
            if !update.announce.is_empty() {
                if update.shared_group_encode.is_some() {
                    self.shared += 1;
                } else {
                    self.private += 1;
                }
            }
            for row in update
                .announce
                .iter()
                .filter(|row| update.announce_source_exclusion != Some(row.peer))
            {
                self.table.insert(row.prefix, row.peer);
                self.rows.push((row.prefix, row.peer));
                self.control_tagged += usize::from(rs_control_route_tagged(
                    row.communities(),
                    row.large_communities(),
                    RS_ASN,
                ));
            }
            self.markers += update.end_of_rib.len();
        }
    }
}

/// Take replay and registration turns, reading every rider but those in
/// `parked`, until `done`.
fn run(
    manager: &mut RibManager,
    riders: &mut [Rider],
    parked: &[u8],
    done: impl Fn(&RibManager, &[Rider]) -> bool,
) {
    for _ in 0..100_000 {
        for rider in riders.iter_mut().filter(|rider| !parked.contains(&rider.n)) {
            rider.read();
        }
        if done(manager, riders) {
            return;
        }
        turn(manager);
    }
    panic!("the cohort never reached its condition");
}

fn complete(_: &RibManager, riders: &[Rider]) -> bool {
    riders.iter().all(|rider| rider.markers == 1)
}

/// Every row of the published table, from `source`.
fn table_from(source: Ipv4Addr, rows: usize) -> HashMap<Prefix, PeerId> {
    (0..u16::try_from(rows).unwrap())
        .map(|index| (prefixes(index)[0], peer_v4(source)))
        .collect()
}

// The cohort resolves each page of its scan once: one universe lookup and
// one winner per key, whatever the riders. Each rider then takes the page's
// rows as one shared payload with one encode cell.
#[test]
fn a_cohort_resolves_each_page_once_and_every_rider_shares_its_rows() {
    let mut resolved = Vec::new();
    for joiners in [8_u8, 32] {
        let Published {
            mut manager,
            tx: _tx,
            ..
        } = published();
        let before = [work("cohort_page_resolves"), work("cohort_shared_rows")];
        let mut riders: Vec<_> = (1..=joiners)
            .map(|n| Rider::join(&mut manager, n, 1 << 12))
            .collect();
        run(&mut manager, &mut riders, &[], complete);
        for rider in &riders {
            assert!(rider.table == table_from(SOURCE, ROWS), "rider {}", rider.n);
            assert!(
                rider.shared >= usize::from(PAGES) && rider.private == 0,
                "rider {}: {} shared, {} private",
                rider.n,
                rider.shared,
                rider.private
            );
        }
        // Every row reached every rider through the shared payload.
        assert_eq!(
            work("cohort_shared_rows") - before[1],
            usize::from(joiners) * ROWS
        );
        resolved.push(work("cohort_page_resolves") - before[0]);
        assert!(
            manager.cohort_scan_riders().is_empty(),
            "a scan outlived its riders"
        );
        crate::manager::tests::assert_paced_fallbacks(&manager.metrics, &[]);
    }
    eprintln!("keys resolved at 8 and 32 riders: {resolved:?}");
    // One resolve per page of the pass, and one more for each page of the
    // next pass that a rider registered too late for: never more than the
    // two passes, whatever the riders.
    assert!(
        resolved.iter().all(|keys| (ROWS..=2 * ROWS).contains(keys)),
        "{resolved:?}"
    );
}

// Keys resolved per cohort under churn. One winner changes every turn, at a
// key every rider already holds, so no page still to be shared contains it.
// Only a page that holds a changed key is resolved again: the resolves do
// not grow with the riders.
#[test]
fn a_change_per_turn_resolves_no_other_page_again_whatever_the_cohort_size() {
    let hot = prefixes(0)[0];
    let mut resolved = Vec::new();
    for joiners in [8_u8, 32] {
        let Published {
            mut manager,
            tx: _tx,
            ..
        } = published();
        let before = work("cohort_page_resolves");
        let mut riders: Vec<_> = (1..=joiners)
            .map(|n| Rider::join(&mut manager, n, 1 << 12))
            .collect();
        run(&mut manager, &mut riders, &[], |_, riders| {
            riders.iter().all(|rider| rider.table.contains_key(&hot))
        });
        assert!(riders.iter().all(|rider| rider.table.len() < ROWS));
        let mut changes = 0_u32;
        for _ in 0..100_000 {
            // A rider that has completed takes the later changes live.
            for rider in riders.iter_mut().filter(|rider| rider.markers == 0) {
                rider.read();
            }
            if complete(&manager, &riders) {
                break;
            }
            changes += 1;
            manager.handle_update(test_routes_received(
                peer_v4(SOURCE),
                vec![route(hot, SOURCE, 100 + changes % 2)],
            ));
            drain_route_chunks(&mut manager);
            turn(&mut manager);
        }
        assert!(complete(&manager, &riders), "the cohort never completed");
        assert!(changes > u32::from(joiners), "too few changes: {changes}");
        for rider in &riders {
            assert!(rider.table == table_from(SOURCE, ROWS), "rider {}", rider.n);
        }
        crate::manager::tests::assert_paced_fallbacks(&manager.metrics, &[]);
        resolved.push(work("cohort_page_resolves") - before);
    }
    eprintln!("keys resolved under a change per turn at 8 and 32 riders: {resolved:?}");
    // The bound without churn: the scan's two passes, whatever the riders.
    assert!(
        resolved.iter().all(|keys| (ROWS..=2 * ROWS).contains(keys)),
        "keys resolved grew with the cohort: {resolved:?}"
    );
}

// A late joiner starts at the scan's position and completes when the scan
// comes back around to it. Completing at the end of the pass it joined would
// leave it without the rows the scan had already passed.
#[test]
fn a_late_joiner_completes_when_the_scan_returns_to_where_it_joined() {
    let Published {
        mut manager,
        tx: _tx,
        ..
    } = published();
    let mut riders = vec![Rider::join(&mut manager, 1, 1 << 12)];
    run(&mut manager, &mut riders, &[], |_, riders| {
        riders[0].table.len() >= ROWS / 2
    });
    assert!(riders[0].table.len() < ROWS && manager.rides_cohort_scan(receiver(1)));
    riders.push(Rider::join(&mut manager, 3, 1 << 12));
    settle(&mut manager);
    assert!(manager.rides_cohort_scan(receiver(3)));
    assert_eq!(manager.pending_group_admitted.replay_universes(), 1);
    assert_eq!(
        manager
            .cohort_scan_riders()
            .iter()
            .map(|scan| scan.0)
            .collect::<Vec<_>>(),
        [2],
        "the late joiner started a scan of its own"
    );
    let reconciles = work("initial_replay_reconciles");
    run(&mut manager, &mut riders, &[], complete);
    for rider in &riders {
        assert!(
            rider.table == table_from(SOURCE, ROWS),
            "rider {}: {} rows",
            rider.n,
            rider.table.len()
        );
    }
    assert_eq!(work("initial_replay_reconciles"), reconciles);
    assert!(manager.dirty_peers.is_empty());
    assert_eq!(manager.cohort_scan_riders(), Vec::new());
}

// A rider whose writer stays full while the others advance falls behind in
// the cohort's log. Once it is a whole log behind, it leaves the scan and
// rescans on its own in pages. The others never wait for it, and nobody
// takes a whole-table turn.
#[test]
fn a_rider_a_whole_log_behind_leaves_into_its_own_reconcile() {
    let Published {
        mut manager,
        tx: _tx,
        ..
    } = published();
    manager.initial_member_replays.cohort_log_pages = Some(2);
    let builds = manager.adj_rib_out_commit_stats.resync_builds;
    let lagged = work("cohort_lag");
    let before = [
        work("cohort_scan_evictions"),
        work("initial_replay_reconciles"),
    ];
    // Rider 2's one-slot writer parks it behind its first page.
    let mut riders = vec![
        Rider::join(&mut manager, 1, 1 << 12),
        Rider::join(&mut manager, 2, 1),
    ];
    settle(&mut manager);
    assert!(manager.rides_cohort_scan(receiver(2)));
    run(&mut manager, &mut riders, &[2], |manager, _| {
        !manager.rides_cohort_scan(receiver(2))
    });
    assert_eq!(work("cohort_scan_evictions") - before[0], 1);
    assert_eq!(work("initial_replay_reconciles") - before[1], 1);
    // The reconcile names the cohort's log as its cause, not the scan's
    // repair log.
    assert_eq!(work("cohort_lag") - lagged, 1);
    assert!(manager.is_initial_member_replay(receiver(2)));
    assert!(
        manager.rides_cohort_scan(receiver(1)),
        "the others keep the scan"
    );
    assert!(riders[0].markers == 0 && riders[0].table.len() < ROWS);

    run(&mut manager, &mut riders, &[], complete);
    for rider in &riders {
        assert!(rider.table == table_from(SOURCE, ROWS), "rider {}", rider.n);
    }
    assert!(manager.dirty_peers.is_empty());
    assert_eq!(manager.adj_rib_out_commit_stats.resync_builds, builds);
    crate::manager::tests::assert_paced_fallbacks(&manager.metrics, &[]);
    assert_eq!(manager.cohort_scan_riders(), Vec::new());
}

// A source departure mid-cohort changes every winner. Its keys queue into
// the cohort's one repair log, every rider reconciles them in pages, and
// each ends with the surviving source's table. Nobody leaves the scan.
#[test]
fn a_source_departure_mid_cohort_queues_into_the_shared_log() {
    const SMALL: usize = 3 * REGISTRATION_PAGE_SIZE;
    let Published {
        mut manager,
        tx: _tx,
        ..
    } = published_with(SMALL);
    let backup = (0..u16::try_from(SMALL).unwrap())
        .map(|index| route(prefixes(index)[0], OTHER, 50))
        .collect();
    manager.handle_update(test_routes_received(peer_v4(OTHER), backup));
    drain_route_chunks(&mut manager);
    let reconciles = work("initial_replay_reconciles");
    let mut riders = vec![
        Rider::join(&mut manager, 1, 1 << 12),
        Rider::join(&mut manager, 2, 1 << 12),
    ];
    run(&mut manager, &mut riders, &[], |_, riders| {
        riders.iter().all(|rider| !rider.table.is_empty())
    });
    assert!(riders.iter().all(|rider| rider.table.len() < SMALL));
    manager.handle_update(RibUpdate::PeerDown {
        peer: peer_v4(SOURCE),
        session_id: 0,
    });
    drain_source_departure(&mut manager);
    assert!(
        [1, 2]
            .iter()
            .all(|n| manager.rides_cohort_scan(receiver(*n)))
    );
    run(&mut manager, &mut riders, &[], complete);
    for rider in &riders {
        assert!(rider.table == table_from(OTHER, SMALL), "rider {}", rider.n);
    }
    assert_eq!(work("initial_replay_reconciles"), reconciles);
    assert!(manager.dirty_peers.is_empty());
    crate::manager::tests::assert_paced_fallbacks(&manager.metrics, &[]);
}

// One rider flaps and another regroups mid-cohort. The flapped session
// drops its place on the scan and its new session joins as a late joiner;
// the regrouped member leaves for its new group's table. The rider that
// stays keeps its pages and its place, and the scan stops with its last rider.
#[test]
fn a_flap_and_a_regroup_leave_the_other_riders_on_the_scan() {
    let Published {
        mut manager,
        tx: _tx,
        ..
    } = published();
    let mut riders = vec![
        Rider::join(&mut manager, 1, 1 << 12),
        Rider::join(&mut manager, 2, 1 << 12),
        Rider::join(&mut manager, 3, 1 << 12),
    ];
    run(&mut manager, &mut riders, &[], |_, riders| {
        riders.iter().all(|rider| !rider.table.is_empty())
    });
    let scanning = |manager: &RibManager| {
        let scans = manager.cohort_scan_riders();
        scans.iter().map(|scan| scan.0).collect::<Vec<_>>()
    };
    assert_eq!(scanning(&manager), [3]);
    // Rider 2's session ends; its replacement starts from an empty table.
    manager.handle_update(RibUpdate::PeerDown {
        peer: receiver(2),
        session_id: 1,
    });
    drain_source_departure(&mut manager);
    assert_eq!(scanning(&manager), [2]);
    riders[1] = Rider {
        rx: {
            let peer = receiver(2);
            manager.handle_update(RibUpdate::SetPeerRsControl {
                peer,
                session_id: 2,
                rs_control_asn: Some(RS_ASN),
            });
            let (out, rx) = mpsc::channel(1 << 12);
            let mut up = test_peer_up(peer, 2, out);
            let RibUpdate::PeerUp {
                peer_asn,
                sendable_families,
                ..
            } = &mut up
            else {
                unreachable!()
            };
            *peer_asn = 64_602;
            *sendable_families = V4.to_vec();
            manager.handle_update(up);
            rx
        },
        ..Rider::join(&mut manager, 99, 1)
    };
    riders[1].n = 2;
    settle(&mut manager);
    assert!(
        manager.rides_cohort_scan(receiver(2)),
        "the new session rejoined"
    );
    // Rider 3's export policy changes: another group's table. Its move is
    // still a counted fallback to the resync tick.
    let (reply, _result) = oneshot::channel();
    manager.handle_update(RibUpdate::ReplacePeerExportPolicy {
        peer: receiver(3),
        export_policy: Some(crate::manager::tests::update_groups::community_chain(
            REGROUP_TAG,
        )),
        reply,
    });
    assert!(!manager.rides_cohort_scan(receiver(3)));
    crate::manager::tests::assert_paced_fallbacks(
        &manager.metrics,
        &[("initial_replay", "group_changed", 1.0)],
    );
    assert!(manager.rides_cohort_scan(receiver(1)));
    run(&mut manager, &mut riders[..2], &[], complete);
    for rider in &riders[..2] {
        assert!(rider.table == table_from(SOURCE, ROWS), "rider {}", rider.n);
    }
    assert!(!manager.dirty_peers.contains(&receiver(1)));
    assert!(!manager.dirty_peers.contains(&receiver(2)));
}

/// A joiner under export `policy`, RS-control for `rs`.
fn policy_client(
    manager: &mut RibManager,
    n: u8,
    rs: Option<u32>,
    policy: &PolicyChain,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let peer = receiver(n);
    manager.handle_update(RibUpdate::SetPeerRsControl {
        peer,
        session_id: 1,
        rs_control_asn: rs,
    });
    let (out, rx) = mpsc::channel(1 << 14);
    let mut up = test_peer_up(peer, 1, out);
    let RibUpdate::PeerUp {
        peer_asn,
        sendable_families,
        export_policy,
        ..
    } = &mut up
    else {
        unreachable!()
    };
    *peer_asn = 64_600 + u32::from(n);
    *sendable_families = V4.to_vec();
    *export_policy = Some(policy.clone());
    manager.handle_update(up);
    rx
}

/// [`published_with`] for a group under export `policy`: member 200
/// publishes it, and rider 1 joins it.
fn published_under(rows: usize, rs: Option<u32>, policy: &PolicyChain) -> (Published, Vec<Rider>) {
    let (mut manager, tx, _) = fixture(0);
    let table = (0..u16::try_from(rows).unwrap())
        .map(|index| route(prefixes(index)[0], SOURCE, 100))
        .collect();
    manager.handle_update(test_routes_received(peer_v4(SOURCE), table));
    drain_route_chunks(&mut manager);
    let mut founder = policy_client(&mut manager, 200, rs, policy);
    settle(&mut manager);
    let gid = manager.grouped_member_of(receiver(200));
    assert!(gid.is_some());
    while founder.try_recv().is_ok() {}
    manager.initial_member_replays.min_routes = Some(1);
    manager.initial_dump_defer_min_routes = 0;
    tx.try_send(test_routes_received(peer_v4(SOURCE), vec![]))
        .unwrap();
    let riders = vec![Rider::new(1, policy_client(&mut manager, 1, rs, policy))];
    settle(&mut manager);
    for rider in &riders {
        assert_eq!(manager.grouped_member_of(receiver(rider.n)), gid);
        assert!(manager.rides_cohort_scan(receiver(rider.n)));
    }
    let published = Published {
        manager,
        tx,
        _founder: founder,
        _dual_founder: None,
    };
    (published, riders)
}

/// Rider 1 rides alone until it holds rows. Rider 2 then registers, and
/// rider 1 takes one more page before rider 2's first turn. Returns a key
/// of that page. Rider 2 has yet to take the page and has not sent, so no
/// change is recorded for it: only the cohort's page can tell it that a row
/// has changed.
fn page_ahead_of_a_late_joiner(
    manager: &mut RibManager,
    riders: &mut Vec<Rider>,
    join: impl FnOnce(&mut RibManager) -> Rider,
) -> Prefix {
    run(manager, riders, &[], |_, riders| {
        !riders[0].table.is_empty()
    });
    riders.push(join(manager));
    for _ in 0..64 {
        if manager.rides_cohort_scan(receiver(2)) {
            break;
        }
        manager.advance_pending_initial_registration();
    }
    assert!(
        manager.rides_cohort_scan(receiver(2)),
        "rider 2 never joined"
    );
    riders[0].read();
    let (rows, shared) = (riders[0].rows.len(), riders[0].shared);
    manager.wake_initial_member_replay();
    assert!(manager.service_initial_member_replay());
    riders[0].read();
    assert!(riders[0].shared > shared, "rider 1 took no shared page");
    riders[1].read();
    assert!(riders[1].table.is_empty(), "rider 2 has sent");
    riders[0].rows[rows].0
}

// Rider A takes a page as shared rows, then a winner in that page changes.
// Rider B has yet to take the page. It gets the new row, never the row the
// cohort resolved for A.
#[test]
fn a_winner_change_drops_the_rows_a_page_resolved_for_an_earlier_rider() {
    let Published {
        mut manager,
        tx: _tx,
        ..
    } = published();
    let mut riders = vec![Rider::join(&mut manager, 1, 1 << 12)];
    let reconciles = work("initial_replay_reconciles");
    let key = page_ahead_of_a_late_joiner(&mut manager, &mut riders, |manager| {
        Rider::join(manager, 2, 1 << 12)
    });
    let b = 1;
    manager.handle_update(test_routes_received(
        peer_v4(OTHER),
        vec![route(key, OTHER, 200)],
    ));
    drain_route_chunks(&mut manager);
    run(&mut manager, &mut riders, &[], complete);
    assert!(
        !riders[b].rows.contains(&(key, peer_v4(SOURCE))),
        "rider {} took a row resolved before the change",
        riders[b].n
    );
    assert!(riders[b].shared > 0);
    let mut expected = table_from(SOURCE, ROWS);
    expected.insert(key, peer_v4(OTHER));
    for rider in &riders {
        assert!(rider.table == expected, "rider {}", rider.n);
    }
    assert_eq!(work("initial_replay_reconciles"), reconciles);
    crate::manager::tests::assert_paced_fallbacks(&manager.metrics, &[]);
}

/// An export policy that rejects the prefixes of a dataset, empty at first.
fn blocked_policy() -> (Arc<DatasetHandle>, PolicyChain) {
    let handle = Arc::new(DatasetHandle::new(
        "blocked",
        DatasetKind::Prefix,
        DatasetData::Prefix(PrefixSet::new([])),
    ));
    let mut bindings = DatasetBindings::new();
    bindings.insert(Arc::clone(&handle));
    let compiled = RpolFile::parse(
        "dataset prefix-set blocked\n\
         policy p { term t { if route.prefix in blocked { reject } accept } }",
    )
    .unwrap()
    .compile_policy_bound("p", &[], &mut SetStore::new(), &bindings)
    .unwrap()
    .unwrap();
    let chain = PolicyChain::from_named(vec![rustbgpd_policy::NamedPolicy::from_rpol(
        "p".to_string(),
        Arc::new(compiled),
    )]);
    (handle, chain)
}

// A reload of the export policy's dataset mid-cohort restages the group
// with no Loc-RIB write: a row rider A already took in a shared page is now
// rejected. A keeps its place on the scan and withdraws the row from the
// cohort's repair log. Rider B, which has yet to take the page, never
// receives the row.
#[test]
fn a_dataset_reload_mid_cohort_restages_a_page_another_rider_has_taken() {
    const SMALL: usize = 3 * REGISTRATION_PAGE_SIZE;
    let (handle, policy) = blocked_policy();
    let (
        Published {
            mut manager,
            tx: _tx,
            ..
        },
        mut riders,
    ) = published_under(SMALL, None, &policy);
    let reconciles = work("initial_replay_reconciles");
    let key = page_ahead_of_a_late_joiner(&mut manager, &mut riders, |manager| {
        Rider::new(2, policy_client(manager, 2, None, &policy))
    });
    let b = 1;
    let Prefix::V4(blocked) = key else {
        unreachable!()
    };
    handle
        .refresh(DatasetData::Prefix(PrefixSet::new([PrefixSetEntry {
            prefix: Prefix::V4(blocked),
            ge: None,
            le: None,
        }])))
        .expect("the dataset changed");
    let (reply, mut response) = oneshot::channel();
    manager.handle_update(RibUpdate::ReevaluatePeerExportPolicies {
        peers: vec![receiver(200), receiver(1), receiver(2)],
        swaps: None,
        reply,
    });
    assert_eq!(response.try_recv().unwrap(), Ok(()));
    assert!(
        riders
            .iter()
            .all(|rider| manager.rides_cohort_scan(receiver(rider.n))),
        "a rider left the scan at the reload"
    );
    run(&mut manager, &mut riders, &[], complete);
    assert!(
        riders[b].rows.iter().all(|(prefix, _)| *prefix != key),
        "rider {} took a row resolved before the reload",
        riders[b].n
    );
    assert!(riders[b].shared > 0);
    let mut expected = table_from(SOURCE, SMALL);
    expected.remove(&key);
    for rider in &riders {
        assert!(rider.table == expected, "rider {}", rider.n);
    }
    assert_eq!(work("initial_replay_reconciles"), reconciles);
    crate::manager::tests::assert_paced_fallbacks(&manager.metrics, &[]);
}

/// A permit-all export policy that edits the route's communities.
fn editing_chain(edit: impl FnOnce(&mut rustbgpd_policy::RouteModifications)) -> PolicyChain {
    let mut statement = deny_statement(Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0));
    statement.prefix = None;
    statement.action = PolicyAction::Permit;
    edit(&mut statement.modifications);
    PolicyChain::new(vec![Policy {
        entries: vec![statement],
        default_action: PolicyAction::Deny,
    }])
}

// The source tags a row "do not announce to rider B" after rider A took its
// page. The export policy strips that community, so the staged row is
// unchanged and only its source-control input moves. B, which has yet to
// take the page, never receives the row the cohort resolved for A.
#[test]
fn a_tag_only_change_drops_the_rows_a_page_resolved_for_an_earlier_rider() {
    // `0:ASN` suppresses the row toward that member.
    let tags = [64_601_u32, 64_602];
    let policy = editing_chain(|edit| edit.communities_remove.extend(tags));
    let (
        Published {
            mut manager,
            tx: _tx,
            ..
        },
        mut riders,
    ) = published_under(ROWS, Some(RS_ASN), &policy);
    let reconciles = work("initial_replay_reconciles");
    let key = page_ahead_of_a_late_joiner(&mut manager, &mut riders, |manager| {
        Rider::new(2, policy_client(manager, 2, Some(RS_ASN), &policy))
    });
    let (a, b) = (0, 1);
    let mut tagged = route(key, SOURCE, 100);
    AttrSet::edit(&mut tagged.attributes, |attrs| {
        attrs.push(PathAttribute::Communities(vec![tags[b]]));
    });
    manager.handle_update(test_routes_received(peer_v4(SOURCE), vec![tagged]));
    drain_route_chunks(&mut manager);
    run(&mut manager, &mut riders, &[], complete);
    assert!(
        riders[b].rows.iter().all(|(prefix, _)| *prefix != key),
        "rider {} took a row resolved before the tag",
        riders[b].n
    );
    assert!(riders[b].shared > 0);
    let full = table_from(SOURCE, ROWS);
    assert!(riders[a].table == full, "rider {}", riders[a].n);
    let mut suppressed = full;
    suppressed.remove(&key);
    assert!(riders[b].table == suppressed, "rider {}", riders[b].n);
    assert_eq!(work("initial_replay_reconciles"), reconciles);
    crate::manager::tests::assert_paced_fallbacks(&manager.metrics, &[]);
}

// The export policy adds a control community for the riders' route-server
// ASN. RFC 7947 scrubs it toward each member, so no such row is the same
// toward every rider: each resolves its own slot, and none receives the
// community.
#[test]
fn a_control_community_the_policy_adds_keeps_a_row_out_of_the_shared_page() {
    let tag = (RS_ASN << 16) | 7;
    let policy = editing_chain(|edit| edit.communities_add.push(tag));
    let (
        Published {
            mut manager,
            tx: _tx,
            ..
        },
        mut riders,
    ) = published_under(ROWS, Some(RS_ASN), &policy);
    riders.push(Rider::new(
        2,
        policy_client(&mut manager, 2, Some(RS_ASN), &policy),
    ));
    run(&mut manager, &mut riders, &[], complete);
    for rider in &riders {
        assert!(rider.table == table_from(SOURCE, ROWS), "rider {}", rider.n);
        assert_eq!(rider.control_tagged, 0, "rider {}", rider.n);
        assert_eq!(rider.shared, 0, "rider {}", rider.n);
    }
    crate::manager::tests::assert_paced_fallbacks(&manager.metrics, &[]);
}

// Three quarters of the rows change before the scan reaches them, so each
// rider takes them as repairs first. A discovery page then holds keys the
// rider has and keys it lacks: it takes the rest key by key. Skipping a
// page it holds only part of would leave it short.
#[test]
fn a_rider_holding_part_of_a_page_takes_the_rest_key_by_key() {
    const SMALL: usize = 3 * REGISTRATION_PAGE_SIZE;
    let Published {
        mut manager,
        tx: _tx,
        ..
    } = published_with(SMALL);
    let mut riders = vec![
        Rider::join(&mut manager, 1, 1 << 12),
        Rider::join(&mut manager, 2, 1 << 12),
    ];
    settle(&mut manager);
    assert!(manager.rides_cohort_scan(receiver(1)) && manager.rides_cohort_scan(receiver(2)));
    let reconciles = work("initial_replay_reconciles");
    let changed = (0..u16::try_from(SMALL).unwrap())
        .filter(|index| index % 4 != 0)
        .map(|index| route(prefixes(index)[0], SOURCE, 150))
        .collect();
    manager.handle_update(test_routes_received(peer_v4(SOURCE), changed));
    drain_route_chunks(&mut manager);
    run(&mut manager, &mut riders, &[], complete);
    for rider in &riders {
        assert!(
            rider.table == table_from(SOURCE, SMALL),
            "rider {}: {} rows",
            rider.n,
            rider.table.len()
        );
    }
    assert_eq!(work("initial_replay_reconciles"), reconciles);
    crate::manager::tests::assert_paced_fallbacks(&manager.metrics, &[]);
}

// An outbound prefix limit lands on one rider mid-cohort. Its commits meet
// the limit on pages the riders before and after it take as the same
// shared rows; they still receive every row.
#[test]
fn a_prefix_limit_caps_one_riders_commit_of_a_page_the_others_share() {
    use crate::manager::tests::outbound_prefix_limits::{apply, limit_config, prepare};

    const LIMIT: u32 = 2_000;
    let Published {
        mut manager,
        tx: _tx,
        ..
    } = published();
    let mut riders: Vec<_> = (1..=3)
        .map(|n| Rider::join(&mut manager, n, 1 << 12))
        .collect();
    run(&mut manager, &mut riders, &[], |_, riders| {
        riders.iter().all(|rider| !rider.table.is_empty())
    });
    assert!(
        riders
            .iter()
            .all(|rider| rider.table.len() < LIMIT as usize)
    );
    prepare(
        &mut manager,
        1,
        limit_config(&[(receiver(2), Some(LIMIT), None)], &[]),
    )
    .expect("the admitted pages fit the limit");
    apply(&mut manager, 1, true).expect("applied mid-cohort");
    assert!((1..=3).all(|n| manager.rides_cohort_scan(receiver(n))));
    run(&mut manager, &mut riders, &[], complete);
    assert_eq!(riders[1].table.len(), LIMIT as usize);
    for rider in [&riders[0], &riders[2]] {
        assert!(rider.table == table_from(SOURCE, ROWS), "rider {}", rider.n);
        assert!(
            rider.shared >= usize::from(PAGES) && rider.private == 0,
            "rider {}: {} shared, {} private",
            rider.n,
            rider.shared,
            rider.private
        );
    }
    assert_eq!(manager.cohort_scan_riders(), Vec::new());
}
