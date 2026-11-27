//! Joiners of one group table ride one scan of the Loc-RIB. Its rows do not
//! grow with the riders, a late joiner completes one pass after it joined,
//! and a rider that falls a whole log behind reconciles on its own.
use super::*;

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
    markers: usize,
    // Route-bearing envelopes with the cohort's encode cell, and without.
    shared: usize,
    private: usize,
}

impl Rider {
    fn join(manager: &mut RibManager, n: u8, capacity: usize) -> Self {
        Self {
            n,
            rx: rs_client(manager, n, capacity),
            table: HashMap::new(),
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
    assert_eq!(resolved[0], resolved[1], "{resolved:?}");
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
