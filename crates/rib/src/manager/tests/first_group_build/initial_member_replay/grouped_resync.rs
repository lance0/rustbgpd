//! A grouped member that fell behind resyncs through a paced reconcile: the
//! resync tick enrolls it instead of building its whole table in one turn.
//! Each test gives member 1 its initial table and End-of-RIB, fills its
//! writer under ordinary churn until a pass marks it dirty, lands more
//! changes while it is dirty, then drives the resync a turn at a time.
use super::*;
use crate::loc_rib::REGISTRATION_PAGE_SIZE;
use crate::update::{RoutePageError, RouteQueryScope};

/// Whole-table units: dirty resync builds (K1), one-turn initial tables (K2)
/// and synchronous group builds (K3).
fn whole_table_units(manager: &RibManager) -> [usize; 3] {
    let work = crate::manager::slice_timing::group_work();
    let count = |stage| work.get(stage).copied().unwrap_or(0);
    [
        manager.adj_rib_out_commit_stats.resync_builds,
        count("initial_table_turns"),
        count("synchronous_group_builds"),
    ]
}

fn work(stage: &str) -> usize {
    crate::manager::slice_timing::group_work()
        .get(stage)
        .copied()
        .unwrap_or(0)
}

/// Each source's preference per prefix; the highest wins. SOURCE holds
/// every initial row at 100, so a change never ties.
type Model = BTreeMap<Prefix, BTreeMap<Ipv4Addr, u32>>;

struct Lagged {
    manager: RibManager,
    _tx: mpsc::Sender<RibUpdate>,
    peer: PeerId,
    rx: mpsc::Receiver<OutboundRouteUpdate>,
    /// What the member holds, from the pages it was sent.
    state: Inventory,
    model: Model,
    markers: usize,
    /// Pages and rows the member received in the last turn.
    last_turn: (usize, usize),
    before: [usize; 3],
    reconciles: usize,
}

impl Lagged {
    /// Member 1 at `rows` IPv4 rows. Its writer of `capacity` envelopes
    /// fills under churn until a pass marks it dirty, then `missed` more
    /// changes land while it is dirty.
    fn new(rows: u16, capacity: usize, missed: u16) -> Self {
        let (mut manager, tx, _) = fixture(0);
        let routes = (0..rows)
            .map(|i| route(prefixes(i)[0], SOURCE, 100))
            .collect();
        manager.handle_update(test_routes_received(peer_v4(SOURCE), routes));
        drain_route_chunks(&mut manager);
        let model = (0..rows)
            .map(|i| (prefixes(i)[0], BTreeMap::from([(SOURCE, 100)])))
            .collect();
        let peer = receiver(1);
        // The initial table goes out in one turn; only the resync is paced.
        manager.first_group_build_min_routes = usize::MAX;
        manager.initial_member_replays.min_routes = Some(usize::MAX);
        let rx = member(&mut manager, peer, capacity, false, false);
        finish(&mut manager);
        let mut lagged = Self {
            manager,
            _tx: tx,
            peer,
            rx,
            state: Inventory::new(),
            model,
            markers: 0,
            last_turn: (0, 0),
            before: [0; 3],
            reconciles: 0,
        };
        lagged.read();
        assert_eq!(lagged.markers, 1, "initial End-of-RIB");
        assert_eq!(lagged.state, lagged.expected());
        lagged.manager.initial_member_replays.min_routes = Some(1);
        // Churn the member does not read fills its writer.
        let mut i = 0;
        while !lagged.manager.dirty_peers.contains(&peer) {
            assert!(i < 64, "the writer never filled");
            lagged.set(i, OTHER, Some(200));
            i += 1;
        }
        // Withdraw held rows, move others and add new ones while it is dirty.
        for n in 0..missed {
            match n % 3 {
                0 => lagged.set(100 + n, SOURCE, None),
                1 => lagged.set(100 + n, OTHER, Some(300)),
                _ => lagged.set(rows + n, OTHER, Some(100)),
            }
        }
        assert!(lagged.manager.dirty_peers.contains(&peer));
        lagged.read();
        lagged.before = whole_table_units(&lagged.manager);
        lagged.reconciles = work("grouped_resync_reconciles");
        lagged
    }

    fn expected(&self) -> Inventory {
        self.model
            .iter()
            .filter_map(|(prefix, paths)| {
                let (source, pref) = paths.iter().max_by_key(|(_, pref)| **pref)?;
                Some((*prefix, (peer_v4(*source), *pref)))
            })
            .collect()
    }

    /// `source` announces row `i` at `pref`, or withdraws it.
    fn set(&mut self, i: u16, source: Ipv4Addr, pref: Option<u32>) {
        let prefix = prefixes(i)[0];
        let mut update = test_routes_received(peer_v4(source), Vec::new());
        let RibUpdate::RoutesReceived {
            announced,
            withdrawn,
            ..
        } = &mut update
        else {
            unreachable!()
        };
        let paths = self.model.entry(prefix).or_default();
        if let Some(pref) = pref {
            announced.push(route(prefix, source, pref));
            paths.insert(source, pref);
        } else {
            withdrawn.push((prefix, 0));
            paths.remove(&source);
        }
        if paths.is_empty() {
            self.model.remove(&prefix);
        }
        self.manager.handle_update(update);
        drain_route_chunks(&mut self.manager);
    }

    /// Apply every queued page to the member's state.
    fn read(&mut self) {
        self.last_turn = (0, 0);
        while let Ok(page) = self.rx.try_recv() {
            self.last_turn.0 += 1;
            for &(prefix, _) in page.unicast_withdrawals() {
                assert!(
                    self.state.remove(&prefix).is_some(),
                    "withdrew unsent {prefix}"
                );
                self.last_turn.1 += 1;
            }
            for row in page
                .announce
                .iter()
                .filter(|row| page.announce_source_exclusion != Some(row.peer))
            {
                self.state.insert(row.prefix, (row.peer, row.local_pref()));
                self.last_turn.1 += 1;
            }
            self.markers += page.end_of_rib.len();
        }
    }

    fn reconciling(&self) -> bool {
        self.manager.is_initial_member_replay(self.peer)
    }

    /// One resync tick, then the rows it sent.
    fn tick(&mut self) -> usize {
        self.manager.resync_dirty_peers_bounded();
        self.read();
        self.last_turn.1
    }

    /// One replay turn, then the rows it sent.
    fn turn(&mut self) -> usize {
        self.read();
        self.manager.wake_initial_member_replay();
        self.manager.advance_pending_initial_registration();
        self.read();
        self.last_turn.1
    }

    /// Run turns and ticks until the member is clean; `between` lands
    /// changes before each turn.
    fn settle(&mut self, mut between: impl FnMut(&mut Self, usize)) {
        for n in 0..20_000 {
            if !self.reconciling() && !self.manager.dirty_peers.contains(&self.peer) {
                self.read();
                return;
            }
            between(self, n);
            if self.reconciling() {
                self.turn();
            } else {
                self.tick();
            }
        }
        panic!("the resync never completed");
    }

    fn listing(&mut self) -> Result<usize, RoutePageError> {
        let (reply, mut response) = oneshot::channel();
        let scope = RouteQueryScope::Advertised { peer: self.peer };
        self.manager
            .handle_query_routes_page_versioned(scope, None, None, None, 100_000, reply);
        response.try_recv().unwrap().map(|page| page.routes.len())
    }

    /// The member holds the exact table, sent no marker since its initial
    /// one, and nothing else is queued.
    fn assert_exact(&mut self) {
        self.read();
        assert_eq!(self.state, self.expected(), "resynced table");
        assert_eq!(self.markers, 1, "a resync owes no End-of-RIB");
        assert!(self.rx.is_empty());
        assert!(!self.manager.dirty_peers.contains(&self.peer));
        assert!(!self.manager.force_outbound_peers.contains(&self.peer));
    }

    fn units(&self) -> [usize; 3] {
        let after = whole_table_units(&self.manager);
        [0, 1, 2].map(|i| after[i] - self.before[i])
    }

    fn reconciles(&self) -> usize {
        work("grouped_resync_reconciles") - self.reconciles
    }

    /// Paced throughout: one reconcile, no whole-table unit, no fallback.
    fn assert_paced(&mut self) {
        self.assert_exact();
        assert_eq!(self.units(), [0; 3], "whole-table units");
        assert_eq!(self.reconciles(), 1, "reconciles enrolled");
        crate::manager::tests::assert_paced_fallbacks(&self.manager.metrics, &[]);
    }
}

// Churn between the reconcile's turns lands behind and ahead of its scan.
// The member ends with the exact table, the read gate refuses its listing
// until then, no whole-table unit runs and no End-of-RIB is sent.
#[test]
fn a_lagged_member_reconciles_its_table_in_pages_under_churn() {
    let mut lagged = Lagged::new(V4_ROWS, 2, 90);
    assert_eq!(lagged.tick(), 0, "the tick sent the table");
    assert!(lagged.reconciling());
    assert!(!lagged.manager.dirty_peers.contains(&lagged.peer));
    // The member is still pending a resync.
    let convergence = lagged.manager.outbound_convergence();
    assert_eq!(convergence.pending_peers, 1);
    assert_eq!(lagged.listing(), Err(RoutePageError::ResyncInProgress));
    let mut n = 0;
    lagged.settle(|lagged, _| {
        for _ in 0..8 {
            if n == 160 {
                break;
            }
            let i = (n * 37) % V4_ROWS;
            match n % 4 {
                0 => lagged.set(i, OTHER, Some(250)),
                1 => lagged.set(i, OTHER, None),
                2 => lagged.set(V4_ROWS + 200 + n, OTHER, Some(90)),
                _ => lagged.set(i, SOURCE, Some(400)),
            }
            n += 1;
        }
        if lagged.reconciling() {
            assert_eq!(lagged.listing(), Err(RoutePageError::ResyncInProgress));
        }
    });
    assert!(n >= 32, "too few mid-reconcile changes: {n}");
    lagged.assert_paced();
    assert_eq!(lagged.manager.outbound_convergence().pending_peers, 0);
    assert!(
        lagged.listing().is_ok(),
        "the read gate outlived the reconcile"
    );
}

// One grouped resync sends at most one page per turn, however large the
// table; on main the tick sends the whole table in its turn.
#[test]
fn a_grouped_resync_sends_one_page_per_turn_from_8_to_32_pages() {
    for pages in [8_u16, 32] {
        let rows = pages * u16::try_from(REGISTRATION_PAGE_SIZE).unwrap();
        let mut lagged = Lagged::new(rows, 2, 90);
        let visits = work("initial_member_replay_visits");
        let mut peak = lagged.tick();
        let mut turns = 0;
        while lagged.reconciling() {
            let before = work("initial_member_replay_visits");
            let rows = lagged.turn();
            peak = peak
                .max(rows)
                .max(work("initial_member_replay_visits") - before);
            turns += 1;
            assert!(
                turns < 50 * usize::from(pages),
                "the reconcile never completed"
            );
        }
        let total = work("initial_member_replay_visits") - visits;
        eprintln!("pages={pages}: peak={peak} total visits={total} turns={turns}");
        assert!(peak <= REGISTRATION_PAGE_SIZE, "pages={pages}: peak {peak}");
        // R1's bucket visits and R2's proof sweep, each about once per row.
        assert!(total <= 4 * usize::from(rows), "pages={pages}: {total}");
        lagged.assert_paced();
    }
}

// A full writer parks the reconcile; the latch release resumes it at its
// cursor. The member is never marked dirty again and no resync is built.
#[test]
fn a_full_writer_parks_the_reconcile_without_a_dirty_mark() {
    let mut lagged = Lagged::new(V4_ROWS, 2, 30);
    lagged.tick();
    let mut parked = 0;
    for _ in 0..20_000 {
        if !lagged.reconciling() {
            break;
        }
        // The second turn finds the first one's page still queued.
        lagged.manager.wake_initial_member_replay();
        lagged.manager.advance_pending_initial_registration();
        lagged.manager.advance_pending_initial_registration();
        if lagged.manager.initial_member_replays.parked() {
            parked += 1;
            assert!(!lagged.manager.dirty_peers.contains(&lagged.peer));
        }
        lagged.read();
    }
    assert!(parked > 0, "the writer never filled");
    lagged.assert_paced();
}

// A second dirty mark mid-reconcile restarts the rescan; it is not a
// fallback, and the force bit of a forced mark holds.
#[test]
fn a_second_dirty_mark_mid_reconcile_rewinds_it() {
    for forced in [false, true] {
        let mut lagged = Lagged::new(V4_ROWS, 2, 30);
        lagged.tick();
        for _ in 0..3 {
            lagged.turn();
        }
        assert!(lagged.reconciling());
        if forced {
            lagged.manager.force_outbound_peers.insert(lagged.peer);
        }
        assert!(lagged.manager.mark_outbound_dirty(lagged.peer));
        lagged.set(7, OTHER, Some(500));
        lagged.turn();
        assert!(lagged.reconciling(), "forced={forced}");
        assert!(!lagged.manager.dirty_peers.contains(&lagged.peer));
        lagged.settle(|_, _| {});
        lagged.assert_paced();
    }
}

// A source departure mid-reconcile is paged and its changes reach the
// member as repairs.
#[test]
fn a_source_departure_mid_reconcile_reaches_the_member_as_repairs() {
    let mut lagged = Lagged::new(V4_ROWS, 2, 30);
    for i in 0..300 {
        lagged.set(V4_ROWS + 1_000 + i, OTHER, Some(100));
        lagged.set(500 + i, OTHER, Some(150));
    }
    lagged.read();
    lagged.tick();
    for _ in 0..2 {
        lagged.turn();
    }
    lagged.manager.handle_update(RibUpdate::PeerDown {
        peer: peer_v4(OTHER),
        session_id: 0,
    });
    drain_source_departure(&mut lagged.manager);
    drain_route_chunks(&mut lagged.manager);
    for paths in lagged.model.values_mut() {
        paths.remove(&OTHER);
    }
    lagged.model.retain(|_, paths| !paths.is_empty());
    lagged.settle(|_, _| {});
    lagged.assert_paced();
}

// A ROUTE-REFRESH mid-reconcile waits for the reconcile, then is answered
// in full.
#[test]
fn a_route_refresh_mid_reconcile_is_answered_after_it() {
    use rustbgpd_wire::RouteRefreshSubtype::{BoRR, EoRR};

    let mut lagged = Lagged::new(V4_ROWS, 2, 30);
    lagged.tick();
    lagged.turn();
    lagged
        .manager
        .handle_update(RibUpdate::RouteRefreshRequest {
            peer: lagged.peer,
            session_id: 7,
            afi: FAMILY.0,
            safi: FAMILY.1,
            queued: Arc::default(),
        });
    let mut refreshed = false;
    for _ in 0..20_000 {
        if !lagged.reconciling() {
            break;
        }
        lagged.manager.wake_initial_member_replay();
        lagged.manager.advance_pending_initial_registration();
        while let Ok(page) = lagged.rx.try_recv() {
            assert!(
                page.refresh_markers.is_empty(),
                "refresh inside the reconcile"
            );
            for &(prefix, _) in page.unicast_withdrawals() {
                assert!(lagged.state.remove(&prefix).is_some());
            }
            for row in page.announce.iter() {
                lagged
                    .state
                    .insert(row.prefix, (row.peer, row.local_pref()));
            }
        }
    }
    assert_eq!(lagged.state, lagged.expected(), "reconciled table");
    lagged.manager.resync_dirty_peers_bounded();
    while let Ok(page) = lagged.rx.try_recv() {
        assert_eq!(
            page.refresh_markers,
            [(FAMILY.0, FAMILY.1, BoRR), (FAMILY.0, FAMILY.1, EoRR)]
        );
        let keys: BTreeSet<_> = page.announce.iter().map(|row| row.prefix).collect();
        assert_eq!(keys, lagged.expected().keys().copied().collect());
        refreshed = true;
    }
    assert!(refreshed, "the refresh was never answered");
    assert_eq!(lagged.units(), [0; 3]);
    assert_eq!(lagged.reconciles(), 1);
    crate::manager::tests::assert_paced_fallbacks(&lagged.manager.metrics, &[]);
}

// A flap mid-reconcile ends it: the new session gets its own initial table
// and End-of-RIB, and the old writer gets nothing more.
#[test]
fn a_flap_mid_reconcile_hands_the_table_to_the_new_session() {
    let mut lagged = Lagged::new(V4_ROWS, 2, 30);
    lagged.tick();
    lagged.turn();
    let peer = lagged.peer;
    lagged.manager.handle_update(RibUpdate::PeerDown {
        peer,
        session_id: 7,
    });
    drain_source_departure(&mut lagged.manager);
    // The member was its group's only one: the new session founds it again.
    lagged.manager.first_group_build_min_routes = 1;
    let mut fresh = member(&mut lagged.manager, peer, 64, false, false);
    let expected = lagged.expected();
    let mut table = Inventory::new();
    let mut markers = 0;
    for _ in 0..20_000 {
        lagged.manager.wake_initial_member_replay();
        lagged.manager.advance_pending_initial_registration();
        while let Ok(page) = fresh.try_recv() {
            for row in page.announce.iter() {
                table.insert(row.prefix, (row.peer, row.local_pref()));
            }
            markers += page.end_of_rib.len();
        }
        if markers != 0 {
            break;
        }
    }
    assert_eq!((table, markers), (expected, 1));
    assert!(lagged.rx.try_recv().is_err(), "the old writer got a page");
    assert_eq!(lagged.units(), [0; 3], "whole-table units");
    crate::manager::tests::assert_paced_fallbacks(&lagged.manager.metrics, &[]);
}

// A regroup mid-reconcile changes the member's group: it falls back to one
// counted resync under its new policy.
#[test]
fn a_regroup_mid_reconcile_takes_one_counted_resync() {
    let mut lagged = Lagged::new(V4_ROWS, 2, 30);
    lagged.tick();
    lagged.turn();
    let (reply, mut result) = oneshot::channel();
    lagged
        .manager
        .handle_update(RibUpdate::ReplacePeerExportPolicy {
            peer: lagged.peer,
            export_policy: Some(community_chain(TAG)),
            reply,
        });
    result.try_recv().unwrap().unwrap();
    lagged.settle(|_, _| {});
    lagged.assert_exact();
    assert_eq!(lagged.units()[0], 1, "one counted resync");
    crate::manager::tests::assert_paced_fallbacks(
        &lagged.manager.metrics,
        &[("grouped_resync", "group_changed", 1.0)],
    );
}

// A forced resync that falls back before R1 resends anything passes its
// force on, so the one-turn resync still resends every row.
#[test]
fn a_forced_resync_reconcile_keeps_its_force_through_a_fallback() {
    let mut lagged = Lagged::new(V4_ROWS, 2, 30);
    lagged.manager.force_outbound_peers.insert(lagged.peer);
    lagged.tick();
    assert!(lagged.reconciling());
    assert!(!lagged.manager.force_outbound_peers.contains(&lagged.peer));
    let _ = lagged.manager.recover_initial_member_replay(
        lagged.peer,
        crate::manager::initial_member_replay::PacedFallbackCause::MissingProof,
    );
    assert!(
        lagged.manager.force_outbound_peers.contains(&lagged.peer),
        "the fallback dropped the forced resync"
    );
    let sent = lagged.tick();
    assert!(
        sent >= lagged.expected().len(),
        "the forced resync resent {sent} rows"
    );
    lagged.assert_exact();
    assert_eq!(lagged.units()[0], 1);
    crate::manager::tests::assert_paced_fallbacks(
        &lagged.manager.metrics,
        &[("grouped_resync", "missing_proof", 1.0)],
    );
}

// A member that cannot reconcile takes the one-turn resync and counts why,
// once, when the resync is built: a tick that finds its writer full builds
// nothing and counts nothing. A table below the pacing threshold takes the
// resync uncounted.
#[test]
fn an_ineligible_member_takes_one_counted_resync() {
    let mut lagged = Lagged::new(V4_ROWS, 2, 30);
    lagged.manager.set_group_recovery_fallback(
        lagged.peer,
        crate::manager::update_groups::RecoveryFallbackCause::PeerLimit,
    );
    let writer = lagged.manager.outbound_peers[&lagged.peer].clone();
    while writer.try_send(OutboundRouteUpdate::default()).is_ok() {}
    for _ in 0..3 {
        lagged.manager.resync_dirty_peers_bounded();
    }
    assert!(lagged.manager.dirty_peers.contains(&lagged.peer));
    assert_eq!(
        lagged.units()[0],
        0,
        "a resync was built into a full writer"
    );
    crate::manager::tests::assert_paced_fallbacks(&lagged.manager.metrics, &[]);
    lagged.settle(|_, _| {});
    lagged.assert_exact();
    assert_eq!(lagged.units()[0], 1);
    assert_eq!(lagged.reconciles(), 0);
    crate::manager::tests::assert_paced_fallbacks(
        &lagged.manager.metrics,
        &[("grouped_resync", "peer_limit", 1.0)],
    );

    let mut small = Lagged::new(V4_ROWS, 2, 30);
    small.manager.initial_member_replays.min_routes = Some(usize::MAX);
    small.settle(|_, _| {});
    small.assert_exact();
    assert_eq!(small.units()[0], 1);
    crate::manager::tests::assert_paced_fallbacks(&small.manager.metrics, &[]);
}

// A marker the member already owes is held through the reconcile and sent
// once, after the complete table.
#[test]
fn an_owed_end_of_rib_follows_the_reconciled_table() {
    let mut lagged = Lagged::new(V4_ROWS, 2, 30);
    lagged.manager.owe_eor(lagged.peer, FAMILY);
    lagged.tick();
    assert!(lagged.reconciling());
    let mut n = 0;
    loop {
        lagged.manager.wake_initial_member_replay();
        lagged.manager.advance_pending_initial_registration();
        while let Ok(page) = lagged.rx.try_recv() {
            for &(prefix, _) in page.unicast_withdrawals() {
                assert!(lagged.state.remove(&prefix).is_some());
            }
            for row in page.announce.iter() {
                lagged
                    .state
                    .insert(row.prefix, (row.peer, row.local_pref()));
            }
            if !page.end_of_rib.is_empty() {
                assert_eq!(page.end_of_rib, [FAMILY]);
                assert_eq!(lagged.state, lagged.expected(), "early End-of-RIB");
                lagged.markers += 1;
            }
        }
        if !lagged.reconciling() {
            break;
        }
        n += 1;
        assert!(n < 20_000);
    }
    assert_eq!(lagged.markers, 2, "the owed marker, once");
    assert_eq!(lagged.units(), [0; 3]);
    crate::manager::tests::assert_paced_fallbacks(&lagged.manager.metrics, &[]);
}
