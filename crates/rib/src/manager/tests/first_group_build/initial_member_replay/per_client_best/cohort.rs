//! Joiners of one group share one proof key universe, each with its own
//! admission mask, and ride one scan of the Loc-RIB. Every member must still
//! end with the table its own one-turn join gives, whatever the others
//! admit, withdraw or lose, and wherever on the scan it joined or left.
use super::*;
use crate::manager::initial_member_replay::PacedFallbackCause;

struct Member {
    n: u8,
    rx: mpsc::Receiver<OutboundRouteUpdate>,
    table: Table,
    markers: usize,
}

struct Cohort {
    manager: RibManager,
    _primary: mpsc::Sender<RibUpdate>,
    founder: mpsc::Receiver<OutboundRouteUpdate>,
    shape: Shape,
    members: Vec<Member>,
    builds: usize,
    // A member whose writer nobody reads: it parks behind its first page.
    parked: Option<u8>,
}

fn work(stage: &str) -> usize {
    crate::manager::slice_timing::group_work()
        .get(stage)
        .copied()
        .unwrap_or(0)
}

impl Cohort {
    /// Members 1, 2 and 3 join the published group together.
    fn start(paced: bool, shape: Shape) -> Self {
        let Run {
            manager,
            _primary: primary,
            founder,
            rx,
            builds,
            ..
        } = Run::start(paced, shape);
        let mut cohort = Self {
            manager,
            _primary: primary,
            founder,
            shape,
            members: vec![Member {
                n: 1,
                rx,
                table: Table::new(),
                markers: 0,
            }],
            builds,
            parked: None,
        };
        for n in [2, 3] {
            cohort.join(n, 1);
        }
        cohort
    }

    /// (Re)join member `n`: a new session starts from an empty table.
    fn join(&mut self, n: u8, session: u64) {
        self.join_with(n, session, 64);
    }

    fn join_with(&mut self, n: u8, session: u64, capacity: usize) {
        let rx = join_pcb(&mut self.manager, n, session, self.shape, capacity);
        self.members.retain(|member| member.n != n);
        self.members.push(Member {
            n,
            rx,
            table: Table::new(),
            markers: 0,
        });
    }

    fn read(&mut self) {
        for member in &mut self.members {
            if self.parked != Some(member.n) {
                read_into(&mut member.rx, &mut member.table, &mut member.markers);
            }
        }
        while self.founder.try_recv().is_ok() {}
    }

    fn turn(&mut self) {
        self.read();
        self.manager.wake_initial_member_replay();
        self.manager.advance_pending_initial_registration();
        self.read();
    }

    fn replaying(&self, n: u8) -> bool {
        self.manager.is_initial_member_replay(receiver(n))
    }

    fn universes(&self) -> usize {
        self.manager.pending_group_admitted.replay_universes()
    }

    /// The cohort's events, one per turn once its first pages are admitted.
    fn event(&mut self, step: u32) {
        let shape = self.shape;
        match step {
            1 => {
                // A late joiner shares the universe the cohort walked.
                self.join(4, 1);
                assert!(self.replaying(4), "{shape:?}");
                assert_eq!(self.universes(), 1, "{shape:?}: late joiner");
                assert!(
                    self.manager.rides_cohort_scan(receiver(4)),
                    "{shape:?}: the late joiner rides the cohort's scan"
                );
                assert_eq!(
                    self.manager.cohort_scan_riders().len(),
                    1,
                    "{shape:?}: the late joiner started a second scan"
                );
            }
            2 => {
                // A member leaves mid-cohort and its new session joins again.
                self.manager.handle_update(RibUpdate::PeerDown {
                    peer: receiver(2),
                    session_id: 1,
                });
                drain_source_departure(&mut self.manager);
                assert!(!self.replaying(2), "{shape:?}");
                self.join(2, 2);
                assert!(self.replaying(2), "{shape:?}");
                assert_eq!(self.universes(), 1, "{shape:?}: rejoin");
            }
            3 => {
                assert!(self.replaying(3), "{shape:?}: member 3 finished early");
                assert!(
                    self.manager.recover_initial_member_replay(
                        receiver(3),
                        PacedFallbackCause::ScanRepairLimit
                    ),
                    "{shape:?}: member 3 did not reconcile"
                );
            }
            _ => {}
        }
    }

    fn tables(mut self) -> Vec<(u8, Table, usize)> {
        self.read();
        self.members.sort_by_key(|member| member.n);
        self.members
            .into_iter()
            .map(|member| (member.n, member.table, member.markers))
            .collect()
    }
}

/// One change at a hot key: a new preference or a withdrawal from any
/// source, or the preferred path again with only its suppression tag drawn.
fn draw_change(next: &mut impl FnMut(usize) -> usize, hot: &[Prefix]) -> Change {
    let tag_only = next(3) == 0;
    let source = if tag_only { 0 } else { next(SOURCES.len()) };
    Change {
        source,
        prefix: hot[next(HOT)],
        pref: (tag_only || next(4) != 0).then(|| {
            if tag_only {
                PREFS[0]
            } else if source == 3 {
                400
            } else {
                50 + 50 * u32::try_from(next(6)).unwrap()
            }
        }),
        suppress: next(2) == 0,
    }
}

/// The paced cohort under churn. Member 5's writer stays full, so it falls
/// a whole log behind the others and leaves their scan for its own
/// reconcile. Once the first pages are admitted, member 4 joins late, part
/// of the way through the scan's pass, member 2 flaps and rejoins, and
/// member 3 loses track of its changes and rewinds into a reconcile.
/// Returns each member's table and markers, and the applied changes.
fn paced_cohort(shape: Shape, seed: u64) -> (Vec<(u8, Table, usize)>, Vec<Change>) {
    let mut cohort = Cohort::start(true, shape);
    cohort.manager.initial_member_replays.cohort_log_pages = Some(2);
    cohort.join_with(5, 1, 1);
    cohort.parked = Some(5);
    let counted = [work("cohort_scan_evictions"), work("cohort_shared_rows")];
    assert!((1..=3).all(|n| cohort.replaying(n)), "{shape:?}");
    assert!(cohort.replaying(5), "{shape:?}");
    assert_eq!(cohort.universes(), 1, "{shape:?}: one universe per cohort");
    assert_eq!(
        cohort.manager.cohort_scan_riders().len(),
        1,
        "{shape:?}: one scan per cohort"
    );
    let mut rng = seed;
    let mut next = move |bound: usize| {
        rng = rng
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        usize::try_from(rng >> 33).unwrap() % bound
    };
    let mut applied = Vec::new();
    let mut hot = Vec::new();
    let mut step = 0;
    for _ in 0..20_000 {
        if !(1..=5).any(|n| cohort.replaying(n))
            && cohort.manager.pending_initial_registrations.is_empty()
        {
            break;
        }
        cohort.turn();
        if cohort.parked.is_some() && !cohort.manager.rides_cohort_scan(receiver(5)) {
            // The log outran member 5: its writer drains from here on.
            assert!(cohort.replaying(5), "{shape:?}: member 5 left its replay");
            // A member draining its own change log one change a turn can
            // fall a two-page log behind as well.
            assert!(
                work("cohort_scan_evictions") > counted[0],
                "{shape:?}: member 5 left without the log outrunning it"
            );
            cohort.parked = None;
        }
        if hot.len() < HOT {
            let first = &cohort.members.iter().find(|m| m.n == 1).unwrap().table;
            hot.extend(first.keys().copied().take(HOT - hot.len()));
            continue;
        }
        step += 1;
        cohort.event(step);
        if applied.len() >= 160 {
            continue;
        }
        for _ in 0..4 {
            let change = draw_change(&mut next, &hot);
            change.apply(&mut cohort.manager);
            applied.push(change);
        }
    }
    assert!(step >= 3, "{shape:?}: the cohort ended before its events");
    assert!(!(1..=5).any(|n| cohort.replaying(n)), "{shape:?}");
    assert!(
        cohort.parked.is_none(),
        "{shape:?}: member 5 never left the scan"
    );
    assert!(
        work("cohort_shared_rows") > counted[1],
        "{shape:?}: no page went out as shared rows"
    );
    assert!(
        cohort.manager.cohort_scan_riders().is_empty(),
        "{shape:?}: a scan outlived its riders"
    );
    assert!(cohort.manager.dirty_peers.is_empty(), "{shape:?}");
    assert_eq!(
        cohort.manager.adj_rib_out_commit_stats.resync_builds, cohort.builds,
        "{shape:?}: a whole-table resync ran"
    );
    assert_eq!(
        cohort.universes(),
        0,
        "{shape:?}: the universe outlived its cohort"
    );
    (cohort.tables(), applied)
}

/// Each member's one-turn join of the same input, then the same changes.
fn reference_cohort(shape: Shape, changes: &[Change]) -> Vec<(u8, Table, usize)> {
    let mut cohort = Cohort::start(false, shape);
    cohort.join_with(5, 1, 1 << 16);
    cohort.join(4, 1);
    settle(&mut cohort.manager);
    for change in changes {
        change.apply(&mut cohort.manager);
        cohort.read();
    }
    cohort.tables()
}

// Exact tables for every member against its own one-turn join. Member 1 is
// suppressed on keys the others receive, and loses its own paths to split
// horizon, so the members admit different sets of the same universe keys:
// a mask shared between them would show as another member's table.
#[test]
fn a_join_cohort_sharing_one_universe_matches_each_members_one_turn_join() {
    const PLAIN: Shape = Shape { rs: false, ..RS };
    for shape in SHAPES.into_iter().chain([PLAIN]) {
        for seed in [1, 7, 42] {
            let (paced, changes) = paced_cohort(shape, seed);
            assert!(changes.len() >= 32, "too few mid-replay changes");
            let reference = reference_cohort(shape, &changes);
            assert_eq!(paced.len(), 5);
            for ((n, table, markers), (_, expected, _)) in paced.iter().zip(&reference) {
                assert_eq!(*markers, 1, "{shape:?} seed={seed}: member {n}");
                assert!(
                    table == expected,
                    "{shape:?} seed={seed}: member {n} differs from its one-turn join: \
                     {} rows against {}",
                    table.len(),
                    expected.len()
                );
            }
            if shape.rs {
                assert_ne!(
                    paced[0].1, paced[1].1,
                    "{shape:?}: the views never differed"
                );
            }
        }
    }
}
