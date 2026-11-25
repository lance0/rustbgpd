//! A per-client-best or route-server-control member replays through the
//! paced lane. A per-client-best slot also follows the runner-up, and an
//! RS-control slot follows the member's RFC 7947 view. Both change without a
//! Loc-RIB write, so every mid-replay change must reach the member as a
//! repair of its current slot.
use rustbgpd_policy::{Policy, PolicyAction, PolicyChain};

use super::*;
use crate::manager::tests::lifecycle::test_session_routes_received;
use crate::manager::tests::update_groups::deny_statement;

const THIRD: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 3);
const RS_ASN: u32 = 65_000;
const ROWS: u16 = 4 * 1024;
// The last source is member 1 itself.
const SOURCES: [Ipv4Addr; 4] = [SOURCE, OTHER, THIRD, Ipv4Addr::new(198, 51, 100, 1)];
const PREFS: [u32; 3] = [300, 200, 100];
const HOT: usize = 24;

/// What the member holds: each prefix's route as delivered.
type Table = BTreeMap<Prefix, String>;

/// The founder's and member's registration profile.
#[derive(Clone, Copy, Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag is an independent registration input of the test matrix"
)]
struct Shape {
    pcb: bool,
    rs: bool,
    policy: bool,
    // Member 9 publishes the group before member 1 joins.
    founder: bool,
}

const PCB: Shape = Shape {
    pcb: true,
    rs: false,
    policy: false,
    founder: true,
};
const PCB_RS: Shape = Shape { rs: true, ..PCB };
// A single-best route-server client: one shared winner, its own view.
const RS: Shape = Shape {
    pcb: false,
    ..PCB_RS
};
// The export policy strips the suppression community, so a change of that
// tag alone moves the member's RFC 7947 view without changing the shared row.
const RS_POLICY: Shape = Shape { policy: true, ..RS };
// Member 1 founds the group: it builds the table in its registration turn,
// then pages its own initial table.
const RS_FOUNDER: Shape = Shape {
    founder: false,
    ..RS_POLICY
};
const SHAPES: [Shape; 5] = [PCB, PCB_RS, RS, RS_POLICY, RS_FOUNDER];

fn strip_chain() -> PolicyChain {
    // `65001:7` names no route server, so RFC 7947 keeps it.
    let mut statement = deny_statement(Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0));
    statement.prefix = None;
    statement.action = PolicyAction::Permit;
    statement.modifications.communities_add.push(0xfde9_0007);
    statement.modifications.communities_remove.push(asn(1));
    PolicyChain::new(vec![Policy {
        entries: vec![statement],
        default_action: PolicyAction::Deny,
    }])
}

fn asn(n: u8) -> u32 {
    64_600 + u32::from(n)
}

/// `0:ASN` suppresses a path toward member 1 when it enforces RFC 7947.
/// OTHER's paths name the founder instead: member 1 receives them, scrubbed
/// of that control community when it enforces RFC 7947.
fn input(prefix: Prefix, source: Ipv4Addr, pref: u32, suppress: bool) -> Route {
    let mut row = route(prefix, source, pref);
    let tags: Vec<u32> = [(suppress, asn(1)), (source == OTHER, asn(9))]
        .into_iter()
        .filter_map(|(tagged, tag)| tagged.then_some(tag))
        .collect();
    if !tags.is_empty() {
        AttrSet::edit(&mut row.attributes, |attrs| {
            attrs.push(PathAttribute::Communities(tags));
        });
    }
    row
}

fn join_pcb(
    manager: &mut RibManager,
    n: u8,
    session_id: u64,
    shape: Shape,
    capacity: usize,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let peer = receiver(n);
    manager.handle_update(RibUpdate::SetPeerRsControl {
        peer,
        session_id,
        rs_control_asn: shape.rs.then_some(RS_ASN),
    });
    let (out, rx) = mpsc::channel(capacity);
    let mut up = test_peer_up(peer, session_id, out);
    let RibUpdate::PeerUp {
        peer_asn,
        per_client_best,
        sendable_families,
        export_policy,
        ..
    } = &mut up
    else {
        unreachable!()
    };
    *peer_asn = asn(n);
    *per_client_best = shape.pcb;
    *sendable_families = vec![FAMILY];
    *export_policy = shape.policy.then(strip_chain);
    manager.handle_update(up);
    rx
}

#[derive(Clone, Copy, Debug)]
struct Change {
    source: usize,
    prefix: Prefix,
    // `None` withdraws the source's path.
    pref: Option<u32>,
    suppress: bool,
}

impl Change {
    fn apply(self, manager: &mut RibManager) {
        let source = SOURCES[self.source];
        // Member 1 sends on its own session.
        let session = u64::from(self.source == 3);
        let mut update = test_session_routes_received(peer_v4(source), session, vec![]);
        let RibUpdate::RoutesReceived {
            announced,
            withdrawn,
            ..
        } = &mut update
        else {
            unreachable!()
        };
        match self.pref {
            Some(pref) => announced.push(input(self.prefix, source, pref, self.suppress)),
            None => withdrawn.push((self.prefix, 0)),
        }
        manager.handle_update(update);
        drain_route_chunks(manager);
    }
}

struct Run {
    manager: RibManager,
    _primary: mpsc::Sender<RibUpdate>,
    founder: mpsc::Receiver<OutboundRouteUpdate>,
    rx: mpsc::Receiver<OutboundRouteUpdate>,
    table: Table,
    markers: usize,
    builds: usize,
}

impl Run {
    /// Members 9 (the founder) and 1 share a published group. Member 1's
    /// replay is paced when `paced`, else one turn.
    fn start(paced: bool, shape: Shape) -> Self {
        let (mut manager, primary, _) = fixture(0);
        register_test_peer(&mut manager, peer_v4(THIRD), 0);
        for (i, source) in SOURCES[..3].iter().copied().enumerate() {
            // Every third preferred path is suppressed toward member 1.
            let rows = (0..ROWS)
                .map(|n| input(prefixes(n)[0], source, PREFS[i], i == 0 && n % 3 == 0))
                .collect();
            manager.handle_update(test_routes_received(peer_v4(source), rows));
            drain_route_chunks(&mut manager);
        }
        let mut founder = if shape.founder {
            join_pcb(&mut manager, 9, 1, shape, 1 << 16)
        } else {
            mpsc::channel(1).1
        };
        settle(&mut manager);
        while founder.try_recv().is_ok() {}
        let gid = manager.grouped_member_of(receiver(9));
        manager.initial_member_replays.min_routes = Some(if paced { 1 } else { usize::MAX });
        let builds = manager.adj_rib_out_commit_stats.resync_builds;
        let rx = join_pcb(&mut manager, 1, 1, shape, 64);
        assert_eq!(manager.is_initial_member_replay(receiver(1)), paced);
        assert_eq!(gid.is_some(), shape.founder);
        Self {
            manager,
            _primary: primary,
            founder,
            rx,
            table: Table::new(),
            markers: 0,
            builds,
        }
    }

    fn read(&mut self) {
        read_into(&mut self.rx, &mut self.table, &mut self.markers);
        while self.founder.try_recv().is_ok() {}
    }

    fn turn(&mut self) {
        self.read();
        self.manager.wake_initial_member_replay();
        self.manager.advance_pending_initial_registration();
        self.read();
    }

    fn replaying(&self) -> bool {
        self.manager.is_initial_member_replay(receiver(1))
    }

    /// Drive the replay, landing `per_turn` changes between its turns once
    /// pages have been admitted. Changes pick hot keys the member already
    /// holds, so they land behind the cursor. Returns the applied changes.
    fn churn(&mut self, seed: u64, per_turn: usize, limit: usize) -> Vec<Change> {
        let mut rng = seed;
        let mut next = move |bound: usize| {
            rng = rng
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            usize::try_from(rng >> 33).unwrap() % bound
        };
        let mut applied = Vec::new();
        let mut hot = Vec::new();
        for _ in 0..10_000 {
            if !self.replaying() && self.manager.pending_initial_registrations.is_empty() {
                break;
            }
            self.turn();
            if hot.len() < HOT {
                hot.extend(self.table.keys().copied().take(HOT - hot.len()));
                continue;
            }
            if applied.len() >= limit {
                continue;
            }
            for _ in 0..per_turn {
                // A third re-announce the preferred path with only its
                // suppression tag drawn again.
                let tag_only = next(3) == 0;
                let source = if tag_only { 0 } else { next(SOURCES.len()) };
                let change = Change {
                    source,
                    prefix: hot[next(HOT)],
                    // The member's own path wins when present.
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
                };
                change.apply(&mut self.manager);
                applied.push(change);
            }
        }
        assert!(!self.replaying(), "replay did not finish");
        self.read();
        applied
    }

    /// The paced run keeps its writer and table: no fallback resync and one marker.
    fn assert_paced(&self) {
        // The replay pages read group rows, so each must be a Loc-RIB key.
        let gid = self.manager.grouped_member_of(receiver(1)).unwrap();
        for row in self.manager.group_ribs[&gid].table.iter() {
            assert!(self.manager.loc_rib.get(&row.prefix).is_some(), "{row:?}");
        }
        assert_eq!(self.markers, 1);
        assert!(!self.manager.dirty_peers.contains(&receiver(1)));
        assert_eq!(
            self.manager.adj_rib_out_commit_stats.resync_builds,
            self.builds
        );
    }
}

fn read_into(rx: &mut mpsc::Receiver<OutboundRouteUpdate>, table: &mut Table, markers: &mut usize) {
    while let Ok(update) = rx.try_recv().map(delivered) {
        for (prefix, _) in update.unicast_withdrawals() {
            table.remove(prefix);
        }
        for row in update
            .announce
            .iter()
            .filter(|row| update.announce_source_exclusion != Some(row.peer))
        {
            table.insert(
                row.prefix,
                format!("{:?}", (row.peer, row.next_hop, &*row.attributes)),
            );
        }
        *markers += update.end_of_rib.len();
    }
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

/// The one-turn join of the same input, then the same changes in order.
fn reference(shape: Shape, changes: &[Change]) -> Table {
    let mut run = Run::start(false, shape);
    settle(&mut run.manager);
    run.read();
    assert_eq!(run.markers, 1);
    for change in changes {
        change.apply(&mut run.manager);
        run.read();
    }
    run.table
}

// Exact table against the synchronous join: the member takes the winner
// (runner-up substitution, or no slot for a single-best member), the
// runner-up changes under the member's own winner (no Loc-RIB write), tags
// move the RS view to fallback rows or suppress the slot, and RFC 7947
// scrubs the control communities. Behind a stripping policy, a tag-only
// change moves the RS view with no change to the shared row.
#[test]
fn per_client_best_paced_replay_matches_the_one_turn_join_under_churn() {
    for shape in SHAPES {
        for seed in [1, 7, 42] {
            let mut paced = Run::start(true, shape);
            let changes = paced.churn(seed, 4, 160);
            assert!(changes.len() >= 32, "too few mid-replay changes");
            paced.assert_paced();
            assert_eq!(
                paced.table,
                reference(shape, &changes),
                "{shape:?} seed={seed}: paced replay differs from the one-turn join"
            );
        }
    }
}

// Churn on admitted keys between every replay turn, never pausing, must not
// hold End-of-RIB back: each page drains at most one page of repairs, and the
// page that drains the last one completes in its own turn.
#[test]
fn per_client_best_replay_completes_under_unbroken_churn() {
    for shape in SHAPES {
        let mut paced = Run::start(true, shape);
        let mut turns = 0;
        let changes = {
            let mut applied = Vec::new();
            let mut hot = Vec::new();
            let mut n = 0_usize;
            while paced.replaying() {
                turns += 1;
                assert!(turns < 512, "{shape:?}: churn held the replay open");
                paced.turn();
                if hot.len() < HOT {
                    hot.extend(paced.table.keys().copied().take(HOT - hot.len()));
                    continue;
                }
                // 16 changes to distinct admitted keys after every turn.
                for _ in 0..16 {
                    n += 1;
                    let change = Change {
                        source: n % 3,
                        prefix: hot[n % HOT],
                        pref: Some(PREFS[n % 3] + u32::try_from(n % 7).unwrap()),
                        suppress: false,
                    };
                    change.apply(&mut paced.manager);
                    applied.push(change);
                }
            }
            paced.read();
            applied
        };
        paced.assert_paced();
        assert_eq!(paced.table, reference(shape, &changes), "{shape:?}");
    }
}

// A source departure pages its candidate removals through ordinary group
// stages. The runner-up's source leaving writes no Loc-RIB row where the
// preferred path stays, but changes every lane and fallback list.
#[test]
fn per_client_best_replay_keeps_its_pages_through_a_runner_up_departure() {
    for shape in SHAPES {
        let mut paced = Run::start(true, shape);
        while paced.table.len() < 1024 {
            paced.turn();
        }
        assert!(paced.replaying());
        paced.manager.handle_update(RibUpdate::PeerDown {
            peer: peer_v4(OTHER),
            session_id: 0,
        });
        drain_source_departure(&mut paced.manager);
        drain_route_chunks(&mut paced.manager);
        paced.churn(0, 0, 0);
        paced.assert_paced();

        let mut synchronous = Run::start(false, shape);
        settle(&mut synchronous.manager);
        synchronous.read();
        synchronous.manager.handle_update(RibUpdate::PeerDown {
            peer: peer_v4(OTHER),
            session_id: 0,
        });
        drain_source_departure(&mut synchronous.manager);
        drain_route_chunks(&mut synchronous.manager);
        synchronous.read();
        // The departure's later pages wait for the writer to release earlier ones.
        for _ in 0..64 {
            synchronous.manager.resync_dirty_peers_bounded();
            drain_unicast_release(&mut synchronous.manager);
            synchronous.read();
        }
        assert_eq!(paced.table, synchronous.table, "{shape:?}");
    }
}

// A flap mid-replay retires the old session's job. The next session enrolls
// afresh and receives its whole table and one marker.
#[test]
fn per_client_best_flap_mid_replay_restarts_with_the_new_session() {
    for shape in [PCB_RS, RS] {
        let mut paced = Run::start(true, shape);
        while paced.table.len() < 1024 {
            paced.turn();
        }
        paced.manager.handle_update(RibUpdate::PeerDown {
            peer: receiver(1),
            session_id: 1,
        });
        paced.rx = join_pcb(&mut paced.manager, 1, 2, shape, 64);
        paced.table.clear();
        paced.markers = 0;
        paced.churn(0, 0, 0);
        assert_eq!(paced.markers, 1);
        assert_eq!(paced.table, reference(shape, &[]), "{shape:?}");
    }
}

// Adding an export policy regroups the member. The replay recovers from its
// changed group instead of finishing against the old table.
#[test]
fn per_client_best_regroup_mid_replay_owes_one_marker_for_the_new_group() {
    fn regroup(run: &mut Run) {
        let old = run.manager.grouped_member_of(receiver(1));
        let (reply, mut result) = oneshot::channel();
        run.manager
            .handle_update(RibUpdate::ReplacePeerExportPolicy {
                peer: receiver(1),
                export_policy: Some(community_chain(TAG)),
                reply,
            });
        assert!(matches!(result.try_recv(), Ok(Ok(()))));
        assert_ne!(run.manager.grouped_member_of(receiver(1)), old);
        for _ in 0..64 {
            run.manager.resync_dirty_peers_bounded();
            run.read();
        }
    }

    for shape in [PCB, RS] {
        let mut paced = Run::start(true, shape);
        while paced.table.len() < 1024 {
            paced.turn();
        }
        regroup(&mut paced);
        assert!(!paced.replaying(), "the regroup retired the replay");
        assert_eq!(paced.markers, 1);
        let mut synchronous = Run::start(false, shape);
        settle(&mut synchronous.manager);
        synchronous.read();
        regroup(&mut synchronous);
        // RFC 7947 scrubs the policy's community, which names the RS ASN.
        let tagged = paced
            .table
            .values()
            .filter(|row| row.contains(&TAG.to_string()))
            .count();
        assert_eq!(tagged, if shape.rs { 0 } else { paced.table.len() });
        assert_eq!(paced.table, synchronous.table, "{shape:?}");
    }
}

// The member's slot changes behind the cursor while its writer is held. The
// listing reads the admission proof and must refuse until the repair is sent.
#[test]
fn per_client_best_listing_refuses_while_a_slot_repair_is_unsent() {
    use crate::update::{RoutePageError, RouteQueryScope};

    fn listing(manager: &mut RibManager) -> Result<Vec<Route>, RoutePageError> {
        let (reply, mut response) = oneshot::channel();
        let scope = RouteQueryScope::Advertised { peer: receiver(1) };
        manager.handle_query_routes_page_versioned(scope, None, None, None, 10_000, reply);
        response.try_recv().unwrap().map(|page| page.routes)
    }

    for shape in [PCB_RS, RS] {
        let mut paced = Run::start(true, shape);
        let first = loop {
            paced.manager.advance_pending_initial_registration();
            if let Ok(page) = paced.rx.try_recv() {
                break page;
            }
        };
        let held = first.announce[0].clone();
        listing(&mut paced.manager).expect("a clean partial replay lists its pages");
        // Member 1 takes the winner: its slot becomes the runner-up, or
        // nothing for a single-best member.
        Change {
            source: 3,
            prefix: held.prefix,
            pref: Some(400),
            suppress: false,
        }
        .apply(&mut paced.manager);
        assert!(
            paced
                .manager
                .initial_member_replay_changes_pending(receiver(1))
        );
        assert!(matches!(
            listing(&mut paced.manager),
            Err(RoutePageError::ResyncInProgress)
        ));
        drop(first);
        read_into(&mut paced.rx, &mut paced.table, &mut paced.markers);
        paced.churn(0, 0, 0);
        paced.assert_paced();
        let listed = listing(&mut paced.manager).expect("the repaired view lists");
        if shape.pcb {
            // The member's own winner substitutes the runner-up, the slot it held.
            let row = &paced.table[&held.prefix];
            assert!(row.starts_with(&format!("({:?}", held.peer)), "{row}");
        } else {
            assert!(!paced.table.contains_key(&held.prefix));
            assert!(listed.iter().all(|row| row.prefix != held.prefix));
        }
    }
}

// Distinct changes faster than a page drains overflow the member's repairs.
// The replay rewinds into a paced reconcile of the current table, keeps its
// writer, builds no whole-table resync and still sends one marker.
#[test]
fn per_client_best_churn_above_the_repair_limit_reconciles_in_pages() {
    for shape in [PCB_RS, RS] {
        let mut paced = Run::start(true, shape);
        while paced.table.len() < 1024 {
            paced.turn();
        }
        // OTHER takes the win on every key and announces 1,000 new ones: more
        // distinct changes than the member's repair log holds.
        let changes: Vec<_> = (0..ROWS + 1000)
            .map(|n| Change {
                source: 1,
                prefix: prefixes(n)[0],
                pref: Some(350),
                suppress: false,
            })
            .collect();
        paced.manager.handle_update(test_routes_received(
            peer_v4(OTHER),
            changes
                .iter()
                .map(|change| input(change.prefix, OTHER, 350, false))
                .collect(),
        ));
        drain_route_chunks(&mut paced.manager);
        paced.turn();
        assert!(paced.replaying(), "overflow retired the replay");
        assert!(!paced.manager.dirty_peers.contains(&receiver(1)));
        for _ in 0..1024 {
            if !paced.replaying() {
                break;
            }
            paced.turn();
        }
        assert!(!paced.replaying(), "the reconcile did not finish");
        paced.read();
        crate::manager::tests::assert_paced_fallbacks(&paced.manager.metrics, &[]);
        paced.assert_paced();
        assert_eq!(paced.table, reference(shape, &changes), "{shape:?}");
    }
}

// An outbound prefix limit applied mid-replay checks the routes admitted so
// far. The later pages then meet it at commit, the last gate before the
// wire, as any later growth of the member's table would.
#[test]
fn outbound_prefix_limit_applied_mid_replay_caps_the_later_pages() {
    use crate::manager::tests::outbound_prefix_limits::{apply, limit_config, prepare};

    const LIMIT: u32 = 2_000;
    for shape in [PCB_RS, RS] {
        let mut paced = Run::start(true, shape);
        while paced.table.len() < 1024 {
            paced.turn();
        }
        assert!(paced.replaying());
        let full = reference(shape, &[]).len();
        assert!(full > LIMIT as usize, "{shape:?}: {full}");
        prepare(
            &mut paced.manager,
            1,
            limit_config(&[(receiver(1), Some(LIMIT), None)], &[]),
        )
        .expect("the admitted pages fit the limit");
        apply(&mut paced.manager, 1, true).expect("applied mid-replay");
        paced.churn(0, 0, 0);
        assert_eq!(paced.markers, 1, "{shape:?}");
        assert_eq!(paced.table.len(), LIMIT as usize, "{shape:?}");
    }
}

// A ROUTE-REFRESH at a partial page waits for the initial marker, then
// answers with the member's whole current table.
#[tokio::test(start_paused = true)]
async fn per_client_best_route_refresh_mid_replay_follows_the_initial_marker() {
    for shape in [PCB_RS, RS] {
        refresh_mid_replay(shape).await;
    }
}

async fn refresh_mid_replay(shape: Shape) {
    use rustbgpd_wire::RouteRefreshSubtype::{BoRR, EoRR};

    let expected = reference(shape, &[]);
    let mut paced = Run::start(true, shape);
    let first = loop {
        paced.manager.advance_pending_initial_registration();
        if let Ok(page) = paced.rx.try_recv() {
            break page;
        }
    };
    paced.manager.handle_update(RibUpdate::RouteRefreshRequest {
        peer: receiver(1),
        session_id: 1,
        afi: FAMILY.0,
        safi: FAMILY.1,
        queued: Arc::default(),
    });
    let mut table = Table::new();
    let mut markers = 0;
    let (tx, mut pages) = mpsc::channel(1);
    tx.try_send(first).unwrap();
    read_into(&mut pages, &mut table, &mut markers);
    let Run {
        manager,
        _primary: primary,
        founder,
        mut rx,
        ..
    } = paced;
    let actor = tokio::spawn(manager.run_actor());
    tokio::time::timeout(Duration::from_secs(15), async {
        while markers == 0 {
            let page = rx.recv().await.unwrap();
            assert!(
                page.refresh_markers.is_empty(),
                "refresh overtook initial EoR"
            );
            tx.try_send(page).unwrap();
            read_into(&mut pages, &mut table, &mut markers);
        }
        assert_eq!(table, expected, "initial pages before the marker");
        let mut refreshed = BTreeSet::new();
        let mut began = false;
        loop {
            let page = rx.recv().await.unwrap();
            began |= page.refresh_markers.contains(&(FAMILY.0, FAMILY.1, BoRR));
            assert!(began, "refresh rows before BoRR");
            refreshed.extend(page.announce.iter().map(|row| row.prefix));
            if page.refresh_markers.contains(&(FAMILY.0, FAMILY.1, EoRR)) {
                break;
            }
        }
        assert_eq!(refreshed, expected.keys().copied().collect());
    })
    .await
    .expect("initial replay and requested refresh");
    drop((primary, founder));
    let _ = actor.await.unwrap();
}
