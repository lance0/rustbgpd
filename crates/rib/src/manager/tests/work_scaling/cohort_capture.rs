//! One cohort capture records the admitted keys of every clean, full member
//! of a group whose projection is the group's own minus the rows it sources
//! (and, with RFC 7947 control, the indexed rows suppressed toward it).
//!
//! A best-path change with every member's channel full captures each
//! member's OLD before staging moves the group table. Captured member by
//! member, that is two walks of the table per member, a members x rows turn.
//! The cohort walks the table twice in all. Every proof it serves is checked
//! against the member's own projection by the capture's test oracle; these
//! contracts also pin the work, the wire stream and the exact healed tables.

use std::collections::BTreeMap;

use crate::attr_set::AttrSet;

use super::super::exportability::ReusableExactExportEncoder;
use super::*;

/// Member channel capacity: small, so the fixture fills it directly.
const CAP: usize = 4;
/// External rows, plus the rows each member sources itself.
const ROWS: usize = 64;
const OWN: usize = 2;

/// What a receiver admitted, by prefix, with withdrawals of prefixes it
/// never admitted counted apart.
#[derive(Default)]
struct Receiver {
    rx: Option<mpsc::Receiver<OutboundRouteUpdate>>,
    admitted: BTreeMap<Prefix, PeerId>,
    unknown_withdrawals: Vec<Prefix>,
    withdrawn: Vec<Prefix>,
}

impl Receiver {
    fn read(&mut self) {
        let Some(rx) = &mut self.rx else {
            return;
        };
        while let Ok(update) = rx.try_recv() {
            for (prefix, _) in update.unicast_withdrawals() {
                self.withdrawn.push(*prefix);
                if self.admitted.remove(prefix).is_none() {
                    self.unknown_withdrawals.push(*prefix);
                }
            }
            for route in update.announce.iter() {
                self.admitted.insert(route.prefix, route.peer);
            }
        }
    }
}

struct Fleet {
    manager: RibManager,
    _tx: mpsc::Sender<RibUpdate>,
    writers: Vec<PeerId>,
    receivers: Vec<Receiver>,
}

/// How one member differs from the plain route-server client.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Odd {
    /// Its encoder refuses every route (a different wire capability set),
    /// so it holds exact-export rejections.
    Narrow,
    /// It negotiated ORF receive, so it is not grouped at all.
    Orf,
}

fn register(
    manager: &mut RibManager,
    index: usize,
    rs_control: bool,
    odd: Option<Odd>,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let peer = member(index);
    let owner = u64::try_from(index).unwrap() + 1;
    let encoder = if odd == Some(Odd::Narrow) {
        ReusableExactExportEncoder::with_limits(owner, WIRE_PROFILE + 1, 64, 32)
    } else {
        ReusableExactExportEncoder::new(owner, WIRE_PROFILE)
    };
    manager.handle_update(RibUpdate::SetPeerExportEncoder {
        peer,
        session_id: 1,
        encoder,
    });
    if rs_control {
        manager.handle_update(RibUpdate::SetPeerRsControl {
            peer,
            session_id: 1,
            rs_control_asn: Some(RS_AS),
        });
    }
    let (outbound_tx, outbound_rx) = mpsc::channel(CAP);
    let mut up = test_peer_up(peer, 1, outbound_tx);
    if let RibUpdate::PeerUp {
        peer_asn,
        negotiated_orf_recv,
        ..
    } = &mut up
    {
        *peer_asn = asn(index);
        if odd == Some(Odd::Orf) {
            *negotiated_orf_recv = vec![(Afi::Ipv4, Safi::Unicast)];
        }
    }
    manager.handle_update(up);
    outbound_rx
}

fn asn(index: usize) -> u32 {
    65_100 + u32::try_from(index).unwrap()
}

/// The external route tagged `0:asn(1)`: RFC 7947 suppresses it toward
/// member 1 when member 1 enforces control communities.
fn tagged() -> Prefix {
    Prefix::V4(prefix(2, 0))
}

/// `k` members of one group, each the source of [`OWN`] rows, beside
/// [`ROWS`] external rows and one tagged row. Member `odd.0` differs as
/// `odd.1` says.
fn fleet(k: usize, rs_control: bool, odd: Option<(usize, Odd)>) -> Fleet {
    let (tx, mut manager) = manager();
    manager.flush_poll_budget = Duration::from_secs(3600);
    manager.handle_update(routes_from(external(), 0, 1, ROWS));
    let IpAddr::V4(next_hop) = external().addr() else {
        unreachable!("test peers are IPv4")
    };
    let mut route = make_route(prefix(2, 0), next_hop);
    AttrSet::edit(&mut route.attributes, |attrs| {
        attrs.push(PathAttribute::Communities(vec![asn(1)]));
    });
    manager.handle_update(test_routes_received(external(), vec![route]));
    drain_route_chunks(&mut manager);
    let writers: Vec<PeerId> = (0..k).map(member).collect();
    let mut receivers: Vec<Receiver> = (0..k)
        .map(|index| {
            let odd = odd.filter(|(at, _)| *at == index).map(|(_, odd)| odd);
            Receiver {
                rx: Some(register(&mut manager, index, rs_control, odd)),
                ..Receiver::default()
            }
        })
        .collect();
    for (index, writer) in writers.iter().enumerate() {
        manager.handle_update(routes_from(*writer, 1, 100 + index, OWN));
        drain_route_chunks(&mut manager);
        receivers.iter_mut().for_each(Receiver::read);
    }
    let mut fleet = Fleet {
        manager,
        _tx: tx,
        writers,
        receivers,
    };
    for index in 0..k {
        fleet.fill(index);
    }
    fleet
}

impl Fleet {
    fn gid(&self) -> usize {
        self.manager
            .grouped_member_of(self.writers[0])
            .expect("writer 0 grouped")
    }

    fn rows(&self) -> usize {
        self.manager.group_ribs[&self.gid()].table.len()
    }

    fn projections(&self) -> usize {
        self.manager
            .adj_rib_out_commit_stats
            .group_capture_projections
    }

    fn captures(&self) -> usize {
        self.manager.adj_rib_out_commit_stats.group_table_captures
    }

    /// Fill writer `index`'s channel with empty envelopes: clean and full.
    fn fill(&mut self, index: usize) {
        let peer = self.writers[index];
        let sender = self.manager.outbound_peers[&peer].clone();
        while sender.try_send(OutboundRouteUpdate::default()).is_ok() {}
        assert!(self.manager.outbound_channel_full(peer));
        assert!(!self.manager.dirty_peers.contains(&peer), "{peer} clean");
        assert!(
            !self.manager.pending_group_admitted.contains_key(&peer),
            "{peer} holds no proof"
        );
    }

    fn announce(&mut self, from: PeerId, session: u64, source: usize, count: usize) {
        self.manager
            .handle_update(routes_from(from, session, source, count));
        drain_route_chunks(&mut self.manager);
    }

    fn withdraw(&mut self, from: PeerId, session: u64, prefix: Prefix) {
        let mut update = test_routes_received(from, Vec::new());
        if let RibUpdate::RoutesReceived {
            session_id,
            withdrawn,
            ..
        } = &mut update
        {
            *session_id = session;
            withdrawn.push((prefix, 0));
        }
        self.manager.handle_update(update);
        drain_route_chunks(&mut self.manager);
    }

    /// Drain and resync until every member is clean and holds no proof.
    fn heal(&mut self) {
        let mut ticks = 0;
        while !self.manager.dirty_peers.is_empty() {
            self.receivers.iter_mut().for_each(Receiver::read);
            self.manager.resync_dirty_peers_bounded();
            ticks += 1;
            assert!(ticks < 200, "members never healed");
        }
        self.receivers.iter_mut().for_each(Receiver::read);
        for peer in &self.writers {
            assert!(
                !self.manager.pending_group_admitted.contains_key(peer),
                "{peer} proof retired"
            );
            assert!(self.manager.group_recovery_fallback(*peer).is_none());
        }
    }

    /// Every member holds the Loc-RIB minus its own rows and the rows
    /// suppressed toward it, and never saw a withdrawal of a key it had not
    /// admitted.
    fn assert_exact(&self, suppressed: impl Fn(usize) -> Vec<Prefix>) {
        for (index, (writer, receiver)) in self.writers.iter().zip(&self.receivers).enumerate() {
            let hidden = suppressed(index);
            let expected: BTreeMap<Prefix, PeerId> = self
                .manager
                .loc_rib
                .iter()
                .filter(|route| route.peer != *writer && !hidden.contains(&route.prefix))
                .map(|route| (route.prefix, route.peer))
                .collect();
            assert_eq!(receiver.admitted, expected, "member {index} final table");
            assert_eq!(
                receiver.unknown_withdrawals,
                Vec::<Prefix>::new(),
                "member {index} withdrawn keys it never admitted"
            );
        }
    }

    fn assert_all_missed_with_proof(&self, peers: &[PeerId]) {
        let fallbacks = counter_metric_value(
            &self.manager.metrics,
            "bgp_update_group_recovery_fallback_total",
            &[("cause", "missing_proof")],
        );
        assert_eq!(fallbacks, 0.0, "no member fell back for a missing proof");
        for peer in peers {
            assert!(self.manager.dirty_peers.contains(peer), "{peer} missed");
            assert!(
                self.manager.pending_group_admitted.contains_key(peer),
                "{peer} proof held"
            );
        }
    }
}

fn no_suppression(_: usize) -> Vec<Prefix> {
    Vec::new()
}

/// The work contract: K clean, full members of one group capture in one
/// pass for 2 x rows projections at K = 8 and K = 32, not 2 x K x rows.
/// Each proof is checked against the member's own capture, and every member
/// heals to its exact table.
#[test]
fn cohort_capture_projects_the_group_table_once() {
    for k in [SMALL, LARGE] {
        let mut fleet = fleet(k, false, None);
        let rows = fleet.rows();
        assert_eq!(rows, ROWS + 1 + k * OWN, "every row staged");
        let (projections, captures) = (fleet.projections(), fleet.captures());
        fleet.announce(external(), 0, 9, 1);
        let writers = fleet.writers.clone();
        fleet.assert_all_missed_with_proof(&writers);
        assert_eq!(
            fleet.captures() - captures,
            k,
            "k={k}: one proof per member"
        );
        assert_eq!(
            fleet.projections() - projections,
            2 * rows,
            "k={k}: the cohort walks the group table twice in all"
        );
        fleet.heal();
        fleet.assert_exact(no_suppression);
    }
}

/// Withdrawals owed after desired state advances use the shared proofs:
/// member 0 withdraws a row it sourced (never admitted by itself), then an
/// external row every member admitted is withdrawn. Every other member
/// withdraws both; member 0 withdraws only the external row.
#[test]
fn cohort_proofs_withdraw_only_admitted_keys() {
    let mut fleet = fleet(SMALL, false, None);
    let own = Prefix::V4(prefix(100, 0));
    let shared = Prefix::V4(prefix(1, 3));
    assert!(fleet.receivers[1].admitted.contains_key(&own));
    assert!(!fleet.receivers[0].admitted.contains_key(&own));
    let writer = fleet.writers[0];
    fleet.withdraw(writer, 1, own);
    // Member 0 is owed nothing for its own row: its speculative proof is
    // released and it stays clean.
    fleet.assert_all_missed_with_proof(&fleet.writers[1..]);
    assert!(!fleet.manager.dirty_peers.contains(&writer));
    assert!(!fleet.manager.pending_group_admitted.contains_key(&writer));
    fleet.withdraw(external(), 0, shared);
    let writers = fleet.writers.clone();
    fleet.assert_all_missed_with_proof(&writers);
    for receiver in &mut fleet.receivers {
        receiver.withdrawn.clear();
    }
    fleet.heal();
    fleet.assert_exact(no_suppression);
    for (index, receiver) in fleet.receivers.iter().enumerate() {
        let mut withdrawn = receiver.withdrawn.clone();
        withdrawn.sort_unstable();
        withdrawn.dedup();
        let mut expected = if index == 0 {
            vec![shared]
        } else {
            vec![own, shared]
        };
        expected.sort_unstable();
        assert_eq!(withdrawn, expected, "member {index} recovery withdrawals");
    }
}

/// RFC 7947 control members share the cohort too: the row tagged toward
/// member 1 is dropped from member 1's proof only, through the group's
/// control index.
#[test]
fn rs_control_members_share_the_cohort_capture() {
    for k in [SMALL, LARGE] {
        let mut fleet = fleet(k, true, None);
        assert!(!fleet.receivers[1].admitted.contains_key(&tagged()));
        assert!(fleet.receivers[2].admitted.contains_key(&tagged()));
        let rows = fleet.rows();
        let projections = fleet.projections();
        fleet.announce(external(), 0, 9, 1);
        let writers = fleet.writers.clone();
        fleet.assert_all_missed_with_proof(&writers);
        assert_eq!(fleet.projections() - projections, 2 * rows, "k={k}");
        let proof = fleet
            .manager
            .pending_group_admitted
            .get(&writers[1])
            .unwrap();
        assert!(!proof.contains(&ExactExportKey::Unicast(tagged(), 0)));
        fleet.heal();
        fleet.assert_exact(|index| {
            if index == 1 {
                vec![tagged()]
            } else {
                Vec::new()
            }
        });
    }
}

/// A member with exact-export rejections (a narrower wire capability set)
/// takes its own capture beside the cohort; an ORF member is not grouped
/// and takes no group capture at all.
#[test]
fn mixed_members_take_their_own_capture() {
    let mut fleet = fleet(SMALL, false, Some((3, Odd::Narrow)));
    let narrow = fleet.writers[3];
    assert!(
        fleet
            .manager
            .peer_unexportable
            .get(&narrow)
            .is_some_and(|keys| !keys.is_empty()),
        "the narrow member holds rejections"
    );
    let orf = member(SMALL);
    let _orf_rx = register(&mut fleet.manager, SMALL, false, Some(Odd::Orf));
    assert!(
        fleet.manager.grouped_member_of(orf).is_none(),
        "ORF member ungrouped"
    );
    let sender = fleet.manager.outbound_peers[&orf].clone();
    while sender.try_send(OutboundRouteUpdate::default()).is_ok() {}
    let rows = fleet.rows();
    let (projections, captures) = (fleet.projections(), fleet.captures());
    fleet.announce(external(), 0, 9, 1);
    let writers = fleet.writers.clone();
    fleet.assert_all_missed_with_proof(&writers);
    assert_eq!(
        fleet.captures() - captures,
        SMALL,
        "one proof per grouped member"
    );
    assert_eq!(
        fleet.projections() - projections,
        4 * rows,
        "the cohort's two walks plus the narrow member's own two"
    );
    assert!(
        fleet
            .manager
            .pending_group_admitted
            .get(&narrow)
            .is_some_and(
                crate::manager::update_groups::admitted_recovery::AdmittedKeyView::is_empty
            ),
        "the narrow member admitted nothing"
    );
    assert!(!fleet.manager.pending_group_admitted.contains_key(&orf));
    fleet.heal();
    let everything: Vec<Prefix> = fleet
        .manager
        .loc_rib
        .iter()
        .map(|route| route.prefix)
        .collect();
    fleet.assert_exact(|index| {
        if index == 3 {
            everything.clone()
        } else {
            Vec::new()
        }
    });
}

/// A later cohort of the same group captures the table as it stands then,
/// not an earlier cohort's view: half the members capture before a
/// withdrawal, the other half, sent that withdrawal, before the next change.
/// Both cohorts share one pool, so only the later table's mask is right.
#[test]
fn a_later_cohort_captures_its_own_table_version() {
    let mut fleet = fleet(SMALL, false, None);
    let (first, second) = fleet.writers.split_at(SMALL / 2);
    let (first, second) = (first.to_vec(), second.to_vec());
    // Drain the second half: only the first is full for the withdrawal.
    for receiver in &mut fleet.receivers[SMALL / 2..] {
        receiver.read();
    }
    let gone = Prefix::V4(prefix(1, 5));
    fleet.withdraw(external(), 0, gone);
    fleet.assert_all_missed_with_proof(&first);
    for peer in &first {
        let proof = fleet.manager.pending_group_admitted.get(peer).unwrap();
        assert!(
            proof.contains(&ExactExportKey::Unicast(gone, 0)),
            "{peer} held it"
        );
    }
    for index in SMALL / 2..SMALL {
        let peer = fleet.writers[index];
        assert!(
            !fleet.manager.dirty_peers.contains(&peer),
            "{peer} was sent the withdrawal"
        );
        fleet.receivers[index].read();
        assert!(!fleet.receivers[index].admitted.contains_key(&gone));
        fleet.fill(index);
    }
    let projections = fleet.projections();
    let rows = fleet.rows();
    fleet.announce(external(), 0, 9, 1);
    fleet.assert_all_missed_with_proof(&second);
    assert_eq!(fleet.projections() - projections, 2 * rows);
    for peer in &second {
        let proof = fleet.manager.pending_group_admitted.get(peer).unwrap();
        assert!(
            !proof.contains(&ExactExportKey::Unicast(gone, 0)),
            "{peer} captured after the withdrawal it admitted"
        );
    }
    fleet.heal();
    fleet.assert_exact(no_suppression);
}
