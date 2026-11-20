//! The batched per-client-best release through the real state machine.
//! Most tests compare every client's exact table and denial set with a
//! `best_path_cmp` model; the rest pin the stage and paging bounds.

use super::*;

const V4: (Afi, Safi) = FAMILY;
const THIRD: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);
const NONE_TO_ANY: u32 = RS_AS; // 0:RS, announce to none
const fn only_to(asn: u32) -> u32 {
    (RS_AS << 16) | asn
}

struct Rng(u64);
impl Rng {
    fn next(&mut self, bound: u32) -> u32 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        u32::try_from((self.0 >> 33) % u64::from(bound)).unwrap()
    }
}

fn prefix_of(family: (Afi, Safi), n: u32) -> Prefix {
    if family == V4 {
        make_indexed_route(n, SOURCE).prefix
    } else {
        let [_, a, b, c] = n.to_be_bytes();
        Prefix::V6(Ipv6Prefix::new(
            Ipv6Addr::new(
                0x2001,
                0xdb8,
                u16::from(a),
                u16::from(b),
                u16::from(c),
                0,
                0,
                0,
            ),
            80,
        ))
    }
}

fn path(family: (Afi, Safi), n: u32, source: Ipv4Addr, lp: u32, communities: Vec<u32>) -> Route {
    let mut route = make_route_with_lp(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 32), source, lp);
    route.prefix = prefix_of(family, n);
    if family != V4 {
        route.next_hop = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xffff, 0, 0, 0, 0, 1));
    }
    if !communities.is_empty() {
        AttrSet::edit(&mut route.attributes, |attrs| {
            attrs.push(PathAttribute::Communities(communities));
        });
    }
    route
}

#[derive(Default)]
struct Seen {
    rows: BTreeMap<Prefix, (PeerId, u32)>,
    envelopes: usize,
    largest: usize,
    markers: usize,
    after_marker: usize,
    over_withdraw: usize,
    repeated: usize,
    own: usize,
}

struct Lab {
    family: (Afi, Safi),
    manager: RibManager,
    receivers: Vec<Option<mpsc::Receiver<OutboundRouteUpdate>>>,
    seen: Vec<Seen>,
    rs: Vec<bool>,
    sent: Candidates,
    _tx: mpsc::Sender<RibUpdate>,
}

impl Lab {
    /// A restarted speaker holding `family` for SOURCE's End-of-RIB.
    fn cold(family: (Afi, Safi)) -> Self {
        let (tx, rx) = mpsc::channel(8);
        let source = peer_v4(SOURCE);
        let mut manager = held_families(rx, &[(source, family)]);
        manager.test_force_ungrouped = false;
        manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
            peer: source,
            session_id: 1,
            peer_restart_state: false,
            peer_gr_helper: true,
            peer_gr_families: vec![family],
            peer_enhanced_refresh: true,
            peer_llgr_families: vec![],
            local_llgr_stale_time: 0,
        });
        register_test_peer(&mut manager, source, 1);
        register_test_peer(&mut manager, peer_v4(OTHER_SOURCE), 1);
        register_test_peer(&mut manager, peer_v4(THIRD), 1);
        assert!(manager.selection_deferred(family));
        Self {
            family,
            manager,
            receivers: Vec::new(),
            seen: Vec::new(),
            rs: Vec::new(),
            sent: Candidates::default(),
            _tx: tx,
        }
    }

    fn join(&mut self, rs_control: bool, capacity: usize) -> usize {
        let n = self.receivers.len();
        if rs_control {
            self.manager.handle_update(RibUpdate::SetPeerRsControl {
                peer: client(n),
                session_id: 2,
                rs_control_asn: Some(RS_AS),
            });
        }
        let mut registration = registering_peer_up(client(n), 2);
        let RibUpdate::PeerUp {
            peer_asn,
            outbound_tx,
            export_policy,
            sendable_families,
            per_client_best,
            ..
        } = &mut registration
        else {
            unreachable!()
        };
        let (tx, rx) = mpsc::channel(capacity);
        *peer_asn = client_asn(n);
        *outbound_tx = tx;
        *export_policy = Some(deny_local_pref_from(DENIED_FROM));
        *sendable_families = vec![self.family];
        *per_client_best = true;
        self.manager.handle_update(registration);
        self.receivers.push(Some(rx));
        self.seen.push(Seen::default());
        self.rs.push(rs_control);
        n
    }

    fn clients(&mut self, count: usize, capacity: usize) {
        for n in 0..count {
            // Two of three enforce control communities, across every page.
            self.join(n % 3 != 1, capacity);
        }
        let gid = self.manager.grouped_member_of(client(0)).expect("grouped");
        for n in 0..count {
            assert_eq!(self.manager.grouped_member_of(client(n)), Some(gid));
        }
        assert!(self.manager.group_ribs[&gid].per_client_best);
    }

    fn send(&mut self, session: u64, routes: Vec<Route>) {
        if !routes.is_empty() {
            self.sent.send(&mut self.manager, session, routes);
        }
    }

    fn receive(&mut self) {
        for (n, receiver) in self.receivers.iter_mut().enumerate() {
            let Some(receiver) = receiver else { continue };
            let seen = &mut self.seen[n];
            while let Ok(update) = receiver.try_recv() {
                let rows =
                    !update.announce.is_empty() || update.unicast_withdrawals().next().is_some();
                seen.after_marker += usize::from(rows && seen.markers > 0);
                seen.envelopes += usize::from(rows);
                seen.largest = seen.largest.max(update.announce.len());
                for &(prefix, _) in update.unicast_withdrawals() {
                    seen.over_withdraw += usize::from(seen.rows.remove(&prefix).is_none());
                }
                for route in update.announce.iter() {
                    assert_eq!(route.path_id, 0);
                    if update.announce_source_exclusion == Some(route.peer) {
                        continue;
                    }
                    seen.own += usize::from(route.peer == client(n));
                    let row = (route.peer, route.local_pref());
                    seen.repeated += usize::from(seen.rows.insert(route.prefix, row) == Some(row));
                }
                seen.markers += usize::from(update.end_of_rib.contains(&self.family));
            }
        }
    }

    /// The model: first candidate in best-path order that policy permits, the
    /// client did not source and no control community hides from it.
    fn model(&self, n: usize) -> BTreeMap<Prefix, (PeerId, u32)> {
        let asn = client_asn(n);
        let mut table = BTreeMap::new();
        for (prefix, paths) in &self.sent.0 {
            let mut ranked: Vec<_> = paths.iter().collect();
            ranked.sort_by(|a, b| crate::best_path::best_path_cmp(a, b));
            let hidden = |route: &Route| {
                let has = |c: u32| route.communities().contains(&c);
                self.rs[n] && (has(asn) || (has(NONE_TO_ANY) && !has(only_to(asn))))
            };
            if let Some(best) = ranked.into_iter().find(|route| {
                route.local_pref() < DENIED_FROM && route.peer != client(n) && !hidden(route)
            }) {
                table.insert(*prefix, (best.peer, best.local_pref()));
            }
        }
        table
    }

    /// Denied candidates the first-permitted walk visits: everything ranked
    /// ahead of the second distinct source with no control community.
    fn model_denials(&self, n: usize) -> BTreeSet<(Prefix, PeerId, u32)> {
        let mut denied = BTreeSet::new();
        for (prefix, paths) in &self.sent.0 {
            let mut ranked: Vec<_> = paths.iter().collect();
            ranked.sort_by(|a, b| crate::best_path::best_path_cmp(a, b));
            let mut clean: Vec<PeerId> = Vec::new();
            let mut winner = false;
            for route in ranked {
                if clean.contains(&route.peer) {
                    continue;
                }
                if route.local_pref() >= DENIED_FROM {
                    if route.peer != client(n) {
                        denied.insert((*prefix, route.peer, route.path_id));
                    }
                    continue;
                }
                if !route.communities().iter().any(|c| c >> 16 == 0) {
                    clean.push(route.peer);
                }
                if winner && clean.len() == 2 {
                    break;
                }
                winner = true;
            }
        }
        denied
    }

    fn end_hold(&mut self) {
        self.manager.handle_update(RibUpdate::EndOfRib {
            peer: peer_v4(SOURCE),
            session_id: 1,
            afi: self.family.0,
            safi: self.family.1,
        });
    }

    /// Run to the next point where the actor admits ordinary input with
    /// release batches still owed. False when the release finished first.
    fn run_to_next_gap(&mut self) -> bool {
        let mut fenced = false;
        while self.manager.unicast_release_runnable() {
            self.manager.advance_unicast_release();
            if self.manager.release_delivery_pending() {
                fenced = true;
            } else if fenced {
                return self.manager.unicast_release_runnable();
            }
        }
        false
    }

    fn finish(&mut self) {
        drain_unicast_release(&mut self.manager);
        drain_resync_ticks(&mut self.manager);
        self.receive();
    }

    /// Exact tables, one marker, nothing after it, denials as the model's,
    /// and a synchronous ranking of every prefix finds nothing to change.
    fn check(&mut self, what: &str, strict_wire: bool) -> Vec<String> {
        let mut wrong = Vec::new();
        for n in 0..self.receivers.len() {
            if self.receivers[n].is_none() {
                continue;
            }
            let (seen, model) = (&self.seen[n], self.model(n));
            if seen.rows != model {
                let diff: Vec<_> = model
                    .iter()
                    .filter(|(prefix, row)| seen.rows.get(prefix) != Some(row))
                    .map(|(prefix, row)| (*prefix, Some(*row), seen.rows.get(prefix).copied()))
                    .chain(
                        seen.rows
                            .iter()
                            .filter(|(prefix, _)| !model.contains_key(prefix))
                            .map(|(prefix, row)| (*prefix, None, Some(*row))),
                    )
                    .take(4)
                    .collect();
                wrong.push(format!(
                    "{what}: client {n} table (prefix, model, wire) {diff:?}"
                ));
            }
            if seen.own != 0 {
                wrong.push(format!(
                    "{what}: client {n} was sent {} own routes",
                    seen.own
                ));
            }
            if seen.markers != 1 || (strict_wire && seen.after_marker != 0) {
                wrong.push(format!(
                    "{what}: client {n} markers {} rows after marker {}",
                    seen.markers, seen.after_marker
                ));
            }
            if strict_wire && (seen.over_withdraw != 0 || seen.repeated != 0) {
                wrong.push(format!(
                    "{what}: client {n} unneeded withdrawals {} repeated rows {}",
                    seen.over_withdraw, seen.repeated
                ));
            }
            let (recorded, model) = (denials(&self.manager, client(n)), self.model_denials(n));
            if recorded != model {
                let extra: Vec<_> = recorded.difference(&model).take(3).collect();
                let missing: Vec<_> = model.difference(&recorded).take(3).collect();
                wrong.push(format!(
                    "{what}: client {n} denials {} model {} extra {extra:?} missing {missing:?}",
                    recorded.len(),
                    model.len()
                ));
            }
        }
        let all: HashSet<Prefix> = self.sent.0.keys().copied().collect();
        let before: Vec<_> = (0..self.receivers.len())
            .map(|n| denials(&self.manager, client(n)))
            .collect();
        self.manager.distribute_changes(&all, &all);
        for (n, receiver) in self.receivers.iter_mut().enumerate() {
            let Some(receiver) = receiver else { continue };
            if receiver.try_recv().is_ok() {
                wrong.push(format!("{what}: client {n} synchronous pass had a delta"));
            }
            if denials(&self.manager, client(n)) != before[n] {
                wrong.push(format!("{what}: client {n} synchronous pass moved denials"));
            }
        }
        wrong
    }
}

/// Mixed candidates: three outside sources, the first eight clients also
/// source, denied top ranks, per-client and announce-to-none communities.
fn mixed(lab: &Lab, rng: &mut Rng, range: std::ops::Range<u32>) -> Vec<(u64, Vec<Route>)> {
    let clients = u32::try_from(lab.receivers.len()).unwrap();
    let sources: Vec<(Ipv4Addr, u64)> = [SOURCE, OTHER_SOURCE, THIRD]
        .into_iter()
        .map(|address| (address, 1))
        .chain((0..8).map(|n| (client_addr(n), 2)))
        .collect();
    let mut by_source: Vec<(u64, Vec<Route>)> = sources
        .iter()
        .map(|&(_, session)| (session, Vec::new()))
        .collect();
    for n in range {
        for (index, &(address, _)) in sources.iter().enumerate() {
            if rng.next(100) >= 45 {
                continue;
            }
            let lp = if rng.next(10) == 0 {
                300
            } else {
                100 + 10 * rng.next(9)
            };
            let communities = match rng.next(10) {
                0..=2 => vec![client_asn(rng.next(clients) as usize)],
                3 => vec![
                    client_asn(rng.next(clients) as usize),
                    client_asn(rng.next(clients) as usize),
                ],
                4 => vec![NONE_TO_ANY, only_to(client_asn(rng.next(clients) as usize))],
                5 => vec![NONE_TO_ANY],
                _ => vec![],
            };
            by_source[index]
                .1
                .push(path(lab.family, n, address, lp, communities));
        }
    }
    by_source
}

fn report(wrong: &[String]) {
    for line in wrong {
        eprintln!("{line}");
    }
    assert!(
        wrong.is_empty(),
        "{} mismatches, first: {}",
        wrong.len(),
        wrong[0]
    );
}

/// A clean client's denied counter after a cold release is the number of
/// denied candidates the walk visited that it did not source, counted once.
fn cold_release(family: (Afi, Safi), seed: u64) {
    let mut lab = Lab::cold(family);
    lab.clients(40, 8_192);
    let mut rng = Rng(seed);
    for (session, routes) in mixed(&lab, &mut rng, 0..2_500) {
        lab.send(session, routes);
    }
    lab.receive();
    assert!(lab.seen.iter().all(|seen| seen.envelopes == 0));
    let before: Vec<_> = (0..40).map(|n| denied_counter(&lab, n)).collect();
    lab.end_hold();
    lab.finish();
    let mut wrong = Vec::new();
    // Clients 0..8 source denied paths of their own.
    let mut own = 0;
    for (n, before) in before.iter().enumerate() {
        let model = lab.model_denials(n).len() as u64;
        own += usize::from(model != lab.model_denials(39).len() as u64);
        let counted = denied_counter(&lab, n) - before;
        if counted != model {
            wrong.push(format!("client {n} denied counter {counted} model {model}"));
        }
    }
    // The synchronous pass inside `check` evaluates again: count first.
    wrong.extend(lab.check("cold", true));
    assert!(own >= 4, "sourcing clients have their own denials excluded");
    report(&wrong);
}

#[test]
fn cold_ipv4_release_matches_the_model_and_counts_each_denial_once() {
    for seed in 1..=2 {
        cold_release(V4, seed);
    }
}

#[test]
fn cold_ipv6_release_matches_the_model_and_counts_each_denial_once() {
    for seed in 3..=4 {
        cold_release(V6, seed);
    }
}

/// Keys change and disappear while release batches are still owed.
#[test]
fn keys_changed_and_withdrawn_between_batches_end_in_exact_tables() {
    for (family, seed) in [(V4, 11), (V6, 13)] {
        let mut lab = Lab::cold(family);
        lab.clients(40, 16_384);
        let mut rng = Rng(seed);
        for (session, routes) in mixed(&lab, &mut rng, 0..3_500) {
            lab.send(session, routes);
        }
        lab.end_hold();
        let mut gaps = 0;
        while lab.run_to_next_gap() {
            gaps += 1;
            // Released or not is unknown to the sender: touch a slice of both.
            let slice = |n: u32| n % 5 == gaps % 5;
            for (peer, session) in [(peer_v4(SOURCE), 1), (client(0), 2)] {
                let gone: Vec<_> = (0..3_500)
                    .filter(|n| slice(*n) && n % 2 == 0)
                    .map(|n| prefix_of(family, n))
                    .filter(|prefix| {
                        lab.sent
                            .0
                            .get(prefix)
                            .is_some_and(|paths| paths.iter().any(|route| route.peer == peer))
                    })
                    .collect();
                if !gone.is_empty() {
                    lab.sent.withdraw(&mut lab.manager, peer, session, gone);
                }
            }
            // A client takes the top rank, a denied path takes it elsewhere,
            // a winner becomes hidden from one client, and new keys arrive.
            let top: Vec<_> = (0..3_500)
                .filter(|n| slice(*n) && n % 2 == 1)
                .map(|n| path(family, n, client_addr(1), 195, vec![]))
                .collect();
            lab.send(2, top);
            let denied: Vec<_> = (0..3_500)
                .filter(|n| slice(*n) && n % 6 == 3)
                .map(|n| path(family, n, OTHER_SOURCE, 300, vec![]))
                .collect();
            lab.send(1, denied);
            let hidden: Vec<_> = (0..3_500)
                .filter(|n| slice(*n) && n % 6 == 4)
                .map(|n| path(family, n, THIRD, 199, vec![client_asn(3), client_asn(30)]))
                .collect();
            lab.send(1, hidden);
            let fresh: Vec<_> = (0..40)
                .map(|n| path(family, 10_000 + 100 * gaps + n, THIRD, 150, vec![]))
                .collect();
            lab.send(1, fresh);
        }
        assert!(gaps >= 2, "{gaps} gaps");
        lab.finish();
        report(&lab.check("between batches", false));
    }
}

/// A source, then a client that is both member and source, go down while
/// batches are owed; a new client joins.
#[test]
fn source_down_member_down_and_a_join_between_batches_end_in_exact_tables() {
    for (family, seed) in [(V4, 21), (V6, 22)] {
        let mut lab = Lab::cold(family);
        lab.clients(40, 16_384);
        let mut rng = Rng(seed);
        for (session, routes) in mixed(&lab, &mut rng, 0..3_500) {
            lab.send(session, routes);
        }
        lab.end_hold();
        assert!(lab.run_to_next_gap());
        let other = peer_v4(OTHER_SOURCE);
        lab.manager.handle_update(RibUpdate::PeerDown {
            peer: other,
            session_id: 1,
        });
        drain_route_chunks(&mut lab.manager);
        lab.sent
            .0
            .values_mut()
            .for_each(|paths| paths.retain(|route| route.peer != other));
        lab.sent.0.retain(|_, paths| !paths.is_empty());
        if lab.run_to_next_gap() {
            lab.manager.handle_update(RibUpdate::PeerDown {
                peer: client(2),
                session_id: 2,
            });
            drain_route_chunks(&mut lab.manager);
            lab.sent
                .0
                .values_mut()
                .for_each(|paths| paths.retain(|route| route.peer != client(2)));
            lab.sent.0.retain(|_, paths| !paths.is_empty());
            lab.receivers[2] = None;
            lab.join(true, 16_384);
        } else {
            panic!("release finished before the second gap");
        }
        lab.finish();
        for _ in 0..8 {
            lab.finish();
        }
        report(&lab.check("down and join", false));
    }
}

/// Crowded prefixes through the real state machine: long fallback lists and
/// denial lists, at and around one page, mixed with ordinary prefixes.
#[test]
fn crowded_fallback_and_denial_lists_release_exact_tables() {
    for family in [V4, V6] {
        let mut lab = Lab::cold(family);
        lab.clients(40, 8_192);
        let mut rng = Rng(31);
        for (session, routes) in mixed(&lab, &mut rng, 0..600) {
            lab.send(session, routes);
        }
        // (key, denied paths, hidden paths); each also has two clean sources
        // ranked below, one of them a client.
        let shapes = [
            (20_000, 127, 0),
            (20_001, 128, 0),
            (20_002, 129, 0),
            (20_003, 0, 127),
            (20_004, 0, 128),
            (20_005, 0, 129),
            (20_006, 64, 64),
            (20_007, 64, 65),
            (20_008, 300, 300),
        ];
        for (key, denied, hidden) in shapes {
            let mut paths = Vec::new();
            for id in 1..=denied {
                let mut route = path(family, key, OTHER_SOURCE, 300, vec![]);
                route.path_id = id;
                paths.push(route);
            }
            for id in 1..=hidden {
                // Hidden from a spread of clients, some from all but one.
                let communities = if id % 3 == 0 {
                    vec![NONE_TO_ANY, only_to(client_asn((id % 40) as usize))]
                } else {
                    vec![
                        client_asn((id % 40) as usize),
                        client_asn(((id * 7) % 40) as usize),
                    ]
                };
                let mut route = path(family, key, OTHER_SOURCE, 190 - id % 5, communities);
                route.path_id = 1_000 + id;
                paths.push(route);
            }
            lab.send(1, paths);
            lab.send(1, vec![path(family, key, THIRD, 120, vec![])]);
            lab.send(2, vec![path(family, key, client_addr(4), 110, vec![])]);
        }
        lab.end_hold();
        lab.finish();
        report(&lab.check("crowded", true));
    }
}

/// A full, a dirty and a late-draining client; counters and denials after.
#[test]
fn refused_and_dirty_clients_recover_exact_tables_and_denials() {
    let mut lab = Lab::cold(V4);
    lab.clients(40, 8_192);
    let mut rng = Rng(41);
    for (session, routes) in mixed(&lab, &mut rng, 0..2_500) {
        lab.send(session, routes);
    }
    // Client 20 is full for the whole release, 33 only for the first batch,
    // 37 is already dirty.
    for n in [20, 33] {
        let writer = lab.manager.outbound_peers[&client(n)].clone();
        while writer.try_send(OutboundRouteUpdate::default()).is_ok() {}
    }
    lab.manager.mark_outbound_dirty(client(37));
    lab.end_hold();
    assert!(lab.run_to_next_gap());
    lab.seen[33] = Seen::default();
    while lab.receivers[33].as_mut().unwrap().try_recv().is_ok() {}
    drain_unicast_release(&mut lab.manager);
    while lab.receivers[20].as_mut().unwrap().try_recv().is_ok() {}
    lab.finish();
    for _ in 0..8 {
        lab.finish();
    }
    for n in [20, 33, 37] {
        assert!(
            !lab.manager.dirty_peers.contains(&client(n)),
            "client {n} still dirty"
        );
    }
    // Clients 9.. source nothing, so their denial counts are the group's.
    assert_eq!(denied_counter(&lab, 10), denied_counter(&lab, 11));
    report(&lab.check("refused", false));
}

/// One prefix at each side of the page boundary, with three plain prefixes:
/// a clean client gets one message when it shares the stage and two when not.
#[test]
fn a_prefix_shares_the_stage_up_to_one_page_of_new_history() {
    // (denied paths, hidden paths, messages). A hidden top path is the winner;
    // the rest and the two clean sources below make the fallback list.
    for (denied, hidden, messages) in [
        (128, 0, 1),
        (129, 0, 2),
        (0, 127, 1),
        (0, 128, 2),
        (64, 63, 1),
        (64, 64, 2),
    ] {
        let mut lab = Lab::cold(V4);
        lab.clients(20, 512);
        for n in 0..3 {
            lab.send(1, vec![path(V4, n, SOURCE, 100, vec![])]);
        }
        let mut paths = Vec::new();
        for id in 1..=denied {
            let mut route = path(V4, 50, OTHER_SOURCE, 300, vec![]);
            route.path_id = id;
            paths.push(route);
        }
        for id in 1..=hidden {
            let mut route = path(V4, 50, OTHER_SOURCE, 190, vec![client_asn(3)]);
            route.path_id = 1_000 + id;
            paths.push(route);
        }
        lab.send(1, paths);
        lab.send(1, vec![path(V4, 50, THIRD, 120, vec![])]);
        lab.send(2, vec![path(V4, 50, client_addr(4), 110, vec![])]);
        lab.end_hold();
        lab.finish();
        let got: BTreeSet<_> = lab.seen.iter().map(|seen| seen.envelopes).collect();
        report(&lab.check("boundary", true));
        assert_eq!(
            got,
            BTreeSet::from([messages]),
            "denied {denied} hidden {hidden}"
        );
    }
}

fn denied_counter(lab: &Lab, n: usize) -> u64 {
    lab.manager
        .export_policy_counters
        .get(&client(n))
        .map_or(0, |counters| {
            counters.snapshot().export_policy_routes_denied
        })
}

impl Lab {
    /// Tables populated with no hold; `hold` then defers the family.
    fn warm(family: (Afi, Safi)) -> Self {
        let (tx, rx) = mpsc::channel(8);
        let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
        manager.test_force_ungrouped = false;
        register_test_peer(&mut manager, peer_v4(SOURCE), 1);
        register_test_peer(&mut manager, peer_v4(OTHER_SOURCE), 1);
        register_test_peer(&mut manager, peer_v4(THIRD), 1);
        Self {
            family,
            manager,
            receivers: Vec::new(),
            seen: Vec::new(),
            rs: Vec::new(),
            sent: Candidates::default(),
            _tx: tx,
        }
    }

    fn hold(&mut self) {
        let source = peer_v4(SOURCE);
        let (_tx, rx) = mpsc::channel(1);
        let spare = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
        let manager = std::mem::replace(&mut self.manager, spare);
        self.manager = manager.with_selection_deferral(SelectionDeferralConfig {
            timeout: Duration::from_mins(1),
            waiters: vec![SelectionDeferralWaiterConfig {
                peer: source.into(),
                families: vec![self.family],
            }],
        });
        let transitions = self
            .manager
            .selection_deferral
            .as_mut()
            .unwrap()
            .classify_session(
                source,
                1,
                false,
                &[self.family].into_iter().collect(),
                &self.manager.metrics,
            );
        assert!(
            transitions.is_empty(),
            "the fixture owes a current-session EoR"
        );
        assert!(self.manager.selection_deferred(self.family));
        for n in 0..self.receivers.len() {
            self.manager.owe_eor(client(n), self.family);
        }
    }
}

/// Populated tables, then a hold with replaced, withdrawn, vanished and new
/// keys, a denial-only key that disappears, and one refused client.
#[test]
fn warm_release_replaces_populated_tables_exactly() {
    for (family, seed) in [(V4, 61), (V6, 63)] {
        let mut lab = Lab::warm(family);
        lab.clients(40, 16_384);
        let mut rng = Rng(seed);
        for (session, routes) in mixed(&lab, &mut rng, 0..1_500) {
            lab.send(session, routes);
        }
        // Keys with only a denied path: recorded as denials, never advertised.
        lab.send(
            1,
            (3_000..3_060)
                .map(|n| path(family, n, OTHER_SOURCE, 300, vec![]))
                .collect(),
        );
        lab.receive();
        report(&lab.check("before the hold", false));
        for seen in &mut lab.seen {
            seen.markers = 0;
            seen.envelopes = 0;
        }
        lab.hold();
        // Replace the paths of a third of the keys with a different draw.
        let mut redraw = Rng(seed + 1_000);
        for (session, routes) in mixed(&lab, &mut redraw, 0..1_500) {
            let routes: Vec<_> = routes
                .into_iter()
                .filter(|route| {
                    lab.sent
                        .0
                        .keys()
                        .position(|p| *p == route.prefix)
                        .is_some_and(|i| i % 3 == 0)
                })
                .collect();
            lab.send(session, routes);
        }
        for (peer, session) in [
            (peer_v4(SOURCE), 1),
            (peer_v4(OTHER_SOURCE), 1),
            (peer_v4(THIRD), 1),
            (client(0), 2),
            (client(5), 2),
        ] {
            let gone: Vec<_> = lab
                .sent
                .0
                .iter()
                .enumerate()
                .filter(|(i, (_, paths))| {
                    (i % 5 == 1 || (i % 7 == 2 && peer == peer_v4(SOURCE)))
                        && paths.iter().any(|route| route.peer == peer)
                })
                .map(|(_, (prefix, _))| *prefix)
                .collect();
            if !gone.is_empty() {
                lab.sent.withdraw(&mut lab.manager, peer, session, gone);
            }
        }
        let vanished: Vec<_> = (3_000..3_030)
            .map(|n| prefix_of(family, n))
            .filter(|prefix| lab.sent.0.contains_key(prefix))
            .collect();
        assert!(vanished.len() > 10);
        lab.sent
            .withdraw(&mut lab.manager, peer_v4(OTHER_SOURCE), 1, vanished);
        for (session, routes) in mixed(&lab, &mut redraw, 1_500..2_100) {
            lab.send(session, routes);
        }
        lab.receive();
        assert!(
            lab.seen.iter().all(|seen| seen.envelopes == 0),
            "sent under the hold"
        );
        let writer = lab.manager.outbound_peers[&client(21)].clone();
        while writer.try_send(OutboundRouteUpdate::default()).is_ok() {}
        lab.end_hold();
        drain_unicast_release(&mut lab.manager);
        assert!(lab.manager.dirty_peers.contains(&client(21)));
        while lab.receivers[21].as_mut().unwrap().try_recv().is_ok() {}
        for _ in 0..8 {
            lab.finish();
        }
        assert!(!lab.manager.dirty_peers.contains(&client(21)));
        report(&lab.check("warm", false));
    }
}

/// Indicative only: a route-server shape with control communities, denials
/// and clients that source, which the ticket's timed shape has none of.
#[test]
#[ignore = "indicative wall-clock timing; run by name in an optimized profile"]
fn timing_tagged_route_server_release() {
    for members in [32, 150] {
        let mut lab = Lab::cold(V4);
        lab.clients(members, 2_048);
        let mut rng = Rng(71);
        let mut paths = 0;
        for (session, routes) in mixed(&lab, &mut rng, 0..16_384) {
            paths += routes.len();
            lab.send(session, routes);
        }
        let start = Instant::now();
        lab.end_hold();
        let (mut polls, mut run, mut longest_polls) = (0, 0, 0);
        let (mut longest, mut fence) = (Duration::ZERO, None);
        while lab.manager.unicast_release_runnable() {
            let opened = *fence.get_or_insert_with(Instant::now);
            lab.manager.advance_unicast_release();
            polls += 1;
            if lab.manager.release_delivery_pending() {
                run += 1;
                longest_polls = longest_polls.max(run);
            } else {
                if run > 0 {
                    longest = longest.max(opened.elapsed());
                }
                run = 0;
                fence = None;
            }
        }
        let wall = start.elapsed();
        lab.finish();
        eprintln!(
            "release timing tagged members={members} prefixes=16384 paths={paths} wall_ms={:.1} longest_fenced_ms={:.1} longest_fenced_polls={longest_polls} polls={polls} most_envelopes={}",
            wall.as_secs_f64() * 1e3,
            longest.as_secs_f64() * 1e3,
            lab.seen.iter().map(|seen| seen.envelopes).max().unwrap()
        );
        report(&lab.check("timing", true));
    }
}

/// The key ranked last is staged alone while a smaller key waits in the
/// shared stage: that key must still be delivered. Key order follows a
/// randomly seeded hash set, so two dozen two-key releases cover both orders.
#[test]
fn shared_stage_survives_a_crowded_last_key() {
    for small in 0..24 {
        let mut lab = Lab::cold(V4);
        lab.clients(20, 512);
        lab.send(1, vec![path(V4, small, SOURCE, 100, vec![])]);
        lab.send(1, denied_paths(5_000, 1..=129));
        lab.send(1, vec![path(V4, 5_000, THIRD, 120, vec![])]);
        lab.end_hold();
        lab.finish();
        report(&lab.check("crowded last key", true));
    }
}

fn denied_paths(key: u32, ids: std::ops::RangeInclusive<u32>) -> Vec<Route> {
    ids.map(|id| {
        let mut route = path(V4, key, OTHER_SOURCE, 300, vec![]);
        route.path_id = id;
        route
    })
    .collect()
}

/// The denials a stage replaces are work too: a prefix whose stored and new
/// denials together pass one page is staged alone, however few are new.
#[test]
fn stored_history_counts_toward_the_page_a_prefix_may_share() {
    // (denied paths before the hold, at the release, messages a client)
    for (stored, new, messages) in [(64, 64, 1), (64, 65, 2), (100, 100, 2)] {
        let mut lab = Lab::warm(V4);
        lab.clients(20, 512);
        for n in 0..3 {
            lab.send(1, vec![path(V4, n, SOURCE, 100, vec![])]);
        }
        lab.send(1, denied_paths(50, 1..=stored));
        lab.send(1, vec![path(V4, 50, THIRD, 120, vec![])]);
        lab.receive();
        report(&lab.check("before the hold", false));
        for seen in &mut lab.seen {
            seen.markers = 0;
            seen.envelopes = 0;
        }
        lab.hold();
        // Every key changes under the hold, so each client is owed four rows.
        for n in 0..3 {
            lab.send(1, vec![path(V4, n, SOURCE, 110, vec![])]);
        }
        lab.send(1, denied_paths(50, stored + 1..=new));
        lab.send(1, vec![path(V4, 50, THIRD, 130, vec![])]);
        lab.end_hold();
        lab.finish();
        let got: BTreeSet<_> = lab.seen.iter().map(|seen| seen.envelopes).collect();
        report(&lab.check("stored history", false));
        assert_eq!(got, BTreeSet::from([messages]), "stored {stored} new {new}");
    }
}

/// A stage closes as soon as its work reaches the cap, not one prefix later.
#[test]
fn a_stage_closes_when_its_work_reaches_the_cap() {
    let mut lab = Lab::cold(V4);
    lab.clients(4, 64);
    // Three denied paths a prefix are four work units: 512 prefixes are 2,048.
    for n in 0..1_024 {
        let mut paths = vec![path(V4, n, OTHER_SOURCE, 100, vec![])];
        paths.extend(denied_paths(n, 1..=3));
        lab.send(1, paths);
    }
    lab.end_hold();
    lab.finish();
    for (n, seen) in lab.seen.iter().enumerate() {
        assert_eq!((seen.envelopes, seen.largest), (2, 512), "client {n}");
    }
    report(&lab.check("stage cap", true));
}

/// One poll spends one page of candidate units, however many prefixes it
/// ranks with them.
#[test]
fn one_release_poll_examines_one_page_of_candidates_across_prefixes() {
    let (mut manager, _tx, _receivers) = held_client_group(4, 1_024, true);
    manager.handle_update(source_end_of_rib());
    let _ = crate::adj_rib_in::AdjRibIn::take_path_visits();
    let (mut most, mut total) = (0, 0);
    while manager.unicast_release_runnable() {
        manager.advance_unicast_release();
        let visits = crate::adj_rib_in::AdjRibIn::take_path_visits();
        most = most.max(visits);
        total += visits;
    }
    assert!(total >= 1_024, "{total} candidates examined");
    assert!(most <= 128, "{most} candidates examined in one poll");
}

/// A locally originated winner keeps its provenance, and a winner the role
/// check blocks is recorded for the group, when both ride the shared stage.
/// IPv6, because a local IPv4 host route is exempt from the hold.
#[test]
fn shared_stage_carries_local_provenance_and_role_blocked_winners() {
    let mut lab = Lab::cold(V6);
    for n in 0..4 {
        lab.manager.handle_update(RibUpdate::SetPeerExportContext {
            peer: client(n),
            session_id: 2,
            local_role: Some(rustbgpd_wire::BgpRole::Customer),
        });
        lab.join(false, 64);
    }
    let gid = lab.manager.grouped_member_of(client(0)).expect("grouped");
    assert_eq!(lab.manager.grouped_member_of(client(3)), Some(gid));
    let mut local = path(V6, 1, SOURCE, 100, vec![]);
    local.peer = LOCAL_PEER;
    local.origin_type = crate::route::RouteOrigin::Local;
    let (reply, _rx) = oneshot::channel();
    lab.manager.handle_inject_route(local, reply);
    let mut blocked = path(V6, 2, OTHER_SOURCE, 190, vec![]);
    AttrSet::edit(&mut blocked.attributes, |attrs| {
        attrs.push(PathAttribute::OnlyToCustomer(64_512));
    });
    lab.send(1, vec![blocked]);
    lab.receive();
    assert!(lab.seen.iter().all(|seen| seen.envelopes == 0));
    lab.end_hold();
    lab.finish();
    let group = &lab.manager.group_ribs[&gid];
    let (local, blocked) = (prefix_of(V6, 1), prefix_of(V6, 2));
    for (n, seen) in lab.seen.iter().enumerate() {
        assert_eq!(
            seen.rows,
            BTreeMap::from([(local, (LOCAL_PEER, 100))]),
            "client {n} table"
        );
        let entry = group.adv_entry_for(client(n), &local, 0, None);
        assert!(
            entry.is_some_and(|entry| entry.local_source.is_some()),
            "client {n} local provenance"
        );
        let recorded = group.otc_blocked_for_member(client(n), Some(&HashSet::from([blocked])));
        assert_eq!(recorded.len(), 1, "client {n} role-blocked candidates");
    }
    // The synchronous ranking of both prefixes finds nothing to change.
    let all = HashSet::from([local, blocked]);
    lab.manager.distribute_changes(&all, &all);
    lab.receive();
    assert!(lab.seen.iter().all(|seen| seen.envelopes == 1));
}
