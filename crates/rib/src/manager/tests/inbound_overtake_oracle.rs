//! Equivalence oracle for the overtake lane: a randomized queue of session
//! bring-up, teardown, context, route, End-of-RIB, refresh and policy
//! messages leaves the same Loc-RIB, the same Adj-RIB-In sizes and the same
//! table on every receiver as strict FIFO processing of the same queue.
//!
//! It also checks what each stable receiver was sent for each prefix, in
//! order. Two runs of one queue need not send identical streams even in
//! strict arrival order, because one distribution window coalesces the
//! messages it happens to hold and the lane changes which messages share a
//! window. The reference is therefore the stream of strict arrival order
//! with one message per window, which shows every state a prefix passes
//! through. Each run's stream for a prefix must be that reference with some
//! intermediate states left out: the same order, the same end, and no state
//! the reference never shows. A repeat of the state just sent, such as a
//! route refresh answer, is not a state change and is left out of both.
//! End-of-RIB markers are events too: each run must send a receiver the same
//! markers in the same order. Which rows a paced replay has sent by the time
//! its marker leaves depends on how its pages interleave with other input
//! even in strict arrival order, so the table at a marker is pinned by the
//! deterministic family-unlock test instead.

use super::exportability::ReusableExactExportEncoder;
use super::inbound_overtake::{Log, collect, overtakes, prefix, source, wired_fleet};
use super::lifecycle::{test_peer_up, test_session_routes_received};
use super::*;

const SOURCES: u8 = 6;
const RECEIVERS: u16 = 4;
/// Prefixes any source may announce, so sources compete for them.
const SHARED: u32 = 24;
const MESSAGES: usize = 96;
/// Fixed seeds; each runs once under strict FIFO and once with the lane.
const SEEDS: [u64; 32] = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30, 31, 32,
];

struct Rng(u64);

impl Rng {
    /// splitmix64.
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: u32) -> u32 {
        u32::try_from(self.next() % u64::from(bound)).unwrap()
    }
}

fn receiver(index: u16) -> PeerId {
    peer_v4(Ipv4Addr::from(0xc000_0201 + u32::from(index)))
}

/// The queue for `seed`. A receiver that rejoins gets a new writer, whose
/// wire log replaces the old one in `wires`.
#[expect(clippy::too_many_lines, reason = "one arm per generated message kind")]
fn queue(seed: u64, wires: &mut [Log], stable: &mut [bool]) -> Vec<RibUpdate> {
    let mut rng = Rng(seed);
    // The session each source's next message names, and whether it is up.
    let mut sessions: Vec<(u64, bool)> = vec![(0, true); usize::from(SOURCES)];
    let mut receiver_sessions = vec![1_u64; usize::from(RECEIVERS)];
    let mut queue = Vec::new();
    while queue.len() < MESSAGES {
        let at = u8::try_from(rng.below(u32::from(SOURCES))).unwrap();
        let from = source(at);
        let peer = peer_v4(from);
        let (session, up) = sessions[usize::from(at)];
        let own = 10_000 * (u32::from(at) + 1);
        match rng.below(100) {
            // A small announcement, mostly of contested prefixes.
            0..=34 if up => {
                let routes = (0..=rng.below(3))
                    .map(|_| make_route(prefix(rng.below(SHARED)), from))
                    .collect();
                queue.push(test_session_routes_received(peer, session, routes));
            }
            // A small withdrawal.
            35..=44 if up => {
                let mut update = test_session_routes_received(peer, session, Vec::new());
                let RibUpdate::RoutesReceived { withdrawn, .. } = &mut update else {
                    unreachable!()
                };
                withdrawn
                    .extend((0..=rng.below(2)).map(|_| (Prefix::V4(prefix(rng.below(SHARED))), 0)));
                queue.push(update);
            }
            // A table-sized announcement that also contests a few prefixes.
            45..=59 if up => {
                let base = own + rng.below(4) * 100;
                let routes = (base..base + 40)
                    .chain((0..rng.below(3)).map(|_| rng.below(SHARED)))
                    .map(|index| make_route(prefix(index), from))
                    .collect();
                queue.push(test_session_routes_received(peer, session, routes));
            }
            // A message that names a session already replaced.
            60..=62 if up && session > 0 => {
                let routes = vec![make_route(prefix(rng.below(SHARED)), from)];
                queue.push(test_session_routes_received(peer, session - 1, routes));
            }
            63..=71 if up => {
                queue.push(RibUpdate::PeerDown {
                    peer,
                    session_id: session,
                });
                sessions[usize::from(at)].1 = false;
            }
            63..=79 if !up => {
                sessions[usize::from(at)] = (session + 1, true);
                queue.push(registering_peer_up(peer, session + 1));
            }
            80..=84 if up => queue.push(RibUpdate::SetPeerRsControl {
                peer,
                session_id: session,
                rs_control_asn: None,
            }),
            85..=88 if up => queue.push(RibUpdate::EndOfRib {
                peer,
                session_id: session,
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
            }),
            89..=99 => {
                let index = u16::try_from(rng.below(u32::from(RECEIVERS))).unwrap();
                let peer = receiver(index);
                let session = receiver_sessions[usize::from(index)];
                match rng.below(4) {
                    // A family unlock on the live session: its table (none
                    // here) and an End-of-RIB marker in mid-stream.
                    3 => queue.push(RibUpdate::PeerFamilySendable {
                        peer,
                        session_id: session,
                        family: (Afi::Ipv6, Safi::Unicast),
                        add_path_send_limit: None,
                    }),
                    0 => queue.push(RibUpdate::RouteRefreshRequest {
                        queued: Arc::default(),
                        session_id: session,
                        peer,
                        afi: Afi::Ipv4,
                        safi: Safi::Unicast,
                    }),
                    1 => queue.push(RibUpdate::ReplacePeerExportPolicy {
                        peer,
                        export_policy: None,
                        reply: oneshot::channel().0,
                    }),
                    _ => {
                        // The receiver flaps and rejoins on a new writer.
                        stable[usize::from(index)] = false;
                        queue.push(RibUpdate::PeerDown {
                            peer,
                            session_id: session,
                        });
                        receiver_sessions[usize::from(index)] = session + 1;
                        queue.push(RibUpdate::SetPeerExportEncoder {
                            peer,
                            session_id: session + 1,
                            encoder: ReusableExactExportEncoder::new(u64::from(index) + 1, 1),
                        });
                        let (outbound_tx, outbound_rx) = mpsc::channel(256);
                        queue.push(test_peer_up(peer, session + 1, outbound_tx));
                        wires[usize::from(index)] = collect(outbound_rx);
                    }
                }
            }
            _ => {}
        }
    }
    queue
}

/// The table a receiver holds after its writer's UPDATE stream.
fn table(wire: &Log) -> BTreeMap<String, String> {
    let mut table = BTreeMap::new();
    for event in wire.lock().unwrap().iter() {
        if event.starts_with("E ") {
            continue;
        }
        if let Some(key) = event.strip_prefix("W ") {
            table.remove(key);
        } else {
            let (key, from) = event.strip_prefix("A ").unwrap().rsplit_once(' ').unwrap();
            table.insert(key.to_owned(), from.to_owned());
        }
    }
    table
}

/// What a receiver was sent for each prefix, in order: `A <source>` or `W`,
/// with a repeat of the state just sent left out. A route refresh answer
/// repeats the receiver's current state for every prefix it holds, and an
/// answer deferred behind a live whole-table update goes out on a later
/// resync tick, after however many queued messages the actor has applied by
/// then. That depends on when the receiver's writer ran, so a repeat is not
/// part of the order a run must keep.
fn sequences(wire: &Log) -> BTreeMap<String, Vec<String>> {
    let mut sequences: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for event in wire.lock().unwrap().iter() {
        if event.starts_with("E ") {
            continue;
        }
        let (key, state) = if let Some(key) = event.strip_prefix("W ") {
            (key, "W".to_owned())
        } else {
            let (key, from) = event.strip_prefix("A ").unwrap().rsplit_once(' ').unwrap();
            (key, format!("A {from}"))
        };
        let states = sequences.entry(key.to_owned()).or_default();
        if states.last() != Some(&state) {
            states.push(state);
        }
    }
    sequences
}

/// The End-of-RIB markers a receiver was sent, in order.
fn markers(wire: &Log) -> Vec<String> {
    wire.lock()
        .unwrap()
        .iter()
        .filter_map(|event| event.strip_prefix("E ").map(str::to_owned))
        .collect()
}

/// Whether `stream` is `reference` with intermediate states left out.
fn coalesces(stream: &[String], reference: &[String]) -> bool {
    let mut rest = reference.iter();
    stream.iter().all(|state| rest.any(|seen| seen == state)) && stream.last() == reference.last()
}

/// One stable receiver's per-prefix sequences and its End-of-RIB markers.
type Streams = (BTreeMap<String, Vec<String>>, Vec<String>);

#[derive(Clone, Copy, Debug, PartialEq)]
enum Mode {
    /// Strict arrival order, one message per distribution window.
    Reference,
    /// Strict arrival order.
    Fifo,
    Lane,
}

thread_local! {
    static PACED_DEPARTURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn note_paced_departure(manager: &RibManager) {
    if manager.source_departure.is_some() {
        PACED_DEPARTURE.set(true);
    }
}

#[derive(Debug, PartialEq)]
struct Outcome {
    loc_rib: BTreeMap<Prefix, PeerId>,
    adj_rib_in: BTreeMap<String, usize>,
    receivers: Vec<BTreeMap<String, String>>,
}

/// The outcome, each stable receiver's per-prefix streams and the overtakes.
/// `capped` gives receiver 0 an outbound prefix limit.
async fn outcome(seed: u64, mode: Mode, capped: bool) -> (Outcome, Vec<Streams>, f64) {
    let (tx, mut manager, _log, mut wires) = wired_fleet(SOURCES, RECEIVERS);
    manager.parked.strict_fifo = mode != Mode::Lane;
    if mode == Mode::Reference {
        manager.distribution_window_limits.messages = 1;
    }
    if capped {
        use super::outbound_prefix_limits::{apply, limit_config, prepare};
        prepare(
            &mut manager,
            1,
            limit_config(&[(receiver(0), Some(8), None)], &[]),
        )
        .expect("preflight passes");
        apply(&mut manager, 1, true).expect("activation passes");
    }
    manager.actor_turn_check = Some(note_paced_departure);
    let mut stable = vec![true; usize::from(RECEIVERS)];
    for update in queue(seed, &mut wires, &mut stable) {
        tx.try_send(update).unwrap();
    }
    let actor = tokio::spawn(manager.run_actor());
    // Paced work, deferred registrations and resync ticks all settle.
    tokio::time::sleep(Duration::from_secs(120)).await;
    drop(tx);
    let manager = actor.await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    let passed = overtakes(&manager).iter().map(|(_, count)| count).sum();
    let outcome = Outcome {
        loc_rib: manager
            .loc_rib
            .iter()
            .map(|route| (route.prefix, route.peer))
            .collect(),
        adj_rib_in: manager
            .ribs
            .iter()
            .map(|(peer, rib)| (peer.to_string(), rib.len()))
            .collect(),
        receivers: wires.iter().map(table).collect(),
    };
    let streams = wires
        .iter()
        .zip(&stable)
        .filter(|(_, stable)| **stable)
        .map(|(wire, _)| (sequences(wire), markers(wire)))
        .collect();
    (outcome, streams, passed)
}

#[tokio::test(start_paused = true)]
async fn the_lane_leaves_the_tables_strict_fifo_leaves() {
    let mut passed = 0.0;
    let mut compared = 0;
    let mut marked = 0;
    for seed in SEEDS {
        // Every eighth seed caps a receiver, which closes the lane.
        let capped = seed % 8 == 0;
        let (mut reference, shown, _) = Box::pin(outcome(seed, Mode::Reference, capped)).await;
        let (mut fifo, fifo_streams, none) = Box::pin(outcome(seed, Mode::Fifo, capped)).await;
        assert!(none == 0.0, "seed {seed}: strict FIFO overtook");
        let (mut lane, lane_streams, count) = Box::pin(outcome(seed, Mode::Lane, capped)).await;
        if capped {
            // Which prefixes of one batch take the capped slots follows
            // table order, which differs between two managers.
            for outcome in [&mut reference, &mut fifo, &mut lane] {
                assert!(outcome.receivers[0].len() <= 8, "seed {seed}: over the cap");
                outcome.receivers[0].clear();
            }
        }
        assert_eq!(
            lane, fifo,
            "seed {seed}: {count} overtakes changed the outcome"
        );
        assert_eq!(fifo, reference, "seed {seed}: the reference run diverged");
        assert!(
            fifo.receivers[1..].iter().any(|table| !table.is_empty()),
            "seed {seed}: no receiver holds a route"
        );
        if capped {
            assert!(
                count == 0.0,
                "seed {seed}: {count} overtakes with a capped receiver"
            );
            continue;
        }
        for (name, streams) in [("FIFO", &fifo_streams), ("lane", &lane_streams)] {
            assert_eq!(streams.len(), shown.len(), "seed {seed}");
            for (at, ((stream, marks), (reference, shown_marks))) in
                streams.iter().zip(&shown).enumerate()
            {
                assert_eq!(
                    marks, shown_marks,
                    "seed {seed}: {name} stable receiver {at} was sent different End-of-RIB markers"
                );
                marked += marks.len();
                assert_eq!(
                    stream.keys().collect::<Vec<_>>(),
                    reference.keys().collect::<Vec<_>>(),
                    "seed {seed}: {name} stable receiver {at} was sent different prefixes"
                );
                for (key, sent) in stream {
                    assert!(
                        coalesces(sent, &reference[key]),
                        "seed {seed}: {name} stable receiver {at}, {key}: sent {sent:?}, \
                         arrival order shows {:?}",
                        reference[key]
                    );
                    compared += 1;
                }
            }
        }
        passed += count;
    }
    eprintln!(
        "overtakes across {} seeds: {passed}; {compared} per-receiver prefix streams and \
         {marked} End-of-RIB markers compared",
        SEEDS.len()
    );
    assert!(passed >= 64.0, "the oracle exercised {passed} overtakes");
    assert!(compared > 1_000, "{compared} streams compared");
    assert!(marked > 100, "{marked} End-of-RIB markers compared");
    assert!(PACED_DEPARTURE.get(), "no seed paced a source departure");
}
