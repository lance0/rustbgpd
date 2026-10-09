//! Same-group joiners completed by one deferred-registration turn from one
//! shared replay (LAN-1826).
//!
//! Every scenario drives the identical script twice: grouped, and with
//! `test_force_ungrouped` putting every peer on the per-peer path (the
//! correctness oracle). A survivor registers on a quiet actor, a source
//! announces the table, then the joiners' `PeerUp`s arrive behind queued
//! actor work so each registration defers (LAN-475). Each joiner's own route
//! imports and reaches the survivor before any joiner's table, then the run
//! loop's advance seam drains the queue. The per-peer normalized streams
//! must match message for message; the grouped side must also prove the
//! cohort really formed (one turn, one shared payload and encode cell).

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::update_groups::CohortExactEncoder;
use super::update_groups_oracle::{NormMsg, normalize};
use super::*;
use crate::manager::peer_lifecycle::MAX_JOIN_COHORT_EXAMINED;

const SESSION: u64 = 1;
const RS_AS: u32 = 65_000;
const SOURCE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const SURVIVOR: Ipv4Addr = Ipv4Addr::new(10, 70, 0, 1);

#[derive(Clone)]
struct Joiner {
    addr: Ipv4Addr,
    asn: u32,
    /// RFC 7947 control context staged before `PeerUp`: the RS ASN.
    rs_asn: Option<u32>,
    /// Local RFC 9234 role staged before `PeerUp`.
    role: Option<rustbgpd_wire::BgpRole>,
    export_policy: Option<rustbgpd_policy::PolicyChain>,
    /// The session's exact-export ceiling (`CohortExactEncoder`).
    max_len: usize,
    sendable: Vec<(Afi, Safi)>,
}

fn joiner(last: u8, asn: u32) -> Joiner {
    Joiner {
        addr: Ipv4Addr::new(10, 70, 1, last),
        asn,
        rs_asn: None,
        role: None,
        export_policy: None,
        max_len: 4_096,
        sendable: ipv4_sendable(),
    }
}

/// `count` same-profile joiners with distinct addresses and peer ASNs.
fn fleet(count: usize) -> Vec<Joiner> {
    (0..count)
        .map(|index| {
            let index = u16::try_from(index).unwrap();
            Joiner {
                addr: Ipv4Addr::new(10, 71, u8::try_from(index / 250).unwrap(), {
                    u8::try_from(index % 250).unwrap() + 1
                }),
                ..joiner(0, 65_200 + u32::from(index))
            }
        })
        .collect()
}

fn rs_joiner(last: u8, asn: u32) -> Joiner {
    Joiner {
        rs_asn: Some(RS_AS),
        ..joiner(last, asn)
    }
}

fn peer_up(
    peer: Ipv4Addr,
    peer_asn: u32,
    sendable_families: Vec<(Afi, Safi)>,
    export_policy: Option<rustbgpd_policy::PolicyChain>,
    outbound_tx: mpsc::Sender<OutboundRouteUpdate>,
) -> RibUpdate {
    RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: SESSION,
        peer: IpAddr::V4(peer),
        peer_asn,
        peer_router_id: peer,
        outbound_tx,
        export_policy,
        sendable_families,
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    }
}

fn announce(peer: Ipv4Addr, announced: Vec<Route>) -> RibUpdate {
    RibUpdate::RoutesReceived {
        // The table source is an unregistered legacy producer.
        session_id: if peer == SOURCE { 0 } else { SESSION },
        peer: IpAddr::V4(peer),
        announced,
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    }
}

fn route_prefix(third_octet: u8) -> Prefix {
    Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 200, third_octet, 0), 24))
}

fn route(third_octet: u8, source: Ipv4Addr, communities: Vec<u32>) -> Route {
    let Prefix::V4(prefix) = route_prefix(third_octet) else {
        unreachable!()
    };
    let mut route = make_route(prefix, source);
    if !communities.is_empty() {
        AttrSet::edit(&mut route.attributes, |attrs| {
            attrs.push(PathAttribute::Communities(communities));
        });
    }
    route
}

fn encoder(
    peer: Ipv4Addr,
    owner: u64,
    max_len: usize,
    probes: &Arc<AtomicUsize>,
    reuses: &Arc<AtomicUsize>,
) -> RibUpdate {
    RibUpdate::SetPeerExportEncoder {
        peer: IpAddr::V4(peer),
        session_id: SESSION,
        encoder: Arc::new(CohortExactEncoder {
            owner,
            profile: 1826,
            max_len,
            generation: AtomicUsize::new(0),
            advance_generation: false,
            probes: Arc::clone(probes),
            reuses: Arc::clone(reuses),
        }),
    }
}

struct Run {
    manager: RibManager,
    streams: BTreeMap<IpAddr, Vec<NormMsg>>,
    raw: BTreeMap<IpAddr, Vec<OutboundRouteUpdate>>,
    /// Joiners whose registration the FIRST advance completed.
    first_turn: Vec<Ipv4Addr>,
    /// Group-table control-tag scans the first advance ran.
    first_turn_tag_scans: usize,
    probes: usize,
    reuses: usize,
}

/// `extra`: routes the table source announces besides its three plain
/// ones. `dead`: that joiner's
/// session receiver is dropped at the first readiness checkpoint inside the
/// first advance, after its registration was admitted and before any table
/// of that turn is sent.
#[expect(
    clippy::too_many_lines,
    reason = "one script drives survivor, table, deferred joiners and the advance seam"
)]
async fn run(
    force_ungrouped: bool,
    joiners: &[Joiner],
    extra: &[Route],
    dead: Option<Ipv4Addr>,
) -> Run {
    let (tx, rx) = mpsc::channel(64);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    manager.test_force_ungrouped = force_ungrouped;
    manager.initial_dump_defer_min_routes = 0;
    let probes = Arc::new(AtomicUsize::new(0));
    let reuses = Arc::new(AtomicUsize::new(0));
    let mut receivers = BTreeMap::new();

    // Survivor: a quiet actor registers it inline. It receives one UPDATE
    // per joiner route, so its channel holds the largest fleet below.
    let (out_tx, out_rx) = mpsc::channel(1_024);
    manager.handle_update(encoder(SURVIVOR, 1, 4_096, &probes, &reuses));
    manager.handle_update(peer_up(SURVIVOR, 65_001, ipv4_sendable(), None, out_tx));
    receivers.insert(IpAddr::V4(SURVIVOR), out_rx);

    let mut table = vec![
        route(1, SOURCE, vec![]),
        route(2, SOURCE, vec![]),
        route(3, SOURCE, vec![]),
    ];
    table.extend_from_slice(extra);
    manager.handle_update(announce(SOURCE, table));
    drain_route_chunks(&mut manager);

    // Queued actor work makes every joiner's registration defer.
    tx.try_send(announce(SOURCE, vec![])).unwrap();
    for (index, joiner) in joiners.iter().enumerate() {
        let peer = IpAddr::V4(joiner.addr);
        if joiner.role.is_some() {
            manager.handle_update(RibUpdate::SetPeerExportContext {
                peer,
                session_id: SESSION,
                local_role: joiner.role,
            });
        }
        if joiner.rs_asn.is_some() {
            manager.handle_update(RibUpdate::SetPeerRsControl {
                peer,
                session_id: SESSION,
                rs_control_asn: joiner.rs_asn,
            });
        }
        manager.handle_update(encoder(
            joiner.addr,
            u64::try_from(index).unwrap() + 2,
            joiner.max_len,
            &probes,
            &reuses,
        ));
        let (out_tx, out_rx) = mpsc::channel(64);
        manager.handle_update(peer_up(
            joiner.addr,
            joiner.asn,
            joiner.sendable.clone(),
            joiner.export_policy.clone(),
            out_tx,
        ));
        assert!(manager.pending_initial_registrations.contains(&peer));
        receivers.insert(peer, out_rx);
    }
    // Each joiner's own route imports (and reaches the survivor) while every
    // joiner's table is still pending; joiner tables replay it to the others.
    for (index, joiner) in joiners.iter().enumerate() {
        let index = u16::try_from(index).unwrap();
        let prefix = Ipv4Prefix::new(
            Ipv4Addr::new(
                10,
                201 + u8::try_from(index / 256).unwrap(),
                u8::try_from(index % 256).unwrap(),
                0,
            ),
            24,
        );
        manager.handle_update(announce(joiner.addr, vec![make_route(prefix, joiner.addr)]));
        drain_route_chunks(&mut manager);
    }
    assert!(!manager.drain_ready_updates().await);

    let dead_rx = dead.map(|peer| {
        Arc::new(Mutex::new(Some(
            receivers.remove(&IpAddr::V4(peer)).expect("dead joiner"),
        )))
    });
    if let Some(dead_rx) = &dead_rx {
        let dead_rx = Arc::clone(dead_rx);
        let hook: Arc<dyn Fn(&'static str) + Send + Sync> =
            Arc::new(move |_| drop(dead_rx.lock().unwrap().take()));
        manager.replacement_readiness_test_hook = Some(hook);
    }
    manager.advance_pending_initial_registration();
    let first_turn_tag_scans = manager.join_cohort_tag_scans;
    manager.replacement_readiness_test_hook = None;
    if let Some(dead_rx) = dead_rx {
        assert!(
            dead_rx.lock().unwrap().is_none(),
            "the dead joiner's session must die inside the first advance"
        );
    }
    let first_turn = joiners
        .iter()
        .map(|joiner| joiner.addr)
        .filter(|addr| {
            manager
                .outbound_session_ids
                .contains_key(&IpAddr::V4(*addr))
        })
        .collect();
    while !manager.pending_initial_registrations.is_empty() {
        manager.advance_pending_initial_registration();
    }

    let mut raw = BTreeMap::new();
    let mut streams = BTreeMap::new();
    for (peer, mut receiver) in receivers {
        let mut updates = Vec::new();
        while let Ok(update) = receiver.try_recv() {
            updates.push(update);
        }
        streams.insert(peer, updates.iter().map(normalize).collect());
        raw.insert(peer, updates);
    }
    Run {
        manager,
        streams,
        raw,
        first_turn,
        first_turn_tag_scans,
        probes: probes.load(Ordering::Relaxed),
        reuses: reuses.load(Ordering::Relaxed),
    }
}

/// The joiner's initial table: exactly one route-bearing envelope, then
/// exactly one `EoR` envelope, nothing after.
fn assert_table_then_eor(run: &Run, peer: Ipv4Addr) -> &OutboundRouteUpdate {
    assert_table_then_families(run, peer, &ipv4_sendable())
}

fn assert_table_then_families<'a>(
    run: &'a Run,
    peer: Ipv4Addr,
    families: &[(Afi, Safi)],
) -> &'a OutboundRouteUpdate {
    let updates = &run.raw[&IpAddr::V4(peer)];
    assert_eq!(updates.len(), 2, "{peer}: one table envelope and one EoR");
    assert!(!updates[0].announce.is_empty() && updates[0].end_of_rib.is_empty());
    assert!(updates[1].announce.is_empty());
    assert_eq!(updates[1].end_of_rib, families, "{peer}: EoR last");
    &updates[0]
}

/// K same-profile joiners (each the source of a route the others must
/// receive) complete in ONE advance from one shared payload and encode cell,
/// with transport-side own-source exclusion, and produce exactly the
/// per-peer oracle's streams. A dual-stack joiner queued among them has a
/// different update-group key: it stays queued for a later turn.
///
/// Dropping the sendable-family comparison from cohort admission makes the
/// `first_turn` assertion red (the dual-stack joiner is taken; its installed
/// membership then sends it down the ordinary path).
#[tokio::test]
async fn deferred_same_group_joiners_share_one_replay_like_ungrouped_oracle() {
    let mut mixed = joiner(4, 65_104);
    mixed.sendable = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
    let joiners = vec![
        joiner(1, 65_101),
        joiner(2, 65_102),
        mixed.clone(),
        joiner(3, 65_103),
    ];
    let grouped = run(false, &joiners, &[], None).await;
    let oracle = run(true, &joiners, &[], None).await;
    assert_eq!(grouped.streams, oracle.streams);

    let cohort = [joiners[0].addr, joiners[1].addr, joiners[3].addr];
    assert_eq!(grouped.first_turn, cohort.to_vec());
    assert_eq!(oracle.first_turn, vec![joiners[0].addr]);
    assert!(grouped.manager.pending_initial_registrations.is_empty());

    let tables: Vec<_> = cohort
        .iter()
        .map(|peer| assert_table_then_eor(&grouped, *peer))
        .collect();
    for (table, peer) in tables.iter().zip(cohort) {
        assert_eq!(table.announce_source_exclusion, Some(IpAddr::V4(peer)));
        assert!(Arc::ptr_eq(&table.announce, &tables[0].announce));
        assert!(Arc::ptr_eq(
            table.shared_group_encode.as_ref().expect("shared encode"),
            tables[0].shared_group_encode.as_ref().unwrap()
        ));
        // Three source routes plus the other two cohort members' routes and
        // the dual-stack joiner's (all four joiners announced before any
        // table was sent).
        assert_eq!(normalize(table).announce.len(), 6);
    }
    let mixed_table = assert_table_then_families(&grouped, mixed.addr, &mixed.sendable);
    assert!(mixed_table.shared_group_encode.is_none());
    assert!(mixed_table.announce_source_exclusion.is_none());
    // One exact-export probe pass serves the cohort; each later member reuses
    // it through the snapshot-equivalence proof with one maximum length.
    assert_eq!(grouped.reuses, 2);
    assert_eq!(oracle.reuses, 0);
    assert!(grouped.probes < oracle.probes);
}

/// RFC 7947 control: an rs-control joiner whose table carries a control-form
/// community for its RS ASN gets a per-target replay (here: one route
/// suppressed toward it), so it must not take the shared payload. With an
/// untagged table it is admitted and matches the oracle (the rewrite is
/// inert).
///
/// Making the RS-ASN tag check always admit makes the tagged case red: the
/// suppressed route reaches the rs-control joiner.
#[tokio::test]
async fn rs_control_joiner_with_tagged_table_keeps_its_own_replay() {
    let joiners = vec![joiner(1, 65_101), rs_joiner(2, 65_102), joiner(3, 65_103)];
    for tag_asn in [Some(65_102), None] {
        let extra: Vec<_> = tag_asn
            .map(|asn| route(4, SOURCE, vec![asn]))
            .into_iter()
            .collect();
        let grouped = run(false, &joiners, &extra, None).await;
        let oracle = run(true, &joiners, &extra, None).await;
        assert_eq!(grouped.streams, oracle.streams, "tag {tag_asn:?}");
        let expected_first: Vec<_> = if tag_asn.is_some() {
            vec![joiners[0].addr, joiners[2].addr]
        } else {
            joiners.iter().map(|joiner| joiner.addr).collect()
        };
        assert_eq!(grouped.first_turn, expected_first, "tag {tag_asn:?}");
        let rs_table = assert_table_then_eor(&grouped, joiners[1].addr);
        assert_eq!(
            rs_table.shared_group_encode.is_some(),
            tag_asn.is_none(),
            "tag {tag_asn:?}"
        );
        if tag_asn.is_some() {
            assert!(
                !rs_table
                    .announce
                    .iter()
                    .any(|route| route.prefix == route_prefix(4)),
                "suppressed toward its target ASN"
            );
        }
    }
}

/// A cohort member whose session dies after the cohort was admitted (its
/// receiver drops at the first readiness checkpoint of the shared pass)
/// fails only its own commit, exactly like the per-peer path, and every
/// other member still receives its full table and `EoR` from the shared
/// payload, identical to the oracle.
#[tokio::test]
async fn dead_cohort_member_does_not_stall_or_corrupt_the_others() {
    let joiners = vec![joiner(1, 65_101), joiner(2, 65_102), joiner(3, 65_103)];
    let dead = joiners[1].addr;
    let grouped = run(false, &joiners, &[], Some(dead)).await;
    let oracle = run(true, &joiners, &[], Some(dead)).await;
    assert_eq!(grouped.streams, oracle.streams);
    assert_eq!(
        grouped.first_turn,
        joiners.iter().map(|joiner| joiner.addr).collect::<Vec<_>>()
    );
    for run in [&grouped, &oracle] {
        // The closed channel fails the dead member's commit; its dirty
        // state is dropped rather than re-marked (its PeerDown cleans up).
        let dead = IpAddr::V4(dead);
        assert!(run.manager.outbound_channel_gone(dead));
        assert!(run.manager.dirty_peers.is_empty());
        assert!(run.manager.pending_initial_registrations.is_empty());
    }
    for peer in [joiners[0].addr, joiners[2].addr] {
        let table = assert_table_then_eor(&grouped, peer);
        assert!(table.shared_group_encode.is_some());
    }
}

/// The cohort bound counts the leader: with 64 joiners queued, one turn
/// completes all 64 registrations; with 65, the 65th stays queued for the
/// next turn, and every joiner still gets the oracle's stream.
///
/// Admitting `MAX_JOIN_COHORT` members besides the leader makes the 65-joiner
/// case red (65 registrations in one turn).
#[tokio::test]
async fn cohort_bound_counts_the_leader() {
    for queued in [64, 65] {
        let joiners = fleet(queued);
        let grouped = run(false, &joiners, &[], None).await;
        let expected: Vec<_> = joiners.iter().take(64).map(|joiner| joiner.addr).collect();
        assert_eq!(grouped.first_turn, expected, "{queued} queued");
        assert!(grouped.manager.pending_initial_registrations.is_empty());
        let oracle = run(true, &joiners, &[], None).await;
        assert_eq!(grouped.streams, oracle.streams, "{queued} queued");
        for joiner in &joiners {
            assert_table_then_eor(&grouped, joiner.addr);
        }
    }
}

/// A reconnect burst of route-server members, each with its own RS ASN, on an
/// untagged table: admission reads the group table's control tags ONCE per
/// turn, whatever the number of distinct RS ASNs, and examines a bounded
/// prefix of the queue. A same-profile joiner queued behind more than that
/// many mismatched joiners stays queued.
///
/// The per-RS-ASN table scan this replaced makes the scan-count assertion red
/// (one scan per distinct RS ASN); examining the whole queue makes the tail
/// assertion red.
#[tokio::test]
async fn cohort_admission_work_is_bounded_per_turn() {
    let mut joiners = fleet(64);
    for (index, joiner) in joiners.iter_mut().enumerate() {
        joiner.rs_asn = Some(64_600 + u32::try_from(index).unwrap());
    }
    let grouped = run(false, &joiners, &[], None).await;
    assert_eq!(grouped.first_turn_tag_scans, 1);
    assert_eq!(
        grouped.first_turn,
        joiners.iter().map(|joiner| joiner.addr).collect::<Vec<_>>()
    );

    // Leader, then a full examination window of dual-stack joiners, then one
    // joiner sharing the leader's profile.
    let mut joiners = fleet(MAX_JOIN_COHORT_EXAMINED + 2);
    for joiner in &mut joiners[1..=MAX_JOIN_COHORT_EXAMINED] {
        joiner.sendable = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
    }
    let grouped = run(false, &joiners, &[], None).await;
    assert_eq!(grouped.first_turn, vec![joiners[0].addr]);
    assert!(grouped.manager.pending_initial_registrations.is_empty());
    let oracle = run(true, &joiners, &[], None).await;
    assert_eq!(grouped.streams, oracle.streams);
}
