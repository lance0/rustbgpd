//! Cell 4: healthy-lag and restart-during-dump probes over the in-process
//! RIB fanout seam. Each counts dirty episodes (a transition of the RIB's
//! dirty-peer set from empty to non-empty) and the rows a receiver queued.
//! Receivers stand in for session tasks by dequeuing envelopes; no wire.

use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use rustbgpd_policy::{NeighborSetMatch, PolicyChain, PolicyStatement};
use rustbgpd_rib::route::{EvpnRibRoute, Route, RouteOrigin};
use rustbgpd_rib::update::{OutboundRouteUpdate, RibUpdate};
use rustbgpd_rib::{AttrSet, PeerId, RibManager};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_transport::{fanout_bench_export_encoder, fanout_bench_route_server_export_encoder};
use rustbgpd_wire::{
    Afi, AsPath, AsPathSegment, EthernetTagId, EvpnImet, EvpnRoute, Ipv4Prefix, Origin,
    PathAttribute, Prefix, RouteDistinguisher, RpkiValidation, Safi,
};
use serde_json::{json, Value};
use tokio::sync::mpsc;

const TABLE: usize = 4_096;
const PASS: usize = 1_024;
const CHANNEL_CAP: usize = 4_096;
const SOURCE: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 1);
const SECOND: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 2);
const FRESH_BASE: usize = 1_000_000;

fn attributes(med: u32) -> Arc<AttrSet> {
    AttrSet::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65_000, 65_100])],
        }),
        PathAttribute::NextHop(SOURCE),
        PathAttribute::LocalPref(100),
        PathAttribute::Med(med),
    ])
}

fn unicast_route(index: usize, attrs: &Arc<AttrSet>, source: Ipv4Addr) -> Route {
    let i = u32::try_from(index).expect("index fits u32");
    Route {
        prefix: Prefix::V4(Ipv4Prefix::new(
            Ipv4Addr::from(0x0a00_0000_u32 + (i << 8)),
            24,
        )),
        next_hop: IpAddr::V4(source),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: PeerId::from_addr(IpAddr::V4(source)),
        attributes: Arc::clone(attrs),
        received_at: rustbgpd_rib::route::ReceivedAt::now(),
        origin_type: RouteOrigin::Ebgp,
        peer_router_id: source,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        received_as_path: None,
        aspa_context: rustbgpd_rib::route::AspaContextId::DEFAULT,
    }
}

fn evpn_route(index: usize, attrs: &Arc<AttrSet>) -> EvpnRibRoute {
    EvpnRibRoute {
        route: EvpnRoute::Imet(EvpnImet {
            rd: RouteDistinguisher([0, 0, 0xfd, 0xe8, 0, 0, 0, 100]),
            ethernet_tag: EthernetTagId(u32::try_from(index + 1).expect("tag fits u32")),
            originator_ip: IpAddr::V4(SOURCE),
        }),
        next_hop: IpAddr::V4(SOURCE),
        link_local_next_hop: None,
        peer: PeerId::from_addr(IpAddr::V4(SOURCE)),
        attributes: Arc::clone(attrs),
        received_at: Instant::now(),
        origin_type: RouteOrigin::Ebgp,
        peer_router_id: SOURCE,
        is_stale: false,
        is_llgr_stale: false,
    }
}

fn update(evpn: bool, source: Ipv4Addr, routes: Vec<usize>, med: u32) -> RibUpdate {
    let attrs = attributes(med);
    let (announced, evpn_announced) = if evpn {
        (
            Vec::new(),
            routes.iter().map(|&i| evpn_route(i, &attrs)).collect(),
        )
    } else {
        (
            routes
                .iter()
                .map(|&i| unicast_route(i, &attrs, source))
                .collect(),
            Vec::new(),
        )
    };
    RibUpdate::RoutesReceived {
        peer: PeerId::from_addr(IpAddr::V4(source)),
        session_id: 0,
        announced,
        withdrawn: Vec::new(),
        flowspec_announced: Vec::new(),
        flowspec_withdrawn: Vec::new(),
        evpn_announced,
        evpn_withdrawn: Vec::new(),
        validated_with: None,
    }
}

/// Permits everything but names a neighbor set, which keeps unicast peers
/// out of update groups.
fn peer_context_export_chain() -> PolicyChain {
    let mut entry = PolicyStatement {
        prefix: None,
        ge: None,
        le: None,
        action: rustbgpd_policy::PolicyAction::Deny,
        match_community: Vec::new(),
        match_as_path: None,
        match_neighbor_set: None,
        match_route_type: None,
        match_evpn_route_type: None,
        match_rpki_validation: None,
        match_aspa_validation: None,
        match_as_path_length_ge: None,
        match_as_path_length_le: None,
        match_local_pref_ge: None,
        match_local_pref_le: None,
        match_med_ge: None,
        match_med_le: None,
        match_next_hop: None,
        modifications: rustbgpd_policy::RouteModifications::default(),
    };
    entry.match_neighbor_set = Some(NeighborSetMatch {
        addresses: Vec::new(),
        remote_asns: vec![65_099],
        peer_groups: Vec::new(),
    });
    PolicyChain::new(vec![rustbgpd_policy::Policy {
        entries: vec![entry],
        default_action: rustbgpd_policy::PolicyAction::Permit,
    }])
}

fn manager(metrics: BgpMetrics) -> (RibManager, mpsc::Sender<RibUpdate>, mpsc::Sender<RibUpdate>) {
    let (tx, rx) = mpsc::channel::<RibUpdate>(64);
    let (qtx, qrx) = mpsc::channel::<RibUpdate>(16);
    let manager = RibManager::new(
        rx,
        qrx,
        None,
        Some(Ipv4Addr::new(10, 255, 255, 255)),
        metrics,
    );
    (manager, tx, qtx)
}

fn rows(envelope: &OutboundRouteUpdate) -> usize {
    envelope.announce.len()
        + envelope.withdraw.len()
        + envelope.evpn_announce.len()
        + envelope.evpn_withdraw.len()
}

/// Rows queued per receiver, draining every receiver.
fn drain_rows(receivers: &mut [mpsc::Receiver<OutboundRouteUpdate>]) -> usize {
    let mut peak = 0;
    for rx in receivers {
        let mut queued = 0;
        while let Ok(envelope) = rx.try_recv() {
            queued += rows(&envelope);
        }
        peak = peak.max(queued);
    }
    peak
}

/// Counts transitions of the dirty-peer set from empty to non-empty.
#[derive(Default)]
struct Episodes {
    count: usize,
    dirty: bool,
}

impl Episodes {
    fn observe(&mut self, manager: &RibManager) {
        let dirty = manager.bench_adj_rib_out_fanout_receipt().dirty_peers > 0;
        self.count += usize::from(dirty && !self.dirty);
        self.dirty = dirty;
    }
}

/// Receivers stop draining for `stall` while 1,024-key passes keep
/// arriving, then drain everything; three cycles.
fn lag_stall(metrics: BgpMetrics, evpn: bool, peers: usize, stall: Duration) -> Value {
    let (mut manager, tx, _qtx) = manager(metrics);
    manager.bench_register_restarted_source(PeerId::from_addr(IpAddr::V4(SOURCE)));
    let mut receivers = if evpn {
        manager.bench_register_unicast_route_server_peers(
            peers,
            &[(Afi::Ipv4, Safi::Unicast), (Afi::L2Vpn, Safi::Evpn)],
            false,
            CHANNEL_CAP,
            |_| fanout_bench_route_server_export_encoder(65_001),
        )
    } else {
        manager.bench_register_peers(
            peers,
            Some(&peer_context_export_chain()),
            true,
            CHANNEL_CAP,
            fanout_bench_export_encoder,
        )
    };
    for start in (0..TABLE).step_by(PASS) {
        tx.try_send(update(evpn, SOURCE, (start..start + PASS).collect(), 50))
            .expect("seed fits the channel");
        manager.bench_drain_primary_updates();
    }
    drain_rows(&mut receivers);
    let mut episodes = Episodes::default();
    let (mut passes, mut peak_envelopes, mut peak_rows) = (Vec::new(), 0, 0);
    let (mut pass_time, mut total_passes, mut round) = (Duration::ZERO, 0, 0_usize);
    for _ in 0..3 {
        let started = Instant::now();
        let mut cycle = 0;
        while started.elapsed() < stall {
            round += 1;
            let start = (round * PASS) % TABLE;
            let med = 100 + u32::try_from(round).expect("round fits u32");
            tx.try_send(update(evpn, SOURCE, (start..start + PASS).collect(), med))
                .expect("pass fits the channel");
            let pass = Instant::now();
            manager.bench_drain_primary_updates();
            pass_time += pass.elapsed();
            cycle += 1;
            episodes.observe(&manager);
            peak_envelopes =
                peak_envelopes.max(receivers.iter().map(mpsc::Receiver::len).max().unwrap_or(0));
        }
        peak_rows = peak_rows.max(drain_rows(&mut receivers));
        total_passes += cycle;
        passes.push(cycle);
    }
    json!({
        "cell": "lag_stall",
        "shape": if evpn { "evpn_private" } else { "unicast_private" },
        "peers": peers,
        "stall_ms": stall.as_millis(),
        "pass_keys": PASS,
        "passes_per_cycle": passes,
        "mean_pass_ms": pass_time.as_secs_f64() * 1e3 / total_passes.max(1) as f64,
        "peak_queued_envelopes": peak_envelopes,
        "peak_queued_rows_per_receiver": peak_rows,
        "dirty_episodes": episodes.count,
    })
}

/// `peers` private peers join while a second source dumps 100k routes over a
/// 100k-route table; the second half of the dump queues behind their
/// initial tables without draining.
fn restart_during_dump(metrics: BgpMetrics, peers: usize) -> Value {
    const DUMP: usize = 100_000;
    let (mut manager, tx, _qtx) = manager(metrics);
    manager.bench_register_restarted_source(PeerId::from_addr(IpAddr::V4(SOURCE)));
    manager.bench_register_restarted_source(PeerId::from_addr(IpAddr::V4(SECOND)));
    for start in (0..DUMP).step_by(PASS) {
        tx.try_send(update(
            false,
            SOURCE,
            (start..(start + PASS).min(DUMP)).collect(),
            50,
        ))
        .expect("dump fits the channel");
        manager.bench_drain_primary_updates();
    }
    let second = |start: usize, end: usize| {
        update(
            false,
            SECOND,
            (FRESH_BASE + start..FRESH_BASE + end).collect(),
            50,
        )
    };
    let started = Instant::now();
    for start in (0..DUMP / 2).step_by(PASS) {
        tx.try_send(second(start, (start + PASS).min(DUMP / 2)))
            .expect("dump fits the channel");
        manager.bench_drain_primary_updates();
    }
    let joined = Instant::now();
    let mut receivers = join_undrained(&mut manager, &tx, peers);
    let join_ms = joined.elapsed().as_secs_f64() * 1e3;
    // The tail must queue behind each receiver's initial table: every
    // receiver still holds its initial-table envelopes here.
    let initial_envelopes = receivers.iter().map(mpsc::Receiver::len).min().unwrap_or(0);
    assert!(
        initial_envelopes > 0,
        "initial tables were drained before the tail"
    );
    let mut episodes = Episodes::default();
    let mut peak_envelopes = 0;
    let tail = Instant::now();
    for start in (DUMP / 2..DUMP).step_by(PASS) {
        tx.try_send(second(start, (start + PASS).min(DUMP)))
            .expect("dump fits the channel");
        manager.bench_drain_primary_updates();
        episodes.observe(&manager);
        peak_envelopes =
            peak_envelopes.max(receivers.iter().map(mpsc::Receiver::len).max().unwrap_or(0));
    }
    let tail_ms = tail.elapsed().as_secs_f64() * 1e3;
    // Every receiver must still hold its whole initial table behind which
    // the tail queued.
    let mut least = usize::MAX;
    let mut peak_rows = 0;
    for rx in &mut receivers {
        let mut queued = 0;
        while let Ok(envelope) = rx.try_recv() {
            queued += rows(&envelope);
        }
        least = least.min(queued);
        peak_rows = peak_rows.max(queued);
    }
    assert!(
        least >= DUMP + DUMP / 2,
        "a receiver queued {least} rows, fewer than its initial table"
    );
    json!({
        "cell": "restart_during_dump",
        "peers": peers,
        "table": DUMP,
        "second_dump": DUMP,
        "join_ms": join_ms,
        "queued_tail_ms": tail_ms,
        "total_ms": started.elapsed().as_secs_f64() * 1e3,
        "peak_queued_envelopes": peak_envelopes,
        "peak_queued_rows_per_receiver": peak_rows,
        "initial_envelopes_queued_at_tail": initial_envelopes,
        "dirty_episodes": episodes.count,
        "ungrouped_peers": manager.bench_adj_rib_out_fanout_receipt().ungrouped_peers,
    })
}

/// Register `peers` private RR clients through the production `PeerUp`
/// path, leaving every initial-table envelope queued (unlike
/// `bench_register_peers`, which drains them).
fn join_undrained(
    manager: &mut RibManager,
    tx: &mpsc::Sender<RibUpdate>,
    peers: usize,
) -> Vec<mpsc::Receiver<OutboundRouteUpdate>> {
    let mut receivers = Vec::with_capacity(peers);
    for index in 0..peers {
        let peer = RibManager::bench_peer_address(index);
        let session_id = u64::try_from(index).expect("index fits u64") + 1;
        let (outbound_tx, outbound_rx) = mpsc::channel(CHANNEL_CAP);
        tx.try_send(RibUpdate::SetPeerExportEncoder {
            peer,
            session_id,
            encoder: fanout_bench_export_encoder(),
        })
        .expect("registration fits the channel");
        tx.try_send(RibUpdate::PeerUp {
            supersedes: None,
            peer,
            session_id,
            peer_asn: 64_512,
            peer_router_id: Ipv4Addr::new(192, 0, 2, 1),
            outbound_tx,
            export_policy: Some(peer_context_export_chain()),
            sendable_families: vec![(Afi::Ipv4, Safi::Unicast)],
            is_ebgp: false,
            route_reflector_client: true,
            orr_vantage: None,
            per_client_best: false,
            interpret_rfc1997: true,
            add_path_send_families: Vec::new(),
            add_path_send_max: 0,
            negotiated_orf_recv: Vec::new(),
            negotiated_llgr_families: Vec::new(),
        })
        .expect("registration fits the channel");
        manager.bench_drain_primary_updates();
        manager.bench_complete_deferred_registrations();
        receivers.push(outbound_rx);
    }
    receivers
}

/// Run every probe cell and write `probes.json`.
pub fn run(
    harness: &tokio::runtime::Runtime,
    output: &Path,
    reduced: bool,
    correctness_only: bool,
) -> Result<bool> {
    let metrics = BgpMetrics::new();
    // The in-process probes run synchronously outside any Tokio runtime.
    let sampling = {
        let _entered = harness.enter();
        crate::credit::MemorySampling::start(metrics.clone())
    };
    let fleets: &[usize] = if reduced { &[16] } else { &[150, 1_000] };
    let stalls: &[Duration] = if reduced {
        &[Duration::from_millis(200)]
    } else {
        &[Duration::from_millis(500), Duration::from_secs(2)]
    };
    let mut cells = Vec::new();
    for evpn in [false, true] {
        for &peers in fleets {
            for &stall in stalls {
                let cell = lag_stall(metrics.clone(), evpn, peers, stall);
                println!("probe {cell}");
                cells.push(cell);
            }
        }
    }
    let cell = restart_during_dump(metrics.clone(), if reduced { 16 } else { 150 });
    println!("probe {cell}");
    cells.push(cell);
    let memory = harness.block_on(sampling.finish())?;
    let clean = cells.iter().all(|cell| cell["dirty_episodes"] == 0);
    let result = json!({
        "schema": "rrtransport-credit/1",
        "cell": "probes",
        "mode": if reduced || correctness_only { "correctness" } else { "measured" },
        "probes": cells,
        "memory": memory,
    });
    std::fs::create_dir_all(output)?;
    std::fs::write(
        output.join("probes.json"),
        serde_json::to_string_pretty(&result)? + "\n",
    )?;
    Ok(clean)
}
