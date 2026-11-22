//! Measure one non-GR source loss through the production RIB actor. Each
//! receiver checks its BGP stream on a separate loopback connection.

use super::source_departure_receivers::ReceiverGroup;
use super::{
    client_addr, empty_routes_received, flood_prefix, invalid_stat, route, source_addr, BATCH,
};
use rustbgpd_rib::route::{FlowSpecRoute, RouteOrigin};
use rustbgpd_rib::update::{OutboundRouteUpdate, RibUpdate};
use rustbgpd_rib::{AttrSet, PeerId, RibManager, SourceDepartureProbe};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{
    Afi, AsPath, ExtendedCommunity, FlowSpecAction, FlowSpecComponent, FlowSpecPrefix,
    FlowSpecRule, Ipv4Prefix, Origin, PathAttribute, Prefix, Safi,
};
use std::{
    io,
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    thread,
    time::Instant,
};
use tokio::runtime::{Builder, Handle};
use tokio::sync::{mpsc, oneshot};

const SESSION: u64 = 1;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Grouped,
    Private,
    FlowSpec,
}

fn parse_mode(name: &str) -> io::Result<Mode> {
    match name {
        "grouped-unicast" => Ok(Mode::Grouped),
        "private-unicast" => Ok(Mode::Private),
        "private-flowspec" => Ok(Mode::FlowSpec),
        _ => Err(invalid_stat(format!(
            "unknown source-departure mode {name:?}"
        ))),
    }
}

/// Run one trial. Only a receiver inventory mismatch is a behavioral `FAIL`;
/// any other error leaves the instrument unqualified.
pub(super) fn main(args: &[String]) {
    if let Err(error) = run(args) {
        if error.to_string().contains("receiver inventory mismatch:") {
            eprintln!("FAIL: source-departure: {error}");
        } else {
            eprintln!("source-departure: {error}");
        }
        std::process::exit(1);
    }
}

fn run(args: &[String]) -> io::Result<()> {
    let [name, clients, rows] = args else {
        return Err(invalid_stat("usage: rrharness source-departure <grouped-unicast|private-unicast|private-flowspec> <receivers> <rows>"));
    };
    let mode = parse_mode(name)?;
    let clients = clients.parse::<u32>().map_err(invalid_number)?;
    let rows = rows.parse::<usize>().map_err(invalid_number)?;
    if clients == 0 || clients > (1 << 22) || rows == 0 || rows > (236 << 16) {
        return Err(invalid_stat(
            "receivers or rows outside fixture address space",
        ));
    }
    Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?
        .block_on(trial(name, mode, clients, rows))
}

fn invalid_number(error: std::num::ParseIntError) -> io::Error {
    invalid_stat(format!("invalid positive integer: {error}"))
}

fn source(index: u32) -> PeerId {
    PeerId::from_addr(IpAddr::V4(source_addr(index)))
}

fn sentinel() -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 254), 32)
}

fn peer_up(
    peer: PeerId,
    outbound_tx: mpsc::Sender<OutboundRouteUpdate>,
    mode: Option<Mode>,
) -> RibUpdate {
    let IpAddr::V4(peer_router_id) = peer.addr() else {
        unreachable!()
    };
    let sendable_families = match mode {
        None => Vec::new(),
        Some(Mode::FlowSpec) => vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv4, Safi::FlowSpec)],
        Some(_) => vec![(Afi::Ipv4, Safi::Unicast)],
    };
    RibUpdate::PeerUp {
        supersedes: None,
        peer,
        session_id: SESSION,
        peer_asn: 64512,
        peer_router_id,
        outbound_tx,
        export_policy: (mode == Some(Mode::Private))
            .then(SourceDepartureProbe::private_export_policy),
        sendable_families,
        is_ebgp: false,
        route_reflector_client: mode.is_some(),
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        add_path_send_families: Vec::new(),
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    }
}

fn received(peer: PeerId, announced: Vec<rustbgpd_rib::route::Route>) -> RibUpdate {
    let mut update = empty_routes_received(peer.addr(), announced);
    let RibUpdate::RoutesReceived { session_id, .. } = &mut update else {
        unreachable!()
    };
    *session_id = SESSION;
    update
}

fn seed(mode: Mode, indices: std::ops::Range<usize>) -> RibUpdate {
    let src = source_addr(0);
    if mode != Mode::FlowSpec {
        return received(
            source(0),
            indices
                .map(|i| route(flood_prefix(i as u64), src, 100))
                .collect(),
        );
    }
    let attrs = AttrSet::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath { segments: vec![] }),
        PathAttribute::LocalPref(100),
        PathAttribute::ExtendedCommunities(vec![ExtendedCommunity::from_flowspec_action(
            &FlowSpecAction::TrafficRateBytes {
                asn: 64512,
                rate: 0.0,
            },
        )]),
    ]);
    let mut update = received(source(0), Vec::new());
    let RibUpdate::RoutesReceived {
        flowspec_announced, ..
    } = &mut update
    else {
        unreachable!()
    };
    *flowspec_announced = indices
        .map(|i| FlowSpecRoute {
            rule: FlowSpecRule {
                components: vec![FlowSpecComponent::DestinationPrefix(FlowSpecPrefix::V4(
                    flood_prefix(i as u64),
                ))],
            },
            afi: Afi::Ipv4,
            rd: None,
            peer: source(0),
            attributes: Arc::clone(&attrs),
            received_at: Instant::now(),
            origin_type: RouteOrigin::Ibgp,
            peer_router_id: src,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
        })
        .collect();
    update
}

async fn send(tx: &mpsc::Sender<RibUpdate>, update: RibUpdate) -> io::Result<()> {
    tx.send(update)
        .await
        .map_err(|_| invalid_stat("RIB input closed"))
}

async fn fence(tx: &mpsc::Sender<RibUpdate>) -> io::Result<usize> {
    let (reply, answer) = oneshot::channel();
    send(tx, RibUpdate::QueryLocRibCount { reply }).await?;
    answer.await.map_err(|_| invalid_stat("RIB query closed"))
}

async fn verify_peers(
    tx: &mpsc::Sender<RibUpdate>,
    mode: Mode,
    peers: &[PeerId],
) -> io::Result<()> {
    let mut shared = None;
    for &peer in peers {
        let (reply, answer) = oneshot::channel();
        send(tx, RibUpdate::QueryPeerUpdateGroup { peer, reply }).await?;
        let label = answer
            .await
            .map_err(|_| invalid_stat("missing peer group"))?;
        match mode {
            Mode::Grouped if label.starts_with("group:") => {
                if let Some(expected) = &shared {
                    if *expected != label {
                        return Err(invalid_stat("grouped receivers do not share a group"));
                    }
                } else {
                    shared = Some(label);
                }
            }
            Mode::Private if label == "policy_peer_context" => {}
            // FlowSpec export always stages against the receiver-local table,
            // including peers that share their separate unicast sentinel.
            Mode::FlowSpec if !label.is_empty() => {}
            _ => {
                return Err(invalid_stat(format!(
                    "unexpected receiver {peer} group {label:?}"
                )))
            }
        }
    }
    if !outbound_settled(tx).await? {
        return Err(invalid_stat("unsettled initial export"));
    }
    Ok(())
}

async fn outbound_settled(tx: &mpsc::Sender<RibUpdate>) -> io::Result<bool> {
    let (reply, answer) = oneshot::channel();
    send(tx, RibUpdate::TestQueryOutboundHealth { reply }).await?;
    let health = answer
        .await
        .map_err(|_| invalid_stat("missing outbound health"))?;
    Ok(health == (0, 0, 0, 0, 0, 0))
}

#[derive(Default)]
struct RecoveryCounts {
    route_drops: u64,
    dirty_resync_ticks: u64,
    owing_fallbacks: u64,
    owing_flips: u64,
    owed_drain_steps: u64,
    commit_refusals: u64,
    refusals_by_reason: std::collections::BTreeMap<String, u64>,
}

impl RecoveryCounts {
    fn read(metrics: &BgpMetrics) -> Self {
        let mut counts = Self::default();
        for family in metrics.registry().gather() {
            let name = family.name();
            let total = match name {
                "bgp_outbound_route_drops_total" => &mut counts.route_drops,
                "bgp_rib_dirty_resync_total" => &mut counts.dirty_resync_ticks,
                "bgp_rib_outbound_owing_fallback_total" => &mut counts.owing_fallbacks,
                "bgp_rib_outbound_owing_flips_total" => &mut counts.owing_flips,
                "bgp_outbound_commit_refusals_total" => &mut counts.commit_refusals,
                "bgp_rib_outbound_owed_drain_step_seconds" => {
                    counts.owed_drain_steps = family
                        .get_metric()
                        .iter()
                        .map(|sample| sample.get_histogram().get_sample_count())
                        .sum();
                    continue;
                }
                _ => continue,
            };
            for sample in family.get_metric() {
                // All of the counter families here are integer counters.
                let value = sample.get_counter().get_value() as u64;
                *total += value;
                if name == "bgp_outbound_commit_refusals_total" {
                    let reason = sample
                        .get_label()
                        .iter()
                        .find(|label| label.name() == "reason")
                        .expect("commit refusals have a reason label")
                        .value();
                    *counts
                        .refusals_by_reason
                        .entry(reason.to_owned())
                        .or_default() += value;
                }
            }
        }
        counts
    }

    fn verify_initial(&self) -> io::Result<()> {
        if self.route_drops != 0
            || self.dirty_resync_ticks != 0
            || self.owing_fallbacks != 0
            || self.owing_flips != 0
            || self.owed_drain_steps != 0
            || self.commit_refusals != 0
        {
            return Err(invalid_stat(format!(
                "initial export contains recovery work: {}",
                self.receipt()
            )));
        }
        Ok(())
    }

    /// One JSON object. Reason keys are fixed snake_case metric labels.
    fn receipt(&self) -> String {
        let reasons: Vec<String> = self
            .refusals_by_reason
            .iter()
            .map(|(reason, count)| format!("\"{reason}\":{count}"))
            .collect();
        format!(
            "{{\"route_drops\":{},\"dirty_resync_ticks\":{},\"owing_fallbacks\":{},\"owing_flips\":{},\"owed_drain_steps\":{},\"commit_refusals\":{},\"commit_refusals_by_reason\":{{{}}}}}",
            self.route_drops,
            self.dirty_resync_ticks,
            self.owing_fallbacks,
            self.owing_flips,
            self.owed_drain_steps,
            self.commit_refusals,
            reasons.join(",")
        )
    }
}

async fn enqueue(
    runtime: &Handle,
    tx: mpsc::Sender<RibUpdate>,
    probe: Arc<SourceDepartureProbe>,
) -> io::Result<(u64, u64)> {
    let marker = received(source(1), vec![route(sentinel(), source_addr(1), 100)]);
    // This task and the RIB run on one current-thread executor. Both
    // messages enter the same FIFO in one poll, with no scheduling point.
    runtime
        .spawn(async move {
            let started = probe.arm();
            tx.try_send(RibUpdate::PeerDown {
                peer: source(0),
                session_id: SESSION,
            })
            .map_err(|_| invalid_stat("could not queue non-GR departure"))?;
            let queued = probe.now_ns();
            tx.try_send(marker)
                .map_err(|_| invalid_stat("could not queue independent UPDATE"))?;
            Ok((started, queued))
        })
        .await
        .map_err(io::Error::other)?
}

/// No decoded or published row for this long, with no outbound debt, ends
/// the producer stream.
const STREAM_QUIET: std::time::Duration = std::time::Duration::from_secs(10);

/// Return once every receiver converged, a reader stopped, or the RIB owes no
/// outbound work and nothing moved for [`STREAM_QUIET`]. The final table
/// checks then judge the stream: a row the RIB never sent becomes a
/// receiver inventory mismatch instead of a timeout.
async fn wait_for_stream(
    tx: &mpsc::Sender<RibUpdate>,
    receivers: &ReceiverGroup,
    probe: &SourceDepartureProbe,
) -> io::Result<()> {
    let mut last = None;
    let mut since = Instant::now();
    loop {
        let (withdrawn, converged, closed) = receivers.snapshot();
        if converged || closed {
            return Ok(());
        }
        let moved = (withdrawn, probe.snapshot().published_withdrawals);
        if last != Some(moved) {
            last = Some(moved);
            since = Instant::now();
        } else if since.elapsed() >= STREAM_QUIET && outbound_settled(tx).await? {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

async fn trial(name: &str, mode: Mode, clients: u32, rows: usize) -> io::Result<()> {
    let peers: Vec<_> = (0..clients)
        .map(|i| PeerId::from_addr(client_addr(i)))
        .collect();
    let watched = if std::env::var_os("RRHARNESS_BREAK_DEPARTURE_WITNESS").as_deref()
        == Some(std::ffi::OsStr::new("1"))
    {
        Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 253), 32)
    } else {
        sentinel()
    };
    let expected = u64::from(clients) * rows as u64;
    let probe = SourceDepartureProbe::new(
        source(0),
        Prefix::V4(watched),
        source(1),
        peers.clone(),
        mode == Mode::FlowSpec,
        expected,
    );
    let (tx, rx) = mpsc::channel(1024);
    let (qtx, qrx) = mpsc::channel(1);
    let (ready, handle) = oneshot::channel();
    let metrics = BgpMetrics::new();
    let actor_metrics = metrics.clone();
    let on_actor = Arc::clone(&probe);
    let actor = thread::Builder::new()
        .name("ribmgr".into())
        .spawn(move || -> io::Result<()> {
            let runtime = Builder::new_current_thread().enable_all().build()?;
            ready
                .send(runtime.handle().clone())
                .map_err(|_| invalid_stat("driver stopped"))?;
            let manager = RibManager::new(
                rx,
                qrx,
                None,
                Some(Ipv4Addr::new(10, 255, 255, 255)),
                actor_metrics,
            )
            .with_bench_source_departure(Arc::clone(&on_actor));
            runtime.block_on(on_actor.observe_polls(manager.run()));
            Ok(())
        })?;
    let runtime = handle
        .await
        .map_err(|_| invalid_stat("RIB thread did not start"))?;
    let mut receivers = ReceiverGroup::start(&peers, rows, mode == Mode::FlowSpec).await?;
    // Source-only registrations stay connected through completion and have
    // no outbound family. A default/non-GR PeerDown tears the whole table down.
    let mut source_outputs = Vec::with_capacity(2);
    for idx in 0..2 {
        let (sink, output) = mpsc::channel(4);
        send(&tx, peer_up(source(idx), sink, None)).await?;
        source_outputs.push(output);
    }
    for (index, &peer) in peers.iter().enumerate() {
        send(
            &tx,
            RibUpdate::SetPeerExportEncoder {
                peer,
                session_id: SESSION,
                encoder: receivers.encoder(index),
            },
        )
        .await?;
        send(&tx, peer_up(peer, receivers.sender(index), Some(mode))).await?;
    }
    for start in (0..rows).step_by(BATCH) {
        let end = (start + BATCH).min(rows);
        send(&tx, seed(mode, start..end)).await?;
        receivers.wait_seeded_through(end).await?;
    }
    receivers.wait_seeded().await?;
    verify_peers(&tx, mode, &peers).await?;
    RecoveryCounts::read(&metrics).verify_initial()?;
    let (started, queued) = enqueue(&runtime, tx.clone(), Arc::clone(&probe)).await?;
    // Selection is certified separately at the exact Loc-RIB write by the probe.
    wait_for_stream(&tx, &receivers, &probe).await?;
    // A last decoded withdrawal can precede the retry tick which retires
    // an obligation. Keep writers alive until that work has settled and
    // let the TCP readers reject any late duplicates through their EOF.
    while !outbound_settled(&tx).await? {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let final_count = fence(&tx).await?;
    if final_count != 1 {
        return Err(invalid_stat(format!(
            "receiver inventory mismatch: expected only the sentinel in Loc-RIB, got {final_count}"
        )));
    }
    // Schedule behind the actor's poll on its own thread so the longest poll
    // includes the poll that finished the work and excludes actor destruction.
    let on_actor = Arc::clone(&probe);
    let observation = runtime
        .spawn(async move { on_actor.snapshot() })
        .await
        .map_err(io::Error::other)?;
    if mode == Mode::FlowSpec {
        let (reply, answer) = oneshot::channel();
        send(
            &tx,
            RibUpdate::QueryFlowSpecRoutes {
                filter: None,
                reply,
            },
        )
        .await?;
        if !answer
            .await
            .map_err(|_| invalid_stat("FlowSpec Loc-RIB query closed"))?
            .is_empty()
        {
            return Err(invalid_stat(
                "receiver inventory mismatch: FlowSpec Loc-RIB has surviving source rows",
            ));
        }
    }
    // Setup required zero cumulative events, so these are departure deltas.
    let recovery = RecoveryCounts::read(&metrics);
    drop(tx);
    drop(qtx);
    actor
        .join()
        .map_err(|_| invalid_stat("RIB actor thread panicked"))??;
    let observations = receivers.finish().await?;
    let applied = observation
        .applied_ns
        .ok_or_else(|| invalid_stat("missing Loc-RIB application witness"))?;
    let last_published = observation
        .last_withdraw_published_ns
        .ok_or_else(|| invalid_stat("missing RIB withdrawal publication"))?;
    let detach = observation
        .detach_started_ns
        .ok_or_else(|| invalid_stat("missing source detach"))?;
    let selected = observation
        .selection_finished_ns
        .ok_or_else(|| invalid_stat("missing source selection"))?;
    if observation.published_withdrawals != expected || observations.len() != peers.len() {
        return Err(invalid_stat(
            "receiver inventory mismatch: receiver count or published RIB withdrawal count differs",
        ));
    }
    let mut last_wire = 0;
    let mut last_marker = 0;
    for (expected_peer, output) in peers.iter().zip(&observations) {
        if *expected_peer != output.peer
            || output.announcements != rows
            || output.withdrawals != rows
        {
            return Err(invalid_stat(
                "receiver inventory mismatch: unexpected final peer or row counts",
            ));
        }
        last_wire = last_wire.max(probe.timestamp_ns(output.last_withdrawal_at));
        last_marker = last_marker.max(probe.timestamp_ns(output.probe_at));
    }
    if !(started <= queued
        && queued <= detach
        && detach <= selected
        && selected <= applied
        && applied != last_published
        && observation.max_rib_poll_ns > 0
        && last_marker >= applied
        && last_wire >= started)
    {
        return Err(invalid_stat("inconsistent source-departure timestamps"));
    }
    // `name` is one of the three validated mode names.
    println!(
        "{{\"mode\":\"{name}\",\"receivers\":{clients},\"rows\":{rows},\"exact\":true,\"post_departure_recovery\":{},\"departure_queued_ns\":{started},\"update_queued_ns\":{queued},\"detach_started_ns\":{detach},\"selection_finished_ns\":{selected},\"loc_rib_applied_ns\":{applied},\"rib_last_withdrawal_ns\":{last_published},\"rib_withdrawal_rows\":{},\"receiver_last_withdrawal_ns\":{last_wire},\"receiver_last_probe_ns\":{last_marker},\"update_to_applied_ns\":{},\"convergence_ns\":{},\"source_detach_selection_ns\":{},\"max_rib_poll_ns\":{},\"max_withdrawals_per_poll\":{},\"update_applied_before_departure_complete\":{}}}",
        recovery.receipt(),
        observation.published_withdrawals,
        applied - queued,
        last_wire.max(last_marker) - started,
        selected - detach,
        observation.max_rib_poll_ns,
        observation.max_withdrawals_per_poll,
        applied < last_published,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustbgpd_telemetry::reason_labels::OutboundCommitRefusal;

    #[test]
    fn recovery_rejects_a_dirty_seed_and_reports_transient_departure_work() {
        let metrics = BgpMetrics::new();
        let initial = RecoveryCounts::read(&metrics);
        initial.verify_initial().unwrap();
        assert!(initial.receipt().contains("\"commit_refusals\":0,"));
        metrics.record_outbound_commit_refusal("192.0.2.1", OutboundCommitRefusal::OutboundCredit);
        metrics.record_outbound_route_drop("192.0.2.2");
        metrics.record_rib_outbound_owing_flip();
        metrics.record_rib_outbound_owing_fallback();
        metrics.record_rib_dirty_resync("cleared");
        metrics.observe_rib_outbound_owed_drain_step("keyed", std::time::Duration::ZERO);
        let after = RecoveryCounts::read(&metrics);
        assert!(after.verify_initial().is_err());
        assert_eq!(
            after.receipt(),
            "{\"route_drops\":1,\"dirty_resync_ticks\":1,\"owing_fallbacks\":1,\"owing_flips\":1,\"owed_drain_steps\":1,\"commit_refusals\":1,\"commit_refusals_by_reason\":{\"outbound_credit\":1}}"
        );
    }
}
