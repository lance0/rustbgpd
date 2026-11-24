//! Measure unrelated UPDATE delivery during a cold first-member join.
use super::*;
use rustbgpd_policy::{Policy, PolicyAction, PolicyChain, PolicyStatement, RouteModifications};
use tokio::sync::{watch, Notify};

mod inventory;
mod markers;
mod observation;
mod workload;

use inventory::Inventory;
use observation::ReplayObservation;
use workload::Workload;

const TAG: u32 = (64_512 << 16) | 31;
const MARKER_SOURCE: u32 = INGRESS_FLOOD;
/// One message of new prefixes, above every 1,024-entry replay change cap.
// Above the replay scan's 4,096-key repair cap. New prefixes also fall back
// above the 1,024-key sparse admission overlay; only changes to prefixes in the
// joiner's initial universe coalesce into page work.
const BURST_ROWS: usize = 8192;

/// Read and reset the production longest-actor-poll window.
fn poll_max_us(metrics: &BgpMetrics) -> u64 {
    metrics.publish_render_window_maxima();
    metrics
        .registry()
        .gather()
        .into_iter()
        .find(|f| f.name() == "bgp_rib_actor_slice_max_microseconds")
        .and_then(|family| {
            family
                .get_metric()
                .iter()
                .find(|m| m.get_label()[0].value() == "actor_poll")
                .map(|m| m.get_gauge().get_value() as u64)
        })
        .expect("actor_poll slice gauge")
}

fn burst_update() -> RibUpdate {
    let source = source_addr(MARKER_SOURCE);
    let routes = (0..BURST_ROWS)
        .map(|i| {
            let addr = u32::from(Ipv4Addr::new(198, 21, 0, 0)) + i as u32;
            route(Ipv4Prefix::new(Ipv4Addr::from(addr), 32), source, 100)
        })
        .collect();
    empty_routes_received(IpAddr::V4(source), routes)
}

fn export_chain() -> PolicyChain {
    let entry = PolicyStatement {
        prefix: None,
        ge: None,
        le: None,
        action: PolicyAction::Permit,
        match_community: vec![],
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
        modifications: RouteModifications {
            communities_add: vec![TAG],
            ..Default::default()
        },
    };
    PolicyChain::new(vec![Policy {
        entries: vec![entry],
        default_action: PolicyAction::Deny,
    }])
}

fn marker_prefix(seq: u16) -> Ipv4Prefix {
    let [hi, lo] = seq.to_be_bytes();
    Ipv4Prefix::new(Ipv4Addr::new(198, 18, hi, lo), 32)
}

fn peer_up(
    peer: PeerId,
    outbound_tx: mpsc::Sender<OutboundRouteUpdate>,
    policy: Option<PolicyChain>,
) -> RibUpdate {
    RibUpdate::PeerUp {
        supersedes: None,
        peer,
        session_id: 1,
        peer_asn: 64512,
        peer_router_id: Ipv4Addr::new(192, 0, 2, 1),
        outbound_tx,
        export_policy: policy,
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
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Cell {
    Clean,
    Mixed,
    Burst,
    BudgetControl,
}

async fn register(
    tx: &mpsc::Sender<RibUpdate>,
    peer: PeerId,
    tagged: bool,
) -> (Instant, mpsc::Receiver<OutboundRouteUpdate>) {
    tx.send(RibUpdate::SetPeerExportEncoder {
        peer,
        session_id: 1,
        encoder: fanout_bench_export_encoder(),
    })
    .await
    .expect("actor accepts encoder");
    let (outbound, rx) = mpsc::channel(CHANNEL_CAP);
    let up = peer_up(peer, outbound, tagged.then(export_chain));
    let permit = tx.reserve().await.expect("actor accepts registration");
    let admitted = Instant::now();
    permit.send(up);
    (admitted, rx)
}

async fn receive(rx: &mut mpsc::Receiver<OutboundRouteUpdate>) -> io::Result<OutboundRouteUpdate> {
    tokio::time::timeout(CONVERGENCE_TIMEOUT, rx.recv())
        .await
        .map_err(|_| invalid_stat("receiver timed out"))?
        .ok_or_else(|| invalid_stat("outbound receiver closed"))
}

struct Witness {
    inventory: Inventory,
    first_flap: Option<Instant>,
    first_stream: Option<Instant>,
    restored_at: Option<Instant>,
    stream_announces: [Option<Instant>; 8],
    stream_withdrawals: [Option<Instant>; 8],
}

async fn witness(
    mut rx: mpsc::Receiver<OutboundRouteUpdate>,
    mut inventory: Inventory,
    arrivals: mpsc::UnboundedSender<(u16, Instant)>,
    gone: watch::Sender<bool>,
) -> io::Result<Witness> {
    let (mut first_flap, mut first_stream, mut restored_at) = (None, None, None);
    let (mut stream_announces, mut stream_withdrawals) = ([None; 8], [None; 8]);
    loop {
        let update = receive(&mut rx).await?;
        let now = Instant::now();
        let observed = inventory.fold(&update).map_err(invalid_stat)?;
        if observed.flap_change {
            first_flap.get_or_insert(now);
        }
        if observed.stream_change {
            first_stream.get_or_insert(now);
        }
        for (index, (announce, withdraw)) in stream_announces
            .iter_mut()
            .zip(&mut stream_withdrawals)
            .enumerate()
        {
            if observed.stream_announced & (1 << index) != 0 {
                announce.get_or_insert(now);
            }
            if observed.stream_withdrawn & (1 << index) != 0 {
                withdraw.get_or_insert(now);
            }
        }
        if !*gone.borrow() && inventory.flap_gone() {
            gone.send_replace(true);
        }
        if inventory.flap_restored() {
            restored_at.get_or_insert(now);
        }
        for seq in observed.markers {
            arrivals
                .send((seq, now))
                .map_err(|_| invalid_stat("marker train closed"))?;
            if seq == u16::MAX {
                return Ok(Witness {
                    inventory,
                    first_flap,
                    restored_at,
                    first_stream,
                    stream_announces,
                    stream_withdrawals,
                });
            }
        }
    }
}

struct Join {
    inventory: Inventory,
    first: Instant,
    eor: Instant,
    build_poll_us: u64,
    replay_poll_us: u64,
}

async fn joiner(
    mut rx: mpsc::Receiver<OutboundRouteUpdate>,
    mut inventory: Inventory,
    start_churn: oneshot::Sender<()>,
    train_wake: Arc<Notify>,
    stop: watch::Sender<bool>,
    quiet: bool,
    metrics: BgpMetrics,
) -> io::Result<Join> {
    let mut start_churn = Some(start_churn);
    let (mut first, mut eor) = (None, None);
    let (mut build_poll_us, mut replay_poll_us) = (0, 0);
    loop {
        let update = receive(&mut rx).await?;
        let now = Instant::now();
        let observed = inventory.fold(&update).map_err(invalid_stat)?;
        if observed.base_rows > 0 && first.is_none() {
            first = Some(now);
            build_poll_us = poll_max_us(&metrics);
            start_churn
                .take()
                .expect("first page")
                .send(())
                .map_err(|_| invalid_stat("churn worker closed"))?;
            train_wake.notify_one();
        }
        drop(update);
        if observed.eor {
            if quiet {
                inventory.check_quiet_initial()
            } else {
                inventory.check_initial()
            }
            .map_err(invalid_stat)?;
            eor = Some(now);
            replay_poll_us = poll_max_us(&metrics);
            stop.send_replace(true);
        }
        if observed.markers.contains(&u16::MAX) {
            return Ok(Join {
                inventory,
                first: first.ok_or_else(|| invalid_stat("missing first base page"))?,
                eor: eor.ok_or_else(|| invalid_stat("final fence preceded initial family EoR"))?,
                build_poll_us,
                replay_poll_us,
            });
        }
    }
}

pub(super) async fn run(args: &[String]) -> io::Result<()> {
    let [rows, profile, mode] = args else {
        return Err(invalid_stat(
            "usage: rrharness cold-join-churn ROWS plain|policy clean|mixed|burst|budget-control",
        ));
    };
    let rows = rows
        .parse::<usize>()
        .map_err(|_| invalid_stat("invalid route count"))?;
    if !(16_384..=1_000_000).contains(&rows) {
        return Err(invalid_stat(
            "expected 16384 through 1000000 initial routes",
        ));
    }
    let tagged = match profile.as_str() {
        "plain" => false,
        "policy" => true,
        _ => return Err(invalid_stat("expected plain or policy")),
    };
    let cell = match mode.as_str() {
        "clean" => Cell::Clean,
        "mixed" => Cell::Mixed,
        "burst" => Cell::Burst,
        "budget-control" => Cell::BudgetControl,
        _ => return Err(invalid_stat("unknown churn cell")),
    };
    tokio::time::timeout(CONVERGENCE_TIMEOUT, trial(rows, tagged, cell, mode))
        .await
        .map_err(|_| invalid_stat("cold join timed out"))?
}

async fn trial(rows: usize, tagged: bool, cell: Cell, mode: &str) -> io::Result<()> {
    let peer = PeerId::from_addr(client_addr(1));
    let clock = Instant::now();
    let observation = Arc::new(ReplayObservation::new(peer, 1, clock));
    let attach = Arc::clone(&observation);
    let h = setup_with_manager(0, MARKER_SOURCE + 1, move |manager| {
        let manager = if cell == Cell::BudgetControl {
            manager.with_bench_initial_replay_peer_limit(64 * 1024)
        } else {
            manager
        };
        attach.attach(manager)
    })
    .await;
    let workload = Workload::default();
    let base = rows - workload.flap_rows as usize;
    h.inject_flood_block(0, base as u64).await;
    workload.seed(&h.tx).await?;
    h.wait_loc_rib_exact(rows, CONVERGENCE_TIMEOUT).await;
    let make_inventory = |tag| {
        Inventory::new(
            base,
            workload.flap_rows as usize,
            workload.stream_block as usize,
            tag,
        )
        .with_burst(if cell == Cell::Burst { BURST_ROWS } else { 0 })
    };
    let (_, mut wrx) = register(&h.tx, PeerId::from_addr(client_addr(0)), !tagged).await;
    let mut seed = make_inventory(!tagged);
    loop {
        if seed
            .fold(&receive(&mut wrx).await?)
            .map_err(invalid_stat)?
            .eor
        {
            break;
        }
    }
    seed.check_seed().map_err(invalid_stat)?;
    let (arrival_tx, mut arrivals) = mpsc::unbounded_channel();
    let (gone, gone_rx) = watch::channel(false);
    let witness = tokio::spawn(witness(wrx, seed, arrival_tx, gone));
    markers::send(&h.tx, &mut arrivals, 0).await?;
    let (start_churn, first_page) = oneshot::channel();
    let (stop, stopped) = watch::channel(false);
    let prompt = Arc::new(Notify::new());
    poll_max_us(&h.metrics);
    let (start, rx) = register(&h.tx, peer, tagged).await;
    let join = tokio::spawn(joiner(
        rx,
        make_inventory(tagged),
        start_churn,
        Arc::clone(&prompt),
        stop,
        cell != Cell::Mixed,
        h.metrics.clone(),
    ));
    let train = markers::train(h.tx.clone(), arrivals, stopped.clone(), prompt);
    let churn = async {
        first_page
            .await
            .map_err(|_| invalid_stat("receiver closed before first page"))?;
        match cell {
            Cell::Mixed => Ok((Some(workload.run(&h.tx, stopped, gone_rx).await?), None)),
            Cell::Burst => {
                let slot =
                    h.tx.reserve()
                        .await
                        .map_err(|_| invalid_stat("RIB input closed"))?;
                let admitted = Instant::now();
                slot.send(burst_update());
                Ok((None, Some(admitted)))
            }
            Cell::Clean | Cell::BudgetControl => Ok((None, None)),
        }
    };
    let settled = async {
        let ((samples, mut arrivals), churn) = tokio::try_join!(train, churn)?;
        markers::send(&h.tx, &mut arrivals, u16::MAX).await?;
        Ok((samples, churn))
    };
    let (join, witness, (samples, (churn, burst))) = tokio::try_join!(
        async { join.await.map_err(io::Error::other)? },
        async { witness.await.map_err(io::Error::other)? },
        settled,
    )?;
    let last = samples
        .last()
        .ok_or_else(|| invalid_stat("empty marker train"))?
        .seq;
    let lp = if churn.is_some() { 110 } else { 100 };
    join.inventory.check_final(last, lp).map_err(invalid_stat)?;
    witness
        .inventory
        .check_final(last, lp)
        .map_err(invalid_stat)?;
    let post_poll_us = poll_max_us(&h.metrics);
    if cell == Cell::Burst
        && !(join.inventory.burst_complete() && witness.inventory.burst_complete())
    {
        return Err(invalid_stat("burst rows missing at the final fence"));
    }
    let (worst_wait, marker_coverage) = markers::report(
        &samples,
        start,
        join.first,
        join.eor,
        cell != Cell::BudgetControl,
    );
    let receipt = observation.receipt()?;
    let join_offset = start.duration_since(clock).as_micros();
    println!("cold_join_churn mode={mode} profile={} rows={rows} base={base} flap_rows={} stream_block={} disposition={} cause={:?} join_offset_us={join_offset} enrolled_us={:?} fallback_us={:?} complete_us={:?} initial_eor=1 exact_at_fence=1",
        if tagged {"policy"} else {"plain"}, workload.flap_rows, workload.stream_block, receipt.disposition, receipt.cause, receipt.enrolled_us, receipt.fallback_us, receipt.completed_us);
    // One parseable verdict line. Offsets are from the joiner's PeerUp admission;
    // `none` means the replay completed paced. A poll is charged to the phase in
    // which it ended (the reading follows it).
    let since = |at: Instant| at.saturating_duration_since(start).as_micros();
    let fallback_at = receipt
        .fallback_us
        .map(|at| clock + Duration::from_micros(at));
    let opt = |v: Option<u128>| v.map_or_else(|| "none".to_owned(), |v| v.to_string());
    println!("cold_join_churn_summary mode={mode} rows={rows} disposition={} fallback={} cause={} fallback_us={} fallback_after_first_page_us={} first_page_us={} eor_us={} burst_admit_us={} worst_wait_us={} build_max_poll_us={} replay_max_poll_us={} post_max_poll_us={post_poll_us}",
        receipt.disposition, u8::from(receipt.fallback_us.is_some()), receipt.cause.unwrap_or("none"),
        opt(fallback_at.map(since)), opt(fallback_at.map(|at| at.saturating_duration_since(join.first).as_micros())),
        since(join.first), since(join.eor), opt(burst.map(since)), worst_wait.as_micros(), join.build_poll_us, join.replay_poll_us);
    if let Some(churn) = churn {
        let offset = |t: Instant| t.saturating_duration_since(start).as_micros();
        let in_replay = |t: Instant| join.first <= t && t <= join.eor;
        let mut input_announces = [0usize; 8];
        let mut input_withdrawals = [0usize; 8];
        for tick in &churn.stream_ticks {
            if in_replay(tick.admitted) {
                let counts = if tick.announce {
                    &mut input_announces
                } else {
                    &mut input_withdrawals
                };
                counts[usize::from(tick.source)] += 1;
            }
        }
        let count: usize = input_announces.iter().chain(&input_withdrawals).sum();
        let applied_announces = witness.stream_announces.map(|t| t.is_some_and(in_replay));
        let applied_withdrawals = witness.stream_withdrawals.map(|t| t.is_some_and(in_replay));
        println!("cold_join_churn_activity flap_down_us={} flap_up_us={} flap_loaded_us={} stream_batches={} stream_batches_in_replay={count} cleanup_batches={} first_flap_seen_us={:?} first_stream_seen_us={:?}",offset(churn.flap_down),offset(churn.flap_up),offset(churn.flap_reannounced),churn.stream_ticks.len(),churn.stream_cleanup_batches,witness.first_flap.map(offset),witness.first_stream.map(offset));
        println!(
            "cold_join_flap restored_all_us={:?}",
            witness.restored_at.map(offset)
        );
        if let Some(at) = receipt.fallback_us {
            let fallback = clock + Duration::from_micros(at);
            if fallback < churn.flap_down || fallback > join.eor {
                return Err(invalid_stat("fallback outside the driven churn interval"));
            }
        }
        println!("cold_join_stream input_announce_batches={input_announces:?} input_withdraw_batches={input_withdrawals:?} witness_announces={applied_announces:?} witness_withdrawals={applied_withdrawals:?}");
        if rows == 1_000_000
            && (applied_announces.contains(&false)
                || applied_withdrawals.contains(&false)
                || input_announces.contains(&0)
                || input_withdrawals.contains(&0))
        {
            return Err(invalid_stat("full cell did not sustain all eight stream sources in both directions during replay"));
        }
        if !in_replay(churn.flap_down)
            || !in_replay(churn.flap_up)
            || count == 0
            || !witness.first_flap.is_some_and(in_replay)
            || !witness.first_stream.is_some_and(in_replay)
        {
            return Err(invalid_stat(
                "flap and stream did not both overlap the joiner's replay",
            ));
        }
    }
    marker_coverage?;
    match (cell, receipt.disposition) {
        (Cell::Clean, "paced_complete")
        | (Cell::BudgetControl, "budget_refusal")
        | (Cell::Burst, "replay_to_dirty")
        | (Cell::Mixed, "replay_to_dirty" | "selection_release_to_dirty" | "paced_complete") => {
            Ok(())
        }
        _ => Err(invalid_stat(format!(
            "unexpected {} for {mode}",
            receipt.disposition
        ))),
    }
}
