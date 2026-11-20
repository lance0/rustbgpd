//! First-refusal capture on established grouped IPv4 route-server clients.
//! Each RIB sender has exactly two real slots. The fixture gates forwarding
//! to real transport writers only after independently verifying the seed.
mod clocks;

use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{ensure, Context, Result};
use rustbgpd_rib::route::{Route, RouteOrigin};
use rustbgpd_rib::update::{OutboundRouteUpdate, RibUpdate};
use rustbgpd_rib::{AttrSet, PeerId, RibManager};
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{AsPath, AsPathSegment, Ipv4Prefix, Origin, PathAttribute, Prefix};
use serde_json::{json, Value};
use tokio::sync::{mpsc, oneshot};

use crate::grouped_old_sessions::SessionFleet;
use crate::grouped_old_wire::{GroupedWire, Phase};

const SOURCE: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 1);
const PROBE_SOURCE: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 2);
const TRIGGER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 253);
const PROBE: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 254);
const DENIED: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 199);
const CHUNK: usize = 1024;

fn host(ip: Ipv4Addr) -> Prefix {
    Prefix::V4(Ipv4Prefix::new(ip, 32))
}
fn seed_ip(index: usize) -> Ipv4Addr {
    Ipv4Addr::from(0x0a00_0000 + u32::try_from(index).unwrap())
}

fn attributes(source: Ipv4Addr, version: u32) -> Arc<AttrSet> {
    AttrSet::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![if source == SOURCE {
                65_000
            } else {
                65_002
            }])],
        }),
        PathAttribute::NextHop(source),
        PathAttribute::LocalPref(100),
        PathAttribute::Communities(vec![(64_512 << 16) | version]),
    ])
}

fn row(ip: Ipv4Addr, source: Ipv4Addr, attrs: &Arc<AttrSet>) -> Route {
    Route {
        prefix: host(ip),
        next_hop: IpAddr::V4(source),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: PeerId::from_ipv4(source),
        attributes: Arc::clone(attrs),
        received_at: rustbgpd_rib::route::ReceivedAt::now(),
        origin_type: RouteOrigin::Ebgp,
        peer_router_id: source,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        received_as_path: None,
        aspa_context: rustbgpd_rib::route::AspaContextId::DEFAULT,
    }
}

fn update(source: Ipv4Addr, announced: Vec<Route>, withdrawn: Vec<(Prefix, u32)>) -> RibUpdate {
    RibUpdate::RoutesReceived {
        peer: PeerId::from_ipv4(source),
        session_id: 1,
        announced,
        withdrawn,
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    }
}

fn source_up(ip: Ipv4Addr, asn: u32, outbound_tx: mpsc::Sender<OutboundRouteUpdate>) -> RibUpdate {
    RibUpdate::PeerUp {
        supersedes: None,
        peer: PeerId::from_ipv4(ip),
        session_id: 1,
        peer_asn: asn,
        peer_router_id: ip,
        outbound_tx,
        export_policy: None,
        sendable_families: vec![],
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    }
}

/// A general query placed *on the primary FIFO*. A preceding RoutesReceived
/// must finish its chunks and flush its window before this message dispatches.
async fn barrier(tx: &mpsc::Sender<RibUpdate>) -> Result<usize> {
    let (reply, response) = oneshot::channel();
    tx.send(RibUpdate::QueryLocRibCount { reply }).await?;
    Ok(response.await?)
}

async fn dirty(tx: &mpsc::Sender<RibUpdate>) -> Result<usize> {
    let (reply, response) = oneshot::channel();
    tx.send(RibUpdate::QueryOutboundConvergence { reply })
        .await?;
    Ok(response.await?.pending_peers)
}

async fn verify_winner(tx: &mpsc::Sender<RibUpdate>, ip: Ipv4Addr, source: Ipv4Addr) -> Result<()> {
    let (reply, response) = oneshot::channel();
    tx.send(RibUpdate::QueryBestRoutesExact {
        prefixes: vec![host(ip)],
        deadline: tokio::time::Instant::now() + Duration::from_secs(60),
        reply,
    })
    .await?;
    let result = response
        .await?
        .map_err(|e| anyhow::anyhow!("winner query: {e:?}"))?;
    ensure!(
        matches!(result.routes.as_slice(), [Some(route)] if route.peer==PeerId::from_ipv4(source) && route.prefix==host(ip)),
        "wrong Loc-RIB winner for {ip}"
    );
    Ok(())
}

struct Client {
    rx: mpsc::Receiver<OutboundRouteUpdate>,
    session: mpsc::Sender<OutboundRouteUpdate>,
    ledger: GroupedWire,
}

async fn forward(clients: &mut [Client]) -> Result<()> {
    for (i, client) in clients.iter_mut().enumerate() {
        while let Ok(envelope) = client.rx.try_recv() {
            client
                .ledger
                .apply(&envelope)
                .context(WireFailure)
                .with_context(|| format!("admitted inventory at receiver {i}"))?;
            client
                .session
                .send(envelope)
                .await
                .context("transport writer closed")?;
        }
    }
    Ok(())
}

fn check(clients: &[Client], phase: Phase) -> Result<()> {
    for (i, client) in clients.iter().enumerate() {
        client
            .ledger
            .verify(phase)
            .context(WireFailure)
            .with_context(|| format!("receiver {i}, {phase:?}"))?;
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) struct WireFailure;

impl std::fmt::Display for WireFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("receiver correctness failure")
    }
}

pub async fn run(output: &Path, peers: usize, rows: usize) -> Result<()> {
    std::fs::create_dir_all(output)?;
    let path = output.join("grouped-old.json");
    let receipt = match cell(peers, rows).await {
        Ok(receipt) => receipt,
        Err(error) if error.is::<WireFailure>() => {
            let evidence = json!({"cell":"grouped-old-capture","peers":peers,"rows":rows,
                "wire_failure":format!("{error:#}")});
            std::fs::write(path, serde_json::to_vec_pretty(&evidence)?)?;
            return Err(error);
        }
        Err(error) => return Err(error),
    };
    std::fs::write(path, serde_json::to_vec_pretty(&receipt)?)?;
    Ok(())
}

async fn cell(peers: usize, rows: usize) -> Result<Value> {
    ensure!(
        matches!(
            tokio::runtime::Handle::current().runtime_flavor(),
            tokio::runtime::RuntimeFlavor::CurrentThread
        ),
        "grouped capture requires a current-thread actor runtime"
    );
    ensure!(
        (1..=65_535).contains(&peers) && (2..=0x0100_0000).contains(&rows),
        "unsupported grouped capture shape"
    );
    let ips: Vec<_> = (0..peers)
        .map(|i| {
            Ipv4Addr::from(u32::from(Ipv4Addr::new(127, 32, 0, 1)) + u32::try_from(i).unwrap())
        })
        .collect();
    let policy = crate::credit::permit_all_but(crate::credit::statement(Some(host(DENIED)), None));
    let mut fleet = SessionFleet::connect(&ips, rows, &policy).await?;
    let (tx, rx) = mpsc::channel(256);
    let (_qtx, qrx) = mpsc::channel(16);
    let manager = RibManager::new(rx, qrx, None, None, BgpMetrics::new());
    let clocks = clocks::Clocks::default();
    let probe = update(
        PROBE_SOURCE,
        vec![row(PROBE, PROBE_SOURCE, &attributes(PROBE_SOURCE, 4))],
        vec![],
    );
    let actor = clocks.observe(manager, tx.clone().reserve_owned().await?, probe);
    let mut sources = Vec::new();
    for (ip, asn) in [(SOURCE, 65_000), (PROBE_SOURCE, 65_002)] {
        let (sender, rx) = mpsc::channel(8);
        tx.send(source_up(ip, asn, sender)).await?;
        sources.push(rx);
    }
    let mut clients = Vec::with_capacity(peers);
    for i in 0..peers {
        let (sender, rx) = mpsc::channel(2);
        for message in fleet.take_registration(i, sender)? {
            tx.send(message).await?;
        }
        clients.push(Client {
            rx,
            session: fleet.writer(i),
            ledger: GroupedWire::new(rows),
        });
    }
    barrier(&tx).await?;
    let mut group = None;
    for &ip in &ips {
        let member = crate::peer_group(&tx, IpAddr::V4(ip)).await?;
        ensure!(
            member.starts_with("group:") && group.as_ref().is_none_or(|g| g == &member),
            "client {ip} did not join common update group: {member}"
        );
        group = Some(member);
    }
    forward(&mut clients).await?;
    // This real Loc-RIB route exercises the shared deny rule. Any export is
    // rejected as an unexpected key by both independent receiver ledgers.
    let base = attributes(SOURCE, 1);
    tx.send(update(SOURCE, vec![row(DENIED, SOURCE, &base)], vec![]))
        .await?;
    barrier(&tx).await?;
    verify_winner(&tx, DENIED, SOURCE).await?;
    for begin in (0..rows).step_by(CHUNK) {
        let seed = (begin..rows.min(begin + CHUNK))
            .map(|i| row(seed_ip(i), SOURCE, &base))
            .collect();
        tx.send(update(SOURCE, seed, vec![])).await?;
        barrier(&tx).await?;
        forward(&mut clients).await?;
    }
    check(&clients, Phase::Seed)?;
    fleet.verify_seed().await?;
    ensure!(
        dirty(&tx).await? == 0,
        "receivers already dirty before fill"
    );
    // Both slots hold real successful changes to one installed route. The
    // following withdrawn route is a different key, so the missed duty is
    // distinguishable after recovery.
    for version in [2, 3] {
        tx.send(update(
            SOURCE,
            vec![row(seed_ip(1), SOURCE, &attributes(SOURCE, version))],
            vec![],
        ))
        .await?;
        barrier(&tx).await?;
    }
    let full = clients
        .iter()
        .filter(|c| c.rx.len() == 2 && c.rx.capacity() == 0)
        .count();
    ensure!(
        full == peers && dirty(&tx).await? == 0,
        "target requires every client newly full and clean: {full}/{peers} full"
    );
    let trigger = update(
        SOURCE,
        vec![row(TRIGGER, SOURCE, &attributes(SOURCE, 3))],
        vec![(host(seed_ip(0)), 0)],
    );
    tx.try_send(trigger)?;
    clocks.trigger();
    // This scalar FIFO fence closes the trigger window before the probe.
    // The pass observer samples the dirty count at completion inside the
    // actor; no receiver scan is interposed before the probe dispatches.
    barrier(&tx).await?;
    let refused = clocks.first_refused()?;
    ensure!(
        refused == peers,
        "first refusal left {refused}/{peers} dirty"
    );
    verify_winner(&tx, PROBE, PROBE_SOURCE).await?;
    clocks.winner();
    // All fixture receivers share this thread with the actor: take both
    // preexisting envelopes before an await permits any recovery send.
    let mut filled = Vec::with_capacity(peers);
    for client in &mut clients {
        let a = client.rx.try_recv()?;
        let b = client.rx.try_recv()?;
        client.ledger.apply(&a).context(WireFailure)?;
        client.ledger.apply(&b).context(WireFailure)?;
        filled.push((a, b));
    }
    check(&clients, Phase::Fill)?;
    for (client, (a, b)) in clients.iter().zip(filled) {
        client.session.send(a).await?;
        client.session.send(b).await?;
    }
    loop {
        forward(&mut clients).await?;
        if dirty(&tx).await? == 0 {
            forward(&mut clients).await?;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    check(&clients, Phase::Final)?;
    let transport = fleet.finish().await?;
    barrier(&tx).await?;
    let mut receipt = clocks.receipt()?;
    let fields = json!({
        "cell":"grouped-old-capture","peers":peers,"rows":rows,"established_group_members":peers,
        "full_receivers_before_trigger":full,"first_refused_receivers":refused,
        "exact_receivers_before_trigger":peers,"exact_receivers_after_recovery":peers,
        "reset_count":transport["resets"],"wire_exact_receivers":transport["wire_exact_receivers"],"transport":transport,
        "policy_denied_winner_absent_on_receivers":true
    });
    receipt
        .as_object_mut()
        .unwrap()
        .extend(fields.as_object().unwrap().clone());
    drop(tx);
    drop(sources);
    actor.await?;
    Ok(receipt)
}
