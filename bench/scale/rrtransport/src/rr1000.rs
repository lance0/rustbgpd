use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, ensure, Context, Result};
use rustbgpd_evpn_load::{establish_on, PeerConfig as StubConfig};
use rustbgpd_rib::route::{Route, RouteOrigin};
use rustbgpd_rib::update::RibUpdate;
use rustbgpd_rib::RibManager;
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_transport::PeerHandle;
use rustbgpd_wire::{
    Afi, AsPath, AspaValidation, AspaValidationContext, Ipv4Prefix, Message, Origin, PathAttribute,
    Prefix, RpkiValidation, Safi,
};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, mpsc::error::TryRecvError, oneshot};

use super::{
    rr1000_support::{assert_established, is_eor, rss_kib, shutdown},
    transport_config,
};

const PEERS: usize = 1000;
const PREFIXES: usize = 100_000;
const SOURCES: usize = 4;
const WORKERS: usize = 12;
const LIMIT: Duration = Duration::from_secs(120);
const SHAPE: &str =
    "rr1000-v1:peers=1000;prefixes=100000;sources=4;workers=12;afi=ipv4-unicast;role=ibgp-rr";
const SHAPE_DIGEST: &str = "109e38772e3bd819";
const BITMAP_DIGEST: &str = "7c50a897bc4a4e51";
const TINY_SHAPE: &str =
    "rrtiny-v1:peers=4;prefixes=100;sources=4;workers=12;afi=ipv4-unicast;role=ibgp-rr";

#[derive(Clone, Copy)]
struct Shape {
    peers: usize,
    prefixes: usize,
    name: &'static str,
    digest: &'static str,
    bitmap_digest: &'static str,
}

struct Bitmap {
    words: Vec<u64>,
    limit: usize,
    duplicates: usize,
    outside: usize,
}

impl Bitmap {
    fn new(limit: usize) -> Self {
        Self {
            words: vec![0; limit.div_ceil(64)],
            limit,
            duplicates: 0,
            outside: 0,
        }
    }

    fn observe(&mut self, value: Ipv4Prefix) {
        let octets = value.addr.octets();
        let index = usize::from(octets[0].saturating_sub(10)) * 65_536
            + usize::from(octets[1]) * 256
            + usize::from(octets[2]);
        if value.len != 24
            || !(10..=11).contains(&octets[0])
            || octets[3] != 0
            || index >= self.limit
        {
            self.outside += 1;
            return;
        }
        let mask = 1_u64 << (index % 64);
        if self.words[index / 64] & mask != 0 {
            self.duplicates += 1;
        }
        self.words[index / 64] |= mask;
    }

    fn coverage(&self) -> usize {
        self.words
            .iter()
            .map(|word| word.count_ones() as usize)
            .sum()
    }

    fn digest(&self) -> u64 {
        self.words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
                (hash ^ u64::from(byte)).wrapping_mul(0x100_0000_01b3)
            })
    }
}

struct WireRow {
    peer: IpAddr,
    messages: usize,
    nlri: usize,
    withdrawals: usize,
    decode_failures: usize,
    bitmap: Bitmap,
    wire_ms: u128,
}
fn value(index: usize) -> Ipv4Prefix {
    let within = index % 65_536;
    Ipv4Prefix::new(
        Ipv4Addr::new(
            10 + u8::try_from(index / 65_536).unwrap(),
            u8::try_from(within >> 8).unwrap(),
            u8::try_from(within & 255).unwrap(),
            0,
        ),
        24,
    )
}
fn source(index: usize) -> Ipv4Addr {
    Ipv4Addr::new(127, 200, 0, u8::try_from(index + 1).unwrap())
}

fn peer_ip(index: usize) -> Ipv4Addr {
    Ipv4Addr::new(
        127,
        2 + u8::try_from(index / 254).unwrap(),
        1 + u8::try_from(index % 254).unwrap(),
        1,
    )
}

fn route(prefix: Ipv4Prefix, peer: Ipv4Addr) -> Route {
    Route {
        prefix: Prefix::V4(prefix),
        next_hop: IpAddr::V4(peer),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: IpAddr::V4(peer),
        attributes: Arc::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath { segments: vec![] }),
            PathAttribute::NextHop(peer),
            PathAttribute::LocalPref(100),
        ]),
        received_at: Instant::now(),
        origin_type: RouteOrigin::Ibgp,
        peer_router_id: peer,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: RpkiValidation::NotFound,
        aspa_state: AspaValidation::Unknown,
        aspa_context: AspaValidationContext::default(),
    }
}

async fn collect(
    peer: IpAddr,
    mut rx: mpsc::Receiver<Message>,
    ready: oneshot::Sender<()>,
    start: oneshot::Receiver<Instant>,
    shape: Shape,
    deadline: tokio::time::Instant,
) -> Result<WireRow> {
    loop {
        let message = tokio::time::timeout_at(deadline, rx.recv())
            .await?
            .context("closed before initial EoR")?;
        if let Message::Update(update) = message {
            let parsed = update.parse(true, false, &[])?;
            ensure!(parsed.announced.is_empty() && parsed.withdrawn.is_empty());
            if is_eor(&update) {
                break;
            }
        }
    }
    ready
        .send(())
        .map_err(|_| anyhow::anyhow!("ready dropped"))?;
    let t0 = tokio::time::timeout_at(deadline, start).await??;
    ensure!(
        matches!(rx.try_recv(), Err(TryRecvError::Empty)),
        "duplicate pre-T0 UPDATE/EoR"
    );
    let mut row = WireRow {
        peer,
        messages: 0,
        nlri: 0,
        withdrawals: 0,
        decode_failures: 0,
        bitmap: Bitmap::new(shape.prefixes),
        wire_ms: 0,
    };
    while row.bitmap.coverage() < shape.prefixes {
        let message = tokio::time::timeout_at(deadline, rx.recv())
            .await?
            .context("closed before wire convergence")?;
        if let Message::Update(update) = message {
            ensure!(!is_eor(&update), "duplicate post-T0 End-of-RIB");
            row.messages += 1;
            let parsed = match update.parse(true, false, &[]) {
                Ok(parsed) => parsed,
                Err(error) => {
                    row.decode_failures += 1;
                    bail!("peer {peer}: decode failed: {error}");
                }
            };
            row.withdrawals += parsed.withdrawn.len();
            row.nlri += parsed.announced.len();
            for announced in parsed.announced {
                row.bitmap.observe(announced.prefix);
            }
        }
        ensure!(row.nlri <= shape.prefixes);
    }
    ensure!(
        row.nlri == shape.prefixes
            && row.withdrawals + row.decode_failures + row.bitmap.duplicates + row.bitmap.outside
                == 0
    );
    row.wire_ms = t0.elapsed().as_millis();
    Ok(row)
}

async fn counts(query: &mpsc::Sender<RibUpdate>) -> Result<HashMap<IpAddr, u64>> {
    let (reply, receive) = oneshot::channel();
    query
        .send(RibUpdate::QueryAdjRibOutCounts { reply })
        .await?;
    Ok(receive
        .await?
        .into_iter()
        .map(|(peer, families)| {
            let count = families
                .into_iter()
                .find(|((afi, safi), _)| *afi == Afi::Ipv4 && *safi == Safi::Unicast)
                .map_or(0, |(_, count)| count);
            (peer, count)
        })
        .collect())
}

async fn group(query: &mpsc::Sender<RibUpdate>, peer: IpAddr) -> Result<String> {
    let (reply, receive) = oneshot::channel();
    query
        .send(RibUpdate::QueryPeerUpdateGroup { peer, reply })
        .await?;
    Ok(receive.await?)
}

pub async fn run(output: &str, tiny: bool) -> Result<()> {
    let shape = if tiny {
        Shape {
            peers: 4,
            prefixes: 100,
            name: TINY_SHAPE,
            digest: "2ab117a2e63de3a0",
            bitmap_digest: "d4e22dcde16f2746",
        }
    } else {
        Shape {
            peers: PEERS,
            prefixes: PREFIXES,
            name: SHAPE,
            digest: SHAPE_DIGEST,
            bitmap_digest: BITMAP_DIGEST,
        }
    };
    let output = Path::new(output);
    fs::create_dir_all(output)?;
    let run_deadline = tokio::time::Instant::now() + LIMIT;
    let metrics = BgpMetrics::new();
    let (rib_tx, rib_rx) = mpsc::channel(1024);
    let (query_tx, query_rx) = mpsc::channel(64);
    let manager = RibManager::new(
        rib_rx,
        query_rx,
        None,
        Some(Ipv4Addr::new(127, 255, 0, 1)),
        metrics.clone(),
    );
    let manager_task = tokio::spawn(manager.run());
    let mut listeners = Vec::with_capacity(shape.peers);
    for index in 0..shape.peers {
        listeners.push(
            tokio::time::timeout_at(run_deadline, TcpListener::bind((peer_ip(index), 0))).await??,
        );
    }
    let addresses = listeners
        .iter()
        .map(TcpListener::local_addr)
        .collect::<std::io::Result<Vec<_>>>()?;
    let mut handshakes = Vec::with_capacity(shape.peers);
    let mut sessions = Vec::with_capacity(shape.peers);
    for (index, (listener, address)) in listeners.into_iter().zip(&addresses).enumerate() {
        handshakes.push(tokio::spawn(establish_on(
            listener,
            StubConfig {
                listen: SocketAddr::new(address.ip(), 0),
                local_as: 64512,
                router_id: peer_ip(index),
                hold_time: 30,
                families: vec![(Afi::Ipv4, Safi::Unicast)],
            },
        )));
        let session = PeerHandle::spawn(
            transport_config(*address),
            metrics.clone(),
            rib_tx.clone(),
            None,
            None,
            None,
            None,
            None,
            false,
        );
        tokio::time::timeout_at(run_deadline, session.start()).await??;
        sessions.push(session);
    }
    let mut stubs = Vec::with_capacity(shape.peers);
    for task in handshakes {
        stubs.push(tokio::time::timeout_at(run_deadline, task).await???);
    }
    assert_established(&sessions, run_deadline).await?;
    let established_rss = rss_kib()?;
    let peers = addresses
        .iter()
        .map(|address| address.ip())
        .collect::<Vec<_>>();
    let mut ready = Vec::new();
    let mut starts = Vec::new();
    let mut stub_senders = Vec::with_capacity(shape.peers);
    let collectors = stubs
        .into_iter()
        .zip(&peers)
        .map(|(stub, peer)| {
            stub_senders.push(stub.tx);
            let (ready_tx, ready_rx) = oneshot::channel();
            let (start_tx, start_rx) = oneshot::channel();
            ready.push(ready_rx);
            starts.push(start_tx);
            tokio::spawn(collect(
                *peer,
                stub.rx,
                ready_tx,
                start_rx,
                shape,
                run_deadline,
            ))
        })
        .collect::<Vec<_>>();
    for drained in ready {
        tokio::time::timeout_at(run_deadline, drained).await??;
    }
    let mut groups = HashSet::new();
    for peer in &peers {
        groups.insert(tokio::time::timeout_at(run_deadline, group(&query_tx, *peer)).await??);
    }
    ensure!(groups.len() == 1 && groups.iter().all(|item| item.starts_with("group:")));
    let t0 = Instant::now();
    for start in starts {
        start
            .send(t0)
            .map_err(|_| anyhow::anyhow!("collector exited"))?;
    }
    for source_index in 0..SOURCES {
        let peer = source(source_index);
        let announced = (source_index * shape.prefixes / SOURCES
            ..(source_index + 1) * shape.prefixes / SOURCES)
            .map(|index| route(value(index), peer))
            .collect();
        rib_tx
            .send(RibUpdate::RoutesReceived {
                peer: IpAddr::V4(peer),
                session_id: 0,
                announced,
                withdrawn: vec![],
                flowspec_announced: vec![],
                flowspec_withdrawn: vec![],
                evpn_announced: vec![],
                evpn_withdrawn: vec![],
            })
            .await?;
    }
    let injection_ms = t0.elapsed().as_millis();
    let staged = loop {
        let current = tokio::time::timeout_at(run_deadline, counts(&query_tx)).await??;
        ensure!(current
            .values()
            .all(|count| *count <= shape.prefixes as u64));
        if peers
            .iter()
            .all(|peer| current.get(peer) == Some(&(shape.prefixes as u64)))
        {
            break current;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    let staged_ms = t0.elapsed().as_millis();
    let staged_rss = rss_kib()?;
    let mut rows = Vec::with_capacity(shape.peers);
    for collector in collectors {
        rows.push(tokio::time::timeout_at(run_deadline, collector).await???);
    }
    ensure!(
        rows.len() == shape.peers
            && rows
                .iter()
                .all(|row| format!("{:016x}", row.bitmap.digest()) == shape.bitmap_digest)
    );
    let wire_ms = rows.iter().map(|row| row.wire_ms).max().unwrap_or_default();
    let wire_rss = rss_kib()?;
    assert_established(&sessions, run_deadline).await?;
    let mut file = BufWriter::new(File::create(output.join("per-peer.tsv"))?);
    writeln!(file, "peer\tstaged\tnlri\tmessages\twithdrawals\tduplicates\toutside\tdecode_failures\tcoverage\tbitmap_digest\tinitial_eor\twire_ms")?;
    for row in &rows {
        writeln!(
            file,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\ttrue\t{}",
            row.peer,
            staged[&row.peer],
            row.nlri,
            row.messages,
            row.withdrawals,
            row.bitmap.duplicates,
            row.bitmap.outside,
            row.decode_failures,
            row.bitmap.coverage(),
            shape.bitmap_digest,
            row.wire_ms
        )?;
    }
    fs::write(output.join("phase.json"), format!(
        "{{\"schema\":1,\"shape\":\"{}\",\"shape_digest\":\"{}\",\"sessions\":{},\"established_before\":{},\"established_after\":{},\"prefixes\":{},\"sources\":{SOURCES},\"workers\":{WORKERS},\"groups\":1,\"initial_eors\":{},\"injection_ms\":{injection_ms},\"staged_ms\":{staged_ms},\"wire_ms\":{wire_ms},\"established_rss_kib\":{},\"established_vmhwm_kib\":{},\"staged_rss_kib\":{},\"staged_vmhwm_kib\":{},\"wire_rss_kib\":{},\"wire_vmhwm_kib\":{}}}\n",
        shape.name, shape.digest, shape.peers, shape.peers, shape.peers, shape.prefixes, shape.peers,
        established_rss.0, established_rss.1, staged_rss.0, staged_rss.1, wire_rss.0, wire_rss.1))?;
    shutdown(sessions, run_deadline).await?;
    drop(rib_tx);
    drop(query_tx);
    manager_task.abort();
    let _ = manager_task.await;
    Ok(())
}
