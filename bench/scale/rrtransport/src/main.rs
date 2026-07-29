use std::collections::{BTreeSet, HashMap};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, ensure, Context, Result};
use rustbgpd_evpn_load::{establish_on, PeerConfig as StubConfig};
use rustbgpd_fsm::{PeerConfig, SessionState};
use rustbgpd_rib::route::{Route, RouteOrigin};
use rustbgpd_rib::update::RibUpdate;
use rustbgpd_rib::RibManager;
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_transport::{
    PeerHandle, RemovePrivateAs, TransportConfig, DEFAULT_SLOW_PEER_DURATION_SECS,
    DEFAULT_SLOW_PEER_THRESHOLD_PCT,
};
use rustbgpd_wire::{
    Afi, AsPath, AspaValidation, AspaValidationContext, Ipv4Prefix, Message, Origin, PathAttribute,
    Prefix, RpkiValidation, Safi,
};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};

mod rr1000;
mod rr1000_support;

const PEERS: usize = 2;
const PREFIXES: usize = 100;
const SOURCES: usize = 4;
const DEADLINE: Duration = Duration::from_secs(20);
const STARTUP_GATE_TIMEOUT: Duration = Duration::from_secs(10);
const STARTUP_READY_ENV: &str = "RRTRANSPORT_STARTUP_READY";
const STARTUP_GO_ENV: &str = "RRTRANSPORT_STARTUP_GO";

fn startup_gate_from_env() -> Result<()> {
    let ready = std::env::var_os(STARTUP_READY_ENV);
    let go = std::env::var_os(STARTUP_GO_ENV);
    match (ready, go) {
        (None, None) => Ok(()),
        (Some(ready), Some(go)) => {
            startup_gate(Path::new(&ready), Path::new(&go), STARTUP_GATE_TIMEOUT)
        }
        _ => bail!("{STARTUP_READY_ENV} and {STARTUP_GO_ENV} must be set together"),
    }
}

fn startup_gate(ready: &Path, go: &Path, timeout: Duration) -> Result<()> {
    let executable = std::env::current_exe()
        .context("resolve rrtransport current executable")?
        .canonicalize()
        .context("canonicalize rrtransport current executable")?;
    let pid = std::process::id();
    let ready_tmp = ready.with_extension(format!("tmp.{pid}"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&ready_tmp)
        .with_context(|| format!("create startup-ready temp file {}", ready_tmp.display()))?;
    writeln!(file, "{pid}")?;
    writeln!(file, "{}", executable.display())?;
    file.sync_all()?;
    drop(file);
    if let Err(error) = fs::rename(&ready_tmp, ready) {
        let _ = fs::remove_file(&ready_tmp);
        return Err(error).context("publish startup-ready identity");
    }

    wait_for_startup_release(go, timeout)
}

fn wait_for_startup_release(go: &Path, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if go.try_exists().context("inspect startup release signal")? {
            return Ok(());
        }
        ensure!(
            Instant::now() < deadline,
            "timed out waiting for rrtransport startup release"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

#[derive(Default)]
struct WireStats {
    update_messages: usize,
    payload_updates: usize,
    announced_nlri: usize,
    withdrawals: usize,
    duplicates: usize,
    decode_failures: usize,
    eor_seen: bool,
    prefixes: BTreeSet<Ipv4Prefix>,
}

fn prefix(index: usize) -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::new(198, 18, u8::try_from(index).unwrap(), 0), 24)
}

fn source(index: usize) -> Ipv4Addr {
    Ipv4Addr::new(127, 1, 0, u8::try_from(index + 1).unwrap())
}

fn route(prefix: Ipv4Prefix, source: Ipv4Addr) -> Route {
    Route {
        prefix: Prefix::V4(prefix),
        next_hop: IpAddr::V4(source),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: IpAddr::V4(source),
        attributes: Arc::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: Vec::new(),
            }),
            PathAttribute::NextHop(source),
            PathAttribute::LocalPref(100),
        ]),
        received_at: Instant::now(),
        origin_type: RouteOrigin::Ibgp,
        peer_router_id: source,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: RpkiValidation::NotFound,
        aspa_state: AspaValidation::Unknown,
        aspa_context: AspaValidationContext::default(),
    }
}

fn transport_config(remote: SocketAddr) -> TransportConfig {
    let mut peer = PeerConfig::new(64512, 64512, Ipv4Addr::new(127, 255, 0, 1));
    peer.connect_retry_secs = 1;
    peer.hold_time = 30;
    peer.families = vec![(Afi::Ipv4, Safi::Unicast)];
    TransportConfig {
        peer,
        remote_addr: remote,
        peer_interface: None,
        peer_scope_id: None,
        connect_timeout: Duration::from_secs(2),
        max_prefixes: None,
        max_prefixes_ipv4: None,
        max_prefixes_ipv6: None,
        peer_group: None,
        md5_password: None,
        tcp_ao: None,
        ttl_security: false,
        local_ipv6_nexthop: None,
        gr_stale_routes_time: 360,
        gr_peer_restart_time_max: 4095,
        llgr_stale_time: 0,
        gr_restart_until: None,
        route_reflector_client: true,
        orr_vantage: None,
        route_server_client: false,
        per_client_best: false,
        next_hop_ownership_strict_peer: false,
        interpret_rfc1997: true,
        rs_control_communities: false,
        remove_private_as: RemovePrivateAs::Disabled,
        cluster_id: Some(Ipv4Addr::new(127, 255, 0, 1)),
        explain_enabled: false,
        explain_cache_size: 0,
        reject_retention_enabled: false,
        reject_retention_capacity: 0,
        bmp_rib_out: false,
        slow_peer_threshold_pct: DEFAULT_SLOW_PEER_THRESHOLD_PCT,
        slow_peer_duration: DEFAULT_SLOW_PEER_DURATION_SECS,
        slow_peer_isolation: false,
    }
}

async fn collect_wire(
    mut rx: mpsc::Receiver<Message>,
    expected: Arc<BTreeSet<Ipv4Prefix>>,
) -> Result<WireStats> {
    let mut stats = WireStats::default();
    loop {
        let message = tokio::time::timeout(DEADLINE, rx.recv())
            .await
            .context("wire initial dump timed out before End-of-RIB")?
            .context("session closed before initial-dump End-of-RIB")?;
        if let Message::Update(update) = message {
            stats.update_messages += 1;
            let is_ipv4_eor = update.withdrawn_routes.is_empty()
                && update.path_attributes.is_empty()
                && update.nlri.is_empty();
            match update.parse(true, false, &[]) {
                Ok(parsed) => {
                    stats.withdrawals += parsed.withdrawn.len();
                    stats.announced_nlri += parsed.announced.len();
                    if !parsed.announced.is_empty() || !parsed.withdrawn.is_empty() {
                        stats.payload_updates += 1;
                    }
                    for entry in parsed.announced {
                        if !stats.prefixes.insert(entry.prefix) {
                            stats.duplicates += 1;
                        }
                    }
                }
                Err(error) => {
                    stats.decode_failures += 1;
                    bail!("wire UPDATE decode failed: {error}");
                }
            }
            if is_ipv4_eor {
                stats.eor_seen = true;
                ensure!(
                    stats.payload_updates >= 1,
                    "End-of-RIB preceded all payload"
                );
                ensure!(stats.announced_nlri == PREFIXES, "initial-dump NLRI count");
                ensure!(stats.withdrawals == 0, "initial-dump withdrawals");
                ensure!(stats.duplicates == 0, "initial-dump duplicate NLRI");
                ensure!(stats.decode_failures == 0, "initial-dump decode failures");
                ensure!(
                    stats.prefixes == *expected,
                    "initial-dump source-set equality failed"
                );
                ensure!(
                    checksum(&stats.prefixes) == checksum(&expected),
                    "initial-dump source-set checksum failed"
                );
                return Ok(stats);
            }
        }
        ensure!(
            stats.prefixes.len() <= PREFIXES && stats.announced_nlri <= PREFIXES,
            "wire announcements overshot target: unique={} decoded={} target={PREFIXES}",
            stats.prefixes.len(),
            stats.announced_nlri,
        );
    }
}

async fn wait_established(session: &PeerHandle) -> Result<()> {
    let deadline = tokio::time::Instant::now() + DEADLINE;
    loop {
        let state = session
            .query_state_timeout(Duration::from_secs(2))
            .await
            .context("session state query failed")?;
        if state.fsm_state == SessionState::Established {
            return Ok(());
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "session did not establish: {:?}",
            state.fsm_state
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn peer_group(rib_query: &mpsc::Sender<RibUpdate>, peer: IpAddr) -> Result<String> {
    let (reply, receive) = oneshot::channel();
    rib_query
        .send(RibUpdate::QueryPeerUpdateGroup { peer, reply })
        .await?;
    Ok(tokio::time::timeout(DEADLINE, receive).await??)
}

async fn wait_shared_group(
    rib_query: &mpsc::Sender<RibUpdate>,
    peers: &[IpAddr; PEERS],
) -> Result<String> {
    let deadline = tokio::time::Instant::now() + DEADLINE;
    loop {
        let groups = [
            peer_group(rib_query, peers[0]).await?,
            peer_group(rib_query, peers[1]).await?,
        ];
        if groups[0].starts_with("group:") && groups[0] == groups[1] {
            return Ok(groups[0].clone());
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "expected exactly one shared update group: {groups:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn staged_counts(rib_query: &mpsc::Sender<RibUpdate>) -> Result<HashMap<IpAddr, u64>> {
    let (reply, receive) = oneshot::channel();
    rib_query
        .send(RibUpdate::QueryAdjRibOutCounts { reply })
        .await?;
    Ok(tokio::time::timeout(DEADLINE, receive)
        .await??
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

async fn wait_staged(
    rib_query: &mpsc::Sender<RibUpdate>,
    peers: &[IpAddr],
) -> Result<HashMap<IpAddr, u64>> {
    let deadline = tokio::time::Instant::now() + DEADLINE;
    loop {
        let counts = staged_counts(rib_query).await?;
        for peer in peers {
            let actual = counts.get(peer).copied().unwrap_or(0);
            ensure!(
                actual <= PREFIXES as u64,
                "staged Adj-RIB-Out overshot for {peer}: {actual} > {PREFIXES}"
            );
        }
        if peers
            .iter()
            .all(|peer| counts.get(peer) == Some(&(PREFIXES as u64)))
        {
            return Ok(counts);
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "timed out before exact staged convergence: {counts:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn checksum(prefixes: &BTreeSet<Ipv4Prefix>) -> u64 {
    prefixes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, prefix| {
        prefix.to_string().bytes().fold(hash, |value, byte| {
            (value ^ u64::from(byte)).wrapping_mul(0x100_0000_01b3)
        })
    })
}

async fn smoke() -> Result<()> {
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

    let expected = Arc::new((0..PREFIXES).map(prefix).collect::<BTreeSet<_>>());
    for source_index in 0..SOURCES {
        let source = source(source_index);
        let announced = (source_index * (PREFIXES / SOURCES)
            ..(source_index + 1) * (PREFIXES / SOURCES))
            .map(|index| route(prefix(index), source))
            .collect();
        rib_tx
            .send(RibUpdate::RoutesReceived {
                peer: IpAddr::V4(source),
                session_id: 0,
                announced,
                withdrawn: Vec::new(),
                flowspec_announced: Vec::new(),
                flowspec_withdrawn: Vec::new(),
                evpn_announced: Vec::new(),
                evpn_withdrawn: Vec::new(),
            })
            .await?;
    }

    let listeners = [
        TcpListener::bind((Ipv4Addr::new(127, 0, 0, 2), 0)).await?,
        TcpListener::bind((Ipv4Addr::new(127, 0, 0, 3), 0)).await?,
    ];
    let addresses = [listeners[0].local_addr()?, listeners[1].local_addr()?];
    let mut stub_tasks = Vec::new();
    let mut sessions = Vec::new();
    for (index, (listener, address)) in listeners.into_iter().zip(addresses).enumerate() {
        let stub_config = StubConfig {
            listen: SocketAddr::new(address.ip(), 0),
            local_as: 64512,
            router_id: Ipv4Addr::new(127, 0, 1, u8::try_from(index + 1).unwrap()),
            hold_time: 30,
            families: vec![(Afi::Ipv4, Safi::Unicast)],
        };
        stub_tasks.push(tokio::spawn(establish_on(listener, stub_config)));
        let session = PeerHandle::spawn(
            transport_config(address),
            metrics.clone(),
            rib_tx.clone(),
            None,
            None,
            None,
            None,
            None,
            false,
        );
        session.start().await?;
        sessions.push(session);
    }

    let mut stubs = Vec::new();
    for task in stub_tasks {
        stubs.push(tokio::time::timeout(DEADLINE, task).await???);
    }
    for session in &sessions {
        wait_established(session).await?;
    }

    let peers = addresses.map(|address| address.ip());
    let mut stub_senders = Vec::new();
    let collectors = stubs
        .into_iter()
        .map(|stub| {
            stub_senders.push(stub.tx);
            tokio::spawn(collect_wire(stub.rx, expected.clone()))
        })
        .collect::<Vec<_>>();
    let staged = wait_staged(&query_tx, &peers).await?;
    let _group = wait_shared_group(&query_tx, &peers).await?;
    let mut wire = Vec::new();
    for collector in collectors {
        wire.push(tokio::time::timeout(DEADLINE, collector).await???);
    }

    let expected_checksum = checksum(&expected);
    for (index, stats) in wire.iter().enumerate() {
        let peer = peers[index];
        ensure!(stats.update_messages >= 1, "peer {peer}: no decoded UPDATE");
        ensure!(stats.payload_updates >= 1, "peer {peer}: no payload UPDATE");
        ensure!(stats.eor_seen, "peer {peer}: End-of-RIB not seen");
        ensure!(stats.announced_nlri == PREFIXES, "peer {peer}: NLRI count");
        ensure!(stats.withdrawals == 0, "peer {peer}: withdrawals");
        ensure!(stats.duplicates == 0, "peer {peer}: duplicate NLRI");
        ensure!(stats.decode_failures == 0, "peer {peer}: decode failures");
        ensure!(
            stats.prefixes == *expected,
            "peer {peer}: source-set equality failed"
        );
        ensure!(
            checksum(&stats.prefixes) == expected_checksum,
            "peer {peer}: source-set checksum failed"
        );
    }

    println!(
        "{{\"kind\":\"rrtransport_smoke\",\"sessions\":{PEERS},\"groups\":1,\
         \"injected\":{PREFIXES},\"staged\":[{},{}],\"decoded_update_messages\":[{},{}],\
         \"decoded_nlri\":[{},{}],\"withdrawals\":[{},{}],\"duplicates\":[{},{}],\
         \"decode_failures\":[{},{}],\"eor_seen\":[{},{}],\"set_equality\":[true,true],\
         \"checksum\":[\"{expected_checksum:016x}\",\"{expected_checksum:016x}\"]}}",
        staged[&peers[0]],
        staged[&peers[1]],
        wire[0].update_messages,
        wire[1].update_messages,
        wire[0].announced_nlri,
        wire[1].announced_nlri,
        wire[0].withdrawals,
        wire[1].withdrawals,
        wire[0].duplicates,
        wire[1].duplicates,
        wire[0].decode_failures,
        wire[1].decode_failures,
        wire[0].eor_seen,
        wire[1].eor_seen,
    );
    println!(
        "rrtransport smoke: sessions={PEERS} groups=1 injected={PREFIXES} \
         staged={PREFIXES}/{PREFIXES} decoded_updates={}/{} decoded_nlri={PREFIXES}/{PREFIXES} \
         withdrawals=0/0 duplicates=0/0 eor_seen={}/{} set_equality=true/true",
        wire[0].update_messages, wire[1].update_messages, wire[0].eor_seen, wire[1].eor_seen
    );

    for session in sessions {
        tokio::time::timeout(DEADLINE, session.shutdown()).await???;
    }
    drop(stub_senders);
    drop(rib_tx);
    drop(query_tx);
    manager_task.abort();
    Ok(())
}

fn main() -> Result<()> {
    ensure!(cfg!(target_os = "linux"), "rrtransport requires Linux");
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [mode] if mode == "smoke" => rr1000_support::runtime(4)?.block_on(smoke()),
        [mode, output] if mode == "rr1000" => {
            rr1000_support::runtime(12)?.block_on(rr1000::run(output, false))
        }
        [mode, output] if mode == "rrtiny" => {
            startup_gate_from_env()?;
            rr1000_support::runtime(12)?.block_on(rr1000::run(output, true))
        }
        _ => bail!(
            "usage: rrtransport smoke | rrtransport rr1000 <output-dir> | rrtransport rrtiny <output-dir>"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_gate_blocks_until_parent_release() {
        let directory = std::env::temp_dir().join(format!(
            "rrtransport-startup-gate-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let ready = directory.join("ready");
        let go = directory.join("go");
        let ready_for_target = ready.clone();
        let go_for_target = go.clone();
        let target = thread::spawn(move || {
            startup_gate(&ready_for_target, &go_for_target, STARTUP_GATE_TIMEOUT)
        });

        // Keep the parent's observation bound comfortably inside the target's
        // release bound so a loaded runner cannot make both expire together.
        let deadline = Instant::now() + Duration::from_secs(5);
        while !ready.exists() {
            assert!(
                Instant::now() < deadline,
                "target did not publish readiness"
            );
            thread::sleep(Duration::from_millis(5));
        }
        assert!(
            !target.is_finished(),
            "target advanced before the parent release"
        );
        let fields = fs::read_to_string(&ready).unwrap();
        assert_eq!(fields.lines().count(), 2);
        assert_eq!(
            fields.lines().next().unwrap(),
            std::process::id().to_string()
        );

        fs::write(&go, b"go\n").unwrap();
        target.join().unwrap().unwrap();
        fs::remove_dir_all(directory).unwrap();
    }
}
