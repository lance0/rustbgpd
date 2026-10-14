//! Memory-only, manager-direct recovery cells. No profiler or elapsed-time
//! output; the correctness-only mode never reads process or cgroup memory.

use super::*;

const RECOVERY_QUEUE_CAPACITY: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cell {
    DatasetReevaluate,
    PeerDown,
}

impl Cell {
    fn name(self) -> &'static str {
        match self {
            Self::DatasetReevaluate => "dataset-reevaluate",
            Self::PeerDown => "peer-down",
        }
    }
}

#[derive(Default, Clone, Copy)]
struct Counts {
    present: usize,
    announces: u64,
    withdraws: u64,
}

struct Inventory {
    words: Vec<u64>,
    prefixes: usize,
    counts: Counts,
}

impl Inventory {
    fn new(prefixes: usize) -> Self {
        Self {
            words: vec![0; prefixes.div_ceil(64)],
            prefixes,
            counts: Counts::default(),
        }
    }

    fn index(&self, prefix: Prefix, path_id: u32) -> usize {
        assert_eq!(path_id, 0, "the fixture did not negotiate Add-Path");
        let Prefix::V4(prefix) = prefix else {
            panic!("unexpected non-IPv4 route")
        };
        let base = u32::from(Ipv4Addr::new(20, 0, 0, 0));
        let offset = u32::from(prefix.addr)
            .checked_sub(base)
            .expect("unknown prefix")
            >> 8;
        let index = usize::try_from(offset).unwrap();
        assert!(
            index < self.prefixes && prefix == flood_prefix(u64::from(offset)),
            "route outside the exact finite inventory"
        );
        index
    }

    fn apply(&mut self, update: OutboundRouteUpdate) {
        // Transport applies the frozen source exclusion to shared inventories.
        for &(prefix, path_id) in &update.withdraw {
            let index = self.index(prefix, path_id);
            let bit = 1_u64 << (index % 64);
            assert_ne!(
                self.words[index / 64] & bit,
                0,
                "withdrawal of an unadmitted exact key"
            );
            self.words[index / 64] &= !bit;
            self.counts.present -= 1;
            self.counts.withdraws += 1;
        }
        for route in update
            .announce
            .iter()
            .filter(|route| update.announce_source_exclusion != Some(route.peer))
        {
            let index = self.index(route.prefix, route.path_id);
            let bit = 1_u64 << (index % 64);
            if self.words[index / 64] & bit == 0 {
                self.counts.present += 1;
            }
            self.words[index / 64] |= bit;
            self.counts.announces += 1;
        }
        assert!(
            update.flowspec_announce.is_empty()
                && update.flowspec_withdraw.is_empty()
                && update.evpn_announce.is_empty()
                && update.evpn_withdraw.is_empty()
                && update.vpn_announce.is_empty()
                && update.vpn_withdraw.is_empty()
                && update.bgpls_announce.is_empty()
                && update.bgpls_withdraw.is_empty()
                && update.labeled_announce.is_empty()
                && update.labeled_withdraw.is_empty()
                && update.rtc_announce.is_empty()
                && update.rtc_withdraw.is_empty(),
            "unexpected fixture family"
        );
    }
}

enum Control {
    Snapshot(oneshot::Sender<Counts>),
    Pause {
        ready: oneshot::Sender<Counts>,
        resume: oneshot::Receiver<()>,
    },
}

struct Receiver {
    peer: IpAddr,
    outbound: mpsc::Sender<OutboundRouteUpdate>,
    control: mpsc::Sender<Control>,
}

impl Receiver {
    async fn snapshot(&self) -> Counts {
        let (reply, result) = oneshot::channel();
        self.control.send(Control::Snapshot(reply)).await.unwrap();
        result.await.expect("receiver fold failed")
    }

    async fn pause(&self) -> oneshot::Sender<()> {
        let (ready, acknowledged) = oneshot::channel();
        let (release, resume) = oneshot::channel();
        self.control
            .send(Control::Pause { ready, resume })
            .await
            .unwrap();
        acknowledged.await.expect("receiver pause failed");
        // Empty queue fillers carry no fabricated route event.
        while self.outbound.capacity() > 0 {
            self.outbound
                .try_send(OutboundRouteUpdate::default())
                .expect("paused receiver queue must have reserved credit");
        }
        assert_eq!(self.outbound.capacity(), 0);
        release
    }
}

async fn consume(
    mut outbound: mpsc::Receiver<OutboundRouteUpdate>,
    mut control: mpsc::Receiver<Control>,
    prefixes: usize,
) {
    let mut inventory = Inventory::new(prefixes);
    loop {
        tokio::select! {
            biased;
            command = control.recv() => match command {
                Some(Control::Snapshot(reply)) => {
                    while let Ok(update) = outbound.try_recv() { inventory.apply(update); }
                    let _ = reply.send(inventory.counts);
                }
                Some(Control::Pause { ready, resume }) => {
                    while let Ok(update) = outbound.try_recv() { inventory.apply(update); }
                    let _ = ready.send(inventory.counts);
                    resume.await.expect("receiver barrier must be released");
                }
                None => break,
            },
            update = outbound.recv() => match update { Some(update) => inventory.apply(update), None => break },
        }
    }
}

struct RecoveryHarness {
    tx: mpsc::Sender<RibUpdate>,
    receivers: Vec<Receiver>,
    metrics: BgpMetrics,
    source: IpAddr,
    source_receiver: Option<Receiver>,
    _query_tx: mpsc::Sender<RibUpdate>,
}

impl RecoveryHarness {
    async fn setup(clients: u32, prefixes: usize) -> Self {
        let (tx, rx) = mpsc::channel(1024);
        let (query_tx, query_rx) = mpsc::channel(1);
        let metrics = BgpMetrics::new();
        let manager_metrics = metrics.clone();
        std::thread::Builder::new()
            .name("ribmgr".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(
                    RibManager::new(
                        rx,
                        query_rx,
                        None,
                        Some(Ipv4Addr::new(10, 255, 255, 255)),
                        manager_metrics,
                    )
                    .run(),
                );
            })
            .unwrap();
        let source = source_addr(0).into();
        let mut harness = Self {
            tx,
            receivers: Vec::new(),
            metrics,
            source,
            source_receiver: None,
            _query_tx: query_tx,
        };
        for i in 0..clients {
            harness.register(client_addr(i), true, prefixes).await;
        }
        // The source is registered for a real generation-matched PeerDown.
        // Its non-client profile has an empty second group; receivers share
        // exactly one plain client group and no private fallback.
        harness.register(source, false, 0).await;
        harness.source_receiver = harness.receivers.pop();
        harness
    }

    async fn register(&mut self, peer: IpAddr, rr_client: bool, prefixes: usize) {
        let (outbound, receiver) = mpsc::channel(RECOVERY_QUEUE_CAPACITY);
        let (control, commands) = mpsc::channel(1);
        tokio::spawn(consume(receiver, commands, prefixes));
        self.tx
            .send(RibUpdate::SetPeerExportEncoder {
                peer,
                session_id: 1,
                encoder: fanout_bench_export_encoder(),
            })
            .await
            .unwrap();
        self.tx
            .send(RibUpdate::PeerUp {
                peer,
                session_id: 1,
                peer_asn: 64512,
                peer_router_id: match peer {
                    IpAddr::V4(ip) => ip,
                    _ => unreachable!(),
                },
                outbound_tx: outbound.clone(),
                export_policy: None,
                sendable_families: vec![(Afi::Ipv4, Safi::Unicast)],
                is_ebgp: false,
                route_reflector_client: rr_client,
                orr_vantage: None,
                per_client_best: false,
                interpret_rfc1997: true,
                add_path_send_families: Vec::new(),
                add_path_send_max: 0,
                negotiated_orf_recv: Vec::new(),
                negotiated_llgr_families: Vec::new(),
            })
            .await
            .unwrap();
        self.receivers.push(Receiver {
            peer,
            outbound,
            control,
        });
    }

    async fn health(&self) -> (usize, usize, usize, usize, usize, usize) {
        let (reply, result) = oneshot::channel();
        self.tx
            .send(RibUpdate::TestQueryOutboundHealth { reply })
            .await
            .unwrap();
        result.await.unwrap()
    }

    async fn staged(&self) -> HashMap<IpAddr, u64> {
        let (reply, result) = oneshot::channel();
        self.tx
            .send(RibUpdate::QueryBmpPeerStats { reply })
            .await
            .unwrap();
        result
            .await
            .unwrap()
            .adj_rib_out_post
            .into_iter()
            .map(|(peer, families)| {
                (
                    peer,
                    families
                        .iter()
                        .find(|(family, _)| *family == (Afi::Ipv4, Safi::Unicast))
                        .map_or(0, |(_, count)| *count),
                )
            })
            .collect()
    }

    async fn counts(&self) -> Vec<Counts> {
        let mut counts = Vec::with_capacity(self.receivers.len());
        for receiver in &self.receivers {
            counts.push(receiver.snapshot().await);
        }
        counts
    }

    async fn settle(&self, expected: usize) -> Vec<Counts> {
        tokio::time::timeout(CONVERGENCE_TIMEOUT, async {
            loop {
                let health = self.health().await;
                let staged = self.staged().await;
                let counts = self.counts().await;
                assert_eq!(
                    self.source_receiver
                        .as_ref()
                        .unwrap()
                        .snapshot()
                        .await
                        .present,
                    0
                );
                if health == (0, 0, 0, 0, 0, 0)
                    && self.receivers.iter().all(|receiver| {
                        staged.get(&receiver.peer).copied().unwrap_or(0) == expected as u64
                    })
                    && counts.iter().all(|count| count.present == expected)
                {
                    return counts;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("operation did not converge to exact advertised and folded receiver state")
    }

    async fn verify_group(&self) {
        let mut labels = Vec::new();
        for receiver in &self.receivers {
            let (reply, result) = oneshot::channel();
            self.tx
                .send(RibUpdate::QueryPeerUpdateGroup {
                    peer: receiver.peer,
                    reply,
                })
                .await
                .unwrap();
            labels.push(result.await.unwrap());
        }
        assert!(
            labels
                .iter()
                .all(|label| label.starts_with("group:") && label == &labels[0]),
            "receivers must share one plain group"
        );
    }
}

fn metrics_json(metrics: &BgpMetrics) -> String {
    let mut values = BTreeMap::new();
    for family in metrics.registry().gather() {
        let name = family.name();
        if name.starts_with("bgp_update_group_recovery_")
            || name == "bgp_evpn_recovery_provenance_exhausted_total"
            || name == "bgp_update_groups"
            || name == "bgp_update_group_residue_entries"
        {
            let mut value = 0.0;
            for metric in family.get_metric() {
                value += if name.ends_with("_total") {
                    metric.get_counter().get_value()
                } else {
                    metric.get_gauge().get_value()
                };
            }
            assert!(value.is_finite() && value >= 0.0 && value.fract() == 0.0);
            values.insert(name.to_owned(), value as u64);
        }
    }
    format!(
        "{{{}}}",
        values
            .into_iter()
            .map(|(name, value)| format!("\"{name}\":{value}"))
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn fallback_causes_json(metrics: &BgpMetrics) -> String {
    let mut causes = BTreeMap::from([
        ("peer_limit", 0_u64),
        ("daemon_limit", 0),
        ("allocation_failure", 0),
        ("missing_proof", 0),
    ]);
    for family in metrics.registry().gather() {
        if family.name() == "bgp_update_group_recovery_fallback_total" {
            for metric in family.get_metric() {
                let cause = metric
                    .get_label()
                    .iter()
                    .find(|label| label.name() == "cause")
                    .expect("recovery fallback counter must carry its fixed cause")
                    .value();
                let value = metric.get_counter().get_value();
                assert!(value.is_finite() && value >= 0.0 && value.fract() == 0.0);
                *causes
                    .get_mut(cause)
                    .expect("unknown recovery fallback cause") += value as u64;
            }
        }
    }
    format!(
        "{{{}}}",
        causes
            .into_iter()
            .map(|(cause, count)| format!("\"{cause}\":{count}"))
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn verify_memory_identity(path: &std::path::Path) {
    let Some(source_sha) = option_env!("RRHARNESS_RECOVERY_SOURCE_SHA") else {
        panic!("measured binary must embed its original source SHA");
    };
    let Some(instrumentation_sha) = option_env!("RRHARNESS_RECOVERY_INSTRUMENTATION_SHA256") else {
        panic!("measured binary must embed its frozen instrumentation digest");
    };
    assert!(
        source_sha.len() == 40
            && source_sha
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "invalid compiled source SHA"
    );
    assert!(
        instrumentation_sha.len() == 64
            && instrumentation_sha
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "invalid compiled instrumentation digest"
    );
    let membership =
        fs::read_to_string("/proc/self/cgroup").expect("unreadable workload cgroup membership");
    let paths: Vec<_> = membership
        .lines()
        .filter_map(|line| line.strip_prefix("0::"))
        .collect();
    assert_eq!(paths.len(), 1, "workload must have one unified cgroup");
    let own = std::path::PathBuf::from(format!("/sys/fs/cgroup{}", paths[0]));
    assert_eq!(
        path.canonicalize().unwrap(),
        own.canonicalize().unwrap(),
        "supplied cgroup is not the workload's cgroup"
    );
    let text = own.to_str().unwrap();
    assert!(
        text.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_/.:".contains(c)),
        "unexpected scope path syntax"
    );
    let stat = fs::read_to_string("/proc/self/stat").expect("unreadable workload identity");
    let (_, fields) = stat.rsplit_once(") ").expect("invalid workload identity");
    let start_ticks: u64 = fields
        .split_whitespace()
        .nth(19)
        .expect("missing workload start time")
        .parse()
        .unwrap();
    println!(
        "recovery_identity {{\"pid\":{},\"start_ticks\":{start_ticks},\"cgroup\":\"{text}\",\"source_sha\":\"{source_sha}\",\"instrumentation_sha256\":\"{instrumentation_sha}\"}}",
        std::process::id()
    );
}

fn cgroup_json(path: Option<&std::path::Path>) -> String {
    let Some(path) = path else {
        return "null".into();
    };
    let read = |name: &str| {
        fs::read_to_string(path.join(name))
            .unwrap_or_else(|error| panic!("required cgroup {name}: {error}"))
    };
    let scalar = |name: &str| {
        read(name)
            .trim()
            .parse::<u64>()
            .unwrap_or_else(|_| panic!("invalid cgroup {name}"))
    };
    assert_eq!(scalar("memory.swap.max"), 0, "swap must be fenced");
    let mut values = BTreeMap::new();
    values.insert("memory.swap.max".to_owned(), 0);
    for name in [
        "memory.current",
        "memory.peak",
        "memory.swap.current",
        "memory.swap.peak",
    ] {
        values.insert(name.to_owned(), scalar(name));
    }
    assert_eq!(values["memory.swap.current"], 0);
    assert_eq!(values["memory.swap.peak"], 0);
    for (file, keys) in [
        ("memory.stat", &["anon", "file", "file_mapped"][..]),
        ("memory.events", &["oom", "oom_kill", "oom_group_kill"][..]),
    ] {
        let text = read(file);
        for key in keys {
            let value = text
                .lines()
                .find_map(|line| line.strip_prefix(&format!("{key} ")))
                .expect("required cgroup field missing")
                .parse::<u64>()
                .unwrap();
            if file == "memory.events" {
                assert_eq!(value, 0, "OOM invalidates a receipt");
            }
            values.insert(format!("{file}.{key}"), value);
        }
    }
    format!(
        "{{{}}}",
        values
            .into_iter()
            .map(|(name, value)| format!("\"{name}\":{value}"))
            .collect::<Vec<_>>()
            .join(",")
    )
}

async fn sample(
    harness: &RecoveryHarness,
    cell: Cell,
    phase: &str,
    clients: u32,
    prefixes: usize,
    memory: Option<&std::path::Path>,
    counts: &[Counts],
) {
    let health = harness.health().await;
    println!("recovery_sample {{\"schema\":\"rustbgpd.recovery-memory.v1\",\"cell\":\"{}\",\"phase\":\"{phase}\",\"clients\":{clients},\"prefixes\":{prefixes},\"receiver_queue_capacity\":{RECOVERY_QUEUE_CAPACITY},\"receiver_bitmap_bytes\":{},\"folded_routes\":{},\"announces\":{},\"withdrawals\":{},\"dirty_peers\":{},\"group_dirty_members\":{},\"metrics\":{},\"fallback_causes\":{},\"cgroup\":{}}}",
        cell.name(), clients as usize * prefixes.div_ceil(64) * 8,
        counts.iter().map(|count| count.present).sum::<usize>(),
        counts.iter().map(|count| count.announces).sum::<u64>(),
        counts.iter().map(|count| count.withdraws).sum::<u64>(), health.0, health.2,
        metrics_json(&harness.metrics), fallback_causes_json(&harness.metrics), cgroup_json(memory));
}

async fn run(cell: Cell, clients: u32, prefixes: usize, memory: Option<&std::path::Path>) {
    assert!(clients > 0 && prefixes > 0);
    let harness = RecoveryHarness::setup(clients, prefixes).await;
    harness.verify_group().await;
    for start in (0..prefixes).step_by(BATCH) {
        let routes = (start..(start + BATCH).min(prefixes))
            .map(|i| route(flood_prefix(i as u64), source_addr(0), 100))
            .collect();
        let mut update = empty_routes_received(harness.source, routes);
        if let RibUpdate::RoutesReceived { session_id, .. } = &mut update {
            *session_id = 1;
        }
        harness.tx.send(update).await.unwrap();
    }
    let initial = harness.settle(prefixes).await;
    assert!(initial
        .iter()
        .all(|count| count.announces >= prefixes as u64 && count.withdraws == 0));
    sample(
        &harness,
        cell,
        "population_ready",
        clients,
        prefixes,
        memory,
        &initial,
    )
    .await;
    let mut release = Vec::new();
    for receiver in &harness.receivers {
        release.push(receiver.pause().await);
    }
    let expected = match cell {
        Cell::DatasetReevaluate => {
            let (reply, accepted) = oneshot::channel();
            harness
                .tx
                .send(RibUpdate::ReevaluatePeerExportPolicies {
                    peers: vec![harness.receivers[0].peer],
                    reply,
                })
                .await
                .unwrap();
            accepted
                .await
                .unwrap()
                .expect("reevaluation must be accepted");
            prefixes
        }
        Cell::PeerDown => {
            harness
                .tx
                .send(RibUpdate::PeerDown {
                    peer: harness.source,
                    session_id: 1,
                })
                .await
                .unwrap();
            let (reply, barrier) = oneshot::channel();
            harness
                .tx
                .send(RibUpdate::QueryLocRibCount { reply })
                .await
                .unwrap();
            assert_eq!(
                barrier.await.unwrap(),
                0,
                "source PeerDown removes the entire actual table"
            );
            0
        }
    };
    let health = harness.health().await;
    assert_eq!(
        health.0, clients as usize,
        "actual simultaneous dirty receivers"
    );
    assert_eq!(
        health.2, clients as usize,
        "actual simultaneous dirty group members"
    );
    // These consumers remain paused; their acknowledged inventory cannot change.
    sample(
        &harness, cell, "retained", clients, prefixes, memory, &initial,
    )
    .await;
    sample(
        &harness,
        cell,
        "operation_end",
        clients,
        prefixes,
        memory,
        &initial,
    )
    .await;
    for resume in release {
        resume.send(()).unwrap();
    }
    let final_counts = harness.settle(expected).await;
    if cell == Cell::PeerDown {
        assert!(final_counts
            .iter()
            .all(|count| count.withdraws == prefixes as u64 && count.present == 0));
    }
    sample(
        &harness,
        cell,
        "settled",
        clients,
        prefixes,
        memory,
        &final_counts,
    )
    .await;
    println!("recovery_complete {{\"cell\":\"{}\",\"expected_routes_per_receiver\":{expected},\"actual_receivers\":{clients}}}", cell.name());
}

pub(super) fn main(args: &[String]) {
    assert!(args.len() == 3 || (args.len() == 4 && args[3] == "--correctness-only"), "usage: rrharness recovery-memory <dataset-reevaluate|peer-down> <clients> <prefixes> [--correctness-only]");
    let cell = match args[0].as_str() {
        "dataset-reevaluate" => Cell::DatasetReevaluate,
        "peer-down" => Cell::PeerDown,
        _ => panic!("unknown recovery cell"),
    };
    let clients = args[1].parse().expect("clients must be a u32");
    let prefixes = args[2].parse().expect("prefixes must be a usize");
    let path = if args.len() == 4 {
        None
    } else {
        Some(std::path::PathBuf::from(
            std::env::var("RRHARNESS_RECOVERY_CGROUP")
                .expect("measured mode requires the swap-fenced launcher"),
        ))
    };
    // Validate the scope before creating the workload or reading any RSS.
    if path.is_some() {
        verify_memory_identity(path.as_deref().unwrap());
        cgroup_json(path.as_deref());
    }
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            tokio::time::timeout(
                CONVERGENCE_TIMEOUT,
                run(cell, clients, prefixes, path.as_deref()),
            )
            .await
            .expect("recovery cell did not complete all acceptance and drain barriers");
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bitmap_tracks_exact_known_keys_without_route_copies() {
        let mut inventory = Inventory::new(100);
        let value = route(flood_prefix(99), source_addr(0), 100);
        inventory.apply(OutboundRouteUpdate {
            announce: vec![value].into(),
            ..Default::default()
        });
        assert_eq!(inventory.counts.present, 1);
        assert_eq!(inventory.words.len() * 8, 16);
        inventory.apply(OutboundRouteUpdate {
            withdraw: vec![(Prefix::V4(flood_prefix(99)), 0)],
            ..Default::default()
        });
        assert_eq!(inventory.counts.present, 0);
    }
    #[test]
    #[should_panic(expected = "unadmitted exact key")]
    fn bitmap_rejects_unknown_withdrawal() {
        Inventory::new(100).apply(OutboundRouteUpdate {
            withdraw: vec![(Prefix::V4(flood_prefix(1)), 0)],
            ..Default::default()
        });
    }
}
