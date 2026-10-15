//! Memory-only, manager-direct recovery cells. No profiler or elapsed-time
//! output; the correctness-only mode never reads process or cgroup memory.

use super::*;

use std::net::Ipv6Addr;

use rustbgpd_rib::route::{VpnRibRoute, VpnRibRouteKey};
use rustbgpd_wire::{Ipv6Prefix, MplsLabelEntry, RouteDistinguisher, VpnNlri, VpnPrefix};

const RECOVERY_QUEUE_CAPACITY: usize = 8;
const RECOVERY_CELL_TIMEOUT: Duration = Duration::from_secs(1800);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cell {
    DatasetReevaluate,
    PeerDown,
    Widen,
    UnsynchronizedDirty,
}
impl Cell {
    fn name(self) -> &'static str {
        match self {
            Self::DatasetReevaluate => "dataset-reevaluate",
            Self::PeerDown => "peer-down",
            Self::Widen => "widen",
            Self::UnsynchronizedDirty => "unsynchronized-dirty",
        }
    }
}

const FAMILY_NAMES: [&str; 4] = ["ipv4_unicast", "ipv6_unicast", "vpnv4", "vpnv6"];
const FAMILIES: [(Afi, Safi); 4] = [
    (Afi::Ipv4, Safi::Unicast),
    (Afi::Ipv6, Safi::Unicast),
    (Afi::Ipv4, Safi::MplsVpn),
    (Afi::Ipv6, Safi::MplsVpn),
];
#[derive(Clone, Copy, Debug)]
struct Spec {
    name: &'static str,
    seed: [usize; 4],
    additions: [usize; 4],
}
impl Spec {
    fn named(name: &str) -> Self {
        let (name, seed, additions) = match name {
            "ipv4-100k" => ("ipv4-100k", [100_000, 0, 0, 0], [0; 4]),
            "full-uc" => ("full-uc", [1_000_000, 230_000, 0, 0], [0; 4]),
            "full-vpn" => (
                "full-vpn",
                [0, 0, 1_000_000, 230_000],
                [0, 0, 100_000, 23_000],
            ),
            "mixed-widen" => (
                "mixed-widen",
                [1_000_000, 230_000, 0, 0],
                [0, 0, 100_000, 23_000],
            ),
            "smoke-uc" => ("smoke-uc", [160, 40, 0, 0], [0; 4]),
            "smoke-vpn" => ("smoke-vpn", [0, 0, 160, 40], [0, 0, 16, 4]),
            "smoke-mixed" => ("smoke-mixed", [160, 40, 0, 0], [0, 0, 16, 4]),
            _ => panic!("unknown recovery profile"),
        };
        Self {
            name,
            seed,
            additions,
        }
    }
    fn counts(self, widened: bool) -> [usize; 4] {
        std::array::from_fn(|f| self.seed[f] + if widened { self.additions[f] } else { 0 })
    }
    fn cell_additions(self, cell: Cell, clients: usize) -> [usize; 4] {
        match cell {
            Cell::Widen => self.additions,
            Cell::UnsynchronizedDirty => {
                let family = self.seed.iter().position(|n| *n > 0).unwrap();
                std::array::from_fn(|f| if f == family { clients } else { 0 })
            }
            Cell::DatasetReevaluate | Cell::PeerDown => [0; 4],
        }
    }
    fn cell_limits(self, cell: Cell, clients: usize) -> [usize; 4] {
        let additions = self.cell_additions(cell, clients);
        std::array::from_fn(|f| self.seed[f] + additions[f])
    }
    fn families(self) -> Vec<(Afi, Safi)> {
        FAMILIES
            .into_iter()
            .enumerate()
            .filter_map(|(f, family)| (self.seed[f] + self.additions[f] > 0).then_some(family))
            .collect()
    }
}
#[derive(Default, Clone, Copy, Debug)]
struct Counts {
    present: [usize; 4],
    announces: [u64; 4],
    withdraws: [u64; 4],
}
impl Counts {
    fn json(self) -> String {
        format!(
            "{{{}}}",
            (0..4)
                .map(|f| format!(
                    "\"{}\":{{\"present\":{},\"announces\":{},\"withdrawals\":{}}}",
                    FAMILY_NAMES[f], self.present[f], self.announces[f], self.withdraws[f]
                ))
                .collect::<Vec<_>>()
                .join(",")
        )
    }
}
fn family_counts_json(counts: [usize; 4]) -> String {
    format!(
        "{{{}}}",
        (0..4)
            .map(|f| format!("\"{}\":{}", FAMILY_NAMES[f], counts[f]))
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn v6_prefix(index: usize) -> Ipv6Prefix {
    Ipv6Prefix::new(
        Ipv6Addr::from(
            u128::from("2001:db8:100::".parse::<Ipv6Addr>().unwrap()) + ((index as u128) << 16),
        ),
        112,
    )
}
fn fixture_prefix(family: usize, index: usize) -> Prefix {
    match family {
        0 => Prefix::V4(flood_prefix(index as u64)),
        1 => Prefix::V6(v6_prefix(index)),
        _ => unreachable!(),
    }
}
fn prefix_index(prefix: Prefix) -> (usize, usize) {
    let (family, index) = match prefix {
        Prefix::V4(p) => (
            0,
            usize::try_from(
                u32::from(p.addr)
                    .checked_sub(u32::from(Ipv4Addr::new(20, 0, 0, 0)))
                    .expect("unknown prefix")
                    >> 8,
            )
            .unwrap(),
        ),
        Prefix::V6(p) => (
            1,
            usize::try_from(
                u128::from(p.addr)
                    .checked_sub(u128::from(v6_prefix(0).addr))
                    .expect("unknown prefix")
                    >> 16,
            )
            .unwrap(),
        ),
    };
    assert_eq!(
        prefix,
        fixture_prefix(family, index),
        "noncanonical or wrong prefix length"
    );
    (family, index)
}
// The two legal encodings have the same display text, but distinct wire identity.
const RDS: [RouteDistinguisher; 2] = [
    RouteDistinguisher([0, 0, 0xfd, 0xe8, 0, 0, 0, 100]),
    RouteDistinguisher([0, 2, 0, 0, 0xfd, 0xe8, 0, 100]),
];
fn vpn_nlri(family: usize, index: usize) -> VpnNlri {
    let prefix = match fixture_prefix(family, index / 2) {
        Prefix::V4(p) => VpnPrefix::v4(p.addr, p.len).unwrap(),
        Prefix::V6(p) => VpnPrefix::v6(p.addr, p.len).unwrap(),
    };
    VpnNlri {
        labels: vec![MplsLabelEntry::try_new(
            16_000 + u32::try_from(index % 1_000_000).unwrap(),
            0,
            true,
        )
        .unwrap()],
        route_distinguisher: RDS[index % 2],
        prefix,
    }
}
fn vpn_index(key: &VpnRibRouteKey) -> (usize, usize) {
    assert_eq!(key.path_id, 0, "the fixture did not negotiate Add-Path");
    let rd = RDS
        .iter()
        .position(|rd| *rd == key.nlri_key.route_distinguisher)
        .expect("unknown raw RD");
    let prefix = match key.nlri_key.prefix {
        VpnPrefix::V4 { addr, len } => Prefix::V4(Ipv4Prefix { addr, len }),
        VpnPrefix::V6 { addr, len } => Prefix::V6(Ipv6Prefix { addr, len }),
    };
    let (family, inner) = prefix_index(prefix);
    (family, inner.checked_mul(2).unwrap() + rd)
}
fn fixture_next_hop(family: usize) -> IpAddr {
    if family == 0 {
        source_addr(0).into()
    } else {
        "2001:db8::1".parse().unwrap()
    }
}
fn expected_attributes(vpn: bool, family: usize) -> Arc<AttrSet> {
    let mut attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath { segments: vec![] }),
    ];
    if !vpn && family == 0 {
        attrs.push(PathAttribute::NextHop(source_addr(0)));
    }
    attrs.push(PathAttribute::LocalPref(100));
    AttrSet::new(attrs)
}
fn fixture_route(family: usize, index: usize) -> Route {
    let mut value = route(flood_prefix(0), source_addr(0), 100);
    value.prefix = fixture_prefix(family, index);
    value.next_hop = fixture_next_hop(family);
    value.attributes = expected_attributes(false, family);
    value
}
fn fixture_vpn_route(family: usize, index: usize) -> VpnRibRoute {
    VpnRibRoute {
        nlri: vpn_nlri(family, index),
        next_hop: fixture_next_hop(family),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: source_addr(0).into(),
        attributes: expected_attributes(true, family),
        received_at: Instant::now(),
        origin_type: RouteOrigin::Ibgp,
        peer_router_id: source_addr(0),
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
    }
}

struct Inventory {
    words: [Vec<u64>; 4],
    limits: [usize; 4],
    expected_attrs: [Arc<AttrSet>; 4],
    counts: Counts,
}
impl Inventory {
    fn new(limits: [usize; 4]) -> Self {
        Self {
            words: limits.map(|n| vec![0; n.div_ceil(64)]),
            limits,
            expected_attrs: std::array::from_fn(|f| expected_attributes(f >= 2, f % 2)),
            counts: Counts::default(),
        }
    }
    fn event(&mut self, family: usize, index: usize, announce: bool) {
        assert!(
            index < self.limits[family],
            "route outside the exact finite inventory"
        );
        let bit = 1_u64 << (index % 64);
        let word = &mut self.words[family][index / 64];
        if announce {
            if *word & bit == 0 {
                self.counts.present[family] += 1;
            }
            *word |= bit;
            self.counts.announces[family] += 1;
        } else {
            assert_ne!(*word & bit, 0, "withdrawal of an unadmitted exact key");
            *word &= !bit;
            self.counts.present[family] -= 1;
            self.counts.withdraws[family] += 1;
        }
    }
    fn apply(&mut self, update: OutboundRouteUpdate) {
        assert!(
            !update.request_refresh_all_negotiated,
            "unexpected receiver registration reset/refresh"
        );
        assert!(
            update.flowspec_announce.is_empty()
                && update.flowspec_withdraw.is_empty()
                && update.evpn_announce.is_empty()
                && update.evpn_withdraw.is_empty()
                && update.bgpls_announce.is_empty()
                && update.bgpls_withdraw.is_empty()
                && update.labeled_announce.is_empty()
                && update.labeled_withdraw.is_empty()
                && update.rtc_announce.is_empty()
                && update.rtc_withdraw.is_empty(),
            "unexpected fixture family"
        );
        for (prefix, path_id) in update.withdraw {
            assert_eq!(path_id, 0, "the fixture did not negotiate Add-Path");
            let (family, index) = prefix_index(prefix);
            self.event(family, index, false);
        }
        for key in &update.vpn_withdraw {
            let (family, index) = vpn_index(key);
            self.event(family + 2, index, false);
        }
        for value in update
            .announce
            .iter()
            .filter(|route| update.announce_source_exclusion != Some(route.peer))
        {
            assert_eq!(value.path_id, 0, "the fixture did not negotiate Add-Path");
            let (family, index) = prefix_index(value.prefix);
            assert_eq!(value.next_hop, fixture_next_hop(family), "wrong next hop");
            assert_eq!(value.peer, IpAddr::V4(source_addr(0)), "wrong route source");
            assert_eq!(
                value.attributes, self.expected_attrs[family],
                "wrong expected attributes"
            );
            assert!(
                value.link_local_next_hop.is_none() && value.next_hop_scope.is_none(),
                "unexpected scoped next hop"
            );
            self.event(family, index, true);
        }
        for value in update.vpn_announce {
            let (family, index) = vpn_index(&value.key());
            assert_eq!(
                value.nlri,
                vpn_nlri(family, index),
                "wrong VPN label or NLRI data"
            );
            assert_eq!(value.next_hop, fixture_next_hop(family), "wrong next hop");
            assert_eq!(value.peer, IpAddr::V4(source_addr(0)), "wrong route source");
            assert_eq!(
                value.attributes,
                self.expected_attrs[family + 2],
                "wrong expected attributes"
            );
            assert!(
                value.link_local_next_hop.is_none() && value.next_hop_scope.is_none(),
                "unexpected scoped next hop"
            );
            self.event(family + 2, index, true);
        }
    }
}

enum Control {
    Credit {
        request: oneshot::Receiver<()>,
        acknowledged: std::sync::mpsc::Sender<Result<(), String>>,
    },
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
    limits: [usize; 4],
) {
    let mut inventory = Inventory::new(limits);
    loop {
        tokio::select! {
            biased;
            command = control.recv() => match command {
                Some(Control::Snapshot(reply)) => {
                    while let Ok(update) = outbound.try_recv() { inventory.apply(update); }
                    let _ = reply.send(inventory.counts);
                }
                Some(Control::Pause { ready, mut resume }) => {
                    while let Ok(update) = outbound.try_recv() { inventory.apply(update); }
                    let _ = ready.send(inventory.counts);
                    loop {
                        tokio::select! {
                            // After resume, snapshots must drain queued route events.
                            biased;
                            _ = &mut resume => break,
                            command = control.recv() => match command {
                                Some(Control::Snapshot(reply)) => {
                                    if paused_snapshot(&mut inventory, &mut outbound, &mut resume, reply) {
                                        break;
                                    }
                                }
                                Some(Control::Credit { request, acknowledged }) => {
                                    let result = async {
                                        request.await.map_err(|_| "credit owner closed".to_owned())?;
                                        let filler = outbound.try_recv().map_err(|e| e.to_string())?;
                                        // No fabricated route or marker is allowed to consume a credit.
                                        assert_empty_credit(&filler);
                                        inventory.apply(filler);
                                        Ok(())
                                    }.await;
                                    let _ = acknowledged.send(result);
                                }
                                _ => panic!("only snapshots and owned credit grants are allowed while paused"),
                            }
                        }
                    }
                }
                Some(Control::Credit { .. }) => panic!("credit requires a paused receiver"),
                None => break,
            },
            update = outbound.recv() => match update { Some(update) => inventory.apply(update), None => break },
        }
    }
}

fn paused_snapshot(
    inventory: &mut Inventory,
    outbound: &mut mpsc::Receiver<OutboundRouteUpdate>,
    resume: &mut oneshot::Receiver<()>,
    reply: oneshot::Sender<Counts>,
) -> bool {
    // Resume may arrive between select's branch polls; recheck before a cached reply.
    let resumed = !matches!(resume.try_recv(), Err(oneshot::error::TryRecvError::Empty));
    if resumed {
        while let Ok(update) = outbound.try_recv() {
            inventory.apply(update);
        }
    }
    let _ = reply.send(inventory.counts);
    resumed
}

fn assert_empty_credit(update: &OutboundRouteUpdate) {
    assert!(
        update.announce.is_empty()
            && update.withdraw.is_empty()
            && update.flowspec_announce.is_empty()
            && update.flowspec_withdraw.is_empty()
            && update.evpn_announce.is_empty()
            && update.evpn_withdraw.is_empty()
            && update.bgpls_announce.is_empty()
            && update.bgpls_withdraw.is_empty()
            && update.vpn_announce.is_empty()
            && update.vpn_withdraw.is_empty()
            && update.labeled_announce.is_empty()
            && update.labeled_withdraw.is_empty()
            && update.rtc_announce.is_empty()
            && update.rtc_withdraw.is_empty()
            && update.otc_blocked.is_empty()
            && update.end_of_rib.is_empty()
            && update.refresh_markers.is_empty()
            && update.next_hop_override.is_empty()
            && !update.request_refresh_all_negotiated
            && update.replay.is_none()
            && update.exact_export_snapshot.is_none()
            && update.announce_source_exclusion.is_none()
            && update.shared_group_encode.is_none(),
        "credit must drain an empty filler"
    );
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
    async fn setup(clients: u32, spec: Spec, limits: [usize; 4]) -> Self {
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
            harness.register(client_addr(i), true, spec, limits).await;
        }
        // The source is registered for a real generation-matched PeerDown.
        // Its non-client profile has an empty second group; receivers share
        // exactly one plain client group and no private fallback.
        harness.register(source, false, spec, [0; 4]).await;
        harness.source_receiver = harness.receivers.pop();
        harness
    }

    async fn register(&mut self, peer: IpAddr, rr_client: bool, spec: Spec, limits: [usize; 4]) {
        let (outbound, receiver) = mpsc::channel(RECOVERY_QUEUE_CAPACITY);
        let (control, commands) = mpsc::channel(1);
        tokio::spawn(consume(receiver, commands, limits));
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
                sendable_families: spec.families(),
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

    async fn staged(&self) -> HashMap<IpAddr, [u64; 4]> {
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
                let counts = FAMILIES.map(|wanted| {
                    families
                        .iter()
                        .find(|(family, _)| *family == wanted)
                        .map_or(0, |(_, count)| *count)
                });
                (peer, counts)
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

    async fn settle(&self, expected: [usize; 4]) -> Vec<Counts> {
        tokio::time::timeout(RECOVERY_CELL_TIMEOUT, async {
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
                    [0; 4]
                );
                if health == (0, 0, 0, 0, 0, 0)
                    && self.receivers.iter().all(|receiver| {
                        staged.get(&receiver.peer).copied().unwrap_or([0; 4])
                            == expected.map(|n| n as u64)
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

    async fn retain_unsynchronized(&self, spec: Spec) -> (Vec<oneshot::Sender<()>>, Vec<Counts>) {
        let mut release = Vec::new();
        let mut retained_counts = self.counts().await;
        let family = spec.seed.iter().position(|n| *n > 0).unwrap();
        for (index, receiver) in self.receivers.iter().enumerate() {
            release.push(receiver.pause().await);
            let added = spec.seed[family] + index;
            let update = if family >= 2 {
                vpn_receipt(self.source, vec![fixture_vpn_route(family % 2, added)])
            } else {
                let mut update =
                    empty_routes_received(self.source, vec![fixture_route(family, added)]);
                if let RibUpdate::RoutesReceived { session_id, .. } = &mut update {
                    *session_id = 1;
                }
                update
            };
            self.tx.send(update).await.unwrap();
            retained_counts = self.unsynchronized_pass(spec, index + 1).await;
        }
        (release, retained_counts)
    }

    async fn unsynchronized_pass(&self, spec: Spec, paused: usize) -> Vec<Counts> {
        let family = spec.seed.iter().position(|n| *n > 0).unwrap();
        tokio::time::timeout(RECOVERY_CELL_TIMEOUT, async {
            loop {
                let health = self.health().await;
                let counts = self.counts().await;
                let ready = health.0 == paused && health.2 == paused
                    && counts.iter().enumerate().all(|(index, count)| {
                        count.present == std::array::from_fn(|f| {
                            spec.seed[f] + if f == family { index.min(paused) } else { 0 }
                        }) && count.withdraws == [0; 4]
                    });
                if ready {
                    let fold = |rows: &[Counts]| {
                        std::array::from_fn(|f| rows.iter().map(|row| row.present[f]).sum::<usize>())
                    };
                    println!(
                        "recovery_unsynchronized {{\"pass\":{},\"clients\":{},\"profile\":\"{}\",\"dirty_peers\":{},\"group_dirty_members\":{},\"paused_families\":{},\"active_families\":{}}}",
                        paused - 1, self.receivers.len(), spec.name, health.0, health.2,
                        family_counts_json(fold(&counts[..paused])),
                        family_counts_json(fold(&counts[paused..])),
                    );
                    return counts;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await.expect("unsynchronized dirty pass did not preserve actual paused OLD and admitted healthy views")
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

pub(super) fn verify_memory_identity(path: &std::path::Path) {
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
    spec: Spec,
    phase: &str,
    memory: Option<&std::path::Path>,
    counts: &[Counts],
) {
    let health = harness.health().await;
    let mut total = Counts::default();
    for count in counts {
        for f in 0..4 {
            total.present[f] += count.present[f];
            total.announces[f] += count.announces[f];
            total.withdraws[f] += count.withdraws[f];
        }
    }
    let clients = harness.receivers.len();
    let limits = spec.cell_limits(cell, clients);
    println!(
        "recovery_sample {{\"schema\":\"rustbgpd.recovery-memory.v2\",\"cell\":\"{}\",\"profile\":\"{}\",\"phase\":\"{phase}\",\"clients\":{clients},\"seed\":{},\"additions\":{},\"receiver_queue_capacity\":{RECOVERY_QUEUE_CAPACITY},\"receiver_bitmap_bytes\":{},\"families\":{},\"folded_routes\":{},\"announces\":{},\"withdrawals\":{},\"dirty_peers\":{},\"group_dirty_members\":{},\"metrics\":{},\"fallback_causes\":{},\"cgroup\":{}}}",
        cell.name(),
        spec.name,
        family_counts_json(spec.seed),
        family_counts_json(spec.cell_additions(cell, clients)),
        clients * limits.iter().map(|n| n.div_ceil(64) * 8).sum::<usize>(),
        total.json(),
        total.present.iter().sum::<usize>(),
        total.announces.iter().sum::<u64>(),
        total.withdraws.iter().sum::<u64>(),
        health.0,
        health.2,
        metrics_json(&harness.metrics),
        fallback_causes_json(&harness.metrics),
        cgroup_json(memory)
    );
}

fn vpn_receipt(source: IpAddr, announced: Vec<VpnRibRoute>) -> RibUpdate {
    RibUpdate::VpnRoutesReceived {
        peer: source,
        session_id: 1,
        announced,
        withdrawn: Vec::new(),
    }
}
async fn populate(harness: &RecoveryHarness, seed: [usize; 4]) {
    for (family, n) in seed.into_iter().enumerate() {
        for start in (0..n).step_by(BATCH) {
            let end = (start + BATCH).min(n);
            let update = if family >= 2 {
                vpn_receipt(
                    harness.source,
                    (start..end)
                        .map(|i| fixture_vpn_route(family % 2, i))
                        .collect(),
                )
            } else {
                let mut update = empty_routes_received(
                    harness.source,
                    (start..end).map(|i| fixture_route(family, i)).collect(),
                );
                if let RibUpdate::RoutesReceived { session_id, .. } = &mut update {
                    *session_id = 1;
                }
                update
            };
            harness.tx.send(update).await.unwrap();
        }
    }
}
async fn run(cell: Cell, clients: u32, spec: Spec, memory: Option<&std::path::Path>) {
    assert!(clients > 0 && spec.seed.iter().sum::<usize>() > 0);
    if cell == Cell::Widen {
        assert!(
            spec.additions.iter().sum::<usize>() > 0,
            "profile has no widening cell"
        );
    }
    let harness =
        RecoveryHarness::setup(clients, spec, spec.cell_limits(cell, clients as usize)).await;
    harness.verify_group().await;
    populate(&harness, spec.seed).await;
    let initial = harness.settle(spec.seed).await;
    assert!(initial.iter().all(|count| count.withdraws == [0; 4]
        && (0..4).all(|f| count.announces[f] >= spec.seed[f] as u64)));
    sample(&harness, cell, spec, "population_ready", memory, &initial).await;
    let mut release = Vec::new();
    let mut retained_counts = initial.clone();
    if cell == Cell::UnsynchronizedDirty {
        let retained = harness.retain_unsynchronized(spec).await;
        release = retained.0;
        retained_counts = retained.1;
    } else {
        for receiver in &harness.receivers {
            release.push(receiver.pause().await);
        }
    }
    let expected = if cell == Cell::UnsynchronizedDirty {
        spec.cell_limits(cell, clients as usize)
    } else if cell == Cell::PeerDown {
        harness
            .tx
            .send(RibUpdate::PeerDown {
                peer: harness.source,
                session_id: 1,
            })
            .await
            .unwrap();
        // BMP query is an actor FIFO barrier and covers VPN as well as unicast.
        let staged = harness.staged().await;
        assert!(
            harness.receivers.iter().all(|receiver| staged
                .get(&receiver.peer)
                .copied()
                .unwrap_or([0; 4])
                == [0; 4]),
            "actual source withdrawal must remove every family"
        );
        [0; 4]
    } else {
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
        spec.seed
    };
    let health = harness.health().await;
    assert_eq!(
        (health.0, health.2),
        (clients as usize, clients as usize),
        "actual simultaneous dirty/group-dirty receivers"
    );
    if cell == Cell::Widen {
        let mut grants = Vec::new();
        for receiver in &harness.receivers {
            let (grant, request) = oneshot::channel();
            let (acknowledged, ack) = std::sync::mpsc::channel();
            receiver
                .control
                .send(Control::Credit {
                    request,
                    acknowledged,
                })
                .await
                .unwrap();
            grants.push((grant, std::sync::Mutex::new(ack)));
        }
        let announced = (2..4)
            .flat_map(|f| {
                (spec.seed[f]..spec.seed[f] + spec.additions[f])
                    .map(move |i| fixture_vpn_route(f % 2, i))
            })
            .collect();
        let (reply, accepted) = oneshot::channel();
        harness
            .tx
            .send(RibUpdate::BenchVpnAdmissionWithCredit {
                grants,
                update: Box::new(vpn_receipt(harness.source, announced)),
                reply,
            })
            .await
            .unwrap();
        accepted
            .await
            .unwrap()
            .expect("one-shot VPN admission must complete");
        let health = harness.health().await;
        assert_eq!(
            (health.0, health.2),
            (clients as usize, clients as usize),
            "new admitted keys must remain inside dirty recovery"
        );
        // Consumers still hold the seed fold. Only the production admitted-key
        // gauge, observed behind the synchronous receipt, proves sparse admission.
        // The measured checker applies capability-specific assertions to each SHA.
    }
    sample(&harness, cell, spec, "retained", memory, &retained_counts).await;
    sample(
        &harness,
        cell,
        spec,
        "operation_end",
        memory,
        &retained_counts,
    )
    .await;
    for resume in release {
        resume.send(()).unwrap();
    }
    let terminal = if cell == Cell::Widen {
        spec.counts(true)
    } else {
        expected
    };
    let final_counts = harness.settle(terminal).await;
    assert!(
        final_counts.iter().all(|count| count.withdraws
            == if cell == Cell::PeerDown {
                spec.seed.map(|n| n as u64)
            } else {
                [0; 4]
            }),
        "wrong exact withdrawal duties or unchanged-policy withdrawal flap"
    );
    sample(&harness, cell, spec, "settled", memory, &final_counts).await;
    println!(
        "recovery_complete {{\"cell\":\"{}\",\"profile\":\"{}\",\"expected_families_per_receiver\":{},\"actual_receivers\":{clients}}}",
        cell.name(),
        spec.name,
        family_counts_json(terminal)
    );
}

pub(super) fn main(args: &[String]) {
    assert!(
        args.len() == 3 || (args.len() == 4 && args[3] == "--correctness-only"),
        "usage: rrharness recovery-memory <dataset-reevaluate|peer-down|widen|unsynchronized-dirty> <clients> <profile> [--correctness-only]"
    );
    let cell = match args[0].as_str() {
        "dataset-reevaluate" => Cell::DatasetReevaluate,
        "peer-down" => Cell::PeerDown,
        "widen" => Cell::Widen,
        "unsynchronized-dirty" => Cell::UnsynchronizedDirty,
        _ => panic!("unknown recovery cell"),
    };
    let clients = args[1].parse().expect("clients must be a u32");
    let spec = Spec::named(&args[2]);
    let path = if args.len() == 4 {
        None
    } else {
        Some(std::path::PathBuf::from(
            std::env::var("RRHARNESS_RECOVERY_CGROUP")
                .expect("measured mode requires the swap-fenced launcher"),
        ))
    };
    if let Some(path) = &path {
        verify_memory_identity(path);
        cgroup_json(Some(path));
    }
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            tokio::time::timeout(
                RECOVERY_CELL_TIMEOUT,
                run(cell, clients, spec, path.as_deref()),
            )
            .await
            .expect("recovery cell did not complete all acceptance and drain barriers");
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn snapshot_rechecks_release_after_a_pending_resume_poll() {
        let (outbound, mut updates) = mpsc::channel(1);
        outbound
            .try_send(OutboundRouteUpdate {
                announce: vec![fixture_route(0, 0)].into(),
                ..Default::default()
            })
            .unwrap();
        let (release, mut resume) = oneshot::channel();
        let mut inventory = Inventory::new([1, 0, 0, 0]);
        let (reply, snapshot) = oneshot::channel();
        assert!(!paused_snapshot(
            &mut inventory,
            &mut updates,
            &mut resume,
            reply
        ));
        assert_eq!(snapshot.await.unwrap().present, [0; 4]);
        assert_eq!(outbound.capacity(), 0);
        std::future::poll_fn(|context| {
            assert!(
                std::future::Future::poll(std::pin::Pin::new(&mut resume), context).is_pending()
            );
            std::task::Poll::Ready(())
        })
        .await;
        release.send(()).unwrap();
        let (reply, snapshot) = oneshot::channel();
        assert!(paused_snapshot(
            &mut inventory,
            &mut updates,
            &mut resume,
            reply
        ));
        assert_eq!(snapshot.await.unwrap().present, [1, 0, 0, 0]);
        assert_eq!(outbound.capacity(), 1);
    }

    #[tokio::test]
    async fn paused_snapshot_preserves_backpressure_until_resume() {
        for _ in 0..32 {
            let (outbound, updates) = mpsc::channel(RECOVERY_QUEUE_CAPACITY);
            let (control, commands) = mpsc::channel(4);
            let consumer = tokio::spawn(consume(updates, commands, [1, 0, 0, 0]));
            let receiver = Receiver {
                peer: IpAddr::V4(source_addr(1)),
                outbound,
                control,
            };
            let (ready, paused) = oneshot::channel();
            let (release, resume) = oneshot::channel();
            receiver
                .control
                .send(Control::Pause { ready, resume })
                .await
                .unwrap();
            paused.await.unwrap();
            receiver
                .outbound
                .try_send(OutboundRouteUpdate {
                    announce: vec![fixture_route(0, 0)].into(),
                    ..Default::default()
                })
                .unwrap();
            while receiver.outbound.capacity() > 0 {
                receiver
                    .outbound
                    .try_send(OutboundRouteUpdate::default())
                    .unwrap();
            }
            assert_eq!(receiver.snapshot().await.present, [0; 4]);
            assert_eq!(receiver.outbound.capacity(), 0);
            release.send(()).unwrap();
            // Current-thread execution makes resume and Snapshot ready together.
            assert_eq!(receiver.snapshot().await.present, [1, 0, 0, 0]);
            assert_eq!(receiver.outbound.capacity(), RECOVERY_QUEUE_CAPACITY);
            drop(receiver);
            consumer.await.unwrap();
        }
    }

    #[test]
    fn bitmap_tracks_full_family_and_raw_rd_identity() {
        let mut inventory = Inventory::new([100; 4]);
        for f in 0..2 {
            inventory.apply(OutboundRouteUpdate {
                announce: vec![fixture_route(f, 99)].into(),
                vpn_announce: vec![fixture_vpn_route(f, 98), fixture_vpn_route(f, 99)],
                ..Default::default()
            });
        }
        assert_eq!(RDS[0].to_string(), RDS[1].to_string());
        assert_ne!(RDS[0], RDS[1]);
        assert_eq!(inventory.counts.present, [1, 1, 2, 2]);
        assert_eq!(
            inventory.words.iter().map(|w| w.len() * 8).sum::<usize>(),
            64
        );
        for f in 0..2 {
            inventory.apply(OutboundRouteUpdate {
                withdraw: vec![(fixture_prefix(f, 99), 0)],
                vpn_withdraw: vec![
                    fixture_vpn_route(f, 98).key(),
                    fixture_vpn_route(f, 99).key(),
                ],
                ..Default::default()
            });
        }
        assert_eq!(inventory.counts.present, [0; 4]);
    }
    #[test]
    #[should_panic(expected = "unadmitted exact key")]
    fn bitmap_rejects_unknown_withdrawal() {
        Inventory::new([100; 4]).apply(OutboundRouteUpdate {
            withdraw: vec![(fixture_prefix(0, 1), 0)],
            ..Default::default()
        });
    }
    #[test]
    #[should_panic(expected = "unadmitted exact key")]
    fn bitmap_rejects_repeated_vpn_withdrawal() {
        let mut inventory = Inventory::new([100; 4]);
        let value = fixture_vpn_route(1, 1);
        inventory.apply(OutboundRouteUpdate {
            vpn_announce: vec![value.clone()],
            ..Default::default()
        });
        for _ in 0..2 {
            inventory.apply(OutboundRouteUpdate {
                vpn_withdraw: vec![value.key()],
                ..Default::default()
            });
        }
    }
    #[test]
    #[should_panic(expected = "wrong VPN label")]
    fn bitmap_rejects_wrong_vpn_label() {
        let mut value = fixture_vpn_route(0, 0);
        value.nlri.labels[0].label += 1;
        Inventory::new([100; 4]).apply(OutboundRouteUpdate {
            vpn_announce: vec![value],
            ..Default::default()
        });
    }
    #[test]
    #[should_panic(expected = "wrong expected attributes")]
    fn bitmap_rejects_wrong_attributes() {
        let mut value = fixture_vpn_route(0, 0);
        value.attributes = expected_attributes(false, 0);
        Inventory::new([100; 4]).apply(OutboundRouteUpdate {
            vpn_announce: vec![value],
            ..Default::default()
        });
    }
    #[test]
    #[should_panic(expected = "outside the exact finite inventory")]
    fn bitmap_rejects_unnegotiated_family() {
        Inventory::new([100, 0, 0, 0]).apply(OutboundRouteUpdate {
            announce: vec![fixture_route(1, 0)].into(),
            ..Default::default()
        });
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn unsynchronized_dirty_retains_actual_old_keys_with_one_bounded_universe() {
        const CLIENTS: u32 = 3;
        for profile in ["smoke-uc", "smoke-vpn"] {
            let spec = Spec::named(profile);
            let limits = spec.cell_limits(Cell::UnsynchronizedDirty, CLIENTS as usize);
            let harness = RecoveryHarness::setup(CLIENTS, spec, limits).await;
            harness.verify_group().await;
            populate(&harness, spec.seed).await;
            harness.settle(spec.seed).await;
            let gauge = |name: &str| {
                harness
                    .metrics
                    .registry()
                    .gather()
                    .into_iter()
                    .find(|m| m.name() == name)
                    .unwrap()
                    .get_metric()[0]
                    .get_gauge()
                    .get_value() as u64
            };
            let healthy_bytes = gauge("bgp_update_group_recovery_bytes");
            let (release, retained) = harness.retain_unsynchronized(spec).await;
            assert_eq!(harness.health().await.0, CLIENTS as usize);
            let expected_keys = u64::from(CLIENTS) * spec.seed.iter().sum::<usize>() as u64
                + u64::from(CLIENTS * (CLIENTS - 1) / 2);
            assert_eq!(
                retained
                    .iter()
                    .map(|row| row.present.iter().sum::<usize>() as u64)
                    .sum::<u64>(),
                expected_keys
            );
            assert_eq!(gauge("bgp_update_group_recovery_entries"), expected_keys);
            // Logical component credits, not an RSS or timing measurement.
            let retained_bytes = gauge("bgp_update_group_recovery_bytes");
            if profile == "smoke-uc" {
                assert!(
                    retained_bytes < 16 * 1024,
                    "three small unicast proofs must share their indexed key universe"
                );
            } else {
                // Each VPN-capable receiver retains its own exact flat key set.
                // Fixed record/slack credits must not hide another route-sized array.
                let key_payload =
                    expected_keys * u64::try_from(std::mem::size_of::<VpnRibRouteKey>()).unwrap();
                assert!(retained_bytes >= healthy_bytes + key_payload);
                assert!(retained_bytes < healthy_bytes + key_payload + u64::from(CLIENTS) * 1024);
            }
            for resume in release {
                resume.send(()).unwrap();
            }
            let final_counts = harness.settle(limits).await;
            assert!(final_counts.iter().all(|row| row.withdraws == [0; 4]));
            assert_eq!(gauge("bgp_update_group_recovery_entries"), 0);
            assert_eq!(gauge("bgp_update_group_recovery_bytes"), healthy_bytes);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn widening_retains_new_admitted_keys_while_dirty() {
        let spec = Spec::named("smoke-mixed");
        let harness = RecoveryHarness::setup(1, spec, spec.counts(true)).await;
        populate(&harness, spec.seed).await;
        harness.settle(spec.seed).await;
        let resume = harness.receivers[0].pause().await;
        let (reply, accepted) = oneshot::channel();
        harness
            .tx
            .send(RibUpdate::ReevaluatePeerExportPolicies {
                peers: vec![harness.receivers[0].peer],
                reply,
            })
            .await
            .unwrap();
        accepted.await.unwrap().unwrap();
        let before = harness
            .metrics
            .registry()
            .gather()
            .into_iter()
            .find(|m| m.name() == "bgp_update_group_recovery_entries")
            .unwrap()
            .get_metric()[0]
            .get_gauge()
            .get_value();
        let (grant, request) = oneshot::channel();
        let (acknowledged, ack) = std::sync::mpsc::channel();
        harness.receivers[0]
            .control
            .send(Control::Credit {
                request,
                acknowledged,
            })
            .await
            .unwrap();
        let (reply, accepted) = oneshot::channel();
        harness
            .tx
            .send(RibUpdate::BenchVpnAdmissionWithCredit {
                grants: vec![(grant, std::sync::Mutex::new(ack))],
                update: Box::new(vpn_receipt(harness.source, vec![fixture_vpn_route(0, 0)])),
                reply,
            })
            .await
            .unwrap();
        accepted.await.unwrap().unwrap();
        let after = harness
            .metrics
            .registry()
            .gather()
            .into_iter()
            .find(|m| m.name() == "bgp_update_group_recovery_entries")
            .unwrap()
            .get_metric()[0]
            .get_gauge()
            .get_value();
        assert_eq!(before, 200.0);
        assert_eq!(after, before + 1.0);
        let health = harness.health().await;
        assert_eq!((health.0, health.2), (1, 1));
        resume.send(()).unwrap();
        harness.settle([160, 40, 1, 0]).await;
    }
}
