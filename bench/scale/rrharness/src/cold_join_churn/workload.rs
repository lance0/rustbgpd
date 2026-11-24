//! The October 2026 converged-rejoin receipt used 572 disjoint routes per
//! source. The September 28 RR soak recorded 3,808 churn cycles in its first
//! 60 s: eight members each toggle 16 prefixes every 125 ms. Use the same
//! phased stream while one other source hard-flaps without GR retention.

use std::{
    io,
    net::{IpAddr, Ipv4Addr},
    time::{Duration, Instant},
};

use rustbgpd_rib::{route::Route, update::RibUpdate, PeerId};
use rustbgpd_wire::{Afi, Ipv4Prefix, Prefix, Safi};
use tokio::{
    sync::{mpsc, watch},
    task::JoinSet,
    time::{self, MissedTickBehavior},
};

use crate::{invalid_stat, route, BATCH, CONVERGENCE_TIMEOUT};

const STREAM_SOURCES: u8 = 8;
const STREAM_WIDTH: u32 = 16;
const PERIOD: Duration = Duration::from_millis(125);
const FLAP_SOURCE: Ipv4Addr = Ipv4Addr::new(10, 2, 0, 1);
const FIRST_SESSION: u64 = 1;
const RETURNING_SESSION: u64 = 2;

#[derive(Clone, Copy)]
pub(super) struct Workload {
    pub(super) flap_rows: u32,
    pub(super) stream_block: u32,
}

impl Default for Workload {
    fn default() -> Self {
        Self {
            flap_rows: 572,
            stream_block: STREAM_WIDTH,
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct StreamTick {
    pub(super) admitted: Instant,
    pub(super) source: u8,
    pub(super) announce: bool,
}

pub(super) struct ChurnReport {
    /// Timestamps at admission to the ordinary primary RIB FIFO.
    pub(super) flap_down: Instant,
    pub(super) flap_up: Instant,
    pub(super) flap_reannounced: Instant,
    /// Sorted admissions of scheduled stream batches. The five-minute timeout
    /// and 125 ms Skip ticker bound storage to about 2,400 times per source.
    /// Cleanup batches do not count as overlap.
    pub(super) stream_ticks: Vec<StreamTick>,
    pub(super) stream_cleanup_batches: usize,
}

fn peer(addr: Ipv4Addr) -> PeerId {
    PeerId::from_addr(IpAddr::V4(addr))
}

fn stream_source(index: u8) -> Ipv4Addr {
    Ipv4Addr::new(10, 2, 1, index + 1)
}

fn prefix(second: u8, index: u32) -> Ipv4Prefix {
    let addr = u32::from(Ipv4Addr::new(198, second, 0, 0)) + index;
    Ipv4Prefix::new(Ipv4Addr::from(addr), 32)
}

async fn send(tx: &mpsc::Sender<RibUpdate>, update: RibUpdate) -> io::Result<Instant> {
    let slot = tx
        .reserve()
        .await
        .map_err(|_| invalid_stat("RIB input closed"))?;
    let admitted = Instant::now();
    slot.send(update);
    Ok(admitted)
}

async fn source_up(
    tx: &mpsc::Sender<RibUpdate>,
    addr: Ipv4Addr,
    session_id: u64,
) -> io::Result<Instant> {
    let (outbound_tx, mut rx) = mpsc::channel(1);
    // The input-only session keeps its receiver alive through PeerDown.
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    send(
        tx,
        RibUpdate::PeerUp {
            supersedes: None,
            peer: peer(addr),
            session_id,
            peer_asn: 64512,
            peer_router_id: addr,
            outbound_tx,
            export_policy: None,
            sendable_families: Vec::new(),
            is_ebgp: false,
            route_reflector_client: false,
            orr_vantage: None,
            per_client_best: false,
            interpret_rfc1997: true,
            add_path_send_families: Vec::new(),
            add_path_send_max: 0,
            negotiated_orf_recv: Vec::new(),
            negotiated_llgr_families: Vec::new(),
        },
    )
    .await
}

fn received(
    source: Ipv4Addr,
    session_id: u64,
    announced: Vec<Route>,
    withdrawn: Vec<(Prefix, u32)>,
) -> RibUpdate {
    RibUpdate::RoutesReceived {
        peer: peer(source),
        session_id,
        announced,
        withdrawn,
        flowspec_announced: Vec::new(),
        flowspec_withdrawn: Vec::new(),
        evpn_announced: Vec::new(),
        evpn_withdrawn: Vec::new(),
        validated_with: None,
    }
}

impl Workload {
    async fn announce_flap_table(
        &self,
        tx: &mpsc::Sender<RibUpdate>,
        session: u64,
        local_pref: u32,
    ) -> io::Result<Instant> {
        let mut start = 0;
        let last = loop {
            let end = (start + BATCH as u32).min(self.flap_rows);
            let batch = (start..end)
                .map(|index| route(prefix(20, index), FLAP_SOURCE, local_pref))
                .collect();
            let admitted = send(tx, received(FLAP_SOURCE, session, batch, Vec::new())).await?;
            if end == self.flap_rows {
                break admitted;
            }
            start = end;
        };
        send(
            tx,
            RibUpdate::EndOfRib {
                peer: peer(FLAP_SOURCE),
                session_id: session,
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
            },
        )
        .await?;
        Ok(last)
    }

    /// Seed both clean and mixed trials before the receiver joins.
    pub(super) async fn seed(&self, tx: &mpsc::Sender<RibUpdate>) -> io::Result<()> {
        source_up(tx, FLAP_SOURCE, FIRST_SESSION).await?;
        for index in 0..STREAM_SOURCES {
            source_up(tx, stream_source(index), FIRST_SESSION).await?;
        }
        self.announce_flap_table(tx, FIRST_SESSION, 100).await?;
        Ok(())
    }

    fn stream_update(&self, index: u8, announce: bool) -> RibUpdate {
        let source = stream_source(index);
        let first = u32::from(index) * STREAM_WIDTH;
        let prefixes = (first..first + self.stream_block).map(|offset| prefix(19, offset));
        if announce {
            let batch = prefixes.map(|key| route(key, source, 100)).collect();
            received(source, FIRST_SESSION, batch, Vec::new())
        } else {
            let batch = prefixes.map(|key| (Prefix::V4(key), 0)).collect();
            received(source, FIRST_SESSION, Vec::new(), batch)
        }
    }

    async fn stream(
        self,
        tx: mpsc::Sender<RibUpdate>,
        mut stop: watch::Receiver<bool>,
        index: u8,
        start: time::Instant,
    ) -> io::Result<(Vec<StreamTick>, bool)> {
        let phase = PERIOD / u32::from(STREAM_SOURCES) * u32::from(index);
        let mut ticker = time::interval_at(start + phase, PERIOD);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut announced = false;
        let mut ticks = Vec::new();
        loop {
            if *stop.borrow_and_update() {
                break;
            }
            tokio::select! {
                biased;
                stopped = stop.changed() => {
                    stopped.map_err(|_| invalid_stat("churn stop channel closed before EoR"))?;
                }
                _ = ticker.tick() => {
                    let announce = !announced;
                    let admitted = send(&tx, self.stream_update(index, announce)).await?;
                    ticks.push(StreamTick { admitted, source: index, announce });
                    announced = announce;
                }
            }
        }
        if announced {
            send(&tx, self.stream_update(index, false)).await?;
        }
        Ok((ticks, announced))
    }

    /// Start at the first base page. The receiver signals stop at its initial
    /// EoR. A separate final fence follows the workload's terminal withdrawals.
    pub(super) async fn run(
        &self,
        tx: &mpsc::Sender<RibUpdate>,
        stop: watch::Receiver<bool>,
        mut flap_gone: watch::Receiver<bool>,
    ) -> io::Result<ChurnReport> {
        time::timeout(CONVERGENCE_TIMEOUT, async {
            if *flap_gone.borrow_and_update() {
                return Err(invalid_stat(
                    "flap witness was already clear before PeerDown",
                ));
            }
            let mut sources = JoinSet::new();
            let start = time::Instant::now();
            for index in 0..STREAM_SOURCES {
                sources.spawn(self.stream(tx.clone(), stop.clone(), index, start));
            }
            let flap_down = send(
                tx,
                RibUpdate::PeerDown {
                    peer: peer(FLAP_SOURCE),
                    session_id: FIRST_SESSION,
                },
            )
            .await?;
            // A returning epoch cannot race the observer's evidence for the
            // original source: every original flap prefix must be gone first.
            flap_gone.wait_for(|gone| *gone).await.map_err(|_| {
                invalid_stat("flap witness closed before all original prefixes withdrew")
            })?;
            let flap_up = source_up(tx, FLAP_SOURCE, RETURNING_SESSION).await?;
            let flap_reannounced = self.announce_flap_table(tx, RETURNING_SESSION, 110).await?;
            let mut stream_ticks = Vec::new();
            let mut stream_cleanup_batches = 0;
            while let Some(source) = sources.join_next().await {
                let (mut ticks, cleanup) = source.map_err(io::Error::other)??;
                stream_ticks.append(&mut ticks);
                stream_cleanup_batches += usize::from(cleanup);
            }
            stream_ticks.sort_unstable_by_key(|tick| tick.admitted);
            if stream_ticks.is_empty() {
                return Err(invalid_stat(
                    "no scheduled stream batch was admitted before stop",
                ));
            }
            Ok(ChurnReport {
                flap_down,
                flap_up,
                flap_reannounced,
                stream_ticks,
                stream_cleanup_batches,
            })
        })
        .await
        .map_err(|_| invalid_stat("source churn exceeded the join deadline"))?
    }
}
