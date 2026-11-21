//! Real eBGP route-server writers behind the cell's controllable RIB queues.
//! Every admitted envelope retains the exact encoder of its physical session.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::{bail, ensure, Context, Result};
use rustbgpd_evpn_load::{establish_on, PeerConfig as StubConfig};
use rustbgpd_policy::PolicyChain;
use rustbgpd_rib::update::{OutboundRouteUpdate, RibUpdate};
use rustbgpd_rib::PeerId;
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_transport::{NeighborCounters, PeerHandle, RibPeerSlot, SessionIdentity};
use rustbgpd_wire::{Afi, Message, RouteRefreshMessage, Safi};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::grouped_old::WireFailure;
use crate::grouped_old_wire::{GroupedWire, Phase};

const REMOTE_AS: u32 = 65_001;
const FAMILY: (Afi, Safi) = (Afi::Ipv4, Safi::Unicast);
const SETUP_TIMEOUT: Duration = Duration::from_secs(60);
/// Keepalives go out every 60 s on both sides. Neither side's timers share a
/// thread with the RIB actor, so the length of an actor turn does not reach
/// them; the hold time only has to outlast a scheduling gap on the 12-worker
/// session runtime, which the receipt records.
pub(crate) const HOLD_TIME_SECS: u16 = 180;
// The fence can be behind a full seed at 700 clients. This is a hang guard only.
const FENCE_TIMEOUT: Duration = Duration::from_secs(30 * 60);

type Writer = mpsc::Sender<OutboundRouteUpdate>;
type Fence = (Phase, oneshot::Sender<Result<Value>>);

struct Client {
    ip: Ipv4Addr,
    session_id: u64,
    session: Option<PeerHandle>,
    counters: NeighborCounters,
    writer: Writer,
    registration: Vec<RibUpdate>,
    events: mpsc::Receiver<RibUpdate>,
    fences: mpsc::Sender<Fence>,
    reader: JoinHandle<Result<()>>,
    stub_tasks: [JoinHandle<()>; 2],
    _stub_tx: mpsc::Sender<Message>,
}

impl Drop for Client {
    fn drop(&mut self) {
        if let Some(session) = &self.session {
            session.abort_for_transport_safety();
        }
        self.reader.abort();
        for task in &self.stub_tasks {
            task.abort();
        }
    }
}

async fn registration(
    events: &mut mpsc::Receiver<RibUpdate>,
    ip: Ipv4Addr,
    id: u64,
) -> Result<(Writer, Vec<RibUpdate>)> {
    let expected_peer = PeerId::from_ipv4(ip);
    let mut registration = Vec::new();
    let mut writer = None;
    let mut has_encoder = false;
    let mut has_rs_context = false;
    while let Some(event) = events.recv().await {
        match &event {
            RibUpdate::SetPeerExportEncoder {
                peer, session_id, ..
            } => {
                ensure!(
                    *peer == expected_peer && *session_id == id && !has_encoder,
                    "unexpected encoder owner"
                );
                has_encoder = true;
            }
            RibUpdate::SetPeerSourceContext {
                peer,
                session_id,
                context,
            } => {
                ensure!(
                    *peer == expected_peer && *session_id == id && context.route_server_client,
                    "unexpected route server context for {ip}"
                );
                has_rs_context = true;
            }
            RibUpdate::PeerUp {
                peer,
                session_id,
                outbound_tx,
                peer_asn,
                peer_router_id,
                export_policy,
                sendable_families,
                is_ebgp,
                interpret_rfc1997,
                add_path_send_families,
                ..
            } => {
                ensure!(
                    has_encoder && has_rs_context && writer.is_none(),
                    "invalid registration order"
                );
                ensure!(
                    *peer == expected_peer
                        && *session_id == id
                        && *peer_router_id == ip
                        && *peer_asn == REMOTE_AS
                        && *is_ebgp
                        && !*interpret_rfc1997
                        && export_policy.is_some()
                        && sendable_families.as_slice() == [FAMILY]
                        && add_path_send_families.is_empty(),
                    "unexpected registration for {ip}"
                );
                writer = Some(outbound_tx.clone());
            }
            RibUpdate::PeerAddPathLimits {
                peer, session_id, ..
            } => {
                ensure!(
                    *peer == expected_peer && *session_id == id,
                    "unexpected final registration owner"
                );
                registration.push(event);
                return Ok((writer.context("registry omitted PeerUp")?, registration));
            }
            RibUpdate::PeerDown { .. } | RibUpdate::PeerGracefulRestart { .. } => {
                bail!("{ip} lost its session before registration");
            }
            _ => {}
        }
        registration.push(event);
    }
    bail!("{ip} registration channel closed");
}

async fn collect(
    rows: usize,
    mut rx: mpsc::Receiver<Message>,
    mut fences: mpsc::Receiver<Fence>,
) -> Result<()> {
    let mut wire = GroupedWire::new(rows);
    let marker = RouteRefreshMessage::new(FAMILY.0, FAMILY.1);
    while let Some(message) = rx.recv().await {
        if matches!(&message, Message::RouteRefresh(refresh) if *refresh == marker) {
            let (phase, reply) = fences.try_recv().context("unexpected wire fence")?;
            let evidence = wire
                .verify(phase)
                .context(WireFailure)
                .map(|()| wire.receipt());
            let failed = evidence.is_err();
            let _ = reply.send(evidence);
            ensure!(!failed, "wire inventory failed at {phase:?}");
        } else {
            wire.apply_message(&message).context(WireFailure)?;
        }
    }
    bail!("decoded session closed");
}

impl Client {
    async fn connect(
        ip: Ipv4Addr,
        index: usize,
        rows: usize,
        metrics: &BgpMetrics,
        policy: &PolicyChain,
    ) -> Result<Self> {
        let listener = TcpListener::bind(SocketAddr::from((ip, 0))).await?;
        let address = listener.local_addr()?;
        let mut config = crate::transport_config(address);
        config.peer.remote_asn = REMOTE_AS;
        config.peer.hold_time = HOLD_TIME_SECS;
        config.peer.send_hold_time = 0;
        config.route_server_client = true;
        config.route_reflector_client = false;
        config.cluster_id = None;
        config.interpret_rfc1997 = false;
        config.rib_peer = RibPeerSlot::assigned(PeerId::from_ipv4(ip));
        let counters = config.neighbor_counters.clone();
        let stub_config = StubConfig {
            listen: address,
            local_as: REMOTE_AS,
            router_id: ip,
            hold_time: config.peer.hold_time,
            families: vec![FAMILY],
            extended_message: false,
        };
        let session_id = u64::try_from(index)? + 1;
        let (tx, mut events) = mpsc::channel(64);
        let session = PeerHandle::spawn_with_identity(
            config,
            metrics.clone(),
            tx,
            None,
            Some(policy.clone()),
            None,
            None,
            None,
            None,
            false,
            SessionIdentity::primary(session_id),
        );
        session.start().await?;
        let pending = async {
            tokio::try_join!(
                async { Ok::<_, anyhow::Error>(establish_on(listener, stub_config).await?) },
                registration(&mut events, ip, session_id),
            )
        };
        let established = tokio::time::timeout(SETUP_TIMEOUT, pending)
            .await
            .context("session handshake timed out")
            .and_then(|r| r);
        let (stub, (writer, registration)) = match established {
            Ok(result) => result,
            Err(error) => {
                session.abort_for_transport_safety_and_wait().await;
                return Err(error);
            }
        };
        let (fences, fence_rx) = mpsc::channel(1);
        Ok(Self {
            ip,
            session_id,
            session: Some(session),
            counters,
            writer,
            registration,
            events,
            fences,
            reader: tokio::spawn(collect(rows, stub.rx, fence_rx)),
            stub_tasks: stub.tasks,
            _stub_tx: stub.tx,
        })
    }

    fn check_registration(&mut self) -> Result<()> {
        let resets = self.counters.flaps();
        if resets != 0 {
            return Err(anyhow::anyhow!("{} had {resets} session resets", self.ip))
                .context(WireFailure);
        }
        loop {
            match self.events.try_recv() {
                Ok(
                    RibUpdate::PeerDown { .. }
                    | RibUpdate::PeerGracefulRestart { .. }
                    | RibUpdate::PeerUp { .. },
                ) => {
                    return Err(anyhow::anyhow!("{} lost or replaced its session", self.ip))
                        .context(WireFailure)
                }
                Ok(_) => {}
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => bail!("{} session ended", self.ip),
            }
        }
        ensure!(
            self.session
                .as_ref()
                .is_some_and(PeerHandle::is_established),
            "{} left Established",
            self.ip
        );
        Ok(())
    }
}

pub(crate) struct SessionFleet {
    clients: Vec<Client>,
    seed_fences: usize,
}

impl SessionFleet {
    pub(crate) async fn connect(
        ips: &[Ipv4Addr],
        rows: usize,
        policy: &PolicyChain,
    ) -> Result<Self> {
        let metrics = BgpMetrics::new();
        let mut clients = Vec::with_capacity(ips.len());
        for (index, &ip) in ips.iter().enumerate() {
            clients.push(
                Client::connect(ip, index, rows, &metrics, policy)
                    .await
                    .with_context(|| format!("establish grouped receiver {ip}"))?,
            );
        }
        Ok(Self {
            clients,
            seed_fences: 0,
        })
    }

    pub(crate) fn writer(&self, index: usize) -> Writer {
        self.clients[index].writer.clone()
    }

    /// Transfer the actual session registration to the measured RIB, swapping
    /// just its receiver queue for the controlled two-slot admission boundary.
    pub(crate) fn take_registration(
        &mut self,
        index: usize,
        gate: Writer,
    ) -> Result<Vec<RibUpdate>> {
        let mut registration = std::mem::take(&mut self.clients[index].registration);
        let target = registration
            .iter_mut()
            .find_map(|update| match update {
                RibUpdate::PeerUp { outbound_tx, .. } => Some(outbound_tx),
                _ => None,
            })
            .context("registration already consumed")?;
        *target = gate;
        Ok(registration)
    }

    // The stub negotiates ordinary RFC 2918 refresh for IPv4 only. No peer
    // replacement or refresh request occurs in this scenario. Transport puts
    // this frame on the same bulk FIFO behind the preceding route envelopes.
    async fn verify(&mut self, phase: Phase) -> Result<Vec<Value>> {
        let deadline = tokio::time::Instant::now() + FENCE_TIMEOUT;
        let mut acknowledgements = Vec::with_capacity(self.clients.len());
        for client in &mut self.clients {
            client.check_registration()?;
            let (tx, rx) = oneshot::channel();
            if let Err(err) = client.fences.try_send((phase, tx)) {
                if matches!(err, mpsc::error::TrySendError::Closed(_)) {
                    (&mut client.reader)
                        .await?
                        .with_context(|| format!("{} wire decode", client.ip))?;
                }
                bail!("closed or occupied {phase:?} fence on {}", client.ip);
            }
            let envelope = OutboundRouteUpdate {
                request_refresh_all_negotiated: true,
                ..Default::default()
            };
            tokio::time::timeout_at(deadline, client.writer.send(envelope))
                .await?
                .map_err(|_| anyhow::anyhow!("writer {} closed before {phase:?}", client.ip))?;
            acknowledgements.push(rx);
        }
        let mut receipts = Vec::with_capacity(self.clients.len());
        for (client, rx) in self.clients.iter_mut().zip(acknowledgements) {
            let result = tokio::time::timeout_at(deadline, rx)
                .await
                .with_context(|| format!("{}: decoded {phase:?} fence timed out", client.ip))?;
            let wire = match result {
                Ok(proof) => proof?,
                Err(error) => {
                    client.check_registration()?;
                    (&mut client.reader).await??;
                    return Err(error.into());
                }
            };
            client.check_registration()?;
            receipts
                .push(json!({"peer": client.ip, "session_id": client.session_id, "wire": wire}));
        }
        Ok(receipts)
    }

    pub(crate) async fn verify_seed(&mut self) -> Result<()> {
        ensure!(self.seed_fences == 0, "seed fence already sent");
        self.seed_fences = self.verify(Phase::Seed).await?.len();
        Ok(())
    }

    pub(crate) async fn finish(mut self) -> Result<Value> {
        let count = self.clients.len();
        ensure!(
            count > 0 && self.seed_fences == count,
            "missing seed witnesses"
        );
        let receivers = self.verify(Phase::Final).await?;
        for client in &mut self.clients {
            client.check_registration()?;
            ensure!(
                !client.reader.is_finished(),
                "{} final reader exited",
                client.ip
            );
        }
        let resets: u64 = self
            .clients
            .iter()
            .map(|client| client.counters.flaps())
            .sum();
        if resets != 0 {
            return Err(anyhow::anyhow!("{resets} session resets")).context(WireFailure);
        }
        let sessions = self
            .clients
            .iter_mut()
            .filter_map(|client| client.session.take())
            .collect();
        crate::rr1000_support::shutdown(sessions, tokio::time::Instant::now() + SETUP_TIMEOUT)
            .await?;
        Ok(json!({
            "sessions": count,
            "established": count,
            "resets": resets,
            "wire_exact_receivers": receivers.len(),
            "seed_fences": self.seed_fences,
            "final_fences": receivers.len(),
            "fence": "decoded IPv4 ROUTE-REFRESH on the session bulk FIFO",
            "receivers": receivers,
        }))
    }
}
