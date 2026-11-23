//! An UPDATE-only loopback link per receiver. The bounded RIB channel feeds
//! actual BGP frames; only the independent TCP decoder advances the inventory.
//! A final KEEPALIVE and clean EOF delimit the end of the producer stream.

use super::{source_addr, OutboundRouteUpdate, PeerId};
use rustbgpd_rib::update::ExactExportEncoder;
use rustbgpd_transport::OutboundEncodeBench;
use rustbgpd_wire::{
    decode_message, encode_message, Afi, FlowSpecAction, FlowSpecComponent, FlowSpecPrefix,
    FlowSpecRule, Ipv4Prefix, Message, PathAttribute, Safi, UpdateMessage, MAX_MESSAGE_LEN,
};
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

const WRITER_CAPACITY: usize = 256;
/// Seeded announcements, decoded withdrawals, converged.
type Progress = (usize, usize, bool);
// Mirrors the RIB's crate-private outbound_credit::CHUNK_ROWS.
const RIB_CHUNK_ROWS: usize = 1_024;

fn invalid(reason: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason.to_string())
}

fn mismatch(reason: impl std::fmt::Display) -> io::Error {
    invalid(format!("receiver inventory mismatch: {reason}"))
}

fn check_probe_attributes(attrs: &[PathAttribute]) -> io::Result<()> {
    // The iBGP source supplies the first four attributes. Reflecting to a
    // client adds the source router ID and this session's single cluster ID.
    let source = source_addr(1);
    let expected = [
        PathAttribute::Origin(rustbgpd_wire::Origin::Igp),
        PathAttribute::AsPath(rustbgpd_wire::AsPath { segments: vec![] }),
        PathAttribute::NextHop(source),
        PathAttribute::LocalPref(100),
        PathAttribute::OriginatorId(source),
        PathAttribute::ClusterList(vec![Ipv4Addr::new(10, 255, 255, 255)]),
    ];
    if attrs.len() != expected.len() || !expected.iter().all(|attr| attrs.contains(attr)) {
        return Err(mismatch(format!("incorrect probe attributes: {attrs:?}")));
    }
    Ok(())
}

fn probe() -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 254), 32)
}

pub(crate) struct ReceiverObservation {
    pub(crate) peer: PeerId,
    pub(crate) announcements: usize,
    pub(crate) withdrawals: usize,
    pub(crate) probe_at: Instant,
    pub(crate) last_withdrawal_at: Instant,
}

pub(crate) struct ReceiverGroup {
    senders: Vec<mpsc::Sender<OutboundRouteUpdate>>,
    encoders: Vec<Arc<dyn ExactExportEncoder>>,
    progress: Vec<watch::Receiver<Progress>>,
    rows: usize,
    tasks: Vec<JoinHandle<io::Result<ReceiverObservation>>>,
}

impl ReceiverGroup {
    pub(crate) async fn start(peers: &[PeerId], rows: usize, flowspec: bool) -> io::Result<Self> {
        if rows == 0 || peers.is_empty() {
            return Err(invalid("empty receiver fixture"));
        }
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let mut group = Self {
            senders: vec![],
            encoders: vec![],
            progress: vec![],
            tasks: vec![],
            rows,
        };
        let metrics = rustbgpd_telemetry::BgpMetrics::new();
        // The RIB reserves the whole split at once. Leave room for the marker
        // alongside every chunk of a full-table withdrawal on an otherwise idle link.
        let rib_capacity = WRITER_CAPACITY.max(rows.div_ceil(RIB_CHUNK_ROWS) + 1);
        for &peer in peers {
            let IpAddr::V4(address) = peer.addr() else {
                return Err(invalid("receiver must be IPv4"));
            };
            let session = OutboundEncodeBench::reflector_client(
                address,
                flowspec,
                metrics.clone(),
                WRITER_CAPACITY,
            );
            group.encoders.push(session.export_encoder());
            let (writer, (reader, _)) = tokio::try_join!(
                TcpStream::connect(listener.local_addr()?),
                listener.accept()
            )?;
            writer.set_nodelay(true)?;
            let (tx, rx) = mpsc::channel(rib_capacity);
            let (ready, progress) = watch::channel((0, 0, false));
            group.senders.push(tx);
            group.progress.push(progress);
            group.tasks.push(tokio::spawn(async move {
                let (_, observed) = tokio::try_join!(
                    write_updates(writer, rx, session),
                    read_updates(reader, peer, rows, flowspec, ready)
                )
                .map_err(|e| io::Error::new(e.kind(), format!("{e} (receiver {peer})")))?;
                Ok(observed)
            }));
        }
        Ok(group)
    }

    pub(crate) fn sender(&self, index: usize) -> mpsc::Sender<OutboundRouteUpdate> {
        self.senders[index].clone()
    }

    pub(crate) fn encoder(&self, index: usize) -> Arc<dyn ExactExportEncoder> {
        Arc::clone(&self.encoders[index])
    }

    pub(crate) async fn wait_seeded(&mut self) -> io::Result<()> {
        self.wait_seeded_through(self.rows).await
    }

    pub(crate) async fn wait_seeded_through(&mut self, rows: usize) -> io::Result<()> {
        if rows > self.rows {
            return Err(invalid("seed checkpoint exceeds fixture"));
        }
        self.wait_for(|&(seeded, _, _)| seeded >= rows).await
    }

    /// Decoded withdrawals across receivers, whether every receiver has
    /// converged, and whether any reader has stopped. Never waits.
    pub(crate) fn snapshot(&self) -> (usize, bool, bool) {
        self.progress
            .iter()
            .fold((0, true, false), |(rows, all, closed), progress| {
                let (_, withdrawn, complete) = *progress.borrow();
                (
                    rows + withdrawn,
                    all && complete,
                    closed || progress.has_changed().is_err(),
                )
            })
    }

    async fn wait_for(&mut self, ready: impl Fn(&Progress) -> bool) -> io::Result<()> {
        for (index, progress) in self.progress.iter_mut().enumerate() {
            if progress.wait_for(&ready).await.is_err() {
                return Err(match (&mut self.tasks[index]).await {
                    Ok(Err(e)) => e,
                    Ok(Ok(_)) => invalid("receiver closed before requested checkpoint"),
                    Err(e) => invalid(e),
                });
            }
        }
        Ok(())
    }

    /// Call after the RIB has dropped all registration senders. Every queued
    /// envelope must make it through the socket before a receipt is returned.
    pub(crate) async fn finish(&mut self) -> io::Result<Vec<ReceiverObservation>> {
        self.senders.clear();
        let mut receipts = Vec::with_capacity(self.tasks.len());
        for task in self.tasks.drain(..) {
            receipts.push(task.await.map_err(invalid)??);
        }
        Ok(receipts)
    }
}

async fn write_updates(
    mut socket: TcpStream,
    mut updates: mpsc::Receiver<OutboundRouteUpdate>,
    mut session: OutboundEncodeBench,
) -> io::Result<()> {
    while let Some(update) = updates.recv().await {
        session.write_envelope(update, &mut socket).await?;
    }
    socket
        .write_all(&encode_message(&Message::Keepalive).map_err(invalid)?)
        .await?;
    socket.shutdown().await
}

struct Table {
    rows: usize,
    bits: Vec<u64>,
    flowspec: bool,
    announced: usize,
    withdrawn: usize,
    probe_seen: bool,
    probe_at: Option<Instant>,
    last_withdrawal_at: Option<Instant>,
    eor: [bool; 2],
}

impl Table {
    fn new(rows: usize, flowspec: bool) -> Self {
        Self {
            rows,
            bits: vec![0; rows.div_ceil(64)],
            flowspec,
            announced: 0,
            withdrawn: 0,
            probe_seen: false,
            probe_at: None,
            last_withdrawal_at: None,
            eor: [false; 2],
        }
    }

    fn row(&mut self, prefix: Ipv4Prefix, flow: bool, withdraw: bool) -> io::Result<()> {
        if prefix == probe() {
            if flow || withdraw || self.announced != self.rows || self.probe_seen {
                return Err(mismatch("unexpected, duplicated, or withdrawn probe"));
            }
            self.probe_seen = true;
            return Ok(());
        }
        let [a, b, c, d] = prefix.addr.octets();
        let index = a
            .checked_sub(20)
            .map(|first| (usize::from(first) << 16) | (usize::from(b) << 8) | usize::from(c));
        let Some(index) =
            index.filter(|i| *i < self.rows && prefix.len == 24 && d == 0 && flow == self.flowspec)
        else {
            return Err(mismatch(format!(
                "unexpected prefix or family {prefix}, FlowSpec={flow}"
            )));
        };
        let word = &mut self.bits[index / 64];
        let mask = 1_u64 << (index % 64);
        if withdraw {
            if self.announced != self.rows || *word & mask == 0 {
                return Err(mismatch(format!("absent or premature withdrawal {prefix}")));
            }
            *word &= !mask;
            self.withdrawn += 1;
        } else {
            if self.announced == self.rows || *word & mask != 0 {
                return Err(mismatch(format!("late or duplicate announcement {prefix}")));
            }
            *word |= mask;
            self.announced += 1;
        }
        Ok(())
    }

    fn marker(&mut self, flow: bool) -> io::Result<()> {
        if (flow && !self.flowspec)
            || self.withdrawn != 0
            || self.probe_seen
            || std::mem::replace(&mut self.eor[usize::from(flow)], true)
        {
            return Err(mismatch("late, duplicate, or unnegotiated End-of-RIB"));
        }
        Ok(())
    }

    fn update(&mut self, message: &UpdateMessage) -> io::Result<()> {
        if message.withdrawn_routes.is_empty()
            && message.nlri.is_empty()
            && message.path_attributes.is_empty()
        {
            return self.marker(false);
        }
        let parsed = message.parse(true, false, &[]).map_err(invalid)?;
        for row in parsed.withdrawn {
            self.row(row.prefix, false, true)?;
        }
        let next_hop = parsed.attributes.iter().find_map(|attr| match attr {
            PathAttribute::NextHop(hop) => Some(*hop),
            _ => None,
        });
        let mut has_mp = false;
        for attr in &parsed.attributes {
            match attr {
                PathAttribute::MpReachNlri(mp)
                    if mp.afi == Afi::Ipv4
                        && mp.safi == Safi::FlowSpec
                        && !mp.flowspec_announced.is_empty() =>
                {
                    let action = rustbgpd_wire::ExtendedCommunity::from_flowspec_action(
                        &FlowSpecAction::TrafficRateBytes {
                            asn: 64512,
                            rate: 0.0,
                        },
                    );
                    if !parsed.attributes.iter().any(|a| matches!(a, PathAttribute::ExtendedCommunities(values) if values.as_slice()==[action])) {
                        return Err(mismatch("missing or changed FlowSpec discard action"));
                    }
                    has_mp = true;
                    for rule in &mp.flowspec_announced {
                        self.row(flow_prefix(rule)?, true, false)?;
                    }
                }
                PathAttribute::MpUnreachNlri(mp)
                    if mp.afi == Afi::Ipv4 && mp.safi == Safi::FlowSpec =>
                {
                    has_mp = true;
                    if mp.flowspec_withdrawn.is_empty() {
                        if parsed.attributes.len() != 1 {
                            return Err(mismatch("unexpected attributes on FlowSpec End-of-RIB"));
                        }
                        self.marker(true)?;
                    }
                    for rule in &mp.flowspec_withdrawn {
                        self.row(flow_prefix(rule)?, true, true)?;
                    }
                }
                PathAttribute::MpReachNlri(_) | PathAttribute::MpUnreachNlri(_) => {
                    return Err(mismatch("unexpected MP UPDATE family"))
                }
                _ => {}
            }
        }
        if !parsed.announced.is_empty()
            || parsed
                .attributes
                .iter()
                .any(|attr| matches!(attr, PathAttribute::MpReachNlri(_)))
        {
            if !parsed
                .attributes
                .iter()
                .any(|a| matches!(a, PathAttribute::LocalPref(100)))
                || !parsed
                    .attributes
                    .iter()
                    .any(|a| matches!(a, PathAttribute::Origin(rustbgpd_wire::Origin::Igp)))
                || !parsed
                    .attributes
                    .iter()
                    .any(|a| matches!(a, PathAttribute::AsPath(path) if path.segments.is_empty()))
            {
                return Err(mismatch("incorrect originating attributes on announcement"));
            }
        } else if !has_mp && message.withdrawn_routes.is_empty() {
            return Err(mismatch("UPDATE has no supported route payload"));
        }
        for row in parsed.announced {
            if next_hop != Some(source_addr(u32::from(row.prefix == probe()))) {
                return Err(mismatch(format!("wrong next hop for {}", row.prefix)));
            }
            if row.prefix == probe() {
                check_probe_attributes(&parsed.attributes)?;
            }
            self.row(row.prefix, false, false)?;
        }
        Ok(())
    }

    fn record_application(&mut self, previous_withdrawn: usize) {
        let new_probe = self.probe_seen && self.probe_at.is_none();
        if new_probe || previous_withdrawn != self.withdrawn {
            let applied_at = Instant::now();
            if new_probe {
                self.probe_at = Some(applied_at);
            }
            if self.withdrawn != previous_withdrawn {
                self.last_withdrawal_at = Some(applied_at);
            }
        }
    }

    fn finish(self, peer: PeerId) -> io::Result<ReceiverObservation> {
        if self.announced != self.rows
            || self.withdrawn != self.rows
            || self.bits.iter().any(|&w| w != 0)
        {
            return Err(mismatch(format!(
                "incomplete table, seeded {}, withdrawn {}, expected {}",
                self.announced, self.withdrawn, self.rows
            )));
        }
        Ok(ReceiverObservation {
            peer,
            announcements: self.announced,
            withdrawals: self.withdrawn,
            probe_at: self
                .probe_at
                .ok_or_else(|| mismatch("missing independent probe"))?,
            last_withdrawal_at: self
                .last_withdrawal_at
                .ok_or_else(|| mismatch("missing departure withdrawals"))?,
        })
    }
}

fn flow_prefix(rule: &FlowSpecRule) -> io::Result<Ipv4Prefix> {
    match rule.components.as_slice() {
        [FlowSpecComponent::DestinationPrefix(FlowSpecPrefix::V4(prefix))] => Ok(*prefix),
        _ => Err(mismatch("unexpected FlowSpec rule components")),
    }
}

async fn read_updates(
    socket: TcpStream,
    peer: PeerId,
    rows: usize,
    flowspec: bool,
    progress: watch::Sender<Progress>,
) -> io::Result<ReceiverObservation> {
    let mut input = BufReader::new(socket);
    let mut table = Table::new(rows, flowspec);
    let mut header = [0; 19];
    loop {
        input.read_exact(&mut header).await?;
        let size = u16::from_be_bytes([header[16], header[17]]);
        if !(19..=MAX_MESSAGE_LEN).contains(&size) {
            return Err(invalid("invalid BGP frame length"));
        }
        let mut frame = vec![0; usize::from(size)];
        frame[..19].copy_from_slice(&header);
        input.read_exact(&mut frame[19..]).await?;
        match decode_message(&mut frame.into(), MAX_MESSAGE_LEN).map_err(invalid)? {
            Message::Update(update) => {
                let before = table.announced;
                let previous_withdrawn = table.withdrawn;
                table.update(&update)?;
                table.record_application(previous_withdrawn);
                let converged = table.probe_at.is_some() && table.withdrawn == rows;
                if table.announced != before || table.withdrawn != previous_withdrawn || converged {
                    progress.send_replace((table.announced, table.withdrawn, converged));
                }
            }
            Message::Keepalive => {
                let mut byte = [0; 1];
                if input.read(&mut byte).await? != 0 {
                    return Err(invalid("data after receiver drain fence"));
                }
                return table.finish(peer);
            }
            message => {
                return Err(invalid(format!(
                    "unexpected session message {:?}",
                    message.message_type()
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustbgpd_wire::{Ipv4NlriEntry, Ipv4UnicastMode};

    fn peer() -> PeerId {
        PeerId::from_addr(IpAddr::V4(Ipv4Addr::LOCALHOST))
    }

    #[test]
    fn final_probe_can_precede_or_follow_the_last_withdrawal() {
        for probe_first in [true, false] {
            let mut table = Table::new(2, false);
            for i in [0, 1] {
                table.row(crate::flood_prefix(i), false, false).unwrap();
            }
            if probe_first {
                table.row(probe(), false, false).unwrap();
            }
            for i in [1, 0] {
                table.row(crate::flood_prefix(i), false, true).unwrap();
            }
            if !probe_first {
                table.row(probe(), false, false).unwrap();
            }
            table.record_application(0);
            let observation = table.finish(peer()).unwrap();
            assert_eq!((observation.announcements, observation.withdrawals), (2, 2));
        }
    }

    #[test]
    fn equal_counts_cannot_hide_a_wrong_missing_or_duplicate_key() {
        let mut table = Table::new(2, true);
        table.row(crate::flood_prefix(0), true, false).unwrap();
        assert!(table.row(crate::flood_prefix(0), true, false).is_err());
        assert!(table.row(crate::flood_prefix(1), false, false).is_err());
        assert!(table.row(crate::flood_prefix(2), true, false).is_err());
        table.row(crate::flood_prefix(1), true, false).unwrap();
        table.row(probe(), false, false).unwrap();
        table.row(crate::flood_prefix(0), true, true).unwrap();
        assert!(table.row(crate::flood_prefix(0), true, true).is_err());
        let error = table
            .finish(peer())
            .err()
            .expect("one withdrawal is missing");
        assert!(error
            .to_string()
            .starts_with("receiver inventory mismatch:"));
    }

    fn probe_update(attrs: &[PathAttribute]) -> UpdateMessage {
        UpdateMessage::build(
            &[Ipv4NlriEntry {
                path_id: 0,
                prefix: probe(),
            }],
            &[],
            attrs,
            true,
            false,
            Ipv4UnicastMode::Body,
        )
    }

    fn reflected_probe_attributes() -> Vec<PathAttribute> {
        vec![
            PathAttribute::ClusterList(vec![Ipv4Addr::new(10, 255, 255, 255)]),
            PathAttribute::OriginatorId(source_addr(1)),
            PathAttribute::NextHop(source_addr(1)),
            PathAttribute::LocalPref(100),
            PathAttribute::AsPath(rustbgpd_wire::AsPath { segments: vec![] }),
            PathAttribute::Origin(rustbgpd_wire::Origin::Igp),
        ]
    }

    #[test]
    fn a_marker_with_a_different_next_hop_is_not_a_winner_witness() {
        let mut table = Table::new(1, false);
        table.row(crate::flood_prefix(0), false, false).unwrap();
        let mut attrs = reflected_probe_attributes();
        attrs[2] = PathAttribute::NextHop(source_addr(0));
        assert!(table
            .update(&probe_update(&attrs))
            .unwrap_err()
            .to_string()
            .contains("wrong next hop"));
        assert!(!table.probe_seen);
    }

    #[test]
    fn a_missing_withdrawal_is_a_receiver_inventory_failure_at_eof() {
        let mut table = Table::new(2, false);
        for i in [0, 1] {
            table.row(crate::flood_prefix(i), false, false).unwrap();
        }
        table.row(probe(), false, false).unwrap();
        table.row(crate::flood_prefix(1), false, true).unwrap();
        table.record_application(0);
        let error = table
            .finish(peer())
            .err()
            .expect("one row was never withdrawn");
        assert!(error
            .to_string()
            .contains("receiver inventory mismatch: incomplete table"));
    }

    #[test]
    fn final_probe_rejects_one_extra_community() {
        let mut table = Table::new(1, false);
        table.row(crate::flood_prefix(0), false, false).unwrap();
        let mut attrs = reflected_probe_attributes();
        attrs.push(PathAttribute::Communities(vec![0xfc00_0001]));
        assert!(table
            .update(&probe_update(&attrs))
            .unwrap_err()
            .to_string()
            .contains("incorrect probe attributes"));
        assert!(!table.probe_seen);

        assert!(attrs.pop().is_some());
        table.update(&probe_update(&attrs)).unwrap();
        assert!(table.probe_seen);
    }
}
