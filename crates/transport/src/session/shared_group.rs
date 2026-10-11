//! Encode-once fanout for update-group shared envelopes (LAN-455/LAN-458),
//! with progressive chunk publication (ADR-0109, amended).
//!
//! A clean grouped export-policy transition releases the *same* announce
//! inventory (`Arc`-shared) to every member of an update-group, differing
//! per member only by `announce_source_exclusion`. Before this seam every
//! session task re-encoded the full table itself, so N members paid N full
//! encodes that fair-shared the cores and delayed everyone's first wire
//! UPDATE by the total encode time divided by the core count.
//!
//! The first member to consume its envelope is elected encoder through the
//! envelope's [`rustbgpd_rib::SharedGroupEncode`] cell, a synchronous `OnceLock`.
//! Election and terminal-guard installation complete before any suspension;
//! the producer retains the guard across slice yields, so an initialized cell
//! has either a live encoder or a terminal stream. After grouping the whole
//! inventory by source, the encoder prepares, groups, and encodes bounded
//! route slices, publishing each slice's chunks as they are produced. Every
//! other member proves byte-equivalence with
//! [`SessionExportProfile::has_same_wire_encoding`] and then *streams* the
//! chunks — sending chunk `i` as soon as it exists instead of awaiting the
//! whole payload — skipping the chunks of its own source (split horizon)
//! and of families it did not negotiate. This makes a member's longest wire
//! silence track per-slice encode latency instead of the full-table encode.
//!
//! Failure semantics: any anomaly (preparation failure, OTC filter hit,
//! single-entry oversize, scoped-link-local IPv4 drop) terminates the
//! stream as `Failed`. The drop guard also publishes failure and notifies
//! waiters if the encoder unwinds or its suspended future is cancelled.
//! Every member falls back to the ordinary per-session encode, which owns
//! the established diagnostics and teardown semantics for each case.
//! Mid-stream fallback is safe by construction — the
//! invariant is per-NLRI attribute identity, not byte-identical chunks (an
//! extended-message member's local re-encode chunks at its negotiated
//! ceiling, and the shared stream's source-sorted walk yields different
//! NLRI order and UPDATE boundaries than the table-order local encode).
//! Every prefix a member already sent carries exactly the attributes the
//! local re-encode attaches to it — the per-route consequence of the
//! wire-equivalence proof — so the receiver sees idempotent
//! re-announcements at the BGP semantic level regardless of message
//! framing, and no route can be skipped: the fallback re-encodes the full
//! envelope from index 0.
//!
//! Chunks never mix source peers even when global attribute interning gives
//! two sources pointer-identical attribute sets: keeping the source in the
//! group key is what lets a member's stream compose exactly as "all chunks
//! minus its own source's". Chunking to the standard (non-extended) ceiling
//! keeps one shared byte stream valid for every member because
//! `has_same_wire_encoding` deliberately ignores the negotiated ceiling —
//! a 4096-byte message is well-formed for an RFC 8654 extended peer too.

use super::export::{PreparedAttrCache, PreparedUnicastCandidate, ReachNlri, SessionExportProfile};
use super::{
    Afi, IpAddr, Ipv4NlriEntry, Ipv4UnicastMode, Ipv6Addr, Message, NlriEntry, OutboundRouteUpdate,
    PathAttribute, PeerSession, Route, Safi, UpdateMessage, debug,
};
use crate::fast_hash::FastMap as HashMap;
use bytes::Bytes;
use std::any::Any;
use std::sync::{Arc, Mutex};

/// Routes per encoder slice: each slice is prepared, grouped, encoded, and
/// published as one unit, so consumers' streaming granularity (and the gap
/// floor between their UPDATEs) tracks one slice's encode latency — single-
/// digit milliseconds at reload-stall route shapes — instead of the full
/// table. Sources spanning a slice boundary cost one extra UPDATE each.
///
/// The elected encoder yields only after publishing a complete slice. Its
/// guard survives every suspension and publishes `Failed` if the producer
/// future is dropped, waking followers so they can use ordinary fallback.
/// Source grouping still prepares the whole inventory before the first slice.
pub(super) const PROGRESSIVE_SLICE_ROUTES: usize = 2048;

/// Inventory indices grouped by source peer: sources in address order,
/// inventory order kept within each source.
///
/// A counting sort over dense source ids. Every observer waits for this
/// before the first chunk exists, and comparison-sorting 400k indices by an
/// indirect `IpAddr` key costs tens of milliseconds; this pass is linear in
/// the inventory plus a sort of the distinct sources.
pub(super) fn source_grouped_order(announce: &[Route]) -> Vec<usize> {
    let mut ids: HashMap<IpAddr, usize> = HashMap::default();
    let source_ids: Vec<usize> = announce
        .iter()
        .map(|route| {
            let next = ids.len();
            *ids.entry(route.peer).or_insert(next)
        })
        .collect();
    let mut sources: Vec<(IpAddr, usize)> = ids.into_iter().collect();
    sources.sort_unstable();
    let mut slot = vec![0usize; sources.len()];
    for &id in &source_ids {
        slot[id] += 1;
    }
    let mut start = 0;
    for &(_, id) in &sources {
        let count = slot[id];
        slot[id] = start;
        start += count;
    }
    let mut order = vec![0usize; announce.len()];
    for (i, &id) in source_ids.iter().enumerate() {
        order[slot[id]] = i;
        slot[id] += 1;
    }
    order
}

/// One pre-encoded wire UPDATE carrying routes from exactly one source peer
/// and one unicast family.
#[derive(Clone)]
pub(super) struct SharedUnicastChunk {
    pub(super) source: IpAddr,
    pub(super) afi: Afi,
    pub(super) bytes: Bytes,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum StreamTerminal {
    /// Every chunk of the inventory has been published.
    Complete,
    /// The stream is truncated (encoder anomaly or unwind); every member
    /// falls back to its ordinary per-session encode.
    Failed,
}

#[derive(Default)]
struct ProgressiveStateInner {
    chunks: Vec<SharedUnicastChunk>,
    terminal: Option<StreamTerminal>,
}

/// Cell payload created by the elected encoder *before* it encodes anything.
pub(super) struct ProgressiveUnicastEncode {
    /// The encoder's profile; consumers reuse chunks only after proving
    /// [`SessionExportProfile::has_same_wire_encoding`] against it.
    profile: SessionExportProfile,
    state: Mutex<ProgressiveStateInner>,
    progress: tokio::sync::Notify,
}

impl ProgressiveUnicastEncode {
    fn new(profile: SessionExportProfile) -> Self {
        Self {
            profile,
            state: Mutex::new(ProgressiveStateInner::default()),
            progress: tokio::sync::Notify::new(),
        }
    }

    fn publish(&self, chunks: Vec<SharedUnicastChunk>) {
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.chunks.extend(chunks);
        }
        self.progress.notify_waiters();
    }

    /// First terminal wins; the encoder's explicit `Complete` makes the
    /// drop guard's `Failed` a no-op on the success path.
    fn finish(&self, terminal: StreamTerminal) {
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.terminal.is_none() {
                state.terminal = Some(terminal);
            }
        }
        self.progress.notify_waiters();
    }

    /// Chunks published since `from`, plus the terminal state. Bytes are
    /// refcounted, so the clone-out is cheap.
    pub(super) fn snapshot_from(
        &self,
        from: usize,
        limit: usize,
    ) -> (Vec<SharedUnicastChunk>, Option<StreamTerminal>) {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let end = from.saturating_add(limit).min(state.chunks.len());
        (
            state.chunks.get(from..end).unwrap_or(&[]).to_vec(),
            (end == state.chunks.len())
                .then_some(state.terminal)
                .flatten(),
        )
    }

    pub(super) async fn ready(&self, next: usize) {
        let notified = self.progress.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let (chunks, terminal) = self.snapshot_from(next, 1);
        if chunks.is_empty() && terminal.is_none() {
            notified.await;
        }
    }

    #[cfg(test)]
    pub(super) fn test_new(profile: SessionExportProfile) -> Self {
        Self::new(profile)
    }
    #[cfg(test)]
    pub(super) fn test_publish(&self, chunks: Vec<SharedUnicastChunk>) {
        self.publish(chunks);
    }
    #[cfg(test)]
    pub(super) fn test_finish(&self, terminal: StreamTerminal) {
        self.finish(terminal);
    }
    #[cfg(test)]
    pub(super) fn test_snapshot(&self) -> (usize, Option<StreamTerminal>) {
        let (chunks, terminal) = self.snapshot_from(0, usize::MAX);
        (chunks.len(), terminal)
    }
}

/// Publishes `Failed` and notifies waiters if the producer returns early,
/// unwinds, or is cancelled before its explicit `finish(Complete)`. Installed
/// before the first suspension and retained across slice yields, the guard
/// keeps the stream backed by either a live encoder or a terminal result.
pub(super) struct EncoderGuard<'cell>(pub(super) &'cell ProgressiveUnicastEncode);

impl Drop for EncoderGuard<'_> {
    fn drop(&mut self) {
        self.0.finish(StreamTerminal::Failed);
    }
}

/// Whether an envelope is shaped like a grouped unicast fanout: unicast
/// announcements, optionally bracketed by refresh markers or `EoR` and preceded
/// by unicast withdrawals. Those phases stay per member in the ordinary
/// cursor; only the announce inventory is shared. Anything richer
/// keeps the ordinary path, which handles every payload kind.
fn shared_encode_eligible(update: &OutboundRouteUpdate) -> bool {
    update.shared_group_encode.is_some()
        && !update.announce.is_empty()
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
        && !update.request_refresh_all_negotiated
}

/// Size-halving chunker mirroring `send_v4_chunked` / `send_mp_chunked`,
/// producing encoded bytes instead of enqueueing. `None` = unshareable
/// (build failure or a single entry over the shared ceiling).
fn encode_chunks<E>(
    entries: &[E],
    max_len: usize,
    mut build: impl FnMut(&[E]) -> Result<UpdateMessage, rustbgpd_wire::EncodeError>,
) -> Option<Vec<Bytes>> {
    let mut out = Vec::new();
    let mut chunk_size: usize = entries.len().min(max_len / 2).max(1);
    let mut idx: usize = 0;
    while idx < entries.len() {
        let end = (idx + chunk_size).min(entries.len());
        let msg = build(&entries[idx..end]).ok()?;
        if msg.encoded_len() > max_len {
            if chunk_size <= 1 {
                return None;
            }
            chunk_size = (chunk_size / 2).max(1);
            continue;
        }
        let encoded = rustbgpd_wire::encode_message_with_limit(
            &Message::Update(msg),
            rustbgpd_wire::MAX_MESSAGE_LEN,
        )
        .ok()?;
        out.push(Bytes::from(encoded));
        idx = end;
    }
    Some(out)
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct SharedGroupKey {
    source: IpAddr,
    attrs_ptr: usize,
    next_hop: Option<IpAddr>,
    link_local_next_hop: Option<Ipv6Addr>,
}

enum SharedGroupBody {
    V4Body {
        attrs: Arc<Vec<PathAttribute>>,
        entries: Vec<Ipv4NlriEntry>,
    },
    Mp {
        afi: Afi,
        next_hop: IpAddr,
        link_local_next_hop: Option<Ipv6Addr>,
        attrs: Arc<Vec<PathAttribute>>,
        ipv4_mode: Ipv4UnicastMode,
        entries: Vec<NlriEntry>,
    },
}

struct SharedGroup {
    source: IpAddr,
    body: SharedGroupBody,
}

/// Prepare, group, and encode one slice of the shared inventory exactly
/// like the per-session path, with the source peer added to the group key.
/// `indices` selects the slice's routes (and their parallel next-hop
/// overrides) out of the full inventory; the encoder passes source-sorted
/// index windows so each slice's groups stay per-source-dense.
/// `None` = the stream is unshareable (the per-session fallback owns the
/// diagnostics and teardown semantics for the failing case).
#[expect(
    clippy::too_many_lines,
    reason = "mirrors the per-session grouping branches in one auditable pass"
)]
pub(super) fn encode_shared_unicast_slice(
    export: &SessionExportProfile,
    cache: &mut PreparedAttrCache,
    announce: &[Route],
    next_hop_override: &[Option<rustbgpd_policy::NextHopAction>],
    indices: &[usize],
) -> Option<Vec<SharedUnicastChunk>> {
    let max_len = usize::from(rustbgpd_wire::MAX_MESSAGE_LEN);
    let local_ipv4 = export.local_ipv4();
    let mut index: HashMap<SharedGroupKey, usize> = HashMap::default();
    let mut groups: Vec<SharedGroup> = Vec::new();
    for &i in indices {
        let route = &announce[i];
        if export.otc_blocks_unicast_egress(route) {
            // RIB staging removes OTC-blocked routes before this seam; if
            // one slips through, the per-session path owns the per-member
            // diagnostics.
            return None;
        }
        let nh_override = next_hop_override.get(i).and_then(Option::as_ref);
        let attrs = export
            .prepared_unicast_attributes_cached(cache, route, local_ipv4, nh_override)
            .clone();
        // `finish_unicast_candidate` picks IPv4-body vs MP_REACH from the
        // profile's Extended Next Hop state itself, so this match covers
        // both per-session grouping branches without re-deriving the mode.
        let (key, body_seed) = match export.finish_unicast_candidate(route, nh_override, attrs) {
            Ok(PreparedUnicastCandidate::Ipv4Body { attrs, entry }) => (
                SharedGroupKey {
                    source: route.peer,
                    attrs_ptr: Arc::as_ptr(&attrs) as usize,
                    next_hop: None,
                    link_local_next_hop: None,
                },
                SharedGroupBody::V4Body {
                    attrs,
                    entries: vec![entry],
                },
            ),
            Ok(PreparedUnicastCandidate::Mp {
                afi,
                next_hop,
                link_local_next_hop,
                attrs,
                entry,
                ipv4_mode,
            }) => (
                SharedGroupKey {
                    source: route.peer,
                    attrs_ptr: Arc::as_ptr(&attrs) as usize,
                    next_hop: Some(next_hop),
                    link_local_next_hop,
                },
                SharedGroupBody::Mp {
                    afi,
                    next_hop,
                    link_local_next_hop,
                    attrs,
                    ipv4_mode,
                    entries: vec![entry],
                },
            ),
            // The exact-export preflight probed every route on this same
            // snapshot before commit; a failure here is the anomaly the
            // per-session path turns into a teardown.
            Err(_) => return None,
        };
        if let Some(&at) = index.get(&key) {
            match (&mut groups[at].body, body_seed) {
                (
                    SharedGroupBody::V4Body { entries, .. },
                    SharedGroupBody::V4Body {
                        entries: seed_entries,
                        ..
                    },
                ) => entries.extend(seed_entries),
                (
                    SharedGroupBody::Mp { entries, .. },
                    SharedGroupBody::Mp {
                        entries: seed_entries,
                        ..
                    },
                ) => entries.extend(seed_entries),
                // A key collision across body kinds cannot happen (MP keys
                // always carry a next hop, body keys never do), but sharing
                // must stay provable rather than clever.
                _ => return None,
            }
        } else {
            index.insert(key, groups.len());
            groups.push(SharedGroup {
                source: route.peer,
                body: body_seed,
            });
        }
    }
    let mut chunks = Vec::new();
    for group in &groups {
        let (afi, encoded) = match &group.body {
            SharedGroupBody::V4Body { attrs, entries } => (
                Afi::Ipv4,
                encode_chunks(entries, max_len, |chunk| {
                    export.build_ipv4_body(chunk, &[], attrs)
                }),
            ),
            SharedGroupBody::Mp {
                afi,
                next_hop,
                link_local_next_hop,
                attrs,
                ipv4_mode,
                entries,
            } => (
                *afi,
                encode_chunks(entries, max_len, |chunk| {
                    export.build_mp_reach(
                        *afi,
                        Safi::Unicast,
                        *next_hop,
                        *link_local_next_hop,
                        attrs,
                        ReachNlri::Unicast(chunk),
                        *ipv4_mode,
                    )
                }),
            ),
        };
        chunks.extend(encoded?.into_iter().map(|bytes| SharedUnicastChunk {
            source: group.source,
            afi,
            bytes,
        }));
    }
    Some(chunks)
}

impl PeerSession {
    /// Only small operator snapshots may interleave an owned wait. Discard
    /// abandoned snapshots; preserve all other commands and their FIFO successors.
    pub(super) fn handle_read_during_wait(&mut self, command: crate::PeerCommand) {
        if command.is_canceled_read() {
            return;
        }
        match command {
            crate::PeerCommand::QueryState { reply } => self.answer_state_query(reply),
            crate::PeerCommand::QueryImportPolicyTermHits { reply } => {
                self.answer_import_policy_term_hits(reply);
            }
            command => self.deferred_command = Some(command),
        }
    }

    /// One command per checkpoint bounds work under a continuous read stream.
    fn poll_shared_group_command(&mut self) {
        if self
            .deferred_command
            .as_ref()
            .is_some_and(crate::PeerCommand::is_canceled_read)
        {
            self.deferred_command = None;
        }
        if self.deferred_command.is_none()
            && let Ok(command) = self.commands.try_recv()
        {
            self.handle_read_during_wait(command);
        }
    }

    /// Elect synchronously, then publish with cooperative slice boundaries.
    /// Both roles subsequently resume from the ordinary session cursor.
    pub(super) async fn prepare_shared_group(
        &mut self,
        update: &OutboundRouteUpdate,
    ) -> Option<(Arc<ProgressiveUnicastEncode>, usize)> {
        if !shared_encode_eligible(update) {
            return None;
        }
        let shared = update.shared_group_encode.as_ref()?;
        let snapshot = update.exact_export_snapshot.as_ref()?;
        let export = snapshot.as_any().downcast_ref::<SessionExportProfile>()?;
        if rustbgpd_rib::ExactExportSnapshot::owner_id(export)
            != rustbgpd_rib::ExactExportEncoder::owner_id(self.export_encoder.as_ref())
        {
            return None;
        }
        let mut elected_encoder = false;
        let cell = shared.cell.get_or_init(|| {
            elected_encoder = true;
            Arc::new(ProgressiveUnicastEncode::new(export.clone())) as Arc<dyn Any + Send + Sync>
        });
        let encode = Arc::clone(cell)
            .downcast::<ProgressiveUnicastEncode>()
            .ok()?;
        if elected_encoder {
            let next = self
                .encode_and_send_shared_group(&encode, update, export)
                .await?;
            Some((encode, next))
        } else if export.has_same_wire_encoding(&encode.profile) {
            Some((encode, 0))
        } else {
            None
        }
    }

    /// Encoder role: encode the inventory slice by slice, publishing each
    /// slice's chunks for the group and sending its own filtered copy along
    /// the way. Scoped-link-local peers and any slice failure terminate the
    /// stream as `Failed` (via the guard) and fall back locally.
    ///
    /// Election and guard construction precede the first suspension. The
    /// producer owns the guard through every slice yield, so cancellation
    /// publishes `Failed` and wakes every follower. Yield only after whole
    /// chunks are published and the stream mutex has been released.
    async fn encode_and_send_shared_group(
        &mut self,
        encode: &ProgressiveUnicastEncode,
        update: &OutboundRouteUpdate,
        export: &SessionExportProfile,
    ) -> Option<usize> {
        let guard = EncoderGuard(encode);
        if export.is_scoped_link_local_peer() {
            // The per-session path owns the per-member IPv4-drop warning.
            return None;
        }
        let mut cache = PreparedAttrCache::default();
        // Iterate the inventory in source-peer order rather than table
        // order. The inventory interleaves sources per prefix, so grouping
        // per slice in table order fragments every source across every
        // slice — measured at reload-stall shape as tens of thousands of
        // tiny UPDATEs per member and writer-channel saturation teardown.
        // Permuting an index keeps announce/next-hop-override alignment and
        // is safe to reorder: the inventory carries one route per prefix,
        // and announcements of distinct prefixes are order-independent.
        let order = source_grouped_order(&update.announce);
        // Keep publishing after this member runs out of writer capacity.
        // Its first unsent chunk becomes the same pending cursor consumers use;
        // the group's publication cannot depend on one member's reader. A
        // A member with its own withdrawals or BoRR sends none of its copy
        // here: every earlier phase must precede announcements. It streams
        // from chunk 0 once the ordinary cursor has admitted those phases.
        // Requests remain excluded by shared_encode_eligible.
        let mut own_send_healthy = update.withdraw.is_empty()
            && !update
                .refresh_markers
                .iter()
                .any(|(_, _, subtype)| *subtype == rustbgpd_wire::RouteRefreshSubtype::BoRR);
        let mut next = 0;
        let mut sent: u64 = 0;
        let mut idx = 0;
        while idx < order.len() {
            self.poll_shared_group_command();
            let end = (idx + PROGRESSIVE_SLICE_ROUTES).min(order.len());
            let chunks = encode_shared_unicast_slice(
                export,
                &mut cache,
                &update.announce,
                &update.next_hop_override,
                &order[idx..end],
            )?;
            if own_send_healthy {
                for chunk in &chunks {
                    if self.wants_shared_chunk(update, chunk) {
                        if self
                            .writer_bulk_tx
                            .as_ref()
                            .is_none_or(|tx| tx.capacity() == 0)
                            || self
                                .enqueue_bulk_encoded(chunk.bytes.clone(), true)
                                .is_err()
                        {
                            own_send_healthy = false;
                            break;
                        }
                        self.updates_sent += 1;
                        self.metrics.record_message_sent(&self.peer_label, "update");
                        sent += 1;
                    }
                    next += 1;
                }
            }
            encode.publish(chunks);
            idx = end;
            if idx < order.len() && idx.is_multiple_of(2 * PROGRESSIVE_SLICE_ROUTES) {
                tokio::task::yield_now().await;
            }
        }
        encode.finish(StreamTerminal::Complete);
        drop(guard);
        debug!(
            peer = %self.peer_label,
            updates = sent,
            "encoded and sent update-group announcements as shared encode"
        );
        Some(next)
    }

    /// Split horizon (own-source exclusion) plus negotiated-family filter.
    pub(super) fn wants_shared_chunk(
        &self,
        update: &OutboundRouteUpdate,
        chunk: &SharedUnicastChunk,
    ) -> bool {
        update.announce_source_exclusion != Some(chunk.source)
            && self
                .negotiated_families()
                .contains(&(chunk.afi, Safi::Unicast))
    }
}
