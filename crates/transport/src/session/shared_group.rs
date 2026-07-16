//! Encode-once fanout for update-group shared envelopes (LAN-455/LAN-458).
//!
//! A clean grouped export-policy transition releases the *same* announce
//! inventory (`Arc`-shared) to every member of an update-group, differing
//! per member only by `announce_source_exclusion`. Before this seam every
//! session task re-encoded the full table itself, so N members paid N full
//! encodes that fair-shared the cores and delayed everyone's first wire
//! UPDATE by the total encode time divided by the core count.
//!
//! Here the first member to consume its envelope encodes the inventory once
//! into per-`(source peer, family)` wire chunks at the standard 4096-byte
//! ceiling and publishes them through the envelope's
//! [`SharedGroupEncode`] cell; every other member awaits the cell, proves
//! byte-equivalence with [`SessionExportProfile::has_same_wire_encoding`],
//! and enqueues the shared bytes — skipping the chunks of its own source
//! (split horizon) and of families it did not negotiate. Any anomaly
//! (profile mismatch, preparation failure, OTC filter hit, single-entry
//! oversize, scoped-link-local IPv4 drop) makes the payload unshareable and
//! each member falls back to the ordinary per-session encode, which owns
//! the established diagnostics and teardown semantics for every such case.
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
use bytes::Bytes;
use rustbgpd_rib::SharedGroupEncode;
use rustc_hash::FxHashMap as HashMap;
use std::any::Any;
use std::sync::Arc;

/// One pre-encoded wire UPDATE carrying routes from exactly one source peer
/// and one unicast family.
pub(super) struct SharedUnicastChunk {
    pub(super) source: IpAddr,
    pub(super) afi: Afi,
    pub(super) bytes: Bytes,
}

/// Cell payload published by the first member to consume its envelope.
pub(super) enum SharedUnicastEncode {
    /// Chunks valid for every member whose export profile proves
    /// [`SessionExportProfile::has_same_wire_encoding`] with `profile`.
    Ready {
        profile: SessionExportProfile,
        chunks: Vec<SharedUnicastChunk>,
    },
    /// The encoding member hit an anomaly; every member (encoder included)
    /// falls back to its ordinary per-session encode.
    Unshareable,
}

/// Whether an envelope is shaped like a clean group-transition fanout:
/// unicast announcements only, everything else empty. Anything richer keeps
/// the ordinary path, which handles every payload kind.
fn shared_encode_eligible(update: &OutboundRouteUpdate) -> bool {
    update.shared_group_encode.is_some()
        && !update.announce.is_empty()
        && update.withdraw.is_empty()
        && update.end_of_rib.is_empty()
        && update.refresh_markers.is_empty()
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

/// Encode the shared inventory once: prepare and group announcements
/// exactly like the per-session path, with the source peer added to the
/// group key, then chunk each group to the standard message ceiling.
#[expect(
    clippy::too_many_lines,
    reason = "mirrors the per-session grouping branches in one auditable pass"
)]
pub(super) fn build_shared_unicast_encode(
    export: &SessionExportProfile,
    announce: &[Route],
    next_hop_override: &[Option<rustbgpd_policy::NextHopAction>],
) -> SharedUnicastEncode {
    // Scoped link-local peers silently drop IPv4 with a per-member warning;
    // keep that behavior on the per-session path.
    if export.is_scoped_link_local_peer() {
        return SharedUnicastEncode::Unshareable;
    }
    let max_len = usize::from(rustbgpd_wire::MAX_MESSAGE_LEN);
    let local_ipv4 = export.local_ipv4();
    let mut cache = PreparedAttrCache::default();
    let mut index: HashMap<SharedGroupKey, usize> = HashMap::default();
    let mut groups: Vec<SharedGroup> = Vec::new();
    for (i, route) in announce.iter().enumerate() {
        if export.otc_blocks_unicast_egress(route) {
            // RIB staging removes OTC-blocked routes before this seam; if
            // one slips through, the per-session path owns the per-member
            // diagnostics.
            return SharedUnicastEncode::Unshareable;
        }
        let nh_override = next_hop_override.get(i).and_then(Option::as_ref);
        let attrs = export
            .prepared_unicast_attributes_cached(&mut cache, route, local_ipv4, nh_override)
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
            Err(_) => return SharedUnicastEncode::Unshareable,
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
                _ => return SharedUnicastEncode::Unshareable,
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
        let Some(encoded) = encoded else {
            return SharedUnicastEncode::Unshareable;
        };
        chunks.extend(encoded.into_iter().map(|bytes| SharedUnicastChunk {
            source: group.source,
            afi,
            bytes,
        }));
    }
    SharedUnicastEncode::Ready {
        profile: export.clone(),
        chunks,
    }
}

impl PeerSession {
    /// Entry point for envelopes from the RIB manager: try the update-group
    /// encode-once path, fall back to the ordinary per-session encode.
    pub(super) async fn handle_outbound_route_update(&mut self, update: OutboundRouteUpdate) {
        if let Some(shared) = update.shared_group_encode.clone()
            && shared_encode_eligible(&update)
            && self.try_send_shared_group(&shared, &update).await
        {
            return;
        }
        self.send_route_update(update);
    }

    /// Returns `true` when this envelope was fully handled through the
    /// shared bytes (including an enqueue failure, whose saturation/teardown
    /// policy already ran — re-encoding locally would duplicate the stream).
    /// `false` = fall back to the ordinary path, which re-runs the snapshot
    /// trust checks and owns their teardown.
    async fn try_send_shared_group(
        &mut self,
        shared: &SharedGroupEncode,
        update: &OutboundRouteUpdate,
    ) -> bool {
        let Some(snapshot) = update.exact_export_snapshot.as_ref() else {
            return false;
        };
        let Some(export) = snapshot.as_any().downcast_ref::<SessionExportProfile>() else {
            return false;
        };
        if rustbgpd_rib::ExactExportSnapshot::owner_id(export)
            != rustbgpd_rib::ExactExportEncoder::owner_id(self.export_encoder.as_ref())
        {
            return false;
        }
        let encoded = shared
            .cell
            .get_or_init(|| {
                let value: Arc<dyn Any + Send + Sync> = Arc::new(build_shared_unicast_encode(
                    export,
                    &update.announce,
                    &update.next_hop_override,
                ));
                std::future::ready(value)
            })
            .await;
        let Some(encode) = encoded.downcast_ref::<SharedUnicastEncode>() else {
            return false;
        };
        let SharedUnicastEncode::Ready { profile, chunks } = encode else {
            return false;
        };
        if !export.has_same_wire_encoding(profile) {
            return false;
        }
        let mut sent: u64 = 0;
        for chunk in chunks {
            if update.announce_source_exclusion == Some(chunk.source) {
                continue;
            }
            if !self
                .negotiated_families
                .contains(&(chunk.afi, Safi::Unicast))
            {
                continue;
            }
            if self
                .enqueue_bulk_encoded(chunk.bytes.clone(), true)
                .is_err()
            {
                // Saturation teardown / writer-closed policy already ran
                // inside; abort the batch like the ordinary chunked senders.
                return true;
            }
            self.updates_sent += 1;
            self.metrics.record_message_sent(&self.peer_label, "update");
            sent += 1;
        }
        debug!(
            peer = %self.peer_label,
            updates = sent,
            "sent update-group announcements from shared encode"
        );
        true
    }
}
