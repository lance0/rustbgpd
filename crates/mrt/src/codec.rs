//! Pure encoding functions for MRT `TABLE_DUMP_V2` records (RFC 6396).
use rustbgpd_rib::route::{EvpnRibRoute, Route};
use rustbgpd_rib::update::MrtPeerEntry;
use rustbgpd_wire::attribute::encode_path_attributes;
use rustbgpd_wire::error::EncodeError as WireEncodeError;
use rustbgpd_wire::{Afi, MpReachNlri, PathAttribute, Prefix, Safi, encode_evpn_nlri};
use std::cmp::Ordering as CmpOrdering;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use thiserror::Error;
const MRT_HEADER_LEN: usize = 12;
/// MRT message type for `TABLE_DUMP_V2`.
pub(crate) const TABLE_DUMP_V2: u16 = 13;
/// `TABLE_DUMP_V2` subtypes.
pub(crate) const PEER_INDEX_TABLE: u16 = 1;
pub(crate) const RIB_IPV4_UNICAST: u16 = 2;
pub(crate) const RIB_IPV6_UNICAST: u16 = 4;
/// RFC 6396 §4.3.5 — generic RIB record carrying any AFI/SAFI.
/// Used here for L2VPN/EVPN (AFI 25 / SAFI 70).
pub(crate) const RIB_GENERIC: u16 = 6;
pub(crate) const RIB_IPV4_UNICAST_ADDPATH: u16 = 8;
pub(crate) const RIB_IPV6_UNICAST_ADDPATH: u16 = 9;
/// An individual RIB entry within a RIB_* record.
pub struct RibEntry {
    /// Index into the `PEER_INDEX_TABLE`.
    pub peer_index: u16,
    /// Unix timestamp when this route was originated.
    pub originated_time: u32,
    /// Add-Path path identifier (RFC 8050). 0 = no Add-Path.
    pub path_id: u32,
    /// BGP path attributes for this RIB entry.
    pub attributes: Vec<PathAttribute>,
}

/// One peer/family for which the warm snapshot must use RFC 8050 framing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MrtAddPathReceiveProfile {
    /// Peer transport address.
    pub peer: IpAddr,
    /// Address family.
    pub afi: Afi,
    /// Subsequent address family.
    pub safi: Safi,
}

/// Shared hard bound and cooperative cancellation contract for warm encoding.
///
/// The same cancellation token and monotonic deadline are used by the shutdown
/// coordinator, MRT encoder, and durable bundle writer. The byte cap applies to
/// the complete encoded snapshot and is checked before every output-buffer
/// reservation, so a rejected checkpoint never materializes an oversized MRT
/// byte vector.
#[derive(Debug, Clone)]
pub struct WarmSnapshotBudget {
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
    max_snapshot_bytes: usize,
}

impl WarmSnapshotBudget {
    /// Create a bounded warm-snapshot work contract.
    #[must_use]
    pub fn new(deadline: Instant, cancelled: Arc<AtomicBool>, max_snapshot_bytes: usize) -> Self {
        Self {
            deadline,
            cancelled,
            max_snapshot_bytes,
        }
    }

    /// Fail closed when the coordinator has gone away or its deadline elapsed.
    ///
    /// # Errors
    ///
    /// Returns [`WarmSnapshotBudgetError::Cancelled`] or
    /// [`WarmSnapshotBudgetError::DeadlineExceeded`] as appropriate.
    pub fn check(&self) -> Result<(), WarmSnapshotBudgetError> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(WarmSnapshotBudgetError::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return Err(WarmSnapshotBudgetError::DeadlineExceeded);
        }
        Ok(())
    }

    pub(crate) fn check_growth(
        &self,
        current: usize,
        additional: usize,
    ) -> Result<usize, WarmSnapshotBudgetError> {
        self.check()?;
        let attempted =
            current
                .checked_add(additional)
                .ok_or(WarmSnapshotBudgetError::SizeLimitExceeded {
                    attempted: usize::MAX,
                    cap: self.max_snapshot_bytes,
                })?;
        if attempted > self.max_snapshot_bytes {
            return Err(WarmSnapshotBudgetError::SizeLimitExceeded {
                attempted,
                cap: self.max_snapshot_bytes,
            });
        }
        Ok(attempted)
    }

    fn check_temporary_allocation(&self, bytes: usize) -> Result<(), WarmSnapshotBudgetError> {
        self.check_growth(0, bytes).map(drop)
    }
}

/// Terminal warm-snapshot work-budget failure.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum WarmSnapshotBudgetError {
    /// The async shutdown coordinator stopped waiting for this work.
    #[error("warm checkpoint work was cancelled")]
    Cancelled,
    /// The shared monotonic shutdown deadline elapsed.
    #[error("warm checkpoint work exceeded its terminal deadline")]
    DeadlineExceeded,
    /// Encoding would exceed the configured complete-snapshot cap.
    #[error("warm checkpoint encoding would need {attempted} bytes, exceeding the {cap}-byte cap")]
    SizeLimitExceeded {
        /// Encoded length that the attempted append would produce.
        attempted: usize,
        /// Maximum complete encoded snapshot length.
        cap: usize,
    },
}

/// MRT encoding errors.
#[derive(Debug, Error)]
pub enum EncodeError {
    /// A field value exceeds the maximum representable MRT wire size.
    #[error("{field} too large for MRT encoding: {value}")]
    FieldTooLarge {
        /// Name of the field that overflowed.
        field: &'static str,
        /// The actual value that was too large.
        value: usize,
    },
    /// A BGP path attribute could not be encoded.
    #[error("path attribute encode failed: {0}")]
    AttributeEncode(#[from] WireEncodeError),
    /// Add-Path profile contained duplicates or an unsupported family.
    #[error("invalid MRT Add-Path receive profile for {peer} ({afi:?}/{safi:?}): {reason}")]
    InvalidAddPathProfile {
        /// Peer in the invalid profile.
        peer: IpAddr,
        /// Address family in the invalid profile.
        afi: Afi,
        /// Subsequent address family in the invalid profile.
        safi: Safi,
        /// Why the profile cannot be encoded.
        reason: &'static str,
    },
    /// A non-Add-Path profile carried a nonzero path identifier.
    #[error("route from {peer} has path_id {path_id} but its MRT profile is not Add-Path")]
    AddPathProfileMismatch {
        /// Advertising peer.
        peer: IpAddr,
        /// Unexpected nonzero path identifier.
        path_id: u32,
    },
    /// A route depends on identity that V1 cannot recover exactly.
    #[error("route from {peer} cannot be used in a V1 warm snapshot: {reason}")]
    UnsupportedWarmRouteProfile {
        /// Advertising peer.
        peer: IpAddr,
        /// Why the route cannot be restored exactly.
        reason: &'static str,
    },
    /// Warm checkpoint cancellation, deadline, or complete-output cap fired.
    #[error(transparent)]
    WarmSnapshotBudget(#[from] WarmSnapshotBudgetError),
    /// A checked output-buffer reservation failed.
    #[error("failed to reserve {attempted} bytes for MRT encoding")]
    AllocationFailed {
        /// Encoded buffer length requested by the failed append.
        attempted: usize,
    },
}

/// Checked append-only view over an MRT output vector.
///
/// Bounded buffers reserve geometrically, but never beyond the remaining hard
/// cap. `try_reserve_exact` avoids `Vec`'s ordinary speculative over-allocation
/// when the buffer is close to that cap.
struct EncodeBuffer<'a> {
    bytes: &'a mut Vec<u8>,
    budget: Option<&'a WarmSnapshotBudget>,
    accounted_prefix: usize,
}

impl<'a> EncodeBuffer<'a> {
    fn new(bytes: &'a mut Vec<u8>, budget: Option<&'a WarmSnapshotBudget>) -> Self {
        Self {
            bytes,
            budget,
            accounted_prefix: 0,
        }
    }

    fn child(
        bytes: &'a mut Vec<u8>,
        budget: Option<&'a WarmSnapshotBudget>,
        accounted_prefix: usize,
    ) -> Self {
        Self {
            bytes,
            budget,
            accounted_prefix,
        }
    }

    fn check(&self) -> Result<(), EncodeError> {
        self.budget.map_or(Ok(()), WarmSnapshotBudget::check)?;
        Ok(())
    }

    fn reserve_for(&mut self, additional: usize) -> Result<usize, EncodeError> {
        let local_attempted =
            self.bytes
                .len()
                .checked_add(additional)
                .ok_or(EncodeError::AllocationFailed {
                    attempted: usize::MAX,
                })?;
        let attempted = if let Some(budget) = self.budget {
            budget.check_growth(self.effective_len(), additional)?
        } else {
            local_attempted
        };
        if local_attempted <= self.bytes.capacity() {
            return Ok(attempted);
        }

        let target_capacity = if let Some(budget) = self.budget {
            let doubled = self.bytes.capacity().max(4096).saturating_mul(2);
            local_attempted.max(doubled).min(
                budget
                    .max_snapshot_bytes
                    .saturating_sub(self.accounted_prefix),
            )
        } else {
            local_attempted
        };
        self.bytes
            .try_reserve_exact(target_capacity.saturating_sub(self.bytes.len()))
            .map_err(|_| EncodeError::AllocationFailed { attempted })?;
        // Cancellation can race the allocation itself. Recheck before any
        // bytes are committed; on failure the caller drops this bounded Vec.
        self.check()?;
        Ok(attempted)
    }

    fn extend_from_slice(&mut self, value: &[u8]) -> Result<(), EncodeError> {
        self.reserve_for(value.len())?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn push(&mut self, value: u8) -> Result<(), EncodeError> {
        self.reserve_for(1)?;
        self.bytes.push(value);
        Ok(())
    }

    fn len(&self) -> usize {
        self.bytes.len()
    }

    fn effective_len(&self) -> usize {
        self.accounted_prefix.saturating_add(self.bytes.len())
    }

    fn truncate(&mut self, len: usize) {
        self.bytes.truncate(len);
    }

    fn finish_record(&mut self, start: usize) -> Result<(), EncodeError> {
        let payload_len = self
            .len()
            .saturating_sub(start)
            .saturating_sub(MRT_HEADER_LEN);
        let length = u32::try_from(payload_len).map_err(|_| EncodeError::FieldTooLarge {
            field: "MRT payload length",
            value: payload_len,
        })?;
        self.bytes[start + 8..start + MRT_HEADER_LEN].copy_from_slice(&length.to_be_bytes());
        Ok(())
    }

    fn patch_u16(&mut self, offset: usize, value: u16) {
        self.bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
    }
}

const CANCELLABLE_SORT_RUN: usize = 256;

fn collect_cancellable<T>(
    values: impl ExactSizeIterator<Item = T>,
    budget: Option<&WarmSnapshotBudget>,
) -> Result<Vec<T>, EncodeError> {
    let len = values.len();
    let allocation_bytes =
        len.checked_mul(std::mem::size_of::<T>())
            .ok_or(EncodeError::AllocationFailed {
                attempted: usize::MAX,
            })?;
    if let Some(budget) = budget {
        budget.check_temporary_allocation(allocation_bytes)?;
    }
    let mut collected = Vec::new();
    collected
        .try_reserve_exact(len)
        .map_err(|_| EncodeError::AllocationFailed {
            attempted: allocation_bytes,
        })?;
    if let Some(budget) = budget {
        budget.check()?;
    }
    for value in values {
        collected.push(value);
        // Iterators used here yield borrowed keys in constant time. Checking
        // after each yield also catches cancellation raised while a key is
        // being materialized rather than waiting for the later sort.
        if let Some(budget) = budget {
            budget.check()?;
        }
    }
    Ok(collected)
}

/// Bottom-up merge sort whose non-cancellable leaf work is capped to a
/// small fixed run. Warm checkpoint inputs use reference/copy keys, so the one
/// scratch allocation never duplicates route attributes or encoded records.
fn sort_cancellable_by<T: Clone>(
    values: &mut [T],
    budget: Option<&WarmSnapshotBudget>,
    compare: impl Fn(&T, &T) -> CmpOrdering + Copy,
) -> Result<(), EncodeError> {
    let Some(budget) = budget else {
        values.sort_by(compare);
        return Ok(());
    };
    if values.len() < 2 {
        return budget.check().map_err(Into::into);
    }

    for run in values.chunks_mut(CANCELLABLE_SORT_RUN) {
        budget.check()?;
        run.sort_unstable_by(compare);
        budget.check()?;
    }

    let scratch_bytes = values.len().checked_mul(std::mem::size_of::<T>()).ok_or(
        EncodeError::AllocationFailed {
            attempted: usize::MAX,
        },
    )?;
    budget.check_temporary_allocation(scratch_bytes)?;
    let mut scratch = Vec::<T>::new();
    scratch
        .try_reserve_exact(values.len())
        .map_err(|_| EncodeError::AllocationFailed {
            attempted: scratch_bytes,
        })?;
    budget.check()?;

    let mut width = CANCELLABLE_SORT_RUN;
    while width < values.len() {
        let step = width.saturating_mul(2);
        let mut start = 0usize;
        while start < values.len() {
            budget.check()?;
            let middle = start.saturating_add(width).min(values.len());
            let end = start.saturating_add(step).min(values.len());
            if middle == end {
                start = end;
                continue;
            }
            scratch.clear();
            let mut left = start;
            let mut right = middle;
            let mut copied = 0usize;
            while left < middle && right < end {
                if copied.is_multiple_of(CANCELLABLE_SORT_RUN) {
                    budget.check()?;
                }
                if compare(&values[left], &values[right]) == CmpOrdering::Greater {
                    scratch.push(values[right].clone());
                    right += 1;
                } else {
                    scratch.push(values[left].clone());
                    left += 1;
                }
                copied += 1;
            }
            while left < middle {
                if copied.is_multiple_of(CANCELLABLE_SORT_RUN) {
                    budget.check()?;
                }
                scratch.push(values[left].clone());
                left += 1;
                copied += 1;
            }
            while right < end {
                if copied.is_multiple_of(CANCELLABLE_SORT_RUN) {
                    budget.check()?;
                }
                scratch.push(values[right].clone());
                right += 1;
                copied += 1;
            }
            values[start..end].clone_from_slice(&scratch);
            start = end;
        }
        width = step;
    }
    budget.check()?;
    Ok(())
}

/// Begin an MRT record with a placeholder payload length.
fn begin_mrt_record(
    buf: &mut EncodeBuffer<'_>,
    timestamp: u32,
    subtype: u16,
) -> Result<usize, EncodeError> {
    let start = buf.len();
    buf.extend_from_slice(&timestamp.to_be_bytes())?;
    buf.extend_from_slice(&TABLE_DUMP_V2.to_be_bytes())?;
    buf.extend_from_slice(&subtype.to_be_bytes())?;
    buf.extend_from_slice(&0u32.to_be_bytes())?;
    Ok(start)
}

#[cfg(test)]
fn encode_mrt_header(buf: &mut Vec<u8>, timestamp: u32, mrt_type: u16, subtype: u16, length: u32) {
    buf.extend_from_slice(&timestamp.to_be_bytes());
    buf.extend_from_slice(&mrt_type.to_be_bytes());
    buf.extend_from_slice(&subtype.to_be_bytes());
    buf.extend_from_slice(&length.to_be_bytes());
}
/// Encode the `PEER_INDEX_TABLE` record (subtype 1).
///
/// Always uses AS4 (type bit 1 set) and includes IPv6 peers (type bit 0).
///
/// # Errors
///
/// Returns [`EncodeError::FieldTooLarge`] if the view name or peer count
/// exceeds the representable MRT field width.
pub fn encode_peer_index_table(
    buf: &mut Vec<u8>,
    timestamp: u32,
    collector_bgp_id: Ipv4Addr,
    view_name: &str,
    peers: &[MrtPeerEntry],
) -> Result<(), EncodeError> {
    let mut output = EncodeBuffer::new(buf, None);
    encode_peer_index_table_inner(&mut output, timestamp, collector_bgp_id, view_name, peers)
}

fn encode_peer_index_table_inner(
    buf: &mut EncodeBuffer<'_>,
    timestamp: u32,
    collector_bgp_id: Ipv4Addr,
    view_name: &str,
    peers: &[MrtPeerEntry],
) -> Result<(), EncodeError> {
    let start = begin_mrt_record(buf, timestamp, PEER_INDEX_TABLE)?;
    let result = (|| {
        // Collector BGP ID
        buf.extend_from_slice(&collector_bgp_id.octets())?;
        // View name
        let name_bytes = view_name.as_bytes();
        let view_name_len =
            u16::try_from(name_bytes.len()).map_err(|_| EncodeError::FieldTooLarge {
                field: "PEER_INDEX_TABLE.view_name length",
                value: name_bytes.len(),
            })?;
        buf.extend_from_slice(&view_name_len.to_be_bytes())?;
        buf.extend_from_slice(name_bytes)?;
        // Peer count
        let peer_count = u16::try_from(peers.len()).map_err(|_| EncodeError::FieldTooLarge {
            field: "PEER_INDEX_TABLE.peer_count",
            value: peers.len(),
        })?;
        buf.extend_from_slice(&peer_count.to_be_bytes())?;
        for peer in peers {
            buf.check()?;
            // Peer type: bit 0 = IPv6, bit 1 = AS4 (always set)
            let peer_type: u8 = match peer.peer_addr {
                IpAddr::V6(_) => 0b11, // IPv6 + AS4
                IpAddr::V4(_) => 0b10, // AS4 only
            };
            buf.push(peer_type)?;
            // Peer BGP ID
            buf.extend_from_slice(&peer.peer_bgp_id.octets())?;
            // Peer IP address
            match peer.peer_addr {
                IpAddr::V4(v4) => buf.extend_from_slice(&v4.octets())?,
                IpAddr::V6(v6) => buf.extend_from_slice(&v6.octets())?,
            }
            // Peer AS (always 4 bytes)
            buf.extend_from_slice(&peer.peer_asn.to_be_bytes())?;
        }
        buf.finish_record(start)
    })();
    if result.is_err() {
        buf.truncate(start);
    }
    result
}
/// Synthesize path attributes for MRT encoding from a `Route`.
///
/// The route's `attributes` vec doesn't contain next-hop or `MP_REACH`
/// (stripped per MP-BGP architecture). We reconstruct the appropriate
/// attribute based on the route's prefix family:
/// - IPv4: `PathAttribute::NextHop(ipv4)` (type 3)
/// - IPv6: `PathAttribute::MpReachNlri` with IPv6 next-hop, empty NLRI
#[must_use]
pub fn synthesize_attributes(route: &Route) -> Vec<PathAttribute> {
    let mut attrs = (*route.attributes).clone();
    match route.prefix {
        Prefix::V4(_) => {
            match route.next_hop {
                IpAddr::V4(nh) => {
                    // Synthesize NEXT_HOP for IPv4.
                    // Insert after ORIGIN and AS_PATH if they exist (canonical order).
                    let insert_pos = attrs
                        .iter()
                        .position(|a| {
                            !matches!(a, PathAttribute::Origin(_) | PathAttribute::AsPath(_))
                        })
                        .unwrap_or(attrs.len());
                    attrs.insert(insert_pos, PathAttribute::NextHop(nh));
                }
                IpAddr::V6(_) => {
                    // RFC 8950: IPv4 NLRI can carry IPv6 next-hop via MP_REACH_NLRI.
                    use rustbgpd_wire::{Afi, MpReachNlri, Safi};
                    attrs.push(PathAttribute::MpReachNlri(MpReachNlri {
                        afi: Afi::Ipv4,
                        safi: Safi::Unicast,
                        next_hop: route.next_hop,
                        link_local_next_hop: route.link_local_next_hop,
                        announced: vec![],
                        flowspec_announced: vec![],
                        evpn_announced: vec![],
                        bgpls_announced: vec![],
                        labeled_announced: vec![],
                        vpn_announced: vec![],
                        rtc_announced: vec![],
                    }));
                }
            }
        }
        Prefix::V6(_) => {
            // Synthesize MP_REACH_NLRI for IPv6 with `next_hop` only (no NLRI —
            // the prefix is in the RIB entry header per `TABLE_DUMP_V2` spec).
            use rustbgpd_wire::{Afi, MpReachNlri, Safi};
            let mp_reach = PathAttribute::MpReachNlri(MpReachNlri {
                afi: Afi::Ipv6,
                safi: Safi::Unicast,
                next_hop: route.next_hop,
                link_local_next_hop: route.link_local_next_hop,
                announced: vec![],
                flowspec_announced: vec![],
                evpn_announced: vec![],
                bgpls_announced: vec![],
                labeled_announced: vec![],
                vpn_announced: vec![],
                rtc_announced: vec![],
            });
            attrs.push(mp_reach);
        }
    }
    attrs
}
/// Synthesize path attributes for an EVPN RIB entry.
///
/// `EvpnRibRoute.attributes` was stripped of `MP_REACH_NLRI` at decode
/// (per MP-BGP architecture). For the MRT encoding we add a fresh
/// `MP_REACH_NLRI` carrying the next-hop only — the EVPN NLRI itself
/// rides in the `RIB_GENERIC` record header per RFC 6396 §4.3.5, not
/// in the attribute. The attribute's NLRI/AFI/SAFI fields are dropped
/// when the entry is serialized by the internal MRT RIB-attribute
/// encoder, which rewrites `MP_REACH_NLRI` to the RFC 6396 §4.3.4
/// reduced form (NH-Len + NH bytes only).
#[must_use]
pub fn synthesize_evpn_attributes(route: &EvpnRibRoute) -> Vec<PathAttribute> {
    let mut attrs = (*route.attributes).clone();
    attrs.push(PathAttribute::MpReachNlri(MpReachNlri {
        afi: Afi::L2Vpn,
        safi: Safi::Evpn,
        next_hop: route.next_hop,
        link_local_next_hop: route.link_local_next_hop,
        announced: vec![],
        flowspec_announced: vec![],
        evpn_announced: vec![],
        bgpls_announced: vec![],
        labeled_announced: vec![],
        vpn_announced: vec![],
        rtc_announced: vec![],
    }));
    attrs
}
/// Encode a single EVPN route as a `RIB_GENERIC` (subtype 6) record.
///
/// Layout per RFC 6396 §4.3.5:
/// ```text
///   Sequence Number (4)
///   AFI (2)              = 25 (L2VPN)
///   SAFI (1)             = 70 (EVPN)
///   NLRI (variable)      = encoded EVPN route TLV (route_type + length + body)
///   Entry Count (2)      = 1 (EVPN does not use Add-Path in this codebase)
///   RIB Entries          = single entry [peer_index, originated_time,
///                          attribute_length, attributes]
/// ```
///
/// # Errors
///
/// Returns [`EncodeError::FieldTooLarge`] if the encoded attribute payload
/// for the entry exceeds the 16-bit `attribute_length` field.
fn encode_evpn_rib_generic(
    buf: &mut EncodeBuffer<'_>,
    timestamp: u32,
    seq_num: u32,
    route: &EvpnRibRoute,
    peer_index: u16,
    originated_time: u32,
) -> Result<(), EncodeError> {
    let start = begin_mrt_record(buf, timestamp, RIB_GENERIC)?;
    let result = (|| {
        buf.extend_from_slice(&seq_num.to_be_bytes())?;
        buf.extend_from_slice(&(Afi::L2Vpn as u16).to_be_bytes())?;
        buf.push(Safi::Evpn as u8)?;
        let mut nlri = Vec::new();
        encode_evpn_nlri(std::slice::from_ref(&route.route), &mut nlri);
        buf.extend_from_slice(&nlri)?;
        buf.extend_from_slice(&1u16.to_be_bytes())?;
        encode_evpn_route_rib_entry(buf, route, peer_index, originated_time)?;
        buf.finish_record(start)
    })();
    if result.is_err() {
        buf.truncate(start);
    }
    result
}
/// Encode a single RIB entry (shared by all RIB_* subtypes).
fn encode_rib_entry(
    buf: &mut EncodeBuffer<'_>,
    entry: &RibEntry,
    add_path: bool,
) -> Result<(), EncodeError> {
    if add_path {
        buf.extend_from_slice(&entry.path_id.to_be_bytes())?;
    }
    buf.extend_from_slice(&entry.peer_index.to_be_bytes())?;
    buf.extend_from_slice(&entry.originated_time.to_be_bytes())?;
    let mut attr_buf = Vec::new();
    {
        let mut checked_attrs = EncodeBuffer::child(
            &mut attr_buf,
            buf.budget,
            buf.effective_len().saturating_add(2),
        );
        encode_mrt_rib_attributes(&entry.attributes, &mut checked_attrs)?;
    }
    let attr_len = u16::try_from(attr_buf.len()).map_err(|_| EncodeError::FieldTooLarge {
        field: "RIB entry attribute length",
        value: attr_buf.len(),
    })?;
    // Account for the two-byte length before appending the bounded attribute
    // buffer. A single RIB entry remains protocol-bounded to u16 bytes.
    if let Some(budget) = buf.budget {
        budget.check_growth(buf.effective_len(), 2usize.saturating_add(attr_buf.len()))?;
    }
    buf.extend_from_slice(&attr_len.to_be_bytes())?;
    buf.extend_from_slice(&attr_buf)?;
    Ok(())
}

fn encode_route_rib_entry(
    buf: &mut EncodeBuffer<'_>,
    route: &Route,
    peer_index: u16,
    originated_time: u32,
    add_path: bool,
) -> Result<(), EncodeError> {
    if add_path {
        buf.extend_from_slice(&route.path_id.to_be_bytes())?;
    }
    buf.extend_from_slice(&peer_index.to_be_bytes())?;
    buf.extend_from_slice(&originated_time.to_be_bytes())?;
    let attr_len_offset = buf.len();
    buf.extend_from_slice(&0u16.to_be_bytes())?;
    let attr_start = buf.len();
    encode_route_mrt_attributes(route, buf)?;
    let attr_len = buf.len().saturating_sub(attr_start);
    let attr_len = u16::try_from(attr_len).map_err(|_| EncodeError::FieldTooLarge {
        field: "RIB entry attribute length",
        value: attr_len,
    })?;
    buf.patch_u16(attr_len_offset, attr_len);
    Ok(())
}

fn encode_evpn_route_rib_entry(
    buf: &mut EncodeBuffer<'_>,
    route: &EvpnRibRoute,
    peer_index: u16,
    originated_time: u32,
) -> Result<(), EncodeError> {
    buf.extend_from_slice(&peer_index.to_be_bytes())?;
    buf.extend_from_slice(&originated_time.to_be_bytes())?;
    let attr_len_offset = buf.len();
    buf.extend_from_slice(&0u16.to_be_bytes())?;
    let attr_start = buf.len();
    for attr in route.attributes.iter() {
        encode_one_mrt_rib_attribute(attr, buf)?;
    }
    encode_mrt_mp_reach(route.next_hop, route.link_local_next_hop, buf)?;
    let attr_len = buf.len().saturating_sub(attr_start);
    let attr_len = u16::try_from(attr_len).map_err(|_| EncodeError::FieldTooLarge {
        field: "RIB entry attribute length",
        value: attr_len,
    })?;
    buf.patch_u16(attr_len_offset, attr_len);
    Ok(())
}

fn encode_route_mrt_attributes(
    route: &Route,
    buf: &mut EncodeBuffer<'_>,
) -> Result<(), EncodeError> {
    let inject_ipv4_next_hop =
        matches!(route.prefix, Prefix::V4(_)) && matches!(route.next_hop, IpAddr::V4(_));
    let mut injected = false;
    for attr in route.attributes.iter() {
        if inject_ipv4_next_hop
            && !injected
            && !matches!(attr, PathAttribute::Origin(_) | PathAttribute::AsPath(_))
        {
            let IpAddr::V4(next_hop) = route.next_hop else {
                unreachable!("IPv4 next-hop profile checked above")
            };
            encode_one_mrt_rib_attribute(&PathAttribute::NextHop(next_hop), buf)?;
            injected = true;
        }
        encode_one_mrt_rib_attribute(attr, buf)?;
    }
    if inject_ipv4_next_hop && !injected {
        let IpAddr::V4(next_hop) = route.next_hop else {
            unreachable!("IPv4 next-hop profile checked above")
        };
        encode_one_mrt_rib_attribute(&PathAttribute::NextHop(next_hop), buf)?;
    } else if !inject_ipv4_next_hop {
        encode_mrt_mp_reach(route.next_hop, route.link_local_next_hop, buf)?;
    }
    Ok(())
}
/// Encode path attributes for an MRT RIB entry per RFC 6396 §4.3.4.
///
/// `MP_REACH_NLRI` is rewritten to the MRT-reduced form: only NH-Len
/// and the next-hop bytes appear in the attribute value. The AFI,
/// SAFI, Reserved, and NLRI fields are omitted because the RIB entry
/// header already carries that information. All other attributes
/// encode identically to a regular BGP UPDATE.
fn encode_mrt_rib_attributes(
    attrs: &[PathAttribute],
    buf: &mut EncodeBuffer<'_>,
) -> Result<(), EncodeError> {
    for attr in attrs {
        buf.check()?;
        encode_one_mrt_rib_attribute(attr, buf)?;
    }
    Ok(())
}

fn encode_one_mrt_rib_attribute(
    attr: &PathAttribute,
    buf: &mut EncodeBuffer<'_>,
) -> Result<(), EncodeError> {
    buf.check()?;
    if let PathAttribute::MpReachNlri(mp) = attr {
        encode_mrt_mp_reach(mp.next_hop, mp.link_local_next_hop, buf)
    } else {
        // The wire encoder is Vec-based. One received BGP attribute is
        // protocol-bounded to u16 bytes; append it immediately rather than
        // retaining owned attributes for a complete prefix record.
        let mut encoded = Vec::new();
        encode_path_attributes(std::slice::from_ref(attr), &mut encoded, true, false)?;
        buf.extend_from_slice(&encoded)
    }
}
/// Append a single `MP_REACH_NLRI` attribute in MRT-reduced form.
///
/// Wire layout per RFC 6396 §4.3.4 — TLV header followed by the
/// reduced value (NH-Len + NH bytes only). The attribute uses the
/// optional flag (0x80) and type code 14, matching the standard
/// `MP_REACH_NLRI` framing.
///
/// When `link_local` is `Some`, the value is 33 bytes: NH-Len=32 +
/// 16-byte global + 16-byte link-local, per RFC 4760 §3 / RFC 2545.
fn encode_mrt_mp_reach(
    next_hop: IpAddr,
    link_local: Option<std::net::Ipv6Addr>,
    buf: &mut EncodeBuffer<'_>,
) -> Result<(), EncodeError> {
    let mut value: Vec<u8> = Vec::with_capacity(33);
    match (next_hop, link_local) {
        (IpAddr::V4(addr), _) => {
            value.push(4);
            value.extend_from_slice(&addr.octets());
        }
        (IpAddr::V6(addr), Some(ll)) => {
            value.push(32);
            value.extend_from_slice(&addr.octets());
            value.extend_from_slice(&ll.octets());
        }
        (IpAddr::V6(addr), None) => {
            value.push(16);
            value.extend_from_slice(&addr.octets());
        }
    }
    buf.push(0x80)?;
    buf.push(14)?;
    #[expect(
        clippy::cast_possible_truncation,
        reason = "value length is at most 33 bytes"
    )]
    buf.push(value.len() as u8)?;
    buf.extend_from_slice(&value)?;
    Ok(())
}
/// Encode a prefix into MRT format: length byte then ceil(len/8) prefix bytes.
fn encode_prefix_bytes(buf: &mut EncodeBuffer<'_>, prefix: &Prefix) -> Result<(), EncodeError> {
    match prefix {
        Prefix::V4(v4) => {
            buf.push(v4.len)?;
            let byte_len = usize::from(v4.len).div_ceil(8);
            buf.extend_from_slice(&v4.addr.octets()[..byte_len])?;
        }
        Prefix::V6(v6) => {
            buf.push(v6.len)?;
            let byte_len = usize::from(v6.len).div_ceil(8);
            buf.extend_from_slice(&v6.addr.octets()[..byte_len])?;
        }
    }
    Ok(())
}
/// Encode a `RIB_IPV4_UNICAST` or `RIB_IPV6_UNICAST` record.
///
/// If any entry has `path_id != 0`, the ADDPATH subtype is used instead.
///
/// # Errors
///
/// Returns [`EncodeError::FieldTooLarge`] if the number of entries or encoded
/// attribute payload for an entry exceeds MRT field limits.
pub fn encode_rib_entries(
    buf: &mut Vec<u8>,
    timestamp: u32,
    seq_num: u32,
    prefix: &Prefix,
    entries: &[RibEntry],
) -> Result<(), EncodeError> {
    let has_addpath = entries.iter().any(|e| e.path_id != 0);
    let mut output = EncodeBuffer::new(buf, None);
    encode_rib_entries_profile(
        &mut output,
        timestamp,
        seq_num,
        prefix,
        entries,
        has_addpath,
    )
}

fn encode_rib_entries_profile(
    buf: &mut EncodeBuffer<'_>,
    timestamp: u32,
    seq_num: u32,
    prefix: &Prefix,
    entries: &[RibEntry],
    has_addpath: bool,
) -> Result<(), EncodeError> {
    let subtype = match (prefix, has_addpath) {
        (Prefix::V4(_), false) => RIB_IPV4_UNICAST,
        (Prefix::V4(_), true) => RIB_IPV4_UNICAST_ADDPATH,
        (Prefix::V6(_), false) => RIB_IPV6_UNICAST,
        (Prefix::V6(_), true) => RIB_IPV6_UNICAST_ADDPATH,
    };
    let start = begin_mrt_record(buf, timestamp, subtype)?;
    let result = (|| {
        buf.extend_from_slice(&seq_num.to_be_bytes())?;
        encode_prefix_bytes(buf, prefix)?;
        let entry_count = u16::try_from(entries.len()).map_err(|_| EncodeError::FieldTooLarge {
            field: "RIB entry count",
            value: entries.len(),
        })?;
        buf.extend_from_slice(&entry_count.to_be_bytes())?;
        for entry in entries {
            buf.check()?;
            encode_rib_entry(buf, entry, has_addpath)?;
        }
        buf.finish_record(start)
    })();
    if result.is_err() {
        buf.truncate(start);
    }
    result
}

#[derive(Clone, Copy)]
enum RouteEntrySelection {
    All,
    Legacy,
    AddPath,
}

fn route_uses_add_path(
    route: &Route,
    profiles: Option<&HashSet<MrtAddPathReceiveProfile>>,
) -> bool {
    profiles.is_some_and(|profiles| {
        let afi = match route.prefix {
            Prefix::V4(_) => Afi::Ipv4,
            Prefix::V6(_) => Afi::Ipv6,
        };
        profiles.contains(&MrtAddPathReceiveProfile {
            peer: route.peer,
            afi,
            safi: Safi::Unicast,
        })
    })
}

#[expect(
    clippy::too_many_arguments,
    reason = "borrowed route records need explicit MRT identity, selection, and timing inputs"
)]
fn encode_route_entries_profile(
    buf: &mut EncodeBuffer<'_>,
    timestamp: u32,
    seq_num: u32,
    prefix: &Prefix,
    routes: &[&Route],
    peer_index: &HashMap<IpAddr, u16>,
    profiles: Option<&HashSet<MrtAddPathReceiveProfile>>,
    selection: RouteEntrySelection,
    entry_count: u16,
    add_path: bool,
    now_secs: u64,
) -> Result<(), EncodeError> {
    let subtype = match (prefix, add_path) {
        (Prefix::V4(_), false) => RIB_IPV4_UNICAST,
        (Prefix::V4(_), true) => RIB_IPV4_UNICAST_ADDPATH,
        (Prefix::V6(_), false) => RIB_IPV6_UNICAST,
        (Prefix::V6(_), true) => RIB_IPV6_UNICAST_ADDPATH,
    };
    let start = begin_mrt_record(buf, timestamp, subtype)?;
    let result = (|| {
        buf.extend_from_slice(&seq_num.to_be_bytes())?;
        encode_prefix_bytes(buf, prefix)?;
        buf.extend_from_slice(&entry_count.to_be_bytes())?;
        let mut encoded_count = 0u16;
        for route in routes {
            buf.check()?;
            let uses_add_path = route_uses_add_path(route, profiles);
            let selected = match selection {
                RouteEntrySelection::All => true,
                RouteEntrySelection::Legacy => !uses_add_path,
                RouteEntrySelection::AddPath => uses_add_path,
            };
            if !selected {
                continue;
            }
            let peer_index = peer_index
                .get(&route.peer)
                .copied()
                .expect("effective peer inventory includes every route origin");
            let age = route.received_at.elapsed().as_secs();
            let originated = u32::try_from(now_secs.saturating_sub(age)).unwrap_or(u32::MAX);
            encode_route_rib_entry(buf, route, peer_index, originated, add_path)?;
            encoded_count = encoded_count
                .checked_add(1)
                .ok_or(EncodeError::FieldTooLarge {
                    field: "RIB entry count",
                    value: usize::from(entry_count).saturating_add(1),
                })?;
        }
        debug_assert_eq!(encoded_count, entry_count);
        buf.finish_record(start)
    })();
    if result.is_err() {
        buf.truncate(start);
    }
    result
}
/// Encode a full MRT `TABLE_DUMP_V2` dump from a snapshot.
///
/// Returns the complete binary output suitable for writing to a file.
///
/// # Errors
///
/// Returns [`EncodeError::FieldTooLarge`] if any encoded MRT field exceeds its
/// wire-size bounds (for example peer index, record payload, or attribute
/// lengths).
pub fn encode_snapshot(
    collector_bgp_id: Ipv4Addr,
    peers: &[MrtPeerEntry],
    routes: &[Route],
    evpn_routes: &[EvpnRibRoute],
    timestamp: u32,
) -> Result<Vec<u8>, EncodeError> {
    encode_snapshot_with_view(collector_bgp_id, "", peers, routes, evpn_routes, timestamp)
}

/// Encode a full MRT snapshot with an explicit `PEER_INDEX_TABLE` view name.
///
/// Warm checkpoints use the view name as a caller-issued generation and bind
/// it into the warm-bundle identity. Periodic dumps should continue to use
/// [`encode_snapshot`], whose view name remains empty for compatibility.
///
/// # Errors
///
/// Returns [`EncodeError::FieldTooLarge`] if the view name or another encoded
/// MRT field exceeds its wire-size bound.
pub fn encode_snapshot_with_view(
    collector_bgp_id: Ipv4Addr,
    view_name: &str,
    peers: &[MrtPeerEntry],
    routes: &[Route],
    evpn_routes: &[EvpnRibRoute],
    timestamp: u32,
) -> Result<Vec<u8>, EncodeError> {
    encode_snapshot_inner(
        collector_bgp_id,
        view_name,
        peers,
        routes,
        evpn_routes,
        timestamp,
        None,
        None,
    )
}

/// Encode a warm snapshot with an exact per-peer Add-Path receive profile.
///
/// Entries for one prefix are split into separate Add-Path and legacy RIB
/// records when peers negotiated different profiles. This preserves a zero
/// path identifier as an Add-Path entry and gives the warm loader an exact
/// record-subtype identity to validate.
///
/// # Errors
///
/// Returns [`EncodeError::InvalidAddPathProfile`] for duplicate or non-unicast
/// profiles, [`EncodeError::AddPathProfileMismatch`] when a route with a
/// nonzero path ID is assigned to a legacy profile, and
/// [`EncodeError::UnsupportedWarmRouteProfile`] when next-hop scope cannot be
/// recovered exactly.
pub fn encode_warm_snapshot(
    collector_bgp_id: Ipv4Addr,
    view_name: &str,
    peers: &[MrtPeerEntry],
    routes: &[Route],
    evpn_routes: &[EvpnRibRoute],
    timestamp: u32,
    add_path_receive: &[MrtAddPathReceiveProfile],
) -> Result<Vec<u8>, EncodeError> {
    encode_warm_snapshot_inner(
        collector_bgp_id,
        view_name,
        peers,
        routes,
        evpn_routes,
        timestamp,
        add_path_receive,
        None,
    )
}

/// Encode a warm snapshot under a hard complete-output cap and shared
/// cancellation/deadline contract.
///
/// Unlike [`encode_warm_snapshot`], every reservation of the complete MRT
/// output is checked before `Vec` growth. The encoder also checks the shared
/// cancellation token throughout peer, route, prefix, and EVPN traversal.
///
/// # Errors
///
/// Returns the same profile errors as [`encode_warm_snapshot`], plus
/// [`EncodeError::WarmSnapshotBudget`] when the cap, cancellation token, or
/// deadline rejects the work.
#[expect(
    clippy::too_many_arguments,
    reason = "bounded warm encoding extends the established snapshot API with one shared work budget"
)]
pub fn encode_warm_snapshot_bounded(
    collector_bgp_id: Ipv4Addr,
    view_name: &str,
    peers: &[MrtPeerEntry],
    routes: &[Route],
    evpn_routes: &[EvpnRibRoute],
    timestamp: u32,
    add_path_receive: &[MrtAddPathReceiveProfile],
    budget: &WarmSnapshotBudget,
) -> Result<Vec<u8>, EncodeError> {
    encode_warm_snapshot_inner(
        collector_bgp_id,
        view_name,
        peers,
        routes,
        evpn_routes,
        timestamp,
        add_path_receive,
        Some(budget),
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "internal wrapper preserves the public snapshot fields plus the optional work budget"
)]
fn encode_warm_snapshot_inner(
    collector_bgp_id: Ipv4Addr,
    view_name: &str,
    peers: &[MrtPeerEntry],
    routes: &[Route],
    evpn_routes: &[EvpnRibRoute],
    timestamp: u32,
    add_path_receive: &[MrtAddPathReceiveProfile],
    budget: Option<&WarmSnapshotBudget>,
) -> Result<Vec<u8>, EncodeError> {
    if let Some(budget) = budget {
        budget.check()?;
    }
    for route in routes {
        if let Some(budget) = budget {
            budget.check()?;
        }
        if route.next_hop_scope.is_some()
            || route.link_local_next_hop.is_some()
            || is_ipv6_link_local(route.next_hop)
        {
            return Err(EncodeError::UnsupportedWarmRouteProfile {
                peer: route.peer,
                reason: "scoped or link-local next-hop identity",
            });
        }
    }
    for route in evpn_routes {
        if let Some(budget) = budget {
            budget.check()?;
        }
        if route.link_local_next_hop.is_some() || is_ipv6_link_local(route.next_hop) {
            return Err(EncodeError::UnsupportedWarmRouteProfile {
                peer: route.peer,
                reason: "link-local next-hop identity",
            });
        }
    }
    let profile_bytes = add_path_receive
        .len()
        .checked_mul(std::mem::size_of::<MrtAddPathReceiveProfile>())
        .ok_or(EncodeError::AllocationFailed {
            attempted: usize::MAX,
        })?;
    if let Some(budget) = budget {
        budget.check_temporary_allocation(profile_bytes)?;
    }
    let mut unique = HashSet::new();
    unique
        .try_reserve(add_path_receive.len())
        .map_err(|_| EncodeError::AllocationFailed {
            attempted: profile_bytes,
        })?;
    for profile in add_path_receive {
        if let Some(budget) = budget {
            budget.check()?;
        }
        if !unique.insert(*profile) {
            return Err(EncodeError::InvalidAddPathProfile {
                peer: profile.peer,
                afi: profile.afi,
                safi: profile.safi,
                reason: "duplicate profile",
            });
        }
        if !matches!(
            (profile.afi, profile.safi),
            (Afi::Ipv4 | Afi::Ipv6, Safi::Unicast)
        ) {
            return Err(EncodeError::InvalidAddPathProfile {
                peer: profile.peer,
                afi: profile.afi,
                safi: profile.safi,
                reason: "only IPv4/IPv6 unicast Add-Path is supported by TABLE_DUMP_V2",
            });
        }
    }
    encode_snapshot_inner(
        collector_bgp_id,
        view_name,
        peers,
        routes,
        evpn_routes,
        timestamp,
        Some(&unique),
        budget,
    )
}

fn is_ipv6_link_local(address: IpAddr) -> bool {
    matches!(address, IpAddr::V6(address) if address.segments()[0] & 0xffc0 == 0xfe80)
}

#[expect(
    clippy::too_many_lines,
    reason = "Single-pass encoder over peer index, unicast prefix groups, and EVPN RIB_GENERIC records — splitting hides the linear flow"
)]
#[expect(
    clippy::too_many_arguments,
    reason = "snapshot identity, route families, Add-Path profile, and work budget are independent inputs"
)]
fn encode_snapshot_inner(
    collector_bgp_id: Ipv4Addr,
    view_name: &str,
    peers: &[MrtPeerEntry],
    routes: &[Route],
    evpn_routes: &[EvpnRibRoute],
    timestamp: u32,
    add_path_receive: Option<&HashSet<MrtAddPathReceiveProfile>>,
    budget: Option<&WarmSnapshotBudget>,
) -> Result<Vec<u8>, EncodeError> {
    let mut buf = Vec::new();
    let mut output = EncodeBuffer::new(&mut buf, budget);
    output.check()?;
    // 1. Build effective peer list from explicit peers + any route-origin peers.
    if peers.len() > usize::from(u16::MAX) {
        return Err(EncodeError::FieldTooLarge {
            field: "PEER_INDEX_TABLE.peer_count",
            value: peers.len(),
        });
    }
    let peer_bytes = peers
        .len()
        .checked_mul(std::mem::size_of::<MrtPeerEntry>())
        .ok_or(EncodeError::AllocationFailed {
            attempted: usize::MAX,
        })?;
    if let Some(budget) = budget {
        budget.check_temporary_allocation(peer_bytes)?;
    }
    let mut effective_peers = Vec::<MrtPeerEntry>::new();
    effective_peers
        .try_reserve_exact(peers.len())
        .map_err(|_| EncodeError::AllocationFailed {
            attempted: peer_bytes,
        })?;
    effective_peers.extend_from_slice(peers);
    let mut seen_peers = HashSet::<IpAddr>::new();
    seen_peers
        .try_reserve(peers.len())
        .map_err(|_| EncodeError::AllocationFailed {
            attempted: peers.len().saturating_mul(std::mem::size_of::<IpAddr>()),
        })?;
    seen_peers.extend(effective_peers.iter().map(|peer| peer.peer_addr));
    for route in routes {
        output.check()?;
        if !seen_peers.contains(&route.peer) {
            if effective_peers.len() == usize::from(u16::MAX) {
                return Err(EncodeError::FieldTooLarge {
                    field: "PEER_INDEX_TABLE.peer_count",
                    value: effective_peers.len().saturating_add(1),
                });
            }
            seen_peers
                .try_reserve(1)
                .map_err(|_| EncodeError::AllocationFailed {
                    attempted: seen_peers
                        .len()
                        .saturating_add(1)
                        .saturating_mul(std::mem::size_of::<IpAddr>()),
                })?;
            effective_peers
                .try_reserve_exact(1)
                .map_err(|_| EncodeError::AllocationFailed {
                    attempted: effective_peers
                        .len()
                        .saturating_add(1)
                        .saturating_mul(std::mem::size_of::<MrtPeerEntry>()),
                })?;
            seen_peers.insert(route.peer);
            effective_peers.push(MrtPeerEntry {
                peer_addr: route.peer,
                peer_bgp_id: Ipv4Addr::UNSPECIFIED,
                peer_asn: 0,
            });
        }
    }
    for route in evpn_routes {
        output.check()?;
        if !seen_peers.contains(&route.peer) {
            if effective_peers.len() == usize::from(u16::MAX) {
                return Err(EncodeError::FieldTooLarge {
                    field: "PEER_INDEX_TABLE.peer_count",
                    value: effective_peers.len().saturating_add(1),
                });
            }
            seen_peers
                .try_reserve(1)
                .map_err(|_| EncodeError::AllocationFailed {
                    attempted: seen_peers
                        .len()
                        .saturating_add(1)
                        .saturating_mul(std::mem::size_of::<IpAddr>()),
                })?;
            effective_peers
                .try_reserve_exact(1)
                .map_err(|_| EncodeError::AllocationFailed {
                    attempted: effective_peers
                        .len()
                        .saturating_add(1)
                        .saturating_mul(std::mem::size_of::<MrtPeerEntry>()),
                })?;
            seen_peers.insert(route.peer);
            effective_peers.push(MrtPeerEntry {
                peer_addr: route.peer,
                peer_bgp_id: Ipv4Addr::UNSPECIFIED,
                peer_asn: 0,
            });
        }
    }
    sort_cancellable_by(&mut effective_peers, budget, |a, b| {
        a.peer_addr
            .cmp(&b.peer_addr)
            .then(a.peer_asn.cmp(&b.peer_asn))
            .then(a.peer_bgp_id.octets().cmp(&b.peer_bgp_id.octets()))
    })?;
    output.check()?;
    // 2. `PEER_INDEX_TABLE`
    encode_peer_index_table_inner(
        &mut output,
        timestamp,
        collector_bgp_id,
        view_name,
        &effective_peers,
    )?;
    // 3. Build peer index lookup
    let mut peer_index = HashMap::<IpAddr, u16>::new();
    peer_index
        .try_reserve(effective_peers.len())
        .map_err(|_| EncodeError::AllocationFailed {
            attempted: effective_peers
                .len()
                .saturating_mul(std::mem::size_of::<(IpAddr, u16)>()),
        })?;
    for (index, peer) in effective_peers.iter().enumerate() {
        output.check()?;
        let index = u16::try_from(index).map_err(|_| EncodeError::FieldTooLarge {
            field: "peer index",
            value: index,
        })?;
        peer_index.insert(peer.peer_addr, index);
    }
    output.check()?;
    // 4. Order borrowed routes once. No path attributes are cloned or retained
    // per prefix; record entries are synthesized directly into the checked
    // output after their profile counts have been preflighted.
    let mut ordered_routes = collect_cancellable(routes.iter(), budget)?;
    sort_cancellable_by(&mut ordered_routes, budget, |a, b| {
        let a_index = peer_index.get(&a.peer).copied().unwrap_or(u16::MAX);
        let b_index = peer_index.get(&b.peer).copied().unwrap_or(u16::MAX);
        a.prefix
            .cmp(&b.prefix)
            .then(a_index.cmp(&b_index))
            .then(a.path_id.cmp(&b.path_id))
    })?;

    // 5. Encode each contiguous prefix group.
    let mut seq_num: u32 = 0;
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut group_start = 0usize;
    while group_start < ordered_routes.len() {
        output.check()?;
        let prefix = ordered_routes[group_start].prefix;
        let mut group_end = group_start + 1;
        while group_end < ordered_routes.len() && ordered_routes[group_end].prefix == prefix {
            if (group_end - group_start).is_multiple_of(CANCELLABLE_SORT_RUN) {
                output.check()?;
            }
            group_end += 1;
        }
        let prefix_routes = &ordered_routes[group_start..group_end];
        if add_path_receive.is_none() {
            let count =
                u16::try_from(prefix_routes.len()).map_err(|_| EncodeError::FieldTooLarge {
                    field: "RIB entry count",
                    value: prefix_routes.len(),
                })?;
            let add_path = prefix_routes.iter().any(|route| route.path_id != 0);
            encode_route_entries_profile(
                &mut output,
                timestamp,
                seq_num,
                &prefix,
                prefix_routes,
                &peer_index,
                None,
                RouteEntrySelection::All,
                count,
                add_path,
                now_secs,
            )?;
            seq_num = seq_num.wrapping_add(1);
            group_start = group_end;
            continue;
        }

        let mut legacy_count = 0usize;
        let mut add_path_count = 0usize;
        for route in prefix_routes {
            output.check()?;
            let uses_add_path = route_uses_add_path(route, add_path_receive);
            if !uses_add_path && route.path_id != 0 {
                return Err(EncodeError::AddPathProfileMismatch {
                    peer: route.peer,
                    path_id: route.path_id,
                });
            }
            if uses_add_path {
                add_path_count = add_path_count.saturating_add(1);
            } else {
                legacy_count = legacy_count.saturating_add(1);
            }
        }
        if legacy_count != 0 {
            let count = u16::try_from(legacy_count).map_err(|_| EncodeError::FieldTooLarge {
                field: "RIB entry count",
                value: legacy_count,
            })?;
            encode_route_entries_profile(
                &mut output,
                timestamp,
                seq_num,
                &prefix,
                prefix_routes,
                &peer_index,
                add_path_receive,
                RouteEntrySelection::Legacy,
                count,
                false,
                now_secs,
            )?;
            seq_num = seq_num.wrapping_add(1);
        }
        if add_path_count != 0 {
            let count = u16::try_from(add_path_count).map_err(|_| EncodeError::FieldTooLarge {
                field: "RIB entry count",
                value: add_path_count,
            })?;
            encode_route_entries_profile(
                &mut output,
                timestamp,
                seq_num,
                &prefix,
                prefix_routes,
                &peer_index,
                add_path_receive,
                RouteEntrySelection::AddPath,
                count,
                true,
                now_secs,
            )?;
            seq_num = seq_num.wrapping_add(1);
        }
        group_start = group_end;
    }
    // 6. Encode EVPN routes as RIB_GENERIC records (RFC 6396 §4.3.5).
    // EVPN does not use Add-Path in this codebase, and EVPN keys are
    // already per-route (RD + ESI + ETag + MAC + IP), so each route maps
    // to a single-entry RIB_GENERIC record. Sort for deterministic output
    // by (peer_index, route).
    // The typed identity key is allocation-free and totally ordered in wire
    // route-type/field order. Do not retain one encoded NLRI Vec per route.
    let mut sorted_evpn = collect_cancellable(evpn_routes.iter(), budget)?;
    sort_cancellable_by(&mut sorted_evpn, budget, |a, b| {
        let a_idx = peer_index.get(&a.peer).copied().unwrap_or(u16::MAX);
        let b_idx = peer_index.get(&b.peer).copied().unwrap_or(u16::MAX);
        a_idx
            .cmp(&b_idx)
            .then_with(|| a.route.key().cmp(&b.route.key()))
    })?;
    for route in sorted_evpn {
        output.check()?;
        let Some(&idx) = peer_index.get(&route.peer) else {
            continue;
        };
        let age = route.received_at.elapsed().as_secs();
        let originated_u64 = now_secs.saturating_sub(age);
        let originated = u32::try_from(originated_u64).unwrap_or(u32::MAX);
        encode_evpn_rib_generic(&mut output, timestamp, seq_num, route, idx, originated)?;
        seq_num = seq_num.wrapping_add(1);
    }
    output.check()?;
    Ok(buf)
}
#[cfg(test)]
mod tests {
    use super::*;
    use rustbgpd_rib::route::{Route, RouteOrigin};
    use rustbgpd_wire::{
        Aggregator, AsPath, Ipv4Prefix, Ipv6Prefix, Origin, PathAttribute, Prefix, RpkiValidation,
    };
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};
    fn make_peer(addr: IpAddr, asn: u32) -> MrtPeerEntry {
        let bgp_id = match addr {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => Ipv4Addr::new(10, 0, 0, 1),
        };
        MrtPeerEntry {
            peer_addr: addr,
            peer_bgp_id: bgp_id,
            peer_asn: asn,
        }
    }
    fn make_route(prefix: Prefix, peer: IpAddr, next_hop: IpAddr) -> Route {
        Route {
            prefix,
            next_hop,
            link_local_next_hop: None,
            next_hop_scope: None,
            peer,
            attributes: Arc::new(vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![rustbgpd_wire::AsPathSegment::AsSequence(vec![65001])],
                }),
                PathAttribute::LocalPref(100),
            ]),
            received_at: Instant::now(),
            origin_type: RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::new(10, 0, 0, 1),
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
            aspa_context: rustbgpd_wire::AspaValidationContext::default(),
        }
    }

    #[test]
    fn bounded_buffer_rejects_before_vec_growth_and_stops_after_cancellation() {
        let cancelled = Arc::new(AtomicBool::new(false));
        let budget = WarmSnapshotBudget::new(
            Instant::now() + Duration::from_mins(1),
            Arc::clone(&cancelled),
            16,
        );
        let mut bytes = Vec::new();
        let mut output = EncodeBuffer::new(&mut bytes, Some(&budget));
        output.extend_from_slice(&[0; 16]).unwrap();
        assert_eq!(output.len(), 16);
        assert!(output.bytes.capacity() <= 16);

        assert!(matches!(
            output.push(1),
            Err(EncodeError::WarmSnapshotBudget(
                WarmSnapshotBudgetError::SizeLimitExceeded {
                    attempted: 17,
                    cap: 16
                }
            ))
        ));
        assert_eq!(output.len(), 16, "cap failure must happen before growth");
        assert!(output.bytes.capacity() <= 16);

        output.truncate(8);
        cancelled.store(true, Ordering::Release);
        assert!(matches!(
            output.push(1),
            Err(EncodeError::WarmSnapshotBudget(
                WarmSnapshotBudgetError::Cancelled
            ))
        ));
        assert_eq!(output.len(), 8, "cancellation must happen before growth");
        assert!(output.bytes.capacity() <= 16);
    }

    #[test]
    fn warm_snapshot_complete_output_cap_fails_closed() {
        let peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let prefix = Prefix::V4(Ipv4Prefix {
            addr: Ipv4Addr::new(198, 51, 100, 0),
            len: 24,
        });
        let peers = [make_peer(peer, 64_501)];
        let routes = [make_route(prefix, peer, peer)];
        let unbounded = encode_warm_snapshot(
            Ipv4Addr::new(10, 0, 0, 1),
            "generation-1",
            &peers,
            &routes,
            &[],
            1_700_000_000,
            &[],
        )
        .unwrap();
        let cap = unbounded.len() - 1;
        let budget = WarmSnapshotBudget::new(
            Instant::now() + Duration::from_mins(1),
            Arc::new(AtomicBool::new(false)),
            cap,
        );

        assert!(matches!(
            encode_warm_snapshot_bounded(
                Ipv4Addr::new(10, 0, 0, 1),
                "generation-1",
                &peers,
                &routes,
                &[],
                1_700_000_000,
                &[],
                &budget,
            ),
            Err(EncodeError::WarmSnapshotBudget(
                WarmSnapshotBudgetError::SizeLimitExceeded { attempted, cap: actual_cap }
            )) if attempted > actual_cap && actual_cap == cap
        ));
    }

    #[test]
    fn cancellable_sort_stops_within_one_bounded_run() {
        let cancelled = Arc::new(AtomicBool::new(false));
        let budget = WarmSnapshotBudget::new(
            Instant::now() + Duration::from_mins(1),
            Arc::clone(&cancelled),
            2 * 1024 * 1024,
        );
        let comparisons = AtomicUsize::new(0);
        let mut values: Vec<_> = (0..100_000usize).rev().collect();
        let result = sort_cancellable_by(&mut values, Some(&budget), |left, right| {
            if comparisons.fetch_add(1, Ordering::Relaxed) == 1_000 {
                cancelled.store(true, Ordering::Release);
            }
            left.cmp(right)
        });

        assert!(matches!(
            result,
            Err(EncodeError::WarmSnapshotBudget(
                WarmSnapshotBudgetError::Cancelled
            ))
        ));
        assert!(
            comparisons.load(Ordering::Relaxed) < 2_000,
            "cancellation must stop before another unbounded sort phase"
        );
    }

    #[test]
    fn cancellation_during_key_materialization_stops_before_sorting() {
        let cancelled = Arc::new(AtomicBool::new(false));
        let budget = WarmSnapshotBudget::new(
            Instant::now() + Duration::from_mins(1),
            Arc::clone(&cancelled),
            2 * 1024 * 1024,
        );
        let materialized = AtomicUsize::new(0);
        let values: Vec<_> = (0..100_000usize).collect();
        let keys = values.iter().enumerate().map(|(index, value)| {
            materialized.fetch_add(1, Ordering::Relaxed);
            if index == 1_000 {
                cancelled.store(true, Ordering::Release);
            }
            value
        });

        assert!(matches!(
            collect_cancellable(keys, Some(&budget)),
            Err(EncodeError::WarmSnapshotBudget(
                WarmSnapshotBudgetError::Cancelled
            ))
        ));
        assert_eq!(materialized.load(Ordering::Relaxed), 1_001);
    }

    #[test]
    fn large_same_prefix_attributes_hit_cap_without_owned_entry_staging() {
        let peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let prefix = Prefix::V4(Ipv4Prefix {
            addr: Ipv4Addr::new(198, 51, 100, 0),
            len: 24,
        });
        let attributes = Arc::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![rustbgpd_wire::AsPathSegment::AsSequence(vec![65001])],
            }),
            PathAttribute::Communities(vec![0x000a_000b; 2_048]),
        ]);
        let routes: Vec<_> = (1..=2_048u32)
            .map(|path_id| {
                let mut route = make_route(prefix, peer, peer);
                route.path_id = path_id;
                route.attributes = Arc::clone(&attributes);
                route
            })
            .collect();
        let budget = WarmSnapshotBudget::new(
            Instant::now() + Duration::from_mins(1),
            Arc::new(AtomicBool::new(false)),
            128 * 1024,
        );

        assert!(matches!(
            encode_warm_snapshot_bounded(
                Ipv4Addr::new(10, 0, 0, 1),
                "generation-large-prefix",
                &[make_peer(peer, 64_501)],
                &routes,
                &[],
                1_700_000_000,
                &[MrtAddPathReceiveProfile {
                    peer,
                    afi: Afi::Ipv4,
                    safi: Safi::Unicast,
                }],
                &budget,
            ),
            Err(EncodeError::WarmSnapshotBudget(
                WarmSnapshotBudgetError::SizeLimitExceeded { cap: 131_072, .. }
            ))
        ));
        assert_eq!(
            Arc::strong_count(&attributes),
            routes.len() + 1,
            "borrowed encoding must retain the shared route attributes"
        );
    }
    #[test]
    fn mrt_header_encoding() {
        let mut buf = Vec::new();
        encode_mrt_header(&mut buf, 1_700_000_000, TABLE_DUMP_V2, PEER_INDEX_TABLE, 42);
        assert_eq!(buf.len(), 12);
        // timestamp
        assert_eq!(
            u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
            1_700_000_000
        );
        // type = 13
        assert_eq!(u16::from_be_bytes([buf[4], buf[5]]), 13);
        // subtype = 1
        assert_eq!(u16::from_be_bytes([buf[6], buf[7]]), 1);
        // length = 42
        assert_eq!(u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]), 42);
    }
    #[test]
    fn peer_index_table_encoding() {
        let peers = vec![
            make_peer(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 65001),
            make_peer(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                65002,
            ),
        ];
        let mut buf = Vec::new();
        encode_peer_index_table(
            &mut buf,
            1_700_000_000,
            Ipv4Addr::new(1, 2, 3, 4),
            "",
            &peers,
        )
        .unwrap();
        // Should have 12-byte header + payload
        assert!(buf.len() > 12);
        // MRT type = 13, subtype = 1
        assert_eq!(u16::from_be_bytes([buf[4], buf[5]]), 13);
        assert_eq!(u16::from_be_bytes([buf[6], buf[7]]), 1);
        // Collector BGP ID at offset 12
        assert_eq!(&buf[12..16], &[1, 2, 3, 4]);
        // View name length = 0
        assert_eq!(u16::from_be_bytes([buf[16], buf[17]]), 0);
        // Peer count = 2
        assert_eq!(u16::from_be_bytes([buf[18], buf[19]]), 2);
        // First peer: type = 0b10 (AS4, IPv4)
        assert_eq!(buf[20], 0b10);
        // Second peer: type = 0b11 (AS4, IPv6)
        // After first peer: 1 (type) + 4 (bgp_id) + 4 (ipv4) + 4 (asn) = 13
        let second_peer_offset = 20 + 13;
        assert_eq!(buf[second_peer_offset], 0b11);
    }
    #[test]
    fn rib_ipv4_unicast_encoding() {
        let entry = RibEntry {
            peer_index: 0,
            originated_time: 1_700_000_000,
            path_id: 0,
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 1)),
            ],
        };
        let prefix = Prefix::V4(Ipv4Prefix {
            addr: Ipv4Addr::new(192, 168, 1, 0),
            len: 24,
        });
        let mut buf = Vec::new();
        encode_rib_entries(&mut buf, 1_700_000_000, 0, &prefix, &[entry]).unwrap();
        assert!(buf.len() > 12);
        // subtype = 2 (RIB_IPV4_UNICAST)
        assert_eq!(u16::from_be_bytes([buf[6], buf[7]]), 2);
        // seq_num at offset 12 = 0
        assert_eq!(u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]), 0);
        // prefix_len at offset 16 = 24
        assert_eq!(buf[16], 24);
        // prefix bytes: 3 bytes for /24
        assert_eq!(&buf[17..20], &[192, 168, 1]);
        // entry_count at offset 20 = 1
        assert_eq!(u16::from_be_bytes([buf[20], buf[21]]), 1);
    }
    #[test]
    fn rib_ipv6_unicast_encoding() {
        let entry = RibEntry {
            peer_index: 1,
            originated_time: 1_700_000_000,
            path_id: 0,
            attributes: vec![PathAttribute::Origin(Origin::Igp)],
        };
        let prefix = Prefix::V6(Ipv6Prefix {
            addr: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            len: 32,
        });
        let mut buf = Vec::new();
        encode_rib_entries(&mut buf, 1_700_000_000, 1, &prefix, &[entry]).unwrap();
        // subtype = 4 (RIB_IPV6_UNICAST)
        assert_eq!(u16::from_be_bytes([buf[6], buf[7]]), 4);
        // prefix_len = 32
        assert_eq!(buf[16], 32);
        // 4 bytes for /32 prefix
        assert_eq!(&buf[17..21], &[0x20, 0x01, 0x0d, 0xb8]);
    }
    #[test]
    fn addpath_subtype_used_when_path_id_nonzero() {
        let entry = RibEntry {
            peer_index: 0,
            originated_time: 1_700_000_000,
            path_id: 42,
            attributes: vec![PathAttribute::Origin(Origin::Igp)],
        };
        let prefix = Prefix::V4(Ipv4Prefix {
            addr: Ipv4Addr::new(10, 0, 0, 0),
            len: 8,
        });
        let mut buf = Vec::new();
        encode_rib_entries(&mut buf, 1_700_000_000, 0, &prefix, &[entry]).unwrap();
        // subtype = 8 (RIB_IPV4_UNICAST_ADDPATH)
        assert_eq!(u16::from_be_bytes([buf[6], buf[7]]), 8);
    }

    #[test]
    fn warm_snapshot_splits_mixed_profiles_and_preserves_zero_addpath_id() {
        let prefix = Prefix::V4(Ipv4Prefix {
            addr: Ipv4Addr::new(198, 51, 100, 0),
            len: 24,
        });
        let add_peer_addr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let plain_peer_addr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        let peers = vec![
            make_peer(add_peer_addr, 64_501),
            make_peer(plain_peer_addr, 64_502),
        ];
        let routes = vec![
            make_route(prefix, add_peer_addr, add_peer_addr),
            make_route(prefix, plain_peer_addr, plain_peer_addr),
        ];
        let snapshot = encode_warm_snapshot(
            Ipv4Addr::new(10, 0, 0, 1),
            "generation-1",
            &peers,
            &routes,
            &[],
            1_700_000_000,
            &[MrtAddPathReceiveProfile {
                peer: add_peer_addr,
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
            }],
        )
        .unwrap();
        let reader = crate::reader::SnapshotReader::new(&snapshot).unwrap();
        assert_eq!(reader.view_name(), "generation-1");
        let entries: Vec<_> = reader.map(Result::unwrap).collect();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|entry| {
            entry.peer.peer_addr == add_peer_addr && entry.add_path && entry.path_id == 0
        }));
        assert!(
            entries
                .iter()
                .any(|entry| entry.peer.peer_addr == plain_peer_addr && !entry.add_path)
        );
    }

    #[test]
    fn warm_snapshot_rejects_link_local_next_hop_before_encoding() {
        let peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let prefix = Prefix::V6(Ipv6Prefix {
            addr: "2001:db8::".parse().unwrap(),
            len: 64,
        });
        let route = make_route(prefix, peer, "fe80::1".parse().unwrap());
        assert!(matches!(
            encode_warm_snapshot(
                Ipv4Addr::new(10, 0, 0, 1),
                "generation-1",
                &[make_peer(peer, 64_501)],
                &[route],
                &[],
                1_700_000_000,
                &[],
            ),
            Err(EncodeError::UnsupportedWarmRouteProfile { .. })
        ));
    }
    #[test]
    fn synthesize_ipv4_next_hop() {
        let route = make_route(
            Prefix::V4(Ipv4Prefix {
                addr: Ipv4Addr::new(10, 0, 0, 0),
                len: 8,
            }),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        );
        let attrs = synthesize_attributes(&route);
        let has_nh = attrs.iter().any(|a| matches!(a, PathAttribute::NextHop(_)));
        assert!(has_nh, "IPv4 route should have synthesized NextHop");
    }
    #[test]
    fn synthesize_ipv6_mp_reach() {
        let route = make_route(
            Prefix::V6(Ipv6Prefix {
                addr: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
                len: 32,
            }),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        );
        let attrs = synthesize_attributes(&route);
        let has_mp = attrs
            .iter()
            .any(|a| matches!(a, PathAttribute::MpReachNlri(_)));
        assert!(has_mp, "IPv6 route should have synthesized MpReachNlri");
    }
    #[test]
    fn synthesize_ipv4_mp_reach_for_ipv6_next_hop() {
        let route = make_route(
            Prefix::V4(Ipv4Prefix {
                addr: Ipv4Addr::new(203, 0, 113, 0),
                len: 24,
            }),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        );
        let attrs = synthesize_attributes(&route);
        assert!(
            attrs
                .iter()
                .any(|a| matches!(a, PathAttribute::MpReachNlri(_))),
            "RFC 8950 IPv4 route with IPv6 NH should synthesize MpReachNlri"
        );
        assert!(
            !attrs.iter().any(|a| matches!(a, PathAttribute::NextHop(_))),
            "RFC 8950 IPv4 route with IPv6 NH must not synthesize IPv4 NextHop"
        );
    }
    #[test]
    fn full_snapshot_encoding() {
        let peer = make_peer(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 65001);
        let route = make_route(
            Prefix::V4(Ipv4Prefix {
                addr: Ipv4Addr::new(192, 168, 0, 0),
                len: 16,
            }),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        );
        let data = encode_snapshot(
            Ipv4Addr::new(1, 2, 3, 4),
            &[peer],
            &[route],
            &[],
            1_700_000_000,
        )
        .unwrap();
        // Should have at least two MRT records (peer index + one RIB entry)
        assert!(data.len() > 24);
        // First record: `PEER_INDEX_TABLE`
        assert_eq!(u16::from_be_bytes([data[4], data[5]]), 13);
        assert_eq!(u16::from_be_bytes([data[6], data[7]]), 1);
        // Find second record
        let first_len = u32::from_be_bytes([data[8], data[9], data[10], data[11]]) as usize;
        let second_offset = 12 + first_len;
        // Second record: RIB_IPV4_UNICAST
        assert_eq!(
            u16::from_be_bytes([data[second_offset + 4], data[second_offset + 5]]),
            13
        );
        assert_eq!(
            u16::from_be_bytes([data[second_offset + 6], data[second_offset + 7]]),
            2
        );
    }

    /// Load-bearing snapshot proof: deleting AGGREGATOR encoding, decoding it
    /// as an untyped compatibility attribute, or clearing Partial makes the
    /// exact typed round-trip assertion fail.
    #[test]
    fn snapshot_round_trip_preserves_typed_aggregator() {
        let peer = make_peer(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 65001);
        let mut route = make_route(
            Prefix::V4(Ipv4Prefix {
                addr: Ipv4Addr::new(192, 168, 0, 0),
                len: 16,
            }),
            peer.peer_addr,
            peer.peer_addr,
        );
        let aggregator = Aggregator {
            asn: 4_200_000_001,
            router_id: Ipv4Addr::new(192, 0, 2, 9),
            partial: true,
        };
        let mut attrs = route.attributes.as_ref().clone();
        attrs.push(PathAttribute::Aggregator(aggregator));
        route.attributes = Arc::new(attrs);

        let snapshot = encode_snapshot(
            Ipv4Addr::new(1, 2, 3, 4),
            &[peer],
            &[route],
            &[],
            1_700_000_000,
        )
        .unwrap();
        let entries: Vec<_> = crate::reader::SnapshotReader::new(&snapshot)
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(entries.len(), 1);
        assert!(
            entries[0]
                .attributes
                .contains(&PathAttribute::Aggregator(aggregator)),
            "MRT snapshot must preserve canonical ASN, router ID, and Partial"
        );
    }
    #[test]
    fn empty_snapshot_encoding() {
        let data =
            encode_snapshot(Ipv4Addr::new(1, 2, 3, 4), &[], &[], &[], 1_700_000_000).unwrap();
        // Should have exactly one MRT record (peer index table with 0 peers)
        assert!(data.len() > 12);
        assert_eq!(u16::from_be_bytes([data[6], data[7]]), 1);
    }
    fn make_evpn_macip(peer: IpAddr, next_hop: IpAddr) -> EvpnRibRoute {
        use rustbgpd_wire::{
            EthernetSegmentIdentifier, EthernetTagId, EvpnMacIp, EvpnRoute, MacAddress, MplsLabel,
            RouteDistinguisher,
        };
        let rd = RouteDistinguisher([0x00, 0x00, 0xFD, 0xE8, 0x00, 0x00, 0x00, 0x64]);
        let mac = MacAddress([0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01]);
        let ip = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)));
        let route = EvpnRoute::MacIp(EvpnMacIp {
            rd,
            esi: EthernetSegmentIdentifier::ZERO,
            ethernet_tag: EthernetTagId(0),
            mac,
            ip,
            label1: MplsLabel::new(100),
            label2: None,
        });
        EvpnRibRoute {
            route,
            next_hop,
            link_local_next_hop: None,
            peer,
            attributes: Arc::new(vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![rustbgpd_wire::AsPathSegment::AsSequence(vec![65001])],
                }),
                PathAttribute::LocalPref(100),
            ]),
            received_at: Instant::now(),
            origin_type: RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
            is_stale: false,
            is_llgr_stale: false,
        }
    }
    fn make_evpn_ipprefix(peer: IpAddr, next_hop: IpAddr) -> EvpnRibRoute {
        use rustbgpd_wire::{
            EthernetSegmentIdentifier, EthernetTagId, EvpnIpPrefixRoute, EvpnIpPrefixValue,
            EvpnRoute, MplsLabel, RouteDistinguisher,
        };
        let rd = RouteDistinguisher([0x00, 0x00, 0xFD, 0xE8, 0x00, 0x00, 0x00, 0x64]);
        let prefix = EvpnIpPrefixValue::V4(Ipv4Prefix {
            addr: Ipv4Addr::new(192, 0, 2, 0),
            len: 24,
        });
        let route = EvpnRoute::IpPrefix(EvpnIpPrefixRoute {
            rd,
            esi: EthernetSegmentIdentifier::ZERO,
            ethernet_tag: EthernetTagId(0),
            prefix,
            gateway: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            label: MplsLabel::new(200),
        });
        EvpnRibRoute {
            route,
            next_hop,
            link_local_next_hop: None,
            peer,
            attributes: Arc::new(vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![rustbgpd_wire::AsPathSegment::AsSequence(vec![65001])],
                }),
                PathAttribute::LocalPref(100),
            ]),
            received_at: Instant::now(),
            origin_type: RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
            is_stale: false,
            is_llgr_stale: false,
        }
    }
    /// Locate an `RIB_GENERIC` (subtype 6) record in `data` after the
    /// `PEER_INDEX_TABLE`. Returns the offset of its MRT header.
    fn find_rib_generic(data: &[u8]) -> Option<usize> {
        let mut offset = 0;
        while offset + 12 <= data.len() {
            let mrt_type = u16::from_be_bytes([data[offset + 4], data[offset + 5]]);
            let subtype = u16::from_be_bytes([data[offset + 6], data[offset + 7]]);
            let length = u32::from_be_bytes([
                data[offset + 8],
                data[offset + 9],
                data[offset + 10],
                data[offset + 11],
            ]) as usize;
            if mrt_type == TABLE_DUMP_V2 && subtype == RIB_GENERIC {
                return Some(offset);
            }
            offset += 12 + length;
        }
        None
    }
    /// EVPN Type 2 (MAC/IP Advertisement) → MRT `RIB_GENERIC`. Asserts the
    /// record carries AFI 25 / SAFI 70 and the encoded EVPN NLRI bytes
    /// match `encode_evpn_nlri` for the same route.
    #[test]
    fn evpn_type2_rib_generic_encoding() {
        let peer_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let peer = make_peer(peer_addr, 65002);
        let route = make_evpn_macip(peer_addr, peer_addr);
        let data = encode_snapshot(
            Ipv4Addr::new(1, 2, 3, 4),
            &[peer],
            &[],
            std::slice::from_ref(&route),
            1_700_000_000,
        )
        .unwrap();
        let rib_offset =
            find_rib_generic(&data).expect("RIB_GENERIC record must be present for EVPN route");
        // Payload starts after 12-byte MRT header.
        let payload = &data[rib_offset + 12..];
        // Sequence Number (4 bytes), then AFI (2), SAFI (1).
        let afi = u16::from_be_bytes([payload[4], payload[5]]);
        let safi = payload[6];
        assert_eq!(afi, 25, "RIB_GENERIC AFI must be 25 (L2VPN) for EVPN");
        assert_eq!(safi, 70, "RIB_GENERIC SAFI must be 70 (EVPN)");
        // NLRI bytes follow. Compare against an independent encode of the
        // same EvpnRoute — proves the record header carries the canonical
        // EVPN NLRI TLV (route_type + length + body).
        let mut expected_nlri = Vec::new();
        encode_evpn_nlri(std::slice::from_ref(&route.route), &mut expected_nlri);
        let nlri_start = 7; // after seq(4) + afi(2) + safi(1)
        let nlri_end = nlri_start + expected_nlri.len();
        assert_eq!(
            &payload[nlri_start..nlri_end],
            expected_nlri.as_slice(),
            "encoded NLRI bytes must match encode_evpn_nlri output"
        );
        // Entry Count (2 bytes) immediately after NLRI = 1.
        let entry_count = u16::from_be_bytes([payload[nlri_end], payload[nlri_end + 1]]);
        assert_eq!(
            entry_count, 1,
            "EVPN does not use Add-Path; entry count must be 1"
        );
    }
    /// EVPN Type 5 (IP Prefix) → MRT `RIB_GENERIC`. Same shape as the Type 2
    /// test but exercises the longer IP-Prefix NLRI encoding.
    #[test]
    fn evpn_type5_rib_generic_encoding() {
        let peer_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let peer = make_peer(peer_addr, 65002);
        let route = make_evpn_ipprefix(peer_addr, peer_addr);
        let data = encode_snapshot(
            Ipv4Addr::new(1, 2, 3, 4),
            &[peer],
            &[],
            std::slice::from_ref(&route),
            1_700_000_000,
        )
        .unwrap();
        let rib_offset =
            find_rib_generic(&data).expect("RIB_GENERIC record must be present for EVPN Type 5");
        let payload = &data[rib_offset + 12..];
        assert_eq!(u16::from_be_bytes([payload[4], payload[5]]), 25);
        assert_eq!(payload[6], 70);
        let mut expected_nlri = Vec::new();
        encode_evpn_nlri(std::slice::from_ref(&route.route), &mut expected_nlri);
        assert_eq!(
            &payload[7..7 + expected_nlri.len()],
            expected_nlri.as_slice()
        );
    }

    #[test]
    fn large_evpn_inventory_hits_cap_without_owned_encoded_sort_keys() {
        use rustbgpd_wire::{EvpnRoute, MacAddress};

        let peer_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let mut routes = Vec::new();
        routes.try_reserve_exact(4_096).unwrap();
        for suffix in 0..4_096u16 {
            let mut route = make_evpn_macip(peer_addr, peer_addr);
            let EvpnRoute::MacIp(mac_ip) = &mut route.route else {
                unreachable!("helper always returns MAC/IP routes")
            };
            let [high, low] = suffix.to_be_bytes();
            mac_ip.mac = MacAddress([0x02, 0, 0, 0, high, low]);
            routes.push(route);
        }
        let budget = WarmSnapshotBudget::new(
            Instant::now() + Duration::from_mins(1),
            Arc::new(AtomicBool::new(false)),
            64 * 1024,
        );

        assert!(matches!(
            encode_warm_snapshot_bounded(
                Ipv4Addr::new(1, 2, 3, 4),
                "generation-large-evpn",
                &[make_peer(peer_addr, 65_002)],
                &[],
                &routes,
                1_700_000_000,
                &[],
                &budget,
            ),
            Err(EncodeError::WarmSnapshotBudget(
                WarmSnapshotBudgetError::SizeLimitExceeded { cap: 65_536, .. }
            ))
        ));
    }
    /// Walk a serialized BGP attribute block and return the value bytes
    /// of the first attribute matching `type_code`. Used by the
    /// MRT-reduced-form regression tests below.
    fn find_attribute_value(attrs: &[u8], type_code: u8) -> Option<&[u8]> {
        let mut offset = 0;
        while offset + 2 <= attrs.len() {
            let flags = attrs[offset];
            let tc = attrs[offset + 1];
            let extended = (flags & 0x10) != 0;
            let (len, header_len) = if extended {
                if offset + 4 > attrs.len() {
                    return None;
                }
                (
                    u16::from_be_bytes([attrs[offset + 2], attrs[offset + 3]]) as usize,
                    4,
                )
            } else {
                if offset + 3 > attrs.len() {
                    return None;
                }
                (attrs[offset + 2] as usize, 3)
            };
            let value_start = offset + header_len;
            let value_end = value_start + len;
            if value_end > attrs.len() {
                return None;
            }
            if tc == type_code {
                return Some(&attrs[value_start..value_end]);
            }
            offset = value_end;
        }
        None
    }
    /// Locate the encoded `MP_REACH_NLRI` (type 14) value bytes inside
    /// the single RIB entry of an EVPN `RIB_GENERIC` record.
    fn evpn_rib_generic_mp_reach_value(data: &[u8]) -> Vec<u8> {
        let rib_offset = find_rib_generic(data).expect("RIB_GENERIC must be present");
        let payload = &data[rib_offset + 12..];
        // Walk: seq(4) + afi(2) + safi(1) + nlri(var) + entry_count(2) + entry.
        let nlri_start = 7;
        // EVPN NLRI = route_type(1) + length(1) + body(length) — peek the
        // length byte to skip past it without re-decoding the whole thing.
        let nlri_body_len = payload[nlri_start + 1] as usize;
        let nlri_end = nlri_start + 2 + nlri_body_len;
        let entry_start = nlri_end + 2; // skip entry_count
        // Entry header: peer_index(2) + originated_time(4) + attr_len(2).
        let attr_len_offset = entry_start + 6;
        let attr_len =
            u16::from_be_bytes([payload[attr_len_offset], payload[attr_len_offset + 1]]) as usize;
        let attrs_start = attr_len_offset + 2;
        let attrs = &payload[attrs_start..attrs_start + attr_len];
        find_attribute_value(attrs, 14)
            .expect("MP_REACH_NLRI must be present in EVPN RIB entry")
            .to_vec()
    }
    /// RFC 6396 §4.3.4: `MP_REACH_NLRI` inside an MRT RIB entry must
    /// carry only NH-Len + NH bytes. AFI/SAFI/Reserved/NLRI must be
    /// omitted because the RIB entry header already encodes them.
    /// Regression for the EVPN export path.
    #[test]
    fn evpn_rib_entry_mp_reach_is_mrt_reduced_form() {
        let peer_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let next_hop = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99));
        let peer = make_peer(peer_addr, 65002);
        let route = make_evpn_macip(peer_addr, next_hop);
        let data = encode_snapshot(
            Ipv4Addr::new(1, 2, 3, 4),
            &[peer],
            &[],
            std::slice::from_ref(&route),
            1_700_000_000,
        )
        .unwrap();
        let mp_value = evpn_rib_generic_mp_reach_value(&data);
        // Reduced form: 1-byte NH-Len + NH octets, nothing else.
        assert_eq!(
            mp_value.len(),
            5,
            "EVPN MP_REACH must be 5 bytes (NH-Len=4 + 4-byte IPv4 NH); got {} bytes",
            mp_value.len()
        );
        assert_eq!(mp_value[0], 4, "NH-Len byte must equal 4 for IPv4 NH");
        assert_eq!(
            &mp_value[1..5],
            &[10, 0, 0, 99],
            "NH bytes must equal the route's next-hop"
        );
    }
    /// Same regression for IPv6 unicast — `MP_REACH` in MRT RIB entries
    /// must be reduced form, not the BGP UPDATE form. Pre-existing
    /// codepath but never byte-level asserted before.
    #[test]
    fn ipv6_unicast_rib_entry_mp_reach_is_mrt_reduced_form() {
        let peer_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let peer = make_peer(peer_addr, 65001);
        let nh = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let route = make_route(
            Prefix::V6(Ipv6Prefix {
                addr: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
                len: 32,
            }),
            peer_addr,
            IpAddr::V6(nh),
        );
        let data = encode_snapshot(
            Ipv4Addr::new(1, 2, 3, 4),
            &[peer],
            &[route],
            &[],
            1_700_000_000,
        )
        .unwrap();
        // Walk past PEER_INDEX_TABLE to the RIB_IPV6_UNICAST record.
        let first_len = u32::from_be_bytes([data[8], data[9], data[10], data[11]]) as usize;
        let rib_offset = 12 + first_len;
        let payload = &data[rib_offset + 12..];
        // Payload: seq(4) + prefix_len(1) + prefix_bytes(ceil(32/8)=4) +
        // entry_count(2) + entry.
        let entry_start = 4 + 1 + 4 + 2;
        let attr_len_offset = entry_start + 6;
        let attr_len =
            u16::from_be_bytes([payload[attr_len_offset], payload[attr_len_offset + 1]]) as usize;
        let attrs = &payload[attr_len_offset + 2..attr_len_offset + 2 + attr_len];
        let mp_value = find_attribute_value(attrs, 14).expect("MP_REACH must be present");
        assert_eq!(
            mp_value.len(),
            17,
            "IPv6 MP_REACH must be 17 bytes (NH-Len=16 + 16-byte IPv6 NH); got {}",
            mp_value.len()
        );
        assert_eq!(mp_value[0], 16, "NH-Len must equal 16 for IPv6 NH");
        assert_eq!(
            &mp_value[1..17],
            &nh.octets(),
            "NH bytes must equal the route's IPv6 next-hop"
        );
    }
    /// RFC 4760 §3 / RFC 2545: IPv6 next-hop can carry global +
    /// link-local (32 bytes total). When `Route.link_local_next_hop`
    /// is `Some`, the MRT-reduced `MP_REACH_NLRI` value must be 33
    /// bytes — NH-Len=32, then the 16-byte global, then the 16-byte
    /// link-local. Regression for the pre-existing gap where this
    /// data was discarded.
    #[test]
    fn ipv6_unicast_32byte_next_hop_emits_33_byte_attribute_value() {
        let peer_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let peer = make_peer(peer_addr, 65001);
        let global = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let mut route = make_route(
            Prefix::V6(Ipv6Prefix {
                addr: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
                len: 32,
            }),
            peer_addr,
            IpAddr::V6(global),
        );
        route.link_local_next_hop = Some(link_local);
        let data = encode_snapshot(
            Ipv4Addr::new(1, 2, 3, 4),
            &[peer],
            &[route],
            &[],
            1_700_000_000,
        )
        .unwrap();
        let first_len = u32::from_be_bytes([data[8], data[9], data[10], data[11]]) as usize;
        let rib_offset = 12 + first_len;
        let payload = &data[rib_offset + 12..];
        let entry_start = 4 + 1 + 4 + 2;
        let attr_len_offset = entry_start + 6;
        let attr_len =
            u16::from_be_bytes([payload[attr_len_offset], payload[attr_len_offset + 1]]) as usize;
        let attrs = &payload[attr_len_offset + 2..attr_len_offset + 2 + attr_len];
        let mp_value = find_attribute_value(attrs, 14).expect("MP_REACH must be present");
        assert_eq!(
            mp_value.len(),
            33,
            "32-byte NH must produce a 33-byte MP_REACH value (NH-Len=32 + 16 + 16); got {}",
            mp_value.len()
        );
        assert_eq!(mp_value[0], 32, "NH-Len must equal 32 for global+LL form");
        assert_eq!(
            &mp_value[1..17],
            &global.octets(),
            "global NH bytes mismatch"
        );
        assert_eq!(
            &mp_value[17..33],
            &link_local.octets(),
            "link-local NH bytes mismatch"
        );
    }
    /// RFC 8950: IPv4 NLRI carried in an `MP_REACH_NLRI` with an IPv6
    /// next-hop. The MRT encoding still uses the reduced form — the
    /// `RIB_IPV4_UNICAST` record header carries the prefix, the
    /// attribute carries only NH-Len + NH.
    #[test]
    fn rfc8950_ipv4_with_ipv6_nh_mp_reach_is_mrt_reduced_form() {
        let peer_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let peer = make_peer(peer_addr, 65001);
        let nh = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 99);
        let route = make_route(
            Prefix::V4(Ipv4Prefix {
                addr: Ipv4Addr::new(203, 0, 113, 0),
                len: 24,
            }),
            peer_addr,
            IpAddr::V6(nh),
        );
        let data = encode_snapshot(
            Ipv4Addr::new(1, 2, 3, 4),
            &[peer],
            &[route],
            &[],
            1_700_000_000,
        )
        .unwrap();
        let first_len = u32::from_be_bytes([data[8], data[9], data[10], data[11]]) as usize;
        let rib_offset = 12 + first_len;
        let payload = &data[rib_offset + 12..];
        // RIB_IPV4_UNICAST payload: seq(4) + prefix_len(1) +
        // prefix_bytes(ceil(24/8)=3) + entry_count(2) + entry.
        let entry_start = 4 + 1 + 3 + 2;
        let attr_len_offset = entry_start + 6;
        let attr_len =
            u16::from_be_bytes([payload[attr_len_offset], payload[attr_len_offset + 1]]) as usize;
        let attrs = &payload[attr_len_offset + 2..attr_len_offset + 2 + attr_len];
        let mp_value = find_attribute_value(attrs, 14).expect("MP_REACH must be present");
        assert_eq!(
            mp_value.len(),
            17,
            "RFC 8950 MP_REACH must be 17 bytes (NH-Len=16 + 16-byte IPv6 NH); got {}",
            mp_value.len()
        );
        assert_eq!(mp_value[0], 16);
        assert_eq!(&mp_value[1..17], &nh.octets());
    }
    #[test]
    fn snapshot_includes_routes_for_missing_peer_metadata() {
        let route = make_route(
            Prefix::V4(Ipv4Prefix {
                addr: Ipv4Addr::new(198, 51, 100, 0),
                len: 24,
            }),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
        );
        let data =
            encode_snapshot(Ipv4Addr::new(1, 2, 3, 4), &[], &[route], &[], 1_700_000_000).unwrap();
        // Must include a peer index table plus at least one RIB record.
        let first_len = u32::from_be_bytes([data[8], data[9], data[10], data[11]]) as usize;
        let second_offset = 12 + first_len;
        assert!(data.len() > second_offset + 12);
        assert_eq!(
            u16::from_be_bytes([data[second_offset + 6], data[second_offset + 7]]),
            RIB_IPV4_UNICAST
        );
    }
}
