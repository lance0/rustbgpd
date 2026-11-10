//! Sizes each outbound UPDATE of one attribute group from encoded bytes.
//!
//! Every UPDATE of a group repeats the same attributes, so its length is a
//! fixed overhead plus the bytes of the entries it carries. Unicast entry
//! sizes are arithmetic. Other families are measured: a built message is
//! taken apart into overhead and entry bytes, and the next chunk assumes the
//! same bytes per entry. The caller still checks the exact encoded length of
//! every message before it sends it.

use rustbgpd_wire::constants::{attr_flags, attr_type};
use rustbgpd_wire::{Ipv4NlriEntry, NlriEntry, Prefix, UpdateMessage};

/// Header plus the two length fields: the least an UPDATE costs.
const MIN_UPDATE_LEN: usize = 23;
/// Largest group without entry sizes that is built whole before anything is
/// measured. A longer one first builds a single entry, which costs one
/// attribute encode and tells how many entries fill a message.
const UNSIZED_WHOLE_TRY: usize = 64;
/// Chunk length when a group could not be measured at all.
const UNMEASURED_CHUNK: usize = 1000;
/// Rejected builds of one unsized group whose measured bytes per entry are
/// taken as they are. Each later one at least doubles the group's assumed
/// bytes per entry, so the number of rejections stays logarithmic in the
/// message limit however the entry sizes are arranged.
const EXACT_MISSES: u32 = 4;

fn prefix_entry_len(bits: u8, add_path: bool) -> usize {
    1 + usize::from(bits).div_ceil(8) + if add_path { 4 } else { 0 }
}

/// Wire size of one IPv4 body NLRI or withdrawn-route entry.
pub(super) fn ipv4_entry_len(add_path: bool) -> impl Fn(&Ipv4NlriEntry) -> usize {
    move |entry| prefix_entry_len(entry.prefix.len, add_path)
}

/// Wire size of one unicast `MP_REACH_NLRI` or `MP_UNREACH_NLRI` entry.
pub(super) fn entry_len(add_path: bool) -> impl Fn(&NlriEntry) -> usize {
    move |entry| prefix_len(entry.prefix, add_path)
}

/// Wire size of one unicast prefix.
pub(super) fn prefix_len(prefix: Prefix, add_path: bool) -> usize {
    let bits = match prefix {
        Prefix::V4(prefix) => prefix.len,
        Prefix::V6(prefix) => prefix.len,
    };
    prefix_entry_len(bits, add_path)
}

/// Whether the message's entries sit in a leading `MP_REACH_NLRI` or
/// `MP_UNREACH_NLRI` that takes the three-byte attribute header.
fn short_mp_header(message: &UpdateMessage) -> bool {
    message.nlri.is_empty()
        && message.withdrawn_routes.is_empty()
        && message
            .path_attributes
            .first()
            .is_some_and(|flags| flags & attr_flags::EXTENDED_LENGTH == 0)
}

/// The message's bytes outside its entries, and its entry bytes. Entries sit
/// in the body or in a leading `MP_REACH_NLRI` / `MP_UNREACH_NLRI`; the
/// overhead of the latter is counted with the four-byte attribute header a
/// value over 255 bytes needs, so it never undercounts a longer chunk. The
/// cost is that a chunk whose whole MP value is at most 255 bytes is sized
/// one byte short, which can leave it one entry short of full.
///
/// Body entries are counted from the message's own buffers, so the UPDATE's
/// withdrawn-routes and total-attribute length fields are never read. MP
/// entries are read from the attribute's own length field, which the
/// encoder truncates to 16 bits. A value over 65,535 bytes therefore reads
/// 65,536 short and leaves at least that many bytes after it, more than
/// the other attributes of any sendable message; such a build is refused.
fn split(message: &UpdateMessage) -> Option<(usize, usize)> {
    let total = message.encoded_len();
    let body = message.nlri.len() + message.withdrawn_routes.len();
    if body != 0 {
        return Some((total - body, body));
    }
    let attrs = &message.path_attributes;
    let extended = attrs.first()? & attr_flags::EXTENDED_LENGTH != 0;
    let (header, value_len) = if extended {
        (
            4,
            usize::from(u16::from_be_bytes([*attrs.get(2)?, *attrs.get(3)?])),
        )
    } else {
        (3, usize::from(*attrs.get(2)?))
    };
    let fixed = match *attrs.get(1)? {
        // AFI, SAFI, next-hop length, next hop, reserved octet.
        attr_type::MP_REACH_NLRI => 5 + usize::from(*attrs.get(header + 3)?),
        // AFI, SAFI.
        attr_type::MP_UNREACH_NLRI => 3,
        _ => return None,
    };
    let entries = value_len.checked_sub(fixed)?;
    if attrs.len().checked_sub(header + value_len)? > usize::from(u16::MAX) {
        return None;
    }
    Some((total - entries + usize::from(!extended), entries))
}

/// Chooses the length of each contiguous chunk of one group.
///
/// With entry sizes (unicast), a group that fits one message is built once,
/// and a group that has to be split costs one build that is not sent: a
/// single entry measured up front, or the whole group when only its
/// attributes pushed it over.
///
/// Without them, a group of more than [`UNSIZED_WHOLE_TRY`] entries always
/// builds one entry first, and each chunk assumes the bytes per entry of
/// the last measured build. If the entries are all one size, that first
/// build is the only one not sent and every message but the last is full.
/// If they vary, a chunk that meets larger entries is rejected and raises
/// the assumption, which from then on never falls: messages after it can
/// be short of full, and one group costs at most
/// `1 + EXACT_MISSES + ceil(log2(max_len))` builds that are not sent (17 at
/// 4,096 bytes, 21 at 65,535) while its builds can be measured. A build
/// that fails or cannot be measured halves the chunk instead.
pub(super) struct ChunkSizer {
    max_len: usize,
    /// Bytes of one UPDATE of this group outside its entries.
    overhead: Option<usize>,
    /// Entry bytes and entry count standing for the bytes per entry the next
    /// unsized chunk assumes.
    worst: (usize, usize),
    /// Upper bound after a rejected build, until one is accepted.
    cap: usize,
    /// Measured rejections in this group.
    misses: u32,
    /// Whether the last chunk length came from exact entry sizes.
    sized: bool,
    probing: bool,
    probed: bool,
}

impl ChunkSizer {
    pub(super) fn new(max_len: usize) -> Self {
        Self {
            max_len,
            overhead: None,
            worst: (0, 1),
            cap: usize::MAX,
            misses: 0,
            sized: false,
            probing: false,
            probed: false,
        }
    }

    /// Entries the next build takes from the front of `rest`: at least one,
    /// never more than remain. `size` is the exact wire size of an entry
    /// where that is arithmetic.
    pub(super) fn next<E>(&mut self, rest: &[E], size: Option<&dyn Fn(&E) -> usize>) -> usize {
        let within = |size: &dyn Fn(&E) -> usize, room: usize| {
            let mut used = 0;
            rest.iter()
                .take_while(|entry| {
                    used += size(entry);
                    used <= room
                })
                .count()
        };
        self.sized = size.is_some();
        let take = if let Some(overhead) = self.overhead {
            let room = self.max_len.saturating_sub(overhead);
            match size {
                Some(size) => within(size, room),
                None => room * self.worst.1 / self.worst.0.max(1),
            }
        } else {
            let whole = match size {
                Some(size) => {
                    within(size, self.max_len.saturating_sub(MIN_UPDATE_LEN)) == rest.len()
                }
                None => rest.len() <= UNSIZED_WHOLE_TRY,
            };
            if whole {
                rest.len()
            } else if self.probed {
                UNMEASURED_CHUNK
            } else {
                self.probing = true;
                self.probed = true;
                return 1;
            }
        };
        take.min(self.cap).clamp(1, rest.len())
    }

    /// Whether the build just made was the single-entry measurement, which
    /// is not sent. `message` is `None` when that build failed. A single
    /// entry that cannot be built, or is over the limit alone, is not a
    /// measurement: the caller goes on to treat it as the unsendable entry
    /// it is.
    pub(super) fn measured_only(&mut self, message: Option<&UpdateMessage>) -> bool {
        if !std::mem::take(&mut self.probing) {
            return false;
        }
        #[cfg(test)]
        tally(1);
        message.is_some_and(|message| {
            message.encoded_len() <= self.max_len && self.measure(message, 1)
        })
    }

    /// A build of `tried` entries was too long or failed: the next is shorter.
    pub(super) fn rejected(&mut self, tried: usize, message: Option<&UpdateMessage>) {
        let predicted = self.sized && self.overhead.is_some();
        let before = self.worst;
        let measured = message.is_some_and(|message| self.measure(message, tried));
        // A measured miss re-sizes the chunk: with exact sizes from the
        // overhead it revealed, without them from the raised bytes per
        // entry. A build that failed, could not be measured, or missed an
        // exact prediction halves instead.
        self.cap = if measured && !predicted {
            tried - 1
        } else {
            tried / 2
        }
        .max(1);
        if measured && !self.sized {
            self.misses += 1;
            if self.misses > EXACT_MISSES && self.worst.0 * before.1 < 2 * before.0 * self.worst.1 {
                self.worst = (2 * before.0, before.1);
            }
        }
        #[cfg(test)]
        tally(tried);
    }

    /// A build of `entries` entries fits and is being sent.
    pub(super) fn accepted(&mut self, message: &UpdateMessage, entries: usize) {
        self.measure(message, entries);
        self.cap = usize::MAX;
        #[cfg(test)]
        tally(entries);
    }

    fn measure(&mut self, message: &UpdateMessage, entries: usize) -> bool {
        let entry_bytes = if let Some(overhead) = self.overhead {
            // The group's overhead does not change, so the entries are the
            // rest of the message, whatever its length fields could hold.
            let short = usize::from(short_mp_header(message));
            (message.encoded_len() + short).saturating_sub(overhead)
        } else {
            let Some((overhead, entry_bytes)) = split(message) else {
                return false;
            };
            self.overhead = Some(overhead);
            entry_bytes
        };
        // Until a build of this group is rejected the assumption follows
        // the last measurement, down as well as up, so a group whose entries
        // get smaller fills its later messages. After that it only rises.
        if self.misses == 0 || entry_bytes * self.worst.1 > self.worst.0 * entries {
            self.worst = (entry_bytes, entries);
        }
        true
    }
}

#[cfg(test)]
thread_local! {
    /// Chunk builds and entries built on this thread, for packing tests.
    pub(super) static BUILT: std::cell::Cell<(usize, usize)> = const { std::cell::Cell::new((0, 0)) };
}

#[cfg(test)]
fn tally(entries: usize) {
    BUILT.with(|built| {
        let (builds, built_entries) = built.get();
        built.set((builds + 1, built_entries + entries));
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustbgpd_wire::{
        Afi, Ipv4UnicastMode, Ipv6Prefix, MpReachNlri, Origin, PathAttribute, Safi,
    };
    use std::net::{IpAddr, Ipv6Addr};

    fn entries(count: u32) -> Vec<NlriEntry> {
        (0..count)
            .map(|i| NlriEntry {
                path_id: 0,
                prefix: Prefix::V6(Ipv6Prefix::new(Ipv6Addr::from(u128::from(i) << 80), 48)),
            })
            .collect()
    }

    fn message(first: PathAttribute) -> UpdateMessage {
        UpdateMessage::try_build(
            &[],
            &[],
            &[first, PathAttribute::Origin(Origin::Igp)],
            true,
            false,
            Ipv4UnicastMode::Body,
        )
        .unwrap()
    }

    /// A message is taken apart into the same overhead whether its
    /// `MP_REACH_NLRI` takes the three-byte or the four-byte attribute
    /// header, and into exactly its entries' bytes.
    #[test]
    fn overhead_is_the_same_on_both_sides_of_the_extended_length_header() {
        let reach = |count| {
            message(PathAttribute::MpReachNlri(Box::new(MpReachNlri {
                afi: Afi::Ipv6,
                safi: Safi::Unicast,
                next_hop: IpAddr::V6(Ipv6Addr::LOCALHOST),
                link_local_next_hop: None,
                announced: entries(count),
                flowspec_announced: vec![],
                evpn_announced: vec![],
                bgpls_announced: vec![],
                labeled_announced: vec![],
                vpn_announced: vec![],
                rtc_announced: vec![],
                vpn_flowspec_announced: vec![],
            })))
        };
        let (short, long) = (reach(1), reach(100));
        assert_eq!(short.path_attributes[0] & attr_flags::EXTENDED_LENGTH, 0);
        assert_ne!(long.path_attributes[0] & attr_flags::EXTENDED_LENGTH, 0);
        let (overhead, entry_bytes) = split(&long).unwrap();
        assert_eq!(entry_bytes, 100 * 7);
        assert_eq!(overhead + entry_bytes, long.encoded_len());
        assert_eq!(split(&short), Some((overhead, 7)));

        // 10,000 entries make a 70 KB attribute whose 16-bit length field
        // has wrapped: it is not measured from that field. A sizer that
        // already knows the group's overhead takes the entries as the rest
        // of the message.
        let wrapped = reach(10_000);
        assert!(wrapped.encoded_len() > 70_000);
        assert_eq!(split(&wrapped), None);
        let mut sizer = ChunkSizer::new(65_535);
        sizer.rejected(10_000, Some(&wrapped));
        assert_eq!(
            sizer.overhead, None,
            "nothing learned from a wrapped length"
        );
        sizer.accepted(&long, 100);
        sizer.rejected(10_000, Some(&wrapped));
        assert_eq!(sizer.worst, (70_000, 10_000));
        assert_eq!(sizer.next(&[(); 20_000], None), (65_535 - overhead) / 7);
        // Anything else leading the attributes is not measured.
        assert_eq!(split(&message(PathAttribute::Med(1))), None);
    }
}
