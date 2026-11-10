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

/// The message's bytes outside its entries, and its entry bytes. Entries sit
/// in the body or in a leading `MP_REACH_NLRI` / `MP_UNREACH_NLRI`; the
/// overhead of the latter is counted with the four-byte attribute header a
/// value over 255 bytes needs, so it never undercounts a longer chunk.
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
    Some((total - entries + usize::from(!extended), entries))
}

/// Chooses the length of each contiguous chunk of one group.
///
/// A group that fits one message is built once. A group that has to be split
/// costs at most one build that is not sent: a single entry measured up
/// front, or the whole group when only its attributes pushed it over.
pub(super) struct ChunkSizer {
    max_len: usize,
    /// Bytes of one UPDATE of this group outside its entries.
    overhead: Option<usize>,
    /// Entry bytes and entry count of the last measured build.
    measured: (usize, usize),
    /// Upper bound after a rejected build, until one is accepted.
    cap: usize,
    rejections: u32,
    probing: bool,
    probed: bool,
}

impl ChunkSizer {
    pub(super) fn new(max_len: usize) -> Self {
        Self {
            max_len,
            overhead: None,
            measured: (0, 0),
            cap: usize::MAX,
            rejections: 0,
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
        let take = if let Some(overhead) = self.overhead {
            let room = self.max_len.saturating_sub(overhead);
            match size {
                Some(size) => within(size, room),
                None => room * self.measured.1 / self.measured.0.max(1),
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
    /// is not sent. `message` is `None` when that build failed.
    pub(super) fn measured_only(&mut self, message: Option<&UpdateMessage>) -> bool {
        if !std::mem::take(&mut self.probing) {
            return false;
        }
        if let Some(message) = message {
            self.measure(message, 1);
        }
        #[cfg(test)]
        tally(1);
        true
    }

    /// A build of `tried` entries was too long or failed: the next is shorter.
    pub(super) fn rejected(&mut self, tried: usize, message: Option<&UpdateMessage>) {
        let measured = message.is_some_and(|message| self.measure(message, tried));
        // The first miss is re-sized from what it measured. A second in a
        // row means entry sizes vary too much to predict, so halve.
        self.cap = if measured && self.rejections == 0 {
            tried - 1
        } else {
            tried / 2
        }
        .max(1);
        self.rejections += 1;
        #[cfg(test)]
        tally(tried);
    }

    /// A build of `entries` entries fits and is being sent.
    pub(super) fn accepted(&mut self, message: &UpdateMessage, entries: usize) {
        self.measure(message, entries);
        self.cap = usize::MAX;
        self.rejections = 0;
        #[cfg(test)]
        tally(entries);
    }

    fn measure(&mut self, message: &UpdateMessage, entries: usize) -> bool {
        let Some((overhead, entry_bytes)) = split(message) else {
            return false;
        };
        self.overhead = Some(overhead);
        self.measured = (entry_bytes, entries);
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
        // Anything else leading the attributes is not measured.
        assert_eq!(split(&message(PathAttribute::Med(1))), None);
    }
}
