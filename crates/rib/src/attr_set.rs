//! Path-attribute sets with a cached best-path selection summary.
//!
//! Unicast best-path comparison reads seven attribute-derived values per route. As
//! `find_map` scans over the `PathAttribute` values, an equal compare
//! walked the attribute list about a dozen times. [`AttrSet`] computes those
//! values once, when the set is built, and interning shares one set (and so
//! one summary) across every route that carries the same attributes.
//! Other route families share this container and use its cached LLGR tier;
//! their remaining selection accessors still read the attribute list.
//!
//! The summary cannot go stale: the attribute list is private, reads go
//! through `Deref`, and the only mutation path, [`AttrSet::edit`], rebuilds
//! the summary after the edit. Debug builds also check every
//! [`AttrSet::summary`] read against a fresh computation.

use std::net::Ipv4Addr;
use std::ops::Deref;
use std::sync::Arc;

use rustbgpd_wire::{AsPathSegment, COMMUNITY_LLGR_STALE, Origin, PathAttribute};

/// The attribute-derived inputs of best-path selection, with the defaults
/// the comparator applies to absent attributes. Each field follows the first
/// matching attribute, as the `Route` accessors do. This unpublished RIB-internal
/// type also uses its spare byte for a derived export-reservation bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectionSummary {
    /// `LOCAL_PREF`, default 100.
    pub local_pref: u32,
    /// `MULTI_EXIT_DISC`, default 0.
    pub med: u32,
    /// `AS_PATH` length for selection (`AS_SET` counts as 1), default 0.
    pub as_path_len: u32,
    /// `CLUSTER_LIST` length, default 0.
    pub cluster_list_len: u32,
    /// `ORIGINATOR_ID`, if present.
    pub originator_id: Option<Ipv4Addr>,
    /// `ORIGIN`, default `Incomplete`.
    pub origin: Origin,
    /// Whether the first COMMUNITIES attribute carries `LLGR_STALE`
    /// (RFC 9494 §4.3).
    pub llgr_stale: bool,
    /// Rounded upward into the existing padding; never used for selection.
    wire_bound: u8,
}

// The same seven first-match slots used while constructing a summary. This
// accumulator stays on the stack; bound-only callers need none of it.
#[derive(Default)]
struct SelectionInputs {
    local_pref: Option<u32>,
    med: Option<u32>,
    as_path_len: Option<u32>,
    cluster_list_len: Option<u32>,
    originator_id: Option<Ipv4Addr>,
    origin: Option<Origin>,
    llgr_stale: Option<bool>,
}

impl SelectionSummary {
    fn compute(attrs: &[PathAttribute]) -> Self {
        let mut selection = SelectionInputs::default();
        let mut wire_bound = 0_usize;
        for attr in attrs {
            wire_bound = wire_bound.saturating_add(attribute_wire_bound_with_selection(
                attr,
                Some(&mut selection),
            ));
        }
        Self {
            local_pref: selection.local_pref.unwrap_or(100),
            med: selection.med.unwrap_or(0),
            as_path_len: selection.as_path_len.unwrap_or(0),
            cluster_list_len: selection.cluster_list_len.unwrap_or(0),
            originator_id: selection.originator_id,
            origin: selection.origin.unwrap_or(Origin::Incomplete),
            llgr_stale: selection.llgr_stale.unwrap_or(false),
            wire_bound: compact_wire_bound(wire_bound),
        }
    }
}

/// Store 0..31 exactly, then round upward to sixteen buckets per power of
/// two. This keeps the reservation conservative without enlarging `AttrSet`.
fn compact_wire_bound(bound: usize) -> u8 {
    let bound = u32::from(u16::try_from(bound).unwrap_or(u16::MAX));
    let compact = if bound < 32 {
        bound
    } else {
        let shift = u32::BITS - bound.leading_zeros() - 5;
        shift * 16 + bound.div_ceil(1 << shift)
    };
    u8::try_from(compact).expect("a saturated 16-bit wire bound fits in one byte")
}

fn expand_wire_bound(compact: u8) -> usize {
    if compact < 32 {
        usize::from(compact)
    } else {
        ((16 + usize::from(compact % 16)) << (compact / 16 - 1)).min(usize::from(u16::MAX))
    }
}

/// Maximum encoded size before session export transforms, excluding the MP
/// attributes that export always replaces. Count four-octet attribute headers
/// and both the legacy and AS4 compatibility forms. A saturated result means
/// the caller must reserve a complete maximum-size frame and let the encoder
/// retain its existing validation/error behavior.
#[inline]
#[must_use]
pub fn attribute_wire_bound(attr: &PathAttribute) -> usize {
    attribute_wire_bound_with_selection(attr, None)
}

#[inline]
fn attribute_wire_bound_with_selection(
    attr: &PathAttribute,
    selection: Option<&mut SelectionInputs>,
) -> usize {
    let value = match attr {
        PathAttribute::Origin(origin) => {
            if let Some(selection) = selection {
                selection.origin.get_or_insert(*origin);
            }
            1
        }
        PathAttribute::AsPath(path) => {
            // Two headers, 2+4 octets per ASN, and two 2-octet segment
            // headers for every group of at most 255 ASNs. Even when an
            // AS4 sidecar is unnecessary this remains an upper bound.
            let mut bound = 8_usize;
            let mut path_len = 0_usize;
            for segment in &path.segments {
                let (asns, count) = match segment {
                    AsPathSegment::AsSequence(asns) => (asns, asns.len()),
                    // AsPath::len counts every AS_SET as one, even if empty.
                    AsPathSegment::AsSet(asns) => (asns, 1),
                };
                path_len = path_len.saturating_add(count);
                bound = bound
                    .saturating_add(asns.len().saturating_mul(6))
                    .saturating_add(asns.len().div_ceil(255).saturating_mul(4));
            }
            if let Some(selection) = selection {
                selection
                    .as_path_len
                    .get_or_insert(saturating_u32(path_len));
            }
            return bound;
        }
        // Legacy AGGREGATOR (6) plus AS4_AGGREGATOR (8), with both headers.
        PathAttribute::Aggregator(_) => return 22,
        PathAttribute::AtomicAggregate => 0,
        PathAttribute::LocalPref(value) => {
            if let Some(selection) = selection {
                selection.local_pref.get_or_insert(*value);
            }
            4
        }
        PathAttribute::Med(value) => {
            if let Some(selection) = selection {
                selection.med.get_or_insert(*value);
            }
            4
        }
        PathAttribute::OriginatorId(value) => {
            if let Some(selection) = selection {
                selection.originator_id.get_or_insert(*value);
            }
            4
        }
        PathAttribute::NextHop(_)
        | PathAttribute::OnlyToCustomer(_)
        | PathAttribute::OnlyToCustomerPartial(_) => 4,
        PathAttribute::Communities(values) | PathAttribute::CommunitiesPartial(values) => {
            if let Some(selection) = selection {
                selection
                    .llgr_stale
                    .get_or_insert_with(|| values.contains(&COMMUNITY_LLGR_STALE));
            }
            values.len().saturating_mul(4)
        }
        PathAttribute::ExtendedCommunities(values)
        | PathAttribute::ExtendedCommunitiesPartial(values) => values.len().saturating_mul(8),
        PathAttribute::Ipv6ExtendedCommunities(values)
        | PathAttribute::Ipv6ExtendedCommunitiesPartial(values) => values.len().saturating_mul(20),
        PathAttribute::LargeCommunities(values)
        | PathAttribute::LargeCommunitiesPartial(values) => values.len().saturating_mul(12),
        PathAttribute::ClusterList(values) => {
            if let Some(selection) = selection {
                selection
                    .cluster_list_len
                    .get_or_insert_with(|| saturating_u32(values.len()));
            }
            values.len().saturating_mul(4)
        }
        PathAttribute::MpReachNlri(_) | PathAttribute::MpUnreachNlri(_) => return 0,
        PathAttribute::PmsiTunnel(tunnel) | PathAttribute::PmsiTunnelPartial(tunnel) => {
            use rustbgpd_wire::PmsiTunnelIdentifier;
            let identifier = match &tunnel.tunnel_identifier {
                PmsiTunnelIdentifier::Empty => 0,
                PmsiTunnelIdentifier::Ipv4(_) => 4,
                PmsiTunnelIdentifier::Ipv6(_) => 16,
                PmsiTunnelIdentifier::Raw(bytes) => bytes.len(),
                _ => return usize::from(u16::MAX),
            };
            identifier.saturating_add(5)
        }
        PathAttribute::Unknown(raw) => raw.data.len(),
        _ => return usize::from(u16::MAX),
    };
    value.saturating_add(4)
}

/// Wire limits keep both lengths far below `u32::MAX`; saturating keeps the
/// order of any larger value.
fn saturating_u32(len: usize) -> u32 {
    u32::try_from(len).unwrap_or(u32::MAX)
}

/// An immutable path-attribute list plus its [`SelectionSummary`].
///
/// Routes hold it as `Arc<AttrSet>`. Equality, hashing and `Debug` cover the
/// attribute list only; the summary and the cached hash are pure functions of
/// it.
#[derive(Clone)]
pub struct AttrSet {
    attrs: Vec<PathAttribute>,
    summary: SelectionSummary,
    /// The attribute list's hash, so a sharded intern lookup (shard choice
    /// plus table probe) and a rehash never walk the list again.
    hash: u64,
}

/// Fx over the attribute list, finished with the murmur3 64-bit mixer. The
/// table hashes this value again with Fx, whose multiply carries only low
/// bits upward; the mixer makes every bit of the cached value depend on every
/// input bit, so that second pass still spreads the bucket bits.
fn content_hash(attrs: &Vec<PathAttribute>) -> u64 {
    use std::hash::BuildHasher;
    let mut hash = crate::fast_hash::FastState::default().hash_one(attrs);
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(0xff51_afd7_ed55_8ccd);
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    hash ^ (hash >> 33)
}

impl AttrSet {
    /// Build a shared attribute set and its selection summary.
    #[must_use]
    pub fn new(attrs: Vec<PathAttribute>) -> Arc<Self> {
        let summary = SelectionSummary::compute(&attrs);
        let hash = content_hash(&attrs);
        Arc::new(Self {
            attrs,
            summary,
            hash,
        })
    }

    /// The cached selection summary.
    #[inline]
    #[must_use]
    pub fn summary(&self) -> &SelectionSummary {
        debug_assert_eq!(
            self.summary,
            SelectionSummary::compute(&self.attrs),
            "stale attribute selection summary"
        );
        debug_assert_eq!(self.hash, content_hash(&self.attrs), "stale attribute hash");
        &self.summary
    }

    /// Conservative encoded size of the stored non-MP attributes, rounded
    /// upward and saturated at 65,535 octets. Session transforms and NLRI
    /// framing are additional.
    /// This is only a reservation bound; the wire encoder validates values.
    #[inline]
    #[must_use]
    pub fn non_mp_wire_size_bound(&self) -> usize {
        debug_assert_eq!(
            self.summary.wire_bound,
            SelectionSummary::compute(&self.attrs).wire_bound,
            "stale attribute wire bound"
        );
        expand_wire_bound(self.summary.wire_bound)
    }

    /// Edit the attribute list copy-on-write (`Arc::make_mut`) and rebuild
    /// the summary and hash, including if the callback unwinds. This is the
    /// only way to mutate an `AttrSet`.
    pub fn edit<R>(this: &mut Arc<Self>, f: impl FnOnce(&mut Vec<PathAttribute>) -> R) -> R {
        struct RebuildSummary<'a>(&'a mut AttrSet);

        impl Drop for RebuildSummary<'_> {
            fn drop(&mut self) {
                self.0.summary = SelectionSummary::compute(&self.0.attrs);
                self.0.hash = content_hash(&self.0.attrs);
            }
        }

        let guard = RebuildSummary(Arc::make_mut(this));
        f(&mut guard.0.attrs)
    }

    /// The attributes other than `NEXT_HOP`, for an encoder that emits the
    /// next hop itself (see [`crate::Route::attributes_except_next_hop`]).
    /// MP-family encoders also use it: a stored `NEXT_HOP` must not appear
    /// beside `MP_REACH_NLRI` (RFC 4760 §3).
    pub fn except_next_hop(&self) -> impl Iterator<Item = &PathAttribute> + Clone {
        self.attrs
            .iter()
            .filter(|attr| !matches!(attr, PathAttribute::NextHop(_)))
    }

    /// The attribute list, without copying when this is the last reference.
    #[must_use]
    pub fn into_vec(this: Arc<Self>) -> Vec<PathAttribute> {
        Arc::try_unwrap(this).map_or_else(|shared| shared.attrs.clone(), |set| set.attrs)
    }
}

impl Deref for AttrSet {
    type Target = Vec<PathAttribute>;

    fn deref(&self) -> &Self::Target {
        &self.attrs
    }
}

impl PartialEq for AttrSet {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash && self.attrs == other.attrs
    }
}

impl Eq for AttrSet {}

impl PartialEq<Vec<PathAttribute>> for AttrSet {
    fn eq(&self, other: &Vec<PathAttribute>) -> bool {
        self.attrs == *other
    }
}

impl std::hash::Hash for AttrSet {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write_u64(self.hash);
    }
}

impl std::fmt::Debug for AttrSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.attrs.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use std::hash::BuildHasher;

    use rustbgpd_wire::{AsPath, AsPathSegment};

    use super::*;

    fn assert_wire_bound(attrs: Vec<PathAttribute>) {
        let set = AttrSet::new(attrs);
        let raw_bound = set.iter().fold(0_usize, |sum, attr| {
            sum.saturating_add(attribute_wire_bound(attr))
        });
        assert_eq!(
            set.non_mp_wire_size_bound(),
            expand_wire_bound(compact_wire_bound(raw_bound))
        );
        for four_octet in [false, true] {
            let mut encoded = Vec::new();
            rustbgpd_wire::attribute::encode_path_attributes(&set, &mut encoded, four_octet, false)
                .unwrap();
            assert!(
                encoded.len().min(usize::from(u16::MAX)) <= set.non_mp_wire_size_bound(),
                "{} bytes exceed bound {} (four-octet={four_octet}): {set:?}",
                encoded.len(),
                set.non_mp_wire_size_bound()
            );
        }
    }

    #[test]
    fn wire_bound_covers_every_non_mp_attribute_and_length_boundary() {
        use rustbgpd_wire::{
            Aggregator, ExtendedCommunity, Ipv6ExtendedCommunity, LargeCommunity, PmsiTunnel,
            PmsiTunnelIdentifier, PmsiTunnelType, RawAttribute,
        };
        let addr = Ipv4Addr::new(192, 0, 2, 1);
        for attr in [
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AtomicAggregate,
            PathAttribute::NextHop(addr),
            PathAttribute::LocalPref(100),
            PathAttribute::Med(100),
            PathAttribute::OriginatorId(addr),
            PathAttribute::OnlyToCustomer(70_000),
            PathAttribute::OnlyToCustomerPartial(70_000),
            PathAttribute::Aggregator(Aggregator {
                asn: 70_000,
                router_id: addr,
                partial: true,
            }),
        ] {
            assert_wire_bound(vec![attr]);
        }
        for count in [1, 63, 64, 255, 256, 4_096] {
            let large: Vec<_> = (0..count)
                .map(|index| LargeCommunity::new(1, u32::try_from(index).unwrap(), 3))
                .collect();
            for attr in [
                PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(vec![70_000; count])],
                }),
                PathAttribute::Communities(vec![100; count]),
                PathAttribute::CommunitiesPartial(vec![100; count]),
                PathAttribute::ExtendedCommunities(vec![ExtendedCommunity::new(1); count]),
                PathAttribute::ExtendedCommunitiesPartial(vec![ExtendedCommunity::new(1); count]),
                PathAttribute::Ipv6ExtendedCommunities(vec![
                    Ipv6ExtendedCommunity::new([0; 20]);
                    count
                ]),
                PathAttribute::Ipv6ExtendedCommunitiesPartial(vec![
                    Ipv6ExtendedCommunity::new(
                        [0; 20]
                    );
                    count
                ]),
                PathAttribute::LargeCommunities(large.clone()),
                PathAttribute::LargeCommunitiesPartial(large),
                PathAttribute::ClusterList(vec![addr; count]),
                PathAttribute::Unknown(RawAttribute {
                    flags: 0xd0,
                    type_code: 200,
                    data: vec![0; count].into(),
                }),
            ] {
                assert_wire_bound(vec![attr]);
            }
        }
        assert_wire_bound(vec![PathAttribute::AsPath(AsPath {
            segments: vec![
                AsPathSegment::AsSequence(vec![]),
                AsPathSegment::AsSequence(vec![70_000; 256]),
            ],
        })]);
        for identifier in [
            PmsiTunnelIdentifier::Empty,
            PmsiTunnelIdentifier::Ipv4(addr),
            PmsiTunnelIdentifier::Ipv6("2001:db8::1".parse().unwrap()),
            PmsiTunnelIdentifier::Raw(vec![0; 256]),
        ] {
            let tunnel = PmsiTunnel {
                flags: 0,
                tunnel_type: PmsiTunnelType::Other(0x7b),
                mpls_label: 1,
                tunnel_identifier: identifier,
            };
            assert_wire_bound(vec![PathAttribute::PmsiTunnel(tunnel.clone())]);
            assert_wire_bound(vec![PathAttribute::PmsiTunnelPartial(tunnel)]);
        }
    }

    #[test]
    fn compact_wire_bound_is_monotonic_conservative_and_saturated() {
        let mut previous = 0;
        for bound in 0..=usize::from(u16::MAX) {
            let compact = compact_wire_bound(bound);
            let expanded = expand_wire_bound(compact);
            assert!(compact <= 208);
            assert!(expanded >= bound, "{bound} rounded down to {expanded}");
            assert!(expanded >= previous, "{bound} went backward to {expanded}");
            assert!(u16::try_from(expanded).is_ok());
            assert!(expanded - bound <= bound.div_ceil(16));
            if bound < 32 {
                assert_eq!(expanded, bound);
            }
            previous = expanded;
        }
        for bound in [usize::from(u16::MAX) + 1, 100_000, usize::MAX] {
            assert_eq!(compact_wire_bound(bound), 208);
            assert_eq!(
                expand_wire_bound(compact_wire_bound(bound)),
                usize::from(u16::MAX)
            );
        }
    }

    #[test]
    fn wire_bound_refreshes_on_new_edit_and_unwind_without_layout_growth() {
        // Freeze both old layouts independently: using the new summary in
        // the old container would conceal growth shared by both sides.
        struct PreviousSelectionSummary {
            _local_pref: u32,
            _med: u32,
            _as_path_len: u32,
            _cluster_list_len: u32,
            _originator_id: Option<Ipv4Addr>,
            _origin: Origin,
            _llgr_stale: bool,
        }
        struct PreviousAttrSet {
            _attrs: Vec<PathAttribute>,
            _summary: PreviousSelectionSummary,
            _hash: u64,
        }
        assert_eq!(
            std::mem::size_of::<SelectionSummary>(),
            std::mem::size_of::<PreviousSelectionSummary>()
        );
        assert_eq!(
            std::mem::align_of::<SelectionSummary>(),
            std::mem::align_of::<PreviousSelectionSummary>()
        );
        assert_eq!(
            std::mem::size_of::<AttrSet>(),
            std::mem::size_of::<PreviousAttrSet>()
        );
        assert_eq!(
            std::mem::align_of::<AttrSet>(),
            std::mem::align_of::<PreviousAttrSet>()
        );
        let mut set = AttrSet::new(vec![PathAttribute::Origin(Origin::Igp)]);
        let shared = Arc::clone(&set);
        let original = set.non_mp_wire_size_bound();
        AttrSet::edit(&mut set, |attrs| {
            attrs.push(PathAttribute::Communities(vec![1; 64]));
        });
        let edited = set.non_mp_wire_size_bound();
        assert!(edited > original);
        assert_eq!(shared.non_mp_wire_size_bound(), original);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            AttrSet::edit(&mut set, |attrs| {
                attrs.push(PathAttribute::ClusterList(vec![Ipv4Addr::LOCALHOST; 64]));
                panic!("interrupted after changing the wire size");
            });
        }));
        assert!(result.is_err());
        assert!(set.non_mp_wire_size_bound() > edited);
        assert_eq!(
            set.non_mp_wire_size_bound(),
            AttrSet::new(set.to_vec()).non_mp_wire_size_bound()
        );
        assert_eq!(shared.non_mp_wire_size_bound(), original);
        AttrSet::edit(&mut set, Vec::clear);
        assert_eq!(set.non_mp_wire_size_bound(), 0);
        AttrSet::edit(&mut set, |attrs| {
            attrs.push(PathAttribute::Unknown(rustbgpd_wire::RawAttribute {
                flags: 0xc0,
                type_code: 200,
                data: vec![0; 70_000].into(),
            }));
        });
        assert_eq!(set.non_mp_wire_size_bound(), usize::from(u16::MAX));
    }

    #[test]
    fn summary_takes_first_match_and_defaults() {
        let set = AttrSet::new(vec![
            PathAttribute::Med(7),
            PathAttribute::Med(9),
            PathAttribute::CommunitiesPartial(vec![COMMUNITY_LLGR_STALE]),
            PathAttribute::Communities(vec![]),
            PathAttribute::AsPath(AsPath {
                segments: vec![
                    AsPathSegment::AsSequence(vec![1, 2]),
                    AsPathSegment::AsSet(vec![3, 4, 5]),
                ],
            }),
        ]);
        assert_eq!(
            *set.summary(),
            SelectionSummary {
                local_pref: 100,
                med: 7,
                as_path_len: 3,
                cluster_list_len: 0,
                originator_id: None,
                origin: Origin::Incomplete,
                llgr_stale: true,
                ..*set.summary()
            }
        );
    }

    #[test]
    fn fused_summary_preserves_first_matches_and_empty_as_sets() {
        let first = Ipv4Addr::new(192, 0, 2, 1);
        let second = Ipv4Addr::new(192, 0, 2, 2);
        let path = AsPath {
            segments: vec![
                AsPathSegment::AsSet(vec![]),
                AsPathSegment::AsSequence(vec![]),
                AsPathSegment::AsSet(vec![1, 2]),
                AsPathSegment::AsSequence(vec![1, 2, 3]),
            ],
        };
        assert_eq!(path.len(), 5);
        let attrs = vec![
            PathAttribute::LocalPref(100),
            PathAttribute::LocalPref(200),
            PathAttribute::Med(7),
            PathAttribute::Med(9),
            PathAttribute::AsPath(path),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![1; 9])],
            }),
            PathAttribute::ClusterList(vec![]),
            PathAttribute::ClusterList(vec![first, second]),
            PathAttribute::OriginatorId(first),
            PathAttribute::OriginatorId(second),
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::Origin(Origin::Egp),
            PathAttribute::CommunitiesPartial(vec![]),
            PathAttribute::Communities(vec![COMMUNITY_LLGR_STALE]),
        ];
        let set = AttrSet::new(attrs.clone());
        assert_eq!(
            *set.summary(),
            SelectionSummary {
                local_pref: 100,
                med: 7,
                as_path_len: 5,
                cluster_list_len: 0,
                originator_id: Some(first),
                origin: Origin::Igp,
                llgr_stale: false,
                ..*set.summary()
            }
        );
        // AS_SET and duplicate attributes exercise selection semantics but
        // are deliberately rejected by the wire encoder.
        let mut selection = SelectionInputs::default();
        let raw_bound = attrs.iter().fold(0_usize, |sum, attr| {
            let fused = attribute_wire_bound_with_selection(attr, Some(&mut selection));
            assert_eq!(fused, attribute_wire_bound(attr));
            sum.saturating_add(fused)
        });
        assert_eq!(
            set.non_mp_wire_size_bound(),
            expand_wire_bound(compact_wire_bound(raw_bound))
        );
    }

    #[test]
    fn edit_rebuilds_summary_and_leaves_sharers_alone() {
        let mut set = AttrSet::new(vec![PathAttribute::LocalPref(50)]);
        let shared = Arc::clone(&set);
        AttrSet::edit(&mut set, |attrs| {
            attrs.insert(0, PathAttribute::LocalPref(200));
            attrs.push(PathAttribute::Communities(vec![COMMUNITY_LLGR_STALE]));
        });
        assert_eq!(set.summary().local_pref, 200);
        assert!(set.summary().llgr_stale);
        assert_eq!(shared.summary().local_pref, 50);
        assert!(!shared.summary().llgr_stale);
    }

    #[test]
    fn edit_rebuilds_summary_when_callback_unwinds() {
        let mut set = AttrSet::new(vec![PathAttribute::LocalPref(50)]);
        let shared = Arc::clone(&set);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            AttrSet::edit(&mut set, |attrs| {
                attrs.insert(0, PathAttribute::LocalPref(200));
                panic!("edit interrupted after changing attributes");
            });
        }));

        assert!(result.is_err());
        assert_eq!(set[0], PathAttribute::LocalPref(200));
        assert_eq!(set.summary().local_pref, 200);
        assert_eq!(shared[0], PathAttribute::LocalPref(50));
        assert_eq!(shared.summary().local_pref, 50);
    }

    /// The cached hash follows every edit, including one whose callback
    /// unwinds, so an edited set still hashes and compares equal to a fresh
    /// set with the same attributes and unequal to its former sharers.
    #[test]
    fn cached_hash_follows_edits_and_unwinds() {
        let hash = |set: &AttrSet| crate::fast_hash::FastState::default().hash_one(set);
        let mut set = AttrSet::new(vec![PathAttribute::LocalPref(50)]);
        let shared = Arc::clone(&set);
        AttrSet::edit(&mut set, |attrs| attrs.push(PathAttribute::Med(7)));
        let fresh = AttrSet::new(vec![PathAttribute::LocalPref(50), PathAttribute::Med(7)]);
        assert_eq!(set.hash, content_hash(&set.attrs));
        assert_eq!(hash(&set), hash(&fresh));
        assert_eq!(set, fresh);
        assert_ne!(set, shared);
        assert_ne!(hash(&set), hash(&shared));

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            AttrSet::edit(&mut set, |attrs| {
                attrs.push(PathAttribute::Med(9));
                panic!("edit interrupted after changing attributes");
            });
        }));
        assert!(result.is_err());
        let fresh = AttrSet::new(vec![
            PathAttribute::LocalPref(50),
            PathAttribute::Med(7),
            PathAttribute::Med(9),
        ]);
        assert_eq!(set.hash, content_hash(&set.attrs));
        assert_eq!(hash(&set), hash(&fresh));
        assert_eq!(set, fresh);
    }

    /// The table hashes the cached `u64` again with Fx. Sets that differ in
    /// one field must still spread over hashbrown's top-7 tag bits, its low
    /// bucket bits and the `ShardedMap` shard bits.
    #[test]
    fn cached_hashes_spread_tag_bucket_and_shard_bits() {
        use std::collections::HashSet;
        const KEYS: u64 = 4096;
        let sets: Vec<Arc<AttrSet>> = (0..KEYS)
            .map(|med| {
                AttrSet::new(vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::Med(u32::try_from(med).unwrap()),
                ])
            })
            .collect();
        let hashes: Vec<u64> = sets
            .iter()
            .map(|set| crate::fast_hash::FastState::default().hash_one(&**set))
            .collect();
        let tags = hashes.iter().map(|h| h >> 57).collect::<HashSet<_>>();
        let starts = hashes
            .iter()
            .map(|h| h & (KEYS - 1))
            .collect::<HashSet<_>>();
        let shards = sets
            .iter()
            .map(|set| crate::fast_hash::shard_index(&**set))
            .collect::<HashSet<_>>();
        // Uniform hashing gives all 128 tags, about 63% of the 4096 starting
        // buckets and all 16 shards.
        assert!(tags.len() >= 120, "{} distinct tags", tags.len());
        assert!(
            starts.len() >= 2300,
            "{} distinct starting buckets",
            starts.len()
        );
        assert_eq!(shards.len(), crate::fast_hash::SHARDS);
    }
}
