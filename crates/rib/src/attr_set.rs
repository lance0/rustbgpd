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

use rustbgpd_wire::{COMMUNITY_LLGR_STALE, Origin, PathAttribute};

/// The attribute-derived inputs of best-path selection, with the defaults
/// the comparator applies to absent attributes. Each field follows the first
/// matching attribute, as the `Route` accessors do.
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
}

impl SelectionSummary {
    fn compute(attrs: &[PathAttribute]) -> Self {
        let mut local_pref = None;
        let mut med = None;
        let mut as_path_len = None;
        let mut cluster_list_len = None;
        let mut originator_id = None;
        let mut origin = None;
        let mut llgr_stale = None;
        for attr in attrs {
            match attr {
                PathAttribute::LocalPref(v) => {
                    local_pref.get_or_insert(*v);
                }
                PathAttribute::Med(v) => {
                    med.get_or_insert(*v);
                }
                PathAttribute::AsPath(path) => {
                    as_path_len.get_or_insert_with(|| saturating_u32(path.len()));
                }
                PathAttribute::ClusterList(ids) => {
                    cluster_list_len.get_or_insert_with(|| saturating_u32(ids.len()));
                }
                PathAttribute::OriginatorId(id) => {
                    originator_id.get_or_insert(*id);
                }
                PathAttribute::Origin(o) => {
                    origin.get_or_insert(*o);
                }
                other => {
                    if let Some(values) = other.communities() {
                        llgr_stale.get_or_insert_with(|| values.contains(&COMMUNITY_LLGR_STALE));
                    }
                }
            }
        }
        Self {
            local_pref: local_pref.unwrap_or(100),
            med: med.unwrap_or(0),
            as_path_len: as_path_len.unwrap_or(0),
            cluster_list_len: cluster_list_len.unwrap_or(0),
            originator_id,
            origin: origin.unwrap_or(Origin::Incomplete),
            llgr_stale: llgr_stale.unwrap_or(false),
        }
    }
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
            }
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
