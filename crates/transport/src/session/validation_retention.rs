//! RFC 9324 local re-evaluation store for validation-dependent sessions.
//!
//! With `[rpki] local_revalidation` enabled, a session whose import chain
//! matches RPKI or ASPA state keeps the decoded pre-policy input of every
//! accepted IPv4/IPv6-unicast route, plus every rejected one that some other
//! validation outcome would have admitted. A VRP or ASPA change queues only
//! the covered identities; the run loop replays them in bounded chunks through
//! the ordinary inbound path, so the peer is not asked for Route Refresh.
//!
//! The store is updated synchronously by every UPDATE, withdrawal, refresh
//! window and session reset. A queued identity is looked up again when its
//! chunk runs, so a route withdrawn or replaced after the delta is never
//! replayed from stale input.
//!
//! Retained rejects are bounded per session. Crossing the bound empties the
//! store and marks it incomplete; later deltas fall back to Route Refresh for
//! this session until it resets, and queued work is replaced by an immediate
//! refresh. The diagnostic `[policy.reject_retention]` LRU is separate: it is
//! lossy by design and never feeds this store.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use rustbgpd_fsm::SessionState;
use rustbgpd_policy::{PolicyAction, PolicyChain, RouteContext};
use rustbgpd_rib::{AttrInternTable, AttrSet};
use rustbgpd_wire::{
    Afi, Ipv4NlriEntry, Ipv4Prefix, Ipv6Prefix, MpReachNlri, NlriEntry, ParsedUpdate,
    PathAttribute, Prefix, Safi,
};
use tracing::{info, warn};

use super::PeerSession;
use crate::{ImportRevalidation, ValidationDelta};

/// Retained validation rejects per session before the store gives up and the
/// peer falls back to Route Refresh.
// ponytail: fixed bound, add a knob if a real table needs more retained rejects.
pub const VALIDATION_REJECT_LIMIT: usize = 65_536;

/// Routes replayed per run-loop turn, so reads, timers and commands
/// interleave with a large re-evaluation.
const REPLAY_CHUNK: usize = 4096;

/// Retained route identity: `(prefix, path_id)`; `path_id` is 0 without
/// Add-Path receive.
pub(super) type RetainedKey = (Prefix, u32);

/// Where the NLRI was carried, so a replay rebuilds the same UPDATE shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum RetainedReach {
    /// IPv4 body NLRI; `NEXT_HOP` is in the retained attributes.
    Body,
    /// Unicast `MP_REACH_NLRI` with its (normalized) next hops.
    Mp {
        afi: Afi,
        next_hop: IpAddr,
        link_local_next_hop: Option<Ipv6Addr>,
    },
}

pub(super) struct RetainedRoute {
    /// Decoded UPDATE attributes without `MP_REACH_NLRI`/`MP_UNREACH_NLRI`.
    attrs: Arc<AttrSet>,
    reach: RetainedReach,
    accepted: bool,
}

/// The overflow that just emptied the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RetentionOverflow;

pub(super) struct ValidationRetention {
    routes: BTreeMap<RetainedKey, RetainedRoute>,
    rejected: usize,
    reject_limit: usize,
    complete: bool,
    attrs: AttrInternTable,
    removals_since_gc: usize,
    /// RFC 7313 windows: identities held before `BoRR` and not yet re-sent.
    /// They are dropped at `EoRR` and never replayed while pending, so local
    /// re-evaluation cannot resurrect a route the peer stopped announcing.
    refresh_stale: HashMap<Afi, HashSet<RetainedKey>>,
    /// Identities a delta covered and the run loop has not replayed yet.
    pending: VecDeque<RetainedKey>,
    queued: HashSet<RetainedKey>,
}

impl ValidationRetention {
    /// `complete` is false when retention starts after routes may already
    /// have been received on this session.
    pub(super) fn new(complete: bool) -> Self {
        Self {
            routes: BTreeMap::new(),
            rejected: 0,
            reject_limit: VALIDATION_REJECT_LIMIT,
            complete,
            attrs: AttrInternTable::new(),
            removals_since_gc: 0,
            refresh_stale: HashMap::new(),
            pending: VecDeque::new(),
            queued: HashSet::new(),
        }
    }

    /// Whether every route this session currently holds is represented.
    pub(super) fn is_complete(&self) -> bool {
        self.complete
    }

    /// Whether queued re-evaluation work remains.
    pub(super) fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Retained identities, and how many of them are rejects.
    pub(super) fn len(&self) -> (usize, usize) {
        (self.routes.len(), self.rejected)
    }

    /// `Some(accepted)` for a retained identity.
    #[cfg(test)]
    pub(super) fn retained(&self, key: &RetainedKey) -> Option<bool> {
        self.routes.get(key).map(|route| route.accepted)
    }

    #[cfg(test)]
    pub(super) fn set_reject_limit(&mut self, limit: usize) {
        self.reject_limit = limit;
    }

    /// Reset for a new session.
    pub(super) fn clear(&mut self) {
        *self = Self::new(true);
    }

    /// Share one allocation per distinct attribute set.
    pub(super) fn intern(&mut self, mut attrs: Arc<AttrSet>) -> Arc<AttrSet> {
        self.attrs.intern(&mut attrs);
        attrs
    }

    /// Forget an identity: withdrawn, re-announced, or rejected for a reason
    /// no validation change can reverse.
    pub(super) fn remove(&mut self, key: &RetainedKey) {
        for stale in self.refresh_stale.values_mut() {
            stale.remove(key);
        }
        if let Some(route) = self.routes.remove(key) {
            if !route.accepted {
                self.rejected -= 1;
            }
            self.removals_since_gc += 1;
            // Amortized: sweep once removals outnumber distinct attribute sets.
            if self.removals_since_gc > self.attrs.len() {
                self.attrs.gc();
                self.removals_since_gc = 0;
            }
        }
    }

    /// Retain one route. A reject beyond [`VALIDATION_REJECT_LIMIT`] empties
    /// the store (and its queue) and leaves it incomplete until the session
    /// resets.
    pub(super) fn insert(
        &mut self,
        key: RetainedKey,
        attrs: Arc<AttrSet>,
        reach: RetainedReach,
        accepted: bool,
    ) -> Result<(), RetentionOverflow> {
        if !self.complete {
            return Ok(());
        }
        self.remove(&key);
        if !accepted {
            if self.rejected >= self.reject_limit {
                *self = Self::new(false);
                return Err(RetentionOverflow);
            }
            self.rejected += 1;
        }
        self.routes.insert(
            key,
            RetainedRoute {
                attrs,
                reach,
                accepted,
            },
        );
        Ok(())
    }

    /// Every retained identity whose prefix equals or is more specific than
    /// `covering`: exactly the routes an RFC 6811 outcome change under a VRP
    /// for `covering` can reach. One ordered range, never a store scan.
    pub(super) fn covered(&self, covering: Prefix) -> impl Iterator<Item = &RetainedKey> {
        // Derived `Prefix` order is (family, address, length), so every
        // contained prefix lies between the covering prefix and the last
        // host route inside it; nothing else does.
        let last = match covering {
            Prefix::V4(prefix) => {
                let host = u32::MAX.checked_shr(u32::from(prefix.len)).unwrap_or(0);
                Prefix::V4(Ipv4Prefix {
                    addr: Ipv4Addr::from(u32::from(prefix.addr) | host),
                    len: 32,
                })
            }
            Prefix::V6(prefix) => {
                let host = u128::MAX.checked_shr(u32::from(prefix.len)).unwrap_or(0);
                Prefix::V6(Ipv6Prefix {
                    addr: Ipv6Addr::from(u128::from(prefix.addr) | host),
                    len: 128,
                })
            }
        };
        self.routes
            .range((covering, 0)..=(last, u32::MAX))
            .map(|(key, _)| key)
    }

    /// Queue every retained identity `delta` can affect. Returns how many
    /// were newly queued.
    pub(super) fn enqueue(&mut self, delta: &ValidationDelta) -> usize {
        let keys: Vec<RetainedKey> = match delta {
            ValidationDelta::Rpki(Some(entries)) => entries
                .iter()
                .filter_map(vrp_covering_prefix)
                .flat_map(|covering| self.covered(covering))
                .copied()
                .collect(),
            ValidationDelta::Aspa(Some(changed)) => {
                // ponytail: one pass over retained entries with one AS_PATH check
                // per distinct attribute set (the RIB's ASPA prefilter shape); add an
                // ASN index if ASPA deltas show up in the session work budget.
                let mut hits: HashMap<*const AttrSet, bool> = HashMap::new();
                self.routes
                    .iter()
                    .filter(|(_, route)| {
                        *hits.entry(Arc::as_ptr(&route.attrs)).or_insert_with(|| {
                            route.attrs.iter().any(|attr| match attr {
                                PathAttribute::AsPath(path) => {
                                    path.asns().any(|asn| changed.contains(&asn))
                                }
                                _ => false,
                            })
                        })
                    })
                    .map(|(key, _)| *key)
                    .collect()
            }
            ValidationDelta::Rpki(None) | ValidationDelta::Aspa(None) => {
                self.routes.keys().copied().collect()
            }
        };
        let mut queued = 0;
        for key in keys {
            if self.queued.insert(key) {
                self.pending.push_back(key);
                queued += 1;
            }
        }
        queued
    }

    /// Take up to `limit` queued identities that are still retained, grouped
    /// into one synthetic UPDATE per (attribute set, reach). An identity
    /// withdrawn or replaced since it was queued replays its current input or
    /// nothing; one still awaiting the peer's refresh replay is skipped.
    fn take_chunk(&mut self, limit: usize) -> Vec<(RetainedReach, Arc<AttrSet>, Vec<RetainedKey>)> {
        let mut groups: Vec<(RetainedReach, Arc<AttrSet>, Vec<RetainedKey>)> = Vec::new();
        let mut index: HashMap<(*const AttrSet, RetainedReach), usize> = HashMap::new();
        let mut taken = 0;
        while taken < limit {
            let Some(key) = self.pending.pop_front() else {
                break;
            };
            self.queued.remove(&key);
            let awaiting_refresh = self
                .refresh_stale
                .values()
                .any(|stale| stale.contains(&key));
            let Some(route) = self.routes.get(&key).filter(|_| !awaiting_refresh) else {
                continue;
            };
            taken += 1;
            match index.entry((Arc::as_ptr(&route.attrs), route.reach)) {
                std::collections::hash_map::Entry::Occupied(slot) => {
                    groups[*slot.get()].2.push(key);
                }
                std::collections::hash_map::Entry::Vacant(slot) => {
                    slot.insert(groups.len());
                    groups.push((route.reach, Arc::clone(&route.attrs), vec![key]));
                }
            }
        }
        groups
    }

    /// Open an RFC 7313 window for one unicast AFI.
    pub(super) fn begin_refresh(&mut self, afi: Afi) {
        if !self.complete {
            return;
        }
        let stale = self
            .routes
            .keys()
            .filter(|(prefix, _)| prefix_afi(*prefix) == afi)
            .copied()
            .collect();
        self.refresh_stale.insert(afi, stale);
    }

    /// Close the window: identities the peer did not re-send are gone.
    pub(super) fn end_refresh(&mut self, afi: Afi) {
        if let Some(stale) = self.refresh_stale.remove(&afi) {
            for key in stale {
                self.remove(&key);
            }
        }
    }

    #[cfg(test)]
    pub(super) fn awaiting_refresh(&self, key: &RetainedKey) -> bool {
        self.refresh_stale.values().any(|stale| stale.contains(key))
    }
}

/// Whether a denied route could be admitted under some other validation
/// outcome, so a later VRP or ASPA change may reverse the deny. A reject that
/// holds for every outcome is not retained.
pub(super) fn reject_depends_on_validation(
    chain: Option<&PolicyChain>,
    ctx: &RouteContext<'_>,
) -> bool {
    use rustbgpd_wire::{AspaValidation, RpkiValidation};
    let Some(chain) = chain else {
        return false;
    };
    let rpki: &[RpkiValidation] = if chain.requires_rpki_validation() {
        &[
            RpkiValidation::Valid,
            RpkiValidation::Invalid,
            RpkiValidation::NotFound,
        ]
    } else {
        &[ctx.validation_state]
    };
    let aspa: &[AspaValidation] = if chain.requires_aspa_validation() {
        &[
            AspaValidation::Valid,
            AspaValidation::Invalid,
            AspaValidation::Unknown,
        ]
    } else {
        &[ctx.aspa_state]
    };
    rpki.iter().any(|&validation_state| {
        aspa.iter().any(|&aspa_state| {
            let alternative = RouteContext {
                validation_state,
                aspa_state,
                ..*ctx
            };
            rustbgpd_policy::evaluate_chain(Some(chain), &alternative).action
                == PolicyAction::Permit
        })
    })
}

/// The prefix a VRP covers (its `max_len` gates only `Valid`).
fn vrp_covering_prefix(entry: &rustbgpd_rpki::VrpEntry) -> Option<Prefix> {
    match entry.prefix {
        IpAddr::V4(addr) if entry.prefix_len <= 32 => {
            Some(Prefix::V4(Ipv4Prefix::new(addr, entry.prefix_len)))
        }
        IpAddr::V6(addr) if entry.prefix_len <= 128 => {
            Some(Prefix::V6(Ipv6Prefix::new(addr, entry.prefix_len)))
        }
        _ => None,
    }
}

impl PeerSession {
    /// Answer [`crate::PeerCommand::RevalidateImport`] and queue the covered
    /// work. The answer is final before any route is re-evaluated.
    pub(super) fn revalidate_import(&mut self, delta: &ValidationDelta) -> ImportRevalidation {
        if self.fsm.state() != SessionState::Established {
            return ImportRevalidation::NotEstablished;
        }
        let Some(store) = self
            .validation_retention
            .as_mut()
            .filter(|store| store.is_complete())
        else {
            return ImportRevalidation::Incomplete;
        };
        let queued = store.enqueue(delta);
        let (retained, retained_rejects) = store.len();
        info!(
            peer = %self.peer_label,
            queued,
            retained,
            retained_rejects,
            "RFC 9324 local import re-evaluation queued"
        );
        // FlowSpec import sees the destination prefix's RPKI state but is not
        // retained; those families keep Route Refresh.
        let refresh_families = match delta {
            ValidationDelta::Rpki(_) => self
                .negotiated_families()
                .iter()
                .copied()
                .filter(|&(_, safi)| safi == Safi::FlowSpec)
                .collect(),
            ValidationDelta::Aspa(_) => Vec::new(),
        };
        ImportRevalidation::Local { refresh_families }
    }

    /// Whether the run loop has queued re-evaluation work to advance.
    pub(super) fn revalidation_pending(&self) -> bool {
        self.fsm.state() == SessionState::Established
            && self
                .validation_retention
                .as_ref()
                .is_some_and(ValidationRetention::has_pending)
    }

    /// Replay one bounded chunk of queued identities through the ordinary
    /// inbound path, against the current snapshot.
    pub(super) async fn advance_revalidation(&mut self) {
        let Some(store) = self.validation_retention.as_mut() else {
            return;
        };
        for (reach, attrs, keys) in store.take_chunk(REPLAY_CHUNK) {
            let mut attributes = attrs.to_vec();
            let announced = match reach {
                RetainedReach::Body => keys
                    .iter()
                    .filter_map(|&(prefix, path_id)| match prefix {
                        Prefix::V4(prefix) => Some(Ipv4NlriEntry { path_id, prefix }),
                        Prefix::V6(_) => None,
                    })
                    .collect(),
                RetainedReach::Mp {
                    afi,
                    next_hop,
                    link_local_next_hop,
                } => {
                    attributes.push(PathAttribute::MpReachNlri(Box::new(MpReachNlri {
                        afi,
                        safi: Safi::Unicast,
                        next_hop,
                        link_local_next_hop,
                        announced: keys
                            .iter()
                            .map(|&(prefix, path_id)| NlriEntry { path_id, prefix })
                            .collect(),
                        flowspec_announced: Vec::new(),
                        evpn_announced: Vec::new(),
                        bgpls_announced: Vec::new(),
                        vpn_announced: Vec::new(),
                        labeled_announced: Vec::new(),
                        rtc_announced: Vec::new(),
                    })));
                    Vec::new()
                }
            };
            let parsed = ParsedUpdate {
                withdrawn: Vec::new(),
                attributes,
                announced,
                bgpls_nlri_discarded: 0,
            };
            self.process_local_replay(parsed).await;
            if self.fsm.state() != SessionState::Established {
                return;
            }
        }
    }

    /// Apply one UPDATE's effect on the store: forget `forget`, then retain or
    /// forget each evaluated identity (`Some((reach, accepted))` = retain).
    pub(super) fn update_validation_retention(
        &mut self,
        forget: impl IntoIterator<Item = RetainedKey>,
        evaluated: Vec<(RetainedKey, Option<(RetainedReach, bool)>)>,
        attrs: impl FnOnce() -> Arc<AttrSet>,
    ) {
        let Some(store) = self.validation_retention.as_mut() else {
            return;
        };
        for key in forget {
            store.remove(&key);
        }
        let had_pending = store.has_pending();
        let mut attrs = evaluated
            .iter()
            .any(|(_, retain)| retain.is_some())
            .then(|| store.intern(attrs()));
        let mut overflowed = false;
        for (key, retain) in evaluated {
            match (retain, attrs.as_ref()) {
                (Some((reach, accepted)), Some(shared)) => {
                    if store
                        .insert(key, Arc::clone(shared), reach, accepted)
                        .is_err()
                    {
                        overflowed = true;
                        attrs = None;
                    }
                }
                _ => store.remove(&key),
            }
        }
        if overflowed {
            warn!(
                peer = %self.peer_label,
                limit = VALIDATION_REJECT_LIMIT,
                "RFC 9324 retained validation rejects exceeded the per-session bound; \
                 this session falls back to Route Refresh until it resets"
            );
            // Queued re-evaluation went with the store: owe the peer's replay.
            if had_pending {
                self.refresh_unicast_after_overflow();
            }
        }
    }

    /// Ask the peer to replay the unicast families the dropped queue covered.
    fn refresh_unicast_after_overflow(&mut self) {
        let families: Vec<_> = self
            .negotiated_families()
            .iter()
            .copied()
            .filter(|&(afi, safi)| safi == Safi::Unicast && matches!(afi, Afi::Ipv4 | Afi::Ipv6))
            .collect();
        let refresh_capable = self
            .negotiated
            .as_ref()
            .is_some_and(|negotiated| negotiated.peer_route_refresh);
        for (afi, safi) in families {
            let result = if refresh_capable {
                self.send_route_refresh(afi, safi)
            } else {
                Err("peer did not negotiate Route Refresh".to_owned())
            };
            if let Err(error) = result {
                warn!(
                    peer = %self.peer_label,
                    ?afi,
                    %error,
                    "RFC 9324 overflow fallback could not request Route Refresh; \
                     queued re-evaluation for this family is lost"
                );
            }
        }
    }
}

pub(super) fn prefix_afi(prefix: Prefix) -> Afi {
    match prefix {
        Prefix::V4(_) => Afi::Ipv4,
        Prefix::V6(_) => Afi::Ipv6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(addr: [u8; 4], len: u8) -> Prefix {
        Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(addr), len))
    }

    fn v6(addr: &str, len: u8) -> Prefix {
        Prefix::V6(Ipv6Prefix::new(addr.parse().unwrap(), len))
    }

    fn store(prefixes: &[Prefix]) -> ValidationRetention {
        let mut store = ValidationRetention::new(true);
        let attrs = AttrSet::new(Vec::new());
        for &prefix in prefixes {
            store
                .insert((prefix, 0), Arc::clone(&attrs), RetainedReach::Body, true)
                .unwrap();
        }
        store
    }

    #[test]
    fn covered_returns_exactly_the_contained_prefixes() {
        let inside = [
            v4([10, 0, 0, 0], 16),
            v4([10, 0, 128, 0], 17),
            v4([10, 0, 255, 255], 32),
        ];
        let outside = [
            v4([10, 0, 0, 0], 8),
            v4([10, 1, 0, 0], 16),
            v4([9, 255, 255, 255], 32),
            v6("::", 0),
        ];
        let all: Vec<_> = inside.iter().chain(&outside).copied().collect();
        let store = store(&all);
        let mut got: Vec<_> = store
            .covered(v4([10, 0, 0, 0], 16))
            .map(|(prefix, _)| *prefix)
            .collect();
        got.sort();
        let mut want = inside.to_vec();
        want.sort();
        assert_eq!(got, want);

        let store = store_v6();
        let got: Vec<_> = store
            .covered(v6("2001:db8::", 32))
            .map(|(prefix, _)| *prefix)
            .collect();
        assert_eq!(got, vec![v6("2001:db8::", 32), v6("2001:db8:ffff::", 48)]);
        assert_eq!(store.covered(v6("::", 0)).count(), 3);
        assert_eq!(store.covered(v4([0, 0, 0, 0], 0)).count(), 0);
    }

    fn store_v6() -> ValidationRetention {
        store(&[
            v6("2001:db8::", 32),
            v6("2001:db8:ffff::", 48),
            v6("2001:db9::", 32),
        ])
    }

    #[test]
    fn reject_overflow_empties_and_stays_incomplete() {
        let mut store = ValidationRetention::new(true);
        store.set_reject_limit(2);
        let attrs = AttrSet::new(Vec::new());
        let reject = |store: &mut ValidationRetention, last: u8| {
            store.insert(
                (v4([192, 0, 2, last], 32), 0),
                AttrSet::new(Vec::new()),
                RetainedReach::Body,
                false,
            )
        };
        reject(&mut store, 1).unwrap();
        reject(&mut store, 2).unwrap();
        // Replacing an existing reject does not count twice; accepts never count.
        reject(&mut store, 2).unwrap();
        store
            .insert(
                (v4([10, 0, 0, 0], 8), 0),
                Arc::clone(&attrs),
                RetainedReach::Body,
                true,
            )
            .unwrap();
        store.enqueue(&ValidationDelta::Rpki(None));
        assert!(store.has_pending());
        assert_eq!(reject(&mut store, 3), Err(RetentionOverflow));
        assert!(!store.is_complete());
        assert_eq!(store.len(), (0, 0));
        assert!(!store.has_pending(), "queued work goes with the store");
        store
            .insert((v4([1, 1, 1, 1], 32), 0), attrs, RetainedReach::Body, true)
            .unwrap();
        assert_eq!(store.len(), (0, 0), "an incomplete store retains nothing");
        store.clear();
        assert!(store.is_complete());
    }

    #[test]
    fn refresh_window_drops_unreplayed_identities() {
        let a = v4([192, 0, 2, 0], 24);
        let b = v4([198, 51, 100, 0], 24);
        let c = v6("2001:db8::", 32);
        let mut store = store(&[a, b, c]);
        store.begin_refresh(Afi::Ipv4);
        assert!(store.awaiting_refresh(&(a, 0)));
        assert!(!store.awaiting_refresh(&(c, 0)));
        // The peer re-sends `a`; `b` never comes back.
        let attrs = AttrSet::new(Vec::new());
        store
            .insert((a, 0), attrs, RetainedReach::Body, true)
            .unwrap();
        assert!(!store.awaiting_refresh(&(a, 0)));
        store.end_refresh(Afi::Ipv4);
        assert!(store.retained(&(a, 0)).is_some());
        assert!(store.retained(&(b, 0)).is_none());
        assert!(store.retained(&(c, 0)).is_some());
    }
}
