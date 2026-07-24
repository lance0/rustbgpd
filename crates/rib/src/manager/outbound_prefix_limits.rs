//! Per-peer outbound unicast prefix accounting (ADR-0113).
//!
//! The RIB manager owns export policy, RFC 9234 OTC filtering, exact-export
//! precommit, and Adj-RIB-Out truth, so it is also the owner of a local
//! capacity policy over what it advertises. This module holds that
//! accounting: a pure per-family batch admission helper plus the per-peer
//! state it reads and advances.
//!
//! Every family is unlimited today. Nothing populates
//! `RibManager::outbound_prefix_limits`, so the export path keeps exactly the
//! state shape and per-route cost it has always had, and an update-group
//! member gains no per-route state. The operator-facing limit — resolved
//! neighbor/peer-group configuration, its transaction and reload semantics,
//! and its API/CLI/metric surface — lands as one later change; ADR-0113
//! sequences it that way so the accounting is reviewable while it is inert.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;

use rustbgpd_wire::{Afi, Prefix};

use super::RibManager;
use super::helpers::prefix_family;

/// The unicast families this accounting covers. VPN, labeled unicast,
/// `FlowSpec`, EVPN, BGP-LS, and RT-Constrain are deliberately out of scope.
pub(in crate::manager) const LIMITED_FAMILIES: [Afi; 2] = [Afi::Ipv4, Afi::Ipv6];

/// One unicast family's admission state for a peer.
#[derive(Debug, Default)]
pub(in crate::manager) struct FamilyAdmission {
    /// Cap on distinct advertised prefixes; `None` is unlimited.
    pub(in crate::manager) limit: Option<NonZeroU32>,
    /// Admitted prefixes for an update-group member, whose unicast
    /// advertised state is group-owned and therefore has no private
    /// Adj-RIB-Out to count (ADR-0098). Bounded by `limit`, per member, and
    /// never part of `GroupKey` — the shared table still stages once.
    ///
    /// An ungrouped peer leaves this empty: its private Adj-RIB-Out prefix
    /// index is the authoritative admitted set and already refcounts
    /// Add-Path identities per prefix.
    pub(in crate::manager) grouped_admitted: HashSet<Prefix>,
    /// Whether a blocking episode is open for this family. Set when a batch
    /// blocks a net-new prefix, cleared when a later batch blocks nothing
    /// and leaves headroom under the cap.
    pub(in crate::manager) blocking: bool,
}

/// A peer's per-family outbound unicast admission state.
///
/// An entry exists only for a peer with at least one configured limit; an
/// absent entry is the unlimited path, which allocates nothing and runs no
/// per-route check.
#[derive(Debug, Default)]
pub(in crate::manager) struct OutboundPrefixLimits {
    ipv4: FamilyAdmission,
    ipv6: FamilyAdmission,
}

impl OutboundPrefixLimits {
    /// Borrow one unicast family's state, or `None` for a family outside
    /// [`LIMITED_FAMILIES`].
    pub(in crate::manager) fn family(&self, afi: Afi) -> Option<&FamilyAdmission> {
        match afi {
            Afi::Ipv4 => Some(&self.ipv4),
            Afi::Ipv6 => Some(&self.ipv6),
            _ => None,
        }
    }

    /// Mutable sibling of [`Self::family`].
    pub(in crate::manager) fn family_mut(&mut self, afi: Afi) -> Option<&mut FamilyAdmission> {
        match afi {
            Afi::Ipv4 => Some(&mut self.ipv4),
            Afi::Ipv6 => Some(&mut self.ipv6),
            _ => None,
        }
    }
}

/// One family's verdict for a single outgoing batch.
#[derive(Debug, Default, PartialEq, Eq)]
pub(in crate::manager) struct BatchAdmission {
    /// Net-new prefixes dropped because the family is at its cap. Every path
    /// for such a prefix is dropped together: a prefix consumes one slot no
    /// matter how many RFC 7911 path identities carry it.
    pub(in crate::manager) blocked: HashSet<Prefix>,
    /// Net-new prefixes that took a free slot in this batch.
    pub(in crate::manager) admitted: HashSet<Prefix>,
}

/// Decide which of one family's announcements fit under `limit`.
///
/// `usage` is the family's distinct admitted-prefix count before the batch,
/// `freed` the prefixes whose last advertised path this batch withdraws, and
/// `is_admitted` answers whether a prefix is advertised today.
///
/// Withdrawals are never gated, and the post-withdraw projection is computed
/// first, so a batch that drops one prefix and adds another fits at a full
/// cap. An announcement for a prefix still admitted after the withdrawals
/// always passes — an attribute change or an additional path identity for an
/// admitted prefix is an update, not a new prefix.
pub(in crate::manager) fn admit_batch<'a>(
    limit: NonZeroU32,
    usage: usize,
    freed: &HashSet<Prefix>,
    announced: impl IntoIterator<Item = &'a Prefix>,
    is_admitted: impl Fn(&Prefix) -> bool,
) -> BatchAdmission {
    let limit = usize::try_from(limit.get()).unwrap_or(usize::MAX);
    let mut usage = usage.saturating_sub(freed.len());
    let mut verdict = BatchAdmission::default();
    for prefix in announced {
        if verdict.admitted.contains(prefix) || verdict.blocked.contains(prefix) {
            continue;
        }
        if is_admitted(prefix) && !freed.contains(prefix) {
            continue;
        }
        if usage < limit {
            usage += 1;
            verdict.admitted.insert(*prefix);
        } else {
            verdict.blocked.insert(*prefix);
        }
    }
    verdict
}

/// One family's resolved batch inputs, carried from the read pass that needs
/// the peer's advertised state to the write pass that advances it.
struct FamilyVerdict {
    afi: Afi,
    /// Prefixes whose last advertised path this batch withdraws.
    freed: HashSet<Prefix>,
    /// Distinct admitted prefixes once this batch commits.
    post_usage: usize,
    limit: usize,
    verdict: BatchAdmission,
}

impl RibManager {
    /// Resolve one batch against every limited family of `peer`, reading the
    /// advertised state that decides admission but mutating nothing.
    ///
    /// A grouped member's admitted set is prefix-only: update groups
    /// disqualify Add-Path (ADR-0099), so its advertised identities are one
    /// path per prefix. An ungrouped peer reads its private Adj-RIB-Out,
    /// which does refcount path identities — there a prefix frees its slot
    /// only when its LAST advertised path leaves.
    fn outbound_limit_verdicts(
        &self,
        peer: IpAddr,
        grouped: bool,
        announce: &[crate::route::Route],
        withdraw: &[(Prefix, u32)],
    ) -> Vec<FamilyVerdict> {
        let Some(limits) = self.outbound_prefix_limits.get(&peer) else {
            return Vec::new();
        };
        let rib_out = self.adj_ribs_out.get(&peer);
        let mut verdicts = Vec::new();
        for afi in LIMITED_FAMILIES {
            let Some(limit) = limits.family(afi).and_then(|family| family.limit) else {
                continue;
            };
            let admitted = limits.family(afi).map(|family| &family.grouped_admitted);
            let advertised_paths = |prefix: &Prefix| {
                rib_out
                    .map(|rib| rib.path_ids_for_prefix(prefix))
                    .unwrap_or_default()
            };
            let is_admitted = |prefix: &Prefix| {
                if grouped {
                    admitted.is_some_and(|admitted| admitted.contains(prefix))
                } else {
                    !advertised_paths(prefix).is_empty()
                }
            };
            let mut withdrawn: HashMap<Prefix, HashSet<u32>> = HashMap::new();
            for (prefix, path_id) in withdraw {
                if prefix_family(prefix).0 == afi {
                    withdrawn.entry(*prefix).or_default().insert(*path_id);
                }
            }
            let freed: HashSet<Prefix> = withdrawn
                .into_iter()
                .filter(|(prefix, path_ids)| {
                    if grouped {
                        is_admitted(prefix)
                    } else {
                        let advertised = advertised_paths(prefix);
                        !advertised.is_empty() && advertised.iter().all(|id| path_ids.contains(id))
                    }
                })
                .map(|(prefix, _)| prefix)
                .collect();
            let usage = if grouped {
                admitted.map_or(0, HashSet::len)
            } else {
                rib_out.map_or(0, |rib| rib.unicast_prefix_count(afi))
            };
            let verdict = admit_batch(
                limit,
                usage,
                &freed,
                announce
                    .iter()
                    .map(|route| &route.prefix)
                    .filter(|prefix| prefix_family(prefix).0 == afi),
                is_admitted,
            );
            if freed.is_empty() && verdict.admitted.is_empty() && verdict.blocked.is_empty() {
                continue;
            }
            verdicts.push(FamilyVerdict {
                afi,
                post_usage: usage.saturating_sub(freed.len()) + verdict.admitted.len(),
                limit: usize::try_from(limit.get()).unwrap_or(usize::MAX),
                verdict,
                freed,
            });
        }
        verdicts
    }

    /// Apply this peer's outbound unicast prefix limits to one final batch.
    ///
    /// Runs at the per-peer commit seam: after export policy, split horizon,
    /// RFC 9234 OTC, and exact-export precommit have each removed everything
    /// this peer must not receive, and before any Adj-RIB-Out or grouped
    /// admitted-set mutation and before the envelope is enqueued. Routes an
    /// earlier gate rejected therefore consume no capacity, and a blocked
    /// prefix never reaches Adj-RIB-Out or the wire.
    ///
    /// The session stays Established: excess announcements are dropped from
    /// the outgoing vector, nothing already advertised is withdrawn, and no
    /// NOTIFICATION is sent.
    ///
    /// Returns immediately for a peer with no configured limit, which is
    /// every peer until the operator-facing knob exists.
    pub(super) fn enforce_outbound_prefix_limits(
        &mut self,
        peer: IpAddr,
        grouped: bool,
        announce: &mut Arc<[crate::route::Route]>,
        next_hop_override: &mut Arc<[Option<rustbgpd_policy::NextHopAction>]>,
        withdraw: &[(Prefix, u32)],
    ) {
        let verdicts = self.outbound_limit_verdicts(peer, grouped, announce, withdraw);
        if verdicts.is_empty() {
            return;
        }

        let blocked: HashSet<Prefix> = verdicts
            .iter()
            .flat_map(|family| family.verdict.blocked.iter().copied())
            .collect();
        if !blocked.is_empty() {
            debug_assert_eq!(announce.len(), next_hop_override.len());
            let (kept_routes, kept_next_hops): (Vec<_>, Vec<_>) = announce
                .iter()
                .zip(next_hop_override.iter())
                .filter(|(route, _)| !blocked.contains(&route.prefix))
                .map(|(route, next_hop)| (route.clone(), next_hop.clone()))
                .unzip();
            *announce = kept_routes.into();
            *next_hop_override = kept_next_hops.into();
        }

        let mut recovered = false;
        let Some(limits) = self.outbound_prefix_limits.get_mut(&peer) else {
            return;
        };
        for family_verdict in verdicts {
            let Some(family) = limits.family_mut(family_verdict.afi) else {
                continue;
            };
            if grouped {
                for prefix in &family_verdict.freed {
                    family.grouped_admitted.remove(prefix);
                }
                family
                    .grouped_admitted
                    .extend(family_verdict.verdict.admitted);
            }
            if family_verdict.verdict.blocked.is_empty() {
                if family.blocking && family_verdict.post_usage < family_verdict.limit {
                    family.blocking = false;
                    recovered = true;
                }
            } else {
                family.blocking = true;
            }
        }
        if recovered {
            // Capacity opened while an episode was open, and blocked intent
            // is deliberately not inventoried (a rejected-prefix overlay
            // grows toward O(table) in exactly the failure this contains),
            // so re-derive it from current intent through the existing
            // export and exact-export path. This resync is peer-wide;
            // ADR-0113 narrows it to the affected family alongside the
            // coalescing and episode telemetry the operator knob needs.
            // It cannot recur while the table stays over the cap: only a
            // batch that leaves headroom clears the latch.
            self.mark_outbound_dirty(peer);
        }
    }
}
