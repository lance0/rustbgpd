//! Per-peer outbound unicast prefix accounting (ADR-0113).
//!
//! The RIB manager owns export policy, RFC 9234 OTC filtering, exact-export
//! precommit, and Adj-RIB-Out truth, so it is also the owner of a local
//! capacity policy over what it advertises. This module holds that
//! accounting: a pure per-family batch admission helper plus the per-peer
//! state it reads and advances.
//!
//! A peer with no configured limit keeps exactly the state shape and
//! per-route cost it had before this accounting existed: no entry in
//! `RibManager::outbound_prefix_limits`, no per-route check, and — for an
//! update-group member — no per-route state.
//!
//! `max_prefixes_out_ipv4` / `max_prefixes_out_ipv6` reach this module as
//! resolver tables ([`OutboundPrefixLimitConfig`]): a neighbor entry
//! overrides its peer group, an absent neighbor entry inherits, and an
//! absent effective value is unlimited. The manager resolves each peer
//! itself, so an accepted dynamic child inherits its configured group's
//! effective values with no separate enumeration of live sessions.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;

use rustbgpd_wire::{Afi, Prefix, Safi};
use tracing::{info, warn};

use super::RibManager;
use super::helpers::prefix_family;
use crate::update::{
    OutboundPrefixLimitConfig, OutboundPrefixLimitFamilyState, OutboundPrefixLimitPair,
    OutboundPrefixLimitViolation,
};

/// The unicast families this accounting covers. VPN, labeled unicast,
/// `FlowSpec`, EVPN, BGP-LS, and RT-Constrain are deliberately out of scope.
pub(in crate::manager) const LIMITED_FAMILIES: [Afi; 2] = [Afi::Ipv4, Afi::Ipv6];

/// Bounded metric/API label for a limited family.
pub(in crate::manager) fn family_label(afi: Afi) -> &'static str {
    match afi {
        Afi::Ipv6 => "ipv6_unicast",
        _ => "ipv4_unicast",
    }
}

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

    /// Whether a grouped member's advertised projection includes `prefix`.
    /// A limited family shows exactly what took a slot; an unlimited one
    /// shows the whole group projection.
    pub(in crate::manager) fn admits_grouped(&self, prefix: &Prefix) -> bool {
        self.family(prefix_family(prefix).0)
            .is_none_or(|family| family.limit.is_none() || family.grouped_admitted.contains(prefix))
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

/// Configuration and transaction state for outbound prefix limits.
///
/// One field on [`RibManager`]: the resolver tables the operator's running
/// configuration installed, the single inactive prepared transaction slot,
/// and the coalesced family-scoped recovery intent.
#[derive(Debug, Default)]
pub(in crate::manager) struct OutboundLimitControl {
    /// Active resolver tables; every registration resolves against these.
    config: OutboundPrefixLimitConfig,
    /// The one prepared, inactive transaction. A second preparation
    /// replaces it, so an activation for a superseded identity is rejected
    /// rather than applied.
    prepared: Option<PreparedOutboundLimits>,
    /// Admission-configuration epoch: bumped whenever an installed limit
    /// changes. A prepared transaction that spans an epoch bump saw a
    /// different admission configuration than the one it would activate
    /// into, so activation rejects instead of applying it.
    epoch: u64,
    /// Last activated transaction identity. Activation is idempotent by it,
    /// so a retry or the boot-repair path cannot apply two transitions.
    activated: Option<u64>,
    /// Coalesced capacity-recovery intent: at most one resync per peer and
    /// family, regardless of how often capacity opens.
    recovery: BTreeMap<IpAddr, HashSet<Afi>>,
}

impl OutboundLimitControl {
    /// Drop one departing registration's pending recovery intent. The
    /// resolver tables are configuration and survive the session; a
    /// reconnect resolves them again.
    pub(in crate::manager) fn reap_peer(&mut self, peer: IpAddr) {
        self.recovery.remove(&peer);
    }
}

/// A preflighted but inactive outbound prefix-limit edit.
#[derive(Debug)]
struct PreparedOutboundLimits {
    txn: u64,
    epoch: u64,
    config: OutboundPrefixLimitConfig,
    /// The complete live target set at preparation, each bound to the peer
    /// generation the candidate was preflighted against.
    targets: Vec<(IpAddr, u64, OutboundPrefixLimitPair)>,
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
            let usage = self.outbound_family_usage(peer, afi, grouped);
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
    /// Returns immediately for a peer with no configured limit.
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

        // One record per family: (afi, prefixes blocked, episode transition).
        let mut episodes: Vec<(Afi, usize, Option<bool>)> = Vec::new();
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
            let blocked = family_verdict.verdict.blocked.len();
            // Only a recovery resync ENDS an episode: it alone re-derives the
            // whole family and can prove nothing is still withheld. An
            // ordinary batch either opens the episode (once) or notices that
            // capacity became available and schedules that resync.
            let transition = if blocked == 0 {
                (family.blocking && family_verdict.post_usage < family_verdict.limit)
                    .then_some(false)
            } else {
                let started = !family.blocking;
                family.blocking = true;
                started.then_some(true)
            };
            episodes.push((family_verdict.afi, blocked, transition));
        }

        let peer_label = peer.to_string();
        for (afi, blocked, transition) in episodes {
            let family = family_label(afi);
            if blocked > 0 {
                // Bounded attempt telemetry: a count, never the prefixes.
                self.metrics.record_outbound_prefix_blocked(
                    &peer_label,
                    family,
                    u64::try_from(blocked).unwrap_or(u64::MAX),
                );
            }
            match transition {
                Some(true) => warn!(
                    %peer,
                    family,
                    blocked,
                    "outbound prefix limit reached: net-new prefixes are being withheld \
                     from this peer while the session stays established"
                ),
                // Blocked intent is deliberately not inventoried — a
                // rejected-prefix overlay grows toward O(table) in exactly the
                // failure this contains — so re-derive it from current Loc-RIB
                // / group intent through the existing export and exact-export
                // path, for this family only. It cannot recursively re-arm
                // while the table stays over the cap: a resync that refills to
                // the cap leaves no headroom to notice.
                Some(false) => self.schedule_outbound_limit_recovery(peer, afi),
                None => {}
            }
        }
        // The gauges are NOT refreshed here: this seam runs before the
        // Adj-RIB-Out commit, so an ungrouped peer's usage would still read
        // the pre-batch count. The commit path refreshes them from the same
        // admitted truth the API reports, once that truth exists.
    }

    /// Distinct admitted prefixes for one limited family.
    ///
    /// The single definition of "usage" for enforcement, preflight, the
    /// neighbor API, and the gauges, so a limited grouped member can never
    /// report the shared group table where its own admitted projection is
    /// the truth.
    pub(in crate::manager) fn outbound_family_usage(
        &self,
        peer: IpAddr,
        afi: Afi,
        grouped: bool,
    ) -> usize {
        if !grouped {
            return self
                .adj_ribs_out
                .get(&peer)
                .map_or(0, |rib| rib.unicast_prefix_count(afi));
        }
        let admitted = self
            .outbound_prefix_limits
            .get(&peer)
            .and_then(|limits| limits.family(afi));
        if let Some(family) = admitted
            && family.limit.is_some()
        {
            return family.grouped_admitted.len();
        }
        // An unlimited member materializes no admitted set, so its usage is
        // the group's own per-family accounting: shared table minus split
        // horizon minus this member's exact-export rejections.
        self.grouped_family_counts(peer)
            .and_then(|counts| {
                counts
                    .into_iter()
                    .find(|(family, _)| *family == (afi, Safi::Unicast))
                    .map(|(_, count)| usize::try_from(count).unwrap_or(usize::MAX))
            })
            .unwrap_or(0)
    }

    /// Resolve a peer's effective maxima against candidate resolver tables:
    /// a neighbor entry overrides its group, an absent entry inherits.
    fn resolve_outbound_limits(
        &self,
        config: &OutboundPrefixLimitConfig,
        peer: IpAddr,
    ) -> OutboundPrefixLimitPair {
        config.neighbors.get(&peer).copied().unwrap_or_else(|| {
            self.peer_group
                .get(&peer)
                .and_then(|group| config.groups.get(group))
                .copied()
                .unwrap_or_default()
        })
    }

    /// Neighbor-facing rows for one peer, one per limited unicast family.
    pub(in crate::manager) fn outbound_prefix_limit_rows(
        &self,
        peer: IpAddr,
    ) -> Vec<OutboundPrefixLimitFamilyState> {
        if !self.outbound_peers.contains_key(&peer) {
            return Vec::new();
        }
        let grouped = self.grouped_member_of(peer).is_some();
        LIMITED_FAMILIES
            .into_iter()
            .map(|afi| {
                let usage = self.outbound_family_usage(peer, afi, grouped);
                let family = self
                    .outbound_prefix_limits
                    .get(&peer)
                    .and_then(|limits| limits.family(afi));
                let limit = family.and_then(|family| family.limit).map(NonZeroU32::get);
                OutboundPrefixLimitFamilyState {
                    family: family_label(afi).to_string(),
                    usage: u64::try_from(usage).unwrap_or(u64::MAX),
                    limit,
                    headroom: limit.map(|limit| {
                        limit.saturating_sub(u32::try_from(usage).unwrap_or(u32::MAX))
                    }),
                    blocking: family.is_some_and(|family| family.blocking),
                }
            })
            .collect()
    }

    /// Republish one peer's capacity gauges from the same admitted truth the
    /// API reports. A family that became unlimited drops its limit and
    /// headroom series instead of keeping a stale finite value.
    pub(in crate::manager) fn refresh_outbound_limit_gauges(&mut self, peer: IpAddr) {
        let peer_label = peer.to_string();
        for row in self.outbound_prefix_limit_rows(peer) {
            self.metrics.set_outbound_prefix_capacity(
                &peer_label,
                &row.family,
                usize::try_from(row.usage).unwrap_or(usize::MAX),
                row.limit,
                row.blocking,
            );
        }
    }

    /// Install this registration's effective limits before its initial feed
    /// is built, so a reconnect starts empty and admits up to the cap
    /// instead of flooding and then discovering it is over one.
    pub(super) fn install_registration_outbound_limits(&mut self, peer: IpAddr) {
        let resolved = self.resolve_outbound_limits(&self.outbound_limit_control.config, peer);
        for afi in LIMITED_FAMILIES {
            if let Some(limit) = resolved.family(afi) {
                self.outbound_prefix_limits
                    .entry(peer)
                    .or_default()
                    .family_mut(afi)
                    .expect("LIMITED_FAMILIES are limited families")
                    .limit = Some(limit);
            }
        }
        self.refresh_outbound_limit_gauges(peer);
    }

    /// Families with a pending capacity-recovery resync for `peer`.
    #[cfg(test)]
    pub(in crate::manager) fn outbound_limit_recovery_for(&self, peer: IpAddr) -> Vec<Afi> {
        LIMITED_FAMILIES
            .into_iter()
            .filter(|afi| {
                self.outbound_limit_control
                    .recovery
                    .get(&peer)
                    .is_some_and(|families| families.contains(afi))
            })
            .collect()
    }

    /// Whether any family-scoped capacity recovery is still owed.
    ///
    /// The resync timer that drains it is otherwise armed only by
    /// `dirty_peers`, and a limit edit deliberately marks no peer dirty, so
    /// this is what keeps a scheduled recovery from parking forever on an
    /// otherwise quiescent daemon.
    pub(in crate::manager) fn outbound_limit_recovery_pending(&self) -> bool {
        !self.outbound_limit_control.recovery.is_empty()
    }

    /// Coalesce one family-scoped capacity-recovery resync.
    fn schedule_outbound_limit_recovery(&mut self, peer: IpAddr, afi: Afi) {
        self.outbound_limit_control
            .recovery
            .entry(peer)
            .or_default()
            .insert(afi);
    }

    /// Run every scheduled family-scoped recovery resync, one per peer and
    /// family. Re-derives current intent through the ordinary export and
    /// exact-export path without touching siblings or other families, and
    /// suppresses the End-of-RIB marker: this is an internal capacity
    /// replay, not an RFC 7313 route-refresh response the peer asked for.
    pub(super) fn drain_outbound_limit_recovery(&mut self) -> bool {
        let scheduled = std::mem::take(&mut self.outbound_limit_control.recovery);
        if scheduled.is_empty() {
            return false;
        }
        for (peer, families) in scheduled {
            if !self.outbound_peers.contains_key(&peer) {
                continue;
            }
            for afi in LIMITED_FAMILIES {
                if !families.contains(&afi) {
                    continue;
                }
                // Clear the latch first: the replay below re-derives the whole
                // family, so it re-sets the latch if excess intent remains and
                // leaves it clear when nothing is still withheld. That is what
                // "a complete recovery resync that blocks nothing ends the
                // episode" means, and it is why an ordinary batch never ends
                // one.
                self.set_outbound_blocking(peer, afi, false);
                self.send_route_refresh_response_inner(peer, afi, Safi::Unicast, true);
                if !self.outbound_blocking(peer, afi) {
                    info!(
                        %peer,
                        family = family_label(afi),
                        "outbound prefix limit recovered: this family no longer withholds intent"
                    );
                }
            }
            self.refresh_outbound_limit_gauges(peer);
        }
        true
    }

    fn outbound_blocking(&self, peer: IpAddr, afi: Afi) -> bool {
        self.outbound_prefix_limits
            .get(&peer)
            .and_then(|limits| limits.family(afi))
            .is_some_and(|family| family.blocking)
    }

    fn set_outbound_blocking(&mut self, peer: IpAddr, afi: Afi, blocking: bool) {
        if let Some(family) = self
            .outbound_prefix_limits
            .get_mut(&peer)
            .and_then(|limits| limits.family_mut(afi))
        {
            family.blocking = blocking;
        }
    }

    /// Preflight one candidate configuration across every live peer and hold
    /// it as an inactive prepared transaction.
    ///
    /// Adding or lowering a maximum is valid only where current usage is at
    /// or below the candidate; lowering is not an implicit pruning policy.
    /// One over-limit family rejects the whole edit — including a group-wide
    /// lowering that only one member cannot accept — and the running
    /// configuration, admission state, Adj-RIB-Out, and wire state are
    /// untouched either way.
    pub(super) fn handle_prepare_outbound_prefix_limits(
        &mut self,
        txn: u64,
        config: OutboundPrefixLimitConfig,
        reply: tokio::sync::oneshot::Sender<Result<(), Vec<OutboundPrefixLimitViolation>>>,
    ) {
        let mut violations = Vec::new();
        let mut targets = Vec::new();
        for peer in self.outbound_peers.keys().copied().collect::<Vec<_>>() {
            let candidate = self.resolve_outbound_limits(&config, peer);
            let grouped = self.grouped_member_of(peer).is_some();
            for afi in LIMITED_FAMILIES {
                let Some(limit) = candidate.family(afi) else {
                    continue;
                };
                let usage = self.outbound_family_usage(peer, afi, grouped);
                if usage > limit.get() as usize {
                    violations.push(OutboundPrefixLimitViolation {
                        peer,
                        family: family_label(afi).to_string(),
                        usage: u64::try_from(usage).unwrap_or(u64::MAX),
                        requested: limit.get(),
                    });
                }
            }
            let session_id = self.outbound_session_ids.get(&peer).copied().unwrap_or(0);
            targets.push((peer, session_id, candidate));
        }
        if violations.is_empty() {
            targets.sort_by_key(|(peer, _, _)| *peer);
            self.outbound_limit_control.prepared = Some(PreparedOutboundLimits {
                txn,
                epoch: self.outbound_limit_control.epoch,
                config,
                targets,
            });
            let _ = reply.send(Ok(()));
        } else {
            self.outbound_limit_control.prepared = None;
            let _ = reply.send(Err(violations));
        }
    }

    /// Activate or discard a prepared outbound prefix-limit transaction.
    ///
    /// Activation rechecks the prepared target set, each peer generation,
    /// the admission epoch, and the lowering preconditions in one commit;
    /// any drift rejects the whole activation rather than applying part of
    /// it. A target whose generation was replaced or whose session is gone
    /// is skipped rather than failing the commit: it holds no admission
    /// state, and its next registration resolves the persisted candidate
    /// from [`Self::install_registration_outbound_limits`].
    pub(super) fn handle_apply_outbound_prefix_limits(
        &mut self,
        txn: u64,
        activate: bool,
        reply: tokio::sync::oneshot::Sender<Result<(), String>>,
    ) {
        if !activate {
            if self
                .outbound_limit_control
                .prepared
                .as_ref()
                .is_some_and(|prepared| prepared.txn == txn)
            {
                self.outbound_limit_control.prepared = None;
            }
            let _ = reply.send(Ok(()));
            return;
        }
        if self.outbound_limit_control.activated == Some(txn) {
            // Idempotent by transaction identity: a retry or the boot-repair
            // path cannot apply two recovery transitions.
            let _ = reply.send(Ok(()));
            return;
        }
        let Some(prepared) = self.outbound_limit_control.prepared.take() else {
            let _ = reply.send(Err(format!(
                "no prepared outbound prefix-limit transaction {txn}"
            )));
            return;
        };
        if prepared.txn != txn {
            let _ = reply.send(Err(format!(
                "prepared outbound prefix-limit transaction {} superseded {txn}",
                prepared.txn
            )));
            return;
        }
        if prepared.epoch != self.outbound_limit_control.epoch {
            let _ = reply.send(Err(
                "outbound prefix-limit admission epoch advanced after preparation".to_string(),
            ));
            return;
        }
        let live: Vec<_> = prepared
            .targets
            .iter()
            .filter(|(peer, session_id, _)| self.outbound_session_ids.get(peer) == Some(session_id))
            .copied()
            .collect();
        for (peer, _, candidate) in &live {
            let grouped = self.grouped_member_of(*peer).is_some();
            for afi in LIMITED_FAMILIES {
                let Some(limit) = candidate.family(afi) else {
                    continue;
                };
                let usage = self.outbound_family_usage(*peer, afi, grouped);
                if usage > limit.get() as usize {
                    let _ = reply.send(Err(format!(
                        "{}",
                        OutboundPrefixLimitViolation {
                            peer: *peer,
                            family: family_label(afi).to_string(),
                            usage: u64::try_from(usage).unwrap_or(u64::MAX),
                            requested: limit.get(),
                        }
                    )));
                    return;
                }
            }
        }
        self.outbound_limit_control.config = prepared.config;
        for (peer, _, candidate) in live {
            for afi in LIMITED_FAMILIES {
                self.install_outbound_limit(peer, afi, candidate.family(afi));
            }
            self.refresh_outbound_limit_gauges(peer);
        }
        self.outbound_limit_control.epoch = self.outbound_limit_control.epoch.wrapping_add(1);
        self.outbound_limit_control.activated = Some(txn);
        let _ = reply.send(Ok(()));
    }

    /// Move one live family to an already-preflighted maximum.
    fn install_outbound_limit(&mut self, peer: IpAddr, afi: Afi, limit: Option<NonZeroU32>) {
        let previous = self
            .outbound_prefix_limits
            .get(&peer)
            .and_then(|limits| limits.family(afi))
            .and_then(|family| family.limit);
        if previous == limit {
            return;
        }
        let grouped = self.grouped_member_of(peer).is_some();
        // A raise or removal is the only edit that opens capacity a blocking
        // episode was withholding; a first install or a lowering can only
        // ever admit fewer prefixes than the peer already has.
        let opens_capacity = match (previous, limit) {
            (Some(_), None) => true,
            (Some(previous), Some(limit)) => limit > previous,
            (None, _) => false,
        };
        // A formerly unlimited grouped member owns no admitted set: preflight
        // proved its whole advertised projection fits, so materialize it as
        // the bounded set the limiter now maintains.
        let materialized = (grouped && limit.is_some() && previous.is_none()).then(|| {
            self.grouped_advertised_routes_iter(peer)
                .map(|routes| {
                    routes
                        .filter(|route| prefix_family(&route.prefix).0 == afi)
                        .map(|route| route.prefix)
                        .collect::<HashSet<_>>()
                })
                .unwrap_or_default()
        });

        let entry = self.outbound_prefix_limits.entry(peer).or_default();
        let Some(family) = entry.family_mut(afi) else {
            return;
        };
        family.limit = limit;
        if let Some(materialized) = materialized {
            family.grouped_admitted = materialized;
        }
        if limit.is_none() {
            family.grouped_admitted = HashSet::new();
            family.blocking = false;
        }
        // Keep the unlimited fast path exactly as it was: a peer with no
        // remaining limit owns no admission state at all.
        if LIMITED_FAMILIES.into_iter().all(|afi| {
            entry
                .family(afi)
                .is_none_or(|family| family.limit.is_none())
        }) {
            self.outbound_prefix_limits.remove(&peer);
        }
        if opens_capacity {
            self.schedule_outbound_limit_recovery(peer, afi);
        }
    }

    /// Carry a limited peer's advertised-prefix ownership across a regroup.
    ///
    /// Entering a group, the private Adj-RIB-Out prefix index is about to be
    /// cleared, so its unicast prefixes become the bounded member set.
    /// Leaving one, the private table is re-seeded in the same pass and
    /// becomes authoritative again, so the member set is released. Existing
    /// regroup baselines and tombstones still own the withdrawals: the
    /// limiter neither forgets an old advertisement nor treats a regroup as
    /// fresh capacity.
    pub(in crate::manager) fn carry_outbound_admitted_across_regroup(
        &mut self,
        peer: IpAddr,
        entering_group: bool,
    ) {
        if !self.outbound_prefix_limits.contains_key(&peer) {
            return;
        }
        let seeded: Vec<(Afi, HashSet<Prefix>)> = LIMITED_FAMILIES
            .into_iter()
            .map(|afi| {
                let admitted = if entering_group {
                    self.adj_ribs_out
                        .get(&peer)
                        .map(|rib| {
                            rib.iter()
                                .filter(|route| prefix_family(&route.prefix).0 == afi)
                                .map(|route| route.prefix)
                                .collect()
                        })
                        .unwrap_or_default()
                } else {
                    HashSet::new()
                };
                (afi, admitted)
            })
            .collect();
        let Some(entry) = self.outbound_prefix_limits.get_mut(&peer) else {
            return;
        };
        for (afi, admitted) in seeded {
            if let Some(family) = entry.family_mut(afi)
                && family.limit.is_some()
            {
                family.grouped_admitted = admitted;
            }
        }
    }
}
