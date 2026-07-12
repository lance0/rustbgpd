//! Update groups: shared outbound staging for peers whose staged routes
//! are identical (slice 2 of the update-groups arc).
//!
//! Slice 1 introduced the [`GroupKey`] fingerprint registry in shadow
//! mode. This slice makes membership REAL for grouped peers: each group
//! owns ONE staged outbound table ([`GroupRibOut`]), the export tail
//! runs once per (group, changed prefix) instead of once per (peer,
//! prefix), and per-member updates are derived from the shared delta by
//! the source-flip matrix ([`emit_group_deltas_for_member`]). Peers
//! hitting a v1 disqualifier keep today's per-peer path entirely — the
//! fallback is structural, and the per-peer path remains the
//! correctness oracle (design risk 1).
//!
//! Group-owned state (design §2): the staged table (post-policy routes
//! with source peer preserved — the equality-suppression baseline),
//! next-hop-override residue, withdrawal tombstones maintained only
//! while ≥1 member is dirty, and the persistent group-verdict
//! policy-denial set. Per-member state is O(1): membership id, dirty
//! flag, and (transiently, across a regroup) a baseline snapshot of the
//! member's previously advertised view. **No per-peer advertised
//! unicast storage exists for grouped peers** — a member's advertised
//! set is `group table − own-sourced entries`.
//!
//! The one load-bearing registry property from slice 1 still holds: the
//! export-chain key component is chain **content** (interned via
//! `PolicyChain` `PartialEq`), never `Arc` identity — a SIGHUP / rpol
//! overlay / ADR-0076 txn that reinstalls a content-identical chain
//! keeps the key stable, does not count as a regroup, and (new in this
//! slice) skips the resync entirely: the staged output is a pure
//! function of the key.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use rustbgpd_policy::{NextHopAction, PolicyAction, PolicyChain, PolicyEvaluation};
use rustbgpd_wire::{Afi, Prefix, Safi};
use rustc_hash::FxHashMap;
use tracing::warn;

use super::helpers::{LOCAL_PEER, routes_equal, vpn_routes_equal};
use super::{PolicyFilteredRouteKey, RibManager, RtcMembership};
use crate::adj_rib_out::AdjRibOut;
use crate::route::{Route, VpnRibRoute, VpnRibRouteKey};
use crate::update::{
    UpdateGroupClassification, UpdateGroupClassifierInput, UpdateGroupPeerSnapshot,
    UpdateGroupSnapshot, classify_update_group,
};
use rustbgpd_wire::{ExtendedCommunity, VpnAddressFamily, VpnRouteKey};

/// Fingerprint of every RIB-staging input that makes per-peer staged
/// output differ (design §1). Per-peer wire preparation (next-hop
/// rewrite, AS prepend, `ORIGINATOR_ID`/`CLUSTER_LIST` stamping, …) lives
/// in transport and deliberately stays out of the key.
#[expect(
    clippy::struct_excessive_bools,
    reason = "the fingerprint key IS a set of independent staging predicates; \
              packing them into a bitset would only obscure the design table"
)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct GroupKey {
    /// Index into [`UpdateGroupRegistry::chains`] — the interned
    /// **content** of the peer's effective export chain (per-peer if
    /// set, else the global fallback). `None` = no export chain at all.
    chain: Option<usize>,
    /// eBGP target (split-horizon / LLGR §4.4 gate input).
    target_is_ebgp: bool,
    /// RFC 4456 route-reflector client (with the global `cluster_id`
    /// this fully captures the reflection semantics split).
    target_is_rr_client: bool,
    /// Sendable IPv4-unicast (v1 keys the unicast subset exactly).
    sendable_ipv4_unicast: bool,
    /// Sendable IPv6-unicast.
    sendable_ipv6_unicast: bool,
    /// Sendable `VPNv4` (SAFI 128) — the v2 VPN-staging key dimension.
    sendable_vpnv4: bool,
    /// Sendable `VPNv6` (SAFI 128).
    sendable_vpnv6: bool,
    /// RT-Constrain negotiated (sendable ∋ `(Ipv4, RtConstrain)`). Stays
    /// in the key (RTC groups must not mix with non-RTC groups: filter
    /// *presence* is group-uniform by construction); the RFC 4684 RT
    /// filter itself (`Φ_m`) is per-member state applied at emit — never
    /// part of the key, so a PE fleet with distinct RT sets still shares
    /// one group (design §2, option b).
    rtc_negotiated: bool,
    /// Exact set of families the peer advertised LLGR for (RFC 9494
    /// export-restriction input), sorted raw `(afi, safi)` values.
    llgr_families: Vec<(u16, u8)>,
}

/// Where a registered peer stands in the registry: grouped under a
/// stable group id, or ungrouped with the v1 disqualifier that put it
/// on the per-peer fallback path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum GroupMembership {
    /// Fingerprint matched — member of the identified group.
    Grouped(usize),
    /// Export chain matches on peer address/ASN/group: content-equal
    /// chains can still yield peer-different verdicts.
    PolicyPeerContext,
    /// Add-Path send negotiated: the multipath candidate set is
    /// per-target (ranks shift when the target's own path is excluded).
    AddPathSend,
    /// RFC 7947 §2.3.2 per-client best-path: the filtered best is
    /// per-target (the member sourcing the Loc-RIB best gets the
    /// runner-up), so no shared staged winner exists.
    PerClientBest,
    /// ORR vantage bound: per-vantage winners are per-target
    /// (ADR-0095 Decision 5).
    OrrVantage,
    /// ORF-receive negotiated: the peer can push arbitrary per-peer
    /// prefix filters (RFC 5291).
    OrfInstalled,
}

impl GroupMembership {
    /// Operator-facing label: `group:N` or the ungrouped reason.
    pub(super) fn label(&self) -> String {
        match self {
            Self::Grouped(id) => format!("group:{id}"),
            Self::PolicyPeerContext => "policy_peer_context".to_string(),
            Self::AddPathSend => "add_path_send".to_string(),
            Self::PerClientBest => "per_client_best".to_string(),
            Self::OrrVantage => "orr_vantage".to_string(),
            Self::OrfInstalled => "orf_installed".to_string(),
        }
    }
}

/// The registry: interned chain contents, group keys, and per-peer
/// membership. Owned by the [`RibManager`] task like all other RIB
/// state — no locking.
#[derive(Debug, Default)]
pub(super) struct UpdateGroupRegistry {
    /// Interned export-chain contents; a [`GroupKey::chain`] indexes
    /// here. Content-equality (`PolicyChain: PartialEq` on `policies`)
    /// is what keeps a no-op reload key-stable.
    // ponytail: linear content-eq scan and no eviction — distinct chain
    // contents per fleet are few; intern-with-refcount if that changes.
    chains: Vec<PolicyChain>,
    /// Group id = index. Ids stay stable for a process lifetime; an
    /// emptied group's slot is kept and reused when its key recurs.
    groups: Vec<GroupKey>,
    /// Membership (group id or ungrouped reason) per registered peer.
    pub(super) members: HashMap<IpAddr, GroupMembership>,
}

impl UpdateGroupRegistry {
    /// Intern a chain by content, returning its stable index.
    fn intern_chain(&mut self, chain: &PolicyChain) -> usize {
        if let Some(idx) = self.chains.iter().position(|c| c == chain) {
            return idx;
        }
        self.chains.push(chain.clone());
        self.chains.len() - 1
    }

    /// Look up (or create) the group for a key, returning its id.
    fn group_for(&mut self, key: GroupKey) -> usize {
        if let Some(idx) = self.groups.iter().position(|g| *g == key) {
            return idx;
        }
        self.groups.push(key);
        self.groups.len() - 1
    }

    /// A registered peer's membership, if any.
    pub(super) fn membership(&self, peer: IpAddr) -> Option<&GroupMembership> {
        self.members.get(&peer)
    }
}

/// One entry of a shared group staging pass: the new staged route (or a
/// withdrawal) for a `(prefix, path_id)` key, plus the source peer of
/// the entry it replaced — everything the source-flip matrix needs.
#[derive(Debug, Clone)]
pub(in crate::manager) struct GroupDelta {
    pub(in crate::manager) prefix: Prefix,
    pub(in crate::manager) path_id: u32,
    /// Newly staged post-policy route + its next-hop-override flag, or
    /// `None` for a withdrawal.
    pub(in crate::manager) new: Option<(Route, Option<NextHopAction>)>,
    /// Source peer of the group-table entry this delta replaces, read
    /// BEFORE commit. `None` = the key was not previously staged.
    pub(in crate::manager) old_source: Option<IpAddr>,
    /// Terminal policy of the permitting evaluation (`None` = inline /
    /// no chain). Retained on the staged entry so a later join can
    /// replay the member's export counters without re-running policy.
    pub(in crate::manager) policy_label: Option<String>,
}

/// The `Arc`-shared unicast announce payload of one group staging pass:
/// the announce vector and its aligned next-hop-override flags, enqueued
/// per member by `Arc` clone.
pub(in crate::manager) type SharedUnicastPayload = (
    std::sync::Arc<[Route]>,
    std::sync::Arc<[Option<NextHopAction>]>,
);

/// Result of one shared staging pass over a group: the deltas (already
/// committed to the group table), the accumulated export-policy
/// verdicts for per-member counter replay, and the pre-built SHARED
/// per-member emission (design §9 / slice 4).
///
/// The shared emission is the source-flip matrix output for any member
/// that is neither the new source nor the displaced old source of any
/// delta — the overwhelming majority in an RR fanout. Those members
/// enqueue `Arc` clones of ONE announce/nh-flag vector (zero `Route`
/// shell copies per member); the exception members (`exceptions`) fall
/// back to the per-member matrix walk.
#[derive(Default)]
pub(in crate::manager) struct GroupStageOutput {
    pub(in crate::manager) deltas: Vec<GroupDelta>,
    pub(in crate::manager) evals: GroupEvalAccumulator,
    /// Announce payload for non-exception members, built once per pass.
    pub(in crate::manager) shared_announce: std::sync::Arc<[Route]>,
    /// Next-hop-override flags aligned with `shared_announce`.
    pub(in crate::manager) shared_nh: std::sync::Arc<[Option<NextHopAction>]>,
    /// Withdraw keys for non-exception members.
    pub(in crate::manager) shared_withdraw: Vec<(Prefix, u32)>,
    /// Members whose emission differs from the shared one: the new
    /// source of an announce delta (announce → skip/withdraw) or the
    /// old source of a withdraw delta (withdraw → skip).
    exceptions: HashSet<IpAddr>,
}

impl GroupStageOutput {
    /// Keys withdrawn by this pass — the tombstone contribution when a
    /// member is (or goes) dirty.
    pub(in crate::manager) fn withdrawn_keys(&self) -> impl Iterator<Item = (Prefix, u32)> + '_ {
        self.deltas
            .iter()
            .filter(|d| d.new.is_none())
            .map(|d| (d.prefix, d.path_id))
    }

    /// Whether the pre-built shared emission is exactly this member's
    /// source-flip matrix output.
    pub(in crate::manager) fn shared_applies_to(&self, member: IpAddr) -> bool {
        !self.exceptions.contains(&member)
    }

    /// Member-scoped withdraw keys of this pass that [`Self::withdrawn_keys`]
    /// (the tombstone feed) never records: the source-flip arm — the
    /// member is the delta's NEW source and the displaced entry was
    /// another peer's, so the member's emission is a withdraw while the
    /// key stays IN the group table. Recorded into the member's extra
    /// (over-)withdraws when its emission is lost to a full channel.
    pub(in crate::manager) fn member_scoped_withdraws(
        &self,
        member: IpAddr,
    ) -> impl Iterator<Item = (Prefix, u32)> + '_ {
        self.deltas.iter().filter_map(move |delta| {
            (delta
                .new
                .as_ref()
                .is_some_and(|(route, _)| route.peer == member)
                && delta.old_source.is_some_and(|source| source != member))
            .then_some((delta.prefix, delta.path_id))
        })
    }

    /// Build the shared emission from the committed deltas (one `Route`
    /// shell clone per delta, TOTAL — not per member).
    fn build_shared_emit(&mut self) {
        let mut announce: Vec<Route> = Vec::new();
        let mut nh: Vec<Option<NextHopAction>> = Vec::new();
        for delta in &self.deltas {
            if let Some((route, flag)) = &delta.new {
                self.exceptions.insert(route.peer);
                nh.push(flag.clone());
                announce.push(route.clone());
            } else {
                if let Some(source) = delta.old_source {
                    self.exceptions.insert(source);
                }
                self.shared_withdraw.push((delta.prefix, delta.path_id));
            }
        }
        self.shared_announce = announce.into();
        self.shared_nh = nh.into();
    }
}

/// Export-policy verdicts of one shared staging pass, aggregated by
/// (terminal policy, action) with a per-source-peer breakdown so each
/// member can be bumped by `totals − own-sourced` — exactly what the
/// per-peer path would have recorded (split horizon skips the eval for
/// the route's own source). Integer adds only; no per-(prefix × peer)
/// prometheus lookups (design §6).
#[derive(Default)]
pub(in crate::manager) struct GroupEvalAccumulator {
    totals: Vec<(Option<String>, PolicyAction, u64)>,
    per_source: FxHashMap<IpAddr, Vec<(Option<String>, PolicyAction, u64)>>,
    /// Verdict (and source peer) of the most recent evaluation, consumed
    /// per key by the staging loops to label the staged entry / denial
    /// residue (single-best stages at most one eval per key).
    last: Option<(Option<String>, PolicyAction, IpAddr)>,
}

fn bump_eval_row(
    rows: &mut Vec<(Option<String>, PolicyAction, u64)>,
    policy: Option<&String>,
    action: PolicyAction,
) {
    if let Some((_, _, n)) = rows
        .iter_mut()
        .find(|(p, a, _)| *a == action && p.as_ref() == policy)
    {
        *n += 1;
    } else {
        rows.push((policy.cloned(), action, 1));
    }
}

impl GroupEvalAccumulator {
    /// Record one chain evaluation for the route sourced by `source`.
    pub(in crate::manager) fn record(&mut self, evaluation: &PolicyEvaluation, source: IpAddr) {
        bump_eval_row(
            &mut self.totals,
            evaluation.matched_policy.as_ref(),
            evaluation.action,
        );
        bump_eval_row(
            self.per_source.entry(source).or_default(),
            evaluation.matched_policy.as_ref(),
            evaluation.action,
        );
        self.last = Some((evaluation.matched_policy.clone(), evaluation.action, source));
    }

    /// Take (and clear) the last recorded verdict — the staging loop's
    /// per-key label / denial-residue hook.
    fn take_last(&mut self) -> Option<(Option<String>, PolicyAction, IpAddr)> {
        self.last.take()
    }
}

/// Per-member emit for one shared staging pass — the source-flip matrix
/// (design §3). Announce / withdraw / skip is decided per delta entry
/// from `(member == new source, member == old source)` alone:
///
/// | entry             | member == `new.peer`                                      | member == `old_source`                       | else     |
/// |-------------------|-----------------------------------------------------------|----------------------------------------------|----------|
/// | announce (`Some`) | old exists ∧ `old_source` ≠ member → withdraw; else skip  | announce (member was excluded, now eligible) | announce |
/// | withdraw (`None`) | —                                                          | skip (member never had it)                   | withdraw |
///
/// `nh_override_flags` stays aligned with `announce` by pushing in the
/// same arm. A free function so the risk-2 unit matrix can drive it
/// directly.
pub(in crate::manager) fn emit_group_deltas_for_member(
    deltas: &[GroupDelta],
    member: IpAddr,
    announce: &mut Vec<Route>,
    withdraw: &mut Vec<(Prefix, u32)>,
    nh_override_flags: &mut Vec<Option<NextHopAction>>,
) {
    for delta in deltas {
        match &delta.new {
            Some((route, nh)) => {
                if route.peer == member {
                    // Split horizon applied at emit: the new best is the
                    // member's own route. If the member previously held a
                    // different source's advertisement for this key it
                    // must be withdrawn (per-peer semantics: best ==
                    // target ⇒ withdraw existing); if the old entry was
                    // also member-sourced (or absent) the member never
                    // had it — skip.
                    if delta.old_source.is_some_and(|source| source != member) {
                        withdraw.push((delta.prefix, delta.path_id));
                    }
                } else {
                    nh_override_flags.push(nh.clone());
                    announce.push(route.clone());
                }
            }
            None => {
                // A member never receives its own-sourced entries, so a
                // withdrawal of one is a no-op for it (and a withdraw
                // delta with no old entry — unreachable by construction
                // — would be a no-op for everyone).
                if delta.old_source.is_some_and(|source| source != member) {
                    withdraw.push((delta.prefix, delta.path_id));
                }
            }
        }
    }
}

/// A persistent group-verdict VPN denial: (source peer, denying policy
/// label, the denied route's extended communities — the Φ gate input
/// for an RTC member's join-time counter replay).
type VpnDenialRecord = (IpAddr, Option<String>, Vec<ExtendedCommunity>);

/// One entry of a shared group VPN staging pass. Unlike the unicast
/// [`GroupDelta`] this carries the full displaced route (`old`), not just
/// its source: the RT-pass matrix needs the displaced entry's extended
/// communities to decide `had` per member (design §2.1). `path_id` is
/// fixed at 0 — Add-Path send disqualifies from grouping.
#[derive(Debug, Clone)]
pub(in crate::manager) struct VpnGroupDelta {
    pub(in crate::manager) key: VpnRouteKey,
    /// Newly staged post-policy route (source-faithful, ADR-0077 §6), or
    /// `None` for a withdrawal.
    pub(in crate::manager) new: Option<VpnRibRoute>,
    /// Prior staged entry for the key, cloned before commit (one clone
    /// per delta, total). `None` = the key was not previously staged.
    pub(in crate::manager) old: Option<VpnRibRoute>,
    /// Terminal policy of the permitting evaluation — join-time counter
    /// replay residue, exactly like [`GroupDelta::policy_label`].
    pub(in crate::manager) policy_label: Option<String>,
}

/// Result of one shared VPN staging pass over a group: deltas (already
/// committed to the group table) plus the accumulated export-policy
/// verdicts for per-member counter replay. No shared-`Arc` payload — the
/// outbound envelope's VPN queue is a `Vec`, so members clone per route
/// either way; the receipt-proven win is collapsing the *staging* (policy
/// eval + suppression per peer), not the emit clones.
#[derive(Default)]
pub(in crate::manager) struct VpnGroupStageOutput {
    pub(in crate::manager) deltas: Vec<VpnGroupDelta>,
    pub(in crate::manager) evals: GroupEvalAccumulator,
}

impl VpnGroupStageOutput {
    /// Member-scoped withdraw keys of this pass that the VPN tombstone
    /// feed (deltas with `new == None`) never records: `had ∧ ¬gets`
    /// entries whose delta still holds a staged route — a source flip
    /// ONTO the member, or a route mutating out of its Φ — so the
    /// member's emission is a withdraw while the key stays IN the group
    /// table. Recorded into the member's extra (over-)withdraws when
    /// its emission is lost to a full channel.
    pub(in crate::manager) fn member_scoped_withdraws<'a>(
        &'a self,
        member: IpAddr,
        filter: Option<&'a RtcMembership>,
    ) -> impl Iterator<Item = VpnRouteKey> + 'a {
        self.deltas.iter().filter_map(move |delta| {
            let had = delta
                .old
                .as_ref()
                .is_some_and(|old| old.peer != member && rt_passes(filter, old));
            let gets = delta
                .new
                .as_ref()
                .is_some_and(|new| new.peer != member && rt_passes(filter, new));
            (delta.new.is_some() && had && !gets).then_some(delta.key)
        })
    }
}

/// Whether a staged VPN route passes a member's RFC 4684 RT filter:
/// no filter (SAFI 132 not negotiated — group-uniform via the key), or
/// any of the route's extended communities falls inside the membership.
/// REUSES [`RtcMembership::matches_any`] — the one implementation of
/// RTC matching semantics (design §2.2: there is no second copy of the
/// 96-bit covering-prefix core to drift).
pub(in crate::manager) fn rt_passes(filter: Option<&RtcMembership>, route: &VpnRibRoute) -> bool {
    filter.is_none_or(|membership| membership.matches_any(route.extended_communities()))
}

/// Per-member VPN emit for one shared staging pass — the design §2.2
/// RT-pass source-flip matrix (`pass_m` = no filter ∨
/// `Φ_m.matches_any`; a non-RTC group passes `None` = the slice-1
/// degenerate `pass ≡ true` case):
///
/// - `had`  = `old` exists ∧ `old.peer ≠ member` ∧ `pass_m(old)`
/// - `gets` = `new` exists ∧ `new.peer ≠ member` ∧ `pass_m(new)`
/// - emit: `gets` → announce `new`; `had ∧ ¬gets` → withdraw `(key, 0)`;
///   else skip.
///
/// Returns the member's net advertised-count delta per VPN family slot
/// `[vpnv4, vpnv6]` (`gets ∧ ¬had` = +1, `had ∧ ¬gets` = −1) — the
/// incremental input for the per-member counters an RT filter makes
/// non-derivable from the group's source counts (design §2.4).
pub(in crate::manager) fn emit_vpn_group_deltas_for_member(
    deltas: &[VpnGroupDelta],
    member: IpAddr,
    filter: Option<&RtcMembership>,
    vpn_announce: &mut Vec<VpnRibRoute>,
    vpn_withdraw: &mut Vec<VpnRibRouteKey>,
) -> [i64; 2] {
    let mut count_delta = [0i64; 2];
    for delta in deltas {
        let had = delta
            .old
            .as_ref()
            .is_some_and(|old| old.peer != member && rt_passes(filter, old));
        let gets = delta
            .new
            .as_ref()
            .is_some_and(|new| new.peer != member && rt_passes(filter, new));
        let slot = GroupRibOut::vpn_count_slot(&delta.key) - 2;
        if gets {
            vpn_announce.push(delta.new.clone().expect("gets implies new exists"));
            if !had {
                count_delta[slot] += 1;
            }
        } else if had {
            vpn_withdraw.push(VpnRibRouteKey {
                nlri_key: delta.key,
                path_id: 0,
            });
            count_delta[slot] -= 1;
        }
    }
    count_delta
}

/// A regrouped member's previously-advertised view, held until its
/// one-shot resync diff succeeds (design §4): the unicast table plus —
/// for a member whose VPN state is group-owned — the VPN view.
#[derive(Debug, Default)]
pub(in crate::manager) struct RegroupBaseline {
    pub(in crate::manager) unicast: FxHashMap<(Prefix, u32), Route>,
    pub(in crate::manager) vpn: FxHashMap<VpnRouteKey, VpnRibRoute>,
}

/// Extra (over-)withdraw keys a member must emit on its next resync:
/// tombstones carried across a regroup by a member that was dirty when
/// it moved. Over-withdraw is the safe direction.
#[derive(Debug, Default)]
pub(in crate::manager) struct ExtraWithdraws {
    pub(in crate::manager) unicast: HashSet<(Prefix, u32)>,
    pub(in crate::manager) vpn: HashSet<VpnRouteKey>,
}

/// The group-owned staged outbound table (design §2): the unicast
/// portion of an [`AdjRibOut`] reused as substrate, plus the group's
/// membership/dirty bookkeeping and the group-uniform staging inputs
/// snapshot. One instance per non-empty group; dropped when the last
/// member leaves.
pub(in crate::manager) struct GroupRibOut {
    /// Post-policy staged routes, source peer preserved (needed by the
    /// source-flip matrix). Only the unicast maps of the substrate are
    /// used. This IS the equality-suppression baseline: `routes_equal`
    /// runs once per group against it.
    pub(in crate::manager) table: AdjRibOut,
    /// Next-hop-override flags for staged entries (`Some` values only)
    /// so joins/replays don't re-run policy to recover them.
    nh_overrides: FxHashMap<(Prefix, u32), NextHopAction>,
    /// Staged-entry count per source peer — O(1) per-member advertised
    /// count synthesis (`len − own`), one slot per staged family
    /// (v4-unicast, v6-unicast, vpnv4, vpnv6) for the BMP stat-17
    /// family counts.
    source_counts: FxHashMap<IpAddr, [usize; 4]>,
    /// Keys withdrawn from the table since the first member went dirty;
    /// empty (and unmaintained) while no member is dirty. A dirty
    /// member's resync withdraws `tombstones ∖ still-staged` — spurious
    /// withdraws of never-advertised prefixes are RFC 4271 no-ops
    /// (over-withdraw is the safe direction).
    pub(in crate::manager) tombstones: HashSet<(Prefix, u32)>,
    /// VPN sibling of `tombstones` (`path_id` fixed at 0).
    pub(in crate::manager) vpn_tombstones: HashSet<VpnRouteKey>,
    pub(in crate::manager) members: HashSet<IpAddr>,
    pub(in crate::manager) dirty_members: HashSet<IpAddr>,
    /// Persistent group-verdict export-policy denials (target stamped
    /// with [`GROUP_FILTERED_PLACEHOLDER`], restamped per member) with
    /// the denying policy's label for join-time counter replay.
    policy_filtered: FxHashMap<PolicyFilteredRouteKey, Option<String>>,
    /// Terminal policy label per staged entry (`None` = inline) —
    /// join-time counter replay residue.
    staged_labels: FxHashMap<(Prefix, u32), Option<String>>,
    /// VPN sibling of `staged_labels`, keyed by RD+prefix identity.
    vpn_staged_labels: FxHashMap<VpnRouteKey, Option<String>>,
    /// Persistent group-verdict VPN export-policy denials: denied key →
    /// (source peer, denying policy label, the denied route's extended
    /// communities). The per-peer VPN path keeps no denial *records*
    /// (unlike unicast `policy_filtered` — VPN has no denied-routes
    /// query), but it DOES record a deny eval per denied key at every
    /// staging pass, so join-time counter replay needs this residue for
    /// parity. The extended communities let an RTC member's replay skip
    /// denials its Φ would have RT-gated before the eval (the per-peer
    /// path's RT gate precedes the policy evaluation).
    vpn_policy_denied: FxHashMap<VpnRouteKey, VpnDenialRecord>,
    /// Per-member advertised VPN counts `[vpnv4, vpnv6]`, maintained
    /// ONLY for RTC-negotiated groups (Φ makes the counts non-derivable
    /// from `source_counts`; design §2.4) at the emit seams: staging
    /// emit, membership delta, join, and resync recompute-by-walk. A
    /// dirty window may drift them; the member's resync recompute
    /// restores exactness. Non-RTC groups keep the O(1) synthesis.
    vpn_member_counts: FxHashMap<IpAddr, [i64; 2]>,
    // Group-uniform staging inputs, snapshot at group creation from the
    // first member (all members are key-equal by construction; a key
    // change moves peers to a different group, so these never mutate).
    pub(in crate::manager) export_chain: Option<PolicyChain>,
    pub(in crate::manager) is_ebgp: bool,
    pub(in crate::manager) is_rr_client: bool,
    pub(in crate::manager) sendable: Vec<(Afi, Safi)>,
    pub(in crate::manager) llgr: Vec<(Afi, Safi)>,
}

/// Placeholder target for group-level policy-denial records; restamped
/// with the concrete member at emit time. `LOCAL_PEER` can never be an
/// outbound target.
const GROUP_FILTERED_PLACEHOLDER: IpAddr = LOCAL_PEER;

impl GroupRibOut {
    fn new(
        export_chain: Option<PolicyChain>,
        is_ebgp: bool,
        is_rr_client: bool,
        sendable: Vec<(Afi, Safi)>,
        llgr: Vec<(Afi, Safi)>,
        capacity: usize,
    ) -> Self {
        Self {
            table: AdjRibOut::with_capacity(GROUP_FILTERED_PLACEHOLDER, capacity),
            nh_overrides: FxHashMap::default(),
            source_counts: FxHashMap::default(),
            tombstones: HashSet::new(),
            vpn_tombstones: HashSet::new(),
            members: HashSet::new(),
            dirty_members: HashSet::new(),
            policy_filtered: FxHashMap::default(),
            staged_labels: FxHashMap::default(),
            vpn_staged_labels: FxHashMap::default(),
            vpn_policy_denied: FxHashMap::default(),
            vpn_member_counts: FxHashMap::default(),
            export_chain,
            is_ebgp,
            is_rr_client,
            sendable,
            llgr,
        }
    }

    /// Whether this group stages VPN routes: `VPNv4` or `VPNv6`
    /// sendable. RTC-negotiated groups stage too (v2 slice 2) — the RFC
    /// 4684 filter `Φ_m` is applied per member at emit by the RT-pass
    /// matrix, never at staging. Group-uniform — the input is in the
    /// [`GroupKey`].
    pub(in crate::manager) fn stages_vpn(&self) -> bool {
        self.sendable.iter().any(|&(_, safi)| safi == Safi::MplsVpn)
    }

    /// Whether this group's members negotiated RT-Constrain — filter
    /// *presence* is group-uniform (`rtc_negotiated` is in the key), so
    /// this decides between the per-member RT-pass emit + maintained
    /// counters (RTC) and the shared unfiltered emit + O(1) count
    /// synthesis (non-RTC).
    pub(in crate::manager) fn rtc_negotiated(&self) -> bool {
        self.sendable.contains(&(Afi::Ipv4, Safi::RtConstrain))
    }

    fn count_slot(prefix: &Prefix) -> usize {
        match prefix {
            Prefix::V4(_) => 0,
            Prefix::V6(_) => 1,
        }
    }

    fn vpn_count_slot(key: &VpnRouteKey) -> usize {
        match key.prefix.family() {
            VpnAddressFamily::V4 => 2,
            VpnAddressFamily::V6 => 3,
        }
    }

    fn dec_source_slot(&mut self, peer: IpAddr, slot: usize) {
        if let Some(counts) = self.source_counts.get_mut(&peer) {
            counts[slot] = counts[slot].saturating_sub(1);
            if counts.iter().all(|&n| n == 0) {
                self.source_counts.remove(&peer);
            }
        }
    }

    fn inc_source_slot(&mut self, peer: IpAddr, slot: usize) {
        self.source_counts.entry(peer).or_default()[slot] += 1;
    }

    fn dec_source(&mut self, peer: IpAddr, prefix: &Prefix) {
        self.dec_source_slot(peer, Self::count_slot(prefix));
    }

    fn inc_source(&mut self, peer: IpAddr, prefix: &Prefix) {
        self.inc_source_slot(peer, Self::count_slot(prefix));
    }

    /// Commit one staged delta into the group table, keeping the
    /// source-count and next-hop-override residue in sync.
    fn apply_delta(&mut self, delta: &GroupDelta) {
        let key = (delta.prefix, delta.path_id);
        if let Some(old) = self.table.get(&delta.prefix, delta.path_id) {
            let old_peer = old.peer;
            self.dec_source(old_peer, &delta.prefix);
        }
        if let Some((route, nh)) = &delta.new {
            self.inc_source(route.peer, &delta.prefix);
            match nh {
                Some(action) => {
                    self.nh_overrides.insert(key, action.clone());
                }
                None => {
                    self.nh_overrides.remove(&key);
                }
            }
            self.staged_labels.insert(key, delta.policy_label.clone());
            self.table.insert(route.clone());
        } else {
            self.table.withdraw(&delta.prefix, delta.path_id);
            self.nh_overrides.remove(&key);
            self.staged_labels.remove(&key);
        }
    }

    /// Commit one staged VPN delta into the group table's VPN maps,
    /// keeping the source counts and label residue in sync. The VPN
    /// sibling of [`Self::apply_delta`]; `path_id` fixed at 0.
    fn apply_vpn_delta(&mut self, delta: &VpnGroupDelta) {
        let rib_key = VpnRibRouteKey {
            nlri_key: delta.key,
            path_id: 0,
        };
        let slot = Self::vpn_count_slot(&delta.key);
        if let Some(old) = self.table.get_vpn(&rib_key) {
            let old_peer = old.peer;
            self.dec_source_slot(old_peer, slot);
        }
        if let Some(route) = &delta.new {
            self.inc_source_slot(route.peer, slot);
            self.vpn_staged_labels
                .insert(delta.key, delta.policy_label.clone());
            self.table.insert_vpn(route.clone());
        } else {
            self.table.remove_vpn(&rib_key);
            self.vpn_staged_labels.remove(&delta.key);
        }
    }

    /// The next-hop-override flag staged for a table entry.
    pub(in crate::manager) fn nh_override(&self, key: (Prefix, u32)) -> Option<NextHopAction> {
        self.nh_overrides.get(&key).cloned()
    }

    /// Number of unicast routes `member` currently has advertised: the
    /// group table minus the member's own-sourced entries. O(1).
    pub(in crate::manager) fn advertised_count_for(&self, member: IpAddr) -> usize {
        let own = self
            .source_counts
            .get(&member)
            .map_or(0, |counts| counts[0] + counts[1]);
        self.table.len().saturating_sub(own)
    }

    /// Number of VPN routes `member` currently has advertised. Non-RTC
    /// group: the group VPN table minus the member's own-sourced entries,
    /// O(1). RTC group: the maintained per-member counter (Φ makes the
    /// count non-derivable from `source_counts`).
    pub(in crate::manager) fn vpn_advertised_count_for(&self, member: IpAddr) -> usize {
        if self.rtc_negotiated() {
            return self
                .vpn_member_counts
                .get(&member)
                .map_or(0, |counts| counts.iter().sum::<i64>().max(0))
                .try_into()
                .unwrap_or(0);
        }
        let own = self
            .source_counts
            .get(&member)
            .map_or(0, |counts| counts[2] + counts[3]);
        self.table.vpn_len().saturating_sub(own)
    }

    /// Recompute (and store) a member's advertised VPN counts from the
    /// group table under its current Φ — the resync/join seam that makes
    /// the incremental counters exact again after a dirty window. O(VPN
    /// table); resyncs and joins are rare. No-op for non-RTC groups.
    pub(in crate::manager) fn recompute_vpn_member_counts(
        &mut self,
        member: IpAddr,
        filter: Option<&RtcMembership>,
    ) {
        if !self.rtc_negotiated() {
            return;
        }
        let counts = self.vpn_member_counts_from_table(member, filter);
        self.vpn_member_counts.insert(member, counts);
    }

    /// A member's advertised VPN counts recomputed from the table (the
    /// invariant reference the incremental counters are checked against).
    pub(in crate::manager) fn vpn_member_counts_from_table(
        &self,
        member: IpAddr,
        filter: Option<&RtcMembership>,
    ) -> [i64; 2] {
        let mut counts = [0i64; 2];
        for route in self.table.iter_vpn() {
            if route.peer != member && rt_passes(filter, route) {
                counts[Self::vpn_count_slot(&route.nlri.key()) - 2] += 1;
            }
        }
        counts
    }

    /// Apply an incremental per-member count delta (an emit seam's
    /// matrix output). No-op for non-RTC groups (O(1) synthesis).
    pub(in crate::manager) fn apply_vpn_member_count_delta(
        &mut self,
        member: IpAddr,
        delta: [i64; 2],
    ) {
        if !self.rtc_negotiated() || delta == [0, 0] {
            return;
        }
        let counts = self.vpn_member_counts.entry(member).or_default();
        counts[0] += delta[0];
        counts[1] += delta[1];
    }

    /// Per-family synthesized advertised counts for a member (BMP RFC
    /// 8671 stat type 17 input). Zero-count families omitted.
    pub(in crate::manager) fn family_counts_for(&self, member: IpAddr) -> Vec<((Afi, Safi), u64)> {
        const FAMILIES: [(Afi, Safi); 4] = [
            (Afi::Ipv4, Safi::Unicast),
            (Afi::Ipv6, Safi::Unicast),
            (Afi::Ipv4, Safi::MplsVpn),
            (Afi::Ipv6, Safi::MplsVpn),
        ];
        let mut totals = [0usize; 4];
        for counts in self.source_counts.values() {
            for (total, n) in totals.iter_mut().zip(counts) {
                *total += n;
            }
        }
        let own = self.source_counts.get(&member).copied().unwrap_or_default();
        // RTC group: the VPN slots come from the maintained per-member
        // counters (Φ-filtered), not the table synthesis.
        let rtc_vpn = self.rtc_negotiated().then(|| {
            self.vpn_member_counts
                .get(&member)
                .copied()
                .unwrap_or([0; 2])
        });
        FAMILIES
            .iter()
            .enumerate()
            .filter_map(|(slot, &family)| {
                let count = match (slot, rtc_vpn) {
                    (2 | 3, Some(counts)) => counts[slot - 2].max(0).unsigned_abs(),
                    _ => totals[slot].saturating_sub(own[slot]) as u64,
                };
                (count > 0).then_some((family, count))
            })
            .collect()
    }

    /// Snapshot of `member`'s advertised unicast view (table minus
    /// own-sourced) — the baseline for a regroup's one-shot diff.
    fn member_view_snapshot(&self, member: IpAddr) -> FxHashMap<(Prefix, u32), Route> {
        self.table
            .iter()
            .filter(|route| route.peer != member)
            .map(|route| ((route.prefix, route.path_id), route.clone()))
            .collect()
    }

    /// VPN sibling of [`Self::member_view_snapshot`], filtered by the
    /// member's Φ at snapshot time — the true advertised set (design
    /// §2.4). Empty when the group does not stage VPN (the substrate's
    /// VPN maps stay unused).
    fn member_vpn_view_snapshot(
        &self,
        member: IpAddr,
        filter: Option<&RtcMembership>,
    ) -> FxHashMap<VpnRouteKey, VpnRibRoute> {
        self.table
            .iter_vpn()
            .filter(|route| route.peer != member && rt_passes(filter, route))
            .map(|route| (route.nlri.key(), route.clone()))
            .collect()
    }

    /// Refresh the persistent group-verdict denial set for one staging
    /// pass: entries for staged prefixes are replaced by the pass's
    /// denials (same transition scope as the per-peer path's
    /// `update_policy_filtered_routes_for_prefixes`).
    fn record_policy_filtered(
        &mut self,
        staged: &HashSet<Prefix>,
        current: &[(PolicyFilteredRouteKey, Option<String>)],
    ) {
        self.policy_filtered
            .retain(|key, _| !staged.contains(&key.prefix));
        self.policy_filtered.extend(current.iter().cloned());
    }

    /// The member's view of the group-verdict denial set, restamped
    /// with the member as target and restricted to `prefixes` (the
    /// pass's evaluation scope). The member's own-sourced denials are
    /// excluded — the per-peer path's split horizon returns before the
    /// policy evaluation for those.
    pub(in crate::manager) fn policy_filtered_for_member<'a>(
        &'a self,
        member: IpAddr,
        prefixes: &'a HashSet<Prefix>,
    ) -> impl Iterator<Item = PolicyFilteredRouteKey> + 'a {
        self.policy_filtered
            .keys()
            .filter(move |key| key.source_peer != member && prefixes.contains(&key.prefix))
            .map(move |key| PolicyFilteredRouteKey {
                target_peer: member,
                ..*key
            })
    }
}

impl RibManager {
    /// The group id a registered peer is a member of, if any.
    pub(in crate::manager) fn grouped_member_of(&self, peer: IpAddr) -> Option<usize> {
        match self.update_groups.members.get(&peer) {
            Some(GroupMembership::Grouped(id)) => Some(*id),
            _ => None,
        }
    }

    /// Mark a peer's outbound channel dirty for the resync timer, and —
    /// for a grouped member — flag it in its group so tombstone
    /// maintenance starts. Every `dirty_peers` insertion site routes
    /// through here.
    pub(in crate::manager) fn mark_outbound_dirty(&mut self, peer: IpAddr) {
        self.dirty_peers.insert(peer);
        if let Some(gid) = self.grouped_member_of(peer)
            && let Some(group) = self.group_ribs.get_mut(&gid)
        {
            group.dirty_members.insert(peer);
        }
    }

    /// Re-derive the withdrawal-residue gauge: group tombstones
    /// (unicast + VPN) plus per-member pending extra withdraws. Called
    /// from EVERY residue mutation site — growth and clear alike, never
    /// behind a clear guard — so a soak slope-gate on the metric can
    /// actually fail (the gate-metric rule). O(groups +
    /// members-with-residue) integer sums over small maps.
    pub(in crate::manager) fn refresh_group_residue_gauge(&self) {
        let residue = self
            .group_ribs
            .values()
            .map(|group| group.tombstones.len() + group.vpn_tombstones.len())
            .sum::<usize>()
            + self
                .pending_extra_withdraws
                .values()
                .map(|extras| extras.unicast.len() + extras.vpn.len())
                .sum::<usize>();
        self.metrics
            .set_update_group_residue_entries(i64::try_from(residue).unwrap_or(i64::MAX));
    }

    /// A member's resync succeeded (or provably had nothing to send):
    /// drop its regroup residue and its group dirty flag; the last
    /// dirty member syncing clears the tombstones. Also the drain
    /// point for a peer on the per-peer path whose residue rode a
    /// grouped→ungrouped move — the group half is a no-op for it.
    /// Callers must have emitted the pending extra withdraws (or shown
    /// them empty/retained) before calling: this drops them.
    pub(in crate::manager) fn clear_grouped_member_synced(&mut self, peer: IpAddr) {
        self.pending_regroup_baseline.remove(&peer);
        self.pending_extra_withdraws.remove(&peer);
        // A completed resync leaves the member advertising exactly the
        // Φ-filtered table — the seam where the incremental per-member
        // VPN counters (which may have drifted across the dirty window)
        // are made exact again.
        let filter = self.member_rt_filter(peer);
        if let Some(gid) = self.grouped_member_of(peer)
            && let Some(group) = self.group_ribs.get_mut(&gid)
        {
            group.recompute_vpn_member_counts(peer, filter.as_ref());
            group.dirty_members.remove(&peer);
            if group.dirty_members.is_empty() {
                group.tombstones.clear();
                group.vpn_tombstones.clear();
            }
        }
        self.refresh_group_residue_gauge();
    }

    /// Whether `peer` is a grouped member whose VPN advertised state is
    /// group-owned (member of a group that stages VPN — RTC groups
    /// included since v2 slice 2).
    pub(in crate::manager) fn vpn_grouped_member_of(&self, peer: IpAddr) -> Option<usize> {
        let gid = self.grouped_member_of(peer)?;
        self.group_ribs
            .get(&gid)
            .is_some_and(GroupRibOut::stages_vpn)
            .then_some(gid)
    }

    /// Whether `peer`'s VPN advertised state is group-owned *whenever
    /// the peer is grouped*: VPN sendable. Pure function of the
    /// session's (fixed) sendable set, so it answers
    /// membership-transition seams before the destination group exists.
    fn peer_vpn_groupable(&self, peer: IpAddr) -> bool {
        self.peer_sendable_families
            .get(&peer)
            .is_some_and(|families| families.iter().any(|&(_, safi)| safi == Safi::MplsVpn))
    }

    /// A grouped member's Φ — the RFC 4684 VPN filter resolved from its
    /// RT membership (`Some` iff the peer negotiated SAFI 132, absent
    /// membership ⇒ strict empty; the [`Self::rtc_vpn_filter`] rule).
    pub(in crate::manager) fn member_rt_filter(&self, peer: IpAddr) -> Option<RtcMembership> {
        self.rtc_vpn_filter(peer, self.peer_sendable_families.get(&peer))
    }

    /// Run the shared staging pass for every live group over the pass's
    /// changed prefixes. Deltas are committed to the group tables here;
    /// the per-peer loop emits them per member via the source-flip
    /// matrix. `memo` is the pass-scoped export memo shared with the
    /// ungrouped fallback staging.
    pub(in crate::manager) fn stage_update_groups(
        &mut self,
        best_changed: &HashSet<Prefix>,
        memo: &mut super::distribution::ExportMemo,
    ) -> HashMap<usize, GroupStageOutput> {
        let mut staged = HashMap::new();
        if best_changed.is_empty() || self.group_ribs.is_empty() {
            return staged;
        }
        let gids: Vec<usize> = self.group_ribs.keys().copied().collect();
        for gid in gids {
            let mut out = self.stage_group_prefixes(gid, best_changed, memo);
            // Built here (the fanout path) and not inside the staging
            // pass: `join_group`'s table-build pass discards its output.
            out.build_shared_emit();
            staged.insert(gid, out);
        }
        staged
    }

    /// One shared export-tail pass for `gid` over `prefixes`, reusing
    /// `distribute_single_best_prefix` with split horizon lifted out
    /// (`ExportTarget::Group`) and the group table as the diff baseline
    /// — the SAME body as the per-peer path, parameterized, never
    /// copied (design risk 1). Deltas are committed before returning;
    /// tombstones extend when a member is already dirty.
    fn stage_group_prefixes(
        &mut self,
        gid: usize,
        prefixes: &HashSet<Prefix>,
        memo: &mut super::distribution::ExportMemo,
    ) -> GroupStageOutput {
        let mut out = GroupStageOutput::default();
        let mut labeled_filtered: Vec<(PolicyFilteredRouteKey, Option<String>)> = Vec::new();
        {
            let Some(group) = self.group_ribs.get(&gid) else {
                return out;
            };
            // `share()`, not `clone()`: evaluations through the group
            // handle must land in the installed chain's ADR-0096 term
            // hit counters, exactly like the per-peer path's handle.
            let chain = group.export_chain.as_ref().map(PolicyChain::share);
            let mut announce: Vec<Route> = Vec::new();
            let mut withdraw: Vec<(Prefix, u32)> = Vec::new();
            let mut nh_flags: Vec<Option<NextHopAction>> = Vec::new();
            let mut filtered: Vec<PolicyFilteredRouteKey> = Vec::new();
            for prefix in prefixes {
                let old_source = group.table.get(prefix, 0).map(|r| r.peer);
                let mut target = super::distribution::ExportTarget::Group {
                    evals: &mut out.evals,
                };
                Self::distribute_single_best_prefix(
                    &self.loc_rib,
                    &group.table,
                    &self.peer_is_rr_client,
                    prefix,
                    &mut target,
                    group.is_ebgp,
                    group.is_rr_client,
                    self.cluster_id,
                    Some(&group.sendable),
                    Some(&group.llgr),
                    chain.as_ref(),
                    None, // ORF disqualifies from grouping — never present here
                    memo,
                    &mut announce,
                    &mut withdraw,
                    &mut nh_flags,
                    &mut filtered,
                    false,
                );
                // Single-best stages at most one evaluation per prefix;
                // its terminal-policy label tags the staged entry (or
                // the denial residue) for join-time counter replay.
                let label = out.evals.take_last().and_then(|(label, _, _)| label);
                for (route, nh) in announce.drain(..).zip(nh_flags.drain(..)) {
                    out.deltas.push(GroupDelta {
                        prefix: *prefix,
                        path_id: route.path_id,
                        new: Some((route, nh)),
                        old_source,
                        policy_label: label.clone(),
                    });
                }
                for (p, path_id) in withdraw.drain(..) {
                    out.deltas.push(GroupDelta {
                        prefix: p,
                        path_id,
                        new: None,
                        old_source,
                        policy_label: None,
                    });
                }
                labeled_filtered.extend(filtered.drain(..).map(|key| (key, label.clone())));
            }
        }
        let group = self
            .group_ribs
            .get_mut(&gid)
            .expect("group staged above still exists");
        for delta in &out.deltas {
            group.apply_delta(delta);
        }
        group.record_policy_filtered(prefixes, &labeled_filtered);
        if !group.dirty_members.is_empty() {
            let withdrawn: Vec<(Prefix, u32)> = out.withdrawn_keys().collect();
            group.tombstones.extend(withdrawn);
            // A member ALREADY dirty when a source flip stages onto it
            // never reaches the per-member matrix (its pass takes the
            // resync arm), so its member-scoped withdraw of the displaced
            // route would be lost: the key stays IN the table (invisible
            // to tombstones) and the resync announces table ∖ own-sourced.
            // Record it as an extra (over-)withdraw at staging; the
            // resync's `member_retains` guard drops it if the source
            // flips back before the resync runs.
            let dirty: Vec<IpAddr> = group.dirty_members.iter().copied().collect();
            for member in dirty {
                let lost: Vec<(Prefix, u32)> = out.member_scoped_withdraws(member).collect();
                if !lost.is_empty() {
                    self.pending_extra_withdraws
                        .entry(member)
                        .or_default()
                        .unicast
                        .extend(lost);
                }
            }
            self.refresh_group_residue_gauge();
        }
        out
    }

    /// Run the shared VPN staging pass for every VPN-staging group over
    /// the pass's changed RD+prefix identities. Deltas are committed to
    /// the group tables here; `recompute_and_distribute_vpn` emits them
    /// per member via the RT-pass source-flip matrix (Φ applied at emit
    /// for RTC-negotiated groups).
    pub(in crate::manager) fn stage_vpn_update_groups(
        &mut self,
        changed: &HashSet<VpnRouteKey>,
    ) -> HashMap<usize, VpnGroupStageOutput> {
        let mut staged = HashMap::new();
        if changed.is_empty() || self.group_ribs.is_empty() {
            return staged;
        }
        let gids: Vec<usize> = self
            .group_ribs
            .iter()
            .filter(|(_, group)| group.stages_vpn())
            .map(|(gid, _)| *gid)
            .collect();
        for gid in gids {
            staged.insert(gid, self.stage_group_vpn_keys(gid, changed));
        }
        staged
    }

    /// One shared VPN export-tail pass for `gid` over `keys`, reusing
    /// `stage_vpn_routes`'s single-best body with split horizon lifted
    /// out (`ExportTarget::Group`) and the group table's VPN maps as the
    /// diff baseline — the SAME body as the per-peer path, parameterized,
    /// never copied (design risk 1). Deltas are committed before
    /// returning; VPN tombstones extend when a member is already dirty.
    fn stage_group_vpn_keys(
        &mut self,
        gid: usize,
        keys: &HashSet<VpnRouteKey>,
    ) -> VpnGroupStageOutput {
        let mut out = VpnGroupStageOutput::default();
        let mut denials: Vec<(VpnRouteKey, VpnDenialRecord)> = Vec::new();
        {
            let Some(group) = self.group_ribs.get(&gid) else {
                return out;
            };
            // `share()`, not `clone()` — ADR-0096 term hit counters, as
            // in `stage_group_prefixes`.
            let chain = group.export_chain.as_ref().map(PolicyChain::share);
            let mut announce: Vec<VpnRibRoute> = Vec::new();
            let mut withdraw: Vec<VpnRibRouteKey> = Vec::new();
            // Reused single-key set: the staging body iterates a key set,
            // but the delta needs per-key `old` capture and eval labels.
            let mut key_set: HashSet<VpnRouteKey> = HashSet::with_capacity(1);
            for key in keys {
                key_set.clear();
                key_set.insert(*key);
                let mut target = super::distribution::ExportTarget::Group {
                    evals: &mut out.evals,
                };
                Self::stage_vpn_routes(
                    &self.loc_rib,
                    &self.ribs,
                    &group.table,
                    &self.peer_is_rr_client,
                    &key_set,
                    &mut target,
                    group.is_ebgp,
                    group.is_rr_client,
                    self.cluster_id,
                    Some(&group.sendable),
                    Some(&group.llgr),
                    // RT gate deferred to member emit: Φ is per-member
                    // state, applied by the RT-pass matrix (the delta
                    // carries `old` for exactly that).
                    None,
                    None, // ORR disqualifies from grouping
                    0,    // Add-Path send disqualifies from grouping
                    &[],
                    chain.as_ref(),
                    &mut announce,
                    &mut withdraw,
                    false,
                );
                // Single-best stages at most one eval per key: a Permit
                // labels the staged entry; a Deny lands in the persistent
                // denial residue (join-time counter replay).
                let last = out.evals.take_last();
                let label = match &last {
                    Some((label, PolicyAction::Permit, _)) => label.clone(),
                    _ => None,
                };
                if let Some((label, PolicyAction::Deny, source)) = last {
                    // The evaluated route is the Loc-RIB best (group
                    // targets never carry ORR); its RTs let an RTC
                    // member's join replay Φ-gate the denial.
                    let rts = self
                        .loc_rib
                        .get_vpn(key)
                        .map(|best| best.extended_communities().to_vec())
                        .unwrap_or_default();
                    denials.push((*key, (source, label, rts)));
                }
                if announce.is_empty() && withdraw.is_empty() {
                    continue;
                }
                // Prior staged entry, cloned before commit — one clone
                // per delta, total (slice 2's Φ(old) input).
                let old = group
                    .table
                    .get_vpn(&VpnRibRouteKey {
                        nlri_key: *key,
                        path_id: 0,
                    })
                    .cloned();
                for route in announce.drain(..) {
                    out.deltas.push(VpnGroupDelta {
                        key: *key,
                        new: Some(route),
                        old: old.clone(),
                        policy_label: label.clone(),
                    });
                }
                for rib_key in withdraw.drain(..) {
                    debug_assert_eq!(rib_key.path_id, 0, "group table stages path 0 only");
                    out.deltas.push(VpnGroupDelta {
                        key: *key,
                        new: None,
                        old: old.clone(),
                        policy_label: None,
                    });
                }
            }
        }
        let group = self
            .group_ribs
            .get_mut(&gid)
            .expect("group staged above still exists");
        for delta in &out.deltas {
            group.apply_vpn_delta(delta);
        }
        // Denial-residue transition scope: this pass's keys replace their
        // prior records (the `record_policy_filtered` shape).
        group.vpn_policy_denied.retain(|key, _| !keys.contains(key));
        group.vpn_policy_denied.extend(denials);
        if !group.dirty_members.is_empty() {
            group
                .vpn_tombstones
                .extend(out.deltas.iter().filter(|d| d.new.is_none()).map(|d| d.key));
            self.refresh_group_residue_gauge();
        }
        out
    }

    /// Unicast portion of a grouped member's resync update, assembled
    /// from the group table with NO policy re-evaluation:
    ///
    /// - plain dirty: announce the full table minus own-sourced,
    ///   withdraw `tombstones ∖ still-retained` (over-withdraw is the
    ///   safe direction — the member's missed sends are unknown);
    /// - regroup (baseline present): one-shot diff — announce entries
    ///   not `routes_equal` to the baseline, withdraw baseline keys the
    ///   member no longer retains;
    /// - force-only (RFC 8326 `GShut` refresh): re-announce everything,
    ///   bypassing the equality diff, withdraw nothing.
    #[expect(
        clippy::too_many_arguments,
        reason = "the resync assembly takes the member's full pending-withdraw context"
    )]
    pub(in crate::manager) fn assemble_group_resync(
        group: &GroupRibOut,
        member: IpAddr,
        is_dirty: bool,
        is_force: bool,
        baseline: Option<&FxHashMap<(Prefix, u32), Route>>,
        extras: Option<&HashSet<(Prefix, u32)>>,
        announce: &mut Vec<Route>,
        withdraw: &mut Vec<(Prefix, u32)>,
        nh_override_flags: &mut Vec<Option<NextHopAction>>,
    ) {
        for route in group.table.iter() {
            if route.peer == member {
                continue;
            }
            let key = (route.prefix, route.path_id);
            if !is_force
                && let Some(base) = baseline
                && base.get(&key).is_some_and(|old| routes_equal(old, route))
            {
                continue;
            }
            nh_override_flags.push(group.nh_override(key));
            announce.push(route.clone());
        }
        // A key the member still retains (staged, not own-sourced) must
        // not be withdrawn — everything else in the candidate sets is a
        // safe (possibly spurious) withdraw.
        let member_retains = |key: &(Prefix, u32)| {
            group
                .table
                .get(&key.0, key.1)
                .is_some_and(|route| route.peer != member)
        };
        let mut keys: HashSet<(Prefix, u32)> = HashSet::new();
        if let Some(base) = baseline {
            keys.extend(base.keys().filter(|key| !member_retains(key)));
        }
        if is_dirty {
            keys.extend(group.tombstones.iter().filter(|key| !member_retains(key)));
        }
        if let Some(extra) = extras {
            keys.extend(extra.iter().filter(|key| !member_retains(key)));
        }
        withdraw.extend(keys);
    }

    /// VPN portion of a grouped member's resync update — the VPN sibling
    /// of [`Self::assemble_group_resync`], same three shapes (plain
    /// dirty / regroup one-shot diff / force), assembled from the group
    /// table's VPN maps with NO policy re-evaluation, under the member's
    /// CURRENT Φ (`filter`). Only called for groups that stage VPN.
    ///
    /// The Φ dimension (design §2.4): announce = table entries passing
    /// `pass_m`, and retention is Φ-aware (a staged key failing Φ is
    /// NOT retained). A membership delta missed while dirty is healed
    /// through `extras`: the Φ-write seam records the keys leaving Φ as
    /// extra (over-)withdraws — exact, instead of the design's blanket
    /// failing-Φ withdraw term, which would put spurious withdraws on
    /// clean regroup diffs too (spurious withdraws are RFC 4271 no-ops,
    /// but the regroup one-shot diff is held to exact-stream parity).
    #[expect(
        clippy::too_many_arguments,
        reason = "the resync assembly takes the member's full pending-withdraw context"
    )]
    pub(in crate::manager) fn assemble_group_vpn_resync(
        group: &GroupRibOut,
        member: IpAddr,
        filter: Option<&RtcMembership>,
        is_dirty: bool,
        is_force: bool,
        baseline: Option<&FxHashMap<VpnRouteKey, VpnRibRoute>>,
        extras: Option<&HashSet<VpnRouteKey>>,
        vpn_announce: &mut Vec<VpnRibRoute>,
        vpn_withdraw: &mut Vec<VpnRibRouteKey>,
    ) {
        for route in group.table.iter_vpn() {
            if route.peer == member || !rt_passes(filter, route) {
                continue;
            }
            if !is_force
                && let Some(base) = baseline
                && base
                    .get(&route.nlri.key())
                    .is_some_and(|old| vpn_routes_equal(old, route))
            {
                continue;
            }
            vpn_announce.push(route.clone());
        }
        let member_retains = |key: &VpnRouteKey| {
            group
                .table
                .get_vpn(&VpnRibRouteKey {
                    nlri_key: *key,
                    path_id: 0,
                })
                .is_some_and(|route| route.peer != member && rt_passes(filter, route))
        };
        let mut keys: HashSet<VpnRouteKey> = HashSet::new();
        if let Some(base) = baseline {
            keys.extend(base.keys().filter(|key| !member_retains(key)));
        }
        if is_dirty {
            keys.extend(
                group
                    .vpn_tombstones
                    .iter()
                    .filter(|key| !member_retains(key)),
            );
        }
        if let Some(extra) = extras {
            keys.extend(extra.iter().filter(|key| !member_retains(key)));
        }
        vpn_withdraw.extend(keys.into_iter().map(|key| VpnRibRouteKey {
            nlri_key: key,
            path_id: 0,
        }));
    }

    /// The membership-delta path for a grouped VPN member whose Φ
    /// changed (design §2.3, the RTC hard part): ONE walk of the group
    /// VPN table — old-Φ vs new-Φ per entry — emitting a member-scoped
    /// announce/withdraw delta. ZERO policy evaluations, the table
    /// untouched (it is a pure function of (Loc-RIB, group key); Φ is
    /// member state and cannot touch it by construction). Wire-
    /// equivalent to the per-peer dirty restage, computed directly.
    ///
    /// Called ONLY from [`RibManager::set_rt_membership`] — the single
    /// Φ-write function (design risk 1).
    pub(in crate::manager) fn apply_rtc_membership_delta_to_grouped_member(
        &mut self,
        peer: IpAddr,
        gid: usize,
        old: &RtcMembership,
        new: &RtcMembership,
    ) {
        let mut vpn_announce: Vec<VpnRibRoute> = Vec::new();
        let mut vpn_withdraw: Vec<VpnRibRouteKey> = Vec::new();
        let mut count_delta = [0i64; 2];
        let mut permit_rows: Vec<(Option<String>, PolicyAction, u64)> = Vec::new();
        // A dirty member cannot take the wire delta (its advertised
        // state is behind); its pending resync announces the Φ-passing
        // table under CURRENT Φ, so only the keys LEAVING Φ need a
        // record — they ride the existing extra-(over-)withdraw residue
        // (exact heal, no blanket over-withdraw; the resync's
        // `member_retains` guard drops any key that re-enters Φ before
        // it runs).
        let is_dirty = self
            .group_ribs
            .get(&gid)
            .is_some_and(|group| group.dirty_members.contains(&peer));
        {
            let Some(group) = self.group_ribs.get(&gid) else {
                return;
            };
            for route in group.table.iter_vpn() {
                if route.peer == peer {
                    continue;
                }
                let rts = route.extended_communities();
                match (old.matches_any(rts), new.matches_any(rts)) {
                    (false, true) if !is_dirty => {
                        // Newly passing: announce the staged route
                        // verbatim; the per-peer restage would record a
                        // permit eval for it — replay from the staged
                        // label (the join-replay trick; still-passing
                        // keys deliberately record nothing, the
                        // documented counter deviation).
                        let key = route.nlri.key();
                        count_delta[GroupRibOut::vpn_count_slot(&key) - 2] += 1;
                        let label = group.vpn_staged_labels.get(&key).cloned().unwrap_or(None);
                        bump_eval_row(&mut permit_rows, label.as_ref(), PolicyAction::Permit);
                        vpn_announce.push(route.clone());
                    }
                    (true, false) => {
                        let key = route.nlri.key();
                        count_delta[GroupRibOut::vpn_count_slot(&key) - 2] -= 1;
                        vpn_withdraw.push(VpnRibRouteKey {
                            nlri_key: key,
                            path_id: 0,
                        });
                    }
                    _ => {}
                }
            }
        }
        if is_dirty {
            if !vpn_withdraw.is_empty() {
                self.pending_extra_withdraws
                    .entry(peer)
                    .or_default()
                    .vpn
                    .extend(vpn_withdraw.iter().map(|key| key.nlri_key));
                self.refresh_group_residue_gauge();
            }
            return;
        }
        if vpn_announce.is_empty() && vpn_withdraw.is_empty() {
            return;
        }
        if let Some(group) = self.group_ribs.get_mut(&gid) {
            // Optimistic: a failed send marks the member dirty and the
            // resync recompute restores exactness.
            group.apply_vpn_member_count_delta(peer, count_delta);
        }
        let withdraw_keys: Vec<VpnRouteKey> = vpn_withdraw.iter().map(|key| key.nlri_key).collect();
        if self.try_send_and_commit_outbound_update(
            peer,
            vec![].into(),
            vec![].into(),
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vpn_announce,
            vpn_withdraw,
            vec![],
            vec![],
            vec![],
            vec![],
        ) {
            self.bump_export_counters(peer, &permit_rows);
        } else {
            warn!(%peer, "outbound channel full — RTC membership delta deferred to resync");
            // The v1 dirty machinery takes over: the member's resync
            // announces the Φ-passing table; the narrow's withdraws
            // ride the extra-withdraw residue.
            self.mark_outbound_dirty(peer);
            self.pending_extra_withdraws
                .entry(peer)
                .or_default()
                .vpn
                .extend(withdraw_keys);
            self.refresh_group_residue_gauge();
        }
    }

    /// Bump a member's export-policy counters by the group verdict:
    /// `totals − own-sourced` per (policy, action), as integer adds —
    /// identical totals to the per-peer path, which skips the eval for
    /// routes the target itself sourced (split horizon precedes the
    /// policy check).
    pub(in crate::manager) fn apply_group_policy_counters(
        &mut self,
        peer: IpAddr,
        evals: &GroupEvalAccumulator,
    ) {
        if evals.totals.is_empty() {
            return;
        }
        let own = evals.per_source.get(&peer);
        let rows: Vec<(Option<String>, PolicyAction, u64)> = evals
            .totals
            .iter()
            .map(|(policy, action, total)| {
                let own_n = own
                    .and_then(|rows| {
                        rows.iter()
                            .find(|(p, a, _)| a == action && p == policy)
                            .map(|(_, _, n)| *n)
                    })
                    .unwrap_or(0);
                (policy.clone(), *action, total.saturating_sub(own_n))
            })
            .collect();
        self.bump_export_counters(peer, &rows);
    }

    /// Reconstruct a joining member's export counters from the group's
    /// staged residue: one permit per replayed table entry (labelled by
    /// its retained terminal policy), one deny per persistent denial —
    /// own-sourced entries excluded on both sides, exactly what the
    /// per-peer initial-dump staging would have recorded, without
    /// re-running policy. A route-refresh replay passes its `family` so
    /// only the refreshed family's entries count (the per-peer path
    /// re-evaluates only that family).
    pub(in crate::manager) fn apply_group_join_counters(
        &mut self,
        peer: IpAddr,
        gid: usize,
        family: Option<(Afi, Safi)>,
    ) {
        // The member's Φ: the per-peer path's RT gate precedes the policy
        // evaluation, so an RT-failed entry records NO eval — the replay
        // must count only Φ-passing permits and denials (design §2.4).
        let vpn_filter = self.rtc_vpn_filter(peer, self.peer_sendable_families.get(&peer));
        let mut rows: Vec<(Option<String>, PolicyAction, u64)> = Vec::new();
        {
            let Some(group) = self.group_ribs.get(&gid) else {
                return;
            };
            let mut bump = |policy: &Option<String>, action: PolicyAction| {
                if let Some((_, _, n)) = rows
                    .iter_mut()
                    .find(|(p, a, _)| *a == action && p == policy)
                {
                    *n += 1;
                } else {
                    rows.push((policy.clone(), action, 1));
                }
            };
            let in_family =
                |prefix: &Prefix| family.is_none_or(|f| super::helpers::prefix_family(prefix) == f);
            for route in group.table.iter() {
                if route.peer == peer || !in_family(&route.prefix) {
                    continue;
                }
                let label = group
                    .staged_labels
                    .get(&(route.prefix, route.path_id))
                    .cloned()
                    .unwrap_or(None);
                bump(&label, PolicyAction::Permit);
            }
            for (key, label) in &group.policy_filtered {
                if key.source_peer == peer || !in_family(&key.prefix) {
                    continue;
                }
                bump(label, PolicyAction::Deny);
            }
            // VPN dimension (only staged for non-RTC groups): permits
            // from the staged labels, denies from the denial residue —
            // own-sourced excluded on both sides (the per-peer path's
            // split horizon returns before the policy evaluation).
            let in_vpn_family = |key: &VpnRouteKey| {
                family.is_none_or(|f| {
                    let afi = match key.prefix.family() {
                        VpnAddressFamily::V4 => Afi::Ipv4,
                        VpnAddressFamily::V6 => Afi::Ipv6,
                    };
                    (afi, Safi::MplsVpn) == f
                })
            };
            for route in group.table.iter_vpn() {
                if route.peer == peer
                    || !in_vpn_family(&route.nlri.key())
                    || !rt_passes(vpn_filter.as_ref(), route)
                {
                    continue;
                }
                let label = group
                    .vpn_staged_labels
                    .get(&route.nlri.key())
                    .cloned()
                    .unwrap_or(None);
                bump(&label, PolicyAction::Permit);
            }
            for (key, (source, label, rts)) in &group.vpn_policy_denied {
                if *source == peer
                    || !in_vpn_family(key)
                    || !vpn_filter.as_ref().is_none_or(|m| m.matches_any(rts))
                {
                    continue;
                }
                bump(label, PolicyAction::Deny);
            }
        }
        self.bump_export_counters(peer, &rows);
    }

    /// Apply aggregated export-policy verdict rows to a peer's counters
    /// (integer adds — no per-(prefix × peer) prometheus lookups).
    fn bump_export_counters(&mut self, peer: IpAddr, rows: &[(Option<String>, PolicyAction, u64)]) {
        let stats = self.export_policy_stats.entry(peer).or_default();
        let peer_label = peer.to_string();
        for (policy, action, n) in rows {
            if *n == 0 {
                continue;
            }
            let action_label = match action {
                PolicyAction::Permit => {
                    stats.export_policy_routes_permitted =
                        stats.export_policy_routes_permitted.saturating_add(*n);
                    "permit"
                }
                PolicyAction::Deny => {
                    stats.export_policy_routes_denied =
                        stats.export_policy_routes_denied.saturating_add(*n);
                    "deny"
                }
            };
            self.metrics.record_policy_routes_by(
                &peer_label,
                policy.as_deref().unwrap_or("inline"),
                "export",
                action_label,
                *n,
            );
        }
    }

    /// Synthesized advertised-route list for a grouped peer (group
    /// table minus own-sourced); `None` for ungrouped peers.
    pub(in crate::manager) fn grouped_advertised_routes(&self, peer: IpAddr) -> Option<Vec<Route>> {
        let group = self.group_ribs.get(&self.grouped_member_of(peer)?)?;
        Some(
            group
                .table
                .iter()
                .filter(|route| route.peer != peer)
                .cloned()
                .collect(),
        )
    }

    /// Synthesized advertised-route count for a grouped peer; `None`
    /// for ungrouped peers.
    pub(in crate::manager) fn grouped_advertised_count(&self, peer: IpAddr) -> Option<usize> {
        self.group_ribs
            .get(&self.grouped_member_of(peer)?)
            .map(|group| group.advertised_count_for(peer))
    }

    /// Compute (or recompute) a registered peer's update-group
    /// membership from the fingerprint inputs already in hand, and run
    /// the membership lifecycle (design §4): join = lookup-or-create
    /// the group (building its table with one shared staging pass when
    /// new); leave = drop membership (last member drops the table);
    /// regroup = leave + join with a baseline snapshot of the member's
    /// old advertised view for the one-shot resync diff. Called at the
    /// session registration seam and the export-policy replacement seam
    /// (per-peer gRPC edits, ADR-0076 live-impact txns, SIGHUP rpol
    /// overlays). A key-stable recompute (content-equal chain
    /// reinstall) is a strict no-op.
    #[expect(
        clippy::too_many_lines,
        reason = "the membership lifecycle keeps every residue-carry rule at one seam"
    )]
    pub(super) fn recompute_update_group(&mut self, peer: IpAddr) {
        let membership = self.compute_update_group_membership(peer);
        let previous = self.update_groups.members.get(&peer).cloned();
        if previous.as_ref() == Some(&membership) {
            // Key-stable fast path: nothing moved, no regroup counted —
            // this is what keeps a 1000-peer txn installing
            // content-identical chains from shattering anything.
            return;
        }
        let prev_gid = match previous {
            Some(GroupMembership::Grouped(id)) => Some(id),
            _ => None,
        };
        let new_gid = match membership {
            GroupMembership::Grouped(id) => Some(id),
            _ => None,
        };
        self.update_groups.members.insert(peer, membership);
        // A regroup is an already-registered peer whose membership
        // moved; first registration doesn't count.
        if previous.is_some() {
            self.metrics.record_update_group_regroup();
        }
        if prev_gid != new_gid {
            // Whether the peer's VPN advertised state is group-owned
            // whenever it is grouped. Sendable families are fixed per
            // session, so this answers for source AND destination.
            let vpn_groupable = self.peer_vpn_groupable(peer);
            // Snapshot the member's currently-advertised view before the
            // move: the destination side diffs against it so only genuine
            // changes reach the wire (design §4 one-shot diff). First
            // registration has no view — the initial dump replays the
            // destination group table.
            // The member's Φ at snapshot time (a regroup never changes
            // Φ — it is keyed by peer, not group).
            let rt_filter = self.member_rt_filter(peer);
            let baseline: Option<RegroupBaseline> = match prev_gid {
                Some(gid) => {
                    let group = self.group_ribs.get(&gid);
                    let base = group.map(|g| RegroupBaseline {
                        unicast: g.member_view_snapshot(peer),
                        vpn: g.member_vpn_view_snapshot(peer, rt_filter.as_ref()),
                    });
                    // A member that leaves while dirty may have missed
                    // withdrawals; carry the group tombstones along as
                    // extra (over-)withdraws for the destination resync.
                    if let Some(g) = group
                        && g.dirty_members.contains(&peer)
                        && (!g.tombstones.is_empty() || !g.vpn_tombstones.is_empty())
                    {
                        let extras = self.pending_extra_withdraws.entry(peer).or_default();
                        extras.unicast.extend(g.tombstones.iter().copied());
                        extras.vpn.extend(g.vpn_tombstones.iter().copied());
                    }
                    base
                }
                None if previous.is_some() => Some(
                    self.adj_ribs_out
                        .get(&peer)
                        .map(|rib_out| RegroupBaseline {
                            unicast: rib_out
                                .iter()
                                .map(|route| ((route.prefix, route.path_id), route.clone()))
                                .collect(),
                            // VPN moves to group ownership only for a
                            // VPN-groupable peer; an RTC peer's VPN state
                            // stays per-peer and must not be captured.
                            vpn: if vpn_groupable {
                                rib_out
                                    .iter_vpn()
                                    .map(|route| (route.nlri.key(), route.clone()))
                                    .collect()
                            } else {
                                FxHashMap::default()
                            },
                        })
                        .unwrap_or_default(),
                ),
                None => None,
            };
            if let Some(gid) = prev_gid {
                self.leave_group(gid, peer);
            } else if previous.is_some() {
                // Moving off the per-peer path: the unicast (and, for a
                // VPN-groupable peer, VPN) advertised state becomes
                // group-owned (captured in the baseline); other families
                // stay per-peer.
                if let Some(rib_out) = self.adj_ribs_out.get_mut(&peer) {
                    rib_out.clear_unicast();
                    if vpn_groupable {
                        rib_out.clear_vpn();
                    }
                }
            }
            if let Some(gid) = new_gid {
                self.join_group(gid, peer);
            }
            match (baseline, new_gid) {
                // A member leaving a group DIRTY has a baseline that is
                // INTENDED state, not wire state: the group table
                // advances before the send that then fails, so the
                // snapshot can hold announces the member never received.
                // Using it for equality suppression would silently drop
                // those announces from the resync — an under-advertise
                // that nothing later heals (LAN-346). Keep only the
                // baseline's withdraw duty: ride its keys (plus any
                // retained baseline from an earlier unfinished regroup)
                // as extra (over-)withdraw residue — the resync's
                // retention guards filter them exactly — and let the
                // dirty resync take the suppression-free arm
                // (over-announce, the plain-dirty safe direction;
                // announces are idempotent). Applies to both grouped and
                // per-peer destinations: neither gets a baseline /
                // seeded Adj-RIB-Out to suppress against.
                (Some(base), _) if prev_gid.is_some() && self.dirty_peers.contains(&peer) => {
                    let extras = self.pending_extra_withdraws.entry(peer).or_default();
                    if let Some(prev) = self.pending_regroup_baseline.remove(&peer) {
                        extras.unicast.extend(prev.unicast.into_keys());
                        extras.vpn.extend(prev.vpn.into_keys());
                    }
                    extras.unicast.extend(base.unicast.into_keys());
                    extras.vpn.extend(base.vpn.into_keys());
                }
                (Some(mut base), Some(_)) => {
                    // A grouped member keeps no per-family record of its
                    // unicast/VPN wire state in `adj_ribs_out` (join clears
                    // it), so its `pending_regroup_baseline` entry is the
                    // ONLY record of what is on its wire. If the member's
                    // prior resync never committed (still dirty), that entry
                    // is the true wire state, while `base` is a snapshot of a
                    // group view the member was never advertised — UNION them
                    // (existing/wire values win on conflict) rather than blind
                    // overwrite. A blind overwrite drops wire keys absent from
                    // BOTH the new snapshot and the new group's table: they
                    // would never be withdrawn and leak as stale routes. One
                    // baseline covers unicast AND VPN, so this covers both.
                    if self.dirty_peers.contains(&peer)
                        && let Some(prev) = self.pending_regroup_baseline.remove(&peer)
                    {
                        base.unicast.extend(prev.unicast);
                        base.vpn.extend(prev.vpn);
                    }
                    self.pending_regroup_baseline.insert(peer, base);
                }
                (Some(mut base), None) => {
                    // Back on the per-peer path: seed Adj-RIB-Out with
                    // the old advertised view so the dirty resync diffs
                    // against it instead of re-flooding the table.
                    // Same union rule as the grouped arm above: a
                    // still-dirty leaver's retained baseline is the
                    // only record of its true wire state — fold it
                    // into the seed (wire values win on conflict) and
                    // consume the entry, or its keys could never be
                    // withdrawn from the per-peer path.
                    if self.dirty_peers.contains(&peer)
                        && let Some(prev) = self.pending_regroup_baseline.remove(&peer)
                    {
                        base.unicast.extend(prev.unicast);
                        base.vpn.extend(prev.vpn);
                    }
                    let loc_rib_len = self.loc_rib.len();
                    let rib_out = self
                        .adj_ribs_out
                        .entry(peer)
                        .or_insert_with(|| AdjRibOut::with_capacity(peer, loc_rib_len));
                    for route in base.unicast.into_values() {
                        rib_out.insert(route);
                    }
                    for route in base.vpn.into_values() {
                        rib_out.insert_vpn(route);
                    }
                }
                (None, _) => {}
            }
        }
        self.refresh_update_group_gauges();
        // The regroup carry (a dirty leaver's tombstones riding into
        // its extra withdraws) mutates residue on this path too.
        self.refresh_group_residue_gauge();
    }

    /// Add a member; a group seen for the first time snapshots its
    /// group-uniform staging inputs from the joining peer (all members
    /// are key-equal) and builds the shared table with one staging pass
    /// — the policy work every subsequent join replays for free.
    fn join_group(&mut self, gid: usize, peer: IpAddr) {
        if !self.group_ribs.contains_key(&gid) {
            let group = GroupRibOut::new(
                // `share()`, not `clone()`: the snapshot must keep
                // feeding the installed chain's ADR-0096 hit counters.
                self.export_policy_for(peer).map(PolicyChain::share),
                self.peer_is_ebgp.get(&peer).copied().unwrap_or(false),
                self.peer_is_rr_client.get(&peer).copied().unwrap_or(false),
                self.peer_sendable_families
                    .get(&peer)
                    .cloned()
                    .unwrap_or_default(),
                self.peer_advertised_llgr_families
                    .get(&peer)
                    .cloned()
                    .unwrap_or_default(),
                self.loc_rib.len(),
            );
            self.group_ribs.insert(gid, group);
            let prefixes: HashSet<Prefix> = self.loc_rib.iter().map(|r| r.prefix).collect();
            let mut memo = super::distribution::ExportMemo::default();
            // Deltas of the build passes are discarded: there are no
            // members yet, and the joining member replays the whole
            // table anyway.
            let _ = self.stage_group_prefixes(gid, &prefixes, &mut memo);
            if self
                .group_ribs
                .get(&gid)
                .is_some_and(GroupRibOut::stages_vpn)
            {
                let keys: HashSet<VpnRouteKey> =
                    self.loc_rib.iter_vpn().map(|r| r.nlri.key()).collect();
                if !keys.is_empty() {
                    let _ = self.stage_group_vpn_keys(gid, &keys);
                }
            }
        }
        // The joining member's advertised-count seed (RTC groups only):
        // the O(table) walk rides the join replay's existing cost.
        let filter = self.member_rt_filter(peer);
        if let Some(group) = self.group_ribs.get_mut(&gid) {
            group.members.insert(peer);
            group.recompute_vpn_member_counts(peer, filter.as_ref());
        }
    }

    fn leave_group(&mut self, gid: usize, peer: IpAddr) {
        let Some(group) = self.group_ribs.get_mut(&gid) else {
            return;
        };
        group.members.remove(&peer);
        group.vpn_member_counts.remove(&peer);
        group.dirty_members.remove(&peer);
        if group.dirty_members.is_empty() {
            group.tombstones.clear();
            group.vpn_tombstones.clear();
        }
        if group.members.is_empty() {
            self.group_ribs.remove(&gid);
        }
        self.refresh_group_residue_gauge();
    }

    /// Drop a departing peer's membership and group state (the
    /// `clear_outbound_peer_state` seam — `PeerDown`, `PeerDeleted`, GR
    /// teardown, and collision replacement all route through it).
    pub(super) fn remove_update_group_member(&mut self, peer: IpAddr) {
        if let Some(membership) = self.update_groups.members.remove(&peer) {
            if let GroupMembership::Grouped(gid) = membership {
                self.leave_group(gid, peer);
            }
            self.refresh_update_group_gauges();
        }
    }

    /// The fingerprint itself: disqualifiers first (design §1), then
    /// the group key from RIB-staging inputs.
    fn compute_update_group_membership(&mut self, peer: IpAddr) -> GroupMembership {
        // Differential-oracle hook: force every peer onto the per-peer
        // fallback path so identical scenarios can be compared grouped
        // vs ungrouped. Reuses the policy-peer-context reason label.
        #[cfg(test)]
        if self.test_force_ungrouped {
            return GroupMembership::PolicyPeerContext;
        }
        // ORF-receive negotiated ⇒ ungrouped from the start (the RFC
        // 5291 §6 gate never meets grouping). Read from the live
        // session record — `peer_orf_pending` drains as gates lift, so
        // it can't answer "was ORF negotiated" later in the session.
        let orf_negotiated = self
            .live_sessions
            .get(&peer)
            .and_then(|sessions| sessions.last())
            .is_some_and(|record| !record.negotiated_orf_recv.is_empty());
        let chain = self.export_policy_for(peer).cloned();
        let input = self.update_group_classifier_input(
            peer,
            chain.as_ref(),
            orf_negotiated || self.peer_orf_filters.contains_key(&peer),
        );
        let fingerprint = match classify_update_group(input) {
            UpdateGroupClassification::PolicyPeerContext => {
                return GroupMembership::PolicyPeerContext;
            }
            UpdateGroupClassification::AddPathSend => return GroupMembership::AddPathSend,
            UpdateGroupClassification::PerClientBest => return GroupMembership::PerClientBest,
            UpdateGroupClassification::OrrVantage => return GroupMembership::OrrVantage,
            UpdateGroupClassification::OrfInstalled => return GroupMembership::OrfInstalled,
            UpdateGroupClassification::Groupable(fingerprint) => fingerprint,
        };

        // Clone released before the &mut intern below; chains are small
        // and this runs at config/session-lifecycle frequency only.
        let chain_idx = chain
            .as_ref()
            .map(|chain| self.update_groups.intern_chain(chain));
        let key = GroupKey {
            chain: chain_idx,
            target_is_ebgp: fingerprint.target_is_ebgp,
            target_is_rr_client: fingerprint.target_is_rr_client,
            sendable_ipv4_unicast: fingerprint.sendable_ipv4_unicast,
            sendable_ipv6_unicast: fingerprint.sendable_ipv6_unicast,
            sendable_vpnv4: fingerprint.sendable_vpnv4,
            sendable_vpnv6: fingerprint.sendable_vpnv6,
            rtc_negotiated: fingerprint.rtc_negotiated,
            llgr_families: fingerprint.llgr_families,
        };
        GroupMembership::Grouped(self.update_groups.group_for(key))
    }

    fn update_group_classifier_input(
        &self,
        peer: IpAddr,
        chain: Option<&PolicyChain>,
        orf_installed: bool,
    ) -> UpdateGroupClassifierInput {
        let sendable = self.peer_sendable_families.get(&peer);
        let mut sendable_families = sendable
            .into_iter()
            .flatten()
            .map(|&(afi, safi)| (afi as u16, safi as u8))
            .collect::<Vec<_>>();
        sendable_families.sort_unstable();
        sendable_families.dedup();
        let mut llgr_families = self
            .peer_advertised_llgr_families
            .get(&peer)
            .into_iter()
            .flatten()
            .map(|&(afi, safi)| (afi as u16, safi as u8))
            .collect::<Vec<_>>();
        llgr_families.sort_unstable();
        llgr_families.dedup();
        UpdateGroupClassifierInput {
            policy_fingerprint: chain.map(|value| format!("{value:?}")),
            policy_provenance: chain.map(|value| value.groupability_provenance().to_string()),
            policy_requires_peer_context: chain.is_some_and(PolicyChain::requires_peer_context),
            target_is_ebgp: self.peer_is_ebgp.get(&peer).copied().unwrap_or(false),
            target_is_rr_client: self.peer_is_rr_client.get(&peer).copied().unwrap_or(false),
            sendable_families,
            llgr_families,
            add_path_send: self.peer_has_any_add_path_send(peer),
            per_client_best: self.peer_per_client_best.contains(&peer),
            orr_vantage: self.peer_orr_vantage.get(&peer).copied(),
            orf_installed,
        }
    }

    pub(super) fn handle_query_update_group_snapshot(
        &self,
        reply: tokio::sync::oneshot::Sender<UpdateGroupSnapshot>,
    ) {
        let mut peers = self
            .update_groups
            .members
            .iter()
            .map(|(&peer, membership)| {
                let chain = self.export_policy_for(peer);
                let orf_negotiated = self
                    .live_sessions
                    .get(&peer)
                    .and_then(|sessions| sessions.last())
                    .is_some_and(|record| !record.negotiated_orf_recv.is_empty());
                let input = self.update_group_classifier_input(
                    peer,
                    chain,
                    orf_negotiated || self.peer_orf_filters.contains_key(&peer),
                );
                UpdateGroupPeerSnapshot {
                    peer,
                    classification: classify_update_group(input.clone()),
                    input,
                    runtime_membership: membership.label(),
                }
            })
            .collect::<Vec<_>>();
        peers.sort_by_key(|row| match row.peer {
            IpAddr::V4(addr) => (0, addr.octets().to_vec()),
            IpAddr::V6(addr) => (1, addr.octets().to_vec()),
        });
        let _ = reply.send(UpdateGroupSnapshot { peers });
    }

    /// Re-derive every update-group gauge from the membership map.
    /// Registered peers are at most low-thousands and this runs only on
    /// lifecycle/config events, so a full recount beats incremental
    /// bookkeeping.
    fn refresh_update_group_gauges(&self) {
        let mut member_counts: HashMap<usize, i64> = HashMap::new();
        let mut fallback = 0i64;
        for membership in self.update_groups.members.values() {
            match membership {
                GroupMembership::Grouped(id) => *member_counts.entry(*id).or_default() += 1,
                _ => fallback += 1,
            }
        }
        self.metrics
            .set_update_groups(i64::try_from(member_counts.len()).unwrap_or(i64::MAX));
        self.metrics.set_update_group_fallback_peers(fallback);
        // Registry growth (LAN-311 observability, no eviction): both
        // vecs are append-only for the process lifetime, so the gauges
        // read as "distinct contents / keys ever seen" — the signal a
        // policy-content-churn deployment watches before the growth
        // costs memory. Every intern happens inside a membership
        // recompute, and every recompute/removal ends here.
        self.metrics.set_update_group_interned_chains(
            i64::try_from(self.update_groups.chains.len()).unwrap_or(i64::MAX),
        );
        self.metrics.set_update_group_keys(
            i64::try_from(self.update_groups.groups.len()).unwrap_or(i64::MAX),
        );
        for id in 0..self.update_groups.groups.len() {
            match member_counts.get(&id) {
                Some(count) => self
                    .metrics
                    .set_update_group_members(&id.to_string(), *count),
                None => self.metrics.remove_update_group_members(&id.to_string()),
            }
        }
    }

    /// TEST ONLY: answer `RibUpdate::TestQueryVpnAdvertised` — the
    /// peer's advertised VPN view recomputed from manager state, the
    /// oracle invariant checker's window (design §5): for a VPN-grouped
    /// member, `adv(m) = { e ∈ group table : e.peer ≠ m ∧ pass_m(e) }`
    /// under the member's CURRENT Φ; for everyone else, the per-peer
    /// Adj-RIB-Out VPN entries. Also cross-checks the incrementally
    /// maintained per-member VPN counters against the table recompute
    /// (the design §2.4 debug assertion).
    #[cfg(test)]
    pub(super) fn handle_test_query_vpn_advertised(
        &mut self,
        peer: IpAddr,
        reply: tokio::sync::oneshot::Sender<Vec<(String, IpAddr)>>,
    ) {
        let filter = self.member_rt_filter(peer);
        let view: Vec<(String, IpAddr)> = match self
            .vpn_grouped_member_of(peer)
            .and_then(|gid| self.group_ribs.get(&gid))
        {
            Some(group) => {
                // Counter invariant: incremental == recompute-from-table
                // whenever the member is in sync (a dirty window may
                // legitimately drift until its resync recompute).
                if group.rtc_negotiated() && !group.dirty_members.contains(&peer) {
                    debug_assert_eq!(
                        group
                            .vpn_member_counts
                            .get(&peer)
                            .copied()
                            .unwrap_or_default(),
                        group.vpn_member_counts_from_table(peer, filter.as_ref()),
                        "per-member VPN counters drifted from the table for {peer}"
                    );
                }
                group
                    .table
                    .iter_vpn()
                    .filter(|route| route.peer != peer && rt_passes(filter.as_ref(), route))
                    .map(|route| (format!("{:?}", route.nlri.key()), route.peer))
                    .collect()
            }
            None => self
                .adj_ribs_out
                .get(&peer)
                .map(|rib_out| {
                    rib_out
                        .iter_vpn()
                        .map(|route| (format!("{:?}", route.nlri.key()), route.peer))
                        .collect()
                })
                .unwrap_or_default(),
        };
        let _ = reply.send(view);
    }

    /// Answer `RibUpdate::QueryPeerUpdateGroup`: the membership label
    /// (`group:N` or the ungrouped reason), or empty for a peer with no
    /// outbound registration.
    pub(super) fn handle_query_peer_update_group(
        &mut self,
        peer: IpAddr,
        reply: tokio::sync::oneshot::Sender<String>,
    ) {
        let label = self
            .update_groups
            .membership(peer)
            .map(GroupMembership::label)
            .unwrap_or_default();
        let _ = reply.send(label);
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use rustbgpd_wire::{
        Ipv4Prefix, MplsLabelEntry, Origin, PathAttribute, RouteDistinguisher, VpnNlri, VpnPrefix,
    };

    use super::*;
    use crate::test_support::make_route;

    const MEMBER: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 9, 0, 1));
    const OTHER1: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 9, 0, 2));
    const OTHER2: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 9, 0, 3));

    fn prefix(n: u8) -> Prefix {
        Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 100, n, 0), 24))
    }

    fn route(p: Prefix, src: IpAddr) -> Route {
        let Prefix::V4(v4) = p else { unreachable!() };
        let IpAddr::V4(src4) = src else {
            unreachable!()
        };
        let mut route = make_route(v4, src4);
        route.peer = src;
        route
    }

    fn empty_group() -> GroupRibOut {
        GroupRibOut::new(
            None,
            false,
            true,
            vec![(Afi::Ipv4, Safi::Unicast)],
            vec![],
            0,
        )
    }

    fn announce_delta(p: Prefix, src: IpAddr, old: Option<IpAddr>) -> GroupDelta {
        GroupDelta {
            prefix: p,
            path_id: 0,
            new: Some((route(p, src), None)),
            old_source: old,
            policy_label: None,
        }
    }

    fn withdraw_delta(p: Prefix, old: Option<IpAddr>) -> GroupDelta {
        GroupDelta {
            prefix: p,
            path_id: 0,
            new: None,
            old_source: old,
            policy_label: None,
        }
    }

    /// Risk-2 exhaustive source-flip matrix: every combination of
    /// `{old_source} × {new source | withdraw}` for a fixed member,
    /// asserted against the per-peer-path reference semantics:
    ///
    /// - the member HAD the key iff an old entry existed with a source
    ///   other than the member (split horizon excluded own-sourced);
    /// - the member GETS the key iff the new entry exists with a source
    ///   other than the member;
    /// - expected announce ⇔ GETS; expected withdraw ⇔ HAD ∧ ¬GETS
    ///   (announce-replaces is BGP implicit withdraw).
    #[test]
    fn source_flip_matrix_exhaustive() {
        let old_sources = [None, Some(MEMBER), Some(OTHER1), Some(OTHER2)];
        // `None` = withdraw delta; `Some(src)` = announce sourced by src.
        let new_sources = [None, Some(MEMBER), Some(OTHER1), Some(OTHER2)];
        for old in old_sources {
            for new in new_sources {
                if new.is_none() && old.is_none() {
                    // A withdraw delta always has an old entry (the
                    // staging body only withdraws existing keys).
                    continue;
                }
                let p = prefix(1);
                let delta = match new {
                    Some(src) => announce_delta(p, src, old),
                    None => withdraw_delta(p, old),
                };
                let mut announce = Vec::new();
                let mut withdraw = Vec::new();
                let mut nh_flags = Vec::new();
                emit_group_deltas_for_member(
                    std::slice::from_ref(&delta),
                    MEMBER,
                    &mut announce,
                    &mut withdraw,
                    &mut nh_flags,
                );

                let member_had = old.is_some_and(|s| s != MEMBER);
                let member_gets = new.is_some_and(|s| s != MEMBER);
                let expect_announce = usize::from(member_gets);
                let expect_withdraw = usize::from(member_had && !member_gets);
                assert_eq!(
                    announce.len(),
                    expect_announce,
                    "announce mismatch for old={old:?} new={new:?}"
                );
                assert_eq!(
                    withdraw.len(),
                    expect_withdraw,
                    "withdraw mismatch for old={old:?} new={new:?}"
                );
                assert_eq!(
                    nh_flags.len(),
                    announce.len(),
                    "nh flags must stay aligned with announces"
                );
                if member_gets {
                    assert_eq!(announce[0].peer, new.unwrap());
                }
            }
        }
    }

    /// Dirty-member resync: full-table announce minus own-sourced;
    /// tombstones withdraw unless the member still retains the key
    /// (staged by another source). Over-withdrawing keys now staged by
    /// the member itself is the deliberate safe direction.
    #[test]
    fn dirty_resync_replays_table_and_tombstones() {
        let mut group = empty_group();
        let (k1, k2, k3, k4) = (prefix(1), prefix(2), prefix(3), prefix(4));
        group.apply_delta(&announce_delta(k1, OTHER1, None));
        group.apply_delta(&announce_delta(k2, MEMBER, None));
        group.apply_delta(&announce_delta(k4, MEMBER, None));
        group.tombstones.insert((k1, 0)); // retained via OTHER1 — no withdraw
        group.tombstones.insert((k3, 0)); // gone — withdraw
        group.tombstones.insert((k4, 0)); // member-sourced now — safe over-withdraw

        let mut announce = Vec::new();
        let mut withdraw = Vec::new();
        let mut nh_flags = Vec::new();
        RibManager::assemble_group_resync(
            &group,
            MEMBER,
            true,
            false,
            None,
            None,
            &mut announce,
            &mut withdraw,
            &mut nh_flags,
        );
        let announced: HashSet<Prefix> = announce.iter().map(|r| r.prefix).collect();
        assert_eq!(
            announced,
            HashSet::from([k1]),
            "own-sourced entries excluded"
        );
        let withdrawn: HashSet<(Prefix, u32)> = withdraw.into_iter().collect();
        assert_eq!(withdrawn, HashSet::from([(k3, 0), (k4, 0)]));
        assert_eq!(nh_flags.len(), announce.len());
    }

    /// Regroup one-shot diff: entries `routes_equal` to the baseline
    /// are suppressed, changed entries announce, baseline keys no
    /// longer retained withdraw — and `force` bypasses only the
    /// equality suppression.
    #[test]
    fn regroup_baseline_diff_and_force() {
        let mut group = empty_group();
        let (k1, k5, k6) = (prefix(1), prefix(5), prefix(6));
        group.apply_delta(&announce_delta(k1, OTHER1, None));
        group.apply_delta(&announce_delta(k6, OTHER2, None));

        let mut baseline: FxHashMap<(Prefix, u32), Route> = FxHashMap::default();
        baseline.insert((k1, 0), route(k1, OTHER1)); // unchanged — suppressed
        baseline.insert((k5, 0), route(k5, OTHER1)); // gone — withdraw
        baseline.insert((k6, 0), route(k6, OTHER1)); // source flipped — announce

        let mut announce = Vec::new();
        let mut withdraw = Vec::new();
        let mut nh_flags = Vec::new();
        RibManager::assemble_group_resync(
            &group,
            MEMBER,
            true,
            false,
            Some(&baseline),
            None,
            &mut announce,
            &mut withdraw,
            &mut nh_flags,
        );
        let announced: HashSet<Prefix> = announce.iter().map(|r| r.prefix).collect();
        assert_eq!(announced, HashSet::from([k6]));
        let withdrawn: HashSet<(Prefix, u32)> = withdraw.into_iter().collect();
        assert_eq!(withdrawn, HashSet::from([(k5, 0)]));

        // Force (GShut refresh): every retained entry re-announces.
        let mut announce = Vec::new();
        let mut withdraw = Vec::new();
        let mut nh_flags = Vec::new();
        RibManager::assemble_group_resync(
            &group,
            MEMBER,
            false,
            true,
            Some(&baseline),
            None,
            &mut announce,
            &mut withdraw,
            &mut nh_flags,
        );
        let announced: HashSet<Prefix> = announce.iter().map(|r| r.prefix).collect();
        assert_eq!(announced, HashSet::from([k1, k6]));
        let withdrawn: HashSet<(Prefix, u32)> = withdraw.into_iter().collect();
        assert_eq!(withdrawn, HashSet::from([(k5, 0)]));
    }

    /// Carried-over extra withdraws (a dirty member regrouping) emit
    /// unless the member retains the key in the new group.
    #[test]
    fn extra_withdraws_respect_retained_keys() {
        let mut group = empty_group();
        let (k1, k7) = (prefix(1), prefix(7));
        group.apply_delta(&announce_delta(k1, OTHER1, None));
        let extras: HashSet<(Prefix, u32)> = HashSet::from([(k1, 0), (k7, 0)]);

        let mut announce = Vec::new();
        let mut withdraw = Vec::new();
        let mut nh_flags = Vec::new();
        RibManager::assemble_group_resync(
            &group,
            MEMBER,
            true,
            false,
            None,
            Some(&extras),
            &mut announce,
            &mut withdraw,
            &mut nh_flags,
        );
        let withdrawn: HashSet<(Prefix, u32)> = withdraw.into_iter().collect();
        assert_eq!(
            withdrawn,
            HashSet::from([(k7, 0)]),
            "a key still retained (k1 via OTHER1) must not be withdrawn"
        );
    }

    fn vpn_key(n: u8) -> VpnRouteKey {
        VpnRouteKey {
            route_distinguisher: RouteDistinguisher([0, 0, 0xFD, 0xE8, 0, 0, 0, n]),
            prefix: VpnPrefix::v4(Ipv4Addr::new(10, 210, n, 0), 24).unwrap(),
        }
    }

    fn vpn_route(n: u8, src: IpAddr) -> VpnRibRoute {
        let key = vpn_key(n);
        VpnRibRoute {
            nlri: VpnNlri {
                labels: vec![MplsLabelEntry::try_new(100, 0, true).unwrap()],
                route_distinguisher: key.route_distinguisher,
                prefix: key.prefix,
            },
            next_hop: src,
            link_local_next_hop: None,
            peer: src,
            attributes: std::sync::Arc::new(vec![PathAttribute::Origin(Origin::Igp)]),
            received_at: std::time::Instant::now(),
            origin_type: crate::route::RouteOrigin::Ibgp,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
        }
    }

    fn vpn_announce_delta(n: u8, src: IpAddr, old: Option<IpAddr>) -> VpnGroupDelta {
        VpnGroupDelta {
            key: vpn_key(n),
            new: Some(vpn_route(n, src)),
            old: old.map(|peer| vpn_route(n, peer)),
            policy_label: None,
        }
    }

    fn vpn_withdraw_delta(n: u8, old: Option<IpAddr>) -> VpnGroupDelta {
        VpnGroupDelta {
            key: vpn_key(n),
            new: None,
            old: old.map(|peer| vpn_route(n, peer)),
            policy_label: None,
        }
    }

    /// Risk-2 exhaustive VPN source-flip matrix: every combination of
    /// `{old source} × {new source | withdraw}` for a fixed member,
    /// asserted against the per-peer-path reference semantics (design
    /// §2.2, `pass ≡ true`): announce ⇔ GETS; withdraw ⇔ HAD ∧ ¬GETS.
    #[test]
    fn vpn_source_flip_matrix_exhaustive() {
        let old_sources = [None, Some(MEMBER), Some(OTHER1), Some(OTHER2)];
        let new_sources = [None, Some(MEMBER), Some(OTHER1), Some(OTHER2)];
        for old in old_sources {
            for new in new_sources {
                if new.is_none() && old.is_none() {
                    // A withdraw delta always has an old entry.
                    continue;
                }
                let delta = match new {
                    Some(src) => vpn_announce_delta(1, src, old),
                    None => vpn_withdraw_delta(1, old),
                };
                let mut announce = Vec::new();
                let mut withdraw = Vec::new();
                let count_delta = emit_vpn_group_deltas_for_member(
                    std::slice::from_ref(&delta),
                    MEMBER,
                    None,
                    &mut announce,
                    &mut withdraw,
                );

                let member_had = old.is_some_and(|s| s != MEMBER);
                let member_gets = new.is_some_and(|s| s != MEMBER);
                assert_eq!(
                    announce.len(),
                    usize::from(member_gets),
                    "announce mismatch for old={old:?} new={new:?}"
                );
                assert_eq!(
                    withdraw.len(),
                    usize::from(member_had && !member_gets),
                    "withdraw mismatch for old={old:?} new={new:?}"
                );
                assert_eq!(
                    count_delta[0],
                    i64::from(member_gets && !member_had) - i64::from(member_had && !member_gets),
                    "count delta mismatch for old={old:?} new={new:?}"
                );
                if member_gets {
                    assert_eq!(announce[0].peer, new.unwrap());
                }
                if member_had && !member_gets {
                    assert_eq!(withdraw[0].nlri_key, vpn_key(1));
                    assert_eq!(withdraw[0].path_id, 0);
                }
            }
        }
    }

    /// VPN dirty-member resync: full-VPN-table announce minus
    /// own-sourced; VPN tombstones withdraw unless the member still
    /// retains the key via another source; own-sourced tombstones are a
    /// safe over-withdraw. Force bypasses only the equality suppression.
    #[test]
    fn vpn_dirty_resync_replays_table_and_tombstones() {
        let mut group = empty_group();
        group.apply_vpn_delta(&vpn_announce_delta(1, OTHER1, None));
        group.apply_vpn_delta(&vpn_announce_delta(2, MEMBER, None));
        group.vpn_tombstones.insert(vpn_key(1)); // retained via OTHER1 — no withdraw
        group.vpn_tombstones.insert(vpn_key(3)); // gone — withdraw
        group.vpn_tombstones.insert(vpn_key(2)); // member-sourced — safe over-withdraw

        let mut announce = Vec::new();
        let mut withdraw = Vec::new();
        RibManager::assemble_group_vpn_resync(
            &group,
            MEMBER,
            None,
            true,
            false,
            None,
            None,
            &mut announce,
            &mut withdraw,
        );
        let announced: HashSet<VpnRouteKey> = announce.iter().map(|r| r.nlri.key()).collect();
        assert_eq!(
            announced,
            HashSet::from([vpn_key(1)]),
            "own-sourced entries excluded"
        );
        let withdrawn: HashSet<VpnRouteKey> = withdraw.iter().map(|k| k.nlri_key).collect();
        assert_eq!(withdrawn, HashSet::from([vpn_key(2), vpn_key(3)]));

        // Regroup one-shot diff: unchanged baseline entry suppressed,
        // baseline key no longer retained withdrawn.
        let mut baseline: FxHashMap<VpnRouteKey, VpnRibRoute> = FxHashMap::default();
        baseline.insert(vpn_key(1), vpn_route(1, OTHER1)); // unchanged — suppressed
        baseline.insert(vpn_key(5), vpn_route(5, OTHER1)); // gone — withdraw
        let mut announce = Vec::new();
        let mut withdraw = Vec::new();
        RibManager::assemble_group_vpn_resync(
            &group,
            MEMBER,
            None,
            true,
            false,
            Some(&baseline),
            None,
            &mut announce,
            &mut withdraw,
        );
        assert!(announce.is_empty(), "baseline-equal entries suppressed");
        let withdrawn: HashSet<VpnRouteKey> = withdraw.iter().map(|k| k.nlri_key).collect();
        assert!(withdrawn.contains(&vpn_key(5)));

        // Force re-announces every retained entry.
        let mut announce = Vec::new();
        let mut withdraw = Vec::new();
        RibManager::assemble_group_vpn_resync(
            &group,
            MEMBER,
            None,
            false,
            true,
            Some(&baseline),
            None,
            &mut announce,
            &mut withdraw,
        );
        let announced: HashSet<VpnRouteKey> = announce.iter().map(|r| r.nlri.key()).collect();
        assert_eq!(announced, HashSet::from([vpn_key(1)]));
    }

    /// VPN count synthesis tracks `apply_vpn_delta` (announce, source
    /// flip, withdraw), and `family_counts_for` buckets VPN by family.
    #[test]
    fn vpn_counts_and_family_synthesis_track_deltas() {
        let mut group = GroupRibOut::new(
            None,
            false,
            true,
            vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv4, Safi::MplsVpn)],
            vec![],
            0,
        );
        assert!(group.stages_vpn());
        group.apply_delta(&announce_delta(prefix(1), OTHER1, None));
        group.apply_vpn_delta(&vpn_announce_delta(1, OTHER1, None));
        group.apply_vpn_delta(&vpn_announce_delta(2, MEMBER, None));
        assert_eq!(group.vpn_advertised_count_for(MEMBER), 1);
        assert_eq!(group.vpn_advertised_count_for(OTHER1), 1);
        assert_eq!(group.vpn_advertised_count_for(OTHER2), 2);
        // Unicast count synthesis is untouched by the VPN entries.
        assert_eq!(group.advertised_count_for(MEMBER), 1);
        assert_eq!(
            group.family_counts_for(MEMBER),
            vec![
                ((Afi::Ipv4, Safi::Unicast), 1),
                ((Afi::Ipv4, Safi::MplsVpn), 1)
            ]
        );
        let view = group.member_vpn_view_snapshot(MEMBER, None);
        assert_eq!(view.len(), 1);
        assert!(view.contains_key(&vpn_key(1)));

        // Source flip key 1 OTHER1 → MEMBER keeps counts exact.
        group.apply_vpn_delta(&vpn_announce_delta(1, MEMBER, Some(OTHER1)));
        assert_eq!(group.vpn_advertised_count_for(MEMBER), 0);
        assert_eq!(group.vpn_advertised_count_for(OTHER1), 2);

        // Withdraw drops the entry and its label residue.
        group.apply_vpn_delta(&vpn_withdraw_delta(1, Some(MEMBER)));
        assert_eq!(group.vpn_advertised_count_for(OTHER1), 1);
        assert_eq!(group.table.vpn_len(), 1);
        assert!(!group.vpn_staged_labels.contains_key(&vpn_key(1)));

        // An RTC-negotiated sendable set stages VPN too (v2 slice 2):
        // Φ is applied per member at emit, not by a staging gate.
        let rtc_group = GroupRibOut::new(
            None,
            false,
            true,
            vec![
                (Afi::Ipv4, Safi::Unicast),
                (Afi::Ipv4, Safi::MplsVpn),
                (Afi::Ipv4, Safi::RtConstrain),
            ],
            vec![],
            0,
        );
        assert!(rtc_group.stages_vpn());
        assert!(rtc_group.rtc_negotiated());
    }

    /// An RTC membership over a specific Route Target (full 96-bit
    /// origin-AS + RT prefix).
    fn membership(rts: &[u64]) -> RtcMembership {
        let mut entries: Vec<rustbgpd_wire::RtcNlri> = rts
            .iter()
            .map(|&rt| {
                let global_admin = (rt >> 32) & 0xFFFF;
                rustbgpd_wire::RtcNlri::new(global_admin as u32, rt, 96).unwrap()
            })
            .collect();
        entries.sort_unstable();
        entries.dedup();
        RtcMembership {
            has_default: false,
            entries,
        }
    }

    /// RT extended community `65000:n` (two-octet-AS route target).
    const fn rt(n: u64) -> u64 {
        0x0002_FDE8_0000_0000 | n
    }

    fn vpn_route_with_rts(n: u8, src: IpAddr, rts: &[u64]) -> VpnRibRoute {
        let mut route = vpn_route(n, src);
        route.attributes = std::sync::Arc::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::ExtendedCommunities(
                rts.iter().copied().map(ExtendedCommunity::new).collect(),
            ),
        ]);
        route
    }

    /// The Φ dimension of the emit matrix (design §2.2): `had`/`gets`
    /// consult `pass_m` via the REUSED `RtcMembership::matches_any` —
    /// route-mutates-out-of-Φ withdraws, into-Φ announces without a
    /// spurious withdraw, strict-empty membership receives nothing and
    /// withdraws nothing (`had` = false for entries it never had).
    #[test]
    fn vpn_matrix_rt_filter_dimension() {
        let phi1 = membership(&[rt(1)]);
        let empty = RtcMembership::default();
        let old_r1 = vpn_route_with_rts(1, OTHER1, &[rt(1)]);
        let new_r2 = vpn_route_with_rts(1, OTHER1, &[rt(2)]);

        // Attr change flips the RT out of Φ: had ∧ ¬gets → withdraw.
        let delta = VpnGroupDelta {
            key: vpn_key(1),
            new: Some(new_r2.clone()),
            old: Some(old_r1.clone()),
            policy_label: None,
        };
        let mut announce = Vec::new();
        let mut withdraw = Vec::new();
        let d = emit_vpn_group_deltas_for_member(
            std::slice::from_ref(&delta),
            MEMBER,
            Some(&phi1),
            &mut announce,
            &mut withdraw,
        );
        assert!(announce.is_empty());
        assert_eq!(withdraw.len(), 1);
        assert_eq!(d, [-1, 0]);

        // The reverse mutation (into Φ): ¬had ∧ gets → announce only.
        let delta = VpnGroupDelta {
            key: vpn_key(1),
            new: Some(old_r1.clone()),
            old: Some(new_r2.clone()),
            policy_label: None,
        };
        let mut announce = Vec::new();
        let mut withdraw = Vec::new();
        let d = emit_vpn_group_deltas_for_member(
            std::slice::from_ref(&delta),
            MEMBER,
            Some(&phi1),
            &mut announce,
            &mut withdraw,
        );
        assert_eq!(announce.len(), 1);
        assert!(withdraw.is_empty());
        assert_eq!(d, [1, 0]);

        // Strict-empty membership: silent for both directions.
        for delta in [
            VpnGroupDelta {
                key: vpn_key(1),
                new: Some(old_r1.clone()),
                old: None,
                policy_label: None,
            },
            VpnGroupDelta {
                key: vpn_key(1),
                new: None,
                old: Some(old_r1.clone()),
                policy_label: None,
            },
        ] {
            let mut announce = Vec::new();
            let mut withdraw = Vec::new();
            let d = emit_vpn_group_deltas_for_member(
                std::slice::from_ref(&delta),
                MEMBER,
                Some(&empty),
                &mut announce,
                &mut withdraw,
            );
            assert!(announce.is_empty() && withdraw.is_empty());
            assert_eq!(d, [0, 0]);
        }
    }

    /// The Φ dimension of the dirty resync (design §2.4): announce only
    /// Φ-passing entries; the failing-retention backstop (over-)withdraws
    /// table keys outside Φ (healing a membership delta missed while
    /// dirty); the snapshot is Φ-filtered.
    #[test]
    fn vpn_dirty_resync_rt_filter_dimension() {
        let phi1 = membership(&[rt(1)]);
        let mut group = GroupRibOut::new(
            None,
            false,
            true,
            vec![
                (Afi::Ipv4, Safi::Unicast),
                (Afi::Ipv4, Safi::MplsVpn),
                (Afi::Ipv4, Safi::RtConstrain),
            ],
            vec![],
            0,
        );
        let in_phi = vpn_route_with_rts(1, OTHER1, &[rt(1)]);
        let out_phi = vpn_route_with_rts(2, OTHER1, &[rt(2)]);
        group.apply_vpn_delta(&VpnGroupDelta {
            key: in_phi.nlri.key(),
            new: Some(in_phi.clone()),
            old: None,
            policy_label: None,
        });
        group.apply_vpn_delta(&VpnGroupDelta {
            key: out_phi.nlri.key(),
            new: Some(out_phi.clone()),
            old: None,
            policy_label: None,
        });

        // A membership narrow missed while dirty lands the leaving key
        // in the extra-withdraw residue; the resync announces only the
        // Φ-passing table and withdraws the residue (Φ-aware retention:
        // a staged-but-Φ-failing key is NOT retained).
        let extras: HashSet<VpnRouteKey> = HashSet::from([out_phi.nlri.key()]);
        let mut announce = Vec::new();
        let mut withdraw = Vec::new();
        RibManager::assemble_group_vpn_resync(
            &group,
            MEMBER,
            Some(&phi1),
            true,
            false,
            None,
            Some(&extras),
            &mut announce,
            &mut withdraw,
        );
        let announced: HashSet<VpnRouteKey> = announce.iter().map(|r| r.nlri.key()).collect();
        assert_eq!(announced, HashSet::from([in_phi.nlri.key()]));
        let withdrawn: HashSet<VpnRouteKey> = withdraw.iter().map(|k| k.nlri_key).collect();
        assert_eq!(
            withdrawn,
            HashSet::from([out_phi.nlri.key()]),
            "a staged key failing Φ is not retained — the extras withdraw must emit"
        );

        // Snapshot under Φ = the true advertised set.
        let view = group.member_vpn_view_snapshot(MEMBER, Some(&phi1));
        assert_eq!(view.len(), 1);
        assert!(view.contains_key(&in_phi.nlri.key()));

        // Count recompute-from-table under Φ.
        assert_eq!(
            group.vpn_member_counts_from_table(MEMBER, Some(&phi1)),
            [1, 0]
        );
        group.recompute_vpn_member_counts(MEMBER, Some(&phi1));
        assert_eq!(group.vpn_advertised_count_for(MEMBER), 1);
        assert_eq!(
            group.family_counts_for(MEMBER),
            vec![((Afi::Ipv4, Safi::MplsVpn), 1)]
        );
    }

    /// The join replay dimension: a joining member's view is the table
    /// minus its own-sourced entries, with O(1) count synthesis kept in
    /// lockstep by `apply_delta` (announce, replace, withdraw).
    #[test]
    fn join_view_and_count_synthesis_track_deltas() {
        let mut group = empty_group();
        let (k1, k2) = (prefix(1), prefix(2));
        group.apply_delta(&announce_delta(k1, OTHER1, None));
        group.apply_delta(&announce_delta(k2, MEMBER, None));
        assert_eq!(group.advertised_count_for(MEMBER), 1);
        assert_eq!(group.advertised_count_for(OTHER1), 1);
        assert_eq!(group.advertised_count_for(OTHER2), 2);
        assert_eq!(
            group.family_counts_for(MEMBER),
            vec![((Afi::Ipv4, Safi::Unicast), 1)]
        );
        let view = group.member_view_snapshot(MEMBER);
        assert_eq!(view.len(), 1);
        assert!(view.contains_key(&(k1, 0)));

        // Source flip k1 OTHER1 → MEMBER keeps counts exact.
        group.apply_delta(&announce_delta(k1, MEMBER, Some(OTHER1)));
        assert_eq!(group.advertised_count_for(MEMBER), 0);
        assert_eq!(group.advertised_count_for(OTHER1), 2);

        // Withdraw drops the entry and its residue.
        group.apply_delta(&withdraw_delta(k1, Some(MEMBER)));
        assert_eq!(group.advertised_count_for(OTHER1), 1);
        assert_eq!(group.table.len(), 1);
    }
}
