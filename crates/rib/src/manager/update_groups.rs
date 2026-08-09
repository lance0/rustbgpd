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
//! set is `group table − own-sourced entries` (plus, for a
//! per-client-best group, the exception-lane substitution at each
//! own-sourced slot: ADR-0126 Decision 4's `adv(m)`, derived solely by
//! [`GroupRibOut::adv_entry`]).
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
use std::sync::Arc;

use rustbgpd_policy::{NextHopAction, PolicyAction, PolicyChain, PolicyEvaluation};
use rustbgpd_wire::{
    Afi, BgpRole, ExtendedCommunity, LargeCommunity, PathAttribute, Prefix, Safi, VpnAddressFamily,
    VpnRouteKey,
};
use rustc_hash::FxHashMap;
use tracing::{debug, info, warn};

mod policy_transition;
mod staging;
mod views;

use super::helpers::{LOCAL_PEER, routes_equal, vpn_routes_equal};
use super::{PolicyFilteredRouteKey, RibManager, RtcMembership};
use crate::adj_rib_out::AdjRibOut;
use crate::route::{Route, VpnRibRoute, VpnRibRouteKey};
use crate::update::{
    ExactExportKey, RouteQueryKey, UpdateGroupClassification, UpdateGroupClassifierInput,
    UpdateGroupComparisonDifference, UpdateGroupComparisonMembership, UpdateGroupComparisonVerdict,
    UpdateGroupPeerComparison, UpdateGroupPeerSnapshot, UpdateGroupSnapshot, classify_update_group,
    route_query_key,
};

fn send_update_group_snapshot(
    reply: tokio::sync::oneshot::Sender<UpdateGroupSnapshot>,
    build: impl FnOnce(
        &tokio::sync::oneshot::Sender<UpdateGroupSnapshot>,
    ) -> Option<UpdateGroupSnapshot>,
) {
    if reply.is_closed() {
        debug!("update-group snapshot query canceled before materialization");
        return;
    }
    let Some(snapshot) = build(&reply) else {
        debug!("update-group snapshot query canceled during materialization");
        return;
    };
    let _ = reply.send(snapshot);
}

#[cfg(test)]
static SNAPSHOT_PEER_ORDER_KEY_CALLS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

fn snapshot_peer_order_key(peer: &IpAddr) -> [u8; 17] {
    #[cfg(test)]
    SNAPSHOT_PEER_ORDER_KEY_CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let mut key = [0; 17];
    match peer {
        IpAddr::V4(addr) => key[1..5].copy_from_slice(&addr.octets()),
        IpAddr::V6(addr) => {
            key[0] = 1;
            key[1..].copy_from_slice(&addr.octets());
        }
    }
    key
}

fn materialize_update_group_snapshot(
    reply: &tokio::sync::oneshot::Sender<UpdateGroupSnapshot>,
    peers: &mut [IpAddr],
    mut build_row: impl FnMut(IpAddr) -> UpdateGroupPeerSnapshot,
) -> Option<UpdateGroupSnapshot> {
    if reply.is_closed() {
        return None;
    }
    peers.sort_by_key(snapshot_peer_order_key);

    let mut rows = Vec::with_capacity(peers.len());
    for &peer in peers.iter() {
        if reply.is_closed() {
            return None;
        }
        rows.push(build_row(peer));
    }
    if reply.is_closed() {
        return None;
    }
    Some(UpdateGroupSnapshot { peers: rows })
}

/// A configured policy name retained by shared staging. `Arc` keeps a
/// group-wide per-route verdict from rebuilding the same owned label at every
/// accumulator, delta, and residue handoff; metric/output boundaries convert
/// only when they need an owned string.
pub(in crate::manager) type PolicyLabel = Arc<str>;

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
    /// RFC 9234 local role (the OTC egress gate is role-dependent).
    target_local_role: Option<u8>,
    /// RFC 1997 `NO_EXPORT` egress enforcement (`interpret_rfc1997`).
    /// The gate outcome is target-dependent like the LLGR §4.4 gate: an
    /// honor-mode eBGP peer and a transparent route-server client must
    /// never share a staged winner for a `NO_EXPORT`-tagged route.
    interpret_rfc1997: bool,
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
    /// RFC 7947 §2.3.2 per-client best-path (ADR-0126 Decision 1): a
    /// mitigated group stages the first *permitted* candidate where a
    /// plain group stages Loc-RIB-best-or-nothing, so the two must
    /// never share a staged table. Set only on unicast-only keys — the
    /// classifier keeps VPN/RTC per-client-best combinations on the
    /// per-peer fallback with the existing `per_client_best` reason.
    per_client_best: bool,
    /// Exact set of families the peer advertised LLGR for (RFC 9494
    /// export-restriction input), sorted raw `(afi, safi)` values.
    llgr_families: Vec<(u16, u8)>,
}

impl GroupKey {
    /// Whether two groups differ only by the effective export-chain content.
    fn same_staging_profile_except_chain(&self, other: &Self) -> bool {
        let mut left = self.clone();
        let mut right = other.clone();
        left.chain = None;
        right.chain = None;
        left == right
    }

    /// PR-1's deliberately narrow transition shape: unicast only, with no
    /// RTC/VPN participation hidden in an otherwise groupable key.
    fn is_unicast_only(&self) -> bool {
        (self.sendable_ipv4_unicast || self.sendable_ipv6_unicast)
            && !self.sendable_vpnv4
            && !self.sendable_vpnv6
            && !self.rtc_negotiated
    }
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
    /// RFC 7947 §2.3.2 per-client best-path on a NON-unicast-only key
    /// (VPN/RTC families negotiated) — the residual fallback since the
    /// ADR-0126 Phase 3 classifier flip; unicast-only per-client-best
    /// peers group on the `per_client_best` key bit instead.
    PerClientBest,
    /// ORR vantage bound: per-vantage winners are per-target
    /// (ADR-0095 Decision 5).
    OrrVantage,
    /// ORF-receive negotiated: the peer can push arbitrary per-peer
    /// prefix filters (RFC 5291).
    OrfInstalled,
    /// Transport flagged the peer slow and `slow_peer_isolation` is
    /// configured (LAN-470): kept on the per-peer path so its wedged
    /// writer cannot hold back a shared group's staging pass. Rejoins
    /// through the ordinary regroup baseline diff when the flag clears.
    SlowPeer,
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
            Self::SlowPeer => "slow_peer".to_string(),
        }
    }

    fn comparison_membership(&self) -> UpdateGroupComparisonMembership {
        match self {
            Self::Grouped(_) => UpdateGroupComparisonMembership::Grouped,
            Self::PolicyPeerContext => UpdateGroupComparisonMembership::PolicyPeerContext,
            Self::AddPathSend => UpdateGroupComparisonMembership::AddPathSend,
            Self::PerClientBest => UpdateGroupComparisonMembership::PerClientBest,
            Self::OrrVantage => UpdateGroupComparisonMembership::OrrVantage,
            Self::OrfInstalled => UpdateGroupComparisonMembership::OrfInstalled,
            Self::SlowPeer => UpdateGroupComparisonMembership::SlowPeer,
        }
    }
}

fn grouped_differences(left: &GroupKey, right: &GroupKey) -> Vec<UpdateGroupComparisonDifference> {
    let GroupKey {
        chain: left_chain,
        target_is_ebgp: left_ebgp,
        target_is_rr_client: left_rr,
        target_local_role: left_role,
        interpret_rfc1997: left_rfc1997,
        sendable_ipv4_unicast: left_v4,
        sendable_ipv6_unicast: left_v6,
        sendable_vpnv4: left_vpnv4,
        sendable_vpnv6: left_vpnv6,
        rtc_negotiated: left_rtc,
        per_client_best: left_pcb,
        llgr_families: left_llgr,
    } = left;
    let GroupKey {
        chain: right_chain,
        target_is_ebgp: right_ebgp,
        target_is_rr_client: right_rr,
        target_local_role: right_role,
        interpret_rfc1997: right_rfc1997,
        sendable_ipv4_unicast: right_v4,
        sendable_ipv6_unicast: right_v6,
        sendable_vpnv4: right_vpnv4,
        sendable_vpnv6: right_vpnv6,
        rtc_negotiated: right_rtc,
        per_client_best: right_pcb,
        llgr_families: right_llgr,
    } = right;
    let mut differences = Vec::new();
    if left_chain != right_chain {
        differences.push(UpdateGroupComparisonDifference::ExportPolicy);
    }
    if left_ebgp != right_ebgp {
        differences.push(UpdateGroupComparisonDifference::SessionKind);
    }
    if left_rr != right_rr {
        differences.push(UpdateGroupComparisonDifference::RouteReflectorClient);
    }
    if left_role != right_role {
        differences.push(UpdateGroupComparisonDifference::LocalRole);
    }
    if left_rfc1997 != right_rfc1997 {
        differences.push(UpdateGroupComparisonDifference::Rfc1997Mode);
    }
    if left_v4 != right_v4
        || left_v6 != right_v6
        || left_vpnv4 != right_vpnv4
        || left_vpnv6 != right_vpnv6
        || left_rtc != right_rtc
    {
        differences.push(UpdateGroupComparisonDifference::NegotiatedFamilies);
    }
    if left_pcb != right_pcb {
        differences.push(UpdateGroupComparisonDifference::PerClientBest);
    }
    if left_llgr != right_llgr {
        differences.push(UpdateGroupComparisonDifference::LlgrFamilies);
    }
    differences
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

    fn group_key(&self, id: usize) -> Option<&GroupKey> {
        self.groups.get(id)
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
    pub(in crate::manager) policy_label: Option<PolicyLabel>,
    /// Pre-policy SOURCE attributes of an announce delta (`None` for a
    /// withdrawal, or when the source carries no communities). RFC 7947
    /// control decisions — per-target suppression and prepend — are
    /// made on the source route, exactly like the ungrouped path's
    /// pre-policy gate; only the scrub reads the post-policy `new`.
    pub(in crate::manager) source_attrs: Option<Arc<Vec<PathAttribute>>>,
    /// ADR-0126 Decision 5: the RECOMPUTED (post-pass) exception-lane
    /// entry for this delta's prefix, carried on per-client-best
    /// announce deltas so [`emit_group_deltas_for_member`] stays a
    /// self-contained free fn. The `member == source(w_new)` arm reads
    /// it directly: a member becoming the winner's source receives the
    /// runner-up substitution (or a withdraw when the lane is empty)
    /// instead of the shared announce. Always `None` for plain groups,
    /// for withdraw deltas (no winner ⇒ no runner-up), and for
    /// non-zero-path residue withdraws.
    pub(in crate::manager) lane: Option<RunnerUp>,
}

/// Capture a source route's attributes for RFC 7947 decisions at the
/// member-emit seams. `None` — no communities at all — keeps the
/// common case allocation-free (the capture itself is an `Arc` clone).
pub(in crate::manager) fn capture_source_attrs(source: &Route) -> Option<Arc<Vec<PathAttribute>>> {
    (!source.communities().is_empty() || !source.large_communities().is_empty())
        .then(|| Arc::clone(&source.attributes))
}

/// One staged runner-up of a per-client-best group (ADR-0126 Decision
/// 3): the exception lane's per-prefix payload — the same shape the
/// group table keeps per staged key: the post-policy route shell with
/// its source peer preserved, the next-hop-override residue, the
/// captured pre-policy SOURCE attributes, and the permitting
/// terminal-policy label for join-time counter replay.
#[derive(Debug, Clone)]
pub(in crate::manager) struct RunnerUp {
    pub(in crate::manager) route: Route,
    pub(in crate::manager) nh: Option<NextHopAction>,
    pub(in crate::manager) source_attrs: Option<Arc<Vec<PathAttribute>>>,
    pub(in crate::manager) policy_label: Option<PolicyLabel>,
    /// Source of the winner this entry substitutes for. Every ADR-0126
    /// Decision 5 lane arm is member-scoped "toward `source(w)`", and
    /// [`LaneDelta::old_source`] carries the old RUNNER-UP's source —
    /// without this field no emit, count, or replay seam could know
    /// which member the substitution targets.
    pub(in crate::manager) winner_source: IpAddr,
}

/// One slot of a member's derived advertised view — what
/// [`GroupRibOut::adv_entry`] resolves `adv(m)` to at one staged key:
/// the route on the member's wire plus the residue every read seam
/// fetches alongside it. Borrowed from the group: either the staged
/// table entry with its table residue, or the exception-lane
/// runner-up substituting for it with the lane's own payload.
pub(in crate::manager) struct AdvEntry<'a> {
    pub(in crate::manager) route: &'a Route,
    /// Next-hop-override residue for the slot.
    pub(in crate::manager) nh: Option<&'a NextHopAction>,
    /// Captured pre-policy SOURCE attributes (RFC 7947 rs-control
    /// decisions read these, never the post-policy route).
    pub(in crate::manager) source_attrs: Option<&'a Arc<Vec<PathAttribute>>>,
    /// Terminal policy label of the permitting evaluation (`None` =
    /// inline verdict) — join-time counter replay residue.
    pub(in crate::manager) policy_label: Option<&'a PolicyLabel>,
}

/// One exception-lane transition of a per-client-best staging pass
/// (ADR-0126 Decision 5): the newly staged runner-up (`None` when the
/// lane empties) plus the source of the lane entry it replaced — the
/// old RUNNER-UP's source, never the winner's (that is
/// [`RunnerUp::winner_source`]) — read BEFORE commit; the same
/// `(new, old_source)` shape as [`GroupDelta`]. Carried beside the
/// winner deltas so the lane-only case (runner-up flips or retires
/// while the winner is unchanged) has a first-class encoding, consumed
/// per member by [`emit_lane_deltas_for_member`].
#[derive(Debug, Clone)]
pub(in crate::manager) struct LaneDelta {
    pub(in crate::manager) prefix: Prefix,
    pub(in crate::manager) new: Option<RunnerUp>,
    pub(in crate::manager) old_source: Option<IpAddr>,
    /// The ONE member this transition emits toward, resolved at
    /// staging time (every Decision 5 lane arm is member-scoped
    /// "toward `source(w)`"): the new entry's [`RunnerUp::winner_source`]
    /// for an announce, the REPLACED entry's for a retire — which is
    /// how a retire knows its target after the lane emptied (the
    /// prior entry is read before commit). `None` when the same
    /// pass's winner announce delta supersedes the lane arm — its
    /// `member == source(w_new)` matrix arm already rewrites the
    /// target's slot from [`GroupDelta::lane`], so a lane emission on
    /// top would double-announce or compose announce+withdraw. The
    /// precedence: the winner-delta arms own every member slot they
    /// rewrite; the lane arm owns exactly the slots they skip
    /// (`source(w)` under an unchanged winner source, and the old
    /// `source(w)` on all-candidates-gone).
    pub(in crate::manager) emit_target: Option<IpAddr>,
    /// Captured source attributes of the REPLACED lane entry — the
    /// was-side input for rs-control verdict flips across the
    /// transition, mirroring [`RsTagTransition::prior_source_attrs`].
    pub(in crate::manager) prior_source_attrs: Option<Arc<Vec<PathAttribute>>>,
    /// The post-policy lane route is content-equal across the
    /// transition (`routes_equal`) — the transition was recorded only
    /// because the SOURCE control communities moved. The emit arm then
    /// mirrors [`emit_rs_tag_transitions`]: nothing toward a non-rs
    /// target (its wire form is unchanged — the per-peer path would
    /// equality-suppress), withdraw/re-announce toward an rs-control
    /// target exactly when its suppress/prepend verdict flips.
    pub(in crate::manager) content_unchanged: bool,
}

/// Outcome of one per-client-best group walk over a prefix (ADR-0126
/// Decision 2): the winner residue for the staged [`GroupDelta`] plus
/// the recomputed exception-lane content. The winner announce/withdraw
/// itself rides the caller's output vectors, like every other
/// distribution body.
#[derive(Default)]
pub(in crate::manager) struct PerClientBestPrefixStage {
    /// Terminal policy of the winner's permitting evaluation, captured
    /// at its own permit point: [`GroupEvalAccumulator::take_last`]
    /// returns the walk's LAST evaluation — the runner-up's permit or
    /// a trailing denial — never the winner's.
    pub(in crate::manager) winner_label: Option<PolicyLabel>,
    /// Captured pre-policy SOURCE attributes of the winner candidate.
    /// The first permitted candidate need not be the Loc-RIB best, so
    /// the caller cannot capture these from the Loc-RIB.
    pub(in crate::manager) winner_source_attrs: Option<Arc<Vec<PathAttribute>>>,
    /// The recomputed runner-up (`None` = lane empty), rebuilt from
    /// scratch every pass — no stale second-best by construction
    /// (ADR-0126 Decision 6).
    pub(in crate::manager) runner_up: Option<RunnerUp>,
}

/// Communities and large communities carried by a captured source
/// attribute list (empty slices when nothing was captured).
pub(in crate::manager) fn source_control_input(
    attrs: Option<&Arc<Vec<PathAttribute>>>,
) -> (&[u32], &[LargeCommunity]) {
    let Some(attrs) = attrs else {
        return (&[], &[]);
    };
    let communities = attrs
        .iter()
        .find_map(|attr| match attr {
            PathAttribute::Communities(values) => Some(values.as_slice()),
            _ => None,
        })
        .unwrap_or(&[]);
    let large_communities = attrs
        .iter()
        .find_map(|attr| match attr {
            PathAttribute::LargeCommunities(values) => Some(values.as_slice()),
            _ => None,
        })
        .unwrap_or(&[]);
    (communities, large_communities)
}

/// A tag-only transition staged by a pass: the post-policy route was
/// equality-suppressed against the group table (nothing changed on the
/// shared wire) while the SOURCE control communities changed — a
/// difference policy made invisible post-policy. Non-rs members see
/// nothing (their wire form is the unchanged staged route), but an
/// rs-control member's suppress/prepend verdict may flip, so these
/// ride next to the deltas through the per-member emit seam.
#[derive(Debug, Clone)]
pub(in crate::manager) struct RsTagTransition {
    pub(in crate::manager) prefix: Prefix,
    pub(in crate::manager) path_id: u32,
    /// The staged (post-policy) route, re-emitted toward members whose
    /// verdict flips to announce.
    pub(in crate::manager) route: Route,
    /// Next-hop-override residue for the staged entry.
    pub(in crate::manager) nh: Option<NextHopAction>,
    /// Captured source attributes before this pass.
    pub(in crate::manager) prior_source_attrs: Option<Arc<Vec<PathAttribute>>>,
    /// Captured source attributes after this pass.
    pub(in crate::manager) source_attrs: Option<Arc<Vec<PathAttribute>>>,
}

/// The `Arc`-shared unicast announce payload of one group staging pass:
/// the announce vector and its aligned next-hop-override flags, enqueued
/// per member by `Arc` clone.
pub(in crate::manager) type SharedUnicastPayload = (
    std::sync::Arc<[Route]>,
    std::sync::Arc<[Option<NextHopAction>]>,
);

/// Immutable old-to-new inventory for the strict clean policy-transition
/// path. The route shells and aligned next-hop decisions are materialized once
/// for the whole cohort; transport excludes each target's own source.
pub(in crate::manager) struct CleanPolicyTransitionInventory {
    pub(in crate::manager) announce: std::sync::Arc<[Route]>,
    pub(in crate::manager) next_hop_override: std::sync::Arc<[Option<NextHopAction>]>,
    /// Destination-group permit verdicts, aggregated once for counter replay.
    pub(in crate::manager) permit_totals: HashMap<Option<String>, u64>,
    /// The subset of each aggregate sourced by one peer. Split-horizon
    /// excludes these verdicts from that peer's counter replay.
    pub(in crate::manager) permit_by_source: HashMap<IpAddr, HashMap<Option<String>, u64>>,
}

/// Pre-emission inventory accumulated by the actor-owned clean transition.
/// The builder is private to that transaction and never represents committed
/// peer-visible state.
#[derive(Default)]
pub(in crate::manager) struct CleanPolicyTransitionInventoryBuilder {
    announce: Vec<Route>,
    next_hop_override: Vec<Option<NextHopAction>>,
    permit_totals: HashMap<Option<String>, u64>,
    permit_by_source: HashMap<IpAddr, HashMap<Option<String>, u64>>,
}

impl CleanPolicyTransitionInventoryBuilder {
    pub(in crate::manager) fn finish(self) -> CleanPolicyTransitionInventory {
        CleanPolicyTransitionInventory {
            announce: self.announce.into(),
            next_hop_override: self.next_hop_override.into(),
            permit_totals: self.permit_totals,
            permit_by_source: self.permit_by_source,
        }
    }
}

pub(in crate::manager) enum PolicyTransitionGroupStart {
    Maintained,
    Created(Vec<Prefix>),
}

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
    /// RFC 9234 denials from this staging pass, replayed per member for
    /// transport's existing metric/event diagnostics.
    pub(in crate::manager) otc_blocked: Vec<Route>,
    /// Announce payload for non-exception members, built once per pass.
    pub(in crate::manager) shared_announce: std::sync::Arc<[Route]>,
    /// Next-hop-override flags aligned with `shared_announce`.
    pub(in crate::manager) shared_nh: std::sync::Arc<[Option<NextHopAction>]>,
    /// Withdraw keys for non-exception members.
    pub(in crate::manager) shared_withdraw: Vec<(Prefix, u32)>,
    /// Tag-only transitions of this pass ([`RsTagTransition`]): keys
    /// whose staged route was equality-suppressed while the source
    /// control communities changed. Deliberately outside the shared
    /// emission — only rs-control members act on them.
    pub(in crate::manager) rs_transitions: Vec<RsTagTransition>,
    /// Exception-lane transitions of this pass ([`LaneDelta`]) —
    /// per-client-best groups only, always empty for plain groups.
    /// Deliberately outside `deltas` and the shared emission: exactly
    /// one member acts on a lane transition (its
    /// [`LaneDelta::emit_target`]), via
    /// [`emit_lane_deltas_for_member`] in the per-member walk.
    pub(in crate::manager) lane_deltas: Vec<LaneDelta>,
    /// Members whose emission differs from the shared one: the new
    /// source of an announce delta (announce → substitution/withdraw),
    /// the old source of a withdraw delta (withdraw → skip/lane
    /// withdraw), or a consumed lane transition's `emit_target`
    /// (member-scoped emission the shared payload does not carry).
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

    /// Whether this pass carries a control-form community for `rs_asn`
    /// (LAN-474). A pass with none — the overwhelming majority — lets
    /// `rs_control_communities` members ride the shared emission
    /// untouched; a tagged pass drops them to the per-member matrix
    /// walk where suppression/prepend/scrub diverge per target. Tagged
    /// on EITHER side of policy: source tags drive suppress/prepend,
    /// post-policy tags need scrubbing; a tag-only transition counts on
    /// either side of the pass. Callers memoize per (group, `rs_asn`).
    pub(in crate::manager) fn has_tagged_route(&self, rs_asn: u32) -> bool {
        use super::distribution::rs_control::rs_control_route_tagged;
        let attrs_tagged = |attrs: Option<&Arc<Vec<PathAttribute>>>| {
            let (communities, large_communities) = source_control_input(attrs);
            rs_control_route_tagged(communities, large_communities, rs_asn)
        };
        self.deltas.iter().any(|delta| {
            delta.new.as_ref().is_some_and(|(route, _)| {
                attrs_tagged(delta.source_attrs.as_ref())
                    || rs_control_route_tagged(
                        route.communities(),
                        route.large_communities(),
                        rs_asn,
                    )
            })
        }) || self.rs_transitions.iter().any(|transition| {
            attrs_tagged(transition.prior_source_attrs.as_ref())
                || attrs_tagged(transition.source_attrs.as_ref())
        }) || self.lane_deltas.iter().any(|delta| {
            // ADR-0126: a tagged lane source must push `source(w)`
            // onto the per-member walk — the substituted announce
            // applies suppress/prepend/scrub from the LANE entry's
            // source attributes, which the shared payload cannot.
            delta.new.as_ref().is_some_and(|entry| {
                attrs_tagged(entry.source_attrs.as_ref())
                    || rs_control_route_tagged(
                        entry.route.communities(),
                        entry.route.large_communities(),
                        rs_asn,
                    )
            })
        })
    }

    /// Member-scoped withdraw keys of this pass that [`Self::withdrawn_keys`]
    /// (the tombstone feed) never records, recorded into the member's
    /// extra (over-)withdraws when its emission is lost to a full
    /// channel:
    ///
    /// - the source-flip arm — the member is the delta's NEW source
    ///   and the displaced entry was another peer's, so the key stays
    ///   IN the group table. Under per-client-best the member's lost
    ///   emission may actually have been a substituted ANNOUNCE
    ///   ([`GroupDelta::lane`]) — or a genuine withdraw when the
    ///   substitution is rs-suppressed toward it, a per-member verdict
    ///   this method cannot see — so the key is recorded
    ///   unconditionally: the resync's `member_retains` guard (routed
    ///   through [`GroupRibOut::adv_entry`]) drops it exactly when the
    ///   lane still substitutes, and the resync substitution announces
    ///   `adv(m)` in its place;
    /// - the ADR-0126 lane-retire arm — a retire toward its
    ///   [`LaneDelta::emit_target`]: the target's wire held the
    ///   substitution while the key stays IN the table, so the retire
    ///   withdraw is invisible to the tombstone feed. A superseded
    ///   retire (`emit_target` = None) needs no record — its target's
    ///   slot is owned by a winner delta this pass, whose own arms
    ///   (above, or the tombstone feed) cover the loss.
    ///
    /// Lost member-scoped ANNOUNCES (a lane flip or a substitution)
    /// leave no residue on purpose: announces are idempotent and the
    /// dirty resync re-derives them from `adv(m)`.
    pub(in crate::manager) fn member_scoped_withdraws(
        &self,
        member: IpAddr,
    ) -> impl Iterator<Item = (Prefix, u32)> + '_ {
        self.deltas
            .iter()
            .filter_map(move |delta| {
                (delta
                    .new
                    .as_ref()
                    .is_some_and(|(route, _)| route.peer == member)
                    && delta.old_source.is_some_and(|source| source != member))
                .then_some((delta.prefix, delta.path_id))
            })
            .chain(self.lane_deltas.iter().filter_map(move |delta| {
                (delta.new.is_none() && delta.emit_target == Some(member))
                    .then_some((delta.prefix, 0))
            }))
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
        // A consumed lane transition emits toward its target alone —
        // the shared payload carries nothing for it, so the target
        // must take the per-member walk (ADR-0126 Decision 5). A
        // superseded transition (`emit_target` = None) needs no entry:
        // its target is either the winner announce's `route.peer`
        // (inserted above) or exactly served by the shared payload
        // (the flip-away arm announces `w'` to it).
        for delta in &self.lane_deltas {
            if let Some(target) = delta.emit_target {
                self.exceptions.insert(target);
            }
        }
        self.shared_announce = announce.into();
        self.shared_nh = nh.into();
    }
}

/// Shared old→new wire delta of one batched authoritative cohort
/// transition ([`RibManager::batched_transition_inventory`]): the
/// equality-suppressed announce/withdraw payload every member shares
/// (split horizon via `announce_source_exclusion`), the member-scoped
/// lane/source-flip corrections, and the pre-aggregated counter rows.
pub(in crate::manager) struct BatchedTransitionInventory {
    /// Destination entries whose wire form differs from the source
    /// entry at the same key — `Arc`-shared across every member
    /// envelope (one `Route` shell clone per changed entry, total).
    pub(in crate::manager) announce: Arc<[Route]>,
    /// Next-hop-override flags aligned with `announce`.
    pub(in crate::manager) next_hop_override: Arc<[Option<NextHopAction>]>,
    /// Keys the destination no longer stages (over-withdraw safe).
    pub(in crate::manager) withdraw: Vec<(Prefix, u32)>,
    /// Member-scoped corrections the shared exclusion cannot express:
    /// the ADR-0126 lane substitution toward each winner's source
    /// (announce) and the displaced/retired own-sourced slot (withdraw).
    pub(in crate::manager) supplements: FxHashMap<IpAddr, BatchedMemberSupplement>,
    counters: BatchedTransitionCounters,
}

/// One member's corrections beside the shared batched-transition payload.
#[derive(Default)]
pub(in crate::manager) struct BatchedMemberSupplement {
    pub(in crate::manager) announce: Vec<(Route, Option<NextHopAction>)>,
    pub(in crate::manager) withdraw: Vec<(Prefix, u32)>,
}

/// Pre-aggregated export-counter rows of one batched cohort transition:
/// permit totals per label with per-source breakdown, the lane's
/// per-winner-source substitution labels, and the denial residue rows —
/// the inputs of the ADR-0126 Decision 4 `totals − own + lane`
/// synthesis, folded once per cohort so the per-member replay is
/// O(labels) instead of the O(table) walk
/// [`RibManager::apply_group_join_counters`] performs.
#[derive(Default)]
struct BatchedTransitionCounters {
    permit_totals: FxHashMap<Option<PolicyLabel>, u64>,
    permit_by_source: FxHashMap<IpAddr, FxHashMap<Option<PolicyLabel>, u64>>,
    lane_by_winner_source: FxHashMap<IpAddr, FxHashMap<Option<PolicyLabel>, u64>>,
    deny_totals: FxHashMap<Option<PolicyLabel>, u64>,
    deny_by_source: FxHashMap<IpAddr, FxHashMap<Option<PolicyLabel>, u64>>,
}

impl BatchedTransitionCounters {
    fn record_permit(&mut self, source: IpAddr, label: Option<PolicyLabel>) {
        *self
            .permit_by_source
            .entry(source)
            .or_default()
            .entry(label.clone())
            .or_default() += 1;
        *self.permit_totals.entry(label).or_default() += 1;
    }

    fn record_lane(&mut self, winner_source: IpAddr, label: Option<PolicyLabel>) {
        *self
            .lane_by_winner_source
            .entry(winner_source)
            .or_default()
            .entry(label)
            .or_default() += 1;
    }

    fn record_deny(&mut self, source: IpAddr, label: Option<PolicyLabel>) {
        *self
            .deny_by_source
            .entry(source)
            .or_default()
            .entry(label.clone())
            .or_default() += 1;
        *self.deny_totals.entry(label).or_default() += 1;
    }

    /// One member's replay rows: `totals − own-sourced (+ lane
    /// substitutions)` per label, permits and denials alike — the fold
    /// [`RibManager::apply_group_join_counters`] derives per member from
    /// a full table walk.
    fn rows_for(&self, peer: IpAddr) -> Vec<(Option<String>, PolicyAction, u64)> {
        let mut rows = Vec::new();
        let own_permits = self.permit_by_source.get(&peer);
        let lane = self.lane_by_winner_source.get(&peer);
        let mut labels: Vec<&Option<PolicyLabel>> = self.permit_totals.keys().collect();
        if let Some(lane) = lane {
            labels.extend(
                lane.keys()
                    .filter(|label| !self.permit_totals.contains_key(*label)),
            );
        }
        for label in labels {
            let total = self.permit_totals.get(label).copied().unwrap_or(0);
            let own = own_permits
                .and_then(|counts| counts.get(label))
                .copied()
                .unwrap_or(0);
            let substituted = lane
                .and_then(|counts| counts.get(label))
                .copied()
                .unwrap_or(0);
            let count = total.saturating_sub(own) + substituted;
            if count > 0 {
                rows.push((
                    label.as_ref().map(ToString::to_string),
                    PolicyAction::Permit,
                    count,
                ));
            }
        }
        let own_denies = self.deny_by_source.get(&peer);
        for (label, total) in &self.deny_totals {
            let own = own_denies
                .and_then(|counts| counts.get(label))
                .copied()
                .unwrap_or(0);
            let count = total.saturating_sub(own);
            if count > 0 {
                rows.push((
                    label.as_ref().map(ToString::to_string),
                    PolicyAction::Deny,
                    count,
                ));
            }
        }
        rows
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
    totals: Vec<(Option<PolicyLabel>, PolicyAction, u64)>,
    per_source: FxHashMap<IpAddr, Vec<(Option<PolicyLabel>, PolicyAction, u64)>>,
    /// Verdict (and source peer) of the most recent evaluation, consumed
    /// per key by the staging loops to label the staged entry / denial
    /// residue (single-best stages at most one eval per key).
    last: Option<(Option<PolicyLabel>, PolicyAction, IpAddr)>,
}

fn bump_eval_row(
    rows: &mut Vec<(Option<PolicyLabel>, PolicyAction, u64)>,
    policy: Option<&PolicyLabel>,
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

/// Materialize a policy label only at the peer-counter boundary. Group
/// staging itself retains `PolicyLabel` handles, but telemetry's keyed rows
/// own their strings after the shared pass is complete.
fn bump_counter_row(
    rows: &mut Vec<(Option<String>, PolicyAction, u64)>,
    policy: Option<&PolicyLabel>,
    action: PolicyAction,
) {
    if let Some((_, _, n)) = rows
        .iter_mut()
        .find(|(p, a, _)| *a == action && p.as_deref() == policy.map(AsRef::as_ref))
    {
        *n += 1;
    } else {
        rows.push((policy.map(ToString::to_string), action, 1));
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
    fn take_last(&mut self) -> Option<(Option<PolicyLabel>, PolicyAction, IpAddr)> {
        self.last.take()
    }
}

/// Per-member emit for one shared staging pass — the source-flip matrix
/// (design §3). Announce / withdraw / skip is decided per delta entry
/// from `(member == new source, member == old source, lane)` alone:
///
/// | entry             | member == `new.peer`                                                          | member == `old_source`                       | else     |
/// |-------------------|-------------------------------------------------------------------------------|----------------------------------------------|----------|
/// | announce (`Some`) | `old_source` = member → skip (lane arms own the slot); else lane → announce `r`; else old exists → withdraw | announce (member was excluded, now eligible) | announce |
/// | withdraw (`None`) | —                                                                             | skip (lane retire arm owns the slot)         | withdraw |
///
/// The `member == new.peer` column is the ADR-0126 Decision 5 arm: a
/// member BECOMING the winner's source has its slot rewritten here —
/// announce the runner-up substitution ([`GroupDelta::lane`], an
/// implicit replace at `path_id 0`) when the lane holds one, withdraw
/// the displaced other-sourced entry otherwise. A member that ALREADY
/// was the source (`old_source` = member) holds the lane substitution,
/// which transitions only with the lane — its emissions ride
/// [`emit_lane_deltas_for_member`] (same for the retiring source of a
/// withdraw delta, whose lane-retire withdraw rides the same arm).
/// For a plain group `lane` is always `None`, reducing every cell to
/// the historical matrix above it.
///
/// `nh_override_flags` stays aligned with `announce` by pushing in the
/// same arm. A free function so the risk-2 unit matrix can drive it
/// directly.
///
/// `rs_control` is `(rs_asn, member_asn)` for an
/// `rs_control_communities` member (LAN-474): a route whose SOURCE
/// control communities (`GroupDelta::source_attrs` — captured
/// pre-policy, like the ungrouped path's gate) suppress it toward this
/// member emits a withdraw of whatever other-sourced entry the member
/// may hold (over-withdraw is the safe direction), and an announced
/// route is rewritten per target — prepend decided on the source,
/// scrub on the post-policy route. `None` — or an untagged source and
/// route — is byte-identical to the shared emission.
pub(in crate::manager) fn emit_group_deltas_for_member(
    deltas: &[GroupDelta],
    member: IpAddr,
    rs_control: Option<(u32, u32)>,
    announce: &mut Vec<Route>,
    withdraw: &mut Vec<(Prefix, u32)>,
    nh_override_flags: &mut Vec<Option<NextHopAction>>,
) {
    use super::distribution::rs_control::{rs_control_route_rewrite, rs_control_suppressed};
    for delta in deltas {
        match &delta.new {
            Some((route, nh)) => {
                let (source_communities, source_large_communities) =
                    source_control_input(delta.source_attrs.as_ref());
                if route.peer == member {
                    // Split horizon applied at emit: the new best is
                    // the member's own route.
                    if delta.old_source == Some(member) {
                        // The member already was the source: its wire
                        // holds the lane substitution (or nothing),
                        // which moves only with the lane — the
                        // LaneDelta arms own this slot.
                    } else if let Some(entry) = &delta.lane {
                        // ADR-0126 Decision 5: the member becoming
                        // `source(w)` receives the runner-up — an
                        // implicit replace of whatever other-sourced
                        // entry its wire held. rs-control decides on
                        // the LANE entry's source attributes.
                        let (lane_communities, lane_large_communities) =
                            source_control_input(entry.source_attrs.as_ref());
                        if rs_control_suppressed(
                            lane_communities,
                            lane_large_communities,
                            rs_control,
                        ) {
                            if delta.old_source.is_some() {
                                withdraw.push((delta.prefix, delta.path_id));
                            }
                        } else {
                            let mut route = entry.route.clone();
                            rs_control_route_rewrite(
                                &mut route,
                                lane_large_communities,
                                rs_control,
                            );
                            nh_override_flags.push(entry.nh.clone());
                            announce.push(route);
                        }
                    } else if delta.old_source.is_some() {
                        // Empty lane: the member previously held a
                        // different source's advertisement for this
                        // key — withdraw it (per-peer semantics: best
                        // == target ⇒ withdraw existing). Absent old
                        // entry ⇒ the member never had it — skip.
                        withdraw.push((delta.prefix, delta.path_id));
                    }
                } else if rs_control_suppressed(
                    source_communities,
                    source_large_communities,
                    rs_control,
                ) {
                    // RFC 7947 §2.3.2 per-target suppression: same
                    // matrix shape as the split-horizon arm — displace
                    // whatever other-sourced entry the member may hold.
                    if delta.old_source.is_some_and(|source| source != member) {
                        withdraw.push((delta.prefix, delta.path_id));
                    }
                } else {
                    let mut route = route.clone();
                    rs_control_route_rewrite(&mut route, source_large_communities, rs_control);
                    nh_override_flags.push(nh.clone());
                    announce.push(route);
                }
            }
            None => {
                // A member never receives its own-sourced entries, so a
                // withdrawal of one is a no-op for it (and a withdraw
                // delta with no old entry — unreachable by construction
                // — would be a no-op for everyone). A per-client-best
                // old source whose wire held the lane substitution gets
                // its withdraw from the lane-retire arm
                // (`emit_lane_deltas_for_member`) — all-candidates-gone
                // recomputes the lane empty, which always records the
                // retire when an entry existed.
                if delta.old_source.is_some_and(|source| source != member) {
                    withdraw.push((delta.prefix, delta.path_id));
                }
            }
        }
    }
}

/// Per-member emit for a pass's exception-lane transitions (ADR-0126
/// Decision 5, the lane arm): each [`LaneDelta`] is member-scoped —
/// it emits toward its [`LaneDelta::emit_target`] (`source(w)`) alone
/// and toward nobody else. Announce the new runner-up `r'` (an
/// implicit replace at `path_id 0`, with its next-hop flag) or
/// withdraw `(prefix, 0)` on a retire. A transition whose winner
/// announce delta superseded it (`emit_target` = None — the
/// winner-delta arms already rewrote the target's slot) emits
/// nothing here; the exhaustive steady-state matrix proves no
/// double-announce or announce+withdraw composition escapes.
///
/// rs-control divergence applies from the LANE entry's source
/// attributes: a suppressed substitution withdraws whatever the
/// target's wire held (over-withdraw is the safe direction, as in the
/// winner matrix), and a content-equal tag-only transition
/// ([`LaneDelta::content_unchanged`]) mirrors
/// [`emit_rs_tag_transitions`] — nothing toward a non-rs target,
/// withdraw/re-announce toward an rs target exactly on a
/// suppress/prepend verdict flip. A no-op for every member other
/// than the target, and for plain groups (no lane deltas exist).
pub(in crate::manager) fn emit_lane_deltas_for_member(
    lane_deltas: &[LaneDelta],
    member: IpAddr,
    rs_control: Option<(u32, u32)>,
    announce: &mut Vec<Route>,
    withdraw: &mut Vec<(Prefix, u32)>,
    nh_override_flags: &mut Vec<Option<NextHopAction>>,
) {
    use super::distribution::rs_control::{
        rs_control_prepend_count, rs_control_route_rewrite, rs_control_suppressed,
    };
    for delta in lane_deltas {
        if delta.emit_target != Some(member) {
            continue;
        }
        match &delta.new {
            Some(entry) => {
                let (communities, large_communities) =
                    source_control_input(entry.source_attrs.as_ref());
                let now = rs_control_suppressed(communities, large_communities, rs_control);
                if delta.content_unchanged {
                    // Tag-only transition: the target's wire form is
                    // unchanged unless its rs-control verdict flips.
                    let (prior_communities, prior_large_communities) =
                        source_control_input(delta.prior_source_attrs.as_ref());
                    let was = rs_control_suppressed(
                        prior_communities,
                        prior_large_communities,
                        rs_control,
                    );
                    if now {
                        if !was {
                            withdraw.push((delta.prefix, 0));
                        }
                    } else if was
                        || rs_control.is_some_and(|(rs_asn, member_asn)| {
                            rs_control_prepend_count(prior_large_communities, rs_asn, member_asn)
                                != rs_control_prepend_count(large_communities, rs_asn, member_asn)
                        })
                    {
                        let mut route = entry.route.clone();
                        rs_control_route_rewrite(&mut route, large_communities, rs_control);
                        nh_override_flags.push(entry.nh.clone());
                        announce.push(route);
                    }
                } else if now {
                    // Suppressed substitution: displace whatever the
                    // target's wire held (its old runner-up).
                    if delta.old_source.is_some() {
                        withdraw.push((delta.prefix, 0));
                    }
                } else {
                    let mut route = entry.route.clone();
                    rs_control_route_rewrite(&mut route, large_communities, rs_control);
                    nh_override_flags.push(entry.nh.clone());
                    announce.push(route);
                }
            }
            None => {
                // Retire: an entry existed (a retire transition is
                // recorded only when one did), and the target's wire
                // held it at the path-id-free slot.
                withdraw.push((delta.prefix, 0));
            }
        }
    }
}

/// Per-member emit for a pass's tag-only transitions
/// ([`RsTagTransition`]): the old/new source verdicts decide the
/// member's exact stream delta — withdraw when suppression turns on,
/// re-announce (rewritten) when it turns off or the prepend count
/// changes, nothing otherwise — matching what the per-peer path's
/// restage + Adj-RIB-Out diff would emit. A no-op for members without
/// `rs_control_communities`: their wire form is the unchanged staged
/// route.
pub(in crate::manager) fn emit_rs_tag_transitions(
    transitions: &[RsTagTransition],
    member: IpAddr,
    rs_control: Option<(u32, u32)>,
    announce: &mut Vec<Route>,
    withdraw: &mut Vec<(Prefix, u32)>,
    nh_override_flags: &mut Vec<Option<NextHopAction>>,
) {
    use super::distribution::rs_control::{
        rs_control_prepend_count, rs_control_route_rewrite, rs_control_suppressed,
    };
    let Some((rs_asn, member_asn)) = rs_control else {
        return;
    };
    for transition in transitions {
        if transition.route.peer == member {
            continue;
        }
        let (old_communities, old_large) =
            source_control_input(transition.prior_source_attrs.as_ref());
        let (new_communities, new_large) = source_control_input(transition.source_attrs.as_ref());
        let was = rs_control_suppressed(old_communities, old_large, rs_control);
        let now = rs_control_suppressed(new_communities, new_large, rs_control);
        if now {
            if !was {
                withdraw.push((transition.prefix, transition.path_id));
            }
        } else if was
            || rs_control_prepend_count(old_large, rs_asn, member_asn)
                != rs_control_prepend_count(new_large, rs_asn, member_asn)
        {
            let mut route = transition.route.clone();
            rs_control_route_rewrite(&mut route, new_large, rs_control);
            nh_override_flags.push(transition.nh.clone());
            announce.push(route);
        }
    }
}

/// A persistent group-verdict VPN denial: (source peer, denying policy
/// label, the denied route's extended communities — the Φ gate input
/// for an RTC member's join-time counter replay).
type VpnDenialRecord = (IpAddr, Option<PolicyLabel>, Vec<ExtendedCommunity>);

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
    pub(in crate::manager) policy_label: Option<PolicyLabel>,
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
#[expect(
    clippy::struct_excessive_bools,
    reason = "the group-uniform snapshot IS a set of independent staging \
              predicates, mirroring the GroupKey fingerprint they derive from"
)]
pub(in crate::manager) struct GroupRibOut {
    /// Post-policy staged routes, source peer preserved (needed by the
    /// source-flip matrix). Only the unicast maps of the substrate are
    /// used. This IS the equality-suppression baseline: `routes_equal`
    /// runs once per group against it.
    pub(in crate::manager) table: AdjRibOut,
    /// Next-hop-override flags for staged entries (`Some` values only)
    /// so joins/replays don't re-run policy to recover them.
    nh_overrides: FxHashMap<(Prefix, u32), NextHopAction>,
    /// Captured pre-policy SOURCE attributes per staged entry (entries
    /// only for sources carrying communities; the `Arc` is shared with
    /// the Adj-RIB-In/Loc-RIB copy). RFC 7947 decisions at the table
    /// replay seams — resync, join, refresh, regroup baseline — read
    /// these, never the staged (post-policy) route: policy may have
    /// stripped a control community (deciding post-policy leaks a
    /// source-prohibited route) or added one (spurious steering).
    source_attrs: FxHashMap<(Prefix, u32), Arc<Vec<PathAttribute>>>,
    /// Staged-entry count per source peer — O(1) per-member advertised
    /// count synthesis (`len − own`), one slot per staged family
    /// (v4-unicast, v6-unicast, vpnv4, vpnv6) for the BMP stat-17
    /// family counts.
    source_counts: FxHashMap<IpAddr, [usize; 4]>,
    /// Running column sums of `source_counts`, so a per-family count stays
    /// O(1) instead of walking every source. Maintained at the only two
    /// sites that move a slot.
    family_totals: [usize; 4],
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
    /// Persistent group-verdict export-policy denials with the denying
    /// policy's label for join-time counter replay, keyed by prefix so
    /// a scoped per-member query probes the pass's staged set instead
    /// of scanning the whole residue. The stored target is always
    /// [`GROUP_FILTERED_PLACEHOLDER`] (every record funnels through
    /// [`Self::record_policy_filtered`] from the group walk), so only
    /// the varying key parts — `(source_peer, path_id)` — are kept;
    /// readers restamp the concrete member. Inner maps are never left
    /// empty ([`Self::record_policy_filtered`] removes whole prefixes),
    /// so outer emptiness remains "no denials".
    policy_filtered: FxHashMap<Prefix, FxHashMap<(IpAddr, u32), Option<PolicyLabel>>>,
    /// Terminal policy label per staged entry — join-time counter replay
    /// residue. Entries ONLY for labelled entries: an inline (unlabelled)
    /// entry stores nothing and its key is removed, so absent and
    /// present-`None` are the same verdict. Every reader collapses the
    /// two, so keep the insert conditional — an unconditional insert
    /// costs a slot per staged route across the whole table for a value
    /// no reader can distinguish from absence.
    staged_labels: FxHashMap<(Prefix, u32), Option<PolicyLabel>>,
    /// VPN sibling of `staged_labels`, keyed by RD+prefix identity, with
    /// the same absent-means-inline invariant.
    vpn_staged_labels: FxHashMap<VpnRouteKey, Option<PolicyLabel>>,
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
    /// Persistent RFC 9234 denial residue for join/resync diagnostics.
    otc_blocked: FxHashMap<(Prefix, u32), Route>,
    /// Count aggregates beside `otc_blocked`, per unicast family
    /// `[v4, v6]`: total blocked staged winners plus their per-source
    /// split — the winner term of the Decision 4 count synthesis's
    /// OTC subtraction (the synthesis reports the backstop's outcome,
    /// not the raw table). Rebuilt from the residue map at its one
    /// mutation seam ([`Self::record_otc_blocked`]); kept zero for
    /// plain groups, whose in-walk gate rejects blocked routes before
    /// the table — their residue names never-staged routes, so
    /// subtracting it would double-count.
    otc_blocked_totals: [usize; 2],
    otc_blocked_sources: FxHashMap<IpAddr, [usize; 2]>,
    /// Lane sibling of `otc_blocked_sources`: per-winner-source counts
    /// of lane entries whose runner-up is OTC-blocked toward this
    /// group — the substitution term of the same subtraction (the
    /// member sourcing the winner receives the runner-up, so ITS
    /// suppressed slot is the lane's, never the winner's). Maintained
    /// entirely by [`Self::apply_lane`], exactly like `lane_counts`.
    lane_otc_blocked_counts: FxHashMap<IpAddr, [usize; 2]>,
    /// Per-member advertised VPN counts `[vpnv4, vpnv6]`, maintained
    /// ONLY for RTC-negotiated groups (Φ makes the counts non-derivable
    /// from `source_counts`; design §2.4) at the emit seams: staging
    /// emit, membership delta, join, and resync recompute-by-walk. A
    /// dirty window may drift them; the member's resync recompute
    /// restores exactness. Non-RTC groups keep the O(1) synthesis.
    vpn_member_counts: FxHashMap<IpAddr, [i64; 2]>,
    /// ADR-0126 Decision 3 exception lane: the per-prefix runner-up
    /// sidecar of a per-client-best group. Populated only where a
    /// distinct-source permitted runner-up exists — O(overlapped
    /// prefixes), never per member — and recomputed alongside the
    /// winner on every staging of the prefix. Always empty for plain
    /// groups.
    runner_up: FxHashMap<Prefix, RunnerUp>,
    /// ADR-0126 Decision 4 count residue: per-winner-source lane-entry
    /// counts `[v4, v6]` — how many lane entries currently substitute
    /// for member m (m receives the runner-up exactly where it sourced
    /// the winner). The derived-count synthesis
    /// (`advertised_count_for` / `family_counts_for`) reads its
    /// `+lane` term from this map; `source_counts` is keyed by
    /// staged-entry source and cannot express it. Maintained entirely
    /// by [`Self::apply_lane`], zeroed rows dropped (the
    /// `inc_source`/`dec_source` hygiene). Always empty for plain
    /// groups.
    pub(in crate::manager) lane_counts: FxHashMap<IpAddr, [usize; 2]>,
    // Group-uniform staging inputs, snapshot at group creation from the
    // first member (all members are key-equal by construction; a key
    // change moves peers to a different group, so these never mutate).
    pub(in crate::manager) export_chain: Option<PolicyChain>,
    pub(in crate::manager) is_ebgp: bool,
    /// RFC 1997 `NO_EXPORT` egress enforcement — group-uniform (in the
    /// [`GroupKey`]).
    pub(in crate::manager) interpret_rfc1997: bool,
    pub(in crate::manager) is_rr_client: bool,
    pub(in crate::manager) local_role: Option<BgpRole>,
    pub(in crate::manager) sendable: Vec<(Afi, Safi)>,
    pub(in crate::manager) llgr: Vec<(Afi, Safi)>,
    /// ADR-0126 staging mode: `true` stages the first export-permitted
    /// candidate (winner walk + runner-up lane) instead of
    /// Loc-RIB-best-or-nothing. Derived from the group key's
    /// `per_client_best` bit (Decision 1) — group-uniform like every
    /// other snapshot field here.
    pub(in crate::manager) per_client_best: bool,
}

/// Placeholder target for group-level policy-denial records; restamped
/// with the concrete member at emit time. `LOCAL_PEER` can never be an
/// outbound target.
const GROUP_FILTERED_PLACEHOLDER: IpAddr = LOCAL_PEER;

impl GroupRibOut {
    #[expect(
        clippy::too_many_arguments,
        clippy::fn_params_excessive_bools,
        reason = "one constructor snapshots every group-uniform staging input; \
                  the bools are the GroupKey's independent staging predicates"
    )]
    fn new(
        export_chain: Option<PolicyChain>,
        is_ebgp: bool,
        interpret_rfc1997: bool,
        is_rr_client: bool,
        local_role: Option<BgpRole>,
        sendable: Vec<(Afi, Safi)>,
        llgr: Vec<(Afi, Safi)>,
        per_client_best: bool,
        capacity: usize,
    ) -> Self {
        Self {
            table: AdjRibOut::with_capacity(GROUP_FILTERED_PLACEHOLDER, capacity),
            nh_overrides: FxHashMap::default(),
            source_attrs: FxHashMap::default(),
            source_counts: FxHashMap::default(),
            family_totals: [0; 4],
            tombstones: HashSet::new(),
            vpn_tombstones: HashSet::new(),
            members: HashSet::new(),
            dirty_members: HashSet::new(),
            policy_filtered: FxHashMap::default(),
            staged_labels: FxHashMap::default(),
            vpn_staged_labels: FxHashMap::default(),
            vpn_policy_denied: FxHashMap::default(),
            otc_blocked: FxHashMap::default(),
            otc_blocked_totals: [0; 2],
            otc_blocked_sources: FxHashMap::default(),
            lane_otc_blocked_counts: FxHashMap::default(),
            vpn_member_counts: FxHashMap::default(),
            runner_up: FxHashMap::default(),
            lane_counts: FxHashMap::default(),
            export_chain,
            is_ebgp,
            interpret_rfc1997,
            is_rr_client,
            local_role,
            sendable,
            llgr,
            per_client_best,
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

    fn record_otc_blocked(&mut self, prefixes: &HashSet<Prefix>, blocked: &[Route]) {
        self.otc_blocked
            .retain(|(prefix, _), _| !prefixes.contains(prefix));
        self.otc_blocked.extend(
            blocked
                .iter()
                .cloned()
                .map(|route| ((route.prefix, route.path_id), route)),
        );
        // Rebuild the count aggregates from the refreshed map — one
        // mutation seam keeps them exact, at O(blocked residue) per
        // pass (zero in the overwhelmingly common no-OTC case). Only
        // a per-client-best group's residue describes STAGED winners;
        // a plain group's names routes its in-walk gate kept out of
        // the table, so its aggregates stay zero and the count
        // synthesis provably subtracts nothing.
        self.otc_blocked_totals = [0; 2];
        self.otc_blocked_sources.clear();
        if self.per_client_best {
            for route in self.otc_blocked.values() {
                let slot = Self::count_slot(&route.prefix);
                self.otc_blocked_totals[slot] += 1;
                self.otc_blocked_sources.entry(route.peer).or_default()[slot] += 1;
            }
        }
    }

    pub(in crate::manager) fn otc_blocked_for_member(
        &self,
        member: IpAddr,
        prefixes: Option<&HashSet<Prefix>>,
    ) -> Vec<Route> {
        let mut blocked: Vec<Route> = self
            .otc_blocked
            .values()
            .filter(|route| {
                route.peer != member
                    && prefixes.is_none_or(|prefixes| prefixes.contains(&route.prefix))
            })
            .cloned()
            .collect();
        // ADR-0126: the member sourcing a staged winner receives the
        // lane runner-up instead (adv(m)), so ITS blocked entry at that
        // slot is the runner-up when that carries OTC — derived from
        // the lane here rather than stored (both slots share the
        // `(prefix, 0)` residue key). `local_role` is group-uniform
        // (snapshot on this group), so one verdict covers every member;
        // the own-source filter above already withholds the winner from
        // `source(w)`. Together the two terms reproduce the pre-commit
        // backstop's per-member outcome, blocked(adv(m)), exactly.
        if self.per_client_best {
            #[cfg(any(test, feature = "bench-internals"))]
            let mut visits = 0_usize;
            let lane_blocked = |entry: &RunnerUp| {
                entry.winner_source == member
                    && super::distribution::otc_egress_blocked(&entry.route, self.local_role)
            };
            match prefixes {
                // The staged scope is the small side on the churn hot
                // path: probe the lane per staged prefix instead of
                // scanning the whole lane per member, keeping the pass
                // at O(members × staged) rather than O(members × lane).
                Some(prefixes) if prefixes.len() <= self.runner_up.len() => {
                    for prefix in prefixes {
                        #[cfg(any(test, feature = "bench-internals"))]
                        {
                            visits += 1;
                        }
                        if let Some(entry) = self.runner_up.get(prefix)
                            && lane_blocked(entry)
                        {
                            blocked.push(entry.route.clone());
                        }
                    }
                }
                // Resync (`None`): the whole table IS the scope, so the
                // lane scan is the small side by definition. A `Some`
                // scope wider than the lane keeps the scan for the same
                // reason.
                _ => {
                    for (prefix, entry) in &self.runner_up {
                        #[cfg(any(test, feature = "bench-internals"))]
                        {
                            visits += 1;
                        }
                        if prefixes.is_none_or(|prefixes| prefixes.contains(prefix))
                            && lane_blocked(entry)
                        {
                            blocked.push(entry.route.clone());
                        }
                    }
                }
            }
            #[cfg(any(test, feature = "bench-internals"))]
            assert_scoped_visit_bound(
                visits,
                prefixes.map_or(usize::MAX, HashSet::len),
                self.runner_up.len(),
            );
        }
        blocked
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
        let Some(counts) = self.source_counts.get_mut(&peer) else {
            return;
        };
        let decremented = counts[slot] > 0;
        if decremented {
            counts[slot] -= 1;
        }
        let empty = counts.iter().all(|&n| n == 0);
        if decremented {
            self.family_totals[slot] -= 1;
        }
        if empty {
            self.source_counts.remove(&peer);
        }
    }

    fn inc_source_slot(&mut self, peer: IpAddr, slot: usize) {
        self.source_counts.entry(peer).or_default()[slot] += 1;
        self.family_totals[slot] += 1;
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
            match &delta.source_attrs {
                Some(attrs) => {
                    self.source_attrs.insert(key, Arc::clone(attrs));
                }
                None => {
                    self.source_attrs.remove(&key);
                }
            }
            match &delta.policy_label {
                Some(label) => {
                    self.staged_labels.insert(key, Some(label.clone()));
                }
                None => {
                    self.staged_labels.remove(&key);
                }
            }
            self.table.insert(route.clone());
        } else {
            self.table.withdraw(&delta.prefix, delta.path_id);
            self.nh_overrides.remove(&key);
            self.source_attrs.remove(&key);
            self.staged_labels.remove(&key);
        }
    }

    /// Commit one recomputed exception-lane entry (ADR-0126 Decision
    /// 6: the lane is rebuilt from scratch every pass, so the commit
    /// is an unconditional replace-or-remove — equality suppression
    /// gates only the [`LaneDelta`] encoding, never the residue).
    /// Keeps `lane_counts` in sync: the incoming entry's winner-source
    /// row increments, the outgoing entry's decrements — so a
    /// winner-source flip under an unchanged runner-up moves the count
    /// even though no [`LaneDelta`] was encoded.
    /// `lane_otc_blocked_counts` rides the same transitions for
    /// entries the RFC 9234 backstop suppresses (`local_role` is a
    /// group-uniform snapshot, so the verdict never changes under an
    /// unmoved entry).
    fn apply_lane(&mut self, prefix: Prefix, entry: Option<RunnerUp>) {
        let slot = Self::count_slot(&prefix);
        let outgoing = match entry {
            Some(entry) => {
                self.lane_counts.entry(entry.winner_source).or_default()[slot] += 1;
                if super::distribution::otc_egress_blocked(&entry.route, self.local_role) {
                    self.lane_otc_blocked_counts
                        .entry(entry.winner_source)
                        .or_default()[slot] += 1;
                }
                self.runner_up.insert(prefix, entry)
            }
            None => self.runner_up.remove(&prefix),
        };
        if let Some(old) = outgoing {
            if let Some(counts) = self.lane_counts.get_mut(&old.winner_source) {
                counts[slot] = counts[slot].saturating_sub(1);
                if counts.iter().all(|&n| n == 0) {
                    self.lane_counts.remove(&old.winner_source);
                }
            }
            if super::distribution::otc_egress_blocked(&old.route, self.local_role)
                && let Some(counts) = self.lane_otc_blocked_counts.get_mut(&old.winner_source)
            {
                counts[slot] = counts[slot].saturating_sub(1);
                if counts.iter().all(|&n| n == 0) {
                    self.lane_otc_blocked_counts.remove(&old.winner_source);
                }
            }
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
            match &delta.policy_label {
                Some(label) => {
                    self.vpn_staged_labels
                        .insert(delta.key, Some(label.clone()));
                }
                None => {
                    self.vpn_staged_labels.remove(&delta.key);
                }
            }
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

    /// RFC 7947 control-decision input for a staged table entry: the
    /// SOURCE route's communities as captured at staging (empty when
    /// the source carried none). Table replay seams must decide
    /// suppression/prepend on this, never on the post-policy entry.
    pub(in crate::manager) fn source_control(
        &self,
        key: (Prefix, u32),
    ) -> (&[u32], &[LargeCommunity]) {
        source_control_input(self.source_attrs.get(&key))
    }

    /// Tag-only transition check for a pass that staged NO delta for
    /// `prefix` (the post-policy route was equality-suppressed): if the
    /// key stays staged while the SOURCE control communities changed —
    /// a difference policy erased post-policy — rs-control members'
    /// suppress/prepend verdicts may flip even though the shared wire
    /// form did not, so the pass records an [`RsTagTransition`].
    fn rs_tag_transition(
        &self,
        prefix: Prefix,
        source_attrs: Option<&Arc<Vec<PathAttribute>>>,
    ) -> Option<RsTagTransition> {
        let staged = self.table.get(&prefix, 0)?;
        let key = (prefix, 0);
        let prior = self.source_attrs.get(&key);
        (source_control_input(source_attrs) != source_control_input(prior)).then(|| {
            RsTagTransition {
                prefix,
                path_id: 0,
                route: staged.clone(),
                nh: self.nh_override(key),
                prior_source_attrs: prior.cloned(),
                source_attrs: source_attrs.cloned(),
            }
        })
    }

    /// Commit a pass's tag-only transitions into the source-attribute
    /// residue (the delta-borne updates ride [`Self::apply_delta`]).
    fn commit_rs_transitions(&mut self, transitions: &[RsTagTransition]) {
        for transition in transitions {
            let key = (transition.prefix, transition.path_id);
            match &transition.source_attrs {
                Some(attrs) => {
                    self.source_attrs.insert(key, Arc::clone(attrs));
                }
                None => {
                    self.source_attrs.remove(&key);
                }
            }
        }
    }

    /// The single ADR-0126 Decision 4 derivation of a member's
    /// advertised slot — `adv(m)` at one staged key:
    ///
    /// > adv(m) = for each prefix: `w` (the staged entry) if
    /// > `source(w) ≠ m`; else `r` (the lane entry) if the lane holds
    /// > one; else nothing — always at `path_id 0`.
    ///
    /// Decision 6's "no second bookkeeping path to diverge" is a code
    /// claim on this method: every read seam — queries, counts,
    /// counter replay — routes through this ONE definition instead of
    /// restating the `peer == member ⇒ skip` rule inline. For a plain
    /// group the lane is empty by construction AND gated off by
    /// `per_client_best`, so this reduces exactly to the historical
    /// skip rule. Meaningful for grouped unicast only (`path_id 0`);
    /// the VPN maps are an ADR-0126 non-goal.
    pub(in crate::manager) fn adv_entry(
        &self,
        member: IpAddr,
        prefix: &Prefix,
        path_id: u32,
    ) -> Option<AdvEntry<'_>> {
        let staged = self.table.get(prefix, path_id)?;
        if staged.peer != member {
            let key = (*prefix, path_id);
            return Some(AdvEntry {
                route: staged,
                nh: self.nh_overrides.get(&key),
                source_attrs: self.source_attrs.get(&key),
                policy_label: self.staged_labels.get(&key).and_then(Option::as_ref),
            });
        }
        if !self.per_client_best {
            return None;
        }
        let entry = self.runner_up.get(prefix)?;
        Some(AdvEntry {
            route: &entry.route,
            nh: entry.nh.as_ref(),
            source_attrs: entry.source_attrs.as_ref(),
            policy_label: entry.policy_label.as_ref(),
        })
    }

    /// [`Self::adv_entry`] minus the RFC 9234 pre-commit backstop's
    /// outcome: `None` when the resolved slot's route is OTC-blocked
    /// toward this group (`local_role` is group-uniform, so one
    /// verdict covers every member). Operator-facing surfaces — the
    /// advertised-route queries and the count synthesis's rejection
    /// overlays — read this form: the backstop strips a blocked route
    /// from every emission, so the ungrouped path's Adj-RIB-Out never
    /// holds it and reported state must not either. Enforcement and
    /// replay seams keep reading [`Self::adv_entry`]: their emissions
    /// pass through the backstop itself. A plain group's staged
    /// entries are never blocked (its in-walk gate rejects them), so
    /// this reduces to `adv_entry` there.
    pub(in crate::manager) fn adv_entry_post_backstop(
        &self,
        member: IpAddr,
        prefix: &Prefix,
        path_id: u32,
    ) -> Option<AdvEntry<'_>> {
        self.adv_entry(member, prefix, path_id)
            .filter(|entry| !super::distribution::otc_egress_blocked(entry.route, self.local_role))
    }

    /// Per-family count of `member`'s `adv(m)` slots the RFC 9234
    /// backstop suppresses: the blocked staged winners it does not
    /// source plus its blocked lane substitutions — the subtraction
    /// the count synthesis applies so it reports the backstop's
    /// outcome. Zero for plain groups: the aggregates are only
    /// maintained where the residue describes staged winners.
    fn otc_suppressed_counts(&self, member: IpAddr) -> [usize; 2] {
        if !self.per_client_best {
            return [0; 2];
        }
        let own = self
            .otc_blocked_sources
            .get(&member)
            .copied()
            .unwrap_or_default();
        let lane = self
            .lane_otc_blocked_counts
            .get(&member)
            .copied()
            .unwrap_or_default();
        [
            self.otc_blocked_totals[0].saturating_sub(own[0]) + lane[0],
            self.otc_blocked_totals[1].saturating_sub(own[1]) + lane[1],
        ]
    }

    /// Number of unicast routes `member` currently has advertised: the
    /// group table minus the member's own-sourced entries plus its
    /// lane substitutions, minus the slots the RFC 9234 backstop
    /// suppresses (the family-summed count of
    /// [`Self::adv_entry_post_backstop`], ADR-0126 Decision 4). O(1).
    pub(in crate::manager) fn advertised_count_for(&self, member: IpAddr) -> usize {
        let own = self
            .source_counts
            .get(&member)
            .map_or(0, |counts| counts[0] + counts[1]);
        let lane = self
            .lane_counts
            .get(&member)
            .map_or(0, |counts| counts[0] + counts[1]);
        let otc = self.otc_suppressed_counts(member);
        (self.table.len().saturating_sub(own) + lane).saturating_sub(otc[0] + otc[1])
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
    /// 8671 stat type 17 input): table minus own-sourced plus the
    /// member's lane substitutions minus its RFC 9234
    /// backstop-suppressed slots, per unicast slot (ADR-0126
    /// Decision 4). Zero-count families omitted.
    pub(in crate::manager) fn family_counts_for(&self, member: IpAddr) -> Vec<((Afi, Safi), u64)> {
        const FAMILIES: [(Afi, Safi); 4] = [
            (Afi::Ipv4, Safi::Unicast),
            (Afi::Ipv6, Safi::Unicast),
            (Afi::Ipv4, Safi::MplsVpn),
            (Afi::Ipv6, Safi::MplsVpn),
        ];
        let totals = self.family_totals;
        let own = self.source_counts.get(&member).copied().unwrap_or_default();
        let lane = self.lane_counts.get(&member).copied().unwrap_or_default();
        let otc = self.otc_suppressed_counts(member);
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
                    (0 | 1, _) => {
                        ((totals[slot].saturating_sub(own[slot]) + lane[slot])
                            .saturating_sub(otc[slot])) as u64
                    }
                    _ => totals[slot].saturating_sub(own[slot]) as u64,
                };
                (count > 0).then_some((family, count))
            })
            .collect()
    }

    /// Snapshot of `member`'s advertised unicast view — `adv(m)` per
    /// staged key ([`Self::adv_entry`], ADR-0126 Decision 4) — the
    /// baseline for a regroup's one-shot diff. A substituted slot
    /// records the LANE entry's wire form (rs-decided and rewritten
    /// from the lane's captured source attributes, exactly how staged
    /// entries are recorded), or the destination-side diff would
    /// compare wire state to a route the member never received.
    fn member_view_snapshot(
        &self,
        member: IpAddr,
        rs_control: Option<(u32, u32)>,
        rejected: &HashSet<ExactExportKey>,
    ) -> FxHashMap<(Prefix, u32), Route> {
        use super::distribution::rs_control::{rs_control_route_rewrite, rs_control_suppressed};
        self.table
            .iter()
            .filter_map(|staged| {
                let key = (staged.prefix, staged.path_id);
                // The substitution shares the staged slot's key, so the
                // member-local rejection overlay applies identically.
                if rejected.contains(&ExactExportKey::Unicast(key.0, key.1)) {
                    return None;
                }
                let entry = self.adv_entry(member, &staged.prefix, staged.path_id)?;
                let (communities, large_communities) = source_control_input(entry.source_attrs);
                // LAN-474: a key whose SOURCE communities suppress it
                // toward the member was never on its wire — the
                // snapshot records true wire state, not the shared
                // table.
                if rs_control_suppressed(communities, large_communities, rs_control) {
                    return None;
                }
                let mut route = entry.route.clone();
                rs_control_route_rewrite(&mut route, large_communities, rs_control);
                Some((key, route))
            })
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
        rejected: &HashSet<ExactExportKey>,
    ) -> FxHashMap<VpnRouteKey, VpnRibRoute> {
        self.table
            .iter_vpn()
            .filter(|route| {
                route.peer != member
                    && rt_passes(filter, route)
                    && !rejected.contains(&ExactExportKey::Vpn(route.key()))
            })
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
        current: &[(PolicyFilteredRouteKey, Option<PolicyLabel>)],
    ) {
        for prefix in staged {
            self.policy_filtered.remove(prefix);
        }
        for (key, label) in current {
            self.policy_filtered
                .entry(key.prefix)
                .or_default()
                .insert((key.source_peer, key.path_id), label.clone());
        }
    }

    /// The member's view of the group-verdict denial set, restamped
    /// with the member as target and restricted to `prefixes` (the
    /// pass's evaluation scope). The member's own-sourced denials are
    /// excluded — the per-peer path's split horizon returns before the
    /// policy evaluation for those.
    ///
    /// Iterates whichever side is smaller: on the churn hot path the
    /// staged scope is a handful of prefixes against a residue that can
    /// hold most of the table, so probing the residue per staged prefix
    /// keeps each distribution pass at O(members × staged) instead of
    /// O(members × residue) — the per-pass lane-scan shape that
    /// saturated the actor at high overlap. A scope wider than the
    /// residue (resync-scale callers pass the whole table) keeps the
    /// residue scan, which is the small side by the same argument.
    pub(in crate::manager) fn policy_filtered_for_member(
        &self,
        member: IpAddr,
        prefixes: &HashSet<Prefix>,
    ) -> Vec<PolicyFilteredRouteKey> {
        #[cfg(any(test, feature = "bench-internals"))]
        let mut visits = 0_usize;
        let mut restamped = Vec::new();
        let mut collect =
            |prefix: Prefix, denials: &FxHashMap<(IpAddr, u32), Option<PolicyLabel>>| {
                restamped.extend(
                    denials
                        .keys()
                        .filter(|(source_peer, _)| *source_peer != member)
                        .map(|&(source_peer, path_id)| PolicyFilteredRouteKey {
                            target_peer: member,
                            source_peer,
                            prefix,
                            path_id,
                        }),
                );
            };
        if prefixes.len() <= self.policy_filtered.len() {
            for prefix in prefixes {
                #[cfg(any(test, feature = "bench-internals"))]
                {
                    visits += 1;
                }
                if let Some(denials) = self.policy_filtered.get(prefix) {
                    collect(*prefix, denials);
                }
            }
        } else {
            for (prefix, denials) in &self.policy_filtered {
                #[cfg(any(test, feature = "bench-internals"))]
                {
                    visits += 1;
                }
                if prefixes.contains(prefix) {
                    collect(*prefix, denials);
                }
            }
        }
        #[cfg(any(test, feature = "bench-internals"))]
        assert_scoped_visit_bound(visits, prefixes.len(), self.policy_filtered.len());
        restamped
    }
}

/// Tripwire for the scoped derived-view queries: a query must touch at
/// most `min(scope, residue)` slots of the residue it consults, keeping
/// the per-pass emit cost O(members × staged prefixes). Restoring a
/// per-member full scan of the lane or denial residue trips this in
/// `cargo test` and in the bench-internals smoke instead of surfacing
/// as actor saturation four hours into a campaign. Compiled into test
/// and bench-internals builds only.
#[cfg(any(test, feature = "bench-internals"))]
fn assert_scoped_visit_bound(visits: usize, scope: usize, residue: usize) {
    assert!(
        visits <= scope.min(residue),
        "scoped derived-view query visited {visits} residue slots; \
         bound is min(scope {scope}, residue {residue})"
    );
}

impl RibManager {
    /// The group id a registered peer is a member of, if any.
    pub(in crate::manager) fn grouped_member_of(&self, peer: IpAddr) -> Option<usize> {
        match self.update_groups.members.get(&peer) {
            Some(GroupMembership::Grouped(id)) => Some(*id),
            _ => None,
        }
    }

    /// Whether `peer`'s outbound channel can never accept another update:
    /// the peer is deregistered, or its session receiver has been dropped
    /// (the session is gone). A full-but-open channel is NOT gone — it
    /// drains and the ordinary dirty resync retries it.
    pub(in crate::manager) fn outbound_channel_gone(&self, peer: IpAddr) -> bool {
        self.outbound_peers
            .get(&peer)
            .is_none_or(tokio::sync::mpsc::Sender::is_closed)
    }

    /// Drop a peer's dirty-resync state because its outbound channel is
    /// gone: the resync timer must not re-arm against a channel that can
    /// never accept — a backlog of dead sessions (e.g. after shutdown tore
    /// the TCP sessions down) would otherwise livelock the actor loop and
    /// block process exit. Session teardown proper stays with the
    /// `PeerDown` path; this only stops the retry.
    pub(in crate::manager) fn drop_gone_dirty_peer(&mut self, peer: IpAddr) {
        self.dirty_peers.remove(&peer);
        if let Some(gid) = self.grouped_member_of(peer)
            && let Some(group) = self.group_ribs.get_mut(&gid)
        {
            group.dirty_members.remove(&peer);
        }
    }

    /// Mark a peer's outbound channel dirty for the resync timer, and —
    /// for a grouped member — flag it in its group so tombstone
    /// maintenance starts. Every `dirty_peers` insertion site routes
    /// through here — including the send-failure retry path, so this is
    /// where a closed channel (peer gone) is distinguished from a full
    /// one (peer slow): only the latter may re-arm the resync timer.
    pub(in crate::manager) fn mark_outbound_dirty(&mut self, peer: IpAddr) {
        if self.outbound_channel_gone(peer) {
            debug!(%peer, "outbound channel closed — dropping dirty state instead of re-marking");
            self.drop_gone_dirty_peer(peer);
            return;
        }
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
                        bump_counter_row(&mut permit_rows, label.as_ref(), PolicyAction::Permit);
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
            let rejected = self
                .peer_unexportable
                .get(&peer)
                .cloned()
                .unwrap_or_default();
            let rs_control = self
                .peer_rs_control
                .get(&peer)
                .copied()
                .zip(self.peer_asn.get(&peer).copied());
            let baseline: Option<RegroupBaseline> = match prev_gid {
                Some(gid) => {
                    let group = self.group_ribs.get(&gid);
                    let base = group.map(|g| RegroupBaseline {
                        unicast: g.member_view_snapshot(peer, rs_control, &rejected),
                        vpn: g.member_vpn_view_snapshot(peer, rt_filter.as_ref(), &rejected),
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
                // ADR-0113: the private prefix index is a limited peer's
                // admitted set, and it is about to be cleared — transfer that
                // ownership into the bounded member set first.
                self.carry_outbound_admitted_across_regroup(peer, true);
                if let Some(rib_out) = self.adj_ribs_out.get_mut(&peer) {
                    rib_out.clear_unicast();
                    if vpn_groupable {
                        rib_out.clear_vpn();
                    }
                }
            }
            if prev_gid.is_some() && new_gid.is_none() {
                // Leaving for the per-peer path: the private Adj-RIB-Out is
                // re-seeded below and becomes authoritative again, so the
                // bounded member set is released rather than double-counted.
                self.carry_outbound_admitted_across_regroup(peer, false);
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
        // Every membership seam funnels through here (registration,
        // recompute, per-peer policy install): a join landing on the gid
        // of a mid-walk destination prestage must discard the prestage
        // BEFORE the member replays any table — adopting the partial
        // table would record the remaining walk's routes as advertised
        // without ever emitting them (LAN-463). The discard makes the
        // group absent again, so the ordinary rebuild below runs.
        self.discard_destination_prestage_on_membership(gid);
        self.ensure_group_table(gid, peer);
        self.install_group_member(gid, peer);
    }

    /// Build the group's staged table when it does not exist yet — the
    /// join-time build pass (one shared staging walk, deltas discarded:
    /// correct only while the group is memberless). `peer` is the
    /// exemplar whose group-uniform staging inputs seed the profile.
    pub(in crate::manager) fn ensure_group_table(&mut self, gid: usize, peer: IpAddr) {
        if !self.group_ribs.contains_key(&gid) {
            let group = GroupRibOut::new(
                // `share()`, not `clone()`: the snapshot must keep
                // feeding the installed chain's ADR-0096 hit counters.
                self.export_policy_for(peer).map(PolicyChain::share),
                self.peer_is_ebgp.get(&peer).copied().unwrap_or(false),
                self.peer_interpret_rfc1997.contains(&peer),
                self.peer_is_rr_client.get(&peer).copied().unwrap_or(false),
                self.peer_local_roles.get(&peer).copied().flatten(),
                self.peer_sendable_families
                    .get(&peer)
                    .cloned()
                    .unwrap_or_default(),
                self.peer_advertised_llgr_families
                    .get(&peer)
                    .cloned()
                    .unwrap_or_default(),
                // ADR-0126 Decision 1: the staging mode derives from
                // the group key's `per_client_best` bit.
                self.update_groups
                    .group_key(gid)
                    .is_some_and(|key| key.per_client_best),
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
    }

    /// Install one peer into an already-created group and make the peer's
    /// operator-visible policy handle share the group's actual counter
    /// instance. Every grouped membership path uses this seam: ordinary
    /// recompute/fallback, rollback to a prior group, and the optimized clean
    /// transition commit. Ungrouped peers never pass through it and retain
    /// their independently installed chain.
    fn install_group_member(&mut self, gid: usize, peer: IpAddr) {
        // Grouped unicast state belongs to GroupRibOut. Install the private
        // multi-family table with no unicast reservation before any family
        // can become its first creator; non-unicast state still lives here,
        // and an eventual ungroup grows the slab while seeding its baseline.
        self.adj_ribs_out
            .entry(peer)
            .or_insert_with(|| AdjRibOut::new(peer));

        let export_chain = self
            .group_ribs
            .get(&gid)
            .expect("group must exist before installing a member")
            .export_chain
            .as_ref()
            .map(PolicyChain::share);
        self.peer_export_policies.insert(peer, export_chain);

        // The joining member's advertised-count seed (RTC groups only):
        // the O(table) walk rides the join replay's existing cost.
        let filter = self.member_rt_filter(peer);
        if let Some(group) = self.group_ribs.get_mut(&gid) {
            group.members.insert(peer);
            group.recompute_vpn_member_counts(peer, filter.as_ref());
        }
    }

    fn leave_group(&mut self, gid: usize, peer: IpAddr) {
        self.leave_group_without_gauge_refresh(gid, peer);
        self.refresh_group_residue_gauge();
    }

    fn leave_group_without_gauge_refresh(&mut self, gid: usize, peer: IpAddr) {
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

    /// Apply a transport slow-peer flag change (LAN-470,
    /// `slow_peer_isolation`): track the peer in
    /// `slow_isolated_peers` and re-run the membership lifecycle so a
    /// grouped slow peer moves to the per-peer fallback path (and a
    /// recovered one regroups through the ordinary baseline diff).
    /// Same recipe as the export-policy replacement seam: recompute,
    /// mark dirty unless key-stable, distribute.
    pub(super) fn handle_peer_slow_state(&mut self, peer: IpAddr, slow: bool) {
        let changed = if slow {
            self.slow_isolated_peers.insert(peer)
        } else {
            self.slow_isolated_peers.remove(&peer)
        };
        if !changed || !self.update_groups.members.contains_key(&peer) {
            // Duplicate signal, or no outbound registration yet — the
            // set alone steers the eventual registration's classify.
            return;
        }
        info!(
            %peer,
            slow,
            "slow-peer isolation: recomputing update-group membership"
        );
        let before = self.grouped_member_of(peer);
        self.recompute_update_group(peer);
        let key_stable = before.is_some() && before == self.grouped_member_of(peer);
        if !key_stable {
            self.mark_outbound_dirty(peer);
        }
        self.distribute_changes_after_advertised_page_advance(&HashSet::new(), &HashSet::new());
    }

    /// Build the classifier input for one peer.
    ///
    /// `with_policy_fingerprint` gates the O(chain-size) planning-identity
    /// digest: runtime classification (registration, policy edits, the
    /// fenced clean-transition phases) passes `false` because runtime group
    /// identity is the interned chain content, not the fingerprint — at IRR
    /// scale rendering the fingerprint per member wedged grouped reloads for
    /// the whole observation window (LAN-886). The observational snapshot
    /// surface passes `true` so live-vs-candidate planning comparisons keep
    /// their chain-content dimension.
    fn update_group_classifier_input(
        &self,
        peer: IpAddr,
        chain: Option<&PolicyChain>,
        orf_installed: bool,
        with_policy_fingerprint: bool,
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
            policy_fingerprint: with_policy_fingerprint
                .then(|| chain.map(|value| value.groupability_fingerprint().to_string()))
                .flatten(),
            policy_provenance: chain.map(|value| value.groupability_provenance().to_string()),
            policy_requires_peer_context: chain.is_some_and(PolicyChain::requires_peer_context),
            target_is_ebgp: self.peer_is_ebgp.get(&peer).copied().unwrap_or(false),
            target_is_rr_client: self.peer_is_rr_client.get(&peer).copied().unwrap_or(false),
            target_local_role: self
                .peer_local_roles
                .get(&peer)
                .copied()
                .flatten()
                .map(BgpRole::to_u8),
            interpret_rfc1997: self.peer_interpret_rfc1997.contains(&peer),
            sendable_families,
            llgr_families,
            // Paths-Limit needs no v2 key dimension today: every Add-Path-send
            // peer is deliberately private (classified `AddPathSend`) and stages
            // with its own exact family-local cap. If Add-Path grouping is
            // introduced, the effective `(AFI, SAFI) -> max` map MUST become part
            // of GroupKey before this disqualifier is relaxed.
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
        send_update_group_snapshot(reply, |reply| {
            let mut peers = self
                .update_groups
                .members
                .keys()
                .copied()
                .collect::<Vec<_>>();
            materialize_update_group_snapshot(reply, &mut peers, |peer| {
                let membership = self
                    .update_groups
                    .members
                    .get(&peer)
                    .expect("snapshot peer collected from update-group membership");
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
                    true,
                );
                UpdateGroupPeerSnapshot {
                    peer,
                    classification: classify_update_group(input.clone()),
                    input,
                    runtime_membership: membership.label(),
                }
            })
        });
    }

    pub(super) fn handle_query_update_group_comparison(
        &self,
        primary: IpAddr,
        comparison: IpAddr,
        reply: tokio::sync::oneshot::Sender<UpdateGroupPeerComparison>,
    ) {
        let _ = reply.send(self.update_group_comparison(primary, comparison));
    }

    /// Compute a comparison without crossing the actor boundary.  The
    /// aggregate `NeighborService` snapshot uses this alongside its primary
    /// peer row, so both values describe one manager generation.
    pub(super) fn update_group_comparison(
        &self,
        primary: IpAddr,
        comparison: IpAddr,
    ) -> UpdateGroupPeerComparison {
        let primary_runtime = self.update_groups.members.get(&primary);
        let comparison_runtime = self.update_groups.members.get(&comparison);
        let primary_membership = primary_runtime.map_or(
            UpdateGroupComparisonMembership::Unknown,
            GroupMembership::comparison_membership,
        );
        let comparison_membership = comparison_runtime.map_or(
            UpdateGroupComparisonMembership::Unknown,
            GroupMembership::comparison_membership,
        );

        let (verdict, differences) = match (primary_runtime, comparison_runtime) {
            (None, _) | (_, None) => (UpdateGroupComparisonVerdict::Unknown, Vec::new()),
            (Some(GroupMembership::Grouped(left)), Some(GroupMembership::Grouped(right))) => {
                if left == right {
                    (UpdateGroupComparisonVerdict::Shared, Vec::new())
                } else {
                    match (
                        self.update_groups.group_key(*left),
                        self.update_groups.group_key(*right),
                    ) {
                        (Some(left), Some(right)) => (
                            UpdateGroupComparisonVerdict::Separate,
                            grouped_differences(left, right),
                        ),
                        _ => (UpdateGroupComparisonVerdict::Unknown, Vec::new()),
                    }
                }
            }
            (Some(_), Some(_)) => (UpdateGroupComparisonVerdict::Private, Vec::new()),
        };

        UpdateGroupPeerComparison {
            primary_update_group: primary_runtime
                .map(GroupMembership::label)
                .unwrap_or_default(),
            verdict,
            primary_membership,
            comparison_membership,
            differences,
        }
    }

    /// Re-derive every update-group gauge from the membership map.
    /// Registered peers are at most low-thousands and this runs only on
    /// lifecycle/config events, so a full recount beats incremental
    /// bookkeeping.
    fn refresh_update_group_gauges(&self) {
        let mut member_counts: HashMap<usize, i64> = HashMap::new();
        let mut fallback = 0i64;
        // Recomputed for every member on each call, so the per-peer group
        // gauge is refreshed on every membership-change path (join, leave,
        // grouped↔grouped move, grouped↔fallback) — no guard. Peers that
        // left the map are dropped here and reaped on peer-down.
        for (peer, membership) in &self.update_groups.members {
            let group_id = if let GroupMembership::Grouped(id) = membership {
                *member_counts.entry(*id).or_default() += 1;
                i64::try_from(*id).unwrap_or(i64::MAX)
            } else {
                fallback += 1;
                rustbgpd_telemetry::BgpMetrics::UPDATE_GROUP_UNGROUPED
            };
            self.metrics
                .set_peer_update_group(&peer.to_string(), group_id);
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
        // Group lifecycle (join builds a lane, the last leave drops
        // it) mutates lane state too, so the membership seams refresh
        // the lane gauge alongside the staging seam.
        self.refresh_lane_gauge();
    }

    /// Re-derive the ADR-0126 exception-lane gauge: total runner-up
    /// entries across per-client-best groups — the observable for the
    /// design's O(overlapped prefixes) state claim (Decision 9).
    /// Called from every lane mutation seam — the staging commit and
    /// the group-lifecycle refresh — never behind a growth-only guard
    /// (the gate-metric rule). O(groups) integer sums.
    pub(in crate::manager) fn refresh_lane_gauge(&self) {
        let entries = self
            .group_ribs
            .values()
            .map(|group| group.runner_up.len())
            .sum::<usize>();
        self.metrics
            .set_update_group_runner_up_entries(i64::try_from(entries).unwrap_or(i64::MAX));
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

    /// Answer the neighbor API's combined outbound-state query atomically.
    pub(super) fn handle_query_peer_outbound_state(
        &mut self,
        peer: IpAddr,
        reply: tokio::sync::oneshot::Sender<crate::update::PeerOutboundState>,
    ) {
        let _ = reply.send(self.peer_outbound_state(peer));
    }

    /// Compute the atomically-read outbound projection for one peer.
    pub(super) fn peer_outbound_state(&self, peer: IpAddr) -> crate::update::PeerOutboundState {
        use crate::update::PeerOutboundState;
        let update_group = self
            .update_groups
            .membership(peer)
            .map(GroupMembership::label)
            .unwrap_or_default();
        let orr_resolved = self
            .peer_orr_vantage
            .get(&peer)
            .is_some_and(|vantage| self.orr.spf.contains_key(vantage));
        let effective_distribution_mode = classify_effective_distribution_mode(
            self.outbound_peers.contains_key(&peer),
            self.peer_has_any_add_path_send(peer),
            self.peer_per_client_best.contains(&peer),
            orr_resolved,
        );
        let outbound_prefix_limits = self.outbound_prefix_limit_rows(peer);
        PeerOutboundState {
            update_group,
            effective_distribution_mode,
            selection_deferral: self
                .selection_deferral
                .as_ref()
                .map_or_else(Vec::new, |selection| selection.peer_snapshot(peer)),
            outbound_prefix_limits,
        }
    }
}

#[expect(
    clippy::fn_params_excessive_bools,
    reason = "pure classifier mirrors four independent live RIB membership predicates"
)]
fn classify_effective_distribution_mode(
    registered: bool,
    add_path: bool,
    per_client_best: bool,
    orr_resolved: bool,
) -> crate::update::EffectiveDistributionMode {
    use crate::update::EffectiveDistributionMode;

    // This scalar reports the dominant live selection surface. An inactive
    // registration is always UNKNOWN; for an active peer, ADD_PATH outranks
    // PER_CLIENT_BEST, which outranks ORR, then ordinary SINGLE_BEST.
    if !registered {
        EffectiveDistributionMode::Unknown
    } else if add_path {
        EffectiveDistributionMode::AddPath
    } else if per_client_best {
        EffectiveDistributionMode::PerClientBest
    } else if orr_resolved {
        EffectiveDistributionMode::Orr
    } else {
        EffectiveDistributionMode::SingleBest
    }
}

#[cfg(test)]
mod tests;
