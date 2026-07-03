//! Update-group fingerprint registry — SHADOW MODE (slice 1 of the
//! update-groups arc).
//!
//! Peers whose staged outbound routes would be identical share a
//! [`GroupKey`]; peers hitting a v1 disqualifier fall back to the
//! per-peer path with a recorded reason. In this slice the registry is
//! purely observational: membership is computed at session
//! registration, recomputed on export-policy replacement, and removed
//! on teardown — but **nothing reads it for distribution decisions**.
//! Every peer stays on today's per-peer distribution path.
//!
//! The one load-bearing property proven here: the export-chain
//! component is keyed by chain **content** (interned via `PolicyChain`
//! `PartialEq`), never by `Arc`/instance identity — so a SIGHUP / rpol
//! overlay / ADR-0076 txn that reinstalls a content-identical chain
//! keeps the key stable and does not count as a regroup.

use std::collections::HashMap;
use std::net::IpAddr;

use rustbgpd_policy::PolicyChain;
use rustbgpd_wire::{Afi, Safi};

use super::RibManager;

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
            Self::OrrVantage => "orr_vantage".to_string(),
            Self::OrfInstalled => "orf_installed".to_string(),
        }
    }
}

/// The shadow-mode registry: interned chain contents, group keys, and
/// per-peer membership. Owned by the [`RibManager`] task like all other
/// RIB state — no locking.
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
    members: HashMap<IpAddr, GroupMembership>,
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

impl RibManager {
    /// Compute (or recompute) a registered peer's update-group
    /// membership from the fingerprint inputs already in hand, record
    /// it, and refresh the observability gauges. Called at the session
    /// registration seam and the export-policy replacement seam (which
    /// is also where SIGHUP rpol overlays and ADR-0076 live-impact txns
    /// land). Shadow mode: distribution never reads the result.
    pub(super) fn recompute_update_group(&mut self, peer: IpAddr) {
        let membership = self.compute_update_group_membership(peer);
        let previous = self.update_groups.members.insert(peer, membership.clone());
        // A regroup is an already-registered peer whose membership
        // moved; first registration and content-identical policy
        // reinstalls (same interned index ⇒ same key) don't count.
        if previous.is_some_and(|prev| prev != membership) {
            self.metrics.record_update_group_regroup();
        }
        self.refresh_update_group_gauges();
    }

    /// Drop a departing peer's membership (the
    /// `clear_outbound_peer_state` seam — `PeerDown`, `PeerDeleted`, GR
    /// teardown, and collision replacement all route through it).
    pub(super) fn remove_update_group_member(&mut self, peer: IpAddr) {
        if self.update_groups.members.remove(&peer).is_some() {
            self.refresh_update_group_gauges();
        }
    }

    /// The fingerprint itself: disqualifiers first (design §1), then
    /// the group key from RIB-staging inputs.
    fn compute_update_group_membership(&mut self, peer: IpAddr) -> GroupMembership {
        if self
            .export_policy_for(peer)
            .is_some_and(PolicyChain::requires_peer_context)
        {
            return GroupMembership::PolicyPeerContext;
        }
        if self.peer_has_any_add_path_send(peer) {
            return GroupMembership::AddPathSend;
        }
        if self.peer_orr_vantage.contains_key(&peer) {
            return GroupMembership::OrrVantage;
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
        if orf_negotiated || self.peer_orf_filters.contains_key(&peer) {
            return GroupMembership::OrfInstalled;
        }

        // Clone released before the &mut intern below; chains are small
        // and this runs at config/session-lifecycle frequency only.
        let chain = self.export_policy_for(peer).cloned();
        let chain_idx = chain
            .as_ref()
            .map(|chain| self.update_groups.intern_chain(chain));
        let sendable = self.peer_sendable_families.get(&peer);
        let contains = |family: (Afi, Safi)| sendable.is_some_and(|f| f.contains(&family));
        let mut llgr_families: Vec<(u16, u8)> = self
            .peer_advertised_llgr_families
            .get(&peer)
            .map(|families| {
                families
                    .iter()
                    .map(|&(afi, safi)| (afi as u16, safi as u8))
                    .collect()
            })
            .unwrap_or_default();
        llgr_families.sort_unstable();
        llgr_families.dedup();
        let key = GroupKey {
            chain: chain_idx,
            target_is_ebgp: self.peer_is_ebgp.get(&peer).copied().unwrap_or(false),
            target_is_rr_client: self.peer_is_rr_client.get(&peer).copied().unwrap_or(false),
            sendable_ipv4_unicast: contains((Afi::Ipv4, Safi::Unicast)),
            sendable_ipv6_unicast: contains((Afi::Ipv6, Safi::Unicast)),
            llgr_families,
        };
        GroupMembership::Grouped(self.update_groups.group_for(key))
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
        for id in 0..self.update_groups.groups.len() {
            match member_counts.get(&id) {
                Some(count) => self
                    .metrics
                    .set_update_group_members(&id.to_string(), *count),
                None => self.metrics.remove_update_group_members(&id.to_string()),
            }
        }
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
