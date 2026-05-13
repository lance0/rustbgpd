//! Dataplane intent and report types — Gate 7b boundary.
//!
//! The daemon publishes [`DataplaneIntent`] snapshots to the Linux
//! dataplane crate (`crates/evpn-linux`) over a
//! `tokio::sync::watch::Sender<Arc<DataplaneIntent>>`. The dataplane
//! actor reconciles its kernel state toward each received snapshot and
//! returns [`DataplaneReport`] values describing what was applied or
//! failed against the corresponding `intent_generation`.
//!
//! These types live in `crates/evpn` rather than `crates/evpn-linux`
//! deliberately — see ADR-0054 §1 / §2 — so that:
//!
//! - The daemon can construct intents on platforms that don't compile
//!   the netlink crate (macOS dev builds).
//! - A future RR-only feature flag can drop `rustbgpd-evpn-linux`
//!   entirely while leaving the intent surface untouched.
//! - The diff and projection unit tests run with no Linux dependencies.
//!
//! ## Reference
//!
//! - ADR-0054 §2 (snapshot/watch input)
//! - ADR-0054 §8 (failures surface as status, not domain mutation)

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;

use crate::ip_vrf::{IpVrfId, IpVrfStatus, IpVrfTable};
use crate::mac::{MacAddress, RemoteMacTable};
use crate::{DfRole, EvpnInstanceId, EvpnInstanceTable};
use rustbgpd_wire::{EthernetSegmentIdentifier, EthernetTagId};

/// Complete desired-state snapshot fed to the Linux dataplane.
///
/// The `generation` counter is the daemon's monotonic publish counter.
/// The dataplane echoes it back on [`DataplaneReport::intent_generation`]
/// so the daemon can correlate "I sent gen N" with "Linux applied/failed
/// gen N" without timestamp guesswork.
///
/// `instances`, `remote_macs`, `bum_enforcement`, `ip_vrfs`, and
/// `remote_ip_prefixes` are `Arc` so the daemon can re-publish a
/// near-identical snapshot (e.g., only the [`RemoteMacTable`]
/// changed) without cloning the full instance / VRF tables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataplaneIntent {
    /// Daemon-side monotonic counter. Strictly increases.
    pub generation: u64,
    /// Desired EVPN instance set on this VTEP.
    pub instances: Arc<EvpnInstanceTable>,
    /// Desired remote-MAC programming for the kernel FDB.
    pub remote_macs: Arc<RemoteMacTable>,
    /// Desired BUM forwarding role per `(ESI, VNI)`. Gate 8b's first
    /// dataplane slice consumes this as an observable enforcement
    /// intent only: the Linux actor resolves bridge / VXLAN / CE-port
    /// identity and reports the plan, but does not mutate kernel
    /// filters until the concrete primitive is selected.
    pub bum_enforcement: Arc<BumEnforcementTable>,
    /// Desired IP-VRF set on this VTEP (Gate 9, ADR-0058). Empty for
    /// any deployment without `[[evpn_ip_vrfs]]` config blocks; the
    /// Linux dataplane short-circuits its `probe_ip_vrfs` netlink dump
    /// when this is empty, so RR-only and L2-only deployments incur
    /// zero added cost.
    pub ip_vrfs: Arc<IpVrfTable>,
    /// Desired remote IP-prefix installs per `(IpVrfId, prefix)`
    /// (Gate 9 slice 6c). The supervisor projects received Type 5
    /// routes through `crate::ip_vrf::project_ip_prefix_routes` once
    /// per pass and re-publishes the resulting
    /// [`crate::ip_vrf::RemoteIpPrefixTable`] here. The Linux
    /// reconciler turns each `RemoteIpPrefixEntry` into a kernel
    /// route + L3VXLAN neighbor + L3VXLAN FDB triple, with
    /// refcounting on `(IpVrfId, vtep_ip, router_mac)` so the
    /// shared L2 resolution objects survive while any installed
    /// prefix still needs them. Empty when no `[[evpn_ip_vrfs]]`
    /// are configured.
    pub remote_ip_prefixes: Arc<crate::ip_vrf::RemoteIpPrefixTable>,
}

impl DataplaneIntent {
    /// Construct an empty intent at generation 0. Suitable as the
    /// initial value of a `watch` channel before the first real
    /// publish lands.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            generation: 0,
            instances: Arc::new(EvpnInstanceTable::new()),
            remote_macs: Arc::new(RemoteMacTable::new()),
            bum_enforcement: Arc::new(BumEnforcementTable::new()),
            ip_vrfs: Arc::new(IpVrfTable::new()),
            remote_ip_prefixes: Arc::new(crate::ip_vrf::RemoteIpPrefixTable::new()),
        }
    }
}

/// Desired forwarding action derived from the local DF role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BumForwardingAction {
    /// Local PE is DF for the segment/VNI and may forward BUM toward
    /// the CE-facing side.
    Allow,
    /// Local PE is Non-DF for the segment/VNI and must suppress BUM
    /// toward the CE-facing side once Gate 8b kernel enforcement lands.
    Suppress,
}

impl BumForwardingAction {
    /// Derive the dataplane action from the DF role.
    #[must_use]
    pub const fn from_df_role(role: DfRole) -> Self {
        match role {
            DfRole::Df => Self::Allow,
            DfRole::NonDf => Self::Suppress,
        }
    }

    /// Lowercase string for logs / future CLI output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Suppress => "suppress",
        }
    }
}

/// Stable key for one BUM-enforcement row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BumEnforcementKey {
    /// Ethernet Segment the role applies to.
    pub esi: EthernetSegmentIdentifier,
    /// Member VNI the role applies to.
    pub vni: EvpnInstanceId,
}

/// One desired BUM-enforcement row from the daemon to the dataplane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BumEnforcementEntry {
    /// Ethernet Segment the role applies to.
    pub esi: EthernetSegmentIdentifier,
    /// Member VNI the role applies to.
    pub vni: EvpnInstanceId,
    /// Local PE's DF role for `(esi, vni)`.
    pub role: DfRole,
    /// Desired forwarding action derived from [`Self::role`].
    pub action: BumForwardingAction,
    /// Operator-configured bridge name for the VNI. The Linux
    /// dataplane resolves this into VXLAN + CE-facing port identity
    /// at reconcile time.
    pub bridge: String,
}

/// Complete desired BUM-enforcement table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BumEnforcementTable {
    entries: BTreeMap<BumEnforcementKey, BumEnforcementEntry>,
}

impl BumEnforcementTable {
    /// Empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace one `(ESI, VNI)` row.
    pub fn insert(
        &mut self,
        esi: EthernetSegmentIdentifier,
        vni: EvpnInstanceId,
        role: DfRole,
        bridge: String,
    ) {
        let key = BumEnforcementKey { esi, vni };
        self.entries.insert(
            key,
            BumEnforcementEntry {
                esi,
                vni,
                role,
                action: BumForwardingAction::from_df_role(role),
                bridge,
            },
        );
    }

    /// Number of rows.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` when there are no rows.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Look up one row.
    #[must_use]
    pub fn get(
        &self,
        esi: EthernetSegmentIdentifier,
        vni: EvpnInstanceId,
    ) -> Option<&BumEnforcementEntry> {
        self.entries.get(&BumEnforcementKey { esi, vni })
    }

    /// Iterate rows in deterministic `(ESI, VNI)` order.
    pub fn iter(&self) -> impl Iterator<Item = &BumEnforcementEntry> {
        self.entries.values()
    }
}

/// Readiness of one BUM-enforcement row after the Linux dataplane
/// resolves it against current link inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BumEnforcementReadiness {
    /// Bridge, VXLAN port, and CE-facing port identity are known.
    Ready,
    /// The row cannot be enforced yet; reason is operator-facing.
    NotReady {
        /// Human-readable reason.
        reason: String,
    },
}

/// Observable BUM-enforcement plan/status row emitted in
/// [`DataplaneReport`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BumEnforcementStatus {
    /// Ethernet Segment the row applies to.
    pub esi: EthernetSegmentIdentifier,
    /// Member VNI the row applies to.
    pub vni: EvpnInstanceId,
    /// Local PE's DF role.
    pub role: DfRole,
    /// Desired forwarding action.
    pub action: BumForwardingAction,
    /// Operator-configured bridge name.
    pub bridge: String,
    /// Resolved VXLAN ifindex when the bridge has exactly one VXLAN
    /// port; absent when the row is not ready.
    pub vxlan_ifindex: Option<u32>,
    /// Resolved CE-facing bridge-port ifindexes. Empty until the
    /// Linux inventory can identify at least one non-VXLAN port.
    pub ce_port_ifindexes: Vec<u32>,
    /// Whether the row has enough identity to be enforced.
    pub readiness: BumEnforcementReadiness,
}

/// Result of a single reconcile pass.
///
/// A report is emitted after every reconcile, including no-op passes
/// where `applied` and `failed` are empty — that's the heartbeat the
/// daemon uses to verify the actor is healthy. `instance_status` is
/// re-emitted on every report so subscribers don't need to track
/// transitions themselves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataplaneReport {
    /// Echoes [`DataplaneIntent::generation`] of the snapshot this
    /// pass acted on.
    pub intent_generation: u64,
    /// Dataplane actor's own monotonic reconcile-pass counter, useful
    /// for metrics and debugging when many reports map to the same
    /// `intent_generation` (e.g., periodic-dump-driven re-reconciles).
    pub reconcile_generation: u64,
    /// One status row per instance in the desired snapshot.
    pub instance_status: Vec<InstanceDataplaneStatus>,
    /// Successfully-applied operations from this pass.
    pub applied: Vec<AppliedOp>,
    /// Operations that failed and are queued for retry.
    pub failed: Vec<FailedOp>,
    /// Observable Gate 8b BUM-enforcement plan. The first Gate 8b
    /// slice reports what would be enforced, but intentionally does
    /// not mutate kernel filters.
    pub bum_enforcement: Vec<BumEnforcementStatus>,
    /// One status row per configured IP-VRF in the desired snapshot
    /// (Gate 9, ADR-0058). Empty when no `[[evpn_ip_vrfs]]` are
    /// configured. Re-emitted on every report so the gRPC / CLI
    /// surfaces don't need to track transitions themselves.
    pub ip_vrf_status: Vec<IpVrfDataplaneStatus>,
    /// Per-IP-VRF kernel-route observation snapshot for this pass
    /// (Gate 9 slice 6a). `Some(empty)` when no `[[evpn_ip_vrfs]]`
    /// are configured (success, zero observations); `None` when the
    /// underlying kernel dump failed transiently and the daemon
    /// should preserve its last-known observation snapshot rather
    /// than treat the field as authoritative.
    ///
    /// ADR-0054 §6 motivates the distinction: the level-triggered
    /// reconciler must not advance state on a netlink failure —
    /// otherwise the L3 originator would interpret a transient dump
    /// failure as "kernel has no routes" and withdraw every
    /// currently-originated Type 5.
    pub ip_vrf_routes: Option<crate::ip_vrf::IpVrfRouteDump>,
    /// Currently-installed remote Type 5 route count per IP-VRF
    /// (Gate 9 slice 6c). Updated on every reconcile pass from the
    /// L3 reconciler's `l3_owned.routes` map. Empty when no
    /// `[[evpn_ip_vrfs]]` are configured. The daemon mirrors this
    /// onto a `tokio::sync::watch` channel so the gRPC
    /// `IpVrfState.installed_routes_count` field reads it
    /// lock-free.
    pub ip_vrf_installed_routes: std::collections::HashMap<IpVrfId, u32>,
    /// Latest owned ADR-0059 FDB nexthop-group state. Empty / zeroed
    /// when no FDB-NHG rows are installed or when the Linux dataplane
    /// actor is not running (RR-only deployments).
    pub fdb_nexthops: FdbNexthopDataplaneStatus,
}

/// Operator-facing summary of owned ADR-0059 FDB nexthop-group state.
///
/// This is intentionally a compact report shape, not a full kernel
/// dump. The Linux reconciler owns the allocator, group refcounts, and
/// stale-adoption bookkeeping; the daemon and gRPC layers only need a
/// stable snapshot that helps operators answer "what does rustbgpd
/// think it owns?" without shelling out to `ip nexthop show`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FdbNexthopDataplaneStatus {
    /// One row per owned FDB nexthop group.
    pub groups: Vec<FdbNexthopGroupStatus>,
    /// Count of rustbgpd-tagged kernel nexthops discovered during
    /// startup adoption / drift recovery but not yet associated with
    /// a live owned group. These are retained or cleaned by the
    /// reconciler depending on current kernel FDB references.
    pub orphan_nexthops_count: u32,
    /// Count of tagged nexthop IDs queued for retry because a kernel
    /// delete failed during GC / teardown.
    pub pending_delete_count: u32,
    /// `true` when steady-state `RTM_GETNEXTHOP` drift recovery was
    /// disabled for this daemon instance after a permanent dump
    /// failure. Normal FDB-NHG apply paths can still work.
    pub drift_recovery_disabled: bool,
}

/// One owned FDB nexthop group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FdbNexthopGroupStatus {
    /// VNI that scoped the Linux-owned alias group.
    pub vni: EvpnInstanceId,
    /// Ethernet Segment Identifier for this alias group.
    pub esi: EthernetSegmentIdentifier,
    /// Ethernet Tag carried by the aliasing control-plane key.
    pub ethernet_tag: EthernetTagId,
    /// Kernel nexthop group ID (`NHG_TAG | bitmap_id`).
    pub group_id: u32,
    /// Canonical member set, rendered with the per-VTEP kernel NHID.
    pub members: Vec<FdbNexthopMemberStatus>,
    /// MACs whose FDB rows currently reference `group_id`.
    pub ref_macs: Vec<MacAddress>,
}

/// One per-VTEP member of an FDB nexthop group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FdbNexthopMemberStatus {
    /// Remote VTEP gateway address.
    pub gateway: IpAddr,
    /// Kernel per-VTEP nexthop ID (`VTEP_NH_TAG | bitmap_id`).
    pub nexthop_id: u32,
}

/// Per-instance status emitted alongside every report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceDataplaneStatus {
    /// VNI this row describes.
    pub vni: EvpnInstanceId,
    /// Coarse-grained state.
    pub state: InstanceState,
    /// Optional human-readable explanation. Populated for `NotReady`
    /// states; empty for `Ready` and `Unbound`.
    pub message: Option<String>,
    /// Linux bridge MAC address if known. `Some` only when the
    /// dataplane has observed a `Ready` bridge with a captured
    /// MAC; `None` for `NotReady` / `Unbound` rows or when the
    /// bridge has no link-layer address attached. Surfaced through
    /// the report (rather than reaching into the dataplane's
    /// `LinkCache`) so the SVI-MAC origination path stays on the
    /// ADR-0054 §1 boundary — Linux observes, daemon decides.
    pub bridge_mac: Option<MacAddress>,
}

/// Coarse-grained per-instance dataplane state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstanceState {
    /// All probe checks passed; remote MACs for this instance are
    /// being reconciled into the kernel FDB.
    Ready,
    /// Bridge missing, VXLAN port missing/mismatched, learning mode
    /// wrong, VLAN-aware bridge, or local IP mismatched. Remote MACs
    /// for this instance are NOT programmed; existing kernel state is
    /// not modified. Detail in [`InstanceDataplaneStatus::message`].
    NotReady,
    /// Instance has `bridge = None` — never enters the dataplane
    /// reconcile loop. Visible via `ListEvpnInstances` but inert.
    Unbound,
}

/// Per-IP-VRF status row emitted on every report (Gate 9).
///
/// Mirrors the shape of [`InstanceDataplaneStatus`] for the L3 side:
/// one row per configured `[[evpn_ip_vrfs]]` entry, carrying the
/// operator-facing handle plus the live [`IpVrfStatus`] verdict from
/// the reconcile actor's last `probe_ip_vrfs` pass. Empty in
/// `DataplaneReport.ip_vrf_status` when no IP-VRFs are configured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpVrfDataplaneStatus {
    /// Stable identifier (the L3VNI of the IP-VRF).
    pub vrf_id: IpVrfId,
    /// Operator-facing handle (from the `name` field on
    /// `[[evpn_ip_vrfs]]`).
    pub vrf_name: String,
    /// Live readiness verdict from the most recent reconcile pass.
    pub status: IpVrfStatus,
}

/// A single dataplane operation that was successfully applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedOp {
    /// VNI the operation acted on.
    pub vni: EvpnInstanceId,
    /// What the operation did.
    pub kind: DataplaneOpKind,
}

/// A single dataplane operation that failed and is queued for retry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailedOp {
    /// VNI the operation tried to act on.
    pub vni: EvpnInstanceId,
    /// What the operation tried to do.
    pub kind: DataplaneOpKind,
    /// Human-readable error string from the dataplane crate. Stable
    /// enough for log correlation; not parsed.
    pub error: String,
    /// Backoff before this op is retried, in milliseconds.
    pub retry_in_ms: u32,
}

/// Discriminator for [`AppliedOp`] / [`FailedOp`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataplaneOpKind {
    /// Add a remote-MAC FDB entry pointing at `dst` (the remote VTEP IP).
    AddRemoteFdb {
        /// MAC the entry programs.
        mac: MacAddress,
        /// Remote VTEP destination IP.
        dst: IpAddr,
    },
    /// Update an existing remote-MAC entry to point at a new VTEP IP
    /// (e.g., MAC mobility — same MAC, different remote).
    UpdateRemoteFdb {
        /// MAC the entry programs.
        mac: MacAddress,
        /// New remote VTEP destination IP.
        dst: IpAddr,
    },
    /// Withdraw a previously-programmed remote-MAC entry.
    RemoveRemoteFdb {
        /// MAC the entry programmed.
        mac: MacAddress,
    },
    /// Apply the BUM-suppression flag triplet to a CE-facing bridge
    /// port (Gate 8b kernel primitive). The MAC / VNI fields used by
    /// FDB ops aren't meaningful here — the affected kernel object
    /// is a bridge port identified by its ifindex.
    SetBumPortFlags {
        /// CE-facing bridge port ifindex.
        ifindex: u32,
    },
    /// Install an FDB row pointing at an FDB nexthop group via
    /// `NDA_NH_ID` (ADR-0059 slice 3 aliasing-ECMP). The kernel
    /// group ID isn't reported here — operators trace it via
    /// structured logs from the coordinator. Single entry per
    /// `(VNI, MAC)`, like the single-dst variants.
    InstallFdbNhg {
        /// MAC the FDB row programs.
        mac: MacAddress,
    },
    /// Update an FDB nexthop group's member set in place (atomic
    /// alias-set swap via `NLM_F_REPLACE` — ADR-0059 §5 invariant 3).
    /// Group-level — no `(VNI, MAC)` row identity. The `(esi,
    /// ethernet_tag)` payload identifies which group the update
    /// touched; `AppliedOp` separately carries the VNI, so the
    /// three together pin down the Linux-owned `AliasGroupKey`.
    UpdateFdbNhgMembers {
        /// Ethernet Segment identifier of the group whose member
        /// set was replaced.
        esi: EthernetSegmentIdentifier,
        /// Ethernet Tag of the EVI within the segment. Distinguishes
        /// groups that share an ESI across multiple bridge domains.
        ethernet_tag: EthernetTagId,
    },
    /// Remove an FDB row that referenced an FDB nexthop group. The
    /// group teardown itself (and any per-VTEP-NH cleanup the
    /// refcount triggers) is internal to the coordinator and not
    /// reported as a separate kind row.
    RemoveFdbNhg {
        /// MAC the FDB row programmed.
        mac: MacAddress,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_intent_is_generation_zero() {
        let intent = DataplaneIntent::empty();
        assert_eq!(intent.generation, 0);
        assert!(intent.instances.is_empty());
        assert!(intent.remote_macs.is_empty());
        assert!(intent.bum_enforcement.is_empty());
    }

    #[test]
    fn empty_intents_compare_equal() {
        // Equality on Arc<EvpnInstanceTable> compares contents, not
        // pointer identity — two independently-constructed empties
        // should still be equal.
        assert_eq!(DataplaneIntent::empty(), DataplaneIntent::empty());
    }

    #[test]
    fn instance_state_is_copy() {
        let s = InstanceState::Ready;
        let t = s;
        assert_eq!(s, InstanceState::Ready);
        assert_eq!(t, s);
    }

    #[test]
    fn op_kind_distinguishes_add_update_remove() {
        let mac = MacAddress::new([1, 2, 3, 4, 5, 6]);
        let dst: IpAddr = "10.0.0.1".parse().unwrap();
        let add = DataplaneOpKind::AddRemoteFdb { mac, dst };
        let upd = DataplaneOpKind::UpdateRemoteFdb { mac, dst };
        let rem = DataplaneOpKind::RemoveRemoteFdb { mac };
        assert_ne!(add, upd);
        assert_ne!(add, rem);
        assert_ne!(upd, rem);
    }

    #[test]
    fn instance_dataplane_status_round_trips_bridge_mac() {
        // ADR-0054 §1: bridge MAC surfaces from the Linux dataplane
        // through `InstanceDataplaneStatus.bridge_mac` rather than via
        // a back-channel into the dataplane crate's LinkCache.
        let mac = MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0xAB]);
        let status = InstanceDataplaneStatus {
            vni: EvpnInstanceId::new(100).unwrap(),
            state: InstanceState::Ready,
            message: None,
            bridge_mac: Some(mac),
        };
        // Equality comparison preserves the field — the daemon's SVI
        // task will memcmp full status rows when deciding whether a
        // re-emission is a no-op.
        let clone = status.clone();
        assert_eq!(status, clone);
        assert_eq!(status.bridge_mac, Some(mac));
    }

    #[test]
    fn intent_generation_increments_via_struct_update() {
        // Demonstrate the daemon-side publish pattern: clone the
        // existing intent, bump generation, swap the table Arc.
        let prev = DataplaneIntent::empty();
        let next = DataplaneIntent {
            generation: prev.generation + 1,
            ..prev.clone()
        };
        assert_eq!(next.generation, 1);
        assert_eq!(prev.generation, 0);
    }

    #[test]
    fn bum_enforcement_table_derives_action_from_role() {
        let esi = EthernetSegmentIdentifier::new([1; 10]);
        let vni = EvpnInstanceId::new(100).unwrap();
        let mut table = BumEnforcementTable::new();
        table.insert(esi, vni, DfRole::NonDf, "br100".to_string());

        let row = table.get(esi, vni).unwrap();
        assert_eq!(row.role, DfRole::NonDf);
        assert_eq!(row.action, BumForwardingAction::Suppress);
        assert_eq!(row.bridge, "br100");
    }

    #[test]
    fn df_role_maps_to_bum_action() {
        assert_eq!(
            BumForwardingAction::from_df_role(DfRole::Df),
            BumForwardingAction::Allow
        );
        assert_eq!(
            BumForwardingAction::from_df_role(DfRole::NonDf),
            BumForwardingAction::Suppress
        );
    }
}
