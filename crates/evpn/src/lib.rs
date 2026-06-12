//! rustbgpd-evpn — local EVPN domain state for VTEP mode (RFC 7432 / RFC 8365).
//!
//! This crate defines the **declarative** domain model the daemon uses to
//! describe local EVPN instances on this VTEP. It is intentionally
//! kernel-free: nothing here touches netlink, the FDB, or VXLAN
//! interfaces. The state shaped here is what later phases will reconcile
//! against the kernel and use to originate RFC 7432 routes.
//!
//! ## Why a declarative model
//!
//! `GoBGP` exposes an *implicit* EVPN model — operators add individual
//! routes via `gobgp global rib add` and the route attributes (RD, RT,
//! VNI) carry all the state. That works for a route reflector or
//! transit AS but not for a VTEP, where the daemon has to know which
//! VNIs are local, where to source VXLAN encap from, and which bridge
//! / SVI ↔ VNI mappings count as "ours" before any route exists. FRR
//! and Cumulus Linux take the declarative path; rustbgpd does too.
//!
//! ## Service interface model
//!
//! v1 follows RFC 7432's *VLAN-Based Service Interface*: one EVPN
//! instance per VNI, single Ethernet Tag. The richer *VLAN-Aware
//! Bundle* shape (many tags per EVI) is deferred — the wire codec
//! already round-trips Ethernet-Tag in every route type, so adding
//! that mode later is purely a domain-model expansion.
//!
//! ## What lives here
//!
//! Configuration / domain types:
//!
//! - [`EvpnInstanceId`] — a validated 24-bit VNI (RFC 8365 §5).
//! - [`RouteTarget`] — typed RFC 4360 RT covering the three
//!   encodings ([`RouteTarget::TwoOctetAs`], [`RouteTarget::Ipv4`],
//!   [`RouteTarget::FourOctetAs`]).
//! - [`EvpnInstance`] — one local EVI's resolved configuration: VNI,
//!   route distinguisher, route targets, local VTEP source IP,
//!   optional Linux bridge name, `advertise_svi_mac`, `sticky_macs`.
//! - [`EvpnInstanceTable`] — uniqueness-enforcing collection,
//!   indexed by VNI, with a parallel RD index that surfaces
//!   collisions between two instances using the same Route
//!   Distinguisher.
//!
//! IP-VRF / Gate 9 symmetric IRB types:
//!
//! - [`ip_vrf::IpVrf`] / [`ip_vrf::IpVrfTable`] — declared
//!   IP-VRF tenants with VRF / L3VXLAN binding + operator-supplied
//!   Router MAC (ADR-0058 §4). The `ip_vrf::readiness` probe
//!   checks the seven ADR-0058 §3 predicates.
//! - Pure-logic Type 5 origination + projection helpers
//!   (RFC 9136 §4.4.2 Interface-less IRB) shipped in v0.18.0;
//!   `RemoteIpPrefixTable` and `OriginatedIpPrefixRoute` flow
//!   through `DataplaneIntent`.
//!
//! Dataplane boundary (consumed by `crates/evpn-linux` per
//! ADR-0054 / ADR-0058 / ADR-0059):
//!
//! - [`RemoteMacTable`] / [`DataplaneIntent`] / [`DataplaneReport`].
//!   Portable domain surface; the kernel-side reconciler lives in
//!   `crates/evpn-linux`. This crate stays kernel-free.
//!   `RemoteMacEntry` carries `alias_vtep_ips` + `alias_group_key`
//!   for ADR-0059 aliasing-ECMP wire intent.
//!
//! Origination state machines (pure deterministic, RFC 7432 §15.1
//! mobility sequencing):
//!
//! - [`LocalMacOriginator`] — MAC-only Type 2 (Gate 7b+1).
//! - [`LocalMacIpOriginator`] — MAC+IP Type 2 (Gate 7b+2 slice 2),
//!   keyed on `(MAC, IP)` with independent sequence chains per
//!   RFC 9135 §4.4 coexistence.
//! - [`LocalEsOriginator`], [`LocalEadPerEsOriginator`],
//!   [`LocalEadPerEviOriginator`] — Type 4 ES and Type 1 EAD
//!   origination state machines for Gate 8 multi-homing.
//! - `ip_vrf::originate_ip_prefix_route` — pure helper for Type 5
//!   construction (the daemon's `evpn_l3_originator` task drives
//!   it under `IpVrfStatus::Ready`).
//!
//! Other modules: `aliasing` (canonical alias VTEP set per
//! `RemoteMacEntry`, plus the ADR-0083 single-active eligible-set /
//! backup-PE derivation), `df_election` (Gate 8 RFC 7432 §8.5),
//! `label_allocator` (Gate 8b per-ESI EVPN label),
//! `mass_withdraw` (Gate 8b RFC 7432 §8.4 receive-side filter),
//! `projection` (RIB → `RemoteMacTable` with same-AF
//! invariant enforcement).
//!
//! Type 3 IMET origination is implemented in the daemon binary
//! (`src/evpn_imet.rs`) rather than here because it depends on the
//! wire encoder; the domain shape is captured by [`EvpnInstance`]
//! alone.

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

pub mod aliasing;
pub mod dataplane;
pub mod df_election;
pub mod duplicate_mac;
pub mod instance;
pub mod ip_vrf;
pub mod label_allocator;
pub mod mac;
pub mod mass_withdraw;
pub mod origination;
pub mod origination_es;
pub mod origination_macip;
pub mod projection;
pub mod route_target;
pub mod runtime;
pub mod segment;

pub use aliasing::{
    AliasEadPerEvi, AliasIndex, EadPerEsMode, SingleActiveBackupView, SingleActiveEligibleIndex,
    alias_resolved_next_hops, group_members,
};
pub use dataplane::{
    AppliedOp, BumEnforcementEntry, BumEnforcementKey, BumEnforcementReadiness,
    BumEnforcementStatus, BumEnforcementTable, BumForwardingAction, DataplaneIntent,
    DataplaneOpKind, DataplaneReport, FailedOp, FdbNexthopDataplaneStatus, FdbNexthopGroupStatus,
    FdbNexthopMemberStatus, FdbNhgDriftCounters, InstanceDataplaneStatus, InstanceState,
    IpVrfDataplaneStatus, L3AdoptionCounters, SameEsiBiasTable, SingleActiveCounters,
};
pub use df_election::{DfCandidate, DfElection, DfElectionError};
pub use duplicate_mac::{
    DEFAULT_DUPLICATE_MAC_RECOVERY, DEFAULT_DUPLICATE_MAC_THRESHOLD, DEFAULT_DUPLICATE_MAC_WINDOW,
    DuplicateMacAction, DuplicateMacConfig, DuplicateMacConfigError, DuplicateMacDecision,
    DuplicateMacDetector, DuplicateMacKey,
};
pub use instance::{
    EvpnInstance, EvpnInstanceId, EvpnInstanceIdError, EvpnInstanceTable, EvpnInstanceTableError,
};
pub use ip_vrf::{
    IpVrf, IpVrfError, IpVrfId, IpVrfIdError, IpVrfRouteDump, IpVrfTable, IpVrfTableError,
    LocalIpRouteObservation, RouteFilterReason, RouteSource,
};
pub use label_allocator::{AllocateError, EsiLabelAllocator, synthesize_from_esi};
pub use mac::{
    LocalMacObservation, MacAddress, RemoteMacEntry, RemoteMacSource, RemoteMacTable,
    RemoteMacTableBuilder, RemoteMacTableBuilderError,
};
pub use mass_withdraw::{AsPathFingerprint, AsPathTracker, MassWithdrawTrigger};
pub use origination::{LocalMacOriginator, OriginationAction, RemoteMacView};
pub use origination_es::{LocalEadPerEsOriginator, LocalEadPerEviOriginator, LocalEsOriginator};
pub use origination_macip::{LocalMacIpOriginator, MacIpKey, RemoteMacIpView};
pub use projection::{
    ProjectedEvpnEadPerEvi, ProjectedEvpnRoute, project_evpn_routes,
    project_evpn_routes_with_aliases, project_evpn_routes_with_backup_paths,
};
pub use route_target::{RouteTarget, RouteTargetParseError};
pub use runtime::{
    EvpnRuntimeApplyError, EvpnRuntimeApplyOutcome, EvpnRuntimeApplyReport, EvpnRuntimeCandidate,
    EvpnRuntimeChangeSet, EvpnRuntimeConvergeError, EvpnRuntimeConverger, EvpnRuntimeCoordinator,
    EvpnRuntimeGeneration, EvpnRuntimeLifecycle, EvpnRuntimeModel, EvpnRuntimeMutationState,
    EvpnRuntimePlan, EvpnRuntimeSnapshot,
};
pub use segment::{DfAlgorithm, DfRole, EthernetSegment, RedundancyMode};

// Re-export the wire `RouteDistinguisher` so consumers of this crate
// (including `crates/evpn-linux` and the daemon's projection layer)
// can name the type without taking a direct `rustbgpd-wire` dep just
// to construct an `EvpnInstance`. The IP-prefix wire types are
// re-exported for the same reason: slice 6 plumbing in `evpn-linux`
// needs to spell out kernel-route prefixes without depending on wire.
pub use rustbgpd_wire::{
    EthernetSegmentIdentifier, EthernetTagId, EvpnIpPrefixValue, Ipv4Prefix, Ipv6Prefix,
    RouteDistinguisher,
};
