//! Linux netlink dataplane reconciler for EVPN VTEP — Gate 7b (RFC 7432 / RFC 8365).
//!
//! This crate consumes desired [`DataplaneIntent`] snapshots (defined
//! in `rustbgpd-evpn`) over a `tokio::sync::watch` channel, observes
//! Linux bridge / VXLAN topology through netlink, and programs *only*
//! rustbgpd-owned remote-MAC FDB entries through the bridge/master
//! path with `extern_learn`.
//!
//! The contract is locked by ADR-0054. By design, this crate cannot
//! depend on `rustbgpd-rib` or `rustbgpd-transport` — see §1 of that
//! ADR. The dependency direction is one-way:
//!
//! ```text
//!  rustbgpd-evpn  --(DataplaneIntent, RemoteMacTable, ...)-->  rustbgpd-evpn-linux
//!
//!  rustbgpd-evpn-linux  -->  Linux netlink (rtnetlink, netlink-packet-route)
//! ```
//!
//! ## Public surface
//!
//! - [`Dataplane`] — abstract trait. The crate ships the
//!   [`InMemoryDataplane`] fake for deterministic tests plus the real
//!   `LinuxDataplane` on Linux behind `#[cfg(target_os = "linux")]`.
//! - [`KernelSnapshot`], [`KernelFdbEntry`], [`KernelLinkInfo`],
//!   [`OwnedSet`], [`InstanceProbes`] — the actor's view of kernel /
//!   per-instance state.
//! - [`diff::compute_diff`] — pure function that produces a [`Plan`]
//!   of dataplane operations from `(desired, snapshot, last_applied,
//!   probes)`. The heart of the crate; backed by case tests in
//!   `src/diff.rs` covering both the single-dst path and the
//!   FDB-NHG Pass 1b (ADR-0059).
//! - [`DataplaneOp`] — what the actor asks the dataplane to apply.
//! - [`enforcement::build_bum_enforcement_status`] — Gate 8b
//!   split-horizon plan derivation. Resolves `(ESI, VNI) -> DF role`
//!   intent into bridge / VXLAN / CE-facing-port status rows.
//!   `apply_bum_enforcement = true` actually programs the kernel
//!   filter; `false` (default) reports the plan only.
//! - [`bum_filter`] — Gate 8b BUM-port flag-flip kernel primitive.
//! - [`l3_diff`] — Gate 9 slice 6 transactional L3 ownership model
//!   for symmetric Interface-less IRB (per-prefix install state +
//!   shared kernel-neighbor / L3VXLAN-FDB refcount, value-aware
//!   drift detection, four-phase apply ordering).
//! - [`group_state`], [`nh_id_alloc`] — ADR-0059 FDB nexthop
//!   group refcount state + tag-bit allocator (`VTEP_NH_TAG`
//!   `0x3000_xxxx`, `NHG_TAG` `0x4000_xxxx`).
//!
//! ## Out of scope
//!
//! - Creating or deleting bridge / VXLAN netdevs (ADR-0054 §4).
//! - VLAN-aware bridges (ADR-0054 §4 — needs schema extension).
//! - Full RFC 9135 overlay-index IRB (Gate 9 ships the
//!   Interface-less variant per RFC 9136 §4.4.2).
//! - EVPN duplicate-MAC quarantine action.
//! - Anti-spoof policy beyond the operator-facing `sticky_macs`
//!   list (ADR-0056) and the same-AF projection invariant
//!   (ADR-0059 §7).
//!
//! ## Reference
//!
//! - ADR-0054 (`docs/adr/0054-evpn-linux-dataplane-boundary.md`)
//! - ADR-0057 (`docs/adr/0057-evpn-gate-8-observable-df-election.md`)
//! - ADR-0058 (`docs/adr/0058-evpn-gate-9-irb-l3vni.md`)
//! - ADR-0059 (`docs/adr/0059-evpn-aliasing-fdb-nexthop-groups.md`)
//! - RFC 7432 — BGP MPLS-Based Ethernet VPN
//! - RFC 8365 — Network Virtualization Overlay Solution Using EVPN
//! - RFC 9136 — IP Prefix Advertisement (Type 5)
//!
//! [`DataplaneIntent`]: rustbgpd_evpn::DataplaneIntent

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

pub mod backoff;
pub mod bum_filter;
pub mod dataplane;
pub mod diff;
pub mod enforcement;
pub mod error;
pub mod group_state;
pub mod in_memory;
pub mod l3_adoption;
pub mod l3_diff;
pub mod nh_id_alloc;
pub mod reconcile;
pub mod snapshot;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "linux")]
pub use linux::LinuxDataplane;

#[cfg(target_os = "linux")]
pub use linux::link_carrier::{LinkCarrierHandle, LinkCarrierMap, spawn_link_carrier_monitor};

#[cfg(target_os = "linux")]
pub use linux::nexthop_raw::{
    NexthopError, NexthopGroupMember, NexthopSocket, NexthopValidationError,
};

pub use backoff::{BACKOFF_CAP, BACKOFF_FACTOR, BACKOFF_INITIAL, FdbRetrySchedule, RetrySchedule};
pub use bum_filter::{BumPortFlagPlan, BumPortFlags, compute_flag_plan, diff_flag_plans};
pub use dataplane::{Dataplane, DataplaneOp, KernelEvent};
pub use diff::{Plan, compute_diff};
pub use enforcement::build_bum_enforcement_status;
pub use error::{DataplaneError, FailureClass};
pub use in_memory::{InMemoryDataplane, InMemoryHandle};
pub use l3_adoption::{AdoptedL3Route, L3AdoptionDump};
pub use reconcile::{ReconcileActor, ReconcileActorConfig};
pub use snapshot::{
    InstanceProbe, InstanceProbes, KernelFdbEntry, KernelFdbFlags, KernelLinkInfo, KernelSnapshot,
    OwnedEntry, OwnedSet,
};
