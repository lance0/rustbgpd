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
//!   probes)`. The heart of the crate; backed by 11 explicit case
//!   tests in `src/diff.rs`.
//! - [`DataplaneOp`] — what the actor asks the dataplane to apply.
//!
//! ## Out of scope (Gate 7b)
//!
//! - Creating or deleting bridge / VXLAN netdevs (ADR-0054 §4).
//! - VLAN-aware bridges (ADR-0054 §4 — needs schema extension).
//! - L3VNI / IRB / Type 5 dataplane.
//! - Local-MAC origination policy knobs. This crate emits *observations*
//!   via [`rustbgpd_evpn::LocalMacObservation`]; the daemon/domain
//!   originator consumes them for MAC-only Type 2 mobility. Sticky/static
//!   MAC config, MAC-with-IP correlation, and anti-spoof policy remain
//!   follow-ups.
//!
//! ## Reference
//!
//! - ADR-0054 (`docs/adr/0054-evpn-linux-dataplane-boundary.md`)
//! - RFC 7432 — BGP MPLS-Based Ethernet VPN
//! - RFC 8365 — Network Virtualization Overlay Solution Using EVPN
//!
//! [`DataplaneIntent`]: rustbgpd_evpn::DataplaneIntent

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

pub mod backoff;
pub mod dataplane;
pub mod diff;
pub mod error;
pub mod in_memory;
pub mod reconcile;
pub mod snapshot;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "linux")]
pub use linux::LinuxDataplane;

pub use backoff::{BACKOFF_CAP, BACKOFF_FACTOR, BACKOFF_INITIAL, RetrySchedule};
pub use dataplane::{Dataplane, DataplaneOp, KernelEvent};
pub use diff::{Plan, compute_diff};
pub use error::{DataplaneError, FailureClass};
pub use in_memory::{InMemoryDataplane, InMemoryHandle};
pub use reconcile::{ReconcileActor, ReconcileActorConfig};
pub use snapshot::{
    InstanceProbe, InstanceProbes, KernelFdbEntry, KernelFdbFlags, KernelLinkInfo, KernelSnapshot,
    OwnedEntry, OwnedSet,
};
