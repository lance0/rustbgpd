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
//! ## What ships in this slice
//!
//! - [`EvpnInstanceId`] — a validated 24-bit VNI (RFC 8365 §5).
//! - [`RouteTarget`] — typed RFC 4360 RT covering the three encodings
//!   ([`RouteTarget::TwoOctetAs`], [`RouteTarget::Ipv4`],
//!   [`RouteTarget::FourOctetAs`]).
//! - [`EvpnInstance`] — one local EVI's resolved configuration: VNI,
//!   route distinguisher, route targets, local VTEP source IP, optional
//!   Linux bridge name, and the `advertise_svi_mac` flag.
//! - [`EvpnInstanceTable`] — uniqueness-enforcing collection, indexed
//!   by VNI, with a parallel RD index that surfaces collisions
//!   between two instances using the same Route Distinguisher.
//! - [`RemoteMacTable`] / [`DataplaneIntent`] / [`DataplaneReport`] —
//!   Gate 7b dataplane boundary types per ADR-0054. Portable domain
//!   surface consumed by `crates/evpn-linux`. The kernel-side
//!   reconciler lives there; this crate stays kernel-free.
//!
//! Mutation surface, kernel reconciliation, and Type 2/3/5
//! origination are explicit follow-up work tracked in
//! `docs/evpn-enablement.md` Gate 7+.

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

pub mod dataplane;
pub mod instance;
pub mod mac;
pub mod route_target;

pub use dataplane::{
    AppliedOp, DataplaneIntent, DataplaneOpKind, DataplaneReport, FailedOp,
    InstanceDataplaneStatus, InstanceState,
};
pub use instance::{
    EvpnInstance, EvpnInstanceId, EvpnInstanceIdError, EvpnInstanceTable, EvpnInstanceTableError,
};
pub use mac::{
    LocalMacObservation, MacAddress, RemoteMacEntry, RemoteMacSource, RemoteMacTable,
    RemoteMacTableBuilder, RemoteMacTableBuilderError,
};
pub use route_target::{RouteTarget, RouteTargetParseError};

// Re-export the wire `RouteDistinguisher` so consumers of this crate
// (including `crates/evpn-linux` and the daemon's projection layer)
// can name the type without taking a direct `rustbgpd-wire` dep just
// to construct an `EvpnInstance`.
pub use rustbgpd_wire::RouteDistinguisher;
