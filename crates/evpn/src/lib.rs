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
//! Dataplane boundary (consumed by `crates/evpn-linux` per
//! ADR-0054):
//!
//! - [`RemoteMacTable`] / [`DataplaneIntent`] / [`DataplaneReport`].
//!   Portable domain surface; the kernel-side reconciler lives in
//!   `crates/evpn-linux`. This crate stays kernel-free.
//!
//! Origination state machines (pure deterministic, RFC 7432 §15.1
//! mobility sequencing):
//!
//! - [`LocalMacOriginator`] — MAC-only Type 2 (Gate 7b+1).
//! - [`LocalMacIpOriginator`] — MAC+IP Type 2 (Gate 7b+2 slice 2),
//!   keyed on `(MAC, IP)` with independent sequence chains per
//!   RFC 9135 §4.4 coexistence.
//!
//! Type 1 (EAD), Type 4 (ES), Type 5 (IP-Prefix) origination are
//! tracked in `docs/evpn-enablement.md` and remain follow-up
//! work. Type 3 IMET origination is implemented in the daemon
//! binary (`src/evpn_imet.rs`) rather than here because it
//! depends on the wire encoder; the domain shape is captured by
//! [`EvpnInstance`] alone.

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

pub mod dataplane;
pub mod instance;
pub mod mac;
pub mod origination;
pub mod origination_macip;
pub mod projection;
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
pub use origination::{LocalMacOriginator, OriginationAction, RemoteMacView};
pub use origination_macip::{LocalMacIpOriginator, MacIpKey, RemoteMacIpView};
pub use projection::{ProjectedEvpnRoute, project_evpn_routes};
pub use route_target::{RouteTarget, RouteTargetParseError};

// Re-export the wire `RouteDistinguisher` so consumers of this crate
// (including `crates/evpn-linux` and the daemon's projection layer)
// can name the type without taking a direct `rustbgpd-wire` dep just
// to construct an `EvpnInstance`.
pub use rustbgpd_wire::RouteDistinguisher;
