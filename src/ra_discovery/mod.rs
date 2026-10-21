//! IPv6 Router Advertisement discovery for interface-only unnumbered
//! neighbors (ADR-0142).
//!
//! An interface-only neighbor names a port and no address. This module learns
//! the peer's link-local address from the Router Advertisements it sends on
//! that port, and advertises this router there so the peer can do the same.
//! It reports candidates and a binding; it never opens, holds or ends a BGP
//! session. The neighbor owner feeds it link state and session outcomes.
//!
//! - [`packet`]: RS/RA grammar and the RFC 4861 §6.1.1/§6.1.2 receive
//!   validation, as pure functions.
//! - [`engine`]: the sans-IO candidate table, binding rules and RFC 4861
//!   §6.2 transmit schedule.
//! - `runtime` (Linux): one raw `ICMPv6` socket per started interface and the
//!   actor that drives the engine, behind [`RaDiscovery`].
//!
//! # Binding rules
//!
//! - A candidate lives for the RA's Router Lifetime, or
//!   [`LIFETIME_ZERO_HOLD`] when that is 0.
//! - Until the session is Established, the binding stays on its candidate
//!   while that candidate is live, and otherwise moves to the numerically
//!   lowest live candidate.
//! - Once Established ([`RaDiscovery::session_established`]), nothing
//!   discovery sees moves the binding: neither a new source (reported as a
//!   [`DiscoveryEvent::Conflict`]) nor expiry of the bound source. Only
//!   [`RaDiscovery::session_failed`] or confirmed carrier loss releases it.
//! - [`LinkState::Down`] and [`LinkState::Removed`] clear every candidate and
//!   the binding, and an `Up` with a new ifindex (a recreated interface)
//!   starts from empty state. [`LinkState::Unknown`] clears nothing.
//!
//! # Privilege
//!
//! Reception needs a raw `ICMPv6` socket, so `CAP_NET_RAW`, whether or not
//! sending is enabled. [`RaDiscovery::spawn`] fails with
//! [`DiscoveryError::MissingCapNetRaw`] without it.

#![cfg_attr(
    not(test),
    expect(
        dead_code,
        unused_imports,
        reason = "the engine is wired to interface-only neighbors in a later change"
    )
)]
#![cfg_attr(
    test,
    allow(
        dead_code,
        unused_imports,
        reason = "tests drive the engine directly; the full API is wired later"
    )
)]

pub mod engine;
pub mod packet;
#[cfg(target_os = "linux")]
mod runtime;

pub use engine::{
    DiscoveryConfig, DiscoveryEvent, Endpoint, LIFETIME_ZERO_HOLD, LinkEvent, LinkState, RaTiming,
};
pub use packet::DropReason;
#[cfg(target_os = "linux")]
pub use runtime::{DiscoveryError, RaDiscovery};

#[cfg(test)]
mod tests;
