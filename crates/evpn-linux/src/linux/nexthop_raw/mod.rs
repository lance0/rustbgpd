//! Raw-netlink primitives for FDB nexthop groups (ADR-0059 slice 2).
//!
//! Emits `RTM_NEWNEXTHOP` / `RTM_DELNEXTHOP` messages with `NHA_FDB`
//! over a dedicated `NETLINK_ROUTE` socket, separate from the
//! daemon's primary `rtnetlink::Handle`. Slice 3's reconcile actor
//! drives this; slice 2 ships the primitive and its byte-fixture
//! tests with no caller wired up.
//!
//! Clean-room from `include/uapi/linux/nexthop.h`. PR #225 in
//! `rust-netlink/netlink-packet-route` is a design reference only.
//!
//! # Public surface
//!
//! - [`NexthopSocket`]: async wrapper over `netlink-sys::TokioSocket`.
//!   `&mut self` methods serialize the send/ACK pairing at the
//!   borrow checker.
//! - [`NexthopGroupMember`]: domain-shaped group-member type; raw
//!   UAPI `NexthopGrp` and constants stay `pub(crate)`.
//! - [`NexthopError`] + [`NexthopValidationError`]: typed failures.

pub(crate) mod encode;
pub mod socket;
pub(crate) mod uapi;

pub use socket::{NexthopError, NexthopGroupMember, NexthopSocket, NexthopValidationError};
