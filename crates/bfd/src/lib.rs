//! rustbgpd-bfd — RFC 5880 BFD control-packet codec + single-hop session FSM
//!
//! Pure and sans-IO, mirroring `rustbgpd-fsm`: the [`Session`] state machine
//! takes packet and timer inputs ([`Event`]) and produces packet, timer, and
//! state-change outputs ([`Action`]). It never reads a clock, opens a socket,
//! or spawns a task — the daemon actor owns the real I/O, timers, and jitter.
//!
//! # Scope
//!
//! - **Single-hop asynchronous mode** (RFC 5880 / RFC 5881) only.
//! - **Out of scope:** multihop (RFC 5883), echo mode, demand mode, and
//!   authentication. Packets with the `A` (auth) bit are decoded structurally
//!   and discarded by the session; the `M` (multipoint) bit is rejected at decode.
//!
//! # Entry points
//!
//! - [`ControlPacket::encode`] / [`ControlPacket::decode`] — the wire codec.
//! - [`Session::new`] / [`Session::handle`] / [`Session::administratively_down`]
//!   — the state machine.
//! - [`DiscriminatorAllocator`] — unique non-zero local discriminators.

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

pub mod action;
pub mod discriminator;
pub mod error;
pub mod event;
pub mod packet;
pub mod session;
pub mod state;

pub use action::{Action, TimerKind};
pub use discriminator::{DiscriminatorAllocationError, DiscriminatorAllocator};
pub use error::DecodeError;
pub use event::Event;
pub use packet::{CONTROL_PACKET_LEN, ControlPacket, Diagnostic};
pub use session::{SLOW_TX_INTERVAL_US, Session, SessionConfig, SessionError};
pub use state::SessionState;
