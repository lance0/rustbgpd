//! rustbgpd-fsm — RFC 4271 BGP finite state machine
//!
//! Pure state machine. Takes message and timer inputs, produces message and
//! state outputs. Never imports tokio, never spawns a task, never touches
//! a file descriptor.
//!
//! # Example
//!
//! Drive a fresh session out of `Idle` with a `ManualStart`:
//!
//! ```rust
//! use std::net::Ipv4Addr;
//!
//! use rustbgpd_fsm::{Event, PeerConfig, Session, SessionState};
//!
//! // `PeerConfig` is `#[non_exhaustive]`, so build it via the constructor
//! // and set any optional fields afterwards.
//! let config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
//!
//! let mut session = Session::new(config);
//! assert_eq!(session.state(), SessionState::Idle);
//!
//! let actions = session.handle_event(Event::ManualStart);
//! assert_eq!(session.state(), SessionState::Connect);
//! assert!(!actions.is_empty());
//! ```
//!
//! # Enum exhaustiveness
//!
//! [`Event`], [`Action`], [`TimerType`], and [`error::FsmError`] are
//! `#[non_exhaustive]`: new protocol features add variants without a
//! semver-major break, so matches outside this crate must carry a
//! wildcard arm. [`SessionState`] stays exhaustively matchable — the six
//! RFC 4271 §8 states are fixed by the protocol.
//!
//! ```rust
//! use rustbgpd_fsm::Action;
//!
//! fn describe(action: &Action) -> &'static str {
//!     match action {
//!         Action::SendKeepalive => "send keepalive",
//!         Action::CloseTcpConnection => "close TCP connection",
//!         // Future actions land here; ignore what you do not drive.
//!         _ => "other",
//!     }
//! }
//! assert_eq!(describe(&Action::SendKeepalive), "send keepalive");
//! ```

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

pub mod action;
pub mod config;
pub mod error;
pub mod event;
pub mod negotiation;
pub mod session;
pub mod state;

pub use action::{Action, NegotiatedSession, TimerType};
pub use config::{
    DEFAULT_HOLD_TIME, PeerConfig, default_send_hold_time, graceful_restart_preserves_family,
};
pub use event::Event;
pub use session::Session;
pub use state::SessionState;
