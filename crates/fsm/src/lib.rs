//! rustbgpd-fsm — RFC 4271 BGP finite state machine
//!
//! Pure state machine. Takes message and timer inputs, produces message and
//! state outputs. Never imports tokio, never spawns a task, never touches
//! a file descriptor.

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
pub use config::PeerConfig;
pub use event::Event;
pub use session::Session;
pub use state::SessionState;
