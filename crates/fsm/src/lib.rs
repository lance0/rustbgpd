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
