//! rustbgpd-fsm — RFC 4271 BGP finite state machine
//!
//! Pure state machine. Takes message and timer inputs, produces message and
//! state outputs. Never imports tokio, never spawns a task, never touches
//! a file descriptor.

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
