//! rustbgpd-api — gRPC API server
//!
//! Tonic bindings for all five rustbgpd services:
//! `GlobalService`, `NeighborService`, `RibService`, `InjectionService`, `ControlService`.

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
