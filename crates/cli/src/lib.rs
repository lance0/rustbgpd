//! Library surface of the `rustbgpctl` package (the shipped binary is
//! `rbgp`). Hosts pure, transport-free tooling logic consumed by the CLI
//! and by ingestion adapters.

#![deny(unsafe_code)]
// As in the binary: no deprecated item, and no local opt-out (see the
// `connection.rs` test in the binary).
#![deny(deprecated)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

pub mod importer;
pub mod ribdiff;
pub mod ribsnap;
pub mod ribsnap_bmp;
