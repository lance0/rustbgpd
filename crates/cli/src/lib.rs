//! Library surface of the `rustbgpctl` package (the shipped binary is
//! `rbgp`). Hosts pure, transport-free tooling logic consumed by the CLI
//! and by ingestion adapters.

#![deny(unsafe_code)]

pub mod ribdiff;
