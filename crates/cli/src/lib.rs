//! Library surface of the `rustbgpctl` package (the shipped binary is
//! `rbgp`). Hosts pure, transport-free tooling logic consumed by the CLI
//! and by ingestion adapters.

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

pub mod importer;
pub mod ribdiff;
pub mod ribsnap;
pub mod ribsnap_bmp;
