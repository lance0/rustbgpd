//! rustbgpd-rib — RIB data structures
//!
//! Adj-RIB-In per neighbor, Loc-RIB best-path selection, Adj-RIB-Out
//! per neighbor. Route objects keyed by (AFI, SAFI, prefix).

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
