//! rustbgpd-wire — BGP message codec
//!
//! Pure codec library for BGP message encoding and decoding.
//! Zero internal dependencies. This crate is independently publishable.
//!
//! Supports: OPEN, KEEPALIVE, UPDATE, NOTIFICATION, ROUTE-REFRESH.
//! Enforces RFC 4271 maximum message size of 4096 bytes.

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
