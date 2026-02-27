//! rustbgpd — API-first BGP daemon
//!
//! Binary entry point. Loads config, wires components, starts runtime.

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

fn main() {
    println!("rustbgpd v{}", env!("CARGO_PKG_VERSION"));
}
