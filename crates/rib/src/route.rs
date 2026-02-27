use std::net::Ipv4Addr;
use std::time::Instant;

use rustbgpd_wire::{Ipv4Prefix, PathAttribute};

/// A single route stored in the Adj-RIB-In.
#[derive(Debug, Clone)]
pub struct Route {
    pub prefix: Ipv4Prefix,
    pub next_hop: Ipv4Addr,
    pub attributes: Vec<PathAttribute>,
    pub received_at: Instant,
}
