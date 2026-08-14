//! Timing entry for the shared VPN query bench body in `vpn_query/mod.rs`.
//!
//! The two `vpn_query_*` targets compile that body from distinct entry files
//! so they do not share a target `path` (cargo warns on that). The binary
//! names are pinned by the event-history host-fence scripts — do not rename
//! or collapse the targets.

mod vpn_query;

fn main() {
    vpn_query::main();
}
