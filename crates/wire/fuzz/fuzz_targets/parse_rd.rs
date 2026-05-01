//! Fuzz `RouteDistinguisher::from_str` against arbitrary input.
//!
//! Goals:
//!  1. Never panic on arbitrary input — the parser must always
//!     return a `Result`, never abort.
//!  2. Successfully-parsed RDs must round-trip through `Display` →
//!     `from_str` and produce a structurally-equal RD. The `Display`
//!     output is the canonical textual form; whatever the fuzzer
//!     fed in to produce a successful parse, the canonical form
//!     must re-parse to the same bytes.
//!
//! Invariant 2 catches subtle bugs in the disambiguation rule
//! (e.g., a Type-0 RD silently re-parsing as Type-2 via Display
//! output, or assigned-number-overflow that survives
//! `to_string`).

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustbgpd_wire::RouteDistinguisher;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(parsed) = s.parse::<RouteDistinguisher>() else {
        return;
    };
    // Display must produce a string the parser accepts as the same RD.
    let canonical = parsed.to_string();
    let reparsed: RouteDistinguisher = canonical
        .parse()
        .expect("Display output must re-parse cleanly");
    assert_eq!(parsed, reparsed, "Display→from_str round-trip must be lossless");
});
