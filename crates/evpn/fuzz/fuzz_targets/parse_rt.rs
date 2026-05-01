//! Fuzz `RouteTarget::from_str` against arbitrary input.
//!
//! Goals:
//!  1. Never panic on arbitrary input — the parser must always
//!     return a `Result`, never abort.
//!  2. Successfully-parsed RTs must round-trip through `Display` →
//!     `from_str` and produce a structurally-equal RT. The `Display`
//!     output is the canonical textual form (without the `RT:`
//!     discriminator since the type itself is a Route Target);
//!     whatever shape the fuzzer fed in, the canonical form must
//!     re-parse to the same enum variant and same bytes.
//!
//! Invariant 2 catches disambiguation bugs (a `TwoOctetAs` form
//! silently re-parsing as `FourOctetAs` via Display output, or
//! an `Ipv4` form whose value overflowed past 16 bits silently
//! truncating on round-trip).

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustbgpd_evpn::RouteTarget;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(parsed) = s.parse::<RouteTarget>() else {
        return;
    };
    // Display must produce a string the parser accepts as the same RT.
    let canonical = parsed.to_string();
    let reparsed: RouteTarget = canonical
        .parse()
        .expect("Display output must re-parse cleanly");
    assert_eq!(
        parsed, reparsed,
        "Display→from_str round-trip must be lossless"
    );
});
