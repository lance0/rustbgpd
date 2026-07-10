//! Guard for the `src/lib.rs` module mirror (LAN-198 class).
//!
//! The library target re-declares the subset of `src/main.rs` modules that
//! `config`'s dependency closure needs under the `bench-internals` feature.
//! A module added to `main.rs` without a deliberate mirror decision breaks
//! `cargo check -p rustbgpd --all-features --lib` only when someone happens
//! to build that combination — this test makes the decision explicit at
//! ordinary `cargo test` time instead.
//!
//! The files are parsed at test run time, never rewritten, so concurrent
//! module additions only ever fail this test with instructions.

use std::collections::BTreeSet;
use std::path::Path;

/// `main.rs` modules deliberately NOT mirrored in `lib.rs`: they are outside
/// the dependency closure of the lib-exposed modules. Adding a module to
/// `main.rs` requires either mirroring it in `lib.rs` (if anything the lib
/// exposes reaches it) or listing it here — that forced choice is the guard.
const NOT_MIRRORED: &[&str] = &[
    "bfd_runtime",
    "blackhole",
    "config_persister",
    "config_transaction_control",
    "confirm_journal",
    "fib_runtime",
    "fib_table_control",
    "gnmi_set_bridge",
    "kernel_route_notify",
    "metrics_server",
    "peer_manager",
    "policy_admin",
    "reload",
];

/// Collect file-backed `mod name;` declarations (any visibility, any cfg
/// attributes). Inline `mod name { .. }` blocks are not mirror candidates.
fn mod_declarations(path: &Path) -> BTreeSet<String> {
    let source = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    source
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let rest = line
                .strip_prefix("pub(crate) ")
                .or_else(|| line.strip_prefix("pub "))
                .unwrap_or(line);
            let name = rest.strip_prefix("mod ")?.strip_suffix(';')?.trim();
            name.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
                .then(|| name.to_string())
        })
        .collect()
}

#[test]
fn lib_rs_mirrors_main_rs_modules() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let main_mods = mod_declarations(&src.join("main.rs"));
    let lib_mods = mod_declarations(&src.join("lib.rs"));
    let exceptions: BTreeSet<&str> = NOT_MIRRORED.iter().copied().collect();

    // Every lib.rs module must exist in main.rs — the lib is a mirror, not
    // an independent module tree.
    let lib_only: Vec<_> = lib_mods
        .iter()
        .filter(|name| !main_mods.contains(*name))
        .collect();
    assert!(
        lib_only.is_empty(),
        "src/lib.rs declares modules absent from src/main.rs: {lib_only:?}"
    );

    // Every main.rs module must be mirrored in lib.rs or deliberately listed
    // in NOT_MIRRORED above.
    let unaccounted: Vec<_> = main_mods
        .iter()
        .filter(|name| !lib_mods.contains(*name) && !exceptions.contains(name.as_str()))
        .collect();
    assert!(
        unaccounted.is_empty(),
        "src/main.rs modules neither mirrored in src/lib.rs nor listed in \
         NOT_MIRRORED (tests/lib_module_mirror.rs): {unaccounted:?}. If the \
         module is reachable from the lib-exposed modules, mirror it in \
         src/lib.rs (see the LAN-198 comment there); otherwise add it to \
         NOT_MIRRORED."
    );

    // Keep the exception list honest: every entry must still be a real,
    // unmirrored main.rs module.
    let stale: Vec<_> = exceptions
        .iter()
        .filter(|name| !main_mods.contains(**name) || lib_mods.contains(**name))
        .collect();
    assert!(
        stale.is_empty(),
        "stale NOT_MIRRORED entries (removed from src/main.rs or now \
         mirrored in src/lib.rs): {stale:?}"
    );
}
