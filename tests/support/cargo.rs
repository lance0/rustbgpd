//! Cargo subprocesses started by integration tests.

use std::process::Command;

/// Keep caller build controls, but discard the enclosing test package's metadata.
/// Build scripts track Cargo's incoming environment before Cargo supplies their
/// own package values; inheriting these values needlessly changes fingerprints.
pub fn command() -> Command {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut command = Command::new(cargo);
    for (key, _) in std::env::vars_os() {
        if key == "CARGO_MANIFEST_DIR"
            || key
                .to_str()
                .is_some_and(|key| key.starts_with("CARGO_PKG_"))
        {
            command.env_remove(key);
        }
    }
    command
}
