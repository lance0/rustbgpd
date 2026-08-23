//! Shared harness pieces for the real-daemon fail-stop integration tests.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Temporary test directory that survives on panic.
///
/// The daemon under test writes its log inside the test's temporary
/// directory, so dropping that directory on an assertion failure destroys
/// the only evidence of why the daemon misbehaved. This guard disarms
/// cleanup while the thread is panicking and names the retained path in the
/// captured test output.
pub struct RetainOnPanic {
    dir: Option<tempfile::TempDir>,
}

impl RetainOnPanic {
    pub fn new(dir: tempfile::TempDir) -> Self {
        Self { dir: Some(dir) }
    }

    pub fn path(&self) -> &Path {
        self.dir
            .as_ref()
            .expect("temporary directory is held until drop")
            .path()
    }
}

impl Drop for RetainOnPanic {
    fn drop(&mut self) {
        let Some(dir) = self.dir.take() else {
            return;
        };
        if std::thread::panicking() {
            let path = dir.keep();
            eprintln!(
                "test panicked: daemon logs and state retained at {}",
                path.display()
            );
        }
    }
}

/// Resolve the `rbgp` CLI binary next to the daemon binary under test.
///
/// `CARGO_BIN_EXE_rbgp` is honoured when the invoker exports it; otherwise
/// the binary must already sit next to `rustbgpd` in the build profile
/// directory, which `cargo test --workspace` guarantees. Falling back to
/// `cargo run` instead would put a build lock and a workspace freshness
/// check on the hot path of grace-window assertions, where seconds of
/// build-load stall turn a live-daemon rejection into a missed deadline.
pub fn rbgp_binary() -> &'static Path {
    static RBGP: OnceLock<PathBuf> = OnceLock::new();
    RBGP.get_or_init(|| {
        let path = std::env::var_os("CARGO_BIN_EXE_rbgp").map_or_else(
            || {
                Path::new(env!("CARGO_BIN_EXE_rustbgpd"))
                    .parent()
                    .expect("rustbgpd binary has a profile directory")
                    .join("rbgp")
            },
            PathBuf::from,
        );
        assert!(
            path.is_file(),
            "build rbgp before this test (cargo test --workspace builds it); missing {}",
            path.display()
        );
        path
    })
}
