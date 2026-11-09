//! Offline policy checks bound diagnostic-location work on generated long lines.

mod support;

use std::process::Command;
use std::time::{Duration, Instant};

#[test]
fn single_line_mebibyte_policy_checks_within_debug_budget() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("dense.rpol");
    let mut source = "@a ".repeat(1_048_576 / 3);
    source.push('@');
    assert_eq!(source.len(), 1_048_576);
    std::fs::write(&path, source).unwrap();
    for json in [false, true] {
        let mut command = Command::new(support::rbgp_binary());
        command.args(["--no-color", "policy", "check"]).arg(&path);
        if json {
            command.arg("--json");
        }
        let start = Instant::now();
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(1));
        // Debug builds and shared CI runners need headroom; work counters in
        // the CLI unit regression catch rescanning independently of the clock.
        assert!(start.elapsed() < Duration::from_secs(30), "json={json}");
        if json {
            let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert!(!document["findings"].as_array().unwrap().is_empty());
        }
    }
}
