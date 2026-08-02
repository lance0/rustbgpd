//! Load-bearing enrollment for the IRR-scale BMP buffer receipt.

fn run(command: &mut std::process::Command, what: &str) -> String {
    let output = command
        .output()
        .unwrap_or_else(|error| panic!("{what}: {error}"));
    assert!(
        output.status.success(),
        "{what} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("UTF-8 command output")
}

fn assert_proofs(output: &str, proofs: &str) {
    for proof in proofs.split_ascii_whitespace() {
        assert!(
            output.lines().any(|line| line == format!("proof:{proof}")),
            "missing proof: {proof}"
        );
    }
}

#[test]
/// Destructive proofs: removing any parser/inventory/order bound makes its
/// named sink mutation pass; removing a metric, repeat, or process-identity
/// gate makes the verifier accept its named corrupt fixture.
fn bmp_buffer_components_reject_their_guarded_failures() {
    let root = env!("CARGO_MANIFEST_DIR");
    assert!(std::panic::catch_unwind(|| assert_proofs("proof:long-name\n", "long")).is_err());
    let sink = run(
        std::process::Command::new("python3").args([
            &format!("{root}/bench/scale/irrreload/bmp-loc-rib-sink.py"),
            "--self-test",
        ]),
        "BMP sink self-test",
    );
    assert_proofs(
        &sink,
        "complete-handshake duplicate-base base-withdrawal unexpected-prefix peer-identity \
         loc-rib-stats-order loc-rib-peer-down eor-order base-before-eor \
         dump-before-live-order frame-bound complete-fin-before-scrape termination-before-scrape",
    );

    let verifier = run(
        std::process::Command::new("python3").args([
            &format!("{root}/bench/scale/irrreload/verify-bmp-buffer-receipt.py"),
            "self-test",
        ]),
        "BMP verifier self-test",
    );
    assert_proofs(
        &verifier,
        "complete-metrics high-watermark-bound socket-open-at-scrape exact-base-inventory \
         post-eor-churn overflow-metrics overflow-discard-count same-outcome-class \
         fresh-process-identity canonical-shape canonical-policy-shape scenario-roster \
         sealed-artifact missing-checksum-seal missing-completed-marker provenance-order \
         provenance-commit checksum-drift symlink-artifact non-finite-metric cli-requires-seal \
         cli-allows-runner-preseal cli-sealed-pass",
    );
}

#[test]
/// Destructive proof: changing the canonical fleet/churn/buffer constants or
/// making the generator omit the Loc-RIB-only collector makes these executed
/// protocol and generated-TOML assertions red.
fn bmp_buffer_runner_and_generator_pin_the_canonical_shape() {
    let root = env!("CARGO_MANIFEST_DIR");
    let runner = format!("{root}/bench/scale/irrreload/run-bmp-buffer-receipt.sh");
    run(
        std::process::Command::new("bash").args(["-n", &runner]),
        "runner shell syntax",
    );
    let protocol = run(
        std::process::Command::new("bash")
            .arg(&runner)
            .env("DRY_RUN_PROTOCOL", "1"),
        "runner dry protocol",
    );
    for expected in [
        "members=320 prefixes=183040 seed=61 filter_entries=3218965",
        "churn=8x16/125ms collector=127.0.0.1:11019 runs=2 timeout=600s",
        "frame_max=1048576 capture_max=1073741824 live_buffer_cap=8192",
    ] {
        assert!(
            protocol.contains(expected),
            "missing protocol pin: {expected}"
        );
    }

    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(root).join("target"));
    let renderer = target.join("debug/rs-config-render");
    assert!(
        renderer.is_file(),
        "missing renderer at {}",
        renderer.display()
    );
    let dir = tempfile::tempdir().expect("tempdir");
    run(
        std::process::Command::new("python3")
            .args([
                &format!("{root}/bench/scale/reloadstall/gen-irr-scenario.py"),
                "rustbgpd",
                "10",
                "100",
            ])
            .arg(dir.path())
            .args(["--min-list", "100", "--max-list", "100", "--render-bin"])
            .arg(&renderer)
            .args(["--bmp-collector", "127.0.0.1:11019"]),
        "BMP scenario generation",
    );
    let config: toml::Value = toml::from_str(
        &std::fs::read_to_string(dir.path().join("config.toml")).expect("generated config"),
    )
    .expect("generated TOML");
    let collectors = config["bmp"]["collectors"]
        .as_array()
        .expect("collector array");
    assert_eq!(collectors.len(), 1);
    assert_eq!(collectors[0]["address"].as_str(), Some("127.0.0.1:11019"));
    assert_eq!(
        collectors[0]["monitor"].as_array(),
        Some(&vec![toml::Value::String("loc_rib".to_owned())])
    );
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.path().join("manifest.json")).expect("generated manifest"),
    )
    .expect("generated manifest JSON");
    assert_eq!(manifest["bmp_collector"], "127.0.0.1:11019");
    assert_eq!(manifest["bmp_version"], 3);
    assert_eq!(manifest["bmp_view"], "loc_rib");
    run(
        std::process::Command::new(env!("CARGO_BIN_EXE_rustbgpd"))
            .arg("--check")
            .arg(dir.path().join("config.toml")),
        "generated BMP scenario daemon check",
    );
}
