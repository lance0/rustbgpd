//! Acceptance gate for the retained 1,000-peer route-server scenario.

#[test]
/// Load-bearing proof: restoring the generator's local ASN to 65500 makes
/// peer 988 iBGP and fails the indexed eBGP assertion before `--check` runs;
/// daemon-invalid generated config or policy fails the real daemon check.
fn emitted_1000_peer_scenario_is_all_ebgp_and_daemon_valid() {
    use std::collections::BTreeSet;

    let dir = tempfile::tempdir().expect("tempdir");
    let generator = format!(
        "{}/bench/scale/reloadstall/gen-scenario.py",
        env!("CARGO_MANIFEST_DIR")
    );
    let output = std::process::Command::new("python3")
        .args([&generator, "1000"])
        .arg(dir.path())
        .args(["1790", "1000"])
        .output()
        .expect("run scenario generator");
    assert!(
        output.status.success(),
        "scenario generator failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let config_path = dir.path().join("config.toml");
    let config_text = std::fs::read_to_string(&config_path).expect("read config");
    let config: toml::Value = toml::from_str(&config_text).expect("parse generated TOML");
    let local_asn = config["global"]["asn"].as_integer().expect("global ASN");
    let neighbors = config["neighbors"].as_array().expect("neighbors array");
    assert_eq!(neighbors.len(), 1000);
    let mut addresses = BTreeSet::new();
    let mut remote_asns = BTreeSet::new();
    let mut common_shape = None;
    for (index, neighbor) in neighbors.iter().enumerate() {
        let address = neighbor["address"].as_str().expect("neighbor address");
        let expected_address = format!("127.1.{}.{}", index / 200, index % 200 + 1);
        assert_eq!(address, expected_address, "peer {index} address");
        assert!(
            addresses.insert(address),
            "duplicate peer address at {index}"
        );
        let remote_asn = neighbor["remote_asn"].as_integer().expect("remote ASN");
        assert_eq!(remote_asn, 64_512 + index as i64, "peer {index} ASN");
        assert!(
            remote_asns.insert(remote_asn),
            "duplicate remote ASN at peer {index}"
        );
        assert_ne!(
            remote_asn, local_asn,
            "peer {index} must be eBGP (local ASN {local_asn}, remote ASN {remote_asn})"
        );
        assert_eq!(neighbor["route_server_client"].as_bool(), Some(true));
        assert_eq!(
            neighbor["families"].as_array(),
            Some(&vec![toml::Value::String("ipv4_unicast".to_owned())]),
            "peer {index} family"
        );
        let mut shape = neighbor.as_table().expect("neighbor table").clone();
        shape.remove("address");
        shape.remove("remote_asn");
        match &common_shape {
            None => common_shape = Some(shape),
            Some(expected) => assert_eq!(&shape, expected, "peer {index} grouped shape"),
        }
    }
    assert_eq!(addresses.len(), 1000);
    assert_eq!(remote_asns.len(), 1000);
    assert!(
        (4_200_000_000..=4_294_967_294).contains(&local_asn),
        "local ASN {local_asn} must be RFC 6996 private four-octet space"
    );

    let checked = std::process::Command::new(env!("CARGO_BIN_EXE_rustbgpd"))
        .arg("--check")
        .arg(&config_path)
        .output()
        .expect("run rustbgpd --check");
    assert!(
        checked.status.success(),
        "rustbgpd --check rejected the generated scenario\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&checked.stdout),
        String::from_utf8_lossy(&checked.stderr)
    );
}

#[test]
/// Red proof: replacing the fingerprint-qualified status match with the old
/// bare `pass` match, or removing the sampler wait/data gate, makes this fail.
/// The column assertion likewise fails if the ambiguous historical label is
/// restored in future output.
fn irr_reload_campaign_seals_resume_rows_and_rss_evidence() {
    let runner = std::fs::read_to_string(format!(
        "{}/bench/scale/irrreload/run-irr-reload.sh",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("read IRR reload runner");

    for required in [
        "pass $CAMPAIGN_FINGERPRINT",
        "provenance.json",
        "DIRTY_STATE_SHA256",
        "bird_image_id",
        "openbgpd_image_id",
        "scenario.sha256",
        "cell_receipt_matches",
        "[ \"$actual_sha\" = \"$scenario_sha\" ] || return 1",
        "pass $CAMPAIGN_FINGERPRINT $scenario_sha",
        "pass $CAMPAIGN_FINGERPRINT $CELL_SCENARIO_SHA256",
        "wait \"$sampler_pid\"",
        "RSS sampler produced empty or invalid data",
        "changed_first_generation_update_p50_ms",
        "changed_first_generation_update_p95_ms",
        "changed_first_generation_update_max_ms",
        "[ \"$PRIOR_FINGERPRINT\" != \"$CAMPAIGN_FINGERPRINT\" ]",
        "[ \"$(head -n1 \"$ART/rows.csv\" 2>/dev/null)\" != \"$ROWS_HEADER\" ]",
        "required manifest/provenance retention failed",
        "rc=97",
        "NF != 23 || $1 != cell || $2 != sprintf(\"%d\", NR)",
        "NR != expected",
        "invalid, missing, or duplicate measurement rows",
        "failed to retain measurement rows",
        "rc=96",
        "[ \"${existing_rows:-0}\" -eq \"$RELOADS\" ]",
        "[ \"${rows:-0}\" -ne \"$RELOADS\" ]",
    ] {
        assert!(
            runner.contains(required),
            "missing receipt seal: {required}"
        );
    }
    assert!(
        !runner.contains("changed_first_update_p50_ms"),
        "future rows must not reuse the ambiguous historical column name"
    );
    let retention_gate = runner
        .find("required manifest/provenance retention failed")
        .expect("retention failure gate");
    let scenario_delete = runner
        .rfind("rm -rf \"$run\"")
        .expect("successful scenario deletion");
    assert!(
        retention_gate < scenario_delete,
        "retention must fail closed before successful scenario deletion"
    );
}
