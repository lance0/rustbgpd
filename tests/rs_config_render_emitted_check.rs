//! Emitted-config gate for `tools/rs-config-render`: what the renderer
//! produces from its checked-in fixture must pass the real daemon's
//! `rustbgpd --check --strict` (which also compiles every referenced
//! `.rpol` file), and the fixture's deliberately-empty IRR bundle must
//! abort the render rather than emit a config at all.
//!
//! Strict, not plain `--check`: the renderer is the IXP adoption path, so
//! its output is the config an operator gates in a refresh loop every day.
//! A plain `--check` here passed while every rendered member session was
//! warned about for resolving no export policy — the tool taught operators
//! that the gate they run is noise.

use rs_config_render::{
    Options, RenderError, SiteLocalFile, SiteLocalInput, render, render_site_local,
};
use sha2::{Digest, Sha256};

const FIXTURE: &str = include_str!("../tools/rs-config-render/tests/fixtures/context-small.yml");

fn rtr_options() -> Options {
    Options {
        rtr_caches: vec!["127.0.0.1:3323".to_owned()],
        ..Options::default()
    }
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn untouched_fixture_aborts_on_the_empty_irr_bundle() {
    match render(FIXTURE, &rtr_options()) {
        Err(RenderError::Implausible(items)) => {
            assert!(items.iter().any(|i| i.contains("AS51325_1")), "{items:?}");
        }
        other => panic!("expected implausible-set abort, got {other:?}"),
    }
}

#[test]
/// Load-bearing proof: dropping the active family ceiling or 37-minute to
/// 2,220-second conversion breaks the exact assertions; emitting a daemon-
/// invalid timer, or dropping the rendered export chain, breaks the real
/// `rustbgpd --check --strict` invocation.
fn emitted_config_passes_rustbgpd_check_strict() {
    // Drop the abort-proving client, then render the healthy context.
    let mut value: serde_yaml::Value = serde_yaml::from_str(FIXTURE).expect("fixture parses");
    value["clients"]
        .as_sequence_mut()
        .expect("clients list")
        .retain(|c| c["id"].as_str() != Some("AS51325_1"));
    value["irrdb_info"]
        .as_mapping_mut()
        .expect("irrdb_info mapping")
        .remove(serde_yaml::Value::String("AS51325_bundle".to_owned()));
    value["cfg"]["filtering"]["max_prefix"]["action"] = "restart".into();
    value["cfg"]["filtering"]["max_prefix"]["restart_after"] = 37.into();
    value["cfg"]["filtering"]["max_prefix"]["count_rejected_routes"] = false.into();
    let yaml = serde_yaml::to_string(&value).expect("context serializes");
    let rendered = render(&yaml, &rtr_options()).expect("healthy context renders");
    assert!(
        rendered.files["config.toml"]
            .contains("max_prefixes_ipv6 = 1000\nmax_prefix_restart_seconds = 2220"),
        "{}",
        rendered.files["config.toml"]
    );
    let client = rendered.receipt["clients"]
        .as_array()
        .unwrap()
        .iter()
        .find(|client| client["id"] == "AS197000_1")
        .unwrap();
    assert_eq!(client["max_prefix_restart_seconds"], 2220);

    let out_dir = tempfile::tempdir().expect("tempdir");
    for (rel_path, contents) in &rendered.files {
        let path = out_dir.path().join(rel_path);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(&path, contents).expect("write rendered file");
    }

    let config = out_dir.path().join("config.toml");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_rustbgpd"))
        .arg("--check")
        .arg("--strict")
        .arg(&config)
        .output()
        .expect("run rustbgpd --check --strict");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "rustbgpd --check --strict rejected the emitted config\nstdout:\n{stdout}\nstderr:\n{stderr}",
    );
    // Assert the summary line, not just the exit code: a warning that
    // somehow exited 0 would otherwise pass this gate silently.
    assert!(
        stdout.contains("config OK"),
        "strict check exited 0 without a clean summary\nstdout:\n{stdout}\nstderr:\n{stderr}",
    );
}

#[test]
fn emitted_blackhole_policy_passes_rpol_and_daemon_checks() {
    let mut value: serde_yaml::Value = serde_yaml::from_str(FIXTURE).expect("fixture parses");
    value["clients"]
        .as_sequence_mut()
        .unwrap()
        .retain(|c| c["id"].as_str() != Some("AS51325_1"));
    value["irrdb_info"]
        .as_mapping_mut()
        .unwrap()
        .remove(serde_yaml::Value::String("AS51325_bundle".into()));
    value["cfg"]["blackhole_filtering"]["policy_ipv4"] = "rewrite-next-hop".into();
    value["cfg"]["blackhole_filtering"]["rewrite_next_hop_ipv4"] = "192.0.2.66".into();
    value["cfg"]["blackhole_filtering"]["add_noexport"] = true.into();
    value["cfg"]["communities"]["blackholing"]["std"] = "65500:666".into();
    value["cfg"]["communities"]["blackholing"]["lrg"] = "65500:666:1".into();
    value["cfg"]["communities"]["blackholing"]["ext"] = "RT:192.0.2.1:65535".into();
    let prefix = &mut value["irrdb_info"]["AS4242_bundle"]["prefixes"][0];
    prefix["exact"] = false.into();
    prefix["ge"] = 26.into();
    prefix["le"] = 28.into();
    let policy = b"policy site-tag { term t { add community 65000:42; accept } }";
    let merge = b"[policy]\nexport_chain=[\"site-tag\"]";
    let site = SiteLocalInput {
        merge: SiteLocalFile {
            source_path: "merge.toml".into(),
            bytes: merge.to_vec(),
        },
        policies: vec![SiteLocalFile {
            source_path: "site.rpol".into(),
            bytes: policy.to_vec(),
        }],
    };
    let rendered = render_site_local(
        &serde_yaml::to_string(&value).unwrap(),
        &rtr_options(),
        &site,
    )
    .unwrap();
    assert!(rendered.files["config.toml"].contains("set_next_hop = \"192.0.2.66\""));
    assert!(
        rendered.files["config.toml"]
            .contains("export_policy_chain = [\"site-tag\", \"rs-blackhole-export-1\"]")
    );
    assert_eq!(
        rendered.receipt["site_local"]["config_sha256"],
        sha256(rendered.files["config.toml"].as_bytes())
    );
    assert_eq!(
        rendered.receipt["site_local"]["extra_policies"][0]["emitted_sha256"],
        sha256(policy)
    );
    for (path, source) in rendered
        .files
        .iter()
        .filter(|(path, _)| path.ends_with(".rpol"))
    {
        let mut source = source.clone();
        if path == "policy/rs-hygiene.rpol" {
            source.push_str(r#"
test bh-invalid-passes-hygiene { route { family ipv4-unicast; prefix 203.0.113.0/26; communities [BLACKHOLE]; as-path "4242"; rpki invalid } expect rs-hygiene == accept }
"#);
        }
        if path == "policy/client-as4242-1.rpol" {
            source.push_str(r#"
test bh-v25-reject { route { family ipv4-unicast; prefix 203.0.113.0/25; communities [BLACKHOLE]; as-path "4242" } expect client-as4242-1 == reject }
test bh-v26-accept { route { family ipv4-unicast; prefix 203.0.113.0/26; communities [BLACKHOLE]; as-path "4242" } expect client-as4242-1 == accept with community BLACKHOLE }
test bh-v26-invalid-accept { route { family ipv4-unicast; prefix 203.0.113.0/26; communities [BLACKHOLE]; as-path "4242"; rpki invalid } expect client-as4242-1 == accept with community BLACKHOLE }
test bh-v32-accept { route { family ipv4-unicast; prefix 203.0.113.0/32; communities [BLACKHOLE]; as-path "4242" } expect client-as4242-1 == accept with community BLACKHOLE }
test ordinary-v24-invalid-reject { route { family ipv4-unicast; prefix 198.51.100.0/24; as-path "4242"; rpki invalid } expect client-as4242-1 == reject }
test bh-unmarked-reject { route { family ipv4-unicast; prefix 203.0.113.0/32; as-path "4242" } expect client-as4242-1 == reject }
test bh-uncovered-reject { route { family ipv4-unicast; prefix 8.8.8.8/32; communities [BLACKHOLE]; as-path "4242" } expect client-as4242-1 == reject }
test bh-origin-reject { route { family ipv4-unicast; prefix 203.0.113.0/32; communities [BLACKHOLE]; as-path "4244" } expect client-as4242-1 == reject }
test bh-std { route { family ipv4-unicast; prefix 203.0.113.0/26; communities [65500:666]; as-path "4242" } expect client-as4242-1 == accept with community BLACKHOLE }
test bh-large { route { family ipv4-unicast; prefix 203.0.113.0/26; large-communities [65500:666:1]; as-path "4242" } expect client-as4242-1 == accept with community BLACKHOLE }
test bh-ext { route { family ipv4-unicast; prefix 203.0.113.0/26; ext-communities [RT:192.0.2.1:65535]; as-path "4242" } expect client-as4242-1 == accept with community BLACKHOLE }
"#);
        }
        let report = rustbgpd_policy::rpol::check_rpol(&source);
        assert!(
            report.is_ok(),
            "{path}: diagnostics={:?} tests={:?}\n{source}",
            report.diagnostics,
            report.tests
        );
    }
    let out_dir = tempfile::tempdir().unwrap();
    for (rel_path, contents) in &rendered.files {
        let path = out_dir.path().join(rel_path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_rustbgpd"))
        .args(["--check", "--strict"])
        .arg(out_dir.path().join("config.toml"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
