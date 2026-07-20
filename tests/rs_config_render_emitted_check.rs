//! Emitted-config gate for `tools/rs-config-render`: what the renderer
//! produces from its checked-in fixture must pass the real daemon's
//! `rustbgpd --check` (which also compiles every referenced `.rpol`
//! file), and the fixture's deliberately-empty IRR bundle must abort
//! the render rather than emit a config at all.

use rs_config_render::{Options, RenderError, render};

const FIXTURE: &str = include_str!("../tools/rs-config-render/tests/fixtures/context-small.yml");

fn rtr_options() -> Options {
    Options {
        rtr_caches: vec!["127.0.0.1:3323".to_owned()],
        ..Options::default()
    }
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
/// invalid timer breaks the real `rustbgpd --check` invocation.
fn emitted_config_passes_rustbgpd_check() {
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
        .arg(&config)
        .output()
        .expect("run rustbgpd --check");
    assert!(
        output.status.success(),
        "rustbgpd --check rejected the emitted config\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
