use std::fs;

use rs_config_render::ixp_manager::{Error, render_document};
use rs_config_render::ixp_manager_host::RenderBinding;

const FIXTURE: &[u8] = include_bytes!("fixtures/ixp-manager-v1-supported.json");
const SECRET: &str = "mcWsqMdzGwTKt67g";

fn digest(path: &std::path::Path) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(fs::read(path).unwrap())
        .iter()
        .fold(String::new(), |mut out, byte| {
            std::fmt::Write::write_fmt(&mut out, format_args!("{byte:02x}")).unwrap();
            out
        })
}

fn value() -> serde_json::Value {
    serde_json::from_slice(FIXTURE).unwrap()
}

fn binding() -> RenderBinding {
    RenderBinding::new(
        "b2-rs1-lan1-ipv4",
        std::path::Path::new("/var/lib/rustbgpd/b2-rs1-lan1-ipv4"),
    )
    .unwrap()
}

fn rendered(input: &serde_json::Value) -> Result<rs_config_render::ixp_manager::Candidate, Error> {
    render_document(&serde_json::to_vec(input).unwrap(), 300, &binding())
}

#[test]
fn supported_render_is_deterministic_and_explicit() {
    let first = render_document(FIXTURE, 300, &binding()).unwrap();
    assert_eq!(
        first.files,
        render_document(FIXTURE, 300, &binding()).unwrap().files
    );
    assert_eq!(first.files.len(), 3);
    let config = &first.files["config.toml"];
    for expected in [
        "listen_addresses = [\"192.0.2.18\"]",
        "runtime_state_dir = \"/var/lib/rustbgpd/b2-rs1-lan1-ipv4\"",
        "path = \"/var/lib/rustbgpd/b2-rs1-lan1-ipv4/grpc.sock\"",
        "next_hop_ownership = \"strict_peer\"",
        "per_client_best = true",
        "rs_control_communities = true",
        "interpret_rfc1997 = true",
        "max_prefix_restart_seconds = 300",
        "md5_password = \"mcWsqMdzGwTKt67g\"",
    ] {
        assert!(config.contains(expected), "missing {expected}");
    }
    let client = &first.files["policy/client-3.rpol"];
    assert!(client.contains("asn-set client-3-origins { 42 }"));
    assert!(client.contains("31.135.128.0/19"));
    assert!(client.contains("term rest { reject }"));
    let mut loose = value();
    loose["clients"][0]["more_specifics"] = true.into();
    assert!(
        rendered(&loose).unwrap().files["policy/client-3.rpol"].contains("31.135.128.0/19 le 24")
    );
    let mut transit = value();
    transit["policy"]["no_transit"]["asns"] = serde_json::json!([42]);
    let hygiene = &rendered(&transit).unwrap().files["policy/ixp-hygiene.rpol"];
    assert!(hygiene.contains("if route.as-path matches \"_(42)_\""));
    assert!(!hygiene.contains("peer.asn in ixp-manager-no-transit"));
    let mut maximum = value();
    maximum["policy"]["minimum_prefix_length"] = 32.into();
    assert!(
        !rendered(&maximum).unwrap().files["policy/ixp-hygiene.rpol"]
            .contains("ixp-manager-too-specific")
    );
}

#[test]
fn strict_schema_completion_and_refusal_matrix_fail_closed() {
    let forged: RenderBinding = serde_json::from_value(serde_json::json!({
        "router_handle": "b2-rs1-lan1-ipv4",
        "runtime_state_dir": "/var/lib/rustbgpd/foreign"
    }))
    .unwrap();
    assert!(matches!(
        render_document(FIXTURE, 300, &forged),
        Err(Error::Refused("invalid router host binding"))
    ));
    let refuses = |pointer: &str, replacement: serde_json::Value| {
        let mut input = value();
        *input.pointer_mut(pointer).unwrap() = replacement;
        assert!(rendered(&input).is_err(), "{pointer} unexpectedly rendered");
    };
    refuses("/schema", serde_json::json!("wrong"));
    refuses("/ixp_manager/version", serde_json::json!("7.5.0"));
    refuses("/router/type", serde_json::json!("collector"));
    refuses("/router/protocol", serde_json::json!(5));
    refuses("/router/quarantine", serde_json::json!(true));
    refuses("/router/bgp_lc", serde_json::json!(false));
    refuses("/policy/no_transit/source", serde_json::json!("default"));
    refuses(
        "/unsupported/active_ui_filters",
        serde_json::json!([{"customer_id":3,"filter_ids":[]}]),
    );
    refuses(
        "/unsupported/route_server_skin_files",
        serde_json::json!(["bird2/standard.foil.php"]),
    );
    refuses("/clients/0/irr_filter", serde_json::json!(false));
    refuses("/clients/0/origins", serde_json::json!([]));
    refuses("/clients/0/origins/0", serde_json::json!(0));
    refuses("/clients/0/prefixes", serde_json::json!([]));
    refuses("/clients/0/address", serde_json::json!("not-an-ip"));
    refuses("/clients/0/address", serde_json::json!("2001:db8::1"));
    refuses(
        "/clients/0/peering_ips",
        serde_json::json!(["10.1.0.36", "10.1.0.37"]),
    );
    refuses("/clients/0/auth/value", serde_json::json!("changeme"));
    refuses("/clients/0/auth/value", serde_json::json!("x".repeat(81)));
    refuses("/policy/rtr_caches", serde_json::json!(["127.0.0.1:0"]));
    refuses("/policy/rtr_caches", serde_json::json!([]));
    refuses("/complete/marker", serde_json::json!("END"));
    refuses("/complete/handle", serde_json::json!("other"));
    refuses("/complete/client_count", serde_json::json!(2));
    refuses("/router/skip_md5", serde_json::json!(true));
    let mut unknown = value();
    unknown["router"]["mystery"] = true.into();
    assert_eq!(rendered(&unknown).unwrap_err(), Error::Input);
    let mut dropped = value();
    dropped["clients"][0]["more_specifics"] = true.into();
    dropped["clients"][0]["prefixes"] = serde_json::json!(["31.135.128.0/25"]);
    assert!(rendered(&dropped).is_err());
    let mut repeated = value();
    let mut client = repeated["clients"][0].clone();
    client["customer_id"] = 4.into();
    client["vlan_interface_id"] = 4.into();
    client["address"] = "10.1.0.37".into();
    client["peering_ips"] = serde_json::json!(["10.1.0.37"]);
    repeated["clients"].as_array_mut().unwrap().push(client);
    repeated["complete"]["client_count"] = 2.into();
    assert!(rendered(&repeated).is_err());
    let mut no_auth = value();
    no_auth["clients"][0]["auth"] = serde_json::json!({"type":"none"});
    assert!(rendered(&no_auth).is_ok());
    no_auth["router"]["skip_md5"] = true.into();
    assert!(rendered(&no_auth).is_ok());
}

#[cfg(unix)]
fn set_mode(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

#[cfg(unix)]
fn mode(path: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[cfg(unix)]
fn run_cli(
    temp: &tempfile::TempDir,
    out: &std::path::Path,
    fail: bool,
    input_mode: u32,
    extra: &[&str],
) -> std::process::Output {
    use std::process::Command;
    let input = temp.path().join("input.json");
    fs::write(&input, FIXTURE).unwrap();
    set_mode(&input, input_mode);
    let log = temp.path().join("checker.log");
    let checker = temp.path().join("checker.sh");
    fs::write(&checker, "#!/bin/sh\n[ ! -e \"$OUT/render-receipt.json\" ] || exit 90\nprintf '%s\\n' \"$*\" >> \"$LOG\"\nif [ \"$1\" = --version ]; then echo \"rustbgpd 0.65.0 $SECRET\"; echo \"$SECRET\" >&2; exit 0; fi\n[ \"$FAIL\" = 0 ] || exit 91\n").unwrap();
    set_mode(&checker, 0o700);
    let runtime = temp.path().join("b2-rs1-lan1-ipv4");
    Command::new(env!("CARGO_BIN_EXE_rs-config-render"))
        .args(["--input-format", "ixp-manager-v1", "--context"])
        .arg(&input)
        .arg("--out-dir")
        .arg(out)
        .args(["--max-prefix-restart-seconds", "300", "--check-with"])
        .arg(&checker)
        .args(["--router-handle", "b2-rs1-lan1-ipv4"])
        .arg("--runtime-state-dir")
        .arg(&runtime)
        .env("OUT", out)
        .env("LOG", log)
        .env("SECRET", SECRET)
        .env("FAIL", if fail { "1" } else { "0" })
        .args(extra)
        .output()
        .unwrap()
}

#[cfg(unix)]
#[test]
fn cli_enforces_private_checker_order_receipt_last_and_redaction() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().unwrap();
    let out = temp.path().join("candidate");
    fs::create_dir(&out).unwrap();
    set_mode(&out, 0o700);
    let result = run_cli(&temp, &out, false, 0o600, &[]);
    assert!(result.status.success(), "{result:?}");
    assert!(!String::from_utf8_lossy(&result.stdout).contains(SECRET));
    assert!(!String::from_utf8_lossy(&result.stderr).contains(SECRET));
    let receipt = fs::read(out.join("render-receipt.json")).unwrap();
    assert!(
        !receipt
            .windows(SECRET.len())
            .any(|w| w == SECRET.as_bytes())
    );
    let receipt: serde_json::Value = serde_json::from_slice(&receipt).unwrap();
    assert_eq!(receipt["strict_check"]["binary_version"], "rustbgpd 0.65.0");
    assert_eq!(receipt["strict_check"]["passed"], true);
    assert_eq!(receipt["counts"]["clients"], 1);
    assert_eq!(receipt["counts"]["prefixes"], 1);
    assert_eq!(receipt["counts"]["origins"], 1);
    assert_eq!(
        receipt["host"],
        serde_json::to_value(
            RenderBinding::new("b2-rs1-lan1-ipv4", &temp.path().join("b2-rs1-lan1-ipv4")).unwrap()
        )
        .unwrap()
    );
    assert_eq!(
        receipt["input"]["sha256"],
        digest(&temp.path().join("input.json"))
    );
    assert_eq!(mode(&out), 0o700);
    assert_eq!(mode(&out.join("policy")), 0o700);
    for path in [
        "config.toml",
        "policy/ixp-hygiene.rpol",
        "policy/client-3.rpol",
        "render-receipt.json",
    ] {
        assert_eq!(mode(&out.join(path)), 0o600);
        if path != "render-receipt.json" {
            assert_eq!(receipt["generated_files"][path], digest(&out.join(path)));
        }
    }
    let log = fs::read_to_string(temp.path().join("checker.log")).unwrap();
    let lines = log.lines().collect::<Vec<_>>();
    assert_eq!(lines[0], "--version");
    assert_eq!(
        lines[1],
        format!("--check --strict {}", out.join("config.toml").display())
    );

    let failed = temp.path().join("failed");
    let result = run_cli(&temp, &failed, true, 0o600, &[]);
    assert_eq!(result.status.code(), Some(3));
    assert!(failed.join("config.toml").is_file());
    assert!(!failed.join("render-receipt.json").exists());
    assert!(!String::from_utf8_lossy(&result.stderr).contains(SECRET));
    let nonempty = temp.path().join("nonempty");
    fs::create_dir(&nonempty).unwrap();
    set_mode(&nonempty, 0o700);
    fs::write(nonempty.join("old"), b"stale").unwrap();
    assert_eq!(
        run_cli(&temp, &nonempty, false, 0o600, &[]).status.code(),
        Some(3)
    );
    let public = temp.path().join("public");
    fs::create_dir(&public).unwrap();
    set_mode(&public, 0o755);
    assert_eq!(
        run_cli(&temp, &public, false, 0o600, &[]).status.code(),
        Some(3)
    );
    assert_eq!(
        run_cli(&temp, &temp.path().join("public-input"), false, 0o644, &[])
            .status
            .code(),
        Some(2)
    );
    let legacy = temp.path().join("legacy");
    assert_eq!(
        run_cli(&temp, &legacy, false, 0o600, &["--min-prefixes", "1"])
            .status
            .code(),
        Some(2)
    );
    let empty = temp.path().join("empty");
    fs::create_dir(&empty).unwrap();
    set_mode(&empty, 0o700);
    let out_link = temp.path().join("output-link");
    symlink(&empty, &out_link).unwrap();
    assert_eq!(
        run_cli(&temp, &out_link, false, 0o600, &[]).status.code(),
        Some(3)
    );
    fs::remove_file(temp.path().join("input.json")).unwrap();
    let input_target = temp.path().join("input-target.json");
    fs::write(&input_target, FIXTURE).unwrap();
    set_mode(&input_target, 0o600);
    symlink(&input_target, temp.path().join("input.json")).unwrap();
    assert_eq!(
        run_cli(&temp, &temp.path().join("linked-input"), false, 0o600, &[])
            .status
            .code(),
        Some(2)
    );
}

#[test]
fn workflow_and_gpl_source_only_boundaries_are_pinned() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let workflow = fs::read_to_string(root.join(".github/workflows/ixp-compat.yml")).unwrap();
    for path in ["tools/rs-config-render/**", "integrations/ixp-manager/**"] {
        assert_eq!(workflow.matches(&format!("- \"{path}\"")).count(), 2);
    }
    for source in [
        "tools/rs-config-render/src/ixp_manager.rs",
        "tools/rs-config-render/src/lib.rs",
        "tools/rs-config-render/src/main.rs",
    ] {
        let text = fs::read_to_string(root.join(source)).unwrap();
        assert!(!text.contains("include_str!(\"../../../integrations/"));
        assert!(!text.contains("include_bytes!(\"../../../integrations/"));
    }
    let binary = fs::read(env!("CARGO_BIN_EXE_rs-config-render")).unwrap();
    assert!(
        !binary
            .windows(b"integrations/ixp-manager/gpl-2.0-only".len())
            .any(|w| w == b"integrations/ixp-manager/gpl-2.0-only")
    );
    for manifest in [
        ".github/workflows/release.yml",
        "scripts/build-packages.sh",
        "Dockerfile",
    ] {
        assert!(
            !fs::read_to_string(root.join(manifest))
                .unwrap()
                .contains("integrations/ixp-manager")
        );
    }
    let allowed = |entries: &[&str]| {
        entries
            .iter()
            .all(|path| !path.starts_with("integrations/"))
    };
    assert!(allowed(&["rustbgpd", "share/rustbgpd/config.toml"]));
    assert!(!allowed(&[
        "rustbgpd",
        "integrations/ixp-manager/gpl-2.0-only/LICENSE"
    ]));
}
