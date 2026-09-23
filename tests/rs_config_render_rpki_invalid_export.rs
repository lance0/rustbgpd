//! Real-daemon regression for rendered arouteserver-mode RPKI handling with
//! `rpki_bgp_origin_validation.reject_invalid: false`.
//!
//! ARouteServer keeps INVALID routes in that mode but never announces ordinary
//! ones to clients. The rendered config runs in a real `rustbgpd` against an
//! in-process RTR cache and raw eBGP members (`tests/support/
//! rs_config_render_rpki_export.py`). One member announces an RPKI-invalid, a
//! valid and a not-found route. Each check requires the invalid route in that
//! member's Adj-RIB-In and absent from every other member's Adj-RIB-Out, both on
//! the wire and in `rbgp rib advertised`.
//!
//! - `plain`: the default permit-all export chain, then a VRP change that makes
//!   the route valid (it is announced) and invalid again (it is withdrawn).
//! - `blackhole-site`: active IPv4 blackhole filtering and a site-local
//!   neighbor export hook that accepts everything. An authorized blackhole
//!   request is invalid by maxLength but, as RFC 7999 §3.3 and ARouteServer
//!   require, still follows each client's blackhole export policy: 127.0.0.3
//!   receives it, and 127.0.0.4, with `announce_to_client: false`, does not.

mod support;

use rs_config_render::{Options, SiteLocalFile, SiteLocalInput, render, render_site_local};

const FIXTURE: &str = include_str!("../tools/rs-config-render/tests/fixtures/context-small.yml");

fn context(blackhole: bool) -> String {
    let client = |id: &str, asn: u32, ip: &str, announce: bool| {
        serde_yaml::from_str::<serde_yaml::Value>(&format!(
            "{{id: {id}, asn: {asn}, ip: '{ip}', description: {id}, cfg: {{rfc8950: false, \
             blackhole_filtering: {{announce_to_client: {announce}}}, filtering: {{irrdb: \
             {{as_set_bundle_ids: [AS4242_bundle]}}, max_prefix: {{limit_ipv4: 100, limit_ipv6: 0}}}}}}}}"
        ))
        .unwrap()
    };
    let mut value: serde_yaml::Value = serde_yaml::from_str(FIXTURE).unwrap();
    value["clients"] = serde_yaml::Value::Sequence(vec![
        client("AS4242_1", 4242, "127.0.0.2", true),
        client("AS4243_1", 4243, "127.0.0.3", true),
        client("AS4244_1", 4244, "127.0.0.4", !blackhole),
    ]);
    value["asns"] = serde_yaml::from_str(
        "{AS4242: {as_sets: [AS-A]}, AS4243: {as_sets: [AS-A]}, AS4244: {as_sets: [AS-A]}}",
    )
    .unwrap();
    value["irrdb_info"] = serde_yaml::from_str(
        "{AS4242_bundle: {asns: [4242, 4243, 4244], prefixes: [\
         {prefix: 198.51.100.0, length: 24, exact: true}, \
         {prefix: 203.0.113.0, length: 24, exact: true}, \
         {prefix: 198.18.0.0, length: 24, exact: true}]}}",
    )
    .unwrap();
    value["cfg"]["filtering"]["rpki_bgp_origin_validation"]["reject_invalid"] = false.into();
    if blackhole {
        value["cfg"]["blackhole_filtering"]["policy_ipv4"] = "propagate-unchanged".into();
        value["cfg"]["communities"]["blackholing"]["std"] = "65500:666".into();
    }
    serde_yaml::to_string(&value).unwrap()
}

fn run(scenario: &str) {
    let options = Options {
        rtr_caches: vec!["127.0.0.1:3323".to_owned()],
        ..Options::default()
    };
    let rendered = if scenario == "plain" {
        render(&context(false), &options)
    } else {
        let site = SiteLocalInput {
            merge: SiteLocalFile {
                source_path: "merge.toml".into(),
                bytes: b"[[neighbors]]\naddress = \"127.0.0.4\"\nexport_policy_chain = [\"site-permit\"]\n"
                    .to_vec(),
            },
            policies: vec![SiteLocalFile {
                source_path: "site.rpol".into(),
                bytes: b"policy site-permit { term permit-all { accept } }\n".to_vec(),
            }],
        };
        render_site_local(&context(true), &options, &site)
    }
    .expect("scenario context renders");

    let evidence = support::RetainOnPanic::new(
        tempfile::Builder::new()
            .prefix("rs-rpki-export-")
            .tempdir()
            .unwrap(),
    );
    let rendered_dir = evidence.path().join("rendered");
    for (path, contents) in &rendered.files {
        let path = rendered_dir.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }
    let output = std::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/support/rs_config_render_rpki_export.py"
        ))
        .arg("--binary")
        .arg(env!("CARGO_BIN_EXE_rustbgpd"))
        .arg("--rbgp")
        .arg(support::rbgp_binary())
        .arg("--rendered")
        .arg(&rendered_dir)
        .arg("--out")
        .arg(evidence.path())
        .arg("--scenario")
        .arg(scenario)
        .output()
        .expect("run the route-server RPKI export harness");
    assert!(
        output.status.success(),
        "{scenario} failed; evidence in {}\n{}\n{}",
        evidence.path().display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    print!("{}", String::from_utf8_lossy(&output.stdout));
}

#[test]
fn ordinary_rpki_invalid_routes_are_kept_but_not_exported_and_follow_vrp_changes() {
    run("plain");
}

#[test]
fn ordinary_rpki_invalid_routes_are_not_exported_through_site_hooks_or_blackhole_policy() {
    run("blackhole-site");
}
