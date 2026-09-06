//! Offline policy coverage thresholds retain distinct evaluated and matched facts.

use std::path::Path;
use std::process::{Command, Output};

const TWO_OF_THREE: &str = "
policy p {
    term a { if route.local-pref >= 500 { reject } }
    term b { if route.med <= 10 { accept } }
    term c { reject }
}
test hits-b { route { med 5 } expect p == accept }
test hits-c { route { med 50 } expect p == reject }
";

fn run(path: &Path, args: &[&str]) -> Output {
    let address = format!("unix://{}/absent.sock", path.parent().unwrap().display());
    Command::new(env!("CARGO_BIN_EXE_rbgp"))
        .args(["--addr", &address, "--no-color", "policy", "check"])
        .arg(path)
        .args(args)
        .output()
        .expect("run offline policy check")
}

#[test]
fn matched_threshold_catches_an_evaluated_but_never_matched_guard() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policy.rpol");
    std::fs::write(&path, TWO_OF_THREE).unwrap();

    let old = run(&path, &["--coverage-min", "100", "-j"]);
    assert_eq!(old.status.code(), Some(0), "{old:?}");
    let old_json: serde_json::Value = serde_json::from_slice(&old.stdout).unwrap();
    assert_eq!(old_json["coverage"]["terms_total"], 3);
    assert_eq!(old_json["coverage"]["terms_exercised"], 3);
    assert_eq!(old_json["coverage"]["percent"], 100.0);
    assert_eq!(old_json["coverage"]["terms_matched"], 2);
    assert_eq!(
        old_json["coverage"]["matched_percent"].as_f64().unwrap(),
        2.0 / 3.0 * 100.0
    );

    let strict = run(&path, &["--coverage-matched-min", "100", "-j"]);
    assert_eq!(strict.status.code(), Some(3), "{strict:?}");
    let strict_json: serde_json::Value = serde_json::from_slice(&strict.stdout).unwrap();
    // The report describes test and coverage facts, independently of
    // the requested threshold. Its existing `ok` still means tests passed.
    assert_eq!(old_json, strict_json);
    assert!(
        String::from_utf8_lossy(&strict.stderr)
            .contains("matched coverage 66.7% is below --coverage-matched-min 100%")
    );

    for (threshold, expected) in [("0", 0), ("66.6", 0), ("66.7", 3)] {
        let output = run(
            &path,
            &["--coverage-min", "100", "--coverage-matched-min", threshold],
        );
        assert_eq!(output.status.code(), Some(expected), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains("matched coverage: 2/3 terms matched by tests")
        );
    }

    let plain = run(&path, &["-j"]);
    assert_eq!(plain.status.code(), Some(0), "{plain:?}");
    let plain_json: serde_json::Value = serde_json::from_slice(&plain.stdout).unwrap();
    assert!(plain_json.get("coverage").is_none());

    std::fs::write(
        &path,
        format!("{TWO_OF_THREE}\ntest hits-a {{ route {{ local-pref 500 }} expect p == reject }}"),
    )
    .unwrap();
    let covered = run(&path, &["--coverage-matched-min", "100"]);
    assert_eq!(covered.status.code(), Some(0), "{covered:?}");
    assert!(
        String::from_utf8_lossy(&covered.stdout)
            .contains("matched coverage: 3/3 terms matched by tests")
    );
}

#[test]
fn matched_threshold_preserves_imports_parameters_and_apply_only_denominator() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("main.rpol");
    let library = directory.path().join("library.rpol");
    std::fs::write(
        &library,
        "policy p(n: u32) {
            term hit { if route.med == n { accept } }
            term rest { reject }
        }
        policy outer { term t { if apply(p(10)) { accept } } }
        policy helper { term t { accept } }
        policy caller { term t { if apply(helper) { accept } } }",
    )
    .unwrap();
    std::fs::write(
        &path,
        "import \"library.rpol\"
        test t {
            route { med 10 }
            expect p(10) == accept
            expect p(20) == reject
            expect outer == accept
            expect caller == accept
        }",
    )
    .unwrap();
    let output = run(&path, &["--coverage-matched-min", "100", "-j"]);
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let coverage = &json["coverage"];
    assert_eq!(coverage["terms_total"], 5);
    assert_eq!(coverage["terms_matched"], 4);
    assert_eq!(coverage["matched_percent"], 80.0);
    let policies = coverage["policies"].as_array().unwrap();
    let p = policies.iter().find(|p| p["name"] == "p").unwrap();
    assert_eq!(p["terms"][0]["matched"], 1);
    assert_eq!(p["terms"][1]["matched"], 1);
    assert!(p["file"].as_str().unwrap().ends_with("library.rpol"));
    let helper = policies.iter().find(|p| p["name"] == "helper").unwrap();
    assert_eq!(helper["status"], "apply-only");
    assert_eq!(helper["terms"][0]["matched"], 0);
    let boundary = run(&path, &["--coverage-matched-min", "80"]);
    assert_eq!(boundary.status.code(), Some(0), "{boundary:?}");
}

#[test]
fn matched_threshold_keeps_error_precedence_and_validates_percentages() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policy.rpol");
    for (source, expected) in [
        ("policy p { term t { if route.zzz == 1 { accept } } }", 1),
        (
            "policy p { term t { reject } } test t { route { med 0 } expect p == accept }",
            2,
        ),
        ("policy p { term t { reject } }", 3),
        ("policy p {}", 0),
    ] {
        std::fs::write(&path, source).unwrap();
        let output = run(&path, &["--coverage-matched-min", "100", "-j"]);
        assert_eq!(output.status.code(), Some(expected), "{source}: {output:?}");
    }
    for threshold in ["-1", "100.1", "NaN", "inf", "-inf", "wrong"] {
        let option = format!("--coverage-matched-min={threshold}");
        let output = run(&path, &[&option]);
        assert_eq!(output.status.code(), Some(2), "{threshold}: {output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("coverage percentage must be a number from 0 through 100")
        );
    }
}
