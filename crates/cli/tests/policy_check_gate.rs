//! `rbgp policy check` as a CI and editor gate: each exit code, the
//! pinned `rbgp-policy-check/1.0` JSON document, located findings across
//! imported files, and the opt-in empty-suite failure.

use std::path::Path;
use std::process::{Command, Output};

use serde_json::{Value, json};

fn run(path: &Path, args: &[&str]) -> Output {
    let address = format!("unix://{}/absent.sock", path.parent().unwrap().display());
    Command::new(env!("CARGO_BIN_EXE_rbgp"))
        .args(["--addr", &address, "--no-color", "policy", "check"])
        .arg(path)
        .args(args)
        .output()
        .expect("run offline policy check")
}

fn json_of(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| panic!("{error}: {output:?}"))
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// The probe file of the original report: a catch-all term shadows the
/// next one, and the file has no tests.
const UNREACHABLE: &str = "policy p {\n    term a { accept }\n    term b { reject }\n}\n";

#[test]
fn every_exit_code_and_its_precedence() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policy.rpol");
    let tested = "policy p { term a { accept } term b { reject } }
                  test t { route { med 0 } expect p == accept }";
    let failing = "policy p { term a { accept } term b { reject } }
                   test t { route { med 0 } expect p == reject }";
    for (source, args, expected) in [
        // Lints are warnings unless denied: the exit code is unchanged.
        (UNREACHABLE, &[][..], 0),
        (UNREACHABLE, &["-j"][..], 0),
        (UNREACHABLE, &["--deny-lints=unused-set,unused-fn"][..], 0),
        (UNREACHABLE, &["--deny-lints=unreachable-term"][..], 4),
        (UNREACHABLE, &["--deny-lints"][..], 4),
        (UNREACHABLE, &["--deny-lints", "-j"][..], 4),
        (UNREACHABLE, &["--fail-on-empty"][..], 2),
        (tested, &["--fail-on-empty"][..], 0),
        // 1 wins over every gate.
        (
            "policy p { term t { if route.prefx == 1 { accept } } }",
            &["--deny-lints", "--fail-on-empty", "--coverage-min", "100"][..],
            1,
        ),
        // 2 wins over 3 and 4.
        (failing, &["--deny-lints", "--coverage-min", "100"][..], 2),
        (
            UNREACHABLE,
            &["--deny-lints", "--fail-on-empty", "--coverage-min", "100"][..],
            2,
        ),
        // 3 wins over 4.
        (tested, &["--deny-lints", "--coverage-min", "100"][..], 3),
        (tested, &["--deny-lints=unreachable-term"][..], 4),
    ] {
        std::fs::write(&path, source).unwrap();
        let output = run(&path, args);
        assert_eq!(
            output.status.code(),
            Some(expected),
            "{source} {args:?}: {output:?}"
        );
    }

    std::fs::write(&path, UNREACHABLE).unwrap();
    let denied = run(&path, &["--deny-lints=unreachable-term"]);
    let text = stderr(&denied);
    let canonical = std::fs::canonicalize(&path).unwrap();
    assert!(
        text.contains(&format!(
            "{}:3:10: error[unreachable-term]: term b in policy p is unreachable",
            canonical.display()
        )),
        "{text}"
    );
    assert!(text.contains("1 lint denied by --deny-lints"), "{text}");
    assert!(!text.contains("unreferenced-policy"), "{text}");
    let unknown = run(&path, &["--deny-lints=unreachable"]);
    assert_eq!(unknown.status.code(), Some(64), "{unknown:?}");
    assert!(unknown.stdout.is_empty());
    assert!(stderr(&unknown).contains("possible values: unused-set"));
}

#[test]
fn json_document_shape_is_pinned() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policy.rpol");
    let given = path.to_str().unwrap();

    std::fs::write(&path, UNREACHABLE).unwrap();
    let canonical = std::fs::canonicalize(&path).unwrap();
    let canonical = canonical.to_str().unwrap();
    let output = run(&path, &["-j", "--deny-lints=unreachable-term"]);
    assert_eq!(output.status.code(), Some(4), "{output:?}");
    assert_eq!(
        json_of(&output),
        json!({
            "format": "rbgp-policy-check",
            "format_version": "1.0",
            "file": given,
            "ok": true,
            "diagnostics": [],
            "findings": [
                {
                    "severity": "error",
                    "code": "unreachable-term",
                    "message": "term b in policy p is unreachable (term a always decides)",
                    "file": canonical,
                    "line": 3, "column": 10, "end_line": 3, "end_column": 11,
                    "label": null, "notes": [], "related": []
                },
                {
                    "severity": "warning",
                    "code": "unreferenced-policy",
                    "message": "policy p is not referenced by any test or apply in these files \
                                (daemon config chain references are not visible to this check)",
                    "file": canonical,
                    "line": 1, "column": 8, "end_line": 1, "end_column": 9,
                    "label": null, "notes": [], "related": []
                }
            ],
            "tests_total": 0,
            "tests_passed": 0,
            "failures": []
        })
    );

    std::fs::write(
        &path,
        "policy p {\n  term t { if route.prefx == 10.0.0.0/8 { accept } }\n}\n",
    )
    .unwrap();
    let output = run(&path, &["-j"]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(
        json_of(&output),
        json!({
            "format": "rbgp-policy-check",
            "format_version": "1.0",
            "file": given,
            "ok": false,
            "diagnostics": ["unknown field `route.prefx`"],
            "findings": [{
                "severity": "error",
                "code": "compile-error",
                "message": "unknown field `route.prefx`",
                "file": canonical,
                "line": 2, "column": 21, "end_line": 2, "end_column": 26,
                "label": "`route` has no field `prefx`",
                "notes": ["did you mean `route.prefix`?"],
                "related": []
            }],
            "tests_total": 0,
            "tests_passed": 0,
            "failures": []
        })
    );
}

/// Resolve a finding's `line`/`column`..`end_line`/`end_column` back to
/// the text it names, from the file the finding itself names.
fn located_text(finding: &Value) -> String {
    let text = std::fs::read_to_string(finding["file"].as_str().unwrap()).unwrap();
    let index = |line: &Value, column: &Value| -> usize {
        let line = usize::try_from(line.as_u64().unwrap()).unwrap();
        let column = usize::try_from(column.as_u64().unwrap()).unwrap();
        let start: usize = text
            .split_inclusive('\n')
            .take(line - 1)
            .map(str::len)
            .sum();
        let line_text = &text[start..];
        start
            + line_text
                .char_indices()
                .nth(column - 1)
                .map_or(line_text.len(), |(offset, _)| offset)
    };
    text[index(&finding["line"], &finding["column"])
        ..index(&finding["end_line"], &finding["end_column"])]
        .to_string()
}

#[test]
fn findings_locate_definitions_across_imported_files() {
    let directory = tempfile::tempdir().unwrap();
    let main = directory.path().join("main.rpol");
    let library = directory.path().join("library.rpol");
    std::fs::write(
        &library,
        "# Shared definitions.\n\
         prefix-set dead-set { 192.0.2.0/24 }\n\
         \n\
         policy shared {\n\
         \x20   term catch-all { accept }\n\
         \x20   term shadowed { reject }\n\
         }\n",
    )
    .unwrap();
    std::fs::write(
        &main,
        "import \"library.rpol\"\n\
         \n\
         fn dead-fn(x: u32) -> u32 { x }\n\
         policy edge { term t { if apply(shared) { accept } } }\n\
         test t { route { med 0 } expect edge == accept }\n",
    )
    .unwrap();
    let output = run(&main, &["-j"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let json = json_of(&output);
    let located: Vec<(String, String, u64, u64, String)> = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|finding| {
            let file = finding["file"].as_str().unwrap();
            (
                finding["code"].as_str().unwrap().to_string(),
                Path::new(file)
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
                finding["line"].as_u64().unwrap(),
                finding["column"].as_u64().unwrap(),
                located_text(finding),
            )
        })
        .collect();
    let row = |code: &str, file: &str, line, column, text: &str| {
        (
            code.to_string(),
            file.to_string(),
            line,
            column,
            text.to_string(),
        )
    };
    assert_eq!(
        located,
        [
            row("unused-set", "library.rpol", 2, 12, "dead-set"),
            row("unused-fn", "main.rpol", 3, 4, "dead-fn"),
            row("unreachable-term", "library.rpol", 6, 10, "shadowed"),
        ]
    );
    for finding in json["findings"].as_array().unwrap() {
        assert_eq!(finding["severity"], "warning");
    }

    // A compile error inside the imported file is located there too.
    std::fs::write(
        &library,
        "policy shared {\n    term t { if route.prefx == 1 { accept } }\n}\n",
    )
    .unwrap();
    let output = run(&main, &["-j"]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let json = json_of(&output);
    let finding = &json["findings"][0];
    assert_eq!(finding["code"], "compile-error");
    assert!(
        finding["file"].as_str().unwrap().ends_with("library.rpol"),
        "{finding}"
    );
    assert_eq!(
        (&finding["line"], &finding["column"]),
        (&json!(2), &json!(23))
    );
    assert_eq!(located_text(finding), "prefx");
}

#[test]
fn empty_suite_fails_only_under_fail_on_empty() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policy.rpol");
    std::fs::write(&path, "policy p { term t { accept } }").unwrap();

    let plain = run(&path, &[]);
    assert_eq!(plain.status.code(), Some(0), "{plain:?}");
    assert!(String::from_utf8_lossy(&plain.stdout).contains("ok (no tests)"));

    let gated = run(&path, &["--fail-on-empty"]);
    assert_eq!(gated.status.code(), Some(2), "{gated:?}");
    assert!(gated.stdout.is_empty(), "{gated:?}");
    assert!(stderr(&gated).contains("no tests (--fail-on-empty)"));

    let gated_json = run(&path, &["--fail-on-empty", "-j"]);
    assert_eq!(gated_json.status.code(), Some(2), "{gated_json:?}");
    let json = json_of(&gated_json);
    assert_eq!(json["ok"], false);
    assert_eq!(json["tests_total"], 0);
    assert_eq!(json_of(&run(&path, &["-j"]))["ok"], true);

    // Tests reached through an import count toward the suite.
    let main = directory.path().join("main.rpol");
    std::fs::write(
        &path,
        "policy p { term t { accept } }\ntest t { route { med 0 } expect p == accept }",
    )
    .unwrap();
    std::fs::write(&main, "import \"policy.rpol\"\n").unwrap();
    let imported = run(&main, &["--fail-on-empty"]);
    assert_eq!(imported.status.code(), Some(0), "{imported:?}");
}
