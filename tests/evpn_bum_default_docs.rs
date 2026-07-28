use std::path::Path;
use std::process::Command;

fn excluded(path: &str) -> bool {
    path == "CHANGELOG.md"
        || path.starts_with("docs/adr/")
        || path.starts_with("docs/soaks/")
        || path.starts_with("docs/perf/")
        || path.starts_with("docs/artifacts/")
        || path.starts_with("scripts/fixtures/release-notes/")
        || (path.starts_with("tests/interop/") && path.ends_with("-receipt.md"))
}

fn normalized(block: &str) -> String {
    block
        .chars()
        .map(|ch| {
            if ch.is_alphanumeric() || ch == '_' {
                ch.to_ascii_lowercase()
            } else {
                ' '
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn stale_class(block: &str) -> Option<&'static str> {
    let concerns_bum = block.contains("apply_bum_enforcement")
        || (block.contains("bum") && block.contains("enforcement"));
    if !concerns_bum {
        return None;
    }
    [
        (
            "apply_bum_enforcement_default_false",
            block.contains("apply_bum_enforcement") && block.contains("default false"),
        ),
        (
            "end_to_end_wired_opt_in_by_config",
            block.contains("end to end wired opt in by config"),
        ),
        (
            "operator_facing_opt_in",
            block.contains("operator facing opt in"),
        ),
        (
            "opt_in_kernel_bum_port_enforcement",
            block.contains("opt in kernel bum port enforcement"),
        ),
        (
            "production_default_awaits_soak",
            block.contains("production default enforcement awaits") && block.contains("soak"),
        ),
        (
            "remaining_soak_question",
            block.contains("remaining soak question"),
        ),
    ]
    .into_iter()
    .find_map(|(class, stale)| stale.then_some(class))
}

#[test]
fn evpn_bum_default_docs_exclude_stale_posture_claims() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let output = Command::new("git")
        .args(["-C", root.to_str().unwrap(), "ls-files", "-z", "--", "*.md"])
        .output()
        .expect("git must enumerate tracked Markdown");
    assert!(output.status.success(), "git ls-files failed");

    let mut stale = Vec::new();
    for bytes in output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|p| !p.is_empty())
    {
        let path = std::str::from_utf8(bytes).expect("tracked path is UTF-8");
        if excluded(path) {
            continue;
        }
        let text = std::fs::read_to_string(root.join(path)).expect("tracked Markdown is readable");
        for block in text.split("\n\n").map(normalized) {
            if let Some(class) = stale_class(&block) {
                stale.push(format!("{path}: {class}"));
            }
        }
    }
    assert!(
        stale.is_empty(),
        "stale EVPN BUM posture claims:\n{}",
        stale.join("\n")
    );
}
