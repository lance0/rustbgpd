use std::process::Command;

fn run_help(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_rs-config-render"))
        .args(args)
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn cli_help_names_operational_modes_and_truthful_paths() {
    let help = run_help(&["--help"]);
    for path in [
        "rs-config-render --context <CONTEXT> --out-dir <OUT_DIR>",
        "rs-config-render activate --help",
        "rs-config-render status --help",
        "rs-config-render prune --help",
        "rs-config-render recover keep-current --help",
        "rs-config-render recover rollback --help",
        "rs-config-render recover release-lock --help",
        "rs-config-render recover clear --help",
        "rs-config-render ixp-manager-lifecycle run --help",
        "rs-config-render ixp-manager-lifecycle resume --help",
    ] {
        assert!(help.contains(path), "missing {path}: {help}");
    }

    for (args, usage) in [
        (
            &["activate", "--help"][..],
            "Usage: rs-config-render activate",
        ),
        (&["status", "--help"][..], "Usage: rs-config-render status"),
        (&["prune", "--help"][..], "Usage: rs-config-render prune"),
        (
            &["recover", "keep-current", "--help"][..],
            "Usage: rs-config-render recover keep-current",
        ),
        (
            &["recover", "rollback", "--help"][..],
            "Usage: rs-config-render recover rollback",
        ),
        (
            &["recover", "release-lock", "--help"][..],
            "Usage: rs-config-render recover release-lock",
        ),
        (
            &["recover", "clear", "--help"][..],
            "Usage: rs-config-render recover clear",
        ),
        (
            &["ixp-manager-lifecycle", "run", "--help"][..],
            "Usage: rs-config-render ixp-manager-lifecycle run",
        ),
        (
            &["ixp-manager-lifecycle", "resume", "--help"][..],
            "Usage: rs-config-render ixp-manager-lifecycle resume",
        ),
    ] {
        let help = run_help(args);
        assert!(help.contains(usage), "missing {usage}: {help}");
    }
}
