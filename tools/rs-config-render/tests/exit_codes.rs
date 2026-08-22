//! One exit-code namespace for every subcommand: the `Exit` enum is the only
//! source of numbers, every error type maps into it, and the README table
//! (plus its `docs/deployment.md` mirror) must list exactly those codes.

use rs_config_render::{
    Exit, RenderError, activation, ixp_manager, ixp_manager_lifecycle, prune, recover,
};

fn table_rows(markdown: &str) -> Vec<String> {
    let mut lines = markdown.lines();
    let mut tables = Vec::new();
    while let Some(line) = lines.next() {
        if line.trim() != "| Exit | Meaning |" {
            continue;
        }
        assert_eq!(lines.next().map(str::trim), Some("|---|---|"));
        let rows: Vec<String> = lines
            .by_ref()
            .take_while(|l| l.starts_with('|'))
            .map(str::to_owned)
            .collect();
        tables.push(rows);
    }
    assert_eq!(
        tables.len(),
        1,
        "expected exactly one `| Exit | Meaning |` table"
    );
    tables.pop().unwrap()
}

fn row_code(row: &str) -> u8 {
    row.trim_start_matches('|')
        .split('|')
        .next()
        .unwrap()
        .trim()
        .parse()
        .unwrap_or_else(|_| panic!("exit-code row without a numeric first column: {row}"))
}

/// Every `Exit` variant, enumerated independently of `Exit::ALL`: a chain
/// whose arms name each variant literally. Adding a variant makes the `match`
/// non-exhaustive until an arm exists, and the linked arm puts it in the chain;
/// exactly one arm (the last variant) ends the chain.
fn witnessed() -> Vec<Exit> {
    let mut chain = Vec::new();
    let mut next = Some(Exit::Success);
    while let Some(exit) = next {
        chain.push(exit);
        next = match exit {
            Exit::Success => Some(Exit::InvalidInput),
            Exit::InvalidInput => Some(Exit::Refused),
            Exit::Refused => Some(Exit::Implausible),
            Exit::Implausible => Some(Exit::ShapeDrift),
            Exit::ShapeDrift => Some(Exit::ManualRecovery),
            Exit::ManualRecovery => Some(Exit::CallbackPending),
            Exit::CallbackPending => Some(Exit::RolledBack),
            Exit::RolledBack => Some(Exit::OutputUnusable),
            Exit::OutputUnusable => Some(Exit::StrictCheckFailed),
            Exit::StrictCheckFailed => None,
        };
    }
    chain
}

#[test]
fn every_exit_code_is_unique_and_enumerated() {
    assert_eq!(
        witnessed(),
        Exit::ALL.to_vec(),
        "`Exit::ALL` must list every variant"
    );
    let codes: Vec<u8> = Exit::ALL.iter().map(|e| e.code()).collect();
    assert_eq!(
        codes
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        codes.len(),
        "duplicate exit code"
    );
    assert_eq!(codes, (0..=9).collect::<Vec<u8>>());
    assert_eq!(
        std::process::ExitCode::from(Exit::RolledBack),
        std::process::ExitCode::from(7)
    );
}

#[test]
fn readme_table_and_deployment_mirror_list_exactly_the_enum() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let readme = std::fs::read_to_string(root.join("README.md")).unwrap();
    let deployment = std::fs::read_to_string(root.join("../../docs/deployment.md")).unwrap();
    let rows = table_rows(&readme);
    assert_eq!(
        rows,
        table_rows(&deployment),
        "docs/deployment.md exit-code table must mirror the README byte for byte"
    );
    let documented: Vec<u8> = rows.iter().map(|r| row_code(r)).collect();
    let defined: Vec<u8> = Exit::ALL.iter().map(|e| e.code()).collect();
    assert_eq!(
        documented, defined,
        "README exit-code table drifted from `Exit`"
    );
}

#[test]
fn every_error_variant_maps_to_the_shared_table() {
    // Each list is exhaustive for its enum; a new variant must be added here
    // (the `match` in each closure makes omission a compile error).
    let render = [
        (RenderError::Parse(String::new()), Exit::InvalidInput),
        (RenderError::Refused(Vec::new()), Exit::Refused),
        (RenderError::Implausible(Vec::new()), Exit::Implausible),
        (
            RenderError::ShapeMismatch {
                expected_fingerprint: String::new(),
                found_fingerprint: String::new(),
                missing: Vec::new(),
                unexpected: Vec::new(),
            },
            Exit::ShapeDrift,
        ),
    ];
    for (error, exit) in &render {
        match error {
            RenderError::Parse(_)
            | RenderError::Refused(_)
            | RenderError::Implausible(_)
            | RenderError::ShapeMismatch { .. } => {}
        }
        assert_eq!(error.exit_code(), *exit, "{error:?}");
    }

    let candidate = [
        (ixp_manager::Error::Input, Exit::InvalidInput),
        (ixp_manager::Error::Refused(""), Exit::Refused),
        (ixp_manager::Error::Output, Exit::OutputUnusable),
        (ixp_manager::Error::CheckerUnavailable, Exit::Refused),
        (ixp_manager::Error::Checker, Exit::StrictCheckFailed),
    ];
    for (error, exit) in &candidate {
        match error {
            ixp_manager::Error::Input
            | ixp_manager::Error::Refused(_)
            | ixp_manager::Error::Output
            | ixp_manager::Error::CheckerUnavailable
            | ixp_manager::Error::Checker => {}
        }
        assert_eq!(error.exit_code(), *exit, "{error:?}");
    }

    let activate = [
        (activation::Error::Refused(""), Exit::Refused),
        (activation::Error::RolledBack, Exit::RolledBack),
        (activation::Error::RecoveryRequired, Exit::ManualRecovery),
    ];
    for (error, exit) in &activate {
        match error {
            activation::Error::Refused(_)
            | activation::Error::RolledBack
            | activation::Error::RecoveryRequired => {}
        }
        assert_eq!(error.exit_code(), *exit, "{error:?}");
    }

    let pruning = [(prune::Error::Refused(""), Exit::Refused)];
    for (error, exit) in &pruning {
        match error {
            prune::Error::Refused(_) => {}
        }
        assert_eq!(error.exit_code(), *exit, "{error:?}");
    }

    let recovery = [
        (recover::Error::Unreadable(""), Exit::InvalidInput),
        (recover::Error::Refused(""), Exit::Refused),
    ];
    for (error, exit) in &recovery {
        match error {
            recover::Error::Unreadable(_) | recover::Error::Refused(_) => {}
        }
        assert_eq!(error.exit_code(), *exit, "{error:?}");
    }

    let lifecycle = [
        (ixp_manager_lifecycle::Error::Refused(""), Exit::Refused),
        (ixp_manager_lifecycle::Error::RolledBack, Exit::RolledBack),
        (
            ixp_manager_lifecycle::Error::ManualRecovery,
            Exit::ManualRecovery,
        ),
        (
            ixp_manager_lifecycle::Error::CallbackPending,
            Exit::CallbackPending,
        ),
    ];
    for (error, exit) in &lifecycle {
        match error {
            ixp_manager_lifecycle::Error::Refused(_)
            | ixp_manager_lifecycle::Error::RolledBack
            | ixp_manager_lifecycle::Error::ManualRecovery
            | ixp_manager_lifecycle::Error::CallbackPending => {}
        }
        assert_eq!(error.exit_code(), *exit, "{error:?}");
    }
}
