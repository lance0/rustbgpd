//! One exit-code namespace for every subcommand: the `Exit` enum is the only
//! source of numbers, every error type maps into it, and the README table
//! (plus its `docs/how-to/deployment.md` mirror) must list exactly those codes.

use std::collections::BTreeSet;

use rs_config_render::{
    Exit, RenderError, activation, ixp_manager, ixp_manager_lifecycle, prune, recover,
};

const PRUNE_HEADING: &str = "#### Bound retained activation generations";
const PRUNE_END_HEADING: &str = "#### rs-config-render exit codes";
const RETENTION_HEADER: &str = "| Retention reason | Protected generation |";
const RETENTION_SEPARATOR: &str = "|---|---|";
const CURRENT_RETENTION_REASONS: [&str; 5] =
    ["current", "receipt", "predecessor", "journal", "keep-N"];

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

fn bounded_prune_section(markdown: &str) -> Result<&str, String> {
    let starts: Vec<usize> = markdown
        .match_indices(PRUNE_HEADING)
        .map(|(offset, _)| offset)
        .collect();
    if starts.len() != 1 {
        return Err(format!(
            "expected exactly one {PRUNE_HEADING:?} heading, found {}",
            starts.len()
        ));
    }
    let content_start = starts[0] + PRUNE_HEADING.len();
    let tail = &markdown[content_start..];
    let ends: Vec<usize> = tail
        .match_indices(PRUNE_END_HEADING)
        .map(|(offset, _)| offset)
        .collect();
    if ends.len() != 1 {
        return Err(format!(
            "expected exactly one following {PRUNE_END_HEADING:?} heading, found {}",
            ends.len()
        ));
    }
    Ok(&tail[..ends[0]])
}

fn documented_retention_reasons(section: &str) -> Result<BTreeSet<String>, String> {
    let lines: Vec<&str> = section.lines().collect();
    let headers: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| (line.trim() == RETENTION_HEADER).then_some(index))
        .collect();
    if headers.len() != 1 {
        return Err(format!(
            "expected exactly one retention table, found {}",
            headers.len()
        ));
    }
    let header = headers[0];
    if lines.get(header + 1).map(|line| line.trim()) != Some(RETENTION_SEPARATOR) {
        return Err("retention table separator drifted".to_owned());
    }

    let mut reasons = BTreeSet::new();
    for row in lines[header + 2..]
        .iter()
        .map(|line| line.trim())
        .take_while(|line| line.starts_with('|'))
    {
        let cells: Vec<&str> = row.trim_matches('|').split('|').map(str::trim).collect();
        if cells.len() != 2 || cells[1].is_empty() {
            return Err(format!("malformed retention row: {row}"));
        }
        let reason = cells[0]
            .strip_prefix('`')
            .and_then(|value| value.strip_suffix('`'))
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("retention reason must be one code literal: {row}"))?;
        if !reasons.insert(reason.to_owned()) {
            return Err(format!("duplicate retention reason {reason:?}"));
        }
    }
    if reasons.is_empty() {
        return Err("retention table has no rows".to_owned());
    }
    Ok(reasons)
}

fn production_retention_reasons() -> Result<BTreeSet<String>, String> {
    let source = include_str!("../src/prune.rs");
    let function = source
        .split_once("pub fn prune(")
        .map(|(_, body)| body)
        .ok_or_else(|| "production prune function is missing".to_owned())?;
    let retention_phase = function
        .split_once("let mut plan = Plan::default();")
        .map(|(phase, _)| phase)
        .ok_or_else(|| "production prune retention phase is missing".to_owned())?;

    let mut reasons = BTreeSet::new();
    let mut remainder = retention_phase;
    let mut calls = 0;
    while let Some(offset) = remainder.find("retain(") {
        remainder = &remainder[offset + "retain(".len()..];
        let (arguments, tail) = remainder
            .split_once(");")
            .ok_or_else(|| "unterminated production retain call".to_owned())?;
        let reason_expression = arguments
            .rsplit_once(',')
            .map(|(_, expression)| expression.trim())
            .ok_or_else(|| format!("production retain call has no reason: {arguments}"))?;
        let reason = reason_expression
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .filter(|value| {
                !value.is_empty()
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            })
            .ok_or_else(|| {
                format!("production retention reason is not one bounded literal: {arguments}")
            })?;
        reasons.insert(reason.to_owned());
        calls += 1;
        remainder = tail;
    }
    if calls == 0 {
        return Err("production prune has no retain calls".to_owned());
    }
    Ok(reasons)
}

fn normalize_whitespace(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn check_deployment_prune_contract(deployment: &str) -> Result<(), String> {
    let deployment = deployment.replace("\r\n", "\n");
    let section = bounded_prune_section(&deployment)?;
    let production = production_retention_reasons()?;
    let expected: BTreeSet<String> = CURRENT_RETENTION_REASONS
        .iter()
        .map(|reason| (*reason).to_owned())
        .collect();
    if production != expected {
        return Err(format!(
            "production retention roster changed: expected {expected:?}, found {production:?}"
        ));
    }
    let documented = documented_retention_reasons(section)?;
    if documented != production {
        return Err(format!(
            "deployment retention roster differs from production: documented {documented:?}, production {production:?}"
        ));
    }

    let prune_source = include_str!("../src/prune.rs");
    let main_source = include_str!("../src/main.rs");
    let host_lock = prune_source
        .find("let _host_lock = ixp_manager_host::host_lock(")
        .ok_or_else(|| "production host-lock seam is missing".to_owned())?;
    let fence = prune_source
        .find("ixp_manager_host::fence_present(")
        .ok_or_else(|| "production host-fence seam is missing".to_owned())?;
    if host_lock >= fence {
        return Err("production host lock no longer precedes its fence check".to_owned());
    }
    if !prune_source.contains("if options.apply {")
        || !main_source.contains("dry run unless --apply")
    {
        return Err("production dry-run/apply seam changed".to_owned());
    }
    if !prune_source.contains("Generations are content-addressed and immutable;")
        || !prune_source.contains("activation path never")
    {
        return Err("production immutable-generation seam changed".to_owned());
    }

    let refusal = prune::Error::Refused("documentation contract").exit_code();
    if refusal != Exit::Refused || refusal.code() != 2 {
        return Err(format!(
            "prune refusal no longer maps to typed exit 2: {refusal:?}"
        ));
    }
    let normalized = normalize_whitespace(section);
    let required = [
        "Every distinct activation leaves an immutable generation under `<state-dir>/generations/`; activation and lifecycle commands never remove one.".to_owned(),
        "Run `rs-config-render prune --keep N` separately. It reports a dry-run plan unless `--apply` is present.".to_owned(),
        format!(
            "Pruning refuses with exit {} while a host fence or competing host command exists",
            refusal.code()
        ),
        "The host lock remains held through removal, so recovery state cannot appear between planning and deletion.".to_owned(),
        "The [tool README's pruning section](../../tools/rs-config-render/README.md#pruning-retained-generations) is authoritative for the complete command, stable output, and cron-safe pattern.".to_owned(),
    ];
    for clause in required {
        if !normalized.contains(&clause) {
            return Err(format!("deployment prune section is missing: {clause}"));
        }
    }
    Ok(())
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
    let deployment = std::fs::read_to_string(root.join("../../docs/how-to/deployment.md")).unwrap();
    let rows = table_rows(&readme);
    assert_eq!(
        rows,
        table_rows(&deployment),
        "docs/how-to/deployment.md exit-code table must mirror the README byte for byte"
    );
    let documented: Vec<u8> = rows.iter().map(|r| row_code(r)).collect();
    let defined: Vec<u8> = Exit::ALL.iter().map(|e| e.code()).collect();
    assert_eq!(
        documented, defined,
        "README exit-code table drifted from `Exit`"
    );
}

#[test]
fn deployment_prune_section_matches_source_contract() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let deployment = std::fs::read_to_string(root.join("../../docs/how-to/deployment.md")).unwrap();
    check_deployment_prune_contract(&deployment).unwrap();
}

#[test]
fn deployment_prune_contract_rejects_roster_mutations() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let deployment = std::fs::read_to_string(root.join("../../docs/how-to/deployment.md")).unwrap();
    let row = "| `current` | The current symlink target |";
    let mutations = [
        ("missing", deployment.replacen(&format!("{row}\n"), "", 1)),
        (
            "duplicate",
            deployment.replacen(row, &format!("{row}\n{row}"), 1),
        ),
        (
            "renamed",
            deployment.replacen("| `current` |", "| `active` |", 1),
        ),
        (
            "moved",
            format!(
                "{}\n{row}\n",
                deployment.replacen(&format!("{row}\n"), "", 1)
            ),
        ),
    ];
    for (name, mutation) in mutations {
        assert!(
            check_deployment_prune_contract(&mutation).is_err(),
            "{name} retention-row mutation escaped the contract"
        );
    }
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
        (recover::Error::ManualRecovery(""), Exit::ManualRecovery),
    ];
    for (error, exit) in &recovery {
        match error {
            recover::Error::Unreadable(_)
            | recover::Error::Refused(_)
            | recover::Error::ManualRecovery(_) => {}
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
