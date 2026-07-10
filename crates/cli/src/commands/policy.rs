//! `rbgp policy ...` — wraps PolicyService gRPCs.
//!
//! - `list` / `get NAME` / `set NAME --from-file FILE` / `delete NAME`
//!   for named `[[policy_definitions]]` entries.
//! - `chain show [--neighbor ADDR]` for global or per-neighbor chains.
//! - `chain set-import [--neighbor ADDR] POL...` /
//!   `chain set-export [--neighbor ADDR] POL...` to install (or
//!   replace) a chain. Omitting `--neighbor` applies the change to
//!   the global chain.
//! - `chain clear-import [--neighbor ADDR]` /
//!   `chain clear-export [--neighbor ADDR]` to drop the resolved
//!   chain entirely. Omitting `--neighbor` clears the global chain.

use serde::Serialize;

use crate::commands::policy_input::{JsonPolicyDefinition, load_json};
use crate::connection::Connection;
use crate::error::CliError;
use crate::output;
use crate::proto::policy_service_client::PolicyServiceClient;
use crate::proto::{
    self, ClearGlobalExportChainRequest, ClearGlobalImportChainRequest,
    ClearNeighborExportChainRequest, ClearNeighborImportChainRequest, DeletePolicyRequest,
    ExplainImportPolicyRequest, GetGlobalPolicyChainsRequest, GetNeighborPolicyChainsRequest,
    GetPolicyRequest, GetPolicyStatsRequest, ListPoliciesRequest, SetGlobalExportChainRequest,
    SetGlobalImportChainRequest, SetNeighborExportChainRequest, SetNeighborImportChainRequest,
    SetPolicyRequest,
};

#[derive(Debug, Serialize)]
struct JsonPolicySummary {
    name: String,
    default_action: String,
    statement_count: usize,
}

#[derive(Debug, Serialize)]
struct JsonPolicyDetail {
    name: String,
    default_action: String,
    statements: Vec<JsonPolicyStatementOut>,
}

#[derive(Debug, Default, Serialize)]
struct JsonPolicyStatementOut {
    action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ge: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    le: Option<u32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    match_community: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    match_as_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    match_as_path_length_ge: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    match_as_path_length_le: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    match_rpki_validation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    match_aspa_validation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    match_neighbor_set: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    match_route_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    match_evpn_route_type: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    match_local_pref_ge: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    match_local_pref_le: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    match_med_ge: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    match_med_le: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    match_next_hop: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    set_local_pref: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    set_med: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    set_next_hop: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    set_community_add: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    set_community_remove: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    set_as_path_prepend: Option<JsonAsPathPrependOut>,
}

#[derive(Debug, Serialize)]
struct JsonAsPathPrependOut {
    asn: u32,
    count: u32,
}

impl From<proto::PolicyStatement> for JsonPolicyStatementOut {
    fn from(s: proto::PolicyStatement) -> Self {
        JsonPolicyStatementOut {
            action: s.action,
            prefix: s.prefix,
            ge: s.ge,
            le: s.le,
            match_community: s.match_community,
            match_as_path: s.match_as_path,
            match_as_path_length_ge: s.match_as_path_length_ge,
            match_as_path_length_le: s.match_as_path_length_le,
            match_rpki_validation: s.match_rpki_validation,
            match_aspa_validation: s.match_aspa_validation,
            match_neighbor_set: s.match_neighbor_set,
            match_route_type: s.match_route_type,
            match_evpn_route_type: s.match_evpn_route_type,
            match_local_pref_ge: s.match_local_pref_ge,
            match_local_pref_le: s.match_local_pref_le,
            match_med_ge: s.match_med_ge,
            match_med_le: s.match_med_le,
            match_next_hop: s.match_next_hop,
            set_local_pref: s.set_local_pref,
            set_med: s.set_med,
            set_next_hop: s.set_next_hop,
            set_community_add: s.set_community_add,
            set_community_remove: s.set_community_remove,
            set_as_path_prepend: s.set_as_path_prepend.map(|p| JsonAsPathPrependOut {
                asn: p.asn,
                count: p.count,
            }),
        }
    }
}

#[derive(Debug, Serialize)]
struct JsonChains {
    #[serde(skip_serializing_if = "Option::is_none")]
    neighbor: Option<String>,
    import_policy_names: Vec<String>,
    export_policy_names: Vec<String>,
}

/// `rbgp policy check <file.rpol>` — run the `.rpol` frontend
/// in-process (import resolution, parse, typecheck, in-language
/// tests); no daemon. `roots` are extra `import` resolution roots
/// (the file's own directory is always one); `list_deps` prints the
/// resolved import graph + content hashes instead of running tests.
///
/// Returns the process exit code: 0 clean, 1 diagnostics (or an
/// unreadable file), 2 test failures. Diagnostics render to stderr,
/// results to stdout.
pub fn check_local(path: &str, roots: &[String], list_deps: bool, json: bool) -> i32 {
    use std::io::IsTerminal;
    use std::path::PathBuf;

    use rustbgpd_policy::rpol::{LoadError, RpolFile};

    let root_paths: Vec<PathBuf> = roots.iter().map(PathBuf::from).collect();
    let (file, diagnostics) = match RpolFile::load(std::path::Path::new(path), &root_paths) {
        Ok(file) => (Some(file), Vec::new()),
        Err(LoadError::Io { path, reason }) => {
            eprintln!("Error: cannot read {path}: {reason}");
            return 1;
        }
        Err(error @ LoadError::Compile { .. }) => {
            if !json {
                let color = std::io::stderr().is_terminal();
                eprint!("{}", error.render(color));
            }
            let messages = error
                .diagnostics()
                .map(|diags| diags.0.iter().map(|d| d.message.clone()).collect())
                .unwrap_or_default();
            (None, messages)
        }
    };

    // --list-deps on a broken graph falls through to the compile
    // diagnostics below (exit 1).
    if list_deps && let Some(file) = &file {
        return print_deps(path, file, json);
    }
    let tests = file.as_ref().map(RpolFile::run_tests);

    if json {
        #[derive(Serialize)]
        struct JsonFailure<'a> {
            name: &'a str,
            message: &'a str,
        }
        #[derive(Serialize)]
        struct JsonCheck<'a> {
            file: &'a str,
            ok: bool,
            diagnostics: &'a [String],
            tests_total: usize,
            tests_passed: usize,
            failures: Vec<JsonFailure<'a>>,
        }
        let out = JsonCheck {
            file: path,
            ok: diagnostics.is_empty()
                && tests
                    .as_ref()
                    .is_none_or(rustbgpd_policy::rpol::TestReport::all_passed),
            diagnostics: &diagnostics,
            tests_total: tests.as_ref().map_or(0, |t| t.total),
            tests_passed: tests
                .as_ref()
                .map_or(0, rustbgpd_policy::rpol::TestReport::passed),
            failures: tests.as_ref().map_or_else(Vec::new, |t| {
                t.failures
                    .iter()
                    .map(|f| JsonFailure {
                        name: &f.name,
                        message: &f.message,
                    })
                    .collect()
            }),
        };
        if output::print_json_pretty(&out).is_err() {
            return 1;
        }
    } else if !diagnostics.is_empty() {
        // Rendered excerpts already went to stderr above.
        eprintln!(
            "{path}: {} error{}",
            diagnostics.len(),
            if diagnostics.len() == 1 { "" } else { "s" }
        );
    } else if let Some(tests) = &tests {
        if tests.total == 0 {
            println!("{path}: ok (no tests)");
        } else {
            for failure in &tests.failures {
                eprintln!("test {} ... FAILED: {}", failure.name, failure.message);
            }
            println!(
                "{path}: {} passed, {} failed",
                tests.passed(),
                tests.failures.len()
            );
        }
    }

    if !diagnostics.is_empty() {
        1
    } else if tests.as_ref().is_some_and(|tests| !tests.all_passed()) {
        2
    } else {
        0
    }
}

/// `rbgp policy check --list-deps` output: the resolved module graph
/// with content hashes, module 0 first (the main file), imports in
/// declaration order. Always exit 0 — the graph compiled.
fn print_deps(path: &str, file: &rustbgpd_policy::rpol::RpolFile, json: bool) -> i32 {
    let modules = file.modules();
    if json {
        #[derive(Serialize)]
        struct JsonDep<'a> {
            path: &'a str,
            sha256: &'a str,
            imports: Vec<&'a str>,
        }
        #[derive(Serialize)]
        struct JsonDeps<'a> {
            file: &'a str,
            modules: Vec<JsonDep<'a>>,
        }
        let out = JsonDeps {
            file: path,
            modules: modules
                .iter()
                .map(|m| JsonDep {
                    path: &m.path,
                    sha256: &m.digest,
                    imports: m
                        .imports
                        .iter()
                        .map(|&id| modules[id as usize].path.as_str())
                        .collect(),
                })
                .collect(),
        };
        if output::print_json_pretty(&out).is_err() {
            return 1;
        }
        return 0;
    }
    println!(
        "{path}: {} module{}",
        modules.len(),
        if modules.len() == 1 { "" } else { "s" }
    );
    for module in modules {
        println!("  {} sha256:{}", module.path, module.digest);
        for &id in &module.imports {
            println!("    imports {}", modules[id as usize].path);
        }
    }
    0
}

/// Options for `rbgp policy test` (ADR-0096 live-RIB dry run).
pub struct TestOptions<'a> {
    /// Path to the local `.rpol` file (its text is sent to the daemon).
    pub file: &'a str,
    /// Policy selection: name or call-form (`"customer-in(200)"`).
    pub policy: &'a str,
    /// `"import"` or `"export"`.
    pub direction: &'a str,
    /// Optional peer scope / export target.
    pub peer: Option<&'a str>,
    /// Optional family filter (`ipv4_unicast`, `ipv6_unicast`).
    pub family: Option<&'a str>,
    /// Max routes evaluated (0 = all).
    pub limit: u32,
    /// Max before/after diff samples.
    pub show_changes: u32,
}

/// `rbgp policy test` — send the local `.rpol` source to the daemon
/// for a read-only dry run over a live-RIB snapshot.
pub async fn test(
    connection: Connection,
    opts: TestOptions<'_>,
    json: bool,
) -> Result<(), CliError> {
    let rpol_source = std::fs::read_to_string(opts.file)
        .map_err(|error| CliError::Argument(format!("cannot read {}: {error}", opts.file)))?;
    let afi_safi = match opts.family {
        None => proto::AddressFamily::Unspecified,
        Some("ipv4_unicast" | "ipv4") => proto::AddressFamily::Ipv4Unicast,
        Some("ipv6_unicast" | "ipv6") => proto::AddressFamily::Ipv6Unicast,
        Some(other) => {
            return Err(CliError::Argument(format!(
                "unsupported family {other:?}; expected ipv4_unicast or ipv6_unicast"
            )));
        }
    };
    let mut client =
        PolicyServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .test_policy(proto::TestPolicyRequest {
            rpol_source,
            policy: opts.policy.to_string(),
            direction: opts.direction.to_string(),
            peer: opts.peer.unwrap_or_default().to_string(),
            afi_safi: afi_safi as i32,
            limit: opts.limit,
            show_changes: opts.show_changes,
        })
        .await?
        .into_inner();

    if json {
        #[derive(Serialize)]
        struct JsonTermHits<'a> {
            term: &'a str,
            hits: u64,
        }
        #[derive(Serialize)]
        struct JsonDiff<'a> {
            prefix: String,
            peer: &'a str,
            changes: &'a [String],
        }
        #[derive(Serialize)]
        struct JsonTest<'a> {
            file: &'a str,
            policy: &'a str,
            direction: &'a str,
            compiled: bool,
            #[serde(skip_serializing_if = "str::is_empty")]
            diagnostics: &'a str,
            routes_evaluated: u64,
            accepted: u64,
            rejected: u64,
            modified: u64,
            term_hits: Vec<JsonTermHits<'a>>,
            diffs: Vec<JsonDiff<'a>>,
        }
        output::print_json_pretty(&JsonTest {
            file: opts.file,
            policy: opts.policy,
            direction: opts.direction,
            compiled: resp.compiled,
            diagnostics: &resp.diagnostics,
            routes_evaluated: resp.routes_evaluated,
            accepted: resp.accepted,
            rejected: resp.rejected,
            modified: resp.modified,
            term_hits: resp
                .term_hits
                .iter()
                .map(|t| JsonTermHits {
                    term: &t.term,
                    hits: t.hits,
                })
                .collect(),
            diffs: resp
                .diffs
                .iter()
                .map(|d| JsonDiff {
                    prefix: format!("{}/{}", d.prefix, d.prefix_length),
                    peer: &d.peer,
                    changes: &d.changes,
                })
                .collect(),
        })?;
        if !resp.compiled {
            std::process::exit(1);
        }
        return Ok(());
    }

    if !resp.compiled {
        eprint!("{}", resp.diagnostics);
        eprintln!("{}: compile failed", opts.file);
        std::process::exit(1);
    }
    println!(
        "policy {:?} ({}) over {} route{}:",
        opts.policy,
        opts.direction,
        resp.routes_evaluated,
        if resp.routes_evaluated == 1 { "" } else { "s" }
    );
    println!(
        "  accepted {}  rejected {}  modified {}",
        resp.accepted, resp.rejected, resp.modified
    );
    if !resp.term_hits.is_empty() {
        println!("Term hits:");
        for t in &resp.term_hits {
            println!("  {:<32} {}", t.term, t.hits);
        }
    }
    if !resp.diffs.is_empty() {
        println!("Changes (up to {}):", opts.show_changes);
        for d in &resp.diffs {
            println!("  {}/{} (from {}):", d.prefix, d.prefix_length, d.peer);
            for change in &d.changes {
                println!("    {change}");
            }
        }
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct JsonPolicyStats {
    peer_address: String,
    direction: String,
    routes_evaluated: u64,
    /// Install identity of the chain instance the counters belong to.
    /// `None` for export chains (install generation not tracked yet,
    /// LAN-311); import chains always report it, so counters that
    /// reset to zero read as "new chain instance", not continuous
    /// history.
    policy_generation: Option<u64>,
    terms: Vec<JsonPolicyTermStat>,
}

#[derive(Debug, Serialize)]
struct JsonPolicyTermStat {
    policy_index: u32,
    policy: Option<String>,
    term_index: u32,
    term: Option<String>,
    hits: u64,
}

/// One external dataset status row (LAN-305).
#[derive(Debug, Serialize)]
struct JsonPolicyDataset {
    name: String,
    kind: String,
    generation: u64,
    records: u64,
    path: String,
    /// Most recent refresh failure; `None` when the last refresh
    /// succeeded. While set, the prior snapshot keeps serving probes.
    last_error: Option<String>,
}

/// Combined `rbgp policy stats --json` document (LAN-305 added the
/// dataset block alongside the chain counters).
#[derive(Debug, Serialize)]
struct JsonPolicyStatsDoc {
    chains: Vec<JsonPolicyStats>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    datasets: Vec<JsonPolicyDataset>,
}

/// `rbgp policy stats [--peer ADDR] [--direction import|export|both]`
/// — live per-term hit counters of the installed chains (ADR-0096).
pub async fn stats(
    connection: Connection,
    peer: Option<&str>,
    direction: &str,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        PolicyServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .get_policy_stats(GetPolicyStatsRequest {
            peer_address: peer.unwrap_or_default().to_string(),
            direction: direction.to_string(),
        })
        .await?
        .into_inner();

    if json {
        let chains: Vec<JsonPolicyStats> = resp
            .chains
            .iter()
            .map(|chain| JsonPolicyStats {
                peer_address: chain.peer_address.clone(),
                direction: chain.direction.clone(),
                routes_evaluated: chain.routes_evaluated,
                policy_generation: (chain.direction == "import").then_some(chain.policy_generation),
                terms: chain
                    .terms
                    .iter()
                    .map(|t| JsonPolicyTermStat {
                        policy_index: t.policy_index,
                        policy: (!t.policy.is_empty()).then(|| t.policy.clone()),
                        term_index: t.term_index,
                        term: (!t.term.is_empty()).then(|| t.term.clone()),
                        hits: t.hits,
                    })
                    .collect(),
            })
            .collect();
        let datasets: Vec<JsonPolicyDataset> = resp
            .datasets
            .iter()
            .map(|d| JsonPolicyDataset {
                name: d.name.clone(),
                kind: d.kind.clone(),
                generation: d.generation,
                records: d.records,
                path: d.path.clone(),
                last_error: (!d.last_error.is_empty()).then(|| d.last_error.clone()),
            })
            .collect();
        output::print_json_pretty(&JsonPolicyStatsDoc { chains, datasets })?;
        return Ok(());
    }

    if resp.chains.is_empty() && resp.datasets.is_empty() {
        println!("No installed policy chains");
        return Ok(());
    }
    if resp.chains.is_empty() {
        println!("No installed policy chains");
    }
    for chain in &resp.chains {
        // Import chains carry an install generation (bumps on every
        // chain install, content-equal reinstalls included); export
        // chains do not track one yet (LAN-311).
        let generation = if chain.direction == "import" {
            format!(" (install generation {})", chain.policy_generation)
        } else {
            String::new()
        };
        println!(
            "{} {} chain — {} routes evaluated since install{generation}",
            chain.peer_address, chain.direction, chain.routes_evaluated
        );
        println!("  {:<32} {:<24} HITS", "POLICY", "TERM");
        for t in &chain.terms {
            let policy = if t.policy.is_empty() {
                "inline".to_string()
            } else {
                t.policy.clone()
            };
            let term = if t.term.is_empty() {
                format!("statement {}", t.term_index)
            } else {
                t.term.clone()
            };
            println!("  {policy:<32} {term:<24} {}", t.hits);
        }
    }
    // LAN-305: external dataset status — generation, size, and the
    // last refresh failure (prior snapshot still serving while set).
    if !resp.datasets.is_empty() {
        println!("Datasets:");
        println!(
            "  {:<24} {:<14} {:>4}  {:>8}  PATH",
            "NAME", "KIND", "GEN", "RECORDS"
        );
        for d in &resp.datasets {
            println!(
                "  {:<24} {:<14} {:>4}  {:>8}  {}",
                d.name, d.kind, d.generation, d.records, d.path
            );
            if !d.last_error.is_empty() {
                println!(
                    "    last refresh FAILED ({}); prior snapshot still serving",
                    d.last_error
                );
            }
        }
    }
    Ok(())
}

pub async fn list(connection: Connection, json: bool) -> Result<(), CliError> {
    let mut client =
        PolicyServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .list_policies(ListPoliciesRequest {})
        .await?
        .into_inner();

    if json {
        let out: Vec<JsonPolicySummary> = resp
            .policies
            .iter()
            .map(|p| JsonPolicySummary {
                name: p.name.clone(),
                default_action: p
                    .definition
                    .as_ref()
                    .map(|d| d.default_action.clone())
                    .unwrap_or_default(),
                statement_count: p
                    .definition
                    .as_ref()
                    .map(|d| d.statements.len())
                    .unwrap_or(0),
            })
            .collect();
        output::print_json_pretty(&out)?;
    } else if resp.policies.is_empty() {
        println!("No policies configured");
    } else {
        println!("{:<32} {:<10} STATEMENTS", "NAME", "DEFAULT");
        for p in &resp.policies {
            let def = p.definition.as_ref();
            let default_action = def.map(|d| d.default_action.as_str()).unwrap_or("-");
            let count = def.map(|d| d.statements.len()).unwrap_or(0);
            println!("{:<32} {:<10} {}", p.name, default_action, count);
        }
    }
    Ok(())
}

pub async fn get(connection: Connection, name: &str, json: bool) -> Result<(), CliError> {
    let mut client =
        PolicyServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .get_policy(GetPolicyRequest {
            name: name.to_string(),
        })
        .await?
        .into_inner();

    let def = resp.definition.unwrap_or_default();
    if json {
        let detail = JsonPolicyDetail {
            name: resp.name.clone(),
            default_action: def.default_action.clone(),
            statements: def.statements.into_iter().map(Into::into).collect(),
        };
        output::print_json_pretty(&detail)?;
    } else {
        println!("Name:           {}", resp.name);
        println!("Default Action: {}", def.default_action);
        println!("Statements:     {}", def.statements.len());
        for (i, s) in def.statements.iter().enumerate() {
            println!("  [{i}] action={}", s.action);
            print_statement_details(s, "      ");
        }
    }
    Ok(())
}

pub async fn set(
    connection: Connection,
    name: &str,
    from_file: &str,
    json: bool,
) -> Result<(), CliError> {
    let definition: JsonPolicyDefinition = load_json(from_file)?;
    let mut client =
        PolicyServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    client
        .set_policy(SetPolicyRequest {
            name: name.to_string(),
            definition: Some(definition.into()),
        })
        .await?;
    output::print_result(json, "set_policy", name, &format!("Policy {name} set"))
}

pub async fn delete(connection: Connection, name: &str, json: bool) -> Result<(), CliError> {
    let mut client =
        PolicyServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    client
        .delete_policy(DeletePolicyRequest {
            name: name.to_string(),
        })
        .await?;
    output::print_result(
        json,
        "delete_policy",
        name,
        &format!("Policy {name} deleted"),
    )
}

#[derive(Debug, Serialize)]
struct JsonImportExplainMatch {
    outcome: String,
    path_id: u32,
    matched_policy: Option<String>,
    rpki_validation: Option<String>,
    aspa_validation: Option<String>,
    modifications: Option<JsonImportExplainModifications>,
    evaluated_at_unix_ns: Option<i64>,
    policy_generation: Option<u64>,
    // Unconditional key (run-stable): empty for outcomes that carry no
    // statement trace (stale / withdrawn / evicted / not_seen /
    // cache_disabled / no_session, or a chain-less peer).
    statements: Vec<JsonImportExplainStatement>,
}

#[derive(Debug, Serialize)]
struct JsonImportExplainStatement {
    policy_index: u32,
    policy_name: Option<String>,
    // `None` when the policy fell through to its default action
    // (`default_action == true`).
    statement_index: Option<u32>,
    default_action: bool,
    action: String,
    matched_conditions: Vec<String>,
    modifications: Vec<String>,
    // rpol deciding-term name (ADR-0096); `None` for TOML statements
    // and fallthroughs.
    term: Option<String>,
    // rpol per-term trace lines; empty for TOML members.
    term_traces: Vec<String>,
}

#[derive(Debug, Serialize)]
struct JsonImportExplainModifications {
    set_local_pref: Option<u32>,
    set_med: Option<u32>,
    set_next_hop: Option<String>,
    communities_add: Vec<u32>,
    communities_remove: Vec<u32>,
    extended_communities_add: Vec<u64>,
    extended_communities_remove: Vec<u64>,
    large_communities_add: Vec<String>,
    large_communities_remove: Vec<String>,
    as_path_prepend_asn: Option<u32>,
    as_path_prepend_count: Option<u32>,
}

#[derive(Debug, Serialize)]
struct JsonImportExplain {
    peer_address: String,
    prefix: String,
    afi_safi: String,
    current_policy_generation: u64,
    matches: Vec<JsonImportExplainMatch>,
}

/// Render a proto outcome enum as a stable lowercase operator string.
fn outcome_label(outcome: i32) -> &'static str {
    match proto::ImportExplainOutcome::try_from(outcome) {
        Ok(proto::ImportExplainOutcome::Permit) => "permit",
        Ok(proto::ImportExplainOutcome::Deny) => "deny",
        Ok(proto::ImportExplainOutcome::Withdrawn) => "withdrawn",
        Ok(proto::ImportExplainOutcome::Evicted) => "evicted",
        Ok(proto::ImportExplainOutcome::Stale) => "stale",
        Ok(proto::ImportExplainOutcome::NotSeen) => "not_seen",
        Ok(proto::ImportExplainOutcome::CacheDisabled) => "cache_disabled",
        Ok(proto::ImportExplainOutcome::NoSession) => "no_session",
        Ok(proto::ImportExplainOutcome::Unspecified) | Err(_) => "unspecified",
    }
}

/// The two LAN-320 outcomes that mean "the question could not be
/// evaluated" (as opposed to `not_seen`, which is an evaluated answer).
/// Rendered as errors with a nonzero exit; in JSON mode the response is
/// still printed first so scripts see the distinct outcome value.
fn unanswerable_error(outcome: i32, neighbor: &str) -> Option<CliError> {
    match proto::ImportExplainOutcome::try_from(outcome) {
        Ok(proto::ImportExplainOutcome::CacheDisabled) => Some(CliError::Rpc(
            "import-decision cache is disabled on this daemon\n  \
             hint: set [policy.explain] enabled = true and reload (memory cost is per cached route)"
                .to_string(),
        )),
        Ok(proto::ImportExplainOutcome::NoSession) => {
            Some(CliError::Rpc(format!("no live session with {neighbor}")))
        }
        _ => None,
    }
}

/// Whether an outcome carries a recorded decision (and therefore
/// populated policy / validation / modification fields).
fn outcome_has_decision(outcome: i32) -> bool {
    matches!(
        proto::ImportExplainOutcome::try_from(outcome),
        Ok(proto::ImportExplainOutcome::Permit
            | proto::ImportExplainOutcome::Deny
            | proto::ImportExplainOutcome::Withdrawn
            | proto::ImportExplainOutcome::Stale)
    )
}

/// Split a CIDR (`"192.0.2.0/24"` / `"2001:db8::/32"`) into the address
/// string, prefix length, and the matching `AddressFamily`. ADR-0073
/// scopes explain to IPv4 / IPv6 unicast, so the address family is
/// inferred from the prefix rather than asked for separately.
fn parse_cidr(prefix: &str) -> Result<(String, u32, proto::AddressFamily), CliError> {
    let (addr, len) = prefix
        .split_once('/')
        .ok_or_else(|| CliError::Argument(format!("--prefix must be CIDR (got {prefix:?})")))?;
    let length: u32 = len
        .parse()
        .map_err(|_| CliError::Argument(format!("invalid prefix length in {prefix:?}")))?;
    let ip: std::net::IpAddr = addr
        .parse()
        .map_err(|_| CliError::Argument(format!("invalid prefix address in {prefix:?}")))?;
    match ip {
        std::net::IpAddr::V4(_) if length <= 32 => {
            Ok((addr.to_string(), length, proto::AddressFamily::Ipv4Unicast))
        }
        std::net::IpAddr::V6(_) if length <= 128 => {
            Ok((addr.to_string(), length, proto::AddressFamily::Ipv6Unicast))
        }
        _ => Err(CliError::Argument(format!(
            "prefix length out of range for address family in {prefix:?}"
        ))),
    }
}

pub async fn explain_import(
    connection: Connection,
    neighbor: &str,
    prefix: &str,
    path_id: Option<u32>,
    json: bool,
) -> Result<(), CliError> {
    let (addr, prefix_length, afi_safi) = parse_cidr(prefix)?;
    let mut client =
        PolicyServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .explain_import_policy(ExplainImportPolicyRequest {
            peer_address: neighbor.to_string(),
            afi_safi: afi_safi as i32,
            prefix: addr,
            prefix_length,
            path_id,
        })
        .await?
        .into_inner();

    // LAN-320: cache-disabled / no-session mean the daemon could not
    // evaluate the question — surface an error (nonzero exit) instead
    // of a lookalike answer. These arrive as a single synthetic match.
    let unanswerable = resp
        .matches
        .iter()
        .find_map(|m| unanswerable_error(m.outcome, neighbor));

    if json {
        let out = JsonImportExplain {
            peer_address: resp.peer_address.clone(),
            prefix: format!("{}/{}", resp.prefix, resp.prefix_length),
            afi_safi: address_family_label(resp.afi_safi).to_string(),
            current_policy_generation: resp.current_policy_generation,
            matches: resp.matches.iter().map(match_to_json).collect(),
        };
        output::print_json_pretty(&out)?;
        // The JSON body already carries the distinct outcome; the
        // error exit still signals "not an evaluated answer".
        return match unanswerable {
            Some(err) => Err(err),
            None => Ok(()),
        };
    }
    if let Some(err) = unanswerable {
        return Err(err);
    }

    println!(
        "import policy explain — peer {} prefix {}/{} (policy generation {})",
        resp.peer_address, resp.prefix, resp.prefix_length, resp.current_policy_generation
    );
    if resp.matches.len() > 1 {
        println!("{} matching paths:", resp.matches.len());
    }
    for m in &resp.matches {
        let path = if m.path_id == 0 {
            String::new()
        } else {
            format!(" path-id {}", m.path_id)
        };
        println!("  {}{}", outcome_label(m.outcome), path);
        if outcome_has_decision(m.outcome) {
            if !m.matched_policy.is_empty() {
                println!("    policy:  {}", m.matched_policy);
            } else {
                println!("    policy:  inline");
            }
            println!(
                "    rpki:    {}    aspa: {}",
                blank_dash(&m.rpki_validation),
                blank_dash(&m.aspa_validation)
            );
            println!("    eval-ns: {}", m.evaluated_at_unix_ns);
            if let Some(mods) = &m.modifications {
                let summary = modifications_summary(mods);
                if !summary.is_empty() {
                    println!("    mods:    {summary}");
                }
            }
            for (i, s) in m.statements.iter().enumerate() {
                if i == 0 {
                    println!("    statements:");
                }
                println!("      {}", statement_line(s));
                for trace in &s.term_traces {
                    println!("        {trace}");
                }
            }
        }
    }
    Ok(())
}

/// One text row per statement-trace step:
/// `[0] policy lp-bump statement 1 permit  match: community 65001:100  set: local_pref 100 -> 200`
/// or, for a default-action fallthrough,
/// `[1] policy guard default-action deny`.
fn statement_line(s: &proto::ImportExplainStatementStep) -> String {
    let policy = if s.policy_name.is_empty() {
        "inline"
    } else {
        &s.policy_name
    };
    let mut line = format!("[{}] policy {policy}", s.policy_index);
    if s.default_action {
        line.push_str(&format!(" default-action {}", s.action));
    } else if !s.term.is_empty() {
        // rpol member: the deciding term has a name.
        line.push_str(&format!(" term {} {}", s.term, s.action));
        if !s.matched_conditions.is_empty() {
            line.push_str(&format!("  match: {}", s.matched_conditions.join(", ")));
        }
        if !s.modifications.is_empty() {
            line.push_str(&format!("  set: {}", s.modifications.join(", ")));
        }
    } else {
        line.push_str(&format!(" statement {} {}", s.statement_index, s.action));
        if !s.matched_conditions.is_empty() {
            line.push_str(&format!("  match: {}", s.matched_conditions.join(", ")));
        }
        if !s.modifications.is_empty() {
            line.push_str(&format!("  set: {}", s.modifications.join(", ")));
        }
    }
    line
}

fn blank_dash(s: &str) -> &str {
    if s.is_empty() { "-" } else { s }
}

/// Map one proto match into its JSON shape. Decision-bearing fields
/// (policy / validation / modifications / timestamps) are populated
/// only for outcomes that recorded a decision; `NOT_SEEN` / `EVICTED`
/// leave them `None` so the JSON doesn't imply data that isn't there.
fn match_to_json(m: &proto::ImportExplainMatch) -> JsonImportExplainMatch {
    let has_decision = outcome_has_decision(m.outcome);
    let non_empty = |s: &str| (!s.is_empty()).then(|| s.to_string());
    JsonImportExplainMatch {
        outcome: outcome_label(m.outcome).to_string(),
        path_id: m.path_id,
        matched_policy: has_decision.then(|| non_empty(&m.matched_policy)).flatten(),
        rpki_validation: has_decision
            .then(|| non_empty(&m.rpki_validation))
            .flatten(),
        aspa_validation: has_decision
            .then(|| non_empty(&m.aspa_validation))
            .flatten(),
        modifications: if has_decision {
            m.modifications.as_ref().map(modifications_to_json)
        } else {
            None
        },
        evaluated_at_unix_ns: has_decision.then_some(m.evaluated_at_unix_ns),
        policy_generation: has_decision.then_some(m.policy_generation),
        statements: m.statements.iter().map(statement_to_json).collect(),
    }
}

fn statement_to_json(s: &proto::ImportExplainStatementStep) -> JsonImportExplainStatement {
    JsonImportExplainStatement {
        policy_index: s.policy_index,
        policy_name: (!s.policy_name.is_empty()).then(|| s.policy_name.clone()),
        statement_index: (!s.default_action).then_some(s.statement_index),
        default_action: s.default_action,
        action: s.action.clone(),
        matched_conditions: s.matched_conditions.clone(),
        modifications: s.modifications.clone(),
        term: (!s.term.is_empty()).then(|| s.term.clone()),
        term_traces: s.term_traces.clone(),
    }
}

fn address_family_label(afi_safi: i32) -> &'static str {
    match proto::AddressFamily::try_from(afi_safi) {
        Ok(proto::AddressFamily::Ipv4Unicast) => "ipv4-unicast",
        Ok(proto::AddressFamily::Ipv6Unicast) => "ipv6-unicast",
        _ => "unspecified",
    }
}

fn modifications_to_json(m: &proto::ExplainModifications) -> JsonImportExplainModifications {
    JsonImportExplainModifications {
        set_local_pref: m.set_local_pref,
        set_med: m.set_med,
        set_next_hop: Some(m.set_next_hop.clone()).filter(|s| !s.is_empty()),
        communities_add: m.communities_add.clone(),
        communities_remove: m.communities_remove.clone(),
        extended_communities_add: m.extended_communities_add.clone(),
        extended_communities_remove: m.extended_communities_remove.clone(),
        large_communities_add: m.large_communities_add.clone(),
        large_communities_remove: m.large_communities_remove.clone(),
        as_path_prepend_asn: m.as_path_prepend_asn,
        as_path_prepend_count: m.as_path_prepend_count,
    }
}

fn modifications_summary(m: &proto::ExplainModifications) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(lp) = m.set_local_pref {
        parts.push(format!("local_pref={lp}"));
    }
    if let Some(med) = m.set_med {
        parts.push(format!("med={med}"));
    }
    if !m.set_next_hop.is_empty() {
        parts.push(format!("next_hop={}", m.set_next_hop));
    }
    if !m.communities_add.is_empty() {
        parts.push(format!("comm+={}", m.communities_add.len()));
    }
    if !m.communities_remove.is_empty() {
        parts.push(format!("comm-={}", m.communities_remove.len()));
    }
    if !m.extended_communities_add.is_empty() {
        parts.push(format!("extcomm+={}", m.extended_communities_add.len()));
    }
    if !m.extended_communities_remove.is_empty() {
        parts.push(format!("extcomm-={}", m.extended_communities_remove.len()));
    }
    if !m.large_communities_add.is_empty() {
        parts.push(format!("largecomm+={}", m.large_communities_add.len()));
    }
    if !m.large_communities_remove.is_empty() {
        parts.push(format!("largecomm-={}", m.large_communities_remove.len()));
    }
    if let (Some(asn), Some(count)) = (m.as_path_prepend_asn, m.as_path_prepend_count) {
        parts.push(format!("prepend={asn}x{count}"));
    }
    parts.join(" ")
}

pub async fn chain_show(
    connection: Connection,
    neighbor: Option<&str>,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        PolicyServiceClient::with_interceptor(connection.channel(), connection.interceptor());

    let (import, export, address) = match neighbor {
        Some(addr) => {
            let resp = client
                .get_neighbor_policy_chains(GetNeighborPolicyChainsRequest {
                    address: addr.to_string(),
                })
                .await?
                .into_inner();
            (
                resp.import_policy_names,
                resp.export_policy_names,
                Some(resp.address),
            )
        }
        None => {
            let resp = client
                .get_global_policy_chains(GetGlobalPolicyChainsRequest {})
                .await?
                .into_inner();
            (resp.import_policy_names, resp.export_policy_names, None)
        }
    };

    if json {
        let out = JsonChains {
            neighbor: address,
            import_policy_names: import,
            export_policy_names: export,
        };
        output::print_json_pretty(&out)?;
    } else {
        let scope = neighbor.unwrap_or("global");
        println!("Scope:        {scope}");
        println!(
            "Import Chain: {}",
            if import.is_empty() {
                "(none)".to_string()
            } else {
                import.join(" -> ")
            }
        );
        println!(
            "Export Chain: {}",
            if export.is_empty() {
                "(none)".to_string()
            } else {
                export.join(" -> ")
            }
        );
    }
    Ok(())
}

pub async fn chain_set(
    connection: Connection,
    direction: ChainDirection,
    neighbor: Option<&str>,
    policy_names: Vec<String>,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        PolicyServiceClient::with_interceptor(connection.channel(), connection.interceptor());

    let (target, message) = match (direction, neighbor) {
        (ChainDirection::Import, None) => {
            client
                .set_global_import_chain(SetGlobalImportChainRequest {
                    policy_names: policy_names.clone(),
                })
                .await?;
            (
                "global".to_string(),
                "Global import chain updated".to_string(),
            )
        }
        (ChainDirection::Export, None) => {
            client
                .set_global_export_chain(SetGlobalExportChainRequest {
                    policy_names: policy_names.clone(),
                })
                .await?;
            (
                "global".to_string(),
                "Global export chain updated".to_string(),
            )
        }
        (ChainDirection::Import, Some(addr)) => {
            client
                .set_neighbor_import_chain(SetNeighborImportChainRequest {
                    address: addr.to_string(),
                    policy_names: policy_names.clone(),
                })
                .await?;
            (
                addr.to_string(),
                format!("Neighbor {addr} import chain updated"),
            )
        }
        (ChainDirection::Export, Some(addr)) => {
            client
                .set_neighbor_export_chain(SetNeighborExportChainRequest {
                    address: addr.to_string(),
                    policy_names: policy_names.clone(),
                })
                .await?;
            (
                addr.to_string(),
                format!("Neighbor {addr} export chain updated"),
            )
        }
    };
    output::print_result(
        json,
        match direction {
            ChainDirection::Import => "set_import_chain",
            ChainDirection::Export => "set_export_chain",
        },
        &target,
        &message,
    )
}

pub async fn chain_clear(
    connection: Connection,
    direction: ChainDirection,
    neighbor: Option<&str>,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        PolicyServiceClient::with_interceptor(connection.channel(), connection.interceptor());

    let (target, message) = match (direction, neighbor) {
        (ChainDirection::Import, None) => {
            client
                .clear_global_import_chain(ClearGlobalImportChainRequest {})
                .await?;
            (
                "global".to_string(),
                "Global import chain cleared".to_string(),
            )
        }
        (ChainDirection::Export, None) => {
            client
                .clear_global_export_chain(ClearGlobalExportChainRequest {})
                .await?;
            (
                "global".to_string(),
                "Global export chain cleared".to_string(),
            )
        }
        (ChainDirection::Import, Some(addr)) => {
            client
                .clear_neighbor_import_chain(ClearNeighborImportChainRequest {
                    address: addr.to_string(),
                })
                .await?;
            (
                addr.to_string(),
                format!("Neighbor {addr} import chain cleared"),
            )
        }
        (ChainDirection::Export, Some(addr)) => {
            client
                .clear_neighbor_export_chain(ClearNeighborExportChainRequest {
                    address: addr.to_string(),
                })
                .await?;
            (
                addr.to_string(),
                format!("Neighbor {addr} export chain cleared"),
            )
        }
    };
    output::print_result(
        json,
        match direction {
            ChainDirection::Import => "clear_import_chain",
            ChainDirection::Export => "clear_export_chain",
        },
        &target,
        &message,
    )
}

#[derive(Clone, Copy, Debug)]
pub enum ChainDirection {
    Import,
    Export,
}

fn print_statement_details(s: &proto::PolicyStatement, indent: &str) {
    if let Some(p) = &s.prefix {
        println!("{indent}prefix={p}");
    }
    if let Some(g) = s.ge {
        println!("{indent}ge={g}");
    }
    if let Some(l) = s.le {
        println!("{indent}le={l}");
    }
    if !s.match_community.is_empty() {
        println!("{indent}match_community={}", s.match_community.join(","));
    }
    if let Some(p) = &s.match_as_path {
        println!("{indent}match_as_path={p}");
    }
    if let Some(n) = &s.match_neighbor_set {
        println!("{indent}match_neighbor_set={n}");
    }
    if let Some(rt) = &s.match_route_type {
        println!("{indent}match_route_type={rt}");
    }
    if let Some(rt) = s.match_evpn_route_type {
        println!("{indent}match_evpn_route_type={rt}");
    }
    if let Some(v) = &s.match_rpki_validation {
        println!("{indent}match_rpki_validation={v}");
    }
    if let Some(v) = &s.match_aspa_validation {
        println!("{indent}match_aspa_validation={v}");
    }
    if let Some(n) = &s.match_next_hop {
        println!("{indent}match_next_hop={n}");
    }
    if let Some(lp) = s.set_local_pref {
        println!("{indent}set_local_pref={lp}");
    }
    if let Some(med) = s.set_med {
        println!("{indent}set_med={med}");
    }
    if let Some(n) = &s.set_next_hop {
        println!("{indent}set_next_hop={n}");
    }
    if !s.set_community_add.is_empty() {
        println!(
            "{indent}set_community_add={}",
            s.set_community_add.join(",")
        );
    }
    if !s.set_community_remove.is_empty() {
        println!(
            "{indent}set_community_remove={}",
            s.set_community_remove.join(",")
        );
    }
    if let Some(p) = &s.set_as_path_prepend {
        println!(
            "{indent}set_as_path_prepend=asn={} count={}",
            p.asn, p.count
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::connect;
    use crate::test_support::spawn_mock_server;
    use std::io::Write;

    fn write_rpol(content: &str) -> tempfile::NamedTempFile {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(tmp, "{content}").unwrap();
        tmp.flush().unwrap();
        tmp
    }

    #[tokio::test]
    async fn test_sends_source_and_selection_and_renders() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        let file = write_rpol("policy p { term t { reject } }");
        test(
            connection,
            TestOptions {
                file: file.path().to_str().unwrap(),
                policy: "customer-in(200)",
                direction: "import",
                peer: Some("10.0.0.9"),
                family: Some("ipv4_unicast"),
                limit: 100,
                show_changes: 5,
            },
            true,
        )
        .await
        .unwrap();
        let captured = server.state.last_test_policy.lock().await.clone().unwrap();
        assert_eq!(captured.rpol_source, "policy p { term t { reject } }");
        assert_eq!(captured.policy, "customer-in(200)");
        assert_eq!(captured.direction, "import");
        assert_eq!(captured.peer, "10.0.0.9");
        assert_eq!(
            captured.afi_safi,
            crate::proto::AddressFamily::Ipv4Unicast as i32
        );
        assert_eq!(captured.limit, 100);
        assert_eq!(captured.show_changes, 5);
    }

    #[tokio::test]
    async fn test_rejects_unknown_family_and_missing_file() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        let file = write_rpol("policy p { term t { reject } }");
        let opts = |file: &str, family: Option<&'static str>| TestOptions {
            file: Box::leak(file.to_string().into_boxed_str()),
            policy: "p",
            direction: "import",
            peer: None,
            family,
            limit: 0,
            show_changes: 0,
        };
        let path = file.path().to_str().unwrap();
        let err = test(connection.clone(), opts(path, Some("l2vpn_evpn")), false)
            .await
            .unwrap_err();
        assert!(matches!(err, CliError::Argument(_)), "{err:?}");
        let err = test(connection, opts("/nonexistent/x.rpol", None), false)
            .await
            .unwrap_err();
        assert!(matches!(err, CliError::Argument(_)), "{err:?}");
    }

    #[test]
    fn check_local_clean_file_exits_zero() {
        let tmp = write_rpol(
            "policy p { term t { if route.rpki == invalid { reject } } }
             test rejects-invalid {
                 route { prefix 10.0.0.0/24; rpki invalid }
                 expect p == reject
             }",
        );
        assert_eq!(
            check_local(tmp.path().to_str().unwrap(), &[], false, false),
            0
        );
        assert_eq!(
            check_local(tmp.path().to_str().unwrap(), &[], false, true),
            0
        );
    }

    #[test]
    fn check_local_diagnostics_exit_one() {
        let tmp = write_rpol("policy p { term t { if route.zzz == 1 { accept } } }");
        assert_eq!(
            check_local(tmp.path().to_str().unwrap(), &[], false, false),
            1
        );
        // Unreadable file is also exit 1.
        assert_eq!(check_local("/nonexistent/nope.rpol", &[], false, false), 1);
    }

    /// LAN-300: `check` resolves the import graph (tests in the main
    /// file exercise imported definitions), `--root` resolves imports
    /// outside the main file's directory, and `--list-deps` exits 0 on
    /// a clean graph / 1 on a broken one.
    #[test]
    fn check_local_resolves_imports_and_lists_deps() {
        let dir = tempfile::tempdir().unwrap();
        let lib = tempfile::tempdir().unwrap();
        std::fs::write(
            lib.path().join("bogons.rpol"),
            "prefix-set bogons { 127.0.0.0/8 le 32 }",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("main.rpol"),
            "import \"bogons.rpol\"\n\
             policy p { term t { if route.prefix in bogons { reject } } }\n\
             test rejects-loopback {\n\
                 route { prefix 127.0.0.1/32 }\n\
                 expect p == reject\n\
             }",
        )
        .unwrap();
        let main = dir.path().join("main.rpol");
        let main = main.to_str().unwrap();
        let root = lib.path().to_str().unwrap().to_string();
        // Without the root the import cannot resolve.
        assert_eq!(check_local(main, &[], false, false), 1);
        // With it: clean check (the cross-module test runs) and deps.
        assert_eq!(
            check_local(main, std::slice::from_ref(&root), false, false),
            0
        );
        assert_eq!(
            check_local(main, std::slice::from_ref(&root), true, false),
            0
        );
        assert_eq!(check_local(main, &[root], true, true), 0);
        // --list-deps on a broken graph still exits 1.
        assert_eq!(check_local(main, &[], true, false), 1);
    }

    #[test]
    fn check_local_failing_test_exits_two() {
        let tmp = write_rpol(
            "policy p { term t { reject } }
             test should-fail {
                 route { prefix 10.0.0.0/24 }
                 expect p == accept
             }",
        );
        assert_eq!(
            check_local(tmp.path().to_str().unwrap(), &[], false, false),
            2
        );
    }

    #[tokio::test]
    async fn list_renders_empty() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        list(connection, true).await.unwrap();
    }

    #[tokio::test]
    async fn set_reads_json_file_and_sends_definition() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();

        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(
            tmp,
            r#"{{"default_action":"deny","statements":[{{"action":"permit","prefix":"10.0.0.0/8","set_local_pref":300}}]}}"#
        )
        .unwrap();
        tmp.flush().unwrap();

        set(
            connection,
            "from-transit",
            tmp.path().to_str().unwrap(),
            true,
        )
        .await
        .unwrap();

        let captured = server.state.last_set_policy.lock().await.clone().unwrap();
        assert_eq!(captured.name, "from-transit");
        let def = captured.definition.unwrap();
        assert_eq!(def.default_action, "deny");
        assert_eq!(def.statements.len(), 1);
        assert_eq!(def.statements[0].action, "permit");
        assert_eq!(def.statements[0].set_local_pref, Some(300));
    }

    #[tokio::test]
    async fn explain_infers_afi_from_prefix_and_sends_request() {
        // Pin: the CLI infers AFI from the prefix (no --afi flag) and
        // sends a well-formed request with the parsed address + length.
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        explain_import(connection, "192.0.2.1", "2001:db8::/32", Some(7), true)
            .await
            .unwrap();
        let captured = server
            .state
            .last_explain_import
            .lock()
            .await
            .clone()
            .unwrap();
        assert_eq!(captured.peer_address, "192.0.2.1");
        assert_eq!(captured.prefix, "2001:db8::");
        assert_eq!(captured.prefix_length, 32);
        assert_eq!(captured.path_id, Some(7));
        assert_eq!(
            captured.afi_safi,
            crate::proto::AddressFamily::Ipv6Unicast as i32,
            "AFI inferred from the v6 prefix"
        );
    }

    #[tokio::test]
    async fn explain_rejects_non_cidr_prefix() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        let err = explain_import(connection, "192.0.2.1", "192.0.2.0", None, true)
            .await
            .unwrap_err();
        assert!(matches!(err, CliError::Argument(_)));
    }

    #[tokio::test]
    async fn explain_all_paths_returns_every_match() {
        // Pin 7: omitting --path-id surfaces all matching paths, not an
        // arbitrary first hit. The mock returns two paths in that case.
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        explain_import(connection, "192.0.2.1", "192.0.2.0/24", None, true)
            .await
            .unwrap();
        let captured = server
            .state
            .last_explain_import
            .lock()
            .await
            .clone()
            .unwrap();
        assert_eq!(captured.path_id, None);
        assert_eq!(
            captured.afi_safi,
            crate::proto::AddressFamily::Ipv4Unicast as i32
        );
    }

    #[tokio::test]
    async fn explain_renders_text_and_json() {
        // Pin 8: both render paths run cleanly over a populated
        // multi-match response (permit + deny, modifications present).
        let server = spawn_mock_server(None).await;
        let json_conn = connect(&server.addr, None).await.unwrap();
        explain_import(json_conn, "192.0.2.1", "192.0.2.0/24", None, true)
            .await
            .unwrap();
        let text_conn = connect(&server.addr, None).await.unwrap();
        explain_import(text_conn, "192.0.2.1", "192.0.2.0/24", None, false)
            .await
            .unwrap();
    }

    /// LAN-320 pin: `cache_disabled` is an error with the config hint
    /// (nonzero exit via `Err`), in both text and JSON modes — never a
    /// `not_seen` lookalike.
    #[tokio::test]
    async fn explain_cache_disabled_errors_with_hint() {
        let server = spawn_mock_server(None).await;
        *server.state.explain_import_synthetic_outcome.lock().await =
            Some(rustbgpd_api::proto::ImportExplainOutcome::CacheDisabled);
        let connection = connect(&server.addr, None).await.unwrap();
        let err = explain_import(connection, "10.0.0.2", "10.0.0.0/24", None, false)
            .await
            .unwrap_err();
        assert!(matches!(err, CliError::Rpc(_)));
        assert_eq!(
            err.to_string(),
            "import-decision cache is disabled on this daemon\n  \
             hint: set [policy.explain] enabled = true and reload (memory cost is per cached route)"
        );
        // JSON mode prints the body (distinct outcome value) but still
        // returns the error so the exit code stays nonzero.
        let json_conn = connect(&server.addr, None).await.unwrap();
        let err = explain_import(json_conn, "10.0.0.2", "10.0.0.0/24", None, true)
            .await
            .unwrap_err();
        assert!(matches!(err, CliError::Rpc(_)));
    }

    /// LAN-320 pin: `no_session` names the neighbor and errors (nonzero
    /// exit) — the question could not be evaluated.
    #[tokio::test]
    async fn explain_no_session_errors_with_neighbor() {
        let server = spawn_mock_server(None).await;
        *server.state.explain_import_synthetic_outcome.lock().await =
            Some(rustbgpd_api::proto::ImportExplainOutcome::NoSession);
        let connection = connect(&server.addr, None).await.unwrap();
        let err = explain_import(connection, "10.0.0.2", "10.0.0.0/24", None, false)
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), "no live session with 10.0.0.2");
        let json_conn = connect(&server.addr, None).await.unwrap();
        let err = explain_import(json_conn, "10.0.0.2", "10.0.0.0/24", None, true)
            .await
            .unwrap_err();
        assert!(matches!(err, CliError::Rpc(_)));
    }

    /// LAN-320 pin: `not_seen` stays an evaluated answer — normal
    /// rendering, `Ok` (exit 0) — in both text and JSON modes.
    #[tokio::test]
    async fn explain_not_seen_stays_ok() {
        let server = spawn_mock_server(None).await;
        *server.state.explain_import_synthetic_outcome.lock().await =
            Some(rustbgpd_api::proto::ImportExplainOutcome::NotSeen);
        let connection = connect(&server.addr, None).await.unwrap();
        explain_import(connection, "10.0.0.2", "10.0.0.0/24", None, false)
            .await
            .unwrap();
        let json_conn = connect(&server.addr, None).await.unwrap();
        explain_import(json_conn, "10.0.0.2", "10.0.0.0/24", None, true)
            .await
            .unwrap();
    }

    /// LAN-320: the JSON outcome strings for the tri-state are stable.
    #[test]
    fn outcome_labels_cover_tristate() {
        assert_eq!(
            outcome_label(proto::ImportExplainOutcome::NotSeen as i32),
            "not_seen"
        );
        assert_eq!(
            outcome_label(proto::ImportExplainOutcome::CacheDisabled as i32),
            "cache_disabled"
        );
        assert_eq!(
            outcome_label(proto::ImportExplainOutcome::NoSession as i32),
            "no_session"
        );
    }

    #[tokio::test]
    async fn stats_renders_text_and_json() {
        let server = spawn_mock_server(None).await;
        let json_conn = connect(&server.addr, None).await.unwrap();
        stats(json_conn, Some("10.0.0.2"), "export", true)
            .await
            .unwrap();
        let text_conn = connect(&server.addr, None).await.unwrap();
        stats(text_conn, None, "export", false).await.unwrap();
    }

    /// The direction flag passes through to the RPC: the mock server
    /// answers "import" and "both" with direction-tagged chains
    /// (import ones carrying an install generation), and both render.
    #[tokio::test]
    async fn stats_renders_import_and_both_directions() {
        let server = spawn_mock_server(None).await;
        let json_conn = connect(&server.addr, None).await.unwrap();
        stats(json_conn, Some("10.0.0.2"), "import", true)
            .await
            .unwrap();
        let text_conn = connect(&server.addr, None).await.unwrap();
        stats(text_conn, None, "both", false).await.unwrap();
    }

    #[test]
    fn statement_line_renders_rpol_term_name() {
        let step = proto::ImportExplainStatementStep {
            policy_index: 0,
            policy_name: "customer-in(200)".to_string(),
            default_action: false,
            statement_index: 2,
            action: "permit".to_string(),
            matched_conditions: vec!["guard route.prefix in customers".to_string()],
            modifications: vec!["local_pref 100 -> 200".to_string()],
            term: "customer-routes".to_string(),
            term_traces: vec![
                "term rpki-guard: route.rpki == invalid => reject [not matched]".to_string(),
            ],
        };
        assert_eq!(
            statement_line(&step),
            "[0] policy customer-in(200) term customer-routes permit  \
             match: guard route.prefix in customers  set: local_pref 100 -> 200"
        );
    }

    #[test]
    fn statement_line_renders_match_and_set_clauses() {
        let step = proto::ImportExplainStatementStep {
            policy_index: 0,
            policy_name: "edge-import".to_string(),
            default_action: false,
            statement_index: 1,
            action: "permit".to_string(),
            matched_conditions: vec![
                "prefix 10.0.0.0/8 le 24".to_string(),
                "community 65001:100".to_string(),
            ],
            modifications: vec!["local_pref 100 -> 200".to_string()],
            term: String::new(),
            term_traces: vec![],
        };
        assert_eq!(
            statement_line(&step),
            "[0] policy edge-import statement 1 permit  \
             match: prefix 10.0.0.0/8 le 24, community 65001:100  \
             set: local_pref 100 -> 200"
        );
    }

    #[test]
    fn statement_line_renders_default_action_and_inline_policy() {
        let step = proto::ImportExplainStatementStep {
            policy_index: 2,
            policy_name: String::new(),
            default_action: true,
            statement_index: 0,
            action: "deny".to_string(),
            matched_conditions: vec![],
            modifications: vec![],
            term: String::new(),
            term_traces: vec![],
        };
        assert_eq!(
            statement_line(&step),
            "[2] policy inline default-action deny"
        );
    }

    #[test]
    fn statement_to_json_nulls_index_on_default_action_only() {
        let matched = proto::ImportExplainStatementStep {
            policy_index: 0,
            policy_name: "p".to_string(),
            default_action: false,
            statement_index: 3,
            action: "permit".to_string(),
            matched_conditions: vec!["any".to_string()],
            modifications: vec![],
            term: String::new(),
            term_traces: vec![],
        };
        let j = statement_to_json(&matched);
        assert_eq!(j.statement_index, Some(3));
        assert_eq!(j.policy_name.as_deref(), Some("p"));

        let fallthrough = proto::ImportExplainStatementStep {
            default_action: true,
            policy_name: String::new(),
            action: "deny".to_string(),
            ..Default::default()
        };
        let j = statement_to_json(&fallthrough);
        assert_eq!(j.statement_index, None, "fallthrough has no statement");
        assert_eq!(j.policy_name, None, "inline policy serializes as null");
    }

    #[tokio::test]
    async fn delete_sends_request() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        delete(connection, "from-transit", true).await.unwrap();
        let captured = server
            .state
            .last_delete_policy
            .lock()
            .await
            .clone()
            .unwrap();
        assert_eq!(captured.name, "from-transit");
    }

    #[tokio::test]
    async fn chain_show_global_prints() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        chain_show(connection, None, true).await.unwrap();
    }

    #[tokio::test]
    async fn chain_show_per_neighbor_prints() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        chain_show(connection, Some("10.0.0.2"), true)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn chain_set_global_import_captures_request() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        chain_set(
            connection,
            ChainDirection::Import,
            None,
            vec!["a".to_string(), "b".to_string()],
            true,
        )
        .await
        .unwrap();
        let captured = server
            .state
            .last_set_global_import_chain
            .lock()
            .await
            .clone()
            .unwrap();
        assert_eq!(
            captured.policy_names,
            vec!["a".to_string(), "b".to_string()]
        );
    }

    #[tokio::test]
    async fn chain_set_neighbor_export_captures_request() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        chain_set(
            connection,
            ChainDirection::Export,
            Some("10.0.0.2"),
            vec!["x".to_string()],
            true,
        )
        .await
        .unwrap();
        let captured = server
            .state
            .last_set_neighbor_export_chain
            .lock()
            .await
            .clone()
            .unwrap();
        assert_eq!(captured.address, "10.0.0.2");
        assert_eq!(captured.policy_names, vec!["x".to_string()]);
    }

    #[tokio::test]
    async fn chain_clear_neighbor_import_captures_request() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        chain_clear(connection, ChainDirection::Import, Some("10.0.0.2"), true)
            .await
            .unwrap();
        let captured = server
            .state
            .last_clear_neighbor_import_chain
            .lock()
            .await
            .clone()
            .unwrap();
        assert_eq!(captured.address, "10.0.0.2");
    }
}
