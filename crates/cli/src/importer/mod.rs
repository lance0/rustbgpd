//! `rbgp config import` — a deliberately bounded structural importer
//! for BIRD 2/3, FRR (vtysh running-config style), and GoBGP TOML
//! configurations.
//!
//! The importer translates only the structural subset every BGP daemon
//! shares: local AS, router-id, neighbors (address, remote AS,
//! description), peer groups, address families, hold timers, and
//! max-prefix limits. It never guesses at policy: BIRD filters, FRR
//! route-maps/prefix-lists, and GoBGP policy-definitions are listed —
//! with source line numbers — in the import report for hand-translation
//! to `.rpol`. Secrets are never imported: MD5/auth *presence* is
//! flagged (report warning + commented placeholder in the emitted
//! config), the secret itself never leaves the source file.
//!
//! Exit-code ladder (mirrors the `rs-config-render` distinct-exit-code
//! convention):
//!
//! | code | meaning                                                    |
//! |------|------------------------------------------------------------|
//! | 0    | clean full structural translation (no warnings or skips)   |
//! | 1    | error: unreadable source, unrecognized format, parse error |
//! | 2    | translated with warnings/skips (config written; review it) |
//! | 3    | refused: no translatable BGP structure in the source       |
//!
//! Anything requiring operator attention is non-zero by construction: a
//! silent partial or placeholder-bearing translation would be worse than an
//! explicit review result.

pub mod bird;
pub mod frr;
pub mod gobgp;

use std::fmt::Write as _;
use std::io::Write as IoWrite;

use serde::Serialize;

/// Guidance attached to every skipped policy stanza.
pub const RPOL_GUIDANCE: &str = "hand-translate to .rpol; see docs/rpol-language.md";
/// Guidance for structural stanzas outside the bounded subset.
pub const GENERIC_GUIDANCE: &str = "outside the structural subset; carry over by hand if needed";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceFormat {
    Bird,
    Frr,
    Gobgp,
}

impl SourceFormat {
    pub fn name(self) -> &'static str {
        match self {
            SourceFormat::Bird => "BIRD 2/3",
            SourceFormat::Frr => "FRR",
            SourceFormat::Gobgp => "GoBGP",
        }
    }
}

/// One source stanza the importer refused to translate.
#[derive(Debug, Clone, Serialize)]
pub struct Skip {
    /// 1-based source line, when the format preserves one.
    pub line: Option<usize>,
    /// The stanza (or its header line) as it appears in the source.
    pub stanza: String,
    /// What to do instead.
    pub guidance: String,
}

/// Intermediate parse result shared by the three format frontends.
#[derive(Debug, Default)]
pub struct Model {
    pub local_asn: Option<u32>,
    pub router_id: Option<String>,
    pub groups: Vec<Group>,
    pub neighbors: Vec<Neighbor>,
    pub skips: Vec<Skip>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Default)]
pub struct Group {
    pub name: String,
    /// Group-level remote AS (FRR peer-groups, GoBGP peer-groups).
    /// rustbgpd has no group-level `remote_asn`, so this is resolved
    /// down onto member neighbors at emit time.
    pub remote_asn: Option<u32>,
    pub hold_time: Option<u16>,
    pub families: Vec<String>,
    pub max_prefixes_ipv4: Option<u32>,
    pub max_prefixes_ipv6: Option<u32>,
    /// Source configures MD5/auth on the group. Never carries the secret.
    pub auth_present: bool,
}

#[derive(Debug, Default)]
pub struct Neighbor {
    pub address: String,
    /// 1-based source line the neighbor was declared on (0 = unknown).
    pub source_line: usize,
    pub remote_asn: Option<u32>,
    pub description: Option<String>,
    pub peer_group: Option<String>,
    pub hold_time: Option<u16>,
    pub families: Vec<String>,
    pub max_prefixes_ipv4: Option<u32>,
    pub max_prefixes_ipv6: Option<u32>,
    /// Source configures MD5/auth for this session. Never carries the secret.
    pub auth_present: bool,
}

#[derive(Debug)]
pub enum ImportError {
    /// Source unreadable. Exit 1.
    Read(String),
    /// Source format could not be determined. Exit 1.
    Format(String),
    /// Source is not parseable as the (detected or forced) format. Exit 1.
    Parse(String),
    /// No translatable BGP structure (no local AS / no neighbors). Exit 3.
    Empty(Vec<String>),
}

impl ImportError {
    pub fn exit_code(&self) -> i32 {
        match self {
            ImportError::Read(_) | ImportError::Format(_) | ImportError::Parse(_) => 1,
            ImportError::Empty(_) => 3,
        }
    }
}

impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImportError::Read(msg) => write!(f, "cannot read source: {msg}"),
            ImportError::Format(msg) => write!(f, "cannot determine source format: {msg}"),
            ImportError::Parse(msg) => write!(f, "source parse error: {msg}"),
            ImportError::Empty(items) => {
                writeln!(f, "import refused — no translatable BGP structure:")?;
                for item in items {
                    writeln!(f, "  - {item}")?;
                }
                write!(f, "nothing written")
            }
        }
    }
}

impl std::error::Error for ImportError {}

/// The import report — the honesty half of the product. Serialized as
/// JSON under `--json`, rendered as text otherwise.
#[derive(Debug, Serialize)]
pub struct Report {
    pub source_format: &'static str,
    pub source_path: String,
    pub local_asn: u32,
    pub router_id: String,
    /// True when the source carried no router-id and a documentation
    /// placeholder (192.0.2.1) was emitted instead.
    pub router_id_placeholder: bool,
    pub neighbor_count: usize,
    pub peer_group_count: usize,
    /// The emitted `[global]` sets `ebgp_requires_policy = true`. Reported
    /// because it changes runtime behavior: it is not a knob the source
    /// config asked for, and a daemon that carries no routes until policy
    /// exists must not be a surprise after an import.
    pub ebgp_requires_policy: bool,
    pub warnings: Vec<String>,
    pub skipped: Vec<Skip>,
    pub exit_code: i32,
}

impl Report {
    pub fn exit_code(&self) -> i32 {
        if self.skipped.is_empty() && self.warnings.is_empty() {
            0
        } else {
            2
        }
    }

    pub fn render_text(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "import report — {} source {}",
            self.source_format, self.source_path
        );
        let _ = writeln!(
            out,
            "translated: local AS {}, router-id {}{}, {} neighbor(s), {} peer group(s)",
            self.local_asn,
            self.router_id,
            if self.router_id_placeholder {
                " (PLACEHOLDER — source had none; set before deploying)"
            } else {
                ""
            },
            self.neighbor_count,
            self.peer_group_count,
        );
        if self.ebgp_requires_policy {
            let _ = writeln!(
                out,
                "\nfail-closed: the emitted [global] sets ebgp_requires_policy = true, which\n\
                 the source config did not ask for. Policy is never translated, so without it\n\
                 every eBGP session below would come up permit-all in both directions. With it,\n\
                 each eBGP direction that resolves no explicit policy carries no routes at all\n\
                 (RFC 8212 reserved deny) until you configure one. Remove the line from the\n\
                 emitted config to run permit-all instead; it is startup-only, so changing it\n\
                 later needs a daemon restart rather than a reload."
            );
        }
        if !self.warnings.is_empty() {
            let _ = writeln!(out, "\nwarnings:");
            for warning in &self.warnings {
                let _ = writeln!(out, "  - {warning}");
            }
        }
        if !self.skipped.is_empty() {
            let _ = writeln!(
                out,
                "\nnot translated (policy is never guessed; hand-translate, then re-run \
                 `rustbgpd --check`):"
            );
            for skip in &self.skipped {
                match skip.line {
                    Some(line) => {
                        let _ = writeln!(out, "  line {line}: {} — {}", skip.stanza, skip.guidance);
                    }
                    None => {
                        let _ = writeln!(out, "  {} — {}", skip.stanza, skip.guidance);
                    }
                }
            }
        }
        let _ = writeln!(
            out,
            "\nresult: {} (exit {})",
            match self.exit_code() {
                0 => "clean full structural translation",
                _ => "translated with warnings/skips; review required",
            },
            self.exit_code()
        );
        out
    }
}

#[derive(Debug)]
pub struct Imported {
    pub config_toml: String,
    pub report: Report,
}

/// Detect the source format from content (extension is only a hint —
/// FRR and BIRD both conventionally use `.conf`).
pub fn detect_format(path: &str, contents: &str) -> Result<SourceFormat, ImportError> {
    if path.ends_with(".toml") || contents.contains("[global.config]") {
        return Ok(SourceFormat::Gobgp);
    }
    if contents
        .lines()
        .any(|l| l.trim().starts_with("router bgp "))
    {
        return Ok(SourceFormat::Frr);
    }
    if contents.contains("protocol bgp") || contents.contains("template bgp") {
        return Ok(SourceFormat::Bird);
    }
    Err(ImportError::Format(format!(
        "{path} does not look like BIRD 2/3 (`protocol bgp`), FRR (`router bgp`), or GoBGP \
         TOML (`[global.config]`); pass --format to force one"
    )))
}

/// Parse and translate one source. `source_path` is used only for
/// labels in the emitted header and report.
pub fn import_source(
    format: SourceFormat,
    source_path: &str,
    contents: &str,
) -> Result<Imported, ImportError> {
    let model = match format {
        SourceFormat::Bird => bird::parse(contents),
        SourceFormat::Frr => frr::parse(contents),
        SourceFormat::Gobgp => gobgp::parse(contents)?,
    };
    finish(format, source_path, model)
}

fn finish(
    format: SourceFormat,
    source_path: &str,
    mut model: Model,
) -> Result<Imported, ImportError> {
    let Some(local_asn) = model.local_asn else {
        let mut items = vec![format!(
            "no local AS found in the {} source (router bgp / local as / global.config.as)",
            format.name()
        )];
        // Frontend warnings (an out-of-range `as`, for one) explain *why*
        // there is no local AS; a refusal must not swallow them.
        items.append(&mut model.warnings);
        return Err(ImportError::Empty(items));
    };
    if local_asn == 0 {
        model.warnings.push(
            "local AS 0 is reserved; emitted verbatim — `rustbgpd --check` rejects this \
             config until a non-zero ASN is configured"
                .to_owned(),
        );
    }

    // Resolve remote AS down from groups (rustbgpd peer groups carry no
    // remote_asn) and drop neighbors that cannot be emitted, moving
    // each to the skip list — a neighbor silently dropped would be a
    // lie, a neighbor emitted without a remote AS fails `--check`.
    let mut neighbors = Vec::new();
    let mut seen_neighbor_addresses = std::collections::HashSet::new();
    for mut neighbor in std::mem::take(&mut model.neighbors) {
        let Ok(address) = neighbor.address.parse::<std::net::IpAddr>() else {
            model.skips.push(Skip {
                line: line_opt(neighbor.source_line),
                stanza: format!("neighbor {}", neighbor.address),
                guidance: "address is not an IP literal (unresolved peer-group reference or \
                           interface peer?); declare the session by hand"
                    .to_owned(),
            });
            continue;
        };
        if neighbor.remote_asn.is_none() {
            neighbor.remote_asn = neighbor
                .peer_group
                .as_ref()
                .and_then(|g| model.groups.iter().find(|group| &group.name == g))
                .and_then(|group| group.remote_asn);
        }
        if neighbor.remote_asn.is_none() {
            model.skips.push(Skip {
                line: line_opt(neighbor.source_line),
                stanza: format!("neighbor {}", neighbor.address),
                guidance: "remote AS is not determinable from the source (rustbgpd requires \
                           `remote_asn`); declare the session by hand"
                    .to_owned(),
            });
            continue;
        }
        if matches!(address, std::net::IpAddr::V6(ip) if ip.is_unicast_link_local()) {
            model.warnings.push(format!(
                "neighbor {} is IPv6 link-local, but the importer cannot preserve its \
                 required interface scope; emitted without an interface — `rustbgpd \
                 --check` rejects this config until the interface is added",
                neighbor.address
            ));
        }
        if !seen_neighbor_addresses.insert(address) {
            model.warnings.push(format!(
                "duplicate neighbor {} resolves to the same IP address as an earlier \
                 neighbor; emitted verbatim — `rustbgpd --check` rejects duplicate \
                 neighbor identities until one is removed",
                neighbor.address
            ));
        }
        if neighbor.remote_asn == Some(0) {
            model.warnings.push(format!(
                "neighbor {}: remote AS 0 is reserved; emitted verbatim — `rustbgpd \
                 --check` rejects this config until a non-zero remote_asn is configured",
                neighbor.address
            ));
        }
        if let Some(hold) = neighbor.hold_time
            && hold != 0
            && hold < 3
        {
            model.warnings.push(format!(
                "neighbor {}: hold time {hold} raised to the protocol minimum 3",
                neighbor.address
            ));
            neighbor.hold_time = Some(3);
        }
        dedupe(&mut neighbor.families);
        neighbors.push(neighbor);
    }
    if neighbors.is_empty() {
        let mut items = vec![format!(
            "no translatable neighbors found in the {} source",
            format.name()
        )];
        items.append(&mut model.warnings);
        return Err(ImportError::Empty(items));
    }
    let mut seen_group_names = std::collections::HashSet::new();
    for group in &mut model.groups {
        if !seen_group_names.insert(group.name.clone()) {
            model.warnings.push(format!(
                "duplicate peer group {:?} would emit the same TOML table twice; \
                 `rustbgpd --check` rejects this config until one definition is removed",
                group.name
            ));
        }
        if let Some(hold) = group.hold_time
            && hold != 0
            && hold < 3
        {
            model.warnings.push(format!(
                "peer group {}: hold time {hold} raised to the protocol minimum 3",
                group.name
            ));
            group.hold_time = Some(3);
        }
        dedupe(&mut group.families);
    }

    // Fail closed on fields the daemon's `--check` rejects wholesale: a
    // clean exit alongside a translation validation refuses would break
    // the ladder's "operator attention is non-zero by construction"
    // contract. The values are still emitted verbatim — the report names
    // them, the exit code forces the review.
    if let Some(id) = &model.router_id {
        match id.parse::<std::net::Ipv4Addr>() {
            Ok(ip) if !ip.is_unspecified() => {}
            _ => model.warnings.push(format!(
                "router-id {id:?} is not a usable IPv4 router_id (rustbgpd requires a \
                 non-zero IPv4 address); emitted verbatim — `rustbgpd --check` rejects \
                 this config until it is corrected"
            )),
        }
    }
    for neighbor in &neighbors {
        if let Some(group) = &neighbor.peer_group
            && !model.groups.iter().any(|g| &g.name == group)
        {
            model.warnings.push(format!(
                "neighbor {}: peer_group {group:?} does not match any translated peer \
                 group; emitted verbatim — `rustbgpd --check` rejects this config until \
                 the group is defined or the reference removed",
                neighbor.address
            ));
        }
    }

    let router_id_placeholder = model.router_id.is_none();
    let router_id = model.router_id.take().unwrap_or_else(|| {
        model.warnings.push(
            "source has no router-id (the source daemon derives one from an interface); \
             emitted the documentation placeholder 192.0.2.1 — set a real router_id before \
             deploying"
                .to_owned(),
        );
        "192.0.2.1".to_owned()
    });

    for neighbor in &neighbors {
        if neighbor.auth_present {
            model.warnings.push(format!(
                "neighbor {}: source configures TCP MD5/auth; secrets are never imported — \
                 set md5_password manually",
                neighbor.address
            ));
        }
    }
    for group in &model.groups {
        if group.auth_present {
            model.warnings.push(format!(
                "peer group {}: source configures TCP MD5/auth; secrets are never imported — \
                 set md5_password manually",
                group.name
            ));
        }
    }

    // Deterministic report order: by source line, un-lined entries last.
    model.skips.sort_by_key(|s| s.line.unwrap_or(usize::MAX));

    let config_toml = emit_toml(
        format,
        source_path,
        local_asn,
        &router_id,
        router_id_placeholder,
        &model.groups,
        &neighbors,
    );
    let mut report = Report {
        source_format: format.name(),
        source_path: source_path.to_owned(),
        local_asn,
        router_id,
        router_id_placeholder,
        neighbor_count: neighbors.len(),
        peer_group_count: model.groups.len(),
        // Unconditional: `emit_toml` always writes the knob. A source with
        // only iBGP neighbors is unaffected by it, so there is nothing to
        // gate on.
        ebgp_requires_policy: true,
        warnings: model.warnings,
        skipped: model.skips,
        exit_code: 0,
    };
    report.exit_code = report.exit_code();
    Ok(Imported {
        config_toml,
        report,
    })
}

fn line_opt(line: usize) -> Option<usize> {
    if line == 0 { None } else { Some(line) }
}

fn dedupe(families: &mut Vec<String>) {
    let mut seen = std::collections::BTreeSet::new();
    families.retain(|f| seen.insert(f.clone()));
}

fn toml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => {
                let _ = write!(out, "\\u{:04X}", u32::from(ch));
            }
            ch => out.push(ch),
        }
    }
    out
}

fn write_families(out: &mut String, families: &[String]) {
    if families.is_empty() {
        return;
    }
    let list = families
        .iter()
        .map(|f| format!("\"{}\"", toml_escape(f)))
        .collect::<Vec<_>>()
        .join(", ");
    let _ = writeln!(out, "families = [{list}]");
}

const AUTH_COMMENT: &str = "# The source configures TCP MD5/auth here. Secrets are never \
                            imported —\n# set the real secret before deploying:\n\
                            # md5_password = \"<set manually>\"\n";

/// RFC 8212 fail-closed, emitted into every generated `[global]`.
///
/// The importer translates no policy by construction, so an eBGP session in a
/// generated config would otherwise come up permit-all in both directions —
/// the daemon would accept and re-advertise everything a peer sends, and
/// `rustbgpd --check` would still pass (a permit-all route server is a
/// legitimate configuration). Setting this makes the generated config fail
/// closed instead: each eBGP direction with no explicit policy runs the
/// reserved internal deny until an operator configures one.
const EBGP_REQUIRES_POLICY_BLOCK: &str = "\
# RFC 8212 fail-closed (ADR-0112). This config was generated by an importer
# that never translates policy, so nothing here filters anything yet. With
# this set, every eBGP direction that resolves no explicit policy carries no
# routes at all — a deliberately empty session beats a silently wide-open
# one. Each direction starts passing traffic as you configure its
# import_policy_chain / export_policy_chain. Remove this line to run
# permit-all instead. Startup-only: changing it needs a daemon restart, not
# a reload.
ebgp_requires_policy = true
";

fn emit_toml(
    format: SourceFormat,
    source_path: &str,
    local_asn: u32,
    router_id: &str,
    router_id_placeholder: bool,
    groups: &[Group],
    neighbors: &[Neighbor],
) -> String {
    // Label with the basename only: config headers must not leak
    // operator filesystem layout when the file is shared.
    let source_label = source_path.rsplit('/').next().unwrap_or(source_path);
    let mut out = format!(
        "# GENERATED by `rbgp config import` — structural translation of {source_label} \
         ({}).\n\
         # Routing POLICY IS NOT translated: every untranslated stanza is listed in\n\
         # the import report (re-run the import to reproduce it). Hand-translate\n\
         # policy to .rpol (docs/rpol-language.md), then validate with\n\
         # `rustbgpd --check` before use.\n",
        format.name()
    );

    let _ = write!(out, "\n[global]\nasn = {local_asn}\n");
    if router_id_placeholder {
        out.push_str("# PLACEHOLDER — the source carried no router-id; set a real one.\n");
    }
    let _ = writeln!(out, "router_id = \"{}\"", toml_escape(router_id));
    out.push_str("listen_port = 179\n");
    out.push_str(EBGP_REQUIRES_POLICY_BLOCK);
    out.push_str(
        "\n# Local management surface (`rbgp` over UDS, file-permission gated) —\n\
         # the same shape as examples/minimal/. Add prometheus_addr here to\n\
         # scrape metrics.\n\
         [global.telemetry]\nlog_format = \"json\"\n\n\
         [global.telemetry.grpc_uds]\npath = \"/var/lib/rustbgpd/grpc.sock\"\nprincipal = \"operator\"\n\n\
         [security.grpc]\nenforcement = \"tier\"\n\n\
         [security.grpc.roles]\noperator = \"operator\"\n",
    );

    for group in groups {
        let _ = write!(out, "\n[peer_groups.\"{}\"]\n", toml_escape(&group.name));
        if let Some(hold) = group.hold_time {
            let _ = writeln!(out, "hold_time = {hold}");
        }
        write_families(&mut out, &group.families);
        if let Some(limit) = group.max_prefixes_ipv4 {
            let _ = writeln!(out, "max_prefixes_ipv4 = {limit}");
        }
        if let Some(limit) = group.max_prefixes_ipv6 {
            let _ = writeln!(out, "max_prefixes_ipv6 = {limit}");
        }
        if group.auth_present {
            out.push_str(AUTH_COMMENT);
        }
    }

    for neighbor in neighbors {
        let _ = write!(
            out,
            "\n[[neighbors]]\naddress = \"{}\"\nremote_asn = {}\n",
            toml_escape(&neighbor.address),
            neighbor.remote_asn.expect("resolved before emit"),
        );
        if let Some(description) = &neighbor.description {
            let _ = writeln!(out, "description = \"{}\"", toml_escape(description));
        }
        if let Some(group) = &neighbor.peer_group {
            let _ = writeln!(out, "peer_group = \"{}\"", toml_escape(group));
        }
        if let Some(hold) = neighbor.hold_time {
            let _ = writeln!(out, "hold_time = {hold}");
        }
        write_families(&mut out, &neighbor.families);
        if let Some(limit) = neighbor.max_prefixes_ipv4 {
            let _ = writeln!(out, "max_prefixes_ipv4 = {limit}");
        }
        if let Some(limit) = neighbor.max_prefixes_ipv6 {
            let _ = writeln!(out, "max_prefixes_ipv6 = {limit}");
        }
        if neighbor.auth_present {
            out.push_str(AUTH_COMMENT);
        }
    }
    out
}

/// CLI entry: read, translate, write, report. Returns the process exit
/// code per the module-level ladder.
pub fn run_import(source: &str, format: Option<&str>, out: Option<&str>, json: bool) -> i32 {
    let stdout = std::io::stdout();
    run_import_with_writer(source, format, out, json, &mut stdout.lock())
}

fn run_import_with_writer(
    source: &str,
    format: Option<&str>,
    out: Option<&str>,
    json: bool,
    stdout: &mut dyn IoWrite,
) -> i32 {
    if json && out.is_none() {
        eprintln!(
            "error: --json prints the import report on stdout; pass --out PATH for the \
             translated config"
        );
        return 1;
    }
    let contents = match std::fs::read_to_string(source) {
        Ok(contents) => contents,
        Err(e) => {
            eprintln!("error: cannot read {source}: {e}");
            return 1;
        }
    };
    let detected = match format {
        Some("bird") => Ok(SourceFormat::Bird),
        Some("frr") => Ok(SourceFormat::Frr),
        Some("gobgp") => Ok(SourceFormat::Gobgp),
        Some(other) => Err(ImportError::Format(format!(
            "unknown format {other:?} (expected bird, frr, or gobgp)"
        ))),
        None => detect_format(source, &contents),
    };
    let imported = detected.and_then(|f| import_source(f, source, &contents));
    let imported = match imported {
        Ok(imported) => imported,
        Err(e) => {
            eprintln!("error: {e}");
            return e.exit_code();
        }
    };
    match out {
        Some(path) => {
            if let Err(e) = std::fs::write(path, &imported.config_toml) {
                eprintln!("error: cannot write {path}: {e}");
                return 1;
            }
        }
        None => {
            if let Err(error) = stdout
                .write_all(imported.config_toml.as_bytes())
                .and_then(|()| stdout.flush())
            {
                if error.kind() != std::io::ErrorKind::BrokenPipe {
                    eprintln!("error: cannot write imported config: {error}");
                }
                return 1;
            }
        }
    }
    if json {
        let rendered = match serde_json::to_string_pretty(&imported.report) {
            Ok(rendered) => rendered,
            Err(error) => {
                eprintln!("error: cannot encode import JSON output: {error}");
                return 1;
            }
        };
        if let Err(error) = stdout
            .write_all(rendered.as_bytes())
            .and_then(|()| stdout.write_all(b"\n"))
            .and_then(|()| stdout.flush())
        {
            if error.kind() != std::io::ErrorKind::BrokenPipe {
                eprintln!("error: cannot write import JSON output: {error}");
            }
            return 1;
        }
    } else {
        eprint!("{}", imported.report.render_text());
    }
    imported.report.exit_code()
}

#[cfg(test)]
mod writer_tests {
    use super::*;

    const FRR: &str = include_str!("../../tests/fixtures/import/frr.conf");

    fn paths() -> (tempfile::TempDir, String, String) {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("frr.conf");
        let out = dir.path().join("rustbgpd.toml");
        std::fs::write(&source, FRR).unwrap();
        (
            dir,
            source.to_str().unwrap().to_string(),
            out.to_str().unwrap().to_string(),
        )
    }

    #[test]
    fn json_report_writer_preserves_pretty_bytes_and_one_newline() {
        let (_dir, source, out) = paths();
        let expected = import_source(SourceFormat::Frr, &source, FRR).unwrap();
        let expected = format!(
            "{}\n",
            serde_json::to_string_pretty(&expected.report).unwrap()
        );
        let mut bytes = Vec::new();

        let code = run_import_with_writer(&source, None, Some(&out), true, &mut bytes);

        assert_eq!(code, 2);
        assert_eq!(bytes, expected.as_bytes());
    }

    struct BrokenWriter;

    impl IoWrite for BrokenWriter {
        fn write(&mut self, _bytes: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn json_report_write_failure_exits_one() {
        let (_dir, source, out) = paths();
        assert_eq!(
            run_import_with_writer(&source, None, Some(&out), true, &mut BrokenWriter),
            1
        );
    }

    struct FlushFailure;

    impl IoWrite for FlushFailure {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::other("flush failed"))
        }
    }

    #[test]
    fn json_report_flush_failure_exits_one() {
        let (_dir, source, out) = paths();
        assert_eq!(
            run_import_with_writer(&source, None, Some(&out), true, &mut FlushFailure),
            1
        );
    }

    #[test]
    fn config_stdout_preserves_bytes_and_rejects_write_failures() {
        let (_dir, source, _out) = paths();
        let expected = import_source(SourceFormat::Frr, &source, FRR).unwrap();
        let mut bytes = Vec::new();
        assert_eq!(
            run_import_with_writer(&source, None, None, false, &mut bytes),
            2
        );
        assert_eq!(bytes, expected.config_toml.as_bytes());
        assert_eq!(
            run_import_with_writer(&source, None, None, false, &mut BrokenWriter),
            1
        );
        assert_eq!(
            run_import_with_writer(&source, None, None, false, &mut FlushFailure),
            1
        );
    }
}
