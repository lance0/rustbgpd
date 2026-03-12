use std::fmt::Write as _;
use std::ops::Range;

use toml_edit::ImDocument;

use super::ConfigError;

/// Render a `ConfigError` with source-level context (rustc-style diagnostics).
///
/// For TOML parse errors, uses the span from `toml::de::Error`.
/// For semantic validation errors, uses `toml_edit` to locate the offending
/// key/value in the source document.
///
/// Returns `None` if no source span can be determined (falls back to plain
/// `Display`).
pub fn render_diagnostic(source: &str, path: &str, error: &ConfigError) -> Option<String> {
    let (span, label) = error_span_and_label(source, error)?;
    // For parse errors, use a short heading instead of the full Display
    // (which already contains its own mini-snippet).
    let heading = match error {
        ConfigError::Parse(_) => "failed to parse config".to_string(),
        _ => error.to_string(),
    };
    Some(render_snippet(source, path, span, &heading, &label))
}

/// Map a `ConfigError` to (byte span, underline label) using the TOML source.
fn error_span_and_label(source: &str, error: &ConfigError) -> Option<(Range<usize>, String)> {
    match error {
        ConfigError::Parse(e) => {
            let span = e.span()?;
            Some((span, e.message().to_string()))
        }
        ConfigError::InvalidRouterId { .. } => {
            lookup_value_span(source, &["global", "router_id"], "not a valid IPv4 address")
        }
        ConfigError::InvalidNeighborAddress { value, reason } => {
            find_neighbor_field_span(source, value, "address", reason)
        }
        ConfigError::InvalidPrometheusAddr { .. } => lookup_value_span(
            source,
            &["global", "telemetry", "prometheus_addr"],
            "not a valid socket address",
        ),
        ConfigError::InvalidHoldTime { value } => find_hold_time_span(source, *value),
        ConfigError::InvalidLocalIpv6Nexthop { value, .. } => find_value_anywhere(
            source,
            "local_ipv6_nexthop",
            value,
            "not a valid IPv6 address",
        ),
        ConfigError::InvalidRuntimeStateDir { .. } => lookup_value_span(
            source,
            &["global", "runtime_state_dir"],
            "must not be empty",
        ),
        ConfigError::InvalidGrpcConfig { reason } => {
            if reason.contains("grpc_tcp.address") {
                lookup_key_span(source, &["global", "telemetry", "grpc_tcp"], reason)
            } else if reason.contains("grpc_uds.path") {
                lookup_value_span(source, &["global", "telemetry", "grpc_uds", "path"], reason)
            } else if reason.contains("grpc_uds.mode") {
                lookup_value_span(source, &["global", "telemetry", "grpc_uds", "mode"], reason)
            } else {
                None
            }
        }
        ConfigError::UndefinedPeerGroup { name } => find_value_anywhere(
            source,
            "peer_group",
            name,
            &format!("peer group {name:?} is not defined"),
        ),
        ConfigError::UndefinedPolicy { name } => {
            find_string_in_source(source, name, &format!("policy {name:?} is not defined"))
        }
        ConfigError::InvalidGrConfig { reason } => try_gr_field_span(source, reason),
        ConfigError::InvalidRrConfig { reason } => {
            if reason.contains("cluster_id") {
                lookup_value_span(source, &["global", "cluster_id"], reason)
            } else if reason.contains("route_reflector_client") {
                find_value_anywhere(source, "route_reflector_client", "true", reason)
            } else {
                None
            }
        }
        ConfigError::InvalidRemovePrivateAs { reason } => {
            find_value_anywhere(source, "remove_private_as", "", reason)
        }
        ConfigError::InvalidLogLevel { value } => find_value_anywhere(
            source,
            "log_level",
            value,
            "expected error, warn, info, debug, or trace",
        ),
        _ => None,
    }
}

/// Render a source snippet with an underlined span, rustc-style.
fn render_snippet(
    source: &str,
    path: &str,
    span: Range<usize>,
    heading: &str,
    label: &str,
) -> String {
    let start = span.start.min(source.len());

    let line_num = source[..start].matches('\n').count() + 1;
    let line_start = source[..start].rfind('\n').map_or(0, |i| i + 1);
    let col = start - line_start + 1;

    let line_end = source[start..]
        .find('\n')
        .map_or(source.len(), |i| start + i);
    let line_text = &source[line_start..line_end];

    let span_len = (span.end - span.start).max(1);
    let underline_len = span_len.min(line_end - start).max(1);

    let line_num_width = line_num.to_string().len();
    let pad = " ".repeat(line_num_width);

    let mut out = String::new();
    let _ = writeln!(out, "error: {heading}");
    let _ = writeln!(out, "{pad} --> {path}:{line_num}:{col}");
    let _ = writeln!(out, "{pad} |");
    let _ = writeln!(out, "{line_num} | {line_text}");
    let _ = write!(
        out,
        "{pad} | {}{} {label}",
        " ".repeat(col - 1),
        "^".repeat(underline_len),
    );
    out
}

/// Parse source into an `ImDocument` (preserves spans, unlike `DocumentMut`).
fn parse_im(source: &str) -> Option<ImDocument<String>> {
    ImDocument::parse(source.to_owned()).ok()
}

/// Look up a value span via a dotted key path.
fn lookup_value_span(source: &str, keys: &[&str], label: &str) -> Option<(Range<usize>, String)> {
    let doc = parse_im(source)?;
    let mut item = doc.as_item();
    for key in keys {
        item = item.as_table()?.get(key)?;
    }
    let span = item.span()?;
    Some((span, label.to_string()))
}

/// Look up a key span (the key itself, not the value).
fn lookup_key_span(source: &str, keys: &[&str], label: &str) -> Option<(Range<usize>, String)> {
    let doc = parse_im(source)?;
    let mut table = doc.as_table();
    for (i, key) in keys.iter().enumerate() {
        if i == keys.len() - 1 {
            let (k, _) = table.get_key_value(key)?;
            let span = k.span()?;
            return Some((span, label.to_string()));
        }
        table = table.get(key)?.as_table()?;
    }
    None
}

/// Try to find a span for `field_name` matching `value_hint` across neighbors
/// and peer groups.
fn find_value_anywhere(
    source: &str,
    field_name: &str,
    value_hint: &str,
    label: &str,
) -> Option<(Range<usize>, String)> {
    let doc = parse_im(source)?;

    if let Some(neighbors) = doc.get("neighbors").and_then(|v| v.as_array_of_tables()) {
        for neighbor in neighbors {
            if let Some(span) = match_field_value(neighbor, field_name, value_hint) {
                return Some((span, label.to_string()));
            }
        }
    }

    if let Some(groups) = doc.get("peer_groups").and_then(|v| v.as_table()) {
        for (_, group) in groups {
            if let Some(table) = group.as_table()
                && let Some(span) = match_field_value(table, field_name, value_hint)
            {
                return Some((span, label.to_string()));
            }
        }
    }

    None
}

/// Check if a table has a field matching `value_hint`, returning its span.
fn match_field_value(
    table: &toml_edit::Table,
    field_name: &str,
    value_hint: &str,
) -> Option<Range<usize>> {
    let item = table.get(field_name)?;
    if value_hint.is_empty() || item.to_string().contains(value_hint) {
        item.span()
    } else {
        None
    }
}

/// Find a neighbor by address, then look up a specific field.
fn find_neighbor_field_span(
    source: &str,
    address: &str,
    field_name: &str,
    label: &str,
) -> Option<(Range<usize>, String)> {
    let doc = parse_im(source)?;
    let neighbors = doc.get("neighbors")?.as_array_of_tables()?;
    for neighbor in neighbors {
        if neighbor.get("address")?.as_str()? == address {
            let span = neighbor.get(field_name)?.span()?;
            return Some((span, label.to_string()));
        }
    }
    None
}

/// Find `hold_time` with a specific value.
fn find_hold_time_span(source: &str, value: u16) -> Option<(Range<usize>, String)> {
    let doc = parse_im(source)?;
    let label = "must be 0 or >= 3";
    let target = i64::from(value);

    if let Some(neighbors) = doc.get("neighbors").and_then(|v| v.as_array_of_tables()) {
        for neighbor in neighbors {
            if let Some(item) = neighbor.get("hold_time")
                && item.as_integer() == Some(target)
                && let Some(span) = item.span()
            {
                return Some((span, label.to_string()));
            }
        }
    }

    if let Some(groups) = doc.get("peer_groups").and_then(|v| v.as_table()) {
        for (_, group) in groups {
            if let Some(item) = group.get("hold_time")
                && item.as_integer() == Some(target)
                && let Some(span) = item.span()
            {
                return Some((span, label.to_string()));
            }
        }
    }

    None
}

/// Try to locate a GR-related field from the error reason text.
fn try_gr_field_span(source: &str, reason: &str) -> Option<(Range<usize>, String)> {
    let field = if reason.contains("gr_restart_time") {
        "gr_restart_time"
    } else if reason.contains("gr_stale_routes_time") {
        "gr_stale_routes_time"
    } else if reason.contains("llgr_stale_time") {
        "llgr_stale_time"
    } else {
        return None;
    };
    find_value_anywhere(source, field, "", reason)
}

/// Find a quoted string in the source text (for undefined policy/chain references).
fn find_string_in_source(
    source: &str,
    needle: &str,
    label: &str,
) -> Option<(Range<usize>, String)> {
    let pattern = format!("\"{needle}\"");
    let pos = source.find(&pattern)?;
    let span = pos..pos + pattern.len();
    Some((span, label.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_parse_error() {
        let source = "[global]\nasn = \n";
        let err: ConfigError = toml::from_str::<super::super::Config>(source)
            .unwrap_err()
            .into();
        let rendered = render_diagnostic(source, "config.toml", &err);
        assert!(rendered.is_some());
        let output = rendered.unwrap();
        assert!(output.contains("error:"));
        assert!(output.contains("-->"));
        assert!(output.contains('^'));
    }

    #[test]
    fn render_invalid_hold_time() {
        let source = "\
[global]
asn = 65000
router_id = \"1.2.3.4\"
listen_port = 179
[global.telemetry]
prometheus_addr = \"0.0.0.0:9090\"
log_format = \"text\"

[[neighbors]]
address = \"10.0.0.1\"
remote_asn = 65001
hold_time = 2
";
        let error = ConfigError::InvalidHoldTime { value: 2 };
        let rendered = render_diagnostic(source, "config.toml", &error).unwrap();
        assert!(rendered.contains("hold_time = 2"), "got: {rendered}");
        assert!(rendered.contains('^'), "got: {rendered}");
        assert!(rendered.contains("must be 0 or >= 3"), "got: {rendered}");
    }

    #[test]
    fn render_invalid_router_id() {
        let source = "\
[global]
asn = 65000
router_id = \"not-an-ip\"
listen_port = 179
[global.telemetry]
prometheus_addr = \"0.0.0.0:9090\"
log_format = \"text\"
";
        let error = ConfigError::InvalidRouterId {
            value: "not-an-ip".to_string(),
            reason: "invalid IPv4 address syntax".to_string(),
        };
        let rendered = render_diagnostic(source, "config.toml", &error).unwrap();
        assert!(rendered.contains("not-an-ip"), "got: {rendered}");
        assert!(rendered.contains('^'), "got: {rendered}");
    }

    #[test]
    fn render_snippet_format() {
        let source = "aaa\nbbb\nhold_time = 2\nccc\n";
        let offset = source.find("= 2").unwrap() + 2;
        let output = render_snippet(
            source,
            "test.toml",
            offset..offset + 1,
            "bad value",
            "must be >= 3",
        );
        assert!(output.contains("error: bad value"), "got: {output}");
        assert!(output.contains("--> test.toml:3:"), "got: {output}");
        assert!(output.contains("hold_time = 2"), "got: {output}");
        assert!(output.contains("^ must be >= 3"), "got: {output}");
    }

    #[test]
    fn returns_none_for_io_error() {
        let error = ConfigError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "not found",
        ));
        assert!(render_diagnostic("", "config.toml", &error).is_none());
    }

    #[test]
    fn full_load_with_diagnostics_invalid_hold_time() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "\
[global]
asn = 65000
router_id = \"1.2.3.4\"
listen_port = 179
[global.telemetry]
prometheus_addr = \"0.0.0.0:9090\"
log_format = \"text\"

[[neighbors]]
address = \"10.0.0.1\"
remote_asn = 65001
hold_time = 2
",
        )
        .unwrap();
        let err = super::super::Config::load_with_diagnostics(path.to_str().unwrap()).unwrap_err();
        assert!(err.contains("hold_time = 2"), "got: {err}");
        assert!(err.contains("must be 0 or >= 3"), "got: {err}");
        assert!(err.contains('^'), "got: {err}");
    }
}
