#!/usr/bin/env python3
"""Validate the shipped Grafana dashboard's load-bearing operator views."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "docs/grafana/rustbgpd-overview.json"
METRICS = ROOT / "crates/telemetry/src/metrics.rs"

VARIABLES = {
    "peer": 'label_values(bgp_peer_admin_enabled{instance=~"$instance"}, peer)',
}

TARGETS = {
    ("Peer administrative / session truth", "A"): (
        'bgp_peer_admin_enabled{instance=~"$instance",peer=~"$peer"}'
    ),
    ("Peer administrative / session truth", "B"): (
        'bgp_peer_session_established{instance=~"$instance",peer=~"$peer"}'
    ),
    ("Outbound queue by peer", "A"): (
        'bgp_peer_outbound_queue_depth{instance=~"$instance",peer=~"$peer"}'
    ),
    ("Event outbox health", "A"): (
        'max(bgp_event_outbox_degraded{instance=~"$instance"})'
    ),
    ("RIB ingest pressure", "B"): (
        "sum by (peer) (rate(bgp_inbound_rib_backpressure_total"
        '{instance=~"$instance",peer=~"$peer"}[$__rate_interval]))'
    ),
    ("RIB ingest pressure", "C"): (
        "sum by (peer) (rate(bgp_outbound_route_drops_total"
        '{instance=~"$instance",peer=~"$peer"}[$__rate_interval]))'
    ),
    ("Slow peers", "A"): (
        'bgp_peer_slow{instance=~"$instance",peer=~"$peer"}'
    ),
    ("Update group by peer", "A"): (
        'bgp_peer_update_group{instance=~"$instance",peer=~"$peer"}'
    ),
    ("Policy transition in progress", "A"): (
        'bgp_rib_policy_transition_in_progress{instance=~"$instance"}'
    ),
    ("Last completed policy transition", "A"): (
        'bgp_rib_policy_transition_last_duration_milliseconds{instance=~"$instance"}'
    ),
    ("Policy-transition actor poll p99", "A"): (
        "histogram_quantile(0.99, sum by (instance, job, poll_kind, le) "
        "(rate(bgp_rib_policy_transition_actor_poll_duration_seconds_bucket"
        '{instance=~"$instance"}[15m])))'
    ),
    ("Policy-transition actor polls over 200ms", "A"): (
        "increase(bgp_rib_policy_transition_actor_poll_duration_seconds_count"
        '{instance=~"$instance"}[15m]) - ignoring(le) '
        "increase(bgp_rib_policy_transition_actor_poll_duration_seconds_bucket"
        '{instance=~"$instance",le="0.2"}[15m])'
    ),
    ("Accepted policy generation age", "A"): (
        "clamp_min(time() - bgp_policy_generation_loaded_timestamp_seconds"
        '{instance=~"$instance"}, 0)'
    ),
    ("Max-prefix usage and finite limit", "A"): (
        'bgp_max_prefix_usage{instance=~"$instance",peer=~"$peer"}'
    ),
    ("Max-prefix usage and finite limit", "B"): (
        'bgp_max_prefix_limit{instance=~"$instance",peer=~"$peer"}'
    ),
    ("Max-prefix remaining headroom", "A"): (
        'bgp_max_prefix_headroom{instance=~"$instance",peer=~"$peer"}'
    ),
    ("Export rejections / malformed UPDATEs", "A"): (
        "sum by (instance, peer, family, reason) "
        "(rate(bgp_exact_export_rejections_total"
        '{instance=~"$instance",peer=~"$peer"}[$__rate_interval])) > 0'
    ),
    ("Export rejections / malformed UPDATEs", "B"): (
        "sum by (instance, peer, disposition) (rate(bgp_update_malformed_total"
        '{instance=~"$instance",peer=~"$peer"}[$__rate_interval])) > 0'
    ),
    ("Selection-deferral state", "A"): (
        'bgp_selection_deferral_active{instance=~"$instance"}'
    ),
    ("Selection-deferral state", "B"): (
        'bgp_selection_deferral_waiters{instance=~"$instance"}'
    ),
    ("Selection-deferral exceptional events", "A"): (
        "sum by (instance, afi_safi) (rate(bgp_selection_deferral_timeouts_total"
        '{instance=~"$instance"}[$__rate_interval])) > 0'
    ),
    ("Selection-deferral exceptional events", "B"): (
        "sum by (instance, afi_safi) "
        "(rate(bgp_selection_deferral_ledger_overflows_total"
        '{instance=~"$instance"}[$__rate_interval])) > 0'
    ),
    ("RFC 8212 missing policy", "A"): (
        'bgp_rfc8212_missing_import_policy{instance=~"$instance",peer=~"$peer"}'
    ),
    ("RFC 8212 missing policy", "B"): (
        'bgp_rfc8212_missing_export_policy{instance=~"$instance",peer=~"$peer"}'
    ),
    ("Outbound prefix capacity", "A"): (
        'bgp_outbound_prefix_usage{instance=~"$instance",peer=~"$peer"}'
    ),
    ("Outbound prefix capacity", "B"): (
        'bgp_outbound_prefix_limit{instance=~"$instance",peer=~"$peer"}'
    ),
    ("Outbound prefix capacity", "C"): (
        'bgp_outbound_prefix_headroom{instance=~"$instance",peer=~"$peer"}'
    ),
    ("Outbound prefix capacity", "D"): (
        'bgp_outbound_prefix_blocking{instance=~"$instance",peer=~"$peer"}'
    ),
    ("Dynamic-neighbor admission capacity", "A"): (
        'bgp_dynamic_neighbor_slots_used{instance=~"$instance"}'
    ),
    ("Dynamic-neighbor admission capacity", "B"): (
        'bgp_dynamic_neighbor_slots_limit{instance=~"$instance"}'
    ),
    ("Dynamic-neighbor admission capacity", "C"): (
        'bgp_dynamic_neighbor_slots_headroom{instance=~"$instance"}'
    ),
    ("Dynamic-neighbor admission rejections", "A"): (
        "rate(bgp_dynamic_neighbor_limit_rejections_total"
        '{instance=~"$instance"}[$__rate_interval]) > 0'
    ),
    ("ORR SPF activity and topology", "A"): (
        "sum by (instance) (rate(bgp_orr_spf_runs_total"
        '{instance=~"$instance"}[$__rate_interval]))'
    ),
    ("ORR SPF activity and topology", "B"): (
        'bgp_orr_topology_nodes{instance=~"$instance"}'
    ),
    ("ORR SPF activity and topology", "C"): (
        'bgp_orr_topology_links{instance=~"$instance"}'
    ),
    ("BLACKHOLE discard activity", "A"): (
        "rate(bgp_blackhole_discard_installed_total"
        '{instance=~"$instance"}[$__rate_interval])'
    ),
    ("BLACKHOLE discard activity", "B"): (
        "rate(bgp_blackhole_discard_withdrawn_total"
        '{instance=~"$instance"}[$__rate_interval])'
    ),
}

REQUIRED_LEGENDS = {
    ("Peer administrative / session truth", "A"): "admin {{peer}} {{interface}}",
    ("Peer administrative / session truth", "B"): "session {{peer}} {{interface}}",
    ("Export rejections / malformed UPDATEs", "A"): (
        "exact {{instance}} {{peer}} {{family}} {{reason}}"
    ),
    ("Export rejections / malformed UPDATEs", "B"): (
        "malformed {{instance}} {{peer}} {{disposition}}"
    ),
    ("Selection-deferral state", "A"): "{{instance}} {{afi_safi}} active",
    ("Selection-deferral state", "B"): "{{instance}} {{afi_safi}} waiters",
    ("Selection-deferral exceptional events", "A"): "{{instance}} {{afi_safi}} timeout",
    ("Selection-deferral exceptional events", "B"): (
        "{{instance}} {{afi_safi}} ledger overflow"
    ),
    ("RFC 8212 missing policy", "A"): "{{peer}} missing import",
    ("RFC 8212 missing policy", "B"): "{{peer}} missing export",
    ("Outbound prefix capacity", "A"): "{{peer}} {{family}} usage",
    ("Outbound prefix capacity", "B"): "{{peer}} {{family}} limit",
    ("Outbound prefix capacity", "C"): "{{peer}} {{family}} headroom",
    ("Outbound prefix capacity", "D"): "{{peer}} {{family}} blocking",
    ("Dynamic-neighbor admission capacity", "A"): "{{instance}} used",
    ("Dynamic-neighbor admission capacity", "B"): "{{instance}} limit",
    ("Dynamic-neighbor admission capacity", "C"): "{{instance}} headroom",
    ("Dynamic-neighbor admission rejections", "A"): "{{instance}} rejected",
    ("RIB ingest pressure", "B"): "inbound safely parked {{peer}}",
    ("RIB ingest pressure", "C"): "outbound work lost {{peer}}",
    ("ORR SPF activity and topology", "A"): "{{instance}} SPF runs/s",
    ("ORR SPF activity and topology", "B"): "{{instance}} nodes",
    ("ORR SPF activity and topology", "C"): "{{instance}} usable links",
    ("BLACKHOLE discard activity", "A"): "{{instance}} installed/s",
    ("BLACKHOLE discard activity", "B"): "{{instance}} withdrawn/s",
}

ROUTE_SAFETY_PANELS = {
    "Export rejections / malformed UPDATEs": 0,
    "Selection-deferral state": 8,
    "Selection-deferral exceptional events": 16,
}

CAPACITY_PANELS = {
    "RFC 8212 missing policy",
    "Outbound prefix capacity",
    "Dynamic-neighbor admission capacity",
    "Dynamic-neighbor admission rejections",
}


def fail(message: str) -> None:
    print(f"dashboard check: {message}", file=sys.stderr)
    raise SystemExit(1)


def normalized(expression: str) -> str:
    return " ".join(expression.split())


def all_panels(panels: list[dict[str, Any]]) -> list[dict[str, Any]]:
    flattened: list[dict[str, Any]] = []
    for panel in panels:
        flattened.append(panel)
        children = panel.get("panels", [])
        if not isinstance(children, list):
            fail(f"panel {panel.get('id')} has a non-list panels field")
        flattened.extend(all_panels(children))
    return flattened


def rust_lex(source: str) -> tuple[str, list[str]]:
    """Mask Rust comments and literals, retaining string values as opaque tokens."""
    output: list[str] = []
    strings: list[str] = []
    index = 0
    while index < len(source):
        if source.startswith("//", index):
            end = source.find("\n", index)
            index = len(source) if end < 0 else end
        elif source.startswith("/*", index):
            depth, end = 1, index + 2
            while end < len(source) and depth:
                if source.startswith("/*", end):
                    depth += 1
                    end += 2
                elif source.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            output.append(" ")
            index = end
        else:
            raw = re.match(r'(?:br|r)(?P<hashes>#{0,255})"', source[index:])
            normal = re.match(r'(?:b)?"', source[index:])
            if raw:
                marker = '"' + raw.group("hashes")
                start = index + raw.end()
                end = source.find(marker, start)
                if end < 0:
                    raise ValueError("unterminated Rust raw string")
                value, index = source[start:end], end + len(marker)
            elif normal:
                start, end = index + normal.end(), index + normal.end()
                while end < len(source):
                    if source[end] == '"':
                        slashes = 0
                        while end > start + slashes and source[end - slashes - 1] == "\\":
                            slashes += 1
                        if slashes % 2 == 0:
                            break
                    end += 2 if source[end] == "\\" else 1
                if end >= len(source):
                    raise ValueError("unterminated Rust string")
                value, index = source[start:end], end + 1
            else:
                output.append(source[index])
                index += 1
                continue
            output.append(f"__RUST_STRING_{len(strings)}__")
            strings.append(value)
    return "".join(output), strings


def dashboard_metric_references(dashboard: dict[str, Any]) -> dict[str, list[str]]:
    references: dict[str, list[str]] = {}

    def add(expression: object, context: str) -> None:
        if not isinstance(expression, str) or not expression.strip():
            raise ValueError(f"empty query at {context}")
        syntax = re.sub(r'"(?:\\.|[^"\\])*"', '""', expression)
        if re.search(r"[A-Za-z_:][A-Za-z0-9_:]*:[A-Za-z0-9_:]*", syntax):
            raise ValueError(f"unsupported bare/colon metric alias at {context}: {expression}")
        names = re.findall(r"(?<![$\w:])([A-Za-z_:][A-Za-z0-9_:]*)\s*(?=\{)", syntax)
        if re.search(r"(?<![\w:])\{[^}]*__name__\s*=", syntax):
            raise ValueError(f"metric-less __name__ selector at {context}")
        remainder = re.sub(r"[A-Za-z_:][\w:]*\s*\{[^}]*\}", " ", syntax)
        remainder = re.sub(r"\{[^}]*\}|\[[^]]*\]|\$\w+", " ", remainder)
        remainder = re.sub(
            r"\b(?:by|without|on|ignoring|group_left|group_right)\s*\([^)]*\)",
            " ", remainder,
        )
        remainder = re.sub(r"\b[A-Za-z_]\w*\s*(?=\()", " ", remainder)
        aliases = re.findall(r"\b[A-Za-z_:][\w:]*\b", remainder)
        if aliases:
            raise ValueError(f"unsupported bare/colon metric alias at {context}: {aliases[0]}")
        for name in names:
            references.setdefault(name, []).append(context)
        if not names and "label_values" not in expression:
            raise ValueError(f"unsupported metric-free query at {context}: {expression}")

    for variable in dashboard.get("templating", {}).get("list", []):
        if variable.get("type") != "query":
            continue
        query = variable.get("query")
        match = re.fullmatch(r"\s*label_values\(\s*([A-Za-z_:][\w:]*)\s*(?:\{[^}]*\})?\s*,[^)]+\)\s*", str(query))
        if not match:
            raise ValueError(f"unsupported template query at ${variable.get('name')}: {query}")
        references.setdefault(match.group(1), []).append(f"${variable.get('name')}")
    for panel in all_panels(dashboard.get("panels", [])):
        for target in panel.get("targets", []):
            add(target.get("expr"), f"{panel.get('title')}/{target.get('refId')}")
    if not references:
        raise ValueError("no dashboard metric references discovered")
    return references


def rust_metric_inventory(source: str) -> dict[str, str]:
    source, strings = rust_lex(source)
    source = source.split("#[cfg(test)]", 1)[0]
    constructors: dict[str, tuple[str, str]] = {}
    pattern = re.compile(
        r"let\s+(\w+)\s*=\s*(IntCounter(?:Vec)?|IntGauge(?:Vec)?|HistogramVec)::new\(\s*"
        r"(?:(?:Opts|HistogramOpts)::new\(\s*)?__RUST_STRING_(\d+)__",
        re.DOTALL,
    )
    for variable, kind, string_index in pattern.findall(source):
        if variable in constructors:
            raise ValueError(f"ambiguous metric constructor variable {variable}")
        constructors[variable] = (strings[int(string_index)], "histogram" if kind == "HistogramVec" else "ordinary")
    registered = re.findall(
        r"\.register\(\s*Box::new\(\s*(\w+)\.clone\(\)\s*,?\s*\)\s*\)", source
    )
    inventory: dict[str, str] = {}
    for variable in registered:
        if variable not in constructors:
            continue
        name, kind = constructors[variable]
        if name in inventory:
            raise ValueError(f"duplicate registered metric name {name}")
        inventory[name] = kind
    if re.search(r"register\(\s*Box::new\(\s*jemalloc_stats::JemallocCollector::new\(\)\s*\)\s*\)", source):
        fields = set(re.findall(r"\b(\w+)\s*:\s*IntGauge\b", source))
        bodies = re.findall(r"(?<!-> )\bSelf\s*\{([^}]*)\}", source)
        wired: dict[str, set[str]] = {}
        for body in bodies:
            for entry in body.split(","):
                parts = [part.strip() for part in entry.split(":", 1)]
                field, variable = (parts[0], parts[-1])
                wired.setdefault(variable, set()).add(field)
        emitted = set(re.findall(r"self\.(\w+)\.collect\(\)", source))
        for variable, (name, kind) in constructors.items():
            if name.startswith("jemalloc_") and wired.get(variable, set()) & fields & emitted:
                inventory[name] = kind
    if not inventory:
        raise ValueError("no registered Rust metrics discovered")
    return inventory


def check_metric_linkage(references: dict[str, list[str]], inventory: dict[str, str]) -> None:
    unresolved: list[str] = []
    for name, contexts in sorted(references.items()):
        if name in inventory:
            continue
        base = next((name.removesuffix(suffix) for suffix in ("_bucket", "_count", "_sum") if name.endswith(suffix)), None)
        if base is None or inventory.get(base) != "histogram":
            unresolved.append(f"{name} ({', '.join(contexts)})")
    if unresolved:
        raise ValueError("unregistered dashboard metrics: " + "; ".join(unresolved))


def main() -> None:
    try:
        dashboard = json.loads(DASHBOARD.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot parse {DASHBOARD.relative_to(ROOT)}: {error}")

    panels = all_panels(dashboard.get("panels", []))
    ids = [panel.get("id") for panel in panels]
    if any(type(panel_id) is not int for panel_id in ids):
        fail("every panel must have an integer id")
    duplicates = sorted({panel_id for panel_id in ids if ids.count(panel_id) > 1})
    if duplicates:
        fail(f"duplicate panel ids: {duplicates}")

    variables = {
        variable.get("name"): variable
        for variable in dashboard.get("templating", {}).get("list", [])
    }
    for name, query in VARIABLES.items():
        variable = variables.get(name)
        if variable is None:
            fail(f"missing ${name} template variable")
        if variable.get("type") != "query" or variable.get("query") != query:
            fail(f"${name} does not use its exact label_values query")
        if variable.get("multi") is not True or variable.get("includeAll") is not True:
            fail(f"${name} must support multi-select and All")
        if variable.get("allValue") != ".*":
            fail(f"${name} All value must be the regex .* ")

    # The `peer` label has one canonical format (the bare neighbor
    # address), so the dashboard must expose exactly one selector for
    # it. A second one reintroduces the split identity that made
    # `by (peer)` joins across metric families silently return empty.
    peer_selectors = sorted(
        name
        for name, variable in variables.items()
        if variable.get("type") == "query"
        and str(variable.get("query", "")).rstrip().endswith(", peer)")
    )
    if peer_selectors != ["peer"]:
        fail(f"exactly one peer selector expected, found {peer_selectors}")

    targets: dict[tuple[str, str], list[str]] = {}
    legends: dict[tuple[str, str], list[str | None]] = {}
    for panel in panels:
        title = panel.get("title")
        for target in panel.get("targets", []):
            key = (title, target.get("refId"))
            targets.setdefault(key, []).append(normalized(target.get("expr", "")))
            legends.setdefault(key, []).append(target.get("legendFormat"))

    for key, expression in TARGETS.items():
        actual = targets.get(key, [])
        expected = [normalized(expression)]
        if actual != expected:
            fail(f"target {key[0]!r}/{key[1]} must equal {expected[0]!r}; got {actual!r}")

    for key, expected in REQUIRED_LEGENDS.items():
        actual = legends.get(key, [])
        if actual != [expected]:
            fail(f"target {key[0]!r}/{key[1]} must use legend {expected!r}; got {actual!r}")

    update_group_panel = next(
        panel for panel in panels if panel.get("title") == "Update group by peer"
    )
    update_group_target = update_group_panel["targets"][0]
    if update_group_panel.get("type") != "table":
        fail("update-group IDs must use a discrete table panel")
    if update_group_panel.get("fieldConfig", {}).get("defaults", {}).get("decimals") != 0:
        fail("update-group IDs must render with zero decimal places")
    if update_group_target.get("format") != "table" or update_group_target.get("instant") is not True:
        fail("update-group target must be an instant table query")

    slow_panel = next(panel for panel in panels if panel.get("title") == "Slow peers")
    slow_defaults = slow_panel.get("fieldConfig", {}).get("defaults", {})
    if slow_defaults.get("min") != 0 or slow_defaults.get("max") != 1:
        fail("slow-peer state must be pinned to the discrete 0..1 range")
    if slow_defaults.get("custom", {}).get("lineInterpolation") != "stepAfter":
        fail("slow-peer state must use step interpolation")

    truth_panel = next(
        panel
        for panel in panels
        if panel.get("title") == "Peer administrative / session truth"
    )
    if truth_panel.get("type") != "timeseries":
        fail("peer administrative/session truth must use a timeseries panel")
    truth_defaults = truth_panel.get("fieldConfig", {}).get("defaults", {})
    if (
        truth_defaults.get("decimals") != 0
        or truth_defaults.get("min") != 0
        or truth_defaults.get("max") != 1
    ):
        fail("peer administrative/session truth must be pinned to whole 0..1 values")
    if truth_defaults.get("custom", {}).get("lineInterpolation") != "stepAfter":
        fail("peer administrative/session truth must use step interpolation")

    route_safety_row = next(
        (panel for panel in panels if panel.get("title") == "Route safety"), None
    )
    if route_safety_row is None or route_safety_row.get("type") != "row":
        fail("Route safety must exist as a dashboard row")
    for title in ROUTE_SAFETY_PANELS:
        panel = next((item for item in panels if item.get("title") == title), None)
        if panel is None or panel.get("type") != "timeseries":
            fail(f"{title} must exist as a timeseries panel")

    selection_panel = next(
        panel for panel in panels if panel.get("title") == "Selection-deferral state"
    )
    selection_defaults = selection_panel.get("fieldConfig", {}).get("defaults", {})
    if selection_defaults.get("decimals") != 0 or selection_defaults.get("min") != 0:
        fail("selection-deferral state must render as nonnegative whole values")
    if selection_defaults.get("custom", {}).get("lineInterpolation") != "stepAfter":
        fail("selection-deferral state must use step interpolation")

    for title in CAPACITY_PANELS:
        panel = next((item for item in panels if item.get("title") == title), None)
        if panel is None or panel.get("type") != "timeseries":
            fail(f"{title} must exist as a timeseries panel")

    rfc8212_panel = next(
        panel for panel in panels if panel.get("title") == "RFC 8212 missing policy"
    )
    rfc8212_refs = [target.get("refId") for target in rfc8212_panel.get("targets", [])]
    if rfc8212_refs != ["A", "B"]:
        fail("RFC 8212 panel must contain exactly targets A and B")
    rfc8212_defaults = rfc8212_panel.get("fieldConfig", {}).get("defaults", {})
    if (
        rfc8212_defaults.get("decimals") != 0
        or rfc8212_defaults.get("min") != 0
        or rfc8212_defaults.get("max") != 1
    ):
        fail("RFC 8212 state must be pinned to whole 0..1 values")
    if rfc8212_defaults.get("custom", {}).get("lineInterpolation") != "stepAfter":
        fail("RFC 8212 state must use step interpolation")
    expected_mappings = [
        {
            "type": "value",
            "options": {
                "0": {"text": "not missing", "color": "green"},
                "1": {"text": "missing", "color": "red"},
            },
        }
    ]
    if rfc8212_defaults.get("mappings") != expected_mappings:
        fail("RFC 8212 state must map 0 to not missing and 1 to missing")

    outbound_panel = next(
        panel for panel in panels if panel.get("title") == "Outbound prefix capacity"
    )
    outbound_refs = [target.get("refId") for target in outbound_panel.get("targets", [])]
    if outbound_refs != ["A", "B", "C", "D"]:
        fail("outbound capacity panel must contain exactly targets A through D")
    if any(
        "bgp_outbound_prefix_blocked_total" in target.get("expr", "")
        for target in outbound_panel.get("targets", [])
    ):
        fail("outbound capacity panel must exclude the cumulative blocked counter")
    outbound_defaults = outbound_panel.get("fieldConfig", {}).get("defaults", {})
    if outbound_defaults.get("decimals") != 0 or outbound_defaults.get("min") != 0:
        fail("outbound capacity counts must render as nonnegative whole values")
    expected_overrides = [
        {
            "matcher": {"id": "byFrameRefID", "options": "D"},
            "properties": [
                {"id": "custom.axisPlacement", "value": "right"},
                {"id": "custom.lineInterpolation", "value": "stepAfter"},
                {"id": "max", "value": 1},
            ],
        }
    ]
    if outbound_panel.get("fieldConfig", {}).get("overrides") != expected_overrides:
        fail("only outbound blocking target D must use a stepped 0..1 right axis")

    dynamic_capacity_panel = next(
        panel
        for panel in panels
        if panel.get("title") == "Dynamic-neighbor admission capacity"
    )
    dynamic_capacity_refs = [
        target.get("refId") for target in dynamic_capacity_panel.get("targets", [])
    ]
    if dynamic_capacity_refs != ["A", "B", "C"]:
        fail("dynamic-neighbor capacity panel must contain exactly targets A through C")
    dynamic_capacity_defaults = dynamic_capacity_panel.get("fieldConfig", {}).get(
        "defaults", {}
    )
    if dynamic_capacity_defaults != {"unit": "short", "decimals": 0, "min": 0}:
        fail("dynamic-neighbor capacity must render as nonnegative whole values")

    dynamic_rejections_panel = next(
        panel
        for panel in panels
        if panel.get("title") == "Dynamic-neighbor admission rejections"
    )
    dynamic_rejection_refs = [
        target.get("refId") for target in dynamic_rejections_panel.get("targets", [])
    ]
    if dynamic_rejection_refs != ["A"]:
        fail("dynamic-neighbor rejections panel must contain exactly target A")
    dynamic_rejection_defaults = dynamic_rejections_panel.get("fieldConfig", {}).get(
        "defaults", {}
    )
    if dynamic_rejection_defaults != {"unit": "ops", "min": 0}:
        fail("dynamic-neighbor rejection rate must render as nonnegative operations")

    orr_panel = next(
        panel for panel in panels if panel.get("title") == "ORR SPF activity and topology"
    )
    orr_refs = [target.get("refId") for target in orr_panel.get("targets", [])]
    if orr_panel.get("type") != "timeseries" or orr_refs != ["A", "B", "C"]:
        fail("ORR activity panel must be a timeseries with exactly targets A through C")

    blackhole_panel = next(
        (
            panel
            for panel in panels
            if panel.get("title") == "BLACKHOLE discard activity"
        ),
        None,
    )
    if blackhole_panel is None:
        fail("BLACKHOLE discard activity panel must exist")
    blackhole_refs = [target.get("refId") for target in blackhole_panel.get("targets", [])]
    if blackhole_panel.get("type") != "timeseries" or blackhole_refs != ["A", "B"]:
        fail("BLACKHOLE discard activity must be a timeseries with exactly targets A and B")
    if blackhole_panel.get("gridPos") != {"h": 8, "w": 24, "x": 0, "y": 192}:
        fail("BLACKHOLE discard activity must retain its full-width layout")

    try:
        references = dashboard_metric_references(dashboard)
        inventory = rust_metric_inventory(METRICS.read_text(encoding="utf-8"))
        check_metric_linkage(references, inventory)
    except (OSError, ValueError) as error:
        fail(str(error))

    print(
        f"dashboard check: {len(panels)} unique panels, "
        f"{len(TARGETS)} operator targets, and {len(references)} linked metrics"
    )


if __name__ == "__main__":
    main()
