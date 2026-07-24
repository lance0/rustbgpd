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
WORKFLOW = ROOT / ".github/workflows/alert-rules.yml"

VARIABLES = {
    "peer": 'label_values(bgp_session_state_transitions_total{instance=~"$instance"}, peer)',
}

TARGETS = {
    ("Outbound queue by peer", "A"): (
        'bgp_peer_outbound_queue_depth{instance=~"$instance",peer=~"$peer"}'
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
}

ROUTE_SAFETY_LEGENDS = {
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
}

ROUTE_SAFETY_PANELS = {
    "Export rejections / malformed UPDATEs": 0,
    "Selection-deferral state": 8,
    "Selection-deferral exceptional events": 16,
}

WORKFLOW_PATHS = {
    "examples/prometheus/**",
    "docs/grafana/rustbgpd-overview.json",
    "scripts/check-grafana-dashboard.py",
    ".github/workflows/alert-rules.yml",
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


def workflow_trigger_paths(text: str) -> dict[str, set[str]]:
    triggers: dict[str, set[str]] = {"push": set(), "pull_request": set()}
    event: str | None = None
    in_paths = False
    for line in text.splitlines():
        event_match = re.fullmatch(r"  (push|pull_request):", line)
        if event_match:
            event = event_match.group(1)
            in_paths = False
            continue
        if event is not None and re.fullmatch(r"    paths:", line):
            in_paths = True
            continue
        if in_paths:
            path_match = re.fullmatch(r'      - ["\']([^"\']+)["\']', line)
            if path_match:
                triggers[event].add(path_match.group(1))
                continue
            if line.strip() and not line.startswith("      "):
                in_paths = False
        if event is not None and line and not line.startswith("  "):
            event = None
            in_paths = False
    return triggers


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

    for key, expected in ROUTE_SAFETY_LEGENDS.items():
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

    route_safety_row = next(
        (panel for panel in panels if panel.get("title") == "Route safety"), None
    )
    if route_safety_row is None or route_safety_row.get("type") != "row":
        fail("Route safety must exist as a dashboard row")
    if route_safety_row.get("collapsed") is not False:
        fail("Route safety row must be expanded by default")
    row_position = route_safety_row.get("gridPos", {})
    expected_row_position = {"h": 1, "w": 24, "x": 0, "y": 152}
    if row_position != expected_row_position:
        fail(f"Route safety row must use grid position {expected_row_position}")
    for title, expected_x in ROUTE_SAFETY_PANELS.items():
        panel = next((item for item in panels if item.get("title") == title), None)
        if panel is None or panel.get("type") != "timeseries":
            fail(f"{title} must exist as a timeseries panel")
        position = panel.get("gridPos", {})
        expected_position = {"h": 8, "w": 8, "x": expected_x, "y": 153}
        if position != expected_position:
            fail(f"{title} must use route-safety grid position {expected_position}")

    selection_panel = next(
        panel for panel in panels if panel.get("title") == "Selection-deferral state"
    )
    selection_defaults = selection_panel.get("fieldConfig", {}).get("defaults", {})
    if selection_defaults.get("decimals") != 0 or selection_defaults.get("min") != 0:
        fail("selection-deferral state must render as nonnegative whole values")
    if selection_defaults.get("custom", {}).get("lineInterpolation") != "stepAfter":
        fail("selection-deferral state must use step interpolation")

    try:
        workflow_text = WORKFLOW.read_text(encoding="utf-8")
    except OSError as error:
        fail(f"cannot read {WORKFLOW.relative_to(ROOT)}: {error}")
    for event, paths in workflow_trigger_paths(workflow_text).items():
        missing = sorted(WORKFLOW_PATHS - paths)
        if missing:
            fail(f"{event} paths are missing {missing}")
    checker_steps = sum(
        line.strip() == "run: python3 scripts/check-grafana-dashboard.py"
        for line in workflow_text.splitlines()
    )
    if checker_steps != 1:
        fail("workflow must contain exactly one executable dashboard-checker step")

    print(
        f"dashboard check: {len(panels)} unique panels, "
        f"{len(TARGETS)} operator targets, and workflow triggers are valid"
    )


if __name__ == "__main__":
    main()
