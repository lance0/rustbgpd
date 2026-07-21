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
    "neighbor": 'label_values(bgp_peer_update_group{instance=~"$instance"}, peer)',
}

TARGETS = {
    ("Outbound queue by peer endpoint", "A"): (
        'bgp_peer_outbound_queue_depth{instance=~"$instance",peer=~"$peer"}'
    ),
    ("Slow peer endpoints", "A"): (
        'bgp_peer_slow{instance=~"$instance",peer=~"$peer"}'
    ),
    ("Update group by neighbor address", "A"): (
        'bgp_peer_update_group{instance=~"$instance",peer=~"$neighbor"}'
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

    targets: dict[tuple[str, str], list[str]] = {}
    for panel in panels:
        title = panel.get("title")
        for target in panel.get("targets", []):
            key = (title, target.get("refId"))
            targets.setdefault(key, []).append(normalized(target.get("expr", "")))

    for key, expression in TARGETS.items():
        actual = targets.get(key, [])
        expected = [normalized(expression)]
        if actual != expected:
            fail(f"target {key[0]!r}/{key[1]} must equal {expected[0]!r}; got {actual!r}")

    update_group_panel = next(
        panel for panel in panels if panel.get("title") == "Update group by neighbor address"
    )
    update_group_target = update_group_panel["targets"][0]
    if update_group_panel.get("type") != "table":
        fail("update-group IDs must use a discrete table panel")
    if update_group_panel.get("fieldConfig", {}).get("defaults", {}).get("decimals") != 0:
        fail("update-group IDs must render with zero decimal places")
    if update_group_target.get("format") != "table" or update_group_target.get("instant") is not True:
        fail("update-group target must be an instant table query")

    slow_panel = next(panel for panel in panels if panel.get("title") == "Slow peer endpoints")
    slow_defaults = slow_panel.get("fieldConfig", {}).get("defaults", {})
    if slow_defaults.get("min") != 0 or slow_defaults.get("max") != 1:
        fail("slow-peer state must be pinned to the discrete 0..1 range")
    if slow_defaults.get("custom", {}).get("lineInterpolation") != "stepAfter":
        fail("slow-peer state must use step interpolation")

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
