#!/usr/bin/env python3
"""Validate one Enhanced Route Refresh receipt phase from Prometheus text."""

import argparse
import json
import math
import pathlib
import re

PEER = "127.1.0.1"
FAMILY = "ipv4_unicast"
PREFIXES = 100_000

EXPECTED = {
    "baseline": (PREFIXES, 0, 0, 0, 0, 0),
    "first-borr": (PREFIXES, 1, PREFIXES, 1, 0, 0),
    "replay-one": (PREFIXES, 1, PREFIXES - 1, 1, 0, 0),
    "duplicate-borr": (PREFIXES, 1, PREFIXES, 2, 0, 0),
    "eorr": (0, 0, 0, 2, 1, 0),
    "restored": (PREFIXES, 0, 0, 2, 1, 0),
    "timeout-borr": (PREFIXES, 1, PREFIXES, 3, 1, 0),
    "timeout-complete": (0, 0, 0, 3, 1, 1),
}

LINE = re.compile(
    r"^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)"
    r"(?:\{(?P<labels>[^}]*)\})?\s+(?P<value>[-+0-9.eE]+)$"
)
LABEL = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:\\.|[^"])*)"')


def parse_metrics(path: pathlib.Path):
    metrics = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw or raw.startswith("#"):
            continue
        match = LINE.match(raw)
        if not match:
            continue
        labels = tuple(
            sorted(
                (name, bytes(value, "utf-8").decode("unicode_escape"))
                for name, value in LABEL.findall(match.group("labels") or "")
            )
        )
        metrics[(match.group("name"), labels)] = float(match.group("value"))
    return metrics


def get(metrics, name, labels=None, *, absent_zero=False):
    key = (name, tuple(sorted((labels or {}).items())))
    if key not in metrics:
        if absent_zero:
            return 0.0
        raise AssertionError(f"missing metric {name}{dict(labels or {})}")
    value = metrics[key]
    if not math.isfinite(value):
        raise AssertionError(f"non-finite metric {name}{dict(labels or {})}: {value}")
    return value


def require(metrics, name, labels, expected, *, absent_zero=False):
    value = get(metrics, name, labels, absent_zero=absent_zero)
    if value != expected:
        raise AssertionError(
            f"{name}{labels}: expected {expected}, got {value:g}"
        )
    return value


def actor_count(metrics, operation):
    return get(
        metrics,
        "bgp_rib_route_refresh_actor_duration_seconds_count",
        {"operation": operation},
    )


def actor_sum(metrics, operation):
    return get(
        metrics,
        "bgp_rib_route_refresh_actor_duration_seconds_sum",
        {"operation": operation},
    )


def validate(phase, metrics, baseline):
    rib, active, stale, begin_delta, eorr_delta, timeout_delta = EXPECTED[phase]
    require(metrics, "bgp_rib_prefixes", {"afi_safi": "all", "peer": PEER}, rib)
    for scope in ("aggregate", "ipv4_unicast"):
        require(metrics, "bgp_max_prefix_usage", {"peer": PEER, "scope": scope}, rib)
    require(
        metrics,
        "bgp_route_refresh_in_progress",
        {"afi_safi": FAMILY, "peer": PEER},
        active,
        absent_zero=True,
    )
    require(
        metrics,
        "bgp_route_refresh_stale_entries",
        {"afi_safi": FAMILY, "peer": PEER},
        stale,
        absent_zero=True,
    )
    require(metrics, "bgp_session_established_total", {"peer": PEER}, 1)
    require(
        metrics,
        "bgp_peer_session_established",
        {"interface": "", "peer": PEER},
        1,
    )
    require(
        metrics,
        "bgp_session_flaps_total",
        {"peer": PEER},
        0,
        absent_zero=True,
    )

    expected_counts = {
        "begin": actor_count(baseline, "begin") + begin_delta,
        "eorr": actor_count(baseline, "eorr") + eorr_delta,
        "timeout": actor_count(baseline, "timeout") + timeout_delta,
    }
    count_deltas = {
        "begin": begin_delta,
        "eorr": eorr_delta,
        "timeout": timeout_delta,
    }
    actor_sums = {}
    for operation, expected in expected_counts.items():
        require(
            metrics,
            "bgp_rib_route_refresh_actor_duration_seconds_count",
            {"operation": operation},
            expected,
        )
        baseline_sum = actor_sum(baseline, operation)
        current_sum = actor_sum(metrics, operation)
        if count_deltas[operation] == 0 and current_sum != baseline_sum:
            raise AssertionError(
                f"{operation} actor sum advanced without an accepted operation: "
                f"{baseline_sum:g} -> {current_sum:g}"
            )
        if count_deltas[operation] > 0 and current_sum <= baseline_sum:
            raise AssertionError(
                f"{operation} actor sum did not advance with "
                f"{count_deltas[operation]} accepted operation(s): "
                f"{baseline_sum:g} -> {current_sum:g}"
            )
        actor_sums[operation] = current_sum

    return {
        "phase": phase,
        "rib_prefixes": rib,
        "refresh_active": active,
        "refresh_stale": stale,
        "max_prefix_usage": rib,
        "session_established_total": 1,
        "session_established": 1,
        "session_flaps_total": 0,
        "actor_begin_count": expected_counts["begin"],
        "actor_eorr_count": expected_counts["eorr"],
        "actor_timeout_count": expected_counts["timeout"],
        "actor_begin_sum_seconds": actor_sums["begin"],
        "actor_eorr_sum_seconds": actor_sums["eorr"],
        "actor_timeout_sum_seconds": actor_sums["timeout"],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=EXPECTED)
    parser.add_argument("metrics", type=pathlib.Path)
    parser.add_argument("baseline", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    arguments = parser.parse_args()

    summary = validate(
        arguments.phase,
        parse_metrics(arguments.metrics),
        parse_metrics(arguments.baseline),
    )
    encoded = json.dumps(summary, sort_keys=True)
    if arguments.output:
        arguments.output.write_text(encoded + "\n", encoding="utf-8")
    print(encoded)


if __name__ == "__main__":
    main()
