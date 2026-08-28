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

PREDECESSOR = {
    "first-borr": "baseline",
    "replay-one": "first-borr",
    "duplicate-borr": "replay-one",
    "eorr": "duplicate-borr",
    "restored": "eorr",
    "timeout-borr": "restored",
    "timeout-complete": "timeout-borr",
}

OPERATIONS = ("begin", "eorr", "timeout")
TIMED_OPERATION = {
    "first-borr": "begin",
    "duplicate-borr": "begin",
    "eorr": "eorr",
    "timeout-borr": "begin",
    "timeout-complete": "timeout",
}
TIMING_CEILINGS_SECONDS = {
    "begin": 0.025,
    "eorr": 0.250,
    "timeout": 0.250,
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
        raise AssertionError(f"{name}{labels}: expected {expected}, got {value:g}")
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


def require_phase_state(phase, metrics):
    rib, active, stale, _, _, _ = EXPECTED[phase]
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


def require_actor_absolute_counts(phase, metrics, baseline):
    deltas = dict(zip(OPERATIONS, EXPECTED[phase][3:], strict=True))
    expected_counts = {
        operation: actor_count(baseline, operation) + deltas[operation] for operation in OPERATIONS
    }
    for operation, expected in expected_counts.items():
        require(
            metrics,
            "bgp_rib_route_refresh_actor_duration_seconds_count",
            {"operation": operation},
            expected,
        )
    return expected_counts


def require_actor_sums(metrics):
    return {operation: actor_sum(metrics, operation) for operation in OPERATIONS}


def validate_transition(phase, current_counts, current_sums, previous_counts, previous_sums):
    timed_operation = TIMED_OPERATION.get(phase)
    for operation in OPERATIONS:
        expected_count_delta = int(operation == timed_operation)
        observed_count_delta = current_counts[operation] - previous_counts[operation]
        if observed_count_delta != expected_count_delta:
            raise AssertionError(
                f"phase={phase} timed_op={timed_operation} op={operation} "
                f"observed_count_delta={observed_count_delta:g} "
                f"expected_count_delta={expected_count_delta}: actor count delta mismatch"
            )

    timed_delta = None
    for operation in OPERATIONS:
        observed = current_sums[operation] - previous_sums[operation]
        if operation != timed_operation:
            if observed != 0:
                raise AssertionError(
                    f"phase={phase} op={operation} observed={observed:g}s ceiling=0s: "
                    "actor sum advanced without an accepted operation"
                )
            continue

        ceiling = TIMING_CEILINGS_SECONDS[operation]
        over_ceiling = observed > ceiling and not math.isclose(
            observed, ceiling, rel_tol=0.0, abs_tol=1e-12
        )
        if observed <= 0 or over_ceiling:
            raise AssertionError(
                f"phase={phase} op={operation} observed={observed:g}s "
                f"ceiling={ceiling:g}s: timed actor delta must be positive and "
                "within the adjacent-phase ceiling"
            )
        timed_delta = observed
    return timed_operation, timed_delta


def validate(phase, metrics, baseline, predecessor=None):
    previous_phase = PREDECESSOR.get(phase)
    if previous_phase is None:
        if predecessor is not None:
            raise AssertionError("phase=baseline must not have predecessor metrics")
        previous_counts = None
        previous_sums = None
    else:
        if predecessor is None:
            raise AssertionError(f"phase={phase}: missing predecessor metrics for {previous_phase}")
        # The predecessor's absolute actor counts are checked against the
        # settled baseline before either its phase state or the new candidate.
        previous_counts = require_actor_absolute_counts(previous_phase, predecessor, baseline)
        require_phase_state(previous_phase, predecessor)
        previous_sums = require_actor_sums(predecessor)

    require_phase_state(phase, metrics)
    expected_counts = require_actor_absolute_counts(phase, metrics, baseline)
    actor_sums = require_actor_sums(metrics)

    timed_operation = None
    timed_delta = None
    if previous_phase is not None:
        timed_operation, timed_delta = validate_transition(
            phase,
            expected_counts,
            actor_sums,
            previous_counts,
            previous_sums,
        )

    rib, active, stale, _, _, _ = EXPECTED[phase]

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
        "actor_timed_operation": timed_operation,
        "actor_timed_delta_seconds": timed_delta,
        "actor_timed_ceiling_seconds": (
            TIMING_CEILINGS_SECONDS[timed_operation] if timed_operation else None
        ),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=EXPECTED)
    parser.add_argument("metrics", type=pathlib.Path)
    parser.add_argument("baseline", type=pathlib.Path)
    parser.add_argument("predecessor", nargs="?", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    arguments = parser.parse_args()

    summary = validate(
        arguments.phase,
        parse_metrics(arguments.metrics),
        parse_metrics(arguments.baseline),
        (parse_metrics(arguments.predecessor) if arguments.predecessor is not None else None),
    )
    encoded = json.dumps(summary, sort_keys=True)
    if arguments.output:
        arguments.output.write_text(encoded + "\n", encoding="utf-8")
    print(encoded)


if __name__ == "__main__":
    main()
