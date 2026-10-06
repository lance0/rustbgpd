#!/usr/bin/env python3
"""Validate compact coverage and recompute the published S3 phase arithmetic."""
import csv
import json
import math
import statistics
import sys
from pathlib import Path

LEGS = ["01-control", "02-instrumented", "03-instrumented", "04-control", "05-control", "06-instrumented"]
PAIRS = [("01-control", "02-instrumented"), ("04-control", "03-instrumented"), ("05-control", "06-instrumented")]
CANONICAL = {"N_PEERS": "700", "TOTAL_PREFIXES": "400400", "PORT": "1790", "RELOADS": "4",
             "CONTROL_SECS": "30", "CHANGED_PEERS": "", "FLAPSTORM": "50", "BIRD_THREADS": "8",
             "PROBE_PREFIXES": "", "FLAP_ROUNDS": "3"}
SPANS = {
    "source_write_to_rib_admit": ("source_write_start_us", "transport_rib_admit_marker_us"),
    "rib_admit_to_ingest": ("transport_rib_admit_marker_us", "rib_ingest_marker_us"),
    "ingest_to_distribution": ("rib_ingest_marker_us", "distribution_start_marker_us"),
    "distribution_to_sample_commit": ("distribution_start_marker_us", "rib_commit_start_marker_us"),
    "sample_commit_to_envelope": ("rib_commit_start_marker_us", "session_envelope_marker_us"),
    "envelope_to_bulk_marker": ("session_envelope_marker_us", "bulk_marker_end_us"),
    "bulk_marker_to_writer_coalesce": ("bulk_marker_end_us", "writer_coalesce_us"),
    "writer_coalesce_to_write": ("writer_coalesce_us", "writer_start_us"),
    "writer_write": ("writer_start_us", "writer_end_us"),
    "writer_end_to_marker_observed": ("writer_end_us", "marker_sample_us"),
    "encode_source_order": ("encode_order_start_marker_us", "encode_order_end_marker_us"),
    "encode_first_slice": ("encode_order_end_marker_us", "first_encoder_chunk_marker_us"),
    "distribution_duration": ("distribution_start_marker_us", "distribution_end_marker_us"),
    "inflight_dump_end_to_ingest": ("inflight_dump_remaining_at_trigger_us", "rib_ingest_marker_us"),
    "inflight_dump_end_to_sample_first": ("inflight_dump_remaining_at_trigger_us", "affected_sample_us"),
    "marker_lag_sample": ("affected_sample_us", "marker_sample_us"),
}


def need(condition, message):
    if not condition:
        raise ValueError(message)


def stats(values):
    return {"median": round(statistics.median(values), 6), "min": round(min(values), 6),
            "max": round(max(values), 6), "n": len(values)}


def main(root):
    provenance = json.loads((root / "provenance.json").read_text())
    with (root / "rounds.csv").open() as file:
        rows = list(csv.DictReader(file))
    expected = {(leg, str(n)) for leg in LEGS for n in range(1, 4)}
    need(len(rows) == 18 and {(r["leg"], r["round"]) for r in rows} == expected, "exactly 18 unique rounds required")
    for row in rows:
        need(row["mode"] == row["leg"].split("-", 1)[1], "arm mismatch")
        for metric in ["first_reann_s", "reannounce_s", "withdraw_s", "rejoin_complete_s"]:
            values = [float(row[metric + "_" + q]) for q in ["p50", "p95", "max"]]
            need(all(math.isfinite(v) and v >= 0 for v in values) and values == sorted(values), "invalid endpoint quantiles")
    legs = json.loads((root / "legs.json").read_text())
    need([leg["leg"] for leg in legs] == LEGS, "six ordered leg receipts required")
    for leg in legs:
        need(leg["status"] == "pass" and leg["runner_exit"] == leg["native_cleanup_exit"] == 0, "failed leg")
        need(set(leg["exits"]) == {"harness", "daemon", "health-before", "health-after"}
             and set(leg["http"]) == {"health-before", "health-after"}, "missing or unexpected native check keys")
        need(all(value == 0 for value in leg["exits"].values()) and all(value == 200 for value in leg["http"].values()), "failed native exit or health")
        need(leg["workload"] == CANONICAL, "noncanonical workload")
        mode = leg["leg"].split("-", 1)[1]
        need(leg["binary_sha256"] == provenance["sha256"]["rustbgpd-" + mode]
             and leg["harness_sha256"] == provenance["sha256"]["reloadstall-" + mode], "arm binary or harness hash mismatch")
        need(leg["source_and_binary_freeze_equal"] and leg["cooldown_observed_s"] >= 300, "freeze drift or shortened cooldown")
        quiet = leg["quiet"]
        need(len(quiet) == 2 and all(q["quiet"] == "true" and q["competitors"] == "none" for q in quiet), "quiet samples required")
        need(float(quiet[1]["epoch_s"]) - float(quiet[0]["epoch_s"]) >= 30, "quiet spacing")
    endpoints = {}
    for metric in ["first_reann_s_p50", "reannounce_s_p50", "withdraw_s_p50", "rejoin_complete_s_p50"]:
        arms = {mode: stats([float(r[metric]) * 1000 for r in rows if r["mode"] == mode]) for mode in ["control", "instrumented"]}
        medians = {leg: statistics.median(float(r[metric]) * 1000 for r in rows if r["leg"] == leg) for leg in LEGS}
        endpoints[metric] = {**arms, "change_pct": round(100 * (arms["instrumented"]["median"] / arms["control"]["median"] - 1), 6),
                             "leg_medians_ms": {leg: round(value, 6) for leg, value in medians.items()},
                             "pair_changes_pct": [round(100 * (medians[b] / medians[a] - 1), 6) for a, b in PAIRS]}
    probes = [r for r in rows if r["mode"] == "instrumented"]
    for row in probes:
        need(int(row["writer_byte_start"]) < int(row["marker_byte_end"]) <= int(row["writer_byte_end"]), "marker outside writer byte bracket")
    with (root / "arrivals.csv").open() as file:
        arrivals = list(csv.DictReader(file))
    expected_arrivals = {(r["leg"], r["round"], str(peer)) for r in probes for peer in range(50, 700)}
    need(len(arrivals) == 5850 and {(a["leg"], a["round"], a["peer"]) for a in arrivals} == expected_arrivals, "5850 unique survivor-rounds required")
    correlation = []
    for row in probes:
        selected = [a for a in arrivals if (a["leg"], a["round"]) == (row["leg"], row["round"])]
        for kind in ["published", "affected", "marker"]:
            values = sorted(int(a[kind + "_us"]) for a in selected)
            need(values[0] >= 0 and values[325] == int(row[kind + "_p50_us"]), "arrival p50 mismatch")
            sample = next(a for a in selected if a["peer"] == "350")
            need(int(sample[kind + "_us"]) == int(row[kind + "_sample_us"]), "sample arrival mismatch")
        need(abs(int(row["published_p50_us"]) / 1e6 - float(row["first_reann_s_p50"])) < 1e-6, "published clock mismatch")
        lags = [int(a["marker_us"]) - int(a["affected_us"]) for a in selected]
        need(min(lags) >= 0, "marker precedes first affected UPDATE")
        correlation.append({"leg": row["leg"], "round": int(row["round"]), "observers": len(selected),
                            "published_equals_affected": sum(a["published_us"] == a["affected_us"] for a in selected),
                            "marker_equals_affected": sum(lag == 0 for lag in lags), "marker_lag_us": stats(lags)})
    matching = [r for r in probes if r["marker_sample_us"] == r["affected_sample_us"]]
    spans = lambda selected: {name: stats([int(r[end]) - int(r[start]) for r in selected]) for name, (start, end) in SPANS.items()}
    phases = {key: stats([float(r[key]) for r in probes]) for key in probes[0] if key.endswith("_us") and key != "t0_wall_us"}
    return {"endpoints_ms": endpoints, "phase_offsets_and_observations_us": phases,
            "signed_spans_us": spans(probes), "matching_marker_signed_spans_us": spans(matching),
            "arrival_correlation": correlation}


if __name__ == "__main__":
    print(json.dumps(main(Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent), indent=2, allow_nan=False))
