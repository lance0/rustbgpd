#!/usr/bin/env python3
"""Validate compact S2 coverage and recompute the published endpoint bars."""
import csv
import json
import math
import re
import statistics
import sys
from pathlib import Path

LEGS = ["01-A", "02-B", "03-B", "04-A", "05-A", "06-B"]
CANONICAL = {"N_PEERS": "700", "TOTAL_PREFIXES": "400400", "PORT": "1790",
             "RELOADS": "4", "CONTROL_SECS": "30", "CHANGED_PEERS": "",
             "FLAPSTORM": "", "BIRD_THREADS": "8", "PROBE_PREFIXES": "",
             "FLAP_ROUNDS": ""}
HEADER = "reload,peers_total,peers_changed,peers_stable,prefixes,completion_p50_s,completion_p95_s,completion_max_s,changed_maxgap_p50_ms,changed_maxgap_p95_ms,changed_maxgap_max_ms,all_observer_maxgap_p50_ms,all_observer_maxgap_p95_ms,all_observer_maxgap_max_ms,changed_first_generation_update_p50_ms,changed_first_generation_update_p95_ms,changed_first_generation_update_max_ms,rss_before_mib,rss_after_mib,stable_marker_peers,sessions_up,parse_errors".split(",")
FAMILIES = [("completion", "s"), ("changed_maxgap", "ms"),
            ("changed_first_generation_update", "ms")]
METRICS = [f"{name}_{quantile}_{unit}" for name, unit in FAMILIES
           for quantile in ("p50", "p95", "max")]
NATIVE_CHECKS = {"harness_exit", "daemon_exit", "cleanup_exit", "cell_exit"}
WRAPPER_CHECKS = {"wrapper", "runner", "sampler", "identity", "cleanup"}
FROZEN_PRODUCERS = {
    "A": ("19842a5a114287af7a8f5ae66407aaacc9d0142a", "fe3a2dbe6e01eb4fbb6aec5482f1184eae1973e9",
          "67ae6325f4392a23ab0c6fbb51b1ed61a25b0caa4d3391224864f278480f93df"),
    "B": ("3cf0dc277dc2f729d01e40207fbdab2d2e5fda11", "da79071dec28b23b23fdc26a9fe67c4f4137886d",
          "dd27aab2cb5246fb535340f9a6f4333245776b2ba78fc3ed034d44b423272d87"),
}
FROZEN_HARNESS_SHA256 = "4dfeccbbf9b4b25aabc1ce678d4973854f4bcddc1779bca3a82e3e7afaf063a4"


def need(condition, message):
    if not condition:
        raise ValueError(message)


def number(value):
    need(not isinstance(value, bool), "boolean numeric field")
    result = float(value)
    need(math.isfinite(result) and result >= 0, "non-finite or negative numeric field")
    return result


def unique_object(pairs):
    result = dict(pairs)
    need(len(result) == len(pairs), "duplicate JSON key")
    return result


def read_json(path):
    return json.loads(path.read_text(), object_pairs_hook=unique_object,
                      parse_constant=lambda value: number(value))


def successful_checks(mapping, expected):
    need(isinstance(mapping, dict) and set(mapping) == expected,
         "missing or unexpected native/wrapper check keys")
    need(all(type(value) is int and value == 0 for value in mapping.values()),
         "failed or invalid native/wrapper exit")


def main(root):
    provenance = read_json(root / "provenance.json")
    need(provenance["competitor_generation"] == "historical", "receipt vocabulary mismatch")
    need(provenance["cell"] == "rustbgpd", "wrong measured daemon")
    need(set(provenance["arms"]) == {"A", "B"}, "both arm producers required")
    for arm in "AB":
        producer = provenance["arms"][arm]
        source = producer["source"]
        need((source["commit"], source["tree"], producer["daemon"]["sha256"]) == FROZEN_PRODUCERS[arm]
             and producer["harness"]["sha256"] == FROZEN_HARNESS_SHA256,
             "dated campaign producer mismatch")
        need(source["dirty"] is False and
             all(re.fullmatch(r"[0-9a-f]{40}", source[key]) for key in ("commit", "tree")),
             "invalid frozen source")
        for kind in ("daemon", "harness"):
            binary = producer[kind]
            need(re.fullmatch(r"[0-9a-f]{64}", binary["sha256"]) and
                 all(re.fullmatch(r"[0-9a-f]{40}", binary[key])
                     for key in ("producer_commit", "producer_tree")), "invalid binary identity")
        need(producer["daemon"]["producer_commit"] == source["commit"] and
             producer["daemon"]["producer_tree"] == source["tree"], "false daemon producer")
        baseline = provenance["arms"]["A"]
        need(producer["harness"] == baseline["harness"] and
             producer["harness"]["producer_commit"] == baseline["source"]["commit"] and
             producer["harness"]["producer_tree"] == baseline["source"]["tree"],
             "shared baseline harness identity mismatch")

    with (root / "reloads-24.csv").open(newline="") as file:
        reader = csv.DictReader(file, strict=True)
        need(reader.fieldnames == ["leg", "arm", *HEADER], "unexpected reload CSV columns")
        raw = list(reader)
    expected = {(leg, str(reload)) for leg in LEGS for reload in range(1, 5)}
    need(len(raw) == 24 and {(row["leg"], row["reload"]) for row in raw} == expected,
         "exactly four unique reloads for each of six legs required")
    rows = []
    for row in raw:
        need(set(row) == {"leg", "arm", *HEADER} and None not in row.values(), "malformed CSV row")
        need(row["arm"] == row["leg"][-1], "row arm mismatch")
        values = {key: number(row[key]) for key in HEADER}
        need(tuple(values[key] for key in ("peers_total", "peers_changed", "peers_stable",
             "prefixes", "sessions_up", "parse_errors", "stable_marker_peers")) ==
             (700, 700, 0, 400400, 700, 0, 0), "wrong workload or failed reload health")
        for name, unit in [*FAMILIES, ("all_observer_maxgap", "ms")]:
            quantiles = [values[f"{name}_{q}_{unit}"] for q in ("p50", "p95", "max")]
            need(quantiles == sorted(quantiles), "invalid endpoint quantile order")
        need(values["completion_p50_s"] > 0, "zero completion")
        rows.append({"leg": row["leg"], "arm": row["arm"], **values})

    legs = read_json(root / "legs.json")
    need([leg["leg"] for leg in legs] == LEGS, "six ordered leg receipts required")
    previous_end = None
    for leg in legs:
        need(leg["status"] == "pass", "native cell failed")
        successful_checks(leg.get("native_checks"), NATIVE_CHECKS)
        successful_checks(leg.get("wrapper_exits"), WRAPPER_CHECKS)
        need(leg["workload"] == CANONICAL, "noncanonical workload")
        producer = provenance["arms"][leg["leg"][-1]]
        need(leg["source"] == producer["source"] and
             leg["daemon"] == producer["daemon"] and leg["harness"] == producer["harness"],
             "arm source/binary/harness mismatch")
        need(leg["source_and_binary_freeze_equal"] is True, "source or binary drift")
        begin, end = number(leg["started_epoch_s"]), number(leg["finished_epoch_s"])
        cell_pass = number(leg["native_cell_pass_epoch_s"])
        need(begin < cell_pass <= end, "native cell pass outside leg interval")
        # The cooldown is the timestamp gap; the recorded field must agree with it.
        cooldown = end - cell_pass
        need(cooldown >= 300, "shortened cooldown")
        need(abs(number(leg["cooldown_observed_s"]) - cooldown) <= 1e-3,
             "cooldown field disagrees with timestamps")
        need(begin < end and (previous_end is None or previous_end <= begin), "overlapping legs")
        previous_end = end
        quiet = leg["quiet"]
        need(len(quiet) == 2, "two quiet samples required")
        for sample in quiet:
            # Native epoch_s is truncated to whole seconds; its one-second
            # interval must intersect the enclosing high-resolution leg interval.
            quiet_epoch = number(sample["epoch_s"])
            need(quiet_epoch.is_integer() and begin < quiet_epoch + 1 and quiet_epoch <= end,
                 "quiet sample outside leg interval")
            need(sample["quiet"] == "true" and sample["competitors"] == "none" and
                 number(sample["load1"]) < 2 and
                 number(sample["performance_governors"]) == number(sample["governor_count"]) > 0,
                 "failed quiet admission")
        need(number(quiet[1]["epoch_s"]) - number(quiet[0]["epoch_s"]) >= 30 and
             all(number(quiet[0][key]) == number(quiet[1][key]) for key in ("pswpin", "pswpout")),
             "quiet spacing or swap activity")

    comparisons = {}
    for metric in METRICS:
        arms = {arm: [row[metric] for row in rows if row["arm"] == arm] for arm in "AB"}
        medians = {leg: statistics.median(row[metric] for row in rows if row["leg"] == leg)
                   for leg in LEGS}
        aggregate = max if metric.endswith(("_max_s", "_max_ms")) else statistics.median
        pooled = {arm: aggregate(values) for arm, values in arms.items()}
        process = {arm: statistics.median(value for leg, value in medians.items() if leg.endswith(arm))
                   for arm in "AB"}
        need(pooled["A"] > 0 and process["A"] > 0, "zero baseline comparison denominator")
        comparisons[metric] = {
            "unit": "seconds" if metric.endswith("_s") else "milliseconds",
            "aggregate": "actual_worst_of_12" if aggregate is max else "median_of_12_correlated_reload_percentiles",
            "A": pooled["A"], "B": pooled["B"],
            "change_percent": (pooled["B"] / pooled["A"] - 1) * 100,
            "within_2_percent": pooled["B"] <= pooled["A"] * 1.02,
            "per_leg_medians": medians,
            "median_of_three_leg_medians": process,
            "three_leg_median_change_percent": (process["B"] / process["A"] - 1) * 100,
            "three_leg_median_within_2_percent": process["B"] <= process["A"] * 1.02,
        }
    stall = comparisons["changed_maxgap_p50_ms"]
    pooled_gain = stall["A"] - stall["B"]
    process_gain = stall["median_of_three_leg_medians"]["A"] - stall["median_of_three_leg_medians"]["B"]
    return {"replication": "3 independent process legs per arm; 4 correlated reloads per leg",
            "scope": "S2 endpoint arithmetic and compact validity checks; raw path/probe and sampling evidence require the frozen full analyzer",
            "endpoints": comparisons,
            "stall_p50_gain_ms": pooled_gain, "three_leg_median_stall_p50_gain_ms": process_gain,
            "timing_bars_pass": pooled_gain >= 60 and process_gain >= 60 and
                all(metric["within_2_percent"] and metric["three_leg_median_within_2_percent"]
                    for metric in comparisons.values())}


if __name__ == "__main__":
    print(json.dumps(main(Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent),
                     indent=2, allow_nan=False))
