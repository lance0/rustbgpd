#!/usr/bin/env python3
"""Validate this frozen K1/K50 receipt, retaining integer-clock derivations."""
import csv
import json
import math
import re
import sys
from pathlib import Path


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def kv(line):
    return dict(item.split("=", 1) for item in line.split(",")[1:])


def quiet(path):
    rows = list(csv.DictReader(path.open(), delimiter="\t"))
    require(len(rows) == 2, f"{path}: exactly two accepted quiet samples")
    for i, row in enumerate(rows, 1):
        require(int(row["sample"]) == i, "quiet sample ordinal")
        require(math.isfinite(float(row["load1"])) and float(row["load1"]) < 2, "quiet load")
        governors = row["governors"].split(",")
        require(len(governors) == int(row["governor_count"]) and set(governors) == {"performance"}, "quiet governors")
        require(int(row["governor_count"]) > 0 and row["performance_governors"] == row["governor_count"], "all CPUs performance")
        require(row["competitors"] == "none" and row["quiet"] == "true" and row["failed_dimensions"] == "none", "quiet dimensions")
    require(int(rows[1]["epoch_s"]) - int(rows[0]["epoch_s"]) >= 30, "quiet sample spacing")
    require(all(rows[0][key] == rows[1][key] for key in ("pswpin", "pswpout")), "swap drift")
    return rows


def stats(lines, name, n):
    matches = [line for line in lines if line.startswith(name + ":")]
    require(len(matches) == 1, f"one {name} row")
    match = re.fullmatch(re.escape(name) + r": p50=([\d.]+) p95=([\d.]+) max=([\d.]+) \(n=(\d+)\)", matches[0])
    require(match is not None, f"{name}: valid stats")
    values = list(map(float, match.groups()[:3]))
    require(int(match[4]) == n and all(math.isfinite(x) and x >= 0 for x in values) and values == sorted(values), f"{name}: count and finite ordered values")
    return dict(zip(("p50", "p95", "max"), values))


def peer_clock(row):
    nums = {key: int(row[key]) for key in ("queue_attempt_us", "written_us", "first_base_us", "table_us", "eor_us", "complete_us", "unique", "expected")}
    q, w, f, t, e, c = (nums[key] for key in ("queue_attempt_us", "written_us", "first_base_us", "table_us", "eor_us", "complete_us"))
    require(0 <= q <= w and q <= f <= t <= e and q <= e and w < c and c == max(t, e), "fresh table/EOR clock ordering")
    require(nums["unique"] == nums["expected"] == 398000, "exact reflected table")
    require(abs(float(row["completion_s"]) * 1e6 - (c - w)) <= 0.50001, "per-peer completion from integer clocks")
    return nums | {"completion_us": c - w, "peer": int(row["peer"])}


def raw(lines, k):
    first = [kv(x) for x in lines if x.startswith("first_exact_bitmap,")]
    require(len(first) == 1, "one initial bitmap proof")
    expected = {"mode": "ibgp-rr", "peers": "200", "total": "400000", "per_peer": "2000", "expected": "398000", "completed": "200", "min_unique": "398000", "max_unique": "398000"}
    require(all(first[0].get(key) == value for key, value in expected.items()), "initial 200 exact tables")
    hold = [dict(re.findall(r"(\w+)=([^ ]+)", x)) for x in lines if x.startswith("rr_hold ")]
    require(len(hold) >= 2 and all(int(x["sessions_up"]) == 200 for x in hold), "hold sessions")
    require(int(hold[-1]["elapsed_s"]) >= 3 and int(hold[-1]["churn_cycles"]) > int(hold[0]["churn_cycles"]) > 0, "live hold churn")
    header = [x.split(",")[1:] for x in lines if x.startswith("rr_refresh_csv_header,")]
    require(len(header) == 1, "one refresh CSV header")
    rounds = [dict(zip(header[0], x.split(",")[1:], strict=True)) for x in lines if x.startswith("rr_refresh_csv,")]
    require([int(x["round"]) for x in rounds] == [1, 2, 3], "exactly three ordered rounds")
    peers = [kv(x) for x in lines if x.startswith("rr_refresh_peer,")]
    ready = [kv(x) for x in lines if x.startswith("rr_readiness_sample,")]
    require(len(peers) == 3 * k and all(int(x["round"]) in (1, 2, 3) for x in peers + ready), "peer/readiness round membership")
    result = []
    for r in rounds:
        rn = int(r["round"])
        require(all(int(r[key]) == value for key, value in {"peers_total": 200, "refreshers": k, "prefixes": 400000, "sessions_up": 200, "parse_errors": 0}.items()), f"round {rn} shape/sessions/parse errors")
        these = [x for x in peers if int(x["round"]) == rn]
        require(sorted(int(x["peer"]) for x in these) == list(range(k)), f"round {rn}: all unique refreshers")
        clocks = [peer_clock(x) for x in these]
        durations = sorted(x["completion_us"] for x in clocks)
        p50, maximum = durations[math.floor((k - 1) * .5 + .5)], durations[-1]
        require(abs(float(r["completion_p50_s"]) * 1e6 - p50) <= .50001 and abs(float(r["completion_max_s"]) * 1e6 - maximum) <= .50001, "CSV completion from integer clocks")
        start, end = int(r["window_start_us"]), int(r["window_end_us"])
        require(0 <= start <= min(x["queue_attempt_us"] for x in clocks) and end == max(x["complete_us"] for x in clocks), "round window clocks")
        if result:
            require(start > result[-1]["window_end_us"], "round windows strictly ordered")
        samples = [x for x in ready if int(x["round"]) == rn]
        require(len(samples) == int(r["readiness_samples"]) > 0 and [int(x["sample"]) for x in samples] == list(range(1, len(samples) + 1)), "readiness count/ordinals")
        overlap = []
        for sample in samples:
            a, b = int(sample["started_us"]), int(sample["finished_us"])
            require(sample["success"] == "true" and 0 <= a <= b and b - a <= 250000, "successful bounded readiness response")
            intersecting = [x["peer"] for x in clocks if a <= x["complete_us"] and b >= x["written_us"]]
            overlap.append({"sample": int(sample["sample"]), "started_us": a, "finished_us": b, "overlaps_round": a <= end and b >= start, "overlapping_peer_write_completion_windows": intersecting})
        require(any(x["overlaps_round"] for x in overlap), "readiness actually overlaps refresh window")
        gap = stats(lines, f"rr_refresh {rn} survivor_maxgap_ms", 200 - k)
        require(math.isfinite(float(r["survivor_maxgap_ms"])) and abs(float(r["survivor_maxgap_ms"]) - gap["max"]) <= .00501, "CSV survivor gap agrees")
        completion = stats(lines, f"rr_refresh {rn} completion_s", k)
        require(abs(completion["p50"] * 1e6 - p50) <= 5000.01 and abs(completion["max"] * 1e6 - maximum) <= 5000.01, "rounded completion agrees")
        result.append({"round": rn, "completion_p50_us": p50, "completion_max_us": maximum, "window_start_us": start, "window_end_us": end, "survivor_gaps_ms": gap, "survivor_maxgap_ms_unrounded": float(r["survivor_maxgap_ms"]), "rss_mib": int(r["rss_mib"]), "readiness": overlap, "peer_clocks": clocks})
    require(any(x.startswith("done rss_mib=") for x in lines), "native terminal completion")
    return {"k": k, "control_gaps_ms": stats(lines, "control_maxgap_ms", 200), "hold": hold, "rounds": result}


def cell(root, k):
    path = root / f"k{k}"
    for name in ("cell.exit", "harness.exit", "daemon.exit", "metrics.exit", "forced-kill.txt"):
        require((path / name).read_text().strip() == "0", f"{path/name}: native success")
    require((root / f"k{k}-wrapper.exit").read_text().strip() == "0", "native cell wrapper success")
    for name in ("harness.pid", "daemon.pid"):
        require(not (Path("/proc") / (path / name).read_text().strip()).exists(), "native owned process reaped")
    config = (path / "config.toml").read_text()
    runtime_paths = re.findall(r'/tmp/rr-control-cell\.[^/"\s]+', config)
    require(runtime_paths and all(not Path(x).exists() for x in runtime_paths), "owned scenario removed")
    return raw((path / "reloadstall.log").read_text().splitlines(), k) | {"quiet": quiet(path / "quiet.tsv"), "cleanup": "native exits zero; no forced kills; owned PIDs and scenario absent"}


def main():
    root = Path(sys.argv[1])
    require((root / "campaign.exit").read_text().strip() == "0", "native campaign success")
    a, b = cell(root, 1), cell(root, 50)
    ratios = [y["completion_max_us"] / x["completion_max_us"] for x, y in zip(a["rounds"], b["rounds"], strict=True)]
    decision = "all ratios <=3: decline cohort" if all(x <= 3 for x in ratios) else "all ratios >3: serialized shape only; cohort not authorized" if all(x > 3 for x in ratios) else "mixed ratios: inconclusive"
    print(json.dumps({"validated": True, "k1": a, "k50": b, "k50_k1_max_completion_ratios": ratios, "shape_decision": decision, "readiness_scope": "successful sampled overlaps only; no continuous-readiness claim"}, indent=2))


if __name__ == "__main__":
    main()
