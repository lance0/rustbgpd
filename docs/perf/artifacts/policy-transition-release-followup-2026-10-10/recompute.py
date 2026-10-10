#!/usr/bin/env python3
"""Recompute the per-reload boundary table and both arm summaries."""

import csv
import datetime
import io
import json
import pathlib
import statistics
import sys

ROOT = pathlib.Path(__file__).resolve().parent


def compute(root, prefix, reloads_per_run):
    records = json.loads((root / f"{prefix}-reloads.json").read_text())
    timeline = [json.loads(line) for line in (root / f"{prefix}-timeline.jsonl").read_text().splitlines()]
    expected = {(f"{arm}-r{run}", reload) for arm in ("pre2952", "post2952")
                for run in (1, 2) for reload in range(1, reloads_per_run + 1)}
    identities = [(record["run"], record["reload"]) for record in records]
    assert len(identities) == len(expected) and set(identities) == expected, "missing or duplicate reload"
    rows = []
    in_band_pairs = dict.fromkeys({run for run, _ in expected}, 0)
    for record in records:
        identity = record["run"], record["reload"]
        assert set(record["exits"]) == {"cell", "daemon", "engine", "probe"}, "missing exit"
        assert record["cell_verdict"] == "PASS" and set(record["exits"].values()) == {0}, "failed cell"
        assert record["rib_transition"]["outcome"] == "committed", "wrong transition outcome"
        assert record["sighup_wall"] < record["rib_commit_wall"] < record["complete_wall"], "invalid boundary"
        events = [event for event in timeline if (event["run"], event["reload"]) == identity]
        for column, message in (("sighup_wall", "SIGHUP received, reloading configuration"),
                                ("rib_commit_wall", "RIB export-policy transition completed"),
                                ("complete_wall", "config reload complete (one runtime generation)")):
            matches = [event for event in events if event["fields"].get("message") == message]
            assert len(matches) == 1, "missing or duplicate boundary log"
            assert datetime.datetime.fromisoformat(matches[0]["timestamp"]).timestamp() == record[column], "boundary differs from selected log"
            if column == "rib_commit_wall":
                assert matches[0]["fields"] == record["rib_transition"], "transition differs from selected log"
        phases = [event for event in events if event["fields"].get("message") == "reload generation phase timing"]
        assert len(phases) == 1, "missing or duplicate phase log"
        phase_wall = datetime.datetime.fromisoformat(phases[0]["timestamp"]).timestamp()
        assert record["rib_commit_wall"] <= phase_wall <= record["complete_wall"], "phase outside completion"
        calls = record["calls"]
        assert len(calls) == 3 and {(call["phase"], call["op"]) for call in calls} == {
            ("pair", "neighbor"), ("pair", "policy_stats"), ("quiescent", "policy_stats")}, "wrong probe identities"
        assert all(call["exit"] == 0 and 0 <= call["duration_ms"] <= 2000 for call in calls), "failed or over-deadline probe"
        in_band_pairs[record["run"]] += all(-220 <= call["start_minus_rib_commit_ms"] <= 0
                                           for call in calls if call["phase"] == "pair")
        neighbor = next(call for call in calls if call["op"] == "neighbor")
        phase = record["phase_timing"]
        assert phase == phases[0]["fields"], "phase differs from selected log"
        assert record["rib_transition"]["member_count"] == 1000, "wrong member count"
        assert phase["outcome"] == "committed" and phase["authoritative_fallback"] is False, "wrong phase outcome"
        assert phase["total_targets"] == phase["cohort_targets"] == 1000 and phase["remainder_targets"] == 0, "wrong cohort shape"
        row = {
            "run": record["run"], "reload": record["reload"],
            "sighup_to_complete_ms": (record["complete_wall"] - record["sighup_wall"]) * 1000,
            "prestage_ms": phase["cohort_prestage_session_apply_us"] / 1000,
            "rib_ms": record["rib_transition"]["elapsed_ms"],
            "cohort_ms": phase["cohort_rib_transition_us"] / 1000,
            "before_phase_ms": (phase_wall - record["sighup_wall"]) * 1000 - phase["total_us"] / 1000,
            "preflight_ms": phase["preflight_us"] / 1000,
            "selection_ms": phase["cohort_selection_us"] / 1000,
            "cohort_outside_rib_ms": phase["cohort_rib_transition_us"] / 1000 - record["rib_transition"]["elapsed_ms"],
            "remainder_ms": phase["authoritative_remainder_apply_us"] / 1000,
            "refresh_ms": phase["deferred_refresh_dispatch_us"] / 1000,
            "convergence_ms": phase["convergence_check_us"] / 1000,
            "unattributed_ms": phase["unattributed_us"] / 1000,
            "after_phase_ms": (record["complete_wall"] - phase_wall) * 1000,
            "rib_to_phase_ms": (phase_wall - record["rib_commit_wall"]) * 1000,
            "rib_to_complete_ms": (record["complete_wall"] - record["rib_commit_wall"]) * 1000,
            "neighbor_duration_ms": neighbor["duration_ms"],
            "neighbor_start_to_rib_ms": neighbor["start_minus_rib_commit_ms"],
            "neighbor_end_to_rib_ms": neighbor["duration_ms"] + neighbor["start_minus_rib_commit_ms"],
        }
        trace = next((event for event in events if event["fields"].get("message") == "post-commit first general query timing"), None)
        for column in ("rib_to_trace_arm_ms", "trace_arm_to_phase_ms", "post_query_wait_ms", "post_query_busy_ms", "post_query_unattributed_ms"):
            row[column] = None
        if trace:
            fields = trace["fields"]
            arm_wall = datetime.datetime.fromisoformat(trace["timestamp"]).timestamp() - fields["first_query_wait_us"] / 1_000_000
            row.update({
                "rib_to_trace_arm_ms": (arm_wall - record["rib_commit_wall"]) * 1000,
                "trace_arm_to_phase_ms": (phase_wall - arm_wall) * 1000,
                "post_query_wait_ms": fields["first_query_wait_us"] / 1000,
                "post_query_busy_ms": fields["busy_us"] / 1000,
                "post_query_unattributed_ms": fields["unattributed_us"] / 1000,
            })
        rows.append(row)
    assert all(count >= 6 for count in in_band_pairs.values()), "fewer than six complete in-band pairs"
    rows.sort(key=lambda row: (row["run"], row["reload"]))
    summary = {}
    for label in sorted({row["run"] for row in rows}) + ["pre2952", "post2952"]:
        selected = [row for row in rows if row["run"] == label or row["run"].startswith(label + "-")]
        summary[label] = {"reloads": len(selected), "long_post_commit_cases": sum(row["rib_to_phase_ms"] > 100 for row in selected)}
        for column in list(rows[0])[2:]:
            values = [row[column] for row in selected if row[column] is not None]
            summary[label][column] = ({"n": len(values), "median": round(statistics.median(values), 3), "mean": round(statistics.mean(values), 3),
                                       "min": round(min(values), 3), "max": round(max(values), 3)} if values else None)
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=list(rows[0]), lineterminator="\n")
    writer.writeheader()
    writer.writerows({key: round(value, 6) if isinstance(value, float) else value for key, value in row.items()} for row in rows)
    return summary, buffer.getvalue()


def main():
    root = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT
    for prefix, count in (("j2", 12), ("confirmation", 8)):
        summary, table = compute(root, prefix, count)
        assert json.loads((root / f"{prefix}-summary.json").read_text()) == summary, "summary differs"
        assert (root / f"{prefix}-correlation.csv").read_text() == table, "boundary table differs"
        print(json.dumps({prefix: summary}, sort_keys=True, indent=2))
    summary = prior_steps(root)
    assert json.loads((root / "pre2952-summary.json").read_text()) == summary, "prior-step summary differs"
    print(json.dumps({"pre2952": summary}, sort_keys=True, indent=2))


def prior_steps(root):
    with (root / "pre2952-actor-reloads.csv").open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    provenance = json.loads((root / "pre2952-provenance.json").read_text())
    summary = {}
    for campaign, arms, runs in (("early-s2", ("base", "main"), 3),
                                 ("prefix-snapshot-s2", ("main", "memo", "snap"), 4)):
        expected = {(arm, str(run), str(reload)) for arm in arms for run in range(1, runs + 1) for reload in range(1, 5)}
        selected = [row for row in rows if row["campaign"] == campaign]
        identities = [(row["arm"], row["run"], row["reload"]) for row in selected]
        assert len(identities) == len(expected) and set(identities) == expected, "missing prior-step reload"
        assert all(row["outcome"] == "committed" and row["member_count"] == "700" for row in selected)
        assert all(source["status"] == "pass" and source["daemon_exit"] == 0 for source in provenance[campaign]["sources"].values())
        summary[campaign] = {}
        for arm in arms:
            for label, minimum in ((arm, 1), (arm + "-reloads2to4", 2)):
                values = [int(row["elapsed_ms"]) for row in selected if row["arm"] == arm and int(row["reload"]) >= minimum]
                summary[campaign][label] = {"n": len(values), "median": statistics.median(values), "min": min(values), "max": max(values)}
    assert len(rows) == 72, "unexpected prior-step campaign"
    return summary


if __name__ == "__main__":
    main()
