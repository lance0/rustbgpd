#!/usr/bin/env python3
"""Post-campaign diagnostics only; this overhead-failed cohort proves no cause."""
import math
import statistics
from collections import Counter
from pathlib import Path

import analyze_receiver as ar

PROBES = ["02-probe", "03-probe", "06-probe"]


def q(values, p):
    return sorted(values)[math.floor((len(values) - 1) * p + .5)]


def bounds_summary(rows):
    if not rows:
        return {}
    return {name: {label: [q([r[name][0] for r in rows], p),
                           q([r[name][1] for r in rows], p)]
                   for label, p in [("p50", .5), ("p95", .95), ("max", 1)]}
            for name in rows[0]}


def phase_rows(member, receiver, writer, polls, receiver_clock, daemon_clock):
    """Return separated diagnostics and conservative absolute interval bounds."""
    m, r, w = member, receiver, writer
    dl, dh = receiver_clock[0] - daemon_clock[1], receiver_clock[1] - daemon_clock[0]
    phases, intervals = {}, {}

    def add(name, start, end, duration=None):
        intervals[name] = [start, end]
        phases[name] = ([end[0] - start[1], end[1] - start[0]]
                        if duration is None else duration)
        phases[name] = [v / 1e6 for v in phases[name]]

    def daemon(t):
        return [t - dh, t - dl]

    def receiver_time(t):
        return [t, t]

    add("release_to_entry", [m["release_before"] - dh, m["release_after"] - dl], daemon(m["entry"]),
        [max(0, m["entry"] - m["release_after"]), m["entry"] - m["release_before"]])
    if m["producer"] == 0:
        ready = [max(m["entry"], m["publication_before"]), max(m["entry"], m["publication_after"])]
        add("entry_to_eligible_publication", daemon(m["entry"]), [ready[0] - dh, ready[1] - dl],
            [ready[0] - m["entry"], ready[1] - m["entry"]])
        add("eligible_ready_to_advance", [ready[0] - dh, ready[1] - dl], daemon(m["poll"]),
            [max(0, m["poll"] - ready[1]), max(0, m["poll"] - ready[0])])
        add("advance_to_snapshot_end", daemon(m["poll"]), daemon(m["snapshot_after"]),
            [m["snapshot_after"] - m["poll"]] * 2)
        add("snapshot_to_enqueue_start", daemon(m["snapshot_after"]), daemon(m["admission_before"]),
            [m["admission_before"] - m["snapshot_after"]] * 2)
    else:
        add("encoder_entry_to_admission", daemon(m["entry"]), daemon(m["admission_after"]),
            [m["admission_after"] - m["entry"]] * 2)
    add("enqueue_bracket", daemon(m["admission_before"]), daemon(m["admission_after"]),
        [m["admission_after"] - m["admission_before"]] * 2)
    target_last_byte = r["frame_end"] - 1
    last = next(p for p in polls if p["result"] > 0
                and w["stream_start"] + p["offset"] <= target_last_byte
                < w["stream_start"] + p["offset"] + p["result"])
    add("last_accept_to_read_poll", [last["before"] - dh, last["after"] - dl], receiver_time(r["last_ready"]))
    for name, start, end in [("last_read_poll", "last_ready", "last_done"),
                             ("final_read_to_decode_start", "last_done", "decode_start"),
                             ("decode", "decode_start", "decode_end"),
                             ("classification", "decode_end", "classify_end")]:
        add(name, receiver_time(r[start]), receiver_time(r[end]))
    return phases, intervals


def overlap(intervals, span):
    # Native event timestamps truncate to microseconds. Retain that uncertainty.
    begin, end = span["start"] * 1000, span["end"] * 1000
    return {name: [max(0, min(stop[0], end) - max(start[1], begin + 999)) / 1e6,
                   max(0, min(stop[1], end + 999) - max(start[0], begin)) / 1e6]
            for name, (start, stop) in intervals.items()}


def associations(outcomes, ids, round_, kind):
    relation = "first_generation_max_gap_relation" if kind == "gap" else "first_generation_all_gap_relation"
    rows = [outcomes[round_, i] for i in ids]
    spans = [s for o in rows for s in o[kind + "s"]]
    return {"observers": len(rows), "relation_counts": dict(Counter(o[relation] for o in rows)),
            "retained_maximum_spans": len(spans),
            "observers_with_tied_maxima": sum(len(o[kind + "s"]) > 1 for o in rows),
            "span_kinds": dict(Counter(s["kind"] for s in spans)),
            "first_frame_endpoint_span_count": sum(s["kind"] != "trailing" and s["end"] == o["first"]
                                                   for o in rows for s in o[kind + "s"])}


def analyze(campaign_path, collector):
    """Return diagnostics from retained records; write nothing."""
    campaign = Path(campaign_path)
    assert not collector["overhead_qualified"]
    result = {"interpretation": "diagnostic null: overhead failed; no production cause or optimization qualifies",
              "method": {"rank": "For each process, median of four within-round follower p95 bounds, descending lower bound. Never sum these quantiles.",
                         "cohort": "Worst ceil(700*0.05)=35 observers per round and gap definition, retaining every observer tied at that cutoff.",
                         "bounds": "Signed accepted-write to successful-read-poll bounds retained. Native-gap intersections retain timestamp truncation uncertainty.",
                         "omitted_overlapping_rank_fields": ["entry_to_admission for followers", "eligible_ready_to_snapshot_end", "first_accept_to_first_read_poll", "frame_read_completion_span"],
                         "limits": ["First-generation frame only; no claim about other maximum-gap endpoints.",
                                    "Ranks describe separate distributions, not one peer's additive latency budget.",
                                    "No kernel readiness, runnable time, wakeup attribution or recoverable-gain estimate."]},
              "processes": [], "control_outcome_associations": []}
    for leg in PROBES:
        folder = campaign / leg
        harness, daemon, publication = folder / "matrix/rustbgpd/reloadstall.log", folder / "matrix/rustbgpd/daemon.log", folder / "publication.csv"
        outcomes, receivers, clocks, _ = ar.read_harness(harness, 700, True)
        writers, polls = ar.read_daemon(daemon)
        _, daemon_clock = ar.read_publication(publication)
        collected = next(l for l in collector["legs"] if l["arm"] == "probe" and l["pair"] == PROBES.index(leg) + 1)
        members = {(m["group"], m["peer"]): m for m in collected["detail"]["publication"]["rows"]}
        process = {"leg": leg, "rounds": []}
        cohorts = {kind: [] for kind in ("gap", "all_gap")}
        for round_ in range(1, 5):
            receiver_clock = ar.clock_interval([clocks[round_, k] for k in ("before", "after")])
            phases, intervals = {}, {}
            encoders = []
            for i in range(700):
                key = (round_, ar.peer_for(i))
                m, r, w = members[key], receivers[round_, i], writers[key]
                pp = [polls[*key, n] for n in range(w["count"])]
                phases[i], intervals[i] = phase_rows(m, r, w, pp, receiver_clock, daemon_clock)
                if m["producer"]:
                    encoders.append(i)
            assert len(encoders) == 1
            followers = [i for i in range(700) if i not in encoders]
            summary = bounds_summary([phases[i] for i in followers])
            row = {"round": round_, "follower_phase_bounds_ms": summary,
                   "follower_p95_rank": sorted(summary, key=lambda name: summary[name]["p95"][0], reverse=True),
                   "encoder": {"observer": encoders[0], "phases_ms": phases[encoders[0]]},
                   "first_last_same_read": sum(all(receivers[round_, i]["first_" + k] == receivers[round_, i]["last_" + k]
                                                  for k in ("start", "end", "ready", "done")) for i in range(700)),
                   "gap_cohorts": {}}
            for kind in ("gap", "all_gap"):
                values = sorted(outcomes[round_, i][kind] for i in range(700))
                cutoff = values[-math.ceil(700 * .05)]
                ids = [i for i in range(700) if outcomes[round_, i][kind] >= cutoff]
                maximum_ids = [i for i in range(700) if outcomes[round_, i][kind] == values[-1]]
                cohorts[kind].append(set(ids))
                matched = [i for i in ids if i in followers and any(s["kind"] != "trailing" and s["end"] == outcomes[round_, i]["first"]
                                                                   for s in outcomes[round_, i][kind + "s"])]
                overlaps = [overlap(intervals[i], span) for i in matched for span in outcomes[round_, i][kind + "s"]
                            if span["kind"] != "trailing" and span["end"] == outcomes[round_, i]["first"]]
                row["gap_cohorts"][kind] = {"all_observers": associations(outcomes, range(700), round_, kind),
                                           "all_tied_maximum_observers": [{"observer": i, "spans": outcomes[round_, i][kind + "s"]}
                                                                          for i in range(700) if len(outcomes[round_, i][kind + "s"]) > 1],
                                           "worst5pct": {"cutoff_ms": cutoff, "observer_ids": ids, "extra_cutoff_ties": len(ids) - 35,
                                                         **associations(outcomes, ids, round_, kind)},
                                           "absolute_maximum": {"value_ms": values[-1], "observer_ids": maximum_ids,
                                                                **associations(outcomes, maximum_ids, round_, kind),
                                                                "spans": [{"observer": i, "spans": outcomes[round_, i][kind + "s"]} for i in maximum_ids]},
                                           "matched_worst_follower_ids": matched,
                                           "matched_worst_follower_first_frame_phase_bounds_ms": bounds_summary([phases[i] for i in matched]),
                                           "matched_worst_follower_gap_intersection_bounds_ms": bounds_summary(overlaps)}
            process["rounds"].append(row)
        summaries = [r["follower_phase_bounds_ms"] for r in process["rounds"]]
        process["median_round_follower_p95_bounds_ms"] = {name: [statistics.median(s[name]["p95"][j] for s in summaries) for j in (0, 1)] for name in summaries[0]}
        process["median_round_follower_p95_rank"] = sorted(process["median_round_follower_p95_bounds_ms"],
                                                         key=lambda name: process["median_round_follower_p95_bounds_ms"][name][0], reverse=True)
        process["cohort_turnover"] = {kind: {"union_observers": len(set.union(*sets)), "present_all_four_rounds": sorted(set.intersection(*sets)),
                                                "successive_intersection_counts": [len(a & b) for a, b in zip(sets, sets[1:])]} for kind, sets in cohorts.items()}
        process["matched_worst_follower_gap_intersection_median_round_p95"] = {}
        for kind in ("gap", "all_gap"):
            summaries = [r["gap_cohorts"][kind]["matched_worst_follower_gap_intersection_bounds_ms"] for r in process["rounds"]]
            values = {name: [statistics.median(s[name]["p95"][j] for s in summaries) for j in (0, 1)] for name in summaries[0]}
            process["matched_worst_follower_gap_intersection_median_round_p95"][kind] = {
                "bounds_ms": values, "rank": sorted(values, key=lambda name: values[name][0], reverse=True)}
        result["processes"].append(process)
    result["top_rank_repeats_all_three_processes"] = len({p["median_round_follower_p95_rank"][0] for p in result["processes"]}) == 1
    result["matched_worst_top_rank_repeats_all_three_processes"] = {
        kind: len({p["matched_worst_follower_gap_intersection_median_round_p95"][kind]["rank"][0] for p in result["processes"]}) == 1
        for kind in ("gap", "all_gap")}
    for leg in ("01-control", "04-control", "05-control"):
        path = campaign / leg / "matrix/rustbgpd/reloadstall.log"
        outcomes, _, _, _ = ar.read_harness(path, 700, False)
        process = {"leg": leg,
                   "scope": "First-generation event only; control has no instrumented frame or phase intervals.", "rounds": []}
        for round_ in range(1, 5):
            row = {"round": round_, "gap_cohorts": {}}
            for kind in ("gap", "all_gap"):
                values = sorted(outcomes[round_, i][kind] for i in range(700))
                cutoff = values[-math.ceil(700 * .05)]
                ids = [i for i in range(700) if outcomes[round_, i][kind] >= cutoff]
                maximum_ids = [i for i in range(700) if outcomes[round_, i][kind] == values[-1]]
                row["gap_cohorts"][kind] = {"all_observers": associations(outcomes, range(700), round_, kind),
                                           "all_tied_maximum_observers": [{"observer": i, "spans": outcomes[round_, i][kind + "s"]}
                                                                          for i in range(700) if len(outcomes[round_, i][kind + "s"]) > 1],
                                           "worst5pct": {"cutoff_ms": cutoff, "observer_ids": ids, "extra_cutoff_ties": len(ids) - 35,
                                                         **associations(outcomes, ids, round_, kind)},
                                           "absolute_maximum": {"value_ms": values[-1], "observer_ids": maximum_ids,
                                                                **associations(outcomes, maximum_ids, round_, kind)}}
            process["rounds"].append(row)
        result["control_outcome_associations"].append(process)
    return result
