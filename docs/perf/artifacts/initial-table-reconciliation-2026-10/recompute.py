#!/usr/bin/env python3
"""Validate the compact ordinary-S3 receipt and recompute its frozen bars."""
import csv
from decimal import Decimal
import hashlib
import json
import math
import statistics
import sys
from pathlib import Path

LEGS = ["01-control", "02-candidate", "03-candidate", "04-control", "05-control", "06-candidate"]
PAIRS = [(LEGS[0], LEGS[1]), (LEGS[3], LEGS[2]), (LEGS[4], LEGS[5])]
METRICS = ["first_reann_s", "reannounce_s", "withdraw_s", "rejoin_complete_s"]
CANONICAL = {"N_PEERS": "700", "TOTAL_PREFIXES": "400400", "PORT": "1790", "RELOADS": "4",
             "CONTROL_SECS": "30", "CHANGED_PEERS": "", "FLAPSTORM": "50", "BIRD_THREADS": "8",
             "PROBE_PREFIXES": "", "FLAP_ROUNDS": "3"}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def read_csv(root, name):
    with (root / name).open() as file:
        return list(csv.DictReader(file))


def quantile(values, fraction):
    return sorted(values)[math.floor((len(values) - 1) * fraction + .5)]


def summarize(rows):
    result = {}
    for metric in [m + "_" + q for m in METRICS for q in ["p50", "p95", "max"]]:
        arms = {mode: statistics.median(r[metric] for r in rows if r["mode"] == mode)
                for mode in ["control", "candidate"]}
        legs = {leg: statistics.median(r[metric] for r in rows if r["leg"] == leg) for leg in LEGS}
        result[metric] = {**arms, "delta_ms": 1000 * (arms["candidate"] - arms["control"]),
                          "change_pct": 100 * (arms["candidate"] / arms["control"] - 1),
                          "pair_changes_pct": [100 * (legs[b] / legs[a] - 1) for a, b in PAIRS],
                          "leg_medians_s": legs}

    def micros(metric, arm):
        return int(Decimal(str(result[metric][arm])) * 1_000_000)

    first_control = micros("first_reann_s_p50", "control")
    first_candidate = micros("first_reann_s_p50", "candidate")
    gates = {
        "first_20ms": first_control - first_candidate >= 20_000,
        "first_10pct": first_candidate * 100 <= first_control * 90,
        "first_all_pairs_improve": all(v < 0 for v in result["first_reann_s_p50"]["pair_changes_pct"]),
        "withdraw_limit": micros("withdraw_s_p50", "candidate") * 100 <= micros("withdraw_s_p50", "control") * 103,
        "full_reannounce_limit": micros("reannounce_s_p50", "candidate") * 100 <= micros("reannounce_s_p50", "control") * 103,
        "returning_p50_not_slower": micros("rejoin_complete_s_p50", "candidate") <= micros("rejoin_complete_s_p50", "control"),
        "returning_max_not_slower": micros("rejoin_complete_s_max", "candidate") <= micros("rejoin_complete_s_max", "control"),
    }
    return {"endpoints": result, "acceptance": gates, "verdict": "qualifies" if all(gates.values()) else "hold"}


def main(root):
    provenance = json.loads((root / "provenance.json").read_text())
    need(hashlib.sha256((root / "common-qualification.patch").read_bytes()).hexdigest()
         == provenance["sha256"]["common-qualification.patch"], "common harness patch hash")
    rows = read_csv(root, "rounds.csv")
    expected = {(leg, str(r)) for leg in LEGS for r in range(1, 4)}
    need(len(rows) == 18 and {(r["leg"], r["round"]) for r in rows} == expected, "exactly 18 unique rounds required")
    for row in rows:
        need(row["mode"] == row["leg"].split("-", 1)[1], "wrong arm")
        for metric in METRICS:
            values = [float(row[metric + "_" + q]) for q in ["p50", "p95", "max"]]
            need(all(math.isfinite(v) and v > 0 for v in values) and values == sorted(values), "invalid endpoint quantiles")
            row.update({metric + "_" + q: value for q, value in zip(["p50", "p95", "max"], values)})

    legs = json.loads((root / "legs.json").read_text())
    need([leg["leg"] for leg in legs] == LEGS, "six ordered leg receipts required")
    for role in ["daemon", "harness"]:
        need(len({leg["process_identity_sha256"][role] for leg in legs}) == 6, "fresh process identities required")
    previous_end = 0
    for leg in legs:
        need(leg["status"] == "pass" and leg["runner_exit"] == leg["qualification_exit"] == 0, "failed leg")
        need(set(leg["exits"]) == {"harness", "daemon", "cleanup", "health-before", "health-after"}
             and set(leg["http"]) == {"health-before", "health-after"}, "native check roster")
        need(all(v == 0 for v in leg["exits"].values()) and all(v == 200 for v in leg["http"].values()), "native check failure")
        need(leg["workload"] == CANONICAL, "noncanonical workload")
        arm = leg["leg"].split("-", 1)[1]
        need(leg["binary_sha256"] == provenance["sha256"]["rustbgpd-" + arm]
             and leg["harness_sha256"] == provenance["sha256"]["reloadstall-common"], "binary/harness identity mismatch")
        need(leg["source_and_binary_freeze_equal"] is True, "source/binary drift")
        stamps = leg["stage_ns"]
        need(len(stamps) == 10 and previous_end < stamps[0] and all(a < b for a, b in zip(stamps, stamps[1:])), "stage/process chronology")
        need(stamps[2] - stamps[1] >= 30_000_000_000 and stamps[8] - stamps[7] >= 300_000_000_000, "quiet/cooldown duration")
        previous_end = stamps[-1]
        quiet = leg["quiet"]
        need(len(quiet) == 2 and all(q["quiet"] == "true" and q["competitors"] == q["failed_dimensions"] == "none" for q in quiet), "quiet gate")
        need(float(quiet[1]["epoch_s"]) - float(quiet[0]["epoch_s"]) >= 30, "quiet spacing")
        readiness = leg["readiness"]
        need(len(readiness) == 3 and {r["round"] for r in readiness} == {1, 2, 3}
             and all(r["samples"] > 0 and r["failures"] == 0 and r["deadline_ms"] == 250 for r in readiness), "readiness coverage/failure")
        need(leg["sessions_and_parse"] == [{"round": r, "sessions_up": 700, "parse_errors": 0} for r in range(1, 4)], "sessions/parse coverage")
        need(leg["initial_exact_coverage"] == "first_exact_bitmap,mode=flapstorm,peers=700,total=400400,per_peer=572,expected=399828,completed=700,min_unique=399828,max_unique=399828", "initial exact coverage")

    catches = read_csv(root, "catchup.csv")
    arrivals = read_csv(root, "survivors.csv")
    for records, peers in [(catches, range(50)), (arrivals, range(50, 700))]:
        identities = {(leg, r, str(p)) for leg, r in expected for p in peers}
        need(len(records) == len(identities) and {(r["leg"], r["round"], r["peer"]) for r in records} == identities, "exact peer-round coverage required")
        for record in records:
            for key in record.keys() - {"leg", "round"}:
                record[key] = int(record[key])
    for row in rows:
        selected = lambda records, row=row: [r for r in records if (r["leg"], r["round"]) == (row["leg"], row["round"])]
        peers, survivors = selected(catches), selected(arrivals)
        for c in peers:
            need(c["unique"] == c["target"] == 399828, "returning current coverage")
            need(0 < c["open_us"] < c["complete_us"] and c["open_us"] <= c["eor_us"] <= c["complete_us"]
                 and c["open_us"] <= c["current_full_us"] <= c["complete_us"], "returning EoR/current-full ordering")
        need(len({a["trigger_us"] for a in survivors}) == 1, "multiple survivor clocks")
        need(all(0 < a["trigger_us"] <= a["first_us"] <= a["complete_us"]
                 and a["trigger_us"] <= a["affected_first_us"] <= a["complete_us"] for a in survivors), "survivor clock ordering")
        need(int(row["published_equals_affected"]) == sum(a["first_us"] == a["affected_first_us"] for a in survivors)
             and int(row["affected_before_trigger"]) == 0, "arrival identity summary mismatch")
        values = {"first_reann_s": [(a["first_us"] - a["trigger_us"]) / 1e6 for a in survivors],
                  "reannounce_s": [(a["complete_us"] - a["trigger_us"]) / 1e6 for a in survivors],
                  "rejoin_complete_s": [(c["complete_us"] - c["open_us"]) / 1e6 for c in peers]}
        for metric, observations in values.items():
            for q, fraction in [("p50", .5), ("p95", .95), ("max", 1)]:
                need(abs(quantile(observations, fraction) - row[metric + "_" + q]) < .00000051, "endpoint/observer quantile mismatch")
    result = summarize(rows)
    result["returning_peer_pairs"] = [
        {"control_leg": a, "candidate_leg": b, "peer": peer,
         "control_s": statistics.median((c["complete_us"] - c["open_us"]) / 1e6 for c in catches if c["leg"] == a and c["peer"] == peer),
         "candidate_s": statistics.median((c["complete_us"] - c["open_us"]) / 1e6 for c in catches if c["leg"] == b and c["peer"] == peer)}
        for a, b in PAIRS for peer in range(50)]
    for pair in result["returning_peer_pairs"]:
        pair["delta_ms"] = 1000 * (pair["candidate_s"] - pair["control_s"])
        pair["change_pct"] = 100 * (pair["candidate_s"] / pair["control_s"] - 1)
    result["first_arrival_identity"] = {"observations": len(arrivals),
                                        "published_equals_affected": sum(a["first_us"] == a["affected_first_us"] for a in arrivals),
                                        "affected_before_trigger": sum(a["affected_first_us"] < a["trigger_us"] for a in arrivals)}
    return result


if __name__ == "__main__":
    print(json.dumps(main(Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent), indent=2, allow_nan=False))
