#!/usr/bin/env python3
"""Extract the per-reload daemon-log rows of this bundle from the retained campaign.

Usage: extract_daemon_log.py CAMPAIGN_DIR OUT_DIR

CAMPAIGN_DIR is the original `just bench-headline` output, which keeps each
leg's full daemon.log (not published). Writes rib-export-transition.csv and
generation-phase.csv to OUT_DIR. Each reload runs from "SIGHUP received" to
"config reload complete"; every reload must carry exactly one of each record
read below, or the script fails.
"""
import csv
import json
import sys
from datetime import datetime
from pathlib import Path

LEGS = [f"matrix-{arm}-r{run}-s2" for arm in ("main", "fast") for run in (1, 2, 3, 4)]


def when(record):
    return datetime.fromisoformat(record["timestamp"].replace("Z", "+00:00")).timestamp()


def reloads(path):
    current, out = None, []
    for line in path.read_text().splitlines():
        if not line.startswith("{"):
            continue
        record = json.loads(line)
        fields = record.get("fields", {})
        message = fields.get("message", "")
        if message.startswith("SIGHUP received"):
            if current is not None:
                raise SystemExit(f"{path}: SIGHUP while a reload is pending")
            current = {"sighup": when(record)}
        elif current is None:
            continue
        elif message in ("RIB export-policy transition completed",
                         "cohort destination prestage round trip",
                         "reload generation phase timing"):
            if message in current:
                raise SystemExit(f"{path}: duplicate {message!r} in one reload")
            current[message] = fields
        elif message.startswith("config reload complete"):
            current["complete"] = when(record)
            out.append(current)
            current = None
    if current is not None:
        raise SystemExit(f"{path}: SIGHUP never completed")
    return out


def main():
    source, dest = Path(sys.argv[1]), Path(sys.argv[2])
    rib_rows, phase_rows = [], []
    for leg in LEGS:
        _, arm, run, _ = leg.split("-")
        found = reloads(source / leg / "rustbgpd" / "daemon.log")
        if len(found) != 4:
            raise SystemExit(f"{leg}: {len(found)} reloads, expected 4")
        for index, reload in enumerate(found, 1):
            rib = reload["RIB export-policy transition completed"]
            prestage = reload["cohort destination prestage round trip"]
            phase = reload["reload generation phase timing"]
            rib_rows.append([leg, arm, run[1:], index, rib["elapsed_ms"], rib["outcome"],
                             rib["member_count"]])
            phase_rows.append([
                leg, arm, run[1:], index,
                round((reload["complete"] - reload["sighup"]) * 1000, 1),
                prestage["elapsed_ms"],
                round(phase["cohort_prestage_session_apply_us"] / 1000, 1),
                round(phase["cohort_rib_transition_us"] / 1000, 1),
                round(phase["deferred_refresh_dispatch_us"] / 1000, 1),
                round(phase["total_us"] / 1000, 1),
                phase["outcome"],
            ])
    with open(dest / "rib-export-transition.csv", "w", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(["leg", "arm", "run", "reload", "elapsed_ms", "outcome", "member_count"])
        writer.writerows(rib_rows)
    with open(dest / "generation-phase.csv", "w", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(["leg", "arm", "run", "reload", "sighup_to_complete_ms",
                         "prestage_round_trip_ms", "prestage_session_apply_ms",
                         "cohort_rib_transition_ms", "deferred_refresh_dispatch_ms",
                         "generation_total_ms", "outcome"])
        writer.writerows(phase_rows)


if __name__ == "__main__":
    main()
