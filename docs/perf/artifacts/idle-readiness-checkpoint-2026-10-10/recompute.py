#!/usr/bin/env python3
"""Recompute the extracted native clocks and require the declared acceptance."""

import csv
from datetime import datetime
import gzip
import hashlib
import json
import math
from pathlib import Path
import statistics as st

from compare_features import compare_scope, validate_capture

ROOT = Path(__file__).resolve().parent
CELLS = ("baseline-r1", "candidate-r1", "candidate-r2", "baseline-r2")
PHASES = [(r, p) for r in range(1, 4) for p in ("disconnected", "settled")]
ARMS = ("baseline", "candidate")


def distribution(values):
    assert values and all(math.isfinite(value) for value in values)
    return {
        "n": len(values),
        "median": st.median(values),
        "min": min(values),
        "max": max(values),
        "mean": st.mean(values),
    }


def elapsed(start, end):
    parse = lambda s: datetime.fromisoformat(s.replace("Z", "+00:00"))
    value = (parse(end) - parse(start)).total_seconds() * 1000
    assert value >= 0
    return value


def require_ok(text):
    lines = text.splitlines()
    assert lines and all(line.endswith(": OK") for line in lines)


def validate_provenance(data, audits, root=ROOT):
    acceptance = data["acceptance"]
    assert acceptance["schedule"] == list(CELLS)
    for key, value in {
        "peers": 700,
        "prefixes": 400400,
        "k": 1,
        "rounds_per_process": 3,
        "processes_per_arm": 2,
        "control_secs": 30,
        "native_exits": 0,
        "sessions_up": 700,
        "parse_errors": 0,
        "readiness_misses": 0,
        "required_table_eor_checkpoints_per_process": 6,
        "required_observer_requests_per_process": 12,
        "replay_gap_cutoff_ms": None,
        "quiet": True,
    }.items():
        assert acceptance[key] == value, key
    window = data["window"]
    assert elapsed(window["start"], window["finish"]) > 0
    assert window["abba_exit"] == window["outer_exit"] == 0
    assert window["reaped_at"] and "light" in window["lock_order"]
    require_ok(window["end_instruments"])
    require_ok(window["end_acceptance"])
    assert (
        "24 complete replay pairs (48 requests); all gaps retained" in window["native_extraction"]
    )
    harness = data["common_harness"]
    assert harness["source_identity"] == [
        acceptance["baseline"],
        acceptance["source_trees"]["baseline"],
    ]
    assert harness["sha256"] == acceptance["common_harness_sha256"]
    assert set(harness["exits"].values()) == {0}
    graph_hash = hashlib.sha256(
        gzip.decompress((root / "normal-build-graph.txt.gz").read_bytes())
    ).hexdigest()
    for arm in ARMS:
        build, audit = data["arms"][arm], audits[arm]
        assert build["source_commit"] == acceptance[arm]
        assert build["source_tree"] == acceptance["source_trees"][arm]
        assert build["source_status_at_build"] == "" and set(build["exits"].values()) == {0}
        assert (
            "cargo build --release --locked -j 4 -p rustbgpd -p rustbgpctl"
            in build["build_identity"]
        )
        assert build["toolchain"] == harness["toolchain"]
        assert build["normalized_resolution_sha256"] == graph_hash
        assert (
            build["input_refresh"]["sha256"]
            == hashlib.sha256(
                ("\0".join(build["input_refresh"]["relative_paths"]) + "\0").encode()
            ).hexdigest()
        )
        assert (
            audit["binary_sha256"]
            == audit["cache_binary_sha256"]
            == build["binary_sha256"]["rustbgpd"]
        )
        assert not audit["normal_missing"] and not audit["including_build_missing"]
        assert not validate_capture(audit), "bench-internals active in daemon/RIB"
        assert len(audit["normal_units"]) == 227 and len(audit["including_build_units"]) == 343
        assert set(audit["fingerprint_signatures"]) == set(audit["including_build_units"])
        # Reconstruct each captured closure by the original signature graph,
        # retaining every matching signature rather than discarding duplicates.
        lookup = {}
        for path, signature in audit["fingerprint_signatures"].items():
            number = int.from_bytes(bytes.fromhex(signature), "little")
            lookup.setdefault(number, []).append(path)
        for scope in ("normal_units", "including_build_units"):
            pending, seen = [audit["entry"]], set()
            while pending:
                path = pending.pop()
                if path in seen:
                    continue
                seen.add(path)
                unit = audit["including_build_units"][path]
                for dep in unit["deps"]:
                    if scope == "normal_units" and dep[1] == "build_script_build":
                        continue
                    assert dep[3] in lookup, "dependency signature missing"
                    pending.extend(lookup[dep[3]])
            assert seen == set(audit[scope]), "actual closure membership differs"
    assert (
        data["arms"]["baseline"]["binary_sha256"]["rbgp"]
        == data["arms"]["candidate"]["binary_sha256"]["rbgp"]
    )
    for scope in ("normal_units", "including_build_units"):
        report = compare_scope(
            audits["baseline"][scope], audits["candidate"][scope], scope == "including_build_units"
        )
        assert report == data["actual_feature_comparison"]["scopes"][scope]
        assert all(
            not report[key]
            for key in (
                "only_baseline_units",
                "only_candidate_units",
                "configuration_differences",
                "dependency_identity_differences",
            )
        )


def compute(records):
    assert tuple(records) == CELLS
    rows, pairs, phases, processes = {}, [], [], {}
    for cell, record in records.items():
        assert set(record["exits"].values()) == {0} and record["outer_cell_exit"] == 0
        assert record["forced_kill"] == 0
        assert (
            not record["full_daemon_scan"]["errors"]
            and not record["full_daemon_scan"]["readiness_failures"]
        )
        for integrity in record["integrity"].values():
            require_ok(integrity)
        quiet = record["quiet_samples"]
        assert len(quiet) == 2 and elapsed(record["started"], record["finished"]) > 0
        for sample in quiet:
            assert sample["quiet"] == "true" and sample["competitors"] == "none"
            assert sample["failed_dimensions"] == "none" and float(sample["load1"]) < 2
            assert sample["performance_governors"] == sample["governor_count"] == "64"
        assert (
            quiet[0]["pswpin"] == quiet[1]["pswpin"] and quiet[0]["pswpout"] == quiet[1]["pswpout"]
        )
        lines = record["harness_log"].splitlines()
        assert not any("FAIL:" in line or "STALLED:" in line for line in lines)
        assert any(line.startswith("done rss_mib=") for line in lines)
        assert (
            "first_exact_bitmap,mode=flapstorm,peers=700,total=400400,per_peer=572,expected=399828,completed=700,min_unique=399828,max_unique=399828"
            in lines
        )
        native = list(
            csv.reader(line for line in lines if line.startswith("converged_rejoin_csv,"))
        )
        assert len(native) == 3
        checks = []
        for line in lines:
            if line.startswith("converged_table_checkpoint,"):
                item = dict(part.split("=", 1) for part in line.split(",")[1:])
                assert (
                    item["observers"] == "1:2"
                    and item["unique"] == "399828"
                    and item["eor"] == "present"
                )
                checks.append((int(item["round"]), item["phase"]))
        assert checks == PHASES
        rows[cell] = []
        for round_number, row in enumerate(native, 1):
            assert len(row) == 12 and row[1:5] == [str(round_number), "700", "1", "400400"]
            assert float(row[5]) > 0 and float(row[6]) == float(row[5])
            assert float(row[7]) >= 0 and int(row[8]) > 0 and row[10:12] == ["700", "0"]
            assert (
                f"flap {round_number} peer 0 rejoin_complete_s={row[5]} eor_before_full_table=false eor=present"
                in lines
            )
            rows[cell].append(
                {
                    "round": round_number,
                    "rejoin_ms": float(row[5]) * 1000,
                    "rejoin_max_ms": float(row[6]) * 1000,
                    "survivor_maxgap_ms": float(row[7]),
                    "readiness_samples": int(row[8]),
                    "rss_mib": int(row[9]),
                    "sessions_up": int(row[10]),
                    "parse_errors": int(row[11]),
                }
            )
        selected = [item["event"] for item in record["selected_daemon_events"]]
        assert all(event["level"] != "ERROR" for event in selected)
        refresh = [
            event
            for event in selected
            if event["fields"]["message"] == "handling route refresh request"
        ]
        assert len(refresh) == 12
        for index, (round_number, phase) in enumerate(PHASES):
            first, second = refresh[2 * index : 2 * index + 2]
            assert {first["fields"]["peer"], second["fields"]["peer"]} == {"127.1.0.2", "127.1.0.3"}
            assert all(
                event["fields"]["afi"] == "Ipv4" and event["fields"]["safi"] == "Unicast"
                for event in (first, second)
            )
            pairs.append(
                {
                    "cell": cell,
                    "round": round_number,
                    "phase": phase,
                    "first": {
                        key: first["fields"][key] if key == "peer" else first[key]
                        for key in ("timestamp", "peer")
                    },
                    "second": {
                        key: second["fields"][key] if key == "peer" else second[key]
                        for key in ("timestamp", "peer")
                    },
                    "inter_handler_gap_ms": elapsed(first["timestamp"], second["timestamp"]),
                }
            )
        join = [
            event
            for event in selected
            if event["fields"]["peer"] == "127.1.0.1"
            and event["fields"]["message"] in ("session established", "sent End-of-RIB")
        ]
        assert len(join) == 8
        assert [event["fields"]["message"] for event in join] == [
            "session established",
            "sent End-of-RIB",
        ] * 4
        for index, row in enumerate(rows[cell]):
            start, end = join[2 + 2 * index : 4 + 2 * index]
            duration = elapsed(start["timestamp"], end["timestamp"])
            phases.append(
                {
                    "cell": cell,
                    "round": row["round"],
                    "native_rejoin_ms": row["rejoin_ms"],
                    "session_established": start["timestamp"],
                    "eor_enqueued_log": end["timestamp"],
                    "session_to_eor_enqueued_ms": duration,
                    "difference_of_durations_ms": row["rejoin_ms"] - duration,
                }
            )
        cell_pairs = [pair for pair in pairs if pair["cell"] == cell]
        processes[cell] = {
            "inter_handler_gap_ms": distribution(
                [pair["inter_handler_gap_ms"] for pair in cell_pairs]
            ),
            "by_checkpoint": {
                phase: distribution(
                    [pair["inter_handler_gap_ms"] for pair in cell_pairs if pair["phase"] == phase]
                )
                for phase in ("disconnected", "settled")
            },
            "by_round": {
                str(r): distribution(
                    [pair["inter_handler_gap_ms"] for pair in cell_pairs if pair["round"] == r]
                )
                for r in (1, 2, 3)
            },
            "rejoin_ms": distribution([row["rejoin_ms"] for row in rows[cell]]),
            "survivor_maxgap_ms": distribution([row["survivor_maxgap_ms"] for row in rows[cell]]),
            "readiness_samples": [row["readiness_samples"] for row in rows[cell]],
        }
    arms = {}
    for arm in ARMS:
        selected = [pair for pair in pairs if pair["cell"].startswith(arm)]
        native = [row for cell in CELLS if cell.startswith(arm) for row in rows[cell]]
        arms[arm] = {
            "processes": 2,
            "correlated_rounds": 6,
            "correlated_pairs": 12,
            "inter_handler_gap_ms": distribution(
                [pair["inter_handler_gap_ms"] for pair in selected]
            ),
            "by_checkpoint": {
                phase: distribution(
                    [pair["inter_handler_gap_ms"] for pair in selected if pair["phase"] == phase]
                )
                for phase in ("disconnected", "settled")
            },
            "first_round_gap_ms": distribution(
                [pair["inter_handler_gap_ms"] for pair in selected if pair["round"] == 1]
            ),
            "later_round_gap_ms": distribution(
                [pair["inter_handler_gap_ms"] for pair in selected if pair["round"] != 1]
            ),
            "rejoin_ms": distribution([row["rejoin_ms"] for row in native]),
            "survivor_maxgap_ms": distribution([row["survivor_maxgap_ms"] for row in native]),
            "readiness_samples": sum(row["readiness_samples"] for row in native),
        }
    return {"processes": processes, "arms": arms, "native_rounds": rows}, pairs, phases


def main():
    records = json.loads((ROOT / "records.json").read_text())
    provenance = json.loads((ROOT / "provenance.json").read_text())
    audits = json.loads((ROOT / "feature-audit.json").read_text())
    validate_provenance(provenance, audits)
    for record in records.values():
        for name, expected in record["normalized_generated_inputs"].items():
            assert hashlib.sha256((ROOT / "inputs" / name).read_bytes()).hexdigest() == expected
    report, pairs, phases = compute(records)
    stored = json.loads((ROOT / "summary.json").read_text())
    assert all(stored[key] == value for key, value in report.items())
    assert pairs == json.loads((ROOT / "observer-replay-pairs.json").read_text())
    assert phases == json.loads((ROOT / "rejoin-phase-clocks.json").read_text())
    print(
        "PASS: 4 processes, 12 rounds, 24 complete pairs, 48 requests; all native controls and actual closures match"
    )


if __name__ == "__main__":
    main()
