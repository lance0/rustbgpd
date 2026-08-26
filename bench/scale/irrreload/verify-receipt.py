#!/usr/bin/env python3
"""Validate IRR reload topology evidence and counterbalanced receipts."""

from __future__ import annotations

import argparse
import codecs
import csv
import hashlib
import json
import math
import mmap
import os
import re
import shutil
import stat
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path


COMPARISON_CELLS = ("rustbgpd-sighup", "bird", "openbgpd")
GROUPED_CELL = "rustbgpd-sighup-grouped-control"
TRANSACTION_CELL = "rustbgpd-txn"
PHASE_FIELDS = (
    "preflight_us", "cohort_selection_us", "cohort_prestage_session_apply_us",
    "cohort_rib_transition_us", "authoritative_remainder_apply_us",
    "deferred_refresh_dispatch_us", "convergence_check_us", "total_us",
    "unattributed_us",
)
AUTHORITATIVE_PHASES = (
    "precondition_us", "registration_membership_us", "cohort_partition_us",
    "cohort_precheck_us", "destination_build_us", "inventory_build_us",
    "membership_commit_us", "filtered_scope_build_us", "member_emit_state_us",
    "cohort_finalize_us", "fallback_regroup_us", "distribution_us",
    "duplicate_fallback_us",
)
CANONICAL_SHAPE = (320, 183040, 1000, 40000, 61)
CANONICAL_FULL_INPUTS = {
    "smoke": "",
    "n_members": "320",
    "total_prefixes": "183040",
    "min_list": "1000",
    "max_list": "40000",
    "seed": "61",
    "changed_fraction": "0.1",
    "port": "1790",
    "reloads": "4",
    "control_secs": "30",
    "txn_max_candidate_bytes": "402653184",
    "cell_timeout": "7200",
    "start_timeout": "600",
    "bird_threads": "8",
    "skip_preflight": "",
    "bird_image": "bird:3.3.1",
    "openbgpd_image": "openbgpd/openbgpd:9.1",
}
ROWS_HEADER = (
    "cell,reload,peers_total,peers_changed,peers_stable,prefixes,"
    "completion_p50_s,completion_p95_s,completion_max_s,"
    "changed_maxgap_p50_ms,changed_maxgap_p95_ms,changed_maxgap_max_ms,"
    "all_observer_maxgap_p50_ms,all_observer_maxgap_p95_ms,"
    "all_observer_maxgap_max_ms,changed_first_generation_update_p50_ms,"
    "changed_first_generation_update_p95_ms,changed_first_generation_update_max_ms,"
    "rss_before_mib,rss_after_mib,stable_marker_peers,sessions_up,parse_errors"
)
METRIC_NAME = re.compile(r"[A-Za-z_:][A-Za-z0-9_:]*")
LABEL_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
FLOAT_VALUE = re.compile(
    r"(?:[-+]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][-+]?[0-9]+)?|NaN|[+-]Inf)"
)
INT64_TIMESTAMP = re.compile(r"[+-]?[0-9]+")
WATCHED = ("bgp_rib_", "bgp_peer_", "bgp_update_group", "bgp_session_")


class InvalidReceipt(ValueError):
    pass


def fail(message: str) -> None:
    raise InvalidReceipt(message)


def validate_reload_phases(daemon_log: Path, reload_log: Path, output: Path) -> None:
    triggers = [
        (int(number), int(wall_us))
        for number, wall_us in re.findall(
            r"^reload (\d+) (?:SIGHUP|reload_cmd) wall_us=(\d+)",
            reload_log.read_text(),
            re.MULTILINE,
        )
    ]
    if not triggers or [number for number, _ in triggers] != list(range(1, len(triggers) + 1)):
        fail(f"{reload_log}: reload triggers are missing, duplicate, or reordered")

    records = []
    for raw in daemon_log.read_text(errors="replace").splitlines():
        try:
            event = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            fail(f"{daemon_log}: JSON log event is not an object")
        fields = event.get("fields", {})
        if not isinstance(fields, dict):
            fail(f"{daemon_log}: JSON log event has non-object fields")
        if fields.get("message") != "reload generation phase timing":
            continue
        if fields.get("target") != "reload_generation_phase":
            fail(f"{daemon_log}: phase record has the wrong structured target")
        try:
            parsed = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
            if parsed.utcoffset() is None:
                raise ValueError("timestamp has no UTC offset")
            since_epoch = parsed - datetime(1970, 1, 1, tzinfo=timezone.utc)
            epoch_us = (
                (since_epoch.days * 86_400 + since_epoch.seconds) * 1_000_000
                + since_epoch.microseconds
            )
        except (ValueError, KeyError, AttributeError, TypeError, OverflowError):
            fail(f"{daemon_log}: phase record has no parseable timestamp")
        required = set(PHASE_FIELDS) | {
            "total_targets", "cohort_targets", "remainder_targets", "refresh_count",
            "outcome", "authoritative_fallback",
        }
        if set(fields) & required != required:
            fail(f"{daemon_log}: malformed phase record")
        try:
            numeric = {key: int(fields[key]) for key in PHASE_FIELDS}
            counts = {key: int(fields[key]) for key in ("total_targets", "cohort_targets", "remainder_targets", "refresh_count")}
        except (TypeError, ValueError, OverflowError):
            fail(f"{daemon_log}: non-integer phase/count field")
        if any(value < 0 for value in (*numeric.values(), *counts.values())):
            fail(f"{daemon_log}: negative phase/count field")
        if counts["cohort_targets"] + counts["remainder_targets"] != counts["total_targets"]:
            fail(f"{daemon_log}: target counts do not close")
        if (
            not isinstance(fields["outcome"], str)
            or fields["outcome"] not in {"committed", "failed"}
            or not isinstance(fields["authoritative_fallback"], bool)
        ):
            fail(f"{daemon_log}: invalid outcome/fallback field")
        phases = sum(numeric[key] for key in PHASE_FIELDS if key != "total_us")
        if abs(phases - numeric["total_us"]) > max(2_000, numeric["total_us"] // 100):
            fail(f"{daemon_log}: phase sum does not materially close")
        records.append((epoch_us, fields, numeric, counts))
    if any(left[0] >= right[0] for left, right in zip(records, records[1:])):
        fail(f"{daemon_log}: phase records are reordered")

    bound = []
    for index, (reload_number, start) in enumerate(triggers):
        end = triggers[index + 1][1] if index + 1 < len(triggers) else None
        matches = [record for record in records if record[0] >= start and (end is None or record[0] < end)]
        if len(matches) != 1:
            fail(f"reload {reload_number}: expected exactly one phase record, found {len(matches)}")
        bound.append((reload_number, matches[0]))

    header = ("reload", "timestamp_epoch_us", "total_targets", "cohort_targets", "remainder_targets",
              "refresh_count", "outcome", "authoritative_fallback", *PHASE_FIELDS)
    with output.open("w", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(header)
        for reload_number, (epoch_us, fields, numeric, counts) in bound:
            writer.writerow((reload_number, epoch_us, counts["total_targets"], counts["cohort_targets"],
                             counts["remainder_targets"], counts["refresh_count"], fields["outcome"],
                             str(fields["authoritative_fallback"]).lower(), *(numeric[key] for key in PHASE_FIELDS)))


def event_epoch_us(event: dict, context: str) -> int:
    try:
        parsed = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
        if parsed.utcoffset() is None:
            raise ValueError("timestamp has no UTC offset")
        since_epoch = parsed - datetime(1970, 1, 1, tzinfo=timezone.utc)
        return (since_epoch.days * 86_400 + since_epoch.seconds) * 1_000_000 + since_epoch.microseconds
    except (ValueError, KeyError, AttributeError, TypeError, OverflowError):
        fail(f"{context}: event has no parseable timestamp")


def validate_dataset_refresh(
    daemon_log: Path, reload_log: Path, manifest_path: Path, output: Path
) -> None:
    triggers = [(int(number), int(wall)) for number, wall in re.findall(
        r"^reload (\d+) SIGHUP wall_us=(\d+)", reload_log.read_text(), re.MULTILINE)]
    if len(triggers) != 4 or [number for number, _ in triggers] != [1, 2, 3, 4]:
        fail("dataset refresh summary requires four ordered SIGHUP triggers")
    if any(left[1] >= right[1] for left, right in zip(triggers, triggers[1:])):
        fail("dataset refresh triggers are not strictly ordered")

    manifest = read_json(manifest_path)
    changed = manifest.get("changed_dataset_files")
    changed_fraction = manifest.get("changed_fraction")
    expected_changed = {0.1: 36, 1.0: 320}.get(changed_fraction)
    if (
        manifest.get("rustbgpd_dataset_mode") is not True
        or manifest.get("n_members") != 320
        or manifest.get("seed") != 61
        or type(changed_fraction) not in (int, float)
        or expected_changed is None
        or set(changed or {}) != {"prefix", "asn"}
        or changed.get("asn") != 0
        or changed.get("prefix") != expected_changed
    ):
        fail("dataset refresh manifest is not a canonical partial/full candidate")
    expected = {
        "dataset_hashed": 640,
        "dataset_parsed": expected_changed,
        "dataset_exact_content_reused": 640 - expected_changed,
        "dataset_source_rebound": 0,
        "dataset_changed": expected_changed,
        "dataset_failed": 0,
    }
    loads, refreshes = [], []
    for raw in daemon_log.read_text(errors="replace").splitlines():
        try:
            event = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            fail("dataset refresh log event is not an object")
        fields = event.get("fields", {})
        if not isinstance(fields, dict):
            fail("dataset refresh log fields are not an object")
        message = fields.get("message")
        if message == "config source loaded":
            if not set(expected) <= set(fields) or any(type(fields[key]) is not int for key in expected):
                fail("dataset config-load counters are malformed")
            loads.append((event_epoch_us(event, "dataset config load"), fields))
        elif message == "processed dataset-swap dependency-scoped refresh":
            required = {"eligible", "refreshed", "skipped_not_established", "failures"}
            if not required <= set(fields) or any(type(fields[key]) is not int for key in required):
                fail("dataset dependency-refresh counters are malformed")
            refreshes.append((event_epoch_us(event, "dataset dependency refresh"), fields))

    rows = []
    for index, (number, start) in enumerate(triggers):
        end = triggers[index + 1][1] if index + 1 < len(triggers) else None
        bound_loads = [record for record in loads if record[0] >= start and (end is None or record[0] < end)]
        bound_refreshes = [record for record in refreshes if record[0] >= start and (end is None or record[0] < end)]
        if len(bound_loads) != 1 or len(bound_refreshes) != 1:
            fail(f"reload {number}: expected one dataset load and refresh record")
        load_time, load = bound_loads[0]
        refresh_time, refresh = bound_refreshes[0]
        if any(load[key] != value for key, value in expected.items()):
            fail(f"reload {number}: dataset load counters differ from candidate contract")
        if (
            refresh_time < load_time
            or refresh["eligible"] != expected_changed
            or refresh["refreshed"] != expected_changed
            or refresh["skipped_not_established"] != 0
            or refresh["failures"] != 0
        ):
            fail(f"reload {number}: dependency-scoped refresh counters are invalid")
        rows.append((number, load_time, refresh_time, load, refresh))

    measurement_rows = [
        line.removeprefix("reloadstall_csv,").split(",")
        for line in reload_log.read_text().splitlines()
        if line.startswith("reloadstall_csv,")
    ]
    if len(measurement_rows) != 4:
        fail("dataset refresh receipt requires four harness measurement rows")
    for number, row in enumerate(measurement_rows, 1):
        if len(row) != 22 or row[0] != str(number) or row[-2:] != ["320", "0"]:
            fail(f"reload {number}: sessions or parse-error receipt is invalid")

    header = (
        "reload", "load_timestamp_epoch_us", "refresh_timestamp_epoch_us", "hashed",
        "parsed", "exact_reused", "source_rebound", "changed", "failed", "eligible",
        "refreshed", "skipped_not_established", "refresh_failures", "sessions_up", "parse_errors",
    )
    with output.open("w", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(header)
        for number, load_time, refresh_time, load, refresh in rows:
            writer.writerow((number, load_time, refresh_time, load["dataset_hashed"],
                load["dataset_parsed"], load["dataset_exact_content_reused"],
                load["dataset_source_rebound"], load["dataset_changed"], load["dataset_failed"],
                refresh["eligible"], refresh["refreshed"], refresh["skipped_not_established"],
                refresh["failures"], 320, 0))


def validate_authoritative_discriminator(daemon_log: Path, reload_log: Path, output: Path) -> None:
    triggers = [(int(number), int(wall)) for number, wall in re.findall(
        r"^reload (\d+) SIGHUP wall_us=(\d+)", reload_log.read_text(), re.MULTILINE)]
    if triggers != [(number, wall) for number, (_, wall) in enumerate(triggers, 1)] or len(triggers) != 4:
        fail("authoritative discriminator requires four ordered SIGHUP reloads")
    if any(left[1] >= right[1] for left, right in zip(triggers, triggers[1:])):
        fail("authoritative discriminator triggers are not strictly ordered")
    records, outers = [], []
    counter_names = ("input_peers", "present_peers", "skipped_peers", "duplicate_peers",
        "candidate_cohorts", "shared_cohorts", "shared_members", "fallback_members",
        "destination_ensures", "destination_builds", "destination_adoptions", "membership_moves",
        "inventory_announces", "inventory_withdraws", "inventory_supplements", "tombstones",
        "lagging_members", "filtered_scope_prefixes", "filtered_scope_member_visits",
        "emits_attempted", "emits_succeeded", "emits_degraded", "distribution_passes",
        "filtered_state_before", "filtered_state_after", "dirty_before", "dirty_after",
        "pending_before", "pending_after", "groups_before", "groups_after")
    for raw in daemon_log.read_text(errors="replace").splitlines():
        try: event = json.loads(raw)
        except json.JSONDecodeError: continue
        if not isinstance(event, dict): fail("authoritative discriminator event is not an object")
        fields = event.get("fields", {})
        if not isinstance(fields, dict): fail("authoritative discriminator fields are not an object")
        message = fields.get("message")
        if message not in {"authoritative_batch_phase", "reload generation phase timing"}: continue
        try:
            parsed = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
            if parsed.utcoffset() is None: raise ValueError
            delta = parsed - datetime(1970, 1, 1, tzinfo=timezone.utc)
            epoch_us = (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds
        except (ValueError, KeyError, AttributeError, TypeError, OverflowError):
            fail("authoritative discriminator timestamp is malformed")
        if message == "reload generation phase timing":
            if fields.get("target") != "reload_generation_phase": fail("outer phase target changed")
            if type(fields.get("total_us")) is not int or fields["total_us"] <= 0: fail("outer total is not positive integer")
            outers.append((epoch_us, fields))
            continue
        if event.get("target", fields.get("target")) != "authoritative_batch_phase":
            fail("authoritative discriminator structured target changed")
        required = set(AUTHORITATIVE_PHASES) | {"total_us", "remainder_us", "outcome",
            "classification", "failure_stage", *counter_names}
        if not required <= set(fields): fail("authoritative discriminator fields are incomplete")
        numeric_names = required - {"outcome", "classification", "failure_stage"}
        if any(type(fields[key]) is not int for key in numeric_names): fail("non-integer discriminator field")
        numeric = {key: fields[key] for key in numeric_names}
        if any(value < 0 for value in numeric.values()): fail("negative discriminator field")
        if sum(numeric[key] for key in AUTHORITATIVE_PHASES) + numeric["remainder_us"] != numeric["total_us"]:
            fail("authoritative discriminator phases do not close exactly")
        if not isinstance(fields["failure_stage"], str) or fields["failure_stage"] not in {"none", "precondition", "duplicate_fallback", "registration_membership", "cohort_partition", "cohort_precheck", "destination_build", "inventory_build", "membership_commit", "filtered_scope_build", "member_emit_state", "cohort_finalize", "fallback_regroup", "distribution"}:
            fail("authoritative discriminator failure stage changed")
        if fields["outcome"] != "committed" or fields["classification"] != "shared" or fields["failure_stage"] != "none":
            fail("authoritative discriminator outcome changed")
        exact = {"input_peers":320, "present_peers":320, "skipped_peers":0, "duplicate_peers":0,
            "candidate_cohorts":1, "shared_cohorts":1, "shared_members":320, "fallback_members":0,
            "destination_ensures":1, "membership_moves":320, "lagging_members":0,
            "emits_attempted":320, "emits_succeeded":320, "emits_degraded":0,
            "distribution_passes":1, "dirty_after":0, "pending_after":0}
        if any(numeric[key] != value for key, value in exact.items()) or numeric["destination_builds"] + numeric["destination_adoptions"] != 1:
            fail("authoritative discriminator canonical counts changed")
        records.append((epoch_us, fields, numeric))
    if len(records) != 4 or len(outers) != 4: fail("expected exactly four inner and outer terminals")
    if any(a[0] >= b[0] for a, b in zip(records, records[1:])): fail("inner terminals reordered")
    if any(a[0] >= b[0] for a, b in zip(outers, outers[1:])): fail("outer terminals reordered")
    bound = []
    for index, (number, start) in enumerate(triggers):
        end = triggers[index + 1][1] if index + 1 < len(triggers) else None
        matches = [record for record in records if record[0] >= start and (end is None or record[0] < end)]
        outer = [record for record in outers if record[0] >= start and (end is None or record[0] < end)]
        if len(matches) != 1 or len(outer) != 1 or matches[0][0] > outer[0][0]:
            fail(f"reload {number}: authoritative inner/outer binding changed")
        bound.append((number, matches[0]))
    outer_totals = [outer[0][1]["total_us"] for index, (_, start) in enumerate(triggers)
        for outer in [[record for record in outers if record[0] >= start and
            (index + 1 == len(triggers) or record[0] < triggers[index + 1][1])]]]
    later_total = sorted(outer_totals[1:])[1]
    delta = later_total - outer_totals[0]
    owned = {"destination_build_us":("destination_builds", "destination_adoptions"),
        "inventory_build_us":("inventory_announces", "inventory_withdraws", "inventory_supplements"),
        "membership_commit_us":("membership_moves",),
        "filtered_scope_build_us":("filtered_scope_prefixes",),
        "member_emit_state_us":("filtered_scope_member_visits", "emits_attempted"),
        "fallback_regroup_us":("fallback_members",),
        "duplicate_fallback_us":("duplicate_peers",)}
    witness = ("", "")
    if delta * 5 >= outer_totals[0]:
        for phase, counters in owned.items():
            phase_delta = sorted([record[2][phase] for _, record in bound[1:]])[1] - bound[0][1][2][phase]
            for counter in counters:
                later = [record[2][counter] for _, record in bound[1:]]
                if phase_delta * 10 >= delta * 7 and len(set(later)) == 1 and later[0] > bound[0][1][2][counter]:
                    witness = (phase, counter); break
            if witness[0]: break
    with output.open("w", newline="") as stream:
        header = ("reload", "timestamp_epoch_us", "outcome", "classification", "failure_stage",
            "total_us", "remainder_us", *AUTHORITATIVE_PHASES, *counter_names,
            "causal_phase", "owned_counter")
        writer = csv.writer(stream); writer.writerow(header)
        for number, (epoch, fields, numeric) in bound:
            writer.writerow((number, epoch, fields["outcome"], fields["classification"],
                fields["failure_stage"], numeric["total_us"], numeric["remainder_us"],
                *(numeric[key] for key in AUTHORITATIVE_PHASES), *(numeric[key] for key in counter_names), *witness))


def validate_authoritative_pair(roots: list[Path], output: Path) -> None:
    runs = [validate_root(root, "sighup") for root in roots]
    if runs[0]["completed"] >= runs[1]["started"] or runs[0]["identities"] == runs[1]["identities"]:
        fail("pair chronology or daemon identity is not independent")
    equal = ("commit", "dataset", "shape", "git", "environment", "inputs")
    if any(runs[0][key] != runs[1][key] for key in equal): fail("pair context/workload differs")
    tables = []
    for root in roots:
        cell = root / "rustbgpd-sighup"
        with tempfile.NamedTemporaryFile() as rebuilt:
            validate_authoritative_discriminator(cell / "daemon.log", cell / "reloadstall.log", Path(rebuilt.name))
            if Path(rebuilt.name).read_bytes() != (cell / "authoritative-phase-timings.csv").read_bytes():
                fail("authoritative CSV does not re-extract byte-identically")
            validate_reload_phases(cell / "daemon.log", cell / "reloadstall.log", Path(rebuilt.name))
            if Path(rebuilt.name).read_bytes() != (cell / "phase-timings.csv").read_bytes():
                fail("outer phase CSV does not re-extract byte-identically")
        tables.append(list(csv.DictReader((cell / "authoritative-phase-timings.csv").open())))
    eligible = {("destination_build_us", counter) for counter in ("destination_builds", "destination_adoptions")}
    eligible |= {("inventory_build_us", counter) for counter in ("inventory_announces", "inventory_withdraws", "inventory_supplements")}
    eligible |= {("membership_commit_us", "membership_moves"),
        ("filtered_scope_build_us", "filtered_scope_prefixes"),
        ("member_emit_state_us", "filtered_scope_member_visits"),
        ("member_emit_state_us", "emits_attempted"), ("fallback_regroup_us", "fallback_members"),
        ("duplicate_fallback_us", "duplicate_peers")}
    pairs = [{(row["causal_phase"], row["owned_counter"]) for row in table} for table in tables]
    pair = next(iter(pairs[0])) if len(pairs[0]) == 1 and pairs[0] == pairs[1] and pairs[0] <= eligible else ("", "")
    phase, counter = pair
    verdict, details = "negative_result", {}
    witnesses = []
    for label, run, rows in zip(("A", "B"), runs, tables, strict=True):
        outer = list(csv.DictReader((run["root"] / "rustbgpd-sighup/phase-timings.csv").open()))
        totals = [int(row["total_us"]) for row in outer]
        phases = [int(row[phase]) for row in rows] if phase else [0] * 4
        counts = [int(row[counter]) for row in rows] if counter else [0] * 4
        delta = sorted(totals[1:])[1] - totals[0]
        witnesses.append(bool(phase) and delta > 0 and delta * 5 >= totals[0] and
            (sorted(phases[1:])[1] - phases[0]) * 10 >= delta * 7 and
            len(set(counts[1:])) == 1 and counts[1] > counts[0])
        details[label] = {"totals_us":totals, "phase_us":phases, "owned_counts":counts}
    if all(witnesses) and [int(row[counter]) for row in tables[0]] == [int(row[counter]) for row in tables[1]]:
        verdict = "mechanism_witness"
    if verdict == "negative_result": phase = counter = ""
    output.write_text(json.dumps({"verdict":verdict, "phase":phase, "counter":counter,
        "commit":runs[0]["commit"], "tree":runs[0]["git"]["tree"], "roots":details}, sort_keys=True) + "\n")


def validate_authoritative_publication(artifact: Path) -> None:
    content = {"authoritative-pair.json", "authoritative-batch-phases.csv"}
    if not artifact.is_dir() or {path.name for path in artifact.iterdir()} != content:
        fail("publication must contain exactly the pair JSON and phase CSV")
    if any((artifact / name).is_symlink() or not (artifact / name).is_file() for name in content):
        fail("publication contains a non-regular input")
    pair = read_json(artifact / "authoritative-pair.json")
    if set(pair) != {"commit", "counter", "phase", "roots", "tree", "verdict"} or set(pair.get("roots", {})) != {"A", "B"}:
        fail("pair output schema changed")
    if any(not isinstance(pair[key], str) or not re.fullmatch(r"[0-9a-f]{40}", pair[key]) for key in ("commit", "tree")):
        fail("pair source identity is malformed")
    if pair["verdict"] not in {"negative_result", "mechanism_witness"} or not all(
        isinstance(pair[key], str) for key in ("phase", "counter")
    ):
        fail("pair verdict is malformed")
    for detail in pair["roots"].values():
        if set(detail) != {"owned_counts", "phase_us", "totals_us"} or any(
            not isinstance(items, list) or len(items) != 4 or any(type(item) is not int or item < 0 for item in items)
            for items in detail.values()
        ) or any(total <= 0 for total in detail["totals_us"]):
            fail("pair timing/count details are malformed")
    expected_header = "repeat,reload,timestamp_epoch_us,outcome,classification,failure_stage,total_us,remainder_us,precondition_us,registration_membership_us,cohort_partition_us,cohort_precheck_us,destination_build_us,inventory_build_us,membership_commit_us,filtered_scope_build_us,member_emit_state_us,cohort_finalize_us,fallback_regroup_us,distribution_us,duplicate_fallback_us,input_peers,present_peers,skipped_peers,duplicate_peers,candidate_cohorts,shared_cohorts,shared_members,fallback_members,destination_ensures,destination_builds,destination_adoptions,membership_moves,inventory_announces,inventory_withdraws,inventory_supplements,tombstones,lagging_members,filtered_scope_prefixes,filtered_scope_member_visits,emits_attempted,emits_succeeded,emits_degraded,distribution_passes,filtered_state_before,filtered_state_after,dirty_before,dirty_after,pending_before,pending_after,groups_before,groups_after,causal_phase,owned_counter".split(",")
    with (artifact / "authoritative-batch-phases.csv").open(newline="") as stream:
        reader = csv.DictReader(stream); rows = list(reader)
    if reader.fieldnames != expected_header or [(row["repeat"], row["reload"]) for row in rows] != [(repeat, str(number)) for repeat in "AB" for number in range(1, 5)]:
        fail("publication rows are missing, extra, or reordered")
    if any(set(row) != set(expected_header) for row in rows):
        fail("publication row field roster changed")
    phases = (*AUTHORITATIVE_PHASES,)
    timestamps = []
    by_root = {"A": [], "B": []}
    for row in rows:
        numeric_names = [key for key in expected_header if key not in {"repeat", "outcome", "classification", "failure_stage", "causal_phase", "owned_counter"}]
        if any(not re.fullmatch(r"0|[1-9][0-9]*", row[key]) for key in numeric_names): fail("publication row has non-canonical integer")
        integers = {key:int(row[key]) for key in numeric_names}
        if any(value < 0 for value in integers.values()) or row["outcome"] != "committed" or row["classification"] != "shared" or row["failure_stage"] != "none" or row["causal_phase"] or row["owned_counter"]:
            fail("publication row outcome/type changed")
        exact = {"input_peers":320, "present_peers":320, "skipped_peers":0, "duplicate_peers":0,
            "candidate_cohorts":1, "shared_cohorts":1, "shared_members":320, "fallback_members":0,
            "destination_ensures":1, "membership_moves":320, "lagging_members":0,
            "emits_attempted":320, "emits_succeeded":320, "emits_degraded":0,
            "distribution_passes":1, "tombstones":0, "filtered_state_before":0,
            "filtered_state_after":0, "dirty_before":0, "dirty_after":0,
            "pending_before":0, "pending_after":0, "groups_before":1, "groups_after":1}
        if any(integers[key] != value for key, value in exact.items()) or integers["destination_builds"] + integers["destination_adoptions"] != 1 or sum(integers[key] for key in phases) + integers["remainder_us"] != integers["total_us"]:
            fail("publication count/phase invariant changed")
        if integers["timestamp_epoch_us"] <= 0 or integers["total_us"] <= 0: fail("publication timing is not positive")
        timestamps.append(integers["timestamp_epoch_us"])
        by_root[row["repeat"]].append((row, integers))
    if any(left >= right for left, right in zip(timestamps, timestamps[1:])): fail("publication chronology changed")
    eligible = {("destination_build_us", counter) for counter in ("destination_builds", "destination_adoptions")}
    eligible |= {("inventory_build_us", counter) for counter in ("inventory_announces", "inventory_withdraws", "inventory_supplements")}
    eligible |= {("membership_commit_us", "membership_moves"),
        ("filtered_scope_build_us", "filtered_scope_prefixes"),
        ("member_emit_state_us", "filtered_scope_member_visits"),
        ("member_emit_state_us", "emits_attempted"), ("fallback_regroup_us", "fallback_members"),
        ("duplicate_fallback_us", "duplicate_peers")}
    retained_direction = any(
        row["causal_phase"] or row["owned_counter"] for root_rows in by_root.values()
        for row, _ in root_rows
    )
    witnesses = []
    for label in "AB":
        details = pair["roots"][label]
        totals = details["totals_us"]
        later, first = sorted(totals[1:])[1], totals[0]
        registration = [values["registration_membership_us"] for _, values in by_root[label]]
        reg_later = sorted(registration[1:])[1]
        delta, registration_delta = later - first, reg_later - registration[0]
        if delta * 5 < first or registration_delta * 10 < delta * 7:
            fail("published growth or attribution no longer meets the frozen gates")
        pairs = {(row["causal_phase"], row["owned_counter"]) for row, _ in by_root[label]}
        candidate = next(iter(pairs)) if len(pairs) == 1 else ("", "")
        if candidate not in eligible:
            candidate = ("", "")
        phase, counter = candidate
        phase_values = [values[phase] for _, values in by_root[label]] if phase else [0] * 4
        count_values = [values[counter] for _, values in by_root[label]] if counter else [0] * 4
        phase_delta = sorted(phase_values[1:])[1] - phase_values[0]
        witnessed = bool(phase) and phase_delta * 10 >= delta * 7 and len(set(count_values[1:])) == 1 and count_values[1] > count_values[0]
        witnesses.append((witnessed, phase, counter, phase_values, count_values))
    directional = all(item[0] for item in witnesses) and witnesses[0][1:3] == witnesses[1][1:3] and witnesses[0][4] == witnesses[1][4]
    if directional:
        phase, counter = witnesses[0][1:3]
        if pair["verdict"] != "mechanism_witness" or (pair["phase"], pair["counter"]) != (phase, counter):
            fail("directional witness is not reported exactly")
        for label, witness in zip("AB", witnesses, strict=True):
            if pair["roots"][label]["phase_us"] != witness[3] or pair["roots"][label]["owned_counts"] != witness[4]:
                fail("pair witness arrays differ from the phase CSV")
    elif pair["verdict"] != "negative_result" or pair["phase"] or pair["counter"] or retained_direction or any(
        item[0] for item in witnesses
    ) or any(pair["roots"][label][key] != [0] * 4 for label in "AB" for key in ("phase_us", "owned_counts")):
        fail("negative result retained or promoted a directional witness")


def quoted(text: str, position: int) -> tuple[str, int]:
    if position >= len(text) or text[position] != '"':
        fail("expected quoted string")
    chars: list[str] = []
    position += 1
    while position < len(text):
        char = text[position]
        position += 1
        if char == '"':
            return "".join(chars), position
        if char == "\\":
            if position >= len(text) or text[position] not in '\\"n':
                fail("malformed label escape")
            chars.append({"\\": "\\", '"': '"', "n": "\n"}[text[position]])
            position += 1
        elif char in "\r\n":
            fail("unescaped line break")
        else:
            chars.append(char)
    fail("unterminated quoted string")


def parse_sample(text: str):
    match = METRIC_NAME.match(text)
    if not match:
        return None
    name, position, labels = match.group(), match.end(), {}
    if position < len(text) and text[position] == "{":
        position += 1
        while True:
            while position < len(text) and text[position] in " \t":
                position += 1
            if position < len(text) and text[position] == "}":
                position += 1
                break
            if position < len(text) and text[position] == '"':
                key, position = quoted(text, position)
            else:
                match = LABEL_NAME.match(text, position)
                if not match:
                    fail("malformed label name")
                key, position = match.group(), match.end()
            while position < len(text) and text[position] in " \t":
                position += 1
            if position >= len(text) or text[position] != "=":
                fail("missing label equals")
            position += 1
            while position < len(text) and text[position] in " \t":
                position += 1
            value, position = quoted(text, position)
            if key in labels:
                fail(f"duplicate label {key!r}")
            labels[key] = value
            while position < len(text) and text[position] in " \t":
                position += 1
            if position < len(text) and text[position] == "}":
                position += 1
                break
            if position >= len(text) or text[position] != ",":
                fail("malformed label separator")
            position += 1
    if position >= len(text) or text[position] not in " \t":
        fail("missing sample value separator")
    tokens = text[position:].split()
    if len(tokens) not in (1, 2) or not FLOAT_VALUE.fullmatch(tokens[0]):
        fail("malformed sample value")
    if len(tokens) == 2:
        if not INT64_TIMESTAMP.fullmatch(tokens[1]):
            fail("malformed sample timestamp")
        timestamp = int(tokens[1])
        if not -(1 << 63) <= timestamp < (1 << 63):
            fail("sample timestamp outside int64")
    return name, labels, float(tokens[0])


def parse_metrics(path: Path) -> dict[str, list[tuple[dict[str, str], float]]]:
    result: dict[str, list[tuple[dict[str, str], float]]] = {}
    identities = set()
    for line in path.read_text().splitlines():
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        try:
            parsed = parse_sample(text)
        except InvalidReceipt:
            if text.startswith(WATCHED):
                raise
            continue
        if parsed is None:
            continue
        name, labels, value = parsed
        identity = (name, tuple(sorted(labels.items())))
        if identity in identities:
            fail(f"duplicate metric sample {identity}")
        identities.add(identity)
        result.setdefault(name, []).append((labels, value))
    return result


def rows(data, name: str, count: int | None = None):
    found = data.get(name, [])
    if count is not None and len(found) != count:
        fail(f"{name}: expected {count} samples, got {len(found)}")
    if any(not math.isfinite(value) for _, value in found):
        fail(f"{name}: non-finite sample")
    return found


def one(data, name: str, expected: int) -> None:
    found = rows(data, name, 1)
    labels, value = found[0]
    if labels or value != expected:
        fail(f"{name}: expected unlabelled {expected}, got {found[0]}")


def peer_rows(data, name: str, peers: int, extra=()):
    found = rows(data, name, peers)
    expected_labels = {"peer", *extra}
    identities = [labels.get("peer") for labels, _ in found]
    if (
        None in identities
        or len(set(identities)) != peers
        or any(set(labels) != expected_labels for labels, _ in found)
    ):
        fail(f"{name}: missing/duplicate peer or unexpected labels")
    return found


def family_rows(data, name: str, peers: set[str], families: tuple[str, ...]):
    found = rows(data, name, len(peers) * len(families))
    expected = {(peer, family) for peer in peers for family in families}
    actual = {(labels.get("peer"), labels.get("afi_safi")) for labels, _ in found}
    if actual != expected or any(set(labels) != {"peer", "afi_safi"} for labels, _ in found):
        fail(f"{name}: family/peer roster mismatch")
    return {(labels["peer"], labels["afi_safi"]): value for labels, value in found}


def member_addr(member: int) -> str:
    """The harness stub source address for member index `member`."""
    return f"127.1.{member // 200}.{member % 200 + 1}"


def load_overlap(manifest_path: Path | None, peers: int, total: int):
    """Read and validate the manifest's LAN-892 overlap allocation.

    Returns (fraction, pairs) where pairs is [(prefix_index, second_member)].
    An absent manifest or absent overlap keys is the historical disjoint
    shape (F=0). The declared fraction must reproduce the allocation size
    exactly, every pair must be in range with a second announcer distinct
    from the slice owner, and prefixes may gain at most one second announcer.
    """
    manifest = read_json(manifest_path) if manifest_path is not None else {}
    fraction = manifest.get("overlap_fraction", 0.0)
    pairs = manifest.get("overlap_pairs", [])
    per_peer = total // peers
    if isinstance(fraction, bool) or not isinstance(fraction, (int, float)) or not 0 <= fraction < 1:
        fail("manifest overlap_fraction is out of range")
    if not isinstance(pairs, list) or (fraction == 0) != (pairs == []):
        fail("manifest overlap_fraction and overlap_pairs disagree")
    if len(pairs) != round(fraction * total):
        fail("manifest overlap allocation does not match its declared fraction")
    seen = set()
    validated = []
    for pair in pairs:
        if (
            not isinstance(pair, list)
            or len(pair) != 2
            or any(isinstance(value, bool) or not isinstance(value, int) for value in pair)
        ):
            fail("malformed overlap pair")
        idx, second = pair
        if not 0 <= idx < total or not 0 <= second < peers or idx // per_peer == second or idx in seen:
            fail("invalid overlap pair (range, own-slice second announcer, or duplicate)")
        seen.add(idx)
        validated.append((idx, second))
    return fraction, validated


def validate_topology(
    mode: str,
    peers: int,
    total: int,
    config: Path,
    timestamps: Path,
    metric_paths: list[Path],
    output: Path,
    manifest: Path | None = None,
) -> None:
    if mode not in ("private", "grouped") or len(metric_paths) != 3:
        fail("topology requires private/grouped mode and exactly three scrapes")
    overlap_fraction, overlap_pairs = load_overlap(manifest, peers, total)
    announced_extra = [0] * peers
    own_overlapped = [0] * peers
    for idx, second in overlap_pairs:
        announced_extra[second] += 1
        own_overlapped[idx // (total // peers)] += 1
    config_text = config.read_text()
    if "[neighbors.add_path]" in config_text:
        fail("topology proof requires Add-Path disabled")
    expected_best = peers if mode == "private" else 0
    if config_text.count("per_client_best = true") != expected_best:
        fail(f"{mode}: per_client_best mapping is not exact")
    timestamp_rows = list(csv.DictReader(timestamps.open(), delimiter="\t"))
    if [row.get("phase") for row in timestamp_rows] != ["scrape1", "scrape2", "scrape3"]:
        fail("topology timestamps must contain exactly three scrapes")
    epoch_ns = [int(row["epoch_ns"]) for row in timestamp_rows]
    if epoch_ns[1] - epoch_ns[0] < 1_000_000_000 or epoch_ns[2] - epoch_ns[1] < 1_000_000_000:
        fail("topology scrapes must be at least one second apart")
    scrapes = [parse_metrics(path) for path in metric_paths]
    stable = []
    peer_roster = None
    group_id = None
    for data in scrapes:
        one(data, "bgp_rib_outbound_registered_peers", peers)
        one(data, "bgp_rib_ingest_channel_depth", 0)
        one(data, "bgp_rib_policy_transition_in_progress", 0)
        sessions = peer_rows(data, "bgp_peer_session_established", peers, ("interface",))
        if any(value != 1 for _, value in sessions):
            fail("not every expected session is established")
        identities = {labels["peer"] for labels, _ in sessions}
        established = peer_rows(data, "bgp_session_established_total", peers)
        if {labels["peer"] for labels, _ in established} != identities:
            fail("session establishment counter roster mismatch")
        if any(value != 1 for _, value in established):
            fail("session establishment counter value mismatch")
        flaps = rows(data, "bgp_session_flaps_total")
        if any(
            set(labels) != {"peer"}
            or labels["peer"] not in identities
            for labels, _ in flaps
        ):
            fail("session flap counter roster/labels mismatch")
        if any(value != 0 for _, value in flaps):
            fail("session flap counter value mismatch")
        queues = peer_rows(data, "bgp_peer_outbound_queue_depth", peers)
        if {labels["peer"] for labels, _ in queues} != identities or any(
            value != 0 for _, value in queues
        ):
            fail("every expected outbound queue must be empty")
        groups = peer_rows(data, "bgp_peer_update_group", peers)
        if {labels["peer"] for labels, _ in groups} != identities:
            fail("group peer roster mismatch")
        if peer_roster is None:
            peer_roster = identities
        elif peer_roster != identities:
            fail("peer roster changed between topology scrapes")
        loc = rows(data, "bgp_rib_loc_prefixes", 1)
        if loc != [({"afi_safi": "all"}, float(total))]:
            fail("Loc-RIB aggregate mismatch")
        per_peer = total // peers
        adj_in = family_rows(data, "bgp_rib_prefixes", identities, ("all", "flowspec"))
        if any(adj_in[(peer, "flowspec")] != 0 for peer in identities):
            fail("Adj-RIB-In aggregate/non-all roster mismatch")
        out_families = ("all", "bgpls", "evpn", "flowspec", "labeled", "rtc", "vpn")
        adj_out = family_rows(data, "bgp_rib_adj_out_prefixes", identities, out_families)
        if any(
            adj_out[(peer, family)] != 0
            for peer in identities
            for family in out_families
            if family != "all"
        ):
            fail("Adj-RIB-Out aggregate/non-all roster mismatch")
        if not overlap_pairs:
            # Disjoint announcements: the historical exact expectations.
            if any(adj_in[(peer, "all")] != per_peer for peer in identities):
                fail("Adj-RIB-In aggregate/non-all roster mismatch")
            if any(adj_out[(peer, "all")] != total - per_peer for peer in identities):
                fail("Adj-RIB-Out aggregate/non-all roster mismatch")
        else:
            # Overlap shape: per-member expectations from the manifest
            # allocation, keyed by the deterministic stub addressing.
            member_of = {member_addr(member): member for member in range(peers)}
            if set(member_of) != identities:
                fail("overlap topology requires the harness stub peer roster")
            for peer in identities:
                member = member_of[peer]
                if adj_in[(peer, "all")] != per_peer + announced_extra[member]:
                    fail("Adj-RIB-In does not reflect the manifest overlap allocation")
            if mode == "private":
                # Per-client best must deliver the runner-up path for every
                # overlapped prefix the observer itself announces: only
                # exclusively-announced prefixes stay suppressed.
                if any(
                    adj_out[(peer, "all")]
                    != total - (per_peer - own_overlapped[member_of[peer]])
                    for peer in identities
                ):
                    fail("per-client-best Adj-RIB-Out must deliver runner-up paths")
            else:
                # One shared group: each prefix is suppressed exactly at its
                # best-path announcer. Which announcer wins an overlapped
                # prefix is a daemon tie-break, so bound per member and pin
                # the exact global suppression count.
                suppressed = 0
                for peer in identities:
                    member = member_of[peer]
                    value = adj_out[(peer, "all")]
                    lower = total - (per_peer + announced_extra[member])
                    upper = total - (per_peer - own_overlapped[member])
                    if not lower <= value <= upper:
                        fail("grouped Adj-RIB-Out outside announcer bounds")
                    suppressed += total - value
                if suppressed != total:
                    fail("grouped suppression must total one best announcer per prefix")
        achieved = sum(adj_in[(peer, "all")] for peer in identities) - total
        if achieved != len(overlap_pairs):
            fail(
                f"achieved overlap ({achieved} second paths) does not match "
                f"the manifest allocation ({len(overlap_pairs)})"
            )
        # ADR-0126 classifier flip: shareable unicast-only per_client_best
        # peers group instead of falling back per peer, so both modes must
        # form exactly one complete group with no fallback peers. The
        # Decision 3 runner-up lane is O(overlapped prefixes): one entry
        # per manifest overlap pair in private (per-client-best) mode,
        # exactly empty in the grouped control.
        one(data, "bgp_update_groups", 1)
        one(data, "bgp_update_group_fallback_peers", 0)
        one(
            data,
            "bgp_update_group_runner_up_entries",
            len(overlap_pairs) if mode == "private" else 0,
        )
        members = rows(data, "bgp_update_group_members", 1)
        labels, member_count = members[0]
        ids = {value for _, value in groups}
        candidate = next(iter(ids)) if len(ids) == 1 else math.nan
        if (
            set(labels) != {"group"}
            or member_count != peers
            or not math.isfinite(candidate)
            or candidate < 0
            or candidate != int(candidate)
            or labels["group"] != str(int(candidate))
        ):
            fail(f"{mode} topology must have one complete nonnegative group")
        if group_id is None:
            group_id = int(candidate)
        group_snapshot = (1, 0, int(candidate), tuple(sorted((labels["peer"], value) for labels, value in groups)))
        route_snapshot = tuple(
            sorted(
                (name, tuple(sorted(labels.items())), value)
                for name, found in data.items()
                if name in {"bgp_rib_loc_prefixes", "bgp_rib_prefixes", "bgp_rib_adj_out_prefixes"}
                for labels, value in found
            )
        )
        stable.append((group_snapshot, route_snapshot))
    if not stable[0] == stable[1] == stable[2]:
        fail("topology was not stable across three scrapes")
    output.write_text(
        json.dumps(
            {
                "status": "pass",
                "mode": mode,
                "peers": peers,
                "scrape_epoch_ns": epoch_ns,
                "group_id": group_id,
                "overlap_fraction": overlap_fraction,
                "overlap_pairs": len(overlap_pairs),
            },
            sort_keys=True,
        )
        + "\n"
    )


def read_received_view(path: Path, peers: int, total: int) -> list[set[int]]:
    """Parse the harness's final-generation received-view dump.

    Returns each observer's MISSING base-prefix set (complement of what it
    observed with the final generation marker, before own-announcement
    exclusion).
    """
    lines = path.read_text().splitlines()
    if not lines or lines[0] != f"received_view_v1\ttotal={total}\tpeers={peers}":
        fail(f"{path}: received-view header mismatch")
    if len(lines) != peers + 1:
        fail(f"{path}: received-view observer roster mismatch")
    missing = []
    for expected_observer, line in enumerate(lines[1:]):
        parts = line.split("\t")
        if len(parts) != 3 or parts[0] != str(expected_observer):
            fail(f"{path}: malformed received-view row")
        try:
            indices = [int(value) for value in parts[2].split(",")] if parts[2] else []
        except ValueError:
            fail(f"{path}: non-integer received-view index")
        if (
            parts[1] != str(len(indices))
            or any(not 0 <= value < total for value in indices)
            or sorted(set(indices)) != indices
        ):
            fail(f"{path}: received-view indices invalid")
        missing.append(set(indices))
    return missing


def received_view_delta(private_cell: Path, grouped_cell: Path) -> dict:
    """Observer-side per-client-best vs grouped received-view delta.

    Counts (member, prefix) pairs where per-client-best delivered a runner-up
    path that grouped mode suppressed, from the two cells' retained
    received-view dumps over the SAME scenario. Every delta pair must be an
    overlapped prefix observed at one of its announcers, grouped deliveries
    must be a pointwise subset of per-client-best deliveries, and the total
    must equal the manifest allocation (exactly one suppressed announcer —
    the best-path one — per overlapped prefix).
    """
    manifests = [read_json(cell / "manifest.json") for cell in (private_cell, grouped_cell)]
    shared = (
        "dataset_sha256",
        "n_members",
        "total_prefixes",
        "seed",
        "overlap_fraction",
        "overlap_pairs",
    )
    if any(manifests[0].get(key) != manifests[1].get(key) for key in shared):
        fail("received-view delta cells do not share one scenario")
    if manifests[0].get("path_hiding") is not True or manifests[1].get("path_hiding") is not False:
        fail("received-view delta requires one private cell and one grouped cell")
    peers, total = manifests[0].get("n_members"), manifests[0].get("total_prefixes")
    if not isinstance(peers, int) or not isinstance(total, int) or peers <= 0 or total <= 0:
        fail("received-view delta manifests lack a valid shape")
    fraction, pairs = load_overlap(private_cell / "manifest.json", peers, total)
    per_peer = total // peers
    announcers = {idx: {idx // per_peer, second} for idx, second in pairs}
    private_missing = read_received_view(private_cell / "received-view.tsv", peers, total)
    grouped_missing = read_received_view(grouped_cell / "received-view.tsv", peers, total)
    delta = 0
    for member in range(peers):
        if not private_missing[member] <= grouped_missing[member]:
            fail("grouped mode delivered a prefix per-client-best did not")
        for idx in grouped_missing[member] - private_missing[member]:
            if member not in announcers.get(idx, ()):
                fail("received-view delta pair is outside the overlap allocation")
            delta += 1
    if delta != len(pairs):
        fail(
            f"received-view delta ({delta}) does not equal the overlap "
            f"allocation ({len(pairs)})"
        )
    return {
        "status": "pass",
        "overlap_fraction": fraction,
        "overlap_pairs": len(pairs),
        "suppressed_runner_up_pairs": delta,
    }


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_json(path: Path):
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        fail(f"{path}: invalid JSON: {error}")


def decode_lossless_path(value, context: str) -> bytes:
    if (
        not isinstance(value, dict)
        or list(value) != ["encoding", "value"]
        or value.get("encoding") != "unix-bytes-hex"
        or not isinstance(value.get("value"), str)
        or len(value["value"]) % 2 or not re.fullmatch(r"[0-9a-f]*", value["value"])
    ):
        fail(f"{context}: invalid lossless path")
    return bytes.fromhex(value["value"])


def inline_manifest_source_sha256(manifest: dict, raw_sha: str) -> str:
    if manifest != {"toml_sha256": raw_sha, "rpol_units": [], "datasets": []}:
        fail("transaction v3 manifest is not the exact inline-policy shape")
    digest = hashlib.sha256(b"rustbgpd.config-source.v2\0")
    for value in (bytes.fromhex(raw_sha), (0).to_bytes(8, "big"), (0).to_bytes(8, "big")):
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)
    return digest.hexdigest()


def canonical_json(path: Path, cap: int, context: str) -> tuple[dict, bytes]:
    raw = path.read_bytes()
    if not raw or len(raw) > cap:
        fail(f"{context}: file is empty or exceeds its cap")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        fail(f"{context}: invalid JSON: {error}")
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode() + b"\n"
    if encoded != raw or not raw.startswith(b'{"version":3,'):
        fail(f"{context}: JSON is not canonical v3")
    return value, raw


def secure_file_identity(path: Path, cap: int, context: str) -> dict:
    if path.is_symlink():
        fail(f"{context}: symlink is forbidden")
    metadata = path.stat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != os.geteuid()
        or metadata.st_size <= 0
        or metadata.st_size > cap
    ):
        fail(f"{context}: type, owner, mode, or size is invalid")
    return {"name": path.name, "device": metadata.st_dev, "inode": metadata.st_ino,
            "bytes": metadata.st_size, "sha256": sha256(path), "mode": "0600",
            "owner_current_uid": True}


def require_utf8(path: Path, context: str) -> None:
    decoder = codecs.getincrementaldecoder("utf-8")("strict")
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                decoder.decode(chunk)
        decoder.decode(b"", final=True)
    except UnicodeDecodeError:
        fail(f"{context}: content is not UTF-8")


def inspect_v3(locator_path: Path, metadata_path: Path, raw_path: Path, config_path: Path, confirm_id: str) -> dict:
    locator_identity = secure_file_identity(locator_path, 512 * 1024, "v3 locator")
    metadata_identity = secure_file_identity(metadata_path, 34 * 1024 * 1024, "v3 metadata")
    raw_identity = secure_file_identity(raw_path, 384 * 1024 * 1024, "v3 raw")
    locator, _ = canonical_json(locator_path, 512 * 1024, "v3 locator")
    metadata, _ = canonical_json(metadata_path, 34 * 1024 * 1024, "v3 metadata")
    locator_fields = ("version", "confirm_id", "metadata_path", "config_target",
                      "prior_sha256", "prior_source_sha256")
    metadata_fields = ("version", "confirm_id", "deadline_unix_seconds", "rollback_failed",
                       "raw_name", "raw_length", "raw_sha256", "raw_source_sha256",
                       "raw_device", "raw_inode", "manifest")
    if tuple(locator or {}) != locator_fields or type(locator.get("version")) is not int or locator["version"] != 3 or locator.get("confirm_id") != confirm_id:
        fail("v3 locator schema or confirmation id is invalid")
    if tuple(metadata or {}) != metadata_fields or type(metadata.get("version")) is not int or metadata["version"] != 3 or metadata.get("confirm_id") != confirm_id:
        fail("v3 metadata schema or confirmation id is invalid")
    if tuple(metadata.get("manifest") or {}) != ("toml_sha256", "rpol_units", "datasets"):
        fail("v3 metadata manifest field order is invalid")
    expected_metadata = os.fsencode(str(metadata_path.resolve(strict=True)))
    expected_config = os.fsencode(str(config_path.resolve(strict=True)))
    if decode_lossless_path(locator["metadata_path"], "v3 metadata path") != expected_metadata:
        fail("v3 locator does not name the expected metadata path")
    if decode_lossless_path(locator["config_target"], "v3 config target") != expected_config:
        fail("v3 locator does not name the expected config target")
    if decode_lossless_path(metadata["raw_name"], "v3 raw name") != b"commit-confirm-v3-prior.toml":
        fail("v3 metadata does not name the fixed raw object")
    require_utf8(raw_path, "v3 raw")
    raw_sha = raw_identity["sha256"]
    source_sha = inline_manifest_source_sha256(metadata["manifest"], raw_sha)
    if (
        metadata.get("rollback_failed") is not False
        or type(metadata.get("deadline_unix_seconds")) is not int
        or metadata["deadline_unix_seconds"] <= 0
        or any(type(metadata.get(field)) is not int for field in ("raw_length", "raw_device", "raw_inode"))
        or metadata.get("raw_length") != raw_identity["bytes"]
        or metadata.get("raw_device") != raw_identity["device"]
        or metadata.get("raw_inode") != raw_identity["inode"]
        or metadata.get("raw_sha256") != raw_sha
        or metadata.get("raw_source_sha256") != source_sha
        or metadata["manifest"].get("toml_sha256") != raw_sha
        or locator.get("prior_sha256") != raw_sha
        or locator.get("prior_source_sha256") != source_sha
    ):
        fail("v3 locator, metadata, manifest, and raw object are not linked")
    return {
        "schema": 1,
        "version": 3,
        "confirm_id": confirm_id,
        "deadline_unix_seconds": metadata["deadline_unix_seconds"],
        "linkage_verified": True,
        "locator": locator_identity,
        "metadata": metadata_identity,
        "raw": raw_identity,
    }


def generation_marker(path: Path) -> str:
    pattern = re.compile(rb'set_community_add\s*=\s*\[\s*"65400:(1000|2000)"\s*,?\s*\]')
    with path.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        markers = pattern.findall(data)
    if len(markers) != 1:
        fail(f"{path}: transaction generation marker is not exact A or B")
    return "65400:" + markers[0].decode()


def validate_quiet(path: Path) -> None:
    data = list(csv.DictReader(path.open(), delimiter="\t"))
    if [row.get("sample") for row in data] != ["1", "2"]:
        fail(f"{path}: quiet gate needs exactly two samples")
    epochs = [int(row["epoch_s"]) for row in data]
    loads = [float(row["load1"]) for row in data]
    if (
        epochs[1] - epochs[0] < 30
        or any(not math.isfinite(load) or load >= 2.0 for load in loads)
        or any(row.get("port1790_free") != "true" or row.get("port9179_free") != "true" for row in data)
        or any(int(row.get("disk_available_kib", "0")) < 40 * 1024 * 1024 for row in data)
        or len({(row.get("pswpin"), row.get("pswpout")) for row in data}) != 1
        or any(not row.get("pswpin", "").isdigit() or not row.get("pswpout", "").isdigit() for row in data)
    ):
        fail(f"{path}: quiet samples fail spacing, load, port, disk, or swap gates")


def validate_process(path: Path) -> tuple[int, int]:
    data = list(csv.DictReader(path.open(), delimiter="\t"))
    if len(data) != 1:
        fail(f"{path}: expected one process identity")
    row = data[0]
    pid, before, after = int(row["pid"]), int(row["starttime_before"]), int(row["starttime_after"])
    if pid <= 0 or before <= 0 or before != after:
        fail(f"{path}: missing, reused, or changed process identity")
    return pid, before


def read_rows(path: Path, expected_cells: tuple[str, ...]) -> list[list[str]]:
    with path.open(newline="") as stream:
        reader = csv.reader(stream)
        header = next(reader, None)
        data = list(reader)
    if header != ROWS_HEADER.split(","):
        fail(f"{path}: unexpected row header")
    if len(data) != 4 * len(expected_cells):
        fail(f"{path}: expected four rows per cell")
    for cell in expected_cells:
        found = [row for row in data if row and row[0] == cell]
        if len(found) != 4 or [row[1] for row in found] != ["1", "2", "3", "4"]:
            fail(f"{path}: {cell} does not have reload rows 1..4")
    if {row[0] for row in data if row} != set(expected_cells):
        fail(f"{path}: unexpected/missing cells")
    if any(len(row) != 23 for row in data):
        fail(f"{path}: malformed measurement row width")
    return data


def validate_preflight(path: Path) -> None:
    text = path.read_text()
    lines = text.splitlines()
    if "[preflight] READY — all pre-flight checks passed" not in lines or any(
        "FAIL:" in line for line in lines
    ):
        fail(f"{path}: preflight did not finish READY without failures")
    phrase = "no pushes to main"
    if not any(phrase in line and "confirmed" in line for line in lines):
        fail(f"{path}: missing manual confirmation for {phrase}")


def validate_measurement_rows(rows_data: list[list[str]], cell: str, peers: int, total: int) -> None:
    for row in rows_data:
        if row[0] != cell:
            fail(f"{cell}: row escaped its cell roster")
        try:
            integers = [int(row[index]) for index in (1, 2, 3, 4, 5, 20, 21, 22)]
            floats = [float(row[index]) for index in range(6, 20)]
        except ValueError:
            fail(f"{cell}: nonnumeric measurement field")
        if any(value < 0 or not math.isfinite(value) for value in floats):
            fail(f"{cell}: negative/non-finite measurement")
        for offset in (0, 3, 6, 9):
            p50, p95, maximum = floats[offset : offset + 3]
            if not p50 <= p95 <= maximum:
                fail(f"{cell}: percentile triplet is not monotonic")
        if floats[0] <= 0 or floats[9] <= 0:
            fail(f"{cell}: completion/first-generation latency must be positive")
        if any(
            first_generation > completion * 1000
            for completion, first_generation in zip(
                floats[0:3], floats[9:12], strict=True
            )
        ):
            fail(f"{cell}: first-generation latency exceeds completion latency")
        if any(
            all_observer < changed_observer
            for changed_observer, all_observer in zip(
                floats[3:6], floats[6:9], strict=True
            )
        ):
            fail(f"{cell}: all-observer max-gap is below changed-observer max-gap")
        reload_no, peers_total, peers_changed, peers_stable, prefixes, stable_marker, sessions, parse_errors = integers
        if (
            reload_no not in range(1, 5)
            or peers_total != peers
            or peers_changed != peers
            or peers_stable != 0
            or prefixes != total
            or stable_marker != 0
            or sessions != peers
            or parse_errors != 0
        ):
            fail(f"{cell}: canonical row invariants failed")


def validate_rss(path: Path) -> None:
    data = list(csv.reader(path.open()))
    if not data or data[0] != ["epoch_s", "total_rss_kib", "pids"] or len(data) < 2:
        fail(f"{path}: RSS evidence is missing or malformed")
    for row in data[1:]:
        if len(row) != 3 or any(not value.isdigit() or int(value) <= 0 for value in row):
            fail(f"{path}: RSS sample is not a positive integer triple")


def validate_cell_evidence(
    root: Path,
    cell: str,
    root_rows: list[list[str]],
    peers: int,
    total: int,
) -> None:
    cdir = root / cell
    cell_rows = list(csv.reader((cdir / "rows.csv").open()))
    expected_rows = [row for row in root_rows if row[0] == cell]
    if cell_rows != expected_rows:
        fail(f"{cdir}: cell rows do not equal their root rows")
    validate_measurement_rows(cell_rows, cell, peers, total)
    logged = []
    for line in (cdir / "reloadstall.log").read_text().splitlines():
        if line.startswith("reloadstall_csv,"):
            logged.append([cell, *line.split(",")[1:]])
    if logged != cell_rows:
        fail(f"{cdir}: retained rows do not re-extract from reloadstall.log")
    validate_rss(cdir / "rss.csv")
    if (cdir / "status").read_text() != "pass\n":
        fail(f"{cdir}: cell did not finish its semantic gates")


def reject_transaction_tokens(value, path="receipt") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in {"plan_token", "runtime_snapshot_token"}:
                fail(f"{path}: token contents were retained")
            reject_transaction_tokens(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_transaction_tokens(child, f"{path}[{index}]")
    elif isinstance(value, str) and (
        re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", value)
        or value.startswith(("kv1:", "kv2:"))
    ):
        fail(f"{path}: token-shaped string was retained")


def validate_content(value, context: str) -> None:
    if set(value or {}) != {"sha256", "bytes", "marker"} or not re.fullmatch(
        r"[0-9a-f]{64}", value.get("sha256", "")
    ) or not isinstance(value.get("bytes"), int) or value["bytes"] <= 0 or value.get(
        "marker"
    ) not in {"65400:1000", "65400:2000"}:
        fail(f"{context}: invalid content identity")


def validate_process_json(value, expected: tuple[int, int], context: str) -> None:
    if (
        set(value or {}) != {"pid", "starttime", "vmrss_kib", "vmhwm_kib"}
        or (value.get("pid"), value.get("starttime")) != expected
        or not all(isinstance(value.get(key), int) and value[key] > 0 for key in value)
        or value["vmhwm_kib"] < value["vmrss_kib"]
    ):
        fail(f"{context}: daemon process/RSS identity is invalid")


def validate_history(value, context: str) -> None:
    if set(value or {}) != {"entries", "files"} or value.get("entries") != [] or value.get("files") != []:
        fail(f"{context}: oversize history was not exactly empty")


def validate_warning(value, context: str) -> tuple[int, int]:
    if (
        set(value or {}) != {"count_before", "count_after", "bytes"}
        or not all(isinstance(value.get(key), int) for key in value)
        or value["count_after"] != value["count_before"] + 1
        or value["bytes"] <= 10 * 1024 * 1024
    ):
        fail(f"{context}: SkippedOversize warning evidence is invalid")
    return value["count_before"], value["count_after"]


def validate_file_identity(value, expected_name: str, context: str) -> None:
    if (
        set(value or {})
        != {"name", "device", "inode", "bytes", "sha256", "mode", "owner_current_uid"}
        or value.get("name") != expected_name
        or not re.fullmatch(r"[0-9a-f]{64}", value.get("sha256", ""))
        or not all(isinstance(value.get(key), int) and value[key] > 0 for key in ("device", "inode", "bytes"))
        or value.get("mode") != "0600"
        or value.get("owner_current_uid") is not True
    ):
        fail(f"{context}: invalid v3 file identity")


def validate_authority(value, confirm_id: str, context: str) -> int:
    deadline = value.get("deadline_unix_seconds") if isinstance(value, dict) else None
    if (
        set(value or {})
        != {
            "schema",
            "version",
            "confirm_id",
            "deadline_unix_seconds",
            "linkage_verified",
            "locator",
            "metadata",
            "raw",
        }
        or value.get("schema") != 1
        or value.get("version") != 3
        or value.get("confirm_id") != confirm_id
        or type(deadline) is not int
        or deadline <= 0
        or value.get("linkage_verified") is not True
    ):
        fail(f"{context}: v3 authority linkage receipt is invalid")
    validate_file_identity(value["locator"], "config.toml.commit-confirm-locator.json", context)
    validate_file_identity(value["metadata"], "commit-confirm-v3-metadata.json", context)
    validate_file_identity(value["raw"], "commit-confirm-v3-prior.toml", context)
    if not 10 * 1024 * 1024 < value["raw"]["bytes"] <= 384 * 1024 * 1024:
        fail(f"{context}: v3 raw snapshot is outside (10 MiB, 384 MiB]")
    return deadline


def validate_state(
    value,
    expected_process: tuple[int, int],
    pending: bool,
    context: str,
    confirm_id: str = "",
    deadline: int = 0,
) -> None:
    common = {"legacy_absent", "history_entries", "history_outcome", "process", "config", "runtime"}
    expected_keys = common | ({"authority"} if pending else {"v3_absent"})
    if (
        set(value or {}) != expected_keys
        or value.get("legacy_absent") is not True
        or value.get("history_entries") != 0
        or value.get("history_outcome") != "skipped_oversize"
        or (not pending and value.get("v3_absent") is not True)
    ):
        fail(f"{context}: lifecycle state shape/outcome is invalid")
    validate_process_json(value["process"], expected_process, context)
    validate_content(value["config"], context)
    validate_content(value["runtime"], context)
    if pending:
        authority_deadline = validate_authority(value["authority"], confirm_id, context)
        if authority_deadline >= deadline:
            fail(f"{context}: v3 authority deadline did not predate the live deadline")


def validate_plan_apply(prefix, confirm_id: str, timeout: int, context: str) -> int:
    plan, apply = prefix.get("plan", {}), prefix.get("apply", {})
    deadline = apply.get("deadline_unix_seconds")
    if (
        plan != {
        "transport": "streamed",
        "status": "committable",
        "plan_token_present": True,
        "runtime_snapshot_token_present": True,
        }
        or type(deadline) is not int
        or deadline <= 0
        or apply
        != {
            "transport": "streamed",
            "explicit_plan_token": True,
            "status": "committable",
            "confirmation_status": "pending",
            "confirm_id": confirm_id,
            "timeout_seconds": timeout,
            "deadline_unix_seconds": deadline,
            "runtime_token_coherent": True,
        }
    ):
        fail(f"{context}: streamed explicit-token confirmed apply contract is invalid")
    return deadline


def validate_transaction_evidence(cdir: Path, identity: tuple[int, int]) -> dict:
    expected_files = {
        "daemon.log", "final-evidence/ack", "final-evidence/ready", "manifest.json",
        "process.tsv", "quiet.tsv", "reloadstall.log", "rows.csv", "rss.csv", "status",
        "transactions/cycles.jsonl", "transactions/lifecycle.json",
    }
    actual_files = {path.relative_to(cdir).as_posix() for path in cdir.rglob("*") if path.is_file()}
    if expected_files != actual_files:
        fail(f"{cdir}: transaction evidence file roster is not exact")
    try:
        cycles = [json.loads(line) for line in (cdir / "transactions/cycles.jsonl").read_text().splitlines()]
    except json.JSONDecodeError as error:
        fail(f"{cdir}: invalid transaction cycle JSONL: {error}")
    if len(cycles) != 4:
        fail(f"{cdir}: expected exactly four transaction cycles")
    warning_edges = []
    candidate_ids = []
    actual_ids = []
    for number, cycle in enumerate(cycles, 1):
        reject_transaction_tokens(cycle)
        if set(cycle) != {"schema", "cycle", "candidate", "plan", "apply", "history", "pending", "confirmed"} or cycle.get("schema") != 2 or cycle.get("cycle") != number:
            fail(f"{cdir}: transaction cycle roster/order is invalid")
        validate_content(cycle["candidate"], f"cycle {number} candidate")
        if not 10 * 1024 * 1024 < cycle["candidate"]["bytes"] <= 384 * 1024 * 1024:
            fail(f"{cdir}: transaction candidate is outside streamed bounds")
        candidate_ids.append(
            (
                cycle["candidate"]["sha256"],
                cycle["candidate"]["bytes"],
                cycle["candidate"]["marker"],
            )
        )
        confirm_id = f"irrreload-measured-{number}"
        deadline = validate_plan_apply(cycle, confirm_id, 600, f"cycle {number}")
        history = cycle.get("history", {})
        if set(history) != {"before", "after", "outcome", "warning"} or history.get("outcome") != "skipped_oversize":
            fail(f"{cdir}: cycle {number} history receipt is invalid")
        validate_history(history["before"], f"cycle {number} history before")
        validate_history(history["after"], f"cycle {number} history after")
        if history["before"] != history["after"]:
            fail(f"{cdir}: cycle {number} changed bounded history")
        warning_edges.append(validate_warning(history["warning"], f"cycle {number}"))
        validate_state(
            cycle["pending"],
            identity,
            True,
            f"cycle {number} pending",
            confirm_id,
            deadline,
        )
        confirmed = cycle["confirmed"]
        if confirmed.get("status") != "confirmed" or confirmed.get("status_view_verified") is not True:
            fail(f"{cdir}: cycle {number} was not confirmed")
        validate_state(
            {
                key: value
                for key, value in confirmed.items()
                if key not in {"status", "status_view_verified"}
            },
            identity,
            False,
            f"cycle {number} confirmed",
        )
        for field in ("config", "runtime"):
            if cycle["pending"][field] != confirmed[field]:
                fail(f"{cdir}: confirm changed {field} identity")
        expected_marker = "65400:2000" if number % 2 else "65400:1000"
        if cycle["candidate"]["marker"] != expected_marker or any(
            confirmed[field]["marker"] != expected_marker
            for field in ("config", "runtime")
        ):
            fail(f"{cdir}: cycle {number} did not apply its sealed generation marker")
        actual_ids.append(
            (
                (
                    confirmed["config"]["sha256"],
                    confirmed["config"]["bytes"],
                    confirmed["config"]["marker"],
                ),
                (
                    confirmed["runtime"]["sha256"],
                    confirmed["runtime"]["bytes"],
                    confirmed["runtime"]["marker"],
                ),
            )
        )
    if not (candidate_ids[0] == candidate_ids[2] and candidate_ids[1] == candidate_ids[3] and candidate_ids[0] != candidate_ids[1]):
        fail(f"{cdir}: measured candidates do not alternate B/A/B/A")
    if not (
        actual_ids[0] == actual_ids[2]
        and actual_ids[1] == actual_ids[3]
        and actual_ids[0] != actual_ids[1]
    ):
        fail(f"{cdir}: persisted config/runtime did not alternate B/A/B/A")

    lifecycle = read_json(cdir / "transactions/lifecycle.json")
    reject_transaction_tokens(lifecycle)
    if set(lifecycle or {}) != {"schema", "generations", "baseline", "abort", "timeout", "restored_current_plan", "final_state"} or lifecycle.get("schema") != 2:
        fail(f"{cdir}: lifecycle roster is invalid")
    generations = lifecycle.get("generations", {})
    if set(generations) != {"current", "opposite"}:
        fail(f"{cdir}: lifecycle generation roster is invalid")
    validate_content(generations["current"], "current generation")
    validate_content(generations["opposite"], "opposite generation")
    if (
        (
            generations["current"]["sha256"],
            generations["current"]["bytes"],
            generations["current"]["marker"],
        )
        != candidate_ids[3]
        or (
            generations["opposite"]["sha256"],
            generations["opposite"]["bytes"],
            generations["opposite"]["marker"],
        )
        != candidate_ids[2]
    ):
        fail(f"{cdir}: lifecycle did not use final A/opposite B generations")
    baseline = lifecycle["baseline"]
    final_state = lifecycle["final_state"]
    for state, label in ((baseline, "baseline"), (final_state, "final")):
        if set(state or {}) != {"history_entries", "history_outcome", "process", "config", "runtime"} or state.get("history_entries") != 0 or state.get("history_outcome") != "skipped_oversize":
            fail(f"{cdir}: {label} restored state is invalid")
        validate_process_json(state["process"], identity, label)
        validate_content(state["config"], label); validate_content(state["runtime"], label)
    if any(baseline[field] != final_state[field] for field in ("config", "runtime")):
        fail(f"{cdir}: final disk/runtime state was not restored exactly")
    if any(
        (baseline[field]["sha256"], baseline[field]["bytes"], baseline[field]["marker"])
        != actual_ids[3][index]
        for index, field in enumerate(("config", "runtime"))
    ):
        fail(f"{cdir}: lifecycle baseline is not measured generation A")
    prior_after = warning_edges[-1][1]
    for name, terminal_status in (("abort", "aborted"), ("timeout", "auto_reverted")):
        phase = lifecycle.get(name, {})
        expected_id = f"irrreload-{name}"
        required = {"candidate_role", "plan", "apply", "history_before", "apply_history_warning", "pending", "terminal"}
        if set(phase or {}) != required or phase.get("candidate_role") != "opposite":
            fail(f"{cdir}: {name} lifecycle roster is invalid")
        deadline = validate_plan_apply(phase, expected_id, 600 if name == "abort" else 10, name)
        validate_history(phase["history_before"], f"{name} history before")
        apply_edge = validate_warning(phase["apply_history_warning"], f"{name} apply")
        validate_state(
            phase["pending"], identity, True, f"{name} pending", expected_id, deadline
        )
        terminal = phase["terminal"]
        extra = {
            "status",
            "status_view_verified",
            "restored_exactly",
            "history_warning",
            "history_after",
        }
        if (
            not extra.issubset(terminal)
            or terminal.get("status") != terminal_status
            or terminal.get("status_view_verified") is not True
            or terminal.get("restored_exactly") is not True
        ):
            fail(f"{cdir}: {name} terminal outcome is invalid")
        validate_state({key: value for key, value in terminal.items() if key not in extra}, identity, False, f"{name} terminal")
        validate_history(terminal["history_after"], f"{name} history after")
        if terminal["history_after"] != phase["history_before"]:
            fail(f"{cdir}: {name} changed bounded history")
        terminal_edge = validate_warning(terminal["history_warning"], f"{name} restore")
        if apply_edge[0] != prior_after or terminal_edge[0] != apply_edge[1]:
            fail(f"{cdir}: {name} history warning sequence is discontinuous")
        prior_after = terminal_edge[1]
        for field in ("config", "runtime"):
            if terminal[field] != baseline[field]:
                fail(f"{cdir}: {name} did not restore {field} exactly")
        for index, field in enumerate(("config", "runtime")):
            pending_identity = (
                phase["pending"][field]["sha256"],
                phase["pending"][field]["bytes"],
                phase["pending"][field]["marker"],
            )
            if pending_identity != actual_ids[2][index]:
                fail(f"{cdir}: {name} pending state is not measured generation B")
    if any(right[0] != left[1] for left, right in zip(warning_edges, warning_edges[1:])) or warning_edges[0][0] != 1 or prior_after != 9:
        fail(f"{cdir}: oversize warning count is not exact across nine persists")
    if lifecycle.get("restored_current_plan") != {"transport": "streamed", "status": "noop", "plan_token_present": False}:
        fail(f"{cdir}: restored-current streamed Plan was not tokenless NOOP")
    warning_lines = [
        line for line in (cdir / "daemon.log").read_text().splitlines()
        if "applied config exceeds the bounded history entry size; history was left unchanged" in line
    ]
    if len(warning_lines) != 9:
        fail(f"{cdir}: daemon log does not contain exactly nine oversize history warnings")
    try:
        warning_bytes = [json.loads(line)["fields"]["bytes"] for line in warning_lines]
    except (json.JSONDecodeError, KeyError, TypeError):
        fail(f"{cdir}: daemon oversize warning lines are malformed")
    if any(not isinstance(size, int) or size <= 10 * 1024 * 1024 for size in warning_bytes):
        fail(f"{cdir}: daemon oversize warning byte counts are invalid")
    compact_warning_bytes = [cycle["history"]["warning"]["bytes"] for cycle in cycles]
    for name in ("abort", "timeout"):
        compact_warning_bytes.extend(
            (
                lifecycle[name]["apply_history_warning"]["bytes"],
                lifecycle[name]["terminal"]["history_warning"]["bytes"],
            )
        )
    if compact_warning_bytes != warning_bytes[1:]:
        fail(f"{cdir}: compact history-warning evidence is not bound to daemon log order")
    return {
        "inputs": {"a": candidate_ids[1], "b": candidate_ids[0]},
        "actual": {
            "a": {"config": actual_ids[1][0], "runtime": actual_ids[1][1]},
            "b": {"config": actual_ids[0][0], "runtime": actual_ids[0][1]},
        },
    }


def validate_root(root: Path, kind: str):
    validate_preflight(root / "preflight.log")
    provenance = read_json(root / "provenance.json")
    inputs, git = provenance.get("inputs", {}), provenance.get("git", {})
    expected_cells = {
        "comparison": COMPARISON_CELLS,
        "grouped": (GROUPED_CELL,),
        "transaction": (TRANSACTION_CELL,),
        "sighup": ("rustbgpd-sighup",),
    }[kind]
    expected_kind = {
        "comparison": "full-cross-daemon",
        "grouped": "full-grouped-control",
        "transaction": "full-transaction",
        "sighup": "full-rustbgpd-sighup",
    }[kind]
    environment = provenance.get("environment")
    if inputs.get("cells") != ",".join(expected_cells):
        fail(f"{root}: wrong {kind} cell roster")
    if inputs.get("campaign_kind") != expected_kind:
        fail(f"{root}: wrong campaign kind for {kind} role")
    if (
        set(provenance)
        != {
            "schema",
            "started_at_epoch_ns",
            "git",
            "environment",
            "inputs",
        }
        or provenance.get("schema") != 1
        or not isinstance(provenance.get("started_at_epoch_ns"), int)
        or provenance.get("started_at_epoch_ns", -1) <= 0
        or not isinstance(environment, dict)
        or set(environment)
        != {"rustc", "cargo", "python", "jq", "docker", "kernel", "cpu_model"}
        or not all(isinstance(value, str) and value for value in environment.values())
    ):
        fail(f"{root}: receipt context is incomplete")
    expected_input_keys = {
        *CANONICAL_FULL_INPUTS,
        "campaign_kind",
        "cells",
        "bird_image_id",
        "openbgpd_image_id",
        "overlap_fraction",
    }
    canonical_inputs = dict(CANONICAL_FULL_INPUTS)
    if kind == "sighup" and inputs.get("changed_fraction") == "1.0":
        canonical_inputs["changed_fraction"] = "1.0"
    if set(inputs) != expected_input_keys or any(
        inputs.get(key) != value for key, value in canonical_inputs.items()
    ):
        fail(f"{root}: full workload inputs are not exact and canonical")
    # The overlap fraction is a legitimate campaign dimension (LAN-892), not
    # a canonical constant: require a well-formed value and bind every cell
    # manifest to it below. Cross-root equality rides the inputs identity.
    inputs_overlap = inputs.get("overlap_fraction")
    if (
        not isinstance(inputs_overlap, str)
        or not re.fullmatch(r"[0-9]+([.][0-9]+)?", inputs_overlap)
        or not 0 <= float(inputs_overlap) < 1
        or kind == "sighup" and inputs_overlap != "0"
    ):
        fail(f"{root}: overlap_fraction input is not a decimal in [0, 1)")
    selected_image = re.compile(r"sha256:[0-9a-f]{64}")
    expected_image_id = selected_image.fullmatch if kind == "comparison" else None
    if (
        kind == "comparison"
        and not all(
            isinstance(inputs.get(key), str) and expected_image_id(inputs[key])
            for key in ("bird_image_id", "openbgpd_image_id")
        )
    ) or (
        kind != "comparison"
        and any(
            inputs.get(key) != "not-selected"
            for key in ("bird_image_id", "openbgpd_image_id")
        )
    ):
        fail(f"{root}: container image identities do not match the campaign role")
    actual_shape = tuple(int(inputs.get(name, -1)) for name in ("n_members", "total_prefixes", "min_list", "max_list", "seed"))
    if actual_shape != CANONICAL_SHAPE or int(inputs.get("reloads", -1)) != 4:
        fail(f"{root}: noncanonical full shape/seed/reload count")
    commit = git.get("commit")
    tree = git.get("tree")
    if (
        not isinstance(commit, str)
        or not re.fullmatch(r"[0-9a-f]{40}", commit)
        or not isinstance(tree, str)
        or not re.fullmatch(r"[0-9a-f]{40}", tree)
        or git.get("dirty") is not False
        or set(git) != {"commit", "tree", "dirty"}
    ):
        fail(f"{root}: commit/tree context is malformed or incomplete")
    dataset = (root / "dataset.sha256").read_text().strip()
    if not re.fullmatch(r"[0-9a-f]{64}", dataset):
        fail(f"{root}: invalid canonical dataset digest")
    rows_data = read_rows(root / "rows.csv", expected_cells)
    completed = read_json(root / "COMPLETED")
    if (
        set(completed) != {"status", "completed_at_epoch_ns", "cells"}
        or completed.get("status") != "pass"
        or completed.get("cells") != ",".join(expected_cells)
        or not isinstance(completed.get("completed_at_epoch_ns"), int)
        or completed.get("completed_at_epoch_ns", -1) <= provenance["started_at_epoch_ns"]
    ):
        fail(f"{root}: COMPLETED does not record status/cells/time")
    identities = []
    transaction_evidence = None
    for cell in expected_cells:
        cdir = root / cell
        validate_quiet(cdir / "quiet.tsv")
        identities.append(validate_process(cdir / "process.tsv"))
        for marker in ("ready", "ack"):
            marker_path = cdir / "final-evidence" / marker
            if marker_path.is_symlink() or not marker_path.is_file() or marker_path.read_text() != f"{marker}\n":
                fail(f"{root}: {cell} final-evidence {marker} is not an exact regular marker")
        manifest = read_json(cdir / "manifest.json")
        validate_cell_evidence(
            root,
            cell,
            rows_data,
            320,
            183040,
        )
        if manifest.get("dataset_sha256") != dataset or manifest.get("admit_churn") is not True:
            fail(f"{root}: {cell} manifest dataset/churn mismatch")
        manifest_fraction = manifest.get("changed_fraction")
        if (
            type(manifest_fraction) not in (int, float)
            or manifest_fraction != float(inputs["changed_fraction"])
        ):
            fail(f"{root}: {cell} manifest changed fraction does not match campaign inputs")
        if manifest.get("overlap_fraction", 0.0) != float(inputs_overlap):
            fail(f"{root}: {cell} manifest overlap does not match campaign inputs")
        load_overlap(cdir / "manifest.json", 320, 183040)
        manifest_shape = tuple(
            int(manifest.get(name, -1))
            for name in ("n_members", "total_prefixes", "min_list", "max_list", "seed")
        )
        if manifest_shape != CANONICAL_SHAPE:
            fail(f"{root}: {cell} manifest does not describe the canonical dataset")
        if cell == "rustbgpd-sighup":
            if manifest.get("path_hiding") is not True or manifest.get("path_hiding_applicable") is not True:
                fail(f"{root}: private rustbgpd path-hiding mode not explicit")
        elif cell == GROUPED_CELL:
            if manifest.get("path_hiding") is not False or manifest.get("path_hiding_applicable") is not True:
                fail(f"{root}: grouped rustbgpd path-hiding mode not explicit")
        elif cell == TRANSACTION_CELL:
            if manifest.get("path_hiding") is not True or manifest.get("path_hiding_applicable") is not True:
                fail(f"{root}: transaction path-hiding mode not explicit")
            transaction_evidence = validate_transaction_evidence(
                cdir, identities[-1]
            )
        elif not (
            manifest.get("path_hiding") is None
            and manifest.get("path_hiding_applicable") is False
            and manifest.get("path_hiding_requested") is True
        ):
            fail(f"{root}: competitor path-hiding applicability is misstated")
        if cell in ("rustbgpd-sighup", GROUPED_CELL):
            if manifest.get("rustbgpd_dataset_mode") is True:
                summary = cdir / "dataset-refresh-summary.csv"
                with tempfile.NamedTemporaryFile() as rebuilt:
                    validate_dataset_refresh(
                        cdir / "daemon.log",
                        cdir / "reloadstall.log",
                        cdir / "manifest.json",
                        Path(rebuilt.name),
                    )
                    if Path(rebuilt.name).read_bytes() != summary.read_bytes():
                        fail(f"{root}: {cell} dataset refresh summary does not re-extract")
            for marker in ("ready", "ack"):
                marker_path = cdir / "pre-churn" / marker
                if marker_path.is_symlink() or not marker_path.is_file() or marker_path.read_text() != f"{marker}\n":
                    fail(f"{root}: {cell} pre-churn {marker} is not an exact regular marker")
            read_received_view(cdir / "received-view.tsv", 320, 183040)
            topology = read_json(cdir / "topology.json")
            expected_mode = "private" if cell == "rustbgpd-sighup" else "grouped"
            with tempfile.NamedTemporaryFile() as revalidated:
                validate_topology(
                    expected_mode,
                    320,
                    183040,
                    cdir / "config.toml",
                    cdir / "topology.tsv",
                    [cdir / f"metrics-{sample}.prom" for sample in range(1, 4)],
                    Path(revalidated.name),
                    cdir / "manifest.json",
                )
                raw_topology = read_json(Path(revalidated.name))
            scrapes = topology.get("scrape_epoch_ns", [])
            if (
                any(topology.get(key) != raw_topology.get(key) for key in ("status", "mode", "peers", "scrape_epoch_ns", "group_id", "overlap_fraction", "overlap_pairs"))
                or topology.get("status") != "pass"
                or topology.get("mode") != expected_mode
                or topology.get("peers") != 320
                or len(scrapes) != 3
                or any(right - left < 1_000_000_000 for left, right in zip(scrapes, scrapes[1:]))
                or scrapes[-1] // 1000 >= int(topology.get("first_reload_wall_us", -1))
            ):
                fail(f"{root}: {cell} pre-reload topology proof is invalid")
    return {
        "root": root,
        "kind": kind,
        "commit": commit,
        "dataset": dataset,
        "shape": actual_shape,
        "started": int(provenance.get("started_at_epoch_ns", -1)),
        "completed": int(completed.get("completed_at_epoch_ns", -1)),
        "git": git,
        "environment": environment,
        "inputs": inputs,
        "identities": identities,
        "rows": rows_data,
        "transaction_evidence": transaction_evidence,
    }


def audit_combined(path: Path, expected_cells: tuple[str, ...]) -> None:
    with path.open(newline="") as stream:
        reader = csv.reader(stream)
        header = next(reader, None)
        data = list(reader)
    if header != ["repeat", *ROWS_HEADER.split(",")]:
        fail(f"{path}: combined output header mismatch")
    if len(data) != 8 * len(expected_cells):
        fail(f"{path}: combined output row count mismatch")
    for repeat in ("A", "B"):
        repeat_rows = [row for row in data if row and row[0] == repeat]
        if len(repeat_rows) != 4 * len(expected_cells) or {
            row[1] for row in repeat_rows
        } != set(expected_cells):
            fail(f"{path}: {repeat} cell roster/count mismatch")
        for cell in expected_cells:
            if [row[2] for row in repeat_rows if row[1] == cell] != ["1", "2", "3", "4"]:
                fail(f"{path}: {repeat}/{cell} reload roster mismatch")
    if {row[0] for row in data if row} != {"A", "B"}:
        fail(f"{path}: repeat labels must be exactly A/B")


def write_combined(path: Path, campaigns, expected_cells: tuple[str, ...]) -> None:
    if len(campaigns) != 2 or any(
        {row[0] for row in campaign["rows"]} != set(expected_cells)
        or len(campaign["rows"]) != 4 * len(expected_cells)
        for campaign in campaigns
    ):
        fail(f"{path}: writer input escaped expected cell roster")
    with path.open("w", newline="") as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(["repeat", *ROWS_HEADER.split(",")])
        for repeat, campaign in zip(("A", "B"), campaigns, strict=True):
            for row in campaign["rows"]:
                writer.writerow([repeat, *row])
    audit_combined(path, expected_cells)


def validate_campaigns(roots: list[Path], output_dir: Path) -> None:
    if len(roots) != 4:
        fail("expected four roots in comparison-A/grouped-A/grouped-B/comparison-B order")
    campaigns = [
        validate_root(roots[0], "comparison"),
        validate_root(roots[1], "grouped"),
        validate_root(roots[2], "grouped"),
        validate_root(roots[3], "comparison"),
    ]
    if len({(entry["commit"], entry["shape"], entry["dataset"]) for entry in campaigns}) != 1:
        fail("four roots do not share commit, canonical shape/seed, and dataset digest")
    starts = [entry["started"] for entry in campaigns]
    if any(value <= 0 for value in starts) or starts != sorted(starts) or len(set(starts)) != 4:
        fail("roots are not in strict A/B/B/A execution order")
    if any(
        campaigns[index]["completed"] >= campaigns[index + 1]["started"]
        for index in range(3)
    ):
        fail("campaign roots overlap or do not finish before the next root starts")
    source_identity = ("git", "environment")
    if any(
        tuple(campaign[key] for key in source_identity)
        != tuple(campaigns[0][key] for key in source_identity)
        for campaign in campaigns[1:]
    ):
        fail("four roots do not share exact source and environment context")
    repeat_identity = ("git", "environment", "inputs")
    for left, right in ((campaigns[0], campaigns[3]), (campaigns[1], campaigns[2])):
        if tuple(left[key] for key in repeat_identity) != tuple(
            right[key] for key in repeat_identity
        ):
            fail("A/B repeats do not share exact protocol and environment context")
    identities = [identity for entry in campaigns for identity in entry["identities"]]
    if len(identities) != len(set(identities)):
        fail("daemon PID/start identity was reused across campaign cells")
    # Received-view delta (LAN-892): per repeat, the observer-side count of
    # (member, prefix) pairs where per-client-best delivered a runner-up path
    # that the grouped control suppressed, over the shared scenario.
    deltas = {
        label: received_view_delta(
            comparison_root / "rustbgpd-sighup", grouped_root / GROUPED_CELL
        )
        for label, comparison_root, grouped_root in (
            ("A", roots[0], roots[1]),
            ("B", roots[3], roots[2]),
        )
    }
    if deltas["A"] != deltas["B"]:
        fail("A/B repeats disagree on the received-view delta")
    output_dir.mkdir(parents=True, exist_ok=False)
    write_combined(
        output_dir / "comparison.csv", (campaigns[0], campaigns[3]), COMPARISON_CELLS
    )
    write_combined(
        output_dir / "grouped-control.csv", (campaigns[1], campaigns[2]), (GROUPED_CELL,)
    )
    (output_dir / "verification.json").write_text(
        json.dumps(
            {
                "status": "pass",
                "order": ["comparison-A", "grouped-A", "grouped-B", "comparison-B"],
                "commit": campaigns[0]["commit"],
                "dataset_sha256": campaigns[0]["dataset"],
                "comparison_rows": len(campaigns[0]["rows"]) + len(campaigns[3]["rows"]),
                "grouped_control_rows": len(campaigns[1]["rows"]) + len(campaigns[2]["rows"]),
                "received_view_delta": deltas["A"],
            },
            sort_keys=True,
        )
        + "\n"
    )


def validate_transactions(roots: list[Path], output_dir: Path) -> None:
    if len(roots) != 2:
        fail("expected exactly two transaction roots in A/B order")
    campaigns = [validate_root(root, "transaction") for root in roots]
    if len({(entry["commit"], entry["shape"], entry["dataset"]) for entry in campaigns}) != 1:
        fail("transaction roots do not share commit, canonical shape/seed, and dataset")
    if campaigns[0]["completed"] >= campaigns[1]["started"]:
        fail("transaction roots overlap or are not in A/B order")
    shared = ("git", "environment", "inputs")
    if any(campaigns[0][key] != campaigns[1][key] for key in shared):
        fail("transaction roots do not share exact source, environment, and inputs")
    if campaigns[0]["transaction_evidence"] != campaigns[1]["transaction_evidence"]:
        fail("transaction roots do not share exact A/B input and applied-state identities")
    identities = [identity for campaign in campaigns for identity in campaign["identities"]]
    if len(identities) != len(set(identities)):
        fail("daemon PID/start identity was reused across transaction roots")
    output_dir.mkdir(parents=True, exist_ok=False)
    write_combined(output_dir / "transactions.csv", campaigns, (TRANSACTION_CELL,))
    (output_dir / "verification.json").write_text(
        json.dumps(
            {
                "status": "pass",
                "order": ["transaction-A", "transaction-B"],
                "commit": campaigns[0]["commit"],
                "dataset_sha256": campaigns[0]["dataset"],
                "transaction_rows": sum(len(campaign["rows"]) for campaign in campaigns),
            },
            sort_keys=True,
        )
        + "\n"
    )


def make_transaction_evidence(cdir: Path, pid: int) -> None:
    size = 11 * 1024 * 1024
    history = {"entries": [], "files": []}
    process = {"pid": pid, "starttime": pid + 100, "vmrss_kib": 1024, "vmhwm_kib": 2048}

    def content(digest):
        return {"sha256": digest * 64, "bytes": size,
                "marker": "65400:1000" if digest == "a" else "65400:2000"}

    def file_identity(name, digest, inode, bytes_count):
        return {"name": name, "device": 1, "inode": inode, "bytes": bytes_count,
                "sha256": digest * 64, "mode": "0600", "owner_current_uid": True}

    def authority(confirm_id, deadline, inode):
        return {"schema": 1, "version": 3, "confirm_id": confirm_id,
            "deadline_unix_seconds": deadline, "linkage_verified": True,
            "locator": file_identity("config.toml.commit-confirm-locator.json", "c", inode, 100),
            "raw": file_identity("commit-confirm-v3-prior.toml", "d", inode + 1, size),
            "metadata": file_identity("commit-confirm-v3-metadata.json", "e", inode + 2, 200)}

    def base_state(digest):
        return {"history_entries": 0, "history_outcome": "skipped_oversize",
                "process": process, "config": content(digest), "runtime": content(digest)}

    def pending(digest, confirm_id, deadline, inode):
        return {"authority": authority(confirm_id, deadline - 1, inode),
                "legacy_absent": True, **base_state(digest)}

    def terminal(digest):
        return {"v3_absent": True, "legacy_absent": True, **base_state(digest)}

    def warning(before):
        return {"count_before": before, "count_after": before + 1, "bytes": size}

    cycles = []
    for number in range(1, 5):
        digest = "b" if number % 2 else "a"
        confirm_id = f"irrreload-measured-{number}"
        deadline = 1_000 + number
        cycles.append(
            {
                "schema": 2,
                "cycle": number,
                "candidate": content(digest),
                "plan": {"transport": "streamed", "status": "committable", "plan_token_present": True, "runtime_snapshot_token_present": True},
                "apply": {"transport": "streamed", "explicit_plan_token": True, "status": "committable", "confirmation_status": "pending", "confirm_id": confirm_id, "timeout_seconds": 600, "deadline_unix_seconds": deadline, "runtime_token_coherent": True},
                "history": {"before": history, "after": history, "outcome": "skipped_oversize", "warning": warning(number)},
                "pending": pending(digest, confirm_id, deadline, 100 + number * 10),
                "confirmed": {"status": "confirmed", "status_view_verified": True, **terminal(digest)},
            }
        )
    txn_dir = cdir / "transactions"
    txn_dir.mkdir()
    (txn_dir / "cycles.jsonl").write_text("".join(json.dumps(cycle) + "\n" for cycle in cycles))

    def phase(name, timeout, apply_before, restore_before, inode):
        confirm_id = f"irrreload-{name}"
        deadline = 2_000 + inode
        return {"candidate_role": "opposite",
            "plan": {"transport": "streamed", "status": "committable", "plan_token_present": True, "runtime_snapshot_token_present": True},
            "apply": {"transport": "streamed", "explicit_plan_token": True, "status": "committable", "confirmation_status": "pending", "confirm_id": confirm_id, "timeout_seconds": timeout, "deadline_unix_seconds": deadline, "runtime_token_coherent": True},
            "history_before": history, "apply_history_warning": warning(apply_before),
            "pending": pending("b", confirm_id, deadline, inode),
            "terminal": {"status": "aborted" if name == "abort" else "auto_reverted",
                "status_view_verified": True, "restored_exactly": True,
                "history_warning": warning(restore_before),
                "history_after": history, **terminal("a")}}

    lifecycle = {
        "schema": 2,
        "generations": {"current": content("a"), "opposite": content("b")},
        "baseline": base_state("a"),
        "abort": phase("abort", 600, 5, 6, 200),
        "timeout": phase("timeout", 10, 7, 8, 300),
        "restored_current_plan": {"transport": "streamed", "status": "noop", "plan_token_present": False},
        "final_state": base_state("a"),
    }
    (txn_dir / "lifecycle.json").write_text(json.dumps(lifecycle) + "\n")
    warning_line = json.dumps({"fields": {"message": "applied config exceeds the bounded history entry size; history was left unchanged", "bytes": size}})
    (cdir / "daemon.log").write_text((warning_line + "\n") * 9)


def make_fixture(root: Path, kind: str, started: int, identity_seed: int) -> None:
    cells = {
        "comparison": COMPARISON_CELLS,
        "grouped": (GROUPED_CELL,),
        "transaction": (TRANSACTION_CELL,),
        "sighup": ("rustbgpd-sighup",),
    }[kind]
    root.mkdir()
    dataset = "a" * 64
    (root / "dataset.sha256").write_text(dataset + "\n")
    image_id = "sha256:" + "a" * 64
    provenance = {
        "schema": 1,
        "started_at_epoch_ns": started,
        "git": {"commit": "c" * 40, "tree": "b" * 40, "dirty": False},
        "environment": {key: "fixture" for key in ("rustc", "cargo", "python", "jq", "docker", "kernel", "cpu_model")},
        "inputs": {
            **CANONICAL_FULL_INPUTS,
            "overlap_fraction": "0",
            "campaign_kind": {"comparison": "full-cross-daemon", "grouped": "full-grouped-control", "transaction": "full-transaction", "sighup": "full-rustbgpd-sighup"}[kind],
            "cells": ",".join(cells),
            "bird_image_id": image_id if kind == "comparison" else "not-selected",
            "openbgpd_image_id": image_id if kind == "comparison" else "not-selected",
        },
    }
    (root / "provenance.json").write_text(json.dumps(provenance))
    (root / "preflight.log").write_text(
        "  ok: no pushes to main during the soak window (confirmed via fixture)\n"
        "[preflight] READY — all pre-flight checks passed\n"
    )
    root_rows = []
    with (root / "rows.csv").open("w") as stream:
        stream.write(ROWS_HEADER + "\n")
        for cell in cells:
            for reload_no in range(1, 5):
                row = [cell, str(reload_no), "320", "320", "0", "183040", *(["1"] * 14), "0", "320", "0"]
                root_rows.append(row)
                stream.write(",".join(row) + "\n")
    for offset, cell in enumerate(cells):
        cdir = root / cell
        cdir.mkdir()
        (cdir / "quiet.tsv").write_text(
            "sample\tepoch_s\tload1\tpswpin\tpswpout\tport1790_free\tport9179_free\tdisk_available_kib\n"
            "1\t1\t0.5\t0\t0\ttrue\ttrue\t41943040\n2\t31\t0.5\t0\t0\ttrue\ttrue\t41943040\n"
        )
        pid = identity_seed + offset
        (cdir / "process.tsv").write_text(f"pid\tstarttime_before\tstarttime_after\n{pid}\t{pid + 100}\t{pid + 100}\n")
        if cell == "rustbgpd-sighup":
            mode = {"path_hiding": True, "path_hiding_applicable": True, "path_hiding_requested": True}
        elif cell == GROUPED_CELL:
            mode = {"path_hiding": False, "path_hiding_applicable": True, "path_hiding_requested": False}
        elif cell == TRANSACTION_CELL:
            mode = {"path_hiding": True, "path_hiding_applicable": True, "path_hiding_requested": True}
        else:
            mode = {"path_hiding": None, "path_hiding_applicable": False, "path_hiding_requested": True}
        runtime_files = {
            "rustbgpd-sighup": ["config.toml", "member.rpol", "gen-a.rpol", "gen-b.rpol"],
            GROUPED_CELL: ["config.toml", "member.rpol", "gen-a.rpol", "gen-b.rpol"],
            TRANSACTION_CELL: ["config.toml", "candidate.toml", "gen-a.toml", "gen-b.toml"],
            "bird": ["bird.conf", "gen.conf", "gen-a.conf", "gen-b.conf"],
            "openbgpd": ["bgpd.conf", "gen.conf", "gen-a.conf", "gen-b.conf"],
        }[cell]
        manifest = {"dataset_sha256": dataset, "admit_churn": True, "n_members": 320, "total_prefixes": 183040, "min_list": 1000, "max_list": 40000, "seed": 61, "changed_fraction": 0.1, "runtime_files": runtime_files, **mode}
        (cdir / "manifest.json").write_text(json.dumps(manifest))
        cell_rows = [row for row in root_rows if row[0] == cell]
        (cdir / "rows.csv").write_text("".join(",".join(row) + "\n" for row in cell_rows))
        (cdir / "reloadstall.log").write_text(
            "".join("reloadstall_csv," + ",".join(row[1:]) + "\n" for row in cell_rows)
        )
        (cdir / "daemon.log").write_text("fixture daemon log\n")
        (cdir / "rss.csv").write_text("epoch_s,total_rss_kib,pids\n1,1024,1\n")
        final_boundary = cdir / "final-evidence"
        final_boundary.mkdir()
        (final_boundary / "ready").write_text("ready\n")
        (final_boundary / "ack").write_text("ack\n")
        if cell in ("rustbgpd-sighup", GROUPED_CELL):
            topology_mode = "private" if cell == "rustbgpd-sighup" else "grouped"
            (cdir / "topology.json").write_text(json.dumps({"status": "pass", "mode": topology_mode, "peers": 320, "scrape_epoch_ns": [1_000_000_000, 2_000_000_000, 3_000_000_000], "group_id": 7, "first_reload_wall_us": 4_000_000, "overlap_fraction": 0.0, "overlap_pairs": 0}))
            received_rows = [f"received_view_v1\ttotal=183040\tpeers=320"]
            for observer in range(320):
                own = ",".join(str(index) for index in range(observer * 572, (observer + 1) * 572))
                received_rows.append(f"{observer}\t572\t{own}")
            (cdir / "received-view.tsv").write_text("\n".join(received_rows) + "\n")
            (cdir / "config.toml").write_text("per_client_best = true\n" * (320 if cell == "rustbgpd-sighup" else 0))
            (cdir / "topology.tsv").write_text("phase\tepoch_ns\nscrape1\t1000000000\nscrape2\t2000000000\nscrape3\t3000000000\n")
            metrics = ["bgp_rib_outbound_registered_peers 320", "bgp_rib_ingest_channel_depth 0", "bgp_rib_policy_transition_in_progress 0", 'bgp_rib_loc_prefixes{afi_safi="all"} 183040']
            for peer in range(320):
                metrics += [f'bgp_peer_session_established{{interface="eth0",peer="p{peer}"}} 1', f'bgp_peer_outbound_queue_depth{{peer="p{peer}"}} 0']
                metrics += [f'bgp_session_established_total{{peer="p{peer}"}} 1']
                metrics += [f'bgp_rib_prefixes{{afi_safi="{family}",peer="p{peer}"}} {572 if family == "all" else 0}' for family in ("all", "flowspec")]
                metrics += [f'bgp_rib_adj_out_prefixes{{afi_safi="{family}",peer="p{peer}"}} {182468 if family == "all" else 0}' for family in ("all", "bgpls", "evpn", "flowspec", "labeled", "rtc", "vpn")]
            metrics += ["bgp_update_groups 1", "bgp_update_group_fallback_peers 0", "bgp_update_group_runner_up_entries 0", 'bgp_update_group_members{group="7"} 320']
            metrics += [f'bgp_peer_update_group{{peer="p{peer}"}} 7' for peer in range(320)]
            for sample in range(1, 4):
                (cdir / f"metrics-{sample}.prom").write_text("\n".join(metrics) + "\n")
            boundary = cdir / "pre-churn"
            boundary.mkdir()
            (boundary / "ready").write_text("ready\n")
            (boundary / "ack").write_text("ack\n")
        elif cell == TRANSACTION_CELL:
            make_transaction_evidence(cdir, pid)
        (cdir / "status").write_text("pass\n")
    (root / "COMPLETED").write_text(json.dumps({
        "status": "pass", "completed_at_epoch_ns": started + 5, "cells": ",".join(cells)
    }))


def self_test() -> None:
    with tempfile.TemporaryDirectory() as phase_tmp:
        root = Path(phase_tmp)
        reload_log = root / "reload.log"
        daemon_log = root / "daemon.log"
        output = root / "phases.csv"
        reload_log.write_text(
            "reload 1 SIGHUP wall_us=8635464000000000 policy=b\n"
            "reload 2 SIGHUP wall_us=8635464001000000 policy=a\n"
        )
        def phase_line(second: int, outcome: str, fallback: bool) -> str:
            fields = {
                "message": "reload generation phase timing", "target": "reload_generation_phase",
                "total_targets": 320, "cohort_targets": 300, "remainder_targets": 20,
                "refresh_count": 32, "outcome": outcome, "authoritative_fallback": fallback,
                "preflight_us": 10, "cohort_selection_us": 20,
                "cohort_prestage_session_apply_us": 30, "cohort_rib_transition_us": 40,
                "authoritative_remainder_apply_us": 50, "deferred_refresh_dispatch_us": 60,
                "convergence_check_us": 70, "total_us": 300, "unattributed_us": 20,
            }
            return json.dumps({"timestamp": f"2243-08-25T12:00:0{second}.000001Z", "level": "INFO",
                               "fields": fields, "target": "rustbgpd::peer_manager::policy"}) + "\n"
        daemon_log.write_text(phase_line(0, "committed", False) + phase_line(1, "failed", True))
        validate_reload_phases(daemon_log, reload_log, output)
        assert [
            int(row["timestamp_epoch_us"])
            for row in csv.DictReader(output.open())
        ] == [8635464000000001, 8635464001000001]
        original = daemon_log.read_text()
        non_numeric = json.loads(phase_line(0, "committed", False))
        non_numeric["fields"]["preflight_us"] = None
        non_string_outcome = json.loads(phase_line(0, "committed", False))
        non_string_outcome["fields"]["outcome"] = []
        for broken in (
            phase_line(0, "committed", False),
            original + phase_line(1, "failed", True),
            "null\n" + original,
            json.dumps({"fields": []}) + "\n" + original,
            json.dumps(non_numeric) + "\n" + phase_line(1, "failed", True),
            json.dumps(non_string_outcome) + "\n" + phase_line(1, "failed", True),
        ):
            daemon_log.write_text(broken)
            try:
                validate_reload_phases(daemon_log, reload_log, output)
            except InvalidReceipt:
                pass
            else:
                fail("reload phase self-test accepted a missing/duplicate record")

        manifest_path = root / "manifest.json"
        manifest_path.write_text(json.dumps({
            "rustbgpd_dataset_mode": True, "n_members": 320, "seed": 61,
            "changed_fraction": 0.1,
            "changed_dataset_files": {"prefix": 36, "asn": 0},
        }))
        reload_log.write_text("".join(
            f"reload {number} SIGHUP wall_us={8635464000000000 + number * 1000000} policy=x\n"
            + ",".join(["reloadstall_csv", str(number), "320", "36", "284", "183040",
                *(["1.0"] * 14), "320", "320", "0"]) + "\n"
            for number in range(1, 5)
        ))
        def dataset_lines(number: int) -> str:
            load = {"message":"config source loaded", "dataset_hashed":640,
                "dataset_parsed":36, "dataset_exact_content_reused":604,
                "dataset_source_rebound":0, "dataset_changed":36, "dataset_failed":0}
            refresh = {"message":"processed dataset-swap dependency-scoped refresh",
                "eligible":36, "refreshed":36, "skipped_not_established":0, "failures":0}
            return "\n".join((
                json.dumps({"timestamp":f"2243-08-25T12:00:0{number}.100001Z", "fields":load}),
                json.dumps({"timestamp":f"2243-08-25T12:00:0{number}.200001Z", "fields":refresh}),
            )) + "\n"
        daemon_log.write_text("".join(dataset_lines(number) for number in range(1, 5)))
        validate_dataset_refresh(daemon_log, reload_log, manifest_path, output)
        dataset_original = daemon_log.read_text()
        reload_original = reload_log.read_text()
        mutations = {
            "parsed": dataset_original.replace('"dataset_parsed": 36', '"dataset_parsed": 35', 1),
            "missing-refresh": "\n".join(dataset_original.splitlines()[1:]) + "\n",
            "source-rebound": dataset_original.replace('"dataset_source_rebound": 0', '"dataset_source_rebound": 1', 1),
            "duplicate-load": dataset_original + dataset_original.splitlines()[0] + "\n",
        }
        for name, broken in mutations.items():
            daemon_log.write_text(broken)
            try: validate_dataset_refresh(daemon_log, reload_log, manifest_path, output)
            except InvalidReceipt: print(f"red-proof dataset-refresh-{name}=pass")
            else: fail(f"dataset refresh self-test accepted {name} mutation")
        daemon_log.write_text(dataset_original)
        reload_log.write_text(reload_original.replace(",320,0\n", ",319,0\n", 1))
        try: validate_dataset_refresh(daemon_log, reload_log, manifest_path, output)
        except InvalidReceipt: print("red-proof dataset-refresh-sessions=pass")
        else: fail("dataset refresh self-test accepted missing session")
        full_labeled = read_json(manifest_path)
        full_labeled["changed_fraction"] = 1.0
        manifest_path.write_text(json.dumps(full_labeled))
        reload_log.write_text(reload_original)
        try: validate_dataset_refresh(daemon_log, reload_log, manifest_path, output)
        except InvalidReceipt: print("red-proof dataset-refresh-full-label-partial=pass")
        else: fail("dataset refresh self-test accepted partial counters as full")

        reload_log.write_text("".join(
            f"reload {number} SIGHUP wall_us={8635464000000000 + number * 1000000} policy=x\n"
            for number in range(1, 5)))
        def discriminator_lines(number: int) -> str:
            distribution = 10 if number == 1 else 250
            phases = {key: (distribution if key == "member_emit_state_us" else 1) for key in AUTHORITATIVE_PHASES}
            fields = {"message":"authoritative_batch_phase", "outcome":"committed",
                "classification":"shared", "failure_stage":"none",
                "total_us":sum(phases.values()) + 1, "remainder_us":1, **phases,
                "input_peers":320, "present_peers":320, "skipped_peers":0, "duplicate_peers":0,
                "candidate_cohorts":1, "shared_cohorts":1, "shared_members":320,
                "fallback_members":0, "destination_ensures":1, "destination_builds":1,
                "destination_adoptions":0, "membership_moves":320, "inventory_announces":10,
                "inventory_withdraws":10, "inventory_supplements":0, "tombstones":0,
                "lagging_members":0, "filtered_scope_prefixes":10,
                "filtered_scope_member_visits":3200 if number == 1 else 6400, "emits_attempted":320,
                "emits_succeeded":320, "emits_degraded":0, "distribution_passes":1,
                "filtered_state_before":1 if number == 1 else 2, "filtered_state_after":1, "dirty_before":0,
                "dirty_after":0, "pending_before":0, "pending_after":0,
                "groups_before":1, "groups_after":1}
            inner = {"timestamp":f"2243-08-25T12:00:0{number}.000001Z",
                "fields":fields, "target":"authoritative_batch_phase"}
            outer = {"timestamp":f"2243-08-25T12:00:0{number}.500001Z",
                "fields":{"message":"reload generation phase timing",
                    "target":"reload_generation_phase", "total_targets":320, "cohort_targets":320,
                    "remainder_targets":0, "refresh_count":0, "outcome":"committed",
                    "authoritative_fallback":True, "preflight_us":10, "cohort_selection_us":10,
                    "cohort_prestage_session_apply_us":10, "cohort_rib_transition_us":10 if number == 1 else 310,
                    "authoritative_remainder_apply_us":10, "deferred_refresh_dispatch_us":10,
                    "convergence_check_us":10, "unattributed_us":30,
                    "total_us":100 if number == 1 else 400}}
            return json.dumps(inner) + "\n" + json.dumps(outer) + "\n"
        daemon_log.write_text("".join(discriminator_lines(number) for number in range(1, 5)))
        validate_authoritative_discriminator(daemon_log, reload_log, output)
        original = daemon_log.read_text()
        assert {row["causal_phase"] for row in csv.DictReader(output.open())} == {"member_emit_state_us"}
        daemon_log.write_text(original.replace('"filtered_scope_member_visits": 6400', '"filtered_scope_member_visits": 3200'))
        validate_authoritative_discriminator(daemon_log, reload_log, output)
        assert {row["causal_phase"] for row in csv.DictReader(output.open())} == {""}
        daemon_log.write_text(original)
        lines = original.splitlines()
        mutations = ["\n".join(lines[2:]) + "\n", original + lines[-2] + "\n",
            "[]\n" + original, "1\n" + original, "null\n" + original,
            original.replace('"target": "authoritative_batch_phase"', '"target": "wrong"', 1),
            original.replace('"input_peers": 320', '"input_peers": true', 1),
            original.replace('"failure_stage": "none"', '"failure_stage": []', 1),
            original.replace('"shared_members": 320', '"shared_members": 319', 1),
            original.replace('"remainder_us": 1', '"remainder_us": 2', 1),
            original.replace('"total_us": 100', '"total_us": 0', 1),
            original.replace('"total_us": 100', '"total_us": -1', 1),
            original.replace(".000001Z", ".900001Z", 1),
            original.replace("12:00:02.000001Z", "12:00:01.000001Z", 1),
            original.replace("12:00:02.000001Z", "12:00:00.900001Z", 1),
            original.replace("12:00:02.500001Z", "12:00:01.500001Z", 1),
            original.replace("12:00:02.500001Z", "12:00:00.500001Z", 1),
            "\n".join([lines[0], *lines[2:]]) + "\n"]
        for mutation, broken in enumerate(mutations):
            daemon_log.write_text(broken)
            try: validate_authoritative_discriminator(daemon_log, reload_log, output)
            except InvalidReceipt: pass
            else: fail(f"discriminator self-test accepted mutation {mutation}")
        daemon_log.write_text(original)
        canonical_reload = reload_log.read_text()
        for changed in (canonical_reload.replace("8635464002000000", "8635464001000000"),
            canonical_reload.replace("8635464002000000", "8635464000500000")):
            reload_log.write_text(changed)
            try: validate_authoritative_discriminator(daemon_log, reload_log, output)
            except InvalidReceipt: pass
            else: fail("discriminator self-test accepted non-strict trigger timestamps")

        roots = [root / "pair-a", root / "pair-b"]
        canonical_triggers = "".join(f"reload {n} SIGHUP wall_us={8635464000000000+n*1000000} policy=x\n" for n in range(1, 5))
        for index, pair_root in enumerate(roots):
            make_fixture(pair_root, "sighup", 100 + index * 100, 900 + index)
            cdir = pair_root / "rustbgpd-sighup"
            cdir.joinpath("reloadstall.log").write_text(cdir.joinpath("reloadstall.log").read_text() + canonical_triggers)
            cdir.joinpath("daemon.log").write_text("".join(discriminator_lines(n) for n in range(1, 5)))
            validate_authoritative_discriminator(cdir / "daemon.log", cdir / "reloadstall.log", cdir / "authoritative-phase-timings.csv")
            validate_reload_phases(cdir / "daemon.log", cdir / "reloadstall.log", cdir / "phase-timings.csv")
        validate_authoritative_pair(roots, output)
        if read_json(output)["verdict"] != "mechanism_witness": fail("pair fixture missed witness")
        print("red-proof authoritative-pair-positive=pass")
        for name, old, new in (("threshold", '"total_us": 400', '"total_us": 110'),
            ("witness", '"filtered_scope_member_visits": 6400', '"filtered_scope_member_visits": 6500')):
            copied = root / f"pair-{name}"; shutil.copytree(roots[1], copied); cdir = copied / "rustbgpd-sighup"
            cdir.joinpath("daemon.log").write_text(cdir.joinpath("daemon.log").read_text().replace(old, new))
            if name == "threshold": cdir.joinpath("daemon.log").write_text(cdir.joinpath("daemon.log").read_text().replace('"cohort_rib_transition_us": 310', '"cohort_rib_transition_us": 20'))
            validate_authoritative_discriminator(cdir / "daemon.log", cdir / "reloadstall.log", cdir / "authoritative-phase-timings.csv")
            validate_reload_phases(cdir / "daemon.log", cdir / "reloadstall.log", cdir / "phase-timings.csv")
            validate_authoritative_pair([roots[0], copied], output)
            if read_json(output)["verdict"] != "negative_result" or read_json(output)["phase"]:
                fail(f"pair fixture did not publish negative {name}")
            print(f"red-proof authoritative-pair-negative-{name}=pass")
        for name, mutate in (
            ("schema", lambda value: value.update(schema=2)),
            ("input", lambda value: value["inputs"].update(overlap_fraction="0.1"))):
            copied = root / f"pair-{name}"; shutil.copytree(roots[1], copied)
            value = read_json(copied / "provenance.json"); mutate(value); copied.joinpath("provenance.json").write_text(json.dumps(value))
            try: validate_authoritative_pair([roots[0], copied], output)
            except InvalidReceipt: pass
            else: fail(f"pair self-test accepted {name} mutation")
            print(f"red-proof authoritative-pair-{name}=pass")
        copied = root / "pair-csv"; shutil.copytree(roots[1], copied)
        path = copied / "rustbgpd-sighup/authoritative-phase-timings.csv"; path.write_text(path.read_text() + "x\n")
        for name, pair_roots in (("csv", [roots[0], copied]), ("reversal", roots[::-1])):
            try: validate_authoritative_pair(pair_roots, output)
            except InvalidReceipt: pass
            else: fail(f"pair self-test accepted {name} mutation")
            print(f"red-proof authoritative-pair-{name}=pass")
        for name, source in (("identity", roots[0]), ("chronology", roots[1])):
            copied = root / f"pair-{name}"; shutil.copytree(roots[1], copied)
            if name == "identity": shutil.copyfile(source / "rustbgpd-sighup/process.tsv", copied / "rustbgpd-sighup/process.tsv")
            else:
                value = read_json(copied / "provenance.json"); value["started_at_epoch_ns"] = 50
                copied.joinpath("provenance.json").write_text(json.dumps(value))
            try: validate_authoritative_pair([roots[0], copied], output)
            except InvalidReceipt: pass
            else: fail(f"pair self-test accepted {name} mutation")
            print(f"red-proof authoritative-pair-{name}=pass")

    proofs = {}
    with tempfile.TemporaryDirectory() as directory:
        base = Path(directory)

        v3_dir = base / "v3"
        v3_dir.mkdir(mode=0o700)
        v3_config, v3_raw = v3_dir / "config.toml", v3_dir / "commit-confirm-v3-prior.toml"
        v3_metadata = v3_dir / "commit-confirm-v3-metadata.json"; v3_locator = v3_dir / "config.toml.commit-confirm-locator.json"
        v3_config.write_text("candidate\n")
        v3_raw.write_text("prior\n")
        v3_raw.chmod(0o600)
        raw_stat = v3_raw.stat()
        raw_sha = sha256(v3_raw)
        manifest = {"toml_sha256": raw_sha, "rpol_units": [], "datasets": []}
        source_sha = inline_manifest_source_sha256(manifest, raw_sha)

        def wire_path(path: Path) -> dict:
            return {"encoding": "unix-bytes-hex", "value": os.fsencode(str(path.resolve(strict=True))).hex()}

        def write_canonical(path: Path, value: dict) -> None:
            path.write_bytes(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode() + b"\n")
            path.chmod(0o600)

        metadata_value = {
            "version": 3, "confirm_id": "fixture-confirm", "deadline_unix_seconds": 1234,
            "rollback_failed": False,
            "raw_name": {"encoding": "unix-bytes-hex", "value": b"commit-confirm-v3-prior.toml".hex()},
            "raw_length": raw_stat.st_size, "raw_sha256": raw_sha, "raw_source_sha256": source_sha,
            "raw_device": raw_stat.st_dev, "raw_inode": raw_stat.st_ino, "manifest": manifest,
        }
        write_canonical(v3_metadata, metadata_value)
        locator_value = {"version": 3, "confirm_id": "fixture-confirm",
                         "metadata_path": wire_path(v3_metadata), "config_target": wire_path(v3_config),
                         "prior_sha256": raw_sha, "prior_source_sha256": source_sha}
        write_canonical(v3_locator, locator_value)
        inspect_v3(v3_locator, v3_metadata, v3_raw, v3_config, "fixture-confirm")

        def inspect_rejected(name: str, mutate) -> None:
            copied = base / f"bad-{name}"
            shutil.copytree(v3_dir, copied)
            copied_raw, copied_metadata = copied / v3_raw.name, copied / v3_metadata.name
            copied_locator, copied_config = copied / v3_locator.name, copied / v3_config.name
            copied_stat = copied_raw.stat()
            copied_metadata_value = read_json(copied_metadata)
            copied_metadata_value.update(raw_device=copied_stat.st_dev, raw_inode=copied_stat.st_ino)
            write_canonical(copied_metadata, copied_metadata_value)
            copied_locator_value = read_json(copied_locator)
            copied_locator_value.update(metadata_path=wire_path(copied_metadata), config_target=wire_path(copied_config))
            write_canonical(copied_locator, copied_locator_value)
            mutate(copied)
            try:
                inspect_v3(copied_locator, copied_metadata, copied_raw, copied_config, "fixture-confirm")
            except InvalidReceipt:
                proofs[name] = True
                return
            fail(f"red v3 inspector fixture unexpectedly accepted: {name}")

        def corrupt_metadata(copied: Path) -> None:
            value = read_json(copied / v3_metadata.name)
            value["raw_sha256"] = "f" * 64
            write_canonical(copied / v3_metadata.name, value)

        def corrupt_target(copied: Path) -> None:
            value = read_json(copied / v3_locator.name)
            value["config_target"] = {"encoding": "unix-bytes-hex", "value": b"/wrong/config.toml".hex()}
            write_canonical(copied / v3_locator.name, value)

        def corrupt_order(copied: Path) -> None:
            value = read_json(copied / v3_locator.name)
            write_canonical(copied / v3_locator.name, {
                "version": value["version"], "metadata_path": value["metadata_path"],
                "confirm_id": value["confirm_id"], "config_target": value["config_target"],
                "prior_sha256": value["prior_sha256"], "prior_source_sha256": value["prior_source_sha256"],
            })

        def corrupt_nested_order(copied: Path) -> None:
            value = read_json(copied / v3_locator.name); wire = value["metadata_path"]
            value["metadata_path"] = {"value": wire["value"], "encoding": wire["encoding"]}
            write_canonical(copied / v3_locator.name, value)

        def corrupt_raw_utf8(copied: Path) -> None:
            raw_path = copied / v3_raw.name; raw_path.write_bytes(b"prior\xff\n"); raw_path.chmod(0o600)
            raw_stat = raw_path.stat(); raw_sha = sha256(raw_path)
            metadata_path = copied / v3_metadata.name; value = read_json(metadata_path)
            value.update(raw_length=raw_stat.st_size, raw_sha256=raw_sha, raw_device=raw_stat.st_dev, raw_inode=raw_stat.st_ino)
            value["manifest"]["toml_sha256"] = raw_sha
            value["raw_source_sha256"] = inline_manifest_source_sha256(value["manifest"], raw_sha)
            write_canonical(metadata_path, value)
            locator_path = copied / v3_locator.name; locator = read_json(locator_path)
            locator.update(prior_sha256=raw_sha, prior_source_sha256=value["raw_source_sha256"])
            write_canonical(locator_path, locator)

        inspect_rejected("v3-inspector-linkage", corrupt_metadata)
        inspect_rejected("v3-inspector-mode", lambda copied: (copied / v3_raw.name).chmod(0o644))
        inspect_rejected("v3-inspector-target", corrupt_target)
        inspect_rejected("v3-inspector-field-order", corrupt_order)
        inspect_rejected("v3-inspector-nested-order", corrupt_nested_order)
        inspect_rejected("v3-inspector-raw-utf8", corrupt_raw_utf8)
        inspect_rejected(
            "v3-inspector-canonical",
            lambda copied: (copied / v3_locator.name).write_text(json.dumps(read_json(copied / v3_locator.name), indent=2) + "\n"),
        )

        topology_dir = base / "topology"
        topology_dir.mkdir()
        timestamps = topology_dir / "timestamps.tsv"
        timestamps.write_text(
            "phase\tepoch_ns\n"
            "scrape1\t1000000000\n"
            "scrape2\t2000000000\n"
            "scrape3\t3000000000\n"
        )

        def metric_text(bad: str | None = None) -> str:
            lines = [
                "bgp_rib_outbound_registered_peers 2",
                "bgp_rib_ingest_channel_depth 0",
                "bgp_rib_policy_transition_in_progress 0",
                f'bgp_rib_loc_prefixes{{afi_safi="all"}} {7 if bad == "route-gauge" else 8}',
            ]
            for peer in ("p0", "p1"):
                established_peer = (
                    "unexpected" if bad == "establishment-roster" and peer == "p1"
                    else peer
                )
                lines += [
                    f'bgp_peer_session_established{{interface="eth0",peer="{peer}"}} {0 if bad == "current-down" else 1}',
                    f'bgp_session_established_total{{peer="{established_peer}"}} {2 if bad == "reestablished" else 1}',
                    f'bgp_peer_outbound_queue_depth{{peer="{peer}"}} 0',
                ]
                if peer == "p0":
                    flap_peer = "unexpected" if bad == "flap-roster" else peer
                    lines.append(
                        f'bgp_session_flaps_total{{peer="{flap_peer}"}} '
                        f'{1 if bad == "flapped" else 0}'
                    )
                lines += [
                    f'bgp_rib_prefixes{{afi_safi="{family}",peer="{peer}"}} '
                    f'{4 if family == "all" else int(bad == "route-family" and peer == "p1")}'
                    for family in ("all", "flowspec")
                ]
                lines += [
                    f'bgp_rib_adj_out_prefixes{{afi_safi="{family}",peer="{peer}"}} '
                    f'{4 if family == "all" else 0}'
                    for family in ("all", "bgpls", "evpn", "flowspec", "labeled", "rtc", "vpn")
                ]
            if bad == "counter-malformed":
                lines.append('bgp_session_flaps_total{peer="p0"} broken')
            if bad == "preflip":
                # The pre-ADR-0126 private shape: no group, every
                # per-client-best peer on the per-peer fallback.
                lines += ["bgp_update_groups 0", "bgp_update_group_fallback_peers 2"]
                lines += [f'bgp_peer_update_group{{peer="p{index}"}} -1' for index in range(2)]
            else:
                group = 8 if bad == "drift" else 7
                lines += [f"bgp_update_groups {2 if bad == 'group' else 1}", "bgp_update_group_fallback_peers 0", f"bgp_update_group_runner_up_entries {1 if bad == 'lane' else 0}", f'bgp_update_group_members{{group="{group}"}} 2']
                lines += [f'bgp_peer_update_group{{peer="p{index}"}} {group}' for index in range(2)]
            return "\n".join(lines) + "\n"

        for mode in ("private", "grouped"):
            config = topology_dir / f"{mode}.toml"
            config.write_text("per_client_best = true\n" * (2 if mode == "private" else 0))
            paths = []
            for sample in range(1, 4):
                path = topology_dir / f"{mode}-{sample}.prom"
                path.write_text(metric_text())
                paths.append(path)
            validate_topology(mode, 2, 8, config, timestamps, paths, topology_dir / f"{mode}.json")
        def topology_rejected(name: str, bad: str, config: Path | None = None, mode: str = "grouped"):
            paths = []
            for sample in range(1, 4):
                path = topology_dir / f"{name}-{sample}.prom"
                if bad in {"drift", "current-down", "counter-malformed", "establishment-roster", "flap-roster"}:
                    effective_bad = bad if sample == 3 else None
                elif bad in {"reestablished", "flapped"}:
                    effective_bad = bad if sample > 1 else None
                else:
                    effective_bad = bad
                path.write_text(metric_text(effective_bad))
                paths.append(path)
            try:
                validate_topology(mode, 2, 8, config or topology_dir / f"{mode}.toml", timestamps, paths, topology_dir / f"{name}.json")
            except InvalidReceipt:
                proofs[name] = True

        topology_rejected("live-topology-gauge", "group")
        topology_rejected("preflip-private", "preflip", mode="private")
        topology_rejected("lane-gauge", "lane")
        topology_rejected("route-gauge", "route-gauge")
        topology_rejected("route-family", "route-family")
        topology_rejected("one-scrape-drift", "drift")
        topology_rejected("current-down", "current-down")
        topology_rejected("reestablished", "reestablished")
        topology_rejected("flapped", "flapped")
        topology_rejected("counter-malformed", "counter-malformed")
        topology_rejected("establishment-roster", "establishment-roster")
        topology_rejected("flap-roster", "flap-roster")
        add_path = topology_dir / "add-path.toml"
        add_path.write_text("[neighbors.add_path]\nsend = true\n")
        topology_rejected("add-path", "none", add_path)
        wrong_count = topology_dir / "wrong-count.toml"
        wrong_count.write_text("per_client_best = true\n")
        topology_rejected("config-count", "none", wrong_count)

        # --- Overlap topology (LAN-892): 2 members x 4 prefixes, prefix 0
        # gains member 1 as second announcer (fraction 1/8). ---
        overlap_dir = base / "overlap"
        overlap_dir.mkdir()
        addr = [member_addr(member) for member in range(2)]

        def overlap_manifest(name, fraction=0.125, pairs=((0, 1),)):
            path = overlap_dir / f"{name}.json"
            path.write_text(
                json.dumps(
                    {
                        "overlap_fraction": fraction,
                        "overlap_pairs": [list(pair) for pair in pairs],
                    }
                )
            )
            return path

        def overlap_metric_text(adj_in, adj_out, lane):
            lines = [
                "bgp_rib_outbound_registered_peers 2",
                "bgp_rib_ingest_channel_depth 0",
                "bgp_rib_policy_transition_in_progress 0",
                'bgp_rib_loc_prefixes{afi_safi="all"} 8',
            ]
            for member, peer in enumerate(addr):
                lines += [
                    f'bgp_peer_session_established{{interface="eth0",peer="{peer}"}} 1',
                    f'bgp_session_established_total{{peer="{peer}"}} 1',
                    f'bgp_peer_outbound_queue_depth{{peer="{peer}"}} 0',
                    f'bgp_rib_prefixes{{afi_safi="all",peer="{peer}"}} {adj_in[member]}',
                    f'bgp_rib_prefixes{{afi_safi="flowspec",peer="{peer}"}} 0',
                ]
                lines += [
                    f'bgp_rib_adj_out_prefixes{{afi_safi="{family}",peer="{peer}"}} '
                    f'{adj_out[member] if family == "all" else 0}'
                    for family in ("all", "bgpls", "evpn", "flowspec", "labeled", "rtc", "vpn")
                ]
            lines += [
                "bgp_update_groups 1",
                "bgp_update_group_fallback_peers 0",
                f"bgp_update_group_runner_up_entries {lane}",
                'bgp_update_group_members{group="7"} 2',
            ]
            lines += [f'bgp_peer_update_group{{peer="{peer}"}} 7' for peer in addr]
            return "\n".join(lines) + "\n"

        def overlap_topology(name, mode, adj_in, adj_out, manifest_path, lane=None):
            if lane is None:
                # ADR-0126 Decision 3: the lane holds one entry per
                # overlapped prefix in private mode, none in grouped.
                lane = 1 if mode == "private" else 0
            config = overlap_dir / f"{name}.toml"
            config.write_text("per_client_best = true\n" * (2 if mode == "private" else 0))
            paths = []
            for sample in range(1, 4):
                path = overlap_dir / f"{name}-{sample}.prom"
                path.write_text(overlap_metric_text(adj_in, adj_out, lane))
                paths.append(path)
            validate_topology(
                mode, 2, 8, config, timestamps, paths, overlap_dir / f"{name}.json", manifest_path
            )

        good_overlap = overlap_manifest("good")
        # Private: runner-up delivery leaves only exclusive announcements
        # suppressed. Grouped: member 0 wins the overlapped prefix.
        overlap_topology("private-green", "private", (4, 5), (5, 4), good_overlap)
        overlap_topology("grouped-green", "grouped", (4, 5), (4, 4), good_overlap)

        def overlap_rejected(name, mode, adj_in, adj_out, manifest_path, lane=None):
            try:
                overlap_topology(f"bad-{name}", mode, adj_in, adj_out, manifest_path, lane)
            except InvalidReceipt:
                proofs[name] = True
                return
            fail(f"red overlap fixture unexpectedly accepted: {name}")

        overlap_rejected(
            "overlap-fraction-mismatch", "private", (4, 5), (5, 4),
            overlap_manifest("fraction-mismatch", fraction=0.25),
        )
        overlap_rejected(
            "overlap-pair-own-slice", "private", (4, 5), (5, 4),
            overlap_manifest("own-slice", pairs=((0, 0),)),
        )
        overlap_rejected("overlap-achieved", "private", (4, 4), (5, 4), good_overlap)
        overlap_rejected("overlap-private-runner-up", "private", (4, 5), (4, 4), good_overlap)
        overlap_rejected("overlap-grouped-bounds", "grouped", (4, 5), (4, 5), good_overlap)
        overlap_rejected("overlap-grouped-sum", "grouped", (4, 5), (5, 4), good_overlap)
        overlap_rejected("overlap-lane-count", "private", (4, 5), (5, 4), good_overlap, lane=0)

        # --- Received-view delta (LAN-892) over the same tiny shape. ---
        def delta_cell(name, path_hiding, missing, dataset="d" * 64):
            cell = base / f"delta-{name}"
            cell.mkdir()
            (cell / "manifest.json").write_text(
                json.dumps(
                    {
                        "dataset_sha256": dataset,
                        "n_members": 2,
                        "total_prefixes": 8,
                        "seed": 61,
                        "path_hiding": path_hiding,
                        "overlap_fraction": 0.125,
                        "overlap_pairs": [[0, 1]],
                    }
                )
            )
            rows = ["received_view_v1\ttotal=8\tpeers=2"]
            for observer, indices in enumerate(missing):
                joined = ",".join(str(index) for index in sorted(indices))
                rows.append(f"{observer}\t{len(indices)}\t{joined}")
            (cell / "received-view.tsv").write_text("\n".join(rows) + "\n")
            return cell

        private_view = delta_cell("private", True, [{1, 2, 3}, {4, 5, 6, 7}])
        grouped_view = delta_cell("grouped", False, [{0, 1, 2, 3}, {4, 5, 6, 7}])
        result = received_view_delta(private_view, grouped_view)
        if result["suppressed_runner_up_pairs"] != 1 or result["status"] != "pass":
            fail("received-view delta green fixture did not pass")

        def delta_rejected(name, private_cell, grouped_cell):
            try:
                received_view_delta(private_cell, grouped_cell)
            except InvalidReceipt:
                proofs[name] = True
                return
            fail(f"red received-view fixture unexpectedly accepted: {name}")

        delta_rejected(
            "received-view-scenario",
            private_view,
            delta_cell("other-dataset", False, [{0, 1, 2, 3}, {4, 5, 6, 7}], dataset="e" * 64),
        )
        delta_rejected(
            "received-view-subset",
            delta_cell("private-undelivered", True, [{0, 1, 2, 3}, {4, 5, 6, 7}]),
            delta_cell("grouped-over", False, [{1, 2, 3}, {4, 5, 6, 7}]),
        )
        delta_rejected(
            "received-view-delta-count",
            delta_cell("private-count", True, [{1, 2, 3}, {4, 5, 6, 7}]),
            delta_cell("grouped-count", False, [{1, 2, 3}, {4, 5, 6, 7}]),
        )
        delta_rejected(
            "received-view-outside-allocation",
            delta_cell("private-outside", True, [{1, 2, 3}, {4, 5, 6, 7}]),
            delta_cell("grouped-outside", False, [{1, 2, 3}, {1, 4, 5, 6, 7}]),
        )
        names = ("comparison-a", "grouped-a", "grouped-b", "comparison-b")
        kinds = ("comparison", "grouped", "grouped", "comparison")
        roots = [base / name for name in names]
        for index, (root, kind) in enumerate(zip(roots, kinds, strict=True)):
            make_fixture(root, kind, 10 + index * 10, 1000 + index * 10)
        good_output = base / "good-output"
        validate_campaigns(roots, good_output)
        audit_combined(good_output / "comparison.csv", COMPARISON_CELLS)
        audit_combined(good_output / "grouped-control.csv", (GROUPED_CELL,))
        txn_roots = [base / "transaction-a", base / "transaction-b"]
        make_fixture(txn_roots[0], "transaction", 100, 2000)
        make_fixture(txn_roots[1], "transaction", 110, 3000)
        transaction_output = base / "transaction-output"
        validate_transactions(txn_roots, transaction_output)
        audit_combined(transaction_output / "transactions.csv", (TRANSACTION_CELL,))

        def mutate_cycle(root, index, function):
            path = root / TRANSACTION_CELL / "transactions/cycles.jsonl"
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            function(rows[index])
            path.write_text("".join(json.dumps(row) + "\n" for row in rows))

        def mutate_lifecycle(root, function):
            path = root / TRANSACTION_CELL / "transactions/lifecycle.json"
            value = read_json(path); function(value); path.write_text(json.dumps(value) + "\n")

        def txn_alter_json(path, function):
            value = read_json(path); function(value); path.write_text(json.dumps(value) + "\n")

        def txn_rejected(name, mutate, root_index=0):
            copied = base / f"bad-txn-{name}"
            shutil.copytree(txn_roots[root_index], copied); mutate(copied)
            pair = txn_roots.copy(); pair[root_index] = copied
            try:
                validate_transactions(pair, base / f"txn-output-{name}")
            except InvalidReceipt:
                proofs[name] = True
                return
            fail(f"red transaction fixture unexpectedly accepted: {name}")

        def txn_pair_rejected(name, mutate):
            pair = []
            for index, root in enumerate(txn_roots):
                copied = base / f"bad-txn-{name}-{index}"
                shutil.copytree(root, copied); mutate(copied); pair.append(copied)
            try:
                validate_transactions(pair, base / f"txn-output-{name}")
            except InvalidReceipt:
                proofs[name] = True; return
            fail(f"red transaction pair unexpectedly accepted: {name}")

        def mutate_candidate_b(root, digest):
            mutate_cycle(root, 0, lambda row: row["candidate"].update({"sha256": digest}))
            mutate_cycle(root, 2, lambda row: row["candidate"].update({"sha256": digest}))
            mutate_lifecycle(root, lambda value: value["generations"]["opposite"].update({"sha256": digest}))

        def swap_state_markers(state):
            for field in ("config", "runtime"):
                marker = state[field]["marker"]
                state[field]["marker"] = "65400:1000" if marker == "65400:2000" else "65400:2000"

        def swap_applied_markers(root):
            for index in range(4):
                mutate_cycle(root, index, lambda row: (swap_state_markers(row["pending"]), swap_state_markers(row["confirmed"])))
            def swap_lifecycle(value):
                for state in (value["baseline"], value["final_state"], value["abort"]["pending"], value["abort"]["terminal"], value["timeout"]["pending"], value["timeout"]["terminal"]):
                    swap_state_markers(state)
            mutate_lifecycle(root, swap_lifecycle)

        def swap_cycle_deadlines(row):
            public = row["apply"]["deadline_unix_seconds"]
            authority = row["pending"]["authority"]["deadline_unix_seconds"]
            row["apply"]["deadline_unix_seconds"] = authority
            row["pending"]["authority"]["deadline_unix_seconds"] = public

        txn_rejected("transaction-cycle-roster", lambda root: mutate_cycle(root, 0, lambda row: row.update({"cycle": 2})))
        txn_rejected("transaction-plan-token", lambda root: mutate_cycle(root, 0, lambda row: row["apply"].update({"explicit_plan_token": False})))
        txn_rejected("transaction-confirm", lambda root: mutate_cycle(root, 0, lambda row: row["confirmed"].update({"status": "pending"})))
        txn_rejected("transaction-v3-pending", lambda root: mutate_cycle(root, 0, lambda row: row["pending"]["authority"]["raw"].update({"bytes": 1024})))
        txn_rejected("transaction-v3-linkage", lambda root: mutate_cycle(root, 0, lambda row: row["pending"]["authority"].update({"linkage_verified": False})))
        txn_rejected("transaction-apply-deadline-missing", lambda root: mutate_cycle(root, 0, lambda row: row["apply"].pop("deadline_unix_seconds")))
        txn_rejected("transaction-apply-deadline-bool", lambda root: mutate_cycle(root, 0, lambda row: row["apply"].update({"deadline_unix_seconds": True})))
        txn_rejected("transaction-v3-deadline-missing", lambda root: mutate_cycle(root, 0, lambda row: row["pending"]["authority"].pop("deadline_unix_seconds")))
        txn_rejected("transaction-v3-deadline-bool", lambda root: mutate_cycle(root, 0, lambda row: row["pending"]["authority"].update({"deadline_unix_seconds": True})))
        txn_rejected("transaction-v3-deadline-stale", lambda root: mutate_cycle(root, 0, lambda row: row["pending"]["authority"].update({"deadline_unix_seconds": row["apply"]["deadline_unix_seconds"]})))
        txn_rejected("transaction-v3-deadline-swapped", lambda root: mutate_cycle(root, 0, swap_cycle_deadlines))
        txn_rejected("transaction-v3-deadline-tamper", lambda root: mutate_cycle(root, 0, lambda row: row["pending"]["authority"].update({"deadline_unix_seconds": 9999})))
        txn_rejected("transaction-schema-v1", lambda root: mutate_cycle(root, 0, lambda row: row.update({"schema": 1})))
        txn_rejected("transaction-lifecycle-schema-v1", lambda root: mutate_lifecycle(root, lambda value: value.update({"schema": 1})))
        txn_rejected("transaction-v3-cleanup", lambda root: mutate_cycle(root, 0, lambda row: row["confirmed"].update({"v3_absent": False})))
        txn_rejected("transaction-history", lambda root: mutate_cycle(root, 0, lambda row: row["history"]["after"]["entries"].append({"index": 0})))
        txn_rejected("transaction-abort", lambda root: mutate_lifecycle(root, lambda value: value["abort"]["terminal"].update({"status": "confirmed"})))
        txn_rejected("transaction-timeout", lambda root: mutate_lifecycle(root, lambda value: value["timeout"]["terminal"].update({"status": "auto_revert_failed"})))
        txn_rejected("transaction-noop", lambda root: mutate_lifecycle(root, lambda value: value["restored_current_plan"].update({"status": "committable"})))
        txn_rejected("transaction-opposite", lambda root: mutate_lifecycle(root, lambda value: value["generations"].update({"opposite": value["generations"]["current"]})))
        txn_rejected("transaction-token-leak", lambda root: mutate_cycle(root, 0, lambda row: row.update({"plan_token": "00000000-0000-4000-8000-000000000000"})))
        txn_rejected("transaction-warning-log", lambda root: (root / TRANSACTION_CELL / "daemon.log").write_text("missing warning\n"))
        txn_rejected("transaction-warning-binding", lambda root: mutate_cycle(root, 0, lambda row: row["history"]["warning"].update({"bytes": 12 * 1024 * 1024})))
        txn_pair_rejected("transaction-applied-generation", swap_applied_markers)
        txn_rejected("transaction-cross-root-generation", lambda root: mutate_candidate_b(root, "f" * 64), root_index=1)
        txn_rejected("transaction-port-gate", lambda root: (root / TRANSACTION_CELL / "quiet.tsv").write_text((root / TRANSACTION_CELL / "quiet.tsv").read_text().replace("true\ttrue", "false\ttrue", 1)))
        txn_rejected("transaction-disk-gate", lambda root: (root / TRANSACTION_CELL / "quiet.tsv").write_text((root / TRANSACTION_CELL / "quiet.tsv").read_text().replace("41943040", "41943039", 1)))
        txn_rejected("transaction-swap-gate", lambda root: (root / TRANSACTION_CELL / "quiet.tsv").write_text((root / TRANSACTION_CELL / "quiet.tsv").read_text().replace("2\t31\t0.5\t0\t0", "2\t31\t0.5\t1\t0")))
        txn_rejected("transaction-fallback-shape", lambda root: txn_alter_json(root / "provenance.json", lambda value: value["inputs"].update({"n_members": "10"})))

        def reuse_transaction_process(root):
            source = txn_roots[0] / TRANSACTION_CELL / "process.tsv"
            shutil.copyfile(source, root / TRANSACTION_CELL / "process.tsv")
            old, new = 3000, 2000
            for relative in ("transactions/cycles.jsonl", "transactions/lifecycle.json"):
                path = root / TRANSACTION_CELL / relative
                path.write_text(path.read_text().replace(f'"pid": {old}', f'"pid": {new}').replace(f'"starttime": {old + 100}', f'"starttime": {new + 100}'))
        txn_rejected("transaction-process-reuse", reuse_transaction_process, root_index=1)
        txn_rejected("transaction-file-tamper", lambda root: (root / TRANSACTION_CELL / "transactions/cycles.jsonl").write_text("tampered\n"))
        txn_rejected("transaction-file-roster", lambda root: (root / TRANSACTION_CELL / "unexpected").write_text("surplus\n"))

        def rejected(name, mutate):
            copied = base / f"bad-{name}"
            shutil.copytree(base / "comparison-a", copied)
            mutate(copied)
            bad_roots = [copied, roots[1], roots[2], roots[3]]
            try:
                validate_campaigns(bad_roots, base / f"output-{name}")
            except InvalidReceipt:
                proofs[name] = True
                return
            fail(f"red fixture unexpectedly accepted: {name}")

        def alter_json(path, function):
            data = read_json(path); function(data); path.write_text(json.dumps(data))
        rejected("default-roster", lambda root: alter_json(root / "provenance.json", lambda data: data["inputs"].update({"cells": "bird"})))
        rejected("mixed-roster", lambda root: alter_json(root / "provenance.json", lambda data: data["inputs"].update({"cells": f"{','.join(COMPARISON_CELLS)},{GROUPED_CELL}"})))
        rejected("mode-flags", lambda root: alter_json(root / "rustbgpd-sighup/manifest.json", lambda data: data.update({"path_hiding": False})))
        rejected("topology-mutation", lambda root: alter_json(root / "rustbgpd-sighup/topology.json", lambda data: data.update({"first_reload_wall_us": 2_000_000})))
        rejected("barrier-marker", lambda root: (root / "rustbgpd-sighup/pre-churn/ack").write_text("stale\n"))
        rejected("final-barrier-marker", lambda root: (root / "bird/final-evidence/ack").write_text("stale\n"))
        rejected("dirty-commit", lambda root: alter_json(root / "provenance.json", lambda data: data["git"].update({"dirty": True})))
        rejected("mismatched-commit", lambda root: alter_json(root / "provenance.json", lambda data: data["git"].update({"commit": "d" * 40})))
        rejected("commit-malformed", lambda root: alter_json(root / "provenance.json", lambda data: data["git"].update({"commit": "C" * 40})))
        def change_input(root, key, value):
            alter_json(root / "provenance.json", lambda data: data["inputs"].update({key: value}))
        rejected("canonical-changed-fraction", lambda root: change_input(root, "changed_fraction", "0.2"))
        rejected("canonical-control-secs", lambda root: change_input(root, "control_secs", "31"))
        rejected("canonical-bird-threads", lambda root: change_input(root, "bird_threads", "7"))
        rejected("repeat-image-identity", lambda root: change_input(root, "bird_image_id", "sha256:" + "b" * 64))
        def overlap_next_root(root):
            alter_json(root / "COMPLETED", lambda data: data.update({"completed_at_epoch_ns": 20}))
        rejected("nonoverlap-order", overlap_next_root)
        rejected("quiet-spacing", lambda root: (root / "bird/quiet.tsv").write_text("sample\tepoch_s\tload1\n1\t1\t0.5\n2\t2\t0.5\n"))
        rejected("preflight-raw", lambda root: (root / "preflight.log").write_text("[preflight] READY — all pre-flight checks passed\n"))
        rejected("cell-status", lambda root: (root / "bird/status").write_text("fail stale\n"))
        def break_manifest_changed_fraction(root):
            cdir = root / "bird"
            alter_json(cdir / "manifest.json", lambda data: data.update({"changed_fraction": 1.0}))
        rejected("manifest-changed-fraction", break_manifest_changed_fraction)
        def break_overlap_input_binding(root):
            # Internally valid manifest overlap (1 pair at the canonical
            # total) while the campaign inputs still declare overlap 0.
            cdir = root / "bird"
            alter_json(
                cdir / "manifest.json",
                lambda data: data.update(
                    {"overlap_fraction": 1 / 183040, "overlap_pairs": [[0, 1]]}
                ),
            )
        rejected("overlap-input-binding", break_overlap_input_binding)
        rejected("cell-root-rows", lambda root: (root / "bird/rows.csv").write_text((root / "bird/rows.csv").read_text().replace(",1,1,1,", ",2,1,1,", 1)))
        rejected("reload-log-rows", lambda root: (root / "bird/reloadstall.log").write_text("reloadstall_csv,missing\n"))
        def break_percentile(root, start, values):
            root_rows_path = root / "rows.csv"
            with root_rows_path.open(newline="") as stream:
                all_rows = list(csv.reader(stream))
            header, data = all_rows[0], all_rows[1:]
            target = next(row for row in data if row[0] == "bird")
            target[start : start + 3] = values
            with root_rows_path.open("w", newline="") as stream:
                writer = csv.writer(stream, lineterminator="\n")
                writer.writerow(header)
                writer.writerows(data)
            bird_rows = [row for row in data if row[0] == "bird"]
            with (root / "bird/rows.csv").open("w", newline="") as stream:
                csv.writer(stream, lineterminator="\n").writerows(bird_rows)
            (root / "bird/reloadstall.log").write_text(
                "".join(
                    "reloadstall_csv," + ",".join(row[1:]) + "\n"
                    for row in bird_rows
                )
            )
        rejected("percentile-order", lambda root: break_percentile(root, 6, ["3", "2", "1"]))
        rejected("percentile-positive", lambda root: break_percentile(root, 15, ["0", "1", "2"]))
        rejected("first-generation-bound", lambda root: break_percentile(root, 15, ["1001", "1001", "1001"]))
        rejected("observer-gap-bound", lambda root: break_percentile(root, 9, ["2", "2", "2"]))
        def break_row_invariant(root):
            for relative in ("rows.csv", "bird/rows.csv", "bird/reloadstall.log"):
                path = root / relative
                path.write_text(path.read_text().replace(",320,320,0,183040,", ",320,319,0,183040,", 1))
        rejected("row-invariants", break_row_invariant)
        def break_row_sessions(root):
            for relative in ("rows.csv", "bird/rows.csv", "bird/reloadstall.log"):
                path = root / relative
                lines = path.read_text().splitlines()
                path.write_text(
                    "\n".join(
                        line.rsplit(",320,0", 1)[0] + ",319,0"
                        if line.startswith(("bird,", "reloadstall_csv,"))
                        else line
                        for line in lines
                    )
                    + "\n"
                )
        rejected("row-session-loss", break_row_sessions)
        rejected("rss-raw", lambda root: (root / "bird/rss.csv").write_text("epoch_s,total_rss_kib,pids\n1,0,1\n"))
        comparison_campaigns = [validate_root(roots[0], "comparison"), validate_root(roots[3], "comparison")]
        escaped = [
            {**campaign, "rows": [row.copy() for row in campaign["rows"]]}
            for campaign in comparison_campaigns
        ]
        escaped[0]["rows"][0][0] = GROUPED_CELL
        original_audit = globals()["audit_combined"]
        globals()["audit_combined"] = lambda _path, _cells: None
        try:
            write_combined(base / "escaped-comparison.csv", escaped, COMPARISON_CELLS)
        except InvalidReceipt:
            proofs["grouped-output-isolation"] = True
        finally:
            globals()["audit_combined"] = original_audit
        corrupted_output = base / "corrupt-comparison.csv"
        shutil.copyfile(good_output / "comparison.csv", corrupted_output)
        corrupted_output.write_text(corrupted_output.read_text().replace("A,", "C,", 1))
        try:
            audit_combined(corrupted_output, COMPARISON_CELLS)
        except InvalidReceipt:
            proofs["output-exact-roster"] = True
        class AuditCalled(Exception):
            pass
        def audit_sentinel(_path, _cells):
            raise AuditCalled
        globals()["audit_combined"] = audit_sentinel
        try:
            write_combined(base / "audit-call.csv", comparison_campaigns, COMPARISON_CELLS)
        except AuditCalled:
            proofs["output-audit-call"] = True
        finally:
            globals()["audit_combined"] = original_audit
        # Separate roots cover ordering and cross-root identity reuse.
        reordered = [roots[0], roots[2], roots[1], roots[3]]
        try:
            validate_campaigns(reordered, base / "output-ordering")
        except InvalidReceipt:
            proofs["ordering"] = True
        reused = base / "reused"
        shutil.copytree(roots[1], reused)
        shutil.copyfile(roots[2] / "rustbgpd-sighup-grouped-control/process.tsv", reused / "rustbgpd-sighup-grouped-control/process.tsv")
        try:
            validate_campaigns([roots[0], reused, roots[2], roots[3]], base / "output-reused")
        except InvalidReceipt:
            proofs["reused-identity"] = True
        def grouped_pair_drift(name, section, key, value):
            changed = []
            for suffix, source in zip(("a", "b"), roots[1:3], strict=True):
                copied = base / f"bad-{name}-{suffix}"
                shutil.copytree(source, copied)
                alter_json(
                    copied / "provenance.json",
                    lambda data: data[section].update({key: value}),
                )
                changed.append(copied)
            try:
                validate_campaigns(
                    [roots[0], *changed, roots[3]], base / f"output-{name}"
                )
            except InvalidReceipt:
                proofs[name] = True
        grouped_pair_drift("cross-role-environment", "environment", "cpu_model", "other-platform")
        expected = {"default-roster", "mixed-roster", "mode-flags", "topology-mutation", "barrier-marker", "final-barrier-marker", "live-topology-gauge", "route-gauge", "route-family", "one-scrape-drift", "add-path", "config-count", "dirty-commit", "mismatched-commit", "commit-malformed", "canonical-changed-fraction", "canonical-control-secs", "canonical-bird-threads", "repeat-image-identity", "nonoverlap-order", "quiet-spacing", "preflight-raw", "cell-status", "manifest-changed-fraction", "cell-root-rows", "reload-log-rows", "percentile-order", "percentile-positive", "first-generation-bound", "observer-gap-bound", "row-invariants", "rss-raw", "grouped-output-isolation", "output-exact-roster", "output-audit-call", "ordering", "reused-identity", "cross-role-environment"}
        expected |= {"current-down", "reestablished", "flapped", "counter-malformed", "establishment-roster", "flap-roster", "row-session-loss"}
        expected |= {"preflip-private", "lane-gauge"}
        expected |= set(
            """overlap-fraction-mismatch overlap-pair-own-slice overlap-achieved
            overlap-private-runner-up overlap-grouped-bounds overlap-grouped-sum
            overlap-lane-count overlap-input-binding received-view-scenario
            received-view-subset received-view-delta-count
            received-view-outside-allocation""".split()
        )
        expected |= set("""v3-inspector-linkage v3-inspector-mode v3-inspector-target v3-inspector-canonical v3-inspector-field-order v3-inspector-nested-order v3-inspector-raw-utf8 transaction-cycle-roster transaction-plan-token transaction-confirm transaction-v3-pending transaction-v3-linkage transaction-apply-deadline-missing transaction-apply-deadline-bool transaction-v3-deadline-missing transaction-v3-deadline-bool transaction-v3-deadline-stale transaction-v3-deadline-swapped transaction-v3-deadline-tamper transaction-schema-v1 transaction-lifecycle-schema-v1 transaction-v3-cleanup transaction-history transaction-abort transaction-timeout transaction-noop transaction-opposite
transaction-token-leak transaction-warning-log transaction-warning-binding transaction-applied-generation transaction-cross-root-generation transaction-port-gate transaction-disk-gate transaction-swap-gate transaction-fallback-shape
transaction-process-reuse transaction-file-tamper transaction-file-roster""".split())
        missing = expected - proofs.keys()
        if missing:
            fail(f"self-test proofs did not reject: {sorted(missing)}")
        publication = Path(__file__).resolve().parents[3] / "docs/perf/artifacts/reload-authoritative-batch-discriminator-2026-08"
        validate_authoritative_publication(publication)
        def publication_rejected(name, mutate):
            copied = base / f"publication-{name}"; shutil.copytree(publication, copied); mutate(copied)
            try: validate_authoritative_publication(copied)
            except InvalidReceipt: print(f"red-proof authoritative-publication-{name}=pass")
            else: fail(f"publication self-test accepted {name}")
        publication_rejected("missing", lambda root: root.joinpath("authoritative-pair.json").unlink())
        publication_rejected("extra", lambda root: root.joinpath("extra").write_text("x"))
        publication_rejected("ordering", lambda root: root.joinpath("authoritative-batch-phases.csv").write_text("\n".join([root.joinpath("authoritative-batch-phases.csv").read_text().splitlines()[0], *reversed(root.joinpath("authoritative-batch-phases.csv").read_text().splitlines()[1:])]) + "\n"))
        def alter_pair(root, mutate):
            path = root / "authoritative-pair.json"; document = read_json(path); mutate(document); path.write_text(json.dumps(document))
        def promote_pair_witness(root):
            alter_pair(root, lambda document: document.update({
                "verdict": "mechanism_witness", "phase": "member_emit_state_us",
                "counter": "emits_attempted",
            }))
        def alter_publication_csv(root, row_index, key, value):
            path = root / "authoritative-batch-phases.csv"
            with path.open(newline="") as stream:
                reader = csv.DictReader(stream); fieldnames, rows = reader.fieldnames, list(reader)
            rows[row_index][key] = value
            with path.open("w", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=fieldnames); writer.writeheader(); writer.writerows(rows)
        def append_publication_csv_value(root):
            path = root / "authoritative-batch-phases.csv"; lines = path.read_text().splitlines()
            lines[1] += ",extra"; path.write_text("\n".join(lines) + "\n")
        def alter_publication_attribution(root, totals=None, registrations=None):
            pair_path = root / "authoritative-pair.json"
            csv_path = root / "authoritative-batch-phases.csv"
            pair = read_json(pair_path)
            if totals is not None:
                pair["roots"]["A"]["totals_us"] = totals; pair_path.write_text(json.dumps(pair))
            if registrations is not None:
                with csv_path.open(newline="") as stream:
                    old_rows = list(csv.DictReader(stream))
                for index, value in enumerate(registrations):
                    old_registration, old_remainder = (int(old_rows[index][key]) for key in ("registration_membership_us", "remainder_us"))
                    alter_publication_csv(root, index, "registration_membership_us", str(value))
                    alter_publication_csv(root, index, "remainder_us", str(old_remainder + old_registration - value))
        publication_rejected("source-id", lambda root: alter_pair(root, lambda pair: pair.update({"commit": "C" * 40})))
        publication_rejected("csv-arithmetic", lambda root: alter_publication_csv(root, 0, "total_us", "1"))
        publication_rejected("csv-chronology", lambda root: alter_publication_csv(root, 1, "timestamp_epoch_us", "1787669377204703"))
        publication_rejected("csv-extra-value", append_publication_csv_value)
        publication_rejected("clean-state", lambda root: alter_publication_csv(root, 0, "dirty_before", "1"))
        publication_rejected("outcome", lambda root: alter_publication_csv(root, 0, "outcome", "failed"))
        publication_rejected("sub-20-growth", lambda root: alter_publication_attribution(root, totals=[100, 110, 110, 110]))
        publication_rejected("sub-70-attribution", lambda root: alter_publication_attribution(root, registrations=[1294, 1300, 1300, 1300]))
        publication_rejected("pair-witness", promote_pair_witness)
        publication_rejected("negative-witness", lambda root: alter_pair(root, lambda pair: pair["roots"]["A"].update({"phase_us": [1, 2, 2, 2], "owned_counts": [1, 2, 2, 2]})))
        publication_rejected("retained-direction", lambda root: alter_publication_csv(root, 0, "causal_phase", "member_emit_state_us"))
        for name in sorted(expected):
            print(f"red-proof {name}=pass")
        print("SELF_TEST pass")


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    topology = subparsers.add_parser("topology")
    topology.add_argument("--mode", choices=("private", "grouped"), required=True)
    topology.add_argument("--peers", type=int, required=True)
    topology.add_argument("--total", type=int, required=True)
    topology.add_argument("--config", type=Path, required=True)
    topology.add_argument("--timestamps", type=Path, required=True)
    topology.add_argument("--output", type=Path, required=True)
    topology.add_argument(
        "--manifest",
        type=Path,
        help="scenario manifest carrying the overlap allocation (absent = disjoint)",
    )
    topology.add_argument("metrics", nargs=3, type=Path)
    delta_parser = subparsers.add_parser("received-view-delta")
    delta_parser.add_argument("--private-cell", required=True, type=Path)
    delta_parser.add_argument("--grouped-cell", required=True, type=Path)
    delta_parser.add_argument("--output", type=Path)
    campaigns = subparsers.add_parser("campaigns")
    campaigns.add_argument("--output-dir", required=True, type=Path)
    campaigns.add_argument("roots", nargs=4, type=Path)
    transactions = subparsers.add_parser("transactions")
    transactions.add_argument("--output-dir", required=True, type=Path)
    transactions.add_argument("roots", nargs=2, type=Path)
    inspect = subparsers.add_parser("inspect-v3")
    inspect.add_argument("--locator", required=True, type=Path)
    inspect.add_argument("--metadata", required=True, type=Path)
    inspect.add_argument("--raw", required=True, type=Path)
    inspect.add_argument("--config", required=True, type=Path)
    inspect.add_argument("--confirm-id", required=True)
    marker = subparsers.add_parser("inspect-generation")
    marker.add_argument("config", type=Path)
    phases = subparsers.add_parser("reload-phases")
    phases.add_argument("--daemon-log", required=True, type=Path)
    phases.add_argument("--reload-log", required=True, type=Path)
    phases.add_argument("--output", required=True, type=Path)
    dataset_refresh = subparsers.add_parser("dataset-refresh")
    dataset_refresh.add_argument("--daemon-log", required=True, type=Path)
    dataset_refresh.add_argument("--reload-log", required=True, type=Path)
    dataset_refresh.add_argument("--manifest", required=True, type=Path)
    dataset_refresh.add_argument("--output", required=True, type=Path)
    discriminator = subparsers.add_parser("authoritative-discriminator")
    discriminator.add_argument("--daemon-log", required=True, type=Path)
    discriminator.add_argument("--reload-log", required=True, type=Path)
    discriminator.add_argument("--output", required=True, type=Path)
    pair = subparsers.add_parser("authoritative-pair")
    pair.add_argument("--output", required=True, type=Path)
    pair.add_argument("roots", nargs=2, type=Path)
    publication = subparsers.add_parser("authoritative-publication")
    publication.add_argument("--artifact-dir", required=True, type=Path)
    subparsers.add_parser("self-test")
    args = parser.parse_args()
    try:
        if args.command == "topology":
            validate_topology(args.mode, args.peers, args.total, args.config, args.timestamps, args.metrics, args.output, args.manifest)
        elif args.command == "received-view-delta":
            result = received_view_delta(args.private_cell, args.grouped_cell)
            if args.output is not None:
                args.output.write_text(json.dumps(result, sort_keys=True) + "\n")
            print(json.dumps(result, sort_keys=True))
        elif args.command == "campaigns":
            validate_campaigns(args.roots, args.output_dir)
        elif args.command == "transactions":
            validate_transactions(args.roots, args.output_dir)
        elif args.command == "inspect-v3":
            print(
                json.dumps(
                    inspect_v3(
                        args.locator,
                        args.metadata,
                        args.raw,
                        args.config,
                        args.confirm_id,
                    ),
                    separators=(",", ":"),
                    sort_keys=True,
                )
            )
        elif args.command == "inspect-generation":
            print(generation_marker(args.config))
        elif args.command == "reload-phases":
            validate_reload_phases(args.daemon_log, args.reload_log, args.output)
        elif args.command == "dataset-refresh":
            validate_dataset_refresh(args.daemon_log, args.reload_log, args.manifest, args.output)
        elif args.command == "authoritative-discriminator":
            validate_authoritative_discriminator(args.daemon_log, args.reload_log, args.output)
        elif args.command == "authoritative-pair":
            validate_authoritative_pair(args.roots, args.output)
        elif args.command == "authoritative-publication":
            validate_authoritative_publication(args.artifact_dir)
        else:
            self_test()
    except (InvalidReceipt, OSError, KeyError, TypeError, ValueError) as error:
        print(f"receipt invalid: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
