#!/usr/bin/env python3
"""Fail-closed classifier for fixed rrtransport rr1000 receipts."""

import csv
import hashlib
import json
import pathlib
import sys

PEERS = 1000
PREFIXES = 100_000
SOURCES = 4
WORKERS = 12
TOTAL_NLRI = PEERS * PREFIXES
RSS_LIMIT_KIB = 2 * 1024 * 1024
SHAPE = (
    "rr1000-v1:peers=1000;prefixes=100000;sources=4;workers=12;"
    "afi=ipv4-unicast;role=ibgp-rr"
)
SHAPE_DIGEST = hashlib.sha256(SHAPE.encode()).hexdigest()[:16]
BITMAP_DIGEST = "7c50a897bc4a4e51"


def fail(message):
    raise ValueError(message)


def load(path):
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def write_rss(directory, sampler_max):
    directory = pathlib.Path(directory)
    phase = load(directory / "phase.json")
    checkpoints = phase.get("resource_observer")
    if phase.get("resource_observer_schema") != 1 or not isinstance(checkpoints, dict):
        fail("phase resource observer is missing or invalid")
    with (directory / "rss.tsv").open("r+", encoding="utf-8") as stream:
        if stream.readline() != "observer\trss_kib\n":
            fail("RSS TSV is missing its observer header")
        stream.seek(0, 2)
        for name in ("established", "staged", "wire"):
            stream.write(
                f"direct_pid_{name}_vmrss\t{checkpoints[name]['direct_pid_vmrss_kib']}\n"
            )
    (directory / "rss.json").write_text(
        json.dumps({"schema": 2, "checkpoints": checkpoints,
                    "process_tree_sampler_max_rss_kib": int(sampler_max)}) + "\n",
        encoding="utf-8",
    )


def verify(directory, tiny=False):
    directory = pathlib.Path(directory)
    peers = 4 if tiny else PEERS
    prefixes = 100 if tiny else PREFIXES
    shape = SHAPE.replace("rr1000-v1:peers=1000;prefixes=100000", "rrtiny-v1:peers=4;prefixes=100") if tiny else SHAPE
    shape_digest = hashlib.sha256(shape.encode()).hexdigest()[:16]
    bitmap_digest = "d4e22dcde16f2746" if tiny else BITMAP_DIGEST
    required = {
        "phase.json",
        "grouped-commit.json",
        "per-peer.tsv",
        "rss.tsv",
        "rss.json",
        "provenance.json",
        "verifier.txt",
    }
    missing = sorted(name for name in required if not (directory / name).is_file())
    if missing:
        fail(f"missing evidence: {', '.join(missing)}")

    phase = load(directory / "phase.json")
    expected_phase = {
        "schema": 2,
        "shape": shape,
        "shape_digest": shape_digest,
        "sessions": peers,
        "established_before": peers,
        "established_after": peers,
        "prefixes": prefixes,
        "sources": SOURCES,
        "workers": WORKERS,
        "groups": 1,
        "initial_eors": peers,
        "wire_completion": "first_exact_bitmap",
    }
    for key, expected in expected_phase.items():
        if phase.get(key) != expected:
            fail(f"phase {key}: expected {expected!r}, got {phase.get(key)!r}")
    for key in ("injection_ms", "staged_ms", "wire_ms"):
        if not isinstance(phase.get(key), int) or phase[key] < 0:
            fail(f"phase {key} is missing or invalid")
    if phase["injection_ms"] > min(phase["staged_ms"], phase["wire_ms"]):
        fail("injection completion follows a convergence timestamp")

    grouped = load(directory / "grouped-commit.json")
    expected_grouped = {
        "schema": 2,
        "timing": "test_profile_untimed_rpol_community_transition",
        "fixture_peers": peers,
        "fixture_prefixes": prefixes,
        "seed": {
            "routes_received_dispatches": 1,
            "routes_received_withdrawals": 0,
            "envelopes": peers,
            "routes_per_envelope": prefixes,
            "shared_group_encode": False,
            "community": "65000:100",
        },
        "transition": {
            "fast_path": True,
            "routes_received_dispatches": 0,
            "routes_received_withdrawals": 0,
            "probe_accounting": "policy_transition_receipt",
            "plan_builds": 1,
            "full_exact_probes": prefixes,
            "route_shell_materializations": prefixes,
            "authoritative_peer_applies": 0,
            "envelopes": peers,
            "routes_per_envelope": prefixes,
            "shared_encode_proof": "collected",
            "snapshot_classification": "concrete_transport_session",
            "snapshot_owner_nonzero": True,
            "snapshot_generation": 0,
            "snapshot_max_message_len": 4096,
            "snapshot_add_path": False,
            "shared_group_encode_classification": "one_arc_all_members",
            "shared_announce_classification": "one_arc_all_members",
            "shared_route_count": prefixes,
            "community": "65000:200",
            "update_groups": 1,
            "grouped_peers": peers,
            "ungrouped_peers": 0,
            "dirty_peers": 0,
            "grouped_unicast_routes": prefixes,
            "private_unicast_routes": 0,
        },
    }
    for key, expected in expected_grouped.items():
        if grouped.get(key) != expected:
            fail(f"grouped commit {key}: expected {expected!r}, got {grouped.get(key)!r}")

    with (directory / "per-peer.tsv").open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream, delimiter="\t"))
    if len(rows) != peers or len({row["peer"] for row in rows}) != peers:
        fail(f"fleet cardinality is not exactly {peers}")
    expected_peers = {f"127.{2 + index // 254}.{1 + index % 254}.1" for index in range(peers)}
    if {row["peer"] for row in rows} != expected_peers:
        fail("peer addresses do not match the canonical fixed fleet")
    totals = {key: 0 for key in ("staged", "nlri", "withdrawals", "duplicates", "outside", "decode_failures", "coverage")}
    for row in rows:
        for key in totals:
            try:
                totals[key] += int(row[key])
            except (KeyError, ValueError) as error:
                fail(f"invalid per-peer {key}: {error}")
        if int(row["staged"]) != prefixes or int(row["nlri"]) != prefixes:
            fail(f"peer {row['peer']} lacks exact staged/wire coverage")
        if int(row["messages"]) <= 0:
            fail(f"peer {row['peer']} has no decoded UPDATE messages")
        if int(row["coverage"]) != prefixes or row["initial_eor"] != "true":
            fail(f"peer {row['peer']} lacks bitmap coverage or initial EoR")
        if row["bitmap_digest"] != bitmap_digest:
            fail(f"peer {row['peer']} has wrong expected-set bitmap digest")
        if int(row["wire_ms"]) < 0:
            fail(f"peer {row['peer']} has a negative wire time")
    if max(int(row["wire_ms"]) for row in rows) != phase["wire_ms"]:
        fail("aggregate wire time is not the exact per-peer maximum")
    if totals["staged"] != peers * prefixes or totals["nlri"] != peers * prefixes:
        fail("100,000,000 staged/wire NLRI contract failed")
    for key in ("withdrawals", "duplicates", "outside", "decode_failures"):
        if totals[key] != 0:
            fail(f"{key} must be zero, got {totals[key]}")

    observer = phase.get("resource_observer")
    if phase.get("resource_observer_schema") != 1 or not isinstance(observer, dict):
        fail("phase resource observer is missing or invalid")
    allocator_keys = (
        "jemalloc_allocated_bytes",
        "jemalloc_active_bytes",
        "jemalloc_resident_bytes",
        "jemalloc_mapped_bytes",
    )
    for name in ("established", "staged", "wire"):
        point = observer.get(name)
        if not isinstance(point, dict):
            fail(f"resource checkpoint {name} is missing or invalid")
        for key in ("direct_pid_vmrss_kib", "direct_pid_vmhwm_kib"):
            if type(point.get(key)) is not int or point[key] <= 0:
                fail(f"resource checkpoint {name}.{key} is missing or invalid")
            if point[key] > RSS_LIMIT_KIB:
                fail(f"RSS ceiling exceeded: {name}.{key}={point[key]} KiB")
        for key in allocator_keys:
            if type(point.get(key)) is not int or point[key] <= 0:
                fail(f"resource checkpoint {name}.{key} is missing or invalid")
        if point["jemalloc_allocated_bytes"] > point["jemalloc_active_bytes"]:
            fail(f"resource checkpoint {name} has allocated bytes above active bytes")
    rss = load(directory / "rss.json")
    if rss.get("schema") != 2 or rss.get("checkpoints") != observer:
        fail("phase and RSS JSON resource checkpoints disagree")
    sampler_max = rss.get("process_tree_sampler_max_rss_kib")
    if type(sampler_max) is not int or sampler_max <= 0:
        fail("process-tree RSS maximum is missing or invalid")
    if sampler_max > RSS_LIMIT_KIB:
        fail(f"RSS ceiling exceeded: process_tree_sampler_max_rss_kib={sampler_max} KiB")
    hwms = [observer[name]["direct_pid_vmhwm_kib"] for name in ("established", "staged", "wire")]
    values = [observer[name]["direct_pid_vmrss_kib"] for name in ("established", "staged", "wire")]
    if hwms != sorted(hwms) or any(hwm < value for hwm, value in zip(hwms, values)):
        fail("VmHWM is non-monotonic or below VmRSS")
    with (directory / "rss.tsv").open(encoding="utf-8") as stream:
        lines = stream.read().splitlines()
    if not lines or lines[0] != "observer\trss_kib":
        fail("RSS TSV is missing its observer header")
    samples = [line.split("\t") for line in lines[1:]]
    try:
        external = [
            int(value)
            for kind, value in samples
            if kind == "process_tree_target_rss_sample"
        ]
        checkpoints = {
            kind: int(value)
            for kind, value in samples
            if kind != "process_tree_target_rss_sample"
        }
    except (TypeError, ValueError) as error:
        fail(f"invalid RSS TSV value: {error}")
    if not external or max(external) != sampler_max:
        fail("process-tree RSS samples are absent or their maximum disagrees")
    expected_checkpoints = {
        f"direct_pid_{name}_vmrss": observer[name]["direct_pid_vmrss_kib"]
        for name in ("established", "staged", "wire")
    }
    if checkpoints != expected_checkpoints:
        fail("direct-PID RSS TSV checkpoints disagree")

    provenance = load(directory / "provenance.json")
    for key in ("head_before", "head_after", "tree_before", "tree_after", "source_sha256",
                "source_after_sha256", "binary_sha256", "governors", "load_before", "load_after"):
        if not provenance.get(key):
            fail(f"provenance {key} is missing")
    for key in ("pswpin_before", "pswpin_after", "pswpout_before", "pswpout_after"):
        if key not in provenance:
            fail(f"provenance {key} is missing")
    if not provenance.get("rustc") or not provenance.get("host") or provenance.get("competitors") != []:
        fail("toolchain, host, or empty competitor provenance is missing")
    if provenance["head_before"] != provenance["head_after"]:
        fail("HEAD changed during run")
    if provenance["tree_before"] != provenance["tree_after"]:
        fail("tree changed during run")
    if provenance["source_sha256"] != provenance["source_after_sha256"]:
        fail("declared source set changed during run")
    if provenance["governors"] != ["performance"]:
        fail("not all CPU governors were performance")
    if (provenance["pswpin_before"], provenance["pswpout_before"]) != (
            provenance["pswpin_after"], provenance["pswpout_after"]):
        fail("kernel swap I/O changed during run")
    source = directory / "source.snapshot"
    binary = directory / "rrtransport.bin"
    if hashlib.sha256(source.read_bytes()).hexdigest() != provenance["source_sha256"]:
        fail("source hash mismatch")
    if hashlib.sha256(binary.read_bytes()).hexdigest() != provenance["binary_sha256"]:
        fail("binary hash mismatch")


if __name__ == "__main__":
    try:
        if len(sys.argv) == 4 and sys.argv[2] == "--write-rss":
            write_rss(sys.argv[1], sys.argv[3])
            sys.exit()
        if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] not in ("--tiny", "--full")):
            fail("usage: verify_receipt.py RECEIPT [--tiny|--full] | RECEIPT --write-rss SAMPLER_MAX")
        verify(sys.argv[1], len(sys.argv) == 3 and sys.argv[2] == "--tiny")
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"FAIL: {error}")
        sys.exit(1)
    print("PASS: fixed rr1000 receipt is complete and exact")
