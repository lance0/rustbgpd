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


def verify(directory, tiny=False):
    directory = pathlib.Path(directory)
    peers = 4 if tiny else PEERS
    prefixes = 100 if tiny else PREFIXES
    shape = SHAPE.replace("rr1000-v1:peers=1000;prefixes=100000", "rrtiny-v1:peers=4;prefixes=100") if tiny else SHAPE
    shape_digest = hashlib.sha256(shape.encode()).hexdigest()[:16]
    bitmap_digest = "d4e22dcde16f2746" if tiny else BITMAP_DIGEST
    required = {
        "phase.json",
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
        "schema": 1,
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

    rss = load(directory / "rss.json")
    for key in ("established_kib", "staged_kib", "wire_kib", "established_vmhwm_kib",
                "staged_vmhwm_kib", "wire_vmhwm_kib", "sampler_max_kib"):
        if not isinstance(rss.get(key), int) or rss[key] <= 0:
            fail(f"RSS evidence {key} is missing or invalid")
        if rss[key] > RSS_LIMIT_KIB:
            fail(f"RSS ceiling exceeded: {key}={rss[key]} KiB")
    pairs = (
        ("established_kib", "established_rss_kib"),
        ("staged_kib", "staged_rss_kib"),
        ("wire_kib", "wire_rss_kib"),
        ("established_vmhwm_kib", "established_vmhwm_kib"),
        ("staged_vmhwm_kib", "staged_vmhwm_kib"),
        ("wire_vmhwm_kib", "wire_vmhwm_kib"),
    )
    if any(rss[left] != phase[right] for left, right in pairs):
        fail("phase and RSS JSON checkpoints disagree")
    hwms = [rss[key] for key in ("established_vmhwm_kib", "staged_vmhwm_kib", "wire_vmhwm_kib")]
    if hwms != sorted(hwms) or any(hwm < value for hwm, value in zip(hwms, (
        rss["established_kib"], rss["staged_kib"], rss["wire_kib"]))):
        fail("VmHWM is non-monotonic or below VmRSS")
    with (directory / "rss.tsv").open(encoding="utf-8") as stream:
        samples = [line.split("\t") for line in stream.read().splitlines()[1:]]
    external = [int(value) for kind, value in samples if kind == "sample"]
    checkpoints = {kind: int(value) for kind, value in samples if kind != "sample"}
    if not external or max(external) != rss["sampler_max_kib"]:
        fail("external RSS samples are absent or their maximum disagrees")
    if checkpoints != {name: rss[f"{name}_kib"] for name in ("established", "staged", "wire")}:
        fail("RSS TSV phase checkpoints disagree")

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
        if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] not in ("--tiny", "--full")):
            fail("usage: verify_receipt.py RECEIPT [--tiny|--full]")
        verify(sys.argv[1], len(sys.argv) == 3 and sys.argv[2] == "--tiny")
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"FAIL: {error}")
        sys.exit(1)
    print("PASS: fixed rr1000 receipt is complete and exact")
