#!/usr/bin/env python3
"""Fail-closed verifier for the v0.61.0 final performance receipt."""

from __future__ import annotations

import csv
import gzip
import hashlib
import json
import math
import re
import statistics
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parent
EXPECTED_COMMIT = "99ee74ba67ec24ce8e09c0c18a83b652da35712b"
EXPECTED_TREE = "c6ef0d7da50b8be28ff62b8edb749f0fae0bd21f"
EXPECTED_BASELINE = "v0.61.0-final-99ee74ba"
EXPECTED_PAIR_INVENTORY_SHA256 = (
    "d3f326d38aea4bc9c62cd6fb0690cd1ba4eb7ec760331aa08ca27a83546fdb47"
)
EXPECTED_RUNS = {
    "final-a-1000x400": 441.8,
    "final-b-1000x400": 441.2,
    "final-c-1000x400": 441.1,
}
RUN_FILES = {
    "binary-hashes.tsv",
    "exit-status.env",
    "host.txt",
    "preflight.tsv",
    "proc-status.txt",
    "provenance.env",
    "reloadstall-summary.txt",
    "rss.tsv.gz",
    "settled-gates.env",
    "settled-metrics.env",
    "settled-proc.env",
    "summary.env",
    "toolchain.txt",
}
GATE_VALUES = {
    "bgp_update_groups_samples": "1",
    "bgp_update_groups_sum": "1",
    "bgp_update_groups_max": "1",
    "bgp_update_group_members_samples": "1",
    "bgp_update_group_members_sum": "1000",
    "bgp_update_group_members_max": "1000",
    "bgp_update_group_fallback_peers_samples": "1",
    "bgp_update_group_fallback_peers_sum": "0",
    "bgp_update_group_fallback_peers_max": "0",
    "bgp_update_group_residue_entries_samples": "1",
    "bgp_update_group_residue_entries_sum": "0",
    "bgp_update_group_residue_entries_max": "0",
    "bgp_rib_outbound_registered_peers_samples": "1",
    "bgp_rib_outbound_registered_peers_sum": "1000",
    "bgp_rib_outbound_registered_peers_max": "1000",
    "bgp_rejected_routes_retained_samples": "1000",
    "bgp_rejected_routes_retained_sum": "0",
    "bgp_rejected_routes_retained_max": "0",
    "bgp_peer_outbound_queue_depth_samples": "1000",
    "bgp_peer_outbound_queue_depth_sum": "0",
    "bgp_peer_outbound_queue_depth_max": "0",
}
ALLOCATOR_FIELDS = (
    "jemalloc_allocated_bytes",
    "jemalloc_active_bytes",
    "jemalloc_resident_bytes",
    "jemalloc_mapped_bytes",
)
REQUIRED_ROWS = {
    "adj_rib_in_insert/10000",
    "rib_pipeline/1000",
    "update_build/1",
    "update_build/ipv6_mp_add_path",
    "update_parse_revised/1",
    "update_parse_revised/ipv6_mp_add_path",
    "policy_chain_eval/1",
    "policy_chain_eval_early_deny",
    "export_policy_eval/lazy_as_path_string",
}


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def read_env(path: Path) -> dict[str, str]:
    if not path.is_file():
        fail(f"missing {path.relative_to(ROOT)}")
    result: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            fail(f"{path.relative_to(ROOT)}: malformed line {line!r}")
        key, value = line.split("=", 1)
        if key in result:
            fail(f"{path.relative_to(ROOT)}: duplicate field {key}")
        result[key] = value.strip()
    return result


def require(env: dict[str, str], expected: dict[str, str], label: str) -> None:
    for key, value in expected.items():
        if env.get(key) != value:
            fail(f"{label}: {key} expected {value!r}, got {env.get(key)!r}")


def suite_for(benchmark: str) -> str:
    if benchmark.startswith(("nlri_", "update_", "attr_")) or benchmark == "validate_update":
        return "codec"
    if benchmark.startswith(
        (
            "policy_",
            "loop_eval/",
            "set_heavy/",
            "value_expr/",
            "fn_eval/",
            "dataset_parity/",
        )
    ):
        return "policy_eval"
    return "rib_ops"


def verify_manifest() -> dict[str, object]:
    manifest = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("schema") != 1:
        fail("manifest schema must be 1")
    source = manifest.get("source", {})
    if source != {"commit": EXPECTED_COMMIT, "tree": EXPECTED_TREE}:
        fail("manifest source revision mismatch")
    route = manifest.get("route_server", {})
    if set(route.get("run_ids", [])) != set(EXPECTED_RUNS):
        fail("manifest accepted route-run inventory mismatch")
    if route.get("steady_rss_mib") != list(EXPECTED_RUNS.values()):
        fail("manifest RSS inventory mismatch")
    criterion = manifest.get("criterion", {})
    if criterion.get("baseline") != EXPECTED_BASELINE:
        fail("manifest Criterion baseline mismatch")
    if criterion.get("row_count") != 71:
        fail("manifest Criterion row count mismatch")
    inventory = criterion.get("row_inventory", [])
    if (
        not isinstance(inventory, list)
        or len(inventory) != 71
        or any(not isinstance(row, str) for row in inventory)
        or len(set(inventory)) != 71
    ):
        fail("manifest Criterion row inventory must contain 71 unique names")
    encoded = "".join(f"{suite_for(row)}\t{row}\n" for row in inventory).encode()
    digest = hashlib.sha256(encoded).hexdigest()
    if digest != EXPECTED_PAIR_INVENTORY_SHA256:
        fail("manifest Criterion suite/benchmark inventory digest mismatch")
    if set(criterion.get("required_rows", [])) != REQUIRED_ROWS:
        fail("manifest required Criterion rows mismatch")
    rejected = manifest.get("rejected_criterion", {})
    if rejected != {
        "reason": "swap-in-pages-advanced",
        "pswpin_delta": 1377,
        "evidence_source": "orchestration-observation-not-retained-raw",
        "estimates_retained": False,
    }:
        fail("manifest rejected-attempt boundary mismatch")
    return manifest


def verify_preflight(path: Path) -> None:
    with path.open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream, delimiter="\t"))
    if len(rows) < 2:
        fail(f"{path.relative_to(ROOT)}: expected at least two admission rows")
    for row in rows:
        if row.get("governors") != "64/64":
            fail(f"{path.relative_to(ROOT)}: not all governors were admitted")
        if row.get("competitors") != "none":
            fail(f"{path.relative_to(ROOT)}: competing workload was admitted")
        if row.get("pswpin_delta") != "0" or row.get("pswpout_delta") != "0":
            fail(f"{path.relative_to(ROOT)}: swap I/O was admitted")
        if row.get("ports_free") != "1":
            fail(f"{path.relative_to(ROOT)}: occupied ports were admitted")


def verify_rss(path: Path, provenance: dict[str, str], summary: dict[str, str]) -> None:
    encoded = path.read_bytes()
    if encoded[:3] != b"\x1f\x8b\x08" or encoded[4:8] != b"\0\0\0\0":
        fail(f"{path.relative_to(ROOT)}: gzip header is not deterministic")
    if encoded[3] & 0x08:
        fail(f"{path.relative_to(ROOT)}: gzip header retains an input filename")
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream, delimiter="\t"))
    expected_samples = int(summary["rss_samples_total"])
    if len(rows) != expected_samples:
        fail(f"{path.relative_to(ROOT)}: expected {expected_samples} samples, got {len(rows)}")
    converged = float(provenance["converged_monotonic"])
    post = [
        int(row["tree_rss_kib"])
        for row in rows
        if float(row["monotonic_seconds"]) >= converged
    ]
    if len(post) != int(summary["rss_samples_post_convergence"]):
        fail(f"{path.relative_to(ROOT)}: post-convergence sample count mismatch")
    if statistics.median(post) != int(summary["steady_rss_kib_median_post_convergence"]):
        fail(f"{path.relative_to(ROOT)}: steady RSS median does not recompute")


def verify_proc_status(path: Path, settled: dict[str, str]) -> None:
    text = path.read_text(encoding="utf-8")
    for field in ("VmRSS", "VmHWM", "VmPeak", "VmSize"):
        found = re.findall(rf"^{field}:\s+([0-9]+)\s+kB$", text, re.MULTILINE)
        if len(found) != 1:
            fail(f"{path.relative_to(ROOT)}: expected one numeric {field}")
        key = f"settled_proc_{field.lower()}_kib"
        if settled.get(key) != found[0]:
            fail(f"{path.relative_to(ROOT)}: {field} disagrees with settled derivative")


def verify_route_runs() -> None:
    root = ROOT / "route-runs"
    found = {path.name for path in root.iterdir() if path.is_dir()}
    if found != set(EXPECTED_RUNS):
        fail(f"accepted route-run inventory mismatch: {sorted(found)}")
    reference_hashes: dict[str, str] | None = None
    for run_id, rss_mib in EXPECTED_RUNS.items():
        run = root / run_id
        files = {path.name for path in run.iterdir() if path.is_file()}
        if files != RUN_FILES:
            fail(f"{run_id}: retained file inventory mismatch")
        provenance = read_env(run / "provenance.env")
        require(
            provenance,
            {
                "commit": EXPECTED_COMMIT,
                "tree": EXPECTED_TREE,
                "peers": "1000",
                "routes_per_peer": "400",
                "total": "400000",
                "explain": "false",
                "dhat": "0",
                "profile": "release",
                "reloads": "0",
                "control_secs": "30",
                "expected_per_observer": "399600",
                "harness_rc": "0",
                "rss_sampler_rc": "0",
            },
            run_id,
        )
        require(
            read_env(run / "exit-status.env"),
            {"status": "success", "exit_status": "0"},
            run_id,
        )
        summary = read_env(run / "summary.env")
        if float(summary.get("steady_rss_mib_median_post_convergence", "nan")) != rss_mib:
            fail(f"{run_id}: steady RSS mismatch")
        metrics = read_env(run / "settled-metrics.env")
        for field in ALLOCATOR_FIELDS:
            try:
                value = int(metrics[field])
            except (KeyError, ValueError):
                fail(f"{run_id}: missing positive allocator gauge {field}")
            if value <= 0:
                fail(f"{run_id}: non-positive allocator gauge {field}")
            if summary.get(field) != str(value):
                fail(f"{run_id}: allocator gauge {field} disagrees with summary")
        require(read_env(run / "settled-gates.env"), GATE_VALUES, run_id)
        verify_proc_status(run / "proc-status.txt", read_env(run / "settled-proc.env"))
        verify_preflight(run / "preflight.tsv")
        verify_rss(run / "rss.tsv.gz", provenance, summary)
        hashes: dict[str, str] = {}
        for line in (run / "binary-hashes.tsv").read_text(encoding="utf-8").splitlines():
            try:
                digest, name = line.split("\t")
            except ValueError:
                fail(f"{run_id}: malformed binary hash row")
            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                fail(f"{run_id}: malformed binary hash for {name}")
            hashes[name] = digest
        if set(hashes) != {"rustbgpd", "reloadstall"}:
            fail(f"{run_id}: binary inventory mismatch")
        if reference_hashes is None:
            reference_hashes = hashes
        elif hashes != reference_hashes:
            fail(f"{run_id}: binary hashes differ across accepted runs")
        harness = (run / "reloadstall-summary.txt").read_text(encoding="utf-8")
        for pattern in (
            r"^established 1000 at ",
            r"^converged \(>= 399600/observer\) at ",
            r"^final sessions_up 1000/1000 parse_errors=0$",
        ):
            if not re.search(pattern, harness, re.MULTILINE):
                fail(f"{run_id}: harness summary missing {pattern!r}")


def verify_criterion(manifest: dict[str, object]) -> None:
    criterion = ROOT / "criterion"
    expected_files = {
        "accepted-receipt.env",
        "binary-hashes.tsv",
        "derive_criterion.py",
        "rejected-attempt.env",
        "results.tsv",
    }
    found_files = {path.name for path in criterion.iterdir() if path.is_file()}
    if found_files != expected_files:
        fail(f"Criterion retained file inventory mismatch: {sorted(found_files)}")
    receipt = read_env(criterion / "accepted-receipt.env")
    require(
        receipt,
        {
            "baseline": EXPECTED_BASELINE,
            "commit": EXPECTED_COMMIT,
            "tree": EXPECTED_TREE,
            "logical_cpu": "8",
            "status": "success",
        },
        "Criterion receipt",
    )
    for side in ("before", "after"):
        match = re.fullmatch(r"pswpin=(\d+) pswpout=(\d+)", receipt[f"swap_{side}"])
        if not match:
            fail(f"Criterion receipt: malformed swap_{side}")
    if receipt["swap_before"] != receipt["swap_after"]:
        fail("Criterion receipt: swap page counters changed")

    rejected = read_env(criterion / "rejected-attempt.env")
    require(
        rejected,
        {
            "status": "rejected",
            "reason": "swap-in-pages-advanced",
            "pswpin_delta": "1377",
            "evidence_source": "orchestration-observation-not-retained-raw",
            "estimates_retained": "false",
            "replacement": "accepted-receipt.env",
        },
        "rejected Criterion attempt",
    )
    if any("rejected" in path.name and path.name != "rejected-attempt.env" for path in criterion.iterdir()):
        fail("rejected Criterion estimates were mixed into the archive")

    with (criterion / "results.tsv").open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream, delimiter="\t"))
    if len(rows) != 71:
        fail(f"Criterion results: expected 71 rows, got {len(rows)}")
    identities = [row["benchmark"] for row in rows]
    if len(set(identities)) != 71:
        fail("Criterion results: benchmark identities are not unique")
    inventory = set(manifest["criterion"]["row_inventory"])  # type: ignore[index]
    if set(identities) != inventory:
        fail(
            "Criterion results: benchmark inventory mismatch: "
            f"missing={sorted(inventory - set(identities))} "
            f"unexpected={sorted(set(identities) - inventory)}"
        )
    missing = REQUIRED_ROWS - set(identities)
    if missing:
        fail(f"Criterion results: missing required rows {sorted(missing)}")
    suites = Counter(row["suite"] for row in rows)
    expected_suites = manifest["criterion"]["suite_rows"]  # type: ignore[index]
    if dict(suites) != expected_suites:
        fail(f"Criterion results: suite counts mismatch {dict(suites)}")
    for row in rows:
        if row["suite"] != suite_for(row["benchmark"]):
            fail(
                "Criterion results: suite mismatch for "
                f"{row['benchmark']}: expected {suite_for(row['benchmark'])!r}, "
                f"got {row['suite']!r}"
            )
        try:
            lower = float(row["median_lower_ns"])
            point = float(row["median_ns"])
            upper = float(row["median_upper_ns"])
            samples = int(row["sample_count"])
        except (KeyError, ValueError):
            fail(f"Criterion results: malformed row {row!r}")
        if not all(math.isfinite(value) and value > 0 for value in (lower, point, upper)):
            fail(f"Criterion results: non-positive or non-finite estimate for {row['benchmark']}")
        if not lower <= point <= upper:
            fail(f"Criterion results: invalid median interval for {row['benchmark']}")
        if samples not in (10, 100) or row["sampling_mode"] != "Linear":
            fail(f"Criterion results: unexpected sampling contract for {row['benchmark']}")

    hashes = (criterion / "binary-hashes.tsv").read_text(encoding="utf-8").splitlines()
    if len(hashes) != 3:
        fail("Criterion binary hash inventory must contain exactly three rows")
    names = set()
    for line in hashes:
        try:
            digest, name = line.split("\t")
        except ValueError:
            fail("Criterion binary hash row is malformed")
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            fail(f"Criterion binary hash is malformed for {name}")
        names.add(name.split("-", 1)[0])
    if names != {"rib_ops", "codec", "policy_eval"}:
        fail(f"Criterion binary inventory mismatch: {sorted(names)}")


def verify_sanitization() -> None:
    identity_terms = b"|".join(
        bytes.fromhex(value)
        for value in (
            "6c616e6365626f78",
            "6c616e6365",
            "636f646578",
            "636f70696c6f74",
            "6167656e746963",
        )
    )
    sensitive_terms = b"|".join(
        bytes.fromhex(value)
        for value in (
            "70617373776f7264",
            "626561726572",
            "736563726574",
            "63726564656e7469616c",
        )
    )
    forbidden = re.compile(
        rb"/(?:home|tmp|var/tmp)/|"
        rb"(?:^|[ =\"'(`])/(?!/)[A-Za-z0-9._$-]|"
        + rb"\b(?:" + identity_terms + rb")\b|"
        + rb"\b" + bytes.fromhex("7069643d") + rb"|"
        rb"\b127\.(?:\d{1,3}\.){2}\d{1,3}\b|"
        rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|"
        + rb"\b(?:" + sensitive_terms + rb"|api[_-]?key)[=:]",
        re.IGNORECASE | re.MULTILINE,
    )
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        data = gzip.open(path, "rb").read() if path.suffix == ".gz" else path.read_bytes()
        if forbidden.search(data):
            fail(f"sanitization scan failed for {path.relative_to(ROOT)}")


def verify_checksums() -> None:
    checksum_path = ROOT / "SHA256SUMS"
    covered: set[Path] = set()
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match:
            fail("SHA256SUMS contains a malformed row")
        expected, relative = match.groups()
        path = ROOT / relative
        if not path.is_file() or path == checksum_path:
            fail(f"SHA256SUMS names an invalid file: {relative}")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            fail(f"checksum mismatch: {relative}")
        covered.add(path)
    expected_files = {path for path in ROOT.rglob("*") if path.is_file() and path != checksum_path}
    if covered != expected_files:
        missing = sorted(str(path.relative_to(ROOT)) for path in expected_files - covered)
        extra = sorted(str(path.relative_to(ROOT)) for path in covered - expected_files)
        fail(f"checksum coverage mismatch: missing={missing} extra={extra}")


def main() -> None:
    manifest = verify_manifest()
    require(
        read_env(ROOT / "environment.txt"),
        {
            "hardware": "AMD Ryzen Threadripper 7970X 32-Cores",
            "online_cpus": "64",
            "memory_total_kib": "131379692",
            "kernel": "Linux 6.17.0-35-generic x86_64",
            "rustc": "1.97.0 2d8144b78 2026-07-07",
            "cargo": "1.97.0 c980f4866 2026-06-30",
            "criterion": "0.8.2",
            "criterion_logical_cpu": "8",
            "route_run_governors": "64/64 performance",
        },
        "environment",
    )
    verify_route_runs()
    verify_criterion(manifest)
    verify_sanitization()
    verify_checksums()
    print("PASS: 3 route runs, 71 Criterion rows, sanitization, and checksums verified")


if __name__ == "__main__":
    try:
        main()
    except (OSError, KeyError, json.JSONDecodeError, csv.Error) as error:
        fail(str(error))
