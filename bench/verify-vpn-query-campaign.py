#!/usr/bin/env python3
"""Fail-closed verifier and retained classifier for VPN query campaigns."""

import argparse
import hashlib
import json
import pathlib
import re
import statistics
import sys

SIZES = (10_000, 100_000, 1_000_000)
CASES = tuple(case for pair in range(1, 9) for case in (f"U{pair}", f"F{pair}"))
CAPACITY = 8 * 1024**3
CHECKSUMS = {
    (10_000, "U"): 11130280336100770277, (10_000, "F"): 7650825114892061189,
    (100_000, "U"): 14231629525132197650, (100_000, "F"): 8208171470299167599,
    (1_000_000, "U"): 17532315466326012662,
    (1_000_000, "F"): 12961212697594295368,
}


class Invalid(ValueError):
    pass


def load(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise Invalid(f"{path}: unreadable JSON: {error}") from error


def require(condition, message):
    if not condition:
        raise Invalid(message)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def expected_cells():
    return [
        (ordinal, size, label[0], int(label[1:]))
        for ordinal, (size, label) in enumerate(
            ((size, label) for size in SIZES for label in CASES), 1
        )
    ]


def verify_affinity(receipt, manifest, label):
    require((receipt.get("declared_cpu"), receipt.get("linux_affinity"))
            == (manifest["declared_cpu"], manifest["linux_affinity"]),
            f"{label}: CPU affinity drift")


def verify_query(query, rows, returned, label):
    require(query.get("actor_rows") == rows, f"{label}: actor rows")
    capacity = query.get("actor_capacity")
    require(type(capacity) is int and capacity >= rows, f"{label}: actor capacity")
    route_size = query.get("vpn_rib_route_size_bytes")
    label_size = query.get("mpls_label_entry_size_bytes")
    lower_bound = query.get("actor_snapshot_lower_bound_bytes")
    require(all(type(value) is int and value > 0
                for value in (route_size, label_size, lower_bound))
            and lower_bound == capacity * route_size + rows * label_size,
            f"{label}: actor snapshot lower bound")
    require(query.get("returned_rows") == returned, f"{label}: returned rows")
    return lower_bound


def verify_receipt(receipt, expected, manifest, attempt):
    ordinal, size, case, repetition = expected
    require(receipt.get("schema") == 3, f"receipt {ordinal}: schema")
    require(receipt.get("mode") == "timing", f"receipt {ordinal}: timing mode")
    require(receipt.get("allocation") is None
            and receipt.get("peak_live_requested_bytes") is None,
            f"receipt {ordinal}: allocation evidence contaminated timing mode")
    verify_affinity(receipt, manifest, f"receipt {ordinal}")
    require(receipt.get("ordinal") == ordinal, f"receipt {ordinal}: ordinal/order")
    require(receipt.get("routes") == size, f"receipt {ordinal}: routes/order")
    require(receipt.get("case") == case, f"receipt {ordinal}: case/order")
    require(receipt.get("repetition") == repetition, f"receipt {ordinal}: repetition")
    require(receipt.get("attempt") == attempt, f"receipt {ordinal}: attempt")
    require("queries" not in receipt, f"receipt {ordinal}: dual-case receipt")
    require(receipt.get("binary_sha256") == manifest["timing_binary_sha256"],
            f"receipt {ordinal}: timing binary drift")
    require(receipt.get("source_commit") == manifest["base_commit"],
            f"receipt {ordinal}: source provenance drift")
    require(receipt.get("timeout_seconds") == 120,
            f"receipt {ordinal}: 120-second censor missing")
    query = receipt.get("query")
    require(isinstance(query, dict), f"receipt {ordinal}: missing query")
    actor = query.get("actor_handler_ns")
    service = query.get("service_method_ns")
    post = query.get("post_actor_ns")
    require(all(isinstance(value, int) and value > 0 for value in (actor, service)),
            f"receipt {ordinal}: missing timing evidence")
    require(isinstance(post, int) and post >= 0,
            f"receipt {ordinal}: missing post-actor evidence")
    require(service >= actor, f"receipt {ordinal}: post-actor underflow")
    require(post == service - actor, f"receipt {ordinal}: post-actor decomposition")
    expected_rows = size if case == "U" else size // 16
    verify_query(query, size, expected_rows, f"receipt {ordinal}")
    require(query.get("dispatch") == 1, f"receipt {ordinal}: dispatch")
    require(type(query.get("checksum")) is int
            and query["checksum"] == CHECKSUMS[(size, case)],
            f"receipt {ordinal}: semantic checksum")
    return actor


def classify(manifest, timings, allocation):
    capacity_censored = allocation["peak_live_requested_bytes"] > CAPACITY
    pair_noise = {}
    noisy = False
    for size in SIZES:
        for case in ("U", "F"):
            samples = timings[(size, case)]
            values = []
            for pair in range(4):
                a, b = samples[pair * 2: pair * 2 + 2]
                noise = abs(a - b) / ((a + b) / 2)
                values.append(noise)
            pair_noise[f"{size}:{case}"] = values
            noisy |= max(values) > (0.10 if size == 1_000_000 else 0.05)
    medians = {
        key: statistics.median(samples) for key, samples in timings.items()
    }
    instrumentation_suspect = False
    for size in SIZES:
        u_median = medians[(size, "U")]
        f_median = medians[(size, "F")]
        agreement = abs(u_median - f_median) / ((u_median + f_median) / 2)
        tolerance = max(
            pair_noise[f"{size}:U"] + pair_noise[f"{size}:F"] + [0.05]
        )
        instrumentation_suspect |= agreement > tolerance
    for case in ("U", "F"):
        instrumentation_suspect |= any(
            medians[(larger, case)] <= medians[(smaller, case)]
            for smaller, larger in zip(SIZES, SIZES[1:])
        )
    worst = max(value for samples in timings.values() for value in samples)
    if capacity_censored:
        outcome = "capacity_censored"
    elif noisy:
        outcome = "inconclusive"
    elif instrumentation_suspect:
        outcome = "instrumentation_suspect"
    elif worst > 200_000_000:
        outcome = "urgent"
    elif worst > 25_000_000:
        outcome = "design_followup"
    else:
        outcome = "no_redesign"
    return {
        "classification": outcome,
        "cell_noise": {key: max(values) for key, values in pair_noise.items()},
        "pair_noise": pair_noise,
        "peak_live_requested_bytes": allocation["peak_live_requested_bytes"],
        "vmrss_bytes_observational": allocation.get("vmrss_bytes"),
        "vmhwm_bytes_observational": allocation.get("vmhwm_bytes"),
    }


def verify(directory):
    manifest = load(directory / "manifest.json")
    require(manifest.get("schema") == 3, "manifest schema")
    require(isinstance(manifest.get("base_commit"), str)
            and re.fullmatch(r"[0-9a-f]{40}", manifest["base_commit"]),
            "invalid base commit provenance")
    require(manifest.get("source_tree_clean") is True,
            "campaign source tree was not clean")
    require(isinstance(manifest.get("source_tree"), str)
            and re.fullmatch(r"[0-9a-f]{40}", manifest["source_tree"]),
            "invalid source tree provenance")
    require(manifest.get("rustc"), "missing rustc provenance")
    require(manifest.get("host_fence") == "pass", "host fence did not pass")
    require(manifest.get("fixed_order") == list(CASES), "fixed order drift")
    require(type(manifest.get("declared_cpu")) is int
            and manifest["declared_cpu"] >= 0, "invalid declared CPU")
    require(manifest.get("linux_affinity") == str(manifest["declared_cpu"]),
            "manifest CPU and Linux affinity differ")
    timing_binary = directory / "bin" / "vpn_query_timing"
    allocation_binary = directory / "bin" / "vpn_query_allocation"
    require(timing_binary.is_file() and allocation_binary.is_file(), "missing binaries")
    require(sha256(timing_binary) == manifest.get("timing_binary_sha256"),
            "timing binary corruption")
    require(sha256(allocation_binary) == manifest.get("allocation_binary_sha256"),
            "allocation binary corruption")

    def verify_phases(expected):
        phases = {}
        lines = (directory / "host-preflight.tsv").read_text(
            encoding="utf-8"
        ).splitlines()
        require(lines and lines[0].startswith("phase\tattempt\t"),
                "host preflight header")
        for line in lines[1:]:
            fields = line.split("\t")
            require(len(fields) == 10, "host preflight row")
            phases.setdefault(fields[0], []).append(fields)
        require(set(phases) == expected, "host preflight phase drift")
        require(all(float(rows[-1][3]) < float(rows[-1][4])
                    and rows[-1][5:9] == ["performance", "performance", "0", "none"]
                    and rows[-1][9] == "pass" for rows in phases.values()),
                "host preflight pass semantics")

    attempts = manifest.get("attempts")
    require(attempts in (1, 2), "campaign permits exactly one attempt and one retry")
    censor_path = directory / "censor.json"
    censor = load(censor_path) if censor_path.exists() else None
    censor_attempt = censor.get("attempt") if censor else attempts
    require(type(censor_attempt) is int and 1 <= censor_attempt <= attempts,
            "censor attempt outside requested attempts")
    entries = {p.name: p for p in directory.iterdir() if p.name.startswith("attempt")}
    expected_attempts = {f"attempt-{n}" for n in range(1, censor_attempt + 1)}
    require(set(entries) == expected_attempts
            and all(path.is_dir() for path in entries.values()),
            "attempt filesystem inventory drift")
    expected_phases = {"build"}
    selected_timings = None
    for attempt in range(1, censor_attempt + 1):
        receipt_paths = sorted((directory / f"attempt-{attempt}" / "timing").glob("*.json"))
        if censor and censor_attempt == attempt:
            require(len(receipt_paths) <= 48,
                    "censor timing prefix exceeds fixed 48-cell shape")
            for path, completed in zip(receipt_paths, expected_cells()):
                verify_receipt(load(path), completed, manifest, attempt)
            expected_phases.update(
                f"attempt-{attempt}-timing-{ordinal}"
                for ordinal in range(1, len(receipt_paths) + 1)
            )
            require(censor.get("outcome") == "capacity_censored", "invalid censor outcome")
            require(censor.get("schema") == 3, "censor schema")
            verify_affinity(censor, manifest, "censor")
            require(censor.get("ordinal") == len(receipt_paths) + 1,
                    "censor must stop the next ordered cell")
            if len(receipt_paths) == 48:
                require(censor.get("mode") == "allocation"
                        and censor.get("routes") == 1_000_000
                        and censor.get("case") == "U",
                        "allocation censor shape drift")
                expected_hash = manifest["allocation_binary_sha256"]
                expected_phases.add("allocation")
            else:
                expected = expected_cells()[len(receipt_paths)]
                require(censor.get("mode") == "timing"
                        and censor.get("routes") == expected[1]
                        and censor.get("case") == expected[2]
                        and censor.get("repetition") == expected[3],
                        "censor cell order drift")
                expected_hash = manifest["timing_binary_sha256"]
                expected_phases.update(
                    f"attempt-{attempt}-timing-{ordinal}"
                    for ordinal in range(1, len(receipt_paths) + 2)
                )
            require(censor.get("binary_sha256") == expected_hash, "censor binary drift")
            require(censor.get("source_commit") == manifest["base_commit"],
                    "censor source drift")
            require(censor.get("timeout_seconds") == 120, "censor timeout drift")
            require(censor.get("attempt") == attempt, "censor attempt drift")
            require(censor.get("censor_phase") in {
                "seed_send", "barrier_send", "barrier_reply", "service_query",
                "actor_receipt", "service_receipt",
            }, "invalid censor phase")
            require(attempt == censor_attempt, "censor attempt binding")
            require(not (directory / "allocation.json").exists(),
                    "allocation must not run after timeout censor")
            verify_phases(expected_phases)
            return {"classification": "capacity_censored",
                    "censor_phase": censor.get("censor_phase")}
        require(len(receipt_paths) == 48,
                f"attempt {attempt} must contain exactly 48 timing receipts")
        timings = {(size, case): [] for size in SIZES for case in ("U", "F")}
        for path, expected in zip(receipt_paths, expected_cells()):
            receipt = load(path)
            elapsed = verify_receipt(receipt, expected, manifest, attempt)
            timings[(expected[1], expected[2])].append(elapsed)
            expected_phases.add(f"attempt-{attempt}-timing-{expected[0]}")
        selected_timings = timings

    allocation = load(directory / "allocation.json")
    require(allocation.get("schema") == 3, "allocation schema")
    require(allocation.get("mode") == "allocation", "allocation mode")
    verify_affinity(allocation, manifest, "allocation")
    require(allocation.get("routes") == 1_000_000, "allocation must use 1M routes")
    require(allocation.get("case") == "U", "allocation must use unfiltered cell")
    require(allocation.get("binary_sha256") == manifest["allocation_binary_sha256"],
            "allocation binary drift")
    require(allocation.get("source_commit") == manifest["base_commit"],
            "allocation source provenance drift")
    require(allocation.get("timeout_seconds") == 120,
            "allocation 120-second censor missing")
    require(allocation.get("attempt") == attempts, "allocation attempt drift")
    counters = allocation.get("allocation")
    require(isinstance(counters, dict), "missing whole-query allocator evidence")
    operation_fields = tuple(f"{operation}_{suffix}"
                             for operation in ("alloc", "alloc_zeroed", "realloc", "dealloc")
                             for suffix in ("calls", "requested_bytes"))
    require(all(type(counters.get(field)) is int and counters[field] >= 0
                for field in operation_fields),
            "invalid whole-query allocator operation evidence")
    require(sum(counters[field] for field in operation_fields if field.endswith("_calls")) > 0
            and sum(counters[field] for field in operation_fields
                    if field.endswith("_requested_bytes")) > 0,
            "empty whole-query allocator operation evidence")
    baseline, final, peak, delta = (counters.get(field) for field in (
        "baseline_live_requested_bytes", "final_live_requested_bytes",
        "peak_live_requested_bytes", "peak_delta_requested_bytes"))
    require(all(type(value) is int and value >= 0
                for value in (baseline, final, peak, delta)),
            "invalid whole-query live-byte evidence")
    require(peak >= baseline and peak >= final and delta == peak - baseline,
            "inconsistent whole-query live-byte evidence")
    require(allocation.get("peak_live_requested_bytes") == peak,
            "absolute allocator peak disagrees with whole-query evidence")
    query = allocation.get("query")
    require(isinstance(query, dict), "missing allocation query")
    actor, service, post = (query.get(name) for name in
                            ("actor_handler_ns", "service_method_ns", "post_actor_ns"))
    require(type(actor) is int and actor > 0 and type(service) is int and service > 0
            and type(post) is int and post >= 0 and service - actor == post,
            "allocation timing decomposition")
    lower_bound = verify_query(query, 1_000_000, 1_000_000, "allocation")
    require(delta >= lower_bound,
            "allocation peak delta is below the actor snapshot lower bound")
    require(type(query.get("checksum")) is int
            and query["checksum"] == CHECKSUMS[(1_000_000, "U")],
            "allocation checksum")
    require(query.get("dispatch") == 1, "allocation dispatch")
    expected_phases.add("allocation")
    verify_phases(expected_phases)
    return classify(manifest, selected_timings, allocation)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("campaign", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    try:
        result = verify(args.campaign)
    except Invalid as error:
        print(f"invalid VPN query campaign: {error}", file=sys.stderr)
        return 1
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
