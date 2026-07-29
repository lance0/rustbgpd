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


def verify_receipt(receipt, expected, manifest):
    ordinal, size, case, repetition = expected
    require(receipt.get("schema") == 2, f"receipt {ordinal}: schema")
    require(receipt.get("mode") == "timing", f"receipt {ordinal}: timing mode")
    require(receipt.get("ordinal") == ordinal, f"receipt {ordinal}: ordinal/order")
    require(receipt.get("routes") == size, f"receipt {ordinal}: routes/order")
    require(receipt.get("case") == case, f"receipt {ordinal}: case/order")
    require(receipt.get("repetition") == repetition, f"receipt {ordinal}: repetition")
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
    require(query.get("actor_rows") == size, f"receipt {ordinal}: actor rows")
    require(query.get("actor_capacity", 0) >= size, f"receipt {ordinal}: actor capacity")
    require(query.get("returned_rows") == expected_rows, f"receipt {ordinal}: returned rows")
    require(query.get("dispatch") == 1, f"receipt {ordinal}: dispatch")
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
    require(manifest.get("schema") == 2, "manifest schema")
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
            phases.setdefault(fields[0], []).append(fields[-1])
        require(set(phases) == expected, "host preflight phase drift")
        require(all(values[-1] == "pass" for values in phases.values()),
                "host preflight phase did not pass")

    attempts = manifest.get("attempts")
    require(attempts in (1, 2), "campaign permits exactly one attempt and one retry")
    require(not (directory / "attempt-3").exists(), "third attempt is forbidden")
    expected_phases = {"build"}
    selected_timings = None
    for attempt in range(1, attempts + 1):
        receipt_paths = sorted((directory / f"attempt-{attempt}" / "timing").glob("*.json"))
        censor_path = directory / "censor.json"
        if censor_path.exists():
            censor = load(censor_path)
            for path, completed in zip(receipt_paths, expected_cells()):
                verify_receipt(load(path), completed, manifest)
            expected_phases.update(
                f"attempt-{attempt}-timing-{ordinal}"
                for ordinal in range(1, len(receipt_paths) + 1)
            )
            require(censor.get("outcome") == "capacity_censored", "invalid censor outcome")
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
            require(isinstance(censor.get("censor_phase"), str), "missing censor phase")
            require(attempt == attempts, "retry cannot follow a censored attempt")
            require(not (directory / "allocation.json").exists(),
                    "allocation must not run after timeout censor")
            verify_phases(expected_phases)
            return {"classification": "capacity_censored",
                    "censor_phase": censor.get("censor_phase")}
        require(len(receipt_paths) == 48,
                f"attempt {attempt} must contain exactly 48 timing receipts")
        timings = {(size, case): [] for size in SIZES for case in ("U", "F")}
        checksums = {(size, case): set() for size in SIZES for case in ("U", "F")}
        for path, expected in zip(receipt_paths, expected_cells()):
            receipt = load(path)
            elapsed = verify_receipt(receipt, expected, manifest)
            timings[(expected[1], expected[2])].append(elapsed)
            checksums[(expected[1], expected[2])].add(receipt["query"]["checksum"])
            expected_phases.add(f"attempt-{attempt}-timing-{expected[0]}")
        require(all(len(values) == 1 for values in checksums.values()),
                f"attempt {attempt}: timing checksum drift")
        selected_timings = timings

    allocation = load(directory / "allocation.json")
    require(allocation.get("schema") == 2, "allocation schema")
    require(allocation.get("mode") == "allocation", "allocation mode")
    require(allocation.get("routes") == 1_000_000, "allocation must use 1M routes")
    require(allocation.get("case") == "U", "allocation must use unfiltered cell")
    require(allocation.get("binary_sha256") == manifest["allocation_binary_sha256"],
            "allocation binary drift")
    require(allocation.get("source_commit") == manifest["base_commit"],
            "allocation source provenance drift")
    require(allocation.get("timeout_seconds") == 120,
            "allocation 120-second censor missing")
    require(isinstance(allocation.get("peak_live_requested_bytes"), int)
            and allocation["peak_live_requested_bytes"] > 0,
            "missing absolute allocator evidence")
    query = allocation.get("query")
    require(isinstance(query, dict), "missing allocation query")
    require(query.get("actor_rows") == 1_000_000, "allocation actor rows")
    require(query.get("actor_capacity", 0) >= 1_000_000, "allocation actor capacity")
    require(query.get("returned_rows") == 1_000_000, "allocation returned rows")
    require(isinstance(query.get("checksum"), int), "allocation checksum")
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
