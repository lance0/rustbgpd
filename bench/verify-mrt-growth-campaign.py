#!/usr/bin/env python3
"""Fail closed on ordinary-MRT output-growth A/B campaign receipts."""

import argparse
import json
import pathlib
import re
import statistics
ORDER = ("control", "candidate", "candidate", "control")
SHAPES = {"ixp-700": (400_400, 400_400, 700), "dual-full-feed": (800_800, 400_400, 2)}
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
FIELDS = set(("schema block slot variant source_commit source_tree harness_sha256 "
              "timing_binary_sha256 diagnostic_binary_sha256 growth_path_assertion shape timing_ns "
              "allocator_calls requested_bytes output_growth_misses output_len_bytes "
              "output_capacity_bytes peak_live_overhead_bytes decoded_entry_count raw_sha256 semantic_sha256").split())
NUMERIC = ("schema block slot allocator_calls requested_bytes output_growth_misses "
           "output_len_bytes output_capacity_bytes peak_live_overhead_bytes decoded_entry_count").split()

class Invalid(ValueError): pass
def require(condition, message):
    if not condition:
        raise Invalid(message)

def verify(rows):
    require(len(rows) == 32, "campaign must contain four complete ABBA blocks")
    cells, identities = {}, {"control": set(), "candidate": set()}
    harnesses = set()
    for row in rows:
        require(type(row) is dict and set(row) == FIELDS, "closed row schema")
        block, slot, shape = row["block"], row["slot"], row["shape"]
        require(all(type(row[field]) is int and row[field] >= 0 for field in NUMERIC),
                "numeric fields must be non-negative integers")
        require(row["schema"] == 1 and block in range(1, 5) and slot in range(1, 5) and shape in SHAPES,
                "block, slot, or shape outside the fixed matrix")
        variant = row["variant"]
        require(variant == ORDER[slot - 1], "ABBA variant identity/order")
        key = (block, slot, shape)
        require(key not in cells, "duplicate ABBA cell")
        cells[key] = row
        commit, tree = row["source_commit"], row["source_tree"]
        hashes = (row["harness_sha256"], row["timing_binary_sha256"], row["diagnostic_binary_sha256"], row["raw_sha256"],
                  row["semantic_sha256"])
        require(all(type(value) is str for value in (commit, tree, *hashes)), "identity fields must be strings")
        require(HEX40.fullmatch(commit) and HEX40.fullmatch(tree) and all(HEX64.fullmatch(value) for value in hashes),
                "source/binary identity")
        identities[variant].add((commit, tree, hashes[1], hashes[2]))
        harnesses.add(hashes[0])
        require(row["growth_path_assertion"] == ("ordinary-unbounded-observed" if variant == "control"
                                                 else "bounded-growth-observed"), "growth-path assertion")
        paths, _, _ = SHAPES[shape]
        require(row["decoded_entry_count"] == paths and row["output_len_bytes"] > 0, "decoded count or output length")
        require(type(row["timing_ns"]) is list and len(row["timing_ns"]) == 7
                and all(type(value) is int and value > 0 for value in row["timing_ns"]),
                "seven positive timing samples")
        require(statistics.pstdev(row["timing_ns"]) / statistics.mean(row["timing_ns"]) <= .05, "timing CV")
        require(row["output_growth_misses"] >= paths if variant == "control" else
                row["output_growth_misses"] <= 64, "growth-path count")
        require(row["output_capacity_bytes"] >= row["output_len_bytes"], "capacity underflow")
    require(all(len(value) == 1 for value in identities.values()), "variant identity drift")
    control, candidate = (next(iter(identities[name])) for name in ORDER[:2])
    require(control[0] != candidate[0] and control[1] != candidate[1], "source commit/tree must differ")
    require(len(harnesses) == 1, "harness source drift")
    for shape in SHAPES:
        group = [row for row in cells.values() if row["shape"] == shape]
        require(len({(row["raw_sha256"], row["semantic_sha256"], row["decoded_entry_count"], row["output_len_bytes"])
                     for row in group}) == 1, "cross-block encoded identity drift")
    for block in range(1, 5):
        for shape in SHAPES:
            group = [cells[block, slot, shape] for slot in range(1, 5)]
            control, candidate = group[::3], group[1:3]
            aggregate = lambda side, field: sum(row[field] for row in side)
            timing = lambda side: statistics.median(statistics.median(row["timing_ns"]) for row in side)
            require(timing(candidate) * 100 <= timing(control) * 95, "five-percent timing gate")
            require(aggregate(candidate, "output_growth_misses") * 100
                    <= aggregate(control, "output_growth_misses"),
                    "output-growth reservation gate")
            require(aggregate(control, "allocator_calls") > 0 and aggregate(candidate, "allocator_calls") * 100
                    <= aggregate(control, "allocator_calls") * 80, "allocator-call gate")
            require(aggregate(control, "requested_bytes") > 0 and aggregate(candidate, "requested_bytes") * 2
                    <= aggregate(control, "requested_bytes"), "requested-byte gate")
            for row in candidate:
                require(row["output_capacity_bytes"] - row["output_len_bytes"] <= row["output_len_bytes"] // 4,
                        "capacity-slack gate")
                require(row["peak_live_overhead_bytes"] <= min(row["output_len_bytes"] // 4, 32 * 1024**2),
                        "peak-overhead gate")
    return {"classification": "go", "blocks": 4, "rows": 32}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("receipt", type=pathlib.Path)
    args = parser.parse_args()
    try:
        rows = [json.loads(line) for line in args.receipt.read_text().splitlines() if line]
        print(json.dumps(verify(rows), sort_keys=True))
    except (OSError, json.JSONDecodeError, Invalid) as error:
        parser.error(str(error))

if __name__ == "__main__":
    main()
