#!/usr/bin/env python3
"""Fail closed on the ordinary-MRT attribute-scratch A/B campaign."""

import argparse, json, pathlib, re, statistics

ORDER = ("control", "candidate", "candidate", "control")
SHAPE_ORDER = ("ixp-700", "dual-full-feed")
SHAPES = {"ixp-700": (400_400, 400_400, 700), "dual-full-feed": (800_800, 400_400, 2)}
HEX40, HEX64 = re.compile(r"[0-9a-f]{40}\Z"), re.compile(r"[0-9a-f]{64}\Z")
FIELDS = set(("schema block slot scratch_variant growth_variant growth_path_assertion shape "
              "source_commit source_tree harness_sha256 "
              "timing_binary_sha256 diagnostic_binary_sha256 timing_ns allocator_calls "
              "eligible_opportunities scratch_reuses retained_scratch_capacity_bytes "
              "output_len_bytes decoded_entry_count prefix_count source_count raw_sha256 semantic_sha256").split())
NUMERIC = ("schema block slot allocator_calls eligible_opportunities scratch_reuses "
           "retained_scratch_capacity_bytes output_len_bytes decoded_entry_count prefix_count source_count").split()

class Invalid(ValueError): pass
def require(condition, message):
    if not condition: raise Invalid(message)

def verify(rows):
    require(len(rows) == 32, "campaign must contain four complete ABBA blocks")
    cells, identities, harnesses = {}, {name: set() for name in set(ORDER)}, set()
    expected_order = [(block, slot, shape) for block in range(1, 5)
                      for slot in range(1, 5) for shape in SHAPE_ORDER]
    for row, expected_key in zip(rows, expected_order):
        require(type(row) is dict and set(row) == FIELDS, "closed row schema")
        require(all(type(row[name]) is int and row[name] >= 0 for name in NUMERIC), "numeric schema")
        block, slot, shape = row["block"], row["slot"], row["shape"]
        scratch_variant = row["scratch_variant"]
        require(row["schema"] == 1 and block in range(1, 5) and slot in range(1, 5)
                and shape in SHAPES and scratch_variant == ORDER[slot - 1], "fixed ABBA matrix/order")
        key = block, slot, shape
        require(key == expected_key, "non-canonical serialized campaign order")
        require(key not in cells, "duplicate campaign cell")
        cells[key] = row
        require(row["growth_variant"] == "candidate", "legacy bounded-growth command variant")
        require(row["growth_path_assertion"] == "bounded-growth-observed",
                "legacy bounded-growth path assertion")
        strings = [row[name] for name in ("source_commit", "source_tree", "harness_sha256",
                   "timing_binary_sha256", "diagnostic_binary_sha256", "raw_sha256", "semantic_sha256")]
        require(all(type(value) is str for value in strings), "identity fields must be strings")
        require(HEX40.fullmatch(strings[0]) and HEX40.fullmatch(strings[1])
                and all(HEX64.fullmatch(value) for value in strings[2:]), "exact source/tree/binary identities")
        identities[scratch_variant].add(tuple(strings[:2] + strings[3:5])); harnesses.add(strings[2])
        paths, prefixes, sources = SHAPES[shape]
        require(row["eligible_opportunities"] == paths * 6, "six eligible attributes per path")
        require(row["decoded_entry_count"] == paths and row["prefix_count"] == prefixes
                and row["source_count"] == sources and row["output_len_bytes"] > 0,
                "shape count/length identity")
        require(row["allocator_calls"] > 0, "every measurement must observe allocator calls")
        require(type(row["timing_ns"]) is list and len(row["timing_ns"]) == 7
                and all(type(value) is int and value > 0 for value in row["timing_ns"]), "seven timing samples")
        require(statistics.pstdev(row["timing_ns"]) / statistics.mean(row["timing_ns"]) <= .05, "timing CV")
        if scratch_variant == "control":
            require(row["scratch_reuses"] == 0 and row["retained_scratch_capacity_bytes"] == 0,
                    "control must expose zero scratch use")
        else:
            require(row["scratch_reuses"] == row["eligible_opportunities"]
                    and 0 < row["retained_scratch_capacity_bytes"] <= 131_072, "candidate scratch contract")
    require(all(len(values) == 1 for values in identities.values()), "variant identity drift")
    control, candidate = (next(iter(identities[name])) for name in ORDER[:2])
    require(len({*control[:2], *candidate[:2]}) == 4,
            "control/candidate commit and tree identities must all differ")
    require(len({*control[2:], *candidate[2:]}) == 4,
            "control/candidate timing and diagnostic binary identities must all differ")
    require(len(harnesses) == 1, "harness source drift")
    shape_identities = {}
    for shape in SHAPE_ORDER:
        group = [row for row in cells.values() if row["shape"] == shape]
        require(len({(row["raw_sha256"], row["semantic_sha256"], row["decoded_entry_count"],
                      row["output_len_bytes"]) for row in group}) == 1, "encoded identity drift")
        shape_identities[shape] = group[0]["raw_sha256"], group[0]["semantic_sha256"]
    require(len({identity[0] for identity in shape_identities.values()}) == len(SHAPES),
            "incompatible shapes must have distinct raw digests")
    require(len({identity[1] for identity in shape_identities.values()}) == len(SHAPES),
            "incompatible shapes must have distinct semantic digests")
    for block in range(1, 5):
        for shape in SHAPE_ORDER:
            group = [cells[block, slot, shape] for slot in range(1, 5)]
            controls, candidates = group[::3], group[1:3]
            require(sum(row["allocator_calls"] for row in controls) > 0
                    and sum(row["allocator_calls"] for row in candidates) * 100
                    <= sum(row["allocator_calls"] for row in controls) * 80, "allocator reduction gate")
            side_median = lambda side: statistics.median(statistics.median(row["timing_ns"])
                                                         for row in side)
            require(side_median(candidates) * 100 <= side_median(controls) * 95, "paired timing gate")
    return {"classification": "go", "blocks": 4, "rows": 32}

def main():
    parser = argparse.ArgumentParser(); parser.add_argument("receipt", type=pathlib.Path); args = parser.parse_args()
    try:
        print(json.dumps(verify([json.loads(line) for line in args.receipt.read_text().splitlines() if line]), sort_keys=True))
    except (OSError, json.JSONDecodeError, Invalid) as error: parser.error(str(error))
if __name__ == "__main__": main()
