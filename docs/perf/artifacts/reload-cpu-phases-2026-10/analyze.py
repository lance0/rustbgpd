#!/usr/bin/env python3
"""Partition the retained six-leg sampler traces at the original reload brackets."""

import argparse
import bisect
import csv
from decimal import Decimal
from pathlib import Path
import sys


FIELDS = ("epoch_us", "monotonic_ns", "read_us", "cpu_seconds",
          "voluntary_switches", "involuntary_switches", "threads_read", "threads_raced")
PHASES = ("before_reload_1", "reload_1", "between_1_2", "reload_2",
          "between_2_3", "reload_3", "between_3_4", "reload_4", "after_reload_4")
LEGS = ("01-A", "02-B", "03-B", "04-A", "05-A", "06-B")
ORIGINAL = Path(__file__).resolve().parent.parent / "export-probe-delta-arcvec-2026-10"


def read_csv(path):
    with path.open(newline="") as stream:
        return list(csv.DictReader(stream))


def partition(leg, samples, brackets):
    times = [int(row["epoch_us"]) for row in samples]
    if len(times) < 2 or any(a >= b for a, b in zip(times, times[1:])):
        raise ValueError("sample timestamps must strictly increase")
    for field in ("cpu_seconds", "voluntary_switches", "involuntary_switches", "monotonic_ns"):
        values = [Decimal(row[field]) for row in samples]
        if any(not value.is_finite() or value < 0 for value in values):
            raise ValueError(f"invalid {field}")
        if any(a > b for a, b in zip(values, values[1:])):
            raise ValueError(f"decreasing {field}")
    if [row["reload"] for row in brackets] != ["1", "2", "3", "4"]:
        raise ValueError("expected four ordered reload brackets")
    indices = [0]
    for row in brackets:
        for field in ("cpu_window_start_epoch_us", "cpu_window_end_epoch_us"):
            timestamp = int(row[field])
            index = bisect.bisect_left(times, timestamp)
            if index == len(times) or times[index] != timestamp:
                raise ValueError("reload boundary absent from sampler trace")
            indices.append(index)
    indices.append(len(samples) - 1)
    if any(a >= b for a, b in zip(indices, indices[1:])):
        raise ValueError("reload brackets must be ordered and disjoint inside trace")
    probe = bisect.bisect_left(times, times[0] + 10_000_000)
    if probe == len(times):
        raise ValueError("trace does not cover ten sampled seconds")
    intervals = [*zip(PHASES, indices, indices[1:]), ("first_10s_probe", 0, probe)]
    result = []
    for phase, start, end in intervals:
        before, after = samples[start], samples[end]
        row = {"leg": leg, "phase": phase, "start_csv_line": start + 2, "end_csv_line": end + 2}
        for endpoint, sample in (("start", before), ("end", after)):
            row.update({f"{endpoint}_{field}": sample[field] for field in FIELDS})
        row["elapsed_s"] = str((Decimal(after["monotonic_ns"]) - Decimal(before["monotonic_ns"])) / 1_000_000_000)
        for field in ("cpu_seconds", "voluntary_switches", "involuntary_switches"):
            row[f"delta_{field}"] = str(Decimal(after[field]) - Decimal(before[field]))
        result.append(row)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("raw_root", type=Path, help="directory containing the six retained leg directories")
    args = parser.parse_args()
    brackets = read_csv(ORIGINAL / "cpu-brackets.csv")
    rows = []
    for leg in LEGS:
        rows.extend(partition(leg, read_csv(args.raw_root / leg / "cgroup-fast.csv"),
                              [row for row in brackets if row["leg"] == leg]))
    writer = csv.DictWriter(sys.stdout, fieldnames=list(rows[0]), lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)


if __name__ == "__main__":
    main()
