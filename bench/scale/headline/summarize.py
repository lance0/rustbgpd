#!/usr/bin/env python3
"""Extract a headline campaign's values into summary.csv and a per-arm table.

Usage: summarize.py SOURCE [--out DIR] [--exclude GLOB ...]

SOURCE is either a campaign output directory written by run-campaign.sh or a
compact receipt bundle under docs/perf/artifacts/ (legs under matrix/, irr/
and rr1000/). Leg directories are named matrix-ARM-rN-sK, irr-ovF-ARM-rN and
rr1000-ARM-cN.

An optional SOURCE/EXCLUDED file lists leg IDs to drop, one per line (`#`
starts a comment), and --exclude GLOB adds more. Each entry must match a leg;
report.md lists the excluded legs under the table, whose counts n are what
remains.

Only finished legs count: a matrix leg whose status is `pass`, an IRR root
whose COMPLETED status is `pass`, and an RR1000 campaign whose COMPLETED is
`pass`. Matrix values come from the labelled reloadstall.log lines, not the
CSV rows. A finished leg that lacks a labelled value it must carry is an
error, not an empty cell: a renamed label would otherwise drop a whole row
from the receipt table without notice.

Writes to DIR (default SOURCE, which must then be a campaign directory;
a bundle needs --out so a committed receipt is never rewritten): summary.csv, one row per run, round and
metric; establishment-span.csv, the first-to-Nth `session established` span
from each matrix leg's daemon log, when the daemon logs are present; and
report.md, the per-arm range, median and count for every metric. S1 values
are read from the convergence phase of the S2 and S3 legs.
"""

import argparse
import csv
import fnmatch
import json
import re
import statistics
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

MATRIX = re.compile(r"^matrix-(.+)-r(\d+)-(s\d)$")
IRR = re.compile(r"^irr-ov([\d.]+)-(.+)-r(\d+)$")
RR = re.compile(r"^rr1000-(.+)-c(\d+)$")

# (metric, labelled-line pattern, unit, scenarios where a pass must carry it)
MATRIX_LINES = [
    ("established", r"^established \d+ at ([\d.]+)s", "s", {"s2", "s3"}),
    ("cold_convergence", r"^converged \(>= \d+/observer\) at ([\d.]+)s", "s", {"s2", "s3"}),
    ("reload_completion_p50", r"^reload \d+ completion_s: p50=([\d.]+)", "s", {"s2"}),
    ("reload_changed_maxgap_p50", r"^reload \d+ maxgap_ms: p50=([\d.]+)", "ms", {"s2"}),
    ("flap_withdraw_p50", r"^flap \d+ withdraw_s: p50=([\d.]+)", "s", {"s3"}),
    ("flap_reannounce_p50", r"^flap \d+ reannounce_s: p50=([\d.]+)", "s", {"s3"}),
    ("flap_first_reannounce_p50", r"^flap \d+ first_reann_s: p50=([\d.]+)", "s", {"s3"}),
    ("flap_post_round_rss", r"^flap \d+ sessions_up \d+/\d+ rss_mib=(\d+)", "MiB", {"s3"}),
]


class ExtractionError(Exception):
    pass


def legs(source, subdir, pattern, exclusions):
    """Leg directories directly under SOURCE (campaign) or SOURCE/SUBDIR (bundle).

    EXCLUSIONS is (globs, excluded): a leg matching a glob is appended to
    `excluded` instead of being returned."""
    globs, excluded = exclusions
    found = []
    for base in (source, source / subdir):
        if not base.is_dir():
            continue
        for path in sorted(base.iterdir()):
            match = pattern.match(path.name)
            if not (path.is_dir() and match):
                continue
            if any(fnmatch.fnmatch(path.name, glob) for glob in globs):
                excluded.append(path.name)
            else:
                found.append((path, match.groups()))
    return found


def read_text(path):
    return path.read_text(errors="replace")


def rss_column(path):
    return [int(row["total_rss_kib"]) for row in csv.DictReader(path.read_text().splitlines())]


def matrix_rows(source, exclusions):
    rows, spans = [], []
    for leg, (arm, run, scenario) in legs(source, "matrix", MATRIX, exclusions):
        cell = leg / "rustbgpd" if (leg / "rustbgpd").is_dir() else leg
        status = cell / "status"
        if not status.exists() or read_text(status).strip() != "pass":
            continue
        log = read_text(cell / "reloadstall.log")
        phase = f"matrix-{scenario}"
        counts = {}
        for metric, pattern, unit, required in MATRIX_LINES:
            values = re.findall(pattern, log, re.M)
            if scenario in required and not values:
                raise ExtractionError(f"{leg.name}: passing {scenario} leg has no '{metric}' line")
            counts[metric] = len(values)
            for index, value in enumerate(values, 1):
                rows.append([phase, arm, run, metric, index, value, unit])
        if scenario == "s2" and counts["reload_completion_p50"] != counts["reload_changed_maxgap_p50"]:
            raise ExtractionError(f"{leg.name}: reload completion and maxgap line counts differ")
        flap_counts = {counts[m] for m, *_ in MATRIX_LINES if m.startswith("flap_")}
        if scenario == "s3" and len(flap_counts) != 1:
            raise ExtractionError(f"{leg.name}: flap metric line counts differ")
        rss = rss_column(cell / "rss.csv")
        if not rss:
            raise ExtractionError(f"{leg.name}: rss.csv has no samples")
        rows.append([phase, arm, run, "settled_rss_last_sample", "", rss[-1], "KiB"])
        rows.append([phase, arm, run, "peak_rss_sample", "", max(rss), "KiB"])
        if (cell / "vmhwm").exists():
            hwm = re.search(r"VmHWM:\s+(\d+)", read_text(cell / "vmhwm"))
            if hwm:
                rows.append([phase, arm, run, "daemon_vmhwm", "", hwm.group(1), "KiB"])
        daemon_log = cell / "daemon.log"
        if daemon_log.exists():
            established = re.search(r"^established (\d+) at", log, re.M)
            if established is None:
                raise ExtractionError(f"{leg.name}: reloadstall.log has no 'established N at' line")
            spans.append([arm, run, scenario, *establishment_span(daemon_log, int(established.group(1)))])
    return rows, spans


def establishment_span(daemon_log, peers):
    stamps = []
    for line in read_text(daemon_log).splitlines():
        if '"session established"' in line:
            stamp = json.loads(line)["timestamp"].replace("Z", "+00:00")
            stamps.append(datetime.fromisoformat(stamp).timestamp())
    stamps.sort()
    span = f"{stamps[peers - 1] - stamps[0]:.3f}" if len(stamps) >= peers else ""
    return len(stamps), peers, span


def irr_rows(source, exclusions):
    rows = []
    for leg, (overlap, arm, run) in legs(source, "irr", IRR, exclusions):
        completed = leg / "COMPLETED"
        if not completed.exists() or json.loads(read_text(completed)).get("status") != "pass":
            continue
        phase = f"irr-ov{overlap}"
        sighup = [r for r in csv.DictReader(read_text(leg / "rows.csv").splitlines()) if r["cell"] == "rustbgpd-sighup"]
        if not sighup:
            raise ExtractionError(f"{leg.name}: completed root has no rustbgpd-sighup rows")
        for row in sighup:
            rows.append([phase, arm, run, "completion_p50", row["reload"], row["completion_p50_s"], "s"])
            rows.append([phase, arm, run, "changed_maxgap_p50", row["reload"], row["changed_maxgap_p50_ms"], "ms"])
        rss = leg / "rustbgpd-sighup" / "rss.csv"
        if rss.exists():
            rows.append([phase, arm, run, "peak_rss_sample", "", max(rss_column(rss)), "KiB"])
    return rows


def rr_rows(source, exclusions):
    rows = []
    for leg, (arm, campaign) in legs(source, "rr1000", RR, exclusions):
        completed = leg / "COMPLETED"
        if not completed.exists() or read_text(completed).split()[:1] != ["pass"]:
            continue
        attempts = sorted(leg.glob("run-*/phase.json"))
        if not attempts:
            raise ExtractionError(f"{leg.name}: completed campaign has no run-*/phase.json")
        for path in attempts:
            phase = json.loads(read_text(path))
            wire = phase["resource_observer"]["wire"]
            run = f"c{campaign}r{path.parent.name.removeprefix('run-')}"
            for key in ("injection_ms", "staged_ms", "wire_ms"):
                rows.append(["rr1000", arm, run, key, "", phase[key], "ms"])
            rows.append(["rr1000", arm, run, "wire_vmrss", "", wire["direct_pid_vmrss_kib"], "KiB"])
            rows.append(["rr1000", arm, run, "wire_vmhwm", "", wire["direct_pid_vmhwm_kib"], "KiB"])
    return rows


def extract(source, excludes=()):
    """Return (rows, spans, excluded leg names)."""
    listed = source / "EXCLUDED"
    lines = read_text(listed).splitlines() if listed.exists() else []
    globs = [entry for line in lines if (entry := line.split("#", 1)[0].strip())] + list(excludes)
    exclusions = (globs, [])
    matrix, spans = matrix_rows(source, exclusions)
    rows = matrix + irr_rows(source, exclusions) + rr_rows(source, exclusions)
    for glob in globs:
        if not any(fnmatch.fnmatch(name, glob) for name in exclusions[1]):
            raise ExtractionError(f"exclusion '{glob}' matches no leg")
    return rows, spans, exclusions[1]


def aggregate(rows, spans):
    """{(phase, metric): {arm: [values]}}, with S1 read from the S2 and S3 legs."""
    table = defaultdict(lambda: defaultdict(list))
    for phase, arm, _run, metric, _round, value, _unit in rows:
        if metric in ("established", "cold_convergence"):
            phase = "matrix-s1"
        table[(phase, metric)][arm].append(float(value))
    for arm, _run, _scenario, _count, _peers, span in spans:
        if span:
            table[("matrix-s1", "establishment_span")][arm].append(float(span))
    return table


def arm_order(source, table):
    arms_file = source / "arms.txt"
    if arms_file.exists():
        return [line.split("=", 1)[0] for line in read_text(arms_file).splitlines() if line]
    return sorted({arm for cells in table.values() for arm in cells})


def report(table, arms, smoke, excluded):
    lines = []
    if smoke:
        lines += ["SMOKE run: pipeline check at a reduced shape, not a measurement.", ""]
    lines += ["| Phase | Metric | " + " | ".join(arms) + " |", "|---|---|" + "---:|" * len(arms)]
    for phase, metric in sorted(table):
        cells = []
        for arm in arms:
            values = table[(phase, metric)].get(arm)
            cells.append(
                f"{min(values):.6g}–{max(values):.6g} (median {statistics.median(values):.6g}, n={len(values)})"
                if values else "-")
        lines.append(f"| {phase} | {metric} | " + " | ".join(cells) + " |")
    lines += ["", "Excluded legs, not counted in n above:" if excluded else "Excluded legs: none."]
    lines += [f"- `{name}`" for name in excluded]
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description="Extract a headline campaign's summary and table.")
    parser.add_argument("source", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--exclude", action="append", default=[])
    args = parser.parse_args(argv)
    if args.out is None and not (args.source / "arms.txt").exists():
        # A receipt bundle is history: write its re-extraction elsewhere.
        print(f"summarize: {args.source} is not a campaign directory; pass --out", file=sys.stderr)
        return 2
    out = args.out or args.source
    try:
        rows, spans, excluded = extract(args.source, args.exclude)
    except (ExtractionError, OSError, KeyError, ValueError) as error:
        print(f"summarize: {error}", file=sys.stderr)
        return 1
    if not rows:
        print(f"summarize: no finished legs under {args.source}", file=sys.stderr)
        return 1
    out.mkdir(parents=True, exist_ok=True)
    with (out / "summary.csv").open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["phase", "arm", "run", "metric", "round", "value", "unit"])
        writer.writerows(rows)
    if spans:
        with (out / "establishment-span.csv").open("w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["arm", "run", "scenario", "session_established_log_lines", "peers",
                             "first_to_nth_established_s"])
            writer.writerows(spans)
    table = aggregate(rows, spans)
    text = report(table, arm_order(args.source, table), (args.source / "SMOKE").exists(), excluded)
    (out / "report.md").write_text(text)
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
