#!/usr/bin/env python3
"""Recompute every number the readiness-checkpoint receipt quotes from this bundle.

Checks leg coverage and identity, cross-checks the extracted daemon-log CSVs
against summary.csv, then compares each quoted range and median. Exits 1 on
any mismatch.
"""
import csv
import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ARMS = ("main", "fast")
ORDER = ["main-r1", "fast-r1", "fast-r2", "main-r2", "main-r3", "fast-r3", "fast-r4", "main-r4"]

# metric: {arm: (per-reload or per-leg min, max, median, per-leg-median min, max)}
# Clock metrics in ms (harness completion in s); memory in MiB (KiB / 1024).
EXPECTED = {
    "daemon_sighup_to_complete": {"main": ("1056.6", "1175.0", "1137.15", "1074.0", "1157.9"),
                                  "fast": ("916.8", "1007.6", "959.15", "936.8", "964.4")},
    "reload_completion_p50": {"main": ("1.09", "1.22", "1.16", "1.095", "1.180"),
                              "fast": ("0.93", "1.02", "0.99", "0.965", "0.990")},
    "reload_changed_maxgap_p50": {"main": ("467.4", "539.5", "480.0", "470.1", "507.7"),
                                  "fast": ("376.4", "443.9", "391.6", "387.0", "400.8")},
    "daemon_rib_transition": {"main": ("487.5", "521.3", "495.5", "495.1", "500.3"),
                              "fast": ("355.5", "387.3", "366.95", "363.7", "367.9")},
    "rib_export_elapsed_ms": {"main": ("487", "512", "494.5", "494.0", "497.5"),
                              "fast": ("355", "381", "365.0", "362.5", "366.0")},
    "generation_total_ms": {"main": ("1014.2", "1138.0", "1094.8", "1033.4", "1114.9"),
                            "fast": ("876.6", "965.7", "917.3", "896.5", "922.6")},
    "prestage_round_trip_ms": {"main": ("434", "523", "494.0", "445.0", "514.0"),
                               "fast": ("367", "456", "411.5", "384.5", "418.0")},
    "deferred_refresh_dispatch_ms": {"main": ("71.8", "95.7", "82.5", "80.1", "89.3"),
                                     "fast": ("112.5", "148.6", "130.7", "122.2", "134.4")},
    "daemon_cg_peak": {"main": ("995", "1173", "1039"), "fast": ("1018", "1282", "1106")},
    "daemon_vmhwm": {"main": ("556", "565", "563"), "fast": ("556", "565", "562")},
    "peak_rss_sample": {"main": ("471", "480", "474"), "fast": ("491", "505", "502")},
    "settled_rss_last_sample": {"main": ("364", "367", "364"), "fast": ("363", "368", "365")},
}
# Median change, fast minus main, in the metric's unit; percentages of the main median.
EXPECTED_DELTA = {
    "daemon_sighup_to_complete": "-178.00", "reload_completion_p50": "-0.17",
    "reload_changed_maxgap_p50": "-88.44", "daemon_rib_transition": "-128.55",
    "rib_export_elapsed_ms": "-129.5", "generation_total_ms": "-177.5",
    "prestage_round_trip_ms": "-82.5", "deferred_refresh_dispatch_ms": "+48.25",
    "daemon_cg_peak": "+68", "daemon_vmhwm": "-1", "peak_rss_sample": "+28",
    "settled_rss_last_sample": "+1",
}
EXPECTED_PERCENT = {"daemon_sighup_to_complete": "-15.7", "daemon_rib_transition": "-25.9",
                    "rib_export_elapsed_ms": "-26.2"}
EXPECTED_SPAN = {"main": ("0.731", "0.752"), "fast": ("0.738", "0.752")}
MEMORY = {"daemon_cg_peak", "daemon_vmhwm", "peak_rss_sample", "settled_rss_last_sample"}

problems = []


def need(ok, message):
    if not ok:
        problems.append(message)


def fmt(value, like):
    """Format VALUE with the decimals of the quoted string LIKE (half away from zero)."""
    places = len(like.split(".")[1]) if "." in like else 0
    scaled = abs(value) * 10 ** places
    rounded = int(scaled + 0.5 + 1e-9) / 10 ** places
    return f"{rounded if value >= 0 else -rounded:.{places}f}"


def rows(name):
    with open(HERE / name, newline="") as handle:
        return list(csv.DictReader(handle))


def main():
    # Coverage and identity.
    identity = {}
    for line in (HERE / "identity.tsv").read_text().splitlines():
        arm, *fields = line.split("\t")
        identity[arm] = dict(field.split("=", 1) for field in fields)
    for leg in ORDER:
        arm, run = leg.split("-")
        cell = HERE / "matrix" / f"matrix-{arm}-{run}-s2"
        need((cell / "status").read_text().strip() == "pass", f"{leg}: status")
        need((cell / "daemon.exit").read_text().strip() == "0", f"{leg}: daemon exit")
        need("cg_swap_max: 0\n" in (cell / "cgroup-memory").read_text(), f"{leg}: swap fence")
        quiet = list(csv.DictReader((cell / "quiet.tsv").open(), delimiter="\t"))
        need(len(quiet) == 2 and all(q["quiet"] == "true" for q in quiet), f"{leg}: quiet samples")
        prov = json.loads((cell / "provenance.json").read_text())
        need(prov["git"]["tree"] == identity[arm]["tree"] and not prov["git"]["dirty"], f"{leg}: tree")
        need(prov["workload"]["sha256"] == identity[arm]["daemon_sha256"], f"{leg}: daemon sha256")
        need(prov["workload"]["inputs"]["N_PEERS"] == "700"
             and prov["workload"]["inputs"]["TOTAL_PREFIXES"] == "400400"
             and prov["workload"]["inputs"]["RELOADS"] == "4", f"{leg}: shape")
    starts = [line.split("] ")[1].split()[0] for line in (HERE / "progress.txt").read_text().splitlines()
              if line.endswith("cpus=0-63") and " start load=" in line]
    measured = [s.replace("matrix-", "").replace("-s2", "") for s in starts[-8:]]
    need(measured == ORDER, f"leg order {measured}")
    need(json.loads((HERE / "provenance.json").read_text())["order"] == ORDER, "provenance order")

    # Values per metric and arm: per reload and per leg.
    values = defaultdict(list)
    legs = defaultdict(lambda: defaultdict(list))

    def add(metric, arm, run, value):
        values[(metric, arm)].append(value)
        legs[(metric, arm)][str(run)].append(value)

    summary = [r for r in rows("summary.csv") if r["phase"] == "matrix-s2"]
    for r in summary:
        value = float(r["value"]) / 1024 if r["metric"] in MEMORY else float(r["value"])
        add(r["metric"], r["arm"], r["run"], value)
    phase = rows("generation-phase.csv")
    rib = rows("rib-export-transition.csv")
    need(len(phase) == 32 and len(rib) == 32, "32 reload rows per extract")
    for r in rib:
        need(r["outcome"] == "committed" and r["member_count"] == "700", f"{r['leg']} reload {r['reload']}")
        add("rib_export_elapsed_ms", r["arm"], r["run"], float(r["elapsed_ms"]))
    for r in phase:
        need(r["outcome"] == "committed", f"{r['leg']} reload {r['reload']} phase outcome")
        for metric in ("generation_total_ms", "prestage_round_trip_ms", "deferred_refresh_dispatch_ms"):
            add(metric, r["arm"], r["run"], float(r[metric]))

    # The extracts must agree with the campaign's own daemon rows.
    by_key = {(r["arm"], r["run"], r["round"], r["metric"]): r["value"] for r in summary}
    for r in phase:
        key = (r["arm"], r["run"], r["reload"])
        need(float(by_key[key + ("daemon_sighup_to_complete",)]) == float(r["sighup_to_complete_ms"]),
             f"{key} sighup_to_complete differs from summary.csv")
        need(float(by_key[key + ("daemon_rib_transition",)]) == float(r["cohort_rib_transition_ms"]),
             f"{key} rib transition differs from summary.csv")

    for metric, arms in EXPECTED.items():
        for arm, quoted in arms.items():
            got = values[(metric, arm)]
            need(len(got) == (4 if metric in MEMORY else 16), f"{metric} {arm}: n={len(got)}")
            computed = [min(got), max(got), statistics.median(got)]
            if len(quoted) == 5:
                medians = [statistics.median(v) for v in legs[(metric, arm)].values()]
                computed += [min(medians), max(medians)]
            actual = tuple(fmt(c, q) for c, q in zip(computed, quoted))
            need(actual == quoted, f"{metric} {arm}: computed {actual}, quoted {quoted}")

    for metric, quoted in EXPECTED_DELTA.items():
        delta = statistics.median(values[(metric, "fast")]) - statistics.median(values[(metric, "main")])
        actual = ("+" if delta > 0 else "-") + fmt(abs(delta), quoted)
        need(actual == quoted, f"{metric} median delta: computed {actual}, quoted {quoted}")
    for metric, quoted in EXPECTED_PERCENT.items():
        base = statistics.median(values[(metric, "main")])
        pct = 100 * (statistics.median(values[(metric, "fast")]) - base) / base
        actual = "-" + fmt(-pct, quoted) if pct < 0 else "+" + fmt(pct, quoted)
        need(actual == quoted, f"{metric} median change: computed {actual}%, quoted {quoted}%")

    spans = defaultdict(list)
    for r in rows("establishment-span.csv"):
        spans[r["arm"]].append(r["first_to_nth_established_s"])
    for arm, (low, high) in EXPECTED_SPAN.items():
        need((min(spans[arm]), max(spans[arm])) == (low, high), f"establishment span {arm}")

    for problem in problems:
        print("MISMATCH:", problem)
    if problems:
        return 1
    print(f"ok: {sum(len(a) for a in EXPECTED.values()) + len(EXPECTED_SPAN)} arm values, "
          f"{len(EXPECTED_DELTA) + len(EXPECTED_PERCENT)} median changes recomputed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
