#!/usr/bin/env python3
"""Supplementary extraction for the v0.74.0 cross-daemon receipt.

summarize.py emits per-reload/round p50s and RSS for matrix legs and the
rustbgpd-sighup IRR rows. This adds, from the same labelled reloadstall.log
lines and the verifier-validated IRR rows.csv/rss.csv:
  matrix-tails.csv  per leg: S2 worst-observer stall and completion max,
                    S3 withdraw/re-announce max, settled/peak RSS per run
  irr-cells.csv     per root and cell: completion/gap p50 per reload, RSS peak
"""
import csv, re, sys
from pathlib import Path

legs = Path(sys.argv[1]); out = Path(sys.argv[2])
with (out / "matrix-tails.csv").open("w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["daemon", "scenario", "run", "metric", "round", "p50", "p95", "max", "unit"])
    for leg in sorted(legs.glob("matrix-s?-r?-*")):
        if not leg.is_dir():
            continue
        _, s, r, c = leg.name.split("-")
        log = (leg / c / "reloadstall.log").read_text()
        for m in re.finditer(r"^(reload|flap) (\d+) (completion_s|maxgap_ms|withdraw_s|reannounce_s|first_reann_s): p50=([\d.]+) p95=([\d.]+) max=([\d.]+)", log, re.M):
            unit = "ms" if m[3].endswith("_ms") else "s"
            w.writerow([c, s, r, m[3].rsplit("_", 1)[0], m[2], m[4], m[5], m[6], unit])
        rss = [int(row["total_rss_kib"]) for row in csv.DictReader((leg / c / "rss.csv").open())]
        w.writerow([c, s, r, "rss_settled_last_sample", "", "", "", rss[-1], "KiB"])
        w.writerow([c, s, r, "rss_peak_sample", "", "", "", max(rss), "KiB"])
with (out / "irr-cells.csv").open("w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["overlap", "run", "cell", "reload", "completion_p50_s", "completion_max_s",
                "changed_maxgap_p50_ms", "sessions_up", "parse_errors", "rss_peak_sample_kib"])
    for root in sorted(legs.glob("irr-ov*-r?")):
        if not root.is_dir():
            continue
        ov, r = root.name.split("-")[1:]
        for row in csv.DictReader((root / "rows.csv").open()):
            rss = max(int(x["total_rss_kib"]) for x in csv.DictReader((root / row["cell"] / "rss.csv").open()))
            w.writerow([ov[2:], r, row["cell"], row["reload"], row["completion_p50_s"], row["completion_max_s"],
                        row["changed_maxgap_p50_ms"], row["sessions_up"], row["parse_errors"], rss])
