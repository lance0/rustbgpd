#!/usr/bin/env python3
# Adapted for publication: absolute scratch, checkout, repository and home paths
# are replaced with SCRATCH, WORKTREES, REPO, BGPERF2 and HOME. Otherwise as run.
"""summary.py <campaign> <bundle>: write summary.csv + establishment-span.csv
from labeled reloadstall lines (not the CSV rows), rows.csv, and phase.json."""
import csv, glob, json, os, re, sys
from datetime import datetime
src, dst = sys.argv[1], sys.argv[2]
NAME = {"v0730": "v0.73.0", "v0720": "v0.72.0", "v0680": "v0.68.0", "xh": "v0.68.0-daemon/v0.72.0-harness"}
out = csv.writer(open(f"{dst}/summary.csv", "w"))
out.writerow(["phase", "arm", "run", "metric", "round", "value", "unit"])
dirs = lambda pat: [d for d in sorted(glob.glob(pat)) if os.path.isdir(d)]
for d in dirs(f"{src}/matrix-*"):
    arm, run, sc = re.search(r"matrix-(\w+)-r(\d)-(s\d)$", d).groups()
    c = f"{d}/rustbgpd"
    if not os.path.exists(f"{c}/status") or open(f"{c}/status").read().strip() != "pass":
        continue
    log = open(f"{c}/reloadstall.log").read()
    def put(metric, pat, unit):
        for i, v in enumerate(re.findall(pat, log, re.M), 1):
            out.writerow([f"matrix-{sc}", NAME[arm], run, metric, i, v, unit])
    put("established", r"^established \d+ at ([\d.]+)s", "s")
    put("cold_convergence", r"^converged \(>= \d+/observer\) at ([\d.]+)s", "s")
    put("reload_completion_p50", r"^reload \d+ completion_s: p50=([\d.]+)", "s")
    put("reload_changed_maxgap_p50", r"^reload \d+ maxgap_ms: p50=([\d.]+)", "ms")
    put("flap_withdraw_p50", r"^flap \d+ withdraw_s: p50=([\d.]+)", "s")
    put("flap_reannounce_p50", r"^flap \d+ reannounce_s: p50=([\d.]+)", "s")
    put("flap_first_reannounce_p50", r"^flap \d+ first_reann_s: p50=([\d.]+)", "s")
    put("flap_post_round_rss", r"^flap \d+ sessions_up \d+/\d+ rss_mib=(\d+)", "MiB")
    rss = [int(r["total_rss_kib"]) for r in csv.DictReader(open(f"{c}/rss.csv"))]
    out.writerow([f"matrix-{sc}", NAME[arm], run, "settled_rss_last_sample", "", rss[-1], "KiB"])
    out.writerow([f"matrix-{sc}", NAME[arm], run, "peak_rss_sample", "", max(rss), "KiB"])
    if os.path.exists(f"{c}/vmhwm"):
        h = re.search(r"VmHWM:\s+(\d+)", open(f"{c}/vmhwm").read()).group(1)
        out.writerow([f"matrix-{sc}", NAME[arm], run, "daemon_vmhwm", "", h, "KiB"])
for d in dirs(f"{src}/irr-ov*"):
    ov, arm, run = re.search(r"irr-ov([\d.]+)-(\w+)-r(\d)$", d).groups()
    if not os.path.exists(f"{d}/rows.csv"):
        continue
    for r in csv.DictReader(open(f"{d}/rows.csv")):
        if r.get("cell", "rustbgpd-sighup") not in ("rustbgpd-sighup",):
            continue
        out.writerow([f"irr-ov{ov}", NAME[arm], run, "completion_p50", r["reload"], r["completion_p50_s"], "s"])
        out.writerow([f"irr-ov{ov}", NAME[arm], run, "changed_maxgap_p50", r["reload"], r["changed_maxgap_p50_ms"], "ms"])
    p = f"{d}/rustbgpd-sighup/rss.csv"
    if os.path.exists(p):
        rss = [int(x["total_rss_kib"]) for x in csv.DictReader(open(p))]
        out.writerow([f"irr-ov{ov}", NAME[arm], run, "peak_rss_sample", "", max(rss), "KiB"])
for d in dirs(f"{src}/rr1000-*"):
    arm, c = re.search(r"rr1000-(\w+)-c(\d)$", d).groups()
    for r in (1, 2, 3):
        f = f"{d}/run-{r}/phase.json"
        if not os.path.exists(f):
            continue
        p = json.load(open(f)); w = p["resource_observer"]["wire"]
        run = f"c{c}r{r}"
        for k in ("injection_ms", "staged_ms", "wire_ms"):
            out.writerow(["rr1000", NAME[arm], run, k, "", p[k], "ms"])
        out.writerow(["rr1000", NAME[arm], run, "wire_vmrss", "", w["direct_pid_vmrss_kib"], "KiB"])
        out.writerow(["rr1000", NAME[arm], run, "wire_vmhwm", "", w["direct_pid_vmhwm_kib"], "KiB"])
w = csv.writer(open(f"{dst}/establishment-span.csv", "w"))
w.writerow(["arm", "run", "scenario", "session_established_log_lines", "first_to_700th_established_s"])
for d in dirs(f"{src}/matrix-*-r*-s*/rustbgpd"):
    if not os.path.exists(f"{d}/status") or open(f"{d}/status").read().strip() != "pass":
        continue
    arm, run, sc = re.search(r"matrix-(\w+)-r(\d)-(s\d)", d).groups()
    ts = []
    for l in open(f"{d}/daemon.log", errors="replace"):
        if '"session established"' in l:
            ts.append(datetime.fromisoformat(json.loads(l)["timestamp"].replace("Z", "+00:00")).timestamp())
    ts.sort()
    w.writerow([NAME[arm], run, sc, len(ts), f"{ts[699] - ts[0]:.3f}" if len(ts) >= 700 else ""])
