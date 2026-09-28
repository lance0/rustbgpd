#!/usr/bin/env python3
# Adapted for publication: absolute scratch, checkout, repository and home paths
# are replaced with SCRATCH, WORKTREES, REPO, BGPERF2 and HOME. Otherwise as run.
"""daemon_reload.py <campaign> <out.csv>: per-reload intervals from the daemon's
own JSON log: SIGHUP received -> config source loaded, -> config reload complete,
plus the logged validate_ms and cohort_rib_transition_us fields."""
import csv, glob, json, re, sys
from datetime import datetime
NAME = {"v0730": "v0.73.0", "v0720": "v0.72.0", "v0680": "v0.68.0", "xh": "v0.68.0-daemon/v0.72.0-harness"}
w = csv.writer(open(sys.argv[2], "w"))
w.writerow(["cell", "arm", "run", "reload", "sighup_to_loaded_ms", "sighup_to_complete_ms", "validate_ms", "rib_transition_ms"])
ts = lambda d: datetime.fromisoformat(d["timestamp"].replace("Z", "+00:00")).timestamp()
logs = [(f, "irr-ov0", re.search(r"irr-ov0-(\w+)-r(\d)/", f).groups()) for f in sorted(glob.glob(f"{sys.argv[1]}/irr-ov0-*/rustbgpd-sighup/daemon.log"))]
logs += [(f, "matrix-s2", re.search(r"matrix-(\w+)-r(\d)-s2/", f).groups()) for f in sorted(glob.glob(f"{sys.argv[1]}/matrix-*-s2/rustbgpd/daemon.log"))]
for f, cell, (arm, run) in logs:
    n = 0; t0 = loaded = None; val = rib = None
    for line in open(f, errors="replace"):
        if "SIGHUP received" not in line and "config source loaded" not in line and "config reload complete" not in line and "reload generation phase timing" not in line:
            continue
        try:
            d = json.loads(line)
        except ValueError:
            continue
        m = d["fields"].get("message", "")
        if m.startswith("SIGHUP received"):
            n += 1; t0 = ts(d); loaded = None; val = rib = None
        elif m == "config source loaded" and t0:
            loaded = ts(d); val = d["fields"].get("validate_ms")
        elif m == "reload generation phase timing" and t0:
            rib = d["fields"].get("cohort_rib_transition_us")
        elif m.startswith("config reload complete") and t0:
            w.writerow([cell, NAME[arm], run, n, round((loaded - t0) * 1000, 1) if loaded else "",
                        round((ts(d) - t0) * 1000, 1), val, round(rib / 1000, 1) if rib else ""])
            t0 = None
