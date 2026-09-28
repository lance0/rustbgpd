#!/usr/bin/env python3
# Adapted for publication: absolute scratch, checkout, repository and home paths
# are replaced with SCRATCH, WORKTREES, REPO, BGPERF2 and HOME. Otherwise as run.
"""bundle.py <campaign> <bundle>: sanitized compact copy of the evidence."""
import glob, os, sys
S, W = os.environ["SCRATCH"], os.environ["WORKTREES"]
src, dst = sys.argv[1], sys.argv[2]
subs = [
    (S + "/headline-v0730/campaign", "<run-root>"),
    (S + "", "<scratch>"),
    (W + "/headline-v0730-v0730", "<v0.73.0-tree>"),
    (W + "/headline-v0730-v0720", "<v0.72.0-tree>"),
    (W + "/headline-v0730-v0680", "<v0.68.0-tree>"),
    (W + "/headline-v0730-xh", "<cross-harness-tree>"),
    (os.environ["HOME"], "~"),
]
def clean(text):
    for a, b in subs:
        text = text.replace(a, b)
    return text
def copy(rel_src, rel_dst):
    p = os.path.join(src, rel_src)
    if not os.path.exists(p):
        return
    q = os.path.join(dst, rel_dst)
    os.makedirs(os.path.dirname(q), exist_ok=True)
    open(q, "w").write(clean(open(p, errors="replace").read()))
for d in sorted(glob.glob(f"{src}/matrix-*")):
    if not os.path.isdir(d):
        continue
    n = os.path.basename(d)
    for f in ("reloadstall.log", "status", "rss.csv", "vmhwm", "provenance.json"):
        copy(f"{n}/rustbgpd/{f}", f"matrix/{n}/{f}")
for d in sorted(glob.glob(f"{src}/irr-ov*")):
    if not os.path.isdir(d):
        continue
    n = os.path.basename(d)
    for f in ("COMPLETED", "rows.csv", "provenance.json", "dataset.sha256",
              "rustbgpd-sighup/rss.csv", "rustbgpd-sighup/dataset-refresh-summary.csv",
              "rustbgpd-sighup/reloadstall.log", "rustbgpd-sighup/status",
              "bird/reloadstall.log", "bird/status", "bird/rss.csv"):
        copy(f"{n}/{f}", f"irr/{n}/{f}")
for d in sorted(glob.glob(f"{src}/rr1000-*")):
    if not os.path.isdir(d):
        continue
    n = os.path.basename(d)
    copy(f"{n}/COMPLETED", f"rr1000/{n}/COMPLETED")
    for r in (1, 2, 3):
        for f in ("phase.json", "provenance.json", "rss.json"):
            copy(f"{n}/run-{r}/{f}", f"rr1000/{n}/run-{r}/{f}")
copy("progress.txt", "progress.txt")
