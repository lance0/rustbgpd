#!/usr/bin/env python3
"""Check archived inputs for three properties the as-run analyzer did not verify.

usage: verify-inputs.py [DIR]   (default: this file's directory)

1. Cells: schedule.txt and runs.tsv each hold exactly the unique (arm, K, rep) set
   {ctl, cand} x {1, 50} x {1, 2, 3}, with no duplicates, and raw/ holds exactly
   those cells.
2. Quiet gate: every quiet/<cell>.tsv has exactly samples 1 and 2, each with
   quiet=true, failed_dimensions=none, load1 < 2.0, no competitors, every
   governor `performance`, and equal pswpin/pswpout across the two samples taken
   at least 30 s apart. These are the defaults of bench/scale/host-quiet.sh;
   the job overrode only the gate's timeout.
3. Shape: every converged_rejoin_csv row reports peers_total 700, the cell's K
   as peers_flapped, and prefixes 400,400, matching identity.txt.

Exit 0 when every check holds, 1 otherwise (each failure is printed).
"""

import csv
import sys
from pathlib import Path

PEERS, PREFIXES = 700, 400400
ARMS, KS, REPS = ("ctl", "cand"), (1, 50), (1, 2, 3)
LOAD_MAX, MIN_SPACING_S = 2.0, 30

d = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent
want = {(a, k, r) for a in ARMS for k in KS for r in REPS}
names = {f"{a}-k{k}-rep{r}" for a, k, r in want}
bad = []


def cells(rows, source):
    got = [(a, int(k), int(r)) for a, k, r in rows]
    if len(got) != len(set(got)):
        bad.append(f"{source}: duplicate cells")
    if set(got) != want:
        bad.append(f"{source}: cells {sorted(set(got) ^ want)} differ from the expected set")


cells([line.split() for line in (d / "schedule.txt").read_text().splitlines() if line.strip()], "schedule.txt")
runs = csv.DictReader((d / "runs.tsv").read_text().splitlines(), delimiter="\t")
cells([(r["arm"], r["k"], r["rep"]) for r in runs], "runs.tsv")
if {p.name for p in (d / "raw").iterdir()} != names:
    bad.append("raw/: cell directories differ from the expected set")
if {p.stem for p in (d / "quiet").glob("*.tsv")} != names:
    bad.append("quiet/: cell files differ from the expected set")

ident = (d / "identity.txt").read_text()
if f"shape peers={PEERS} prefixes={PREFIXES} ks='1 50' repeats=3 rounds=3 " not in ident:
    bad.append("identity.txt: shape line differs")

for name in sorted(names):
    rows = list(csv.DictReader((d / "quiet" / f"{name}.tsv").read_text().splitlines(), delimiter="\t"))
    if [r["sample"] for r in rows] != ["1", "2"]:
        bad.append(f"quiet/{name}: samples {[r['sample'] for r in rows]}, need 1 and 2")
        continue
    for r in rows:
        try:
            ok = (
                r["quiet"] == "true"
                and r["failed_dimensions"] == "none"
                and float(r["load1"]) < LOAD_MAX
                and r["competitors"] == "none"
                and int(r["governor_count"]) > 0
                and int(r["performance_governors"]) == int(r["governor_count"])
                and r["governors"].split(",") == ["performance"] * int(r["governor_count"])
            )
        except (KeyError, ValueError):
            ok = False
        if not ok:
            bad.append(f"quiet/{name} sample {r['sample']}: fails the gate thresholds")
    a, b = rows
    if (a["pswpin"], a["pswpout"]) != (b["pswpin"], b["pswpout"]):
        bad.append(f"quiet/{name}: swap moved between samples")
    if int(b["epoch_s"]) - int(a["epoch_s"]) < MIN_SPACING_S:
        bad.append(f"quiet/{name}: samples under {MIN_SPACING_S} s apart")

    k = int(name.split("-k")[1].split("-")[0])
    log = (d / "raw" / name / "reloadstall.log").read_text()
    csvrows = [line.split(",")[1:] for line in log.splitlines() if line.startswith("converged_rejoin_csv,")]
    if len(csvrows) != 3:
        bad.append(f"raw/{name}: {len(csvrows)} converged_rejoin_csv rows, need 3")
    for row in csvrows:
        if (row[1], row[2], row[3]) != (str(PEERS), str(k), str(PREFIXES)):
            bad.append(f"raw/{name} round {row[0]}: peers/flapped/prefixes {row[1:4]}")

for line in bad:
    print(f"FAIL {line}")
print(f"verify-inputs: {'FAIL' if bad else 'PASS'} ({len(names)} cells checked)")
sys.exit(1 if bad else 0)
