#!/usr/bin/env python3
"""Recompute every number quoted in the prestaged-transition-inventory receipt.

Reads only the committed CSVs next to this file, validates coverage and arm
identity, derives the fence span and BuildInventory busy time from the
per-poll rows, prints the A/B table, and exits non-zero if any quoted value
or public-claim rounding does not reproduce.
"""
import csv
import datetime
import statistics
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ORDER = ["main", "fix", "fix", "main", "main", "fix"]
DAEMON = {
    "main": "ab8a5902eb2c6c908cbd66b1dd90d7df1fc3ea580627dab2674ac5b47a365ea1",
    "fix": "ef83eae041e4301ced7a11046a12f61445399304ec89a3db68a500f7bf43b833",
}
HARNESS = "7651f049971e3c0ccb909457db1465e87305b043de6302e1cf4b80c2a80d0884"
BASE = "65aa92cc017e0905584563d9041f17f7ecdbb06c"

# metric -> (decimals, {arm: (median, min, max)}) as quoted in the receipt.
EXPECTED = {
    "prestage_ms": (0, {"main": (316, 290, 335), "fix": (448, 391, 482)}),
    "fence_ms": (1, {"main": (335.4, 318.5, 373.2), "fix": (185.6, 183.6, 210.4)}),
    "rib_ms": (1, {"main": (335.0, 318, 372), "fix": (185.0, 183, 210)}),
    "build_inventory_ms": (1, {"main": (173.2, 163.7, 220.1), "fix": (28.1, 25.9, 53.1)}),
    "build_inventory_polls": (0, {"main": (7, 7, 9), "fix": (1, 1, 1)}),
    "stall_p50_ms": (1, {"main": (364.9, 343.2, 401.6), "fix": (208.3, 198.9, 231.8)}),
    "stall_p95_ms": (1, {"main": (448.8, 389.3, 543.9), "fix": (288.6, 240.8, 382.1)}),
    "stall_max_ms": (1, {"main": (528.3, 432.3, 561.9), "fix": (370.9, 285.7, 405.3)}),
    "completion_p50_ms": (0, {"main": (857, 828, 903), "fix": (846, 776, 892)}),
    "first_generation_update_p50_ms": (0, {"main": (712, 686, 768), "fix": (700, 645, 758)}),
    "base_updates_member_median": (0, {"main": (893, 893, 893), "fix": (893, 893, 893)}),
    "base_updates_member_min": (0, {"main": (892, 892, 892), "fix": (892, 892, 892)}),
    "vmhwm_mib": (0, {"main": (567, 558, 571), "fix": (570, 559, 571)}),
}
# Per-leg medians of the four reloads (decimals 1).
EXPECTED_LEG = {
    "stall_p50_ms": {"main-1": 359.1, "main-4": 376.8, "main-5": 360.6,
                     "fix-2": 207.9, "fix-3": 211.2, "fix-6": 208.7},
    "build_inventory_ms": {"main-1": 170.3, "main-4": 171.1, "main-5": 176.5,
                           "fix-2": 27.3, "fix-3": 29.7, "fix-6": 28.1},
}
# The #2930 PR-body table read the harness's two-decimal summary lines, not
# the native CSV rows; with that rounding applied first, these cells reproduce.
PR_TABLE = {
    ("changed_maxgap_p50_ms", 1, 1): {"main": "364.9 [343.2-401.6]", "fix": "208.3 [198.9-231.8]"},
    ("changed_maxgap_p95_ms", 1, 1): {"main": "448.8 [389.3-543.9]", "fix": "288.6 [240.8-382.1]"},
    ("changed_maxgap_max_ms", 1, 1): {"main": "528.3 [432.3-561.9]", "fix": "370.9 [285.7-405.4]"},
    ("completion_p50_s", 1000, 0): {"main": "860 [830-900]", "fix": "845 [780-890]"},
}
# CHANGELOG v0.75.0 wording for #2930: "about 173 ms to 28 ms" (fenced
# inventory) and "about 365 ms to 208 ms" (per-observer stall p50).
PUBLIC = {"build_inventory_ms": (173, 28), "stall_p50_ms": (365, 208)}


def need(ok, msg):
    if not ok:
        raise SystemExit(f"FAIL: {msg}")


def read(name):
    with open(HERE / name, newline="") as fh:
        return list(csv.DictReader(fh))


def us(ts):
    t = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    return round(t.timestamp() * 1_000_000)


def main():
    legs = read("legs.csv")
    need([r["arm"] for r in sorted(legs, key=lambda r: int(r["order"]))] == ORDER, "leg order is not ABBAAB")
    for r in legs:
        need(r["leg"] == f"{r['arm']}-{r['order']}", f"leg label {r['leg']}")
        need(r["status"] == "pass" and r["daemon_exit"] == "0", f"{r['leg']} did not pass")
        need(r["source_commit"] == BASE and r["source_dirty"] == "true", f"{r['leg']} source identity")
        need(r["daemon_sha256"] == DAEMON[r["arm"]], f"{r['leg']} daemon digest")
        need(r["harness_sha256"] == HARNESS, f"{r['leg']} harness digest")
        need(r["quiet_samples"] == "2" and r["quiet_all_true"] == "true"
             and r["quiet_swap_unchanged"] == "true", f"{r['leg']} quiet samples")
        need(r["cg_swap_max"] == "0", f"{r['leg']} swap not fenced")
    leg_arm = {r["leg"]: r["arm"] for r in legs}

    reloads = read("reloads.csv")
    need(sorted((r["leg"], int(r["reload"])) for r in reloads)
         == sorted((leg, n) for leg in leg_arm for n in (1, 2, 3, 4)), "reload coverage")
    for r in reloads:
        need(r["arm"] == leg_arm[r["leg"]], "arm label")
        need(r["sessions_up"] == "700" and r["parse_errors"] == "0", "session/parse health")
        need(r["peers_changed"] == "700" and r["prefixes"] == "400400", "shape")
        need(r["rib_outcome"] == "committed" and r["members"] == "700" and r["prestaged"] == "true",
             "transition outcome")

    polls = {}
    for p in read("transition-polls.csv"):
        need(p["arm"] == leg_arm[p["leg"]], "poll arm label")
        polls.setdefault((p["leg"], int(p["reload"])), []).append(p)
    need(set(polls) == {(r["leg"], int(r["reload"])) for r in reloads}, "poll coverage")

    vals = {k: {"main": [], "fix": []} for k in EXPECTED}
    per_leg = {k: {} for k in EXPECTED_LEG}
    per_leg_all = {}
    reloads.sort(key=lambda r: (r["leg"], int(r["reload"])))
    for r in reloads:
        ps = polls[(r["leg"], int(r["reload"]))]
        need(ps[0]["phase"] == "classify", "first poll is not classify")
        need(ps[-1]["phase"] == "commit_members" and ps[-1]["terminal"] == "true", "last poll is not commit")
        need(sum(p["terminal"] == "true" for p in ps) == 1, "exactly one terminal poll")
        start = us(ps[0]["timestamp"]) - int(ps[0]["poll_us"])
        fence = (us(ps[-1]["timestamp"]) - start) / 1000
        bi = [int(p["poll_us"]) for p in ps if p["phase"] == "build_inventory"]
        row = {
            "prestage_ms": float(r["prestage_ms"]),
            "fence_ms": fence,
            "rib_ms": float(r["rib_ms"]),
            "build_inventory_ms": sum(bi) / 1000,
            "build_inventory_polls": len(bi),
            "stall_p50_ms": float(r["changed_maxgap_p50_ms"]),
            "stall_p95_ms": float(r["changed_maxgap_p95_ms"]),
            "stall_max_ms": float(r["changed_maxgap_max_ms"]),
            "completion_p50_ms": float(r["completion_p50_s"]) * 1000,
            "first_generation_update_p50_ms": float(r["changed_first_generation_update_p50_ms"]),
            "base_updates_member_median": float(r["base_updates_member_median"]),
            "base_updates_member_min": float(r["base_updates_member_min"]),
        }
        for k, v in row.items():
            vals[k][r["arm"]].append(v)
        for k in EXPECTED_LEG:
            per_leg[k].setdefault(r["leg"], []).append(row[k])
        for k in ("fence_ms", "build_inventory_ms"):
            per_leg_all.setdefault(r["leg"], {}).setdefault(k, []).append(row[k])
    for r in legs:
        vals["vmhwm_mib"][r["arm"]].append(int(r["vmhwm_kib"]) / 1024)

    bad = []
    # Receipt text: each main leg's first reload holds its highest fence span
    # and BuildInventory time.
    for leg, arm in leg_arm.items():
        if arm != "main":
            continue
        for k in ("fence_ms", "build_inventory_ms"):
            series = per_leg_all[leg][k]
            if series.index(max(series)) != 0:
                bad.append(f"{leg} {k}: maximum is not reload 1")
    print("| metric, median [range] | main | fix |")
    print("| -- | -- | -- |")
    for k, (p, exp) in EXPECTED.items():
        cells = []
        for arm in ("main", "fix"):
            v = vals[k][arm]
            need(len(v) == (3 if k == "vmhwm_mib" else 12), f"{k} {arm} count")
            got = tuple(round(x, p) for x in (statistics.median(v), min(v), max(v)))
            if got != tuple(round(x, p) for x in exp[arm]):
                bad.append(f"{k} {arm}: got {got} expected {exp[arm]}")
            cells.append(f"{got[0]:.{p}f} [{got[1]:.{p}f}-{got[2]:.{p}f}]")
        print(f"| {k} | {cells[0]} | {cells[1]} |")
    print()
    for k, exp in EXPECTED_LEG.items():
        got = {leg: round(statistics.median(v), 1) for leg, v in per_leg[k].items()}
        print(f"per-leg median {k}: {got}")
        if got != exp:
            bad.append(f"per-leg {k}: got {got} expected {exp}")
    for (col, scale, p), exp in PR_TABLE.items():
        for arm in ("main", "fix"):
            v = [round(float(r[col]), 2) * scale for r in reloads if r["arm"] == arm]
            got = f"{statistics.median(v):.{p}f} [{min(v):.{p}f}-{max(v):.{p}f}]"
            print(f"PR-table {col} {arm}: {got}")
            if got != exp[arm]:
                bad.append(f"PR-table {col} {arm}: got {got} expected {exp[arm]}")
    # Receipt text: median shifts, full separation and quiet-sample loads.
    med = {k: {a: statistics.median(v[a]) for a in v} for k, v in vals.items()}
    shifts = {k: round(abs(med[k]["main"] - med[k]["fix"])) for k in
              ("prestage_ms", "completion_p50_ms", "first_generation_update_p50_ms")}
    print(f"median shifts (ms): {shifts}")
    if shifts != {"prestage_ms": 132, "completion_p50_ms": 11, "first_generation_update_p50_ms": 12}:
        bad.append(f"median shifts {shifts}")
    for k in ("fence_ms", "build_inventory_ms", "stall_p50_ms"):
        if not min(vals[k]["main"]) > max(vals[k]["fix"]):
            bad.append(f"{k}: arm ranges overlap")
    loads = [float(x) for r in legs for x in r["quiet_load1"].split()]
    if (min(loads), max(loads)) != (1.09, 1.87):
        bad.append(f"quiet load range {(min(loads), max(loads))}")
    for k, (m, f) in PUBLIC.items():
        got = tuple(round(statistics.median(vals[k][arm])) for arm in ("main", "fix"))
        print(f"public claim {k}: about {got[0]} ms to {got[1]} ms")
        if got != (m, f):
            bad.append(f"public {k}: got {got} expected {(m, f)}")
    if bad:
        print("\n".join(bad), file=sys.stderr)
        return 1
    print("ok: all quoted values reproduce")
    return 0


if __name__ == "__main__":
    sys.exit(main())
