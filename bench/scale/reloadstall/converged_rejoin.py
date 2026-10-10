#!/usr/bin/env python3
"""Converged-rejoin A/B campaign: shape, schedule and verdict.

run-converged-rejoin.sh drives the cells; this file owns everything the
verdict depends on, so the shape, the schedule and the bars are fixed in
OUT_DIR/campaign.json before the first cell runs and the analysis reads only
that file and the cell outputs.

usage:
  converged_rejoin.py init OUT_DIR --peers N --prefixes N --ks KLO,KHI
                      --repeats N --rounds N --quiet 0|1 [--smoke]
                      [--acceptance FILE]
      Write OUT_DIR/campaign.json. FILE is a JSON object overriding any of
      the default bars below; an unknown key or a non-numeric value is
      refused.
  converged_rejoin.py schedule OUT_DIR
      Print 'ARM K REP' per cell in run order: odd repetitions run
      base-Klo head-Klo head-Khi base-Khi, even repetitions the reverse.
  converged_rejoin.py analyze OUT_DIR
      Read campaign.json, runs.tsv, quiet/*.tsv and raw/*/reloadstall.log;
      write samples.tsv and verdict.json; print a table and one verdict line.
      Exit 0 PASS, 1 FAIL, 4 INVALID (any scheduled cell missing or invalid).

Bars (head against base, per-round values pooled over the repetitions):
  B1  K_hi rejoin_max_s. high_k="improve": head median below base median and
      head max below base min (disjoint). high_k="not_worse": head median
      <= base median * (1 + rejoin_rel) + rejoin_abs_s.
  B2  K_lo rejoin_max_s: head median <= base median * (1 + rejoin_rel)
      + rejoin_abs_s.
  B3  survivor_maxgap_ms, for each K: head median <= base median *
      (1 + gap_median_rel) + gap_median_abs_ms and head max <= base max *
      (1 + gap_max_rel) + gap_max_abs_ms.

Cell validity: harness and daemon exit 0, an accepted second quiet-host
sample when the campaign is quiet-gated, and exactly ROUNDS
converged_rejoin_csv rows numbered 1..ROUNDS, each with peers_total =
PEERS, peers_flapped = K, sessions_up = PEERS, parse_errors = 0,
readiness_samples > 0 and finite non-negative timings with p50 <= max.
The harness exits non-zero on a /readyz sample that is not 200 within
250 ms, so a readiness miss makes its cell, and the verdict, INVALID.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics as st
import sys
from pathlib import Path

DEFAULT_BARS = {
    "high_k": "improve",
    "rejoin_rel": 0.10,
    "rejoin_abs_s": 0.030,
    "gap_median_rel": 0.10,
    "gap_median_abs_ms": 50.0,
    "gap_max_rel": 0.10,
    "gap_max_abs_ms": 100.0,
}
ARMS = ("base", "head")
CSV_FIELDS = ("round", "total", "flapped", "prefixes", "p50", "max", "gap", "ready", "rss", "up", "perr")


def bars_from(path: Path | None) -> dict:
    bars = dict(DEFAULT_BARS)
    if path is None:
        return bars
    override = json.loads(path.read_text())
    if not isinstance(override, dict):
        raise ValueError(f"{path}: acceptance must be a JSON object")
    for key, value in override.items():
        if key not in bars:
            raise ValueError(f"{path}: unknown bar {key!r}")
        if key == "high_k":
            if value not in ("improve", "not_worse"):
                raise ValueError(f"{path}: high_k must be 'improve' or 'not_worse'")
        elif isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
            raise ValueError(f"{path}: {key} must be a non-negative number")
        bars[key] = value
    return bars


def schedule(c: dict) -> list[tuple[str, int, int]]:
    klo, khi = c["ks"]
    order = [("base", klo), ("head", klo), ("head", khi), ("base", khi)]
    cells = []
    for rep in range(1, c["repeats"] + 1):
        for arm, k in order if rep % 2 else reversed(order):
            cells.append((arm, k, rep))
    return cells


def cmd_init(a: argparse.Namespace) -> int:
    try:
        klo, khi = (int(x) for x in a.ks.split(","))
    except ValueError:
        print(f"--ks must be two integers KLO,KHI: {a.ks}", file=sys.stderr)
        return 2
    if not 1 <= klo < khi:
        print(f"--ks needs 1 <= KLO < KHI: {a.ks}", file=sys.stderr)
        return 2
    for name in ("peers", "prefixes", "repeats", "rounds"):
        if getattr(a, name) < 1:
            print(f"--{name} must be positive", file=sys.stderr)
            return 2
    try:
        bars = bars_from(a.acceptance)
    except (OSError, ValueError) as e:
        print(f"acceptance: {e}", file=sys.stderr)
        return 2
    campaign = {"peers": a.peers, "prefixes": a.prefixes, "ks": [klo, khi], "repeats": a.repeats,
                "rounds": a.rounds, "quiet": bool(a.quiet), "smoke": a.smoke, "bars": bars}
    (a.out / "campaign.json").write_text(json.dumps(campaign, indent=2) + "\n")
    return 0


def load_campaign(out: Path) -> dict:
    c = json.loads((out / "campaign.json").read_text())
    klo, khi = c["ks"]
    if not (isinstance(klo, int) and isinstance(khi, int) and 1 <= klo < khi):
        raise ValueError(f"bad ks {c['ks']}")
    for key in ("peers", "prefixes", "repeats", "rounds"):
        if not isinstance(c[key], int) or c[key] < 1:
            raise ValueError(f"bad {key} {c[key]!r}")
    if set(c["bars"]) != set(DEFAULT_BARS):
        raise ValueError(f"bars keys {sorted(c['bars'])} differ from {sorted(DEFAULT_BARS)}")
    return c


def cmd_schedule(a: argparse.Namespace) -> int:
    for arm, k, rep in schedule(load_campaign(a.out)):
        print(arm, k, rep)
    return 0


def read(p: Path) -> str:
    try:
        return p.read_text(errors="replace")
    except OSError:
        return ""


def cell_rows(c: dict, out: Path, arm: str, k: int, rep: int) -> tuple[list[dict], str | None]:
    """The cell's per-round rows, or the reason it is invalid."""
    name = f"{arm}-k{k}-rep{rep}"
    if c["quiet"]:
        q = read(out / "quiet" / f"{name}.tsv")
        if not any(line.startswith("2\t") for line in q.splitlines()):
            return [], "no accepted second quiet-host sample"
    log = read(out / "raw" / name / "reloadstall.log")
    raw = [line.split(",")[1:] for line in log.splitlines() if line.startswith("converged_rejoin_csv,")]
    if len(raw) != c["rounds"]:
        return [], f"{len(raw)}/{c['rounds']} converged_rejoin_csv rows"
    rows = []
    for fields in raw:
        if len(fields) != len(CSV_FIELDS):
            return [], f"row has {len(fields)} fields, expected {len(CSV_FIELDS)}: {fields}"
        try:
            row = {key: (float(v) if key in ("p50", "max", "gap") else int(v)) for key, v in zip(CSV_FIELDS, fields)}
        except ValueError:
            return [], f"unparseable row {fields}"
        if not (row["total"] == c["peers"] and row["flapped"] == k and row["prefixes"] == c["prefixes"]
                and row["up"] == c["peers"] and row["perr"] == 0 and row["ready"] > 0
                and all(math.isfinite(row[x]) and row[x] >= 0 for x in ("p50", "max", "gap"))
                and row["p50"] <= row["max"]):
            return [], (f"round {row['round']} fails the peers/flapped/prefixes/sessions_up/parse_errors/"
                        f"readiness/value checks: {fields}")
        rows.append(dict(arm=arm, k=k, rep=rep, **row))
    if sorted(r["round"] for r in rows) != list(range(1, c["rounds"] + 1)):
        return [], f"rounds {sorted(r['round'] for r in rows)} != 1..{c['rounds']}"
    return rows, None


def summarize(rows: list[dict]) -> dict | None:
    if not rows:
        return None
    mx, gap = [r["max"] for r in rows], [r["gap"] for r in rows]
    return {"n": len(rows), "max_med": st.median(mx), "max_min": min(mx), "max_max": max(mx),
            "p50_med": st.median(r["p50"] for r in rows), "gap_med": st.median(gap), "gap_max": max(gap),
            "ready": sum(r["ready"] for r in rows), "rss_med": st.median(r["rss"] for r in rows)}


def not_worse(head: float, base: float, rel: float, absolute: float) -> tuple[bool, float]:
    limit = base * (1 + rel) + absolute
    return head <= limit, limit


def judge(c: dict, table: dict) -> dict:
    b = c["bars"]
    klo, khi = c["ks"]
    bars = {}
    h, s = table[f"head_k{khi}"], table[f"base_k{khi}"]
    if b["high_k"] == "improve":
        ok = h["max_med"] < s["max_med"] and h["max_max"] < s["max_min"]
        bars["B1"] = (ok, f"K={khi} rejoin_max: head median {h['max_med']:.3f}s vs base {s['max_med']:.3f}s; "
                          f"head max {h['max_max']:.3f}s < base min {s['max_min']:.3f}s required (disjoint)")
    else:
        ok, lim = not_worse(h["max_med"], s["max_med"], b["rejoin_rel"], b["rejoin_abs_s"])
        bars["B1"] = (ok, f"K={khi} rejoin_max: head median {h['max_med']:.3f}s <= {lim:.3f}s")
    h, s = table[f"head_k{klo}"], table[f"base_k{klo}"]
    ok, lim = not_worse(h["max_med"], s["max_med"], b["rejoin_rel"], b["rejoin_abs_s"])
    bars["B2"] = (ok, f"K={klo} rejoin_max: head median {h['max_med']:.3f}s <= {lim:.3f}s")
    gap_ok, text = True, []
    for k in (klo, khi):
        h, s = table[f"head_k{k}"], table[f"base_k{k}"]
        ok_med, lm = not_worse(h["gap_med"], s["gap_med"], b["gap_median_rel"], b["gap_median_abs_ms"])
        ok_max, lx = not_worse(h["gap_max"], s["gap_max"], b["gap_max_rel"], b["gap_max_abs_ms"])
        gap_ok &= ok_med and ok_max
        text.append(f"K={k} head median {h['gap_med']:.1f} <= {lm:.1f} ms and max {h['gap_max']:.1f} <= {lx:.1f} ms")
    bars["B3"] = (gap_ok, "survivor max gap: " + "; ".join(text))
    return bars


def cmd_analyze(a: argparse.Namespace) -> int:
    out = a.out
    try:
        c = load_campaign(out)
    except (OSError, ValueError, KeyError, TypeError) as e:
        print(f"VERDICT: INVALID (campaign.json: {e})")
        return 4
    klo, khi = c["ks"]
    problems = []
    runs = {}
    for r in csv.DictReader(read(out / "runs.tsv").splitlines(), delimiter="\t"):
        key = (r.get("arm"), r.get("k"), r.get("rep"))
        if key in runs:
            problems.append(f"duplicate runs.tsv row {key}")
        runs[key] = r
    rows = []
    for arm, k, rep in schedule(c):
        name = f"{arm}-k{k}-rep{rep}"
        r = runs.get((arm, str(k), str(rep)))
        if r is None:
            problems.append(f"{name}: not run")
            continue
        if r.get("harness_rc") != "0" or r.get("daemon_rc") != "0":
            problems.append(f"{name}: harness_rc={r.get('harness_rc')} daemon_rc={r.get('daemon_rc')}")
            continue
        cell, bad = cell_rows(c, out, arm, k, rep)
        if bad:
            problems.append(f"{name}: {bad}")
        rows += cell

    with (out / "samples.tsv").open("w") as f:
        f.write("arm\tk\trep\tround\trejoin_p50_s\trejoin_max_s\tsurvivor_maxgap_ms\treadiness_samples\trss_mib\n")
        for x in rows:
            f.write(f"{x['arm']}\t{x['k']}\t{x['rep']}\t{x['round']}\t{x['p50']}\t{x['max']}\t{x['gap']}\t"
                    f"{x['ready']}\t{x['rss']}\n")

    print(f"converged rejoin A/B, {c['peers']} peers x {c['prefixes']} prefixes, K={klo},{khi}, "
          f"{c['repeats']} reps x {c['rounds']} rounds per arm and K" + (" (SMOKE: not a measurement)" if c["smoke"] else ""))
    print(f'{"arm":5} {"K":>3} {"n":>3} {"rejoin_max med [min-max] s":>30} {"rejoin_p50 med s":>17} '
          f'{"gap med ms":>11} {"gap max ms":>11} {"ready":>6} {"rss med MiB":>11}')
    need = c["repeats"] * c["rounds"]
    table = {}
    for k in (klo, khi):
        for arm in ARMS:
            t = summarize([x for x in rows if x["arm"] == arm and x["k"] == k])
            if t is None:
                print(f"{arm:5} {k:>3} {0:>3}  (no valid rounds)")
            else:
                table[f"{arm}_k{k}"] = t
                print(f'{arm:5} {k:>3} {t["n"]:>3} {t["max_med"]:>10.3f} [{t["max_min"]:.3f}-{t["max_max"]:.3f}]'
                      f'{"":>4} {t["p50_med"]:>17.3f} {t["gap_med"]:>11.1f} {t["gap_max"]:>11.1f} {t["ready"]:>6} '
                      f'{t["rss_med"]:>11.0f}')
            if (t or {}).get("n", 0) != need:
                problems.append(f"{arm} K={k}: {(t or {}).get('n', 0)} valid rounds, need {need}")

    bars = judge(c, table) if len(table) == 4 else {}
    for name, (ok, text) in sorted(bars.items()):
        print(f'{name} {"PASS" if ok else "FAIL"}: {text}')
    for arm in ARMS:
        hi, lo = table.get(f"{arm}_k{khi}"), table.get(f"{arm}_k{klo}")
        if hi and lo and lo["max_med"] > 0:
            print(f"info: {arm} K={khi}/K={klo} median rejoin_max ratio {hi['max_med'] / lo['max_med']:.2f}")
    if problems:
        verdict = "INVALID"
    elif bars and all(ok for ok, _ in bars.values()):
        verdict = "PASS"
    else:
        verdict = "FAIL"
    for p in problems:
        print(f"invalid: {p}")
    (out / "verdict.json").write_text(json.dumps(
        {"verdict": verdict, "smoke": c["smoke"], "problems": problems, "table": table,
         "bars": {n: {"pass": ok, "detail": t} for n, (ok, t) in bars.items()}}, indent=2) + "\n")
    print(f"VERDICT: {verdict}" + (f" ({len(problems)} validity problems)" if problems else ""))
    return {"PASS": 0, "FAIL": 1, "INVALID": 4}[verdict]


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("init")
    i.add_argument("out", type=Path)
    for name in ("peers", "prefixes", "repeats", "rounds"):
        i.add_argument(f"--{name}", type=int, required=True)
    i.add_argument("--ks", required=True)
    i.add_argument("--quiet", type=int, choices=(0, 1), required=True)
    i.add_argument("--smoke", action="store_true")
    i.add_argument("--acceptance", type=Path)
    for name in ("schedule", "analyze"):
        sub.add_parser(name).add_argument("out", type=Path)
    a = p.parse_args(argv)
    return {"init": cmd_init, "schedule": cmd_schedule, "analyze": cmd_analyze}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
