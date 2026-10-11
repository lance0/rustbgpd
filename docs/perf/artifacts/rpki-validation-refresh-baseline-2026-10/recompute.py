#!/usr/bin/env python3
"""Recompute the RPKI validation-refresh baseline receipt from its compact artifacts.

Re-runs every per-cell validity check from the original job's analysis, rebuilds each
cell row, requires the rows to equal the retained `cells.json`, and prints the per-N
medians published in the receipt. Exits non-zero on any failed check or mismatch.
"""

import datetime
import json
import re
import statistics
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TAIL_SECS = 10.0
# Published medians per N: settle, revalidation, refresh pass, last UPDATE, net CPU, raw CPU, RTR lag.
PUBLISHED = {
    10: (0.36, 0.16, 0.19, 0.36, 0.66, 0.74, 2.53),
    100: (0.24, 0.16, 0.19, 0.24, 0.48, 0.53, 2.52),
    1000: (0.34, 0.20, 0.18, 0.34, 0.62, 0.69, 2.43),
}


def ts(s):
    return datetime.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def metric_sum(text, prefix):
    return sum(float(l.rsplit(" ", 1)[1]) for l in text.splitlines() if l.startswith(prefix))


def tsv(path):
    lines = path.read_text().splitlines()
    head = lines[0].split("\t")
    return [dict(zip(head, l.split("\t"))) for l in lines[1:] if l]


def cell_row(cell):
    env = dict(l.split("=", 1) for l in (cell / "cell.env").read_text().split())
    n, peers = int(env["n"]), int(env["peers"])
    assert env["harness_rc"] == "0" and env["daemon_rc"] == "0", "harness or daemon exit code"
    read = lambda name: json.loads((cell / name).read_text())
    b = read("caches-before.json")["caches"][0]
    a = read("caches-after.json")
    assert a["complete"] and len(a["caches"]) == 1, "cache list after"
    a = a["caches"][0]
    ba, aa = b["accepted"], a["accepted"]
    assert a["connected"] and (aa["protocol_version"], aa["session_id"]) == (ba["protocol_version"], ba["session_id"]), "RTR session changed"
    assert aa["serial"] == (ba["serial"] + 1) & 0xFFFFFFFF, "serial did not advance by one"
    assert (aa["vrp_v4_count"], aa["vrp_v6_count"]) == (ba["vrp_v4_count"], ba["vrp_v6_count"]), "VRP counts changed"
    nb, na = tsv(cell / "neighbors-before.tsv"), tsv(cell / "neighbors-after.tsv")
    assert len(na) == peers and all(x["state"] == "Established" for x in na), "sessions not all Established after"
    assert {x["address"]: x["flap_count"] for x in nb} == {x["address"]: x["flap_count"] for x in na}, "flap counts changed"
    ev = []
    for l in (cell / "daemon-events.jsonl").read_text().splitlines():
        j = json.loads(l)
        ev.append((ts(j["timestamp"]), j["fields"]))
    upd = [(t, f) for t, f in ev if f["message"] == "RTR incremental update received" and (f.get("vrps_announced", 0) or f.get("vrps_withdrawn", 0))]
    assert len(upd) == 1 and upd[0][1]["vrps_announced"] == upd[0][1]["vrps_withdrawn"] == n, "incremental update"
    t0 = upd[0][0]
    assert not any(f["message"] == "RTR full table received" for _, f in ev), "full table after injection"
    rib = [(t, f) for t, f in ev if f["message"] == "RPKI cache update re-validation complete"]
    assert len(rib) == 1 and rib[0][1]["mode"] == "delta" and rib[0][1]["changed_routes"] == 0, "RIB revalidation"
    ref = [(t, f) for t, f in ev if f["message"] == "processed validation-cache import-policy refresh" and f.get("dependency") == "Rpki"]
    assert len(ref) == 1, "Rpki refresh passes"
    rf = ref[0][1]
    assert rf["eligible"] == rf["refreshed"] == peers and rf["skipped_not_established"] == rf["skipped_state_unknown"] == rf["failures"] == 0, "refresh pass"
    h = (cell / "reloadstall.log").read_text()
    assert f"final sessions_up {peers}/{peers} parse_errors=0" in h and "FAIL:" not in h, "harness final sessions/parse"
    acc = [tuple(map(int, x)) for x in re.findall(
        r"route_refresh_accounting,peer=(\d+),family=ipv[46],received=(\d+),suppressed=(\d+),completed=(\d+),sent_nlri=(\d+)", h)]
    assert len(acc) == 2 * peers and all(x[1] >= 1 for x in acc), "refresh accounting rows"
    mb, ma = (cell / "refresh-counter-before.prom").read_text(), (cell / "refresh-counter-after.prom").read_text()
    rdelta = {o: metric_sum(ma, f'bgp_validation_import_refreshes_total{{dependency="rpki",outcome="{o}"}}')
              - metric_sum(mb, f'bgp_validation_import_refreshes_total{{dependency="rpki",outcome="{o}"}}')
              for o in ("eligible", "refreshed", "skipped_not_established", "skipped_state_unknown", "failed")}
    assert rdelta["refreshed"] == peers, "refresh counter delta"
    polls = [p for p in tsv(cell / "poll.tsv") if int(p["updates_received"]) >= 0]
    inj, inj_ticks, clk = float(env["inject_epoch"]), int(env["inject_ticks"]), int(env["clk_tck"])
    after = [p for p in polls if float(p["epoch"]) >= inj]
    base_upd = max((int(p["updates_received"]) for p in polls if float(p["epoch"]) < inj), default=None)
    assert base_upd is not None and after, "no polls around injection"
    last_inc, prev = None, base_upd
    for p in after:
        u = int(p["updates_received"])
        if u > prev:
            last_inc = float(p["epoch"])
        prev = u
    assert last_inc is not None, "no replayed UPDATE observed"
    assert float(after[-1]["epoch"]) - last_inc >= TAIL_SECS, "replay not quiet before the hold ended"
    settle_end = max(rib[0][0], ref[0][0], last_inc)
    start = [p for p in polls if float(p["epoch"]) <= t0][-1]
    row = next(p for p in after if float(p["epoch"]) >= settle_end)
    cpu_raw = (int(row["ticks"]) - int(start["ticks"])) / clk
    idle_rate = (inj_ticks - int(env["idle_ticks"])) / clk / (inj - float(env["idle_epoch"]))
    cpu_net = cpu_raw - idle_rate * (float(row["epoch"]) - float(start["epoch"]))
    rdy = [r for r in tsv(cell / "readyz.tsv") if t0 <= float(r["epoch"]) <= settle_end]
    lat = [float(r["latency_ms"]) for r in rdy]
    return dict(n=n, rep=env["rep"], rtr_lag=t0 - inj, settle=settle_end - t0, reval=rib[0][0] - t0,
                refresh_pass=ref[0][0] - t0, last_update=last_inc - t0, cpu_raw=cpu_raw, cpu_net=cpu_net,
                idle_rate=idle_rate, rr_pdus=sum(x[1] for x in acc), rr_suppressed=sum(x[2] for x in acc),
                rr_completed=sum(x[3] for x in acc), sent_nlri=sum(x[4] for x in acc),
                peers_refreshed=len({x[0] for x in acc if x[1] > 0}), updates=prev - base_upd,
                refresh_counter=rdelta, revalidated=rib[0][1].get("routes_revalidated"),
                rib_elapsed_ms=rib[0][1].get("elapsed_ms"), ready_n=len(rdy),
                ready_non200=sum(r["status"] != "200" for r in rdy), ready_max_ms=max(lat, default=0.0),
                ready_over_250=sum(x > 250 for x in lat))


def main():
    errors = []
    rows = []
    for cell in sorted((HERE / "cells").glob("n*-rep*")):
        try:
            rows.append(cell_row(cell))
        except AssertionError as e:
            errors.append(f"{cell.name}: {e}")
    retained = json.loads((HERE / "cells.json").read_text())
    if rows != retained:
        errors.append("recomputed cell rows differ from cells.json")
    print("N  cells  settle  reval  refresh  last-UPDATE  cpu-net  cpu-raw  rtr-lag  ROUTE-REFRESH  NLRI  UPDATEs  readyz max ms")
    for n, want in PUBLISHED.items():
        rs = [r for r in rows if r["n"] == n]
        if not rs:
            errors.append(f"N={n}: no valid cell")
            continue
        got = tuple(round(statistics.median(r[k] for r in rs), 2) for k in
                    ("settle", "reval", "refresh_pass", "last_update", "cpu_net", "cpu_raw", "rtr_lag"))
        burden = {(r["rr_pdus"], r["rr_suppressed"], r["sent_nlri"], r["updates"], r["peers_refreshed"]) for r in rs}
        print(f"{n:<4} {len(rs)}  " + "  ".join(f"{x:.2f}" for x in got)
              + f"  {burden}  {max(r['ready_max_ms'] for r in rs):.1f}")
        if got != want:
            errors.append(f"N={n}: medians {got} differ from published {want}")
        if burden != {(1400, 0, 400400, 1400, 700)}:
            errors.append(f"N={n}: member burden {burden}")
        if not (got[0] < 1 and got[4] < 1):
            errors.append(f"N={n}: decline bar not met")
        if any(r["ready_non200"] or r["ready_over_250"] for r in rs):
            errors.append(f"N={n}: readiness sample failed or exceeded 250 ms")
    for e in errors:
        print("FAIL:", e, file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
