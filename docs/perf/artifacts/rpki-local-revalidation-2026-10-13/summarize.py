#!/usr/bin/env python3
"""Summary for the second run. Derived from the r1 rediag copy (summarize-rediag.py). Changes vs r1:
  R1 (rediag, kept) refresh-accounting rows: reloadstall prints a row only for a member/family with
     received>0, after "done rss_mib=" on its only exit(0) path. Arm A still requires 2*PEERS rows;
     arm B requires the "done rss_mib=" line and <= 2*PEERS rows. Zero rows => 0 PDUs.
  R2 (rediag) reverted: cg-delta-peak.txt is required again (the r2 job writes it before the views).
  S  settle and CPU-seconds on the daemon log clock (`settle`, `cpu net`). The CPU-busy clock is
     reported only, and its window now ends at the first RTR incremental update after the injected
     one (the periodic serial query, no VRP change), which r1 counted as 30 s of settle.
  M  reject-retention size: retained identities and retained rejects from the B queue log, B-A
     steady cgroup memory per N, and that difference per retained identity (an arm difference,
     not a store measurement: the daemon exposes no store-size gauge).
  B3 /readyz window is injection .. +BUSY_WINDOW_SECS (fixed), not injection .. settle.
usage: summarize.py OUT "10 100 1000" TAIL_SECS BUSY_WINDOW_SECS DEFERRED
--- r1 docstring (bars, validity) ---
A/B summary. usage: summarize.py OUT "10 100 1000" TAIL_SECS BUSY_WINDOW_SECS DEFERRED
   self-check: summarize.py --check-baseline BASELINE_OUT   (arm-A path on the 2026-10-03 cells)

Per-cell validity (fail closed) is the validation-refresh baseline job's, split by arm:
  both: harness/daemon rc 0; same RTR session, serial +1, VRP counts unchanged; all sessions
        Established, no flaps; exactly one incremental update announced=withdrawn=N, no full
        table; one RIB re-validation mode=delta changed_routes=0; harness final sessions/parse ok;
        2*PEERS refresh-accounting rows.
  A:    one "processed validation-cache import-policy refresh" eligible=refreshed=PEERS, no
        skips/failures; refreshed counter delta == PEERS; every member/family >= 1 ROUTE-REFRESH;
        replay observed and quiet TAIL_SECS before the hold ended.
  B:    exactly one "processed validation-cache import re-evaluation" pass log.
Bars (fixed before the run; INVALID if any scheduled cell is missing/invalid):
  B1 every B cell: ROUTE-REFRESH PDUs at members == 0 and replayed NLRI == 0
  B2 every B cell: revalidated_locally delta == PEERS and fallback_refresh delta == 0
  B3 every cell of both arms: /readyz non-200 == 0 and none > 250 ms during delta..settle
  B4 per N: member-view digests (2 members x 2 families, plus every member's prefix counts)
     equal across A and B; a within-arm mismatch across repeats makes B4 INCONCLUSIVE.
Reported, not barred: settle, CPU-seconds, queued/retained/retained_rejects, cgroup
steady/per-delta peak, poll-sampled max memory.current.
"""
import datetime, json, re, statistics, sys
from pathlib import Path


def ts(s): return datetime.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def metric_sum(text, prefix):
    return sum(float(l.rsplit(" ", 1)[1]) for l in text.splitlines() if l.startswith(prefix))


def tsv(path):
    lines = path.read_text().splitlines()
    head = lines[0].split("\t")
    return [dict(zip(head, l.split("\t"))) for l in lines[1:] if l]


def kv(path):
    return dict(l.split("=", 1) for l in path.read_text().split()) if path.exists() else {}


OUTCOMES = ("eligible", "refreshed", "skipped_not_established", "skipped_state_unknown", "failed",
            "revalidated_locally", "fallback_refresh")


def cell_result(cell, arm, tail, busy_window, baseline=False):
    env = dict(l.split("=", 1) for l in (cell / "cell.env").read_text().split())
    n, peers = int(env["n"]), int(env["peers"])
    assert env["harness_rc"] == "0" and env["daemon_rc"] == "0", f"harness_rc={env['harness_rc']} daemon_rc={env['daemon_rc']}"
    read = lambda name: json.loads((cell / name).read_text())
    b = read("caches-before.json")["caches"][0]; a = read("caches-after.json")
    assert a["complete"] and len(a["caches"]) == 1, "cache list after"
    a = a["caches"][0]; ba, aa = b["accepted"], a["accepted"]
    assert a["connected"] and (aa["protocol_version"], aa["session_id"]) == (ba["protocol_version"], ba["session_id"]), "RTR session changed"
    assert aa["serial"] == (ba["serial"] + 1) & 0xffffffff, f"serial {ba['serial']} -> {aa['serial']}"
    assert (aa["vrp_v4_count"], aa["vrp_v6_count"]) == (ba["vrp_v4_count"], ba["vrp_v6_count"]), "VRP counts changed"
    nb, na = read("neighbors-before.json"), read("neighbors-after.json")
    assert len(na) == peers and all(x["state"] == "Established" for x in na), "sessions not all Established after"
    assert {x["address"]: x["flap_count"] for x in nb} == {x["address"]: x["flap_count"] for x in na}, "flap counts changed"
    lines = (cell / "daemon.log").read_text(errors="replace").splitlines()[int(env["pre_inject_log_lines"]):]
    ev = []
    for l in lines:
        if l.startswith("{"):
            try:
                j = json.loads(l); ev.append((ts(j["timestamp"]), j.get("fields", {})))
            except (ValueError, KeyError):
                pass
    upd = [(t, f) for t, f in ev if f.get("message") == "RTR incremental update received" and (f.get("vrps_announced", 0) or f.get("vrps_withdrawn", 0))]
    assert len(upd) == 1 and upd[0][1]["vrps_announced"] == upd[0][1]["vrps_withdrawn"] == n, f"incremental updates {upd}"
    t0 = upd[0][0]
    next_rtr = min((t for t, f in ev if f.get("message") == "RTR incremental update received" and t > t0), default=float("inf"))
    assert not any(f.get("message") == "RTR full table received" for _, f in ev), "full table after injection"
    rib = [(t, f) for t, f in ev if f.get("message") == "RPKI cache update re-validation complete"]
    assert len(rib) == 1 and rib[0][1]["mode"] == "delta" and rib[0][1]["changed_routes"] == 0, f"RIB revalidation {rib}"
    h = (cell / "reloadstall.log").read_text(errors="replace")
    assert f"final sessions_up {peers}/{peers} parse_errors=0" in h and "FAIL:" not in h, "harness final sessions/parse"
    acc = [tuple(map(int, x)) for x in re.findall(r"route_refresh_accounting,peer=(\d+),family=ipv[46],received=(\d+),suppressed=(\d+),completed=(\d+),sent_nlri=(\d+)", h)]
    if arm == "A":
        assert len(acc) == 2 * peers, f"refresh accounting rows {len(acc)}"
    else:
        assert "\ndone rss_mib=" in h and len(acc) <= 2 * peers, f"refresh accounting rows {len(acc)} / done line"
    mb, ma = (cell / "metrics-before.prom").read_text(), (cell / "metrics-after.prom").read_text()
    rdelta = {o: metric_sum(ma, f'bgp_validation_import_refreshes_total{{dependency="rpki",outcome="{o}"}}')
              - metric_sum(mb, f'bgp_validation_import_refreshes_total{{dependency="rpki",outcome="{o}"}}') for o in OUTCOMES}
    queued = [f for _, f in ev if f.get("message") == "RFC 9324 local import re-evaluation queued"]
    queued_t = [t for t, f in ev if f.get("message") == "RFC 9324 local import re-evaluation queued"]
    polls = [p for p in tsv(cell / "poll.tsv") if int(p["updates_received"]) >= 0]
    inj, inj_ticks, clk = float(env["inject_epoch"]), int(env["inject_ticks"]), int(env["clk_tck"])
    after = [p for p in polls if float(p["epoch"]) >= inj]
    base_upd = max((int(p["updates_received"]) for p in polls if float(p["epoch"]) < inj), default=None)
    assert base_upd is not None and after, "no polls around injection"
    last_inc = None; prev = base_upd
    for p in after:
        u = int(p["updates_received"])
        if u > prev: last_inc = float(p["epoch"])
        prev = u
    if arm == "A":
        ref = [(t, f) for t, f in ev if f.get("message") == "processed validation-cache import-policy refresh" and f.get("dependency") == "Rpki"]
        assert len(ref) == 1, f"{len(ref)} Rpki refresh passes"
        rf = ref[0][1]
        assert rf["eligible"] == rf["refreshed"] == peers and rf["skipped_not_established"] == rf["skipped_state_unknown"] == rf["failures"] == 0, f"refresh pass {rf}"
        assert rdelta["refreshed"] == peers, f"refresh counter delta {rdelta}"
        assert all(x[1] >= 1 for x in acc), "a member/family received no ROUTE-REFRESH"
        assert last_inc is not None, "no replayed UPDATE observed"
        assert float(after[-1]["epoch"]) - last_inc >= tail, "replay not quiet before the hold ended"
        log_end = max(rib[0][0], ref[0][0], last_inc)
    else:
        ref = [(t, f) for t, f in ev if f.get("message") == "processed validation-cache import re-evaluation" and f.get("dependency") == "Rpki"]
        assert len(ref) == 1, f"{len(ref)} Rpki re-evaluation passes"
        rf = ref[0][1]
        log_end = max([rib[0][0], ref[0][0]] + queued_t + ([last_inc] if last_inc else []))
    # CPU-busy clock: last poll within busy_window whose tick delta exceeds 2x idle + 2 ticks.
    idle_rate = (inj_ticks - int(env["idle_ticks"])) / clk / (inj - float(env["idle_epoch"]))
    busy_end = t0
    window = [p for p in polls if t0 - 1 <= float(p["epoch"]) <= min(t0 + busy_window, next_rtr)]
    if window and float(window[-1]["epoch"]) >= next_rtr:
        window = window[:-1]
    for p, q in zip(window, window[1:]):
        dt = float(q["epoch"]) - float(p["epoch"])
        if int(q["ticks"]) - int(p["ticks"]) > 2 * idle_rate * clk * dt + 2:
            busy_end = max(busy_end, float(q["epoch"]))
    busy_settle_end = max(log_end, busy_end)
    settle_end = log_end
    start = [p for p in polls if float(p["epoch"]) <= t0][-1]
    row = next(p for p in after if float(p["epoch"]) >= busy_settle_end)
    cpu_raw = (int(row["ticks"]) - int(start["ticks"])) / clk
    cpu_net_busy = cpu_raw - idle_rate * (float(row["epoch"]) - float(start["epoch"]))
    row_log = next(p for p in after if float(p["epoch"]) >= log_end)  # the validation-refresh baseline receipt's window
    cpu_net_log = (int(row_log["ticks"]) - int(start["ticks"])) / clk - idle_rate * (float(row_log["epoch"]) - float(start["epoch"]))
    # B3 window: injection .. +BUSY_WINDOW_SECS (50 s, before the views at +60 s). r1's window ran to its
    # RTR-inflated settle (~30 s); a fixed 50 s keeps B3 at least that strict now that settle is short.
    rdy = [r for r in tsv(cell / "readyz.tsv") if t0 <= float(r["epoch"]) <= t0 + busy_window]
    lat = [float(r["latency_ms"]) for r in rdy]
    pre, post = kv(cell / "cgroup-pre.txt"), kv(cell / "cgroup-post.txt")
    dpeak = (cell / "cg-delta-peak.txt").read_text().strip() if (cell / "cg-delta-peak.txt").exists() else None
    hpeak = (cell / "cg-hold-peak.txt").read_text().strip() if (cell / "cg-hold-peak.txt").exists() else None
    if not baseline:
        assert pre.get("swap_max") == "0" and dpeak and dpeak.isdigit(), f"cgroup evidence {pre} {dpeak}"
    views = {}
    if (cell / "views.tsv").exists():
        for l in (cell / "views.tsv").read_text().splitlines():
            peer, fam, digest, count = l.split()[:4]
            assert int(count) > 0, f"empty view {peer} {fam}"
            views[f"{peer}/{fam}"] = digest
    counts = sorted((x["address"], x["prefixes_received"], x["prefixes_sent"]) for x in na)
    return dict(arm=arm, n=n, rep=env["rep"], rtr_lag=t0 - inj, settle_log=log_end - t0, settle_cpu=busy_end - t0,
                settle=settle_end - t0, next_rtr=next_rtr - t0, reval=rib[0][0] - t0, pass_log=ref[0][0] - t0, pass_fields={k: rf.get(k) for k in
                ("eligible", "revalidated_locally", "fallback", "refreshed", "skipped_not_established", "skipped_state_unknown", "failures")},
                last_update=(last_inc - t0) if last_inc else None, cpu_raw=cpu_raw, cpu_net=cpu_net_log, cpu_net_log=cpu_net_log, cpu_net_busy=cpu_net_busy,
                idle_rate=idle_rate,
                rr_pdus=sum(x[1] for x in acc), rr_suppressed=sum(x[2] for x in acc), sent_nlri=sum(x[4] for x in acc),
                peers_refreshed=len({x[0] for x in acc if x[1] > 0}), updates=prev - base_upd, refresh_counter=rdelta,
                queued_lines=len(queued), queued=sum(f.get("queued", 0) for f in queued),
                retained=sum(f.get("retained", 0) for f in queued), retained_rejects=sum(f.get("retained_rejects", 0) for f in queued),
                ready_n=len(rdy), ready_non200=sum(r["status"] != "200" for r in rdy), ready_max_ms=max(lat, default=0.0),
                ready_over_250=sum(x > 250 for x in lat),
                cg_steady_mib=int(pre["steady_current"]) / 2**20 if pre.get("steady_current") else None,
                cg_delta_peak_mib=int(dpeak) / 2**20 if dpeak and dpeak.isdigit() else None,
                cg_hold_peak_mib=int(hpeak) / 2**20 if hpeak and hpeak.isdigit() else None,
                cg_lifetime_peak_mib=int(post["lifetime_peak"]) / 2**20 if post.get("lifetime_peak") else None,
                cg_sampled_max_mib=max((int(p["cg_current"]) for p in polls if "cg_current" in p), default=0) / 2**20 or None,
                views=views, counts_digest=hash(tuple(counts)))


med = lambda xs: statistics.median(xs) if xs else float("nan")


def fmt_med(rs, k, f="{:.2f}"):
    xs = [r[k] for r in rs if r.get(k) is not None]
    return (f.format(med(xs)) + f" [{f.format(min(xs))}-{f.format(max(xs))}]") if xs else "-"


def main(argv):
    if argv[0] == "--check-baseline":
        out = Path(argv[1])
        rs = [cell_result(c, "A", 10.0, 50.0, baseline=True) for c in sorted((out / "raw").glob("n*-rep*"))]
        s = {n: med([r["settle_log"] for r in rs if r["n"] == n]) for n in (10, 100, 1000)}
        c = {n: med([r["cpu_net"] for r in rs if r["n"] == n]) for n in (10, 100, 1000)}
        cl = {n: round(med([r["cpu_net_log"] for r in rs if r["n"] == n]), 2) for n in (10, 100, 1000)}
        print("baseline arm-A path:", {n: (round(s[n], 2), round(c[n], 2)) for n in s})
        assert len(rs) == 6 and all(r["rr_pdus"] == 1400 and r["sent_nlri"] == 400400 for r in rs)
        assert (round(s[10], 2), round(s[100], 2), round(s[1000], 2)) == (0.36, 0.24, 0.34), s
        assert cl == {10: 0.66, 100: 0.48, 1000: 0.62}, cl
        print("self-check OK: arm-A validity and baseline settle reproduce the validation-refresh baseline receipt;"
              f" cpu_net (log clock) {c} (receipt 0.66/0.48/0.62)")
        return 0
    out, deltas, tail, busy, deferred = Path(argv[0]), [int(x) for x in argv[1].split()], float(argv[2]), float(argv[3]), argv[4]
    sched = [tuple(l.split(":")) for l in (out / "schedule.txt").read_text().split()]
    results, bad = [], []
    for arm, n, rep in sched:
        cell = out / "raw" / f"{arm}-n{n}-rep{rep}"
        try:
            results.append(cell_result(cell, arm, tail, busy))
        except Exception as e:
            bad.append(f"{cell.name}: {e!r}")
    (out / "cells.json").write_text(json.dumps(results, indent=1, default=str))
    print("RFC 9324 local re-evaluation A/B, per arm x N (median [min-max] over cells; times from the daemon's RTR-incremental-update log;")
    print("  settle and cpu net on the log clock; settle_cpu/cpu net@busy end before the next periodic RTR update)")
    print(f"{'arm':3} {'N':>5} {'n':>2} {'settle s':>18} {'settle_cpu s':>18} {'cpu net s':>18} {'cpu net@busy s':>18} {'RR PDUs':>8} {'replay NLRI':>11} "
          f"{'reval_loc':>9} {'fallback':>8} {'queued':>8} {'retained':>9} {'ret_rejects':>11} {'steady MiB':>18} {'delta peak MiB':>20} {'hold peak MiB':>20} {'readyz':>14}")
    for n in deltas:
        for arm in ("A", "B"):
            rs = [r for r in results if r["n"] == n and r["arm"] == arm]
            if not rs:
                print(f"{arm:3} {n:>5}  0 no valid cell"); continue
            print(f"{arm:3} {n:>5} {len(rs):>2} {fmt_med(rs, 'settle'):>18} {fmt_med(rs, 'settle_cpu'):>18} {fmt_med(rs, 'cpu_net'):>18} {fmt_med(rs, 'cpu_net_busy'):>18} "
                  f"{med([r['rr_pdus'] for r in rs]):>8.0f} {med([r['sent_nlri'] for r in rs]):>11.0f} "
                  f"{med([r['refresh_counter']['revalidated_locally'] for r in rs]):>9.0f} {med([r['refresh_counter']['fallback_refresh'] for r in rs]):>8.0f} "
                  f"{med([r['queued'] for r in rs]):>8.0f} {med([r['retained'] for r in rs]):>9.0f} {med([r['retained_rejects'] for r in rs]):>11.0f} "
                  f"{fmt_med(rs, 'cg_steady_mib', '{:.0f}'):>18} {fmt_med(rs, 'cg_delta_peak_mib', '{:.0f}'):>20} {fmt_med(rs, 'cg_hold_peak_mib', '{:.0f}'):>20} "
                  f"{sum(r['ready_n'] for r in rs)}/{sum(r['ready_non200'] + r['ready_over_250'] for r in rs)}bad")
    a_cells = [r for r in results if r["arm"] == "A"]; b_cells = [r for r in results if r["arm"] == "B"]
    print("reject retention (B): retained identities, retained rejects, B-A steady MiB (median per arm), B-A per retained identity")
    for n in deltas:
        ra = [r for r in a_cells if r["n"] == n]; rb = [r for r in b_cells if r["n"] == n]
        if not ra or not rb:
            continue
        ret = med([r["retained"] for r in rb]); rej = med([r["retained_rejects"] for r in rb])
        dmib = med([r["cg_steady_mib"] for r in rb]) - med([r["cg_steady_mib"] for r in ra])
        print(f"  N={n:<5} retained={ret:.0f} retained_rejects={rej:.0f} ({rej / ret * 100 if ret else 0:.2f}%) "
              f"B-A steady={dmib:+.1f} MiB ({dmib * 2**20 / ret if ret else float('nan'):.0f} B/identity)")
    bars = {
        "B1 no ROUTE-REFRESH/replay in B": bool(b_cells) and all(r["rr_pdus"] == 0 and r["sent_nlri"] == 0 for r in b_cells),
        "B2 revalidated_locally=PEERS fallback=0 in B": bool(b_cells) and all(
            r["refresh_counter"]["revalidated_locally"] == 700 and r["refresh_counter"]["fallback_refresh"] == 0 for r in b_cells),
        "B3 readiness held": bool(results) and all(r["ready_non200"] == 0 and r["ready_over_250"] == 0 for r in results),
    }
    view_state, notes = True, []
    for n in deltas:
        per = {arm: [(tuple(sorted(r["views"].items())), r["counts_digest"]) for r in results if r["n"] == n and r["arm"] == arm] for arm in "AB"}
        if not per["A"] or not per["B"]:
            view_state = False; notes.append(f"N={n} views missing"); continue
        if any(len(set(v)) > 1 for v in per.values()):
            view_state = None if view_state is not False else False; notes.append(f"N={n} within-arm views differ (volatile digest?)"); continue
        if per["A"][0] != per["B"][0]:
            view_state = False; notes.append(f"N={n} A and B views differ")
    bars["B4 member views equal A vs B"] = view_state
    for k, v in bars.items():
        print(f"  {k}: {'PASS' if v else ('INCONCLUSIVE' if v is None else 'FAIL')}")
    if notes: print("  view notes: " + "; ".join(notes))
    expected = len(sched)
    if bad or len(results) != expected or deferred:
        verdict = f"INVALID ({len(results)}/{expected} valid cells{'; deferred: ' + deferred if deferred else ''})"
    elif all(v is True for v in bars.values()):
        verdict = "PASS"
    elif any(v is False for v in bars.values()):
        verdict = "FAIL (" + ", ".join(k.split()[0] for k, v in bars.items() if v is False) + ")"
    else:
        verdict = "INCONCLUSIVE (B4)"
    sa = med([r["settle"] for r in a_cells]); sb = med([r["settle"] for r in b_cells])
    ca = med([r["cpu_net"] for r in a_cells]); cb = med([r["cpu_net"] for r in b_cells])
    print(f"VERDICT={verdict}; pooled median settle A {sa:.2f}s B {sb:.2f}s, cpu net A {ca:.2f}s B {cb:.2f}s; "
          f"B retained_rejects median {med([r['retained_rejects'] for r in b_cells]):.0f}")
    for b in bad:
        print("  invalid: " + b)
    return 0 if verdict == "PASS" else (4 if verdict.startswith("INVALID") else 1)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
