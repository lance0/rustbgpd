#!/usr/bin/env python3
"""phase 0 post-processing: per-run table, per-surface distributions,
paired (B-A)/A CI on cg memory.peak against the preregistered bands,
and the optional B->C bridge as its own series."""
import csv, glob, os, statistics as st

S = os.path.dirname(os.path.abspath(__file__))
MIB = 1024 * 1024
# Runs excluded from the contract set (foreign load overlap); still printed.
CONTAMINATED = set()
T95 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262}

rows = []
for log in sorted(glob.glob(os.path.join(S, "r*_*.log"))):
    run = os.path.basename(log).split("_")[0]
    side = os.path.basename(log).split("_")[1].split(".")[0]
    csv_line = None
    with open(log) as f:
        for line in f:
            if line.startswith("rustbgpd,"):
                csv_line = line.strip()
    assert csv_line, log
    c = next(csv.reader([csv_line]))
    # name,target,version,peers,pfx,required,received,monitor,elapsed,pfx_recv,
    # testers,total,maxcpu,maxmem_gib,minidle,...
    total_s = float(c[11]); maxcpu = float(c[12]); maxmem_mib = float(c[13]) * 1024
    monitor_s = int(c[7]); elapsed_s = int(c[8]); minidle = int(c[14])
    required, received = int(c[5]), int(c[6])
    cg_max = anon_max = peak_max = pt_max = pta_max = 0
    cg_last = anon_last = pt_last = pta_last = None
    with open(os.path.join(S, f"{run}_{side}.samples.tsv")) as f:
        next(f)
        for ln in f:
            p = ln.rstrip("\n").split("\t")
            if len(p) != 6 or p[1] == "NA":
                continue
            cur, anon, peak, pt, pta = int(p[1]), int(p[2]), int(p[3]), int(p[4]), int(p[5])
            cg_max = max(cg_max, cur); anon_max = max(anon_max, anon)
            peak_max = max(peak_max, peak); pt_max = max(pt_max, pt); pta_max = max(pta_max, pta)
            cg_last, anon_last, pt_last, pta_last = cur, anon, pt, pta
    rows.append(dict(run=run, side=side, pair=(int(run[1:]) + 1) // 2,
                     clean=run not in CONTAMINATED,
                     total_s=total_s, monitor_s=monitor_s, elapsed_s=elapsed_s,
                     maxcpu=maxcpu, minidle=minidle, conv=f"{received}/{required}",
                     bgperf_maxmem_mib=round(maxmem_mib, 1),
                     cg_peak_mib=round(peak_max / MIB, 1),
                     cg_cur_max_mib=round(cg_max / MIB, 1),
                     cg_anon_max_mib=round(anon_max / MIB, 1),
                     cg_anon_settled_mib=round(anon_last / MIB, 1) if anon_last else None,
                     ptree_rss_max_mib=round(pt_max / 1024, 1),
                     ptree_rss_settled_mib=round(pt_last / 1024, 1) if pt_last else None,
                     ptree_anon_settled_mib=round(pta_last / 1024, 1) if pta_last else None))

hdr = list(rows[0].keys())
print("\t".join(hdr))
for r in rows:
    print("\t".join(str(r[k]) for k in hdr))

def dist(vals):
    vals = [v for v in vals if v]
    if len(vals) < 2:
        return "n<2", None, None
    med = st.median(vals)
    txt = (f"n={len(vals)} min={min(vals):.1f} med={med:.1f} max={max(vals):.1f} "
           f"spread=(max-min)/med={100*(max(vals)-min(vals))/med:.1f}% stdev={st.stdev(vals):.2f}")
    return txt, med, max(vals) - min(vals)

SURFACES = ("bgperf_maxmem_mib", "cg_peak_mib", "cg_anon_max_mib",
            "cg_anon_settled_mib", "ptree_rss_max_mib", "ptree_rss_settled_mib",
            "ptree_anon_settled_mib", "total_s")

clean_rows = [r for r in rows if r["clean"]]
print()
meds = {}
for side in ("base", "head", "c"):
    sel = [r for r in clean_rows if r["side"] == side]
    if not sel:
        continue
    print(f"== {side} CLEAN (n={len(sel)})")
    for k in SURFACES:
        txt, med, rng = dist([r[k] for r in sel])
        meds[(side, k)] = (med, rng)
        print(f"  {k:24} {txt}")

def paired_ci(lo_side, hi_side, key, pair_pool):
    """Per-pair (hi - lo) / lo on `key`; returns (deltas_pct, mean, ci_lo, ci_hi)."""
    by_pair = {}
    for r in pair_pool:
        by_pair.setdefault(r["pair"], {})[r["side"]] = r
    deltas = []
    for p in sorted(by_pair):
        d = by_pair[p]
        if lo_side in d and hi_side in d:
            lo, hi = d[lo_side][key], d[hi_side][key]
            if lo and hi:
                deltas.append(100.0 * (hi - lo) / lo)
    if len(deltas) < 2:
        return deltas, None, None, None
    m = st.mean(deltas); sd = st.stdev(deltas)
    t = T95.get(len(deltas) - 1)
    half = t * sd / (len(deltas) ** 0.5) if t else None
    return deltas, m, (m - half) if half is not None else None, (m + half) if half is not None else None

print()
print("== PRIMARY A/B: paired (B-A)/A, clean pairs only")
for k in SURFACES:
    if k == "total_s":
        continue
    deltas, m, lo, hi = paired_ci("base", "head", k, [r for r in clean_rows if r["side"] in ("base", "head")])
    # A None CI bound must never crash or default into a band (coordinator
    # order 2026-08-14): without a CI the verdict is INCONCLUSIVE, stated.
    tag = ""
    if k == "cg_peak_mib":
        if m is None or lo is None or hi is None:
            tag = "  -> PREREGISTERED BAND: INCONCLUSIVE (insufficient clean pairs for CI)"
        elif lo > 10.0:
            tag = "  -> PREREGISTERED BAND: DAEMON-SIDE"
        elif hi < 5.0:
            tag = "  -> PREREGISTERED BAND: HARNESS-SIDE COLLAPSE"
        else:
            tag = "  -> PREREGISTERED BAND: INCONCLUSIVE"
    if m is None:
        print(f"  {k:24} n(pairs)={len(deltas)} insufficient{tag}")
        continue
    ci = f"95%CI=[{lo:+.1f}%, {hi:+.1f}%]" if lo is not None and hi is not None else "95%CI=n/a"
    print(f"  {k:24} pairs={len(deltas)} deltas%=[{', '.join(f'{d:+.1f}' for d in deltas)}] "
          f"mean={m:+.1f}% {ci}{tag}")

c_rows = [r for r in clean_rows if r["side"] in ("head", "c")]
if any(r["side"] == "c" for r in c_rows):
    print()
    print("== C ARM (separate series): paired (C-B)/B, clean pairs only")
    for k in SURFACES:
        if k == "total_s":
            continue
        deltas, m, lo, hi = paired_ci("head", "c", k, c_rows)
        if m is None:
            print(f"  {k:24} n(pairs)={len(deltas)} insufficient")
            continue
        ci = f"95%CI=[{lo:+.1f}%, {hi:+.1f}%]" if lo is not None and hi is not None else "95%CI=n/a"
        print(f"  {k:24} pairs={len(deltas)} deltas%=[{', '.join(f'{d:+.1f}' for d in deltas)}] "
              f"mean={m:+.1f}% {ci}")
    # Absolute MiB deltas on the surfaces the #1675 prediction names,
    # restricted to the C series' own pairs (never the primary A/B head runs).
    c_pairs = {r["pair"] for r in c_rows if r["side"] == "c"}
    series = [r for r in c_rows if r["pair"] in c_pairs]
    for k in ("cg_anon_settled_mib", "ptree_rss_settled_mib", "ptree_anon_settled_mib", "cg_peak_mib"):
        b = [r[k] for r in series if r["side"] == "head" and r[k]]
        cc = [r[k] for r in series if r["side"] == "c" and r[k]]
        if b and cc:
            print(f"  abs med(B)-med(C) {k:24} {st.median(b) - st.median(cc):+.1f} MiB "
                  f"(prediction: C ~= B - ~4.8 MiB on settled surfaces)")

excl = [r for r in rows if not r["clean"]]
if excl:
    print()
    print("== EXCLUDED (contaminated, corroborating-only):", ", ".join(r["run"] for r in excl))
