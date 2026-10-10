#!/usr/bin/env python3
"""J1 analyzer: apply the bars predeclared before the converged-rejoin qualification ran.

usage: analyze_j1.py OUT_DIR
Reads OUT_DIR/{identity.txt,schedule.txt,runs.tsv,raw/*/reloadstall.log,quiet/*.tsv}.
Writes OUT_DIR/{samples.tsv,verdict.json}; prints a per-signal table and one verdict line.
Exit: 0 PASS, 1 FAIL, 4 INVALID (fails closed: any scheduled cell missing or invalid).
"""
import csv
import json
import math
import re
import statistics as st
import sys
from pathlib import Path

# ---- predeclared bars (stated in the receipt; fixed before the run) ----
K1_REL, K1_ABS_S = 0.10, 0.030          # B2: cand K_lo median <= ctl median * 1.10 + 30 ms
GAP_MED_REL, GAP_MED_ABS = 0.10, 50.0   # B3: cand gap median <= ctl median * 1.10 + 50 ms
GAP_MAX_REL, GAP_MAX_ABS = 0.10, 100.0  # B3: cand gap max <= ctl max * 1.10 + 100 ms

out = Path(sys.argv[1])
problems = []


def read(p):
    try:
        return p.read_text(errors='replace')
    except OSError:
        return None


ident = read(out / 'identity.txt') or ''
m = re.search(r'shape peers=(\d+) prefixes=(\d+) ks=\'(\d+) (\d+)\' repeats=(\d+) rounds=(\d+) '
              r'control_secs=\d+ quiet=(\d)', ident)
if not m:
    print('J1 VERDICT: INVALID (identity.txt shape line missing)')
    sys.exit(4)
peers, prefixes, klo, khi, repeats, rounds, quiet = map(int, m.groups())

sched = [tuple(l.split()) for l in (read(out / 'schedule.txt') or '').splitlines() if l.strip()]
if len(sched) != 4 * repeats:
    problems.append(f'schedule.txt has {len(sched)} cells, expected {4 * repeats}')
runs = {}
for r in csv.DictReader((read(out / 'runs.tsv') or '').splitlines(), delimiter='\t'):
    key = (r['arm'], r['k'], r['rep'])
    if key in runs:
        problems.append(f'duplicate runs.tsv row {key}')
    runs[key] = r

rows = []
for arm, k, rep in sched:
    name = f'{arm}-k{k}-rep{rep}'
    r = runs.get((arm, k, rep))
    if r is None:
        problems.append(f'{name}: not run')
        continue
    if r['harness_rc'] != '0' or r['daemon_rc'] != '0':
        problems.append(f'{name}: harness_rc={r["harness_rc"]} daemon_rc={r["daemon_rc"]}')
        continue
    if quiet:
        q = read(out / 'quiet' / f'{name}.tsv') or ''
        if not any(l.startswith('2\t') for l in q.splitlines()):
            problems.append(f'{name}: no accepted second quiet-host sample')
            continue
    log = read(out / 'raw' / name / 'reloadstall.log') or ''
    csvrows = [l.split(',')[1:] for l in log.splitlines() if l.startswith('converged_rejoin_csv,')]
    bad = None
    if len(csvrows) != rounds:
        bad = f'{len(csvrows)}/{rounds} converged_rejoin_csv rows'
    recs = []
    for c in csvrows if bad is None else []:
        try:
            rnd, total, flapped, pfx, p50, mx, gap, ready, rss, up, perr = c
            row = {'round': int(rnd), 'total': int(total), 'flapped': int(flapped), 'p50': float(p50),
                   'max': float(mx), 'gap': float(gap), 'ready': int(ready), 'rss': int(rss), 'up': int(up),
                   'perr': int(perr)}
        except ValueError:
            bad = f'unparseable row {c}'
            break
        if not (row['total'] == peers and row['flapped'] == int(k) and row['up'] == peers
                and row['perr'] == 0 and row['ready'] > 0
                and all(math.isfinite(row[x]) and row[x] >= 0 for x in ('p50', 'max', 'gap'))
                and row['p50'] <= row['max']):
            bad = f'round {rnd} fails peers/flapped/sessions_up/parse_errors/readiness/value checks: {c}'
            break
        recs.append(dict(arm=arm, k=int(k), rep=int(rep), **row))
    if bad is None and sorted(x['round'] for x in recs) != list(range(1, rounds + 1)):
        bad = f'rounds {sorted(x["round"] for x in recs)} != 1..{rounds}'
    if bad:
        problems.append(f'{name}: {bad}')
        continue
    rows += recs

with (out / 'samples.tsv').open('w') as f:
    f.write('arm\tk\trep\tround\trejoin_p50_s\trejoin_max_s\tsurvivor_maxgap_ms\treadiness_samples\trss_mib\n')
    for x in rows:
        f.write(f"{x['arm']}\t{x['k']}\t{x['rep']}\t{x['round']}\t{x['p50']}\t{x['max']}\t{x['gap']}\t{x['ready']}\t{x['rss']}\n")


def series(arm, k, key):
    return [x[key] for x in rows if x['arm'] == arm and x['k'] == k]


need = repeats * rounds
for arm in ('ctl', 'cand'):
    for k in (klo, khi):
        if len(series(arm, k, 'max')) != need:
            problems.append(f'{arm} K={k}: {len(series(arm, k, "max"))} valid rounds, need {need}')

print(f'J1 converged rejoin, {peers} peers x {prefixes} prefixes, {repeats} reps x {rounds} rounds per arm and K')
for line in ident.splitlines():
    if line.startswith(('pr_head', 'cand_commit', 'cand ', 'candidate_note')):
        print(f'candidate: {line}')
print(f'{"arm":5} {"K":>3} {"n":>3} {"rejoin_max med [min-max] s":>30} {"rejoin_p50 med s":>17} '
      f'{"gap med ms":>11} {"gap max ms":>11} {"ready":>6} {"rss med MiB":>11}')
table = {}
for k in (klo, khi):
    for arm in ('ctl', 'cand'):
        mx = series(arm, k, 'max')
        if not mx:
            print(f'{arm:5} {k:>3} {0:>3}  (no valid rounds)')
            continue
        g = series(arm, k, 'gap')
        t = {'n': len(mx), 'max_med': st.median(mx), 'max_min': min(mx), 'max_max': max(mx),
             'p50_med': st.median(series(arm, k, 'p50')), 'gap_med': st.median(g), 'gap_max': max(g),
             'ready': sum(series(arm, k, 'ready')), 'rss_med': st.median(series(arm, k, 'rss'))}
        table[f'{arm}_k{k}'] = t
        print(f'{arm:5} {k:>3} {t["n"]:>3} {t["max_med"]:>10.3f} [{t["max_min"]:.3f}-{t["max_max"]:.3f}]'
              f'{"":>4} {t["p50_med"]:>17.3f} {t["gap_med"]:>11.1f} {t["gap_max"]:>11.1f} {t["ready"]:>6} {t["rss_med"]:>11.0f}')

bars = {}
c_hi, k_hi = table.get(f'cand_k{khi}'), table.get(f'ctl_k{khi}')
c_lo, k_lo = table.get(f'cand_k{klo}'), table.get(f'ctl_k{klo}')
if c_hi and k_hi:
    ok = c_hi['max_med'] < k_hi['max_med'] and c_hi['max_max'] < k_hi['max_min']
    bars['B1'] = (ok, (f'K={khi} rejoin_max: cand median {c_hi["max_med"]:.3f}s vs ctl {k_hi["max_med"]:.3f}s; '
                       f'cand max {c_hi["max_max"]:.3f}s < ctl min {k_hi["max_min"]:.3f}s required (disjoint)'))
if c_lo and k_lo:
    lim = k_lo['max_med'] * (1 + K1_REL) + K1_ABS_S
    bars['B2'] = (c_lo['max_med'] <= lim, f'K={klo} rejoin_max: cand median {c_lo["max_med"]:.3f}s <= {lim:.3f}s')
gap_ok, gap_txt = True, []
for k in (klo, khi):
    c, b = table.get(f'cand_k{k}'), table.get(f'ctl_k{k}')
    if not (c and b):
        gap_ok = False
        continue
    lm = b['gap_med'] * (1 + GAP_MED_REL) + GAP_MED_ABS
    lx = b['gap_max'] * (1 + GAP_MAX_REL) + GAP_MAX_ABS
    gap_ok &= c['gap_med'] <= lm and c['gap_max'] <= lx
    gap_txt.append(f'K={k} cand median {c["gap_med"]:.1f} <= {lm:.1f} ms and max {c["gap_max"]:.1f} <= {lx:.1f} ms')
bars['B3'] = (gap_ok, 'survivor max gap: ' + '; '.join(gap_txt))
bars['B4'] = (all(x['ready'] > 0 for x in rows) and bool(rows),
              (f'readiness: {sum(x["ready"] for x in rows)} samples over {len(rows)} valid rounds; '
               'the harness fails a run on any non-200 or >250 ms /readyz, so harness rc 0 = zero failures'))
for b, (ok, txt) in sorted(bars.items()):
    print(f'{b} {"PASS" if ok else "FAIL"}: {txt}')
for arm in ('ctl', 'cand'):
    a, b = table.get(f'{arm}_k{khi}'), table.get(f'{arm}_k{klo}')
    if a and b:
        print(f'info: {arm} K={khi}/K={klo} median rejoin_max ratio {a["max_med"] / b["max_med"]:.2f} '
              f'(original kill bar 3x, informational)')

if problems:
    verdict = 'INVALID'
elif len(bars) == 4 and all(ok for ok, _ in bars.values()):
    verdict = 'PASS'
else:
    verdict = 'FAIL'
for p in problems:
    print(f'invalid: {p}')
json.dump({'verdict': verdict, 'problems': problems, 'table': table,
           'bars': {b: {'pass': ok, 'detail': t} for b, (ok, t) in bars.items()}},
          (out / 'verdict.json').open('w'), indent=2)
print(f'J1 VERDICT: {verdict}' + (f' ({len(problems)} validity problems)' if problems else ''))
sys.exit({'PASS': 0, 'FAIL': 1, 'INVALID': 4}[verdict])
