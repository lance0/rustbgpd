#!/usr/bin/env python3
"""J2 (policy-transition attribution, Q1-Q4) analyzer: apply the bars predeclared in ACCEPTANCE-J2.md.

usage: analyze_j2.py OUT_DIR
Reads OUT_DIR/j2-identity.txt (the requested Qs), q1/*/summary.json, q2/summary.csv + q2.exit,
q3/<arm>/rustbgpd/{status,daemon.exit,daemon.log}, q4/*/summary.json, j2-progress.txt.
Prints a per-signal table and a PASS/FAIL/INVALID (or SKIPPED) verdict per Q; writes j2-verdict.json.
Exit: 0 every requested Q PASS or SKIPPED (Q4 only), 1 any FAIL, 4 any INVALID.
"""
import csv
import json
import re
import statistics as st
import sys
from collections import defaultdict
from pathlib import Path

# ---- predeclared bars (ACCEPTANCE-J2.md; change both together, before the run) ----
Q1_ARMS, Q1_RUNS = ('pre2952', 'post2952'), 2
Q1_BANDS = {'pre2952': (170, 230), 'post2952': (45, 60)}   # scout prediction, reported only
Q2_FLOOR_KIB = 50 * 1024                                    # upper end of the 30-50 MiB noise floor
Q2_RUNS = 3
Q2_PRIMARY = {
    'matrix-s2:daemon_rib_transition': 'clock', 'matrix-s2:daemon_sighup_to_complete': 'clock',
    'matrix-s2:reload_completion_p50': 'clock', 'matrix-s2:daemon_cg_peak': 'memory',
    'irr-ov0:daemon_rib_transition': 'clock', 'irr-ov0:daemon_sighup_to_complete': 'clock',
    'irr-ov0:completion_p50': 'clock', 'irr-ov0:irr_daemon_cg_peak': 'memory',
}
Q3_ARMS = ('pre2952', 'post2952')
Q3_REL, Q3_ABS_MS = 0.10, 20.0     # cohort_rib_transition medians equal within max(10%, 20 ms)
Q4_BAND = (525, 641)               # v0.73.0 RIB elapsed median: 583 ms +/- 10 %

out = Path(sys.argv[1])
ident = (out / 'j2-identity.txt').read_text() if (out / 'j2-identity.txt').exists() else ''
m = re.search(r"qs='([^']*)'", ident)
QS = m.group(1).split() if m else ['q1', 'q2', 'q3', 'q4']
progress = (out / 'j2-progress.txt').read_text() if (out / 'j2-progress.txt').exists() else ''
results = {}


def rng(v):
    return f'{st.median(v):8.1f} [{min(v):.1f}-{max(v):.1f}] n={len(v)}' if v else '   (none)'


def policy_runs(qdir, arm, runs, problems):
    """Per-reload values from policy_stats_cell runs; validity per run."""
    pooled = defaultdict(list)
    for r in range(1, runs + 1):
        d = qdir / f'{arm}-r{r}'
        name = f'{qdir.name}/{d.name}'
        try:
            cell = (d / 'cell.exit').read_text().strip()
            eng = (d / 'engine.exit').read_text().strip()
            dae = (d / 'daemon.exit').read_text().strip()
            s = json.loads((d / 'summary.json').read_text())
            env = json.loads((d / 'environment.json').read_text())
        except (OSError, ValueError) as e:
            problems.append(f'{name}: missing/unreadable artefact ({e.__class__.__name__}: {e})')
            continue
        if eng != '0' or dae != '0' or cell not in ('0', '1', '3'):
            problems.append(f'{name}: engine.exit={eng} daemon.exit={dae} cell.exit={cell}')
            continue
        want = env['shape']['reloads']
        rl = s.get('reloads') or []
        vals = defaultdict(list)
        bad = None if len(rl) == want else f'{len(rl)}/{want} reloads'
        for x in rl if bad is None else []:
            rt, pt = x.get('rib_transition') or {}, x.get('phase_timing') or {}
            try:
                if rt.get('outcome') != 'committed':
                    raise ValueError(f'reload {x.get("reload")} RIB outcome {rt.get("outcome")}')
                vals['rib_elapsed_ms'].append(float(rt['elapsed_ms']))
                vals['cohort_rib_transition_ms'].append(float(pt['cohort_rib_transition_us']) / 1000)
                vals['sighup_to_complete_ms'].append(float(x['sighup_to_complete_ms']))
            except (KeyError, TypeError, ValueError) as e:
                bad = f'reload {x.get("reload")}: {e}'
                break
        if bad:
            problems.append(f'{name}: {bad}')
            continue
        print(f'  {name:22} cell.exit={cell} rib_elapsed_ms {rng(vals["rib_elapsed_ms"])}')
        for k, v in vals.items():
            pooled[k] += v
    return pooled


def verdict_of(problems, ok):
    return 'INVALID' if problems else ('PASS' if ok else 'FAIL')


# ---------------------------------------------------------------- Q1
if 'q1' in QS:
    print('== Q1 policy-stats cell: #2952 step at 1000 x 400k (pooled per-reload values, both runs) ==')
    probs, pooled = [], {}
    for arm in Q1_ARMS:
        pooled[arm] = policy_runs(out / 'q1', arm, Q1_RUNS, probs)
    for k in ('rib_elapsed_ms', 'cohort_rib_transition_ms', 'sighup_to_complete_ms'):
        for arm in Q1_ARMS:
            print(f'  {k:26} {arm:9} {rng(pooled[arm].get(k, []))}')
    pre, post = pooled['pre2952'].get('rib_elapsed_ms', []), pooled['post2952'].get('rib_elapsed_ms', [])
    ok = bool(pre and post) and max(post) < min(pre)
    for arm in Q1_ARMS:
        v = pooled[arm].get('rib_elapsed_ms', [])
        lo, hi = Q1_BANDS[arm]
        if v:
            print(f'  info: {arm} median {st.median(v):.1f} ms {"inside" if lo <= st.median(v) <= hi else "OUTSIDE"} predicted {lo}-{hi} ms')
    print(f'  bar: post2952 max RIB elapsed < pre2952 min (disjoint) -> {"met" if ok else "NOT met (arms overlap: bisect v0.73.0..v0.75.0 on this cell next)"}')
    results['q1'] = (verdict_of(probs, ok), probs)

# ---------------------------------------------------------------- Q2
if 'q2' in QS:
    print('== Q2 headline S2 + IRR ov0: main (591ac39d4) vs v0.75.0, per-leg medians ==')
    probs = []
    ex = (out / 'q2.exit').read_text().strip() if (out / 'q2.exit').exists() else 'missing'
    if ex != '0':
        probs.append(f'q2 campaign exit {ex}')
    legs = defaultdict(lambda: defaultdict(dict))
    try:
        rows = list(csv.DictReader((out / 'q2' / 'summary.csv').open()))
    except OSError:
        rows = []
        probs.append('q2/summary.csv missing')
    per = defaultdict(list)
    for r in rows:
        per[(r['phase'], r['metric'], r['arm'], r['run'])].append(float(r['value']))
    for (ph, me, arm, run), v in per.items():
        legs[f'{ph}:{me}'][arm][run] = st.median(v)
    worse, s2_better = [], False
    for metric, kind in Q2_PRIMARY.items():
        a, b = list(legs[metric]['v075'].values()), list(legs[metric]['main'].values())
        if len(a) != Q2_RUNS or len(b) != Q2_RUNS:
            probs.append(f'{metric}: legs v075={len(a)} main={len(b)}, need {Q2_RUNS} each')
            print(f'  {metric:38} insufficient')
            continue
        ma, mb = st.median(a), st.median(b)
        better, wrs = max(b) < min(a), min(b) > max(a)
        if kind == 'memory':
            better, wrs = better and ma - mb >= Q2_FLOOR_KIB, wrs and mb - ma >= Q2_FLOOR_KIB
        res = 'better' if better else 'worse' if wrs else 'no difference'
        if wrs:
            worse.append(metric)
        if metric == 'matrix-s2:daemon_rib_transition':
            s2_better = better
        print(f'  {metric:38} v075 {ma:10.1f} [{min(a):.1f}-{max(a):.1f}]  main {mb:10.1f} [{min(b):.1f}-{max(b):.1f}]  '
              f'delta {mb - ma:+.1f}  {res}')
    print('  bar: S2 RIB transition better on main (disjoint) and no primary metric worse '
          f'-> s2_better={s2_better} worse={worse or "none"}')
    results['q2'] = (verdict_of(probs, s2_better and not worse), probs)

# ---------------------------------------------------------------- Q3
if 'q3' in QS:
    print('== Q3 S2 filtering discriminator (GEN/RELOADSTALL_FILTER_COUNT=64) ==')
    probs, cohort, committed = [], {}, 0
    for arm in Q3_ARMS:
        d = out / 'q3' / arm / 'rustbgpd'
        try:
            status = (d / 'status').read_text().strip()
            dae = (d / 'daemon.exit').read_text().strip()
            lines = [json.loads(l) for l in (d / 'daemon.log').read_text(errors='replace').splitlines()
                     if l.startswith('{')]
            reloads = int(json.loads((d / 'provenance.json').read_text())['workload']['inputs']['RELOADS'])
        except (OSError, ValueError, KeyError) as e:
            probs.append(f'q3/{arm}: missing/unreadable artefact ({e})')
            continue
        if status != 'pass' or dae != '0':
            probs.append(f'q3/{arm}: status={status} daemon.exit={dae}')
            continue
        fields = [x.get('fields', {}) for x in lines]
        rib = [f for f in fields if f.get('message') == 'RIB export-policy transition completed']
        pt = [f for f in fields if f.get('message') == 'reload generation phase timing']
        if len(pt) != reloads:
            probs.append(f'q3/{arm}: {len(pt)} phase-timing lines, expected {reloads}')
            continue
        outcomes = defaultdict(int)
        for f in rib:
            outcomes[f.get('outcome')] += 1
        committed += outcomes.get('committed', 0)
        cohort[arm] = [float(f['cohort_rib_transition_us']) / 1000 for f in pt]
        fb = sum(1 for f in pt if f.get('authoritative_fallback'))
        print(f'  {arm:9} RIB outcomes {dict(outcomes)}  authoritative_fallback {fb}/{len(pt)}  '
              f'cohort_rib_transition_ms {rng(cohort[arm])}  total_ms {rng([float(f["total_us"]) / 1000 for f in pt])}')
    ok = False
    if len(cohort) == 2:
        a, b = st.median(cohort['pre2952']), st.median(cohort['post2952'])
        tol = max(Q3_REL * a, Q3_ABS_MS)
        ok = committed == 0 and abs(b - a) <= tol
        print(f'  bar: zero committed fast-path transitions (got {committed}) and |post-pre| cohort median '
              f'{abs(b - a):.1f} <= {tol:.1f} ms')
        if committed:
            print('  NOTE: a committed transition under filtering contradicts the scout code reading; stop and re-read')
    results['q3'] = (verdict_of(probs, ok), probs)

# ---------------------------------------------------------------- Q4
if 'q4' in QS:
    print('== Q4 policy-stats cell at v0.73.0 (1 run) ==')
    if 'q4 skipped' in progress:
        print('  skipped (past Q4_NOT_AFTER)')
        results['q4'] = ('SKIPPED', [])
    else:
        probs = []
        p = policy_runs(out / 'q4', 'v073', 1, probs)
        v = p.get('rib_elapsed_ms', [])
        ok = bool(v) and Q4_BAND[0] <= st.median(v) <= Q4_BAND[1]
        for k in ('rib_elapsed_ms', 'cohort_rib_transition_ms', 'sighup_to_complete_ms'):
            print(f'  {k:26} v073      {rng(p.get(k, []))}')
        print(f'  bar: median RIB elapsed in {Q4_BAND[0]}-{Q4_BAND[1]} ms (reproduces ~583 ms) -> {"met" if ok else "NOT met"}')
        results['q4'] = (verdict_of(probs, ok), probs)

for q in QS:
    v, probs = results.get(q, ('INVALID', ['not analysed']))
    for p in probs:
        print(f'  invalid {q}: {p}')
    print(f'{q.upper()} VERDICT: {v}')
json.dump({q: {'verdict': v, 'problems': p} for q, (v, p) in results.items()},
          (out / 'j2-verdict.json').open('w'), indent=2)
vs = [results.get(q, ('INVALID',))[0] for q in QS]
sys.exit(4 if 'INVALID' in vs else 1 if 'FAIL' in vs else 0)
