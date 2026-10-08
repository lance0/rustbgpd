#!/usr/bin/env python3
"""Apply the predeclared bars (acceptance.md) to one campaign stage.

usage: analyze.py STAGE_DIR BASE_LABEL ARM_LABEL ARM_CONF

Reads STAGE_DIR/headline/summary.csv, identity.tsv and progress.txt,
STAGE_DIR/policy-stats/*/summary.json, STAGE_DIR/progress.txt and
STAGE_DIR/allocator-watch.tsv. Writes STAGE_DIR/verdict.json and verdict.md.
Exit 0 when the stage is valid (whatever the verdict), 1 when invalid.
"""
import csv
import json
import re
import statistics
import subprocess
import sys
import tempfile
from collections import defaultdict
from datetime import datetime
from pathlib import Path

root, A, B, CONF = Path(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
FLOOR_KIB = 50 * 1024  # upper end of the 30-50 MiB noise floor
MIN_N = 2
problems = []

# ---- per-leg values -------------------------------------------------------
legs = defaultdict(lambda: defaultdict(dict))  # metric -> arm -> run -> value
summary = root / 'headline' / 'summary.csv'
rows = list(csv.DictReader(summary.open())) if summary.exists() else []
if not rows:
    problems.append('headline summary.csv missing or empty')
per_round = defaultdict(list)
for r in rows:
    per_round[(r['phase'], r['metric'], r['arm'], r['run'])].append(float(r['value']))
for (phase, metric, arm, run), values in per_round.items():
    legs[f'{phase}:{metric}'][arm][run] = statistics.median(values)

ps_dir = root / 'policy-stats'
for p in sorted(ps_dir.glob('*/summary.json')) if ps_dir.exists() else []:
    m = re.fullmatch(r'(.+)-r(\d+)', p.parent.name)
    exit_file = p.parent / 'cell.exit'
    rc = exit_file.read_text().strip() if exit_file.exists() else 'missing'
    if not m or rc not in ('0', '1'):  # 2 = setup/runtime, 3 = INVALID: reported, not counted
        problems.append(f'policy-stats {p.parent.name}: cell exit {rc}, not counted')
        continue
    s = json.loads(p.read_text())
    arm, run = m.group(1), m.group(2)
    t = s['timing']['in_band']
    for metric, value in (
            ('read:in_band_external_p50_ms', t['external_ms']['p50']),
            ('read:in_band_external_max_ms', t['external_ms']['max']),
            ('read:in_band_stage_sum_max_ms', t['stage_sum_ms']['max']),
            ('read:quiescent_external_p50_ms', s['timing']['quiescent']['external_ms']['p50']),
            ('read:deadline_misses', s['deadline_misses'] + s['calls_over_2s']),
            ('read:sighup_to_complete_p50_ms', s['reload_ms']['sighup_to_complete']['p50'])):
        if value is None:  # no calls in that group: no value, not zero
            problems.append(f'policy-stats {p.parent.name}: no {metric} value')
        else:
            legs[metric][arm][run] = value

# kind: clock (disjoint ranges), memory (disjoint and median delta >= floor), read (disjoint)
PRIMARY = {
    'matrix-s2:daemon_sighup_to_complete': 'clock',
    'matrix-s2:reload_completion_p50': 'clock',
    'irr-ov0:daemon_sighup_to_complete': 'clock',
    'irr-ov0:completion_p50': 'clock',
    'matrix-s2:daemon_cg_peak': 'memory',
    'irr-ov0:irr_daemon_cg_peak': 'memory',
    'matrix-s2:settled_rss_last_sample': 'memory',
    'read:in_band_external_p50_ms': 'read',
    'read:in_band_external_max_ms': 'read',
    'read:in_band_stage_sum_max_ms': 'read',
}
SECONDARY = {
    'matrix-s2:peak_rss_sample': 'memory', 'matrix-s2:daemon_vmhwm': 'memory',
    'irr-ov0:peak_rss_sample': 'memory', 'irr-ov0:daemon_vmhwm': 'memory',
    'matrix-s2:settled_cg_current_last_sample': 'memory',
    'matrix-s2:daemon_rib_transition': 'clock', 'irr-ov0:daemon_rib_transition': 'clock',
    'matrix-s2:reload_changed_maxgap_p50': 'clock', 'irr-ov0:changed_maxgap_p50': 'clock',
    'read:quiescent_external_p50_ms': 'read', 'read:sighup_to_complete_p50_ms': 'clock',
}


def judge(metric, kind):
    a, b = list(legs[metric][A].values()), list(legs[metric][B].values())
    out = {'metric': metric, 'kind': kind, A: sorted(a), B: sorted(b)}
    if len(a) < MIN_N or len(b) < MIN_N:
        out['result'] = 'insufficient'
        return out
    ma, mb = statistics.median(a), statistics.median(b)
    out['median_delta'] = mb - ma
    better, worse = max(b) < min(a), min(b) > max(a)
    if kind == 'memory':
        better = better and ma - mb >= FLOOR_KIB
        worse = worse and mb - ma >= FLOOR_KIB
    out['result'] = 'better' if better else 'worse' if worse else 'no difference'
    return out


primary = [judge(m, k) for m, k in PRIMARY.items()]
secondary = [judge(m, k) for m, k in SECONDARY.items() if legs[m]]
misses = {arm: sum(legs['read:deadline_misses'][arm].values()) for arm in (A, B)}

# ---- validity: identical binaries, verified allocator setting per leg ------
ident = {}
idf = root / 'headline' / 'identity.tsv'
for line in idf.read_text().splitlines() if idf.exists() else []:
    f = dict(x.split('=', 1) for x in line.split('\t')[1:] if '=' in x)
    ident[line.split('\t')[0]] = f
if set(ident) != {A, B}:
    problems.append(f'identity.tsv arms {sorted(ident)}')
# Each arm builds in its own directory, and the build embeds that directory
# (generated-source paths), which reorders .rodata string merging and so the
# RIP-relative displacements that point into it. Same-length labels keep the
# layout fixed. With the base path substituted, the arms must have: the same
# size for every loaded section, a byte-identical .eh_frame (identical
# function boundaries) and .gcc_except_table, and .rodata equal as a byte
# multiset (same constants, different order).
binary_identity = {}


def sections(path):
    out = subprocess.run(['readelf', '-SW', path], capture_output=True, text=True, check=True).stdout
    found = {}
    for line in out.splitlines():
        m = re.match(r'\s*\[\s*\d+\]\s+(\S+)\s+\S+\s+([0-9a-f]+)\s+[0-9a-f]+\s+([0-9a-f]+)\s+\S+\s+(\S*)', line)
        if m and 'A' in m.group(4):
            found[m.group(1)] = int(m.group(3), 16)
    return found


def section_bytes(path, name, tmp):
    out = Path(tmp) / 'section'
    subprocess.run(['objcopy', '-O', 'binary', f'--only-section={name}', path, str(out)], check=True)
    return out.read_bytes()


def same_build(a_path, b_path):
    with tempfile.TemporaryDirectory() as tmp:
        a_sub = Path(tmp) / 'a'
        a_sub.write_bytes(a_path.read_bytes().replace(f'/trees/{A}/'.encode(), f'/trees/{B}/'.encode()))
        if a_sub.read_bytes() == b_path.read_bytes():
            return 'identical'
        if sections(str(a_sub)) != sections(str(b_path)):
            return 'loaded section sizes differ'
        for name in ('.eh_frame', '.gcc_except_table'):
            if section_bytes(str(a_sub), name, tmp) != section_bytes(str(b_path), name, tmp):
                return f'{name} differs'
        if sorted(section_bytes(str(a_sub), '.rodata', tmp)) != sorted(section_bytes(str(b_path), '.rodata', tmp)):
            return '.rodata content differs'
        return 'same layout; .rodata order differs'


if len(A) != len(B):
    problems.append(f'arm labels {A!r} and {B!r} differ in length; binaries cannot be compared')
else:
    trees = root / 'headline' / 'trees'
    for rel in ('target/release/rustbgpd', 'target/scale/reloadstall'):
        try:
            same = same_build(trees / A / rel, trees / B / rel)
        except (OSError, subprocess.CalledProcessError) as e:
            same = f'unreadable: {e}'
        binary_identity[rel] = same
        if same not in ('identical', 'same layout; .rodata order differs'):
            problems.append(f'{rel}: arms differ beyond the build-directory path ({same})')
diff_files = sorted(set(re.findall(r'^diff --git a/(\S+)', (root / 'arm.diff').read_text(), re.M)))
if diff_files != ['bench/scale/cgroup-memory.sh', 'bench/scale/reloadstall/policy_stats_cell.sh']:
    problems.append(f'arm diff touches {diff_files}')

TS = re.compile(r'^\[([^\]]+)\] (\S+) (start|rc=\S+)')
windows = {}  # leg -> [start, end]
for prog in (root / 'headline' / 'progress.txt', root / 'progress.txt'):
    for line in prog.read_text().splitlines() if prog.exists() else []:
        m = TS.match(line)
        if m:
            t = datetime.fromisoformat(m.group(1)).timestamp()
            windows.setdefault(m.group(2), [None, None])[0 if m.group(3) == 'start' else 1] = t


def leg_arm(leg):
    for arm in (A, B):
        if re.fullmatch(rf'(matrix-{arm}-r\d+-s\d|irr-ov[\d.]+-{arm}-r\d+|policy-{arm}-r\d+)', leg):
            return arm
    return None


watch = []
wf = root / 'allocator-watch.tsv'
for r in csv.DictReader(wf.open(), delimiter='\t') if wf.exists() else []:
    m = re.search(r'/trees/([^/]+)/target/release/rustbgpd$', r['exe'])
    r['arm'] = m.group(1) if m else None
    r['t'] = float(r['first_seen_epoch'])
    watch.append(r)


def expected(r, arm):
    conf, bg = r['rjem_malloc_conf'], int(r['bg_threads_max'])
    return (conf == '-' and bg == 0) if arm == A else (conf == CONF and bg > 0)


verify = {}
for leg, (start, end) in sorted(windows.items(), key=lambda kv: kv[1][0] or 0):
    arm = leg_arm(leg)
    if arm is None or start is None or end is None:
        continue
    # Leg stamps are whole seconds (date -Is); the daemon's first sighting is
    # fractional, so [start, end + 1) holds every daemon the leg started.
    inside = [r for r in watch if start <= r['t'] < end + 1 and int(r['checks']) >= 1]
    bad = [r for r in inside if r['arm'] != arm or not expected(r, arm)]
    ok = bool(inside) and not bad
    verify[leg] = {'arm': arm, 'daemons_checked': len(inside), 'ok': ok,
                   'observed': sorted({(r['rjem_malloc_conf'], int(r['bg_threads_max'])) for r in inside})}
    if not ok:
        problems.append(f'{leg}: allocator setting not verified ({verify[leg]})')
for r in watch:
    if int(r['checks']) >= 1 and r['arm'] in (A, B) and not expected(r, r['arm']):
        problems.append(f"daemon pid {r['pid']} of arm {r['arm']} ran with conf={r['rjem_malloc_conf']} bg={r['bg_threads_max']}")

# ---- verdict --------------------------------------------------------------
better = [j['metric'] for j in primary if j['result'] == 'better']
worse = [j['metric'] for j in primary if j['result'] == 'worse']
if misses[B] > misses[A]:
    worse.append(f'read:deadline_misses ({misses[B]} vs {misses[A]})')
valid = not problems
if not valid:
    verdict = 'INVALID'
elif better and not worse:
    verdict = 'WIN'
elif better and worse:
    verdict = 'MIXED'
elif worse:
    verdict = 'REGRESSION'
else:
    verdict = 'NULL'
result = {'base': A, 'arm': B, 'conf': CONF, 'verdict': verdict, 'better': better, 'worse': worse,
          'deadline_misses': misses, 'binary_identity': binary_identity, 'diff_files': diff_files,
          'problems': problems, 'primary': primary, 'secondary': secondary,
          'allocator_verification': verify}
(root / 'verdict.json').write_text(json.dumps(result, indent=2) + '\n')

UNIT = {'memory': 'MiB'}


def fmt(j):
    scale = 1024 if j['kind'] == 'memory' else 1
    vals = lambda arm: ', '.join(f'{v / scale:.1f}' if scale > 1 else f'{v:g}' for v in j[arm])
    delta = j.get('median_delta')
    d = '' if delta is None else (f'{delta / scale:+.1f}' if scale > 1 else f'{delta:+.3g}')
    return f"| `{j['metric']}` | {j['kind']} | {vals(A)} | {vals(B)} | {d} | {j['result']} |"


lines = [f'# jemalloc run-time option A/B: {A} vs {B} (`_RJEM_MALLOC_CONF={CONF}`)', '',
         f'Verdict: **{verdict}**', '',
         f'Better: {", ".join(better) or "none"}. Worse: {", ".join(worse) or "none"}.', '',
         f'Deadline misses plus calls over 2 s: {A} {misses[A]}, {B} {misses[B]}.', '',
         'Per-leg values (memory in MiB; clocks in the summary unit; read in ms).', '',
         f'| Metric | Kind | {A} | {B} | Median delta | Result |', '| --- | --- | --- | --- | --- | --- |']
lines += [fmt(j) for j in primary]
lines += ['', 'Secondary (reported, not judged):', '',
          f'| Metric | Kind | {A} | {B} | Median delta | Result |', '| --- | --- | --- | --- | --- | --- |']
lines += [fmt(j) for j in secondary]
lines += ['', 'Allocator verification per leg:', '']
lines += [f"- {leg}: {v['arm']}, {v['daemons_checked']} daemon(s), observed {v['observed']}, "
          f"{'ok' if v['ok'] else 'FAILED'}" for leg, v in verify.items()]
if problems:
    lines += ['', 'Problems:', ''] + [f'- {p}' for p in problems]
(root / 'verdict.md').write_text('\n'.join(lines) + '\n')
print('\n'.join(lines))
sys.exit(0 if valid else 1)
