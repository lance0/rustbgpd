#!/usr/bin/env python3
"""GetPolicyStats reload cell helpers: CPU sampler, probe driver, analyzer.

`policy_stats_cell.sh` runs the cell. Per reload the probe fires one
concurrent `neighbor` + `policy stats --direction both` pair at a fixed offset
after the cohort hot-apply completes (targeting the RIB commit band), and one
quiescent `policy stats --direction both` probe a fixed time after the reload
completes. The analyzer matches each stats call to its daemon audit record,
reports stage and import sub-stage timing, and evaluates the ADR-0136
"flat through reloads" criterion. It retains every call; nothing is retried.
"""
import argparse
import collections
import datetime
import gzip
import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

BAND_MS = (-220.0, 0.0)
EXTERNAL_LIMIT_MS = 2000.0
MIN_IN_BAND_PAIRS = 6
COMPILERS = ('cargo', 'rustc', 'rustdoc', 'clippy-driver')


def wall(timestamp):
    return datetime.datetime.fromisoformat(timestamp.replace('Z', '+00:00')).timestamp()


def percentile(values, pct):
    """Nearest-rank percentile; None for an empty sample."""
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, -(-len(ordered) * pct // 100))
    return ordered[int(rank) - 1]


def median(values):
    if not values:
        return None
    ordered = sorted(values)
    mid = len(ordered) // 2
    return ordered[mid] if len(ordered) % 2 else (ordered[mid - 1] + ordered[mid]) / 2


def distribution(values):
    return {'n': len(values), 'min': min(values, default=None), 'p50': percentile(values, 50),
            'p95': percentile(values, 95), 'max': max(values, default=None)}


STAGE = re.compile(r'stage=(\w+) elapsed_ms=(\d+) budget_ms=(\d+) rpc_elapsed_ms=(\d+) code=(\w+)'
                   r'(?: (admission=pending|admission_ms=\d+ collection_ms=\d+ publications=\d+/\d+ yields=\d+))?')
STAGE_ORDER = ('export', 'import', 'datasets')  # a fleet `--direction both` request
IMPORT_DETAIL = ('admission_ms', 'collection_ms', 'publications_read', 'publications_selected', 'yields')


def parse_summary(summary):
    """Parse a GetPolicyStats audit request_summary into per-stage records.

    Raises ValueError on any segment that is not exactly one stage record, so
    a malformed audit can never shrink the summed stage time silently.
    """
    stages = []
    for segment in summary.split(';'):
        segment = segment.strip()
        match = STAGE.fullmatch(segment)
        if not match:
            raise ValueError(f'malformed audit segment: {segment!r}')
        name, elapsed, budget, rpc, code, detail = match.groups()
        stage = {'stage': name, 'elapsed_ms': int(elapsed), 'budget_ms': int(budget),
                 'rpc_elapsed_ms': int(rpc), 'code': code}
        if detail == 'admission=pending':
            stage['admission'] = 'pending'
        elif detail:
            stage.update(zip(IMPORT_DETAIL, map(int, re.findall(r'\d+', detail))))
        stages.append(stage)
    return stages


def stage_set_problem(stages, result):
    """Why these stages are not a complete audit of a `both` call, or None.

    Stages run in STAGE_ORDER and stop at the first failure, so a record must
    be a prefix of it ending at any non-Ok stage; a successful handler must
    carry all three. The import stage must carry its sub-stages (or pending).
    """
    names = [s['stage'] for s in stages]
    if names != list(STAGE_ORDER[:len(names)]) or not names:
        return f'stage sequence {names}, expected a prefix of {list(STAGE_ORDER)}'
    failed = [i for i, s in enumerate(stages) if s['code'] != 'Ok']
    if failed and failed[0] != len(stages) - 1:
        return f'stages recorded after failed stage {names[failed[0]]}'
    if result == 'handler_ok' and (failed or len(stages) != len(STAGE_ORDER)):
        return f'handler_ok with incomplete or failed stages {names}'
    for s in stages:
        if s['stage'] == 'import' and s.get('admission') != 'pending' and not all(k in s for k in IMPORT_DETAIL):
            return 'import stage without admission/collection/publications/yields'
        if s['stage'] != 'import' and ('admission' in s or 'yields' in s):
            return f"{s['stage']} stage carries import sub-stages"
    return None


def classify_stats_call(summary, result):
    """Return (stages, stage_sum_ms, invalid_reason) for one matched audit."""
    try:
        stages = parse_summary(summary)
    except ValueError as exc:
        return [], None, str(exc)
    problem = stage_set_problem(stages, result)
    return stages, (None if problem else sum(s['elapsed_ms'] for s in stages)), problem


def run_verdict(errors, invalid_calls, flat):
    """INVALID (incomplete evidence) outranks FAIL (a criterion missed)."""
    if invalid_calls:
        return 'INVALID'
    return 'PASS' if not errors and flat['pass'] else 'FAIL'


def flat_verdict(in_band_sums, quiescent_sums):
    """ADR-0136: in-band max of summed stage elapsed <= 2 x quiescent median + 50 ms."""
    if not in_band_sums or not quiescent_sums:
        return {'pass': False, 'reason': 'missing in-band or quiescent samples'}
    quiet = median(quiescent_sums)
    limit = 2 * quiet + 50
    worst = max(in_band_sums)
    return {'pass': worst <= limit, 'in_band_max_ms': worst, 'quiescent_median_ms': quiet, 'limit_ms': limit}


def validate_reply(op, body, peers):
    data = json.loads(body)
    if op == 'neighbor':
        assert isinstance(data, list), 'neighbor shape'
        addresses = {r['address'] for r in data}
        assert len(data) == len(addresses) == peers, 'neighbor cardinality'
        stale = sum(bool(r.get('stale')) or r.get('state') == 'Stale' for r in data)
        return {'rows': len(data), 'stale_rows': stale}
    assert isinstance(data, dict) and isinstance(data.get('datasets', []), list), 'stats shape/datasets'
    result = {}
    for direction in ('import', 'export'):
        rows = [r for r in data['chains'] if r['direction'] == direction]
        assert len(rows) == len({r['peer_address'] for r in rows}) == peers, direction + ' complete fleet'
        assert all(r['terms'] and r['eval_errors'] == 0 for r in rows), direction + ' terms/errors'
        result[direction + '_rows'] = len(rows)
        result[direction + '_policy_generations'] = dict(collections.Counter(
            str(r.get('policy_generation')) for r in rows))
    assert len(data['chains']) == 2 * peers, 'stats total rows'
    return result


# ---------------------------------------------------------------- sampler

def cpu_times():
    busy = {}
    for line in open('/proc/stat'):
        name, *fields = line.split()
        if name.startswith('cpu') and name != 'cpu':
            v = list(map(int, fields))
            busy[name[3:]] = v[0] + v[1] + v[2] + v[5] + v[6] + v[7]
    return busy


def proc_ticks(pid):
    try:
        text = Path(f'/proc/{pid}/stat').read_text()
    except OSError:
        return None
    fields = text[text.rindex(')') + 2:].split()
    return int(fields[11]) + int(fields[12])


def compiler_count():
    count = 0
    for p in os.listdir('/proc'):
        if p.isdigit():
            try:
                count += Path(f'/proc/{p}/comm').read_text().strip() in COMPILERS
            except OSError:
                pass
    return count


def siblings(cpu):
    text = Path(f'/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list').read_text().strip()
    out = set()
    for part in text.split(','):
        lo, _, hi = part.partition('-')
        out.update(range(int(lo), int(hi or lo) + 1))
    return out


def sample(args):
    daemon = sorted(os.sched_getaffinity(args.pid))
    engine = sorted(os.sched_getaffinity(args.engine_pid))
    sibs = sorted(set().union(*(siblings(c) for c in daemon + engine)) - set(daemon) - set(engine))
    meta = {'record': 'meta', 'hz': os.sysconf('SC_CLK_TCK'), 'daemon_cpus': daemon, 'engine_cpus': engine,
            'sibling_cpus': sibs}
    with open(args.output, 'w', buffering=1) as out:
        out.write(json.dumps(meta) + '\n')
        while True:
            busy = cpu_times()
            out.write(json.dumps({'wall': time.time(), 'cpu_busy': {c: busy[str(c)] for c in daemon + engine + sibs},
                                  'daemon_ticks': proc_ticks(args.pid), 'engine_ticks': proc_ticks(args.engine_pid),
                                  'compilers': compiler_count()}) + '\n')
            time.sleep(1)


# ------------------------------------------------------------------ probe

def probe(args):
    directory = Path(args.output).parent
    lock = threading.Lock()
    workers = []
    reload_n = 0
    armed = False
    deadline = time.monotonic() + args.cap_secs
    with open(args.output, 'w', buffering=1) as out:
        def emit(row):
            with lock:
                out.write(json.dumps(row, sort_keys=True) + '\n')

        def read(n, phase, op):
            words = ['policy', 'stats', '--direction', 'both'] if op == 'policy_stats' else ['neighbor']
            command = ['taskset', '-c', args.cpus, args.rbgp, '-s', args.socket, '--json', *words]
            start, mstart = time.time(), time.monotonic()
            try:
                result = subprocess.run(command, capture_output=True, timeout=5)
                code, body, error = result.returncode, result.stdout, result.stderr
            except subprocess.TimeoutExpired as exc:
                code, body, error = None, exc.stdout or b'', exc.stderr or b''
            end, mend = time.time(), time.monotonic()
            stem = f'probe-{n:02d}-{phase}-{op}'
            (directory / (stem + '.stdout.gz')).write_bytes(gzip.compress(body, mtime=0))
            row = {'record': 'probe', 'reload': n, 'phase': phase, 'op': op, 'started_wall': start,
                   'completed_wall': end, 'duration_ms': (mend - mstart) * 1000, 'exit': code,
                   'body_sha256': hashlib.sha256(body).hexdigest(), 'stdout': stem + '.stdout.gz',
                   'stderr': error.decode(errors='replace').strip()}
            if code == 0:
                try:
                    row['shape'] = validate_reply(op, body, args.peers)
                except (ValueError, KeyError, TypeError, AssertionError) as exc:
                    row['invalid_reply'] = str(exc)
            emit(row)

        def later(at, target):
            time.sleep(max(0.0, at - time.time()))
            target()

        def pair(n):
            threads = [threading.Thread(target=read, args=(n, 'pair', op)) for op in ('neighbor', 'policy_stats')]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        def spawn(at, target):
            t = threading.Thread(target=later, args=(at, target))
            workers.append(t)
            t.start()

        with open(args.log, errors='replace') as log:
            log.seek(0, 2)
            while time.monotonic() < deadline:
                line = log.readline()
                if not line:
                    if reload_n == args.reloads and len(workers) == 2 * args.reloads and \
                            not any(t.is_alive() for t in workers):
                        emit({'record': 'probe_complete', 'wall': time.time()})
                        return 0
                    time.sleep(.003)
                    continue
                try:
                    r = json.loads(line)
                    f = r['fields']
                    message = f.get('message', '')
                    stamp = wall(r['timestamp'])
                except (ValueError, KeyError):
                    continue
                if message.startswith('SIGHUP received'):
                    reload_n += 1
                    armed = True
                    emit({'record': 'sighup', 'reload': reload_n, 'wall': stamp})
                    if reload_n > args.reloads:
                        raise RuntimeError('unexpected extra SIGHUP')
                elif armed and message == 'cohort session hot-apply progress' and \
                        f.get('applied') == f.get('cohort_targets'):
                    # A session that misses cohort classification goes to the
                    # remainder, so the cohort can be smaller than the fleet.
                    armed = False
                    n = reload_n
                    emit({'record': 'hot_apply_complete', 'reload': n, 'wall': stamp, 'cohort_targets': f['applied']})
                    spawn(stamp + args.pair_offset, lambda n=n: pair(n))
                elif message == 'config reload complete (one runtime generation)' and reload_n:
                    n = reload_n
                    spawn(stamp + args.quiescent_offset, lambda n=n: read(n, 'quiescent', 'policy_stats'))
    raise RuntimeError('probe monitor exceeded its cap')


# ---------------------------------------------------------------- analyze

def load_records(path):
    records, non_json = [], 0
    for line in open(path, errors='replace'):
        try:
            r = json.loads(line)
            records.append({'wall': wall(r['timestamp']), 'level': r['level'], **r['fields']})
        except (ValueError, KeyError, TypeError):
            non_json += 1
    return records, non_json


def cpu_summary(path, windows):
    rows = [json.loads(line) for line in open(path)]
    meta, samples = rows[0], rows[1:]
    hz = meta['hz']
    daemon, sibs = [str(c) for c in meta['daemon_cpus']], [str(c) for c in meta['sibling_cpus']]
    intervals = []
    for a, b in zip(samples, samples[1:]):
        dt = b['wall'] - a['wall']
        if dt <= 0 or a['daemon_ticks'] is None or b['daemon_ticks'] is None:
            continue
        core = sum(b['cpu_busy'][c] - a['cpu_busy'][c] for c in daemon) / hz / dt
        own = (b['daemon_ticks'] - a['daemon_ticks']) / hz / dt
        sib = sum(b['cpu_busy'][c] - a['cpu_busy'][c] for c in sibs) / hz / dt
        intervals.append({'start': a['wall'], 'end': b['wall'], 'daemon_cores': own,
                          'foreign_on_daemon_cpus': max(0.0, core - own), 'smt_sibling_busy': sib,
                          'compilers': max(a['compilers'], b['compilers'])})

    def summarize(selected):
        return {k: distribution([i[k] for i in selected]) for k in
                ('daemon_cores', 'foreign_on_daemon_cpus', 'smt_sibling_busy', 'compilers')}
    during = [i for i in intervals if any(i['end'] >= s and i['start'] <= e for s, e in windows)]
    return {'placement': {k: meta[k] for k in ('daemon_cpus', 'engine_cpus', 'sibling_cpus')},
            'whole_run': summarize(intervals), 'during_calls': summarize(during)}


def analyze(root, peers, reloads):
    root = Path(root)
    records, non_json = load_records(root / 'rustbgpd.log')
    probes = [json.loads(line) for line in open(root / 'probes.jsonl')]
    calls = [p for p in probes if p.get('record') == 'probe']
    errors = []

    def check(ok, message):
        if not ok:
            errors.append(message)

    def marker(message, **match):
        return [r for r in records if r.get('message') == message and all(r.get(k) == v for k, v in match.items())]
    sighups = [r for r in records if r.get('message', '').startswith('SIGHUP received')]
    commits = marker('RIB export-policy transition completed')
    phases = marker('reload generation phase timing')
    completes = marker('config reload complete (one runtime generation)')
    for name, rows in (('SIGHUP', sighups), ('RIB commit', commits), ('phase timing', phases),
                       ('reload complete', completes)):
        check(len(rows) == reloads, f'{len(rows)} {name} markers, expected {reloads}')
    exclusions = marker('classified export policy cohort state exclusions')
    for c, r in zip(commits, phases):
        check(c.get('outcome') == 'committed' and r.get('outcome') == 'committed' and
              r.get('authoritative_fallback') is False and r.get('total_targets') == peers and
              c.get('member_count') == r.get('cohort_targets'), 'reload not a committed cohort without fallback')
    end_wall = json.loads((root / 'final-evidence-completed.json').read_text())['wall']
    check(not [r for r in records if r['level'] == 'ERROR' and r['wall'] <= end_wall], 'daemon ERROR during measurement')

    audits = [r for r in records if str(r.get('method', '')).endswith('GetPolicyStats') and r.get('request_summary')]
    used = set()
    invalid_calls = []
    per_reload = []
    for index in range(1, reloads + 1):
        if min(len(sighups), len(commits), len(completes)) < index:
            break
        start = sighups[index - 1]['wall']
        stop = sighups[index]['wall'] if index < len(sighups) else end_wall
        commit, complete = commits[index - 1]['wall'], completes[index - 1]['wall']
        rows = []
        for call in [c for c in calls if c['reload'] == index]:
            offset = (call['started_wall'] - commit) * 1000
            row = {k: call.get(k) for k in ('phase', 'op', 'duration_ms', 'exit', 'shape', 'invalid_reply')}
            row['start_minus_rib_commit_ms'] = offset
            row['in_band'] = call['phase'] == 'pair' and BAND_MS[0] <= offset <= BAND_MS[1]
            check(start <= call['started_wall'] and call['completed_wall'] < stop, f'R{index} call outside its reload')
            check(call['exit'] == 0 and 'shape' in call and 'invalid_reply' not in call,
                  f"R{index} {call['phase']} {call['op']} failed: exit={call['exit']} {call.get('invalid_reply', '')}")
            check(call['duration_ms'] <= EXTERNAL_LIMIT_MS, f"R{index} {call['phase']} {call['op']} over 2 s")
            if call['phase'] == 'quiescent':
                row['start_minus_reload_complete_ms'] = (call['started_wall'] - complete) * 1000
                check(call['started_wall'] - complete >= 10, f'R{index} quiescent probe too close to reload complete')
            if call['op'] == 'policy_stats':
                matched = [i for i, a in enumerate(audits) if i not in used and
                           call['started_wall'] <= a['wall'] <= call['completed_wall']]
                check(len(matched) == 1, f"R{index} {call['phase']} stats call matched {len(matched)} audits")
                if len(matched) == 1:
                    used.add(matched[0])
                    audit = audits[matched[0]]
                    row['audit'] = {'result': audit.get('result'), 'request_summary': audit['request_summary']}
                    row['stages'], row['stage_sum_ms'], reason = classify_stats_call(
                        audit['request_summary'], audit.get('result'))
                    if reason:
                        row['invalid_audit'] = reason
                else:
                    row['invalid_audit'] = f'matched {len(matched)} audit records'
                if 'invalid_audit' in row:
                    invalid_calls.append({'reload': index, 'phase': call['phase'], 'reason': row['invalid_audit']})
            rows.append(row)
        check(collections.Counter((r['phase'], r['op']) for r in rows) ==
              collections.Counter({('pair', 'neighbor'): 1, ('pair', 'policy_stats'): 1, ('quiescent', 'policy_stats'): 1}),
              f'R{index} probe identities')
        per_reload.append({'reload': index, 'sighup_wall': start, 'rib_commit_wall': commit, 'complete_wall': complete,
                           'sighup_to_commit_ms': (commit - start) * 1000, 'sighup_to_complete_ms': (complete - start) * 1000,
                           'rib_transition': {k: v for k, v in commits[index - 1].items() if k not in ('wall', 'level')},
                           'phase_timing': {k: v for k, v in phases[index - 1].items() if k not in ('wall', 'level')},
                           'cohort_exclusions': [{k: v for k, v in e.items() if k.startswith('excluded')}
                                                 for e in exclusions if start <= e['wall'] <= commit],
                           'complete_pair_in_band': sum(r['in_band'] for r in rows) == 2, 'calls': rows})
    check(len(used) == len(audits), f'{len(audits) - len(used)} unmatched GetPolicyStats audits')
    pairs_in_band = sum(r['complete_pair_in_band'] for r in per_reload)
    check(pairs_in_band >= MIN_IN_BAND_PAIRS, f'{pairs_in_band} complete in-band pairs, need {MIN_IN_BAND_PAIRS}')

    engine = (root / 'reloadstall.log').read_text()
    check('final sessions_up %d/%d parse_errors=0' % (peers, peers) in engine, 'engine final inventory')
    check('FAIL:' not in engine, 'engine FAIL record')
    settled = re.findall(r'^reload (\d+) daemon_applied complete_before=(\d+) complete_after=(\d+)$', engine, re.M)
    check(len(settled) == reloads and all(int(a) == int(b) + 1 for _, b, a in settled), 'engine settlement records')

    stats = [c for r in per_reload for c in r['calls'] if c['op'] == 'policy_stats' and 'invalid_audit' not in c]
    groups = {'in_band': [c for c in stats if c['in_band']], 'pair_all': [c for c in stats if c['phase'] == 'pair'],
              'quiescent': [c for c in stats if c['phase'] == 'quiescent']}
    timing = {}
    for name, group in groups.items():
        by_stage = collections.defaultdict(list)
        for c in group:
            for s in c['stages']:
                by_stage[s['stage']].append(s['elapsed_ms'])
        imports = [s for c in group for s in c['stages'] if s['stage'] == 'import']
        timing[name] = {
            'external_ms': distribution([c['duration_ms'] for c in group]),
            'stage_sum_ms': distribution([c['stage_sum_ms'] for c in group]),
            'stages_ms': {k: distribution(v) for k, v in by_stage.items()},
            'import_substages': {k: distribution([s[k] for s in imports if k in s])
                                 for k in ('admission_ms', 'collection_ms', 'yields', 'publications_read')},
            'import_admission_pending': sum(s.get('admission') == 'pending' for s in imports),
        }
    misses = [c for c in stats if c['audit']['result'] != 'handler_ok' or any(s['code'] != 'Ok' for s in c['stages'])]
    flat = flat_verdict([c['stage_sum_ms'] for c in groups['in_band']], [c['stage_sum_ms'] for c in groups['quiescent']])
    neighbors = [c for r in per_reload for c in r['calls'] if c['op'] == 'neighbor' and c.get('shape')]
    result = {
        'environment': json.loads((root / 'environment.json').read_text()),
        'verdict': run_verdict(errors, invalid_calls, flat), 'invalid_calls': invalid_calls,
        'checks_pass': not errors, 'errors': errors, 'flat': flat,
        'in_band_pairs': pairs_in_band, 'deadline_misses': len(misses),
        'calls_over_2s': sum(c['duration_ms'] > EXTERNAL_LIMIT_MS for r in per_reload for c in r['calls']),
        'neighbor_stale_rows': [c['shape']['stale_rows'] for c in neighbors],
        'timing': timing,
        'remainder_targets': [r['phase_timing'].get('remainder_targets') for r in per_reload],
        'reload_ms': {'sighup_to_commit': distribution([r['sighup_to_commit_ms'] for r in per_reload]),
                      'sighup_to_complete': distribution([r['sighup_to_complete_ms'] for r in per_reload])},
        'cpu': cpu_summary(root / 'cpu.jsonl', [(c['started_wall'], c['completed_wall']) for c in calls]),
        'daemon_non_json_lines': non_json,
        'reloads': per_reload,
    }
    (root / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
    brief = {k: result[k] for k in ('verdict', 'invalid_calls', 'checks_pass', 'errors', 'flat', 'in_band_pairs',
                                    'deadline_misses', 'calls_over_2s')}
    brief['timing'] = {k: {'stage_sum_ms': v['stage_sum_ms'], 'external_ms': v['external_ms']} for k, v in timing.items()}
    print(json.dumps(brief, indent=2))
    return {'PASS': 0, 'FAIL': 1, 'INVALID': 3}[result['verdict']]


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest='cmd', required=True)
    s = sub.add_parser('sample')
    s.add_argument('--pid', type=int, required=True)
    s.add_argument('--engine-pid', type=int, required=True)
    s.add_argument('--output', required=True)
    s = sub.add_parser('probe')
    for name in ('--log', '--rbgp', '--socket', '--output', '--cpus'):
        s.add_argument(name, required=True)
    s.add_argument('--peers', type=int, required=True)
    s.add_argument('--reloads', type=int, required=True)
    s.add_argument('--pair-offset', type=float, required=True)
    s.add_argument('--quiescent-offset', type=float, required=True)
    s.add_argument('--cap-secs', type=float, required=True)
    s = sub.add_parser('analyze')
    s.add_argument('root')
    a = p.parse_args()
    if a.cmd == 'sample':
        return sample(a)
    if a.cmd == 'probe':
        return probe(a)
    shape = json.loads((Path(a.root) / 'environment.json').read_text())['shape']
    return analyze(a.root, shape['peers'], shape['reloads'])


if __name__ == '__main__':
    sys.exit(main())
