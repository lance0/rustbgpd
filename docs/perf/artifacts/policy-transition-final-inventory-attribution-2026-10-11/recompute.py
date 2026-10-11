#!/usr/bin/env python3
"""Recompute the selected published evidence; never run a workload or binary."""
import base64
import collections
import csv
import datetime
import gzip
import hashlib
import io
import json
import math
from pathlib import Path
import re
from statistics import mean, median

from feature_compare import compare_scope, validate_capture

STAGE = re.compile(r'stage=(\w+) elapsed_ms=(\d+) budget_ms=(\d+) rpc_elapsed_ms=(\d+) code=(\w+)'
                   r'(?: (admission=pending|admission_ms=\d+ collection_ms=\d+ publications=\d+/\d+ yields=\d+'
                   r'|publications=\d+/\d+ yields=\d+))?')
STAGE_ORDER = ('export', 'import', 'datasets')  # a fleet `--direction both` request
# The import stage reads the peer manager's published roster (ADR-0136) and
# records only its capture: publications read/selected and waits taken.
IMPORT_DETAIL = ('publications_read', 'publications_selected', 'yields')
# Runs before the roster (slice 0) also recorded the peer-manager wait.
LEGACY_IMPORT_DETAIL = ('admission_ms', 'collection_ms') + IMPORT_DETAIL


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
            fields = LEGACY_IMPORT_DETAIL if detail.startswith('admission_ms=') else IMPORT_DETAIL
            stage.update(zip(fields, map(int, re.findall(r'\d+', detail))))
        stages.append(stage)
    return stages


def stage_set_problem(stages, result):
    """Why these stages are not a complete audit of a `both` call, or None.

    Stages run in STAGE_ORDER and stop at the first failure, so a record must
    be a prefix of it ending at any non-Ok stage; a successful handler must
    carry all three. The import stage must carry its capture detail (or, in a
    run from before the published roster, its pending admission).
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
            return 'import stage without publications/yields'
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


LEGS = ('baseline-r1', 'candidate-r1', 'candidate-r2', 'baseline-r2')
ARMS = ('baseline', 'candidate')
SOURCES = ('6ee2a052607b34a11e8daa2f4a4d4639b5101690',
           'aceacb435677291fdb20c2e792f58cb9e4575b74')
TREES = ('393acc58915f65e9e021fb2ec92db1d0d763bfb2',
         'e43026bd5e90766e8da8fea419fa736463f19117')
TOOLCHAIN = ('rustc 1.99.0 (b940084d7 2026-09-28)\n'
             'binary: rustc\n'
             'commit-hash: b940084d7eb6a299eb4bfeb8e34901bc051e7ac4\n'
             'commit-date: 2026-09-28\n'
             'host: x86_64-unknown-linux-gnu\n'
             'release: 1.99.0\n'
             'LLVM version: 23.1.1\n'
             'cargo 1.99.0 (5f94df478 2026-08-27)\n')
COMPONENTS = ('preflight_us', 'cohort_selection_us', 'cohort_prestage_session_apply_us',
              'cohort_rib_transition_us', 'authoritative_remainder_apply_us',
              'deferred_refresh_dispatch_us', 'convergence_check_us', 'unattributed_us')
METRICS = ('actor_ms', 'cohort_ms', 'prestage_ms', 'complete_ms', 'generation_ms',
           'wire_p50_ms', 'wire_p95_ms', 'wire_max_ms')


def wall(timestamp):
    return datetime.datetime.fromisoformat(timestamp.replace('Z', '+00:00')).timestamp()


def event(raw):
    return {'wall': wall(raw['timestamp']), 'level': raw['level'], **raw['fields']}


def distribution(rows):
    return {key: {'n': len(rows), 'median': median(r[key] for r in rows),
                 'min': min(r[key] for r in rows), 'max': max(r[key] for r in rows),
                 'mean': mean(r[key] for r in rows)} for key in METRICS}


def rpc_distribution(calls):
    values = [call['duration_ms'] for call in calls]
    return {'n': len(values), 'median': median(values), 'min': min(values),
            'max': max(values), 'mean': mean(values)}


def validate_builds(provenance, captures):
    """Actual binary-bound units, including build scripts; resolution is separate."""
    for arm, source, tree in zip(ARMS, SOURCES, TREES, strict=True):
        identity, capture = provenance['arms'][arm], captures[arm]
        assert identity['source'] == source
        assert identity['daemon_sha256'] == capture['binary_sha256'] == capture['cache_binary_sha256']
        assert identity['tree'] == tree, 'source tree differs from recorded arm'
        assert identity['toolchain'] == TOOLCHAIN, 'Rust/Cargo identity differs from recorded matching toolchain'
        assert identity['build_command'] == (
            'taskset -c 40-63 cargo build --release --locked -j 4 -p rustbgpd -p rustbgpctl')
        assert set(identity['build_exits']) == {'cargo-build.exit', 'build-stage.exit'}
        assert all(code == 0 for code in identity['build_exits'].values())
        assert not capture['normal_missing'] and not capture['including_build_missing']
        assert not validate_capture(capture), 'daemon/RIB bench-internals forbidden independently'
    assert provenance['arms']['baseline']['cli_sha256'] == provenance['arms']['candidate']['cli_sha256']
    for scope, count in (('normal_units', 227), ('including_build_units', 342)):
        report = compare_scope(captures['baseline'][scope], captures['candidate'][scope],
                               scope == 'including_build_units')
        assert report == provenance['actual_feature_comparison']['scopes'][scope]
        assert report['baseline_artifact_units'] == report['candidate_artifact_units'] == count
        assert all(not report[key] for key in ('only_baseline_units', 'only_candidate_units',
                   'configuration_differences', 'dependency_identity_differences'))
    assert provenance['actual_feature_comparison']['normal_build_resolution_equal'] is True


def compute(records, responses, provenance, captures):
    assert set(records) == set(provenance['legs']) == set(LEGS)
    assert set(provenance['native_exits']) == {'logs/build.exit', 'logs/abba.exit', 'logs/abba-wrapper.exit'}
    assert all(code == 0 for code in provenance['native_exits'].values())
    assert wall(provenance['window_start']) < wall(provenance['window_finish'])
    assert provenance['end_instrument_ok_count'] == 8
    validate_builds(provenance, captures)
    rows, metadata, used_responses = [], {}, set()
    for leg in LEGS:
        data, native, control = records[leg], records[leg]['native_summary'], provenance['legs'][leg]
        assert native['verdict'] == 'PASS' and native['checks_pass'] is True
        assert not native['errors'] and not native['invalid_calls']
        assert native['deadline_misses'] == native['calls_over_2s'] == 0
        assert native['remainder_targets'] == [0] * 8 and native['neighbor_stale_rows'] == [0] * 8
        assert set(control['exits']) == {'daemon', 'engine', 'probe', 'cell'}
        assert all(code == 0 for code in control['exits'].values()) and control['outer_leg_exit'] == 0
        assert control['daemon_errors_through_evidence_end'] == 0
        assert control['non_json_lines'] == native['daemon_non_json_lines']
        env = control['environment']
        arm = leg.split('-')[0]
        assert env['source_head'] == provenance['instrument_source'] and not env['source_dirty']
        assert env['binaries']['rustbgpd'] == provenance['arms'][arm]['daemon_sha256']
        assert env['binaries']['rbgp'] == provenance['arms']['baseline']['cli_sha256']
        assert env['binaries']['reloadstall'] == provenance['original_instrument_sha256'][
            '<ENGINE_DIRECTORY>/reloadstall']
        assert {key: env['shape'][key] for key in ('peers', 'prefixes', 'reloads', 'control_secs',
                'quiesce_secs', 'pair_lead_s', 'quiescent_offset_s')} == {
            'peers': 1000, 'prefixes': 400000, 'reloads': 8, 'control_secs': 15,
            'quiesce_secs': 40, 'pair_lead_s': 0.11, 'quiescent_offset_s': 20}
        assert env['placement'] == {'daemon_cpus': '2-3', 'engine_cpus': '4-5', 'probe_cpus': '8-15'}
        assert env['compiler_processes_at_start'] == 0
        quiet = control['quiet_samples']
        assert len(quiet) >= 2
        accepted = [q for q in quiet if q['quiet'] == 'true']
        assert len(accepted) >= 2 and int(accepted[-1]['epoch_s']) - int(accepted[-2]['epoch_s']) >= 30
        assert accepted[-1]['pswpin'] == accepted[-2]['pswpin']
        assert accepted[-1]['pswpout'] == accepted[-2]['pswpout']
        assert all(float(q['load1']) < 2 and q['competitors'] == q['failed_dimensions'] == 'none'
                   and int(q['performance_governors']) == int(q['governor_count']) == 64
                   for q in accepted[-2:])
        assert wall(provenance['window_start']) <= wall(control['start']) < wall(control['finish']) <= wall(provenance['window_finish'])
        assert all(len(data[key]) == 8 for key in ('starts', 'commits', 'phases', 'completes', 'wire'))
        assert len(native['reloads']) == 8 and len(data['probes']) == 24 and len(data['audits']) == 16
        selected, band_sums, quiet_sums, used_audits = [], [], [], set()
        for index in range(8):
            start, commit, phase, complete = (event(data[key][index]) for key in
                                             ('starts', 'commits', 'phases', 'completes'))
            record, wire = native['reloads'][index], data['wire'][index]
            assert record['reload'] == int(wire['reload']) == index + 1
            assert start['message'].startswith('SIGHUP received')
            assert commit['message'] == 'RIB export-policy transition completed'
            assert phase['message'] == 'reload generation phase timing'
            assert complete['message'] == 'config reload complete (one runtime generation)'
            assert start['wall'] == record['sighup_wall']
            assert commit['wall'] == record['rib_commit_wall']
            assert complete['wall'] == record['complete_wall']
            assert start['wall'] <= commit['wall'] <= phase['wall'] <= complete['wall']
            assert record['rib_transition'] == {k: v for k, v in commit.items() if k not in ('wall', 'level')}
            assert record['phase_timing'] == {k: v for k, v in phase.items() if k not in ('wall', 'level')}
            assert commit['outcome'] == phase['outcome'] == 'committed'
            assert commit['member_count'] == phase['cohort_targets'] == phase['total_targets'] == 1000
            assert phase['authoritative_fallback'] is False and phase['remainder_targets'] == 0
            assert all(isinstance(phase[k], int) and phase[k] >= 0 for k in COMPONENTS)
            assert sum(phase[k] for k in COMPONENTS) == phase['total_us']
            complete_ms = (complete['wall'] - start['wall']) * 1000
            assert record['sighup_to_complete_ms'] == complete_ms
            calls = [p for p in data['probes'] if p['reload'] == index + 1]
            assert collections.Counter((p['phase'], p['op']) for p in calls) == collections.Counter({
                ('pair', 'neighbor'): 1, ('pair', 'policy_stats'): 1, ('quiescent', 'policy_stats'): 1})
            assert len(record['calls']) == 3
            stop = event(data['starts'][index + 1])['wall'] if index < 7 else control['evidence_end_wall']
            in_band_count = 0
            for raw, call in zip(calls, record['calls'], strict=True):
                assert raw['exit'] == 0 and math.isfinite(raw['duration_ms']) and 0 <= raw['duration_ms'] <= 2000
                assert start['wall'] <= raw['started_wall'] < raw['completed_wall'] < stop
                assert all(raw.get(k) == call.get(k) for k in ('phase', 'op', 'duration_ms', 'exit', 'shape', 'invalid_reply'))
                response_key = f"{leg}/{raw['stdout']}"
                assert response_key not in used_responses
                used_responses.add(response_key)
                reply = responses[response_key]
                compressed = base64.b64decode(reply['gzip_base64'], validate=True)
                assert hashlib.sha256(compressed).hexdigest() == reply['compressed_sha256']
                body = gzip.decompress(compressed)
                assert hashlib.sha256(body).hexdigest() == raw['body_sha256']
                assert validate_reply(raw['op'], body.decode(), 1000) == raw['shape']
                if raw['op'] == 'neighbor':
                    assert raw['shape']['stale_rows'] == 0
                offset = (raw['started_wall'] - commit['wall']) * 1000
                in_band = raw['phase'] == 'pair' and -220 <= offset <= 0
                assert call['start_minus_rib_commit_ms'] == offset and call['in_band'] is in_band
                in_band_count += in_band
                if raw['phase'] == 'quiescent':
                    assert raw['started_wall'] - complete['wall'] >= 10
                if raw['op'] == 'policy_stats':
                    matches = [(i, event(a)) for i, a in enumerate(data['audits'])
                               if raw['started_wall'] <= wall(a['timestamp']) <= raw['completed_wall']]
                    assert len(matches) == 1 and matches[0][0] not in used_audits
                    used_audits.add(matches[0][0])
                    audit = matches[0][1]
                    assert call['audit'] == {'result': audit['result'], 'request_summary': audit['request_summary']}
                    stages, total, error = classify_stats_call(audit['request_summary'], audit['result'])
                    assert not error and audit['result'] == 'handler_ok'
                    assert stages == call['stages'] and total == call['stage_sum_ms']
                    assert all(s['code'] == 'Ok' for s in stages)
                    if in_band:
                        band_sums.append(total)
                    elif raw['phase'] == 'quiescent':
                        quiet_sums.append(total)
            assert record['complete_pair_in_band'] is (in_band_count == 2)
            assert all(int(wire[k]) == v for k, v in {'peers_total': 1000, 'peers_changed': 1000,
                'peers_stable': 0, 'prefixes': 400000, 'sessions_up': 1000, 'parse_errors': 0,
                'stable_marker_peers': 0}.items())
            quantiles = [float(wire[k]) * 1000 for k in ('completion_p50_s', 'completion_p95_s', 'completion_max_s')]
            assert all(math.isfinite(q) and q > 0 for q in quantiles) and quantiles == sorted(quantiles)
            generation_ms = phase['total_us'] / 1000
            row = {'leg': leg, 'arm': arm, 'reload': index + 1, 'actor_ms': commit['elapsed_ms'],
                   'cohort_ms': phase['cohort_rib_transition_us'] / 1000,
                   'prestage_ms': phase['cohort_prestage_session_apply_us'] / 1000,
                   'complete_ms': complete_ms, 'generation_ms': generation_ms,
                   'before_timed_generation_ms': (phase['wall'] - start['wall']) * 1000 - generation_ms,
                   'after_phase_log_to_complete_ms': (complete['wall'] - phase['wall']) * 1000,
                   'complete_pair_in_band': record['complete_pair_in_band'],
                   **{k[:-3] + '_ms': phase[k] / 1000 for k in COMPONENTS},
                   **dict(zip(('wire_p50_ms', 'wire_p95_ms', 'wire_max_ms'), quantiles, strict=True))}
            assert abs(row['before_timed_generation_ms'] + generation_ms + row['after_phase_log_to_complete_ms'] - complete_ms) < 1e-6
            selected.append(row)
        assert len(used_audits) == 16
        assert native['flat'] == flat_verdict(band_sums, quiet_sums) and native['flat']['pass'] is True
        assert sum(r['complete_pair_in_band'] for r in selected) == native['in_band_pairs'] >= 6
        rows.extend(selected)
        metadata[leg] = {'start': control['start'], 'finish': control['finish'], 'verdict': 'PASS',
                         'native_exit': 0, 'reloads': 8, 'raw_rpc_calls': 24,
                         'in_band_pairs': native['in_band_pairs'], 'all': distribution(selected),
                         'first': distribution(selected[:1]), 'later': distribution(selected[1:]),
                         'rpc_duration_ms': rpc_distribution(data['probes'])}
    assert used_responses == set(responses) and len(used_responses) == 96
    phases = ('before_timed_generation_ms',) + tuple(k[:-3] + '_ms' for k in COMPONENTS) + ('after_phase_log_to_complete_ms',)
    arms = {}
    for arm in ARMS:
        group = [r for r in rows if r['arm'] == arm]
        arms[arm] = {'all': distribution(group), 'first': distribution([r for r in group if r['reload'] == 1]),
                     'later': distribution([r for r in group if r['reload'] > 1]),
                     'additive_means_ms': {k: mean(r[k] for r in group) for k in phases},
                     'complete_mean_ms': mean(r['complete_ms'] for r in group),
                     'rpc_duration_ms': rpc_distribution([call for leg in LEGS if leg.split('-')[0] == arm
                                                          for call in records[leg]['probes']])}
        assert abs(sum(arms[arm]['additive_means_ms'].values()) - arms[arm]['complete_mean_ms']) < 1e-6
    return {'status': 'VALID four-cell native ABBA; selected public evidence reconciled',
            'source_parent': SOURCES[0], 'source_candidate': SOURCES[1],
            'window_start': provenance['window_start'], 'window_finish': provenance['window_finish'],
            'outer_exit': 0, 'processes_per_arm': 2, 'correlated_reloads_per_arm': 16,
            'total_raw_reload_rows': len(rows), 'total_raw_rpc_calls': 96,
            'rpc_duration_ms': rpc_distribution([call for leg in LEGS for call in records[leg]['probes']]),
            'legs': metadata, 'arms': arms, 'reloads': rows}


def render_tsv(report):
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=report['reloads'][0], delimiter='\t', lineterminator='\n')
    writer.writeheader()
    writer.writerows(report['reloads'])
    return output.getvalue()


def render_table(report):
    lines = ['# Recomputed clocks — 2026-10-11', '',
             'All clocks in ms. Median [minimum, maximum]; two processes per arm.', '',
             '| Process | Actor | Cohort | Prestage | Daemon complete | Wire p50 | Wire p95 | Wire max |',
             '| --- | --- | --- | --- | --- | --- | --- | --- |']
    keys = ('actor_ms', 'cohort_ms', 'prestage_ms', 'complete_ms', 'wire_p50_ms', 'wire_p95_ms', 'wire_max_ms')
    for leg in LEGS:
        d = report['legs'][leg]['all']
        lines.append('| ' + leg + ' | ' + ' | '.join(
            f"{d[k]['median']:.3f} [{d[k]['min']:.3f}, {d[k]['max']:.3f}]" for k in keys) + ' |')
    lines += ['', '| Population | Actor | Cohort | Prestage | Daemon complete | Wire p50 | Wire p95 | Wire max |',
              '| --- | --- | --- | --- | --- | --- | --- | --- |']
    for population in ('all', 'first', 'later'):
        for arm in ARMS:
            d = report['arms'][arm][population]
            lines.append('| ' + f"{arm} {population} (n={d['actor_ms']['n']})" + ' | ' + ' | '.join(
                f"{d[k]['median']:.3f} [{d[k]['min']:.3f}, {d[k]['max']:.3f}]" for k in keys) + ' |')
    lines += ['', 'The first population is the first reload of each process; all reloads remain in the primary population.', '',
              '| Additive mean span | Parent | Child | Child minus parent |', '| --- | --- | --- | --- |']
    a, b = (report['arms'][arm]['additive_means_ms'] for arm in ARMS)
    for key in a:
        lines.append(f'| {key} | {a[key]:.6f} | {b[key]:.6f} | {b[key] - a[key]:+.6f} |')
    aa, bb = (report['arms'][arm]['complete_mean_ms'] for arm in ARMS)
    lines.append(f'| complete mean | {aa:.6f} | {bb:.6f} | {bb - aa:+.6f} |')
    lines += ['', '| RPC population | Calls | Minimum | Median | Mean | Maximum |',
              '| --- | --- | --- | --- | --- | --- |']
    populations = [(leg, report['legs'][leg]['rpc_duration_ms']) for leg in LEGS]
    populations += [(arm, report['arms'][arm]['rpc_duration_ms']) for arm in ARMS]
    populations.append(('all', report['rpc_duration_ms']))
    for name, d in populations:
        lines.append(f"| {name} | {d['n']} | {d['min']:.6f} | {d['median']:.6f} | {d['mean']:.6f} | {d['max']:.6f} |")
    return '\n'.join(lines) + '\n'


def load(root):
    return tuple(json.loads((root / name).read_text()) for name in
                 ('records.json', 'rpc-responses.json', 'provenance.json', 'feature-audit.json'))


def main(root):
    inputs = load(root)
    report = compute(*inputs)
    helper = inputs[2]['reproduction_helper_provenance']
    for name, key in (('recompute.py', 'public_checker_sha256'), ('test_recompute.py', 'public_controls_sha256')):
        assert hashlib.sha256((root / name).read_bytes()).hexdigest() == helper[key]
    outputs = {'summary.json': json.dumps(report, indent=2) + '\n',
               'reloads.tsv': render_tsv(report), 'timing.md': render_table(report)}
    for name, content in outputs.items():
        assert (root / name).read_text() == content, f'{name} does not reproduce'
    graph = gzip.decompress((root / 'normal-build-graph.txt.gz').read_bytes())
    assert len(graph.splitlines()) == 17891
    assert hashlib.sha256(graph).hexdigest() == 'c1364681434d3ae9a897ba64fc6193abc8127c70d557fda52986d549c88c87cf'
    print('PASS: 32 reloads, 128 selected boundaries, 96 RPC replies/durations, 64 audits, 32 wire rows; '
          '227 normal/342 including-build units per arm; all summary/table/TSV bytes reproduce')


if __name__ == '__main__':
    main(Path(__file__).resolve().parent)
