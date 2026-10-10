#!/usr/bin/env python3
"""Recompute retained clock distributions and validate extraction controls."""
import collections
import csv
import datetime
import gzip
import hashlib
import io
import json
import pathlib
import re
import statistics
import sys

ROOT = pathlib.Path(__file__).resolve().parent
COMPONENTS = ('preflight_us', 'cohort_selection_us', 'cohort_prestage_session_apply_us',
              'cohort_rib_transition_us', 'authoritative_remainder_apply_us',
              'deferred_refresh_dispatch_us', 'convergence_check_us', 'unattributed_us')
MESSAGES = {'sighup': 'SIGHUP received, reloading configuration',
            'rib': 'RIB export-policy transition completed',
            'phase': 'reload generation phase timing',
            'complete': 'config reload complete (one runtime generation)'}
STAGE = re.compile(r'stage=(\w+) elapsed_ms=(\d+) budget_ms=(\d+) rpc_elapsed_ms=(\d+) code=(\w+)'
                   r'(?: publications=(\d+)/(\d+) yields=(\d+))?')


def wall(event):
    return datetime.datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00')).timestamp()


def distribution(values):
    return {key: round(value, 6) for key, value in
            {'n': len(values), 'median': statistics.median(values), 'mean': statistics.mean(values),
             'min': min(values), 'max': max(values)}.items()}


def compute(root, prefix='initial'):
    proof = json.loads((root / 'provenance.json').read_text())
    campaign = proof['campaigns'][prefix]
    records = json.loads((root / f'{prefix}-records.json').read_text())
    order = ['baseline-r1', 'candidate-r1', 'candidate-r2', 'baseline-r2']
    assert campaign['status'] == 'VALID' and campaign['run_order'] == order, 'wrong campaign status/order'
    assert campaign['outer_process_exit'] == campaign['abba_exit'] == campaign['end_integrity_exit'] == 0, 'failed outer stage'
    assert set(campaign['build_exits'].values()) == {0}, 'failed build'
    start = datetime.datetime.fromisoformat(campaign['window_start']).timestamp()
    finish = datetime.datetime.fromisoformat(campaign['window_finish']).timestamp()
    assert start < finish, 'missing or invalid finished window'
    assert campaign['driver_sha256'] == campaign['build_driver_sha256'], 'changed driver'
    expected = {(run, reload) for run in order for reload in range(1, 9)}
    identities = [(record['run'], record['reload']) for record in records]
    assert len(identities) == len(expected) and set(identities) == expected, 'missing or duplicate reload'
    previous = start
    for run in order:
        native = campaign['runs'][run]
        began = datetime.datetime.fromisoformat(native['started']).timestamp()
        ended = datetime.datetime.fromisoformat(native['finished']).timestamp()
        assert previous <= began < ended <= finish, 'invalid process window'
        previous = ended
        assert native['wrapper_exit'] == 0 and set(native['exits']) == {'cell', 'daemon', 'engine', 'probe'} and set(native['exits'].values()) == {0}, 'failed runtime exit'
        verdict = native['native']
        assert verdict['verdict'] == 'PASS' and verdict['checks_pass'] and not verdict['errors'] and not verdict['invalid_calls'], 'failed native verdict'
        assert verdict['flat']['pass'] and verdict['flat']['in_band_max_ms'] <= 2 * verdict['flat']['quiescent_median_ms'] + 50, 'failed native flatness'
        assert verdict['deadline_misses'] == verdict['calls_over_2s'] == 0, 'native deadline miss'
        environment = native['environment']
        assert environment['source_head'] == proof['instrument']['source_commit'] and not environment['source_dirty'], 'changed instrument'
        arm = campaign['arms'][run.split('-')[0]]
        assert not arm['source_status'] and arm['profile'] == 'release', 'dirty or wrong build'
        refreshed = arm['cache_freshness']
        build_window = campaign['build_windows'][run.split('-')[0]]
        assert refreshed['input_count'] == 781 and set(refreshed['locks_held']) == {'canonical host lock', 'shared Cargo target build lock'}, 'wrong refreshed input scope'
        assert datetime.datetime.fromisoformat(build_window['started']) <= datetime.datetime.fromisoformat(refreshed['refreshed_at']) <= datetime.datetime.fromisoformat(build_window['finished']) <= datetime.datetime.fromtimestamp(start, datetime.timezone.utc), 'wrong input refresh timing'
        assert arm['command'] == 'cargo build --release --locked -j 4 -p rustbgpd -p rustbgpctl', 'unmatched package build'
        assert all(environment['binaries'][name] == arm['binaries'][name]['sha256'] for name in ('rustbgpd', 'rbgp')), 'wrong arm binary'
        assert environment['binaries']['reloadstall'] == proof['instrument']['files']['bin/harness-main/reloadstall'], 'wrong harness binary'
        shape = environment['shape']
        assert (shape['peers'], shape['prefixes'], shape['reloads'], shape['quiesce_secs'], shape['pair_lead_s']) == (1000, 400000, 8, 40, .110), 'wrong measured shape'
        assert len(native['settlement_records']) == 8 and native['final_inventory'], 'missing native settlement/inventory'
        assert len(native['quiet_samples']) >= 2 and all(s['quiet'] == 'true' and s['competitors'] == 'none' for s in native['quiet_samples'][-2:]), 'failed quiet gate'
    assert campaign['arms']['baseline']['binaries']['rbgp']['sha256'] == campaign['arms']['candidate']['binaries']['rbgp']['sha256'], 'changed shared CLI'
    baseline = campaign['arms']['baseline']
    assert (baseline['source_commit'], baseline['source_tree']) == ('436de7a9f18580620a0da6c42b20e3385a4c4658', '43ce7f0b4ba9fa83054802e7d570524ecffa28d3'), 'wrong baseline source'
    if prefix == 'initial':
        candidate = campaign['arms']['candidate']
        assert (candidate['source_commit'], candidate['source_tree']) == ('f4df7aaf18edb1987aebbd6a12038772ada2f948', '13a215adf6185add5cbad634f777557e97232c81'), 'wrong initial source'
    if prefix == 'final':
        candidate = campaign['arms']['candidate']
        assert (candidate['source_commit'], candidate['source_tree']) == ('8df8f397c7a77e0b1e3cecf8e4e628915d4f64e6', 'a00331032f5abca54e88ffbbed8b4f17e20b8976'), 'wrong final source'
    assert campaign['arms']['baseline']['toolchain'] == campaign['arms']['candidate']['toolchain'], 'unmatched toolchain'
    assert campaign['arms']['baseline']['cache_freshness']['input_list_sha256'] == campaign['arms']['candidate']['cache_freshness']['input_list_sha256'], 'unmatched refreshed input list'
    rows = []
    pairs = collections.Counter()
    for record in records:
        run, number = record['run'], record['reload']
        events = record['events']
        assert all(events[label]['fields']['message'] == message for label, message in MESSAGES.items()), 'wrong selected boundary'
        h, c, g, e = (events[label] for label in ('sighup', 'rib', 'phase', 'complete'))
        native = campaign['runs'][run]
        began = datetime.datetime.fromisoformat(native['started']).timestamp()
        ended = datetime.datetime.fromisoformat(native['finished']).timestamp()
        assert began <= wall(h) < wall(c) <= wall(g) < wall(e) <= ended, 'invalid reload boundary'
        next_record = next((r for r in records if r['run'] == run and r['reload'] == number + 1), None)
        stop = wall(next_record['events']['sighup']) if next_record else ended
        commit, phase = c['fields'], g['fields']
        assert commit['outcome'] == phase['outcome'] == 'committed' and phase['authoritative_fallback'] is False, 'failed or fallback transition'
        assert commit['member_count'] == phase['total_targets'] == phase['cohort_targets'] == 1000 and phase['remainder_targets'] == 0, 'wrong cohort inventory'
        assert phase['total_us'] == sum(phase[key] for key in COMPONENTS), 'phase components do not sum'
        row = {'run': run, 'reload': number, 'actor_ms': commit['elapsed_ms'],
               'cohort_ms': phase['cohort_rib_transition_us'] / 1000,
               'prestage_ms': phase['cohort_prestage_session_apply_us'] / 1000,
               'daemon_complete_ms': (wall(e) - wall(h)) * 1000,
               'before_phase_ms': (wall(g) - wall(h)) * 1000 - phase['total_us'] / 1000,
               'after_phase_ms': (wall(e) - wall(g)) * 1000,
               'cohort_outside_actor_ms': phase['cohort_rib_transition_us'] / 1000 - commit['elapsed_ms'],
               'rib_to_phase_ms': (wall(g) - wall(c)) * 1000}
        row.update({key.removesuffix('_us') + '_ms': phase[key] / 1000 for key in COMPONENTS})
        calls = record['calls']
        assert len(calls) == 3 and {(call['phase'], call['op']) for call in calls} == {('pair', 'neighbor'), ('pair', 'policy_stats'), ('quiescent', 'policy_stats')}, 'missing or duplicate probe identity'
        in_band = True
        for call in calls:
            assert call['exit'] == 0 and 0 <= call['duration_ms'] <= 2000 and 'shape' in call and 'invalid_reply' not in call, 'failed or over-deadline probe'
            assert wall(h) <= call['started_wall'] < call['completed_wall'] < stop, 'probe outside reload'
            offset = (call['started_wall'] - wall(c)) * 1000
            if call['phase'] == 'pair':
                in_band &= -220 <= offset <= 0
            else:
                assert call['started_wall'] - wall(e) >= 10, 'quiescent probe before quiet interval'
            if call['op'] == 'policy_stats':
                audit = call['audit']
                audit_event = call['audit_event']
                assert call['started_wall'] <= wall(audit_event) <= call['completed_wall'], 'stats audit outside call'
                assert str(audit_event['fields']['method']).endswith('GetPolicyStats') and audit == {key: audit_event['fields'][key] for key in ('result', 'request_summary')}, 'stats audit differs from selected event'
                segments = [STAGE.fullmatch(part.strip()) for part in audit['request_summary'].split(';')]
                assert audit['result'] == 'handler_ok' and len(segments) == 3 and all(segments), 'incomplete stats audit'
                assert [match[1] for match in segments] == ['export', 'import', 'datasets'] and all(match[5] == 'Ok' for match in segments), 'failed stats stage'
                assert segments[1][6] is not None, 'missing published roster detail'
                row[call['phase'] + '_stats_stage_sum_ms'] = sum(int(match[2]) for match in segments)
                assert call['shape']['import_rows'] == call['shape']['export_rows'] == 1000, 'wrong stats reply shape'
            else:
                assert call['shape']['rows'] == 1000, 'wrong neighbor reply shape'
            label = call['phase'] + '_' + call['op']
            row[label + '_ms'] = call['duration_ms']
            row[label + '_start_to_rib_ms'] = offset
            row[label + '_end_to_rib_ms'] = (call['completed_wall'] - wall(c)) * 1000
        pairs[run] += in_band
        wire = record['wire']
        assert int(wire['reload']) == number and int(wire['sessions_up']) == int(wire['peers_changed']) == int(wire['peers_total']) == 1000 and int(wire['prefixes']) == 400000 and int(wire['parse_errors']) == int(wire['peers_stable']) == 0, 'wrong wire inventory'
        row.update({'wire_' + key: float(value) for key, value in wire.items() if key.startswith(('completion_', 'changed_first_generation_update_', 'changed_maxgap_', 'all_observer_maxgap_'))})
        assert row['wire_completion_p50_s'] <= row['wire_completion_p95_s'] <= row['wire_completion_max_s'], 'invalid wire quantiles'
        rows.append(row)
    assert all(pairs[run] == campaign['runs'][run]['native']['in_band_pairs'] >= 6 for run in order), 'insufficient or mismatched pair coverage'
    rows.sort(key=lambda row: (row['run'], row['reload']))
    summaries = {}
    for scope in order + ['baseline', 'candidate']:
        selected = [row for row in rows if row['run'] == scope or row['run'].startswith(scope + '-')]
        summaries[scope] = {}
        for subset, group in [('all', selected), ('first_two', [row for row in selected if row['reload'] <= 2]), ('remaining', [row for row in selected if row['reload'] > 2])]:
            summaries[scope][subset] = {key: distribution([row[key] for row in group]) for key in group[0] if key not in ('run', 'reload')}
    buffer = io.StringIO(newline='')
    writer = csv.DictWriter(buffer, fieldnames=list(rows[0]), lineterminator='\n')
    writer.writeheader()
    writer.writerows({key: round(value, 6) if isinstance(value, float) else value for key, value in row.items()} for row in rows)
    return summaries, buffer.getvalue()


def features(root, prefix='initial'):
    filename = 'feature-audit.json' if prefix == 'initial' else f'{prefix}-feature-audit.json'
    audit = json.loads((root / filename).read_text())
    proof = json.loads((root / 'provenance.json').read_text())['campaigns'][prefix]
    for arm in ('baseline', 'candidate'):
        assert audit['matched_binary_hashes'][arm] == audit['release_artifact_hashes'][arm] == proof['arms'][arm]['binaries']['rustbgpd']['sha256'], 'feature audit bound to wrong binary'
    configs = []
    for arm in ('baseline', 'candidate'):
        units = audit['units'][arm]
        assert len(units) == 227, 'missing library unit'
        lookup = collections.defaultdict(list)
        for name, unit in units.items():
            lookup[int.from_bytes(bytes.fromhex(unit['signature']), 'little')].append(name)
        pending = ['rustbgpd-a3deef477fc8ee80/bin-rustbgpd.json']
        seen = set()
        while pending:
            name = pending.pop()
            if name in seen:
                continue
            seen.add(name)
            for dep in units[name]['configuration']['deps']:
                if dep[1] != 'build_script_build':
                    assert dep[3] in lookup, 'missing runtime dependency fingerprint'
                    pending.extend(lookup[dep[3]])
        assert seen == set(units), 'unreachable library unit'
        config = {}
        for unit in units.values():
            data = dict(unit['configuration'])
            key = tuple(data[field] for field in ('target', 'profile', 'path', 'compile_kind'))
            data['deps'] = sorted(dep[:3] for dep in data['deps'] if dep[1] != 'build_script_build')
            assert key not in config, 'duplicate unit configuration'
            config[key] = data
        configs.append(config)
    assert configs[0] == configs[1], 'unmatched library features/configuration/dependency identities'
    graphs = audit['resolved_graphs']
    normalized = gzip.decompress((root / 'normal-build-graph.txt.gz').read_bytes())
    assert graphs['equal'] and graphs['edges'] == ['normal', 'build'] and graphs['dev_edges'] is False, 'wrong resolved graph scope'
    assert all(arm['lines'] == len(normalized.splitlines()) == 17893 and arm['normalized_sha256'] == hashlib.sha256(normalized).hexdigest() for arm in graphs['arms'].values()), 'resolved graph differs'
    invalid = json.loads((root / 'invalid-build-confound.json').read_text())
    assert invalid['status'] == 'ABORTED_BUILD_CONFOUND' and invalid['exec_process_exit'] == 143 and invalid['driver_exit_trap_record'] == 0 and invalid['window_finish_present'] is False and invalid['closing_baseline_started'] is False and invalid['whole_window_success'] is False, 'invalid aborted history'
    assert len(audit['original_feature_differences']) == 6, 'missing original confound evidence'


def main():
    root = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT
    proof = json.loads((root / 'provenance.json').read_text())
    for prefix in proof['campaigns']:
        features(root, prefix)
        summaries, table = compute(root, prefix)
        assert json.loads((root / f'{prefix}-summary.json').read_text()) == summaries, 'stored summary differs'
        assert (root / f'{prefix}-correlation.csv').read_text() == table, 'stored table differs'
        print(json.dumps({prefix: summaries}, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
