#!/usr/bin/env python3
"""Fail closed on one matrix cell; retain numerical evidence and warning phases."""
import csv
import datetime
import json
import math
from pathlib import Path
import re
import sys


def check(root, peers, total, ipv4, changed, filtered, reloads=4):
    cell = root / 'rustbgpd'
    errors = []

    def require(ok, message):
        if not ok:
            errors.append(message)

    require((root / 'driver.exit').read_text().strip() == '0', 'driver exit')
    require((cell / 'status').read_text().strip() == 'pass', 'harness status')
    require('harness rc=0 ' in (root / 'driver.log').read_text(), 'harness exit receipt')
    text = (cell / 'reloadstall.log').read_text()
    lines = text.splitlines()

    def rows(prefix):
        header = next(csv.reader([next(x for x in lines if x.startswith(prefix + '_header,'))]))[1:]
        return [dict(zip(header, next(csv.reader([x]))[1:], strict=True))
                for x in lines if x.startswith(prefix + ',')]

    def kv(line):
        return dict(x.split('=', 1) for x in line.split(',')[1:])

    for prefix, count in [('first_exact_bitmap', ipv4), ('first_exact_bitmap6', total-ipv4)]:
        found = [kv(x) for x in lines if x.startswith(prefix + ',')]
        require(len(found) == 1, prefix + ' receipt count')
        if found:
            row = found[0]
            require(int(row['completed']) == peers and int(row['total']) == count, prefix + ' inventory')
            require(int(row['min_unique']) == count - math.ceil(count/peers), prefix + ' minimum')
            require(int(row['max_unique']) == count - count//peers, prefix + ' maximum')
    dual = rows('reloadstall_dualstack_csv')
    main = rows('reloadstall_csv')
    overlaps = [kv(x) for x in lines if x.startswith('reloadstall_churn_overlap,')]
    for name, records in [('dual', dual), ('main', main), ('overlap', overlaps)]:
        require([int(x['reload']) for x in records] == list(range(1, reloads+1)), name + ' reload sequence')
    for row in dual:
        r = int(row['reload'])
        expected = (changed-1)*filtered if r % 2 else 0
        values = {'peers_total': peers, 'peers_changed': changed, 'prefixes_total': total,
                  'ipv4_prefixes': ipv4, 'ipv6_prefixes': total-ipv4, 'filter_count': filtered,
                  'sessions_up': peers, 'parse_errors': 0, 'filtered_leaked': 0,
                  'bystander_withdrawn': 0, 'stable_withdrawn': 0,
                  'duplicate_withdrawn': 0,
                  'stable_marker_peers_v4': peers-changed, 'stable_marker_peers_v6': peers-changed}
        for family in ('v4', 'v6'):
            values[family+'_filtered_withdrawn'] = expected
            values[family+'_filtered_expected'] = expected
        for key, value in values.items():
            require(int(row[key]) == value, f'reload {r}: {key}')
        require(row['generation'] == ('b' if r % 2 else 'a'), f'reload {r}: generation')
        for key, value in row.items():
            if key.endswith(('_s', '_ms')):
                require(math.isfinite(float(value)) and float(value) >= 0, f'reload {r}: {key}')
    for row in main:
        require(int(row['sessions_up']) == peers and int(row['parse_errors']) == 0, 'main session/error')
    for row in overlaps:
        require(row['overlap_observed'] == 'true', 'churn overlap')
        start, end = int(row['trigger_us']), int(row['completion_us'])
        for family in ('v4', 'v6'):
            require(int(row[family+'_writes']) > 0, family + ' churn writes')
            times = [re.fullmatch(r'Some\((\d+)\)', row[family+'_'+edge+'_us']) for edge in ('first', 'last')]
            require(all(times) and start <= int(times[0][1]) <= int(times[1][1]) <= end, family + ' churn timestamps')
    triggers = [int(x)/1e6 for x in re.findall(r'SIGHUP wall_us=(\d+)', text)]
    require(len(triggers) == reloads, 'SIGHUP count')
    end = triggers[-1] + float(main[-1]['completion_max_s'])
    query_summary = {}
    for filename in ('probes.csv', 'queries.csv'):
        records = list(csv.DictReader((cell / filename).open()))
        require(bool(records), filename + ' empty')
        require(all(int(x['exit']) == 0 for x in records), filename + ' failure')
        require(min(float(x['epoch_s']) for x in records) <= triggers[0] and
                max(float(x['epoch_s']) for x in records) >= end, filename + ' reload-span coverage')
        if filename == 'queries.csv':
            require({x['prefix'] for x in records} == {'20.0.0.0/24', '3001::/48'}, 'both query families')
        latencies = sorted(float(x['latency_ms']) for x in records)
        query_summary[filename] = {'count': len(records), 'max_ms': max(latencies),
                                   'p95_ms': latencies[math.ceil(len(latencies)*.95)-1]}
    rss = list(csv.DictReader((cell / 'rss.csv').open()))
    peak = max(int(x['total_rss_kib']) for x in rss)
    hwm = int(re.search(r'VmHWM:\s+(\d+)', (cell / 'vmhwm').read_text())[1])
    require(0 < peak <= 100*1024*1024 and 0 < hwm <= 100*1024*1024, 'RSS limit')
    quiet = list(csv.DictReader((cell / 'quiet.tsv').open(), delimiter='\t'))
    require(len(quiet) == 2 and all(x['quiet'] == 'true' for x in quiet), 'quiet receipt')
    events = []
    for line in (cell / 'daemon.log').read_text().splitlines():
        if not line.strip() or line.startswith(('  rustbgpd ', '  |- ')):
            continue
        events.append(json.loads(line))
    def epoch(event):
        return datetime.datetime.fromisoformat(event['timestamp']).timestamp()
    downs = [epoch(x) for x in events if x['fields'].get('message') == 'session down']
    require(bool(downs) and min(downs) > end, 'session loss before measured completion')
    peer_down_times = {}
    for event in events:
        if event['fields'].get('message') == 'session down':
            peer = event['fields'].get('peer')
            peer_down_times[peer] = min(peer_down_times.get(peer, float('inf')), epoch(event))
    warnings = []
    for event in events:
        level, message, t = event['level'], event['fields'].get('message', ''), epoch(event)
        require(level != 'ERROR', 'daemon ERROR: ' + message)
        if level != 'WARN':
            continue
        phase = 'startup' if t < triggers[0] else ('teardown' if downs and t >= min(downs) else 'active')
        allowed = (message.startswith('rfc8212_secure_default_ready:') and phase == 'startup') or (
            'marking dirty for resync' in message and phase == 'teardown') or (
            message == 'writer: write/flush failed' and
            event['fields'].get('error_kind') == 'BrokenPipe' and phase == 'teardown' and
            peer_down_times.get(event['fields'].get('peer'), float('inf')) <= t)
        require(allowed, 'unclassified/active WARN: ' + message)
        warnings.append({'timestamp': event['timestamp'], 'phase': phase, 'message': message})
    return {'gate_version': 2, 'pass': not errors, 'errors': errors, 'dualstack': dual, 'churn_overlap': overlaps,
            'queries': query_summary, 'peak_sample_rss_kib': peak, 'vmhwm_kib': hwm, 'warnings': warnings}


if __name__ == '__main__':
    try:
        result = check(Path(sys.argv[1]), *map(int, sys.argv[2:]))
    except (OSError, ValueError, KeyError, StopIteration, IndexError, TypeError) as exc:
        result = {'pass': False, 'errors': [str(exc)]}
    print(json.dumps(result, indent=2))
    sys.exit(0 if result['pass'] else 1)
