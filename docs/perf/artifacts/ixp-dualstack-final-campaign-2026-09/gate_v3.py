#!/usr/bin/env python3
"""Supplement gate v2 with a proven post-measurement administrative-close case."""
import csv
import datetime
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re
import sys

V2_SHA256 = '9ec25e91d1a2ed9a2a8c55d7a251cff4b3e31214e7e753a4ebf3940dcee16543'
REFUSAL_ERROR = 'unclassified/active WARN: TCP connect failed'


def cleanup_refusals(events, end):
    """Return indices proven to follow their own peer's final administrative close."""
    if not math.isfinite(end):
        raise ValueError('nonfinite measured completion')
    candidates = [event for event in events
                  if event['level'] == 'WARN' and event['fields'].get('message') == 'TCP connect failed']
    if not candidates:
        return []
    candidate_peers = {event['fields'].get('peer') for event in candidates}
    if any(not isinstance(peer, str) or not peer for peer in candidate_peers):
        raise ValueError('refusal warning lacks peer identity')
    shutdowns = {}
    last_times = {}
    accepted = []
    for index, event in enumerate(events):
        fields = event['fields']
        message = fields.get('message')
        if message not in {'BGP NOTIFICATION', 'session down', 'session established', 'session state changed', 'TCP connect failed'}:
            continue
        peer = fields.get('peer')
        if peer not in candidate_peers:
            continue
        stamp = datetime.datetime.fromisoformat(event['timestamp'])
        if stamp.tzinfo is None:
            raise ValueError('event timestamp lacks timezone')
        t = stamp.timestamp()
        if t <= end:
            continue  # Original v2 retains active warnings; no earlier close can qualify.
        if t < last_times.get(peer, -math.inf):
            raise ValueError('peer event timestamps moved backwards')
        last_times[peer] = t
        if message == 'session established' or (message == 'session state changed' and fields.get('to') == 'established'):
            shutdowns.pop(peer, None)
        elif message == 'BGP NOTIFICATION':
            shutdowns.pop(peer, None)
            if (fields.get('direction') == 'received'
                    and type(fields.get('code')) is int and fields['code'] == 6
                    and type(fields.get('subcode')) is int and fields['subcode'] == 2
                    and t > end):
                shutdowns[peer] = (t, None)
        elif message == 'session down':
            state = shutdowns.pop(peer, None)
            if state is not None and state[0] <= t:
                shutdowns[peer] = (state[0], t)
        elif (event['level'] == 'WARN'
                and fields.get('failure_source') == 'socket'
                and fields.get('previously_established') is True
                and fields.get('error') == 'Connection refused (os error 111)'):
            state = shutdowns.get(peer)
            if state is not None and state[1] is not None and state[1] <= t:
                accepted.append(index)
    return accepted


def reclassify(original, events, end):
    result = dict(original)
    result['errors'] = list(original['errors'])
    result['gate_version'] = 3
    correction = {
        'base_gate_version': 2,
        'base_gate_sha256': V2_SHA256,
        'original_gate_pass': original['pass'],
        'original_gate_errors': list(original['errors']),
        'method': 'socket refusal after own received Cease/6/2 and session down after measured completion, with no intervening establishment',
        'measured_completion_epoch_s': end,
        'classified_warning_count': 0,
        'classified_warnings': [],
    }
    result['cleanup_tcp_refusal_correction'] = correction
    try:
        accepted = cleanup_refusals(events, end)
        candidates = sum(e['level'] == 'WARN' and e['fields'].get('message') == 'TCP connect failed' for e in events)
        if result['errors'].count(REFUSAL_ERROR) != candidates:
            raise ValueError('v2 refusal errors do not match raw WARN count')
        for index in accepted:
            result['errors'].remove(REFUSAL_ERROR)
            event = events[index]
            correction['classified_warnings'].append({'timestamp': event['timestamp'], 'peer': event['fields']['peer']})
        correction['classified_warning_count'] = len(accepted)
    except (ValueError, KeyError, TypeError, AttributeError, OverflowError) as exc:
        result['errors'] = list(original['errors']) + ['cleanup classification evidence: ' + str(exc)]
        correction['classified_warnings'] = []
        correction['classified_warning_count'] = 0
    result['pass'] = not result['errors']
    return result


def check(root, peers, total, ipv4, changed, filtered, reloads=4):
    gate_path = root / 'gate.py'
    if hashlib.sha256(gate_path.read_bytes()).hexdigest() != V2_SHA256:
        raise ValueError('original gate v2 hash changed')
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location('retained_gate_v2', gate_path)
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    original = gate.check(root, peers, total, ipv4, changed, filtered, reloads)
    text = (root / 'rustbgpd/reloadstall.log').read_text()
    lines = text.splitlines()
    header = next(csv.reader([next(x for x in lines if x.startswith('reloadstall_csv_header,'))]))[1:]
    rows = [dict(zip(header, next(csv.reader([x]))[1:], strict=True)) for x in lines if x.startswith('reloadstall_csv,')]
    triggers = [int(x)/1e6 for x in re.findall(r'SIGHUP wall_us=(\d+)', text)]
    end = triggers[-1] + float(rows[-1]['completion_max_s'])
    events = [json.loads(line) for line in (root / 'rustbgpd/daemon.log').read_text().splitlines()
              if line.strip() and not line.startswith(('  rustbgpd ', '  |- '))]
    return reclassify(original, events, end)


if __name__ == '__main__':
    try:
        result = check(Path(sys.argv[1]), *map(int, sys.argv[2:]))
    except (OSError, ValueError, KeyError, StopIteration, IndexError, TypeError, AttributeError, OverflowError) as exc:
        result = {'gate_version': 3, 'pass': False, 'errors': [str(exc)]}
    print(json.dumps(result, indent=2))
    sys.exit(0 if result['pass'] else 1)
