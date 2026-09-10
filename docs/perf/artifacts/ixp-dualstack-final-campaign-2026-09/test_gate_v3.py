#!/usr/bin/env python3
"""Synthetic event regressions for the single gate-v3 cleanup exception."""
from copy import deepcopy

from gate_v3 import REFUSAL_ERROR, cleanup_refusals, reclassify


def event(second, message, **fields):
    return {'timestamp': f'2026-09-10T00:00:{second:02d}+00:00',
            'level': 'WARN' if message == 'TCP connect failed' else 'INFO',
            'fields': {'peer': '127.1.0.1', 'message': message, **fields}}


valid = [event(11, 'BGP NOTIFICATION', direction='received', code=6, subcode=2),
         event(12, 'session down'),
         event(17, 'TCP connect failed', failure_source='socket', previously_established=True,
               error='Connection refused (os error 111)')]
from datetime import datetime
end = datetime.fromisoformat('2026-09-10T00:00:10+00:00').timestamp()
assert cleanup_refusals(valid, end) == [2]
base = {'gate_version': 2, 'pass': False, 'errors': [REFUSAL_ERROR], 'warnings': ['retained raw classification']}
result = reclassify(base, valid, end)
assert result['pass'] and result['cleanup_tcp_refusal_correction']['classified_warning_count'] == 1
assert result['warnings'] == base['warnings'] and base['errors'] == [REFUSAL_ERROR]
checks = 1


def reject(events):
    global checks
    result = reclassify(base, events, end)
    assert not result['pass'] and REFUSAL_ERROR in result['errors'], result
    assert result['cleanup_tcp_refusal_correction']['classified_warning_count'] == 0, result
    checks += 1


for row, key, value in [
    (0, 'direction', 'sent'), (0, 'code', 5), (0, 'subcode', 4),
    (0, 'code', '6'), (0, 'peer', '127.1.0.2'), (1, 'peer', '127.1.0.2'),
    (2, 'peer', '127.1.0.2'), (2, 'failure_source', 'task'),
    (2, 'previously_established', False), (2, 'previously_established', 'true'),
    (2, 'error', 'Connection timed out (os error 110)'),
]:
    events = deepcopy(valid); events[row]['fields'][key] = value; reject(events)
for row in (0, 1, 2):
    events = deepcopy(valid); del events[row]['fields']['peer']; reject(events)
reject(valid[1:])  # Missing notification.
reject([valid[0], valid[2]])  # Missing own down.
reject([valid[0], valid[1], event(13, 'session established'), valid[2]])
reject([valid[0], valid[1], event(13, 'session state changed', to='established'), valid[2]])
events = deepcopy(valid)
for row, second in zip(events, (1, 2, 7)):
    row['timestamp'] = f'2026-09-10T00:00:{second:02d}+00:00'
reject(events)  # Whole sequence occurs before measured completion.
events = deepcopy(valid); events[0]['timestamp'] = '2026-09-10T00:00:10+00:00'; reject(events)
events = deepcopy(valid); events[1]['timestamp'] = 'invalid'; reject(events)
events = deepcopy(valid); events[1]['timestamp'] = '2026-09-10T00:00:12'; reject(events)
reject([valid[1], valid[0], valid[2]])  # Wrong notification/down order.
# Independently classified warnings must never erase an active refusal with identical text.
active = event(7, 'TCP connect failed', failure_source='socket', previously_established=True,
               error='Connection refused (os error 111)')
result = reclassify({**base, 'errors': [REFUSAL_ERROR, REFUSAL_ERROR, 'probes.csv failure']}, [active, *valid], end)
assert result['errors'] == [REFUSAL_ERROR, 'probes.csv failure'] and not result['pass']
assert result['cleanup_tcp_refusal_correction']['classified_warning_count'] == 1
# Daemon errors, session-loss failures, health failures and unrelated warning errors survive.
for error in ('daemon ERROR: failed', 'session loss before measured completion', 'probes.csv failure', 'unclassified/active WARN: TCP connect task failed'):
    result = reclassify({**base, 'errors': [REFUSAL_ERROR, error]}, valid, end)
    assert result['errors'] == [error] and not result['pass']
    checks += 1
# A count mismatch is malformed evidence, not permission to drop an error.
result = reclassify({**base, 'errors': [REFUSAL_ERROR, REFUSAL_ERROR]}, valid, end)
assert not result['pass'] and result['errors'][:2] == [REFUSAL_ERROR, REFUSAL_ERROR]
# Concurrent startup logging may be unordered; v3 must not invent a failure.
unordered_startup = [event(3, 'session down'), event(2, 'BGP NOTIFICATION', direction='received', code=6, subcode=2)]
clean = {'gate_version': 2, 'pass': True, 'errors': [], 'warnings': []}
result = reclassify(clean, unordered_startup, end)
assert result['pass'] and result['errors'] == []
# Even for the candidate peer, startup ordering cannot invalidate proven final cleanup.
result = reclassify(base, [*unordered_startup, *valid], end)
assert result['pass'] and result['cleanup_tcp_refusal_correction']['classified_warning_count'] == 1
# Unrelated peers are outside the supplemental rule, including after completion.
unrelated = [event(19, 'session down', peer='127.1.0.9'), event(18, 'session established', peer='127.1.0.9')]
result = reclassify(base, [*unrelated, *valid], end)
assert result['pass'] and result['cleanup_tcp_refusal_correction']['classified_warning_count'] == 1
print(f'{checks + 5} cleanup-classifier cases passed')
