#!/usr/bin/env python3
"""Compare every retained health invocation marker with its exact CSV start key."""
from collections import Counter
import csv
import json
from pathlib import Path
import re
import sys


def audit(root):
    with (root / 'rustbgpd/probes.csv').open() as f:
        rows = list(csv.DictReader(f))
    blocks = []
    unassociated = []
    for line in (root / 'rustbgpd/probes.csv.stderr.log').read_text().splitlines():
        start = re.fullmatch(r'probe_start epoch_s=([0-9.]+)', line)
        if start:
            blocks.append({'epoch_s':start[1], 'stderr':[]})
        elif line.strip():
            (blocks[-1]['stderr'] if blocks else unassociated).append(line)
    starts = Counter(b['epoch_s'] for b in blocks)
    completions = Counter(r['epoch_s'] for r in rows)
    unmatched_starts = starts - completions
    unmatched_csv = completions - starts
    return {
        'method':'exact epoch_s string comparison between probe_start markers and CSV rows',
        'started_invocations':len(blocks),
        'completed_csv_rows':len(rows),
        'failed_csv_rows':sum(int(r['exit']) != 0 for r in rows),
        'all_start_markers_have_csv_rows':not unmatched_starts,
        'all_csv_rows_have_start_markers':not unmatched_csv,
        'duplicate_start_keys':{k:v for k,v in starts.items() if v > 1},
        'duplicate_csv_keys':{k:v for k,v in completions.items() if v > 1},
        'unmatched_started_invocations':[b for b in blocks if b['epoch_s'] in unmatched_starts],
        'unmatched_csv_keys':dict(unmatched_csv),
        'invocations_with_stderr':[b for b in blocks if b['stderr']],
        'unassociated_stderr':unassociated,
        'rib_query_invocation_start_markers_recorded':False,
    }

if __name__ == '__main__':
    print(json.dumps(audit(Path(sys.argv[1])), indent=2))
