#!/usr/bin/env python3
"""Recompute every native join and the failed six-process overhead qualification."""
import csv
import hashlib
import importlib.machinery
import importlib.util
import json
from decimal import Decimal
from pathlib import Path
import re
import tarfile
import tempfile

import analyze_receiver as receiver
import collect_campaign as campaign
import qualify
import read_publication as publication

ROOT = Path(__file__).resolve().parent
SOURCE = '49abbb0171cbb889b7e2618c2bdcec6ea35699ae'
TREE = 'c70b6296af9880d350acea376eb1942ba8dbc72d'
METHOD_SHA = 'b28669ef45471c6ea885f8635d4adccc6b329cf6409d887198357386a905b632'
BUILD_SHA = 'c74744cb4f5ddbce45cc29a1d4cd70e81ccc81c9f8f663e62d5d5b896c819def'
PEERS = 700
ROUNDS = range(1, 5)
require = receiver.require


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def relative_file(root, name):
    require(isinstance(name, str) and Path(name).name == name and name not in ('', '.', '..'),
            'artifact name must be a local basename')
    path = root / name
    require(path.is_file() and not path.is_symlink(), 'artifact absent or symbolic')
    return path


def verify_hashes(root):
    entries = {}
    for line in (root / 'SHA256SUMS').read_text().splitlines():
        sha, name = line.split('  ', 1)
        require(name not in entries and len(sha) == 64, 'duplicate or malformed hash entry')
        entries[name] = sha
    require(set(entries) == {p.name for p in root.iterdir() if p.is_file() and p.name != 'SHA256SUMS'},
            'hash manifest must cover every artifact')
    for name, sha in entries.items():
        require(digest(relative_file(root, name)) == sha, f'artifact hash mismatch: {name}')


def extract_native(root, destination):
    manifest = json.loads((root/'native-extraction.json').read_text())['files']
    with tarfile.open(root/'native-records.tar.gz', 'r:gz') as archive:
        members = archive.getmembers()
        require(len(members) == len(manifest) and {m.name for m in members} == set(manifest),
                'native archive coverage differs from manifest')
        for member in members:
            require(member.isfile() and not Path(member.name).is_absolute() and
                    '..' not in Path(member.name).parts, 'unsafe native archive entry')
            data = archive.extractfile(member).read()
            require(hashlib.sha256(data).hexdigest() == manifest[member.name]['public_sha256'],
                    'native extract hash mismatch')
            path = destination/member.name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)


def validate_plan(plan):
    require(plan['source_commit'] == SOURCE and plan['schema'] == 1, 'wrong source or plan schema')
    require(plan['shape'] == {'peers': 700, 'prefixes': 400400, 'rounds_per_process': 4,
        'control_seconds': 30, 'changed_peers': 'all', 'policy': 'canonical import plus export',
        'reader_pacing': 'none', 'added_rtt_ms': 0, 'allocator': 'jemalloc default',
        'daemon_features': 'default'}, 'wrong canonical workload')
    require([(v['pair'], v['arm']) for v in plan['order']] == qualify.ORDER, 'wrong planned arm order')
    require(plan['overhead']['maximum_regression_percent'] == 2 and
            plan['overhead']['metrics'] == ['changed_maxgap_p50_ms', 'completion_p50_s'], 'changed overhead bar')
    require(plan['clock']['receiver_epoch_intersection_width_budget_us'] == 50 and
            plan['clock']['publication_start_end_budget_us'] == 100, 'changed clock budget')


def probe_rows(harness, daemon, pub_path, leg_name):
    # Original parsers retain the canonical identities and reject duplicate or absent records.
    pub = publication.read(pub_path)
    require(pub['cross_process_clock_qualified'], 'publication clock rejected')
    outcomes, received, clocks, _ = receiver.read_harness(harness, PEERS, True)
    writers, polls = receiver.read_daemon(daemon)
    members, daemon_clock = receiver.read_publication(pub_path)
    publication_rows = {(row['group'], row['peer']): row for row in pub['rows']}
    joined = []
    for round_ in ROUNDS:
        receiver_clock = receiver.clock_interval([clocks[round_, kind] for kind in ('before', 'after')])
        for observer in range(PEERS):
            peer = receiver.peer_for(observer)
            key = round_, peer
            w = writers[key]
            phases = receiver.join_one(outcomes[round_, observer], received[round_, observer], w,
                [polls[*key, i] for i in range(w['count'])], members[key], receiver_clock, daemon_clock)
            row = {'leg': leg_name, 'round': round_, 'observer': observer, 'peer': peer}
            for prefix, values in [('outcome', outcomes[round_, observer]), ('publication', publication_rows[key]),
                                   ('receiver', received[round_, observer]), ('writer', w), ('phase', phases)]:
                for name, value in values.items():
                    if prefix == 'publication' and isinstance(value, list):
                        for suffix, item in zip(('lower', 'upper'), value, strict=True):
                            row[f'{prefix}_{name}_{suffix}'] = item
                    elif isinstance(value, (list, dict)):
                        row[f'{prefix}_{name}'] = json.dumps(value, sort_keys=True, separators=(',', ':'))
                    else:
                        row[f'{prefix}_{name}'] = value
            joined.append(row)
    return pub, joined


def validate_bindings(root):
    require(digest(root/'execution-methods.sha256') == METHOD_SHA, 'wrong executed method freeze')
    require(digest(root/'build-bindings.json') == BUILD_SHA, 'wrong frozen binary bindings')
    frozen = json.loads((root/'build-bindings.json').read_text())
    require(frozen['source_commit'] == SOURCE, 'wrong producer source')
    methods = dict(line.split('  ', 1)[::-1] for line in (root/'execution-methods.sha256').read_text().splitlines())
    bindings = json.loads((root/'method-bindings.json').read_text())
    for name, item in bindings['public_method_files'].items():
        require(item['executed_sha256'] == methods[name] and item['public_sha256'] == digest(root/name),
                'public method binding differs')
        if item['unchanged']:
            require(item['public_sha256'] == item['executed_sha256'], 'false unchanged helper claim')
        else:
            require(digest(root/('executed-'+name+'.txt')) == item['executed_sha256'],
                    'missing executed helper original')
    receipts = json.loads((root/'execution-receipts.json').read_text())
    require(receipts['source_commit'] == SOURCE and receipts['source_tree'] == TREE, 'wrong receipt source')
    require(len(receipts['legs']) == 6, 'incomplete execution receipts')
    for leg in receipts['legs']:
        require(leg['source_before_sha256'] == leg['source_after_sha256'], 'source changed during execution')
        require(leg['cleanup_exit'] == 0 and leg['owned_processes_remaining'] == 0, 'incomplete cleanup receipt')
    return frozen


def original_receiver(root):
    loader = importlib.machinery.SourceFileLoader('executed_receiver', str(root/'executed-analyze_receiver.py.txt'))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
    loader.exec_module(module)
    return module


def compute_native(root, native, verify_original=True):
    frozen = validate_bindings(root)
    validate_plan(json.loads((root/'plan.json').read_text()))
    previous_end, previous_mono = Decimal(0), 0
    previous_boot, previous_start = None, 0
    legs, summaries, joined = [], [], []
    original = original_receiver(root) if verify_original else None
    for number, (pair, arm) in enumerate(qualify.ORDER, 1):
        label = f'{number:02d}-{arm}'
        leg = native/label
        cell = leg/'matrix/rustbgpd'
        campaign.validate_method_freeze(leg, (root/'execution-methods.sha256').read_bytes())
        previous_end = campaign.validate_leg_metadata(leg, arm, frozen, previous_end, previous_mono)
        previous_mono = int((leg/'finished.monotonic_ns').read_text())
        for name in ('runner.exit', 'identity.exit', 'sampler.exit', 'cleanup.exit'):
            require((leg/name).read_text().strip() == '0', f'{name} failed')
        require((cell/'status').read_text().strip() == 'pass' and
                (cell/'daemon.exit').read_text().strip() == '0', 'failed native execution')
        match = re.search(r'^pid=(\d+) pgid=(\d+) starttime=(\d+) cgroup=', (leg/'sampler.log').read_text())
        require(match is not None, 'missing process identity')
        identity, previous_boot, previous_start = campaign.validate_process(
            match, json.loads((leg/'runner.owner.json').read_text()), previous_boot, previous_start)
        harness = cell/'reloadstall.log'
        probe = arm == 'probe'
        daemon, pub_path = (cell/'daemon.log', leg/'publication.csv') if probe else (None, None)
        parsed = receiver.analyze(harness, daemon, pub_path)
        if original:
            require(parsed == original.analyze(harness, daemon, pub_path), 'public helper changed full analysis')
        outcomes, _, _, rows = receiver.read_harness(harness, PEERS, probe)
        detail = {'receiver': parsed}
        if probe:
            pub, joined_rows = probe_rows(harness, daemon, pub_path, label)
            detail['publication'] = pub
            joined.extend(joined_rows)
        else:
            require((cell/'daemon.log').read_text() == '' and not (leg/'publication.csv').exists(), 'probe in control')
        native_rows = [{'round': r, 'stall_p50_ms': rows[r][9], 'completion_p50_s': rows[r][6]} for r in ROUNDS]
        legs.append({'pair': pair, 'arm': arm, 'process_identity': identity,
                     'native_rounds': native_rows, 'joins_and_clocks_qualified': True, 'errors': [], 'detail': detail})
        summaries.append({'leg': label, 'native_rounds': [rows[r] for r in ROUNDS], 'receiver': parsed,
                          'publication_groups': detail.get('publication', {}).get('groups', []),
                          'outcome_count': len(outcomes)})
    with (root/'rounds.csv').open() as stream:
        table = list(csv.reader(stream))
    native_header = next(line.split(',') for line in harness.read_text().splitlines()
                         if line.startswith('reloadstall_csv_header,'))
    require(table[0] == ['leg', 'round', *native_header[2:]], 'native round table header differs')
    require(table[1:] == [[leg['leg'], *row[1:]] for leg in summaries for row in leg['native_rounds']],
            'native round table differs from logs')
    result = qualify.qualify(legs)
    require(len(joined) == 8400, 'incomplete exact first-frame joins')
    import diagnostics
    diagnostics_result = diagnostics.analyze(native, result)
    compact_qualification = {k: v for k, v in result.items() if k != 'legs'}
    output = {'source_commit': SOURCE, 'attempt': 'campaign-01', 'retry_performed': False,
            'native_rounds': 24, 'outcomes': 16800, 'joined_first_frames': len(joined),
            'joined_rows_sha256': fingerprint(joined), 'original_reader_equal': verify_original,
            'qualification': compact_qualification, 'legs': summaries, 'diagnostics': diagnostics_result}
    # JSON object keys are strings; normalize only at the artifact boundary.
    return json.loads(json.dumps(output, allow_nan=False))


def recompute(root=ROOT):
    verify_hashes(root)
    with tempfile.TemporaryDirectory() as tmp:
        native = Path(tmp)
        extract_native(root, native)
        actual = compute_native(root, native)
    expected = json.loads((root/'results.json').read_text())
    require(actual == expected, 'recomputed result differs from retained receipt')
    return actual


if __name__ == '__main__':
    result = recompute()
    print(json.dumps({key: value for key, value in result.items() if key not in ('legs', 'diagnostics')}, indent=2))
