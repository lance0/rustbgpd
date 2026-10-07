#!/usr/bin/env python3
"""Strict reader for temporary publication traces; no production-tail qualification."""
import argparse
import csv
import json
import math
from pathlib import Path

FIELDS = ('release_before release_after entry producer polls poll snapshot_before '
          'snapshot_after admission_before admission_after ordinal byte_start byte_end invalid').split()
HEADER = ['member_header', 'group', 'peer', *FIELDS]
CLOCK_BUDGET_NS = 100_000


def require(condition, message):
    if not condition:
        raise ValueError(message)


def natural(text):
    require(text.isascii() and text.isdecimal(), f'non-integer observation {text!r}')
    return int(text)


def unique(mapping, key, value):
    require(key not in mapping, f'duplicate identity {key}')
    mapping[key] = value


def quantiles(values):
    values = sorted(values)
    require(bool(values), 'empty distribution')
    return {label: values[round((len(values) - 1) * p)]
            for label, p in [('p50', .5), ('p95', .95), ('max', 1)]}


def read(path, members=700, rounds=4, min_routes=400400):
    groups, peers, chunks, clocks = {}, {}, {}, {}
    header = False
    for row in csv.reader(Path(path).read_text().splitlines()):
        require(bool(row), 'blank row')
        kind = row[0]
        if kind == 'member_header':
            require(not header and row == HEADER, 'duplicate or altered member header')
            header = True
        elif kind in ('clock', 'clock_end'):
            require(len(row) == 4, 'bad clock arity')
            unique(clocks, kind, list(map(natural, row[1:])))
        elif kind == 'group':
            require(len(row) == 8, 'bad group arity')
            group, routes, count, chunk_count, overflow, terminal, pointer = map(natural, row[1:])
            unique(groups, group, dict(routes=routes, members=count, chunks=chunk_count,
                                      overflow=overflow, terminal=terminal, pointer=pointer))
        elif kind == 'member':
            require(len(row) == 3 + len(FIELDS), 'bad member arity')
            group, peer = natural(row[1]), row[2]
            unique(peers, (group, peer), dict(zip(FIELDS, map(natural, row[3:]), strict=True)))
        elif kind == 'chunk':
            require(len(row) == 8, 'bad chunk arity')
            group, ordinal = map(natural, row[1:3])
            source = row[3]
            afi, length, before, after = map(natural, row[4:])
            unique(chunks, (group, ordinal), dict(source=source, afi=afi, length=length,
                                                before=before, after=after))
        else:
            raise ValueError(f'unknown row {kind!r}')
    require(header and set(clocks) == {'clock', 'clock_end'}, 'incomplete headers')
    require(set(groups) == set(range(1, rounds + 1)), 'incomplete group identities')
    require(len(peers) == members * rounds, 'incomplete peer coverage')
    require(all(group in groups for group, _ in peers), 'unknown peer group')
    require(all(group in groups for group, _ in chunks), 'unknown chunk group')
    initial_before, initial_after, dump_start = clocks['clock']
    end_before, end_wall, end_after = clocks['clock_end']
    require(0 < initial_before <= initial_after and 0 < dump_start <= end_before <= end_after,
            'invalid or swapped clock columns')
    # now() is origin.elapsed()+1, so subtract one when mapping to wall time.
    drift_low = end_wall - (initial_after + end_after - 1)
    drift_high = end_wall - (initial_before + end_before - 1)
    clock_stable = max(abs(drift_low), abs(drift_high), initial_after-initial_before,
                       end_after-end_before) <= CLOCK_BUDGET_NS
    result = dict(clock=dict(initial_wall_bracket_ns=[initial_before, initial_after],
                             end_monotonic_bracket_ns=[end_before, end_after],
                             end_wall_ns=end_wall, drift_bounds_ns=[drift_low, drift_high],
                             budget_ns=CLOCK_BUDGET_NS, stable=clock_stable), groups=[], rows=[])
    expected_peers = None
    for group, meta in sorted(groups.items()):
        require(meta['routes'] >= min_routes and meta['members'] == members and meta['pointer'] > 0,
                'wrong inventory or cohort size')
        require(meta['overflow'] == 0 and meta['terminal'] == 1, 'overflow or failed producer')
        group_chunks = dict(sorted((ordinal, chunk) for (g, ordinal), chunk in chunks.items() if g == group))
        require(set(group_chunks) == set(range(meta['chunks'])) and meta['chunks'] > 0,
                'incomplete chunk ordinals')
        group_peers = {peer: value for (g, peer), value in peers.items() if g == group}
        require(len(group_peers) == members, 'incomplete group peer coverage')
        if expected_peers is None:
            expected_peers = set(group_peers)
        require(set(group_peers) == expected_peers, 'changing peer inventory')
        require({v['source'] for v in group_chunks.values()} == expected_peers,
                'published source coverage differs from canonical cohort')
        require(sum(v['producer'] for v in group_peers.values()) == 1 and
                all(v['producer'] in (0, 1) for v in group_peers.values()), 'producer ownership')
        previous = None
        for chunk in group_chunks.values():
            require(chunk['afi'] == 1 and 19 <= chunk['length'] <= 4096, 'noncanonical chunk')
            require(0 < chunk['before'] <= chunk['after'] <= dump_start, 'invalid publication bounds')
            if previous is not None:
                require(chunk['before'] == previous['before'] and chunk['after'] == previous['after']
                        or chunk['before'] >= previous['after'], 'unordered publication batches')
            previous = chunk
        rows = []
        for peer, member in sorted(group_peers.items()):
            require(member['invalid'] == 0, 'inventory, exclusion, or duplicate entry mismatch')
            require(0 < member['release_before'] <= member['release_after'] <= dump_start,
                    'invalid release bounds')
            require(member['release_before'] <= member['entry'] <= member['admission_before']
                    <= member['admission_after'] <= dump_start, 'invalid member stage order')
            first = next(i for i, c in group_chunks.items() if c['source'] != peer and c['afi'] == 1)
            require(member['ordinal'] == first, 'not the first source-excluding eligible chunk')
            chunk = group_chunks[first]
            require(member['byte_end'] - member['byte_start'] == chunk['length'], 'chunk FIFO length mismatch')
            row = dict(group=group, peer=peer, inventory=meta['pointer'], chunk_source=chunk['source'],
                       chunk_len=chunk['length'], publication_before=chunk['before'],
                       publication_after=chunk['after'], **member)
            # Each exact release/publication time lies in its retained bracket.
            row['release_to_entry_bounds_ms'] = [max(0, member['entry'] - member['release_after'])/1e6,
                                                 (member['entry']-member['release_before'])/1e6]
            row['entry_to_admission_ms'] = (member['admission_after']-member['entry'])/1e6
            row['enqueue_bracket_ms'] = (member['admission_after']-member['admission_before'])/1e6
            if member['poll'] == 0:
                require(member['producer'] == 1 and member['polls'] == 0 and
                        member['snapshot_before'] == member['snapshot_after'] == 0,
                        'only elected synchronous producer may omit consumer stages')
            else:
                require(member['polls'] > 0 and member['entry'] <= member['poll'] <= member['snapshot_before']
                        <= member['snapshot_after'] <= member['admission_before'], 'invalid advance/snapshot order')
                require(chunk['before'] <= member['snapshot_after'], 'admitted chunk not yet published')
                row['advance_to_snapshot_end_ms'] = (member['snapshot_after'] - member['poll'])/1e6
                row['snapshot_to_enqueue_start_ms'] = (member['admission_before'] - member['snapshot_after'])/1e6
                # Do not force upper publication <= snapshot/poll: concurrent observations can overlap.
                if member['producer'] == 0:
                    row['entry_to_eligible_publication_bounds_ms'] = [max(0, chunk['before']-member['entry'])/1e6,
                                                                     max(0, chunk['after']-member['entry'])/1e6]
                    row['eligible_ready_to_advance_bounds_ms'] = [max(0, member['poll']-max(member['entry'], chunk['after']))/1e6,
                                                                max(0, member['poll']-max(member['entry'], chunk['before']))/1e6]
                    row['eligible_ready_to_snapshot_end_bounds_ms'] = [max(0, member['snapshot_after']-max(member['entry'], chunk['after']))/1e6,
                                                                     max(0, member['snapshot_after']-max(member['entry'], chunk['before']))/1e6]
            rows.append(row)
        release_low = max(v['release_before'] for v in rows) - min(v['release_after'] for v in rows)
        release_high = max(v['release_after'] for v in rows) - min(v['release_before'] for v in rows)
        summary = dict(group=group, inventory_routes=meta['routes'], chunks=meta['chunks'],
                       release_span_bounds_ms=[max(0, release_low)/1e6, release_high/1e6],
                       publication_bracket_ms=quantiles([(c['after']-c['before'])/1e6 for c in group_chunks.values()]),
                       late_release_peers=[v['peer'] for v in sorted(rows, key=lambda v:v['release_before'])[-math.ceil(members*.05):]])
        for name in ('release_to_entry_bounds_ms', 'entry_to_eligible_publication_bounds_ms',
                     'eligible_ready_to_advance_bounds_ms', 'eligible_ready_to_snapshot_end_bounds_ms'):
            selected = [v[name] for v in rows if name in v]
            summary[name] = dict(lower=quantiles([v[0] for v in selected]), upper=quantiles([v[1] for v in selected]))
        for name in ('entry_to_admission_ms', 'enqueue_bracket_ms', 'advance_to_snapshot_end_ms', 'snapshot_to_enqueue_start_ms'):
            summary[name] = quantiles([v[name] for v in rows if name in v])
        result['groups'].append(summary)
        result['rows'].extend(rows)
    result['cross_process_clock_qualified'] = clock_stable
    result['qualification'] = ('join-valid only; six-process overhead and component-repeatability qualification required'
                               if clock_stable else 'clock rejected; cross-process attribution prohibited, internal-clock joins retained')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trace', type=Path)
    parser.add_argument('--members', type=int, default=700)
    parser.add_argument('--rounds', type=int, default=4)
    parser.add_argument('--min-routes', type=int, default=400400)
    args = parser.parse_args()
    print(json.dumps(read(args.trace, args.members, args.rounds, args.min_routes), indent=2))
