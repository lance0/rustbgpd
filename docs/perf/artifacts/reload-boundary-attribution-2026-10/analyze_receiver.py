#!/usr/bin/env python3
"""Validate bounded canonical receiver trace; never infer kernel readiness."""
import argparse
import csv
import json
import math
from pathlib import Path
import statistics


def require(ok, why):
    if not ok:
        raise ValueError(why)


def insert(rows, key, value, label):
    require(key not in rows, f'duplicate {label}: {key}')
    rows[key] = value


def fields(line, prefix, names):
    row = next(csv.reader([line]))
    require(row[0] == prefix and len(row) == len(names) + 1, f'malformed {prefix}')
    return dict(zip(names, row[1:]))


def integers(row, except_fields=()):
    result = {k: (v if k in except_fields else int(v)) for k, v in row.items()}
    require(all(v >= 0 for k, v in result.items() if k not in except_fields and k != 'result'), 'negative trace field')
    return result


def quantiles(values):
    require(bool(values), 'empty distribution')
    values = sorted(values)
    return {name: values[math.floor((len(values)-1)*p + 0.5)]
            for name, p in [('p50', .5), ('p95', .95), ('max', 1)]}


def clock_interval(anchors):
    require(bool(anchors), 'missing clock anchors')
    for before, wall, after in anchors:
        require(0 <= before <= after and wall > after, 'invalid clock bracket')
    low = max(wall-after for before, wall, after in anchors)
    high = min(wall-before for before, wall, after in anchors)
    require(low <= high, 'clock anchors disagree: realtime/monotonic mapping unqualified')
    require(high-low <= 50_000, 'clock bracket exceeds declared 50 us budget')
    return low, high


OUTCOME = 'round observer trigger end first complete unique marker gap gap_count all_gap all_gap_count'.split()
RECEIVER = ('round observer marker frame_start frame_end '
            'first_start first_end first_poll first_ready first_done first_pending '
            'last_start last_end last_poll last_ready last_done last_pending '
            'decode_start decode_end classify_end observer_us').split()
WRITER = ('round peer bulk_start bulk_end target_start target_end stream_start '
          'started finished success accepted count dumped').split()
POLL = 'round peer ordinal before after offset result'.split()
MEMBER = ('round peer release_before release_after entry producer polls poll snapshot_before '
          'snapshot_after admission_before admission_after ordinal byte_start byte_end invalid').split()


def read_harness(path, peers, probe):
    outcomes, receiver, clocks, native, gaps, all_gaps = {}, {}, {}, {}, {}, {}
    for line in Path(path).read_text().splitlines():
        if line.startswith('phase_outcome,'):
            row = integers(fields(line, 'phase_outcome', OUTCOME), ('gap','all_gap'))
            for name in ('gap','all_gap'):
                row[name]=float(row[name])
                require(math.isfinite(row[name]) and row[name]>=0,'invalid gap')
            insert(outcomes, (row['round'], row['observer']), row, 'outcome')
        elif line.startswith(('phase_gap,','phase_all_gap,')):
            prefix=line.split(',',1)[0]
            row=integers(fields(line,prefix,'round observer ordinal start end kind'.split()),('kind',))
            require(row['kind'] in ('leading','update','trailing'),'unknown gap kind')
            insert(gaps if prefix=='phase_gap' else all_gaps,(row['round'],row['observer'],row['ordinal']),row,'gap span')
        elif line.startswith('phase_receiver,') and probe is not None:
            row = integers(fields(line, 'phase_receiver', RECEIVER))
            insert(receiver, (row['round'], row['observer']), row, 'receiver')
        elif line.startswith('phase_clock,'):
            row = integers(fields(line, 'phase_clock', 'round kind before wall after'.split()), ('kind',))
            require(row['kind'] in ('before', 'after'), 'unknown clock kind')
            insert(clocks, (row['round'], row['kind']), tuple(row[k] for k in ('before', 'wall', 'after')), 'clock')
        elif line.startswith('reloadstall_csv,') and line.split(',')[1].isdigit():
            row = next(csv.reader([line]))
            require(len(row) == 23, 'native aggregate columns changed')
            insert(native, int(row[1]), row, 'native aggregate')
    expected = {(r, i) for r in range(1,5) for i in range(peers)}
    require(set(outcomes) == expected, 'incomplete exact observer/round coverage')
    if probe is not None:
        require(set(receiver) == (expected if probe else set()), 'incorrect receiver probe coverage')
    require(set(clocks) == {(r, k) for r in range(1,5) for k in ('before','after')}, 'clock coverage')
    require(set(native) == set(range(1,5)), 'native round coverage')
    for name,values in [('gap',gaps),('all_gap',all_gaps)]:
        require(set(values)=={(r,i,j) for (r,i),o in outcomes.items() for j in range(o[name+'_count'])},'missing or extra maximum-gap tie')
    for (r, i), row in outcomes.items():
        require(0 < row['trigger'] <= row['first'] <= row['complete'] <= row['end'], 'outcome time order')
        require(row['unique'] == peers*572-572, 'outcome exact generation prefix coverage')
        for name,entries,end,trailing in [('gap',gaps,row['complete'],False),('all_gap',all_gaps,row['end'],True)]:
            require(row[name+'_count']>0,'missing maximum gap')
            spans=[entries[r,i,j] for j in range(row[name+'_count'])]
            previous=row['trigger']
            for span in spans:
                require(row['trigger']<=span['start']<=span['end']<=end and span['start']>=previous,'gap span order/window')
                require(abs(span['end']-span['start']-row[name]*1000)<.00001,'gap span magnitude mismatch')
                require(span['kind']!='leading' or span['start']==row['trigger'],'leading span origin')
                require(span['kind']!='trailing' or (trailing and span['end']==end),'trailing span end/scope')
                previous=span['end']
            row[name+'s']=spans
            matches=[span['kind']!='trailing' and span['end']==row['first'] for span in spans]
            relation='all' if all(matches) else ('one_of_ties' if any(matches) else 'none')
            row['first_generation_max_gap_relation' if name=='gap' else 'first_generation_all_gap_relation']=relation
        n = native[r]
        require([int(x) for x in n[2:6]] == [peers, peers, 0, peers*572], 'wrong canonical native shape')
        require([int(x) for x in n[20:23]] == [0,peers,0], 'native integrity failure')
    prior_end = 0
    for r in range(1, 5):
        n = native[r]
        rows = [v for (round_, _),v in outcomes.items() if round_ == r]
        for field, index, unit in [('gap', 9, 1), ('all_gap', 12, 1), ('complete', 6, 1e6), ('first', 15, 1000)]:
            values = [v[field] if field in ('gap','all_gap') else (v[field]-v['trigger'])/unit for v in rows]
            measured = quantiles(values)
            for j, q in enumerate(('p50', 'p95', 'max')):
                require(abs(measured[q]-float(n[index+j])) <= (.00000051 if field == 'complete' else .00051), 'observer/native aggregate mismatch')
        require({v['marker'] for v in rows} == {(65400 << 16) | (2000 if r % 2 else 1000)}, 'round marker mismatch')
        require(len({(v['trigger'],v['end']) for v in rows}) == 1, 'inconsistent round window')
        require(rows[0]['trigger'] > prior_end, 'overlapping or relabeled rounds')
        prior_end = rows[0]['end']
    return outcomes, receiver, clocks, native


def read_daemon(path):
    writers, polls = {}, {}
    for line in Path(path).read_text().splitlines():
        if line.startswith('phase_writer,'):
            row = integers(fields(line, 'phase_writer', WRITER), ('peer',))
            insert(writers, (row['round'], row['peer']), row, 'writer')
        elif line.startswith('phase_write_poll,'):
            row = integers(fields(line, 'phase_write_poll', POLL), ('peer',))
            insert(polls, (row['round'], row['peer'], row['ordinal']), row, 'write poll')
    return writers, polls


def read_publication(path):
    members, anchors = {}, []
    for line in Path(path).read_text().splitlines():
        if line.startswith('member,'):
            row = integers(fields(line, 'member', MEMBER), ('peer',))
            insert(members, (row['round'],row['peer']), row, 'member')
        elif line.startswith('clock,'):
            _, before, after, _ = line.split(',')
            # publication_trace::now uses epoch elapsed + 1 ns.
            anchors.append((1, int(after), 1 + int(after)-int(before)))
        elif line.startswith('clock_end,'):
            _, before, wall, after = line.split(',')
            anchors.append((int(before), int(wall), int(after)))
    return members, clock_interval(anchors)


def peer_for(i):
    return f'127.1.{i//200}.{i%200+1}'


def join_one(outcome, receiver, writer, polls, member, receiver_clock, daemon_clock):
    o, r, w, m = outcome, receiver, writer, member
    require(m['admission_before'] <= w['started'], 'writer predates queue admission bracket')
    require(w['success'] == 1 and w['accepted'] == w['bulk_end']-w['bulk_start'], 'incomplete writer batch')
    require(0 <= w['bulk_start'] <= w['target_start'] < w['target_end'] <= w['bulk_end'], 'invalid FIFO containment')
    require([w['target_start'],w['target_end']] == [m['byte_start'],m['byte_end']], 'writer/admission mismatch')
    mapped = [w['stream_start']+w[k]-w['bulk_start'] for k in ('target_start','target_end')]
    require(mapped == [r['frame_start'],r['frame_end']], 'expected frame is not the exact admitted chunk')
    require(r['marker'] == o['marker'] and r['observer_us'] == o['first'], 'wrong generation/event join')
    require(w['count'] == len(polls) and 0 < len(polls) <= 64, 'write poll count/overflow')
    require(w['finished'] <= w['dumped'], 'writer dump predates write completion')
    offset, previous = 0, w['started']
    accepted = []
    for i, p in enumerate(polls):
        require(p['ordinal'] == i and p['offset'] == offset, 'write poll FIFO discontinuity')
        require(previous <= p['before'] <= p['after'] <= w['finished'], 'write poll time order')
        require(p['result'] == -1 or p['result'] > 0, 'failed/zero write poll')
        previous = p['after']
        if p['result'] > 0:
            accepted.append((w['stream_start']+offset, w['stream_start']+offset+p['result'], p))
            offset += p['result']
    require(offset == w['accepted'], 'writer poll acceptance mismatch')
    for label, byte in [('first',r['frame_start']),('last',r['frame_end']-1)]:
        require(0 <= r[label+'_start'] <= byte < r[label+'_end'], 'read byte interval mismatch')
        require(0 < r[label+'_poll'] <= r[label+'_ready'] <= r[label+'_done'], 'read poll time order')
    require(r['first_start'] <= r['last_start'] and r['first_end'] <= r['last_end'], 'read FIFO order')
    require(r['first_done'] <= r['last_done'] <= r['decode_start'] <= r['decode_end'] <= r['classify_end'] < (r['observer_us']+1)*1000, 'receiver phase order')
    first_write = next((p for start,end,p in accepted if start <= r['frame_start'] < end),None)
    last_write = next((p for start,end,p in accepted if start <= r['frame_end']-1 < end),None)
    require(first_write is not None and last_write is not None, 'missing accepted frame bytes')
    # Difference between process monotonic epochs; no wall-clock timestamps on hot path.
    delta_low, delta_high = receiver_clock[0]-daemon_clock[1], receiver_clock[1]-daemon_clock[0]
    for label,p in [('first',first_write),('last',last_write)]:
        require(r[label+'_done'] + delta_high >= p['before'], 'receiver completed bytes before writer acceptance bracket')
    values = {
        'first_read_poll_ns': r['first_done']-r['first_ready'],
        'last_read_poll_ns': r['last_done']-r['last_ready'],
        'frame_read_completion_span_ns': r['last_done']-r['first_done'],
        'final_read_to_decode_start_ns': r['decode_start']-r['last_done'],
        'decode_ns': r['decode_end']-r['decode_start'],
        'classification_ns': r['classify_end']-r['decode_end'],
    }
    for label,p in [('first',first_write),('last',last_write)]:
        values[label+'_accept_to_read_poll_lower_ns'] = r[label+'_ready'] + delta_low - p['after']
        values[label+'_accept_to_read_poll_upper_ns'] = r[label+'_ready'] + delta_high - p['before']
    return values


def require_deferred_dump(writer, final_end_us, receiver_clock, daemon_clock):
    require(writer['dumped'] + daemon_clock[0] >= final_end_us*1000 + receiver_clock[1],
            'writer emitted trace before final measured window ended')


def analyze(harness, daemon=None, publication=None, peers=700):
    probe = daemon is not None
    outcomes, receivers, clocks, native = read_harness(harness, peers, probe)
    summary = {'probe': probe, 'observers_per_round': peers, 'rounds': {},
               'native_stall_p50_median_ms': statistics.median(float(native[r][9]) for r in range(1,5)),
               'native_completion_p50_median_s': statistics.median(float(native[r][6]) for r in range(1,5))}
    summary['native_rounds'] = [{'round': r, 'stall_p50_ms': float(native[r][9]),
                                 'completion_p50_s': float(native[r][6])} for r in range(1,5)]
    if not probe:
        return summary
    writers, all_polls = read_daemon(daemon)
    members, daemon_clock = read_publication(publication)
    expected = {(r,peer_for(i)) for r in range(1,5) for i in range(peers)}
    require(set(writers) == expected and set(members) == expected, 'exact writer/member coverage')
    require(set(all_polls) == {(r,p,j) for (r,p),w in writers.items() for j in range(w['count'])}, 'extraneous/missing write polls')
    final_clock = clock_interval([clocks[4,k] for k in ('before','after')])
    for w in writers.values():
        require_deferred_dump(w, outcomes[4,0]['end'], final_clock, daemon_clock)
    for round_ in range(1,5):
        receiver_clock = clock_interval([clocks[round_,k] for k in ('before','after')])
        values=[]
        for i in range(peers):
            key=(round_,peer_for(i));w=writers[key]
            values.append(join_one(outcomes[round_,i],receivers[round_,i],w,
                [all_polls[*key,j] for j in range(w['count'])],members[key],receiver_clock,daemon_clock))
        summary['rounds'][round_] = {
            'first_generation_max_gap_relations': {relation:[i for i in range(peers) if outcomes[round_,i]['first_generation_max_gap_relation']==relation] for relation in ('all','one_of_ties','none')},
            'first_generation_all_gap_relations': {relation:[i for i in range(peers) if outcomes[round_,i]['first_generation_all_gap_relation']==relation] for relation in ('all','one_of_ties','none')},
            'phases': {name: quantiles([v[name] for v in values]) for name in values[0]},
            'slowest_observers': sorted(range(peers),key=lambda i: outcomes[round_,i]['gap'])[-math.ceil(peers*.05):],
            'receiver_clock_offset_bounds_ns': receiver_clock,
            'daemon_clock_offset_bounds_ns': daemon_clock,
        }
    return summary


if __name__ == '__main__':
    p=argparse.ArgumentParser()
    p.add_argument('harness'); p.add_argument('--daemon'); p.add_argument('--publication')
    p.add_argument('--peers',type=int,default=700)
    a=p.parse_args()
    print(json.dumps(analyze(a.harness,a.daemon,a.publication,a.peers),indent=2))
