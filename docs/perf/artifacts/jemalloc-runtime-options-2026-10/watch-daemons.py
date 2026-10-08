#!/usr/bin/env python3
"""Record the allocator settings of every rustbgpd process started during the campaign.

usage: watch-daemons.py OUT_TSV

Polls /proc once a second. For each new process whose comm is `rustbgpd` it
records the executable, the _RJEM_MALLOC_CONF in its environment ('-' when
absent) and, at about 2, 10 and 30 s after first sight (or at exit, whichever
is first), the number of `jemalloc_bg_thd` threads. A thread named
jemalloc_bg_thd exists only when jemalloc's opt.background_thread is on, so
the count is the read-back of the setting. One row per process is appended
when its last check is done or the process exits. Read-only: it never signals
or touches the daemon.
"""
import os
import sys
import time

out = sys.argv[1]
CHECKS = (2, 10, 30)


def read(path, mode='r'):
    try:
        with open(path, mode) as f:
            return f.read()
    except OSError:
        return None


def bg_threads(pid):
    try:
        tids = os.listdir(f'/proc/{pid}/task')
    except OSError:
        return None
    n = 0
    for tid in tids:
        comm = read(f'/proc/{pid}/task/{tid}/comm')
        if comm and comm.strip() == 'jemalloc_bg_thd':
            n += 1
    return n, len(tids)


seen = {}  # 'pid:starttime' -> state
with open(out, 'a', buffering=1) as f:
    if f.tell() == 0:
        f.write('first_seen\tfirst_seen_epoch\tpid\texe\trjem_malloc_conf\tbg_threads_max\tthreads_last\tchecks\n')
    while True:
        now = time.time()
        for name in os.listdir('/proc'):
            if not name.isdigit():
                continue
            comm = read(f'/proc/{name}/comm')
            if not comm or comm.strip() != 'rustbgpd':
                continue
            stat = read(f'/proc/{name}/stat')
            key = name + ':' + (stat.rsplit(')', 1)[1].split()[19] if stat else '')
            if key in seen:
                continue
            try:
                exe = os.readlink(f'/proc/{name}/exe')
            except OSError:
                continue
            env = read(f'/proc/{name}/environ', 'rb') or b''
            conf = '-'
            for item in env.split(b'\0'):
                if item.startswith(b'_RJEM_MALLOC_CONF='):
                    conf = item.split(b'=', 1)[1].decode()
            seen[key] = {'pid': name, 't0': now, 'exe': exe, 'conf': conf, 'bg': 0, 'threads': 0, 'checks': 0, 'done': False}
        for s in seen.values():
            if s['done']:
                continue
            pid = s['pid']
            alive = os.path.exists(f'/proc/{pid}/task')
            due = s['checks'] < len(CHECKS) and now - s['t0'] >= CHECKS[s['checks']]
            if due and alive:
                r = bg_threads(pid)
                if r:
                    s['bg'] = max(s['bg'], r[0])
                    s['threads'] = r[1]
                    s['checks'] += 1
            if s['checks'] == len(CHECKS) or not alive:
                f.write('%s\t%.3f\t%s\t%s\t%s\t%d\t%d\t%d\n' % (
                    time.strftime('%Y-%m-%dT%H:%M:%S%z', time.localtime(s['t0'])), s['t0'], pid, s['exe'],
                    s['conf'], s['bg'], s['threads'], s['checks']))
                s['done'] = True
        time.sleep(1)
