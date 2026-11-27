#!/usr/bin/env python3
"""Probe whether the host kernel installs FRR's EVPN multihoming VXLAN FDB entry.

FRR installs a remote MAC behind a multihomed Ethernet segment as a dynamic,
externally learned VXLAN FDB entry that references an FDB nexthop group
(state NUD_REACHABLE, flags NTF_SELF|NTF_MASTER|NTF_EXT_LEARNED, NDA_NH_ID).
Some kernels reject that entry with "A nexthop fdb cannot be dynamic"; Linux
commit 7308ef8b4a67 restores it. M121 cannot pass on a rejecting kernel, and
FRR's containers share the host kernel, so the host answer is representative.

The probe also tries rustbgpd's own static form of the row (NUD_NOARP|
NUD_PERMANENT, same flags). That result is recorded only; it never decides the
verdict.

Prints a JSON record on stdout. Verdicts: "supported" (the entry installed),
"rejected" (the kernel refused it with the known message) or "error"
(anything else, exit 1). Under GitHub Actions it also writes the step output
`verdict`, a step summary and, on rejection, a warning annotation.
Commands run through `sudo -n` unless the probe already runs as root.
"""
import json
import os
import subprocess
import sys

UPSTREAM_FIX = '7308ef8b4a67'
REJECTIONS = ('nexthop fdb cannot be dynamic', 'cannot make a nexthop fdb dynamic')
GROUP = '536870913'
# Mirrors one M121 leaf: VNI 100 over a 10.211.0.0/24 underlay, learning off,
# and the two-member remote group FRR builds for the multihomed segment.
SETUP = [
    ['ip', 'link', 'add', 'ul', 'type', 'dummy'],
    ['ip', 'addr', 'add', '10.211.0.3/24', 'dev', 'ul'],
    ['ip', 'link', 'set', 'ul', 'up'],
    ['ip', 'link', 'add', 'br100', 'type', 'bridge', 'mcast_snooping', '0'],
    ['ip', 'link', 'add', 'vx100', 'type', 'vxlan', 'id', '100', 'dstport', '4789',
     'local', '10.211.0.3', 'dev', 'ul', 'nolearning'],
    ['ip', 'link', 'set', 'vx100', 'master', 'br100'],
    ['bridge', 'link', 'set', 'dev', 'vx100', 'learning', 'off'],
    ['ip', 'link', 'set', 'br100', 'up'],
    ['ip', 'link', 'set', 'vx100', 'up'],
    ['ip', 'nexthop', 'add', 'id', '1', 'via', '10.211.0.1', 'fdb'],
    ['ip', 'nexthop', 'add', 'id', '2', 'via', '10.211.0.2', 'fdb'],
    ['ip', 'nexthop', 'add', 'id', GROUP, 'group', '1/2', 'fdb'],
]
# iproute2 starts from NUD_NOARP: "dynamic" clears it and sets NUD_REACHABLE
# (FRR's state); "permanent" adds NUD_PERMANENT (rustbgpd's state).
FORMS = {
    'frr_dynamic': ('02:aa:bb:cc:dd:10', 'dynamic'),
    'rustbgpd_static': ('02:aa:bb:cc:dd:11', 'permanent'),
}


def run(argv):
    prefix = [] if os.geteuid() == 0 else ['sudo', '-n']
    done = subprocess.run(prefix + argv, capture_output=True, text=True, timeout=30)
    return done.returncode, done.stdout, done.stderr


def fdb_command(ns, mac, state, group=GROUP):
    return ['ip', 'netns', 'exec', ns, 'bridge', 'fdb', 'replace', mac, 'dev', 'vx100',
            'self', 'master', 'extern_learn', state, 'nhid', group]


def try_form(runner, ns, mac, state, group=GROUP):
    argv = fdb_command(ns, mac, state, group)
    rc, _, stderr = runner(argv)
    result = dict(command=' '.join(argv), rc=rc, stderr=stderr.strip(), row_installed=False)
    if rc == 0:
        show_rc, out, show_err = runner(['ip', 'netns', 'exec', ns, 'bridge', '-j', 'fdb', 'show', 'dev', 'vx100'])
        if show_rc != 0:
            raise RuntimeError(f'bridge fdb show failed: {show_err.strip()}')
        result['row_installed'] = any(
            row.get('mac') == mac and str(row.get('nhid')) == group and 'self' in row.get('flags', [])
            and 'extern_learn' in row.get('flags', []) for row in json.loads(out or '[]'))
    if result['row_installed']:
        result['result'] = 'supported'
    elif rc != 0 and any(text in stderr.lower() for text in REJECTIONS):
        result['result'] = 'rejected'
    else:
        result['result'] = 'error'
    return result


def probe(runner=run, ns=None, group=GROUP):
    ns = ns or f'm121-fdb-probe-{os.getpid()}'
    record = dict(kernel=os.uname().release, namespace=ns, verdict='error')
    try:
        rc, _, err = runner(['ip', 'netns', 'add', ns])
        if rc != 0:
            raise RuntimeError(f'ip netns add {ns} failed: {err.strip()}')
        try:
            for argv in SETUP:
                rc, _, err = runner(['ip', 'netns', 'exec', ns] + argv)
                if rc != 0:
                    raise RuntimeError(f'{" ".join(argv)} failed: {err.strip()}')
            for name, (mac, state) in FORMS.items():
                record[name] = try_form(runner, ns, mac, state, group)
        finally:
            runner(['ip', 'netns', 'del', ns])
        record['verdict'] = record['frr_dynamic']['result']
    except (RuntimeError, OSError, subprocess.SubprocessError, ValueError) as error:
        record['error'] = str(error)
    return record


def report(record, env=os.environ):
    """Write the GitHub step output, summary and annotation; return the exit code."""
    kernel, verdict = record['kernel'], record['verdict']
    static = record.get('rustbgpd_static', {}).get('result', 'not run')
    if env.get('GITHUB_OUTPUT'):
        with open(env['GITHUB_OUTPUT'], 'a') as output:
            output.write(f'verdict={verdict}\n')
    lines = ['### M121 kernel FDB nexthop probe', '',
             f'- Kernel: `{kernel}`',
             f'- FRR dynamic `extern_learn` entry with `nhid`: **{verdict}**',
             f'- rustbgpd static entry with `nhid` (report only): {static}']
    if verdict == 'rejected':
        lines.append(f'- M121 skipped: kernel `{kernel}` rejects VXLAN FDB nexthop entries '
                     f'(known kernel defect; upstream fix {UPSTREAM_FIX})')
        print(f'::warning title=M121 skipped::kernel {kernel} rejects VXLAN FDB nexthop entries '
              f'(known kernel defect; upstream fix {UPSTREAM_FIX})', file=sys.stderr)
    elif verdict == 'error':
        print(f'::error title=M121 kernel probe::{record.get("error") or record["frr_dynamic"]["stderr"]}',
              file=sys.stderr)
    if env.get('GITHUB_STEP_SUMMARY'):
        with open(env['GITHUB_STEP_SUMMARY'], 'a') as summary:
            summary.write('\n'.join(lines) + '\n')
    print('\n'.join(lines), file=sys.stderr)
    return 1 if verdict == 'error' else 0


def main():
    record = probe()
    print(json.dumps(record, indent=2))
    return report(record)


if __name__ == '__main__':
    sys.exit(main())
