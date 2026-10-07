#!/usr/bin/env python3
"""Local PID/start/PGID/SID guard, following flagship-lifecycle.sh's pidfd check."""
import json
import os
from pathlib import Path
import select
import signal
import sys
import time


def identity(pid):
    fields = Path(f'/proc/{pid}/stat').read_text().rsplit(') ', 1)[1].split()
    return {'pid': pid, 'ppid': int(fields[1]), 'start': int(fields[19]), 'pgid': int(fields[2]),
            'sid': int(fields[3]), 'boot': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}


def matches(expected, observed):
    # Reparenting after an owner exits does not change a retained process identity.
    return all(expected[k] == observed[k] for k in ('pid', 'start', 'pgid', 'sid', 'boot'))


def owned_signal(owner, name, group=False):
    pid = owner['pid']
    # Keep a reference to the original process while checking the numeric identity.
    fd = os.pidfd_open(pid)
    try:
        if not matches(owner, identity(pid)) or select.select([fd], [], [], 0)[0]:
            raise RuntimeError('refusing signal: owner absent or identity mismatched')
        sig = getattr(signal, 'SIG' + name)
        if group:
            if owner['pgid'] != pid or owner['sid'] != pid:
                raise RuntimeError('refusing group signal: owner is not session/group leader')
            os.killpg(pid, sig)
        else:
            signal.pidfd_send_signal(fd, sig)
    finally:
        os.close(fd)


def main():
    action, path = sys.argv[1:3]
    if action == 'capture':
        pid = int(sys.argv[3])
        first = identity(pid)
        if pid == os.getpid() or first['ppid'] != os.getppid():
            raise RuntimeError('capture target is not the launching shell child')
        deadline = time.monotonic() + 2
        while True:
            current = identity(pid)
            if current['start'] != first['start'] or current['boot'] != first['boot']:
                raise RuntimeError('owner changed during launch capture')
            if len(sys.argv) == 4 or current['pgid'] == current['sid'] == pid:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError('runner did not become owned session/group leader')
            time.sleep(0.01)
        Path(path).write_text(json.dumps(current) + '\n')
    else:
        owner = json.loads(Path(path).read_text())
        if action == 'alive':
            if not matches(owner, identity(owner['pid'])):
                raise RuntimeError('owner identity mismatched')
        else:
            owned_signal(owner, action, len(sys.argv) > 3 and sys.argv[3] == 'group')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
