import fcntl
import json
import os
import pathlib
import socket
import subprocess

out = pathlib.Path(__file__).resolve().parent
benchmark_lock = open("/tmp/rustbgpd-bench.lock", "a")
fcntl.flock(benchmark_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
os.sched_setaffinity(0, {31})
(out / "affinity.json").write_text(json.dumps({"cpus": sorted(os.sched_getaffinity(0)), "lock": "/tmp/rustbgpd-bench.lock"}) + "\n")
receipts = []
for index, arm in enumerate(['baseline', 'candidate', 'candidate', 'baseline', 'baseline', 'candidate']):
    control, child_control = socket.socketpair()
    control.settimeout(15)
    fd = child_control.fileno()
    counter_file = out / f'{index}-{arm}.stat'
    command = ['perf', 'stat', '--delay=-1', f'--control=fd:{fd},{fd}', '-e', 'instructions:u,cycles:u', '-x', ',', '-o', str(counter_file), '--', str(out / arm)]
    with open(out / f'{index}-{arm}.stderr', 'w') as stderr:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr, text=True, pass_fds=(fd,))
        child_control.close()
        try:
            ready = process.stdout.readline().strip()
            assert ready == 'READY', ready
            control.sendall(b'enable\n')
            enabled = control.recv(1024).decode().strip("\x00\r\n ")
            assert enabled == 'ack', enabled
            process.stdin.write('go\n')
            process.stdin.flush()
            done = process.stdout.readline().strip()
            assert done.startswith('DONE '), done
            control.sendall(b'disable\n')
            disabled = control.recv(1024).decode().strip("\x00\r\n ")
            assert disabled == 'ack', disabled
            process.stdin.write('finish\n')
            process.stdin.flush()
            returncode = process.wait(timeout=15)
            assert returncode == 0, returncode
            receipts.append({'arm': arm, 'index': index, 'callback_count': int(done.split()[1]), 'returncode': returncode, 'counters': counter_file.read_text()})
        finally:
            control.close()
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=15)
(out / 'receipts.json').write_text(json.dumps(receipts, indent=2) + '\n')
for receipt in receipts:
    print(receipt['arm'], receipt['callback_count'], receipt['counters'])
