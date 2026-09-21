#!/usr/bin/env python3
"""Reproduce the dated controller-injection receipt from the repository root."""
import argparse
import asyncio
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time
import urllib.request

import grpc
import rustbgpd_pb2 as pb
import rustbgpd_pb2_grpc as rpc

ROOT = Path.cwd()
spec = importlib.util.spec_from_file_location('membership', ROOT / 'bench/scale/reloadstall/membership_churn.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
original_apply = m.apply_update
states = {}


def observed_update(body, inventories, total, marker=None):
    original_apply(body, inventories, total, marker=None)
    state = states[id(inventories)]
    state['updates'] += 1
    withdrawn = int.from_bytes(body[:2], 'big')
    for index in m.nlri_indices(body[2:2 + withdrawn], 4, total):
        state['withdrawals'] += 1
        del state['routes'][index]
    offset = 4 + withdrawn
    length = int.from_bytes(body[offset - 2:offset], 'big')
    attrs, nlri = body[offset:offset + length], body[offset + length:]
    communities = []
    while attrs:
        flags, kind = attrs[:2]
        width = 2 if flags & 16 else 1
        size = int.from_bytes(attrs[2:2 + width], 'big')
        value, attrs = attrs[2 + width:2 + width + size], attrs[2 + width + size:]
        if kind == 8:
            communities += [int.from_bytes(value[i:i + 4], 'big') for i in range(0, len(value), 4)]
    for index in m.nlri_indices(nlri, 4, total):
        state['announcements'] += 1
        state['routes'][index] = communities


m.apply_update = observed_update


def prefix(index):
    return f'{20 + (index >> 16)}.{(index >> 8) & 255}.{index & 255}.0'


def expected(index, epoch, distinct):
    return [epoch * 1_000_000 + (index if distinct else 0)]


def metrics(out, name, port):
    with urllib.request.urlopen(f'http://127.0.0.1:{port}/metrics', timeout=5) as response:
        data = response.read()
    (out / f'{name}.prom').write_bytes(data)


def process_cpu(pid):
    fields = Path(f'/proc/{pid}/stat').read_text().split()
    return (int(fields[13]) + int(fields[14])) / os.sysconf('SC_CLK_TCK')


async def reconcile(stub, count, epoch, distinct, output):
    token = ''
    seen = set()
    pages = 0
    version = None
    while True:
        page = await stub.ListReceivedRoutes(pb.ListRoutesRequest(
            neighbor_address='0.0.0.0', page_size=1000, page_token=token), timeout=10)
        current = (page.page_version.epoch, page.page_version.generation)
        if version is None:
            version = current
        assert version == current
        assert page.total_count == count, (page.total_count, count)
        for route in page.routes:
            index = (int.from_bytes(socket.inet_aton(route.prefix), 'big') >> 8) - (20 << 16)
            assert 0 <= index < count and index not in seen
            assert route.prefix_length == 24 and route.peer_address == '0.0.0.0'
            assert list(route.communities) == expected(index, epoch, distinct)
            seen.add(index)
        pages += 1
        token = page.next_page_token
        if not token:
            break
    assert len(seen) == count
    output.write_text(json.dumps({'count': len(seen), 'pages': pages, 'page_version': version,
                                  'all_prefixes_and_communities_verified': True}, indent=2) + '\n')


async def run(args):
    out = args.output
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.chmod(out, 0o700)
    config = f'''config_epoch = 2
[global]
asn = 4200000000
router_id = "10.0.0.1"
listen_port = {args.port}
runtime_state_dir = "{out}"
ebgp_requires_policy = true
[global.telemetry]
log_format = "json"
prometheus_addr = "127.0.0.1:{args.metrics_port}"
[global.telemetry.grpc_uds]
path = "{out}/grpc.sock"
[policy]
rpol_files = ["permit.rpol"]
import_chain = ["permit"]
export_chain = ["permit"]
'''
    for i in range(args.peers):
        config += f'''\n[[neighbors]]
address = "{m.address(i)}"
remote_asn = {64512 + i}
route_server_client = true
families = ["ipv4_unicast", "ipv6_unicast"]
hold_time = 180
'''
    (out / 'config.toml').write_text(config)
    (out / 'permit.rpol').write_text('policy permit { term all { accept } }\n')
    subprocess.run([str(args.daemon), '--check', str(out / 'config.toml')], check=True,
                   stdout=(out / 'check.log').open('w'), stderr=subprocess.STDOUT)
    daemon_command = [str(args.daemon), str(out / 'config.toml')]
    if args.daemon_cpus:
        daemon_command = ['taskset', '-c', args.daemon_cpus] + daemon_command
    daemon = subprocess.Popen(daemon_command,
                              stdout=(out / 'daemon.log').open('w'), stderr=subprocess.STDOUT)
    receivers, tasks = [], []
    result = {'source': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
              'daemon_sha256': hashlib.sha256(args.daemon.read_bytes()).hexdigest(),
              'count': args.count, 'peers': args.peers, 'distinct': args.distinct,
              'unary_concurrency': 1, 'phase_cap_seconds': args.phase_cap, 'phases': [],
              'driver_affinity': sorted(os.sched_getaffinity(0)), 'daemon_cpus': args.daemon_cpus}
    try:
        await m.wait_until(lambda: (out / 'grpc.sock').exists() or daemon.poll() is not None, 15, 'daemon socket')
        assert daemon.poll() is None
        channel = grpc.aio.insecure_channel(f'unix:{out}/grpc.sock', options=[('grpc.default_authority', 'localhost')])
        injection, rib = rpc.InjectionServiceStub(channel), rpc.RibServiceStub(channel)
        async with channel:
            for i in range(args.peers):
                receiver = m.Receiver(i, False, args.port, args.count)
                receiver.marker = None
                receivers.append(receiver)
                states[id(receiver.inventories)] = {'updates': 0, 'announcements': 0, 'withdrawals': 0, 'routes': {}}
                tasks.append(asyncio.create_task(receiver.run()))
            await m.wait_until(lambda: all(r.established for r in receivers), 15, 'BGP established')
            await asyncio.sleep(1)
            await reconcile(rib, 0, 0, args.distinct, out / 'initial-reconciliation.json')
            for name, epoch in [('insert', 1), ('replace', 2), ('delete', 0)]:
                metrics(out, name + '-before', args.metrics_port)
                before = [{k: v for k, v in states[id(r.inventories)].items() if k != 'routes'} for r in receivers]
                cpu_start, start = process_cpu(daemon.pid), time.monotonic()
                completed = 0
                phase = {'name': name, 'start_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
                result['phases'].append(phase)
                try:
                    async with asyncio.timeout(args.phase_cap):
                        for index in range(args.count):
                            if epoch:
                                await injection.AddPath(pb.AddPathRequest(prefix=prefix(index), prefix_length=24,
                                    next_hop='192.0.2.1', communities=expected(index, epoch, args.distinct)), timeout=5)
                            else:
                                await injection.DeletePath(pb.DeletePathRequest(prefix=prefix(index), prefix_length=24), timeout=5)
                            completed += 1
                            if completed % 1000 == 0:
                                print(json.dumps({'phase': name, 'completed': completed, 'seconds': time.monotonic() - start}), flush=True)
                    phase['rpc_seconds'] = time.monotonic() - start
                    phase['daemon_cpu_seconds'] = process_cpu(daemon.pid) - cpu_start
                    target = args.count if epoch else 0
                    await m.wait_until(lambda target=target, epoch=epoch: all(len(states[id(r.inventories)]['routes']) == target and
                        (not epoch or states[id(r.inventories)]['announcements'] >= epoch * args.count)
                        for r in receivers), 30, 'wire completion')
                    for receiver in receivers:
                        routes = states[id(receiver.inventories)]['routes']
                        assert routes == {i: expected(i, epoch, args.distinct) for i in range(target)}
                    phase['wire_complete_seconds'] = time.monotonic() - start
                    phase['wire_deltas'] = [{k: states[id(r.inventories)][k] - old[k] for k in old}
                                            for r, old in zip(receivers, before)]
                    await reconcile(rib, target, epoch, args.distinct, out / f'{name}-reconciliation.json')
                    metrics(out, name + '-after', args.metrics_port)
                    phase['pass'] = True
                finally:
                    phase['daemon_cpu_seconds_at_finally'] = process_cpu(daemon.pid) - cpu_start
                    phase['completed_rpcs'] = completed
                    phase['elapsed_seconds'] = time.monotonic() - start
                    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
                print(json.dumps(phase), flush=True)
            result['pass'] = True
            await m.finish_receivers(receivers, tasks)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if daemon.poll() is None:
            daemon.send_signal(signal.SIGTERM)
        try:
            daemon.wait(timeout=15)
        except subprocess.TimeoutExpired:
            daemon.kill()
            daemon.wait()
        result['daemon_exit'] = daemon.returncode
        (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--daemon', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--count', type=int, required=True)
    parser.add_argument('--peers', type=int, default=1)
    parser.add_argument('--distinct', action='store_true')
    parser.add_argument('--phase-cap', type=int, default=180)
    parser.add_argument('--daemon-cpus')
    parser.add_argument('--port', type=int, default=1795)
    parser.add_argument('--metrics-port', type=int, default=9175)
    asyncio.run(run(parser.parse_args()))
