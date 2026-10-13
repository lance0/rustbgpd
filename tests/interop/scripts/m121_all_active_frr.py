#!/usr/bin/env python3
"""M121's isolated FRR/rustbgpd all-active cells; invoked by the lab shell driver."""
import argparse
from collections import Counter
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

CELLS = ('frr-df', 'rust-df', 'modulo-hazard', 'core-isolation')
IPS = {'a': '10.211.0.1', 'b': '10.211.0.2', 'r': '10.211.0.3'}
ESI = '03:aa:bb:cc:dd:ee:ff:00:00:01'
PEER_MAC = '02:aa:bb:cc:dd:10'
RUST_MAC = '02:aa:bb:cc:dd:20'
REMOTE_MAC = '02:aa:bb:cc:dd:99'
BASELINE_B = [10,11,12,13,16,18,19,21,30,32,33,34,36,37,38,39,41,42,44,46,47,50,56,57,58,60,61,62,63,64,67,68,69,73]
BASELINE_A = sorted(set(range(10, 74)) - set(BASELINE_B))
OUT = None
PIDS = {}
DAEMON = None
CAPTURES = []
NETNS_ROOT = Path('/run/netns')
NAMESPACE_HANDLES = {}
HARNESS_INPUTS = (
    'tests/interop/scripts/m121_all_active_frr.py',
    'tests/interop/scripts/m121_all_active_oracle.py',
    'tests/interop/scripts/m121_all_active_wire.py',
    'tests/interop/scripts/evpn_frr_peer_sync.py',
    'tests/interop/scripts/m105_capture_oracle.py',
    'tests/interop/scripts/test-m121-evpn-all-active-frr.sh',
    'tests/interop/scripts/source-id-guard.sh',
    'scripts/source-id.sh',
    'tests/interop/configs/rustbgpd-m121-pe.toml',
    'tests/interop/m121-evpn-all-active-frr.clab.yml',
    'tests/fixtures/grpc-test-only-operator.token',
    'docs/artifacts/interop/evpn-frr-peer-sync-20261011/result.json',
)


def record_host_metadata(root, out, topology):
    """Identify repository inputs, including dirty and untracked scoped paths."""
    def git(*args):
        return subprocess.check_output(['git', '-C', str(root), *args], text=True)
    scopes = dict(runtime=['Cargo.toml', 'Cargo.lock', '.cargo', 'src', 'crates', 'proto',
                           'bench', 'benches', 'examples', 'tools'],
                  harness=['tests/interop', 'tests/fixtures/grpc-test-only-operator.token',
                           'scripts/source-id.sh', 'docs/artifacts/interop/evpn-frr-peer-sync-20261011/result.json'])
    meta = dict(source_commit=git('rev-parse', 'HEAD').strip(), repository_scopes=scopes,
                harness_sha256={name: hashlib.sha256((root / name).read_bytes()).hexdigest()
                                for name in HARNESS_INPUTS}, containers={})
    for scope, paths in scopes.items():
        meta[scope + '_diff'] = git('diff', 'HEAD', '--', *paths)
        meta[scope + '_status'] = git('status', '--porcelain', '--untracked-files=all', '--', *paths)
    for node in ('a', 'r', 'controller'):
        info = json.loads(subprocess.check_output(['docker', 'inspect', f'clab-{topology}-{node}']))[0]
        meta['containers'][node] = dict(image=info['Config']['Image'], image_id=info['Image'])
    (out / 'host-metadata.json').write_text(json.dumps(meta, indent=2) + '\n')


def render_config(template, cell):
    """Render exactly the three lab configurations without privileged side effects."""
    if cell not in CELLS:
        raise ValueError(f'unknown M121 cell: {cell}')
    if cell == 'rust-df':
        for before, after in [('vni = 100', 'vni = 101'), ('10.211.0.2:100', '10.211.0.2:101'),
                              ('65000:100', '65000:101'), ('member_vnis = [100]', 'member_vnis = [101]'),
                              ('df_preference = 100', 'df_preference = 300')]:
            template = template.replace(before, after)
    elif cell == 'modulo-hazard':
        template = template.replace('df_algorithm = "highest-preference"\n', '')
        template = template.replace('df_preference = 100\n', '')
    elif cell == 'core-isolation':
        # ADR-0140 defaults (10 s settle hold, 180 s backstop); a short BGP
        # hold time lets the sessions expire while the underlay is cut.
        template = template.replace('hold_time = 30', 'hold_time = 9')
        template += '\n[evpn_core_isolation]\nenabled = true\nuplinks = ["ul"]\n'
    return template


def historical_comparison_enabled(value):
    if value not in ('0', '1'):
        raise ValueError('M121_COMPARE_HISTORICAL must be 0 or 1')
    return value == '1'


def verify_historical_flows(a, b, enabled):
    if enabled:
        assert sorted(b) == BASELINE_B and sorted(a) == BASELINE_A, 'flow identity differs from immutable baseline'


def verify_frr_version(version):
    assert re.search(r'^FRRouting 10\.7\.1(?:_git)?(?:\s|\()', version, re.MULTILINE), version


def save(name, value):
    (OUT / name).write_text(json.dumps(value, indent=2) + '\n')


def event(name, **fields):
    row = dict(event=name, monotonic=time.monotonic(), wall_time=time.time(), **fields)
    with (OUT / 'events.jsonl').open('a') as log:
        log.write(json.dumps(row) + '\n')
    return row


def run(*args, check=True, timeout=30):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    with (OUT / 'commands.jsonl').open('a') as log:
        log.write(json.dumps(dict(command=args, exit=result.returncode, stdout=result.stdout, stderr=result.stderr)) + '\n')
    if check and result.returncode:
        raise RuntimeError(f'{args}: {result.stderr}')
    return result.stdout


def prefix(node):
    return ['ip', 'netns', 'exec', node]


def ns(node, *args, **kw):
    return run(*prefix(node), *args, **kw)


def frr_run(node, *args, check=True, timeout=30):
    # Host docker exec enters the sibling container's PID namespace correctly.
    request = dict(node=node, args=args, timeout=timeout)
    print(json.dumps(request), flush=True)
    line = sys.stdin.readline()
    if not line:
        raise RuntimeError('host FRR command channel closed')
    response = json.loads(line)
    with (OUT / 'commands.jsonl').open('a') as log:
        log.write(json.dumps(dict(frr_request=request, **response)) + '\n')
    if check and response['exit']:
        raise RuntimeError(f'{request}: {response["stderr"]}')
    return response['stdout']


def frr(node, command):
    return frr_run(node, 'vtysh', '-c', command)


def execute_frr_request(request):
    """The host bridge accepts only this topology's fixed FRR operations."""
    assert set(request) == {'node', 'args', 'timeout'}, request
    node, args, timeout = request['node'], request['args'], request['timeout']
    assert node in ('a', 'r') and type(timeout) is int and 0 < timeout <= 60, request
    shows = {'show version', 'show evpn es detail', 'show bgp l2vpn evpn route json',
             'show evpn mac vni 100', 'show evpn mac vni 101',
             *{f'show evpn mac vni {vni} mac {RUST_MAC} json' for vni in (100, 101)}}
    assert (len(args) == 3 and args[:2] == ['vtysh', '-c'] and args[2] in shows) or args in (
        ['/usr/lib/frr/frrinit.sh', 'start'], ['/usr/lib/frr/frrinit.sh', 'stop']), request
    try:
        result = subprocess.run(['docker', 'exec', f'clab-m121-evpn-all-active-frr-{node}', *args],
                                capture_output=True, text=True, timeout=timeout)
        return dict(exit=result.returncode, stdout=result.stdout, stderr=result.stderr)
    except subprocess.TimeoutExpired:
        return dict(exit=124, stdout='', stderr='FRR command exceeded bounded timeout')


def host_run():
    """Relay fixed FRR commands while the isolated controller runs."""
    topology = 'm121-evpn-all-active-frr'
    compare = os.environ.get('M121_COMPARE_HISTORICAL', '0')
    historical_comparison_enabled(compare)
    process = subprocess.Popen(['docker', 'exec', '-i', '-e', 'FRR_PIDS=' + os.environ['FRR_PIDS'],
                                '-e', 'M121_COMPARE_HISTORICAL=' + compare,
                                f'clab-{topology}-controller', 'python3',
                                '/m121/scripts/m121_all_active_frr.py', '--config', '/m121/config.toml'],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
    try:
        for line in process.stdout:
            response = execute_frr_request(json.loads(line))
            process.stdin.write(json.dumps(response) + '\n')
            process.stdin.flush()
        code = process.wait(timeout=30)
        if code:
            raise SystemExit(code)
    finally:
        process.stdin.close()
        if process.poll() is None:
            # Terminate only the exact controller script recorded by this run.
            terminate = ("import os,signal; from pathlib import Path; p=Path('/receipt/driver.pid'); "
                         "pid=int(p.read_text()) if p.exists() else 0; "
                         "cmd=Path(f'/proc/{pid}/cmdline').read_bytes() if pid else b''; "
                         "assert not pid or b'/m121/scripts/m121_all_active_frr.py\\0' in cmd; "
                         "os.kill(pid,signal.SIGTERM) if pid else None")
            subprocess.run(['docker', 'exec', f'clab-{topology}-controller', 'python3', '-c', terminate],
                           capture_output=True, text=True, timeout=10, check=False)
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
        if os.environ.get('M121_HOST_OUT'):
            Path(os.environ['M121_HOST_OUT'], 'controller-exit.json').write_text(
                json.dumps(dict(exit=process.returncode)) + '\n')
        # Scoped stop also covers an interrupted command channel.
        for node in ('a', 'r'):
            execute_frr_request(dict(node=node, args=['/usr/lib/frr/frrinit.sh', 'stop'], timeout=30))


def ctl(*args):
    return json.loads(ns('b', '/usr/local/bin/rbgp', '--addr', 'http://127.0.0.1:50051', '-j', *args))


def wait(check, description, timeout=90):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        if DAEMON is not None and DAEMON.poll() is not None:
            raise RuntimeError(f'rustbgpd exited with {DAEMON.returncode} while waiting for {description}')
        try:
            if check():
                return
        except (AssertionError, RuntimeError, ValueError, KeyError, IndexError) as error:
            last = str(error)
        time.sleep(.25)
    raise AssertionError(f'timed out waiting for {description}: {last}')


def snapshot(name, vni):
    state = {}
    for node in IPS:
        state[node] = dict(fdb=json.loads(ns(node, 'bridge', '-j', 'fdb', 'show')),
                           ports=json.loads(ns(node, 'bridge', '-j', '-d', 'link', 'show')),
                           nexthops=json.loads(ns(node, 'ip', '-j', 'nexthop', 'show')))
        if node == 'b':
            state[node].update(routes=ctl('evpn'), segments=ctl('evpn', 'es', 'list'), neighbors=ctl('neighbor'))
        else:
            state[node].update(routes=json.loads(frr(node, 'show bgp l2vpn evpn route json')),
                               es=frr(node, 'show evpn es detail'), mac=frr(node, f'show evpn mac vni {vni}'))
    for node in ['a', 'b', 'ce']:
        state.setdefault(node, {})['bond'] = ns(node, 'cat', '/proc/net/bonding/' + ('bond0' if node == 'ce' else 'es0'))
    save(name + '.json', state)
    return state


def start_capture(name, node, interface, expression, snaplen=None):
    err = (OUT / (name + '.stderr')).open('w')
    snap = [] if snaplen is None else ['-s', str(snaplen)]
    process = subprocess.Popen([*prefix(node), 'tcpdump', '--immediate-mode', '-U', '-n', '-i', interface, *snap,
                                '-w', str(OUT / (name + '.pcap')), *expression],
                               stdout=subprocess.DEVNULL, stderr=err)
    item = (name, process, err)
    CAPTURES.append(item)
    return item


def capture_ready(items):
    for name, process, _ in items:
        if process.poll() is not None:
            raise RuntimeError(f'tcpdump {name} exited before admission')
    return all('listening on' in (OUT / (name + '.stderr')).read_text() for name, _, _ in items)


def stop_captures(items):
    for _, process, _ in items:
        if process.poll() is None:
            process.send_signal(signal.SIGINT)
    for item in items:
        name, process, err = item
        process.wait(timeout=10)
        err.close()
        CAPTURES.remove(item)
        assert process.returncode == 0, f'tcpdump {name}: exit {process.returncode}'


def wait_bgp_capture(bgp, vni, preference):
    """Wait for complete wire evidence before stopping a still-live capture."""
    from m121_all_active_wire import verify_pcap
    name, process, _ = bgp
    deadline, last = time.monotonic() + 30, None
    while (remaining := deadline - time.monotonic()) > 0:
        if process.poll() is not None:
            raise RuntimeError(f'tcpdump {name} exited before wire evidence')
        try:
            verify_pcap(OUT / (name + '.pcap'), RUST_MAC, vni,
                        df_preference=preference, timeout=remaining)
        except (ValueError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
            # A live PCAP can end in a partial record or an incomplete TCP message.
            last = str(error)
        else:
            if process.poll() is not None:
                raise RuntimeError(f'tcpdump {name} exited during wire verification')
            return
        time.sleep(min(.25, max(0, deadline - time.monotonic())))
    raise AssertionError(f'timed out waiting for complete BGP capture: {last}')


def send(node, interface, seeds, count=1, destination=PEER_MAC, source=REMOTE_MAC):
    from m121_all_active_oracle import make_frame
    frames = [make_frame(seed, copy, destination, source).hex() for seed in seeds for copy in range(count)]
    ns(node, 'python3', '-c', 'import socket,sys; s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW); s.bind((sys.argv[1],0)); [s.send(bytes.fromhex(p)) for p in sys.argv[2:]]', interface, *frames)


def capture(phase, seeds, count=10, direction='remote-to-ce', destination=PEER_MAC, source=REMOTE_MAC, bum_winner='unicast'):
    from m121_all_active_oracle import packet_identities, verify_identities
    interfaces = [('a', 'vx100'), ('b', 'vx100'), ('ce', 'cea'), ('ce', 'ceb'), ('ce', 'bond0'), ('hr', 'eth0')]
    # Immediate-mode rings sized for the default snaplen drop frames from a
    # 340-frame burst; probes are small and the oracle rejects truncated frames.
    items = [start_capture(f'{phase}-{n}-{dev}', n, dev, ['udp', 'dst', 'port', '45000'], snaplen=1024)
             for n, dev in interfaces]
    try:
        wait(lambda: capture_ready(items), 'all packet capture listeners', timeout=10)
        node, interface = ('hr', 'eth0') if direction == 'remote-to-ce' else ('ce', 'bond0')
        event('send', phase=phase, node=node, interface=interface, seeds=seeds, frames_per_flow=count,
              destination=destination, source=source)
        send(node, interface, seeds, count, destination, source)
        # Packet drain only; this interval does not measure convergence or latency.
        time.sleep(1)
    finally:
        stop_captures(items)
    identities = {f'{phase}-{n}-{dev}': packet_identities(OUT / f'{phase}-{n}-{dev}.pcap') for n, dev in interfaces}
    save(phase + '-identities.json', identities)
    result = {key: [seed for seed, _packet_id in rows] for key, rows in identities.items()}
    save(phase + '-packets.json', result)
    verify_identities(identities, phase, seeds, count, bum_winner=bum_winner)
    return result


def setup_namespaces():
    # ip netns initializes its parent mount before we attach sibling handles.
    for node in ['b', 'ce', 'hr']:
        run('ip', 'netns', 'add', node)
    for node, pid in PIDS.items():
        path = NETNS_ROOT / node
        path.touch(exist_ok=False)
        NAMESPACE_HANDLES[node] = False
        run('mount', '--bind', f'/hostproc/{pid}/ns/net', str(path))
        NAMESPACE_HANDLES[node] = True


def setup(config, vni):
    run('ip', 'link', 'add', 'underlay', 'type', 'bridge')
    run('ip', 'link', 'set', 'underlay', 'up')
    setup_namespaces()
    for node in ['a', 'b', 'r', 'ce', 'hr']:
        ns(node, 'ip', 'link', 'set', 'lo', 'up')
        ns(node, 'sysctl', '-wq', 'net.ipv6.conf.all.disable_ipv6=1')
        ns(node, 'sysctl', '-wq', 'net.ipv6.conf.default.disable_ipv6=1')
    for node, ip in IPS.items():
        run('ip', 'link', 'add', 'ul-' + node, 'type', 'veth', 'peer', 'name', 'leg-' + node)
        run('ip', 'link', 'set', 'leg-' + node, 'netns', node)
        run('ip', 'link', 'set', 'ul-' + node, 'master', 'underlay')
        run('ip', 'link', 'set', 'ul-' + node, 'up')
        ns(node, 'ip', 'link', 'set', 'leg-' + node, 'name', 'ul')
        ns(node, 'ip', 'addr', 'add', ip + '/24', 'dev', 'ul')
        ns(node, 'ip', 'link', 'set', 'ul', 'up')
        ns(node, 'ip', 'link', 'add', 'br100', 'type', 'bridge', 'mcast_snooping', '0')
        ns(node, 'ip', 'link', 'add', 'vx100', 'type', 'vxlan', 'id', str(vni), 'dstport', '4789', 'local', ip, 'dev', 'ul', 'nolearning')
        ns(node, 'ip', 'link', 'set', 'vx100', 'master', 'br100')
        ns(node, 'bridge', 'link', 'set', 'dev', 'vx100', 'learning', 'off')
        ns(node, 'ip', 'link', 'set', 'br100', 'multicast', 'off')
        ns(node, 'ip', 'link', 'set', 'br100', 'up')
        ns(node, 'ip', 'link', 'set', 'vx100', 'up')
    ns('ce', 'ip', 'link', 'add', 'bond0', 'type', 'bond', 'mode', '802.3ad', 'miimon', '100', 'lacp_rate', 'fast')
    ns('ce', 'ip', 'link', 'set', 'bond0', 'address', PEER_MAC)
    for node in ['a', 'b']:
        ns(node, 'ip', 'link', 'add', 'es0', 'type', 'bond', 'mode', '802.3ad', 'miimon', '100', 'lacp_rate', 'fast', 'ad_actor_system', 'aa:bb:cc:dd:ee:ff')
        ns(node, 'ip', 'link', 'set', 'es0', 'address', 'aa:bb:cc:dd:ee:ff')
        ns(node, 'ip', 'link', 'add', 'ac', 'type', 'veth', 'peer', 'name', 'ce' + node)
        ns(node, 'ip', 'link', 'set', 'ce' + node, 'netns', 'ce')
        ns(node, 'ip', 'link', 'set', 'ac', 'master', 'es0')
        ns(node, 'ip', 'link', 'set', 'es0', 'master', 'br100')
        ns(node, 'ip', 'link', 'set', 'ac', 'up')
        ns(node, 'ip', 'link', 'set', 'es0', 'up')
        ns('ce', 'ip', 'link', 'set', 'ce' + node, 'master', 'bond0')
        ns('ce', 'ip', 'link', 'set', 'ce' + node, 'up')
    ns('ce', 'ip', 'link', 'set', 'bond0', 'up')
    ns('r', 'ip', 'link', 'add', 'injbr', 'type', 'veth', 'peer', 'name', 'inject')
    ns('r', 'ip', 'link', 'set', 'inject', 'netns', 'hr')
    ns('r', 'ip', 'link', 'set', 'injbr', 'master', 'br100')
    ns('r', 'ip', 'link', 'set', 'injbr', 'up')
    ns('hr', 'ip', 'link', 'set', 'inject', 'name', 'eth0')
    ns('hr', 'ip', 'link', 'set', 'eth0', 'address', REMOTE_MAC)
    ns('hr', 'ip', 'link', 'set', 'eth0', 'up')
    # Capture the real Rust -> FRR session before any UPDATE can be emitted.
    bgp = start_capture('rust-bgp', 'b', 'ul', ['tcp', 'port', '179'])
    wait(lambda: capture_ready([bgp]), 'BGP capture listener', timeout=10)
    for node in ['a', 'r']:
        root = Path(f'/hostproc/{PIDS[node]}/root/etc/frr')
        daemons = root / 'daemons'
        daemons.write_text(daemons.read_text().replace('bgpd=no', 'bgpd=yes'))
        lines = ['frr defaults traditional', f'hostname {node}', 'log stdout', 'no ipv6 forwarding', 'evpn mh startup-delay 5']
        if node == 'a':
            lines += ['interface es0', ' evpn mh es-id 1', ' evpn mh es-sys-mac aa:bb:cc:dd:ee:ff', ' evpn mh es-df-pref 200', '!']
        lines += ['router bgp 65000', f' bgp router-id {IPS[node]}', ' no bgp default ipv4-unicast']
        for peer, ip in IPS.items():
            if peer != node:
                lines += [f' neighbor {ip} remote-as 65000']
        lines += [' address-family l2vpn evpn']
        for peer, ip in IPS.items():
            if peer != node:
                lines += [f'  neighbor {ip} activate']
        lines += ['  advertise-all-vni', ' exit-address-family', '!', 'end', '']
        rendered = '\n'.join(lines)
        (root / 'vtysh.conf').write_text('service integrated-vtysh-config\n')
        (root / 'frr.conf').write_text(rendered)
        (OUT / (node + '.conf')).write_text(rendered)
        frr_run(node, '/usr/lib/frr/frrinit.sh', 'start', timeout=60)
        version = frr(node, 'show version')
        (OUT / (node + '-version.txt')).write_text(version)
        verify_frr_version(version)
    # Each cell gets a fresh durable state directory as well as fresh namespaces.
    config = config.replace('/var/lib/rustbgpd-m121', str(OUT / 'runtime-state'))
    (OUT / 'b.toml').write_text(config)
    start_daemon('b-daemon.log')
    return bgp


def start_daemon(log_name):
    global DAEMON
    with (OUT / log_name).open('w') as log:
        DAEMON = subprocess.Popen([*prefix('b'), '/usr/local/bin/rustbgpd', str(OUT / 'b.toml')],
                                  stdout=log, stderr=log)
    event('daemon_started', pid=DAEMON.pid, log=log_name)


def ready(vni, winner):
    from m121_all_active_oracle import verify_bridge_flood, verify_frr_es_routes
    neighbors = ctl('neighbor')
    assert len(neighbors) == 2 and all(row['state'] == 'Established' for row in neighbors)
    segment = ctl('evpn', 'es', 'list')['segments'][0]
    assert segment['redundancy_mode'] == 'all-active' and not segment['drained']
    assert segment['members'][0]['df_role'] == ('df' if winner == 'b' else 'nondf')
    assert segment['members'][0]['same_esi_bias_eligible']
    ports = json.loads(ns('b', 'bridge', '-j', '-d', 'link', 'show', 'dev', 'es0'))
    verify_bridge_flood(ports[0], winner == 'b')
    frr_es = frr('a', 'show evpn es detail')
    wanted = 'df' if winner == 'a' else 'non-df'
    assert re.search(r'DF status:\s*' + re.escape(wanted) + r'\b', frr_es, re.IGNORECASE), frr_es
    assert 'Number of ports: 2' in ns('ce', 'cat', '/proc/net/bonding/bond0')
    verify_frr_es_routes(json.loads(frr('r', 'show bgp l2vpn evpn route json')), True, vni)
    return True


def nhg(mac, expected):
    from m121_all_active_oracle import verify_nhg
    return verify_nhg(json.loads(ns('r', 'bridge', '-j', 'fdb', 'show')),
                      json.loads(ns('r', 'ip', '-j', 'nexthop', 'show')), mac, expected)


def learn(node, mac):
    destination = json.loads(ns(node, 'ip', '-j', 'link', 'show', 'br100'))[0]['address']
    send('ce', 'ce' + node, [1], destination=destination, source=mac)


def peer_only_ready():
    from evpn_frr_peer_sync import verify_peer_rows
    routes = ctl('evpn')
    assert any(r.get('mac') == PEER_MAC and r.get('peer') == IPS['a'] and r.get('esi') == ESI for r in routes)
    assert not any(r.get('mac') == PEER_MAC and r.get('peer') == '0.0.0.0' for r in routes)
    verify_peer_rows([r for r in json.loads(ns('b', 'bridge', '-j', 'fdb', 'show')) if r.get('mac') == PEER_MAC])
    return True


def peer_only(vni, compare_baseline):
    from evpn_frr_peer_sync import verify_delivery
    from m121_all_active_oracle import verify_discovery
    learn('a', PEER_MAC)
    wait(lambda: nhg(PEER_MAC, {IPS['a'], IPS['b']}), 'FRR-only target two-member NHG')
    wait(peer_only_ready, 'peer-only marked local FDB pair without Rust origination')
    snapshot('peer-only-before', vni)
    discovered = capture('discover', list(range(10, 74)), count=1)
    paths = verify_discovery(discovered, 'discover', list(range(10, 74)))
    a, b = paths['a'], paths['b']
    verify_historical_flows(a, b, compare_baseline)
    for label, seeds, member in [('peer-a', a, 'a'), ('peer-b', b, 'b')]:
        packets = capture(label, seeds)
        verify_delivery(packets, label, seeds, member, True)
    peer_only_ready()
    snapshot('peer-only-after', vni)
    return dict(b_flow_seeds=b, b_delivered=len(b) * 10, a_flow_seeds=a, a_delivered=len(a) * 10,
                compared_with_historical_baseline=compare_baseline, per_frame_identity_verified=True)


def rust_origin(vni, preference, bgp):
    from m121_all_active_oracle import verify_frr_originated, verify_local_originated, verify_frr_synced_mac
    learn('b', RUST_MAC)
    def check():
        verify_local_originated(ctl('evpn'), RUST_MAC, vni)
        verify_frr_originated(json.loads(frr('r', 'show bgp l2vpn evpn route json')), RUST_MAC, vni)
        state = json.loads(frr('a', f'show evpn mac vni {vni} mac {RUST_MAC} json'))
        save('rust-origin-frr-sync.json', state)
        verify_frr_synced_mac(state, RUST_MAC)
        nhg(RUST_MAC, {IPS['a'], IPS['b']})
        return True
    wait(check, 'Rust original, FRR synchronized proxy and two-member NHG')
    snapshot('rust-only-before-bidirectional', vni)
    wait_bgp_capture(bgp, vni, preference)
    stop_captures([bgp])
    # Extract raw TCP bytes; the oracle checks the actual BGP NLRI/attributes.
    from m121_all_active_wire import verify_pcap
    result = verify_pcap(OUT / 'rust-bgp.pcap', RUST_MAC, vni, df_preference=preference)
    save('wire-result.json', result)
    return result


def bidirectional(vni):
    from m121_all_active_oracle import verify_discovery, verify_unicast
    # Rust origination and the initial peer-only paths were pinned before this change.
    ns('ce', 'ip', 'link', 'set', 'bond0', 'address', RUST_MAC)
    ns('ce', 'ip', 'link', 'set', 'bond0', 'type', 'bond', 'xmit_hash_policy', 'layer3+4')
    wait(lambda: ready(vni, 'a' if vni == 100 else 'b'),
         'full LACP/EVPN readiness after selecting the independently qualified CE MAC')
    bond = ns('ce', 'cat', '/proc/net/bonding/bond0')
    assert 'Transmit Hash Policy: layer3+4' in bond, bond
    (OUT / 'bidirectional-ce-bond.txt').write_text(bond)
    assert json.loads(ns('ce', 'ip', '-j', 'link', 'show', 'bond0'))[0]['address'] == RUST_MAC
    event('bidirectional_ce_identity', mac=RUST_MAC, xmit_hash_policy='layer3+4')
    wait(lambda: nhg(RUST_MAC, {IPS['a'], IPS['b']}), 'Rust-originated bidirectional target NHG')
    result = {}
    for direction, phase, candidates, destination, source in [
        ('remote-to-ce', 'unicast-down', list(range(90, 154)), RUST_MAC, REMOTE_MAC),
        ('ce-to-remote', 'unicast-up', list(range(154, 218)), REMOTE_MAC, RUST_MAC),
    ]:
        if direction == 'ce-to-remote':
            def remote_known():
                return any(row.get('mac') == REMOTE_MAC and row.get('peer') == IPS['r'] for row in ctl('evpn'))
            wait(remote_known, 'remote host Type2 before return traffic')
        discovery = capture(phase + '-discover', candidates, count=1, direction=direction,
                            destination=destination, source=source)
        paths = verify_discovery(discovery, phase + '-discover', candidates)
        assert len(paths['a']) >= 2 and len(paths['b']) >= 2, paths
        selected = paths['a'][:2] + paths['b'][:2]
        packets = capture(phase, selected, direction=direction, destination=destination, source=source)
        verify_unicast(packets, phase, selected, direction)
        result[direction] = dict(delivered=40, flow_seeds=selected,
                                 discovered_a=paths['a'], discovered_b=paths['b'])
    snapshot('bidirectional-after', vni)
    return result


def frr_non_enforcement():
    """Stock FRR 10.7.1 reports non-DF but its Linux provider leaves flooding on."""
    from m121_all_active_oracle import verify_frr_non_enforcement
    es_detail = frr('a', 'show evpn es detail')
    port = json.loads(ns('a', 'bridge', '-j', '-d', 'link', 'show', 'dev', 'es0'))[0]
    save('frr-non-enforcement-witness.json', dict(es_detail=es_detail, port=port))
    return verify_frr_non_enforcement(es_detail, port)


def modulo_fallback(vni):
    from m121_all_active_oracle import verify_modulo_fallback
    segment = ctl('evpn', 'es', 'list')['segments'][0]
    routes = ctl('evpn')
    es_detail = frr('a', 'show evpn es detail')
    port = json.loads(ns('b', 'bridge', '-j', '-d', 'link', 'show', 'dev', 'es0'))[0]
    save('modulo-fallback.json', dict(segment=segment, routes=routes, frr_es_detail=es_detail, rust_port=port))
    return verify_modulo_fallback(segment, routes, es_detail, vni)


def bum(vni, winner):
    from m121_all_active_oracle import verify_bum
    # No test command inserts a flood row: remote FRR must consume real IMET.
    def imet_flood():
        rows = json.loads(ns('r', 'bridge', '-j', 'fdb', 'show', 'dev', 'vx100'))
        destinations = [row.get('dst') for row in rows if row.get('mac') == '00:00:00:00:00:00']
        assert Counter(destinations) == Counter([IPS['a'], IPS['b']]), destinations
        return True
    wait(imet_flood, 'remote FRR IMET-derived flood list')
    snapshot('bum-before', vni)
    # The witness is checked on both sides of the packet proof.
    witness = None if winner == 'a' else frr_non_enforcement()
    packets = capture('bum', [121], count=1, destination='ff:ff:ff:ff:ff:ff', bum_winner=winner)
    verify_bum(packets, 'bum', 121, winner)
    if witness is not None:
        witness = frr_non_enforcement()
    snapshot('bum-after', vni)
    return dict(vxlan_ingress_a=1, vxlan_ingress_b=1, ce_cea=1, ce_ceb=int(winner == 'b'),
                ce_bond0=1 + (winner == 'b'), rust_member_copies=int(winner == 'b'), df=winner,
                frr_non_enforcement_witness=witness)


@contextmanager
def pause_owned_daemon():
    """Confirm the owned child is stopped, and always resume it before cleanup."""
    process = DAEMON
    assert process is not None and process.pid > 1, 'missing owned daemon'
    try:
        process.send_signal(signal.SIGSTOP)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            pid, status = os.waitpid(process.pid, os.WUNTRACED | os.WNOHANG)
            if pid:
                if not os.WIFSTOPPED(status):
                    process.returncode = os.waitstatus_to_exitcode(status)
                    raise RuntimeError(f'owned daemon exited before stop handshake: {process.returncode}')
                if os.WSTOPSIG(status) != signal.SIGSTOP:
                    raise RuntimeError('owned daemon stopped with unexpected signal')
                break
            time.sleep(.01)
        else:
            raise RuntimeError('owned daemon stop handshake exceeded five seconds')
        event('daemon_stop_confirmed_for_carrier', pid=process.pid)
        yield
    finally:
        process.send_signal(signal.SIGCONT)
        event('daemon_resume_requested_after_carrier', pid=process.pid)


def carrier_cycle(vni, survivor_seeds):
    from evpn_frr_peer_sync import verify_delivery
    from m121_all_active_oracle import verify_discovery, verify_frr_es_routes, verify_frr_peer_originated
    assert survivor_seeds, 'carrier proof needs initially Rust-selected flows'
    ns('ce', 'ip', 'link', 'set', 'bond0', 'address', PEER_MAC)
    wait(lambda: ready(vni, 'a'),
         'full LACP/EVPN readiness after restoring the original FRR-only CE identity')
    assert json.loads(ns('ce', 'ip', '-j', 'link', 'show', 'bond0'))[0]['address'] == PEER_MAC
    learn('a', PEER_MAC)
    wait(lambda: nhg(PEER_MAC, {IPS['a'], IPS['b']}) and peer_only_ready(),
         'pre-failure original FRR-origin target NHG and exclusive peer-only FDB pair')
    snapshot('carrier-before', vni)
    event('carrier_down_requested')
    ns('b', 'ip', 'link', 'set', 'ac', 'down')
    def withdrawn():
        segment = ctl('evpn', 'es', 'list')['segments'][0]
        assert segment['drained']
        routes = json.loads(frr('r', 'show bgp l2vpn evpn route json'))
        verify_frr_es_routes(routes, False, vni)
        verify_frr_peer_originated(routes, PEER_MAC, vni)
        nhg(PEER_MAC, {IPS['a']})
        return True
    wait(withdrawn, 'Rust AC drain, Type4/EAD withdrawals and surviving FRR-only nexthop')
    snapshot('carrier-withdrawn', vni)
    packets = capture('carrier-survivor', survivor_seeds)
    verify_delivery(packets, 'carrier-survivor', survivor_seeds, 'a', True)
    # The actor cannot arm recovery before this observation while its process is stopped.
    with pause_owned_daemon():
        event('carrier_up_requested')
        ns('b', 'ip', 'link', 'set', 'ac', 'up')
        wait(lambda: 'LOWER_UP' in json.loads(ns('b', 'ip', '-j', 'link', 'show', 'es0'))[0]['flags'],
             'actual Rust attachment-circuit carrier return')
        carrier = event('carrier_up_observed', daemon_stopped=True)
    samples = []
    while time.monotonic() - carrier['monotonic'] < 5:
        state = ctl('evpn', 'es', 'list')
        elapsed = time.monotonic() - carrier['monotonic']
        samples.append(dict(carrier_observation_elapsed_seconds=elapsed, state=state))
        save('carrier-recovery-hold.json', samples)
        if elapsed < 5:
            assert state['segments'][0]['drained'], f'link drain cleared before recovery delay at {elapsed}'
        time.sleep(.25)
    assert any(4 <= sample['carrier_observation_elapsed_seconds'] < 5 for sample in samples), 'no deep recovery-hold sample'
    wait(lambda: ready(vni, 'a') and nhg(PEER_MAC, {IPS['a'], IPS['b']}),
         'recovered EAD-per-EVI, preference roles and actual two-member NHG')
    elapsed = time.monotonic() - carrier['monotonic']
    assert elapsed >= 5, 'recovery completed before configured five-second hold'
    snapshot('carrier-recovered', vni)
    discovery = capture('carrier-rediscover', list(range(10, 74)), count=1)
    paths = verify_discovery(discovery, 'carrier-rediscover', list(range(10, 74)))
    a, b = paths['a'], paths['b']
    packets = capture('carrier-restored', b)
    verify_delivery(packets, 'carrier-restored', b, 'b', True)
    return dict(surviving_frr_delivered=len(survivor_seeds) * 10, survivor_flow_seeds=survivor_seeds,
                recovered_rust_delivered=len(b) * 10,
                recovered_rust_flow_seeds=b, recovered_frr_flow_seeds=a,
                recovery_delay_seconds=5, carrier_observation_elapsed_seconds=elapsed,
                timing_scope='controlled daemon resume after observed carrier return; five-second recovery ordering, not natural timer latency')


HOLD_AFTER_SYNC = 10
BACKSTOP = 180
SOFT_FAILURES = []


def aggregator_ports(text):
    """The port count of the CE bond's active LACP aggregator."""
    ports = re.search(r'Active Aggregator Info:\s*\n\s*Aggregator ID: \d+\s*\n\s*Number of ports: (\d+)', text)
    return int(ports[1]) if ports else 0


def bond_member_active(text, member):
    """From a CE /proc/net/bonding report: is `member` up, collecting and
    distributing in the active LACP aggregator?"""
    head, *slaves = re.split(r'^Slave Interface: ', text, flags=re.MULTILINE)
    active = re.search(r'Active Aggregator Info:\s*\n\s*Aggregator ID: (\d+)', head)
    for section in slaves:
        if section.split('\n', 1)[0].strip() != member:
            continue
        mii = re.search(r'^MII Status: (\S+)', section, re.MULTILINE)
        aggregator = re.search(r'^Aggregator ID: (\d+)', section, re.MULTILINE)
        actor = re.search(r'details actor lacp pdu:.*?port state: (\d+)', section, re.DOTALL)
        assert mii and aggregator and actor, section
        # Actor port state bits 4 and 5: collecting and distributing.
        return bool(active and mii[1] == 'up' and aggregator[1] == active[1]
                    and int(actor[1]) & 0x30 == 0x30)
    raise AssertionError(f'{member} is not enslaved to the CE bond: {text}')


def soft(name, action):
    """Run one core-isolation assertion and record it. Later assertions still
    run, so a red run shows every assertion that fails."""
    try:
        detail = action()
    except AssertionError as error:
        SOFT_FAILURES.append(name)
        event('assertion', assertion=name, passed=False, detail=str(error)[:2000])
        return None
    event('assertion', assertion=name, passed=True, detail=detail)
    return detail


def core_state():
    text = ns('b', 'python3', '-c', 'import urllib.request,sys; sys.stdout.write(urllib.request.urlopen('
              '"http://127.0.0.1:9179/metrics", timeout=5).read().decode())')
    states = [labels for labels in re.findall(r'^evpn_es_core_isolation_state\{([^}]*)\} 1$', text, re.MULTILINE)
              if 'interface="es0"' in labels]
    assert len(states) == 1, states
    return re.search(r'state="([^"]+)"', states[0])[1]


def link_sample(origin):
    """Kernel view: rustbgpd's member admin state and the CE's LACP membership."""
    elapsed = time.monotonic() - origin
    bond = ns('ce', 'cat', '/proc/net/bonding/bond0')
    sample = dict(elapsed=elapsed,
                  rust_member_admin_up='UP' in json.loads(ns('b', 'ip', '-j', 'link', 'show', 'ac'))[0]['flags'],
                  ce_ceb_active=bond_member_active(bond, 'ceb'), ce_aggregator_ports=aggregator_ports(bond))
    try:
        sample.update(established=sum(row['state'] == 'Established' for row in ctl('neighbor')),
                      state=core_state())
    except RuntimeError:
        # A restarted daemon's API is not up yet; the kernel state still counts.
        sample.update(established=None, state=None)
    return sample


def watch(name, origin, done, timeout):
    """Sample until `done(sample)` or the deadline; the deadline is not an error."""
    samples = []
    deadline = time.monotonic() + timeout
    while True:
        if DAEMON is not None and DAEMON.poll() is not None:
            raise RuntimeError(f'rustbgpd exited with {DAEMON.returncode} during {name}')
        sample = link_sample(origin)
        samples.append(sample)
        if done(sample) or time.monotonic() > deadline:
            save(name + '.json', samples)
            return samples
        time.sleep(.2)


def held(sample):
    return (not sample['rust_member_admin_up'] and not sample['ce_ceb_active']
            and sample['ce_aggregator_ports'] == 1)


def both_active(sample):
    return sample['rust_member_admin_up'] and sample['ce_ceb_active'] and sample['ce_aggregator_ports'] == 2


def cut_underlay(phase):
    event(phase + '_underlay_cut')
    run('ip', 'link', 'set', 'ul-b', 'down')
    samples = watch(phase + '-cut', time.monotonic(), held, 10)

    def removed():
        assert held(samples[-1]), ('member up or in the CE aggregator 10 s after the cut', samples[-1])
        return dict(elapsed=samples[-1]['elapsed'], state=samples[-1]['state'])
    return soft(phase + ': rustbgpd admin-downs its member and the CE drops it from the aggregator', removed)


def restore_underlay(phase):
    """The member must stay down for the settle hold after the sessions return,
    then come up, and the CE must re-add it."""
    run('ip', 'link', 'set', 'ul-b', 'up')
    event(phase + '_underlay_restored')
    samples = watch(phase + '-recovery', time.monotonic(), both_active, 90)
    held_at_restore = held(samples[0])
    established = next((s['elapsed'] for s in samples if s['established']), None)
    raised = next((s['elapsed'] for s in samples if s['rust_member_admin_up']), None)
    readded = next((s['elapsed'] for s in samples if both_active(s)), None)

    def hold():
        assert established is not None and raised is not None, ('no session before the member came up',
                                                                established, raised)
        # Release needs EVPN sync, which follows Established, plus the settle hold.
        assert raised >= established + HOLD_AFTER_SYNC - 2, ('raised before sync plus the hold', established, raised)
        assert raised <= established + HOLD_AFTER_SYNC + 20, ('not raised after sync plus the hold', established, raised)
        assert all(held(s) for s in samples if s['elapsed'] < raised), 'member up or in the aggregator during the hold'
        assert not any(s['state'] == 'backstop_released' for s in samples), 'backstop release'
        return dict(first_established=established, raised=raised, raised_after_established=raised - established)

    def readd():
        assert held_at_restore, ('member was not out of the CE aggregator when the underlay returned', samples[0])
        assert raised is not None and readded is not None and readded >= raised, (raised, readded)
        assert readded <= raised + 10, ('CE did not re-add the member within 10 s', raised, readded)
        return dict(raised=raised, ce_readded=readded)
    return dict(held_at_restore=held_at_restore,
                hold=soft(phase + ': member held for the settle hold after sync, then raised', hold),
                readd=soft(phase + ': CE re-adds the member to its aggregator', readd))


def core_isolation(vni):
    """ADR-0140 end to end: underlay cut, recovery hold, and restart before End-of-RIB."""
    from m121_all_active_oracle import verify_discovery
    ns('ce', 'ip', 'link', 'set', 'bond0', 'type', 'bond', 'xmit_hash_policy', 'layer3+4')
    wait(lambda: ready(vni, 'a') and bond_member_active(ns('ce', 'cat', '/proc/net/bonding/bond0'), 'ceb')
         and core_state() == 'released', 'both CE members active after the startup hold released')
    # The remote host's Type 2 makes CE -> remote traffic known unicast at both PEs.
    send('hr', 'eth0', [1], destination=PEER_MAC, source=REMOTE_MAC)

    def remote_known():
        assert any(r.get('mac') == REMOTE_MAC and r.get('peer') == IPS['r'] for r in ctl('evpn'))
        rows = json.loads(ns('a', 'bridge', '-j', 'fdb', 'show', 'dev', 'vx100'))
        assert any(r.get('mac') == REMOTE_MAC and r.get('dst') == IPS['r'] for r in rows), rows
        return True
    wait(remote_known, 'remote host Type 2 at both PEs')
    seeds = list(range(154, 218))
    paths = verify_discovery(capture('isolation-discover', seeds, count=1, direction='ce-to-remote',
                                     destination=REMOTE_MAC, source=PEER_MAC), 'isolation-discover', seeds)
    moved, kept = paths['b'][:4], paths['a'][:2]
    assert len(moved) == 4 and len(kept) == 2, paths
    snapshot('isolation-before', vni)
    result = dict(hold_after_sync_seconds=HOLD_AFTER_SYNC, backstop_seconds=BACKSTOP,
                  flows_hashed_to_rust=moved, flows_hashed_to_frr=kept)

    result['cut'] = cut_underlay('isolation')
    snapshot('isolation-cut', vni)

    def traffic_moves():
        phase = 'isolation-traffic'
        packets = capture(phase, moved + kept, direction='ce-to-remote', destination=REMOTE_MAC, source=PEER_MAC)
        assert not packets[f'{phase}-ce-ceb'] and not packets[f'{phase}-b-vx100'], 'traffic still sent to rustbgpd'
        return dict(delivered_through_frr=len(packets[f'{phase}-hr-eth0']))
    result['traffic'] = soft('isolation: CE traffic, including flows hashed to rustbgpd, moves to the FRR PE',
                             traffic_moves)
    wait(lambda: not any(r['state'] == 'Established' for r in ctl('neighbor')),
         'rustbgpd EVPN sessions to expire with the underlay cut', timeout=40)
    result['recovery'] = restore_underlay('isolation')

    # Restart variant: kill rustbgpd while isolated, so before End-of-RIB.
    result['restart_cut'] = cut_underlay('restart')
    receipt_path = OUT / 'runtime-state' / 'evpn-core-isolation-owned.json'
    receipt = json.loads(receipt_path.read_text()) if receipt_path.exists() else None
    save('restart-receipt-before-kill.json', receipt)
    DAEMON.kill()
    DAEMON.wait(timeout=10)
    event('daemon_killed', exit=DAEMON.returncode)
    start_daemon('b-daemon-restart.log')
    origin = time.monotonic()
    log = OUT / 'b-daemon-restart.log'
    samples = watch('restart-startup', origin, lambda s: s['state'] == 'startup_hold'
                    and 'core-isolation receipt found at startup' in log.read_text(), 20)
    # Keep the underlay cut a little longer: no session, so no End-of-RIB.
    samples += watch('restart-isolated', origin, lambda s: False, 5)

    def adopted():
        text = log.read_text()
        assert receipt and [e['link']['name'] for e in receipt['links']] == ['ac'], ('no owned receipt entry', receipt)
        assert 'core-isolation receipt found at startup' in text, 'receipt not adopted'
        assert 'took a CE-facing member administratively down' not in text, 'member taken down again, not adopted'
        assert samples[-1]['state'] == 'startup_hold', samples[-1]
        assert all(held(s) and not s['established'] for s in samples), 'member up before End-of-RIB'
        return dict(samples=len(samples), held_for=samples[-1]['elapsed'])
    result['restart_adoption'] = soft('restart: receipt adopted and the member stays down before End-of-RIB',
                                      adopted)
    result['restart_recovery'] = restore_underlay('restart')
    released = time.monotonic() - origin

    def no_backstop():
        assert result['restart_recovery']['held_at_restore'], 'no restart hold to release'
        assert released < BACKSTOP / 2, ('release near the backstop', released)
        assert 'backstop_unsynced' not in log.read_text(), 'backstop release logged'
        return dict(release_after_restart=released)
    result['restart_backstop'] = soft('restart: released by sync plus the hold, not the 180 s backstop',
                                      no_backstop)
    snapshot('isolation-after', vni)
    result['soft_failures'] = list(SOFT_FAILURES)
    save('core-isolation-result.json', result)
    assert not SOFT_FAILURES, SOFT_FAILURES
    return result


def cleanup_diagnostics(phase):
    (OUT / f'cleanup-{phase}-mountinfo.txt').write_text(Path('/proc/self/mountinfo').read_text())
    processes = {}
    for node, pid in PIDS.items():
        rows = []
        for path in Path(f'/hostproc/{pid}/root/proc').iterdir():
            if not path.name.isdigit():
                continue
            try:
                rows.append(dict(pid=int(path.name), status=(path / 'status').read_text(),
                                 cmdline=(path / 'cmdline').read_bytes().replace(b'\0', b' ').decode(errors='replace')))
            except FileNotFoundError:
                continue  # A process may exit while the snapshot is read.
        processes[node] = rows
    save(f'cleanup-{phase}-processes.json', processes)


def cleanup():
    errors = []
    def attempt(description, action):
        try:
            return action()
        except (OSError, RuntimeError, AssertionError, subprocess.SubprocessError) as error:
            errors.append(f'{description}: {error}')
            return None
    attempt('initial diagnostics', lambda: cleanup_diagnostics('before'))
    attempt('packet capture stop', lambda: stop_captures(list(CAPTURES)))
    def stop_daemon():
        global DAEMON
        if DAEMON is not None:
            if DAEMON.poll() is None:
                DAEMON.terminate()
                try:
                    DAEMON.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    DAEMON.kill()
                    DAEMON.wait(timeout=10)
            event('daemon_stopped', exit=DAEMON.returncode)
            DAEMON = None
    attempt('rustbgpd stop', stop_daemon)
    for node in ['a', 'r']:
        attempt(f'{node} FRR stop', lambda node=node: frr_run(node, '/usr/lib/frr/frrinit.sh', 'stop', timeout=30))
    for node in ['a', 'r']:
        for interface in ['ac', 'es0', 'injbr', 'vx100', 'br100', 'ul']:
            attempt(f'{node} {interface} removal', lambda node=node, interface=interface:
                    ns(node, 'ip', 'link', 'del', interface, check=False))
    for node in ['b', 'ce', 'hr']:
        attempt(f'{node} namespace removal', lambda node=node: run('ip', 'netns', 'del', node, check=False))
    attempt('underlay removal', lambda: run('ip', 'link', 'del', 'underlay', check=False))
    for node, mounted in list(NAMESPACE_HANDLES.items()):
        def detach(node=node, mounted=mounted):
            path = NETNS_ROOT / node
            if mounted:
                run('umount', str(path))
                NAMESPACE_HANDLES[node] = False
            path.unlink()
            del NAMESPACE_HANDLES[node]
        attempt(f'{node} handle removal', detach)
    remaining = attempt('namespace inventory', lambda: run('ip', 'netns', 'list'))
    if remaining is not None and any(line.split()[0] in ['a', 'r', 'b', 'ce', 'hr'] for line in remaining.splitlines()):
        errors.append(f'owned namespace handles remain: {remaining}')
    attempt('final diagnostics', lambda: cleanup_diagnostics('after'))
    save('cleanup.json', dict(remaining_namespace_handles=None if remaining is None else remaining.splitlines(), errors=errors))
    assert not errors, errors


def cleanup_preserving_error():
    primary = sys.exception()
    try:
        cleanup()
    except Exception as error:
        if primary is None:
            raise
        primary.add_note(f'Cleanup also failed: {error}')


def main():
    global OUT, PIDS
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--render-config', choices=CELLS)
    parser.add_argument('--host-run', action='store_true')
    parser.add_argument('--config', type=Path, default=Path(__file__).resolve().parents[1] / 'configs/rustbgpd-m121-pe.toml')
    args = parser.parse_args()
    if args.host_run:
        host_run()
        return
    template = args.config.read_text()
    if args.render_config:
        print(render_config(template, args.render_config), end='')
        return
    compare_historical = historical_comparison_enabled(os.environ.get('M121_COMPARE_HISTORICAL', '0'))
    root = Path('/receipt')
    root.mkdir(exist_ok=True)
    (root / 'driver.pid').write_text(str(os.getpid()) + '\n')
    def terminate(_signum, _frame):
        raise SystemExit(143)
    signal.signal(signal.SIGTERM, terminate)
    OUT = root
    PIDS = json.loads(os.environ['FRR_PIDS'])
    assert set(PIDS) == {'a', 'r'} and all(isinstance(pid, int) and pid > 1 for pid in PIDS.values())
    metadata = dict(daemon_sha256=hashlib.sha256(Path('/usr/local/bin/rustbgpd').read_bytes()).hexdigest(),
                    cli_sha256=hashlib.sha256(Path('/usr/local/bin/rbgp').read_bytes()).hexdigest(),
                    source_id=Path('/usr/local/share/rustbgpd/source-id').read_text().strip(),
                    driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    compare_historical=compare_historical,
                    kernel=run('uname', '-r').strip(), tshark_version=run('tshark', '--version').splitlines()[0])
    save('metadata.json', metadata)
    results = {}
    try:
        for cell in CELLS:
            OUT = root / cell
            OUT.mkdir()
            vni = 101 if cell == 'rust-df' else 100
            winner = {'frr-df': 'a', 'rust-df': 'b', 'modulo-hazard': None, 'core-isolation': 'a'}[cell]
            try:
                bgp = setup(render_config(template, cell), vni)
                wait(lambda vni=vni, winner=winner: ready(vni, winner), 'BGP, LACP and expected DF roles')
                result = dict(vni=vni, expected_df=winner)
                if cell == 'core-isolation':
                    result['core_isolation'] = core_isolation(vni)
                elif winner is not None:
                    result['peer_only'] = peer_only(vni, compare_historical and cell == 'frr-df')
                    result['rust_origin'] = rust_origin(vni, 300 if cell == 'rust-df' else 100, bgp)
                    result['bidirectional'] = bidirectional(vni)
                else:
                    result['modulo_fallback'] = modulo_fallback(vni)
                if cell != 'core-isolation':
                    result['bum'] = bum(vni, winner)
                if cell == 'frr-df':
                    result['carrier'] = carrier_cycle(vni, result['peer_only']['b_flow_seeds'])
                save('result.json', result)
                results[cell] = result
            finally:
                cleanup_preserving_error()
        OUT = root
        save('result.json', dict(status='passed', cells=results, compare_historical=compare_historical,
                                scope='functional packet and protocol-state correctness; no scale or performance claim',
                                fresh_packet_identity='IPv4 ID = seed * 16 + copy; exact unique identities at ingress and delivery',
                                historical_packet_scope='retained baseline uses per-seed counters; not retroactively identity-qualified'))
    finally:
        OUT = root
        primary = sys.exception()
        try:
            save('final-cleanup.json', dict(named_namespaces=run('ip', 'netns', 'list').splitlines()))
            (root / 'driver.pid').unlink(missing_ok=True)
        except Exception as error:
            if primary is None:
                raise
            primary.add_note(f'Final cleanup receipt also failed: {error}')


if __name__ == '__main__':
    main()
