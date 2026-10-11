#!/usr/bin/env python3
"""Cross-vendor all-active peer-only MAC forwarding, run by the Docker wrapper."""
from collections import Counter
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import time

OUT = Path('/receipt')
PIDS = json.loads(os.environ.get('FRR_PIDS', '{}'))
MAC = '02:aa:bb:cc:dd:10'
ESI = '03:aa:bb:cc:dd:ee:ff:00:00:01'
IPS = {'a': '10.211.0.1', 'b': '10.211.0.2', 'r': '10.211.0.3'}
LOG = OUT / 'commands.jsonl'

def run(*args, check=True):
    p = subprocess.run(args, text=True, capture_output=True, timeout=30)
    with LOG.open('a') as log:
        log.write(json.dumps({'command': args, 'exit': p.returncode,
                              'stdout': p.stdout, 'stderr': p.stderr}) + '\n')
    if check and p.returncode:
        raise RuntimeError(f'{args}: {p.stderr}')
    return p.stdout

def prefix(n):
    return ['nsenter', '-t', str(PIDS[n]), '-n'] if n in PIDS else ['ip', 'netns', 'exec', n]

def ns(n, *args, **kw):
    return run(*prefix(n), *args, **kw)

def frr(n, command):
    return run('nsenter', '-t', str(PIDS[n]), '-m', '-n', 'vtysh', '-c', command)

def cli(n, *args):
    return json.loads(ns(n, '/binaries/rbgp', '--addr',
                        'http://127.0.0.1:50051', '--token-file', '/receipt/token',
                        '-j', *args))

def wait(predicate, description):
    end = time.monotonic() + 90
    error = None
    while time.monotonic() < end:
        try:
            if predicate():
                return
        except (RuntimeError, ValueError, KeyError, IndexError) as exc:
            error = str(exc)
        time.sleep(.25)
    raise AssertionError(f'{description}: {error}')

def checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack('!' + 'H' * (len(data)//2), data))
    total = (total & 65535) + (total >> 16)
    total = (total & 65535) + (total >> 16)
    return (~total) & 65535

def frame(seed, destination=MAC, source='02:aa:bb:cc:dd:99'):
    body = b'PEER-SYNC:' + str(seed).encode()
    udp = struct.pack('!HHHH', 30000+seed, 45000, 8+len(body), 0) + body
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(udp), seed, 0,
                         64, 17, 0, socket.inet_aton(f'198.18.{seed//250}.{seed%250+1}'),
                         socket.inet_aton('192.0.2.10'))
    header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
    return bytes.fromhex(destination.replace(':', '')) + bytes.fromhex(source.replace(':', '')) + b'\x08\x00' + header + udp

def send(n, interface, seeds, count=1, destination=MAC, source='02:aa:bb:cc:dd:99'):
    packets = [frame(seed, destination, source).hex() for seed in seeds for _ in range(count)]
    ns(n, 'python3', '-c', "import socket,sys; s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW); s.bind((sys.argv[1],0)); [s.send(bytes.fromhex(p)) for p in sys.argv[2:]]", interface, *packets)

def packets(path):
    data = path.read_bytes()
    assert len(data) >= 24, f'bad pcap {path}'
    endian = '<' if data[:4] == b'\xd4\xc3\xb2\xa1' else '>'
    offset, seeds = 24, []
    while offset < len(data):
        _, _, length, _ = struct.unpack_from(endian+'IIII', data, offset)
        packet = data[offset+16:offset+16+length]
        offset += 16+length
        if b'PEER-SYNC:' in packet:
            seeds.append(int(packet.split(b'PEER-SYNC:', 1)[1]))
    return seeds

def capture(phase, seeds, count=1):
    procs = []
    for n, interface in [('a','vx100'), ('b','vx100'), ('ce','cea'), ('ce','ceb'), ('ce','bond0')]:
        name = f'{phase}-{n}-{interface}'
        err = (OUT / (name+'.stderr')).open('w')
        p = subprocess.Popen([*prefix(n),'tcpdump','-U','-n','-i',interface,
                              '-w',str(OUT/(name+'.pcap')), 'udp dst port 45000'],
                             stdout=subprocess.DEVNULL, stderr=err)
        procs.append((name,p,err))
    try:
        wait(lambda: all('listening on' in (OUT/(name+'.stderr')).read_text() for name,_,_ in procs), 'tcpdump capture admission')
        before = {n: json.loads(ns(n,'ip','-s','-j','link','show')) for n in ['a','b','ce']}
        send('r','inject',seeds,count)
        # Packet drain only; no latency or performance claim is made.
        time.sleep(1)
        after = {n: json.loads(ns(n,'ip','-s','-j','link','show')) for n in ['a','b','ce']}
    finally:
        for _,p,_ in procs:
            p.send_signal(signal.SIGINT)
        for _,p,err in procs:
            p.wait(timeout=10)
            err.close()
    result = {name: packets(OUT/(name+'.pcap')) for name,_,_ in procs}
    (OUT/(phase+'-counters.json')).write_text(json.dumps({'before':before,'after':after},indent=2)+'\n')
    (OUT/(phase+'-packets.json')).write_text(json.dumps(result,indent=2)+'\n')
    return result

def snapshot(name):
    state = {}
    for n in IPS:
        state[n] = {'fdb': json.loads(ns(n,'bridge','-j','fdb','show')),
                    'ports': json.loads(ns(n,'bridge','-j','-d','link','show')),
                    'nexthops': json.loads(ns(n,'ip','-j','nexthop','show'))}
        if n == 'b':
            state[n].update(segments=cli(n,'evpn','es','list'), routes=cli(n,'evpn'), neighbors=cli(n,'neighbor'))
        else:
            state[n].update(es=frr(n,'show evpn es detail'), mac=frr(n,'show evpn mac vni 100'), routes=frr(n,'show bgp l2vpn evpn route json'))
    for n in ['a','b','ce']:
        state.setdefault(n,{})['bond'] = ns(n,'cat','/proc/net/bonding/'+('bond0' if n=='ce' else 'es0'))
    (OUT/(name+'.json')).write_text(json.dumps(state,indent=2)+'\n')
    return state


def setup():
    run('ip','link','add','underlay','type','bridge')
    run('ip','link','set','underlay','up')
    for n in ['b','ce']:
        run('ip','netns','add',n)
    for n in ['a','b','r','ce']:
        ns(n,'ip','link','set','lo','up')
        ns(n,'sysctl','-wq','net.ipv6.conf.all.disable_ipv6=1')
        ns(n,'sysctl','-wq','net.ipv6.conf.default.disable_ipv6=1')
    for n,ip in IPS.items():
        run('ip','link','add','ul-'+n,'type','veth','peer','name','leg-'+n)
        run('ip','link','set','leg-'+n,'netns',str(PIDS.get(n,n)))
        run('ip','link','set','ul-'+n,'master','underlay')
        run('ip','link','set','ul-'+n,'up')
        ns(n,'ip','link','set','leg-'+n,'name','ul')
        ns(n,'ip','addr','add',ip+'/24','dev','ul')
        ns(n,'ip','link','set','ul','up')
        ns(n,'ip','link','add','br100','type','bridge','mcast_snooping','0')
        ns(n,'ip','link','add','vx100','type','vxlan','id','100','dstport','4789','local',ip,'dev','ul','nolearning')
        ns(n,'ip','link','set','vx100','master','br100')
        ns(n,'bridge','link','set','dev','vx100','learning','off')
        ns(n,'ip','link','set','br100','multicast','off')
        ns(n,'ip','link','set','br100','up')
        ns(n,'ip','link','set','vx100','up')
    ns('ce','ip','link','add','bond0','type','bond','mode','802.3ad','miimon','100','lacp_rate','fast')
    ns('ce','ip','link','set','bond0','address',MAC)
    for n in ['a','b']:
        ns(n,'ip','link','add','es0','type','bond','mode','802.3ad','miimon','100','lacp_rate','fast','ad_actor_system','aa:bb:cc:dd:ee:ff')
        ns(n,'ip','link','set','es0','address','aa:bb:cc:dd:ee:ff')
        ns(n,'ip','link','add','ac','type','veth','peer','name','ce'+n)
        ns(n,'ip','link','set','ce'+n,'netns','ce')
        ns(n,'ip','link','set','ac','master','es0')
        ns(n,'ip','link','set','es0','master','br100')
        ns(n,'ip','link','set','ac','up')
        ns(n,'ip','link','set','es0','up')
        ns('ce','ip','link','set','ce'+n,'master','bond0')
        ns('ce','ip','link','set','ce'+n,'up')
    ns('ce','ip','link','set','bond0','up')
    ns('r','ip','link','add','inject','type','veth','peer','name','injbr')
    ns('r','ip','link','set','injbr','master','br100')
    ns('r','ip','link','set','inject','up')
    ns('r','ip','link','set','injbr','up')
    for n in ['a','r']:
        root=Path(f'/proc/{PIDS[n]}/root/etc/frr')
        daemons=root/'daemons'
        daemons.write_text(daemons.read_text().replace('bgpd=no','bgpd=yes'))
        config=f'''frr defaults traditional
hostname {n}
log stdout
no ipv6 forwarding
evpn mh startup-delay 5
'''
        if n=='a':
            config+='''interface es0
 evpn mh es-id 1
 evpn mh es-sys-mac aa:bb:cc:dd:ee:ff
 evpn mh es-df-pref 200
!
'''
        config+=f'router bgp 65000\n bgp router-id {IPS[n]}\n no bgp default ipv4-unicast\n'
        for peer,ip in IPS.items():
            if peer!=n:
                config+=f' neighbor {ip} remote-as 65000\n'
        config+=' address-family l2vpn evpn\n'
        for peer,ip in IPS.items():
            if peer!=n:
                config+=f'  neighbor {ip} activate\n'
        config+='  advertise-all-vni\n exit-address-family\n!\nend\n'
        (root/'vtysh.conf').write_text('service integrated-vtysh-config\n')
        (root/'frr.conf').write_text(config)
        (OUT/(n+'.conf')).write_text(config)
        with (OUT/(n+'-frr.log')).open('w') as log:
            subprocess.run(['nsenter','-t',str(PIDS[n]),'-m','-n','-p','/usr/lib/frr/frrinit.sh','start'], stdout=log, stderr=log, timeout=60, check=True)
    config=f'''[global]
asn = 65000
router_id = "{IPS['b']}"
listen_port = 179
runtime_state_dir = "/var/lib/rustbgpd-proof"
[global.telemetry]
log_format = "json"
prometheus_addr = "0.0.0.0:9179"
[global.telemetry.grpc_tcp]
address = "0.0.0.0:50051"
token_file = "/receipt/token"
principal = "rustbgpd://operator/test-only"
[[evpn_instances]]
vni = 100
rd = "{IPS['b']}:100"
route_targets = ["65000:100"]
local_vtep_ip = "{IPS['b']}"
bridge = "br100"
advertise_svi_mac = false
[[ethernet_segments]]
esi = "{ESI}"
member_vnis = [100]
df_algorithm = "highest-preference"
df_preference = 100
redundancy_mode = "all-active"
originator_ip = "{IPS['b']}"
interface = "es0"
recovery_delay_seconds = 0
'''
    for n in ['a','r']:
        config+=f'''[[neighbors]]
address = "{IPS[n]}"
remote_asn = 65000
families = ["l2vpn_evpn"]
hold_time = 30
'''
    config+='''[security.grpc]
enforcement = "tier"
[security.grpc.roles]
"rustbgpd://operator/test-only" = "operator"
'''
    (OUT/'b.toml').write_text(config)
    log=(OUT/'b-daemon.log').open('w')
    subprocess.Popen([*prefix('b'),'/binaries/rustbgpd',str(OUT/'b.toml')],stdout=log,stderr=log)


def verify_delivery(result,phase,seeds,member,delivered):
    expected=Counter({seed:10 for seed in seeds})
    other='b' if member=='a' else 'a'
    assert Counter(result[f'{phase}-{member}-vx100'])==expected, 'missing or duplicate decapsulated frames'
    assert not result[f'{phase}-{other}-vx100'], 'flow selected the other PE'
    assert Counter(result[f'{phase}-ce-ce{member}'])==(expected if delivered else Counter()), 'missing or duplicate CE delivery'
    assert not result[f'{phase}-ce-ce{other}'], 'unexpected delivery over the other CE member'
    assert Counter(result[f'{phase}-ce-bond0'])==(expected if delivered else Counter()), 'CE bond did not accept the exact frames'


def main():
    setup()
    wait(lambda: len(cli('b','neighbor'))==2 and all(row['state']=='Established' for row in cli('b','neighbor')), 'fully meshed EVPN peers')
    wait(lambda: json.loads(ns('b','bridge','-j','-d','link','show','dev','es0'))[0]['flood'] is False, 'non-DF B flood suppression')
    wait(lambda: 'DF status: df ' in frr('a','show evpn es detail'), 'FRR A DF settled')
    wait(lambda: 'Number of ports: 2' in ns('ce','cat','/proc/net/bonding/bond0'), 'CE two-port LACP aggregator')
    # Pin the source frame to FRR's CE member; both LACP members remain active.
    a_mac=json.loads(ns('a','ip','-j','link','show','br100'))[0]['address']
    send('ce','cea',[1],destination=a_mac,source=MAC)
    wait(lambda: any(row.get('mac')==MAC and row.get('nhid') for row in json.loads(ns('r','bridge','-j','fdb','show','dev','vx100'))), 'FRR remote alias NHG for FRR-only CE MAC')
    expected=sys.argv[1]
    if expected=='fixed':
        wait(lambda: any(row.get('mac')==MAC and row.get('ifname')=='es0' and 'extern_learn' in row.get('flags',[]) for row in json.loads(ns('b','bridge','-j','fdb','show'))), 'owned peer-sync local row')
    state=snapshot('before')
    segment=state['b']['segments']['segments'][0]
    assert segment['redundancy_mode']=='all-active' and not segment['drained']
    assert segment['members'][0]['df_role']=='nondf' and segment['members'][0]['same_esi_bias_eligible']
    assert any(row.get('mac')==MAC and row.get('ifname')=='es0' for row in state['a']['fdb'])
    assert any(row.get('mac')==MAC and row.get('esi')==ESI for row in state['b']['routes'])
    b_rows=[row for row in state['b']['fdb'] if row.get('mac')==MAC]
    if expected=='baseline':
        assert not b_rows, 'baseline must have no locally learned or peer-sync CE row'
    else:
        assert len(b_rows)==1 and b_rows[0]['ifname']=='es0' and 'extern_learn' in b_rows[0]['flags']
        assert b_rows[0].get('master')=='br100' and not b_rows[0].get('dst') and not b_rows[0].get('nhid')
    assert not any(row.get('mac')==MAC and row.get('peer')=='0.0.0.0' for row in state['b']['routes']), 'B must not originate a locally learned CE route'
    remote_row=next(row for row in state['r']['fdb'] if row.get('mac')==MAC and row.get('nhid'))
    group=next(row for row in state['r']['nexthops'] if row['id']==remote_row['nhid'])
    ids={row['id'] for row in group['group']}
    assert len(ids)==2
    assert {row.get('via',row.get('gateway')) for row in state['r']['nexthops'] if row['id'] in ids}=={IPS['a'],IPS['b']}
    discovery=capture('discover',list(range(10,74)))
    a_seeds=discovery['discover-a-vx100']
    b_seeds=discovery['discover-b-vx100']
    assert a_seeds and b_seeds, 'FRR NHG must select both real members'
    assert Counter(a_seeds+b_seeds)==Counter(range(10,74)), 'every discovery frame selects one member'
    assert Counter(discovery['discover-ce-cea'])==Counter(a_seeds)
    assert Counter(discovery['discover-ce-ceb'])==Counter(b_seeds if expected=='fixed' else [])
    assert Counter(discovery['discover-ce-bond0'])==Counter(a_seeds+(b_seeds if expected=='fixed' else []))
    control=capture('df',a_seeds,10)
    verify_delivery(control,'df',a_seeds,'a',True)
    result=capture('non-df',b_seeds,10)
    verify_delivery(result,'non-df',b_seeds,'b',expected=='fixed')
    sent=len(b_seeds)*10
    delivered=len(result['non-df-ce-ceb'])
    final=snapshot('after')
    assert final['b']['segments']['segments'][0]['members'][0]['df_role']=='nondf'
    assert any(row.get('ifname')=='es0' and row.get('flood') is False for row in final['b']['ports'])
    assert not any(row.get('mac')==MAC and row.get('peer')=='0.0.0.0' for row in final['b']['routes']), 'peer-sync row must not become a locally originated MAC'
    (OUT/'result.json').write_text(json.dumps({'expectation':expected,'flows':len(b_seeds),'frames_per_flow':10,'decapsulated':sent,'CE_delivered':delivered,'loss_percent':100*(sent-delivered)/sent,'flow_seeds':b_seeds,'control_flows':len(a_seeds),'control_decapsulated':len(a_seeds)*10,'control_delivered':len(control['df-ce-cea'])},indent=2)+'\n')
    print((OUT/'result.json').read_text())

if __name__=='__main__':
    main()
