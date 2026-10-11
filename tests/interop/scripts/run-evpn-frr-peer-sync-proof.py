#!/usr/bin/env python3
"""Run the peer-only MAC FRR proof in disposable privileged containers."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import uuid


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--daemon', required=True, type=Path)
    parser.add_argument('--cli', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--expect', choices=['baseline', 'fixed'], required=True)
    parser.add_argument('--keep', action='store_true', help='keep owned containers for diagnosis')
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    tree = Path(__file__).resolve().parents[3]
    (out/'token').write_bytes((tree/'tests/fixtures/grpc-test-only-operator.token').read_bytes())
    prefix = 'evpn-peer-sync-frr-' + uuid.uuid4().hex[:8]
    containers = []
    frr_image = 'quay.io/frrouting/frr:10.7.1'
    metadata = {'frr_image':frr_image, 'daemon_sha256':hashlib.file_digest(args.daemon.open('rb'),'sha256').hexdigest(),
                'cli_sha256':hashlib.file_digest(args.cli.open('rb'),'sha256').hexdigest(),
                'harness_commit':run('git','-C',str(tree),'rev-parse','HEAD'), 'kernel':run('uname','-r')}
    (out/'runtime.patch').write_bytes(subprocess.check_output(['git','-C',str(tree),'diff','HEAD','--','src','crates']))
    for script in ['evpn_frr_peer_sync.py', 'run-evpn-frr-peer-sync-proof.py', 'test_evpn_frr_peer_sync.py']:
        (out/script).write_bytes((tree/'tests/interop/scripts'/script).read_bytes())
    try:
        pids = {}
        for name in ['a','r']:
            container = prefix+'-'+name
            run('docker','run','-d','--privileged','--network','none','--name',container,
                '--entrypoint','/bin/sh',frr_image,'-c','sleep infinity')
            containers.append(container)
            pids[name] = int(run('docker','inspect','-f','{{.State.Pid}}',container))
        ctl = prefix+'-ctl'
        run('docker','run','-d','--privileged','--pid','host','--name',ctl,
            '-v',str(tree)+':/tree:ro','-v',str(out)+':/receipt',
            '-v',str(args.daemon.resolve())+':/binaries/rustbgpd:ro',
            '-v',str(args.cli.resolve())+':/binaries/rbgp:ro',
            'ubuntu:24.04','sleep','infinity')
        containers.append(ctl)
        metadata['containers'] = containers
        metadata['frr_image_id'] = run('docker','image','inspect','-f','{{.Id}}',frr_image)
        (out/'metadata.json').write_text(json.dumps(metadata,indent=2)+'\n')
        with (out/'setup.log').open('w') as log:
            subprocess.run(['docker','exec',ctl,'sh','-ec',
                            'apt-get update && apt-get install -y python3 iproute2 tcpdump procps util-linux'],
                           stdout=log,stderr=log,check=True)
        run('docker','network','disconnect','bridge',ctl)
        with (out/'run.log').open('w') as log:
            result = subprocess.run(['docker','exec','-e','FRR_PIDS='+json.dumps(pids),ctl,
                                     'python3','/tree/tests/interop/scripts/evpn_frr_peer_sync.py',args.expect],
                                    stdout=log,stderr=log,check=False)
            (out/'run.exit').write_text(str(result.returncode)+'\n')
            result.check_returncode()
        print((out/'result.json').read_text())
    finally:
        for name in containers:
            with (out/(name+'.log')).open('w') as log:
                subprocess.run(['docker','logs',name],stdout=log,stderr=log,check=False)
        if not args.keep:
            cleanup = []
            for name in reversed(containers):
                result = subprocess.run(['docker','rm','-f',name],capture_output=True,text=True,check=False)
                cleanup.append({'container':name,'exit':result.returncode,'stdout':result.stdout,'stderr':result.stderr})
            (out/'cleanup.json').write_text(json.dumps(cleanup,indent=2)+'\n')
            if any(row['exit'] for row in cleanup):
                raise RuntimeError('Owned container cleanup failed; see cleanup.json')
        else:
            print('Retained containers:', ', '.join(containers))


if __name__ == '__main__':
    main()
