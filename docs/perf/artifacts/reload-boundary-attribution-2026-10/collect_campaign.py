#!/usr/bin/env python3
"""Join all predeclared process legs; preserve unqualified evidence and errors."""
import json
import csv
from decimal import Decimal
from datetime import datetime
from pathlib import Path
import re
import sys
from analyze_receiver import analyze, read_harness, require
from read_publication import read as read_publication
from qualify import ORDER, qualify


def validate_leg_metadata(leg, arm, frozen, previous_end, previous_mono=0):
    cell=leg/'matrix/rustbgpd'
    start=Decimal((leg/'started.epoch').read_text().strip())
    end=Decimal((leg/'finished.epoch').read_text().strip())
    require(start.is_finite() and end.is_finite() and previous_end <= start < end,
            'campaign chronology overlaps or is reordered')
    start_mono=int((leg/'started.monotonic_ns').read_text())
    end_mono=int((leg/'finished.monotonic_ns').read_text())
    cooldown_start=int((cell/'cooldown-start.monotonic_ns').read_text())
    cooldown_end=int((cell/'cooldown-end.monotonic_ns').read_text())
    require(0 <= previous_mono <= start_mono <= cooldown_start <= cooldown_end <= end_mono,
            'monotonic leg/cooldown chronology invalid')
    require(cooldown_end-cooldown_start >= 300_000_000_000, 'monotonic cooldown shorter than 300 seconds')
    provenance=json.loads((cell/'provenance.json').read_text())
    require(provenance['git']['commit']==frozen['source_commit'],'leg source commit mismatch')
    require(provenance['workload']['inputs']=={'N_PEERS':'700','TOTAL_PREFIXES':'400400','PORT':'1790',
        'RELOADS':'4','CONTROL_SECS':'30','CHANGED_PEERS':'','FLAPSTORM':'','BIRD_THREADS':'8','PROBE_PREFIXES':''},
        'native workload inputs differ from declaration')
    require(provenance['workload']['sha256']==frozen['binaries']['rustbgpd-'+arm], 'actual daemon arm mismatch')
    require(provenance['sources']['reloadstall']['sha256']==frozen['binaries']['reloadstall-'+arm], 'actual harness arm mismatch')
    require(provenance['sources']['common']==frozen['native_common'], 'native runner/helper source mismatch')
    require(provenance['sources']['generator']==frozen['native_generator'], 'native generator mismatch')
    q=list(csv.DictReader((cell/'quiet.tsv').read_text().splitlines(),delimiter='\t'))
    require(len(q)==2 and [v['sample'] for v in q]==['1','2'],'quiet sample coverage')
    require(all(v['quiet']=='true' and v['failed_dimensions']=='none' and v['competitors']=='none'
                and Decimal(v['load1'])<2 and int(v['performance_governors'])==int(v['governor_count'])>0
                for v in q),'quiet admission failed')
    require(q[0]['pswpin']==q[1]['pswpin'] and q[0]['pswpout']==q[1]['pswpout'], 'swap activity during admission')
    epochs=[Decimal(v['epoch_s']) for v in q]
    require(start-1 <= epochs[0] and epochs[1]-epochs[0]>=30 and epochs[1]<end,'quiet spacing or time invalid')
    text=(leg/'runner.log').read_text()
    starts=re.findall(r'^=== cell rustbgpd start (.+) ===$',text,re.M)
    passed=re.findall(r'^=== cell rustbgpd PASS (.+) ===$',text,re.M)
    require(len(starts)==len(passed)==1 and text.count('cool-down 300s')==1
            and 'matrix done; per-cell status under ' in text,'native cooldown witness missing')
    native_start=Decimal(str(datetime.fromisoformat(starts[0]).timestamp()))
    native_pass=Decimal(str(datetime.fromisoformat(passed[0]).timestamp()))
    require(epochs[1] <= native_start <= native_pass and native_pass+300 <= end,
            'full native cooldown or admission chronology missing')
    return end


def validate_process(match, owner, previous_boot, previous_start):
    require(int(match[2])==owner['pid']==owner['pgid']==owner['sid'], 'daemon is outside retained runner group/session')
    require(previous_boot in (None,owner['boot']), 'campaign boot identity changed')
    start=int(match[3])
    require(start>previous_start, 'daemon process order is reused or reversed')
    return f"{owner['boot']}:{match[1]}:{start}", owner['boot'], start


def validate_method_freeze(leg, expected):
    require((leg/"methods.sha256").read_bytes()==expected, "campaign method freeze differs between legs")


def collect(root):
    legs=[]
    method_freeze=(Path(__file__).parent/"methods.sha256").read_bytes()
    frozen=json.loads((Path(__file__).parent/'builds/frozen-binaries.json').read_text())
    previous_end=Decimal(0)
    previous_boot,previous_start=None,0
    previous_mono=0
    for number,(pair,arm) in enumerate(ORDER,1):
        leg=root/f'{number:02d}-{arm}'
        cell=leg/'matrix/rustbgpd'
        errors=[]
        try:
            validate_method_freeze(leg,method_freeze)
            previous_end=validate_leg_metadata(leg,arm,frozen,previous_end,previous_mono)
            previous_mono=int((leg/'finished.monotonic_ns').read_text())
            for file in ('runner.exit','identity.exit','sampler.exit','cleanup.exit'):
                require((leg/file).read_text().strip()=='0',f'{file} failed')
            require((cell/'status').read_text().strip()=='pass','native cell failed')
            require((cell/'daemon.exit').read_text().strip()=='0','daemon failed')
        except (OSError,ValueError) as error:
            errors.append(str(error))
        # Keep overhead numbers when trace validation fails; native full maps still gate.
        _,_,_,native=read_harness(cell/'reloadstall.log',700,None)
        rows=[{'round':r,'stall_p50_ms':native[r][9],'completion_p50_s':native[r][6]} for r in range(1,5)]
        match=re.search(r'^pid=(\d+) pgid=(\d+) starttime=(\d+) cgroup=',(leg/'sampler.log').read_text(),re.M)
        require(match is not None,'missing daemon process identity')
        owner=json.loads((leg/'runner.owner.json').read_text())
        process_identity,previous_boot,previous_start=validate_process(match,owner,previous_boot,previous_start)
        detail={}
        try:
            if arm=='probe':
                publication=read_publication(leg/'publication.csv')
                require(publication['cross_process_clock_qualified'] is True,'publication clock rejected')
                detail['publication']=publication
                detail['receiver']=analyze(cell/'reloadstall.log',cell/'daemon.log',leg/'publication.csv')
            else:
                require('phase_writer,' not in (cell/'daemon.log').read_text(),'writer probe in control')
                require(not (leg/'publication.csv').exists(),'publication probe in control')
                detail['receiver']=analyze(cell/'reloadstall.log')
        except (OSError,ValueError) as error:
            errors.append(str(error))
        legs.append({'pair':pair,'arm':arm,'process_identity':process_identity,'native_rounds':rows,
                     'joins_and_clocks_qualified':not errors,'errors':errors,'detail':detail})
    return qualify(legs)

if __name__=='__main__':
    print(json.dumps(collect(Path(sys.argv[1])),indent=2))
