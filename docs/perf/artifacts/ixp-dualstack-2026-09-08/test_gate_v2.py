import datetime, importlib.util, json, re, shutil, tempfile
from pathlib import Path
PREP=Path(__file__).resolve().parent
SOURCE=PREP/'200-validation-50-P'
def module(path):
 spec=importlib.util.spec_from_file_location(path.stem,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
v1=module(PREP/'gate-v1.py');v2=module(PREP/'gate.py')
args=(200,114400,57200,170,0)
old=v1.check(SOURCE,*args);new=v2.check(SOURCE,*args)
assert not old['pass'] and len(old['errors'])==102 and set(old['errors'])=={'unclassified/active WARN: writer: write/flush failed'}
assert new['pass'],new['errors']
results={'original_gate_errors':len(old['errors']),'candidate_actual_cell_pass':new['pass']}
with tempfile.TemporaryDirectory(prefix='dualstack-gate-v2-tests-') as scratch:
 cell=Path(scratch)/'cell';shutil.copytree(SOURCE,cell,ignore=shutil.ignore_patterns('scenario'))
 logfile=cell/'rustbgpd/daemon.log';lines=logfile.read_text().splitlines();index=next(i for i,s in enumerate(lines) if s.startswith('{') and json.loads(s)['fields'].get('message')=='writer: write/flush failed')
 original=lines[index];event=json.loads(original)
 trigger=int(re.search(r'SIGHUP wall_us=(\d+)',(cell/'rustbgpd/reloadstall.log').read_text())[1])/1e6
 event['timestamp']=datetime.datetime.fromtimestamp(trigger+0.001,datetime.timezone.utc).isoformat()
 lines[index]=json.dumps(event);logfile.write_text('\n'.join(lines)+'\n')
 active=v2.check(cell,*args);assert not active['pass'] and active['errors']==['unclassified/active WARN: writer: write/flush failed'],active['errors']
 results['active_broken_pipe_rejected']=True
 event=json.loads(original);event['fields']['error_kind']='Other';lines[index]=json.dumps(event);logfile.write_text('\n'.join(lines)+'\n')
 other=v2.check(cell,*args);assert not other['pass'] and other['errors']==['unclassified/active WARN: writer: write/flush failed'],other['errors']
 results['other_teardown_writer_error_rejected']=True
 event=json.loads(original);event['fields']['peer']='198.51.100.254';lines[index]=json.dumps(event);logfile.write_text('\n'.join(lines)+'\n')
 live=v2.check(cell,*args);assert not live['pass'] and live['errors']==['unclassified/active WARN: writer: write/flush failed'],live['errors']
 results['peer_without_down_event_rejected']=True
print(json.dumps(results,indent=2))
