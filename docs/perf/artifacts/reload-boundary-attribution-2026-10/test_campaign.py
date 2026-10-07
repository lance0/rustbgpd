import csv
from datetime import datetime, timezone
from decimal import Decimal
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from collect_campaign import validate_leg_metadata, validate_process, validate_method_freeze
from owned_process import identity, matches, owned_signal

class TestMetadata(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.leg=Path(self.tmp.name);self.cell=self.leg/'matrix/rustbgpd';self.cell.mkdir(parents=True)
        self.frozen={'source_commit':'source','binaries':{'rustbgpd-control':'controlD','reloadstall-control':'controlH'},'native_common':{'runner':'abc'},'native_generator':{'generator':'def'}}
        self.provenance={'git':{'commit':'source'},'workload':{'sha256':'controlD','inputs':{'N_PEERS':'700','TOTAL_PREFIXES':'400400','PORT':'1790','RELOADS':'4','CONTROL_SECS':'30','CHANGED_PEERS':'','FLAPSTORM':'','BIRD_THREADS':'8','PROBE_PREFIXES':''}},'sources':{'reloadstall':{'sha256':'controlH'},'common':{'runner':'abc'},'generator':{'generator':'def'}}}
        self.save_provenance()
        (self.leg/'started.epoch').write_text('1700000000.123')
        (self.leg/'finished.epoch').write_text('1700000350.000')
        (self.leg/'started.monotonic_ns').write_text('1000000000')
        (self.leg/'finished.monotonic_ns').write_text('400000000000')
        (self.cell/'cooldown-start.monotonic_ns').write_text('50000000000')
        (self.cell/'cooldown-end.monotonic_ns').write_text('350000000000')
        self.quiet=[dict(sample=str(i+1),epoch_s=str(1700000001+30*i),load1='0.4',pswpin='123',pswpout='456',performance_governors='64',governor_count='64',competitors='none',quiet='true',failed_dimensions='none') for i in range(2)]
        self.save_quiet()
        iso=lambda ts:datetime.fromtimestamp(ts,timezone.utc).isoformat()
        (self.leg/'runner.log').write_text(f'=== cell rustbgpd start {iso(1700000032)} ===\n=== cell rustbgpd PASS {iso(1700000040)} ===\ncool-down 300s\nmatrix done; per-cell status under output/*/status\n')
    def save_provenance(self):(self.cell/'provenance.json').write_text(json.dumps(self.provenance))
    def save_quiet(self):
        with (self.cell/'quiet.tsv').open('w') as f:
            w=csv.DictWriter(f,fieldnames=list(self.quiet[0]),delimiter='\t');w.writeheader();w.writerows(self.quiet)
    def check(self,previous=Decimal(0)):return validate_leg_metadata(self.leg,'control',self.frozen,previous)
    def test_valid(self):self.assertEqual(self.check(),Decimal('1700000350'))
    def test_method_freeze_matches_every_leg(self):
        (self.leg/'methods.sha256').write_bytes(b'expected freeze')
        validate_method_freeze(self.leg,b'expected freeze')
        with self.assertRaisesRegex(ValueError,'method freeze'):
            validate_method_freeze(self.leg,b'another freeze')
    def test_short_monotonic_cooldown(self):
        (self.cell/'cooldown-end.monotonic_ns').write_text('349999999999')
        with self.assertRaisesRegex(ValueError,'monotonic cooldown'):self.check()
    def test_reordered_monotonic_leg(self):
        with self.assertRaisesRegex(ValueError,'monotonic leg'):
            validate_leg_metadata(self.leg,'control',self.frozen,Decimal(0),1000000001)
    def test_wrong_control_duration(self):
        self.provenance['workload']['inputs']['CONTROL_SECS']='1';self.save_provenance()
        with self.assertRaisesRegex(ValueError,'workload inputs'):self.check()
    def test_wrong_daemon_arm(self):
        self.provenance['workload']['sha256']='probeD';self.save_provenance()
        with self.assertRaisesRegex(ValueError,'daemon arm'):self.check()
    def test_wrong_harness_arm(self):
        self.provenance['sources']['reloadstall']['sha256']='probeH';self.save_provenance()
        with self.assertRaisesRegex(ValueError,'harness arm'):self.check()
    def test_swapped_chronology(self):
        with self.assertRaisesRegex(ValueError,'chronology'):self.check(Decimal('1700000351'))
    def test_truncated_cooldown(self):
        (self.leg/'finished.epoch').write_text('1700000339')
        with self.assertRaisesRegex(ValueError,'cooldown'):self.check()
    def test_quiet_spacing(self):
        self.quiet[1]['epoch_s']='1700000030';self.save_quiet()
        with self.assertRaisesRegex(ValueError,'quiet spacing'):self.check()
    def test_wrong_runner_source(self):
        self.provenance['sources']['common']['runner']='changed';self.save_provenance()
        with self.assertRaisesRegex(ValueError,'helper source'):self.check()

class TestOwnership(unittest.TestCase):
    def test_fresh_process_identity(self):
        import re
        match=re.match(r'(\d+) (\d+) (\d+)','22 11 100')
        owner={'pid':11,'pgid':11,'sid':11,'boot':'boot'}
        self.assertEqual(validate_process(match,owner,None,0),('boot:22:100','boot',100))
        for bad,boot,start in [({**owner,'pid':12},None,0),(owner,'other',0),(owner,'boot',100)]:
            with self.assertRaises(ValueError):validate_process(match,bad,boot,start)

    def test_reparenting_preserves_stable_identity(self):
        row={'pid':1,'ppid':2,'start':3,'pgid':4,'sid':5,'boot':'boot'}
        reparented={**row,'ppid':999}
        self.assertTrue(matches(row,reparented))
        self.assertFalse(matches(row,{**reparented,'start':4}))
    def test_refuses_changed_owner_then_reaps_owned_child(self):
        child=subprocess.Popen([sys.executable,'-c','import signal; signal.pause()'],start_new_session=True)
        try:
            owner=identity(child.pid)
            with self.assertRaises(RuntimeError):owned_signal({**owner,'start':owner['start']+1},'TERM')
            self.assertIsNone(child.poll())
            owned_signal(owner,'TERM')
            child.wait(timeout=2)
        finally:
            if child.poll() is None:child.kill();child.wait()

if __name__=='__main__':unittest.main()
