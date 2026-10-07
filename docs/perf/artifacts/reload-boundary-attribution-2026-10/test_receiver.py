import tempfile
import unittest
from pathlib import Path
import analyze_receiver as a


def fixture():
    o={'marker':44,'first':1}
    r=dict(marker=44,frame_start=110,frame_end=140,first_start=100,first_end=120,
           first_poll=110,first_ready=120,first_done=130,first_pending=1,
           last_start=120,last_end=160,last_poll=200,last_ready=210,last_done=220,last_pending=0,
           decode_start=230,decode_end=240,classify_end=1000,observer_us=1)
    w=dict(success=1,accepted=60,bulk_start=0,bulk_end=60,target_start=10,target_end=40,
           stream_start=100,count=3,started=10,finished=100,dumped=9999)
    polls=[dict(ordinal=0,offset=0,before=20,after=30,result=20),
           dict(ordinal=1,offset=20,before=40,after=50,result=-1),
           dict(ordinal=2,offset=20,before=60,after=70,result=40)]
    m={'byte_start':10,'byte_end':40,'admission_before':5}
    return [o,r,w,polls,m,(1_000_000,1_000_000),(1_000_000,1_000_000)]


def harness_fixture():
    lines=[]
    for r in range(1,5):
        t=r*10_000; marker=(65400 << 16) | (2000 if r % 2 else 1000)
        for i in range(2):
            lines.append(f'phase_outcome,{r},{i},{t},{t+9000},{t+1000+i*100},{t+5000+i*100},572,{marker},{1+i}.000000,1,{4-i*.1:.6f},1')
            lines.append(f'phase_gap,{r},{i},0,{t+2000},{t+3000+i*1000},update')
            lines.append(f'phase_all_gap,{r},{i},0,{t+5000+i*100},{t+9000},trailing')
        for kind, ts in [('before',(t-10)*1000),('after',(t+9100)*1000)]:
            lines.append(f'phase_clock,{r},{kind},{ts},{10**15+ts+1},{ts+2}')
        row=[r,2,2,0,1144,.0051,.0051,.0051,2,2,2,4,4,4,1.1,1.1,1.1,1,1,0,2,0]
        lines.append('reloadstall_csv,'+','.join(map(str,row)))
    return lines


class TestReceiver(unittest.TestCase):
    def read_fixture(self, lines):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'harness.log';path.write_text('\n'.join(lines)+'\n')
            return a.read_harness(path,2,False)

    def test_full_control_map(self):
        self.assertEqual(len(self.read_fixture(harness_fixture())[0]),8)

    def test_missing_tied_maximum(self):
        lines=harness_fixture();row=lines[0].split(',');row[10]='2';lines[0]=','.join(row)
        with self.assertRaisesRegex(ValueError,'maximum-gap tie'):self.read_fixture(lines)

    def test_first_generation_tie_relation(self):
        lines=harness_fixture();row=lines[0].split(',');row[10]='2';lines[0]=','.join(row)
        lines[1]='phase_gap,1,0,0,10000,11000,leading'
        lines.append('phase_gap,1,0,1,14000,15000,update')
        self.assertEqual(self.read_fixture(lines)[0][1,0]['first_generation_max_gap_relation'],'one_of_ties')

    def test_changed_and_all_window_gaps_are_distinct(self):
        outcomes,_,_,native=self.read_fixture(harness_fixture())
        self.assertEqual((outcomes[1,0]['gap'],outcomes[1,0]['all_gap']),(1,4))
        self.assertEqual((float(native[1][9]),float(native[1][12])),(2,4))

    def test_wrong_all_window_p50(self):
        lines=harness_fixture();index=next(i for i,v in enumerate(lines) if v.startswith('reloadstall_csv,'))
        row=lines[index].split(',');row[12]=row[9];lines[index]=','.join(row)
        with self.assertRaisesRegex(ValueError,'aggregate mismatch'):self.read_fixture(lines)

    def test_changed_gap_cannot_extend_to_full_window(self):
        lines=harness_fixture();lines[1]='phase_gap,1,0,0,18000,19000,trailing'
        with self.assertRaisesRegex(ValueError,'gap span order/window'):self.read_fixture(lines)

    def test_missing_all_window_tie_rejected(self):
        lines=[v for v in harness_fixture() if not v.startswith('phase_all_gap,1,0,')]
        with self.assertRaisesRegex(ValueError,'maximum-gap tie'):self.read_fixture(lines)

    def test_single_missing_observer(self):
        lines=harness_fixture();lines.pop(0)
        with self.assertRaisesRegex(ValueError,'observer/round coverage'):self.read_fixture(lines)

    def test_duplicate_native_observer(self):
        lines=harness_fixture();lines.append(lines[0])
        with self.assertRaisesRegex(ValueError,'duplicate outcome'):self.read_fixture(lines)

    def test_missing_entire_round(self):
        lines=[line for line in harness_fixture() if line.split(',')[1]!='2']
        with self.assertRaisesRegex(ValueError,'observer/round coverage'):self.read_fixture(lines)

    def test_round_identity_swap(self):
        lines=[]
        for line in harness_fixture():
            row=line.split(',');row[1]={'1':'3','3':'1'}.get(row[1],row[1]);lines.append(','.join(row))
        with self.assertRaisesRegex(ValueError,'relabeled rounds'):self.read_fixture(lines)

    def test_wrong_changed_p50(self):
        lines=harness_fixture();index=next(i for i,v in enumerate(lines) if v.startswith('reloadstall_csv,'));row=lines[index].split(',');row[9]='1';lines[index]=','.join(row)
        with self.assertRaisesRegex(ValueError,'aggregate mismatch'):self.read_fixture(lines)

    def test_inconsistent_round_window(self):
        lines=harness_fixture();row=lines[0].split(',');row[4]=str(int(row[4])+1);lines[0]=','.join(row)
        index=next(i for i,v in enumerate(lines) if v.startswith('phase_all_gap,1,0,'));span=lines[index].split(',');span[4]=str(int(span[4])+1);span[5]=str(int(span[5])+1);lines[index]=','.join(span)
        with self.assertRaisesRegex(ValueError,'inconsistent round window'):self.read_fixture(lines)

    def test_dump_after_final_window_with_clock_uncertainty(self):
        a.require_deferred_dump({'dumped':1002},1,(100,102),(100,101))
        with self.assertRaisesRegex(ValueError,'before final measured'):
            a.require_deferred_dump({'dumped':1001},1,(100,102),(100,101))

    def test_negative_counter_rejected(self):
        with self.assertRaisesRegex(ValueError,'negative trace field'):
            a.integers({'first_pending':'-1'})

    def test_partial_writes_and_split_frame(self):
        result=a.join_one(*fixture())
        self.assertEqual(result['first_accept_to_read_poll_lower_ns'],90)
        self.assertEqual(result['last_accept_to_read_poll_lower_ns'],140)
        self.assertEqual(result['frame_read_completion_span_ns'],90)

    def test_writer_before_admission_rejected(self):
        args=fixture();args[4]['admission_before']=11
        with self.assertRaisesRegex(ValueError,'predates queue'):a.join_one(*args)

    def test_wrong_frame_in_correct_batch_rejected(self):
        args=fixture();args[1]['frame_start']+=1
        with self.assertRaisesRegex(ValueError,'exact admitted chunk'):a.join_one(*args)

    def test_wrong_admission_interval_rejected(self):
        args=fixture();args[4]['byte_start']+=1
        with self.assertRaisesRegex(ValueError,'admission mismatch'):a.join_one(*args)

    def test_wrong_marker_rejected(self):
        args=fixture();args[1]['marker']+=1
        with self.assertRaisesRegex(ValueError,'generation/event'):a.join_one(*args)

    def test_wrong_observer_event_rejected(self):
        args=fixture();args[1]['observer_us']+=1
        with self.assertRaisesRegex(ValueError,'generation/event'):a.join_one(*args)

    def test_incomplete_writer_rejected(self):
        args=fixture();args[2]['accepted']-=1
        with self.assertRaisesRegex(ValueError,'incomplete writer'):a.join_one(*args)

    def test_wrong_poll_offset_rejected(self):
        args=fixture();args[3][2]['offset']+=1
        with self.assertRaisesRegex(ValueError,'FIFO discontinuity'):a.join_one(*args)

    def test_write_error_rejected(self):
        args=fixture();args[3][1]['result']=-2
        with self.assertRaisesRegex(ValueError,'failed/zero'):a.join_one(*args)

    def test_missing_poll_rejected(self):
        args=fixture();args[3].pop()
        with self.assertRaisesRegex(ValueError,'count/overflow'):a.join_one(*args)

    def test_missing_read_bytes_rejected(self):
        args=fixture();args[1]['last_end']=130
        with self.assertRaisesRegex(ValueError,'read byte interval'):a.join_one(*args)

    def test_decode_before_complete_read_rejected(self):
        args=fixture();args[1]['decode_start']=215
        with self.assertRaisesRegex(ValueError,'receiver phase order'):a.join_one(*args)

    def test_clock_disagreement_rejected(self):
        with self.assertRaisesRegex(ValueError,'clocks|clock anchors'):a.clock_interval([(10,1000,12),(20,2000,22)])

    def test_wide_clock_rejected(self):
        with self.assertRaisesRegex(ValueError,'50 us'):a.clock_interval([(10,1_000_000,100_000)])

    def test_known_clock_interval(self):
        self.assertEqual(a.clock_interval([(10,1000,12),(20,1010,21)]),(989,990))

    def test_duplicate_record_rejected(self):
        with self.assertRaisesRegex(ValueError,'duplicate'):a.insert({(1,1):{}},(1,1),{},'outcome')

    def test_missing_all700_map_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'harness.log';p.write_text('')
            with self.assertRaisesRegex(ValueError,'observer/round coverage'):a.read_harness(p,700,False)

    def test_nonfinite_gap_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'harness.log';p.write_text('phase_outcome,1,0,1,3,1,2,399828,44,nan,1,0,1\n')
            with self.assertRaisesRegex(ValueError,'invalid gap'):a.read_harness(p,700,False)

    def test_startup_clock_mapping(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'publication.csv';p.write_text('clock,999,1001,123\nclock_end,100,1100,102\n')
            self.assertEqual(a.read_publication(p)[1],(998,1000))

if __name__=='__main__':unittest.main()
