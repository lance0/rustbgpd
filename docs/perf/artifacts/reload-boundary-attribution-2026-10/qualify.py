#!/usr/bin/env python3
"""Predeclared six-process overhead gate. Failing evidence remains reportable."""
import json
from decimal import Decimal
from pathlib import Path
import statistics
import sys
from analyze_receiver import require

ORDER=[(1,'control'),(1,'probe'),(2,'probe'),(2,'control'),(3,'control'),(3,'probe')]


def change(control,probe):
    require(control>0 and probe>=0,'invalid metric')
    return float((Decimal(str(probe))/Decimal(str(control))-1)*100)


def qualify(legs):
    require([(v['pair'],v['arm']) for v in legs] == ORDER,'campaign order/independent process coverage')
    require(len({v['process_identity'] for v in legs}) == 6,'reused process identity')
    result={'legs':legs,'metrics':{},'all_joins_and_clocks_qualified':all(v['joins_and_clocks_qualified'] is True for v in legs)}
    exact_pass=[]
    for field in ('stall_p50_ms','completion_p50_s'):
        values={arm:[] for arm in ('control','probe')}
        medians={arm:[] for arm in values}
        for leg in legs:
            rows=leg['native_rounds']
            require([v['round'] for v in rows] == [1,2,3,4],'native round coverage/order')
            series=[v[field] for v in rows]
            require(all(isinstance(v,(int,float,str)) and not isinstance(v,bool) for v in series),'invalid metric type')
            series=[Decimal(str(v)) for v in series]
            require(all(v.is_finite() and v>0 for v in series),'nonfinite/invalid metric')
            values[leg['arm']].extend(series)
            medians[leg['arm']].append(statistics.median(series))
        hierarchy={arm:statistics.median(v) for arm,v in medians.items()}
        pooled={arm:statistics.median(v) for arm,v in values.items()}
        exact_pass.extend([hierarchy['probe'] <= hierarchy['control'] * Decimal('1.02'),
                           pooled['probe'] <= pooled['control'] * Decimal('1.02')])
        result['metrics'][field]={'leg_medians':{arm:list(map(float,v)) for arm,v in medians.items()},
            'hierarchical':{arm:float(v) for arm,v in hierarchy.items()},'pooled':{arm:float(v) for arm,v in pooled.items()},
            'paired_changes_percent':[change(medians['control'][i],medians['probe'][i]) for i in range(3)],
            'hierarchical_change_percent':change(hierarchy['control'],hierarchy['probe']),
            'pooled_change_percent':change(pooled['control'],pooled['probe'])}
    result['overhead_qualified']=all(exact_pass)
    result['measurement_overhead_and_joins_qualified']=result['overhead_qualified'] and result['all_joins_and_clocks_qualified']
    result['production_tail_component_attribution_qualified']=False
    result['causal_optimization_selected']=False
    result['repeatability_required']='Inspect separate phase ranks across all three probe processes; overhead qualification alone identifies no dominant cause.'
    return result

if __name__=='__main__':
    print(json.dumps(qualify(json.loads(Path(sys.argv[1]).read_text())),indent=2))
