"""Audit every saved trial and statistic; checks remain active under python -O.

Default: replay all trials. --sample-replays is a faster, explicitly partial check.
The aggregation and bootstrap checks below do not call the study summarizers.
"""
import argparse
from collections import defaultdict
from dataclasses import asdict
import csv
import hashlib
import json
import math
from pathlib import Path
import random

from goblintrap.engine import Config, POLICIES, SCENARIOS, VERSION, trial, verify_events
from goblintrap.study import configs as planned_configs, scalar


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_csv(path):
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        require(reader.fieldnames is not None and len(reader.fieldnames)==len(set(reader.fieldnames)),
                f"duplicate/missing columns: {path.name}")
        rows=list(reader)
    require(all(None not in r and None not in r.values() for r in rows), f"ragged CSV: {path.name}")
    return rows


BOOLS={"malicious","detected","contained","false_positive","false_containment","persistence_survived"}
TIMES={"detection_step","response_step","containment_step"}
STRINGS={"scenario","policy","config_id"}


def parse(row):
    result={}
    for key,value in row.items():
        if key in STRINGS:
            result[key]=value
        elif key in BOOLS:
            require(value in ("True","False"),f"invalid boolean {key}")
            result[key]=value=="True"
        elif key in TIMES:
            result[key]=None if value=="" else int(value)
        elif key=="evidence_completeness":
            result[key]=float(value)
            require(math.isfinite(result[key]),"nonfinite completeness")
        else:
            result[key]=int(value)
    return result


SUMMARY_METRICS={
    "harmful_actions":("harmful_actions",True), "exfil_actions":("exfil_actions",True),
    "detection_rate":("detected",True), "containment_rate":("contained",True),
    "detection_time_capped":("detection_time_capped",True),
    "containment_time_capped":("containment_time_capped",True),
    "post_detection_harm":("post_detection_harm",True), "decoy_actions":("decoy_actions",True),
    "false_positive_rate":("false_positive",False), "false_containment_rate":("false_containment",False),
    "benign_disrupted_actions":("disrupted_actions",False), "evidence_completeness":("evidence_completeness",None),
}


def near(claim, expected, context):
    value=float(claim)
    require(math.isfinite(value) and math.isclose(value,expected,rel_tol=1e-11,abs_tol=1e-11),
            f"statistic mismatch {context}: {value} != {expected}")


def check_intervals(saved, rows, baseline, wanted_policies):
    lookup={(r['scenario'],r['seed'],r['policy']):r for r in rows}
    seeds=sorted({r['seed'] for r in rows})
    metrics={'harmful_actions':True,'containment_time_capped':True,'false_positive':False,'disrupted_actions':False}
    require(len(saved)==len(wanted_policies)*len(metrics),"paired output count mismatch")
    require({(r['policy'],r['metric']) for r in saved}=={(p,m) for p in wanted_policies for m in metrics},
            "paired output keys incomplete/duplicate")
    for row in saved:
        policy,metric=row['policy'],row['metric']
        require(row['baseline']==baseline and int(row['seeds'])==len(seeds),"paired metadata mismatch")
        families=[s for s in SCENARIOS if (not s.startswith('benign_'))==metrics[metric]]
        values=[math.fsum(lookup[s,seed,policy][metric]-lookup[s,seed,baseline][metric] for s in families)/len(families)
                for seed in seeds]
        near(row['difference'], math.fsum(values)/len(values),f'{policy}/{metric} difference')
        rng=random.Random(f'CI|{baseline}|{policy}|{metric}')
        samples=sorted(math.fsum(rng.choices(values,k=len(seeds)))/len(seeds) for _ in range(2000))
        for field,q in (('ci_low',.025),('ci_high',.975)):
            position=(len(samples)-1)*q
            low=int(position)
            estimate=samples[low]+(position-low)*(samples[min(low+1,len(samples)-1)]-samples[low])
            near(row[field],estimate,f'{policy}/{metric}/{field}')


def verify(root, full_replay=True):
    root=Path(root)
    meta=json.loads((root/'metadata.json').read_text())
    require(meta.get('version')==VERSION and meta.get('status')=='complete','incomplete or wrong-version study')
    project=Path(__file__).resolve().parents[1]
    expected_sources={f'src/goblintrap/{p.name}' for p in (project/'src/goblintrap').glob('*.py')}
    require(set(meta['source_sha256'])==expected_sources,'source manifest incomplete')
    for name,expected in meta['source_sha256'].items():
        require(hashlib.sha256((project/name).read_bytes()).hexdigest()==expected,f'source drift: {name}')
    configurations=json.loads((root/'configurations.json').read_text())
    expected_configs=dict(planned_configs())
    actual_names=[c['config_id'] for c in configurations]
    require(actual_names==list(expected_configs) or actual_names==['primary'],'configuration matrix mismatch')
    require(meta['configurations']==len(configurations),'metadata configuration count')
    saved_summary=read_csv(root/'summary.csv')
    require(len(saved_summary)==len(configurations)*len(POLICIES),'summary count')
    summary={(r['config_id'],r['policy']):r for r in saved_summary}
    require(len(summary)==len(saved_summary),'duplicate summary keys')
    expected_columns=set(scalar(trial('fast','revoke',0,retain_events=False)))|{'config_id'}
    total,replayed=0,0
    for conf in configurations:
        name=conf['config_id']
        count=conf['seeds']
        cfg=Config(**{k:v for k,v in conf.items() if k not in ('config_id','seeds')})
        require(asdict(cfg)==asdict(expected_configs[name]),f'changed config {name}')
        require(count==meta['primary_runs' if name=='primary' else 'sensitivity_runs'],f'seed count {name}')
        require(type(count) is int and count>=2,'invalid seed count')
        raw=read_csv(root/f'trials_{name}.csv')
        require(len(raw)==count*len(SCENARIOS)*len(POLICIES),f'trial count {name}')
        require(all(set(r)==expected_columns for r in raw),f'trial columns {name}')
        rows=[parse(r) for r in raw]
        expected_keys={(s,p,seed) for s in SCENARIOS for p in POLICIES for seed in range(count)}
        require({(r['scenario'],r['policy'],r['seed']) for r in rows}==expected_keys,f'trial keys {name}')
        for r in rows:
            require(r['config_id']==name,'misassigned config')
            if full_replay or r['seed']==0:
                replay=scalar(trial(r['scenario'],r['policy'],r['seed'],cfg,retain_events=False))
                require({k:v for k,v in r.items() if k!='config_id'}==replay,
                        f'replay mismatch {name}/{r["scenario"]}/{r["policy"]}/{r["seed"]}')
                replayed+=1
        for policy in POLICIES:
            group=[r for r in rows if r['policy']==policy]
            saved=summary[name,policy]
            require(set(saved)==set(SUMMARY_METRICS)|{'policy','config_id','malicious_trials','benign_trials'},'summary columns')
            for flag,field in ((True,'malicious_trials'),(False,'benign_trials')):
                require(int(saved[field])==sum(r['malicious']==flag for r in group),f'count {name}/{policy}')
            for field,(source,flag) in SUMMARY_METRICS.items():
                subset=[r for r in group if flag is None or r['malicious']==flag]
                near(saved[field],math.fsum(r[source] for r in subset)/len(subset),f'{name}/{policy}/{field}')
        if name=='primary':
            per=read_csv(root/'by_scenario.csv')
            require(len(per)==len(SCENARIOS)*len(POLICIES),'scenario output count')
            require({(r['scenario'],r['policy']) for r in per}=={(s,p) for s in SCENARIOS for p in POLICIES},'scenario keys')
            for saved in per:
                subset=[r for r in rows if r['scenario']==saved['scenario'] and r['policy']==saved['policy']]
                require(int(saved['seeds'])==len(subset),'scenario seed count')
                for metric in set(saved)-{'scenario','policy','seeds'}:
                    near(saved[metric],math.fsum(r[metric] for r in subset)/len(subset),f'scenario/{metric}')
            check_intervals(read_csv(root/'paired.csv'),rows,'revoke',set(POLICIES)-{'revoke'})
            check_intervals(read_csv(root/'signal_paired.csv'),rows,'deception_silent',{'deception'})
        total+=len(rows)
        print(f'verified {name}: {len(rows)} rows',flush=True)
    require(total==meta['total_trials'],'metadata total mismatch')
    expected_timeline_names={f'timeline_{s}_{p}.jsonl' for s in ('fast','switcher','benign_drill')
                             for p in ('revoke','deception','isolate')}
    require({p.name for p in root.glob('timeline_*.jsonl')}==expected_timeline_names,'timeline set mismatch')
    for file in root.glob('timeline_*.jsonl'):
        events=[json.loads(line) for line in file.read_text().splitlines()]
        anchor=json.loads(file.with_name(file.name.replace('timeline_','anchor_').replace('.jsonl','.json')).read_text())
        require(verify_events(events,anchor),f'invalid chain/context: {file.name}')
        run_context=anchor['run']
        require(file.name==f'timeline_{run_context["scenario"]}_{run_context["policy"]}.jsonl' and run_context['seed']==0,
                'timeline filename/context mismatch')
        require(run_context['config']==asdict(Config()),'example config mismatch')
        replay=trial(run_context['scenario'],run_context['policy'],0)
        require(replay['events']==events and replay['anchor']==anchor,'timeline differs from exact replay')
    report=dict(status='PASS',full_replay=full_replay,total_rows_checked=total,exact_trial_replays=replayed,
                configurations=len(configurations),anchored_timelines_verified=len(expected_timeline_names),
                aggregate_fields_checked='All summary and scenario fields; all paired effects and interval endpoints.',
                source_hashes_verified=True,
                scope='Recomputed statistics independently; replay uses the same engine, not independent model validation.')
    report_name='verification.json' if full_replay else 'verification-sampled.json'
    (root/report_name).write_text(json.dumps(report,indent=2)+'\n')
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root',nargs='?',default='results/v3')
    parser.add_argument('--sample-replays',action='store_true')
    args=parser.parse_args()
    print(json.dumps(verify(args.root,not args.sample_replays),indent=2))
