"""Derived paired comparisons; seed bootstrap conditions on frozen selections."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import random
from statistics import mean, quantiles

from goblintrap.study import write_csv


def read(path):
    with path.open(newline='',encoding='utf-8') as f:
        return list(csv.DictReader(f))


def interval(differences, label, resamples=2000):
    if len(differences)<2:
        raise ValueError('Two or more paired seeds required')
    rng = random.Random('v4-paired|'+label)
    samples = sorted(sum(rng.choices(differences,k=len(differences)))/len(differences) for _ in range(resamples))
    cuts = quantiles(samples,n=40,method='inclusive')
    return dict(difference=mean(differences),ci_low=cuts[0],ci_high=cuts[-1],seeds=len(differences))


def paired(rows, silent_candidate, signal_candidate, split, label):
    groups = {}
    for row in rows:
        if row['split']!=split: continue
        if (row['policy'],row['candidate']) not in (('deception_silent',silent_candidate),('deception',signal_candidate)): continue
        key = row['policy'],row['scenario'],int(row['seed'])
        if key in groups: raise ValueError('Duplicate paired cell')
        groups[key] = row
    left = {(s,n) for p,s,n in groups if p=='deception_silent'}
    right = {(s,n) for p,s,n in groups if p=='deception'}
    if not left or left!=right: raise ValueError('Missing paired cells')
    seeds = sorted({n for s,n in left})
    scenarios = sorted({s for s,n in left})
    if left!={(s,n) for s in scenarios for n in seeds}: raise ValueError('Incomplete family/seed grid')
    out = {}
    for metric, field, malicious in (('harm','harmful_actions',True),('containment','contained',True),('benign_cost','benign_cost',False)):
        families = [s for s in scenarios if (not s.startswith('benign_'))==malicious]
        if not families: raise ValueError('Missing class')
        def value(row): return float(row[field]=='True') if field=='contained' else float(row[field])
        differences = [mean(value(groups['deception',s,n])-value(groups['deception_silent',s,n]) for s in families) for n in seeds]
        out[metric] = interval(differences,label+'|'+metric)
    return out


def analyze(directory, output):
    directory, output = Path(directory), Path(output)
    audit=json.loads((directory/'verification.json').read_text())
    if audit['status']!='PASS' or not audit['full_replay']: raise ValueError('Full verification required')
    plan=json.loads((directory/'protocol.json').read_text())
    budgets=read(directory/'budget_results.csv')
    output.mkdir(parents=True,exist_ok=True)
    fixed, comparisons, cache = [], [], {}
    for environment in plan['environments']:
        rows=read(directory/f'evaluation_{environment}.csv')
        for split in ('test','family_shift'):
            ci=paired(rows,'t8_l1','t8_l1',split,environment+'|'+split+'|t8_l1|t8_l1')
            for metric,data in ci.items(): fixed.append(dict(environment=environment,split=split,metric=metric,**data))
            for budget in plan['budgets']:
                for alert_limit in plan['alert_limits']:
                    selected={r['policy']:r for r in budgets if r['environment']==environment and r['split']==split
                              and float(r['budget'])==budget and float(r['alert_limit'])==alert_limit}
                    silent,signal=selected['deception_silent'],selected['deception']
                    feasible=all(r['calibration_feasible']=='True' for r in (silent,signal))
                    pair_key=environment,split,silent['candidate'],signal['candidate']
                    if feasible and pair_key not in cache:
                        cache[pair_key]=paired(rows,silent['candidate'],signal['candidate'],split,'|'.join(pair_key))
                    for metric in ('harm','containment','benign_cost'):
                        data=cache[pair_key][metric] if feasible else dict(difference=None,ci_low=None,ci_high=None,seeds=len(plan['test_seeds']))
                        comparisons.append(dict(environment=environment,split=split,budget=budget,alert_limit=alert_limit,
                            silent_candidate=silent['candidate'],signal_candidate=signal['candidate'],
                            calibration_feasible=feasible,heldout_both_feasible=all(r['heldout_feasible']=='True' for r in (silent,signal)),
                            metric=metric,**data))
        print('analyzed '+environment,flush=True)
    write_csv(output/'fixed-signal-effects.csv',fixed)
    write_csv(output/'budget-signal-effects.csv',comparisons)
    matched=[r for r in comparisons if r['metric']=='harm' and r['split']=='test']
    feasible=[r for r in matched if r['calibration_feasible']]
    payload=dict(version=plan['version'],fixed_effects=fixed,
        original_family_comparisons=len(matched),calibration_feasible_pairs=len(feasible),
        heldout_both_feasible_pairs=sum(r['heldout_both_feasible'] for r in feasible),
        signal_less_harm=sum(r['difference'] < -1e-12 for r in feasible),
        signal_equal_harm=sum(abs(r['difference'])<=1e-12 for r in feasible),
        signal_more_harm=sum(r['difference'] > 1e-12 for r in feasible),
        budget_rows=len(budgets),calibration_infeasible_rows=sum(r['calibration_feasible']=='False' for r in budgets),
        original_family_budget_violations=sum(r['calibration_feasible']=='True' and r['heldout_feasible']=='False' and r['split']=='test' for r in budgets),
        shift_budget_violations=sum(r['calibration_feasible']=='True' and r['heldout_feasible']=='False' and r['split']=='family_shift' for r in budgets),
        uncertainty='2000 paired seed-cluster percentile bootstrap resamples, inclusive interpolation. Conditions on fixed calibrated choices and designed families; omits selection and world uncertainty. Correlated grid cells are not replications.',
        input_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(directory.glob('*.csv'))})
    (output/'analysis.json').write_text(json.dumps(payload,indent=2)+'\n')
    return {k:v for k,v in payload.items() if k not in ('fixed_effects','input_sha256')}


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--data',default='results/v4')
    parser.add_argument('--output',default='output/v4')
    args=parser.parse_args()
    print(json.dumps(analyze(args.data,args.output),indent=2))
