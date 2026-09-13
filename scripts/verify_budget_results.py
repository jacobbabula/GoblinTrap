"""Check complete v4 cells, replay every trial, recompute selection and summaries.

Aggregates and selection are independently coded here. Trial replay shares the
engine and is not independent validation of world assumptions. No asserts.
"""
import argparse
import csv
import hashlib
import json
import math
from pathlib import Path

from goblintrap.extended_engine import Config, trial

METRICS = {'harm': ('harmful_actions', True), 'containment': ('contained', True),
           'benign_cost': ('benign_cost', False), 'disruption': ('disrupted_actions', False),
           'false_alert': ('false_positive', False),
           'benign_collateral': ('collateral_disrupted_calls', False),
           'attack_collateral': ('collateral_disrupted_calls', True)}


def require(value, message):
    if not value:
        raise ValueError(message)


def read(path):
    with path.open(newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        require(reader.fieldnames and len(reader.fieldnames)==len(set(reader.fieldnames)), f'Bad columns: {path}')
        rows = list(reader)
    require(all(None not in r and None not in r.values() for r in rows), f'Ragged rows: {path}')
    return rows


def number(value):
    if value in ('True', 'False'):
        return float(value == 'True')
    result = float(value)
    require(math.isfinite(result), 'Nonfinite number')
    return result


def close(actual, expected, where):
    require(math.isclose(number(actual), expected, rel_tol=1e-11, abs_tol=1e-11), f'Mismatch {where}: {actual} != {expected}')


def statistics(rows):
    out = {}
    for key, (field, malicious) in METRICS.items():
        values = [number(r[field]) for r in rows if r['malicious']==str(malicious)]
        require(values, 'Missing family class')
        out[key] = math.fsum(values) / len(values)
    return out


def verify(directory, *, write=True):
    directory = Path(directory)
    root = Path(__file__).resolve().parents[1]
    plan = json.loads((directory/'protocol.json').read_text())
    meta = json.loads((directory/'metadata.json').read_text())
    choices = json.loads((directory/'frozen_choices.json').read_text())
    for name, key in (('protocol.json','protocol_sha256'),('frozen_choices.json','choices_sha256')):
        require(hashlib.sha256((directory/name).read_bytes()).hexdigest()==meta[key], f'Changed {name}')
    require(meta['source_sha256']==plan['source_sha256'], 'Source metadata mismatch')
    for name, value in plan['source_sha256'].items():
        require(hashlib.sha256((root/name).read_bytes()).hexdigest()==value, f'Source drift {name}')
    require(not set(plan['calibration_seeds']) & set(plan['test_seeds']), 'Seed leakage')
    require(not set(plan['calibration_families']) & set(plan['shift_families']), 'Family leakage')
    require(len(set(plan['calibration_seeds']))==len(plan['calibration_seeds']) and
            len(set(plan['test_seeds']))==len(plan['test_seeds']), 'Duplicate seeds')
    cal_saved = read(directory/'calibration_summary.csv')
    budget_saved = read(directory/'budget_results.csv')
    family_saved = read(directory/'by_family.csv')
    expected_choice_keys = {(e,b,a,p) for e in plan['environments'] for b in plan['budgets']
                            for a in plan['alert_limits'] for p in plan['arms']}
    choice_keys = [(c['environment'],c['budget'],c['alert_limit'],c['policy']) for c in choices]
    require(len(choice_keys)==len(set(choice_keys)) and set(choice_keys)==expected_choice_keys, 'Choice cells incomplete/duplicate')
    require(len(cal_saved)==len(plan['environments'])*len(plan['thresholds'])*len(plan['delays'])*len(plan['arms']), 'Calibration summary count')
    require(len(budget_saved)==len(choices)*2, 'Budget summary count')
    total = 0
    expected_family_keys = set()
    for environment, base in plan['environments'].items():
        configs = {}
        for threshold in plan['thresholds']:
            for delay in plan['delays']:
                configs[f't{threshold:g}_l{delay}'] = Config(**{**base,'threshold':threshold,'latency':delay})
        aggregates = {}
        for split_kind in ('calibration', 'evaluation'):
            rows = read(directory/f'{split_kind}_{environment}.csv')
            if split_kind == 'calibration':
                expected = {(p,c,'calibration',s,str(seed)) for p in plan['arms'] for c in configs
                            for s in plan['calibration_families'] for seed in plan['calibration_seeds']}
            else:
                wanted = {(c['policy'],c['candidate']) for c in choices
                          if c['environment']==environment and c['candidate'] is not None}
                wanted.update((p,'t8_l1') for p in plan['arms'])
                expected = {(p,c,split,s,str(seed)) for p,c in wanted
                            for split, families in (('test',plan['calibration_families']),('family_shift',plan['shift_families']))
                            for s in families for seed in plan['test_seeds']}
            keys = [(r['policy'],r['candidate'],r['split'],r['scenario'],r['seed']) for r in rows]
            require(len(keys)==len(set(keys)) and set(keys)==expected, f'Incomplete/duplicate cells {environment}/{split_kind}')
            grouped = {}
            family_groups = {}
            for row in rows:
                require(row['environment']==environment, 'Misattributed environment')
                replay = trial(row['scenario'],row['policy'],int(row['seed']),configs[row['candidate']],retain_events=False)
                replay = {k:v for k,v in replay.items() if k not in ('events','anchor','ground_truth','evidence_integrity')}
                require(set(row)==set(replay)|{'environment','candidate','split'}, 'Trial schema mismatch')
                for key,value in replay.items():
                    require(row[key]==('' if value is None else str(value)), f'Replay mismatch {environment}/{row["candidate"]}/{row["scenario"]}/{row["seed"]}/{key}')
                group = row['policy'],row['candidate'],row['split']
                grouped.setdefault(group,[]).append(row)
                family_groups.setdefault((*group,row['scenario']),[]).append(row)
            for key, group in grouped.items():
                aggregates[key] = statistics(group)
            total += len(rows)
            if split_kind=='evaluation':
                for (arm,candidate,split,scenario), group in family_groups.items():
                    expected_family_keys.add((environment,arm,candidate,split,scenario))
                    saved = [r for r in family_saved if (r['environment'],r['policy'],r['candidate'],r['split'],r['scenario'])==
                             (environment,arm,candidate,split,scenario)]
                    require(len(saved)==1, 'Family summary incomplete/duplicate')
                    for field in ('harmful_actions','contained','benign_cost','false_positive','disrupted_actions','collateral_disrupted_calls'):
                        close(saved[0][field],math.fsum(number(r[field]) for r in group)/len(group),f'family/{field}')
        candidates_by_arm = {p:[] for p in plan['arms']}
        for arm in plan['arms']:
            for candidate, cfg in configs.items():
                metrics = aggregates[arm,candidate,'calibration']
                saved = [r for r in cal_saved if (r['environment'],r['policy'],r['candidate'])==(environment,arm,candidate)]
                require(len(saved)==1, 'Calibration summary keys')
                close(saved[0]['threshold'],cfg.threshold,'threshold')
                close(saved[0]['latency'],cfg.latency,'latency')
                for key,value in metrics.items(): close(saved[0][key],value,'calibration/'+key)
                candidates_by_arm[arm].append(dict(candidate=candidate,threshold=cfg.threshold,latency=cfg.latency,**metrics))
        for choice in (c for c in choices if c['environment']==environment):
            valid = [r for r in candidates_by_arm[choice['policy']] if r['benign_cost']<=choice['budget']+1e-12
                     and r['false_alert']<=choice['alert_limit']+1e-12]
            best = sorted(valid,key=lambda r:(r['harm'],-r['containment'],r['benign_cost'],r['false_alert'],r['threshold'],r['latency']))[0] if valid else None
            require(choice['candidate']==(best['candidate'] if best else None), 'Incorrect calibrated selection')
            require((choice['calibration'] is None)==(best is None), 'Selection feasibility metadata')
            if best:
                require(choice['calibration']['environment']==environment and choice['calibration']['policy']==choice['policy'] and
                        choice['calibration']['candidate']==best['candidate'], 'Selection identity')
                for key in (*METRICS,'threshold','latency'): close(str(choice['calibration'][key]),best[key],'choice/'+key)
            for split in ('test','family_shift'):
                saved = [r for r in budget_saved if r['environment']==environment and r['policy']==choice['policy'] and
                         float(r['budget'])==choice['budget'] and float(r['alert_limit'])==choice['alert_limit'] and r['split']==split]
                require(len(saved)==1, 'Budget summary keys')
                saved = saved[0]
                require(saved['candidate']==(choice['candidate'] or '') and saved['calibration_feasible']==str(best is not None), 'Budget selection mismatch')
                metrics = aggregates[choice['policy'],choice['candidate'],split] if best else None
                feasible = metrics is not None and metrics['benign_cost']<=choice['budget']+1e-12 and metrics['false_alert']<=choice['alert_limit']+1e-12
                require(saved['heldout_feasible']==str(feasible), 'Hidden heldout budget violation')
                for key in METRICS:
                    if metrics: close(saved[key],metrics[key],'budget/'+key)
                    else: require(saved[key]=='', 'Infeasible metric must be empty')
        print(f'verified {environment}',flush=True)
    require(len(family_saved)==len(expected_family_keys), 'Extra family summaries')
    require(total==meta['total_trials'], 'Total trial mismatch')
    result = dict(status='PASS',full_replay=True,total_rows_checked=total,
                  choices_checked=len(choices),budget_rows_checked=len(budget_saved),
                  family_rows_checked=len(family_saved),source_hashes_verified=True,
                  scope='Independent aggregate and selection implementation; replay shares simulation engine. No independent researcher or model validation.')
    if write: (directory/'verification.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('directory',nargs='?',default='results/v4')
    print(json.dumps(verify(parser.parse_args().directory),indent=2))
