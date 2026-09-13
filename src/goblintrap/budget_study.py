"""Calibrate constrained policies, freeze choices, then evaluate unused seeds.

All grids and tie breaks are explicit. Budget matching means a common upper
bound, not identical realized cost. No test outcomes enter selection.
"""
from collections import defaultdict
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
from statistics import mean

from .extended_engine import Config, CALIBRATION_SCENARIOS, SHIFT_SCENARIOS, trial, VERSION
from .study import write_csv, scalar

ARMS = ("revoke", "deception_silent", "deception", "isolate")
THRESHOLDS = (3., 5., 8., 12., 20., 1000.)
DELAYS = (0, 1, 3)
BUDGETS = (0., 1., 3., 6., 12.)
ALERT_LIMITS = (.34, .67)
METRICS = {"harm": ("harmful_actions", True), "containment": ("contained", True),
           "benign_cost": ("benign_cost", False), "disruption": ("disrupted_actions", False),
           "false_alert": ("false_positive", False),
           "benign_collateral": ("collateral_disrupted_calls", False),
           "attack_collateral": ("collateral_disrupted_calls", True)}


def environments():
    base = Config()
    yield "ideal", base
    for name, changes in (
        ("coverage_half", dict(isolation_coverage=.5)),
        ("reliability_half", dict(isolation_reliability=.5)),
        ("collateral_quarter", dict(collateral_calls_per_step=.25)),
        ("collateral_one", dict(collateral_calls_per_step=1.)),
        ("background_empty", dict(background_empty_probability=.15)),
        ("recognition_half", dict(recognition_probability=.5)),
        ("patience_four", dict(recognition_patience=4)),
        ("avoidance_half", dict(bait_avoidance=.5)),
        ("avoidance_all", dict(bait_avoidance=1.)),
        ("adaptive_avoidance", dict(adaptive_avoidance=1.)),
        ("combined", dict(isolation_coverage=.5, isolation_reliability=.5,
                          collateral_calls_per_step=.25, background_empty_probability=.15,
                          recognition_probability=.5, bait_avoidance=.5, adaptive_avoidance=1.))):
        yield name, replace(base, **changes)


def candidates(base):
    for threshold in THRESHOLDS:
        for delay in DELAYS:
            yield f"t{threshold:g}_l{delay}", replace(base, threshold=threshold, latency=delay)


def aggregate(rows):
    return {name: mean(float(r[field]) for r in rows if r["malicious"] == malicious)
            for name, (field, malicious) in METRICS.items()}


def select(summaries, budget, alert_limit):
    feasible = [r for r in summaries if r["benign_cost"] <= budget + 1e-12
                and r["false_alert"] <= alert_limit + 1e-12]
    if not feasible:
        return None
    # Cost-constrained harm minimization on calibration data only.
    return min(feasible, key=lambda r: (r["harm"], -r["containment"], r["benign_cost"],
                                       r["false_alert"], r["threshold"], r["latency"]))


def source_hashes():
    root = Path(__file__).resolve().parents[2]
    paths = [root / 'src/goblintrap' / n for n in
             ('extended_engine.py', 'budget_study.py', 'study.py', 'engine.py')]
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}


def protocol(calibration_seeds=80, test_seeds=200):
    if type(calibration_seeds) is not int or type(test_seeds) is not int or min(calibration_seeds, test_seeds) < 2:
        raise ValueError("At least two seeds per split required")
    return dict(version=VERSION, calibration_seeds=list(range(calibration_seeds)),
                test_seeds=list(range(100000, 100000 + test_seeds)),
                calibration_families=list(CALIBRATION_SCENARIOS), shift_families=list(SHIFT_SCENARIOS),
                thresholds=list(THRESHOLDS), delays=list(DELAYS), budgets=list(BUDGETS),
                alert_limits=list(ALERT_LIMITS), arms=list(ARMS),
                environments={name: asdict(cfg) for name, cfg in environments()},
                source_sha256=source_hashes(),
                selection="Calibration harm minimum subject to mean benign cost and false-alert ceilings; ties: containment descending, cost, alerts, threshold, delay ascending.",
                scope="Exploratory extension informed by v3; frozen locally before v4 outcomes, not external preregistration. Family shift is designed, not sampled from a population.")


def run(output, calibration_seeds=80, test_seeds=200):
    output = Path(output)
    if output.exists() and any(output.iterdir()):
        raise ValueError("Output directory must be empty")
    plan = protocol(calibration_seeds, test_seeds)
    output.mkdir(parents=True, exist_ok=True)
    plan_text = json.dumps(plan, indent=2) + "\n"
    (output / 'protocol.json').write_bytes(plan_text.encode('utf-8'))
    summaries, choices, total = [], [], 0
    # Finish every calibration and freeze every choice before any evaluation.
    for environment, base in environments():
        rows = []
        for candidate, config in candidates(base):
            for arm in ARMS:
                group = [dict(environment=environment, candidate=candidate, split="calibration",
                              **scalar(trial(s, arm, seed, config, retain_events=False)))
                         for seed in plan['calibration_seeds'] for s in CALIBRATION_SCENARIOS]
                rows.extend(group)
                summaries.append(dict(environment=environment, candidate=candidate, policy=arm,
                                      threshold=config.threshold, latency=config.latency, **aggregate(group)))
        write_csv(output / f'calibration_{environment}.csv', rows)
        total += len(rows)
        for budget in BUDGETS:
            for alert_limit in ALERT_LIMITS:
                for arm in ARMS:
                    chosen = select([r for r in summaries if r['environment']==environment and r['policy']==arm],
                                    budget, alert_limit)
                    choices.append(dict(environment=environment, budget=budget, alert_limit=alert_limit,
                                        policy=arm, candidate=chosen['candidate'] if chosen else None,
                                        calibration=chosen))
        print(f'calibration {environment}: {len(rows)} rows', flush=True)
    write_csv(output / 'calibration_summary.csv', summaries)
    choice_text = json.dumps(choices, indent=2) + '\n'
    (output / 'frozen_choices.json').write_bytes(choice_text.encode('utf-8'))
    choice_hash = hashlib.sha256(choice_text.encode()).hexdigest()
    evaluations, family_rows = [], []
    for environment, base in environments():
        definitions = dict(candidates(base))
        wanted = {(c['policy'], c['candidate']) for c in choices
                  if c['environment']==environment and c['candidate'] is not None}
        # Fixed-threshold silent vs signal comparison is retained separately.
        wanted.update((arm, 't8_l1') for arm in ARMS)
        rows, lookup = [], {}
        for arm, candidate in sorted(wanted):
            for split, families in (('test', CALIBRATION_SCENARIOS), ('family_shift', SHIFT_SCENARIOS)):
                group = [dict(environment=environment, candidate=candidate, split=split,
                              **scalar(trial(s, arm, seed, definitions[candidate], retain_events=False)))
                         for seed in plan['test_seeds'] for s in families]
                rows.extend(group)
                lookup[arm, candidate, split] = aggregate(group)
                for scenario in families:
                    subset = [r for r in group if r['scenario']==scenario]
                    family_rows.append(dict(environment=environment, candidate=candidate, policy=arm,
                        split=split, scenario=scenario,
                        **{field: mean(float(r[field]) for r in subset) for field in
                           ('harmful_actions','contained','benign_cost','false_positive','disrupted_actions','collateral_disrupted_calls')}))
        write_csv(output / f'evaluation_{environment}.csv', rows)
        total += len(rows)
        for choice in (c for c in choices if c['environment']==environment):
            for split in ('test', 'family_shift'):
                feasible = choice['candidate'] is not None
                metrics = lookup[choice['policy'], choice['candidate'], split] if feasible else {k: None for k in METRICS}
                evaluations.append(dict(environment=environment, budget=choice['budget'],
                    alert_limit=choice['alert_limit'], policy=choice['policy'], candidate=choice['candidate'], split=split,
                    calibration_feasible=feasible,
                    heldout_feasible=(metrics['benign_cost'] <= choice['budget'] + 1e-12 and
                                      metrics['false_alert'] <= choice['alert_limit'] + 1e-12) if feasible else False,
                    **metrics))
        print(f'evaluation {environment}: {len(rows)} rows', flush=True)
    write_csv(output / 'budget_results.csv', evaluations)
    write_csv(output / 'by_family.csv', family_rows)
    if hashlib.sha256((output/'frozen_choices.json').read_bytes()).hexdigest() != choice_hash:
        raise ValueError('Choices changed during evaluation')
    metadata = dict(version=VERSION, status='complete', total_trials=total,
                    protocol_sha256=hashlib.sha256(plan_text.encode()).hexdigest(),
                    choices_sha256=choice_hash, source_sha256=plan['source_sha256'])
    (output / 'metadata.json').write_text(json.dumps(metadata, indent=2)+'\n')
    return metadata
