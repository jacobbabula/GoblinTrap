"""Reproducible study runner and paired, seed-cluster uncertainty summaries."""
from collections import defaultdict
import csv
import hashlib
from dataclasses import asdict, replace
import json
from pathlib import Path
import platform
import random
from statistics import mean, quantiles

from .engine import Config, POLICIES, SCENARIOS, VERSION, trial


def write_csv(path, rows):
    rows = list(rows)
    if not rows:
        raise ValueError("cannot write empty dataset")
    with Path(path).open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def scalar(result):
    return {k: v for k, v in result.items() if k not in ("events", "anchor", "ground_truth", "evidence_integrity")}


def summarize(rows):
    groups = defaultdict(list)
    for row in rows:
        groups[row["policy"]].append(row)
    output = []
    for policy, group in groups.items():
        attack = [r for r in group if r["malicious"]]
        benign = [r for r in group if not r["malicious"]]
        output.append(dict(policy=policy, malicious_trials=len(attack), benign_trials=len(benign),
            harmful_actions=mean(r["harmful_actions"] for r in attack),
            exfil_actions=mean(r["exfil_actions"] for r in attack),
            detection_rate=mean(r["detected"] for r in attack),
            containment_rate=mean(r["contained"] for r in attack),
            detection_time_capped=mean(r["detection_time_capped"] for r in attack),
            containment_time_capped=mean(r["containment_time_capped"] for r in attack),
            post_detection_harm=mean(r["post_detection_harm"] for r in attack),
            decoy_actions=mean(r["decoy_actions"] for r in attack),
            false_positive_rate=mean(r["false_positive"] for r in benign),
            false_containment_rate=mean(r["false_containment"] for r in benign),
            benign_disrupted_actions=mean(r["disrupted_actions"] for r in benign),
            evidence_completeness=mean(r["evidence_completeness"] for r in group)))
    return output


def paired(rows, bootstrap=2000, baseline="revoke"):
    if type(bootstrap) is not int or bootstrap < 2:
        raise ValueError("at least two bootstrap resamples required")
    if baseline not in POLICIES:
        raise ValueError("unknown baseline")
    lookup = {(r["scenario"], r["seed"], r["policy"]): r for r in rows}
    seeds = sorted({r["seed"] for r in rows})
    expected = {(s,seed,p) for s in SCENARIOS for seed in seeds for p in POLICIES}
    if len(seeds) < 2 or len(lookup) != len(rows) or set(lookup) != expected:
        raise ValueError("paired input must have unique, complete scenario/seed/arm cells and >=2 seeds")
    output = []
    for policy in POLICIES:
        if policy == baseline:
            continue
        for metric, malicious in (("harmful_actions", True), ("containment_time_capped", True),
                                  ("false_positive", False), ("disrupted_actions", False)):
            scenarios = [s for s in SCENARIOS if (not s.startswith("benign_")) == malicious]
            differences = [mean(lookup[s, seed, policy][metric]-lookup[s, seed, baseline][metric]
                                for s in scenarios) for seed in seeds]
            rng = random.Random(f"CI|{baseline}|{policy}|{metric}")
            samples = sorted(mean(rng.choices(differences, k=len(seeds))) for _ in range(bootstrap))
            cuts = quantiles(samples, n=40, method="inclusive")
            output.append(dict(policy=policy, baseline=baseline, metric=metric,
                               difference=mean(differences), ci_low=cuts[0],
                               ci_high=cuts[-1], seeds=len(seeds)))
    return output


def configs():
    base = Config()
    yield "primary", base
    for threshold in (5., 8., 12.):
        for probability in (0., .5, 1.):
            for latency in (0, 1, 3):
                value = replace(base, threshold=threshold, canary_probability=probability, latency=latency)
                if value != base:
                    yield f"grid_t{threshold:g}_p{probability:g}_l{latency}", value
    for field, values in (("decoy_probability", (0., .7, 1.)),
                          ("telemetry_loss", (.1, .4, 1.)),
                          ("decay", (0., 1.5)), ("horizon", (12, 48)),
                          ("persistence_enabled", (False,))):
        for value in values:
            yield f"stress_{field}_{value}", replace(base, **{field: value})
    yield "no_bait", replace(base, canary_probability=0., decoy_probability=0.)


def run(output, primary_runs=500, sensitivity_runs=100, full=True):
    if any(type(v) is not int or v < 2 for v in (primary_runs,sensitivity_runs)):
        raise ValueError("at least two seeds required")
    output = Path(output)
    if output.exists() and any(output.iterdir()):
        raise ValueError("output directory must be empty; use a fresh directory to avoid mixing runs")
    output.mkdir(parents=True, exist_ok=True)
    all_summaries, definitions = [], []
    total = 0
    for name, config in configs():
        if not full and name != "primary":
            continue
        count = primary_runs if name == "primary" else sensitivity_runs
        definitions.append(dict(config_id=name, seeds=count, **asdict(config)))
        rows = []
        for seed in range(count):
            for scenario in SCENARIOS:
                for policy in POLICIES:
                    rows.append(dict(config_id=name, **scalar(trial(scenario, policy, seed, config, retain_events=False))))
        total += len(rows)
        write_csv(output / f"trials_{name}.csv", rows)
        summary = [dict(config_id=name, **r) for r in summarize(rows)]
        all_summaries.extend(summary)
        if name == "primary":
            write_csv(output / "paired.csv", paired(rows))
            write_csv(output / "signal_paired.csv", [r for r in paired(rows, baseline="deception_silent")
                                                     if r["policy"] == "deception"])
            per_scenario = []
            for scenario in SCENARIOS:
                for policy in POLICIES:
                    subset = [r for r in rows if r["scenario"] == scenario and r["policy"] == policy]
                    per_scenario.append(dict(scenario=scenario, policy=policy, seeds=count,
                        **{metric: mean(r[metric] for r in subset) for metric in (
                            "harmful_actions", "contained", "detected", "false_positive", "disrupted_actions",
                            "containment_time_capped", "decoy_actions", "alert_events")}))
            write_csv(output / "by_scenario.csv", per_scenario)
        print(f"{name}: {len(rows)} trials", flush=True)
    write_csv(output / "summary.csv", all_summaries)
    (output / "configurations.json").write_text(json.dumps(definitions, indent=2)+"\n", encoding="utf-8")
    for scenario in ("fast", "switcher", "benign_drill"):
        for policy in ("revoke", "deception", "isolate"):
            result = trial(scenario, policy, 0)
            path = output / f"timeline_{scenario}_{policy}.jsonl"
            path.write_text("".join(json.dumps(e, sort_keys=True)+"\n" for e in result["events"]), encoding="utf-8")
            (output / f"anchor_{scenario}_{policy}.json").write_text(json.dumps(result["anchor"], indent=2)+"\n", encoding="utf-8")
    source_root = Path(__file__).resolve().parent
    source_hashes = {f"src/goblintrap/{p.name}": hashlib.sha256(p.read_bytes()).hexdigest()
                     for p in sorted(source_root.glob("*.py"))}
    metadata = dict(version=VERSION, status="complete", source_sha256=source_hashes,
        python=platform.python_version(), total_trials=total,
        configurations=len(definitions), primary_runs=primary_runs, sensitivity_runs=sensitivity_runs,
        uncertainty="95% percentile bootstrap over paired seed clusters, 2000 resamples; linear inclusive quantiles; conditional Monte Carlo uncertainty only.",
        weighting="Equal weights over four malicious or three benign scenario families; not deployment prevalence.",
        censoring="Undetected/uncontained assigned horizon+1; capped-time metric is not a conditional mean over successes.",
        integrity="Hash checks use retained example traces. Completeness uses observed actions / simulated actions. Hash anchors are not independently trusted in this package.")
    (output / "metadata.json").write_text(json.dumps(metadata, indent=2)+"\n", encoding="utf-8")
    return metadata
