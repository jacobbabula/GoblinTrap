# GoblinTrap v4: cost-constrained extension

This protocol was written before running the v4 matrix. The questions and design
were informed by v3 results and the user's review. This is a locally recorded
exploratory protocol, not external preregistration or independent validation.

## Question and estimand

Does the extra tripwire signal help after each defense can tune its threshold
and response delay under the same benign-cost and false-alert ceilings? Does the
answer change under imperfect isolation, collateral outages, ambiguous feedback,
and bait avoidance? All performance claims concern the stipulated symbolic world.

## Calibration and evaluation

Four arms: revocation, silent bait plus revocation, bait plus alerts plus
revocation, isolation. Each searches the full threshold grid {3,5,8,12,20,1000}
and delay grid {0,1,3}. Threshold 1000 disables response within this horizon;
it does not disable diversion. A bait arm can consequently be infeasible even
when no response occurs. No alternative arm is silently substituted.

Calibration uses seeds 0-79 and the original four malicious / three benign
families. For each world, arm, cost budget {0,1,3,6,12}, and alert ceiling
{0.34,0.67}, select the minimum calibration mean harm subject to both constraints.
Ties prefer higher containment, lower benign cost, lower false-alert rate, lower
threshold, then shorter delay. Selection may use calibration malicious outcomes.
All choices across all worlds are saved before any evaluation.

Evaluation uses seeds 100000-100199, with equal family weights within each class.
Report original-family evaluation and a separate family-shift test containing
patient and cycler malicious policies and burst-audit and recovery benign
policies. The new families are hand-designed, not independent real workloads.
Patient makes productive moves every fourth step. Cycler prioritizes persistence
and switches labels every second step after initial exfiltration. Burst auditing
performs two audits in each six-step cycle; recovery repeats acquisition,
health, audit, work, health, wait. No evaluation outcomes retune the choices.

Budget matching means common upper bounds, not equal realized costs. Report
calibration infeasibility and held-out violations explicitly. No claim of
population-level cost control follows from satisfying a sample-average constraint.
For each selected policy report harm, containment, benign cost, direct disruption,
false alerts, and collateral loss separately. Always retain the fixed t8_l1
comparison to distinguish signal effects at shared settings from tuning effects.

## Revised world

The v3 engine remains unchanged. The extension is a separate frozen copy, with
default-outcome regression tests against v3. Horizon 24, base scores, decay,
action ordering, token probabilities and complete telemetry are unchanged.

Isolation always attempts baseline revocation. Independent per-episode coverage
and reliability draws determine whether it additionally blocks the persistent
route. If either fails, only revocation applies. This is one persistent route,
not a realistic network graph. Coverage and reliability have the same effective
product here and are not separately identifiable performance mechanisms.

Every isolation attempt incurs an optional additional collateral workload cost:
rate * (horizon - response_step). This represents expected lost calls in a
separate workload, begins after the response action, and is charged even when
route isolation fails. Direct disrupted calls and collateral calls are disjoint
by definition; their sum is the benign cost for benign episodes. Collateral
cost during malicious episodes is also reported, but is not folded into the
benign-only calibration constraint. Joint utility would need attack prevalence
and severity weights, which are not assumed. Fractional costs are expected-call
units, not observed integral call counts. No outage duration beyond the horizon
is counted; no repair/recovery process is modeled.

Background empty output changes feedback after successful exfil/pivot/audit
actions without undoing completed work or harm and without adding a tripwire.
Recognition probability controls whether an empty observation increments the
suspicion counter; patience is the required cumulative count. On reaching it,
the agent retries acquisition and marks bait suspected. Adaptive avoidance then
reduces future bait attraction. Static avoidance reduces attraction throughout;
the legacy avoider still rejects all bait. These rules also affect benign agents
where applicable. Probabilities are assumptions, not empirical estimates.

## Twelve environments, all retained

1. Ideal: v3 defaults.
2. Persistent-route isolation coverage 0.5.
3. Isolation reliability 0.5.
4. Collateral lost calls per remaining action 0.25.
5. Collateral lost calls per remaining action 1.0.
6. Background empty probability 0.15.
7. Empty recognition probability 0.5.
8. Recognition patience four empties.
9. Static bait avoidance 0.5.
10. Static bait avoidance 1.0.
11. Adaptive bait avoidance 1.0 after suspicion.
12. Combined: coverage 0.5, reliability 0.5, collateral rate 0.25,
    background empty probability 0.15, recognition probability 0.5,
    static avoidance 0.5, adaptive avoidance 1.0.

This is a one-factor stress design plus one combined case, not a factorial
identification of interactions. It does not estimate how often a world occurs.

## Verification and reporting

Save every calibration trial, every evaluated unique policy/candidate/family/seed,
all candidate summaries, frozen selections, evaluation summaries and by-family
outcomes. Save protocol, selection and source hashes. The verifier must recompute
every saved aggregate and selection, check complete unique cells and disjoint
splits, and replay every trial with the same engine. This checks reproducibility,
not the realism of the model or independence of the review. Uncertainty intervals
are paired seed-cluster bootstraps, conditional on fixed calibrated choices and
designed families. They do not include calibration selection uncertainty or
world uncertainty. No empirical real-agent or production defense claim is made.
