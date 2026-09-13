# GoblinTrap 0.4: cost-constrained extension

Start with `output/v4/GoblinTrap-v4-technical-brief.pdf` or the editable
`output/v4/technical-notes.md`. This is an offline symbolic experiment, not a
real AI-agent evaluation or a production-defense test. Jacob Babula supplied
the project direction and requested revisions. Codex assisted with code,
experiments, validation, analysis and report writing.

The extension calibrates four defenses at common benign-cost and false-alert
ceilings; freezes those choices; and evaluates unused seeds and new scripted
families. Twelve designed worlds vary isolation coverage/reliability, collateral
cost, ambiguous feedback, recognition, and bait avoidance. All 912,840 trial rows
are retained. The original v3 engine is preserved; v4 uses
`goblintrap.extended_engine` and `goblintrap.budget_study` explicitly.

## Results to read carefully

At the illustrative cost ceiling 3 and alert ceiling 67% in the ideal world,
tuned silent bait yields 8.15875 harmful actions versus 8.40875 with alerts;
isolation yields 3.0. Under the combined assumptions, silent bait yields 9.0625
versus isolation's 11.32, with higher benign cost. The tuned alert arm exceeds
its held-out cost ceiling in that combined case. All four selected arms violate
at least one ceiling under the designed family shift in the ideal example.

Common ceilings do not mean equal realized costs. Tuned comparisons include
threshold/delay changes and must not be interpreted as the isolated effect of
the signal. Fixed-setting paired comparisons are reported separately. All
probabilities, workloads and route rules remain assumptions.

## Reproduce

Python 3.11+; no third-party packages are needed for experiments or verification.
From the extracted package root, in PowerShell:

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
python scripts/run_budget_study.py --output results/reproduction-v4
python -O scripts/verify_budget_results.py results/reproduction-v4
python scripts/analyze_budget_results.py --data results/reproduction-v4 --output output/reproduction-v4
```

Use a fresh run directory: nonempty directories are rejected. On POSIX use
`export PYTHONPATH=src`. To verify the retained run directly:

```powershell
python -O scripts/verify_budget_results.py results/v4
```

To regenerate the retained report from its retained, verified data:

```powershell
python scripts/run_checks.py --output results/v4
python scripts/analyze_budget_results.py
python scripts/build_budget_brief.py
python scripts/package_budget_artifact.py
```

The optional PDF builder needs ReportLab and pypdf. Rebuilding uses local data;
no network or model calls occur. The report builder targets `results/v4` and
`output/v4`. A small smoke study can use `--calibration-seeds 2 --test-seeds 2`;
its results are not substitutes for the retained run.

## Files and evidence

- `docs/V4_EXPERIMENT_SPEC.md`: design, costs, policies, splits and limitations.
- `results/v4/protocol.json`: complete machine-readable design and source hashes.
- `results/v4/frozen_choices.json`: all selected settings and infeasible cells.
- `results/v4/calibration_*.csv`: all training trials and candidate summaries.
- `results/v4/evaluation_*.csv`: evaluated unique candidates, original/new families.
- `results/v4/budget_results.csv`: costs, harm, containment and feasibility flags.
- `results/v4/by_family.csv`: separate scripted-family outcomes.
- `results/v4/verification.json`: full replay and independently coded aggregate/selection checks.
- `results/v4/tests.json` and `tests.txt`: 54 passing tests, including tamper rejection.
- `output/v4/fixed-signal-effects.csv`: same-setting signal differences and intervals.
- `output/v4/budget-signal-effects.csv`: tuned-policy differences and intervals.
- `output/v4/analysis.json`, `report-data.json`: numerical report context.
- `MANIFEST.json`: file hashes; consistency is not authenticity.

The first v4 computation failed a Windows newline hash check. Serialization was
fixed and the same design was rerun cleanly. That incomplete local run and the
original v3 package are excluded from this standalone v4 distribution. Legacy
source and the legacy verifier are included because regression tests use them.

The same assistant performed implementation, experiments, analysis and checks.
Full replay uses the same engine and is not independent researcher validation.
Bootstrap intervals condition on selected settings and fixed families; they omit
calibration-selection uncertainty and uncertainty about the simulated world.
No external preregistration, independent researcher review or acceptance is claimed.
