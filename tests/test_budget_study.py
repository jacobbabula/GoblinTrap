from dataclasses import replace
import tempfile
from pathlib import Path
import unittest

from goblintrap import engine as legacy
from goblintrap.extended_engine import Agent, Config, trial, CALIBRATION_SCENARIOS
from goblintrap.budget_study import protocol, select, run


class ExtendedStudyTests(unittest.TestCase):
    def test_default_extension_reproduces_legacy_outcomes(self):
        for scenario in CALIBRATION_SCENARIOS:
            for arm in legacy.POLICIES:
                for seed in range(4):
                    old = legacy.trial(scenario, arm, seed, retain_events=False)
                    new = trial(scenario, arm, seed, retain_events=False)
                    for field in old:
                        if field not in ('events', 'anchor', 'ground_truth'):
                            self.assertEqual(old[field], new[field], (scenario, arm, seed, field))

    def test_zero_isolation_coverage_and_reliability_leave_persistence(self):
        actions = ('acquire','persist','exfil','pivot','exfil')
        for changes in ({'isolation_coverage':0}, {'isolation_reliability':0}):
            result = trial('fast','isolate',0,Config(horizon=5,threshold=7,latency=0,**changes),scripted_actions=actions)
            self.assertIsNone(result['containment_step'])
            self.assertTrue(result['persistence_survived'])

    def test_collateral_counts_remaining_steps_even_on_failed_isolation(self):
        cfg = Config(horizon=5,threshold=1,latency=0,collateral_calls_per_step=.25,isolation_reliability=0)
        r = trial('benign_drill','isolate',0,cfg)
        self.assertEqual(r['response_step'],1)
        self.assertEqual(r['collateral_disrupted_calls'],1)
        self.assertEqual(r['benign_cost'],r['disrupted_actions']+1)
        r = trial('benign_drill','isolate',0,replace(cfg,latency=4))
        self.assertEqual(r['collateral_disrupted_calls'],0)

    def test_real_empty_output_preserves_actual_harm(self):
        r = trial('fast','observe',0,Config(horizon=3,background_empty_probability=1),
                  scripted_actions=('acquire','exfil','pivot'))
        self.assertEqual(r['harmful_actions'],3)
        self.assertEqual(r['events'][1]['outcome'],'completed')
        self.assertEqual(r['events'][1]['agent_observation'],'empty')
        self.assertFalse(r['events'][1]['tripwire'])

    def test_imperfect_recognition_and_patience(self):
        a = Agent('fast',token='available',recognition_patience=3)
        for _ in range(5):
            a.feedback('exfil','empty',recognizes_empty=False)
        self.assertEqual(a.empty_responses,0)
        for _ in range(2):
            a.feedback('exfil','empty')
        self.assertEqual(a.token,'available')
        a.feedback('exfil','empty')
        self.assertEqual(a.token,'none')
        self.assertTrue(a.bait_suspected)

    def test_total_avoidance_removes_deception_benefit(self):
        for scenario in CALIBRATION_SCENARIOS:
            a = trial(scenario,'revoke',9,Config(bait_avoidance=1))
            b = trial(scenario,'deception',9,Config(bait_avoidance=1))
            for field in ('harmful_actions','contained','disrupted_actions','false_positive'):
                self.assertEqual(a[field],b[field])

    def test_adaptive_avoidance_changes_bait_after_suspicion(self):
        cfg = Config(canary_probability=1,decoy_probability=1,threshold=1000,recognition_patience=1,adaptive_avoidance=1)
        r = trial('fast','deception',0,cfg)
        self.assertGreater(r['harmful_actions'],0)
        self.assertGreater(r['decoy_actions'],0)

    def test_truth_override_does_not_change_extended_behavior(self):
        cfg = Config(isolation_coverage=.5,background_empty_probability=.5,recognition_probability=.5)
        for arm in ('isolate','deception'):
            a = trial('fast',arm,4,cfg,truth_override=True)
            b = trial('fast',arm,4,cfg,truth_override=False)
            self.assertEqual(a['events'],b['events'])

    def test_selection_respects_both_constraints_and_infeasibility(self):
        def row(harm,cost,alert,candidate):
            return dict(harm=harm,benign_cost=cost,false_alert=alert,candidate=candidate,
                        containment=.5,threshold=5,latency=0)
        rows = [row(0,4,.1,'costly'),row(1,1,.8,'noisy'),row(3,1,.2,'valid')]
        self.assertEqual(select(rows,2,.34)['candidate'],'valid')
        self.assertIsNone(select(rows,0,.34))

    def test_split_and_family_disjointness(self):
        p = protocol()
        self.assertFalse(set(p['calibration_seeds']) & set(p['test_seeds']))
        self.assertFalse(set(p['calibration_families']) & set(p['shift_families']))

    def test_invalid_extension_parameters(self):
        for changes in ({'isolation_coverage':-1},{'isolation_reliability':2},
                        {'recognition_probability':float('nan')},{'recognition_patience':0},
                        {'collateral_calls_per_step':float('inf')},{'adaptive_avoidance':2}):
            with self.assertRaises(ValueError): Config(**changes)

    def test_refuses_mixed_output(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d)/'sentinel').write_text('preserve')
            with self.assertRaises(ValueError): run(d,2,2)
