import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('analyze_budget_results',Path(__file__).parents[1]/'scripts/analyze_budget_results.py')
analysis=importlib.util.module_from_spec(spec)
spec.loader.exec_module(analysis)


class BudgetAnalysisTests(unittest.TestCase):
    def test_constant_paired_effect_has_exact_interval(self):
        r=analysis.interval([2.,2.,2.],'constant')
        self.assertEqual((r['difference'],r['ci_low'],r['ci_high']),(2.,2.,2.))

    def test_pairing_removes_shared_seed_variation(self):
        rows=[]
        for seed in range(3):
            for scenario in ('fast','benign_admin'):
                for arm in ('deception_silent','deception'):
                    rows.append(dict(seed=str(seed),scenario=scenario,policy=arm,candidate='x',split='test',
                                     harmful_actions=str(seed*10+(1 if arm=='deception' else 0)),
                                     contained='False',benign_cost='0'))
        r=analysis.paired(rows,'x','x','test','fixture')
        self.assertEqual(r['harm']['difference'],1)
        self.assertEqual(r['harm']['ci_low'],1)
        self.assertEqual(r['harm']['ci_high'],1)
        with self.assertRaises(ValueError): analysis.paired(rows[:-1],'x','x','test','fixture')
        with self.assertRaises(ValueError): analysis.paired(rows+rows[:1],'x','x','test','fixture')
