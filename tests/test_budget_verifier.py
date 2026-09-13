from contextlib import redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from goblintrap import budget_study
from goblintrap.extended_engine import Config

spec = importlib.util.spec_from_file_location('verify_budget_results', Path(__file__).parents[1]/'scripts/verify_budget_results.py')
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


class BudgetVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.temp.name)/'fixture'
        with patch.object(budget_study,'environments',lambda:iter([('ideal',Config())])), redirect_stdout(io.StringIO()):
            budget_study.run(cls.directory,2,2)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def check(self):
        with redirect_stdout(io.StringIO()):
            return verifier.verify(self.directory,write=False)

    def edit(self,name,transform):
        path = self.directory/name
        original = path.read_bytes()
        self.addCleanup(path.write_bytes,original)
        path.write_text(transform(original.decode()))

    def test_all_fixture_rows_replay(self):
        result = self.check()
        self.assertEqual(result['status'],'PASS')
        self.assertGreater(result['total_rows_checked'],1000)

    def test_removed_calibration_row_rejected(self):
        self.edit('calibration_ideal.csv',lambda text:'\n'.join(text.splitlines()[:-1])+'\n')
        with self.assertRaisesRegex(ValueError,'Incomplete/duplicate'): self.check()

    def test_changed_trial_rejected(self):
        def change(text):
            lines=text.splitlines()
            columns=lines[0].split(',')
            row=lines[1].split(',')
            row[columns.index('harmful_actions')]='999'
            lines[1]=','.join(row)
            return '\n'.join(lines)+'\n'
        self.edit('evaluation_ideal.csv',change)
        with self.assertRaisesRegex(ValueError,'Replay mismatch'): self.check()

    def test_changed_choice_rejected(self):
        def change(text):
            data=json.loads(text)
            data[0]['candidate']='t3_l0'
            return json.dumps(data)
        self.edit('frozen_choices.json',change)
        with self.assertRaisesRegex(ValueError,'Changed frozen_choices'): self.check()

    def test_hidden_budget_violation_rejected(self):
        def change(text):
            lines=text.splitlines()
            columns=lines[0].split(',')
            row=lines[1].split(',')
            i=columns.index('heldout_feasible')
            row[i]='False' if row[i]=='True' else 'True'
            lines[1]=','.join(row)
            return '\n'.join(lines)+'\n'
        self.edit('budget_results.csv',change)
        with self.assertRaisesRegex(ValueError,'Hidden heldout'): self.check()
