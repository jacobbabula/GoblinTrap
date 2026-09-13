import contextlib
import csv
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from goblintrap.study import run

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('goblintrap_result_verifier',ROOT/'scripts/verify_results.py')
verifier=importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


class VerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture=tempfile.TemporaryDirectory()
        with contextlib.redirect_stdout(io.StringIO()):
            run(cls.fixture.name,2,2,False)

    @classmethod
    def tearDownClass(cls):
        cls.fixture.cleanup()

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)/'study'
        shutil.copytree(self.fixture.name,self.root)
        self.addCleanup(self.temp.cleanup)

    def verify(self):
        with contextlib.redirect_stdout(io.StringIO()):
            return verifier.verify(self.root)

    def edit_csv(self,name,change):
        file=self.root/name
        with file.open(newline='') as f:
            rows=list(csv.DictReader(f))
        change(rows)
        with file.open('w',newline='') as f:
            writer=csv.DictWriter(f,fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)

    def test_clean_fixture_replays_every_row(self):
        result=self.verify()
        self.assertEqual(result['exact_trial_replays'],112)
        self.assertTrue(result['full_replay'])

    def test_nonzero_seed_unaggregated_field_tamper_detected(self):
        def change(rows):
            row=next(r for r in rows if r['seed']=='1')
            row['alert_events']=str(int(row['alert_events'])+1)
        self.edit_csv('trials_primary.csv',change)
        with self.assertRaisesRegex(ValueError,'replay mismatch'):
            self.verify()

    def test_interval_endpoint_tamper_detected(self):
        self.edit_csv('paired.csv',lambda rows:rows[0].update(ci_high='999'))
        with self.assertRaisesRegex(ValueError,'statistic mismatch'):
            self.verify()

    def test_optimized_python_still_rejects_bad_summary(self):
        self.edit_csv('summary.csv',lambda rows:rows[0].update(evidence_completeness='0.123'))
        result=subprocess.run([sys.executable,'-O',str(ROOT/'scripts/verify_results.py'),str(self.root)],
                              capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('statistic mismatch',result.stderr)

    def test_missing_expected_timeline_detected(self):
        (self.root/'timeline_fast_revoke.jsonl').unlink()
        with self.assertRaisesRegex(ValueError,'timeline set mismatch'):
            self.verify()
