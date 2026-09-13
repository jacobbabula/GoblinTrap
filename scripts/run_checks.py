"""Run the test suite and retain a machine-readable result and full log."""
import argparse
import io
import json
from pathlib import Path
import sys
import unittest

parser=argparse.ArgumentParser()
parser.add_argument('--output',default='results/v3')
args=parser.parse_args()
root=Path(__file__).resolve().parents[1]
out=Path(args.output)
out.mkdir(parents=True,exist_ok=True)
suite=unittest.defaultTestLoader.discover(str(root/'tests'))
stream=io.StringIO()
result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
(out/'tests.txt').write_text(stream.getvalue(),encoding='utf-8')
payload=dict(tests_run=result.testsRun,failures=len(result.failures),errors=len(result.errors),
             skipped=len(result.skipped),status='PASS' if result.wasSuccessful() else 'FAIL')
(out/'tests.json').write_text(json.dumps(payload,indent=2)+'\n')
print(stream.getvalue())
print(json.dumps(payload))
sys.exit(0 if result.wasSuccessful() else 1)
