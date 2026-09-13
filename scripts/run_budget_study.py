import argparse
import json
from goblintrap.budget_study import run

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', default='results/v4')
    parser.add_argument('--calibration-seeds', type=int, default=80)
    parser.add_argument('--test-seeds', type=int, default=200)
    args = parser.parse_args()
    print(json.dumps(run(args.output, args.calibration_seeds, args.test_seeds), indent=2))
