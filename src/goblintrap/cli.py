import argparse
import json
from .study import run


def main():
    parser = argparse.ArgumentParser(description="GoblinTrap offline symbolic containment study")
    parser.add_argument("--output", default="results/v3")
    parser.add_argument("--primary-runs", type=int, default=500)
    parser.add_argument("--sensitivity-runs", type=int, default=100)
    parser.add_argument("--primary-only", action="store_true")
    args = parser.parse_args()
    print(json.dumps(run(args.output, args.primary_runs, args.sensitivity_runs, not args.primary_only), indent=2))


if __name__ == "__main__":
    main()
