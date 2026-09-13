import csv
from dataclasses import asdict
import tempfile
from pathlib import Path
import unittest

from goblintrap.engine import Config, POLICIES, SCENARIOS, World, execute, trial
from goblintrap.study import configs, paired, scalar, summarize, write_csv


class StudyTests(unittest.TestCase):
    def test_structural_reachability_exhaustive(self):
        from itertools import product
        for entry, revoked, isolated, token, persistence in product(
            (False, True), (False, True), (False, True), ("none", "real", "honey"), (False, True)):
            w = World(entry, revoked, isolated, token, persistence)
            outcomes = [execute(World(**asdict(w)), a, False, False, True)[0]
                        for a in ("acquire", "persist", "exfil", "pivot")]
            self.assertEqual(w.contained(), "completed" not in outcomes)

    def test_honey_acquisition_not_scored_as_real_harm(self):
        r = trial("fast", "canary_revoke", 0, Config(horizon=2, canary_probability=1),
                  scripted_actions=("acquire", "persist"))
        self.assertEqual(r["harmful_actions"], 0)

    def test_misses_use_horizon_plus_one(self):
        r = trial("fast", "observe", 0, Config(horizon=7, threshold=999))
        self.assertIsNone(r["detection_step"])
        self.assertEqual(r["detection_time_capped"], 8)
        self.assertEqual(r["containment_time_capped"], 8)

    def test_matrix_complete_and_unique(self):
        matrix = list(configs())
        self.assertEqual(len(matrix), 39)
        self.assertEqual(len({tuple(asdict(c).values()) for _, c in matrix}), 39)

    def test_pairing_and_aggregate_zero_effect_control(self):
        cfg = Config(canary_probability=0, decoy_probability=0)
        rows = [scalar(trial(s, p, seed, cfg)) for seed in range(4) for s in SCENARIOS for p in POLICIES]
        summary = {r["policy"]: r for r in summarize(rows)}
        self.assertEqual(summary["revoke"]["harmful_actions"], summary["deception"]["harmful_actions"])
        for result in paired(rows, bootstrap=100):
            if result["policy"] in ("canary_revoke", "decoy_revoke", "deception"):
                self.assertEqual((result["difference"],result["ci_low"],result["ci_high"]), (0,0,0))

    def test_csv_roundtrip_retains_all_rows_and_missing_times(self):
        rows = [scalar(trial("fast", p, 0)) for p in POLICIES]
        with tempfile.TemporaryDirectory() as d:
            file = Path(d)/"trials.csv"
            write_csv(file, rows)
            with file.open(encoding="utf-8") as handle:
                actual = list(csv.DictReader(handle))
            self.assertEqual(len(actual), len(POLICIES))
            self.assertEqual(actual[0]["containment_step"], "")


if __name__ == "__main__":
    unittest.main()
