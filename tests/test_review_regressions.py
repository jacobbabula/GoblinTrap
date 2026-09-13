from copy import deepcopy
import tempfile
from pathlib import Path
import unittest

from goblintrap.engine import Agent, Config, World, execute, trial, verify_events
from goblintrap.study import paired, run


class ReviewRegressions(unittest.TestCase):
    def test_failed_persistence_falls_back_to_useful_action(self):
        agent = Agent("switcher", step=3, token="available")
        agent.feedback("persist", "denied")
        self.assertEqual(agent.choose(), "switch")
        self.assertEqual(agent.choose(), "exfil")

    def test_policy_rejects_ground_truth_decoy_label(self):
        with self.assertRaises(ValueError):
            Agent("fast").feedback("exfil", "decoy")

    def test_silent_control_retains_diversion_without_bonus(self):
        cfg = Config(horizon=4, threshold=999, canary_probability=1, decoy_probability=1)
        loud = trial("fast", "deception", 0, cfg)
        silent = trial("fast", "deception_silent", 0, cfg)
        self.assertEqual([e["outcome"] for e in loud["events"]], [e["outcome"] for e in silent["events"]])
        self.assertGreater(loud["decoy_actions"], 0)
        self.assertFalse(any(e["tripwire"] for e in silent["events"]))
        self.assertGreater(loud["events"][-1]["risk"], silent["events"][-1]["risk"])

    def test_anchor_rejects_misattributed_run(self):
        result = trial("fast", "deception", 0)
        anchor = deepcopy(result["anchor"])
        anchor["run"]["seed"] = 1
        self.assertFalse(verify_events(result["events"], anchor))

    def test_malformed_evidence_fails_closed(self):
        self.assertFalse(verify_events([None]))
        self.assertFalse(verify_events([{"sequence": 1, "previous_hash":"GENESIS", "risk":float("nan")}]))

    def test_unknown_actions_and_responses_rejected(self):
        with self.assertRaises(ValueError):
            execute(World(token="real"), "unknown", False, False, True)
        with self.assertRaises(ValueError):
            World().intervene("none")

    def test_short_script_and_bad_seed_rejected(self):
        with self.assertRaises(ValueError):
            trial("fast", "revoke", 0, scripted_actions=("acquire",))
        with self.assertRaises(ValueError):
            trial("fast", "revoke", -1)
        with self.assertRaises(ValueError):
            Config(persistence_enabled="false")

    def test_paired_rejects_duplicate_and_incomplete_cells(self):
        item=trial("fast","revoke",0)
        for rows in ([], [item], [item,item]):
            with self.assertRaises(ValueError):
                paired(rows)

    def test_existing_output_cannot_mix_experiments(self):
        with tempfile.TemporaryDirectory() as directory:
            sentinel=Path(directory)/"old.csv"
            sentinel.write_text("old data")
            with self.assertRaises(ValueError):
                run(directory,2,2,False)
            self.assertEqual(sentinel.read_text(),"old data")


if __name__ == "__main__":
    unittest.main()
