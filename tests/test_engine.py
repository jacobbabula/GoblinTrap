import ast
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import unittest

from goblintrap.engine import (Agent, Config, POLICIES, SCENARIOS, World, execute,
                               seal_events, trial, verify_events)


class EngineTests(unittest.TestCase):
    def scripted(self, actions, policy="revoke", **kwargs):
        return trial("fast", policy, 0, Config(horizon=len(actions), **kwargs), scripted_actions=actions)

    def test_truth_label_never_changes_defense_or_agent(self):
        for scenario in SCENARIOS:
            for policy in POLICIES:
                a = trial(scenario, policy, 3, truth_override=True)
                b = trial(scenario, policy, 3, truth_override=False)
                self.assertEqual(a["events"], b["events"])
                self.assertEqual(a["containment_step"], b["containment_step"])

    def test_no_bait_equivalence(self):
        cfg = Config(canary_probability=0, decoy_probability=0)
        for scenario in SCENARIOS:
            baseline = trial(scenario, "revoke", 2, cfg)
            for policy in ("deception", "canary_revoke", "decoy_revoke", "deception_silent"):
                actual = trial(scenario, policy, 2, cfg)
                behavior = lambda events: [{k:v for k,v in e.items() if k not in
                    ("run_id","event_hash","previous_hash")} for e in events]
                self.assertEqual(behavior(baseline["events"]), behavior(actual["events"]))

    def test_triggering_action_is_not_retroactively_blocked(self):
        r = self.scripted(("acquire", "exfil", "pivot"), threshold=5, latency=0)
        self.assertEqual(r["detection_step"], 2)
        self.assertEqual(r["response_step"], 2)
        self.assertEqual([e["outcome"] for e in r["events"]], ["completed", "completed", "denied"])
        self.assertEqual(r["harmful_actions"], 2)

    def test_latency_is_exact_number_of_extra_actions(self):
        r = self.scripted(("acquire", "exfil", "pivot", "exfil", "pivot"), threshold=5, latency=2)
        self.assertEqual(r["response_step"], 4)
        self.assertEqual(r["harmful_actions"], 4)
        self.assertEqual(r["post_detection_harm"], 2)

    def test_persistence_survives_revocation_but_not_isolation(self):
        actions = ("acquire", "persist", "exfil", "pivot", "exfil")
        revoke = self.scripted(actions, threshold=7, latency=0)
        isolate = self.scripted(actions, "isolate", threshold=7, latency=0)
        self.assertIsNone(revoke["containment_step"])
        self.assertTrue(revoke["persistence_survived"])
        self.assertEqual(isolate["containment_step"], 3)
        self.assertEqual(isolate["events"][-1]["outcome"], "denied")

    def test_benign_false_positive_has_real_disruption(self):
        r = trial("benign_drill", "deception", 0, Config(canary_probability=1, latency=0))
        self.assertTrue(r["false_positive"])
        self.assertTrue(r["false_containment"])
        self.assertGreater(r["disrupted_actions"], 0)

    def test_canary_credential_cannot_create_real_persistence(self):
        w = World()
        execute(w, "acquire", True, False, True)
        outcome, alarm = execute(w, "persist", False, False, True)
        self.assertEqual(outcome, "decoy")
        self.assertTrue(alarm)
        self.assertFalse(w.persistence)

    def test_agent_reacts_to_feedback(self):
        a = Agent("fast", step=2, token="available")
        a.feedback("exfil", "denied")
        self.assertEqual(a.choose(), "switch")
        a.feedback("exfil", "empty")
        a.feedback("exfil", "empty")
        self.assertEqual(a.choose(), "acquire")

    def test_deception_without_response_is_not_containment(self):
        r = trial("fast", "deception_observe", 0, Config(canary_probability=1, decoy_probability=1))
        self.assertGreater(r["decoy_actions"], 0)
        self.assertIsNone(r["containment_step"])

    def test_complete_telemetry_loss_causes_no_detection(self):
        r = trial("fast", "deception", 0, Config(telemetry_loss=1))
        self.assertFalse(r["detected"])
        self.assertEqual(r["evidence_completeness"], 0)
        self.assertTrue(r["evidence_integrity"])

    def test_hash_mutation_reordering_deletion_and_anchored_truncation(self):
        r = trial("fast", "deception", 0)
        events, anchor = r["events"], r["anchor"]
        self.assertTrue(verify_events(events, anchor))
        changed = deepcopy(events)
        changed[0]["outcome"] = "tampered"
        self.assertFalse(verify_events(changed, anchor))
        self.assertFalse(verify_events(events[1:], anchor))
        self.assertFalse(verify_events(list(reversed(events)), anchor))
        self.assertTrue(verify_events(events[:-1]))  # Local chain alone misses tail loss.
        self.assertFalse(verify_events(events[:-1], anchor))
        self.assertFalse(verify_events([], anchor))
        changed = seal_events([{k:v for k,v in e.items() if k not in ("sequence", "previous_hash", "event_hash")}
                               for e in changed])
        self.assertTrue(verify_events(changed))  # Rehashable by a writer.
        self.assertFalse(verify_events(changed, anchor))

    def test_structural_containment_blocks_every_harmful_route(self):
        for persistence in (False, True):
            w = World(token="real", persistence=persistence)
            w.intervene("revoke")
            self.assertEqual(w.contained(), not persistence)
            w.intervene("isolate")
            self.assertTrue(w.contained())
            for action in ("acquire", "persist", "exfil", "pivot"):
                self.assertEqual(execute(w, action, False, False, True)[0], "denied")

    def test_parameters_rejected(self):
        for kwargs in ({"threshold": float("nan")}, {"decay": -1}, {"horizon": 0},
                       {"latency": -1}, {"telemetry_loss": 2}, {"canary_probability": -.1}):
            with self.assertRaises(ValueError):
                Config(**kwargs)

    def test_deterministic_replay(self):
        self.assertEqual(trial("switcher", "deception", 123), trial("switcher", "deception", 123))

    def test_engine_has_no_external_execution_imports(self):
        path = Path(__file__).parents[1]/"src/goblintrap/engine.py"
        tree = ast.parse(path.read_text())
        forbidden = {"socket", "subprocess", "requests", "urllib", "http", "os"}
        imports = {n.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import) for n in node.names}
        imports |= {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
        self.assertFalse(imports & forbidden)


if __name__ == "__main__":
    unittest.main()
