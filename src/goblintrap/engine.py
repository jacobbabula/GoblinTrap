"""Offline finite-state experiment. No network, subprocess, or executable intents.

Ground-truth maliciousness is used only to score outcomes, never by the defender.
All randomness is keyed by scenario/seed/step/purpose, independent of defense.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import math


VERSION = "0.3.0"
# canary, decoy service, response, tripwire signal enabled
POLICIES = {
    "observe": (False, False, "none", True),
    "revoke": (False, False, "revoke", True),
    "canary_revoke": (True, False, "revoke", True),
    "decoy_revoke": (False, True, "revoke", True),
    "deception_silent": (True, True, "revoke", False),
    "deception": (True, True, "revoke", True),
    "deception_observe": (True, True, "none", True),
    "isolate": (False, False, "isolate", True),
}
SCENARIOS = ("fast", "switcher", "slow", "avoider", "benign_build", "benign_admin", "benign_drill")
RISK = {"recon": 1., "acquire": 2., "persist": 3., "exfil": 4., "pivot": 4.,
        "switch": 1., "work": 0., "health": 0., "audit": 3., "wait": 0.}
HARM_ACTIONS = {"acquire", "persist", "exfil", "pivot"}


@dataclass(frozen=True)
class Config:
    horizon: int = 24
    threshold: float = 8.
    decay: float = .5
    canary_probability: float = .5
    decoy_probability: float = .35
    latency: int = 1
    telemetry_loss: float = 0.
    persistence_enabled: bool = True

    def __post_init__(self):
        for name in ("canary_probability", "decoy_probability", "telemetry_loss"):
            if not 0 <= getattr(self, name) <= 1:
                raise ValueError(f"{name} must be in [0, 1]")
        if not math.isfinite(self.threshold) or self.threshold <= 0:
            raise ValueError("threshold must be finite and positive")
        if not math.isfinite(self.decay) or self.decay < 0:
            raise ValueError("decay must be finite and nonnegative")
        if type(self.horizon) is not int or self.horizon < 1:
            raise ValueError("horizon must be a positive integer")
        if type(self.latency) is not int or self.latency < 0:
            raise ValueError("latency must be a nonnegative integer")
        if type(self.persistence_enabled) is not bool:
            raise ValueError("persistence_enabled must be boolean")


def draw(scenario: str, seed: int, step: int, purpose: str) -> float:
    key = f"goblintrap-v2|{scenario}|{seed}|{step}|{purpose}"
    return int.from_bytes(hashlib.sha256(key.encode()).digest()[:8], "big") / 2**64


def digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     allow_nan=False).encode()).hexdigest()


def seal_events(events: list[dict]) -> list[dict]:
    previous = "GENESIS"
    sealed = []
    for sequence, event in enumerate(events, 1):
        item = {k: v for k, v in event.items() if k not in ("sequence", "previous_hash", "event_hash")}
        item.update(sequence=sequence, previous_hash=previous)
        item["event_hash"] = digest(item)
        previous = item["event_hash"]
        sealed.append(item)
    return sealed


def _verify_events(events: list[dict], anchor: dict | None = None) -> bool:
    previous = "GENESIS"
    run_id = digest(anchor["run"]) if anchor is not None and "run" in anchor else None
    for sequence, event in enumerate(events, 1):
        body = {k: v for k, v in event.items() if k != "event_hash"}
        if body.get("sequence") != sequence or body.get("previous_hash") != previous:
            return False
        if digest(body) != event.get("event_hash"):
            return False
        if run_id is not None and body.get("run_id") != run_id:
            return False
        previous = event["event_hash"]
    if anchor is not None:
        return len(events) == anchor.get("count") and previous == anchor.get("head")
    return True


def verify_events(events: list[dict], anchor: dict | None = None) -> bool:
    """Malformed records fail closed; optional checkpoint binds run context."""
    try:
        return _verify_events(events, anchor)
    except (TypeError, ValueError, KeyError, AttributeError, OverflowError):
        return False


@dataclass
class World:
    entry_active: bool = True
    revoked: bool = False
    isolated: bool = False
    token: str = "none"
    persistence: bool = False

    def real_route(self) -> bool:
        return not self.isolated and (self.persistence or (self.token == "real" and not self.revoked))

    def contained(self) -> bool:
        # Structural reachability, independent of which action the agent chooses.
        return self.isolated or (not self.entry_active and not self.real_route())

    def intervene(self, response: str):
        if response not in ("revoke", "isolate"):
            raise ValueError("unknown intervention")
        self.entry_active = False
        self.revoked = True
        if response == "isolate":
            self.isolated = True


@dataclass
class Agent:
    scenario: str
    step: int = 0
    token: str = "none"  # What the agent believes; does not reveal honey identity.
    persisted: bool = False
    empty_responses: int = 0
    persistence_failed: bool = False
    last_outcome: str = ""
    channel: int = 0
    exfil_done: bool = False

    def choose(self) -> str:
        self.step += 1
        if self.scenario == "benign_build":
            return ("work", "health", "wait")[self.step % 3]
        if self.scenario == "benign_admin":
            return ("recon", "health", "audit", "work", "wait", "wait")[ (self.step-1) % 6]
        if self.scenario == "benign_drill":
            if self.step == 1:
                return "recon"
            if self.token == "none":
                return "acquire"
            return ("audit", "health", "work", "wait")[(self.step-1) % 4]
        if self.last_outcome == "denied":
            self.channel = (self.channel + 1) % 3
            self.last_outcome = "switched"
            return "switch"
        if self.scenario == "slow" and self.step % 3 != 0:
            return "wait" if self.step % 3 == 1 else "recon"
        if self.step == 1:
            return "recon"
        if self.token == "none":
            return "acquire"
        if self.scenario == "switcher" and not self.persisted and not self.persistence_failed:
            return "persist"
        if not self.exfil_done:
            return "exfil"
        if not self.persisted and not self.persistence_failed:
            return "persist"
        if self.scenario == "switcher" and self.step % 3 == 0:
            self.channel = (self.channel + 1) % 3
            return "switch"
        return "pivot" if self.step % 2 == 0 else "exfil"

    def feedback(self, action: str, observation: str):
        """Policy sees success/empty/denied/local, never a ground-truth decoy label."""
        if observation not in ("success", "empty", "denied", "local"):
            raise ValueError("unknown agent observation")
        self.last_outcome = observation
        if action == "acquire" and observation == "success":
            self.token = "available"
            self.persistence_failed = False
        if observation == "empty":
            self.empty_responses += 1
            if self.empty_responses >= 2:
                # Toy recognition rule: abandon after two empty responses.
                self.token = "none"
                self.empty_responses = 0
        if action == "persist" and observation == "denied":
            self.persistence_failed = True
        if action == "persist" and observation == "success":
            self.persisted = True
        if action == "exfil" and observation == "success":
            self.exfil_done = True


def execute(world: World, action: str, honey_credential: bool, honey_service: bool,
            persistence_enabled: bool) -> tuple[str, bool]:
    """Returns outcome and observed tripwire. No ground-truth class is accepted."""
    if action not in RISK:
        raise ValueError("unknown symbolic action")
    if action in ("wait", "switch"):
        return "local", False
    if world.isolated:
        return "denied", False
    if action == "acquire":
        if not world.entry_active:
            return "denied", False
        world.token = "honey" if honey_credential else "real"
        # Reading a candidate credential does not itself fire the token.
        return "completed", False
    if action in ("recon", "work", "health"):
        return ("completed" if world.entry_active or world.real_route() else "denied"), False
    if world.token == "honey" and not world.persistence:
        return "decoy", True
    if action == "audit" and world.entry_active:
        return ("decoy", True) if honey_service else ("completed", False)
    if not world.real_route():
        return "denied", False
    if honey_service and action in ("exfil", "pivot", "audit"):
        return "decoy", True
    if action == "persist":
        if not persistence_enabled:
            return "denied", False
        world.persistence = True
    return "completed", False


def trial(scenario: str, policy: str, seed: int, config: Config = Config(),
          *, truth_override: bool | None = None, scripted_actions: tuple[str, ...] | None = None,
          retain_events: bool = True) -> dict:
    if scenario not in SCENARIOS or policy not in POLICIES:
        raise ValueError("unknown scenario or policy")
    if type(seed) is not int or seed < 0:
        raise ValueError("seed must be a nonnegative integer")
    if scripted_actions is not None and len(scripted_actions) != config.horizon:
        raise ValueError("script must contain exactly horizon actions")
    has_canary, has_decoy, response, signals = POLICIES[policy]
    run_context = dict(version=VERSION, scenario=scenario, policy=policy, seed=seed, config=asdict(config))
    if scripted_actions is not None:
        run_context["scripted_actions"] = list(scripted_actions)
    run_id = digest(run_context)
    malicious = not scenario.startswith("benign_") if truth_override is None else truth_override
    agent, world = Agent(scenario), World()
    risk, detected, responded, contained = 0., None, None, None
    due = None
    harmful, exfil, post_alert, decoys, alerts, disrupted = 0, 0, 0, 0, 0, 0
    full_events, observed_events = [], []
    for step in range(1, config.horizon + 1):
        action = scripted_actions[step-1] if scripted_actions is not None else agent.choose()
        if action not in RISK:
            raise ValueError("unknown symbolic action")
        # Avoider explicitly rejects all bait; no claim this models a real LLM.
        attraction = 0. if scenario == "avoider" else 1.
        hc = has_canary and draw(scenario, seed, step, "credential") < config.canary_probability * attraction
        hd = has_decoy and draw(scenario, seed, step, "service") < config.decoy_probability * attraction
        outcome, tripwire = execute(world, action, hc, hd, config.persistence_enabled)
        tripwire = tripwire and signals
        harm = (malicious and outcome == "completed" and action in HARM_ACTIONS
                and not (action == "acquire" and world.token == "honey"))
        harmful += int(harm)
        exfil += int(harm and action == "exfil")
        post_alert += int(harm and detected is not None)
        decoys += int(outcome == "decoy")
        disrupted += int(not malicious and outcome in ("denied", "decoy"))
        visible = draw(scenario, seed, step, "telemetry") >= config.telemetry_loss
        risk = max(0., risk - config.decay)
        if visible:
            risk += RISK[action] + (6. if tripwire else 0.)
        alarm = visible and risk >= config.threshold
        alerts += int(alarm)
        if alarm and detected is None:
            detected = step
            if response != "none":
                due = step + config.latency
        # Post-action response: the triggering action always finishes first.
        if due == step and responded is None:
            world.intervene(response)
            responded = step
        if world.contained() and contained is None:
            contained = step
        observation = {"completed": "success", "decoy": "empty", "denied": "denied", "local": "local"}[outcome]
        event = dict(run_id=run_id, step=step, action=action, channel=agent.channel, outcome=outcome,
                     agent_observation=observation,
                     tripwire=tripwire, visible=visible, risk=risk, alarm=alarm,
                     response_applied=responded is not None, contained=world.contained(),
                     persistence=world.persistence)
        full_events.append(event)
        if visible:
            observed_events.append(event)
        agent.feedback(action, observation)
    events = seal_events(observed_events) if retain_events else []
    anchor = {"count": len(events), "head": events[-1]["event_hash"] if events else "GENESIS", "run": run_context}
    return dict(scenario=scenario, policy=policy, seed=seed, malicious=malicious,
                detection_step=detected, response_step=responded, containment_step=contained,
                detection_time_capped=detected if detected is not None else config.horizon+1,
                containment_time_capped=contained if contained is not None else config.horizon+1,
                detected=detected is not None, contained=contained is not None,
                harmful_actions=harmful, exfil_actions=exfil, post_detection_harm=post_alert,
                decoy_actions=decoys, alert_events=alerts, false_positive=(not malicious and detected is not None),
                false_containment=(not malicious and contained is not None),
                disrupted_actions=disrupted, persistence_survived=world.persistence and not world.isolated,
                evidence_completeness=len(observed_events)/config.horizon,
                evidence_integrity=verify_events(events, anchor) if retain_events else None,
                events=events, anchor=anchor, ground_truth=full_events if retain_events else [])
