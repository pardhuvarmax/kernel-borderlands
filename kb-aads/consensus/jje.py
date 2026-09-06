import os

import ray
import asyncio
from agents.base_agent import BaseAgent, AgentRole

# confidence is a 0.0-1.0 float everywhere else in the system (see
# kb-control-plane's SubmitAgentDecision and kb.proto) — this threshold used
# to be 75.0, which no realistic confidence value can ever exceed, making
# the CONTAIN vote dead code (BUG-003).
CONTAIN_VOTE_THRESHOLD = 0.75

# Pulled out as a plain function (not a JuryAgent method) so the voting
# decision is unit-testable without spinning up a Ray actor. This is the
# FALLBACK path — used when either no trained checkpoint exists yet, or
# the caller only supplied a bare confidence score (no full obs vector) —
# see JuryAgent.evaluate_and_vote below for the RL path, per
# marl/README.md's "RL scope" (Jury: bounded binary decision, trained).
def decide_vote(score: float) -> str:
    return "CONTAIN" if score > CONTAIN_VOTE_THRESHOLD else "ALLOW"

# Populated by kb-aads/marl/train_jury.py — mirrors
# agents/containment.py's CHECKPOINT_DIR/_load_policy pattern exactly.
JURY_CHECKPOINT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "marl", "checkpoints", "jury_ppo",
)
_RL_MODULE_SUBPATH = os.path.join("learner_group", "learner", "rl_module", "default_policy")


def _load_jury_policy(checkpoint_dir: str = JURY_CHECKPOINT_DIR):
    """
    Loads the trained Jury RL policy for inference only — same shape as
    agents/containment.py's _load_policy. Returns None if no checkpoint
    exists (e.g. train_jury.py hasn't been run against this checkout),
    so callers fall back to decide_vote's fixed threshold rather than
    guessing.
    """
    rl_module_path = os.path.join(checkpoint_dir, _RL_MODULE_SUBPATH)
    if not os.path.isdir(rl_module_path):
        return None
    from ray.rllib.core.rl_module.rl_module import RLModule
    return RLModule.from_checkpoint(rl_module_path)

# Pulled out for the same reason: unit-testable without Ray. votes is a list
# of {"vote": ..., "weight": ...} dicts (already excluding any juror whose
# evaluate_and_vote call failed — see coordinate_consensus below, BUG-007).
# Returns False on an empty vote list rather than raising ZeroDivisionError.
def quorum_reached(votes: list) -> bool:
    if not votes:
        return False
    contain_votes = sum(v["weight"] for v in votes if v["vote"] == "CONTAIN")
    total_votes = sum(v["weight"] for v in votes)
    return contain_votes / total_votes > 0.5

@ray.remote
class JuryAgent(BaseAgent):
    """
    Dynamic actor spawned to verify threats and cast votes.

    Voting logic is a trained RLlib PPO policy (kb-aads/marl/train_jury.py,
    reusing Containment's own labeled dataset — see marl/env.py's JuryEnv
    docstring) when BOTH a checkpoint exists AND alert_payload carries a
    full observation vector (score/zone/uid_is_root/score_delta/
    event_type, the same shape ContainmentAgent.decide expects) — falls
    back to decide_vote's fixed confidence threshold otherwise, so a
    caller that only ever sends {"confidence": ...} (as every existing
    caller and test in this repo does today) keeps working unchanged.
    """
    def __init__(self, agent_id: str):
        super().__init__(agent_id, AgentRole.JURY)
        self._policy = _load_jury_policy()

    def _rl_vote(self, obs: dict) -> str:
        import numpy as np
        import torch

        vec = np.array([
            obs["score"], obs["zone"], obs["uid_is_root"],
            obs["score_delta"], obs["event_type"],
        ], dtype=np.float32)
        with torch.no_grad():
            out = self._policy.forward_inference({"obs": torch.from_numpy(vec).unsqueeze(0)})
            action = int(torch.argmax(out["action_dist_inputs"], dim=-1).item())
        return "CONTAIN" if action == 1 else "ALLOW"

    async def evaluate_and_vote(self, alert_payload: dict) -> dict:
        obs = alert_payload.get("obs")
        if self._policy is not None and obs is not None:
            vote = self._rl_vote(obs)
        else:
            vote = decide_vote(alert_payload.get("confidence", 0.0))
        return {"agent_id": self.state.agent_id, "vote": vote, "weight": 1.0}

@ray.remote
class JudgeAgent(BaseAgent):
    """Orchestrates consensus rounds when Patrollers raise anomaly alerts."""
    def __init__(self, agent_id: str, executor_ref, jury_pool_size: int = 5, jury_agent_cls=None):
        super().__init__(agent_id, AgentRole.JUDGE)
        self.executor = executor_ref
        self.jury_pool_size = jury_pool_size
        # Injectable for testing (a fake jury class that votes/fails
        # deterministically) without changing production behavior — real
        # callers never pass this, so it defaults to the real JuryAgent.
        self.jury_agent_cls = jury_agent_cls or JuryAgent

    async def coordinate_consensus(self, alert_payload: dict):
        # Dynamically spawn a Jury pool sized from config/agents.yaml's
        # jury.pool_size (defaults to 5 if not configured, BUG-006).
        jury_pool = [self.jury_agent_cls.remote(f"jury-{i}") for i in range(self.jury_pool_size)]

        # Broadcast evaluation tasks. Each juror is awaited individually so
        # one crashed/misbehaving actor doesn't take down the whole round —
        # ray.get(vote_futures) would raise and abort consensus entirely on
        # a single failure (BUG-007).
        vote_futures = [jury.evaluate_and_vote.remote(alert_payload) for jury in jury_pool]
        results = await asyncio.gather(*vote_futures, return_exceptions=True)
        votes = []
        for result in results:
            if isinstance(result, Exception):
                print(f"[JudgeAgent] jury vote failed, excluding from quorum: {result}")
            else:
                votes.append(result)

        if not votes:
            print("[JudgeAgent] no jury votes collected — skipping consensus round")
            return

        if quorum_reached(votes):
            # Trigger containment via the Executor
            await self.executor.execute_quarantine.remote(alert_payload)