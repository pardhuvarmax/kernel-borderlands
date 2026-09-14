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
    def __init__(self, agent_id: str, executor_ref, jury_pool_size: int = 5, jury_agent_cls=None, registry=None,
                 error_count_threshold: int = 5, liveness_check_seconds: float = 3.0):
        super().__init__(agent_id, AgentRole.JUDGE)
        self.executor = executor_ref
        self.jury_pool_size = jury_pool_size
        # Injectable for testing (a fake jury class that votes/fails
        # deterministically) without changing production behavior — real
        # callers never pass this, so it defaults to the real JuryAgent.
        self.jury_agent_cls = jury_agent_cls or JuryAgent
        # Optional swarm/registry.py SwarmRegistry handle — backs both
        # registering this round's dynamically-spawned Jury pool (so JJE
        # courthouse oversight can reach them later) and the courthouse
        # methods below (assess_severity/enforce_verdict), which look up
        # OTHER agents' handles through it. None in tests that don't
        # exercise either path.
        self.registry = registry
        self._round_counter = 0
        # Placeholders, not calibrated — see assess_severity's docstring.
        # Constructor-configurable (rather than hardcoded class constants)
        # purely so tests don't need a real multi-second sleep to exercise
        # the liveness-check path.
        self.error_count_threshold = error_count_threshold
        self.liveness_check_seconds = liveness_check_seconds

    async def coordinate_consensus(self, alert_payload: dict):
        # Dynamically spawn a Jury pool sized from config/agents.yaml's
        # jury.pool_size (defaults to 5 if not configured, BUG-006).
        self._round_counter += 1
        jury_pool = [self.jury_agent_cls.remote(f"jury-{i}") for i in range(self.jury_pool_size)]
        if self.registry is not None:
            # Registry keys carry a round suffix (unlike the jury actors'
            # own internal agent_id above, kept as plain "jury-{i}" to
            # match test_jje_consensus.py's existing per-index
            # assertions) so consecutive rounds' registrations don't
            # collide/overwrite each other in the registry.
            for i, jury in enumerate(jury_pool):
                self.registry.register.remote(f"jury-round{self._round_counter}-{i}", AgentRole.JURY.value, jury)

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

    # ---- JJE courthouse oversight -----------------------------------
    # Per docs/development/control-aads/aads-intelligence-roadmap.md's
    # "JJE's second role" section: JJE has real authority to stop a rogue
    # sub-agent (Patroller/Hunter/Healer/Containment militia/signal
    # relay), via a restart/revoke/terminate severity ladder, reusing this
    # same JudgeAgent rather than inventing new authority elsewhere.
    #
    # Severity classification below covers ONLY the "restart" tier
    # (liveness/error-count) with a real, computable signal — this
    # codebase has no output-drift-from-peer-baseline detector (the
    # "revoke" trigger) or authorization-boundary-violation detector (the
    # "terminate" trigger) anywhere, so assess_severity never returns
    # those tiers on its own. This is a real, stated gap (same posture as
    # HealerAgent's documented RL gap) — call enforce_verdict directly
    # with "revoke"/"terminate" once some other detector (not yet built)
    # determines one applies. The numeric thresholds below are
    # placeholders, not calibrated — the roadmap doc explicitly says real
    # cutoffs need labeled rogue-agent-behavior data from a Phase-0-style
    # scenario that doesn't exist yet (self.error_count_threshold /
    # self.liveness_check_seconds, set in __init__ above — same posture
    # as HealerAgent's DEFAULT_SAFE_SCORE_THRESHOLD).

    async def assess_severity(self, agent_id: str) -> str:
        """
        Returns "healthy", "restart", or "terminate" (only if agent_id is
        already gone from the registry — nothing to restart/revoke).
        Never returns "revoke" — see the class-level note above.
        """
        if self.registry is None:
            raise RuntimeError("assess_severity requires this JudgeAgent to have been constructed with a registry")

        handle = await self.registry.get_handle.remote(agent_id)
        if handle is None:
            return "terminate"

        status_before = await handle.get_status.remote()
        if status_before["status"] != "active":
            return "restart"
        if status_before["error_count"] >= self.error_count_threshold:
            return "restart"

        await asyncio.sleep(self.liveness_check_seconds)
        status_after = await handle.get_status.remote()
        if status_after["uptime"] <= status_before["uptime"]:
            return "restart"

        return "healthy"

    async def enforce_verdict(self, agent_id: str, tier: str) -> dict:
        """
        Applies the roadmap's graduated response. Quorum-vs-unilateral
        gating (per the roadmap: low/mid tiers go through Judge->Jury
        quorum first, "terminate" acts immediately with post-hoc review)
        is deliberately NOT implemented here — see this method's own
        docstring note below. This method is the mechanism only; callers
        decide when it's appropriate to invoke it.

        - "restart": stop() then re-issue start() on the SAME actor —
          resumes its own tick loop without killing the underlying Ray
          process. For a stuck/unresponsive actor with no evidence of
          compromise (the roadmap's own "restart" example).
        - "revoke": stop() the actor AND mark it revoked in the registry
          (pulls it out of active rotation/lookup) without killing the
          process — e.g. an out-of-pool Jury member.
        - "terminate": ray.kill() the actor and remove it from the
          registry entirely — for behavior consistent with compromise.

        NOT implemented, and stated honestly rather than guessed: the
        roadmap's quorum-gating for restart/revoke (route the verdict
        through Judge->Jury before acting) needs Jury to vote on "is this
        sub-agent's behavior actually rogue," a structurally different
        question from JuryAgent.evaluate_and_vote's existing CONTAIN/ALLOW
        threat vote. Reusing that vote for this would mean feeding it a
        fabricated confidence score to force an outcome — not a real
        vote. Building a genuine verdict-vote path needs its own design
        (what does Jury actually evaluate for a sub-agent verdict?), which
        this session doesn't have a real signal to base on yet.
        """
        if self.registry is None:
            raise RuntimeError("enforce_verdict requires this JudgeAgent to have been constructed with a registry")

        handle = await self.registry.get_handle.remote(agent_id)
        if handle is None:
            return {"agent_id": agent_id, "tier": tier, "applied": False, "reason": "not registered"}

        if tier == "restart":
            await handle.stop.remote()
            handle.start.remote()
            return {"agent_id": agent_id, "tier": tier, "applied": True}
        if tier == "revoke":
            await handle.stop.remote()
            await self.registry.revoke.remote(agent_id)
            return {"agent_id": agent_id, "tier": tier, "applied": True}
        if tier == "terminate":
            ray.kill(handle)
            await self.registry.unregister.remote(agent_id)
            return {"agent_id": agent_id, "tier": tier, "applied": True}
        raise ValueError(f"enforce_verdict: unknown severity tier {tier!r}")