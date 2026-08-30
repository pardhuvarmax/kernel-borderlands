import ray
import asyncio
from agents.base_agent import BaseAgent, AgentRole

# confidence is a 0.0-1.0 float everywhere else in the system (see
# kb-control-plane's SubmitAgentDecision and kb.proto) — this threshold used
# to be 75.0, which no realistic confidence value can ever exceed, making
# the CONTAIN vote dead code (BUG-003).
CONTAIN_VOTE_THRESHOLD = 0.75

# Pulled out as a plain function (not a JuryAgent method) so the voting
# decision is unit-testable without spinning up a Ray actor.
def decide_vote(score: float) -> str:
    return "CONTAIN" if score > CONTAIN_VOTE_THRESHOLD else "ALLOW"

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
    """Dynamic actor spawned to verify threats and cast votes."""
    def __init__(self, agent_id: str):
        super().__init__(agent_id, AgentRole.JURY)

    async def evaluate_and_vote(self, alert_payload: dict) -> dict:
        score = alert_payload.get("confidence", 0.0)
        return {"agent_id": self.state.agent_id, "vote": decide_vote(score), "weight": 1.0}

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