import ray
import asyncio
from agents.base_agent import BaseAgent, AgentRole

@ray.remote
class JuryAgent(BaseAgent):
    """Dynamic actor spawned to verify threats and cast votes."""
    def __init__(self, agent_id: str):
        super().__init__(agent_id, AgentRole.JURY)
        
    async def evaluate_and_vote(self, alert_payload: dict) -> dict:
        score = alert_payload.get("confidence", 0.0)
        # Quorum voting logic based on threat telemetry
        vote = "CONTAIN" if score > 75.0 else "ALLOW"
        return {"agent_id": self.state.agent_id, "vote": vote, "weight": 1.0}

@ray.remote
class JudgeAgent(BaseAgent):
    """Orchestrates consensus rounds when Patrollers raise anomaly alerts."""
    def __init__(self, agent_id: str, executor_ref):
        super().__init__(agent_id, AgentRole.JUDGE)
        self.executor = executor_ref

    async def coordinate_consensus(self, alert_payload: dict):
        # Dynamically spawn a Jury pool of 5 remote actors
        jury_pool = [JuryAgent.remote(f"jury-{i}") for i in range(5)]
        
        # Broadcast evaluation tasks
        vote_futures = [jury.evaluate_and_vote.remote(alert_payload) for jury in jury_pool]
        votes = ray.get(vote_futures)
        
        # Tally weighted votes
        contain_votes = sum(v["weight"] for v in votes if v["vote"] == "CONTAIN")
        total_votes = sum(v["weight"] for v in votes)
        
        if contain_votes / total_votes > 0.5:
            # Trigger containment via the Executor
            await self.executor.execute_quarantine.remote(alert_payload)