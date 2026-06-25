from .base_agent import BaseAgent, AgentRole, AgentStatus
import asyncio

class HunterAgent(BaseAgent):
    """
    Hunter agents investigate suspicious processes.
    Activated when KB reports SUSPICIOUS zone transitions.
    """

    def __init__(self, agent_id: str):
        super().__init__(agent_id, AgentRole.HUNTER)
        self.investigations = {}

    async def tick(self):
        self.state.last_action = "Scanning for threats"

    async def handle_message(self, message: dict):
        if message.get("type") == "ZONE_TRANSITION":
            if message.get("to_zone") == "SUSPICIOUS":
                await self.investigate(message["pid"], message["score"])

    async def investigate(self, pid: int, score: float):
        print(f"[{self.state.agent_id}] Investigating PID={pid} score={score}")
        self.state.last_action = f"Investigating PID {pid}"
        self.investigations[pid] = {
            "score": score,
            "started_at": self.state.uptime
        }
        # TODO: query KB control plane for process history
        # TODO: build evidence chain
        # TODO: calculate confidence
        # TODO: submit to jury