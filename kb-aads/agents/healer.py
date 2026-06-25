from .base_agent import BaseAgent, AgentRole


class HealerAgent(BaseAgent):
    """
    Healer agents recover compromised systems and restore normal operation.
    """

    def __init__(self, agent_id: str):
        super().__init__(agent_id, AgentRole.HEALER)

    async def tick(self):
        self.state.last_action = "Monitoring recovery tasks"

    async def handle_message(self, message: dict):
        if message.get("type") == "RECOVER":
            self.state.last_action = f"Recovering PID {message.get('pid')}"