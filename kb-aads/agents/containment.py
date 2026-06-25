from .base_agent import BaseAgent, AgentRole


class ContainmentAgent(BaseAgent):
    """
    Containment agents isolate malicious processes.
    """

    def __init__(self, agent_id: str):
        super().__init__(agent_id, AgentRole.CONTAINMENT)

    async def tick(self):
        self.state.last_action = "Awaiting containment orders"

    async def handle_message(self, message: dict):
        if message.get("type") == "CONTAIN":
            self.state.last_action = f"Containing PID {message.get('pid')}"