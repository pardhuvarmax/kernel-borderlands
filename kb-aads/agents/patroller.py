from .base_agent import BaseAgent, AgentRole

class PatrollerAgent(BaseAgent):
    """
    Patroller agents monitor baseline process behavior.
    Always active, watching for deviations.
    """

    def __init__(self, agent_id: str):
        super().__init__(agent_id, AgentRole.PATROLLER)
        self.monitored_pids = set()

    async def tick(self):
        self.state.last_action = "Monitoring baseline"
        
    async def handle_message(self, message: dict):
        if message.get("type") == "KB_EVENT":
            pid = message.get("pid")
            if pid:
                self.monitored_pids.add(pid)