import ray
import asyncio
from agents.base_agent import BaseAgent, AgentRole

class RaySwarmOrchestrator:
    """Connects to the Ray Cluster and manages remote agent actors."""
    def __init__(self):
        # Auto-connect to existing cluster running on host
        ray.init(address="auto", ignore_reinit_error=True)
        self.agents = {}
        self.agent_counter = 0

    def spawn_agent(self, role: AgentRole):
        self.agent_counter += 1
        agent_id = f"agent-{self.agent_counter}"
        
        # Deploy as remote Ray Actor
        agent_actor = BaseAgent.remote(agent_id, role)
        self.agents[agent_id] = agent_actor
        return agent_actor

    async def start_swarm(self, config: dict):
        for role_name, count in config.items():
            role = AgentRole(role_name)
            for _ in range(count):
                self.spawn_agent(role)
        
        # Trigger start lifecycle on all remote actors concurrently
        await asyncio.gather(*[
            agent.start.remote() for agent in self.agents.values()
        ])

    def get_status(self) -> dict:
        status_refs = [agent.get_status.remote() for agent in self.agents.values()]
        statuses = ray.get(status_refs)
        return {
            "total": len(self.agents),
            "agents": statuses
        }