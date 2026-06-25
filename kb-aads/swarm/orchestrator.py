from agents.base_agent import BaseAgent, AgentRole
from agents.hunter import HunterAgent
from agents.patroller import PatrollerAgent
from agents.healer import HealerAgent
from agents.containment import ContainmentAgent
import asyncio

class SwarmOrchestrator:
    """
    Manages the agent swarm lifecycle.
    Creates, monitors, and rebalances agents.
    """

    def __init__(self):
        self.agents = {}
        self.agent_counter = 0

    def create_agent(self, role: AgentRole):
        self.agent_counter += 1
        agent_id = f"agent-{self.agent_counter}"
        
        if role == AgentRole.PATROLLER:
            agent = PatrollerAgent(agent_id)
        elif role == AgentRole.HUNTER:
            agent = HunterAgent(agent_id)
        elif role == AgentRole.HEALER:
            agent = HealerAgent(agent_id)
        elif role == AgentRole.CONTAINMENT:
            agent = ContainmentAgent(agent_id)
        else:
            agent = BaseAgent(agent_id, role)

        self.agents[agent_id] = agent
        print(f"[Swarm] Created {role.value} agent: {agent_id}")
        return agent

    async def start_swarm(self, config: dict):
        """Initialize swarm with default role distribution"""
        print("[Swarm] Initializing KB Agent Swarm...")

        # Default swarm composition
        for _ in range(config.get("patrollers", 2)):
            self.create_agent(AgentRole.PATROLLER)
        for _ in range(config.get("hunters", 2)):
            self.create_agent(AgentRole.HUNTER)
        for _ in range(config.get("healers", 1)):
            self.create_agent(AgentRole.HEALER)
        for _ in range(config.get("containment", 1)):
            self.create_agent(AgentRole.CONTAINMENT)

        print(f"[Swarm] {len(self.agents)} agents initialized")

        # Start all agents
        await asyncio.gather(*[
            agent.start() for agent in self.agents.values()
        ])

    def get_status(self):
        return {
            "total": len(self.agents),
            "by_role": {
                role.value: sum(
                    1 for a in self.agents.values()
                    if a.state.role == role
                )
                for role in AgentRole
            }
        }