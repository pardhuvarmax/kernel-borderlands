import ray
import asyncio
from agents.base_agent import RemoteBaseAgent, AgentRole
from agents.hunter import HunterAgent
from agents.patroller import PatrollerAgent
from agents.healer import HealerAgent
from agents.containment import ContainmentAgent
from agents.executor import ExecutorAgent
from consensus.jje import JudgeAgent

ROLE_CLASSES = {
    AgentRole.HUNTER: HunterAgent,
    AgentRole.PATROLLER: PatrollerAgent,
    AgentRole.HEALER: HealerAgent,
    AgentRole.CONTAINMENT: ContainmentAgent,
}


class RaySwarmOrchestrator:
    """Connects to (or starts) a Ray runtime and manages remote agent actors."""

    def __init__(self, ray_mode: str = "local"):
        if ray_mode == "cluster":
            # Join an existing head node started via `ray start --head`.
            ray.init(address="auto", ignore_reinit_error=True)
        else:
            # Single-node dev: starts a local head in-process, no
            # external `ray start` step required.
            ray.init(ignore_reinit_error=True)

        self.agents = {}
        self.agent_counter = 0
        self.judge = None
        self.executor = None

    def spawn_agent(self, role: AgentRole):
        self.agent_counter += 1
        agent_id = f"agent-{self.agent_counter}"

        agent_cls = ROLE_CLASSES.get(role)
        agent_actor = agent_cls.remote(agent_id) if agent_cls else RemoteBaseAgent.remote(agent_id, role)

        self.agents[agent_id] = agent_actor
        return agent_actor

    async def start_swarm(self, config: dict, grpc_socket: str = "/run/kb/kba.sock"):
        # Executor and Judge are singletons — JJE consensus routes through
        # one gateway back to kb-control-plane. Jury actors are spawned
        # dynamically per round by JudgeAgent.coordinate_consensus (see
        # consensus/jje.py), not here.
        self.executor = ExecutorAgent.remote("executor-1", socket_path=grpc_socket)
        self.judge = JudgeAgent.remote("judge-1", self.executor)
        self.agents["executor-1"] = self.executor
        self.agents["judge-1"] = self.judge

        for role_name, count in config.items():
            role = AgentRole(role_name)
            for _ in range(count):
                self.spawn_agent(role)

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
