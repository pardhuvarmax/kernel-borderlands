import ray
import asyncio
from agents.base_agent import RemoteBaseAgent, AgentRole
from agents.hunter import HunterAgent
from agents.patroller import PatrollerAgent
from agents.healer import HealerAgent
from agents.containment import ContainmentAgent
from agents.executor import ExecutorAgent
from agents.militia import MilitiaSquadLeadAgent
from agents.signal_relay import SignalRelayAgent
from consensus.jje import JudgeAgent
from swarm.registry import SwarmRegistry

ROLE_CLASSES = {
    AgentRole.HUNTER: HunterAgent,
    AgentRole.PATROLLER: PatrollerAgent,
    AgentRole.HEALER: HealerAgent,
    AgentRole.CONTAINMENT: ContainmentAgent,
    AgentRole.SIGNAL_RELAY: SignalRelayAgent,
}


class RaySwarmOrchestrator:
    """Connects to (or starts) a Ray runtime and manages remote agent actors."""

    def __init__(self, ray_mode: str = "local"):
        if ray_mode == "cluster":
            # Join an existing head node started via `ray start --head`.
            # dashboard_host is a no-op here since the dashboard is served
            # by the head node's own `ray start`, not this init() call.
            ray.init(address="auto", ignore_reinit_error=True)
        else:
            # Single-node dev: starts a local head in-process, no
            # external `ray start` step required. dashboard_host="0.0.0.0"
            # so the dashboard is reachable from outside the VM (default
            # is 127.0.0.1, which only NAT/hypervisor port-forwarding
            # can't reach).
            ray.init(ignore_reinit_error=True, dashboard_host="0.0.0.0")

        self.agents = {}
        self.agent_counter = 0
        self.judge = None
        self.executor = None
        self.grpc_socket = None
        # SwarmRegistry backs JJE's courthouse oversight (see
        # consensus/jje.py's JudgeAgent.assess_severity/enforce_verdict) —
        # a lookup Judge can use to reach ANY agent's handle, including
        # ones spawned dynamically after swarm start (Jury pools,
        # militia squads), which a one-time snapshot handed to Judge at
        # boot would miss. See registry.py's docstring for why
        # registration happens at each spawn site instead of via
        # self-registration in BaseAgent.
        self.registry = SwarmRegistry.remote()

    def spawn_agent(self, role: AgentRole, **extra_kwargs):
        self.agent_counter += 1
        agent_id = f"agent-{self.agent_counter}"

        agent_cls = ROLE_CLASSES.get(role)
        agent_actor = (
            agent_cls.remote(agent_id, **extra_kwargs) if agent_cls
            else RemoteBaseAgent.remote(agent_id, role)
        )

        self.agents[agent_id] = agent_actor
        self.registry.register.remote(agent_id, role.value, agent_actor)
        return agent_actor

    async def start_swarm(self, config: dict, grpc_socket: str = "/run/kb/kba.sock", jury_pool_size: int = 5,
                           patroller_suspicious_threshold: float = 40.0):
        # Executor and Judge are singletons — JJE consensus routes through
        # one gateway back to kb-control-plane. Jury actors are spawned
        # dynamically per round by JudgeAgent.coordinate_consensus (see
        # consensus/jje.py), not here.
        self.executor = ExecutorAgent.remote("executor-1", socket_path=grpc_socket)
        self.judge = JudgeAgent.remote("judge-1", self.executor, jury_pool_size=jury_pool_size, registry=self.registry)
        self.agents["executor-1"] = self.executor
        self.agents["judge-1"] = self.judge
        self.registry.register.remote("executor-1", AgentRole.EXECUTOR.value, self.executor)
        self.registry.register.remote("judge-1", AgentRole.JUDGE.value, self.judge)
        self.grpc_socket = grpc_socket

        # Hunters must exist before Patrollers so Patroller's escalation
        # target (agents/patroller.py's hunter_pool) can be wired at
        # construction — same "spawn dependency first" shape as
        # Executor/Judge above, just for a non-singleton role. Config
        # dict iteration order (from agents.yaml) is not trusted for this.
        remaining = dict(config)
        hunter_count = remaining.pop("hunter", 0)
        hunter_pool = [self.spawn_agent(AgentRole.HUNTER) for _ in range(hunter_count)]

        patroller_count = remaining.pop("patroller", 0)
        for _ in range(patroller_count):
            self.spawn_agent(
                AgentRole.PATROLLER,
                hunter_pool=hunter_pool,
                suspicious_threshold=patroller_suspicious_threshold,
            )

        # Signal relays route to the hunter pool by name — the one
        # concrete route wired up today (see agents/signal_relay.py's
        # scoping note: which other agent-pairs go through a relay
        # instead of a direct call is still an open Phase-4 decision, not
        # decided here). Also needs the hunter pool to exist first, same
        # "spawn dependency first" ordering as Patroller above.
        relay_count = remaining.pop("signal_relay", 0)
        for _ in range(relay_count):
            self.spawn_agent(AgentRole.SIGNAL_RELAY, routes={"hunter": hunter_pool})

        for role_name, count in remaining.items():
            role = AgentRole(role_name)
            for _ in range(count):
                self.spawn_agent(role)

        await asyncio.gather(*[
            agent.start.remote() for agent in self.agents.values()
        ])

    def spawn_militia_squad(self, pid: int, target_level: int, reason: str = ""):
        """
        Commands a containment militia squad against one PID.

        Per the roadmap's spawn-lifecycle note (mirroring Jury's dynamic
        per-incident spawn, see consensus/jje.py's coordinate_consensus),
        a squad lead is spawned fresh per incident rather than kept as a
        standing pool — squad members are then spawned by the lead itself,
        one per stage, only for the stages actually needed (see
        agents/militia.py's MilitiaSquadLeadAgent.command_squad).

        Not wired into JudgeAgent.coordinate_consensus automatically —
        that would require Judge to also carry a containment-level
        decision (from agents/containment.py's ContainmentAgent), which is
        a separate, undecided integration question the roadmap leaves open
        for Phase 4. Call this directly (or from a caller that already has
        both a quorum decision and a containment level) until that's
        resolved.
        """
        self.agent_counter += 1
        lead_id = f"militia-lead-{self.agent_counter}"
        lead = MilitiaSquadLeadAgent.remote(
            lead_id, socket_path=self.grpc_socket or "/run/kb/kba.sock", registry=self.registry,
        )
        self.agents[lead_id] = lead
        self.registry.register.remote(lead_id, AgentRole.MILITIA_LEAD.value, lead)
        return lead.command_squad.remote(pid, target_level, reason)

    def get_status(self) -> dict:
        status_refs = [agent.get_status.remote() for agent in self.agents.values()]
        statuses = ray.get(status_refs)
        return {
            "total": len(self.agents),
            "agents": statuses
        }