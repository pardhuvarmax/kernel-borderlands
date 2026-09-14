import ray


@ray.remote
class SwarmRegistry:
    """
    Lookup table of every live agent actor, by agent_id.

    Per docs/development/control-aads/aads-intelligence-roadmap.md's
    "Registry ownership" section: RaySwarmOrchestrator is a plain Python
    object in the driver process, not a Ray actor — it holds every handle
    in self.agents, but a remote JudgeAgent can't reach into that dict
    across the process boundary. This actor is the fix: whoever spawns an
    agent (RaySwarmOrchestrator.spawn_agent, JudgeAgent's dynamic Jury
    pool, MilitiaSquadLeadAgent's dynamic squad members) registers it here
    right after creation, so Judge can look up ANY agent's handle later —
    including ones spawned dynamically after swarm start, which a static
    snapshot handed to Judge once at boot would miss.

    Registration happens at the spawn site (not via each agent
    self-registering in its own start()) — the spawner already has the
    handle the instant .remote() returns, so this needs no changes to
    BaseAgent or any existing agent subclass's constructor.
    """

    def __init__(self):
        self._agents = {}  # agent_id -> {"role": str, "handle": ActorHandle, "status": "active"|"revoked"}

    def register(self, agent_id: str, role: str, handle):
        self._agents[agent_id] = {"role": role, "handle": handle, "status": "active"}

    def unregister(self, agent_id: str):
        self._agents.pop(agent_id, None)

    def revoke(self, agent_id: str):
        if agent_id in self._agents:
            self._agents[agent_id]["status"] = "revoked"

    def get_handle(self, agent_id: str):
        entry = self._agents.get(agent_id)
        return entry["handle"] if entry else None

    def list_by_role(self, role: str) -> list:
        return [
            (agent_id, entry["handle"])
            for agent_id, entry in self._agents.items()
            if entry["role"] == role and entry["status"] == "active"
        ]

    def list_all(self) -> dict:
        return {
            agent_id: {"role": entry["role"], "status": entry["status"]}
            for agent_id, entry in self._agents.items()
        }
