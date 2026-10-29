import asyncio
import ray
from .base_agent import BaseAgent, AgentRole
from comms.grpc_client import ControlPlaneClient
from pipeline.flow import run_staged, LEVEL_NAMES


@ray.remote
class ExecutorAgent(BaseAgent):
    """
    Gateway back to the Go Control Plane. Receives consensus decisions from
    the Judge and submits them over the kba.sock UDS gRPC channel via
    SubmitAgentDecision — enforcement always happens in kb-control-plane,
    never here; this only carries the recommendation across the boundary.

    Sends real containment levels (CGROUP/SECCOMP/NAMESPACE/TERMINATE),
    staged in order. It used to send a "QUARANTINE" action that kbd
    reported as executed without enforcing anything; kbd now rejects
    unknown actions, and this class no longer produces one.
    """

    def __init__(self, agent_id: str, socket_path: str = "/run/kb/kba.sock"):
        super().__init__(agent_id, AgentRole.EXECUTOR)
        self.client = ControlPlaneClient(socket_path=socket_path)
        self._decision_counter = 0
        self._results = {"applied": 0, "refused": 0}

    def _submit(self, action, pid, confidence, authorized_by):
        self._decision_counter += 1
        return self.client.submit_decision(
            decision_id=f"{self.state.agent_id}-{self._decision_counter}",
            agent_id=self.state.agent_id, pid=pid, action=action,
            confidence=confidence, authorized_by=authorized_by,
        )

    async def execute_containment(self, alert_payload: dict) -> dict:
        """Stage containment on alert_payload['pid'] up to alert_payload['level'] (1-4)."""
        level = int(alert_payload.get("level", 1))
        if not 1 <= level <= 4:
            return {"applied": [], "halted_at": None, "final_level": 0, "message": f"invalid level {level}"}
        result = await asyncio.to_thread(
            run_staged, self._submit, alert_payload["pid"], level,
            float(alert_payload.get("confidence", 0.0)),
            alert_payload.get("authorized_by") or ["judge"],
        )
        self._results["refused" if result["halted_at"] else "applied"] += 1
        self.state.last_action = (
            f"PID {alert_payload['pid']} -> {LEVEL_NAMES[result['final_level']]}"
            + (f" (halted at {result['halted_at']}: {result['message']})" if result["halted_at"] else "")
        )
        return result

    async def execute_quarantine(self, alert_payload: dict) -> dict:
        """Back-compat name: now stages to the payload's level (default CGROUP)."""
        return await self.execute_containment(alert_payload)

    async def stop(self):
        self.client.close()
        await super().stop()
