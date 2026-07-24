import asyncio
import ray
from .base_agent import BaseAgent, AgentRole
from comms.grpc_client import ControlPlaneClient


@ray.remote
class ExecutorAgent(BaseAgent):
    """
    Gateway back to the Go Control Plane. Receives consensus decisions from
    the Judge and submits them over the kba.sock UDS gRPC channel via
    SubmitAgentDecision — enforcement always happens in kb-control-plane,
    never here; this only carries the recommendation across the boundary.
    """

    def __init__(self, agent_id: str, socket_path: str = "/run/kb/kba.sock"):
        super().__init__(agent_id, AgentRole.EXECUTOR)
        self.client = ControlPlaneClient(socket_path=socket_path)
        self._decision_counter = 0

    async def execute_quarantine(self, alert_payload: dict) -> dict:
        self._decision_counter += 1
        decision_id = f"{self.state.agent_id}-{self._decision_counter}"
        pid = alert_payload["pid"]
        confidence = float(alert_payload.get("confidence", 0.0))

        ack = await asyncio.to_thread(
            self.client.submit_decision,
            decision_id=decision_id,
            agent_id=self.state.agent_id,
            pid=pid,
            action="QUARANTINE",
            confidence=confidence,
            authorized_by=alert_payload.get("authorized_by", []),
        )
        return {"decision_id": decision_id, "success": ack.success, "message": ack.message}

    async def stop(self):
        self.client.close()
        await super().stop()
