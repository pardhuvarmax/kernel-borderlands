import grpc
import os
import sys

# Auto-import generated proto classes
sys.path.insert(0, os.path.dirname(__file__))
import kb_pb2
import kb_pb2_grpc

class ControlPlaneClient:
    """gRPC Client communicating with the Go Control Plane over Unix Domain Sockets."""
    def __init__(self, socket_path="/run/kb/kba.sock"):
        self.uds_path = f"unix://{socket_path}"
        # Create UDS channel
        self.channel = grpc.insecure_channel(self.uds_path)
        self.stub = kb_pb2_grpc.KernelBorderlandsStub(self.channel)

    def get_process_state(self, pid: int):
        """Query process state by PID."""
        request = kb_pb2.PidRequest(pid=pid)
        return self.stub.GetProcessState(request)

    def list_zone(self, zone):
        """List processes in a zone (can be Zone enum, string, or int)."""
        if isinstance(zone, str):
            zone_enum = kb_pb2.Zone.Value(zone.upper())
        elif isinstance(zone, int):
            zone_enum = zone
        else:
            zone_enum = zone
            
        request = kb_pb2.ZoneRequest(zone=zone_enum)
        return self.stub.ListZone(request)

    def set_containment(self, pid: int, level, reason: str):
        """Set containment level for a PID."""
        if isinstance(level, str):
            level_enum = kb_pb2.ContainmentLevel.Value(level.upper())
        elif isinstance(level, int):
            level_enum = level
        else:
            level_enum = level

        request = kb_pb2.ContainmentRequest(pid=pid, level=level_enum, reason=reason)
        return self.stub.SetContainment(request)

    def stream_events(self, event_types=None):
        """Stream real-time events from eBPF layer."""
        filt = kb_pb2.EventFilter(event_types=event_types or [])
        return self.stub.StreamEvents(filt)

    def stream_alerts(self, event_types=None):
        """Stream real-time security alerts from the control plane."""
        filt = kb_pb2.EventFilter(event_types=event_types or [])
        return self.stub.StreamAlerts(filt)

    def submit_decision(self, decision_id: str, agent_id: str, pid: int, action: str, confidence: float, authorized_by=None):
        """Submit agent action back to the Go Control Plane for enforcement."""
        decision = kb_pb2.AgentDecision(
            decision_id=decision_id,
            agent_id=agent_id,
            pid=pid,
            action=action,
            confidence=confidence,
            authorized_by=authorized_by or []
        )
        return self.stub.SubmitAgentDecision(decision)

    def close(self):
        """Close the gRPC channel."""
        self.channel.close()