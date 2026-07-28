import grpc
import os
import sys

# Auto-import generated proto classes
sys.path.insert(0, os.path.dirname(__file__))
import kb_pb2
import kb_pb2_grpc

class ControlPlaneClient:
    """gRPC Client communicating with the Go Control Plane over Unix Domain Sockets.

    One instance = one gRPC channel. get_process_state/set_containment/
    submit_decision ("unary" calls) and stream_events/stream_alerts
    ("streaming" calls) are mutually exclusive on a given instance —
    enforced by _mark_unary()/_mark_streaming() below, not just documented.
    Mixing them would let a slow/stalled stream-consume loop back up the
    shared channel's underlying connection and delay a unary call's
    response on that same connection under load — the same class of
    coupling kb-core's kbd.sock/kbct.sock split fixed (see
    docs/development/core-control/control-plane-catalog.md §5.3), just at
    the gRPC-channel layer instead of the OS-socket layer. Cheap to avoid
    here (a second instance opens its own channel for free), so it's
    enforced now rather than left as a landmine for whenever a live
    streaming consumer actually gets built — there's a real, currently
    unused caller class (any future kb-events consumer) this WILL bite
    the moment it exists, since it would naturally reach for the same
    ControlPlaneClient instance an agent already holds for submit_decision.
    """
    def __init__(self, socket_path="/run/kb/kba.sock"):
        self.uds_path = f"unix://{socket_path}"
        # Create UDS channel
        self.channel = grpc.insecure_channel(self.uds_path)
        self.stub = kb_pb2_grpc.KernelBorderlandsStub(self.channel)
        self._streaming_committed = False
        self._unary_committed = False

    def _mark_streaming(self):
        if self._unary_committed:
            raise RuntimeError(
                "ControlPlaneClient: this instance already made a unary call "
                "(get_process_state/set_containment/submit_decision) and "
                "cannot now also stream (stream_events/stream_alerts) — "
                "create a separate ControlPlaneClient instance for the "
                "stream. See this class's docstring for why."
            )
        self._streaming_committed = True

    def _mark_unary(self):
        if self._streaming_committed:
            raise RuntimeError(
                "ControlPlaneClient: this instance is already streaming "
                "(stream_events/stream_alerts) and cannot now also make a "
                "unary call (get_process_state/set_containment/"
                "submit_decision) — create a separate ControlPlaneClient "
                "instance for the unary call. See this class's docstring "
                "for why."
            )
        self._unary_committed = True

    def get_process_state(self, pid: int):
        """Query process state by PID."""
        self._mark_unary()
        request = kb_pb2.PidRequest(pid=pid)
        return self.stub.GetProcessState(request)

    def list_zone(self, zone):
        """List processes in a zone (can be Zone enum, string, or int).

        Deliberately excluded from the unary/streaming guard above: this
        RPC is itself server-streaming at the protocol level (a bounded
        snapshot list, not a continuous feed), and its risk profile
        relative to stream_events/stream_alerts hasn't been analyzed —
        left unguarded rather than silently folded into either category.
        """
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
        self._mark_unary()
        if isinstance(level, str):
            level_enum = kb_pb2.ContainmentLevel.Value(level.upper())
        elif isinstance(level, int):
            level_enum = level
        else:
            level_enum = level

        request = kb_pb2.ContainmentRequest(pid=pid, level=level_enum, reason=reason)
        return self.stub.SetContainment(request)

    def stream_events(self, event_types=None):
        """Stream real-time events from eBPF layer.

        Not currently called by any live agent — and unlike what an
        earlier version of comms/README.md claimed, there is no ZeroMQ
        fallback either (that design predates the Ray-only pivot and was
        never built; see comms/README.md's corrected version). There is
        currently no live path for kb-events to reach the swarm at all.
        Raises RuntimeError if this instance already made a unary call
        (see this class's docstring) — use a separate ControlPlaneClient
        instance for the stream consumer.
        """
        self._mark_streaming()
        filt = kb_pb2.EventFilter(event_types=event_types or [])
        return self.stub.StreamEvents(filt)

    def stream_alerts(self, event_types=None):
        """Stream real-time security alerts from the control plane.

        Raises RuntimeError if this instance already made a unary call —
        see stream_events() and this class's docstring.
        """
        self._mark_streaming()
        filt = kb_pb2.EventFilter(event_types=event_types or [])
        return self.stub.StreamAlerts(filt)

    def submit_decision(self, decision_id: str, agent_id: str, pid: int, action: str, confidence: float, authorized_by=None):
        """Submit agent action back to the Go Control Plane for enforcement.

        Live today via ExecutorAgent (kb-aads/agents/executor.py). Raises
        RuntimeError if this instance is already streaming — see this
        class's docstring.
        """
        self._mark_unary()
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