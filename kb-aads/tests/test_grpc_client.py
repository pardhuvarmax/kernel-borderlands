import os
import sys
import time
import grpc
import pytest
from concurrent import futures

# Add comms and project root to the python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../comms")))

import kb_pb2
import kb_pb2_grpc
from comms.grpc_client import ControlPlaneClient


class MockKernelBorderlandsServicer(kb_pb2_grpc.KernelBorderlandsServicer):
    def GetProcessState(self, request, context):
        return kb_pb2.ProcessState(
            pid=request.pid,
            ppid=1,
            comm="mock_proc",
            score=15.0,
            zone=kb_pb2.Zone.SAFE,
            uid=1000,
            containment=kb_pb2.ContainmentLevel.NONE,
            first_seen=int(time.time()) - 10,
            last_seen=int(time.time())
        )

    def ListZone(self, request, context):
        yield kb_pb2.ProcessState(
            pid=1001,
            ppid=1,
            comm="suspicious_proc",
            score=78.0,
            zone=request.zone,
            uid=1000,
            containment=kb_pb2.ContainmentLevel.CGROUP,
            first_seen=int(time.time()) - 5,
            last_seen=int(time.time())
        )

    def SetContainment(self, request, context):
        return kb_pb2.ContainmentResponse(success=True)

    def StreamEvents(self, request, context):
        yield kb_pb2.KBEvent(
            pid=1002,
            ppid=1,
            comm="bash",
            event_type="execve",
            score_delta=5.0,
            timestamp=int(time.time())
        )

    def SubmitAgentDecision(self, request, context):
        return kb_pb2.DecisionAck(success=True, message=f"Mock Ack for {request.decision_id}")

    def StreamAlerts(self, request, context):
        yield kb_pb2.Alert(
            alert_id=request.event_types[0] if request.event_types else "alert-123",
            alert_type="exfiltration",
            pid=1003,
            comm="curl",
            confidence=95.0,
            severity="HIGH",
            timestamp=int(time.time()),
            evidence=["high rate connection to unknown IP"]
        )


@pytest.fixture(scope="module")
def grpc_server():
    # Use workspace folder for the socket file to ensure write permissions
    socket_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "test-kba.sock"))
    if os.path.exists(socket_path):
        try:
            os.remove(socket_path)
        except OSError:
            pass

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
    kb_pb2_grpc.add_KernelBorderlandsServicer_to_server(MockKernelBorderlandsServicer(), server)
    
    # In python grpc, the format for UDS binding is unix:/path/to/socket
    server.add_insecure_port(f"unix:{socket_path}")
    server.start()

    yield socket_path

    server.stop(0)
    if os.path.exists(socket_path):
        try:
            os.remove(socket_path)
        except OSError:
            pass


def test_get_process_state(grpc_server):
    client = ControlPlaneClient(grpc_server)
    try:
        response = client.get_process_state(999)
        assert response.pid == 999
        assert response.comm == "mock_proc"
        assert response.zone == kb_pb2.Zone.SAFE
    finally:
        client.close()


def test_list_zone(grpc_server):
    client = ControlPlaneClient(grpc_server)
    try:
        responses = list(client.list_zone("SUSPICIOUS"))
        assert len(responses) == 1
        assert responses[0].pid == 1001
        assert responses[0].zone == kb_pb2.Zone.SUSPICIOUS
    finally:
        client.close()


def test_set_containment(grpc_server):
    client = ControlPlaneClient(grpc_server)
    try:
        response = client.set_containment(999, "CGROUP", "Suspicious CPU load")
        assert response.success is True
    finally:
        client.close()


def test_stream_events(grpc_server):
    client = ControlPlaneClient(grpc_server)
    try:
        responses = list(client.stream_events(["execve"]))
        assert len(responses) == 1
        assert responses[0].pid == 1002
        assert responses[0].event_type == "execve"
    finally:
        client.close()


def test_stream_alerts(grpc_server):
    client = ControlPlaneClient(grpc_server)
    try:
        responses = list(client.stream_alerts(["custom-alert"]))
        assert len(responses) == 1
        assert responses[0].alert_id == "custom-alert"
        assert responses[0].alert_type == "exfiltration"
    finally:
        client.close()


def test_submit_decision(grpc_server):
    client = ControlPlaneClient(grpc_server)
    try:
        response = client.submit_decision(
            decision_id="dec-789",
            agent_id="agent-01",
            pid=1234,
            action="QUARANTINE",
            confidence=0.95,
            authorized_by=["patroller"]
        )
        assert response.success is True
        assert "dec-789" in response.message
    finally:
        client.close()
