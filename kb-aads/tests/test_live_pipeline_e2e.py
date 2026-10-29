"""
End-to-end through the real swarm (Ingest -> Patroller -> Hunter -> Judge ->
Jury -> Executor) against a fake kbd gRPC server on a UDS. Asserts what the
fake kbd actually RECEIVED as enforcement decisions, not what the agents
claim, so a green run cannot hide a no-op (the QUARANTINE failure mode).
"""
import os
import sys
import tempfile
import threading
import time
from concurrent import futures

import grpc
import pytest
import ray

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../comms")))
import kb_pb2
import kb_pb2_grpc

from swarm.orchestrator import RaySwarmOrchestrator


class FakeKbd(kb_pb2_grpc.KernelBorderlandsServicer):
    def __init__(self, events):
        self.events, self.decisions, self.lock = events, [], threading.Lock()

    def GetProcessState(self, request, context):
        return kb_pb2.ProcessState(pid=request.pid, comm="evil", score=92.0, zone=kb_pb2.Zone.BORDERLANDS, uid=0)

    def StreamEvents(self, request, context):
        for ev in self.events:
            yield ev
        while context.is_active():
            time.sleep(0.1)

    def SubmitAgentDecision(self, request, context):
        with self.lock:
            self.decisions.append((request.pid, request.action, round(request.confidence, 2), list(request.authorized_by)))
        return kb_pb2.DecisionAck(success=True, message="executed")


@pytest.fixture(scope="module")
def kbd():
    d = tempfile.mkdtemp()
    sock = os.path.join(d, "kba.sock")
    events = [kb_pb2.KBEvent(pid=777, comm="evil", event_type="process_state", score_delta=float(s),
                             timestamp=i, metadata={"zone": "BORDERLANDS", "uid": "0"})
              for i, s in enumerate([10, 95, 30, 92])]  # burst for one PID
    events += [kb_pb2.KBEvent(pid=900 + i, comm="ok", event_type="process_state", score_delta=3.0,
                              timestamp=i, metadata={"zone": "SAFE", "uid": "1000"}) for i in range(50)]
    fake = FakeKbd(events)
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    kb_pb2_grpc.add_KernelBorderlandsServicer_to_server(fake, server)
    server.add_insecure_port(f"unix://{sock}")
    server.start()
    yield fake, sock
    server.stop(0)


def test_burst_becomes_one_staged_containment_and_benign_pids_untouched(kbd):
    fake, sock = kbd
    ray.init(include_dashboard=False, ignore_reinit_error=True, num_cpus=4)
    try:
        orch = RaySwarmOrchestrator.__new__(RaySwarmOrchestrator)  # reuse the running Ray session
        from swarm.registry import SwarmRegistry
        orch.agents, orch.agent_counter, orch.judge, orch.ingest = {}, 0, None, None
        orch.executor, orch.grpc_socket, orch.registry = None, None, SwarmRegistry.remote()
        threading.Thread(target=lambda: __import__("asyncio").run(orch.start_swarm(
            {"patroller": 1, "hunter": 1, "containment": 1}, grpc_socket=sock, jury_pool_size=3)), daemon=True).start()

        deadline = time.time() + 60
        while time.time() < deadline:
            with fake.lock:
                if len(fake.decisions) >= 4:
                    break
            time.sleep(0.25)
        with fake.lock:
            decisions = list(fake.decisions)
        diag = {
            "ingest": ray.get(orch.ingest.get_ingest_stats.remote()),
            "judge": ray.get(orch.judge.get_round_stats.remote()),
            "hunters": [ray.get(a.get_stats.remote()) for k, a in orch.agents.items() if k.startswith("agent-") and "get_stats" in dir(a)],
        }
        assert [d[1] for d in decisions[:4]] == ["CGROUP", "SECCOMP", "NAMESPACE", "TERMINATE"], (decisions, diag)
        assert {d[0] for d in decisions} == {777}, "only the hot PID may be contained"
        assert all(d[2] >= 0.85 for d in decisions)
        assert all("judge" in d[3] for d in decisions)
        time.sleep(1.0)
        with fake.lock:
            assert len(fake.decisions) == 4, "burst must collapse to ONE incident (dedup/cooldown)"
        stats = ray.get(orch.ingest.get_ingest_stats.remote())
        assert stats["received"] >= 54 and stats["stream"] == "streaming"
    finally:
        ray.shutdown()
