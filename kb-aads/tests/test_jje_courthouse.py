import os
import sys

import pytest
import ray

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from consensus.jje import JudgeAgent
from swarm.registry import SwarmRegistry


@pytest.fixture(scope="module", autouse=True)
def ray_session():
    ray.init(include_dashboard=False, ignore_reinit_error=True, num_cpus=2)
    yield
    ray.shutdown()


@ray.remote
class FakeExecutorActor:
    async def execute_quarantine(self, alert_payload):
        return {"decision_id": "test", "success": True, "message": "ok"}


@ray.remote
class ControllableAgent:
    """Stands in for any real sub-agent under JJE oversight — status
    fields are settable directly so tests can drive each severity branch
    deterministically instead of needing a real agent to misbehave."""

    def __init__(self, status="active", error_count=0, uptime=0, auto_advance_uptime=False):
        self.status = status
        self.error_count = error_count
        self.uptime = uptime
        self.stopped = False
        self.started = False
        # Simulates a live tick loop actually advancing uptime between
        # assess_severity's two get_status reads, without relying on real
        # concurrency/timing races in the test.
        self.auto_advance_uptime = auto_advance_uptime

    def get_status(self):
        status = {"status": self.status, "error_count": self.error_count, "uptime": self.uptime}
        if self.auto_advance_uptime:
            self.uptime += 1
        return status

    async def stop(self):
        self.stopped = True

    async def start(self):
        self.started = True

    def was_stopped(self):
        return self.stopped

    def was_started(self):
        return self.started


def _judge(**kwargs):
    executor = FakeExecutorActor.remote()
    registry = SwarmRegistry.remote()
    judge = JudgeAgent.remote("judge-courthouse-test", executor, registry=registry, **kwargs)
    return judge, registry


def test_assess_severity_requires_registry():
    executor = FakeExecutorActor.remote()
    judge = JudgeAgent.remote("judge-no-registry", executor)  # no registry
    with pytest.raises(Exception):
        ray.get(judge.assess_severity.remote("agent-1"))


def test_assess_severity_terminate_for_unregistered_agent():
    judge, registry = _judge()
    assert ray.get(judge.assess_severity.remote("nonexistent")) == "terminate"


def test_assess_severity_restart_for_non_active_status():
    judge, registry = _judge()
    agent = ControllableAgent.remote(status="error")
    ray.get(registry.register.remote("agent-1", "patroller", agent))
    assert ray.get(judge.assess_severity.remote("agent-1")) == "restart"


def test_assess_severity_restart_for_high_error_count():
    judge, registry = _judge(error_count_threshold=3)
    agent = ControllableAgent.remote(status="active", error_count=5)
    ray.get(registry.register.remote("agent-1", "hunter", agent))
    assert ray.get(judge.assess_severity.remote("agent-1")) == "restart"


def test_assess_severity_restart_for_stalled_uptime():
    judge, registry = _judge(liveness_check_seconds=0.05)
    agent = ControllableAgent.remote(status="active", error_count=0, uptime=10)
    ray.get(registry.register.remote("agent-1", "healer", agent))
    # uptime never advances during the liveness window -> stalled.
    assert ray.get(judge.assess_severity.remote("agent-1")) == "restart"


def test_assess_severity_healthy_when_uptime_advances():
    judge, registry = _judge(liveness_check_seconds=0.05)
    agent = ControllableAgent.remote(status="active", error_count=0, uptime=10, auto_advance_uptime=True)
    ray.get(registry.register.remote("agent-1", "healer", agent))
    assert ray.get(judge.assess_severity.remote("agent-1")) == "healthy"


def test_enforce_verdict_restart_stops_and_restarts():
    judge, registry = _judge()
    agent = ControllableAgent.remote()
    ray.get(registry.register.remote("agent-1", "patroller", agent))

    result = ray.get(judge.enforce_verdict.remote("agent-1", "restart"))
    assert result["applied"] is True
    assert ray.get(agent.was_stopped.remote()) is True
    assert ray.get(agent.was_started.remote()) is True
    # restart keeps the agent registered and active.
    assert ray.get(registry.get_handle.remote("agent-1")) is not None


def test_enforce_verdict_revoke_stops_and_marks_revoked():
    judge, registry = _judge()
    agent = ControllableAgent.remote()
    ray.get(registry.register.remote("agent-1", "jury", agent))

    result = ray.get(judge.enforce_verdict.remote("agent-1", "revoke"))
    assert result["applied"] is True
    assert ray.get(agent.was_stopped.remote()) is True
    snapshot = ray.get(registry.list_all.remote())
    assert snapshot["agent-1"]["status"] == "revoked"


def test_enforce_verdict_terminate_unregisters():
    judge, registry = _judge()
    agent = ControllableAgent.remote()
    ray.get(registry.register.remote("agent-1", "militia_member", agent))

    result = ray.get(judge.enforce_verdict.remote("agent-1", "terminate"))
    assert result["applied"] is True
    assert ray.get(registry.get_handle.remote("agent-1")) is None


def test_enforce_verdict_unregistered_agent_reports_not_applied():
    judge, registry = _judge()
    result = ray.get(judge.enforce_verdict.remote("nonexistent", "restart"))
    assert result == {"agent_id": "nonexistent", "tier": "restart", "applied": False, "reason": "not registered"}


def test_enforce_verdict_rejects_unknown_tier():
    judge, registry = _judge()
    agent = ControllableAgent.remote()
    ray.get(registry.register.remote("agent-1", "patroller", agent))
    with pytest.raises(Exception):
        ray.get(judge.enforce_verdict.remote("agent-1", "banish"))
