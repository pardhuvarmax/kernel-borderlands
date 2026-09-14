import os
import sys

import pytest
import ray

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from agents.militia import MilitiaSquadLeadAgent, ESCALATION_STAGES


@pytest.fixture(scope="module", autouse=True)
def ray_session():
    ray.init(include_dashboard=False, ignore_reinit_error=True, num_cpus=2)
    yield
    ray.shutdown()


@ray.remote
class RecordingSquadMember:
    """Stands in for MilitiaSquadMemberAgent so squad-lead sequencing can
    be tested without a real gRPC channel to kb-control-plane."""

    def __init__(self, agent_id, stage, socket_path=None):
        self.stage = stage

    async def execute(self, pid, reason):
        return {"stage": self.stage, "pid": pid, "success": True, "message": "ok"}


@ray.remote
class FailingAtNamespaceMember:
    """Fails specifically at the NAMESPACE stage, to test that escalation
    halts on first failure rather than continuing past it."""

    def __init__(self, agent_id, stage, socket_path=None):
        self.stage = stage

    async def execute(self, pid, reason):
        if self.stage == "NAMESPACE":
            return {"stage": self.stage, "pid": pid, "success": False, "message": "denied"}
        return {"stage": self.stage, "pid": pid, "success": True, "message": "ok"}


def test_command_squad_executes_stages_in_order_up_to_target_level():
    lead = MilitiaSquadLeadAgent.remote("lead-test-1", squad_member_cls=RecordingSquadMember)
    report = ray.get(lead.command_squad.remote(pid=100, target_level=3, reason="test"))

    assert report["pid"] == 100
    assert report["target_level"] == 3
    assert [s["stage"] for s in report["stages"]] == ESCALATION_STAGES[:3]
    assert all(s["success"] for s in report["stages"])


def test_command_squad_target_level_one_runs_only_cgroup():
    lead = MilitiaSquadLeadAgent.remote("lead-test-2", squad_member_cls=RecordingSquadMember)
    report = ray.get(lead.command_squad.remote(pid=200, target_level=1, reason="test"))
    assert [s["stage"] for s in report["stages"]] == ["CGROUP"]


def test_command_squad_target_level_four_runs_full_sequence():
    lead = MilitiaSquadLeadAgent.remote("lead-test-3", squad_member_cls=RecordingSquadMember)
    report = ray.get(lead.command_squad.remote(pid=300, target_level=4, reason="test"))
    assert [s["stage"] for s in report["stages"]] == ESCALATION_STAGES


def test_command_squad_halts_on_stage_failure():
    lead = MilitiaSquadLeadAgent.remote("lead-test-4", squad_member_cls=FailingAtNamespaceMember)
    report = ray.get(lead.command_squad.remote(pid=400, target_level=4, reason="test"))

    # CGROUP, SECCOMP succeed; NAMESPACE fails and halts before TERMINATE.
    assert [s["stage"] for s in report["stages"]] == ["CGROUP", "SECCOMP", "NAMESPACE"]
    assert report["stages"][-1]["success"] is False


def test_command_squad_rejects_invalid_target_level():
    lead = MilitiaSquadLeadAgent.remote("lead-test-5", squad_member_cls=RecordingSquadMember)
    with pytest.raises(Exception):
        ray.get(lead.command_squad.remote(pid=500, target_level=0, reason="test"))
    with pytest.raises(Exception):
        ray.get(lead.command_squad.remote(pid=500, target_level=5, reason="test"))


def test_handle_message_routes_contain_squad():
    lead = MilitiaSquadLeadAgent.remote("lead-test-6", squad_member_cls=RecordingSquadMember)
    ray.get(lead.receive_message.remote({
        "type": "CONTAIN_SQUAD", "pid": 600, "target_level": 2, "reason": "beacon detected",
    }))
    ray.get(lead.process_messages.remote())
    status = ray.get(lead.get_status.remote())
    assert "PID 600" in status["last_action"]


def test_handle_message_ignores_other_types():
    lead = MilitiaSquadLeadAgent.remote("lead-test-7", squad_member_cls=RecordingSquadMember)
    ray.get(lead.receive_message.remote({"type": "SOMETHING_ELSE"}))
    ray.get(lead.process_messages.remote())
    status = ray.get(lead.get_status.remote())
    assert status["last_action"] == ""
