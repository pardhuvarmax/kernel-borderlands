import os
import sys

import pytest
import ray

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from swarm.registry import SwarmRegistry


@pytest.fixture(scope="module", autouse=True)
def ray_session():
    ray.init(include_dashboard=False, ignore_reinit_error=True, num_cpus=2)
    yield
    ray.shutdown()


@ray.remote
class DummyAgent:
    def get_status(self):
        return {"agent_id": "dummy"}


def test_register_and_get_handle():
    registry = SwarmRegistry.remote()
    dummy = DummyAgent.remote()
    ray.get(registry.register.remote("agent-1", "patroller", dummy))

    handle = ray.get(registry.get_handle.remote("agent-1"))
    assert handle is not None
    assert ray.get(handle.get_status.remote()) == {"agent_id": "dummy"}


def test_get_handle_returns_none_for_unknown_agent():
    registry = SwarmRegistry.remote()
    assert ray.get(registry.get_handle.remote("nonexistent")) is None


def test_unregister_removes_agent():
    registry = SwarmRegistry.remote()
    dummy = DummyAgent.remote()
    ray.get(registry.register.remote("agent-1", "hunter", dummy))
    ray.get(registry.unregister.remote("agent-1"))
    assert ray.get(registry.get_handle.remote("agent-1")) is None


def test_list_by_role_filters_active_only():
    registry = SwarmRegistry.remote()
    a = DummyAgent.remote()
    b = DummyAgent.remote()
    ray.get(registry.register.remote("agent-a", "hunter", a))
    ray.get(registry.register.remote("agent-b", "hunter", b))
    ray.get(registry.revoke.remote("agent-b"))

    active_hunters = ray.get(registry.list_by_role.remote("hunter"))
    assert [aid for aid, _ in active_hunters] == ["agent-a"]


def test_list_all_reports_role_and_status():
    registry = SwarmRegistry.remote()
    ray.get(registry.register.remote("agent-1", "patroller", DummyAgent.remote()))
    ray.get(registry.revoke.remote("agent-1"))

    snapshot = ray.get(registry.list_all.remote())
    assert snapshot == {"agent-1": {"role": "patroller", "status": "revoked"}}
