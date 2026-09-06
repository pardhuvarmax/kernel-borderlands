import os
import sys

import pytest
import ray

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from agents.patroller import PatrollerAgent


@pytest.fixture(scope="module", autouse=True)
def ray_session():
    ray.init(include_dashboard=False, ignore_reinit_error=True, num_cpus=2)
    yield
    ray.shutdown()


@ray.remote
class RecordingHunter:
    """Records every message it receives, standing in for a real
    HunterAgent so tests can assert on exactly what Patroller dispatched
    without depending on Hunter's own (separately tested) logic."""

    def __init__(self):
        self.received = []

    async def receive_message(self, message: dict):
        self.received.append(message)

    def get_received(self):
        return self.received


def _drain(patroller_actor):
    # PatrollerAgent.handle_message is invoked via BaseAgent's
    # process_messages loop (start()'s tick loop), not directly — but
    # calling handle_message would require reaching into actor internals.
    # Simplest correct approach: call receive_message then manually pump
    # process_messages once, mirroring what start()'s loop does per tick.
    ray.get(patroller_actor.process_messages.remote())


def test_patroller_escalates_pid_crossing_threshold():
    hunter = RecordingHunter.remote()
    patroller = PatrollerAgent.remote("patroller-test", hunter_pool=[hunter], suspicious_threshold=40.0)

    ray.get(patroller.receive_message.remote({"type": "KB_EVENT", "pid": 123, "score": 55.0}))
    _drain(patroller)

    received = ray.get(hunter.get_received.remote())
    assert len(received) == 1
    assert received[0] == {"type": "ZONE_TRANSITION", "to_zone": "SUSPICIOUS", "pid": 123, "score": 55.0}


def test_patroller_does_not_escalate_below_threshold():
    hunter = RecordingHunter.remote()
    patroller = PatrollerAgent.remote("patroller-test-2", hunter_pool=[hunter], suspicious_threshold=40.0)

    ray.get(patroller.receive_message.remote({"type": "KB_EVENT", "pid": 456, "score": 10.0}))
    _drain(patroller)

    assert ray.get(hunter.get_received.remote()) == []


def test_patroller_escalates_only_once_per_pid_until_score_drops():
    hunter = RecordingHunter.remote()
    patroller = PatrollerAgent.remote("patroller-test-3", hunter_pool=[hunter], suspicious_threshold=40.0)

    # Same PID crossing the threshold repeatedly should only escalate once.
    for _ in range(3):
        ray.get(patroller.receive_message.remote({"type": "KB_EVENT", "pid": 789, "score": 60.0}))
        _drain(patroller)
    assert len(ray.get(hunter.get_received.remote())) == 1

    # Score drops back below threshold, then crosses again — should escalate a second time.
    ray.get(patroller.receive_message.remote({"type": "KB_EVENT", "pid": 789, "score": 10.0}))
    _drain(patroller)
    ray.get(patroller.receive_message.remote({"type": "KB_EVENT", "pid": 789, "score": 65.0}))
    _drain(patroller)
    assert len(ray.get(hunter.get_received.remote())) == 2


def test_patroller_with_no_hunter_pool_does_not_raise():
    patroller = PatrollerAgent.remote("patroller-test-4")  # no hunter_pool
    ray.get(patroller.receive_message.remote({"type": "KB_EVENT", "pid": 1, "score": 90.0}))
    _drain(patroller)  # must not raise
    status = ray.get(patroller.get_status.remote())
    assert "Escalating PID 1" in status["last_action"]


def test_patroller_ignores_non_kb_event_messages():
    hunter = RecordingHunter.remote()
    patroller = PatrollerAgent.remote("patroller-test-5", hunter_pool=[hunter], suspicious_threshold=40.0)
    ray.get(patroller.receive_message.remote({"type": "SOMETHING_ELSE", "pid": 1, "score": 99.0}))
    _drain(patroller)
    assert ray.get(hunter.get_received.remote()) == []


def test_patroller_round_robins_across_multiple_hunters():
    hunter_a = RecordingHunter.remote()
    hunter_b = RecordingHunter.remote()
    patroller = PatrollerAgent.remote("patroller-test-6", hunter_pool=[hunter_a, hunter_b], suspicious_threshold=40.0)

    for pid in (1, 2, 3, 4):
        ray.get(patroller.receive_message.remote({"type": "KB_EVENT", "pid": pid, "score": 50.0}))
        _drain(patroller)

    a_count = len(ray.get(hunter_a.get_received.remote()))
    b_count = len(ray.get(hunter_b.get_received.remote()))
    assert (a_count, b_count) == (2, 2)
