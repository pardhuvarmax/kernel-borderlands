import os
import sys

import pytest
import ray

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from agents.signal_relay import SignalRelayAgent


@pytest.fixture(scope="module", autouse=True)
def ray_session():
    ray.init(include_dashboard=False, ignore_reinit_error=True, num_cpus=2)
    yield
    ray.shutdown()


@ray.remote
class RecordingActor:
    def __init__(self):
        self.received = []

    async def receive_message(self, message: dict):
        self.received.append(message)

    def get_received(self):
        return self.received


def _drain(relay_actor):
    ray.get(relay_actor.process_messages.remote())


def test_relay_forwards_payload_to_named_route():
    target = RecordingActor.remote()
    relay = SignalRelayAgent.remote("relay-test-1", routes={"hunter": [target]})

    ray.get(relay.receive_message.remote({
        "type": "RELAY", "route": "hunter", "payload": {"pid": 1, "score": 99.0},
    }))
    _drain(relay)

    assert ray.get(target.get_received.remote()) == [{"pid": 1, "score": 99.0}]


def test_relay_round_robins_across_route_pool():
    target_a = RecordingActor.remote()
    target_b = RecordingActor.remote()
    relay = SignalRelayAgent.remote("relay-test-2", routes={"hunter": [target_a, target_b]})

    for i in range(4):
        ray.get(relay.receive_message.remote({"type": "RELAY", "route": "hunter", "payload": {"i": i}}))
        _drain(relay)

    a_count = len(ray.get(target_a.get_received.remote()))
    b_count = len(ray.get(target_b.get_received.remote()))
    assert (a_count, b_count) == (2, 2)


def test_relay_drops_unknown_route_without_raising():
    relay = SignalRelayAgent.remote("relay-test-3", routes={"hunter": [RecordingActor.remote()]})
    ray.get(relay.receive_message.remote({"type": "RELAY", "route": "nonexistent", "payload": {}}))
    _drain(relay)  # must not raise
    status = ray.get(relay.get_status.remote())
    assert "Relayed" not in status["last_action"]


def test_relay_ignores_non_relay_messages():
    target = RecordingActor.remote()
    relay = SignalRelayAgent.remote("relay-test-4", routes={"hunter": [target]})
    ray.get(relay.receive_message.remote({"type": "SOMETHING_ELSE"}))
    _drain(relay)
    assert ray.get(target.get_received.remote()) == []


def test_relay_with_no_routes_does_not_raise():
    relay = SignalRelayAgent.remote("relay-test-5")
    ray.get(relay.receive_message.remote({"type": "RELAY", "route": "hunter", "payload": {}}))
    _drain(relay)  # must not raise
