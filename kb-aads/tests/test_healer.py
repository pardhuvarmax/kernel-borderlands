import os
import sys

import pytest
import ray

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from agents.healer import HealerAgent, DEFAULT_MIN_CONTAINMENT_TICKS, DEFAULT_SAFE_SCORE_THRESHOLD


@pytest.fixture(scope="module", autouse=True)
def ray_session():
    ray.init(include_dashboard=False, ignore_reinit_error=True, num_cpus=2)
    yield
    ray.shutdown()


def test_decide_restores_when_all_conditions_met():
    healer = HealerAgent.remote("healer-test")
    decision = ray.get(healer.decide.remote({
        "pid": 1, "zone": 0, "score": 5.0, "ticks_contained": 120,
    }))
    assert decision == "RESTORE"


def test_decide_keeps_contained_when_zone_not_safe():
    healer = HealerAgent.remote("healer-test-2")
    decision = ray.get(healer.decide.remote({
        "pid": 1, "zone": 1, "score": 5.0, "ticks_contained": 120,  # SUSPICIOUS, not SAFE
    }))
    assert decision == "KEEP_CONTAINED"


def test_decide_keeps_contained_when_score_still_high():
    healer = HealerAgent.remote("healer-test-3")
    decision = ray.get(healer.decide.remote({
        "pid": 1, "zone": 0, "score": 50.0, "ticks_contained": 120,
    }))
    assert decision == "KEEP_CONTAINED"


def test_decide_keeps_contained_when_not_enough_time_elapsed():
    healer = HealerAgent.remote("healer-test-4")
    decision = ray.get(healer.decide.remote({
        "pid": 1, "zone": 0, "score": 5.0, "ticks_contained": 1,
    }))
    assert decision == "KEEP_CONTAINED"


def test_decide_defaults_to_keep_contained_on_missing_fields():
    # No fields at all — must default to the least permissive
    # interpretation, never accidentally RESTORE.
    healer = HealerAgent.remote("healer-test-5")
    decision = ray.get(healer.decide.remote({"pid": 1}))
    assert decision == "KEEP_CONTAINED"


def test_handle_message_routes_recover_and_updates_last_action():
    healer = HealerAgent.remote("healer-test-6")
    ray.get(healer.receive_message.remote({
        "type": "RECOVER", "pid": 42, "zone": 0, "score": 1.0,
        "ticks_contained": DEFAULT_MIN_CONTAINMENT_TICKS,
    }))
    ray.get(healer.process_messages.remote())
    status = ray.get(healer.get_status.remote())
    assert "PID 42 -> RESTORE" in status["last_action"]


def test_handle_message_ignores_non_recover_messages():
    healer = HealerAgent.remote("healer-test-7")
    ray.get(healer.receive_message.remote({"type": "SOMETHING_ELSE", "pid": 1}))
    ray.get(healer.process_messages.remote())
    status = ray.get(healer.get_status.remote())
    assert "PID" not in status["last_action"]


def test_thresholds_are_configurable_per_instance():
    healer = HealerAgent.remote("healer-test-8", min_containment_ticks=5, safe_score_threshold=90.0)
    decision = ray.get(healer.decide.remote({
        "pid": 1, "zone": 0, "score": 80.0, "ticks_contained": 5,
    }))
    assert decision == "RESTORE"
