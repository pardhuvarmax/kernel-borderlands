import os
import sys

import pytest
import ray

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from consensus.jje import JudgeAgent


@pytest.fixture(scope="module", autouse=True)
def ray_session():
    ray.init(include_dashboard=False, ignore_reinit_error=True, num_cpus=2)
    yield
    ray.shutdown()


@ray.remote
class FakeExecutorActor:
    """Records whether execute_quarantine was invoked, without touching
    the real gRPC/UDS path ExecutorAgent uses."""

    def __init__(self):
        self.calls = []

    async def execute_quarantine(self, alert_payload):
        self.calls.append(alert_payload)
        return {"decision_id": "test", "success": True, "message": "ok"}

    def get_calls(self):
        return self.calls


@ray.remote
class SpawnCounter:
    """Named actor jurors register with on construction, so the test can
    observe how many jurors JudgeAgent actually spawned — Ray doesn't
    expose actor-spawn counts to the driver any other way."""

    def __init__(self):
        self.count = 0

    def increment(self):
        self.count += 1

    def get(self):
        return self.count


@ray.remote
class RecordingJuryAgent:
    """Registers with the SpawnCounter named actor on construction, then
    always votes ALLOW — used to verify how many jurors get spawned
    (BUG-006 — pool size must come from config, not a hardcoded 5)."""

    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        ray.get_actor("spawn-counter").increment.remote()

    async def evaluate_and_vote(self, alert_payload):
        return {"agent_id": self.agent_id, "vote": "ALLOW", "weight": 1.0}


@ray.remote
class FlakyJuryAgent:
    """Jurors named jury-0/jury-1 always raise; every other juror votes
    CONTAIN — simulates crashed/misbehaving jurors (BUG-007)."""

    def __init__(self, agent_id: str):
        self.agent_id = agent_id

    async def evaluate_and_vote(self, alert_payload):
        if self.agent_id in ("jury-0", "jury-1"):
            raise RuntimeError(f"simulated crash for {self.agent_id}")
        return {"agent_id": self.agent_id, "vote": "CONTAIN", "weight": 1.0}


# --- BUG-006: jury pool size must come from config, not a hardcoded 5. ---

def test_jury_pool_size_matches_configured_value():
    counter = SpawnCounter.options(name="spawn-counter").remote()
    executor = FakeExecutorActor.remote()
    judge = JudgeAgent.remote("judge-test", executor, jury_pool_size=3, jury_agent_cls=RecordingJuryAgent)
    ray.get(judge.coordinate_consensus.remote({"confidence": 0.1, "pid": 1}))

    assert ray.get(counter.get.remote()) == 3, "expected exactly 3 jurors spawned for jury_pool_size=3"
    calls = ray.get(executor.get_calls.remote())
    assert calls == [], "all-ALLOW votes must not trigger containment"
    ray.kill(counter)


def test_jury_pool_size_of_one_with_contain_vote_triggers_containment():
    @ray.remote
    class SingleContainJury:
        def __init__(self, agent_id: str):
            self.agent_id = agent_id

        async def evaluate_and_vote(self, alert_payload):
            return {"agent_id": self.agent_id, "vote": "CONTAIN", "weight": 1.0}

    executor = FakeExecutorActor.remote()
    judge = JudgeAgent.remote("judge-test", executor, jury_pool_size=1, jury_agent_cls=SingleContainJury)
    ray.get(judge.coordinate_consensus.remote({"confidence": 0.9, "pid": 1}))
    calls = ray.get(executor.get_calls.remote())
    assert len(calls) == 1, "a jury_pool_size=1 round with a single CONTAIN vote should trigger containment"


# --- BUG-007: one crashed juror must not abort the whole consensus round;
# quorum is decided among whichever jurors actually responded. ---

def test_crashed_juror_does_not_abort_round_and_quorum_still_reached():
    executor = FakeExecutorActor.remote()
    judge = JudgeAgent.remote("judge-test", executor, jury_pool_size=3, jury_agent_cls=FlakyJuryAgent)
    # jury-0/jury-1 raise; jury-2 survives and votes CONTAIN. Must not
    # raise up through ray.get() despite two of three jurors crashing.
    ray.get(judge.coordinate_consensus.remote({"confidence": 0.9, "pid": 1}))

    calls = ray.get(executor.get_calls.remote())
    assert len(calls) == 1, "the one surviving juror's CONTAIN vote should still reach quorum (1/1 > 0.5)"


def test_all_jurors_crashing_skips_round_without_raising():
    executor = FakeExecutorActor.remote()
    judge = JudgeAgent.remote("judge-test", executor, jury_pool_size=2, jury_agent_cls=FlakyJuryAgent)
    # jury-0 and jury-1 both raise — every juror in this round fails.
    ray.get(judge.coordinate_consensus.remote({"confidence": 0.9, "pid": 1}))

    calls = ray.get(executor.get_calls.remote())
    assert calls == [], "no containment should be triggered when every juror failed"
