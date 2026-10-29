import os
import sys

import pytest
import ray

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from consensus.jje import JuryAgent, JURY_CHECKPOINT_DIR, _load_jury_policy


@pytest.fixture(scope="module", autouse=True)
def ray_session():
    # Actors get the research-only override so the LEGACY checkpoint's own
    # behaviour stays testable; the driver process does not (see
    # test_default_refuses_legacy_checkpoint). Production never sets this.
    ray.init(include_dashboard=False, ignore_reinit_error=True, num_cpus=2,
             runtime_env={"env_vars": {"KB_ALLOW_LEGACY_POLICY": "1"}})
    yield
    ray.shutdown()


def test_jury_checkpoint_exists_and_loads():
    # Guards against the checkpoint directory silently going missing/
    # moving — if this starts failing, JuryAgent has silently fallen back
    # to the fixed-threshold vote for every real deployment.
    assert os.path.isdir(JURY_CHECKPOINT_DIR), (
        f"expected a trained checkpoint at {JURY_CHECKPOINT_DIR} — "
        "run marl/train_jury.py if this is a fresh checkout without it"
    )
    # Driver has no override: the legacy checkpoint must be refused here.
    assert _load_jury_policy() is None


def test_default_refuses_legacy_checkpoint():
    # The shipped checkpoint was trained on a label-derived event_type that
    # kbd never emits; serving it on live data answers ALLOW for everything.
    # It must not load unless explicitly overridden (features/schema.py).
    assert "KB_ALLOW_LEGACY_POLICY" not in os.environ
    assert _load_jury_policy() is None


def test_jury_agent_uses_rl_policy_when_full_obs_supplied():
    jury = JuryAgent.remote("jury-rl-test")

    # A clear attack-shaped observation (high score, BORDERLANDS zone,
    # root, large positive score_delta, a non-zero engineered event_type)
    # — the trained policy should vote CONTAIN.
    attack_obs = {"score": 85.0, "zone": 2, "uid_is_root": 1, "score_delta": 40.0, "event_type": 3}
    result = ray.get(jury.evaluate_and_vote.remote({"confidence": 0.0, "obs": attack_obs}))
    assert result["vote"] == "CONTAIN", f"expected CONTAIN for a clear-attack obs, got {result}"

    # A clear benign-shaped observation — should vote ALLOW.
    benign_obs = {"score": 5.0, "zone": 0, "uid_is_root": 0, "score_delta": 0.5, "event_type": 0}
    result = ray.get(jury.evaluate_and_vote.remote({"confidence": 0.0, "obs": benign_obs}))
    assert result["vote"] == "ALLOW", f"expected ALLOW for a clear-benign obs, got {result}"


def test_jury_agent_falls_back_to_threshold_without_obs():
    # No "obs" key at all — every existing caller/test in this repo sends
    # only {"confidence": ...}, and must keep working unchanged.
    jury = JuryAgent.remote("jury-fallback-test")
    result = ray.get(jury.evaluate_and_vote.remote({"confidence": 0.95}))
    assert result["vote"] == "CONTAIN"
    result = ray.get(jury.evaluate_and_vote.remote({"confidence": 0.1}))
    assert result["vote"] == "ALLOW"
