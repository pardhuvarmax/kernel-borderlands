import os
import random

import gymnasium as gym
import numpy as np
import pandas as pd
from gymnasium import spaces

# ContainmentLevel enum values, must match kb-control-plane/proto/kb.proto exactly.
NONE, CGROUP, SECCOMP, NAMESPACE, TERMINATE = 0, 1, 2, 3, 4
N_CONTAINMENT_LEVELS = 5


class ContainmentEnv(gym.Env):
    """
    Training environment for the Containment agent's RL policy.

    Scoped-down replacement for the original AADSEnv stub (see roadmap
    Phase 1: docs/development/control-aads/aads-intelligence-roadmap.md).
    What changed from the stub, and what's still a known limitation:

    - Observation space is now built from real ProcessState/KBEvent wire
      fields (score, zone, uid, score_delta, event_type — see
      kb-control-plane/proto/kb.proto), not placeholder floats. Values are
      sourced from scripts/dataset/label.py's output (real NSL-KDD network-
      intrusion data + real /proc telemetry from this machine), not
      fabricated per-episode.
    - Reward is no longer a hardcoded "+1.0 for quarantine" stub — it's
      computed from the labeled target_containment level vs. the action
      taken, with an explicit over-/under-containment asymmetry (see
      `_reward`).
    - STILL single-step episodes (terminated=True after one action), unlike
      the roadmap's "real multi-tick episodes" goal for Jury/consensus.
      This is an intentional, honest scope cut: Containment's actual
      decision ("given this process state, which level?") is a per-alert
      classification, not a multi-tick trajectory the way Jury's consensus
      voting is — so a single-step (contextual-bandit-shaped) MDP is a
      defensible formulation for this specific agent, not a corner cut to
      match the old stub. Multi-step containment-escalation sequencing
      (the "militia" stage progression) is unbuilt and out of scope here.
    """

    def __init__(self, env_config=None):
        super().__init__()
        env_config = env_config or {}
        csv_path = env_config.get("csv_path")
        if csv_path is None:
            raise ValueError("ContainmentEnv requires env_config['csv_path']")

        df = pd.read_csv(csv_path)
        self._df = df
        # Class-balanced sampling: NSL-KDD's u2r/r2l classes are heavily
        # underrepresented (52 / 995 rows vs. 67k normal) — a plain uniform
        # sample would train a policy that rarely ever sees a TERMINATE-
        # worthy example. Sample category first, uniformly, then a row
        # within that category, so rare-but-severe classes get equal
        # training attention despite being rare in the raw data.
        self._rows_by_category = {
            cat: sub.to_dict("records") for cat, sub in df.groupby("category")
        }
        self._categories = list(self._rows_by_category.keys())

        self.observation_space = spaces.Box(
            low=np.array([0.0, 0.0, 0.0, -100.0, 0.0], dtype=np.float32),
            high=np.array([100.0, 2.0, 1.0, 100.0, 3.0], dtype=np.float32),
            dtype=np.float32,
        )
        self.action_space = spaces.Discrete(N_CONTAINMENT_LEVELS)
        self._current_target = None

    def _sample_row(self):
        cat = random.choice(self._categories)
        return random.choice(self._rows_by_category[cat])

    def _obs_from_row(self, row):
        return np.array([
            row["score"],
            row["zone"],
            row["uid_is_root"],
            row["score_delta"],
            row["event_type"],
        ], dtype=np.float32)

    def reset(self, *, seed=None, options=None):
        super().reset(seed=seed)
        row = self._sample_row()
        self._current_target = int(row["target_containment"])
        obs = self._obs_from_row(row)
        return obs, {"target_containment": self._current_target}

    def _reward(self, action: int, target: int) -> float:
        if action == target:
            return 1.0
        distance = abs(action - target)
        penalty = 0.3 * distance
        if action < target:
            # Under-containment: a real threat left less-contained than it
            # should be. Weighted worse than over-containment (roadmap:
            # "over-contain and under-contain both have a cost", but a
            # missed U2R-severity threat is worse than an over-cautious
            # cgroup limit on a benign process).
            penalty += 0.2 * distance
        return round(1.0 - penalty, 4)

    def step(self, action):
        reward = self._reward(int(action), self._current_target)
        terminated = True
        truncated = False
        obs = np.zeros(5, dtype=np.float32)  # terminal obs, unused past this step
        info = {"target_containment": self._current_target}
        return obs, reward, terminated, truncated, info
