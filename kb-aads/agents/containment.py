import os

import numpy as np
import ray

from .base_agent import BaseAgent, AgentRole

LEVEL_NAMES = ["NONE", "CGROUP", "SECCOMP", "NAMESPACE", "TERMINATE"]

# Populated by kb-aads/marl/train_containment.py (or its Colab notebook
# counterpart, train_containment.ipynb) — see marl/README.md's RL scope.
# Path is relative to this file so it resolves regardless of cwd.
CHECKPOINT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "marl", "checkpoints", "containment_ppo",
)
RL_MODULE_SUBPATH = os.path.join("learner_group", "learner", "rl_module", "default_policy")


def _load_policy(checkpoint_dir: str = CHECKPOINT_DIR):
    """
    Loads the trained RL policy for inference only — RLModule.from_checkpoint,
    not a full Algorithm.from_checkpoint, so this doesn't need ray.init() or
    the training stack (env runners, learner group) in the agent process,
    just the trained weights + a forward pass.

    Returns None if no checkpoint exists yet (e.g. this repo hasn't had
    train_containment.py/ipynb run against it) — callers must handle that
    by falling back to a documented, explicit non-model default, not by
    guessing.
    """
    rl_module_path = os.path.join(checkpoint_dir, RL_MODULE_SUBPATH)
    if not os.path.isdir(rl_module_path):
        return None
    from ray.rllib.core.rl_module.rl_module import RLModule
    return RLModule.from_checkpoint(rl_module_path)


@ray.remote
class ContainmentAgent(BaseAgent):
    """
    Containment agents isolate malicious processes.

    Decision logic (which ContainmentLevel to apply) is an RLlib PPO policy
    trained per kb-aads/marl/train_containment.py against real syscall-
    behavior-derived data (see scripts/dataset/{collect,label,split}.py) —
    not a hardcoded threshold. See marl/README.md's "RL scope" section for
    why Containment specifically gets a trained policy (Judge/Executor/
    Patroller don't).

    Falls back to NONE (no containment) with an explicit `model_loaded:
    False` status if no checkpoint has been trained yet, rather than
    silently guessing — see `_load_policy`.
    """

    def __init__(self, agent_id: str):
        super().__init__(agent_id, AgentRole.CONTAINMENT)
        self._policy = _load_policy()
        self._last_target_pid = None

    async def tick(self):
        if self._policy is None:
            self.state.last_action = "No trained checkpoint found — awaiting containment orders"
            return
        self.state.last_action = "Awaiting containment orders (policy loaded, idle)"

    async def decide(self, obs: dict) -> dict:
        """
        obs: {"score": float, "zone": int, "uid_is_root": int,
              "score_delta": float, "event_type": int}
        matching the ProcessState/KBEvent-derived schema training was run
        against (see kb-aads/marl/env.py).
        """
        if self._policy is None:
            return {"level": 0, "level_name": "NONE", "model_loaded": False}

        import torch

        vec = np.array([
            obs["score"], obs["zone"], obs["uid_is_root"],
            obs["score_delta"], obs["event_type"],
        ], dtype=np.float32)
        with torch.no_grad():
            out = self._policy.forward_inference({"obs": torch.from_numpy(vec).unsqueeze(0)})
            action = int(torch.argmax(out["action_dist_inputs"], dim=-1).item())

        return {"level": action, "level_name": LEVEL_NAMES[action], "model_loaded": True}

    async def handle_message(self, message: dict):
        if message.get("type") == "CONTAIN":
            pid = message.get("pid")
            self._last_target_pid = pid
            decision = await self.decide(message["obs"])
            self.state.last_action = (
                f"PID {pid} -> {decision['level_name']} "
                f"({'trained policy' if decision['model_loaded'] else 'no model loaded'})"
            )
