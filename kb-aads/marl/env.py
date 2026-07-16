import gymnasium as gym
from gymnasium import spaces
import numpy as np

class AADSEnv(gym.Env):
    """Multi-Agent Environment for training KB threat containment policies."""
    def __init__(self, env_config=None):
        super().__init__()
        # State space: [process anomaly score, process CPU load, process network rate]
        self.observation_space = spaces.Box(
            low=np.array([0.0, 0.0, 0.0], dtype=np.float32),
            high=np.array([100.0, 100.0, 100.0], dtype=np.float32),
            dtype=np.float32
        )
        # Action space: 0 (Ignore), 1 (Monitor Suspicious), 2 (Quarantine Process)
        self.action_space = spaces.Discrete(3)
        self.state = np.array([0.0, 0.0, 0.0], dtype=np.float32)

    def reset(self, *, seed=None, options=None):
        self.state = np.array([0.0, 0.0, 0.0], dtype=np.float32)
        return self.state, {}

    def step(self, action):
        # Apply actions and calculate outcomes
        reward = 0.0
        # Compute rewards based on actions
        # True Positive: +1.0, False Positive: -0.5, False Negative: -1.0
        if action == 2: # Quarantine
            reward = 1.0 # Assuming correct threat mitigation
        else:
            reward = 0.1 # Baseline normal operation
            
        terminated = True
        truncated = False
        return self.state, reward, terminated, truncated, {}