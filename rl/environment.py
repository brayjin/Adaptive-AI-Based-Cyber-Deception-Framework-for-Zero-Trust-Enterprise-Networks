import numpy as np
import gymnasium as gym
from gymnasium import spaces


class DeceptionEnv(gym.Env):
    """Gymnasium environment for six-action deception strategy selection."""

    metadata = {"render_modes": []}

    def __init__(self, max_steps: int = 20):
        super().__init__()
        self.observation_space = spaces.Box(0.0, 1.0, shape=(12,), dtype=np.float32)
        self.action_space = spaces.Discrete(6)
        self.max_steps = max_steps
        self.steps = 0
        self.state = np.zeros(12, dtype=np.float32)

    def reset(self, *, seed: int | None = None, options: dict | None = None):
        super().reset(seed=seed)
        self.steps = 0
        self.state = self.np_random.random(12).astype(np.float32)
        return self.state.copy(), {}

    def step(self, action: int):
        risk = float(np.mean(self.state[:3]))
        engagement = float(self.state[3])
        device = float(self.state[4])
        behaviour = float(self.state[1])
        network = float(self.state[2])
        composite = float(self.state[6])
        targeted = action < 5
        if action == 0:
            alignment = device
        elif action == 1:
            alignment = 0.5
        elif action == 2:
            alignment = float(self.state[5])
        elif action == 3:
            alignment = behaviour
        elif action == 4:
            alignment = network
        else:
            alignment = 1.0 - composite
        reward = risk * 0.5 + alignment * 0.35 + (engagement * 0.2 if targeted else -0.15)
        if action == 5 and composite >= 0.6:
            reward -= 0.25
        self.state[3] = np.clip(engagement + (0.12 if targeted else -0.05), 0.0, 1.0)
        self.state[4] = float(targeted)
        self.steps += 1
        terminated = self.steps >= self.max_steps
        return self.state.copy(), float(reward), terminated, False, {}