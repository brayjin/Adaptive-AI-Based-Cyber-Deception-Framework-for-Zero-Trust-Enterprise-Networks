from dataclasses import dataclass, field
import random

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim


DECEPTION_ACTIONS = (
    "FAKE_SSH",
    "FAKE_WEB",
    "FAKE_DB",
    "FAKE_CREDENTIALS",
    "DIGITAL_TWIN",
    "NORMAL_RESPONSE",
)


@dataclass
class DeceptionEnv:
    """Small deterministic environment for simulator-backed policy training."""

    state_dim: int = 12
    action_count: int = len(DECEPTION_ACTIONS)
    state: np.ndarray = field(default_factory=lambda: np.zeros(12, dtype=np.float32))

    def reset(self, state: np.ndarray | None = None) -> np.ndarray:
        self.state = np.asarray(
            state if state is not None else np.zeros(self.state_dim),
            dtype=np.float32,
        )[: self.state_dim]
        return self.state.copy()

    def step(self, action: int) -> tuple[np.ndarray, float, bool, dict]:
        if not 0 <= action < self.action_count:
            raise ValueError(f"Action must be between 0 and {self.action_count - 1}")
        risk = float(np.clip(np.mean(self.state[:3]), 0.0, 1.0))
        engagement = float(np.clip(self.state[3], 0.0, 1.0))
        targeted = int(action in {0, 1, 2, 3, 4})
        reward = (risk * 0.8) + (engagement * 0.4 if targeted else -0.2)
        self.state[3] = np.clip(engagement + (0.1 if targeted else -0.05), 0.0, 1.0)
        self.state[4] = float(targeted)
        return self.state.copy(), float(reward), True, {"action": DECEPTION_ACTIONS[action]}


class DQNNetwork(nn.Module):
    def __init__(self, state_dim: int, action_count: int):
        super().__init__()
        self.network = nn.Sequential(
            nn.Linear(state_dim, 64),
            nn.ReLU(),
            nn.Linear(64, 64),
            nn.ReLU(),
            nn.Linear(64, action_count),
        )

    def forward(self, state: torch.Tensor) -> torch.Tensor:
        return self.network(state)


class AdaptiveDeceptionPolicy:
    def __init__(self, seed: int = 42):
        self.random = random.Random(seed)
        torch.manual_seed(seed)
        self.model = DQNNetwork(12, len(DECEPTION_ACTIONS))
        self.optimizer = optim.Adam(self.model.parameters(), lr=0.001)
        self.trained_episodes = 0

    def select_action(self, state: np.ndarray, explore: bool = False) -> int:
        if explore and self.random.random() < 0.15:
            return self.random.randrange(len(DECEPTION_ACTIONS))
        with torch.no_grad():
            values = self.model(torch.as_tensor(state, dtype=torch.float32).unsqueeze(0))
        return int(torch.argmax(values, dim=1).item())

    def train(self, episodes: int = 100) -> dict:
        environment = DeceptionEnv()
        rewards = []
        for _ in range(episodes):
            state = environment.reset(np.random.default_rng(self.trained_episodes).random(12))
            action = self.select_action(state, explore=True)
            _, reward, _, _ = environment.step(action)
            state_tensor = torch.as_tensor(state, dtype=torch.float32).unsqueeze(0)
            action_tensor = torch.tensor([[action]], dtype=torch.long)
            target = torch.tensor([[reward]], dtype=torch.float32)
            prediction = self.model(state_tensor).gather(1, action_tensor)
            loss = nn.functional.mse_loss(prediction, target)
            self.optimizer.zero_grad()
            loss.backward()
            self.optimizer.step()
            rewards.append(reward)
            self.trained_episodes += 1
        q_values = self.model(torch.zeros((1, 12))).detach().numpy()[0]
        return {
            "episodes": self.trained_episodes,
            "mean_reward": float(np.mean(rewards)) if rewards else 0.0,
            "q_values": q_values.tolist(),
        }

    def describe(self) -> dict:
        q_values = self.model(torch.zeros((1, 12))).detach().numpy()[0]
        return {
            "actions": list(DECEPTION_ACTIONS),
            "q_values": q_values.tolist(),
            "trained_episodes": self.trained_episodes,
            "algorithm": "DQN",
        }

    def evaluate_baselines(self, episodes: int = 100) -> dict:
        environment = DeceptionEnv()
        policies = {
            "random": lambda _: self.random.randrange(len(DECEPTION_ACTIONS)),
            "static": lambda _: 0,
            "round_robin": lambda index: index % len(DECEPTION_ACTIONS),
            "dqn": lambda state: self.select_action(state),
        }
        results = {}
        for name, selector in policies.items():
            rewards = []
            for index in range(episodes):
                state = environment.reset(
                    np.random.default_rng(index).random(environment.state_dim)
                )
                _, reward, _, _ = environment.step(selector(index if name == "round_robin" else state))
                rewards.append(reward)
            results[name] = {
                "episodes": episodes,
                "mean_reward": float(np.mean(rewards)),
            }
        return results


adaptive_policy = AdaptiveDeceptionPolicy()