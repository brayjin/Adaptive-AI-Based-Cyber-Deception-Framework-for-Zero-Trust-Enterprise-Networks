from pathlib import Path

from stable_baselines3 import DQN

from rl.environment import DeceptionEnv


_trained_model: DQN | None = None


def train_dqn(total_timesteps: int = 10_000, output: Path | None = None) -> DQN:
    global _trained_model
    model = DQN(
        "MlpPolicy",
        DeceptionEnv(),
        learning_rate=1e-3,
        buffer_size=5_000,
        learning_starts=100,
        batch_size=32,
        exploration_fraction=0.2,
        seed=42,
        verbose=0,
    )
    model.learn(total_timesteps=total_timesteps)
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        model.save(output)
    _trained_model = model
    return model


def get_trained_dqn() -> DQN | None:
    return _trained_model