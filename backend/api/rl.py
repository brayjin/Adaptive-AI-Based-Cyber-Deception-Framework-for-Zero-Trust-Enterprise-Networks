from fastapi import APIRouter, Query
from pathlib import Path

from backend.services.rl_deception import adaptive_policy
from rl.train import train_dqn


router = APIRouter(prefix="/rl", tags=["Reinforcement Learning"])


@router.post("/train")
async def train_policy(episodes: int = Query(100, ge=1, le=10000)):
    return adaptive_policy.train(episodes)


@router.get("/policy")
async def get_policy():
    return adaptive_policy.describe()


@router.post("/evaluate")
async def evaluate_policy(episodes: int = Query(100, ge=1, le=10000)):
    return adaptive_policy.evaluate_baselines(episodes)


@router.post("/train/stable-baselines")
async def train_stable_baselines(timesteps: int = Query(1000, ge=100, le=100000)):
    output = Path("ml/saved_models/deception_dqn")
    model = train_dqn(timesteps, output)
    return {
        "algorithm": "Stable-Baselines3 DQN",
        "timesteps": timesteps,
        "path": f"{output}.zip",
        "live_controller": True,
    }